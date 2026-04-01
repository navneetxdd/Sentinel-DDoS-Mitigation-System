/*
 * Sentinel DDoS Core - AF_XDP Pipeline Daemon
 *
 * Lockless, zero-copy packet pipeline.
 * Reads raw Ethernet frames directly from the NIC utilizing an AF_XDP 
 * User Memory (UMEM) ring-buffer. Bypasses the Linux kernel completely.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <stdatomic.h>
#include "sentinel_core/platform_compat.h"

#ifndef SENTINEL_LINUX_RUNTIME
#define SENTINEL_LINUX_RUNTIME 0
#endif

#if SENTINEL_LINUX_RUNTIME
# include <strings.h>
# include <unistd.h>
# include <getopt.h>
# include <poll.h>
# include <pthread.h>
# include <sched.h>
# include <sys/socket.h>
# include <sys/mman.h>
# include <sys/syscall.h>
# include <sys/times.h>
# include <sys/wait.h>
# include <sys/ioctl.h>
# include <linux/if_xdp.h>
# ifndef XDP_UMEM_PGOFF_FILL_RING
# define XDP_UMEM_PGOFF_FILL_RING 0x100000000ULL
# endif
# include <linux/if_link.h>
# include <linux/bpf.h>
# include <linux/rtnetlink.h>
# include <linux/if_packet.h>
# include <net/if.h>
# include <netinet/in.h>
# include <net/ethernet.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <arpa/inet.h>
# include <curl/curl.h>
#else
/* Non-Linux editor stubs for IDE/IntelliSense only; not used at runtime on Linux. */
# include "sentinel_core/sentinel_pipeline_stubs.h"
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#include "sentinel_core/sentinel_types.h"
#include "l1_native/feature_extractor.h"
#include "ml_engine/decision_engine.h"
#include "sdncontrol/sdn_controller.h"
#include "feedback/feedback.h"
#include "websocket/websocket_server.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 64
#endif

/* ============================================================================
 * REAL SYSTEM METRICS (parse /proc)
 * ============================================================================ */

static double read_cpu_usage(void)
{
#if SENTINEL_LINUX_RUNTIME
    static unsigned long last_utime = 0, last_stime = 0;
    static struct timespec last_ts = { 0, 0 };
    FILE *f = fopen("/proc/self/stat", "r");
    if (!f) return 0.0;
    unsigned long utime = 0, stime = 0;
    /* pid (comm) state ppid ... utime(14) stime(15); comm may contain spaces/parens */
    int n = fscanf(f, "%*d %*[^)]%*c %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                   &utime, &stime);
    fclose(f);
    if (n != 2) return 0.0;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0.0;

    if (last_ts.tv_sec == 0 && last_ts.tv_nsec == 0) {
        last_utime = utime; last_stime = stime; last_ts = now;
        return 0.0;
    }
    double elapsed = (double)(now.tv_sec - last_ts.tv_sec) + (double)(now.tv_nsec - last_ts.tv_nsec) / 1e9;
    if (elapsed <= 0) return 0.0;
    long ticks = sysconf(_SC_CLK_TCK);
    if (ticks <= 0) ticks = 100;
    double delta_ticks = (double)((utime + stime) - (last_utime + last_stime));
    last_utime = utime; last_stime = stime; last_ts = now;
    return (delta_ticks / (double)ticks / elapsed) * 100.0;
#else
    return 0.0;
#endif
}

static double read_mem_usage(void)
{
#if SENTINEL_LINUX_RUNTIME
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0.0;
    char line[256];
    unsigned long vm_rss_kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%lu", &vm_rss_kb);
            break;
        }
    }
    fclose(f);
    return (double)vm_rss_kb / 1024.0;
#else
    return 0.0;
#endif
}

/* Baremetal BPF syscall wrapper. On non-Linux (e.g. Windows IDE) returns -1 for IntelliSense. */
static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#if SENTINEL_LINUX_RUNTIME
    return (int)syscall(__NR_bpf, cmd, attr, size);
#else
    (void)cmd;
    (void)attr;
    (void)size;
    return -1;
#endif
}

static int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uintptr_t)key,
        .value  = (uintptr_t)value,
        .flags  = flags,
    };
    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_delete_elem(int fd, const void *key)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uintptr_t)key,
    };
    return bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr = {
        .map_fd  = fd,
        .key     = (uintptr_t)key,
        .value   = (uintptr_t)next_key,
    };
    return bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

/* Activity ring: primitives only (no snprintf in hot path); formatted in 1s drain. */
typedef struct activity_raw_s {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    sentinel_verdict_e verdict;
    sentinel_attack_type_t attack_type;
    double threat_score;
    double confidence;
    double score_ml;
    double ml_reliability;
    int enforced;  /* 1 if block/rate_limit was applied, 0 if auto-mitigation disabled */
} activity_raw_t;

#define IP_IDENTITY_MAP_CAP 8192u
#define IP_IDENTITY_PROBE 16u
#define IP_IDENTITY_TTL_NS (180ULL * 1000000000ULL)
typedef struct ip_identity_entry_s {
    uint32_t key_ip;
    uint8_t ip_family;
    uint64_t last_seen_ns;
    char ip_text[64];
    uint8_t used;
} ip_identity_entry_t;
static ip_identity_entry_t g_ip_identity_map[IP_IDENTITY_MAP_CAP];

static uint32_t ip_identity_slot(uint32_t key_ip)
{
    return (uint32_t)(((uint64_t)ntohl(key_ip) * 2654435761u) % IP_IDENTITY_MAP_CAP);
}

static void ip_identity_record(uint32_t key_ip, uint8_t ip_family, const char *ip_text, uint64_t now_ns)
{
    if (key_ip == 0 || !ip_text || ip_text[0] == '\0') return;
    uint32_t slot = ip_identity_slot(key_ip);
    uint32_t replace_idx = slot;
    uint64_t oldest_seen = UINT64_MAX;
    for (uint32_t i = 0; i < IP_IDENTITY_PROBE; i++) {
        uint32_t idx = (slot + i) % IP_IDENTITY_MAP_CAP;
        ip_identity_entry_t *e = &g_ip_identity_map[idx];
        if (!e->used || e->key_ip == key_ip) {
            e->used = 1;
            e->key_ip = key_ip;
            e->ip_family = ip_family;
            e->last_seen_ns = now_ns;
            snprintf(e->ip_text, sizeof(e->ip_text), "%s", ip_text);
            return;
        }
        if (e->last_seen_ns < oldest_seen) {
            oldest_seen = e->last_seen_ns;
            replace_idx = idx;
        }
    }
    ip_identity_entry_t *e = &g_ip_identity_map[replace_idx];
    e->used = 1;
    e->key_ip = key_ip;
    e->ip_family = ip_family;
    e->last_seen_ns = now_ns;
    snprintf(e->ip_text, sizeof(e->ip_text), "%s", ip_text);
}

static int ip_identity_lookup(uint32_t key_ip, char *out_text, size_t out_text_sz, char *out_family, size_t out_family_sz)
{
    if (!out_text || out_text_sz == 0) return 0;
    out_text[0] = '\0';
    if (out_family && out_family_sz > 0) out_family[0] = '\0';
    uint32_t slot = ip_identity_slot(key_ip);
    for (uint32_t i = 0; i < IP_IDENTITY_PROBE; i++) {
        const ip_identity_entry_t *e = &g_ip_identity_map[(slot + i) % IP_IDENTITY_MAP_CAP];
        if (!e->used) continue;
        if (e->key_ip == key_ip) {
            if (e->last_seen_ns > 0) {
                uint64_t now_ns = (uint64_t)time(NULL) * 1000000000ULL;
                if (now_ns > e->last_seen_ns && (now_ns - e->last_seen_ns) > IP_IDENTITY_TTL_NS) {
                    return 0;
                }
            }
            snprintf(out_text, out_text_sz, "%s", e->ip_text);
            if (out_family && out_family_sz > 0) {
                snprintf(out_family, out_family_sz, "%s", (e->ip_family == 6) ? "ipv6" : "ipv4");
            }
            return 1;
        }
    }
    return 0;
}

/* IPv6 keys are encoded as pseudo IPv4 in 0.x.y.z for internal flow keying. */
static int ip_is_pseudo_ipv6_key(uint32_t ip_net_order)
{
    uint32_t host = ntohl(ip_net_order);
    return ((host >> 24) == 0u) && (host != 0u);
}

static void fill_ip_identity_fallback(uint32_t ip_key, char *ip_text, size_t ip_text_sz, char *ip_family, size_t ip_family_sz)
{
    if (!ip_text || ip_text_sz == 0) return;
    if (ip_is_pseudo_ipv6_key(ip_key)) {
        if (ip_family && ip_family_sz > 0) snprintf(ip_family, ip_family_sz, "%s", "ipv6");
        snprintf(ip_text, ip_text_sz, "%s", "unresolved_ipv6");
        return;
    }
    if (ip_family && ip_family_sz > 0) snprintf(ip_family, ip_family_sz, "%s", "ipv4");
    inet_ntop(AF_INET, &ip_key, ip_text, ip_text_sz);
}

/* Feedback thread: lockless handoff; main loop must never call futex (no mutex). */
#define FEEDBACK_SLOTS 32
/* Shared-memory contract: main thread writes src_ips/scores and updates ready_slot/work_ready
 * with atomic_store (release). feedback_worker reads with atomic_load (acquire). Only atomics
 * and the double-buffered arrays are shared; any new field must be atomic or documented. */
typedef struct feedback_shared_s {
    uint32_t src_ips[2][FEEDBACK_SLOTS];
    double   scores[2][FEEDBACK_SLOTS];
    char     _pad1[64]; /* Prevents false sharing between data and control atoms */
    atomic_uint ready_count;
    atomic_int  ready_slot;   /* which buffer (0 or 1) is ready for consumer */
    atomic_int  work_ready;
    _Atomic int stop;        /* set by main on shutdown; worker reads with atomic_load */
    char     _pad2[64];
} feedback_shared_t;

static volatile sig_atomic_t g_running = 1;

typedef struct pipeline_integration_flags {
    int intel_feed_enabled;
    int model_extension_enabled;
    int controller_extension_enabled;
    int signature_feed_enabled;
    int dataplane_extension_enabled;
    char profile[WS_INTEGRATION_PROFILE_MAX];
} pipeline_integration_flags_t;

typedef struct controller_extension_state {
    int enabled;
    uint64_t min_interval_ns;
    uint64_t last_exec_ns;
    char command[256];
} controller_extension_state_t;

typedef enum pipeline_dataplane_mode {
    PIPELINE_DATAPLANE_AF_XDP_AUTO = 0,
    PIPELINE_DATAPLANE_AF_XDP_ZEROCOPY,
    PIPELINE_DATAPLANE_AF_XDP_COPY,
    PIPELINE_DATAPLANE_RAW_FALLBACK
} pipeline_dataplane_mode_t;


static unsigned long parse_env_ul_bound(const char *name,
                                        unsigned long default_value,
                                        unsigned long min_value,
                                        unsigned long max_value)
{
    const char *raw = getenv(name);
    if (!raw || !raw[0]) return default_value;

    char *endptr = NULL;
    unsigned long parsed = strtoul(raw, &endptr, 10);
    if (!endptr || *endptr != '\0') return default_value;
    if (parsed < min_value || parsed > max_value) return default_value;
    return parsed;
}

static int parse_env_bool_default(const char *name, int default_value)
{
    const char *raw = getenv(name);
    if (!raw || !raw[0]) return default_value;
    if (strcmp(raw, "1") == 0 || strcasecmp(raw, "true") == 0 || strcasecmp(raw, "yes") == 0 || strcasecmp(raw, "on") == 0)
        return 1;
    if (strcmp(raw, "0") == 0 || strcasecmp(raw, "false") == 0 || strcasecmp(raw, "no") == 0 || strcasecmp(raw, "off") == 0)
        return 0;
    return default_value;
}

static const char *first_nonempty_env(const char *primary, const char *alias)
{
    const char *raw = NULL;
    if (primary && primary[0]) {
        raw = getenv(primary);
        if (raw && raw[0]) return raw;
    }
    if (alias && alias[0]) {
        raw = getenv(alias);
        if (raw && raw[0]) return raw;
    }
    return NULL;
}

static int parse_env_bool_alias_default(const char *primary,
                                        const char *alias,
                                        int default_value)
{
    const char *raw = first_nonempty_env(primary, alias);
    if (!raw || !raw[0]) return default_value;
    if (strcmp(raw, "1") == 0 || strcasecmp(raw, "true") == 0 || strcasecmp(raw, "yes") == 0 || strcasecmp(raw, "on") == 0)
        return 1;
    if (strcmp(raw, "0") == 0 || strcasecmp(raw, "false") == 0 || strcasecmp(raw, "no") == 0 || strcasecmp(raw, "off") == 0)
        return 0;
    return default_value;
}

static const char *pipeline_dataplane_mode_str(pipeline_dataplane_mode_t mode)
{
    switch (mode) {
        case PIPELINE_DATAPLANE_AF_XDP_ZEROCOPY: return "AF_XDP_ZEROCOPY";
        case PIPELINE_DATAPLANE_AF_XDP_COPY: return "AF_XDP_COPY";
        case PIPELINE_DATAPLANE_RAW_FALLBACK: return "RAW_SOCKET_FALLBACK";
        case PIPELINE_DATAPLANE_AF_XDP_AUTO:
        default:
            return "AF_XDP_AUTO";
    }
}

static int parse_command_argv(const char *command, char *storage, size_t storage_len,
                              char **argv, size_t argv_cap)
{
    size_t argc = 0;
    char *p;
    if (!command || !storage || storage_len == 0 || !argv || argv_cap < 2) return -1;
    snprintf(storage, storage_len, "%s", command);
    p = storage;
    while (*p && argc + 1 < argv_cap) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) break;
        *p++ = '\0';
    }
    argv[argc] = NULL;
    return (argc > 0) ? 0 : -1;
}

static int parse_default_route_iface(char *out, size_t out_len)
{
#if SENTINEL_LINUX_RUNTIME
    FILE *f;
    char line[256];

    if (!out || out_len == 0) return -1;
    f = fopen("/proc/net/route", "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ] = {0};
        unsigned long dest = 0;
        unsigned long flags = 0;
        int n = sscanf(line, "%15s %lx %*x %lx", iface, &dest, &flags);
        if (n == 3 && dest == 0UL && (flags & 0x1UL) != 0UL && strcmp(iface, "lo") != 0) {
            snprintf(out, out_len, "%s", iface);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
#else
    (void)out;
    (void)out_len;
#endif
    return -1;
}

static int parse_first_non_loopback_iface(char *out, size_t out_len)
{
#if SENTINEL_LINUX_RUNTIME
    FILE *f;
    char line[256];

    if (!out || out_len == 0) return -1;
    f = fopen("/proc/net/dev", "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ] = {0};
        char *colon = strchr(line, ':');
        char *start = line;
        size_t len;
        if (!colon) continue;
        while (*start == ' ' || *start == '\t') start++;
        len = (size_t)(colon - start);
        while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t')) len--;
        if (len == 0 || len >= sizeof(iface)) continue;
        memcpy(iface, start, len);
        iface[len] = '\0';
        if (strcmp(iface, "lo") == 0) continue;
        snprintf(out, out_len, "%s", iface);
        fclose(f);
        return 0;
    }

    fclose(f);
#else
    (void)out;
    (void)out_len;
#endif
    return -1;
}

static int parse_ifconf_iface(char *out, size_t out_len)
{
#if SENTINEL_LINUX_RUNTIME
    int fd = -1;
    struct ifconf ifc;
    char buf[8192];

    if (!out || out_len == 0) return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_len = (int)sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(fd, SIOCGIFCONF, &ifc) != 0) {
        close(fd);
        return -1;
    }

    {
        char *ptr = ifc.ifc_buf;
        char *end = ifc.ifc_buf + ifc.ifc_len;
        while (ptr + (int)sizeof(struct ifreq) <= end) {
            struct ifreq *ifr = (struct ifreq *)ptr;
            struct ifreq flags_req;
            ptr += sizeof(struct ifreq);

            if (!ifr->ifr_name[0])
                continue;
            if (strcmp(ifr->ifr_name, "lo") == 0)
                continue;

            memset(&flags_req, 0, sizeof(flags_req));
            snprintf(flags_req.ifr_name, sizeof(flags_req.ifr_name), "%s", ifr->ifr_name);
            if (ioctl(fd, SIOCGIFFLAGS, &flags_req) != 0)
                continue;
            if ((flags_req.ifr_flags & IFF_UP) == 0)
                continue;
            if ((flags_req.ifr_flags & IFF_LOOPBACK) != 0)
                continue;

            snprintf(out, out_len, "%s", ifr->ifr_name);
            close(fd);
            return 0;
        }
    }

    close(fd);
#else
    (void)out;
    (void)out_len;
#endif
    return -1;
}

static const char *resolve_capture_interface(const char *requested_ifname, char *out, size_t out_len)
{
    const char *env_iface;
    if (!out || out_len == 0) return "eth0";

    if (requested_ifname && requested_ifname[0] && strcmp(requested_ifname, "auto") != 0) {
        snprintf(out, out_len, "%s", requested_ifname);
        return out;
    }

    env_iface = getenv("SENTINEL_INTERFACE");
    if (!env_iface || !env_iface[0])
        env_iface = getenv("SENTINEL_CAPTURE_IFACE");
    if (env_iface && env_iface[0] && strcmp(env_iface, "auto") != 0) {
        snprintf(out, out_len, "%s", env_iface);
        return out;
    }

    if (parse_default_route_iface(out, out_len) == 0)
        return out;
    if (parse_ifconf_iface(out, out_len) == 0)
        return out;
    if (parse_first_non_loopback_iface(out, out_len) == 0)
        return out;

    snprintf(out, out_len, "%s", "eth0");
    return out;
}

static void load_integration_flags(pipeline_integration_flags_t *flags)
{
    const char *profile;
    int default_intel = 1;
    int default_model = 1;
    int default_controller = 1;
    int default_signature = 1;
    int default_dataplane = 1;

    if (!flags) return;

    profile = first_nonempty_env("SENTINEL_PROFILE", "SENTINEL_INTEGRATION_PROFILE");
    if (!profile || !profile[0]) profile = "production";

    if (strcasecmp(profile, "baseline") == 0) {
        default_intel = 0;
        default_model = 0;
        default_controller = 0;
        default_signature = 0;
        default_dataplane = 0;
    } else if (strcasecmp(profile, "progressive") == 0) {
        default_controller = 0;
        default_dataplane = 0;
    }

    flags->intel_feed_enabled = parse_env_bool_alias_default(
        "SENTINEL_INTEL_FEED_ENABLED",
        "SENTINEL_ENABLE_INTEL_FEED",
        default_intel
    );
    flags->model_extension_enabled = parse_env_bool_alias_default(
        "SENTINEL_MODEL_EXTENSION_ENABLED",
        "SENTINEL_ENABLE_MODEL_EXTENSION",
        default_model
    );
    flags->controller_extension_enabled = parse_env_bool_alias_default(
        "SENTINEL_CONTROLLER_EXTENSION_ENABLED",
        "SENTINEL_ENABLE_CONTROLLER_EXTENSION",
        default_controller
    );
    flags->signature_feed_enabled = parse_env_bool_alias_default(
        "SENTINEL_SIGNATURE_FEED_ENABLED",
        "SENTINEL_ENABLE_SIGNATURE_FEED",
        default_signature
    );
    flags->dataplane_extension_enabled = parse_env_bool_alias_default(
        "SENTINEL_DATAPLANE_EXTENSION_ENABLED",
        "SENTINEL_ENABLE_DATAPLANE_EXTENSION",
        default_dataplane
    );
    snprintf(flags->profile, sizeof(flags->profile), "%s", profile);
}


static void load_controller_extension_state(controller_extension_state_t *state)
{
    const char *cmd;
    const char *interval_ms;
    unsigned long parsed;

    if (!state) return;
    memset(state, 0, sizeof(*state));

    /* Always attempt controller extension; graceful fallback if cmd not set */
    state->enabled = 1;
    cmd = getenv("SENTINEL_CONTROLLER_EXTENSION_CMD");
    if (cmd && *cmd) {
        snprintf(state->command, sizeof(state->command), "%s", cmd);
    } else {
        snprintf(state->command, sizeof(state->command), "%s", "");
    }

    parsed = 2000UL;
    interval_ms = getenv("SENTINEL_CONTROLLER_EXTENSION_MIN_INTERVAL_MS");
    if (interval_ms && *interval_ms) {
        char *end = NULL;
        unsigned long v = strtoul(interval_ms, &end, 10);
        if (end && *end == '\0' && v > 0 && v <= 600000UL) {
            parsed = v;
        }
    }
    state->min_interval_ns = (uint64_t)parsed * 1000000ULL;
}

static void maybe_run_controller_extension(controller_extension_state_t *state,
                                           const sentinel_threat_assessment_t *assessment,
                                           const sentinel_sdn_rule_t *rule,
                                           int enforcing,
                                           int sdn_push_rc,
                                           uint64_t now_ns)
{
    char src_ip[INET_ADDRSTRLEN];
    char score_buf[32];
    char confidence_buf[32];
    struct in_addr ia;
    const char *action;
    char attack_type_buf[16];
    int rc;
    int status = 0;
    pid_t pid;
    char cmd_storage[sizeof(state->command)];
    char *argv_exec[32];

    if (!state || !state->enabled || !assessment || !rule) return;
    if (!state->command[0]) return;
    if (!enforcing) return;
    if (assessment->verdict == VERDICT_ALLOW) return;
    if (now_ns - state->last_exec_ns < state->min_interval_ns) return;

    ia.s_addr = assessment->src_ip;
    if (!inet_ntop(AF_INET, &ia, src_ip, sizeof(src_ip))) {
        snprintf(src_ip, sizeof(src_ip), "unknown");
    }
    if (assessment->verdict == VERDICT_DROP) action = "BLOCK";
    else if (assessment->verdict == VERDICT_RATE_LIMIT) action = "RATE_LIMIT";
    else action = "MONITOR";

    snprintf(attack_type_buf, sizeof(attack_type_buf), "%u", (unsigned)assessment->attack_type);

    snprintf(score_buf, sizeof(score_buf), "%.4f", assessment->threat_score);
    snprintf(confidence_buf, sizeof(confidence_buf), "%.4f", assessment->confidence);

    setenv("SENTINEL_EXTENSION_SRC_IP", src_ip, 1);
    setenv("SENTINEL_EXTENSION_ACTION", action, 1);
    setenv("SENTINEL_EXTENSION_ATTACK_TYPE", attack_type_buf, 1);
    setenv("SENTINEL_EXTENSION_THREAT_SCORE", score_buf, 1);
    setenv("SENTINEL_EXTENSION_CONFIDENCE", confidence_buf, 1);
    setenv("SENTINEL_EXTENSION_RULE_ID", "0", 1);
    if (rule->rule_id > 0) {
        char rule_id_buf[32];
        snprintf(rule_id_buf, sizeof(rule_id_buf), "%u", rule->rule_id);
        setenv("SENTINEL_EXTENSION_RULE_ID", rule_id_buf, 1);
    }
    setenv("SENTINEL_EXTENSION_SDN_PUSH_OK", (sdn_push_rc == 0) ? "1" : "0", 1);

    if (parse_command_argv(state->command, cmd_storage, sizeof(cmd_storage), argv_exec, 32) != 0) {
        fprintf(stderr, "[WARN] Controller extension command parse failed: %s\n", state->command);
        return;
    }

    pid = fork();
    if (pid == 0) {
        execvp(argv_exec[0], argv_exec);
        _exit(127);
    }
    if (pid < 0) {
        fprintf(stderr, "[WARN] Controller extension fork failed: %s\n", strerror(errno));
        return;
    }

    if (waitpid(pid, &status, 0) < 0) {
        rc = -1;
    } else if (WIFEXITED(status)) {
        rc = WEXITSTATUS(status);
    } else {
        rc = -1;
    }

    state->last_exec_ns = now_ns;
    if (rc != 0) {
        fprintf(stderr, "[WARN] Controller extension command returned %d\n", rc);
    }
}

static inline int pipeline_running(void) {
    return g_running;
}

static void *feedback_worker(void *arg)
{
    void **a = (void **)arg;
    fb_context_t *fb_ctx = (fb_context_t *)a[0];
    de_context_t *de_ctx = (de_context_t *)a[1];
    feedback_shared_t *shr = (feedback_shared_t *)a[3];
    uint32_t local_ips[FEEDBACK_SLOTS];
    double   local_scores[FEEDBACK_SLOTS];
    uint32_t n = 0;
    while (!atomic_load_explicit(&shr->stop, memory_order_acquire)) {
        struct timespec ts1 = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&ts1, NULL);
        if (atomic_load_explicit(&shr->stop, memory_order_acquire)) break;
        if (atomic_load_explicit(&shr->work_ready, memory_order_acquire)) {
            int slot = atomic_load_explicit(&shr->ready_slot, memory_order_acquire);
            n = atomic_load_explicit(&shr->ready_count, memory_order_acquire);
            if (n > FEEDBACK_SLOTS) n = FEEDBACK_SLOTS;
            memcpy(local_ips, shr->src_ips[slot], n * sizeof(uint32_t));
            memcpy(local_scores, shr->scores[slot], n * sizeof(double));
            atomic_store_explicit(&shr->work_ready, 0, memory_order_release);
            fb_adjustments_t adj;
            fb_suggest_adjustments(fb_ctx, &adj);
            if (adj.should_adjust)
                de_apply_adjustments(de_ctx, &adj);
            for (uint32_t k = 0; k < n; k++) {
                fb_auto_detect_fn(fb_ctx, local_ips[k], local_scores[k]);
                fb_auto_detect_fp(fb_ctx, local_ips[k], local_scores[k]);
            }
        }
    }
    return NULL;
}

/* Fast FNV1a hash for Tier-1 Ingress Identity */
static inline uint32_t fnv1a_hash(const void *key, size_t len)
{
    const uint8_t *p = (const uint8_t *)key;
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= 16777619U;
    }
    return hash;
}

/*
 * Dynamic BPF map discovery: iterate loaded maps via kernel syscalls and match by name.
 * Returns an open map FD on success, or -1 if not found / permission denied.
 * Caller owns the returned fd and should close it when done.
 */
static int find_map_fd_by_name(const char *map_name)
{
    if (!map_name || !map_name[0])
        return -1;

    __u32 next_id = 0;
    int map_fd = -1;

    /* Iterative discovery: BPF_MAP_GET_NEXT_ID over all map IDs */
    for (;;) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.start_id = next_id;
        attr.next_id  = 0;

        if (bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) != 0) {
            if (errno == ENOENT)
                break;
            if (errno == EPERM) {
                fprintf(stderr, "[WARN] BPF map discovery requires CAP_SYS_ADMIN or run as root (sudo)\n");
                return -1;
            }
            break;
        }
        next_id = attr.next_id;

        /* Open map by ID (kernel returns new fd) */
        memset(&attr, 0, sizeof(attr));
        attr.map_id = next_id;
        map_fd = bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
        if (map_fd < 0) {
            if (errno == EPERM) {
                fprintf(stderr, "[WARN] BPF map open requires CAP_SYS_ADMIN or run as root (sudo)\n");
                return -1;
            }
            continue;
        }

        /* Get map info to read name (64-bit kernel ABI for info pointer) */
        struct bpf_map_info info;
        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd   = map_fd;
        attr.info.info_len = sizeof(info);
        attr.info.info     = (uintptr_t)&info;

        if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0) {
            close(map_fd);
            map_fd = -1;
            continue;
        }

        if (strncmp(info.name, map_name, sizeof(info.name)) == 0)
            return map_fd;

        close(map_fd);
        map_fd = -1;
    }

    /* Fallback: open from configurable pinned path (BPF FS). */
    {
        const char *pinned_path = NULL;
        char generated_path[512];

        const char *explicit_map_path = getenv("SENTINEL_BPF_MAP_PATH");
        const char *xsks_map_path = getenv("SENTINEL_XSKS_MAP_PATH");
        const char *pin_dir = getenv("SENTINEL_BPF_PIN_DIR");

        if (explicit_map_path && explicit_map_path[0]) {
            pinned_path = explicit_map_path;
        } else if (xsks_map_path && xsks_map_path[0] && strcmp(map_name, "xsks_map") == 0) {
            pinned_path = xsks_map_path;
        } else {
            if (!pin_dir || !pin_dir[0]) pin_dir = "/sys/fs/bpf";
            snprintf(generated_path, sizeof(generated_path), "%s/%s", pin_dir, map_name);
            pinned_path = generated_path;
        }

        union bpf_attr get_attr;
        memset(&get_attr, 0, sizeof(get_attr));
        get_attr.pathname = (uintptr_t)pinned_path;
        map_fd = bpf(BPF_OBJ_GET, &get_attr, sizeof(get_attr));
        if (map_fd >= 0)
            return map_fd;
    }

    return -1;
}

#if SENTINEL_LINUX_RUNTIME
/* HTTP health listener: GET /health or GET / on ws_port+1 returns 200 (for load balancers). */
static void *health_listener_thread(void *arg)
{
    uint16_t port = *(const uint16_t *)arg;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return NULL;
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 5) < 0) {
        close(listen_fd);
        return NULL;
    }
    static const char resp[] = "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    while (pipeline_running()) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_fd, &fds);
        if (select(listen_fd + 1, &fds, NULL, NULL, &tv) <= 0)
            continue;
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) continue;
        char buf[256];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "GET"))
                (void)send(fd, resp, (size_t)(sizeof(resp) - 1), 0);
        }
        close(fd);
    }
    close(listen_fd);
    return NULL;
}
#endif

/* ============================================================================
 * GLOBALS & LOGGING
 * ============================================================================ */

static void sig_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        g_running = 0;
}

static FILE *g_log_file = NULL;

static void logmsg(const char *level, const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    /* Log to stderr as before */
    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            ts.tv_nsec / 1000000, level);

    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    /* Production Hardening: Persistent file logging */
    if (g_log_file) {
        fprintf(g_log_file, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                ts.tv_nsec / 1000000, level);
        vfprintf(g_log_file, fmt, ap2);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }
    va_end(ap2);
}

#define LOG_INFO(...)     logmsg("INFO",     __VA_ARGS__)
#define LOG_WARN(...)     logmsg("WARN",     __VA_ARGS__)
#define LOG_ERROR(...)    logmsg("ERROR",    __VA_ARGS__)
#define LOG_CRITICAL(...) logmsg("CRITICAL", __VA_ARGS__)
#define LOG_DEBUG(...)    do { } while (0)

static const char *attack_type_str(sentinel_attack_type_t t)
{
    switch (t) {
        case SENTINEL_ATTACK_NONE:       return "NONE";
        case SENTINEL_ATTACK_SYN_FLOOD: return "SYN_FLOOD";
        case SENTINEL_ATTACK_UDP_FLOOD: return "UDP_FLOOD";
        case SENTINEL_ATTACK_ICMP_FLOOD: return "ICMP_FLOOD";
        case SENTINEL_ATTACK_DNS_AMP:   return "DNS_AMP";
        case SENTINEL_ATTACK_NTP_AMP:   return "NTP_AMP";
        case SENTINEL_ATTACK_SLOWLORIS: return "SLOWLORIS";
        case SENTINEL_ATTACK_PORT_SCAN: return "PORT_SCAN";
        case SENTINEL_ATTACK_LAND:      return "LAND";
        case SENTINEL_ATTACK_SMURF:     return "SMURF";
        default:                        return "UNKNOWN";
    }
}

static const char *verdict_to_action(sentinel_verdict_e v)
{
    switch (v) {
        case VERDICT_DROP:       return "BLOCK";
        case VERDICT_RATE_LIMIT: return "RATE_LIMIT";
        case VERDICT_QUARANTINE: return "QUARANTINE";
        case VERDICT_REDIRECT:   return "REDIRECT";
        default:                 return "ALLOW";
    }
}

/* ============================================================================
 * AF_XDP CONSTANTS & STRUCTURES (Lockless Memory Maps)
 * ============================================================================ */

#define NUM_FRAMES         262144
#define FRAME_SIZE         2048
#define FRAME_SHIFT        11
#define FRAME_HEADROOM     256
#define UMEM_SIZE          ((uint64_t)NUM_FRAMES * (uint64_t)FRAME_SIZE)  /* UMEM bounds limit */
#define ACTIVITY_RING_SIZE 4096
#define INVALID_UMEM_FRAME UINT64_MAX

struct xdp_umem_uqueue {
    __u32 cached_prod;
    __u32 cached_cons;
    __u32 mask;
    __u32 size;
    __u32 *producer;
    __u32 *consumer;
    __u64 *ring;
    void *map;
};

struct xdp_umem {
    char *frames;
    size_t frames_len;
    int frames_is_mmap;
    struct xdp_umem_uqueue fq;
    struct xdp_umem_uqueue cq;
    int fd;
    size_t fq_region_size;  /* for munmap on teardown */
};

struct xdp_rx_queue {
    __u32 cached_prod;
    __u32 cached_cons;
    __u32 mask;
    __u32 size;
    __u32 *producer;
    __u32 *consumer;
    struct xdp_desc *ring;
    void *map;
    size_t map_size;
};

struct xsk_socket_info {
    struct xdp_rx_queue rx;
    struct xdp_umem *umem;
    int xsk_fd;
    __u32 outstanding_tx;
};

/* ============================================================================
 * EXPLICIT RING MACROS (To physically process frames without libxdp stubs)
 * ============================================================================ */

static inline __u32 xsk_ring_cons__peek(struct xdp_rx_queue *rx, __u32 nb, __u32 *idx)
{
    __u32 entries = *rx->producer - *rx->consumer;
    if (entries == 0) return 0;
    if (entries > nb) entries = nb;
    *idx = *rx->consumer;
    return entries;
}

static inline const struct xdp_desc *xsk_ring_cons__rx_desc(struct xdp_rx_queue *rx, __u32 idx)
{
    return &rx->ring[idx & rx->mask];
}

static inline void xsk_ring_cons__release(struct xdp_rx_queue *rx, __u32 nb)
{
    *rx->consumer += nb;
}

static inline void *xsk_umem__get_data(void *umem_area, __u64 addr)
{
    return &((char *)umem_area)[addr];
}

static int allocate_umem_frames(struct xdp_umem *umem, size_t bytes)
{
    if (!umem || bytes == 0) return -1;

    umem->frames = NULL;
    umem->frames_len = 0;
    umem->frames_is_mmap = 0;

#if SENTINEL_LINUX_RUNTIME
    if (parse_env_bool_default("SENTINEL_UMEM_USE_HUGEPAGE", 0)) {
        void *hp = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB,
                        -1, 0);
        if (hp != MAP_FAILED) {
            umem->frames = (char *)hp;
            umem->frames_len = bytes;
            umem->frames_is_mmap = 1;
            return 0;
        }
        LOG_WARN("Hugepage UMEM allocation failed (%s). Falling back to page-aligned UMEM.", strerror(errno));
    }
#endif

    void *bufs = NULL;
    if (posix_memalign(&bufs, getpagesize(), bytes) != 0)
        return -1;

    umem->frames = (char *)bufs;
    umem->frames_len = bytes;
    umem->frames_is_mmap = 0;
    return 0;
}

static void free_umem_frames(struct xdp_umem *umem)
{
    if (!umem || !umem->frames) return;

#if SENTINEL_LINUX_RUNTIME
    if (umem->frames_is_mmap) {
        if (umem->frames_len > 0)
            munmap(umem->frames, umem->frames_len);
    } else
#endif
    {
        free(umem->frames);
    }

    umem->frames = NULL;
    umem->frames_len = 0;
    umem->frames_is_mmap = 0;
}

/* ============================================================================
 * PACKET PARSING (Ethernet L2 or raw L3 TUN/Tailscale -> feature metadata)
 * ============================================================================ */

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

/* Hash IPv6 128-bit address to 32-bit for use in existing flow key (no full IPv6 key yet). */
static inline uint32_t hash_ipv6_to_32(const uint8_t *addr16)
{
    return fnv1a_hash(addr16, 16);
}

/* Encode IPv6 hash into 0.x.y.z pseudo IPv4 space so UI never renders fake public IPv4s. */
static inline uint32_t encode_ipv6_hash_pseudo_ipv4(uint32_t h)
{
    return htonl(h & 0x00FFFFFFu);
}

/* TUN/Tailscale/wg deliver IPv4/IPv6 without an Ethernet header; L2 capture uses 802.3 framing. */
static int g_capture_is_l3 = 0;

#if SENTINEL_LINUX_RUNTIME
static int sentinel_iface_is_l3_tunnel(const char *ifname)
{
    const char *o = getenv("SENTINEL_L3_CAPTURE");
    if (o && o[0]) {
        if (strcmp(o, "1") == 0 || strcasecmp(o, "true") == 0 || strcasecmp(o, "yes") == 0)
            return 1;
        if (strcmp(o, "0") == 0 || strcasecmp(o, "false") == 0 || strcasecmp(o, "no") == 0)
            return 0;
    }
    if (!ifname || !ifname[0])
        return 0;
    if (strncasecmp(ifname, "tailscale", 9) == 0)
        return 1;
    if (strncasecmp(ifname, "tun", 3) == 0)
        return 1;
    if (strncasecmp(ifname, "wg", 2) == 0)
        return 1;
    return 0;
}

static int check_sentinel_trial_expiry(void)
{
    const char *exp = getenv("SENTINEL_TRIAL_EXPIRES_UNIX");
    if (!exp || !exp[0])
        return 0;
    char *end = NULL;
    unsigned long long t = strtoull(exp, &end, 10);
    if (end == exp || *end != '\0') {
        LOG_WARN("Invalid SENTINEL_TRIAL_EXPIRES_UNIX, ignoring license check");
        return 0;
    }
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    if ((uint64_t)ts.tv_sec > (uint64_t)t) {
        fprintf(stderr, "[FATAL] Sentinel trial period expired (SENTINEL_TRIAL_EXPIRES_UNIX=%s)\n", exp);
        return -1;
    }
    LOG_INFO("Trial / entitlement window active until UNIX time %llu", (unsigned long long)t);
    return 0;
}
#else
static int sentinel_iface_is_l3_tunnel(const char *ifname)
{
    (void)ifname;
    return 0;
}
static int check_sentinel_trial_expiry(void)
{
    return 0;
}
#endif

static int parse_raw_packet(const char *frame_data, uint32_t len, fe_packet_t *pkt, uint64_t pkt_id, uint64_t now_ns)
{
    uint16_t ether_type;
    const char *ip_start;
    uint32_t ip_len;

    memset(pkt, 0, sizeof(*pkt));
    pkt->packet_id = pkt_id;
    pkt->direction = 0;
    pkt->timestamp_ns = now_ns;

    if (g_capture_is_l3) {
        if (len < 1u)
            return -1;
        {
            uint8_t ip_ver = ((const uint8_t *)frame_data)[0] >> 4;
            if (ip_ver == 4) {
                if (len < (uint32_t)sizeof(struct iphdr))
                    return -1;
                ether_type = ETHERTYPE_IP;
                ip_start = frame_data;
                ip_len = len;
            } else if (ip_ver == 6) {
                if (len < 40u)
                    return -1;
                ether_type = ETHERTYPE_IPV6;
                ip_start = frame_data;
                ip_len = len;
            } else {
                return -1;
            }
        }
    } else {
        if (len < sizeof(struct ether_header))
            return -1;
        {
            const struct ether_header *eth = (const struct ether_header *)frame_data;
            ether_type = ntohs(eth->ether_type);
            ip_start = frame_data + sizeof(struct ether_header);
            ip_len = len - (uint32_t)sizeof(struct ether_header);
            if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) {
                /* WSL/raw fallback: some kernels can deliver L3 payloads on AF_PACKET paths.
                 * If the frame starts with a valid IP version nibble, treat it as L3 directly. */
                uint8_t ip_ver = ((const uint8_t *)frame_data)[0] >> 4;
                if (ip_ver == 4) {
                    if (len < (uint32_t)sizeof(struct iphdr)) return -1;
                    ether_type = ETHERTYPE_IP;
                    ip_start = frame_data;
                    ip_len = len;
                } else if (ip_ver == 6) {
                    if (len < 40u) return -1;
                    ether_type = ETHERTYPE_IPV6;
                    ip_start = frame_data;
                    ip_len = len;
                }
            }
        }
    }

    if (ether_type == ETHERTYPE_IP) {
        /* IPv4 */
        if (ip_len < sizeof(struct iphdr)) return -1;
        const struct iphdr *iph = (const struct iphdr *)ip_start;
        uint32_t ip_hdr_size = iph->ihl * 4;
        if (ip_hdr_size < sizeof(struct iphdr)) return -1;
        if (ip_len < ip_hdr_size) return -1;

        pkt->src_ip = iph->saddr;
        pkt->dst_ip = iph->daddr;
        pkt->ip_family = 4;
        if (!inet_ntop(AF_INET, &iph->saddr, pkt->src_ip_text, sizeof(pkt->src_ip_text)))
            pkt->src_ip_text[0] = '\0';
        if (!inet_ntop(AF_INET, &iph->daddr, pkt->dst_ip_text, sizeof(pkt->dst_ip_text)))
            pkt->dst_ip_text[0] = '\0';
        pkt->protocol = iph->protocol;
        pkt->ttl = iph->ttl;
        {
            uint16_t frag = ntohs(iph->frag_off);
            if ((frag & 0x1FFFu) != 0) {
                /* Non-first fragment: transport header not guaranteed in this fragment. */
                goto parsed_l3_only;
            }
        }

        const char *transport_start = ip_start + ip_hdr_size;
        uint32_t transport_len = ip_len - ip_hdr_size;

        if (iph->protocol == IPPROTO_TCP && transport_len >= sizeof(struct tcphdr)) {
            const struct tcphdr *tcph = (const struct tcphdr *)transport_start;
            pkt->src_port = tcph->source;
            pkt->dst_port = tcph->dest;
            pkt->tcp_flags = transport_start[13];
            uint32_t tcp_hdr_size = tcph->doff * 4;
            if (tcp_hdr_size < sizeof(struct tcphdr) || tcp_hdr_size > transport_len)
                return -1;
            if (transport_len > tcp_hdr_size) {
                pkt->payload = (const uint8_t *)(transport_start + tcp_hdr_size);
                pkt->payload_len = transport_len - tcp_hdr_size;
            }
        } else if (iph->protocol == IPPROTO_UDP && transport_len >= sizeof(struct udphdr)) {
            const struct udphdr *udph = (const struct udphdr *)transport_start;
            pkt->src_port = udph->source;
            pkt->dst_port = udph->dest;
            if (transport_len > sizeof(struct udphdr)) {
                pkt->payload = (const uint8_t *)(transport_start + sizeof(struct udphdr));
                pkt->payload_len = transport_len - sizeof(struct udphdr);
            }
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        /* Skip IPv6 extension headers before L4 parsing. */
        if (ip_len < 40) return -1;
        const uint8_t *ip6 = (const uint8_t *)ip_start;
        pkt->src_ip = encode_ipv6_hash_pseudo_ipv4(hash_ipv6_to_32(ip6 + 8));
        pkt->dst_ip = encode_ipv6_hash_pseudo_ipv4(hash_ipv6_to_32(ip6 + 24));
        pkt->ip_family = 6;
        if (!inet_ntop(AF_INET6, ip6 + 8, pkt->src_ip_text, sizeof(pkt->src_ip_text)))
            pkt->src_ip_text[0] = '\0';
        if (!inet_ntop(AF_INET6, ip6 + 24, pkt->dst_ip_text, sizeof(pkt->dst_ip_text)))
            pkt->dst_ip_text[0] = '\0';
        pkt->ttl    = ip6[7];

        uint8_t next_hdr = ip6[6];
        const char *ptr = ip_start + 40;
        uint32_t remaining = ip_len - 40;
        int nonfirst_fragment = 0;

        /* Iterate through extension headers (Hop-by-Hop, Routing, Fragment, etc.) */
        /* Bound max extension headers to prevent loops or CPU exhaustion. */
        for (int i = 0; i < 8; i++) {
            /* Stop if we hit a transport layer or 'No Next Header' */
            if (next_hdr == IPPROTO_TCP || next_hdr == IPPROTO_UDP || 
                next_hdr == 58 /* ICMPV6 */ || next_hdr == IPPROTO_NONE) {
                break;
            }
            
            /* Bounds check before reading extension header length */
            if (remaining < 8) break;

            uint8_t hdr_len;
            if (next_hdr == 44 /* Fragment Header */) {
                hdr_len = 8;
                /* If not first fragment, transport header is absent here; stop parsing safely. */
                if (remaining >= 8) {
                    const uint8_t *ptr8 = (const uint8_t *)ptr;
                    uint16_t frag_off_flags = (uint16_t)((ptr8[2] << 8) | ptr8[3]);
                    if ((frag_off_flags & 0xFFF8u) != 0) {
                        next_hdr = ptr8[0];
                        ptr += 8;
                        remaining -= 8;
                        nonfirst_fragment = 1;
                        break;
                    }
                }
            } else if (next_hdr == 51 /* Authentication Header (AH) */) {
                /* AH length is in 32-bit words minus 2. */
                const uint8_t *ptr8 = (const uint8_t *)ptr;
                hdr_len = (uint8_t)((ptr8[1] + 2) << 2);
            } else {
                /* Standard format: length field is in 8-byte units, excluding the first 8 bytes. */
                const uint8_t *ptr8 = (const uint8_t *)ptr;
                hdr_len = (uint8_t)((ptr8[1] + 1) << 3);
            }

            if (remaining < hdr_len || hdr_len == 0) break;
            
            next_hdr = ((const uint8_t *)ptr)[0];
            ptr += hdr_len;
            remaining -= hdr_len;
        }
        pkt->protocol = next_hdr;
        if (nonfirst_fragment)
            return 0;

        if (next_hdr == IPPROTO_TCP && remaining >= sizeof(struct tcphdr)) {
            const struct tcphdr *tcph = (const struct tcphdr *)ptr;
            pkt->src_port = tcph->source;
            pkt->dst_port = tcph->dest;
            pkt->tcp_flags = ptr[13];
            uint32_t tcp_hdr_size = tcph->doff * 4;
            if (tcp_hdr_size < sizeof(struct tcphdr) || tcp_hdr_size > remaining)
                return -1;
            if (remaining > tcp_hdr_size) {
                pkt->payload = (const uint8_t *)(ptr + tcp_hdr_size);
                pkt->payload_len = remaining - tcp_hdr_size;
            }
        } else if (next_hdr == IPPROTO_UDP && remaining >= sizeof(struct udphdr)) {
            const struct udphdr *udph = (const struct udphdr *)ptr;
            pkt->src_port = udph->source;
            pkt->dst_port = udph->dest;
            if (remaining > sizeof(struct udphdr)) {
                pkt->payload = (const uint8_t *)(ptr + sizeof(struct udphdr));
                pkt->payload_len = remaining - sizeof(struct udphdr);
            }
        }
        /* ICMPv6 (58) and other next_header: ports remain 0, protocol and IP-hash set */
    } else {
        return -1; /* unsupported L3 */
    }

compute_hash:
    {
        sentinel_flow_key_t key = {
            .src_ip = pkt->src_ip, .dst_ip = pkt->dst_ip,
            .src_port = pkt->src_port, .dst_port = pkt->dst_port,
            .protocol = pkt->protocol
        };
        pkt->hw_hash = fnv1a_hash(&key, sizeof(key));
        return 0;
    }

parsed_l3_only:
    goto compute_hash;
}

/* ============================================================================
 * MAIN ZERO-COPY LOOP
 * ============================================================================ */

#if SENTINEL_LINUX_RUNTIME

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) ((struct rtattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

static int nl_addattr_l(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
    size_t new_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    struct rtattr *rta;
    if (new_len > maxlen)
        return -1;
    rta = NLMSG_TAIL(n);
    rta->rta_type = (unsigned short)type;
    rta->rta_len = (unsigned short)len;
    if (alen > 0 && data)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = (unsigned int)new_len;
    return 0;
}

static struct rtattr *nl_addattr_nest(struct nlmsghdr *n, size_t maxlen, int type)
{
    struct rtattr *start = NLMSG_TAIL(n);
    if (nl_addattr_l(n, maxlen, type, NULL, 0) != 0)
        return NULL;
    return start;
}

static void nl_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    if (!nest) return;
    nest->rta_len = (unsigned short)((char *)NLMSG_TAIL(n) - (char *)nest);
}

static int rtnl_set_link_xdp_fd(int ifindex, int prog_fd, __u32 xdp_flags)
{
#if SENTINEL_LINUX_RUNTIME
    struct {
        struct nlmsghdr nh;
        struct ifinfomsg ifm;
        char buf[256];
    } req;
    struct sockaddr_nl nladdr;
    char ackbuf[4096];
    ssize_t nread;
    int rem;
    struct nlmsghdr *h;
    int fd = -1;
    struct rtattr *xdp;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_type = RTM_SETLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq = 1;
    req.ifm.ifi_family = AF_UNSPEC;
    req.ifm.ifi_index = ifindex;

    xdp = nl_addattr_nest(&req.nh, sizeof(req), IFLA_XDP);
    if (!xdp) return -1;
    if (nl_addattr_l(&req.nh, sizeof(req), IFLA_XDP_FD, &prog_fd, sizeof(prog_fd)) != 0)
        return -1;
    if (nl_addattr_l(&req.nh, sizeof(req), IFLA_XDP_FLAGS, &xdp_flags, sizeof(xdp_flags)) != 0)
        return -1;
    nl_addattr_nest_end(&req.nh, xdp);

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        close(fd);
        return -1;
    }

    nread = recv(fd, ackbuf, sizeof(ackbuf), 0);
    close(fd);
    if (nread < 0)
        return -1;

    rem = (int)nread;
    for (h = (struct nlmsghdr *)ackbuf; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
            if (err->error == 0)
                return 0;
            errno = (err->error < 0) ? -err->error : err->error;
            return -1;
        }
    }
#else
    (void)ifindex;
    (void)prog_fd;
    (void)xdp_flags;
#endif
    return -1;
}

static int maybe_attach_xdp_driver_mode(const char *ifname)
{
#if SENTINEL_LINUX_RUNTIME
    const char *pin_path = getenv("SENTINEL_XDP_PROG_PIN_PATH");
    int allow_skb_fallback = parse_env_bool_default("SENTINEL_XDP_ALLOW_SKB_FALLBACK", 1);
    int ifindex;
    int prog_fd;
    __u32 flags;
    union bpf_attr get_attr;

    if (!pin_path || !pin_path[0])
        return 0;

    ifindex = (int)if_nametoindex(ifname);
    if (ifindex <= 0) {
        LOG_WARN("XDP driver attach skipped: invalid interface %s", ifname);
        return -1;
    }

    memset(&get_attr, 0, sizeof(get_attr));
    get_attr.pathname = (uintptr_t)pin_path;
    prog_fd = bpf(BPF_OBJ_GET, &get_attr, sizeof(get_attr));
    if (prog_fd < 0) {
        LOG_WARN("XDP driver attach skipped: unable to open pinned program %s (%s)", pin_path, strerror(errno));
        return -1;
    }

    flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (rtnl_set_link_xdp_fd(ifindex, prog_fd, flags) == 0) {
        LOG_INFO("XDP attached in driver mode (flags=0x%x) on %s", flags, ifname);
        close(prog_fd);
        return 0;
    }

    LOG_WARN("XDP driver-mode attach failed on %s (%s)", ifname, strerror(errno));
    if (allow_skb_fallback) {
        flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
        if (rtnl_set_link_xdp_fd(ifindex, prog_fd, flags) == 0) {
            LOG_WARN("XDP attached in skb mode fallback (flags=0x%x) on %s", flags, ifname);
            close(prog_fd);
            return 0;
        }
        LOG_WARN("XDP skb fallback attach also failed on %s (%s)", ifname, strerror(errno));
    }

    close(prog_fd);
#else
    (void)ifname;
#endif
    return -1;
}

#else

static int maybe_attach_xdp_driver_mode(const char *ifname)
{
    (void)ifname;
    return 0;
}

#endif

/* 
 * AF_XDP socket and UMEM initialization.
 * This physically binds the userspace daemon to the NIC driver queue.
 */
static struct xsk_socket_info* configure_xsk(const char *ifname, int queue_id, int *xdp_bind_mode) {
    LOG_INFO("Binding AF_XDP zero-copy socket on %s queue %d", ifname, queue_id);
    
    struct xsk_socket_info *xsk = calloc(1, sizeof(struct xsk_socket_info));
    if (!xsk) return NULL;

    xsk->umem = calloc(1, sizeof(struct xdp_umem));
    if (!xsk->umem) { free(xsk); return NULL; }

    /* 1. Allocate hugepage-backed (optional) or page-aligned memory for UMEM. */
    if (allocate_umem_frames(xsk->umem, NUM_FRAMES * FRAME_SIZE) != 0) {
        LOG_ERROR("Failed to allocate AF_XDP UMEM memory");
        free(xsk->umem);
        free(xsk);
        return NULL;
    }
    void *bufs = xsk->umem->frames;

    /* 2. Create the AF_XDP Socket (Inode descriptor) */
    xsk->xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->xsk_fd < 0) {
        LOG_WARN("AF_XDP socket creation failed (Requires root/capabilities or newer kernel)");
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

    /* 3. Register UMEM to the Socket via setsockopt */
    struct xdp_umem_reg mr;
    memset(&mr, 0, sizeof(mr));
    mr.addr = (__u64)(uintptr_t)bufs;
    mr.len = NUM_FRAMES * FRAME_SIZE;
    mr.chunk_size = FRAME_SIZE;
    mr.headroom = FRAME_HEADROOM;

    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        LOG_CRITICAL("AF_XDP setsockopt XDP_UMEM_REG failed.");
        close(xsk->xsk_fd);
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

    /* 4. Configure the Fill and RX Rings */
    int fq_size = 2048;
    int rx_size = 2048;
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size, sizeof(int)) < 0) {
        LOG_CRITICAL("AF_XDP setsockopt XDP_UMEM_FILL_RING failed.");
        close(xsk->xsk_fd);
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_RX_RING, &rx_size, sizeof(int)) < 0) {
        LOG_CRITICAL("AF_XDP setsockopt XDP_RX_RING failed.");
        close(xsk->xsk_fd);
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

    /* 5. Bind the socket to the explicit NIC Interface and RX Queue */
    struct sockaddr_xdp sxdp;
    memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family = PF_XDP;
    sxdp.sxdp_ifindex = if_nametoindex(ifname);
    if (sxdp.sxdp_ifindex == 0) {
        LOG_CRITICAL("Invalid interface name '%s' (if_nametoindex failed)", ifname);
        close(xsk->xsk_fd);
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

    /* Best effort: request pinned XDP program attach with driver-mode priority. */
    (void)maybe_attach_xdp_driver_mode(ifname);

    sxdp.sxdp_queue_id = queue_id;
    sxdp.sxdp_flags = 0;

    int bind_ok = 0;
    int bind_mode = 0;

#ifdef XDP_ZEROCOPY
    sxdp.sxdp_flags = XDP_ZEROCOPY;
    if (bind(xsk->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0) {
        bind_ok = 1;
        bind_mode = 1;
    }
#endif
#ifdef XDP_COPY
    if (!bind_ok) {
        sxdp.sxdp_flags = XDP_COPY;
        if (bind(xsk->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0) {
            bind_ok = 1;
            bind_mode = 2;
        }
    }
#endif
    if (!bind_ok) {
        sxdp.sxdp_flags = 0;
        if (bind(xsk->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0) {
            bind_ok = 1;
            bind_mode = 0;
        }
    }

    if (!bind_ok) {
        /* Downgraded to INFO: expected on loopback or virtual interfaces like WSL2 */
        LOG_INFO("AF_XDP physical NIC bind skipped (using system fallback for %s)", ifname);
        close(xsk->xsk_fd);
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

    if (xdp_bind_mode) *xdp_bind_mode = bind_mode;
    LOG_INFO("AF_XDP bind mode selected: %s",
             bind_mode == 1 ? "XDP_ZEROCOPY" : (bind_mode == 2 ? "XDP_COPY" : "AUTO"));

    /* 6. Mmap the RX Ring to Kernel Memory */
    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    if (getsockopt(xsk->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) == 0) {
        xsk->rx.map = mmap(NULL, off.rx.desc + rx_size * sizeof(struct xdp_desc),
                           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                           xsk->xsk_fd, XDP_PGOFF_RX_RING);
        if (xsk->rx.map != MAP_FAILED) {
            xsk->rx.map_size = off.rx.desc + rx_size * sizeof(struct xdp_desc);
            xsk->rx.producer = (__u32 *)((char *)xsk->rx.map + off.rx.producer);
            xsk->rx.consumer = (__u32 *)((char *)xsk->rx.map + off.rx.consumer);
            xsk->rx.ring = (struct xdp_desc *)((char *)xsk->rx.map + off.rx.desc);
        } else {
            LOG_CRITICAL("AF_XDP mmap for RX ring failed.");
            close(xsk->xsk_fd);
            free_umem_frames(xsk->umem);
            free(xsk->umem);
            free(xsk);
            return NULL;
        }
    } else {
        LOG_CRITICAL("AF_XDP getsockopt MMAP_OFFSETS failed.");
        close(xsk->xsk_fd);
        free_umem_frames(xsk->umem);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

    /* We manually wire up the structs so zero-copy math runs flawlessly */
    xsk->rx.mask = rx_size - 1;
    xsk->rx.size = rx_size;

    /* Map FILL ring and seed up to ring capacity with frame addresses. */
    {
        size_t fq_region = (size_t)off.fr.desc + (size_t)fq_size * sizeof(__u64);
        void *fq_map = mmap(NULL, fq_region, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                            xsk->xsk_fd, XDP_UMEM_PGOFF_FILL_RING);
        if (fq_map != MAP_FAILED) {
            xsk->umem->fq.map = fq_map;
            xsk->umem->fq_region_size = fq_region;
            xsk->umem->fq.ring = (__u64 *)((char *)fq_map + off.fr.desc);
            xsk->umem->fq.producer = (__u32 *)((char *)fq_map + off.fr.producer);
            xsk->umem->fq.consumer = (__u32 *)((char *)fq_map + off.fr.consumer);
            xsk->umem->fq.mask = fq_size - 1;
            xsk->umem->fq.size = (__u32)fq_size;
            xsk->umem->fq.cached_prod = 0;
            __u32 seed = (NUM_FRAMES < (__u32)fq_size) ? NUM_FRAMES : (__u32)fq_size;
            for (__u32 i = 0; i < seed; i++) {
                xsk->umem->fq.ring[xsk->umem->fq.cached_prod & xsk->umem->fq.mask] = (__u64)(i * FRAME_SIZE);
                xsk->umem->fq.cached_prod++;
            }
            *xsk->umem->fq.producer = xsk->umem->fq.cached_prod;
        } else {
            LOG_CRITICAL("AF_XDP mmap for FILL ring failed.");
            munmap(xsk->rx.map, xsk->rx.map_size);
            close(xsk->xsk_fd);
            free_umem_frames(xsk->umem);
            free(xsk->umem);
            free(xsk);
            return NULL;
        }
    }

    /*
     * 7. Wire the XSK FD into the BPF map for hardware redirection.
     * Map FD is obtained from the kernel via find_map_fd_by_name (no hardcoded FDs).
     */
    int map_fd = find_map_fd_by_name("xsks_map");
    if (map_fd > 0) {
        if (bpf_map_update_elem(map_fd, &queue_id, &xsk->xsk_fd, 0) == 0) {
            LOG_INFO("XSK FD %d mapped to BPF queue %d.", xsk->xsk_fd, queue_id);
            close(map_fd);
        } else {
            LOG_WARN("Failed to link XSK FD to BPF Redirect Map (Is the program loaded?)");
            close(map_fd);
        }
    } else {
        LOG_WARN("xsks_map not found. Load and pin the XDP program for hardware redirect.");
    }

    return xsk;
}

/*
 * Raw-socket fallback for environments without AF_XDP support (e.g. WSL2).
 * Uses AF_PACKET + SOCK_RAW to capture all Ethernet frames via the kernel
 * network stack.  Much slower than AF_XDP zero-copy, but works on any NIC.
 */
static struct xsk_socket_info* configure_raw_socket(const char *ifname) {
    LOG_INFO("AF_XDP unavailable on %s, falling back to raw socket capture (kernel path)", ifname);

    int raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_fd < 0) {
        LOG_ERROR("Raw socket creation failed (requires root/CAP_NET_RAW): %s", strerror(errno));
        return NULL;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        LOG_ERROR("Invalid interface '%s' for raw socket: %s", ifname, strerror(errno));
        close(raw_fd);
        return NULL;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;

    if (bind(raw_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR("Raw socket bind to %s failed: %s", ifname, strerror(errno));
        close(raw_fd);
        return NULL;
    }

    /* Allocate the same struct so main() can use xsk->xsk_fd uniformly. */
    struct xsk_socket_info *xsk = calloc(1, sizeof(struct xsk_socket_info));
    if (!xsk) { close(raw_fd); return NULL; }
    xsk->xsk_fd = raw_fd;
    xsk->umem   = NULL;  /* NULL umem signals "raw socket mode" */
    memset(&xsk->rx, 0, sizeof(xsk->rx));

    LOG_INFO("Raw socket capture active on %s (fd %d)", ifname, raw_fd);
    return xsk;
}

/* Populate XDP whitelist_map so it is not a ghost map; call after XDP is loaded. */
static void pipeline_sync_whitelist_to_bpf(int whitelist_map_fd, de_context_t *de,
                                            const uint32_t *ips, uint32_t n)
{
    if (whitelist_map_fd < 0 || !de) return;
    const __u8 one = 1;
    for (uint32_t i = 0; i < n; i++) {
        de_add_allowlist(de, ips[i]);
        bpf_map_update_elem(whitelist_map_fd, &ips[i], &one, 0);
    }
}

/* Insert an IP into the kernel BPF blacklist map. IP must be in network byte order. */
static void pipeline_blacklist_ip(int map_fd, uint32_t src_ip_net_order, uint64_t timestamp_ns)
{
    if (map_fd < 0) return;
    /* IP is already in network byte order (from iph->saddr, inet_pton, or assessment.src_ip) */
    bpf_map_update_elem(map_fd, &src_ip_net_order, &timestamp_ns, 0);
}

/* Remove an IP from the kernel BPF blacklist map. IP must be in network byte order. */
static void pipeline_unblacklist_ip(int map_fd, uint32_t src_ip_net_order)
{
    if (map_fd < 0) return;
    /* IP is already in network byte order. */
    (void)bpf_map_delete_elem(map_fd, &src_ip_net_order);
}

/* Remove all entries from the kernel BPF blacklist map. */
static void pipeline_clear_blacklist_map(int map_fd)
{
    if (map_fd < 0) return;
    uint32_t next_key;
    while (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        (void)bpf_map_delete_elem(map_fd, &next_key);
    }
}

/* ============================================================================
 * WEBSOCKET COMMAND HANDLER (browser Quick Actions -> decision engine)
 * ============================================================================ */

typedef struct { de_context_t *de; ws_context_t *ws; sdn_context_t *sdn; } ws_cmd_ctx_t;
static ws_cmd_ctx_t ws_cmd_ctx_storage;

#define SENTINEL_SHARED_STATE_MAGIC 0x53544c53u /* STLS */
#define SENTINEL_SHARED_STATE_VERSION 1u

typedef struct sentinel_shared_state_s {
    uint32_t magic;
    uint32_t version;
    char capture_interface[IFNAMSIZ];
    _Atomic int dataplane_mode;
    _Atomic uint64_t last_update_ns;
    _Atomic uint64_t rx_packets_total;
    _Atomic uint64_t packets_per_sec;
    _Atomic uint64_t bytes_per_sec;
    _Atomic uint32_t active_flows;
    _Atomic uint32_t active_sources;
    _Atomic uint32_t total_blocked;
    _Atomic uint32_t total_rate_limited;
    _Atomic uint32_t total_monitored;
    _Atomic uint32_t ml_classifications_per_sec;
    _Atomic uint32_t skipped_classifications_per_sec;
    _Atomic int auto_mitigation_enabled;
    _Atomic int sdn_connected;  /* -1=never probed, 0=last push failed, 1=last push ok */
    _Atomic uint32_t pending_clear_rate_limit_ip;
    _Atomic int pending_clear_rate_limit;
    _Atomic int has_pending_unblock_ip;
    _Atomic uint32_t pending_unblock_ip;
    _Atomic int pending_block_all;
    _Atomic int pending_clear_all;
} sentinel_shared_state_t;

static sentinel_shared_state_t g_shared_state_local;
static sentinel_shared_state_t *g_shared_state = &g_shared_state_local;

#if SENTINEL_LINUX_RUNTIME
static int g_shared_state_fd = -1;
static int g_shared_state_uses_mmap = 0;
#endif

static void shared_state_defaults(sentinel_shared_state_t *st)
{
    if (!st) return;
    memset(st, 0, sizeof(*st));
    st->magic = SENTINEL_SHARED_STATE_MAGIC;
    st->version = SENTINEL_SHARED_STATE_VERSION;
    snprintf(st->capture_interface, sizeof(st->capture_interface), "%s", "auto");
    atomic_init(&st->dataplane_mode, (int)PIPELINE_DATAPLANE_AF_XDP_AUTO);
    atomic_init(&st->last_update_ns, 0ULL);
    atomic_init(&st->rx_packets_total, 0ULL);
    atomic_init(&st->packets_per_sec, 0ULL);
    atomic_init(&st->bytes_per_sec, 0ULL);
    atomic_init(&st->active_flows, 0U);
    atomic_init(&st->active_sources, 0U);
    atomic_init(&st->total_blocked, 0U);
    atomic_init(&st->total_rate_limited, 0U);
    atomic_init(&st->total_monitored, 0U);
    atomic_init(&st->ml_classifications_per_sec, 0U);
    atomic_init(&st->skipped_classifications_per_sec, 0U);
    atomic_init(&st->auto_mitigation_enabled, 1);
    atomic_init(&st->sdn_connected, -1);
    atomic_init(&st->pending_clear_rate_limit_ip, 0u);
    atomic_init(&st->pending_clear_rate_limit, 0);
    atomic_init(&st->has_pending_unblock_ip, 0);
    atomic_init(&st->pending_unblock_ip, 0u);
    atomic_init(&st->pending_block_all, 0);
    atomic_init(&st->pending_clear_all, 0);
}

static void shared_state_publish_metrics(sentinel_shared_state_t *st,
                                         const char *ifname,
                                         pipeline_dataplane_mode_t mode,
                                         uint64_t rx_total,
                                         uint64_t pps,
                                         uint64_t bytes_per_sec,
                                         uint32_t active_flows,
                                         uint32_t active_sources,
                                         uint32_t total_blocked,
                                         uint32_t total_rate_limited,
                                         uint32_t total_monitored,
                                         uint32_t ml_cls_per_sec,
                                         uint32_t skipped_cls_per_sec)
{
    struct timespec ts;
    uint64_t now_ns = 0;
    if (!st) return;

    if (ifname && ifname[0])
        snprintf(st->capture_interface, sizeof(st->capture_interface), "%s", ifname);

    atomic_store_explicit(&st->dataplane_mode, (int)mode, memory_order_release);
    atomic_store_explicit(&st->rx_packets_total, rx_total, memory_order_release);
    atomic_store_explicit(&st->packets_per_sec, pps, memory_order_release);
    atomic_store_explicit(&st->bytes_per_sec, bytes_per_sec, memory_order_release);
    atomic_store_explicit(&st->active_flows, active_flows, memory_order_release);
    atomic_store_explicit(&st->active_sources, active_sources, memory_order_release);
    atomic_store_explicit(&st->total_blocked, total_blocked, memory_order_release);
    atomic_store_explicit(&st->total_rate_limited, total_rate_limited, memory_order_release);
    atomic_store_explicit(&st->total_monitored, total_monitored, memory_order_release);
    atomic_store_explicit(&st->ml_classifications_per_sec, ml_cls_per_sec, memory_order_release);
    atomic_store_explicit(&st->skipped_classifications_per_sec, skipped_cls_per_sec, memory_order_release);
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    atomic_store_explicit(&st->last_update_ns, now_ns, memory_order_release);
}

static void shared_state_init(void)
{
    shared_state_defaults(&g_shared_state_local);
    g_shared_state = &g_shared_state_local;

#if SENTINEL_LINUX_RUNTIME
    {
        const char *backend = getenv("SENTINEL_SHARED_STATE_BACKEND");
        const char *shm_name = getenv("SENTINEL_SHARED_STATE_NAME");
        void *mapped;

        if (backend && backend[0] && strcasecmp(backend, "shm") != 0) {
            LOG_INFO("Shared state backend set to local process memory");
            return;
        }
        if (!shm_name || !shm_name[0]) shm_name = "/sentinel_state_v1";

        g_shared_state_fd = shm_open(shm_name, O_RDWR | O_CREAT, 0660);
        if (g_shared_state_fd < 0) {
            LOG_WARN("Shared state shm_open failed (%s). Continuing with local state.", strerror(errno));
            return;
        }
        if (ftruncate(g_shared_state_fd, (off_t)sizeof(sentinel_shared_state_t)) != 0) {
            LOG_WARN("Shared state ftruncate failed (%s). Continuing with local state.", strerror(errno));
            close(g_shared_state_fd);
            g_shared_state_fd = -1;
            return;
        }

        mapped = mmap(NULL,
                      sizeof(sentinel_shared_state_t),
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED,
                      g_shared_state_fd,
                      0);
        if (mapped == MAP_FAILED) {
            LOG_WARN("Shared state mmap failed (%s). Continuing with local state.", strerror(errno));
            close(g_shared_state_fd);
            g_shared_state_fd = -1;
            return;
        }

        g_shared_state = (sentinel_shared_state_t *)mapped;
        g_shared_state_uses_mmap = 1;

        if (g_shared_state->magic != SENTINEL_SHARED_STATE_MAGIC ||
            g_shared_state->version != SENTINEL_SHARED_STATE_VERSION) {
            shared_state_defaults(g_shared_state);
        }
        LOG_INFO("Shared state backend enabled: POSIX SHM (%s)", shm_name);
    }
#endif
}

static void shared_state_destroy(void)
{
#if SENTINEL_LINUX_RUNTIME
    if (g_shared_state_uses_mmap && g_shared_state) {
        munmap(g_shared_state, sizeof(sentinel_shared_state_t));
        g_shared_state = &g_shared_state_local;
        g_shared_state_uses_mmap = 0;
    }
    if (g_shared_state_fd >= 0) {
        close(g_shared_state_fd);
        g_shared_state_fd = -1;
    }
#endif
}

static sentinel_feature_vector_t g_last_feature_vector;
static int g_has_last_feature_vector = 0;
static double g_last_chi_square_score = 0.0;

/* Convert feature state to 22 raw doubles: the explain API consumes the first 21, and
 * the UI uses the final value as destination-scoped fan-in evidence. */
static void fv_to_raw_vector(const sentinel_feature_vector_t *f,
                             double chi_square_score,
                             ws_raw_feature_vector_t *out)
{
    out->values[0]  = f->packets_per_second;
    out->values[1]  = f->bytes_per_second;
    out->values[2]  = f->syn_ratio;
    out->values[3]  = f->rst_ratio;
    out->values[4]  = f->dst_port_entropy;
    out->values[5]  = f->payload_byte_entropy;
    out->values[6]  = (double)f->unique_dst_ports;
    out->values[7]  = f->avg_packet_size;
    out->values[8]  = f->stddev_packet_size;
    out->values[9]  = (double)f->http_request_count;
    out->values[10] = f->fin_ratio;
    out->values[11] = f->src_port_entropy;
    out->values[12] = (double)f->unique_src_ports;
    out->values[13] = f->avg_ttl;
    out->values[14] = f->stddev_ttl;
    out->values[15] = f->avg_iat_us;
    out->values[16] = f->stddev_iat_us;
    out->values[17] = (double)f->src_total_flows;
    out->values[18] = f->src_packets_per_second;
    out->values[19] = (double)f->dns_query_count;
    out->values[20] = chi_square_score;
    out->values[21] = (double)f->unique_src_ips_to_dst;
}

/* Pending clear_rate_limit: main loop processes, cmd handler sets */
#define CLEARED_RATE_LIMIT_MAX 64
static uint32_t g_cleared_rate_limits[CLEARED_RATE_LIMIT_MAX];
static int g_cleared_rate_limit_count = 0;

/* Global blacklist map FD for WebSocket command handler (block_ip) */
static int g_blacklist_map_fd = -1;

/* Contributor threshold: only consider IPs that contribute >= this % of top-source traffic (0 = disabled). */
static double g_contributor_threshold_pct = 0.0;

/* Dashboard simulation: 0=off, 1=flash crowd, 2=ddos (telemetry overlay only; no kernel/dataplane changes). */
static atomic_int g_pipeline_sim_mode = ATOMIC_VAR_INIT(0);

/* Pending unblock_ip, block_all_flagged, clear_all_blocks: main loop processes, cmd handler sets */

static uint32_t pipeline_sim_src_ip_ipv4(void)
{
    const char *sim_ip = getenv("SENTINEL_SIM_SRC_IP");
    if (sim_ip && sim_ip[0]) {
        struct in_addr ia;
        if (inet_pton(AF_INET, sim_ip, &ia) == 1)
            return ia.s_addr;
    }
    return htonl(0xC0A80101); /* 192.168.1.1 */
}

static void pipeline_apply_sim_traffic_overlay(int mode, ws_metrics_t *wm, ws_traffic_rate_t *tr, ws_protocol_dist_t *pd)
{
    if (!wm || !tr || !pd) return;
    if (mode == 2) {
        wm->packets_per_sec = 750000;
        wm->bytes_per_sec = 500000000ULL;
        wm->active_flows = 85000;
        wm->active_sources = 3200;
        wm->ml_classifications_per_sec = 120000;
        tr->total_pps = 750000;
        tr->total_bps = 4000000000ULL;
        tr->tcp_pps = 700000;
        tr->udp_pps = 40000;
        tr->icmp_pps = 5000;
        tr->icmpv6_pps = 0;
        tr->other_pps = 5000;
        pd->tcp_percent = 93.0;
        pd->udp_percent = 5.3;
        pd->icmp_percent = 0.7;
        pd->icmpv6_percent = 0.0;
        pd->other_percent = 1.0;
        pd->tcp_bytes = tr->tcp_pps * 600ULL;
        pd->udp_bytes = tr->udp_pps * 200ULL;
        pd->icmp_bytes = tr->icmp_pps * 64ULL;
        pd->icmpv6_bytes = 0;
        pd->other_bytes = tr->other_pps * 128ULL;
        pd->other_top_proto = 0;
    } else if (mode == 1) {
        wm->packets_per_sec = 120000;
        wm->bytes_per_sec = 90000000ULL;
        wm->active_flows = 40000;
        wm->active_sources = 12000;
        wm->ml_classifications_per_sec = 45000;
        tr->total_pps = 120000;
        tr->total_bps = 750000000ULL;
        tr->tcp_pps = 70000;
        tr->udp_pps = 45000;
        tr->icmp_pps = 2000;
        tr->icmpv6_pps = 0;
        tr->other_pps = 3000;
        pd->tcp_percent = 58.0;
        pd->udp_percent = 37.5;
        pd->icmp_percent = 2.0;
        pd->icmpv6_percent = 0.0;
        pd->other_percent = 2.5;
        pd->tcp_bytes = tr->tcp_pps * 1500ULL;
        pd->udp_bytes = tr->udp_pps * 512ULL;
        pd->icmp_bytes = tr->icmp_pps * 64ULL;
        pd->icmpv6_bytes = 0;
        pd->other_bytes = tr->other_pps * 256ULL;
        pd->other_top_proto = 0;
    }
}

static void pipeline_apply_sim_feature_overlay(int mode, ws_feature_importance_t *wi)
{
    if (!wi) return;
    if (mode == 2) {
        wi->avg_threat_score = 0.88;
        wi->avg_score_volume = 0.95;
        wi->avg_score_entropy = 0.88;
        wi->avg_score_protocol = 0.82;
        wi->avg_score_behavioral = 0.75;
        wi->avg_score_ml = 0.90;
        wi->avg_score_l7 = 0.40;
        wi->avg_score_anomaly = 0.92;
        wi->avg_score_chi_square = 0.85;
        wi->avg_fanin_score = 0.78;
        wi->avg_score_fanin = 0.78;
        wi->avg_signature_score = 0.65;
        wi->avg_score_signature = 0.65;
        wi->detections_last_10s = 450;
    } else if (mode == 1) {
        wi->avg_threat_score = 0.42;
        wi->avg_score_volume = 0.55;
        wi->avg_score_entropy = 0.38;
        wi->avg_score_protocol = 0.45;
        wi->avg_score_behavioral = 0.40;
        wi->avg_score_ml = 0.35;
        wi->avg_score_l7 = 0.30;
        wi->avg_score_anomaly = 0.36;
        wi->avg_score_chi_square = 0.32;
        wi->avg_fanin_score = 0.28;
        wi->avg_score_fanin = 0.28;
        wi->avg_signature_score = 0.15;
        wi->avg_score_signature = 0.15;
        wi->detections_last_10s = 85;
    }
}

static void ws_emit_command_result(ws_cmd_ctx_t *ctx, const char *cmd, const char *request_id,
                                   uint32_t contract_version, int success, const char *fmt, ...)
{
    if (!ctx || !ctx->ws || !cmd) return;

    ws_command_result_t result;
    memset(&result, 0, sizeof(result));
    result.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
    result.contract_version = contract_version;
    result.success = success ? 1 : 0;
    if (request_id && request_id[0] != '\0') {
        snprintf(result.request_id, sizeof(result.request_id), "%s", request_id);
    }
    snprintf(result.command, sizeof(result.command), "%s", cmd);

    if (fmt && fmt[0] != '\0') {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(result.message, sizeof(result.message), fmt, ap);
        va_end(ap);
    } else {
        snprintf(result.message, sizeof(result.message), "%s", success ? "ok" : "failed");
    }

    ws_push_command_result(ctx->ws, &result);
}

static int ws_cmd_is_ip_arg_command(const char *cmd)
{
    return cmd && (
        strcmp(cmd, "block_ip") == 0 ||
        strcmp(cmd, "unblock_ip") == 0 ||
        strcmp(cmd, "whitelist_ip") == 0 ||
        strcmp(cmd, "remove_whitelist") == 0 ||
        strcmp(cmd, "clear_rate_limit") == 0
    );
}

static int ws_parse_double_arg(const char *arg, double *out)
{
    if (!arg || !out) return 0;
    errno = 0;
    char *endptr = NULL;
    double v = strtod(arg, &endptr);
    if (endptr == arg || (endptr && *endptr != '\0') || errno != 0) return 0;
    *out = v;
    return 1;
}

static int ws_sim_commands_enabled(void)
{
#if defined(SENTINEL_DISABLE_SIM_COMMANDS) && SENTINEL_DISABLE_SIM_COMMANDS
    return 0;
#else
    return parse_env_bool_default("SENTINEL_ALLOW_SIM_COMMANDS", 0);
#endif
}

static void ws_pipeline_cmd_handler(const char *cmd, const char *arg,
                                    const char *request_id, uint32_t contract_version,
                                    void *udata) {
    ws_cmd_ctx_t *c = (ws_cmd_ctx_t *)udata;
    if (!c || !c->de || !cmd) return;

    if (contract_version != WS_COMMAND_CONTRACT_VERSION) {
        LOG_WARN("[WS-CMD] Contract version mismatch for %s: got=%u expected=%u",
                 cmd, contract_version, (unsigned)WS_COMMAND_CONTRACT_VERSION);
        ws_emit_command_result(c, cmd, request_id, WS_COMMAND_CONTRACT_VERSION, 0,
                               "unsupported contract_version=%u (expected %u)",
                               contract_version, (unsigned)WS_COMMAND_CONTRACT_VERSION);
        return;
    }

    struct in_addr ia;
    int has_valid_ip_arg = (arg && inet_pton(AF_INET, arg, &ia) == 1);

    if (strcmp(cmd, "block_ip") == 0 && has_valid_ip_arg) {
        de_add_denylist(c->de, ia.s_addr);
        if (g_blacklist_map_fd >= 0) {
            uint64_t ts = (uint64_t)time(NULL) * 1000000000ULL;
            pipeline_blacklist_ip(g_blacklist_map_fd, ia.s_addr, ts);
        }
        LOG_INFO("[WS-CMD] block_ip %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "blocked %s", arg);
    }
    else if (strcmp(cmd, "block_ip_port") == 0 && arg) {
        uint32_t ip = 0;
        uint16_t port_host = 0;
        const char *colon = strchr(arg, ':');
        if (colon && colon > arg) {
            char ip_buf[64];
            size_t ip_len = (size_t)(colon - arg);
            char *endptr = NULL;
            unsigned long parsed_port = 0;
            if (ip_len >= sizeof(ip_buf)) ip_len = sizeof(ip_buf) - 1;
            memcpy(ip_buf, arg, ip_len);
            ip_buf[ip_len] = '\0';
            if (inet_pton(AF_INET, ip_buf, &ia) == 1) {
                ip = ia.s_addr;
                parsed_port = strtoul(colon + 1, &endptr, 10);
                if (endptr != colon + 1 && endptr && *endptr == '\0' && parsed_port > 0 && parsed_port <= 65535UL) {
                    port_host = (uint16_t)parsed_port;
                }
            }
        } else if (inet_pton(AF_INET, arg, &ia) == 1) {
            ip = ia.s_addr;
        }
        if (ip != 0) {
            de_add_denylist(c->de, ip);
            if (g_blacklist_map_fd >= 0) {
                uint64_t ts = (uint64_t)time(NULL) * 1000000000ULL;
                pipeline_blacklist_ip(g_blacklist_map_fd, ip, ts);
            }
            if (port_host != 0 && c->sdn) {
                sentinel_sdn_rule_t rule;
                memset(&rule, 0, sizeof(rule));
                rule.rule_id = (uint32_t)((ip ^ ((uint32_t)port_host << 16)) & 0x7FFFFFFFu);
                rule.priority = 2000;
                rule.match_src_ip = ip;
                rule.match_src_port = htons(port_host);
                rule.action = SDN_ACTION_DROP;
                rule.triggered_by = SENTINEL_ATTACK_SYN_FLOOD;
                rule.threat_score = 1.0;
                rule.created_ns = (uint64_t)time(NULL) * 1000000000ULL;
                if (sdn_push_rule(c->sdn, &rule) == 0)
                    LOG_INFO("[WS-CMD] block_ip_port %s:%u - SDN rule pushed", arg, (unsigned)port_host);
            }
            LOG_INFO("[WS-CMD] block_ip_port %s", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 1, "blocked %s", arg);
        } else {
            LOG_WARN("[WS-CMD] block_ip_port invalid arg: %s", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid ip or ip:port");
        }
    }
    else if (strcmp(cmd, "unblock_ip") == 0 && has_valid_ip_arg) {
        de_remove_denylist(c->de, ia.s_addr);
        atomic_store_explicit(&g_shared_state->pending_unblock_ip, ia.s_addr, memory_order_release);
        atomic_store_explicit(&g_shared_state->has_pending_unblock_ip, 1, memory_order_release);
        LOG_INFO("[WS-CMD] unblock_ip %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "unblocked %s", arg);
    }
    else if (strcmp(cmd, "whitelist_ip") == 0 && has_valid_ip_arg) {
        de_add_allowlist(c->de, ia.s_addr);
        LOG_INFO("[WS-CMD] whitelist_ip %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "whitelisted %s", arg);
    }
    else if (strcmp(cmd, "remove_whitelist") == 0 && has_valid_ip_arg) {
        de_remove_allowlist(c->de, ia.s_addr);
        LOG_INFO("[WS-CMD] remove_whitelist %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "removed %s from whitelist", arg);
    }
    else if (strcmp(cmd, "block_all_flagged") == 0) {
        atomic_store_explicit(&g_shared_state->pending_block_all, 1, memory_order_release);
        LOG_INFO("[WS-CMD] block_all_flagged - will take effect on next telemetry cycle");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "queued block for all flagged sources");
    }
    else if (strcmp(cmd, "clear_all_blocks") == 0) {
        atomic_store_explicit(&g_shared_state->pending_clear_all, 1, memory_order_release);
        LOG_INFO("[WS-CMD] clear_all_blocks");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "queued clear for all block/rate-limit entries");
    }
    else if (strcmp(cmd, "apply_rate_limit") == 0) {
        de_set_global_rate_limit(c->de, 0.40, 0.70);
        LOG_INFO("[WS-CMD] apply_rate_limit - thresholds set to 0.40/0.70");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "global rate limit thresholds set to 0.40/0.70");
    }
    else if (strcmp(cmd, "enable_monitoring") == 0) {
        LOG_INFO("[WS-CMD] enable_monitoring - enhanced monitoring enabled");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "enhanced monitoring enabled");
    }
    else if (strcmp(cmd, "enable_auto_mitigation") == 0) {
        atomic_store_explicit(&g_shared_state->auto_mitigation_enabled, 1, memory_order_release);
        LOG_INFO("[WS-CMD] enable_auto_mitigation");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "auto mitigation enabled");
    }
    else if (strcmp(cmd, "disable_auto_mitigation") == 0) {
        atomic_store_explicit(&g_shared_state->auto_mitigation_enabled, 0, memory_order_release);
        LOG_INFO("[WS-CMD] disable_auto_mitigation");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "auto mitigation disabled");
    }
    else if (strcmp(cmd, "clear_rate_limit") == 0 && has_valid_ip_arg) {
        atomic_store_explicit(&g_shared_state->pending_clear_rate_limit_ip, ia.s_addr, memory_order_release);
        atomic_store_explicit(&g_shared_state->pending_clear_rate_limit, 1, memory_order_release);
        LOG_INFO("[WS-CMD] clear_rate_limit %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "queued rate-limit clear for %s", arg);
    }
    else if (strcmp(cmd, "simulate_ddos") == 0 && c->ws) {
        if (ws_sim_commands_enabled()) {
            atomic_store_explicit(&g_pipeline_sim_mode, 2, memory_order_release);
            ws_activity_t wa;
            wa.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
            wa.src_ip = pipeline_sim_src_ip_ipv4();
            snprintf(wa.ip_family, sizeof(wa.ip_family), "%s", "ipv4");
            inet_ntop(AF_INET, &wa.src_ip, wa.src_ip_text, sizeof(wa.src_ip_text));
            wa.threat_score = 0.92;
            wa.enforced = 0;
            snprintf(wa.action, sizeof(wa.action), "DETECTED");
            snprintf(wa.attack_type, sizeof(wa.attack_type), "SYN_FLOOD");
            snprintf(wa.reason, sizeof(wa.reason), "[SIMULATED] score=0.920 conf=0.95 ml=0.88 rel=0.90");
            ws_push_activity(c->ws, &wa);
            LOG_INFO("[WS-CMD] simulate_ddos - injected synthetic activity + telemetry overlay (mode=2)");
            ws_emit_command_result(c, cmd, request_id, contract_version, 1, "simulated ddos activity injected");
        } else {
            LOG_WARN("[WS-CMD] simulate_ddos rejected: simulation disabled");
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "simulation commands are disabled (set SENTINEL_ALLOW_SIM_COMMANDS=1)");
        }
    }
    else if (strcmp(cmd, "simulate_flash_crowd") == 0 && c->ws) {
        if (ws_sim_commands_enabled()) {
            atomic_store_explicit(&g_pipeline_sim_mode, 1, memory_order_release);
            ws_activity_t wa;
            wa.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
            wa.src_ip = pipeline_sim_src_ip_ipv4();
            if (wa.src_ip == htonl(0xC0A80101))
                wa.src_ip = htonl(0xC0A80102); /* distinguish flash crowd default IP */
            snprintf(wa.ip_family, sizeof(wa.ip_family), "%s", "ipv4");
            inet_ntop(AF_INET, &wa.src_ip, wa.src_ip_text, sizeof(wa.src_ip_text));
            wa.threat_score = 0.45;
            wa.enforced = 0;
            snprintf(wa.action, sizeof(wa.action), "MONITOR");
            snprintf(wa.attack_type, sizeof(wa.attack_type), "NONE");
            snprintf(wa.reason, sizeof(wa.reason), "[SIMULATED] Flash crowd - score=0.450 conf=0.70 ml=0.35 rel=0.80");
            ws_push_activity(c->ws, &wa);
            LOG_INFO("[WS-CMD] simulate_flash_crowd - injected synthetic activity + telemetry overlay (mode=1)");
            ws_emit_command_result(c, cmd, request_id, contract_version, 1, "simulated flash crowd activity injected");
        } else {
            LOG_WARN("[WS-CMD] simulate_flash_crowd rejected: simulation disabled");
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "simulation commands are disabled (set SENTINEL_ALLOW_SIM_COMMANDS=1)");
        }
    }
    else if (strcmp(cmd, "stop_simulation") == 0) {
        atomic_store_explicit(&g_pipeline_sim_mode, 0, memory_order_release);
        LOG_INFO("[WS-CMD] stop_simulation - simulation cleared");
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "simulation stopped");
    }
    else if (strcmp(cmd, "set_syn_threshold") == 0 && arg) {
        double v = 0.0;
        if (!ws_parse_double_arg(arg, &v)) {
            LOG_WARN("[WS-CMD] set_syn_threshold invalid value: %s", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid numeric value: %s", arg);
            return;
        }
        de_set_syn_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_syn_threshold %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "syn threshold set to %.3f", v);
    }
    else if (strcmp(cmd, "set_conn_threshold") == 0 && arg) {
        double v = 0.0;
        if (!ws_parse_double_arg(arg, &v)) {
            LOG_WARN("[WS-CMD] set_conn_threshold invalid value: %s", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid numeric value: %s", arg);
            return;
        }
        de_set_conn_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_conn_threshold %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "connection threshold set to %.3f", v);
    }
    else if (strcmp(cmd, "set_pps_threshold") == 0 && arg) {
        double v = 0.0;
        if (!ws_parse_double_arg(arg, &v)) {
            LOG_WARN("[WS-CMD] set_pps_threshold invalid value: %s", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid numeric value: %s", arg);
            return;
        }
        de_set_pps_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_pps_threshold %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "packet-rate threshold set to %.3f", v);
    }
    else if (strcmp(cmd, "set_entropy_threshold") == 0 && arg) {
        double v = 0.0;
        if (!ws_parse_double_arg(arg, &v)) {
            LOG_WARN("[WS-CMD] set_entropy_threshold invalid value: %s", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid numeric value: %s", arg);
            return;
        }
        de_set_entropy_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_entropy_threshold %s", arg);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "entropy threshold set to %.3f", v);
    }
    else if (strcmp(cmd, "set_contributor_threshold") == 0 && arg) {
        double v = 0.0;
        if (!ws_parse_double_arg(arg, &v) || v < 0.0 || v > 100.0) {
            LOG_WARN("[WS-CMD] set_contributor_threshold invalid value: %s (expect 0-100)", arg);
            ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid value (expect 0-100)");
            return;
        }
        g_contributor_threshold_pct = v;
        LOG_INFO("[WS-CMD] set_contributor_threshold %.2f%%", v);
        ws_emit_command_result(c, cmd, request_id, contract_version, 1, "contributor threshold set to %.2f%%", v);
    }
    else if (ws_cmd_is_ip_arg_command(cmd)) {
        LOG_WARN("[WS-CMD] %s invalid IPv4 argument: %s", cmd, arg ? arg : "none");
        ws_emit_command_result(c, cmd, request_id, contract_version, 0, "invalid IPv4 argument");
    }
    else {
        LOG_WARN("[WS-CMD] Unknown command: %s (arg: %s)", cmd, arg ? arg : "none");
        ws_emit_command_result(c, cmd, request_id, contract_version, 0, "unknown command");
    }
}

int main(int argc, char **argv)
{
    /* 1. Initialization: Logging & Environment */
    const char *log_path = getenv("SENTINEL_LOG_FILE");
    if (log_path) {
        g_log_file = fopen(log_path, "a");
        if (!g_log_file) {
            fprintf(stderr, "[CRITICAL] Failed to open log file: %s\n", log_path);
        } else {
            LOG_INFO("--- Sentinel Core Persistent Log Initialized ---");
        }
    }

    if (check_sentinel_trial_expiry() != 0)
        return EXIT_FAILURE;

    const char *ifname = "auto";
    char resolved_ifname[IFNAMSIZ] = {0};
    int queue_id = 0;
    uint16_t ws_port = 0;
    char *controller_url = NULL;
    uint64_t dpid = 1;
    int verbose = 0;
    int opt;
    pipeline_integration_flags_t integration_flags;
    controller_extension_state_t controller_extension;
    memset(&integration_flags, 0, sizeof(integration_flags));
    memset(&controller_extension, 0, sizeof(controller_extension));

    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"queue",      required_argument, 0, 'q'},
        {"websocket",  required_argument, 0, 'w'},
        {"controller", required_argument, 0, 'c'},
        {"dpid",       required_argument, 0, 'd'},
        {"mode",       required_argument, 0, 'm'},
        {"whitelist",  required_argument, 0, 'W'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
#define MAX_WHITELIST_STATIC 64
    uint32_t whitelist_static[MAX_WHITELIST_STATIC];
    uint32_t n_whitelist_static = 0;

    while ((opt = getopt_long(argc, argv, "i:q:w:c:d:m:W:vh", long_options, NULL)) != -1) {
        char *end;
        switch (opt) {
            case 'i': ifname = optarg; break;
            case 'q': {
                long q = strtol(optarg, &end, 10);
                if (*end != '\0' || q < 0 || q > 65535) {
                    fprintf(stderr, "Invalid queue_id: %s (use 0-65535)\n", optarg);
                    return EXIT_FAILURE;
                }
                queue_id = (int)q;
                break;
            }
            case 'w': {
                unsigned long p = strtoul(optarg, &end, 10);
                if (*end != '\0' || p == 0 || p > 65535) {
                    fprintf(stderr, "Invalid websocket port: %s (use 1-65535)\n", optarg);
                    return EXIT_FAILURE;
                }
                ws_port = (uint16_t)p;
                break;
            }
            case 'c': controller_url = optarg; break;
            case 'd': dpid = (uint64_t)strtoull(optarg, NULL, 0); break;
            case 'm': (void)optarg; break; /* AF_XDP only; ignore legacy */
            case 'W': {
                if (n_whitelist_static >= MAX_WHITELIST_STATIC) break;
                struct in_addr ia;
                if (inet_pton(AF_INET, optarg, &ia) == 1) {
                    whitelist_static[n_whitelist_static++] = ia.s_addr;
                }
                break;
            }
            case 'v': verbose = 1; break;
            case 'h':
            default:
                printf("Usage: %s [-i interface] [-q queue_id] [-w websocket_port] [--controller URL] [--dpid ID] [--whitelist IP]... [-v]\n", argv[0]);
                return EXIT_SUCCESS;
        }
    }

    LOG_INFO("Starting Sentinel DDoS Core (AF_XDP mode)");
    shared_state_init();
    load_integration_flags(&integration_flags);
    load_controller_extension_state(&controller_extension);
    ifname = resolve_capture_interface(ifname, resolved_ifname, sizeof(resolved_ifname));
    LOG_INFO("Integration profile: %s", integration_flags.profile);
    LOG_INFO("Integration flags: intel=%d model=%d controller=%d signature=%d dataplane=%d",
             integration_flags.intel_feed_enabled,
             integration_flags.model_extension_enabled,
             integration_flags.controller_extension_enabled,
             integration_flags.signature_feed_enabled,
             integration_flags.dataplane_extension_enabled);
    if (controller_extension.enabled) {
        LOG_INFO("Controller extension command enabled with %llu ms minimum interval",
                 (unsigned long long)(controller_extension.min_interval_ns / 1000000ULL));
    }
    LOG_INFO("Binding to interface: %s, queue: %d", ifname, queue_id);
    LOG_INFO(
        "RSS scaling: this process binds AF_XDP queue %d. For multi-Gbps line-rate, configure NIC RSS/queues "
        "(e.g. ethtool -L), load XDP redirect for each queue, and run one sentinel_pipeline instance per queue "
        "with distinct -q and CPU affinity (SENTINEL_CPU_PIN).",
        queue_id
    );
    g_capture_is_l3 = sentinel_iface_is_l3_tunnel(ifname);
    if (g_capture_is_l3) {
        LOG_INFO("L3 capture mode (no Ethernet header): parser aligned for TUN/Tailscale-style frames on %s", ifname);
    }
    if (verbose)
        LOG_INFO("Verbose mode enabled");

    /* TIER-1: CPU Core Pinning (defaults to Core 1, overridable with SENTINEL_CPU_PIN) */
    cpu_set_t cpuset;
    int target_cpu = 1;
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    const char *cpu_pin_env = getenv("SENTINEL_CPU_PIN");
    if (cpu_pin_env && cpu_pin_env[0]) {
        char *endptr = NULL;
        unsigned long parsed = strtoul(cpu_pin_env, &endptr, 10);
        if (endptr != cpu_pin_env && endptr && *endptr == '\0' && parsed < (unsigned long)((cpu_count > 0) ? cpu_count : 1)) {
            target_cpu = (int)parsed;
        } else {
            LOG_WARN("Invalid SENTINEL_CPU_PIN=%s, using default core 1", cpu_pin_env);
        }
    }
    CPU_ZERO(&cpuset);
    CPU_SET(target_cpu, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == 0) {
        LOG_INFO("Successfully pinned process to CPU Core %d", target_cpu);
    } else {
        LOG_WARN("Failed to pin process to CPU Core %d (Requires CAP_SYS_NICE or root)", target_cpu);
    }

    struct sigaction sa = { .sa_handler = sig_handler };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Initialize physical models */
    fe_config_t fe_cfg = FE_CONFIG_DEFAULT;
    fe_context_t *fe = fe_init(&fe_cfg);
    if (!fe) {
        LOG_ERROR("fe_init failed");
        return EXIT_FAILURE;
    }

    de_thresholds_t de_cfg = DE_THRESHOLDS_DEFAULT;
    de_context_t *de = de_init(&de_cfg);
    if (!de) {
        LOG_ERROR("de_init failed");
        fe_destroy(fe);
        return EXIT_FAILURE;
    }

    /* Always load reflection signatures (production requirement) */
    const char *sig_file = getenv("SENTINEL_SIGNATURES_FILE");
    if (!sig_file || !sig_file[0])
        sig_file = getenv("SENTINEL_REFLECTION_PORTS_FILE");
    if (!sig_file || !sig_file[0])
        sig_file = "signatures/methods.json";
    uint32_t n_sigs = de_load_signatures(de, sig_file);
    LOG_INFO("Loaded %u reflection signatures from %s (always enabled)", n_sigs, sig_file);

    /* Initialize detached SDN controller (override URL/dpid if provided) */
    sdn_config_t sdn_cfg = SDN_CONFIG_DEFAULT;
    if (controller_url) snprintf(sdn_cfg.controller_url, sizeof(sdn_cfg.controller_url), "%s", controller_url);
    sdn_cfg.default_dpid = dpid;
    sdn_context_t *sdn = sdn_init(&sdn_cfg);
    if (!sdn) {
        LOG_ERROR("sdn_init failed");
        de_destroy(de);
        fe_destroy(fe);
        return EXIT_FAILURE;
    }

    /* Telemetry: feedback (lock-free) and optional WebSocket */
    fb_config_t fb_cfg = FB_CONFIG_DEFAULT;
    fb_context_t *fb = fb_init(&fb_cfg);
    if (!fb) {
        LOG_ERROR("fb_init failed");
        sdn_destroy(sdn);
        de_destroy(de);
        fe_destroy(fe);
        return EXIT_FAILURE;
    }

    ws_context_t *ws = NULL;
#if SENTINEL_LINUX_RUNTIME
    pthread_t health_listener_thread_id;
    int health_listener_started = 0;
#endif
    if (ws_port > 0) {
        ws_config_t ws_cfg = WS_CONFIG_DEFAULT;
        ws_cfg.port = ws_port;
        const char *ws_api_key = getenv("SENTINEL_WS_API_KEY");
        if (ws_api_key) snprintf(ws_cfg.api_key, sizeof(ws_cfg.api_key), "%s", ws_api_key);
        
        ws = ws_init(&ws_cfg);
        if (ws && ws_start(ws) == 0) {
            LOG_INFO("WebSocket telemetry on port %u", (unsigned)ws_port);
            /* Register command handler so browser Quick Actions reach the decision engine */
            ws_cmd_ctx_storage.de = de;
            ws_cmd_ctx_storage.ws = ws;
            ws_cmd_ctx_storage.sdn = sdn;
            ws_set_command_callback(ws, ws_pipeline_cmd_handler, &ws_cmd_ctx_storage);
#if SENTINEL_LINUX_RUNTIME
            {
                uint16_t health_port = (uint16_t)(ws_port + 1);
                if (pthread_create(&health_listener_thread_id, NULL, health_listener_thread, &health_port) == 0) {
                    health_listener_started = 1;
                    LOG_INFO("HTTP health listener on port %u", (unsigned)health_port);
                } else
                    LOG_WARN("Health listener thread not started on port %u", (unsigned)health_port);
            }
#endif
        }
        else if (ws) {
            ws_destroy(ws);
            ws = NULL;
        }
    }

    int xdp_bind_mode = 0;
    pipeline_dataplane_mode_t dataplane_mode = PIPELINE_DATAPLANE_AF_XDP_AUTO;
    struct xsk_socket_info *xsk = configure_xsk(ifname, queue_id, &xdp_bind_mode);
    int use_raw_fallback = 0;
    if (!xsk) {
        /* AF_XDP failed (expected on WSL2 / VMs); try kernel raw socket. */
        xsk = configure_raw_socket(ifname);
        if (!xsk) {
            LOG_ERROR("Both AF_XDP and raw socket initialization failed. Exiting.");
            if (ws) { ws_stop(ws); ws_destroy(ws); }
            fb_destroy(fb);
            sdn_destroy(sdn);
            de_destroy(de);
            fe_destroy(fe);
            return EXIT_FAILURE;
        }
        use_raw_fallback = 1;
        dataplane_mode = PIPELINE_DATAPLANE_RAW_FALLBACK;
    } else {
        dataplane_mode = (xdp_bind_mode == 1)
            ? PIPELINE_DATAPLANE_AF_XDP_ZEROCOPY
            : (xdp_bind_mode == 2 ? PIPELINE_DATAPLANE_AF_XDP_COPY : PIPELINE_DATAPLANE_AF_XDP_AUTO);
    }
    LOG_INFO("Dataplane capture mode: %s", pipeline_dataplane_mode_str(dataplane_mode));
    LOG_INFO("Simulation WS commands: %s (set SENTINEL_ALLOW_SIM_COMMANDS=1 to enable)",
             ws_sim_commands_enabled() ? "enabled" : "disabled");
    uint64_t rx_packets = 0;
    uint64_t last_rx_for_metrics = 0;
    uint64_t coarse_now_ns = 0;  /* heartbeat: every 128 packets for <10us jitter at 14.88Mpps */
    {
        struct timespec ts0;
        if (clock_gettime(CLOCK_MONOTONIC, &ts0) == 0)
            coarse_now_ns = (uint64_t)ts0.tv_sec * 1000000000ULL + ts0.tv_nsec;
    }
    uint32_t classifications_this_sec = 0;
    uint32_t skipped_classifications_this_sec = 0;
    const unsigned long max_classifications_per_sec =
        parse_env_ul_bound("SENTINEL_MAX_CLASSIFICATIONS_PER_SEC", 2000, 100, 1000000);

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOG_ERROR("curl_global_init failed");
        if (ws) { ws_stop(ws); ws_destroy(ws); }
        fb_destroy(fb);
        sdn_destroy(sdn);
        de_destroy(de);
        fe_destroy(fe);
        if (!use_raw_fallback) {
            if (xsk->umem && xsk->umem->fq.map != NULL && xsk->umem->fq_region_size > 0)
                munmap(xsk->umem->fq.map, xsk->umem->fq_region_size);
            if (xsk->rx.map != NULL && xsk->rx.map_size > 0)
                munmap(xsk->rx.map, xsk->rx.map_size);
            if (xsk->umem) {
                free_umem_frames(xsk->umem);
                free(xsk->umem);
            }
        }
        if (xsk->xsk_fd >= 0)
            close(xsk->xsk_fd);
        free(xsk);
        return EXIT_FAILURE;
    }

    /* SDN Health Check Timer - probe every 5 seconds to catch early connectivity */
    uint64_t last_sdn_health_check = 0;
    uint64_t sdn_health_check_interval = 5;  /* seconds */

    int whitelist_map_fd = find_map_fd_by_name("whitelist_map");
    if (whitelist_map_fd > 0 && n_whitelist_static > 0) {
        pipeline_sync_whitelist_to_bpf(whitelist_map_fd, de, whitelist_static, n_whitelist_static);
        LOG_INFO("Whitelist map populated with %u IP(s)", (unsigned)n_whitelist_static);
    }
    if (whitelist_map_fd > 0)
        close(whitelist_map_fd);

    int blacklist_map_fd = find_map_fd_by_name("blacklist_map");
    g_blacklist_map_fd = blacklist_map_fd;
    if (blacklist_map_fd > 0) {
        LOG_INFO("Linked to kernel eBPF Blacklist Map (Hardware Offload Active)");
    } else {
        LOG_WARN("blacklist_map not found. Kernel dropping disabled.");
    }

    feedback_shared_t feedback_shared = {
        .ready_count = 0,
        .ready_slot = 0,
        .work_ready = 0,
    };
    atomic_init(&feedback_shared.stop, 0);
    int feedback_write_idx = 0;  /* main thread double-buffer index; never locks */
    pthread_t feedback_thread;
    int feedback_thread_started = 0;
    void *feedback_thread_arg[4];
    feedback_thread_arg[0] = fb;
    feedback_thread_arg[1] = de;
    feedback_thread_arg[2] = fe;
    feedback_thread_arg[3] = &feedback_shared;
    if (!integration_flags.intel_feed_enabled) {
        LOG_INFO("Feedback loop disabled by profile/env; running without RL threshold adjustments.");
    } else if (pthread_create(&feedback_thread, NULL, feedback_worker, feedback_thread_arg) != 0) {
        LOG_WARN("Feedback thread create failed; running without background adjustments.");
    } else {
        feedback_thread_started = 1;
    }

    time_t last_gc = time(NULL);
    time_t last_gc_log = last_gc;
    uint32_t gc_evicted_accum = 0;
    time_t last_metrics = time(NULL);
    time_t last_top_sources = time(NULL);
    time_t last_feature_importance = time(NULL);
    time_t last_feedback = time(NULL);

#define TELEM_IP_MAX 128
#define ACTIVITY_RING_SIZE 4096   /* Scale up to 4096 for burst absorption */
    ws_ip_entry_t blocked_ips[TELEM_IP_MAX];
    ws_ip_entry_t rate_limited_ips[TELEM_IP_MAX];
    ws_ip_entry_t monitored_ips[TELEM_IP_MAX];
    ws_ip_entry_t whitelisted_ips[TELEM_IP_MAX];
    uint32_t blocked_head = 0, rate_limited_head = 0, monitored_head = 0;  /* cyclic ring write index */
    _Atomic uint32_t total_blocked = 0;
    _Atomic uint32_t total_rate_limited = 0;
    uint32_t total_monitored = 0;
    _Atomic uint32_t detections_10s = 0;
    _Atomic double threat_sum_10s = 0.0;
    _Atomic double volume_sum_10s = 0.0;
    _Atomic double entropy_sum_10s = 0.0;
    _Atomic double protocol_sum_10s = 0.0;
    _Atomic double behavioral_sum_10s = 0.0;
    _Atomic double ml_sum_10s = 0.0;
    _Atomic double l7_sum_10s = 0.0;
    _Atomic double anomaly_sum_10s = 0.0;
    _Atomic double chi_square_sum_10s = 0.0;
    _Atomic double fanin_sum_10s = 0.0;
    _Atomic double signature_sum_10s = 0.0;
    _Atomic double baseline_threat_sum_10s = 0.0;
    _Atomic uint32_t classified_count_10s = 0;
    _Atomic uint32_t ml_activated_10s = 0;

    activity_raw_t activity_ring[ACTIVITY_RING_SIZE];
    uint32_t activity_ring_head = 0;  /* next write */
    uint32_t activity_ring_tail = 0;   /* next read (drain in 1s block) */

    _Atomic uint64_t period_tcp_pkts = 0, period_udp_pkts = 0, period_icmp_pkts = 0, period_icmpv6_pkts = 0, period_other_pkts = 0;
    _Atomic uint64_t period_tcp_bytes = 0, period_udp_bytes = 0, period_icmp_bytes = 0, period_icmpv6_bytes = 0, period_other_bytes = 0;
    uint64_t period_proto_bytes[256] = {0};
    _Atomic uint64_t period_bytes_total = 0;
    uint32_t packet_event_sample_rate = 16;

    memset(blocked_ips, 0, sizeof(blocked_ips));
    memset(rate_limited_ips, 0, sizeof(rate_limited_ips));
    memset(monitored_ips, 0, sizeof(monitored_ips));
    memset(whitelisted_ips, 0, sizeof(whitelisted_ips));
    memset(activity_ring, 0, sizeof(activity_ring));
    for (uint32_t i = 0; i < n_whitelist_static && i < TELEM_IP_MAX; i++) {
        whitelisted_ips[i].ip = whitelist_static[i];
        whitelisted_ips[i].timestamp_added = (uint64_t)time(NULL) * 1000000000ULL;
    }

    /* Primary Lockless Event Loop */
    while (pipeline_running()) {
        time_t now = time(NULL);

        /* Liveness: GC every 1s so old flows are pruned and 10s rolling window is accurate (no ghost-flow leak). */
        if (now - last_gc >= 1) {
            int evicted = fe_gc(fe);
            if (evicted > 0) {
                gc_evicted_accum += (uint32_t)evicted;
                if ((now - last_gc_log) >= 5 || evicted >= 1000) {
                    LOG_INFO("GC: Evicted %u stale flows (last %lds)",
                             gc_evicted_accum,
                             (long)(now - last_gc_log));
                    gc_evicted_accum = 0;
                    last_gc_log = now;
                }
            }
            last_gc = now;
        }

        /* Telemetry: 1s metrics, traffic_rate, protocol_dist, mitigation_status */
        if (ws && now - last_metrics >= 1) {
            shared_state_publish_metrics(g_shared_state,
                                         ifname,
                                         dataplane_mode,
                                         rx_packets,
                                         rx_packets - last_rx_for_metrics,
                                         period_bytes_total,
                                         fe_active_flows(fe),
                                         fe_active_sources(fe),
                                         atomic_load_explicit(&total_blocked, memory_order_acquire),
                                         atomic_load_explicit(&total_rate_limited, memory_order_acquire),
                                         total_monitored,
                                         classifications_this_sec,
                                         skipped_classifications_this_sec);

            ws_metrics_t wm;
            wm.packets_per_sec = rx_packets - last_rx_for_metrics;
            wm.bytes_per_sec = period_bytes_total;
            wm.active_flows = fe_active_flows(fe);
            wm.active_sources = fe_active_sources(fe);
            wm.ml_classifications_per_sec = classifications_this_sec;
            wm.cpu_usage_percent = read_cpu_usage();
            wm.memory_usage_mb = read_mem_usage();
            wm.kernel_drops = atomic_load_explicit(&total_blocked, memory_order_acquire);
            wm.userspace_drops = atomic_load_explicit(&total_rate_limited, memory_order_acquire);

            if (skipped_classifications_this_sec > 0) {
                LOG_WARN("Classification backpressure active: skipped %u extracts in last second (cap=%lu/s)",
                         skipped_classifications_this_sec,
                         max_classifications_per_sec);
            }

            ws_traffic_rate_t tr;
            tr.total_pps = period_tcp_pkts + period_udp_pkts + period_icmp_pkts + period_icmpv6_pkts + period_other_pkts;
            tr.total_bps = period_bytes_total * 8;
            tr.tcp_pps = period_tcp_pkts;
            tr.udp_pps = period_udp_pkts;
            tr.icmp_pps = period_icmp_pkts;
            tr.icmpv6_pps = period_icmpv6_pkts;
            tr.other_pps = period_other_pkts;

            {
                uint64_t pps = tr.total_pps;
                if      (pps > 10000) packet_event_sample_rate = 1024;
                else if (pps > 5000)  packet_event_sample_rate = 512;
                else if (pps > 1000)  packet_event_sample_rate = 128;
                else if (pps > 100)   packet_event_sample_rate = 32;
                else                  packet_event_sample_rate = 16;
            }

            uint64_t total_p = tr.total_pps;
            ws_protocol_dist_t pd;
            pd.tcp_bytes = period_tcp_bytes;
            pd.udp_bytes = period_udp_bytes;
            pd.icmp_bytes = period_icmp_bytes;
            pd.icmpv6_bytes = period_icmpv6_bytes;
            pd.other_bytes = period_other_bytes;
            pd.other_top_proto = 0;
            if (total_p > 0) {
                pd.tcp_percent = 100.0 * (double)period_tcp_pkts / total_p;
                pd.udp_percent = 100.0 * (double)period_udp_pkts / total_p;
                pd.icmp_percent = 100.0 * (double)period_icmp_pkts / total_p;
                pd.icmpv6_percent = 100.0 * (double)period_icmpv6_pkts / total_p;
                pd.other_percent = 100.0 * (double)period_other_pkts / total_p;
            } else {
                pd.tcp_percent = pd.udp_percent = pd.icmp_percent = pd.icmpv6_percent = pd.other_percent = 0.0;
            }

            if (pd.other_bytes > 0) {
                uint64_t best_bytes = 0;
                uint8_t best_proto = 0;
                for (uint32_t p = 0; p < 256; p++) {
                    if (p == IPPROTO_TCP || p == IPPROTO_UDP || p == IPPROTO_ICMP || p == IPPROTO_ICMPV6) {
                        continue;
                    }
                    if (period_proto_bytes[p] > best_bytes) {
                        best_bytes = period_proto_bytes[p];
                        best_proto = (uint8_t)p;
                    }
                }
                pd.other_top_proto = best_proto;
            }

            {
                int sim_mode = atomic_load_explicit(&g_pipeline_sim_mode, memory_order_acquire);
                if (sim_mode != 0 && ws_sim_commands_enabled()) {
                    pipeline_apply_sim_traffic_overlay(sim_mode, &wm, &tr, &pd);
                }
            }
            ws_update_metrics(ws, &wm);
            ws_update_traffic_rate(ws, &tr);
            ws_update_protocol_dist(ws, &pd);

            /* Active connections telemetry from top active flows. */
            {
                fe_top_flow_t top_flows[10];
                ws_connection_t conns[10];
                uint32_t nc = fe_get_top_flows(fe, top_flows, 10);
                uint32_t out_conn = 0;
                for (uint32_t i = 0; i < nc && out_conn < 10; i++) {
                    if (top_flows[i].src_ip_text[0] == '\0' || top_flows[i].dst_ip_text[0] == '\0')
                        continue; /* Real-address-only display: skip unresolved identities. */
                    if (strcmp(top_flows[i].src_ip_text, "::") == 0 || strcmp(top_flows[i].dst_ip_text, "::") == 0)
                        continue; /* Suppress unspecified IPv6 address from connection table. */
                    conns[out_conn].src_ip = top_flows[i].key.src_ip;
                    conns[out_conn].dst_ip = top_flows[i].key.dst_ip;
                    snprintf(conns[out_conn].ip_family, sizeof(conns[out_conn].ip_family), "%s", (top_flows[i].ip_family == 6) ? "ipv6" : "ipv4");
                    snprintf(conns[out_conn].src_ip_text, sizeof(conns[out_conn].src_ip_text), "%s", top_flows[i].src_ip_text);
                    snprintf(conns[out_conn].dst_ip_text, sizeof(conns[out_conn].dst_ip_text), "%s", top_flows[i].dst_ip_text);
                    conns[out_conn].src_port = top_flows[i].key.src_port;
                    conns[out_conn].dst_port = top_flows[i].key.dst_port;
                    conns[out_conn].protocol = top_flows[i].key.protocol;
                    conns[out_conn].packets = top_flows[i].packets;
                    conns[out_conn].bytes = top_flows[i].bytes;
                    conns[out_conn].last_seen_ns = top_flows[i].last_seen_ns;
                    out_conn++;
                }
                ws_update_connections(ws, conns, out_conn);
            }

            ws_mitigation_status_t ms;
            memset(&ms, 0, sizeof(ms));
            {
                uint32_t total_blocked_snapshot = atomic_load_explicit(&total_blocked, memory_order_acquire);
                uint32_t total_rate_limited_snapshot = atomic_load_explicit(&total_rate_limited, memory_order_acquire);
                ms.total_blocked = total_blocked_snapshot;
                ms.total_rate_limited = total_rate_limited_snapshot;
                ms.active_sdn_rules = (total_blocked_snapshot > TELEM_IP_MAX ? TELEM_IP_MAX : total_blocked_snapshot)
                    + (total_rate_limited_snapshot > TELEM_IP_MAX ? TELEM_IP_MAX : total_rate_limited_snapshot);
            }
            ms.total_monitored = total_monitored;
            ms.total_whitelisted = n_whitelist_static;
            ms.kernel_verdict_cache_hits = 0;
            ms.kernel_verdict_cache_misses = 0;
            ms.auto_mitigation_enabled = atomic_load_explicit(&g_shared_state->auto_mitigation_enabled, memory_order_acquire);
            ms.kernel_dropping_enabled = (blacklist_map_fd > 0) ? 1 : 0;
            snprintf(ms.dataplane_mode, sizeof(ms.dataplane_mode), "%s", pipeline_dataplane_mode_str(dataplane_mode));
            
            /* Periodic SDN health check (every 5s) to catch early connectivity status */
            if (now - last_sdn_health_check >= sdn_health_check_interval) {
                int health = sdn_health_check(sdn);
                atomic_store_explicit(&g_shared_state->sdn_connected, (health == 0) ? 1 : 0, memory_order_release);
                last_sdn_health_check = now;
            }
            
            ms.sdn_connected = atomic_load_explicit(&g_shared_state->sdn_connected, memory_order_acquire);
            sdn_get_last_error(sdn, ms.sdn_last_error, sizeof(ms.sdn_last_error));
            ws_update_mitigation_status(ws, &ms);

            ws_integration_status_t ist;
            memset(&ist, 0, sizeof(ist));
            ist.intel_feed_enabled = integration_flags.intel_feed_enabled;
            ist.model_extension_enabled = integration_flags.model_extension_enabled;
            ist.controller_extension_enabled = integration_flags.controller_extension_enabled;
            ist.signature_feed_enabled = integration_flags.signature_feed_enabled;
            ist.dataplane_extension_enabled = integration_flags.dataplane_extension_enabled;
            snprintf(ist.profile, sizeof(ist.profile), "%s", integration_flags.profile);
            ws_update_integration_status(ws, &ist);

            /* Process pending clear_rate_limit from WebSocket command */
            if (atomic_exchange_explicit(&g_shared_state->pending_clear_rate_limit, 0, memory_order_acquire)) {
                uint32_t ip = atomic_load_explicit(&g_shared_state->pending_clear_rate_limit_ip, memory_order_relaxed);
                sdn_remove_rules_for_src(sdn, ip);
                if (g_cleared_rate_limit_count < CLEARED_RATE_LIMIT_MAX) {
                    g_cleared_rate_limits[g_cleared_rate_limit_count++] = ip;
                }
            }

            /* Process pending unblock_ip: remove from eBPF blacklist map */
            if (atomic_exchange_explicit(&g_shared_state->has_pending_unblock_ip, 0, memory_order_acquire)) {
                uint32_t ip = atomic_load_explicit(&g_shared_state->pending_unblock_ip, memory_order_relaxed);
                pipeline_unblacklist_ip(blacklist_map_fd, ip);
                LOG_INFO("[PIPELINE] unblock_ip: removed from kernel blacklist");
            }

            /* Process pending block_all_flagged: move monitored IPs to blocklist */
            if (atomic_exchange_explicit(&g_shared_state->pending_block_all, 0, memory_order_acquire)) {
                uint32_t n_mon = (total_monitored < TELEM_IP_MAX) ? total_monitored : TELEM_IP_MAX;
                uint32_t mon_start = (total_monitored >= TELEM_IP_MAX) ? monitored_head : 0;
                uint64_t ts = (uint64_t)now * 1000000000ULL;
                for (uint32_t i = 0; i < n_mon; i++) {
                    uint32_t ip = monitored_ips[(mon_start + i) % TELEM_IP_MAX].ip;
                    de_add_denylist(de, ip);
                    pipeline_blacklist_ip(blacklist_map_fd, ip, ts);
                    if (blocked_head < TELEM_IP_MAX || 1) {
                        blocked_ips[blocked_head % TELEM_IP_MAX].ip = ip;
                        blocked_ips[blocked_head % TELEM_IP_MAX].timestamp_added = ts;
                        blocked_ips[blocked_head % TELEM_IP_MAX].rule_id = 0;
                        blocked_ips[blocked_head % TELEM_IP_MAX].rate_limit_pps = 0;
                        blocked_head = (blocked_head + 1) % TELEM_IP_MAX;
                        atomic_fetch_add_explicit(&total_blocked, 1, memory_order_acq_rel);
                    }
                }
                total_monitored = 0;
                monitored_head = 0;
                LOG_INFO("[PIPELINE] block_all_flagged: blocked %u monitored IP(s)", (unsigned)n_mon);
            }

            /* Process pending clear_all_blocks: flush eBPF map, clear denylist, reset counters */
            if (atomic_exchange_explicit(&g_shared_state->pending_clear_all, 0, memory_order_acquire)) {
                uint32_t total_blocked_snapshot = atomic_load_explicit(&total_blocked, memory_order_acquire);
                uint32_t total_rate_limited_snapshot = atomic_load_explicit(&total_rate_limited, memory_order_acquire);
                uint32_t n_blocked = (total_blocked_snapshot < TELEM_IP_MAX) ? total_blocked_snapshot : TELEM_IP_MAX;
                uint32_t n_rl = (total_rate_limited_snapshot < TELEM_IP_MAX) ? total_rate_limited_snapshot : TELEM_IP_MAX;
                uint32_t blocked_start = (total_blocked_snapshot >= TELEM_IP_MAX) ? blocked_head : 0;
                uint32_t rl_start = (total_rate_limited_snapshot >= TELEM_IP_MAX) ? rate_limited_head : 0;
                for (uint32_t i = 0; i < n_blocked; i++)
                    sdn_remove_rules_for_src(sdn, blocked_ips[(blocked_start + i) % TELEM_IP_MAX].ip);
                for (uint32_t i = 0; i < n_rl; i++)
                    sdn_remove_rules_for_src(sdn, rate_limited_ips[(rl_start + i) % TELEM_IP_MAX].ip);
                pipeline_clear_blacklist_map(blacklist_map_fd);
                de_clear_denylist(de);
                atomic_store_explicit(&total_blocked, 0, memory_order_release);
                blocked_head = 0;
                atomic_store_explicit(&total_rate_limited, 0, memory_order_release);
                rate_limited_head = 0;
                g_cleared_rate_limit_count = 0;
                LOG_INFO("[PIPELINE] clear_all_blocks: kernel map and denylist cleared");
            }

            /* Out-of-band: blocked/rate_limited IPs (JSON serialization here, not in packet path) */
            {
                ws_ip_entry_t blocked_ordered[TELEM_IP_MAX], rate_limited_ordered[TELEM_IP_MAX];
                ws_ip_entry_t monitored_ordered[TELEM_IP_MAX];
                uint32_t total_blocked_snapshot = atomic_load_explicit(&total_blocked, memory_order_acquire);
                uint32_t total_rate_limited_snapshot = atomic_load_explicit(&total_rate_limited, memory_order_acquire);
                uint32_t blocked_count = (total_blocked_snapshot < TELEM_IP_MAX) ? total_blocked_snapshot : TELEM_IP_MAX;
                uint32_t rate_limited_count = (total_rate_limited_snapshot < TELEM_IP_MAX) ? total_rate_limited_snapshot : TELEM_IP_MAX;
                uint32_t monitored_count = (total_monitored < TELEM_IP_MAX) ? total_monitored : TELEM_IP_MAX;
                uint32_t whitelist_count = (n_whitelist_static < TELEM_IP_MAX) ? n_whitelist_static : TELEM_IP_MAX;
                uint32_t blocked_start = (total_blocked_snapshot >= TELEM_IP_MAX) ? blocked_head : 0;
                uint32_t rate_limited_start = (total_rate_limited_snapshot >= TELEM_IP_MAX) ? rate_limited_head : 0;
                uint32_t monitored_start = (total_monitored >= TELEM_IP_MAX) ? monitored_head : 0;
                for (uint32_t i = 0; i < blocked_count; i++) {
                    blocked_ordered[i] = blocked_ips[(blocked_start + i) % TELEM_IP_MAX];
                    if (!ip_identity_lookup(blocked_ordered[i].ip, blocked_ordered[i].ip_text, sizeof(blocked_ordered[i].ip_text), blocked_ordered[i].ip_family, sizeof(blocked_ordered[i].ip_family))) {
                        fill_ip_identity_fallback(blocked_ordered[i].ip, blocked_ordered[i].ip_text, sizeof(blocked_ordered[i].ip_text), blocked_ordered[i].ip_family, sizeof(blocked_ordered[i].ip_family));
                    }
                }
                uint32_t rl_out = 0;
                for (uint32_t i = 0; i < rate_limited_count && rl_out < TELEM_IP_MAX; i++) {
                    ws_ip_entry_t e = rate_limited_ips[(rate_limited_start + i) % TELEM_IP_MAX];
                    int cleared = 0;
                    for (int j = 0; j < g_cleared_rate_limit_count; j++) {
                        if (g_cleared_rate_limits[j] == e.ip) { cleared = 1; break; }
                    }
                    if (!cleared) {
                        if (!ip_identity_lookup(e.ip, e.ip_text, sizeof(e.ip_text), e.ip_family, sizeof(e.ip_family))) {
                            fill_ip_identity_fallback(e.ip, e.ip_text, sizeof(e.ip_text), e.ip_family, sizeof(e.ip_family));
                        }
                        rate_limited_ordered[rl_out++] = e;
                    }
                }
                rate_limited_count = rl_out;
                for (uint32_t i = 0; i < monitored_count; i++) {
                    monitored_ordered[i] = monitored_ips[(monitored_start + i) % TELEM_IP_MAX];
                    if (!ip_identity_lookup(monitored_ordered[i].ip, monitored_ordered[i].ip_text, sizeof(monitored_ordered[i].ip_text), monitored_ordered[i].ip_family, sizeof(monitored_ordered[i].ip_family))) {
                        fill_ip_identity_fallback(monitored_ordered[i].ip, monitored_ordered[i].ip_text, sizeof(monitored_ordered[i].ip_text), monitored_ordered[i].ip_family, sizeof(monitored_ordered[i].ip_family));
                    }
                }
                for (uint32_t i = 0; i < whitelist_count; i++) {
                    if (!ip_identity_lookup(whitelisted_ips[i].ip, whitelisted_ips[i].ip_text, sizeof(whitelisted_ips[i].ip_text), whitelisted_ips[i].ip_family, sizeof(whitelisted_ips[i].ip_family))) {
                        fill_ip_identity_fallback(whitelisted_ips[i].ip, whitelisted_ips[i].ip_text, sizeof(whitelisted_ips[i].ip_text), whitelisted_ips[i].ip_family, sizeof(whitelisted_ips[i].ip_family));
                    }
                }
                ws_update_blocked_ips(ws, blocked_ordered, blocked_count);
                ws_update_rate_limited_ips(ws, rate_limited_ordered, rate_limited_count);
                ws_update_monitored_ips(ws, monitored_ordered, monitored_count);
                ws_update_whitelisted_ips(ws, whitelisted_ips, whitelist_count);
            }

            /* Drain activity ring: cap iterations to avoid telemetry-induced pipeline stall.
             * Under multi-vector flood (e.g. 10k events/sec) we drain at most ACTIVITY_DRAIN_CAP
             * per tick and advance tail past the rest so the packet thread never blocks. */
#define ACTIVITY_DRAIN_CAP 200
            uint32_t drained = 0;
            while (activity_ring_tail != activity_ring_head && drained < ACTIVITY_DRAIN_CAP) {
                const activity_raw_t *ar = &activity_ring[activity_ring_tail % ACTIVITY_RING_SIZE];
                ws_activity_t wa;
                wa.timestamp_ns = ar->timestamp_ns;
                wa.src_ip = ar->src_ip;
                if (!ip_identity_lookup(ar->src_ip, wa.src_ip_text, sizeof(wa.src_ip_text), wa.ip_family, sizeof(wa.ip_family))) {
                    fill_ip_identity_fallback(ar->src_ip, wa.src_ip_text, sizeof(wa.src_ip_text), wa.ip_family, sizeof(wa.ip_family));
                }
                wa.threat_score = ar->threat_score;
                wa.enforced = ar->enforced;
                snprintf(wa.action, sizeof(wa.action), "%s", verdict_to_action(ar->verdict));
                snprintf(wa.attack_type, sizeof(wa.attack_type), "%s", attack_type_str(ar->attack_type));
                snprintf(
                    wa.reason,
                    sizeof(wa.reason),
                    "score=%.3f conf=%.2f ml=%.2f rel=%.2f",
                    ar->threat_score,
                    ar->confidence,
                    ar->score_ml,
                    ar->ml_reliability
                );
                ws_push_activity(ws, &wa);
                activity_ring_tail++;
                drained++;
            }
            if (activity_ring_tail != activity_ring_head)
                activity_ring_tail = activity_ring_head; /* drop remainder; never stall packet path */
#undef ACTIVITY_DRAIN_CAP

            last_rx_for_metrics = rx_packets;
            last_metrics = now;
            classifications_this_sec = 0;
            skipped_classifications_this_sec = 0;
            period_tcp_pkts = period_udp_pkts = period_icmp_pkts = period_icmpv6_pkts = period_other_pkts = 0;
            period_tcp_bytes = period_udp_bytes = period_icmp_bytes = period_icmpv6_bytes = period_other_bytes = 0;
            memset(period_proto_bytes, 0, sizeof(period_proto_bytes));
            period_bytes_total = 0;
        }

        if (!ws && now - last_metrics >= 1) {
            shared_state_publish_metrics(g_shared_state,
                                         ifname,
                                         dataplane_mode,
                                         rx_packets,
                                         rx_packets - last_rx_for_metrics,
                                         period_bytes_total,
                                         fe_active_flows(fe),
                                         fe_active_sources(fe),
                                         atomic_load_explicit(&total_blocked, memory_order_acquire),
                                         atomic_load_explicit(&total_rate_limited, memory_order_acquire),
                                         total_monitored,
                                         classifications_this_sec,
                                         skipped_classifications_this_sec);

            if (skipped_classifications_this_sec > 0) {
                LOG_WARN("Classification backpressure active: skipped %u extracts in last second (cap=%lu/s)",
                         skipped_classifications_this_sec,
                         max_classifications_per_sec);
            }

            last_rx_for_metrics = rx_packets;
            last_metrics = now;
            classifications_this_sec = 0;
            skipped_classifications_this_sec = 0;
            period_tcp_pkts = period_udp_pkts = period_icmp_pkts = period_icmpv6_pkts = period_other_pkts = 0;
            period_tcp_bytes = period_udp_bytes = period_icmp_bytes = period_icmpv6_bytes = period_other_bytes = 0;
            memset(period_proto_bytes, 0, sizeof(period_proto_bytes));
            period_bytes_total = 0;
        }

        /* Telemetry: 5s - top_sources with real-time ML classification */
        if (ws && now - last_top_sources >= 5) {
            int sim_mode_ts = atomic_load_explicit(&g_pipeline_sim_mode, memory_order_acquire);
            if (sim_mode_ts != 0 && ws_sim_commands_enabled()) {
                ws_top_source_t ws_top[1];
                memset(&ws_top, 0, sizeof(ws_top));
                ws_top[0].src_ip = pipeline_sim_src_ip_ipv4();
                if (sim_mode_ts == 1 && ws_top[0].src_ip == htonl(0xC0A80101))
                    ws_top[0].src_ip = htonl(0xC0A80102);
                snprintf(ws_top[0].ip_family, sizeof(ws_top[0].ip_family), "%s", "ipv4");
                inet_ntop(AF_INET, &ws_top[0].src_ip, ws_top[0].src_ip_text, sizeof(ws_top[0].src_ip_text));
                if (sim_mode_ts == 2) {
                    ws_top[0].packets = 5000000ULL;
                    ws_top[0].bytes = 3200000000ULL;
                    ws_top[0].flow_count = 12000U;
                    ws_top[0].suspicious = 1;
                    ws_top[0].threat_score = 0.92;
                } else {
                    ws_top[0].packets = 800000ULL;
                    ws_top[0].bytes = 400000000ULL;
                    ws_top[0].flow_count = 9000U;
                    ws_top[0].suspicious = 0;
                    ws_top[0].threat_score = 0.45;
                }
                ws_update_top_sources(ws, ws_top, 1);
            } else {
                fe_top_source_t top[10];
                uint32_t n = fe_get_top_sources(fe, top, 10);
                if (n > 0) {
                    ws_top_source_t ws_top[10];
                    sentinel_feature_vector_t fv;
                    sentinel_threat_assessment_t assessment;
                    uint64_t total_top_packets = 0;
                    for (uint32_t k = 0; k < n; k++)
                        total_top_packets += top[k].packets;
                    uint32_t out = 0;
                    for (uint32_t k = 0; k < n && out < 10; k++) {
                        if (g_contributor_threshold_pct > 0.0 && total_top_packets > 0) {
                            double pct = (double)top[k].packets * 100.0 / (double)total_top_packets;
                            if (pct < g_contributor_threshold_pct)
                                continue;
                        }
                        ws_top[out].src_ip = top[k].src_ip;
                        snprintf(ws_top[out].ip_family, sizeof(ws_top[out].ip_family), "%s", (top[k].ip_family == 6) ? "ipv6" : "ipv4");
                        snprintf(ws_top[out].src_ip_text, sizeof(ws_top[out].src_ip_text), "%s", top[k].src_ip_text);
                        if (ws_top[out].src_ip_text[0] == '\0')
                            continue; /* Real-address-only display: skip unresolved identities. */
                        if (strcmp(ws_top[out].src_ip_text, "::") == 0)
                            continue; /* Suppress unspecified IPv6 address from top sources. */
                        ws_top[out].packets = top[k].packets;
                        ws_top[out].bytes = top[k].bytes;
                        ws_top[out].flow_count = top[k].flow_count;
                        ws_top[out].suspicious = 0;
                        ws_top[out].threat_score = 0.0;
                        if (fe_extract_source(fe, top[k].src_ip, &fv) == 0 &&
                            de_classify(de, &fv, &assessment, integration_flags.model_extension_enabled) == 0) {
                            ws_top[out].threat_score = assessment.threat_score;
                            ws_top[out].suspicious = (assessment.verdict != VERDICT_ALLOW) ? 1 : 0;
                        }
                        out++;
                    }
                    ws_update_top_sources(ws, ws_top, out);
                }
            }
            last_top_sources = now;
        }

        /* Telemetry: 10s - feature_importance (from de_get_thresholds) */
        if (ws && now - last_feature_importance >= 10) {
            const de_thresholds_t *dt = de_get_thresholds(de);
            if (dt) {
                ws_feature_importance_t wi;
                int sim_mode_fi = atomic_load_explicit(&g_pipeline_sim_mode, memory_order_acquire);
                fb_policy_stats_t ps;
                memset(&ps, 0, sizeof(ps));
                (void)fb_get_policy_stats(fb, &ps);
                wi.volume_weight = dt->weight_volume;
                wi.entropy_weight = dt->weight_entropy;
                wi.protocol_weight = dt->weight_protocol;
                wi.behavioral_weight = dt->weight_behavioral;
                wi.ml_weight = dt->weight_ml;
                wi.l7_weight = dt->weight_l7;
                wi.anomaly_weight = dt->weight_anomaly;
                wi.chi_square_weight = dt->weight_chi_square;
                wi.fanin_weight = dt->weight_fanin;
                wi.avg_threat_score = (classified_count_10s > 0)
                    ? (threat_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_fanin_score = (classified_count_10s > 0)
                    ? (fanin_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.signature_weight = dt->weight_signature;
                wi.avg_signature_score = (classified_count_10s > 0)
                    ? (signature_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_volume = (classified_count_10s > 0)
                    ? (volume_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_entropy = (classified_count_10s > 0)
                    ? (entropy_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_protocol = (classified_count_10s > 0)
                    ? (protocol_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_behavioral = (classified_count_10s > 0)
                    ? (behavioral_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_ml = (classified_count_10s > 0)
                    ? (ml_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_l7 = (classified_count_10s > 0)
                    ? (l7_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_anomaly = (classified_count_10s > 0)
                    ? (anomaly_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_chi_square = (classified_count_10s > 0)
                    ? (chi_square_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.avg_score_fanin = wi.avg_fanin_score;
                wi.avg_score_signature = wi.avg_signature_score;
                wi.avg_baseline_threat_score = (classified_count_10s > 0)
                    ? (baseline_threat_sum_10s / (double)classified_count_10s)
                    : 0.0;
                wi.ml_activation_threshold = 0.15;
                wi.detections_last_10s = detections_10s;
                wi.classifications_last_10s = classified_count_10s;
                wi.ml_activated_last_10s = ml_activated_10s;
                wi.policy_arm = ps.active_arm;
                wi.policy_updates = ps.update_count;
                wi.policy_last_reward = ps.last_reward;
                if (sim_mode_fi != 0 && ws_sim_commands_enabled()) {
                    pipeline_apply_sim_feature_overlay(sim_mode_fi, &wi);
                }
                ws_update_feature_importance(ws, &wi);
            }
            if (ws) {
                int sim_mode_fv = atomic_load_explicit(&g_pipeline_sim_mode, memory_order_acquire);
                if (sim_mode_fv != 0 && ws_sim_commands_enabled()) {
                    ws_raw_feature_vector_t raw_vec;
                    memset(&raw_vec, 0, sizeof(raw_vec));
                    if (sim_mode_fv == 2) {
                        raw_vec.values[0] = 800000.0;
                        raw_vec.values[1] = 4e8;
                        raw_vec.values[2] = 0.95;
                        raw_vec.values[3] = 0.02;
                        raw_vec.values[4] = 6.5;
                        raw_vec.values[5] = 5.8;
                        raw_vec.values[6] = 120.0;
                        raw_vec.values[7] = 180.0;
                        raw_vec.values[8] = 45.0;
                        raw_vec.values[9] = 2.0;
                        raw_vec.values[10] = 0.01;
                        raw_vec.values[11] = 4.2;
                        raw_vec.values[12] = 80.0;
                        raw_vec.values[13] = 52.0;
                        raw_vec.values[14] = 8.0;
                        raw_vec.values[15] = 150.0;
                        raw_vec.values[16] = 90.0;
                        raw_vec.values[17] = 5000.0;
                        raw_vec.values[18] = 750000.0;
                        raw_vec.values[19] = 5.0;
                        raw_vec.values[20] = 0.85;
                        raw_vec.values[21] = 150.0;
                    } else {
                        raw_vec.values[0] = 95000.0;
                        raw_vec.values[1] = 8e7;
                        raw_vec.values[2] = 0.35;
                        raw_vec.values[3] = 0.08;
                        raw_vec.values[4] = 5.2;
                        raw_vec.values[5] = 4.1;
                        raw_vec.values[6] = 400.0;
                        raw_vec.values[7] = 512.0;
                        raw_vec.values[8] = 120.0;
                        raw_vec.values[9] = 0.0;
                        raw_vec.values[10] = 0.12;
                        raw_vec.values[11] = 5.5;
                        raw_vec.values[12] = 2000.0;
                        raw_vec.values[13] = 64.0;
                        raw_vec.values[14] = 4.0;
                        raw_vec.values[15] = 800.0;
                        raw_vec.values[16] = 400.0;
                        raw_vec.values[17] = 8000.0;
                        raw_vec.values[18] = 95000.0;
                        raw_vec.values[19] = 12.0;
                        raw_vec.values[20] = 0.32;
                        raw_vec.values[21] = 40.0;
                    }
                    ws_update_feature_vector(ws, &raw_vec);
                } else if (g_has_last_feature_vector) {
                    ws_raw_feature_vector_t raw_vec;
                    fv_to_raw_vector(&g_last_feature_vector, g_last_chi_square_score, &raw_vec);
                    ws_update_feature_vector(ws, &raw_vec);
                }
            }
            detections_10s = 0;
            threat_sum_10s = 0.0;
            volume_sum_10s = 0.0;
            entropy_sum_10s = 0.0;
            protocol_sum_10s = 0.0;
            behavioral_sum_10s = 0.0;
            ml_sum_10s = 0.0;
            l7_sum_10s = 0.0;
            anomaly_sum_10s = 0.0;
            chi_square_sum_10s = 0.0;
            fanin_sum_10s = 0.0;
            signature_sum_10s = 0.0;
            baseline_threat_sum_10s = 0.0;
            classified_count_10s = 0;
            ml_activated_10s = 0;
            last_feature_importance = now;
        }

        /* 60s: producer writes only when consumer has consumed (work_ready==0); no torn read. */
        if (integration_flags.intel_feed_enabled &&
            now - last_feedback >= 60 &&
            atomic_load_explicit(&feedback_shared.work_ready, memory_order_acquire) == 0) {
            fe_top_source_t top[FEEDBACK_SLOTS];
            uint32_t n = fe_get_top_sources(fe, top, FEEDBACK_SLOTS);
            uint32_t filled = 0;
            int w = feedback_write_idx;
            for (uint32_t k = 0; k < n && filled < FEEDBACK_SLOTS; k++) {
                sentinel_feature_vector_t fv;
                sentinel_threat_assessment_t assessment;
                if (fe_extract_source(fe, top[k].src_ip, &fv) == 0 &&
                    de_classify(de, &fv, &assessment, integration_flags.model_extension_enabled) == 0) {
                    feedback_shared.src_ips[w][filled] = top[k].src_ip;
                    feedback_shared.scores[w][filled] = assessment.threat_score;
                    filled++;
                }
            }
            atomic_store_explicit(&feedback_shared.ready_count, filled, memory_order_release);
            atomic_store_explicit(&feedback_shared.ready_slot, w, memory_order_release);
            atomic_store_explicit(&feedback_shared.work_ready, 1, memory_order_release);
            feedback_write_idx = 1 - feedback_write_idx;
            last_feedback = now;
        }

        struct pollfd fds[1];
        fds[0].fd = xsk->xsk_fd;
        fds[0].events = POLLIN;

        int ret = poll(fds, 1, use_raw_fallback ? 10 : 0);  /* Raw: 10ms block; AF_XDP: busy-poll. */
        if (ret < 0) continue;
        if (ret == 0 && use_raw_fallback) continue;

        if (use_raw_fallback) {
            /* ---- RAW SOCKET PATH ---- */
            char raw_buf[FRAME_SIZE];
            ssize_t nbytes = recvfrom(xsk->xsk_fd, raw_buf, sizeof(raw_buf), MSG_DONTWAIT, NULL, NULL);
            if (nbytes <= 0) continue;

            rx_packets++;
            if ((rx_packets & 0x7F) == 0) {
                struct timespec ts;
                if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
                    coarse_now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
            }

            uint32_t len = (uint32_t)nbytes;
            fe_packet_t fe_pkt;
            if (parse_raw_packet(raw_buf, len, &fe_pkt, rx_packets, coarse_now_ns) != 0)
                continue;

            /* Reflection signature matching (always enabled) */
            fe_pkt.sig_boost = de_match_packet(de, &fe_pkt);

            /* Per-protocol counters for telemetry (1s traffic_rate / protocol_dist) */
            if (fe_pkt.protocol == IPPROTO_TCP) { 
                atomic_fetch_add_explicit(&period_tcp_pkts, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&period_tcp_bytes, len, memory_order_relaxed);
            } else if (fe_pkt.protocol == IPPROTO_UDP) {
                atomic_fetch_add_explicit(&period_udp_pkts, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&period_udp_bytes, len, memory_order_relaxed);
            } else if (fe_pkt.protocol == IPPROTO_ICMP) {
                atomic_fetch_add_explicit(&period_icmp_pkts, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&period_icmp_bytes, len, memory_order_relaxed);
            } else if (fe_pkt.protocol == IPPROTO_ICMPV6) {
                atomic_fetch_add_explicit(&period_icmpv6_pkts, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&period_icmpv6_bytes, len, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&period_other_pkts, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&period_other_bytes, len, memory_order_relaxed);
            }
            period_proto_bytes[fe_pkt.protocol] += (uint64_t)len;
            atomic_fetch_add_explicit(&period_bytes_total, len, memory_order_relaxed);

            ip_identity_record(fe_pkt.src_ip, fe_pkt.ip_family, fe_pkt.src_ip_text, coarse_now_ns);
            ip_identity_record(fe_pkt.dst_ip, fe_pkt.ip_family, fe_pkt.dst_ip_text, coarse_now_ns);
            if (ws && (rx_packets % packet_event_sample_rate) == 0u) {
                ws_packet_event_t pe;
                memset(&pe, 0, sizeof(pe));
                pe.timestamp_ns = coarse_now_ns;
                snprintf(pe.ip_family, sizeof(pe.ip_family), "%s", (fe_pkt.ip_family == 6) ? "ipv6" : "ipv4");
                snprintf(pe.src_ip_text, sizeof(pe.src_ip_text), "%s", fe_pkt.src_ip_text);
                snprintf(pe.dst_ip_text, sizeof(pe.dst_ip_text), "%s", fe_pkt.dst_ip_text);
                pe.protocol = fe_pkt.protocol;
                pe.src_port = fe_pkt.src_port;
                pe.dst_port = fe_pkt.dst_port;
                pe.packet_len = len;
                ws_push_packet_event(ws, &pe);
            }
            fe_ingest_packet(fe, &fe_pkt);

            sentinel_feature_vector_t fv;
            if (fe_should_extract(fe, coarse_now_ns) && fe_extract_last(fe, &fv) == 0) {
                fe_mark_extracted(fe, coarse_now_ns);
                if (classifications_this_sec >= max_classifications_per_sec) {
                    skipped_classifications_this_sec++;
                    continue;
                }
                sentinel_threat_assessment_t assessment;
                if (de_classify(de, &fv, &assessment, integration_flags.model_extension_enabled) == 0) {
                    g_last_feature_vector = fv;
                    g_has_last_feature_vector = 1;
                    g_last_chi_square_score = assessment.score_chi_square;
                    classifications_this_sec++;
                    threat_sum_10s += assessment.threat_score;
                    volume_sum_10s += assessment.score_volume;
                    entropy_sum_10s += assessment.score_entropy;
                    protocol_sum_10s += assessment.score_protocol;
                    behavioral_sum_10s += assessment.score_behavioral;
                    ml_sum_10s += assessment.score_ml;
                    l7_sum_10s += assessment.score_l7;
                    anomaly_sum_10s += assessment.score_anomaly;
                    chi_square_sum_10s += assessment.score_chi_square;
                    fanin_sum_10s += assessment.score_fanin;
                    signature_sum_10s += assessment.score_signature;
                    baseline_threat_sum_10s += assessment.baseline_threat_score;
                    classified_count_10s++;
                    if (assessment.ml_activated)
                        ml_activated_10s++;
                    if (assessment.verdict != VERDICT_ALLOW) {
                        detections_10s++;
                        int enforcing = atomic_load_explicit(&g_shared_state->auto_mitigation_enabled, memory_order_acquire);
                        sentinel_sdn_rule_t rule;
                        int sdn_push_rc = -1;
                        sdn_build_rule_from_assessment(sdn, &assessment, &rule);
                        if (enforcing) {
                            sdn_push_rc = sdn_push_rule(sdn, &rule);
                            atomic_store_explicit(&g_shared_state->sdn_connected, (sdn_push_rc == 0) ? 1 : 0, memory_order_release);
                        }
                        maybe_run_controller_extension(&controller_extension, &assessment, &rule,
                                                       enforcing, sdn_push_rc, coarse_now_ns);

                        {
                            uint64_t ts_ns = coarse_now_ns;
                            if (enforcing && assessment.verdict == VERDICT_DROP) {
                                atomic_fetch_add_explicit(&total_blocked, 1, memory_order_acq_rel);
                                pipeline_blacklist_ip(blacklist_map_fd, assessment.src_ip, ts_ns);
                                blocked_ips[blocked_head].ip = assessment.src_ip;
                                blocked_ips[blocked_head].timestamp_added = ts_ns;
                                blocked_ips[blocked_head].rule_id = rule.rule_id;
                                blocked_ips[blocked_head].rate_limit_pps = 0;
                                blocked_head = (blocked_head + 1) % TELEM_IP_MAX;
                            } else if (enforcing && assessment.verdict == VERDICT_RATE_LIMIT) {
                                atomic_fetch_add_explicit(&total_rate_limited, 1, memory_order_acq_rel);
                                rate_limited_ips[rate_limited_head].ip = assessment.src_ip;
                                rate_limited_ips[rate_limited_head].timestamp_added = ts_ns;
                                rate_limited_ips[rate_limited_head].rule_id = rule.rule_id;
                                rate_limited_ips[rate_limited_head].rate_limit_pps = de_cfg.default_rate_limit;
                                rate_limited_head = (rate_limited_head + 1) % TELEM_IP_MAX;
                            }
                        }

                        sentinel_flow_key_t fv_key = {
                            .src_ip = fv.src_ip, .dst_ip = fv.dst_ip,
                            .src_port = fv.src_port, .dst_port = fv.dst_port,
                            .protocol = fv.protocol
                        };
                        fe_writeback_threat(fe, &fv_key, assessment.threat_score);
                        fb_record_action(fb, assessment.src_ip, assessment.verdict,
                                        assessment.attack_type, assessment.threat_score);

                        if (ws) {
                            uint64_t current_head = atomic_load_explicit(&activity_ring_head, memory_order_relaxed);
                            uint64_t current_tail = atomic_load_explicit(&activity_ring_tail, memory_order_acquire);
                            
                            activity_raw_t *ar = &activity_ring[current_head % ACTIVITY_RING_SIZE];
                            ar->timestamp_ns = assessment.assessment_time_ns;
                            ar->src_ip = assessment.src_ip;
                            ar->verdict = assessment.verdict;
                            ar->attack_type = assessment.attack_type;
                            ar->threat_score = assessment.threat_score;
                            ar->confidence = assessment.confidence;
                            ar->score_ml = assessment.score_ml;
                            ar->ml_reliability = assessment.ml_reliability;
                            ar->enforced = enforcing;

                            if (current_head - current_tail >= ACTIVITY_RING_SIZE) {
                                atomic_store_explicit(&activity_ring_tail, current_tail + 1, memory_order_release);
                            }
                            atomic_store_explicit(&activity_ring_head, current_head + 1, memory_order_release);
                        }
                    } else if (assessment.threat_score >= 0.20) {
                        uint64_t ts_ns = coarse_now_ns;
                        total_monitored++;
                        monitored_ips[monitored_head].ip = assessment.src_ip;
                        monitored_ips[monitored_head].timestamp_added = ts_ns;
                        monitored_ips[monitored_head].rule_id = 0;
                        monitored_ips[monitored_head].rate_limit_pps = 0;
                        monitored_head = (monitored_head + 1) % TELEM_IP_MAX;
                    }
                }
            }
        } else {
            /* ---- AF_XDP ZERO-COPY PATH ---- */
            __u32 idx_rx = 0;
            int rcvd = xsk_ring_cons__peek(&xsk->rx, 64, &idx_rx);
            if (ret == 0 && rcvd == 0) continue;

            __u64 refill_addrs[64];
            int n_refill = 0;

            for (int i = 0; i < rcvd; i++) {
                rx_packets++;
                if ((rx_packets & 0x7F) == 0) {
                    struct timespec ts;
                    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
                        coarse_now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
                }

                const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
                if (desc->addr >= UMEM_SIZE) continue;
                refill_addrs[n_refill++] = desc->addr;
                if (desc->len == 0 || (desc->addr + (__u64)desc->len) > UMEM_SIZE) continue;
                char *pkt_data = xsk_umem__get_data(xsk->umem->frames, desc->addr);
                uint32_t len = desc->len;

                fe_packet_t fe_pkt;
                if (parse_raw_packet(pkt_data, len, &fe_pkt, rx_packets, coarse_now_ns) != 0)
                    continue;

                /* Reflection signature matching (always enabled) */
                fe_pkt.sig_boost = de_match_packet(de, &fe_pkt);

                /* Per-protocol counters for telemetry (1s traffic_rate / protocol_dist) */
                if (fe_pkt.protocol == IPPROTO_TCP) { 
                    atomic_fetch_add_explicit(&period_tcp_pkts, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&period_tcp_bytes, len, memory_order_relaxed);
                } else if (fe_pkt.protocol == IPPROTO_UDP) {
                    atomic_fetch_add_explicit(&period_udp_pkts, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&period_udp_bytes, len, memory_order_relaxed);
                } else if (fe_pkt.protocol == IPPROTO_ICMP) {
                    atomic_fetch_add_explicit(&period_icmp_pkts, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&period_icmp_bytes, len, memory_order_relaxed);
                } else if (fe_pkt.protocol == IPPROTO_ICMPV6) {
                    atomic_fetch_add_explicit(&period_icmpv6_pkts, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&period_icmpv6_bytes, len, memory_order_relaxed);
                } else {
                    atomic_fetch_add_explicit(&period_other_pkts, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&period_other_bytes, len, memory_order_relaxed);
                }
                period_proto_bytes[fe_pkt.protocol] += (uint64_t)len;
                atomic_fetch_add_explicit(&period_bytes_total, (uint64_t)len, memory_order_relaxed);

                ip_identity_record(fe_pkt.src_ip, fe_pkt.ip_family, fe_pkt.src_ip_text, coarse_now_ns);
                ip_identity_record(fe_pkt.dst_ip, fe_pkt.ip_family, fe_pkt.dst_ip_text, coarse_now_ns);
                if (ws && (rx_packets % packet_event_sample_rate) == 0u) {
                    ws_packet_event_t pe;
                    memset(&pe, 0, sizeof(pe));
                    pe.timestamp_ns = coarse_now_ns;
                    snprintf(pe.ip_family, sizeof(pe.ip_family), "%s", (fe_pkt.ip_family == 6) ? "ipv6" : "ipv4");
                    snprintf(pe.src_ip_text, sizeof(pe.src_ip_text), "%s", fe_pkt.src_ip_text);
                    snprintf(pe.dst_ip_text, sizeof(pe.dst_ip_text), "%s", fe_pkt.dst_ip_text);
                    pe.protocol = fe_pkt.protocol;
                    pe.src_port = fe_pkt.src_port;
                    pe.dst_port = fe_pkt.dst_port;
                    pe.packet_len = len;
                    ws_push_packet_event(ws, &pe);
                }
                fe_ingest_packet(fe, &fe_pkt);

                sentinel_feature_vector_t fv;
                if (fe_should_extract(fe, coarse_now_ns) && fe_extract_last(fe, &fv) == 0) {
                    fe_mark_extracted(fe, coarse_now_ns);
                    if (classifications_this_sec >= max_classifications_per_sec) {
                        skipped_classifications_this_sec++;
                        continue;
                    }
                    sentinel_threat_assessment_t assessment;
                    if (de_classify(de, &fv, &assessment, integration_flags.model_extension_enabled) == 0) {
                        g_last_feature_vector = fv;
                        g_has_last_feature_vector = 1;
                        g_last_chi_square_score = assessment.score_chi_square;
                        classifications_this_sec++;
                        threat_sum_10s += assessment.threat_score;
                        volume_sum_10s += assessment.score_volume;
                        entropy_sum_10s += assessment.score_entropy;
                        protocol_sum_10s += assessment.score_protocol;
                        behavioral_sum_10s += assessment.score_behavioral;
                        ml_sum_10s += assessment.score_ml;
                        l7_sum_10s += assessment.score_l7;
                        anomaly_sum_10s += assessment.score_anomaly;
                        chi_square_sum_10s += assessment.score_chi_square;
                        fanin_sum_10s += assessment.score_fanin;
                        signature_sum_10s += assessment.score_signature;
                        baseline_threat_sum_10s += assessment.baseline_threat_score;
                        classified_count_10s++;
                        if (assessment.ml_activated)
                            ml_activated_10s++;
                        if (assessment.verdict != VERDICT_ALLOW) {
                            detections_10s++;
                            int enforcing = atomic_load_explicit(&g_shared_state->auto_mitigation_enabled, memory_order_acquire);
                            sentinel_sdn_rule_t rule;
                            int sdn_push_rc = -1;
                            sdn_build_rule_from_assessment(sdn, &assessment, &rule);
                            if (enforcing) {
                                sdn_push_rc = sdn_push_rule(sdn, &rule);
                                    atomic_store_explicit(&g_shared_state->sdn_connected, (sdn_push_rc == 0) ? 1 : 0, memory_order_release);
                            }
                            maybe_run_controller_extension(&controller_extension, &assessment, &rule,
                                                           enforcing, sdn_push_rc, coarse_now_ns);

                            {
                                uint64_t ts_ns = coarse_now_ns;
                                if (enforcing && assessment.verdict == VERDICT_DROP) {
                                    atomic_fetch_add_explicit(&total_blocked, 1, memory_order_acq_rel);
                                    pipeline_blacklist_ip(blacklist_map_fd, assessment.src_ip, ts_ns);
                                    blocked_ips[blocked_head].ip = assessment.src_ip;
                                    blocked_ips[blocked_head].timestamp_added = ts_ns;
                                    blocked_ips[blocked_head].rule_id = rule.rule_id;
                                    blocked_ips[blocked_head].rate_limit_pps = 0;
                                    blocked_head = (blocked_head + 1) % TELEM_IP_MAX;
                                } else if (enforcing && assessment.verdict == VERDICT_RATE_LIMIT) {
                                    atomic_fetch_add_explicit(&total_rate_limited, 1, memory_order_acq_rel);
                                    rate_limited_ips[rate_limited_head].ip = assessment.src_ip;
                                    rate_limited_ips[rate_limited_head].timestamp_added = ts_ns;
                                    rate_limited_ips[rate_limited_head].rule_id = rule.rule_id;
                                    rate_limited_ips[rate_limited_head].rate_limit_pps = de_cfg.default_rate_limit;
                                    rate_limited_head = (rate_limited_head + 1) % TELEM_IP_MAX;
                                }
                            }

                            sentinel_flow_key_t fv_key = {
                                .src_ip = fv.src_ip, .dst_ip = fv.dst_ip,
                                .src_port = fv.src_port, .dst_port = fv.dst_port,
                                .protocol = fv.protocol
                            };
                            fe_writeback_threat(fe, &fv_key, assessment.threat_score);
                            fb_record_action(fb, assessment.src_ip, assessment.verdict,
                                            assessment.attack_type, assessment.threat_score);

                            if (ws) {
                                uint64_t current_head = atomic_load_explicit(&activity_ring_head, memory_order_relaxed);
                                uint64_t current_tail = atomic_load_explicit(&activity_ring_tail, memory_order_acquire);
                                
                                activity_raw_t *ar = &activity_ring[current_head % ACTIVITY_RING_SIZE];
                                ar->timestamp_ns = assessment.assessment_time_ns;
                                ar->src_ip = assessment.src_ip;
                                ar->verdict = assessment.verdict;
                                ar->attack_type = assessment.attack_type;
                                ar->threat_score = assessment.threat_score;
                                ar->confidence = assessment.confidence;
                                ar->score_ml = assessment.score_ml;
                                ar->ml_reliability = assessment.ml_reliability;
                                ar->enforced = enforcing;

                                if (current_head - current_tail >= ACTIVITY_RING_SIZE) {
                                    atomic_store_explicit(&activity_ring_tail, current_tail + 1, memory_order_release);
                                }
                                atomic_store_explicit(&activity_ring_head, current_head + 1, memory_order_release);
                            }
                        } else if (assessment.threat_score >= 0.20) {
                            uint64_t ts_ns = coarse_now_ns;
                            total_monitored++;
                            monitored_ips[monitored_head].ip = assessment.src_ip;
                            monitored_ips[monitored_head].timestamp_added = ts_ns;
                            monitored_ips[monitored_head].rule_id = 0;
                            monitored_ips[monitored_head].rate_limit_pps = 0;
                            monitored_head = (monitored_head + 1) % TELEM_IP_MAX;
                        }
                    }
                }
            }

            /* Return consumed frame addresses to FILL ring. */
            if (rcvd > 0) {
                xsk_ring_cons__release(&xsk->rx, rcvd);
                if (xsk->umem->fq.ring != NULL && n_refill > 0) {
                    __u32 prod = xsk->umem->fq.cached_prod;
                    for (int j = 0; j < n_refill; j++)
                        xsk->umem->fq.ring[(prod + j) & xsk->umem->fq.mask] = refill_addrs[j];
                    xsk->umem->fq.cached_prod = prod + (__u32)n_refill;
                    *xsk->umem->fq.producer = xsk->umem->fq.cached_prod;
                }
            }
        }
    }

    LOG_INFO("Shutting down %s Pipeline. Processed %llu packets.",
             use_raw_fallback ? "Raw Socket" : "AF_XDP",
             (unsigned long long)rx_packets);

    atomic_store_explicit(&feedback_shared.stop, 1, memory_order_release);
    if (feedback_thread_started)
        pthread_join(feedback_thread, NULL);
#if SENTINEL_LINUX_RUNTIME
    if (health_listener_started)
        pthread_join(health_listener_thread_id, NULL);
#endif
    if (ws) { ws_stop(ws); ws_destroy(ws); }
    if (blacklist_map_fd > 0) close(blacklist_map_fd);
    curl_global_cleanup();
    fb_destroy(fb);
    sdn_destroy(sdn);
    de_destroy(de);
    fe_destroy(fe);
    if (!use_raw_fallback) {
        if (xsk->umem && xsk->umem->fq.map != NULL && xsk->umem->fq_region_size > 0)
            munmap(xsk->umem->fq.map, xsk->umem->fq_region_size);
        if (xsk->rx.map != NULL && xsk->rx.map_size > 0)
            munmap(xsk->rx.map, xsk->rx.map_size);
        if (xsk->umem) {
            free_umem_frames(xsk->umem);
            free(xsk->umem);
        }
    }
    if (xsk->xsk_fd >= 0)
        close(xsk->xsk_fd);
    free(xsk);

    shared_state_destroy();

    return 0;
}


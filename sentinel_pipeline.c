/*
 * Sentinel DDoS Core - AF_XDP Pipeline Daemon
 *
 * Lockless, zero-copy packet pipeline.
 * Reads raw Ethernet frames directly from the NIC utilizing an AF_XDP 
 * User Memory (UMEM) ring-buffer. Bypasses the Linux kernel completely.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include "sentinel_core/platform_compat.h"

#ifdef __linux__
# include <sys/socket.h>
# include <sys/mman.h>
# include <sys/syscall.h>
# include <sys/times.h>
# include <linux/if_xdp.h>
# ifndef XDP_UMEM_PGOFF_FILL_RING
# define XDP_UMEM_PGOFF_FILL_RING 0x100000000ULL
# endif
# include <linux/if_link.h>
# include <linux/bpf.h>
# include <linux/if_packet.h>
# include <net/if.h>
# include <netinet/in.h>
# include <net/ethernet.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <arpa/inet.h>
#else
/* Non-Linux editor stubs for IDE/IntelliSense only; not used at runtime on Linux. */
# include "sentinel_pipeline_stubs.h"
#endif

#include "sentinel_core/sentinel_types.h"
#include "l1_native/feature_extractor.h"
#include "ml_engine/decision_engine.h"
#include "sdncontrol/sdn_controller.h"
#include "feedback/feedback.h"
#include "websocket/websocket_server.h"

/* ============================================================================
 * REAL SYSTEM METRICS (parse /proc)
 * ============================================================================ */

static double read_cpu_usage(void)
{
#ifdef __linux__
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
#ifdef __linux__
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
#ifdef __linux__
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

/* Feedback thread: lockless handoff; main loop must never call futex (no mutex). */
#define FEEDBACK_SLOTS 32
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

    /* Fallback: open from default pinned path (BPF FS) */
    {
        const char *pinned_path = "/sys/fs/bpf/xsks_map";
        union bpf_attr get_attr;
        memset(&get_attr, 0, sizeof(get_attr));
        get_attr.pathname = (uintptr_t)pinned_path;
        map_fd = bpf(BPF_OBJ_GET, &get_attr, sizeof(get_attr));
        if (map_fd >= 0)
            return map_fd;
    }

    return -1;
}

/* ============================================================================
 * GLOBALS & LOGGING
 * ============================================================================ */

static void sig_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        g_running = 0;
}

static void logmsg(const char *level, const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            ts.tv_nsec / 1000000, level);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
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

#define NUM_FRAMES         65536
#define FRAME_SIZE         2048
#define FRAME_SHIFT        11
#define FRAME_HEADROOM     256
#define UMEM_SIZE          ((uint64_t)NUM_FRAMES * (uint64_t)FRAME_SIZE)  /* UMEM bounds limit */
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

/* ============================================================================
 * PACKET PARSING (Raw L2 -> featureextractor metadata)
 * ============================================================================ */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

/* Hash IPv6 128-bit address to 32-bit for use in existing flow key (no full IPv6 key yet). */
static inline uint32_t hash_ipv6_to_32(const uint8_t *addr16)
{
    return fnv1a_hash(addr16, 16);
}

static int parse_raw_packet(const char *frame_data, uint32_t len, fe_packet_t *pkt, uint64_t pkt_id, uint64_t now_ns)
{
    if (len < sizeof(struct ether_header)) return -1;

    const struct ether_header *eth = (const struct ether_header *)frame_data;
    uint16_t ether_type = ntohs(eth->ether_type);
    const char *ip_start = frame_data + sizeof(struct ether_header);
    uint32_t ip_len = len - sizeof(struct ether_header);

    memset(pkt, 0, sizeof(*pkt));
    pkt->packet_id = pkt_id;
    pkt->direction = 0;
    pkt->timestamp_ns = now_ns;

    if (ether_type == ETHERTYPE_IP) {
        /* IPv4 */
        if (ip_len < sizeof(struct iphdr)) return -1;
        const struct iphdr *iph = (const struct iphdr *)ip_start;
        uint32_t ip_hdr_size = iph->ihl * 4;
        if (ip_hdr_size < sizeof(struct iphdr)) return -1;
        if (ip_len < ip_hdr_size) return -1;

        pkt->src_ip = iph->saddr;
        pkt->dst_ip = iph->daddr;
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
        pkt->src_ip = hash_ipv6_to_32(ip6 + 8);
        pkt->dst_ip = hash_ipv6_to_32(ip6 + 24);
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

/* 
 * AF_XDP socket and UMEM initialization.
 * This physically binds the userspace daemon to the NIC driver queue.
 */
static struct xsk_socket_info* configure_xsk(const char *ifname, int queue_id) {
    LOG_INFO("Binding AF_XDP zero-copy socket on %s queue %d", ifname, queue_id);
    
    struct xsk_socket_info *xsk = calloc(1, sizeof(struct xsk_socket_info));
    if (!xsk) return NULL;

    xsk->umem = calloc(1, sizeof(struct xdp_umem));
    if (!xsk->umem) { free(xsk); return NULL; }

    /* 1. Allocate hugepage or page-aligned memory for UMEM (Zero-Copy frame storage) */
    void *bufs = NULL;
    if (posix_memalign(&bufs, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        LOG_ERROR("Failed to allocate AF_XDP UMEM memory");
        free(xsk->umem);
        free(xsk);
        return NULL;
    }
    xsk->umem->frames = bufs;

    /* 2. Create the AF_XDP Socket (Inode descriptor) */
    xsk->xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->xsk_fd < 0) {
        LOG_WARN("AF_XDP socket creation failed (Requires root/capabilities or newer kernel)");
        free(bufs);
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
        free(bufs);
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
        free(bufs);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_RX_RING, &rx_size, sizeof(int)) < 0) {
        LOG_CRITICAL("AF_XDP setsockopt XDP_RX_RING failed.");
        close(xsk->xsk_fd);
        free(bufs);
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
        free(bufs);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }
    sxdp.sxdp_queue_id = queue_id;
    sxdp.sxdp_flags = 0;

    if (bind(xsk->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        LOG_CRITICAL("AF_XDP physical NIC bind failed.");
        close(xsk->xsk_fd);
        free(bufs);
        free(xsk->umem);
        free(xsk);
        return NULL;
    }

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
            free(bufs);
            free(xsk->umem);
            free(xsk);
            return NULL;
        }
    } else {
        LOG_CRITICAL("AF_XDP getsockopt MMAP_OFFSETS failed.");
        close(xsk->xsk_fd);
        free(bufs);
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
            free(bufs);
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

/* Insert an IP into the kernel BPF blacklist map. IP is converted to Net Order. */
static void pipeline_blacklist_ip(int map_fd, uint32_t src_ip_host_order, uint64_t timestamp_ns)
{
    if (map_fd < 0) return;
    uint32_t key = htonl(src_ip_host_order);
    bpf_map_update_elem(map_fd, &key, &timestamp_ns, 0);
}

/* Remove an IP from the kernel BPF blacklist map. */
static void pipeline_unblacklist_ip(int map_fd, uint32_t src_ip_host_order)
{
    if (map_fd < 0) return;
    uint32_t key = htonl(src_ip_host_order);
    (void)bpf_map_delete_elem(map_fd, &key);
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

typedef struct { de_context_t *de; ws_context_t *ws; } ws_cmd_ctx_t;
static ws_cmd_ctx_t ws_cmd_ctx_storage;
static _Atomic int g_auto_mitigation_enabled = 1;
static _Atomic int g_sdn_connected = -1;  /* -1=never probed, 0=last push failed, 1=last push ok */

static sentinel_feature_vector_t g_last_feature_vector;
static int g_has_last_feature_vector = 0;

/* Convert sentinel_feature_vector_t to 20 raw doubles (same order as ml_model.h / SHAP API) */
static void fv_to_raw_vector(const sentinel_feature_vector_t *f, ws_raw_feature_vector_t *out)
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
}

/* Pending clear_rate_limit: main loop processes, cmd handler sets */
#define CLEARED_RATE_LIMIT_MAX 64
static _Atomic uint32_t g_pending_clear_rate_limit_ip = 0;
static _Atomic int g_pending_clear_rate_limit = 0;
static uint32_t g_cleared_rate_limits[CLEARED_RATE_LIMIT_MAX];
static int g_cleared_rate_limit_count = 0;

/* Global blacklist map FD for WebSocket command handler (block_ip) */
static int g_blacklist_map_fd = -1;

/* Pending unblock_ip, block_all_flagged, clear_all_blocks: main loop processes, cmd handler sets */
static _Atomic int g_has_pending_unblock_ip = 0;
static _Atomic uint32_t g_pending_unblock_ip = 0;
static _Atomic int g_pending_block_all = 0;
static _Atomic int g_pending_clear_all = 0;

static void ws_pipeline_cmd_handler(const char *cmd, const char *arg, void *udata) {
    ws_cmd_ctx_t *c = (ws_cmd_ctx_t *)udata;
    if (!c || !c->de || !cmd) return;

    struct in_addr ia;

    if (strcmp(cmd, "block_ip") == 0 && arg && inet_pton(AF_INET, arg, &ia) == 1) {
        de_add_denylist(c->de, ia.s_addr);
        if (g_blacklist_map_fd >= 0) {
            uint64_t ts = (uint64_t)time(NULL) * 1000000000ULL;
            pipeline_blacklist_ip(g_blacklist_map_fd, ia.s_addr, ts);
        }
        LOG_INFO("[WS-CMD] block_ip %s", arg);
    }
    else if (strcmp(cmd, "unblock_ip") == 0 && arg && inet_pton(AF_INET, arg, &ia) == 1) {
        de_remove_denylist(c->de, ia.s_addr);
        atomic_store_explicit(&g_pending_unblock_ip, ia.s_addr, memory_order_release);
        atomic_store_explicit(&g_has_pending_unblock_ip, 1, memory_order_release);
        LOG_INFO("[WS-CMD] unblock_ip %s", arg);
    }
    else if (strcmp(cmd, "whitelist_ip") == 0 && arg && inet_pton(AF_INET, arg, &ia) == 1) {
        de_add_allowlist(c->de, ia.s_addr);
        LOG_INFO("[WS-CMD] whitelist_ip %s", arg);
    }
    else if (strcmp(cmd, "remove_whitelist") == 0 && arg && inet_pton(AF_INET, arg, &ia) == 1) {
        de_remove_allowlist(c->de, ia.s_addr);
        LOG_INFO("[WS-CMD] remove_whitelist %s", arg);
    }
    else if (strcmp(cmd, "block_all_flagged") == 0) {
        atomic_store_explicit(&g_pending_block_all, 1, memory_order_release);
        LOG_INFO("[WS-CMD] block_all_flagged — will take effect on next telemetry cycle");
    }
    else if (strcmp(cmd, "clear_all_blocks") == 0) {
        atomic_store_explicit(&g_pending_clear_all, 1, memory_order_release);
        LOG_INFO("[WS-CMD] clear_all_blocks");
    }
    else if (strcmp(cmd, "apply_rate_limit") == 0) {
        de_set_global_rate_limit(c->de, 0.40, 0.70);
        LOG_INFO("[WS-CMD] apply_rate_limit — thresholds set to 0.40/0.70");
    }
    else if (strcmp(cmd, "enable_monitoring") == 0) {
        LOG_INFO("[WS-CMD] enable_monitoring — enhanced monitoring enabled");
    }
    else if (strcmp(cmd, "enable_auto_mitigation") == 0) {
        atomic_store_explicit(&g_auto_mitigation_enabled, 1, memory_order_release);
        LOG_INFO("[WS-CMD] enable_auto_mitigation");
    }
    else if (strcmp(cmd, "disable_auto_mitigation") == 0) {
        atomic_store_explicit(&g_auto_mitigation_enabled, 0, memory_order_release);
        LOG_INFO("[WS-CMD] disable_auto_mitigation");
    }
    else if (strcmp(cmd, "clear_rate_limit") == 0 && arg && inet_pton(AF_INET, arg, &ia) == 1) {
        atomic_store_explicit(&g_pending_clear_rate_limit_ip, ia.s_addr, memory_order_release);
        atomic_store_explicit(&g_pending_clear_rate_limit, 1, memory_order_release);
        LOG_INFO("[WS-CMD] clear_rate_limit %s", arg);
    }
    else if (strcmp(cmd, "simulate_ddos") == 0 && c->ws) {
        ws_activity_t wa;
        wa.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
        wa.src_ip = htonl(0xC0A80101);  /* 192.168.1.1 */
        wa.threat_score = 0.92;
        wa.enforced = 0;
        snprintf(wa.action, sizeof(wa.action), "DETECTED");
        snprintf(wa.attack_type, sizeof(wa.attack_type), "SYN_FLOOD");
        snprintf(wa.reason, sizeof(wa.reason), "[SIMULATED] score=0.920 conf=0.95 ml=0.88 rel=0.90");
        ws_push_activity(c->ws, &wa);
        LOG_INFO("[WS-CMD] simulate_ddos — injected synthetic activity");
    }
    else if (strcmp(cmd, "simulate_flash_crowd") == 0 && c->ws) {
        ws_activity_t wa;
        wa.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
        wa.src_ip = htonl(0xC0A80102);  /* 192.168.1.2 */
        wa.threat_score = 0.45;
        wa.enforced = 0;
        snprintf(wa.action, sizeof(wa.action), "MONITOR");
        snprintf(wa.attack_type, sizeof(wa.attack_type), "NONE");
        snprintf(wa.reason, sizeof(wa.reason), "[SIMULATED] Flash crowd — score=0.450 conf=0.70 ml=0.35 rel=0.80");
        ws_push_activity(c->ws, &wa);
        LOG_INFO("[WS-CMD] simulate_flash_crowd — injected synthetic activity");
    }
    else if (strcmp(cmd, "set_syn_threshold") == 0 && arg) {
        double v = strtod(arg, NULL);
        de_set_syn_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_syn_threshold %s", arg);
    }
    else if (strcmp(cmd, "set_conn_threshold") == 0 && arg) {
        double v = strtod(arg, NULL);
        de_set_flow_count_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_conn_threshold %s", arg);
    }
    else if (strcmp(cmd, "set_pps_threshold") == 0 && arg) {
        double v = strtod(arg, NULL);
        de_set_pps_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_pps_threshold %s", arg);
    }
    else if (strcmp(cmd, "set_entropy_threshold") == 0 && arg) {
        double v = strtod(arg, NULL);
        de_set_entropy_threshold(c->de, v);
        LOG_INFO("[WS-CMD] set_entropy_threshold %s", arg);
    }
    else {
        LOG_WARN("[WS-CMD] Unknown command: %s (arg: %s)", cmd, arg ? arg : "none");
    }
}

int main(int argc, char **argv)
{
    const char *ifname = "eth0";
    int queue_id = 0;
    uint16_t ws_port = 0;
    char *controller_url = NULL;
    uint64_t dpid = 1;
    int verbose = 0;
    int opt;

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
    LOG_INFO("Binding to interface: %s, queue: %d", ifname, queue_id);
    if (verbose)
        LOG_INFO("Verbose mode enabled");

    /* TIER-1: CPU Core Pinning (Pin to Core 1 to prevent cache invalidation) */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == 0) {
        LOG_INFO("Successfully pinned process to CPU Core 1");
    } else {
        LOG_WARN("Failed to pin process to CPU Core 1 (Requires CAP_SYS_NICE or root)");
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
    if (ws_port > 0) {
        ws_config_t ws_cfg = WS_CONFIG_DEFAULT;
        ws_cfg.port = ws_port;
        ws = ws_init(&ws_cfg);
        if (ws && ws_start(ws) == 0) {
            LOG_INFO("WebSocket telemetry on port %u", (unsigned)ws_port);
            /* Register command handler so browser Quick Actions reach the decision engine */
            ws_cmd_ctx_storage.de = de;
            ws_cmd_ctx_storage.ws = ws;
            ws_set_command_callback(ws, ws_pipeline_cmd_handler, &ws_cmd_ctx_storage);
        }
        else if (ws) {
            ws_destroy(ws);
            ws = NULL;
        }
    }

    struct xsk_socket_info *xsk = configure_xsk(ifname, queue_id);
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
    }
    uint64_t rx_packets = 0;
    uint64_t last_rx_for_metrics = 0;
    uint64_t coarse_now_ns = 0;  /* heartbeat: every 128 packets for <10us jitter at 14.88Mpps */
    {
        struct timespec ts0;
        if (clock_gettime(CLOCK_MONOTONIC, &ts0) == 0)
            coarse_now_ns = (uint64_t)ts0.tv_sec * 1000000000ULL + ts0.tv_nsec;
    }
    uint32_t classifications_this_sec = 0;

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
    if (pthread_create(&feedback_thread, NULL, feedback_worker, feedback_thread_arg) != 0) {
        LOG_WARN("Feedback thread create failed; running without background adjustments.");
    } else {
        feedback_thread_started = 1;
    }

    time_t last_gc = time(NULL);
    time_t last_metrics = time(NULL);
    time_t last_top_sources = time(NULL);
    time_t last_feature_importance = time(NULL);
    time_t last_feedback = time(NULL);

#define TELEM_IP_MAX 128
#define ACTIVITY_RING_SIZE 256   /* Pre-allocated ring: primitives only; no snprintf in hot path */
    ws_ip_entry_t blocked_ips[TELEM_IP_MAX];
    ws_ip_entry_t rate_limited_ips[TELEM_IP_MAX];
    ws_ip_entry_t monitored_ips[TELEM_IP_MAX];
    ws_ip_entry_t whitelisted_ips[TELEM_IP_MAX];
    uint32_t blocked_head = 0, rate_limited_head = 0, monitored_head = 0;  /* cyclic ring write index */
    uint32_t total_blocked = 0, total_rate_limited = 0, total_monitored = 0;
    uint32_t detections_10s = 0;
    double threat_sum_10s = 0.0;
    uint32_t threat_count_10s = 0;

    activity_raw_t activity_ring[ACTIVITY_RING_SIZE];
    uint32_t activity_ring_head = 0;  /* next write */
    uint32_t activity_ring_tail = 0;   /* next read (drain in 1s block) */

    uint64_t period_tcp_pkts = 0, period_udp_pkts = 0, period_icmp_pkts = 0, period_other_pkts = 0;
    uint64_t period_tcp_bytes = 0, period_udp_bytes = 0, period_icmp_bytes = 0, period_other_bytes = 0;
    uint64_t period_bytes_total = 0;

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
            if (evicted > 0) LOG_INFO("GC: Evicted %d stale flows", evicted);
            last_gc = now;
        }

        /* Telemetry: 1s metrics, traffic_rate, protocol_dist, mitigation_status */
        if (ws && now - last_metrics >= 1) {
            ws_metrics_t wm;
            wm.packets_per_sec = rx_packets - last_rx_for_metrics;
            wm.bytes_per_sec = period_bytes_total;
            wm.active_flows = fe_active_flows(fe);
            wm.active_sources = fe_active_sources(fe);
            wm.ml_classifications_per_sec = classifications_this_sec;
            wm.cpu_usage_percent = read_cpu_usage();
            wm.memory_usage_mb = read_mem_usage();
            wm.kernel_drops = total_blocked;
            wm.userspace_drops = total_rate_limited;
            ws_update_metrics(ws, &wm);

            ws_traffic_rate_t tr;
            tr.total_pps = period_tcp_pkts + period_udp_pkts + period_icmp_pkts + period_other_pkts;
            tr.total_bps = period_bytes_total * 8;
            tr.tcp_pps = period_tcp_pkts;
            tr.udp_pps = period_udp_pkts;
            tr.icmp_pps = period_icmp_pkts;
            tr.other_pps = period_other_pkts;
            ws_update_traffic_rate(ws, &tr);

            uint64_t total_p = tr.total_pps;
            ws_protocol_dist_t pd;
            pd.tcp_bytes = period_tcp_bytes;
            pd.udp_bytes = period_udp_bytes;
            pd.icmp_bytes = period_icmp_bytes;
            pd.other_bytes = period_other_bytes;
            if (total_p > 0) {
                pd.tcp_percent = 100.0 * (double)period_tcp_pkts / total_p;
                pd.udp_percent = 100.0 * (double)period_udp_pkts / total_p;
                pd.icmp_percent = 100.0 * (double)period_icmp_pkts / total_p;
                pd.other_percent = 100.0 * (double)period_other_pkts / total_p;
            } else {
                pd.tcp_percent = pd.udp_percent = pd.icmp_percent = pd.other_percent = 0.0;
            }
            ws_update_protocol_dist(ws, &pd);

            /* Active connections telemetry from top active flows. */
            {
                fe_top_flow_t top_flows[10];
                ws_connection_t conns[10];
                uint32_t nc = fe_get_top_flows(fe, top_flows, 10);
                for (uint32_t i = 0; i < nc; i++) {
                    conns[i].src_ip = top_flows[i].key.src_ip;
                    conns[i].dst_ip = top_flows[i].key.dst_ip;
                    conns[i].src_port = top_flows[i].key.src_port;
                    conns[i].dst_port = top_flows[i].key.dst_port;
                    conns[i].protocol = top_flows[i].key.protocol;
                    conns[i].packets = top_flows[i].packets;
                    conns[i].bytes = top_flows[i].bytes;
                    conns[i].last_seen_ns = top_flows[i].last_seen_ns;
                }
                ws_update_connections(ws, conns, nc);
            }

            ws_mitigation_status_t ms;
            memset(&ms, 0, sizeof(ms));
            ms.total_blocked = total_blocked;
            ms.total_rate_limited = total_rate_limited;
            ms.total_monitored = total_monitored;
            ms.total_whitelisted = n_whitelist_static;
            ms.kernel_verdict_cache_hits = 0;
            ms.kernel_verdict_cache_misses = 0;
            ms.active_sdn_rules = (total_blocked > TELEM_IP_MAX ? TELEM_IP_MAX : total_blocked)
                + (total_rate_limited > TELEM_IP_MAX ? TELEM_IP_MAX : total_rate_limited);
            ms.auto_mitigation_enabled = atomic_load_explicit(&g_auto_mitigation_enabled, memory_order_acquire);
            ms.kernel_dropping_enabled = (blacklist_map_fd > 0) ? 1 : 0;
            ms.sdn_connected = atomic_load_explicit(&g_sdn_connected, memory_order_acquire);
            sdn_get_last_error(sdn, ms.sdn_last_error, sizeof(ms.sdn_last_error));
            ws_update_mitigation_status(ws, &ms);

            /* Process pending clear_rate_limit from WebSocket command */
            if (atomic_exchange_explicit(&g_pending_clear_rate_limit, 0, memory_order_acquire)) {
                uint32_t ip = atomic_load_explicit(&g_pending_clear_rate_limit_ip, memory_order_relaxed);
                sdn_remove_rules_for_src(sdn, ip);
                if (g_cleared_rate_limit_count < CLEARED_RATE_LIMIT_MAX) {
                    g_cleared_rate_limits[g_cleared_rate_limit_count++] = ip;
                }
            }

            /* Process pending unblock_ip: remove from eBPF blacklist map */
            if (atomic_exchange_explicit(&g_has_pending_unblock_ip, 0, memory_order_acquire)) {
                uint32_t ip = atomic_load_explicit(&g_pending_unblock_ip, memory_order_relaxed);
                pipeline_unblacklist_ip(blacklist_map_fd, ip);
                LOG_INFO("[PIPELINE] unblock_ip: removed from kernel blacklist");
            }

            /* Process pending block_all_flagged: move monitored IPs to blocklist */
            if (atomic_exchange_explicit(&g_pending_block_all, 0, memory_order_acquire)) {
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
                        total_blocked++;
                    }
                }
                total_monitored = 0;
                monitored_head = 0;
                LOG_INFO("[PIPELINE] block_all_flagged: blocked %u monitored IP(s)", (unsigned)n_mon);
            }

            /* Process pending clear_all_blocks: flush eBPF map, clear denylist, reset counters */
            if (atomic_exchange_explicit(&g_pending_clear_all, 0, memory_order_acquire)) {
                uint32_t n_blocked = (total_blocked < TELEM_IP_MAX) ? total_blocked : TELEM_IP_MAX;
                uint32_t n_rl = (total_rate_limited < TELEM_IP_MAX) ? total_rate_limited : TELEM_IP_MAX;
                uint32_t blocked_start = (total_blocked >= TELEM_IP_MAX) ? blocked_head : 0;
                uint32_t rl_start = (total_rate_limited >= TELEM_IP_MAX) ? rate_limited_head : 0;
                for (uint32_t i = 0; i < n_blocked; i++)
                    sdn_remove_rules_for_src(sdn, blocked_ips[(blocked_start + i) % TELEM_IP_MAX].ip);
                for (uint32_t i = 0; i < n_rl; i++)
                    sdn_remove_rules_for_src(sdn, rate_limited_ips[(rl_start + i) % TELEM_IP_MAX].ip);
                pipeline_clear_blacklist_map(blacklist_map_fd);
                de_clear_denylist(de);
                total_blocked = 0;
                blocked_head = 0;
                total_rate_limited = 0;
                rate_limited_head = 0;
                g_cleared_rate_limit_count = 0;
                LOG_INFO("[PIPELINE] clear_all_blocks: kernel map and denylist cleared");
            }

            /* Out-of-band: blocked/rate_limited IPs (JSON serialization here, not in packet path) */
            {
                ws_ip_entry_t blocked_ordered[TELEM_IP_MAX], rate_limited_ordered[TELEM_IP_MAX];
                ws_ip_entry_t monitored_ordered[TELEM_IP_MAX];
                uint32_t blocked_count = (total_blocked < TELEM_IP_MAX) ? total_blocked : TELEM_IP_MAX;
                uint32_t rate_limited_count = (total_rate_limited < TELEM_IP_MAX) ? total_rate_limited : TELEM_IP_MAX;
                uint32_t monitored_count = (total_monitored < TELEM_IP_MAX) ? total_monitored : TELEM_IP_MAX;
                uint32_t whitelist_count = (n_whitelist_static < TELEM_IP_MAX) ? n_whitelist_static : TELEM_IP_MAX;
                uint32_t blocked_start = (total_blocked >= TELEM_IP_MAX) ? blocked_head : 0;
                uint32_t rate_limited_start = (total_rate_limited >= TELEM_IP_MAX) ? rate_limited_head : 0;
                uint32_t monitored_start = (total_monitored >= TELEM_IP_MAX) ? monitored_head : 0;
                for (uint32_t i = 0; i < blocked_count; i++) {
                    blocked_ordered[i] = blocked_ips[(blocked_start + i) % TELEM_IP_MAX];
                }
                uint32_t rl_out = 0;
                for (uint32_t i = 0; i < rate_limited_count && rl_out < TELEM_IP_MAX; i++) {
                    ws_ip_entry_t e = rate_limited_ips[(rate_limited_start + i) % TELEM_IP_MAX];
                    int cleared = 0;
                    for (int j = 0; j < g_cleared_rate_limit_count; j++) {
                        if (g_cleared_rate_limits[j] == e.ip) { cleared = 1; break; }
                    }
                    if (!cleared) rate_limited_ordered[rl_out++] = e;
                }
                rate_limited_count = rl_out;
                for (uint32_t i = 0; i < monitored_count; i++) {
                    monitored_ordered[i] = monitored_ips[(monitored_start + i) % TELEM_IP_MAX];
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
            period_tcp_pkts = period_udp_pkts = period_icmp_pkts = period_other_pkts = 0;
            period_tcp_bytes = period_udp_bytes = period_icmp_bytes = period_other_bytes = 0;
            period_bytes_total = 0;
        }

        /* Telemetry: 5s – top_sources with real-time ML classification */
        if (ws && now - last_top_sources >= 5) {
            fe_top_source_t top[10];
            uint32_t n = fe_get_top_sources(fe, top, 10);
            if (n > 0) {
                ws_top_source_t ws_top[10];
                sentinel_feature_vector_t fv;
                sentinel_threat_assessment_t assessment;
                for (uint32_t k = 0; k < n; k++) {
                    ws_top[k].src_ip = top[k].src_ip;
                    ws_top[k].packets = top[k].packets;
                    ws_top[k].bytes = top[k].bytes;
                    ws_top[k].flow_count = top[k].flow_count;
                    ws_top[k].suspicious = 0;
                    ws_top[k].threat_score = 0.0;
                    if (fe_extract_source(fe, top[k].src_ip, &fv) == 0 &&
                        de_classify(de, &fv, &assessment) == 0) {
                        ws_top[k].threat_score = assessment.threat_score;
                        ws_top[k].suspicious = (assessment.verdict != VERDICT_ALLOW) ? 1 : 0;
                    }
                }
                ws_update_top_sources(ws, ws_top, n);
            }
            last_top_sources = now;
        }

        /* Telemetry: 10s – feature_importance (from de_get_thresholds) */
        if (ws && now - last_feature_importance >= 10) {
            const de_thresholds_t *dt = de_get_thresholds(de);
            if (dt) {
                ws_feature_importance_t wi;
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
                wi.avg_threat_score = (threat_count_10s > 0)
                    ? (threat_sum_10s / (double)threat_count_10s)
                    : 0.0;
                wi.detections_last_10s = detections_10s;
                wi.policy_arm = ps.active_arm;
                wi.policy_updates = ps.update_count;
                wi.policy_last_reward = ps.last_reward;
                ws_update_feature_importance(ws, &wi);
            }
            if (ws && g_has_last_feature_vector) {
                ws_raw_feature_vector_t raw_vec;
                fv_to_raw_vector(&g_last_feature_vector, &raw_vec);
                ws_update_feature_vector(ws, &raw_vec);
            }
            detections_10s = 0;
            threat_sum_10s = 0.0;
            threat_count_10s = 0;
            last_feature_importance = now;
        }

        /* 60s: producer writes only when consumer has consumed (work_ready==0); no torn read. */
        if (now - last_feedback >= 60 &&
            atomic_load_explicit(&feedback_shared.work_ready, memory_order_acquire) == 0) {
            fe_top_source_t top[FEEDBACK_SLOTS];
            uint32_t n = fe_get_top_sources(fe, top, FEEDBACK_SLOTS);
            uint32_t filled = 0;
            int w = feedback_write_idx;
            for (uint32_t k = 0; k < n && filled < FEEDBACK_SLOTS; k++) {
                sentinel_feature_vector_t fv;
                sentinel_threat_assessment_t assessment;
                if (fe_extract_source(fe, top[k].src_ip, &fv) == 0 &&
                    de_classify(de, &fv, &assessment) == 0) {
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

            /* Per-protocol counters for telemetry (1s traffic_rate / protocol_dist) */
            if (fe_pkt.protocol == IPPROTO_TCP) { period_tcp_pkts++; period_tcp_bytes += len; }
            else if (fe_pkt.protocol == IPPROTO_UDP) { period_udp_pkts++; period_udp_bytes += len; }
            else if (fe_pkt.protocol == IPPROTO_ICMP) { period_icmp_pkts++; period_icmp_bytes += len; }
            else { period_other_pkts++; period_other_bytes += len; }
            period_bytes_total += len;

            fe_ingest_packet(fe, &fe_pkt);

            sentinel_feature_vector_t fv;
            if (fe_should_extract(fe, coarse_now_ns) && fe_extract_last(fe, &fv) == 0) {
                fe_mark_extracted(fe, coarse_now_ns);
                sentinel_threat_assessment_t assessment;
                if (de_classify(de, &fv, &assessment) == 0) {
                    g_last_feature_vector = fv;
                    g_has_last_feature_vector = 1;
                    classifications_this_sec++;
                    threat_sum_10s += assessment.threat_score;
                    threat_count_10s++;
                    if (assessment.verdict != VERDICT_ALLOW) {
                        detections_10s++;
                        int enforcing = atomic_load_explicit(&g_auto_mitigation_enabled, memory_order_acquire);
                        sentinel_sdn_rule_t rule;
                        sdn_build_rule_from_assessment(sdn, &assessment, &rule);
                        if (enforcing) {
                            int rc = sdn_push_rule(sdn, &rule);
                            atomic_store_explicit(&g_sdn_connected, (rc == 0) ? 1 : 0, memory_order_release);
                        }

                        {
                            uint64_t ts_ns = coarse_now_ns;
                            if (enforcing && assessment.verdict == VERDICT_DROP) {
                                total_blocked++;
                                pipeline_blacklist_ip(blacklist_map_fd, assessment.src_ip, ts_ns);
                                blocked_ips[blocked_head].ip = assessment.src_ip;
                                blocked_ips[blocked_head].timestamp_added = ts_ns;
                                blocked_ips[blocked_head].rule_id = rule.rule_id;
                                blocked_ips[blocked_head].rate_limit_pps = 0;
                                blocked_head = (blocked_head + 1) % TELEM_IP_MAX;
                            } else if (enforcing && assessment.verdict == VERDICT_RATE_LIMIT) {
                                total_rate_limited++;
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
                            activity_raw_t *ar = &activity_ring[activity_ring_head % ACTIVITY_RING_SIZE];
                            ar->timestamp_ns = assessment.assessment_time_ns;
                            ar->src_ip = assessment.src_ip;
                            ar->verdict = assessment.verdict;
                            ar->attack_type = assessment.attack_type;
                            ar->threat_score = assessment.threat_score;
                            ar->confidence = assessment.confidence;
                            ar->score_ml = assessment.score_ml;
                            ar->ml_reliability = assessment.ml_reliability;
                            ar->enforced = enforcing;
                            if (activity_ring_head - activity_ring_tail >= ACTIVITY_RING_SIZE)
                                activity_ring_tail++;
                            activity_ring_head++;
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

                if (fe_pkt.protocol == IPPROTO_TCP) { period_tcp_pkts++; period_tcp_bytes += len; }
                else if (fe_pkt.protocol == IPPROTO_UDP) { period_udp_pkts++; period_udp_bytes += len; }
                else if (fe_pkt.protocol == IPPROTO_ICMP) { period_icmp_pkts++; period_icmp_bytes += len; }
                else { period_other_pkts++; period_other_bytes += len; }
                period_bytes_total += len;

                fe_ingest_packet(fe, &fe_pkt);

                sentinel_feature_vector_t fv;
                if (fe_should_extract(fe, coarse_now_ns) && fe_extract_last(fe, &fv) == 0) {
                    fe_mark_extracted(fe, coarse_now_ns);
                    sentinel_threat_assessment_t assessment;
                    if (de_classify(de, &fv, &assessment) == 0) {
                        g_last_feature_vector = fv;
                        g_has_last_feature_vector = 1;
                        classifications_this_sec++;
                        threat_sum_10s += assessment.threat_score;
                        threat_count_10s++;
                        if (assessment.verdict != VERDICT_ALLOW) {
                            detections_10s++;
                            int enforcing = atomic_load_explicit(&g_auto_mitigation_enabled, memory_order_acquire);
                            sentinel_sdn_rule_t rule;
                            sdn_build_rule_from_assessment(sdn, &assessment, &rule);
                            if (enforcing) {
                                int rc = sdn_push_rule(sdn, &rule);
                                atomic_store_explicit(&g_sdn_connected, (rc == 0) ? 1 : 0, memory_order_release);
                            }

                            {
                                uint64_t ts_ns = coarse_now_ns;
                                if (enforcing && assessment.verdict == VERDICT_DROP) {
                                    total_blocked++;
                                    pipeline_blacklist_ip(blacklist_map_fd, assessment.src_ip, ts_ns);
                                    blocked_ips[blocked_head].ip = assessment.src_ip;
                                    blocked_ips[blocked_head].timestamp_added = ts_ns;
                                    blocked_ips[blocked_head].rule_id = rule.rule_id;
                                    blocked_ips[blocked_head].rate_limit_pps = 0;
                                    blocked_head = (blocked_head + 1) % TELEM_IP_MAX;
                                } else if (enforcing && assessment.verdict == VERDICT_RATE_LIMIT) {
                                    total_rate_limited++;
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
                                activity_raw_t *ar = &activity_ring[activity_ring_head % ACTIVITY_RING_SIZE];
                                ar->timestamp_ns = assessment.assessment_time_ns;
                                ar->src_ip = assessment.src_ip;
                                ar->verdict = assessment.verdict;
                                ar->attack_type = assessment.attack_type;
                                ar->threat_score = assessment.threat_score;
                                ar->confidence = assessment.confidence;
                                ar->score_ml = assessment.score_ml;
                                ar->ml_reliability = assessment.ml_reliability;
                                ar->enforced = enforcing;
                                if (activity_ring_head - activity_ring_tail >= ACTIVITY_RING_SIZE)
                                    activity_ring_tail++;
                                activity_ring_head++;
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

    if (ws) { ws_stop(ws); ws_destroy(ws); }
    if (blacklist_map_fd > 0) close(blacklist_map_fd);
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
            free(xsk->umem->frames);
            free(xsk->umem);
        }
    }
    if (xsk->xsk_fd >= 0)
        close(xsk->xsk_fd);
    free(xsk);

    return 0;
}

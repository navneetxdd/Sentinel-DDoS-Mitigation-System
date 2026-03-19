/*
 * Sentinel DDoS Core - WebSocket Server Implementation
 *
 * Lightweight WebSocket server using POSIX sockets + HTTP upgrade.
 * Broadcasts JSON data to all connected clients.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <endian.h>
#include <openssl/sha.h>
#include <stdatomic.h>

#include "websocket_server.h"
#include "../sentinel_core/platform_compat.h"

/* Simple WebSocket implementation */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_FRAME_SIZE (64 * 1024)

/* WebSocket opcodes */
#define WS_OPCODE_TEXT   0x1
#define WS_OPCODE_CLOSE  0x8
#define WS_OPCODE_PING   0x9
#define WS_OPCODE_PONG   0xA

/* ============================================================================
 * CLIENT STATE
 * ============================================================================ */

#define WS_OUT_BUF_SIZE (128 * 1024)  /* 128KB per client buffer */

#define WS_CMD_RATE_LIMIT_PER_SEC 10

typedef struct ws_client {
    int      fd;
    int      handshake_done;
    time_t   connect_time;
    time_t   last_ping;
    time_t   cmd_window_sec;   /* rate limit: window start */
    int      cmd_count;       /* commands in current 1s window */
    char     remote_addr[64];
    /* Non-blocking write buffer */
    unsigned char out_buf[WS_OUT_BUF_SIZE];
    size_t   out_len;
} ws_client_t;

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

#define MAX_PENDING_MESSAGES 1000

typedef enum {
    WS_MSG_TYPE_METRICS,
    WS_MSG_TYPE_ACTIVITY,
    WS_MSG_TYPE_IP_LIST_BLOCKED,
    WS_MSG_TYPE_IP_LIST_RATE_LIMITED,
    WS_MSG_TYPE_IP_LIST_MONITORED,
    WS_MSG_TYPE_IP_LIST_WHITELISTED,
    WS_MSG_TYPE_TRAFFIC_RATE,
    WS_MSG_TYPE_PROTOCOL_DIST,
    WS_MSG_TYPE_TOP_SOURCES,
    WS_MSG_TYPE_FEATURE_IMPORTANCE,
    WS_MSG_TYPE_FEATURE_VECTOR,
    WS_MSG_TYPE_CONNECTIONS,
    WS_MSG_TYPE_MITIGATION_STATUS,
    WS_MSG_TYPE_INTEGRATION_STATUS,
    WS_MSG_TYPE_COMMAND_RESULT
} ws_msg_type_t;

#define MAX_IP_LIST_BATCH 128
#define MAX_TOP_SOURCES_BATCH 10
#define MAX_CONNECTIONS_BATCH 10
/* Cap entries per JSON message so 16KB buf_local never overflows (avoids silent drop). */
#define WS_MAX_JSON_IP_ENTRIES  64
#define WS_MAX_JSON_TOP_SOURCES 32
#define WS_MAX_JSON_CONNECTIONS 64

typedef struct ws_raw_msg {
    ws_msg_type_t type;
    union {
        ws_metrics_t metrics;
        ws_activity_t activity;
        struct {
            ws_ip_entry_t entries[MAX_IP_LIST_BATCH];
            uint32_t count;
        } ip_list;
        ws_traffic_rate_t traffic_rate;
        ws_protocol_dist_t protocol_dist;
        struct {
            ws_top_source_t sources[MAX_TOP_SOURCES_BATCH];
            uint32_t count;
        } top_sources;
        ws_feature_importance_t feature_importance;
        ws_raw_feature_vector_t feature_vector;
        struct {
            ws_connection_t conns[MAX_CONNECTIONS_BATCH];
            uint32_t count;
        } connections;
        ws_mitigation_status_t mitigation_status;
        ws_integration_status_t integration_status;
        ws_command_result_t command_result;
    } data;
} ws_raw_msg_t;

struct ws_context {
    ws_config_t      cfg;
    int              listen_fd;
    pthread_t        thread;
    atomic_int       running;
    
    /* Client management */
    ws_client_t      clients[100];
    int              client_count;
    pthread_mutex_t  client_mutex;
    
    /* Message queue (SPSC; primitives only, no malloc in producer) */
    ws_raw_msg_t      messages[MAX_PENDING_MESSAGES];
    atomic_uint       msg_head;
    atomic_uint       msg_tail;
    
    /* Command callback (browser -> pipeline) */
    ws_command_cb_t   cmd_cb;
    void             *cmd_cb_udata;

    /* Statistics */
    atomic_uint_fast64_t messages_sent;
    atomic_uint_fast64_t messages_dropped;
};

/* ============================================================================
 * BASE64 ENCODING (for WebSocket handshake)
 * ============================================================================ */

static const char b64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *in, size_t len, char *out)
{
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t v = (in[i] << 16) | 
                     ((i + 1 < len) ? (in[i + 1] << 8) : 0) | 
                     ((i + 2 < len) ? in[i + 2] : 0);
        out[j]     = b64_table[(v >> 18) & 0x3F];
        out[j + 1] = b64_table[(v >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? b64_table[v & 0x3F] : '=';
    }
    out[j] = '\0';
}

static void ws_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* SHA-1 for WebSocket handshake using OpenSSL */
static void sha1_hash(const unsigned char *msg, size_t len, unsigned char hash[20])
{
    SHA1(msg, len, hash);
}

/* ============================================================================
 * WEBSOCKET FRAME ENCODING
 * ============================================================================ */

static int ws_enqueue_frame(ws_client_t *c, uint8_t opcode, const char *data, size_t len)
{
    unsigned char header[10];
    size_t hdr_len = 2;
    
    header[0] = 0x80 | (opcode & 0x0F);
    if (len < 126) {
        header[1] = (uint8_t)len;
    } else if (len < 65536) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        hdr_len = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (len >> (56 - i * 8)) & 0xFF;
        hdr_len = 10;
    }
    
    if (c->out_len + hdr_len + len > WS_OUT_BUF_SIZE)
        return -1; /* Buffer full, drop frame */
        
    memcpy(c->out_buf + c->out_len, header, hdr_len);
    c->out_len += hdr_len;
    if (len > 0) {
        memcpy(c->out_buf + c->out_len, data, len);
        c->out_len += len;
    }
    return 0;
}

static void ws_flush_client(ws_client_t *c)
{
    if (c->out_len == 0) return;
    ssize_t nw = send(c->fd, c->out_buf, c->out_len, MSG_NOSIGNAL);
    if (nw > 0) {
        if ((size_t)nw < c->out_len)
            memmove(c->out_buf, c->out_buf + nw, c->out_len - (size_t)nw);
        c->out_len -= (size_t)nw;
    } else if (nw < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        /* Error will be handled by main select loop */
    }
}

static int json_append(char *buf, size_t cap, size_t *used, const char *fmt, ...)
{
    if (!buf || !used || *used >= cap) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= (cap - *used)) {
        *used = cap;
        return -1;
    }
    *used += (size_t)n;
    return 0;
}

/* ============================================================================
 * WEBSOCKET HANDSHAKE
 * ============================================================================ */

static int ws_handshake(ws_context_t *ctx, int fd, const char *request)
{
    /* Production Hardening: Mandatory API-Key check via Sec-WebSocket-Protocol.
     * This is required because standard browser WebSocket APIs cannot send custom headers. */
    if (ctx->cfg.api_key[0] != '\0') {
        char protocol_header[128];
        snprintf(protocol_header, sizeof(protocol_header), "Sec-WebSocket-Protocol: %s", ctx->cfg.api_key);
        if (!strstr(request, protocol_header)) {
            LOG_WARN("[WS] Handshake failed: Missing or invalid API key in Sec-WebSocket-Protocol");
            const char *fail = "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n";
            send(fd, fail, strlen(fail), MSG_NOSIGNAL);
            return -1;
        }
    }

    char key[256] = {0};
    const char *p = strstr(request, "Sec-WebSocket-Key:");
    if (!p) return -1;
    
    p += 18;
    while (*p == ' ') p++;
    
    char *end = strchr(p, '\r');
    if (!end || end - p > 255) return -1;
    memcpy(key, p, end - p);
    
    /* Compute accept key: SHA1(key + GUID) */
    char combined[512];
    snprintf(combined, sizeof(combined), "%s%s", key, WS_GUID);
    
    unsigned char hash[20];
    sha1_hash((unsigned char *)combined, strlen(combined), hash);
    
    char accept[64];
    base64_encode(hash, 20, accept);
    
    /* Send HTTP 101 Switching Protocols */
    char response[1024];
    int n = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", accept);
    
    return send(fd, response, n, MSG_NOSIGNAL) > 0 ? 0 : -1;
}

/* ============================================================================
 * CLIENT MANAGEMENT
 * ============================================================================ */

static void ws_add_client(ws_context_t *ctx, int fd, const char *addr)
{
    pthread_mutex_lock(&ctx->client_mutex);
    
    int limit = ctx->cfg.max_clients;
    if (limit > (int)(sizeof(ctx->clients) / sizeof(ctx->clients[0])))
        limit = (int)(sizeof(ctx->clients) / sizeof(ctx->clients[0]));

    if (ctx->client_count < limit) {
        ws_set_nonblocking(fd);
        ws_client_t *c = &ctx->clients[ctx->client_count++];
        memset(c, 0, sizeof(*c));
        c->fd = fd;
        c->handshake_done = 0;
        c->connect_time = time(NULL);
        c->last_ping = time(NULL);
        snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", addr);
    } else {
        close(fd);
    }
    
    pthread_mutex_unlock(&ctx->client_mutex);
}

/* Remove a client by index; caller MUST hold client_mutex */
static void ws_remove_client_locked(ws_context_t *ctx, int idx)
{
    close(ctx->clients[idx].fd);
    for (int j = idx; j < ctx->client_count - 1; j++)
        ctx->clients[j] = ctx->clients[j + 1];
    ctx->client_count--;
}

/* ============================================================================
 * MESSAGE QUEUE
 * ============================================================================ */

static void ws_queue_raw(ws_context_t *ctx, const ws_raw_msg_t *msg)
{
    unsigned int tail = atomic_load_explicit(&ctx->msg_tail, memory_order_relaxed);
    unsigned int head = atomic_load_explicit(&ctx->msg_head, memory_order_acquire);
    unsigned int next = (tail + 1) % MAX_PENDING_MESSAGES;

    if (next == head) {
        /* Queue full: drop oldest (advance head), then enqueue new in freed slot. */
        atomic_fetch_add_explicit(&ctx->messages_dropped, 1, memory_order_relaxed);
        unsigned int new_head = (head + 1) % MAX_PENDING_MESSAGES;
        atomic_store_explicit(&ctx->msg_head, new_head, memory_order_release);
        ctx->messages[head] = *msg;
        atomic_store_explicit(&ctx->msg_tail, new_head, memory_order_release);
        return;
    }

    ctx->messages[tail] = *msg;
    atomic_store_explicit(&ctx->msg_tail, next, memory_order_release);
}

static int ws_dequeue_raw(ws_context_t *ctx, ws_raw_msg_t *msg)
{
    unsigned int head = atomic_load_explicit(&ctx->msg_head, memory_order_relaxed);
    unsigned int tail = atomic_load_explicit(&ctx->msg_tail, memory_order_acquire);

    if (head == tail) return 0;

    *msg = ctx->messages[head];
    
    unsigned int next = (head + 1) % MAX_PENDING_MESSAGES;
    atomic_store_explicit(&ctx->msg_head, next, memory_order_release);
    
    return 1;
}

/* ============================================================================
 * COMMAND PARSING (browser -> pipeline)
 * ============================================================================ */

/* Minimal JSON string extractor: finds "key":"value" and copies value.
 * Returns 0 on success, -1 if key not found. */
static int json_extract_string(const char *json, const char *key, char *out, size_t out_sz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

/* Minimal JSON unsigned extractor: finds "key":123 and parses decimal value. */
static int json_extract_uint(const char *json, const char *key, uint32_t *out)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p || !out) return -1;
    p += strlen(needle);
    while (*p == ' ') p++;
    errno = 0;
    char *endptr = NULL;
    unsigned long v = strtoul(p, &endptr, 10);
    if (endptr == p || errno != 0 || v > 0xFFFFFFFFUL) return -1;
    *out = (uint32_t)v;
    return 0;
}

static void ws_handle_command_json(ws_context_t *ctx, const char *json)
{
    char cmd[WS_COMMAND_NAME_MAX] = {0};
    char arg[128] = {0};
    char request_id[WS_COMMAND_REQUEST_ID_MAX] = {0};
    uint32_t contract_version = 0;
    if (json_extract_string(json, "command", cmd, sizeof(cmd)) != 0)
        return;  /* No "command" field */
    
    json_extract_string(json, "ip", arg, sizeof(arg));
    if (arg[0] == '\0')
        json_extract_string(json, "value", arg, sizeof(arg));

    /* Production Hardening: Input Sanitization (IP validation) */
    if (arg[0] != '\0' && (strstr(cmd, "ip") || strstr(cmd, "whitelist"))) {
        /* block_ip_port accepts "ip:port"; validate IP part only in that case */
        int skip_strict = (strcmp(cmd, "block_ip_port") == 0);
        if (!skip_strict) {
            struct in_addr sa;
            if (inet_pton(AF_INET, arg, &sa) != 1) {
                return;
            }
        }
    }

    (void)json_extract_string(json, "request_id", request_id, sizeof(request_id));
    (void)json_extract_uint(json, "contract_version", &contract_version);
    if (ctx->cmd_cb)
        ctx->cmd_cb(cmd,
                    arg[0] ? arg : NULL,
                    request_id[0] ? request_id : NULL,
                    contract_version,
                    ctx->cmd_cb_udata);
}

/* ============================================================================
 * SERVER THREAD
 * ============================================================================ */

static void *ws_server_thread(void *arg)
{
    ws_context_t *ctx = (ws_context_t *)arg;
    char buf[8192];
    
    while (atomic_load_explicit(&ctx->running, memory_order_acquire)) {
        fd_set readfds, writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(ctx->listen_fd, &readfds);
        
        int max_fd = ctx->listen_fd;
        
        pthread_mutex_lock(&ctx->client_mutex);
        for (int i = 0; i < ctx->client_count; i++) {
            int fd = ctx->clients[i].fd;
            FD_SET(fd, &readfds);
            if (ctx->clients[i].out_len > 0)
                FD_SET(fd, &writefds);
            if (fd > max_fd) max_fd = fd;
        }
        pthread_mutex_unlock(&ctx->client_mutex);

        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 }; /* 50ms wait */
        int sel = select(max_fd + 1, &readfds, &writefds, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        /* Accept new connections */
        if (FD_ISSET(ctx->listen_fd, &readfds)) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            int fd = accept(ctx->listen_fd, (struct sockaddr *)&addr, &len);
            if (fd >= 0) {
                /* Set non-blocking so recv() won't stall the thread */
                int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                
                char ip[64];
                inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                ws_add_client(ctx, fd, ip);
            }
        }
        
        /* Handle client I/O */
        pthread_mutex_lock(&ctx->client_mutex);
        time_t now = time(NULL);
        for (int i = 0; i < ctx->client_count; i++) {
            /* Handshake timeout (slow-loris protection) */
            if (!ctx->clients[i].handshake_done && (now - ctx->clients[i].connect_time > 5)) {
                ws_remove_client_locked(ctx, i);
                i--;
                continue;
            }

            int fd = ctx->clients[i].fd;
            
            /* Read Phase */
            if (FD_ISSET(fd, &readfds)) {
                ssize_t nr = recv(fd, buf, sizeof(buf) - 1, 0);
                if (nr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    /* Spurious wake or no data; safe to ignore, handle write phase */
                    goto flush_phase;
                } else if (nr <= 0) {
                    ws_remove_client_locked(ctx, i);
                    i--;
                    continue;
                }
                
                if (!ctx->clients[i].handshake_done) {
                    buf[nr] = '\0';
                    if (ws_handshake(ctx, fd, buf) == 0)
                        ctx->clients[i].handshake_done = 1;
                    else {
                        ws_remove_client_locked(ctx, i);
                        i--;
                        continue;
                    }
                } else {
                    /* Post-handshake: decode WebSocket text frames for commands */
                    unsigned char *frame = (unsigned char *)buf;
                    if (nr >= 2) {
                        uint8_t opcode = frame[0] & 0x0F;
                        int masked = (frame[1] & 0x80) != 0;
                        uint64_t payload_len = frame[1] & 0x7F;
                        size_t hdr = 2;
                        if (payload_len == 126 && nr >= 4) {
                            payload_len = ((uint64_t)frame[2] << 8) | frame[3];
                            hdr = 4;
                        } else if (payload_len == 127 && nr >= 10) {
                            payload_len = 0;
                            for (int b = 0; b < 8; b++)
                                payload_len = (payload_len << 8) | frame[2 + b];
                            hdr = 10;
                        }
                        uint8_t mask_key[4] = {0};
                        if (masked) {
                            if ((size_t)nr >= hdr + 4) {
                                memcpy(mask_key, frame + hdr, 4);
                                hdr += 4;
                            } else {
                                goto skip_frame;
                            }
                        }
                        if (opcode == WS_OPCODE_TEXT && payload_len > 0 &&
                            (size_t)nr >= hdr + payload_len && payload_len < 4096) {
                            /* Per-client command rate limit (max WS_CMD_RATE_LIMIT_PER_SEC per second) */
                            time_t now_sec = time(NULL);
                            if (now_sec != ctx->clients[i].cmd_window_sec) {
                                ctx->clients[i].cmd_window_sec = now_sec;
                                ctx->clients[i].cmd_count = 0;
                            }
                            ctx->clients[i].cmd_count++;
                            if (ctx->clients[i].cmd_count > WS_CMD_RATE_LIMIT_PER_SEC) {
                                /* Drop excess commands; no callback */
                            } else {
                                /* Unmask payload */
                                char cmd_buf[4096];
                                for (uint64_t j = 0; j < payload_len; j++)
                                    cmd_buf[j] = (char)(frame[hdr + j] ^ mask_key[j % 4]);
                                cmd_buf[payload_len] = '\0';
                                if (ctx->cmd_cb) {
                                    ws_handle_command_json(ctx, cmd_buf);
                                }
                            }
                        } else if (opcode == WS_OPCODE_CLOSE) {
                            ws_remove_client_locked(ctx, i);
                            i--;
                            continue;
                        } else if (opcode == WS_OPCODE_PING) {
                            ws_enqueue_frame(&ctx->clients[i], WS_OPCODE_PONG, NULL, 0);
                        }
                    }
                    skip_frame: (void)0;
                }
            }
            
flush_phase:
            /* Write Phase (Async Flush) */
            if (FD_ISSET(fd, &writefds)) {
                ws_flush_client(&ctx->clients[i]);
            }
        }
        pthread_mutex_unlock(&ctx->client_mutex);
        
        /* Broadcast: snapshot client FDs under lock, then send without lock */
        ws_raw_msg_t raw_msg;
        while (ws_dequeue_raw(ctx, &raw_msg)) {
            char buf_local[16384];   /* Increased to 16KB to prevent truncation in large IP list batches */
            int n_json = 0;

            /* Format raw data to JSON ON THE BACKGROUND THREAD (Safe for hot-path) */
            switch (raw_msg.type) {
                case WS_MSG_TYPE_METRICS: {
                    ws_metrics_t *m = &raw_msg.data.metrics;
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"metrics\",\"data\":{"
                        "\"packets_per_sec\":%lu,\"bytes_per_sec\":%lu,\"active_flows\":%u,"
                        "\"active_sources\":%u,\"ml_classifications_per_sec\":%u,"
                        "\"cpu_usage_percent\":%.2f,\"memory_usage_mb\":%.2f,"
                        "\"kernel_drops\":%lu,\"userspace_drops\":%lu}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        (unsigned long)m->packets_per_sec, (unsigned long)m->bytes_per_sec,
                        m->active_flows, m->active_sources, m->ml_classifications_per_sec,
                        m->cpu_usage_percent, m->memory_usage_mb,
                        (unsigned long)m->kernel_drops, (unsigned long)m->userspace_drops);
                    break;
                }
                case WS_MSG_TYPE_ACTIVITY: {
                    ws_activity_t *a = &raw_msg.data.activity;
                    char ip[INET_ADDRSTRLEN];
                    struct in_addr addr = { .s_addr = a->src_ip };
                    inet_ntop(AF_INET, &addr, ip, sizeof(ip));
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"activity_logs\",\"data\":{"
                        "\"timestamp\":%lu,\"src_ip\":\"%s\",\"action\":\"%s\","
                        "\"attack_type\":\"%s\",\"threat_score\":%.3f,\"reason\":\"%s\",\"enforced\":%s}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        (unsigned long)(a->timestamp_ns / 1000000000ULL),
                        ip, a->action, a->attack_type, a->threat_score, a->reason, a->enforced ? "true" : "false");
                    break;
                }
                case WS_MSG_TYPE_IP_LIST_BLOCKED:
                case WS_MSG_TYPE_IP_LIST_RATE_LIMITED:
                case WS_MSG_TYPE_IP_LIST_MONITORED:
                case WS_MSG_TYPE_IP_LIST_WHITELISTED: {
                    const char *type_str = (raw_msg.type == WS_MSG_TYPE_IP_LIST_BLOCKED) ? "blocked_ips" :
                                           (raw_msg.type == WS_MSG_TYPE_IP_LIST_RATE_LIMITED) ? "rate_limited_ips" :
                                           (raw_msg.type == WS_MSG_TYPE_IP_LIST_MONITORED) ? "monitored_ips" : "whitelisted_ips";
                    size_t used = 0;
                    if (json_append(buf_local, sizeof(buf_local), &used, "{\"schema_version\":%u,\"type\":\"%s\",\"data\":[", (unsigned)WS_TELEMETRY_SCHEMA_VERSION, type_str) != 0) {
                        n_json = -1;
                        break;
                    }
                    uint32_t ip_cap = raw_msg.data.ip_list.count;
                    if (ip_cap > (uint32_t)WS_MAX_JSON_IP_ENTRIES) ip_cap = (uint32_t)WS_MAX_JSON_IP_ENTRIES;
                    for (uint32_t i = 0; i < ip_cap; i++) {
                        ws_ip_entry_t *e = &raw_msg.data.ip_list.entries[i];
                        char ip[INET_ADDRSTRLEN];
                        struct in_addr addr = { .s_addr = e->ip };
                        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
                        int append_rc;
                        if (raw_msg.type == WS_MSG_TYPE_IP_LIST_RATE_LIMITED) {
                            append_rc = json_append(buf_local, sizeof(buf_local), &used,
                                "%s{\"ip\":\"%s\",\"limit_pps\":%u,\"rule_id\":%u}",
                                i > 0 ? "," : "", ip, e->rate_limit_pps, e->rule_id);
                        } else if (raw_msg.type == WS_MSG_TYPE_IP_LIST_WHITELISTED) {
                            append_rc = json_append(buf_local, sizeof(buf_local), &used,
                                "%s{\"ip\":\"%s\"}",
                                i > 0 ? "," : "", ip);
                        } else {
                            append_rc = json_append(buf_local, sizeof(buf_local), &used,
                                "%s{\"ip\":\"%s\",\"rule_id\":%u,\"timestamp\":%lu}",
                                i > 0 ? "," : "", ip, e->rule_id,
                                (unsigned long)(e->timestamp_added / 1000000000ULL));
                        }
                        if (append_rc != 0) break;
                    }
                    if (json_append(buf_local, sizeof(buf_local), &used, "]}") != 0) {
                        n_json = -1;
                        break;
                    }
                    n_json = (int)used;
                    break;
                }
                case WS_MSG_TYPE_TRAFFIC_RATE: {
                    ws_traffic_rate_t *r = &raw_msg.data.traffic_rate;
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"traffic_rate\",\"data\":{"
                        "\"total_pps\":%lu,\"total_bps\":%lu,\"tcp_pps\":%lu,\"udp_pps\":%lu,\"icmp_pps\":%lu,\"other_pps\":%lu}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        (unsigned long)r->total_pps, (unsigned long)r->total_bps, (unsigned long)r->tcp_pps,
                        (unsigned long)r->udp_pps, (unsigned long)r->icmp_pps, (unsigned long)r->other_pps);
                    break;
                }
                case WS_MSG_TYPE_PROTOCOL_DIST: {
                    ws_protocol_dist_t *d = &raw_msg.data.protocol_dist;
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"protocol_distribution\",\"data\":{"
                        "\"tcp_percent\":%.2f,\"udp_percent\":%.2f,\"icmp_percent\":%.2f,\"other_percent\":%.2f,"
                        "\"tcp_bytes\":%lu,\"udp_bytes\":%lu,\"icmp_bytes\":%lu,\"other_bytes\":%lu}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        d->tcp_percent, d->udp_percent, d->icmp_percent, d->other_percent,
                        (unsigned long)d->tcp_bytes, (unsigned long)d->udp_bytes, (unsigned long)d->icmp_bytes, (unsigned long)d->other_bytes);
                    break;
                }
                case WS_MSG_TYPE_TOP_SOURCES: {
                    size_t used = 0;
                    if (json_append(buf_local, sizeof(buf_local), &used, "{\"schema_version\":%u,\"type\":\"top_sources\",\"data\":[", (unsigned)WS_TELEMETRY_SCHEMA_VERSION) != 0) {
                        n_json = -1;
                        break;
                    }
                    uint32_t top_cap = raw_msg.data.top_sources.count;
                    if (top_cap > (uint32_t)WS_MAX_JSON_TOP_SOURCES) top_cap = (uint32_t)WS_MAX_JSON_TOP_SOURCES;
                    for (uint32_t i = 0; i < top_cap; i++) {
                        ws_top_source_t *s = &raw_msg.data.top_sources.sources[i];
                        char ip[INET_ADDRSTRLEN];
                        struct in_addr addr = { .s_addr = s->src_ip };
                        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
                        if (json_append(buf_local, sizeof(buf_local), &used,
                            "%s{\"ip\":\"%s\",\"packets\":%lu,\"bytes\":%lu,\"flows\":%u,\"suspicious\":%d,\"threat_score\":%.3f}",
                            i > 0 ? "," : "", ip, (unsigned long)s->packets, (unsigned long)s->bytes,
                            s->flow_count, s->suspicious, s->threat_score) != 0) {
                            break;
                        }
                    }
                    if (json_append(buf_local, sizeof(buf_local), &used, "]}") != 0) {
                        n_json = -1;
                        break;
                    }
                    n_json = (int)used;
                    break;
                }
                case WS_MSG_TYPE_FEATURE_IMPORTANCE: {
                    ws_feature_importance_t *f = &raw_msg.data.feature_importance;
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"feature_importance\",\"data\":{"
                        "\"volume_weight\":%.3f,\"entropy_weight\":%.3f,\"protocol_weight\":%.3f,\"behavioral_weight\":%.3f,"
                        "\"ml_weight\":%.3f,\"l7_weight\":%.3f,\"anomaly_weight\":%.3f,\"chi_square_weight\":%.3f,\"fanin_weight\":%.3f,"
                        "\"signature_weight\":%.3f,\"avg_threat_score\":%.3f,\"avg_fanin_score\":%.3f,\"avg_signature_score\":%.3f,"
                        "\"detections_last_10s\":%u,"
                        "\"policy_arm\":%u,\"policy_updates\":%lu,\"policy_last_reward\":%.3f}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        f->volume_weight, f->entropy_weight, f->protocol_weight, f->behavioral_weight,
                        f->ml_weight, f->l7_weight, f->anomaly_weight, f->chi_square_weight, f->fanin_weight,
                        f->signature_weight, f->avg_threat_score, f->avg_fanin_score, f->avg_signature_score, f->detections_last_10s,
                        f->policy_arm, (unsigned long)f->policy_updates, f->policy_last_reward);
                    break;
                }
                case WS_MSG_TYPE_FEATURE_VECTOR: {
                    ws_raw_feature_vector_t *v = &raw_msg.data.feature_vector;
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"feature_vector\",\"data\":[%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,"
                        "%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f]}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        v->values[0], v->values[1], v->values[2], v->values[3], v->values[4],
                        v->values[5], v->values[6], v->values[7], v->values[8], v->values[9],
                        v->values[10], v->values[11], v->values[12], v->values[13], v->values[14],
                        v->values[15], v->values[16], v->values[17], v->values[18], v->values[19], v->values[20],
                        v->values[21]);
                    break;
                }
                case WS_MSG_TYPE_CONNECTIONS: {
                    size_t used = 0;
                    if (json_append(buf_local, sizeof(buf_local), &used, "{\"schema_version\":%u,\"type\":\"active_connections\",\"data\":[", (unsigned)WS_TELEMETRY_SCHEMA_VERSION) != 0) {
                        n_json = -1;
                        break;
                    }
                    uint32_t conn_cap = raw_msg.data.connections.count;
                    if (conn_cap > (uint32_t)WS_MAX_JSON_CONNECTIONS) conn_cap = (uint32_t)WS_MAX_JSON_CONNECTIONS;
                    for (uint32_t i = 0; i < conn_cap; i++) {
                        ws_connection_t *c = &raw_msg.data.connections.conns[i];
                        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
                        struct in_addr sa = { .s_addr = c->src_ip };
                        struct in_addr da = { .s_addr = c->dst_ip };
                        inet_ntop(AF_INET, &sa, sip, sizeof(sip));
                        inet_ntop(AF_INET, &da, dip, sizeof(dip));
                        if (json_append(buf_local, sizeof(buf_local), &used,
                            "%s{\"src\":\"%s:%u\",\"dst\":\"%s:%u\",\"proto\":%u,\"packets\":%lu,\"bytes\":%lu}",
                            i > 0 ? "," : "", sip, ntohs(c->src_port), dip, ntohs(c->dst_port),
                            c->protocol, (unsigned long)c->packets, (unsigned long)c->bytes) != 0) {
                            break;
                        }
                    }
                    if (json_append(buf_local, sizeof(buf_local), &used, "]}") != 0) {
                        n_json = -1;
                        break;
                    }
                    n_json = (int)used;
                    break;
                }
                case WS_MSG_TYPE_MITIGATION_STATUS: {
                    ws_mitigation_status_t *s = &raw_msg.data.mitigation_status;
                    /* JSON-escape sdn_last_error: " -> \", \ -> \\ */
                    char err_esc[WS_SDN_LAST_ERROR_MAX * 2 + 1];
                    {
                        const char *src = s->sdn_last_error;
                        char *dst = err_esc;
                        size_t remain = sizeof(err_esc) - 1;
                        while (*src && remain > 1) {
                            if (*src == '"') {
                                *dst++ = '\\'; *dst++ = '"';
                                remain -= 2;
                            } else if (*src == '\\') {
                                *dst++ = '\\'; *dst++ = '\\';
                                remain -= 2;
                            } else if ((unsigned char)*src >= 0x20) {
                                *dst++ = *src;
                                remain--;
                            }
                            src++;
                        }
                        *dst = '\0';
                    }
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"mitigation_status\",\"data\":{"
                        "\"total_blocked\":%u,\"total_rate_limited\":%u,\"total_monitored\":%u,\"total_whitelisted\":%u,"
                        "\"kernel_verdict_cache_hits\":%lu,\"kernel_verdict_cache_misses\":%lu,\"active_sdn_rules\":%u,"
                        "\"auto_mitigation_enabled\":%s,\"kernel_dropping_enabled\":%s,\"sdn_connected\":%d,"
                        "\"sdn_last_error\":\"%s\"}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        s->total_blocked, s->total_rate_limited, s->total_monitored, s->total_whitelisted,
                        (unsigned long)s->kernel_verdict_cache_hits, (unsigned long)s->kernel_verdict_cache_misses,
                        s->active_sdn_rules, s->auto_mitigation_enabled ? "true" : "false",
                        (s->kernel_dropping_enabled != 0) ? "true" : "false", s->sdn_connected, err_esc);
                    break;
                }
                case WS_MSG_TYPE_INTEGRATION_STATUS: {
                    ws_integration_status_t *s = &raw_msg.data.integration_status;
                    char profile_esc[WS_INTEGRATION_PROFILE_MAX * 2 + 1];
                    char gatekeeper_err_esc[WS_GATEKEEPER_LAST_ERROR_MAX * 2 + 1];
                    {
                        const char *src = s->profile;
                        char *dst = profile_esc;
                        size_t remain = sizeof(profile_esc) - 1;
                        while (*src && remain > 1) {
                            if (*src == '"') {
                                *dst++ = '\\'; *dst++ = '"';
                                remain -= 2;
                            } else if (*src == '\\') {
                                *dst++ = '\\'; *dst++ = '\\';
                                remain -= 2;
                            } else if ((unsigned char)*src >= 0x20) {
                                *dst++ = *src;
                                remain--;
                            }
                            src++;
                        }
                        *dst = '\0';
                    }
                    {
                        const char *src = s->gatekeeper_last_error;
                        char *dst = gatekeeper_err_esc;
                        size_t remain = sizeof(gatekeeper_err_esc) - 1;
                        while (*src && remain > 1) {
                            if (*src == '"') {
                                *dst++ = '\\'; *dst++ = '"';
                                remain -= 2;
                            } else if (*src == '\\') {
                                *dst++ = '\\'; *dst++ = '\\';
                                remain -= 2;
                            } else if ((unsigned char)*src >= 0x20) {
                                *dst++ = *src;
                                remain--;
                            }
                            src++;
                        }
                        *dst = '\0';
                    }
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"integration_status\",\"data\":{"
                        "\"intel_feed_enabled\":%s,\"model_extension_enabled\":%s,\"controller_extension_enabled\":%s,"
                        "\"signature_feed_enabled\":%s,\"dataplane_extension_enabled\":%s,"
                        "\"gatekeeper_enabled\":%s,\"gatekeeper_connected\":%d,"
                        "\"gatekeeper_failure_count\":%u,\"gatekeeper_failure_threshold\":%u,"
                        "\"gatekeeper_circuit_open\":%s,\"gatekeeper_next_retry_sec\":%u,"
                        "\"gatekeeper_last_error\":\"%s\","
                        "\"profile\":\"%s\"}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        s->intel_feed_enabled ? "true" : "false",
                        s->model_extension_enabled ? "true" : "false",
                        s->controller_extension_enabled ? "true" : "false",
                        s->signature_feed_enabled ? "true" : "false",
                        s->dataplane_extension_enabled ? "true" : "false",
                        s->gatekeeper_enabled ? "true" : "false",
                        s->gatekeeper_connected,
                        s->gatekeeper_failure_count,
                        s->gatekeeper_failure_threshold,
                        s->gatekeeper_circuit_open ? "true" : "false",
                        s->gatekeeper_next_retry_sec,
                        gatekeeper_err_esc,
                        profile_esc);
                    break;
                }
                case WS_MSG_TYPE_COMMAND_RESULT: {
                    ws_command_result_t *r = &raw_msg.data.command_result;
                    char req_esc[WS_COMMAND_REQUEST_ID_MAX * 2 + 1];
                    char cmd_esc[WS_COMMAND_NAME_MAX * 2 + 1];
                    char msg_esc[WS_COMMAND_MESSAGE_MAX * 2 + 1];
                    {
                        const char *src = r->request_id;
                        char *dst = req_esc;
                        size_t remain = sizeof(req_esc) - 1;
                        while (*src && remain > 1) {
                            if (*src == '"') {
                                *dst++ = '\\'; *dst++ = '"';
                                remain -= 2;
                            } else if (*src == '\\') {
                                *dst++ = '\\'; *dst++ = '\\';
                                remain -= 2;
                            } else if ((unsigned char)*src >= 0x20) {
                                *dst++ = *src;
                                remain--;
                            }
                            src++;
                        }
                        *dst = '\0';
                    }
                    {
                        const char *src = r->command;
                        char *dst = cmd_esc;
                        size_t remain = sizeof(cmd_esc) - 1;
                        while (*src && remain > 1) {
                            if (*src == '"') {
                                *dst++ = '\\'; *dst++ = '"';
                                remain -= 2;
                            } else if (*src == '\\') {
                                *dst++ = '\\'; *dst++ = '\\';
                                remain -= 2;
                            } else if ((unsigned char)*src >= 0x20) {
                                *dst++ = *src;
                                remain--;
                            }
                            src++;
                        }
                        *dst = '\0';
                    }
                    {
                        const char *src = r->message;
                        char *dst = msg_esc;
                        size_t remain = sizeof(msg_esc) - 1;
                        while (*src && remain > 1) {
                            if (*src == '"') {
                                *dst++ = '\\'; *dst++ = '"';
                                remain -= 2;
                            } else if (*src == '\\') {
                                *dst++ = '\\'; *dst++ = '\\';
                                remain -= 2;
                            } else if ((unsigned char)*src >= 0x20) {
                                *dst++ = *src;
                                remain--;
                            }
                            src++;
                        }
                        *dst = '\0';
                    }
                    n_json = snprintf(buf_local, sizeof(buf_local),
                        "{\"schema_version\":%u,\"type\":\"command_result\",\"data\":{"
                        "\"timestamp\":%lu,\"contract_version\":%u,\"request_id\":\"%s\","
                        "\"command\":\"%s\",\"success\":%s,\"message\":\"%s\"}}",
                        (unsigned)WS_TELEMETRY_SCHEMA_VERSION,
                        (unsigned long)(r->timestamp_ns / 1000000000ULL),
                        r->contract_version,
                        req_esc,
                        cmd_esc,
                        r->success ? "true" : "false",
                        msg_esc);
                    break;
                }
                default: break;
            }

            if (n_json <= 0) continue;

            /* Broadcast to all ready clients */
            pthread_mutex_lock(&ctx->client_mutex);
            for (int i = 0; i < ctx->client_count; i++) {
                if (ctx->clients[i].handshake_done) {
                    if (ws_enqueue_frame(&ctx->clients[i], WS_OPCODE_TEXT, buf_local, n_json) == 0)
                        atomic_fetch_add_explicit(&ctx->messages_sent, 1, memory_order_relaxed);
                }
            }
            pthread_mutex_unlock(&ctx->client_mutex);
        }
    }
    
    return NULL;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

ws_context_t *ws_init(const ws_config_t *cfg)
{
    ws_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    
    if (cfg)
        ctx->cfg = *cfg;
    else {
        ws_config_t def = WS_CONFIG_DEFAULT;
        ctx->cfg = def;
    }
    
    if (ctx->cfg.max_clients <= 0)
        ctx->cfg.max_clients = 1;
    if (ctx->cfg.max_clients > (int)(sizeof(ctx->clients) / sizeof(ctx->clients[0])))
        ctx->cfg.max_clients = (int)(sizeof(ctx->clients) / sizeof(ctx->clients[0]));

    pthread_mutex_init(&ctx->client_mutex, NULL);
    atomic_init(&ctx->running, 0);
    atomic_init(&ctx->msg_head, 0);
    atomic_init(&ctx->msg_tail, 0);
    
    /* Create listen socket */
    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_fd < 0) {
        pthread_mutex_destroy(&ctx->client_mutex);
        free(ctx);
        return NULL;
    }
    
    int opt = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ctx->cfg.port),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (strcmp(ctx->cfg.bind_addr, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, ctx->cfg.bind_addr, &addr.sin_addr) != 1) {
            close(ctx->listen_fd);
            pthread_mutex_destroy(&ctx->client_mutex);
            free(ctx);
            return NULL;
        }
    }
    
    if (bind(ctx->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(ctx->listen_fd, 10) < 0) {
        close(ctx->listen_fd);
        pthread_mutex_destroy(&ctx->client_mutex);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void ws_destroy(ws_context_t *ctx)
{
    if (!ctx) return;
    
    ws_stop(ctx);
    
    pthread_mutex_lock(&ctx->client_mutex);
    for (int i = 0; i < ctx->client_count; i++)
        close(ctx->clients[i].fd);
    pthread_mutex_unlock(&ctx->client_mutex);
    
    close(ctx->listen_fd);
    
    /* msg_head/tail are atomic_uint; no msg_mutex exists in the struct. Removed to fix crash. */
    pthread_mutex_destroy(&ctx->client_mutex);
    
    free(ctx);
}

int ws_start(ws_context_t *ctx)
{
    if (!ctx) return -1;
    if (atomic_load_explicit(&ctx->running, memory_order_acquire)) return -1;
    
    atomic_store_explicit(&ctx->running, 1, memory_order_release);
    if (pthread_create(&ctx->thread, NULL, ws_server_thread, ctx) != 0) {
        atomic_store_explicit(&ctx->running, 0, memory_order_release);
        return -1;
    }
    
    return 0;
}

void ws_stop(ws_context_t *ctx)
{
    if (!ctx) return;
    if (!atomic_load_explicit(&ctx->running, memory_order_acquire)) return;
    
    atomic_store_explicit(&ctx->running, 0, memory_order_release);
    pthread_join(ctx->thread, NULL);
}

/* ============================================================================
 * STREAM UPDATES (JSON formatting + queue)
 * ============================================================================ */

void ws_update_metrics(ws_context_t *ctx, const ws_metrics_t *m)
{
    if (!ctx || !m) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_METRICS, .data.metrics = *m };
    ws_queue_raw(ctx, &msg);
}

void ws_push_activity(ws_context_t *ctx, const ws_activity_t *a)
{
    if (!ctx || !a) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_ACTIVITY, .data.activity = *a };
    ws_queue_raw(ctx, &msg);
}

void ws_update_blocked_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx || !ips) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_IP_LIST_BLOCKED };
    msg.data.ip_list.count = (count > MAX_IP_LIST_BATCH) ? MAX_IP_LIST_BATCH : count;
    memcpy(msg.data.ip_list.entries, ips, msg.data.ip_list.count * sizeof(ws_ip_entry_t));
    ws_queue_raw(ctx, &msg);
}

void ws_update_rate_limited_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx || !ips) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_IP_LIST_RATE_LIMITED };
    msg.data.ip_list.count = (count > MAX_IP_LIST_BATCH) ? MAX_IP_LIST_BATCH : count;
    memcpy(msg.data.ip_list.entries, ips, msg.data.ip_list.count * sizeof(ws_ip_entry_t));
    ws_queue_raw(ctx, &msg);
}

void ws_update_monitored_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx || !ips) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_IP_LIST_MONITORED };
    msg.data.ip_list.count = (count > MAX_IP_LIST_BATCH) ? MAX_IP_LIST_BATCH : count;
    memcpy(msg.data.ip_list.entries, ips, msg.data.ip_list.count * sizeof(ws_ip_entry_t));
    ws_queue_raw(ctx, &msg);
}

void ws_update_whitelisted_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx || !ips) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_IP_LIST_WHITELISTED };
    msg.data.ip_list.count = (count > MAX_IP_LIST_BATCH) ? MAX_IP_LIST_BATCH : count;
    memcpy(msg.data.ip_list.entries, ips, msg.data.ip_list.count * sizeof(ws_ip_entry_t));
    ws_queue_raw(ctx, &msg);
}

void ws_update_traffic_rate(ws_context_t *ctx, const ws_traffic_rate_t *r)
{
    if (!ctx || !r) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_TRAFFIC_RATE, .data.traffic_rate = *r };
    ws_queue_raw(ctx, &msg);
}

void ws_update_protocol_dist(ws_context_t *ctx, const ws_protocol_dist_t *d)
{
    if (!ctx || !d) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_PROTOCOL_DIST, .data.protocol_dist = *d };
    ws_queue_raw(ctx, &msg);
}

void ws_update_top_sources(ws_context_t *ctx, const ws_top_source_t *sources, uint32_t count)
{
    if (!ctx || !sources) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_TOP_SOURCES };
    msg.data.top_sources.count = (count > MAX_TOP_SOURCES_BATCH) ? MAX_TOP_SOURCES_BATCH : count;
    memcpy(msg.data.top_sources.sources, sources, msg.data.top_sources.count * sizeof(ws_top_source_t));
    ws_queue_raw(ctx, &msg);
}

void ws_update_feature_importance(ws_context_t *ctx, const ws_feature_importance_t *f)
{
    if (!ctx || !f) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_FEATURE_IMPORTANCE, .data.feature_importance = *f };
    ws_queue_raw(ctx, &msg);
}

void ws_update_feature_vector(ws_context_t *ctx, const ws_raw_feature_vector_t *vec)
{
    if (!ctx || !vec) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_FEATURE_VECTOR, .data.feature_vector = *vec };
    ws_queue_raw(ctx, &msg);
}

void ws_update_connections(ws_context_t *ctx, const ws_connection_t *conns, uint32_t count)
{
    if (!ctx || !conns) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_CONNECTIONS };
    msg.data.connections.count = (count > MAX_CONNECTIONS_BATCH) ? MAX_CONNECTIONS_BATCH : count;
    memcpy(msg.data.connections.conns, conns, msg.data.connections.count * sizeof(ws_connection_t));
    ws_queue_raw(ctx, &msg);
}

void ws_update_mitigation_status(ws_context_t *ctx, const ws_mitigation_status_t *s)
{
    if (!ctx || !s) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_MITIGATION_STATUS, .data.mitigation_status = *s };
    ws_queue_raw(ctx, &msg);
}

void ws_update_integration_status(ws_context_t *ctx, const ws_integration_status_t *s)
{
    if (!ctx || !s) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_INTEGRATION_STATUS, .data.integration_status = *s };
    ws_queue_raw(ctx, &msg);
}

void ws_push_command_result(ws_context_t *ctx, const ws_command_result_t *result)
{
    if (!ctx || !result) return;
    ws_raw_msg_t msg = { .type = WS_MSG_TYPE_COMMAND_RESULT, .data.command_result = *result };
    ws_queue_raw(ctx, &msg);
}

uint32_t ws_get_client_count(ws_context_t *ctx)
{
    if (!ctx) return 0;
    pthread_mutex_lock(&ctx->client_mutex);
    uint32_t n = (uint32_t)ctx->client_count;
    pthread_mutex_unlock(&ctx->client_mutex);
    return n;
}

uint64_t ws_get_messages_sent(const ws_context_t *ctx)
{
    return ctx ? atomic_load_explicit(&ctx->messages_sent, memory_order_relaxed) : 0;
}

uint64_t ws_get_messages_dropped(const ws_context_t *ctx)
{
    return ctx ? atomic_load_explicit(&ctx->messages_dropped, memory_order_relaxed) : 0;
}

void ws_set_command_callback(ws_context_t *ctx, ws_command_cb_t cb, void *udata)
{
    if (!ctx) return;
    ctx->cmd_cb = cb;
    ctx->cmd_cb_udata = udata;
}

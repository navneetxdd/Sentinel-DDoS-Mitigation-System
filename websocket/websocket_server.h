/*
 * Sentinel DDoS Core - WebSocket Server for Real-time Data Streaming
 *
 * Broadcasts 14 data streams to connected web clients:
 *   1. metrics (1s)             - System performance counters
 *   2. activity_logs (event)    - Mitigation actions
 *   3. blocked_ips (change)     - Blocked IP list
 *   4. rate_limited_ips (change)- Rate limited IPs
 *   5. monitored_ips (change)   - Monitored IPs
 *   6. whitelisted_ips (change) - Whitelisted IPs
 *   7. traffic_rate (1s)        - Traffic throughput
 *   8. protocol_distribution (1s)- Protocol breakdown
 *   9. top_sources (5s)         - Top traffic sources
 *  10. feature_importance (10s) - ML detection factors
 *  11. active_connections (1s)  - Active flows
 *  12. mitigation_status (1s)   - Mitigation summary
 *  13. integration_status (1s)  - External integration flags/profile
 *  14. command_result (event)    - Browser command ACK/error status
 *
 * Also accepts JSON commands from clients (browser -> pipeline).
 * Uses a lightweight built-in WebSocket implementation.
 */

#ifndef SENTINEL_WEBSOCKET_SERVER_H
#define SENTINEL_WEBSOCKET_SERVER_H

#include <stdint.h>
#include <time.h>
#include "../sentinel_core/sentinel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct ws_config {
    uint16_t port;                  /* WebSocket port (default 8765) */
    char     bind_addr[64];         /* Bind address (default "0.0.0.0") */
    int      max_clients;           /* Max concurrent clients */
    int      ping_interval_sec;     /* WebSocket ping interval */
    char     api_key[64];           /* Mandatory API key for handshake */
} ws_config_t;

#define WS_CONFIG_DEFAULT { \
    .port = 8765,               \
    .bind_addr = "0.0.0.0",     \
    .max_clients = 100,         \
    .ping_interval_sec = 30,    \
    .api_key = ""               \
}

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/* Stream 1: Metrics */
typedef struct ws_metrics {
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t active_flows;
    uint32_t active_sources;
    uint32_t ml_classifications_per_sec;
    double   cpu_usage_percent;
    double   memory_usage_mb;
    uint64_t kernel_drops;
    uint64_t userspace_drops;
} ws_metrics_t;

/* Stream 2: Activity Log Entry */
typedef struct ws_activity {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    char     action[16];           /* BLOCK/RATE_LIMIT/MONITOR/WHITELIST */
    char     attack_type[32];
    double   threat_score;
    char     reason[128];
    int      enforced;             /* 1 if the action was applied, 0 if only observed */
} ws_activity_t;

/* Stream 3-6: IP Lists */
typedef struct ws_ip_entry {
    uint32_t ip;
    uint64_t timestamp_added;
    uint32_t rule_id;              /* For blocked/rate_limited */
    uint32_t rate_limit_pps;       /* For rate_limited only */
} ws_ip_entry_t;

/* Stream 7: Traffic Rate */
typedef struct ws_traffic_rate {
    uint64_t total_pps;
    uint64_t total_bps;
    uint64_t tcp_pps;
    uint64_t udp_pps;
    uint64_t icmp_pps;
    uint64_t other_pps;
} ws_traffic_rate_t;

/* Stream 8: Protocol Distribution */
typedef struct ws_protocol_dist {
    double tcp_percent;
    double udp_percent;
    double icmp_percent;
    double other_percent;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
    uint64_t icmp_bytes;
    uint64_t other_bytes;
} ws_protocol_dist_t;

/* Stream 9: Top Source */
typedef struct ws_top_source {
    uint32_t src_ip;
    uint64_t packets;
    uint64_t bytes;
    uint32_t flow_count;
    int      suspicious;           /* 1 if flagged */
    double   threat_score;
} ws_top_source_t;

/* Stream 10a: Raw feature vector for SHAP explain API.
 * 22 doubles = 20 ML features + 2 heuristic meta-scores (chi_square, fan-in).
 * The frontend slices the first 20 elements for SHAP requests. */
typedef struct ws_raw_feature_vector {
    double values[22];
} ws_raw_feature_vector_t;

/* Stream 10: Feature Importance */
typedef struct ws_feature_importance {
    double volume_weight;
    double entropy_weight;
    double protocol_weight;
    double behavioral_weight;
    double ml_weight;
    double l7_weight;
    double anomaly_weight;
    double chi_square_weight;
    double fanin_weight;
    double signature_weight;   /* reflection signature weight */
    double avg_threat_score;
    double avg_fanin_score;
    double avg_signature_score;/* average signature boost in current window */
    double avg_score_volume;
    double avg_score_entropy;
    double avg_score_protocol;
    double avg_score_behavioral;
    double avg_score_ml;
    double avg_score_l7;
    double avg_score_anomaly;
    double avg_score_chi_square;
    double avg_score_fanin;
    double avg_score_signature;
    uint32_t detections_last_10s;
    uint32_t policy_arm;
    uint64_t policy_updates;
    double   policy_last_reward;
} ws_feature_importance_t;

/* Stream 11: Active Connection */
typedef struct ws_connection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint64_t packets;
    uint64_t bytes;
    uint64_t last_seen_ns;
} ws_connection_t;

#define WS_SDN_LAST_ERROR_MAX 128
#define WS_INTEGRATION_PROFILE_MAX 64
#define WS_DATAPLANE_MODE_MAX 32
#define WS_COMMAND_NAME_MAX 64
#define WS_COMMAND_MESSAGE_MAX 160
#define WS_COMMAND_REQUEST_ID_MAX 64
#define WS_COMMAND_CONTRACT_VERSION 1
#define WS_TELEMETRY_SCHEMA_VERSION 1

/* Stream 12: Mitigation Status */
typedef struct ws_mitigation_status {
    uint32_t total_blocked;
    uint32_t total_rate_limited;
    uint32_t total_monitored;
    uint32_t total_whitelisted;
    uint64_t kernel_verdict_cache_hits;
    uint64_t kernel_verdict_cache_misses;
    uint32_t active_sdn_rules;
    int      auto_mitigation_enabled;
    int      kernel_dropping_enabled;  /* 1=eBPF blacklist active, 0=fallback (no kernel drops) */
    char     dataplane_mode[WS_DATAPLANE_MODE_MAX]; /* AF_XDP_ZEROCOPY/AF_XDP_COPY/RAW_SOCKET_FALLBACK */
    int      sdn_connected;            /* 1=last push ok, 0=last push failed, -1=never probed */
    char     sdn_last_error[WS_SDN_LAST_ERROR_MAX];  /* Last SDN push error for ops debugging */
} ws_mitigation_status_t;

/* Stream 13: Integration status (phase-gated external modules) */
typedef struct ws_integration_status {
    int  intel_feed_enabled;
    int  model_extension_enabled;
    int  controller_extension_enabled;
    int  signature_feed_enabled;
    int  dataplane_extension_enabled;
    char profile[WS_INTEGRATION_PROFILE_MAX];
} ws_integration_status_t;

/* Command execution result (browser command -> pipeline ack) */
typedef struct ws_command_result {
    uint64_t timestamp_ns;
    uint32_t contract_version;
    char     request_id[WS_COMMAND_REQUEST_ID_MAX];
    char     command[WS_COMMAND_NAME_MAX];
    int      success;
    char     message[WS_COMMAND_MESSAGE_MAX];
} ws_command_result_t;

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct ws_context ws_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

ws_context_t *ws_init(const ws_config_t *cfg);
void           ws_destroy(ws_context_t *ctx);
int            ws_start(ws_context_t *ctx);  /* Starts background thread */
void           ws_stop(ws_context_t *ctx);

/* ============================================================================
 * STREAM UPDATES (called from main pipeline thread)
 * ============================================================================ */

void ws_update_metrics(ws_context_t *ctx, const ws_metrics_t *metrics);
void ws_push_activity(ws_context_t *ctx, const ws_activity_t *activity);
void ws_update_blocked_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);
void ws_update_rate_limited_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);
void ws_update_monitored_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);
void ws_update_whitelisted_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);
void ws_update_traffic_rate(ws_context_t *ctx, const ws_traffic_rate_t *rate);
void ws_update_protocol_dist(ws_context_t *ctx, const ws_protocol_dist_t *dist);
void ws_update_top_sources(ws_context_t *ctx, const ws_top_source_t *sources, uint32_t count);
void ws_update_feature_importance(ws_context_t *ctx, const ws_feature_importance_t *importance);
void ws_update_feature_vector(ws_context_t *ctx, const ws_raw_feature_vector_t *vec);
void ws_update_connections(ws_context_t *ctx, const ws_connection_t *conns, uint32_t count);
void ws_update_mitigation_status(ws_context_t *ctx, const ws_mitigation_status_t *status);
void ws_update_integration_status(ws_context_t *ctx, const ws_integration_status_t *status);
void ws_push_command_result(ws_context_t *ctx, const ws_command_result_t *result);

/* ============================================================================
 * COMMAND CALLBACK (browser -> pipeline)
 * ============================================================================ */

/* Called on the WS server thread when a client sends a JSON command.
 * cmd               - command string, e.g. "block_ip", "whitelist_ip"
 * arg               - argument string, e.g. an IP address "1.2.3.4" (may be NULL)
 * request_id        - caller-generated request id (may be NULL)
 * contract_version  - command payload contract version (0 when omitted)
 * udata             - user-provided context (typically the de_context_t pointer) */
typedef void (*ws_command_cb_t)(const char *cmd, const char *arg,
                                const char *request_id, uint32_t contract_version,
                                void *udata);

void ws_set_command_callback(ws_context_t *ctx, ws_command_cb_t cb, void *udata);

/* ============================================================================
 * STATISTICS
 * ============================================================================ */

uint32_t ws_get_client_count(ws_context_t *ctx);
uint64_t ws_get_messages_sent(const ws_context_t *ctx);
uint64_t ws_get_messages_dropped(const ws_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_WEBSOCKET_SERVER_H */

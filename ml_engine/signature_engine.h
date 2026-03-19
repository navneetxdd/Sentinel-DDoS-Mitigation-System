/*
 * Sentinel DDoS Core - Signature Engine
 *
 * Pattern matching against packet payloads and L4 headers using
 * signatures from a JSON file (e.g. signatures/methods.json).
 */

#ifndef SENTINEL_SIGNATURE_ENGINE_H
#define SENTINEL_SIGNATURE_ENGINE_H

#include "../sentinel_core/sentinel_types.h"
#include "../l1_native/feature_extractor.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SIGNATURES 256
#define MAX_SIG_PAYLOAD 64

typedef enum {
    SIG_TYPE_HEX,       /* Pure hex payload match */
    SIG_TYPE_PORT_PROTO, /* protocol + port match */
    SIG_TYPE_OTHER      /* complex/composite matching */
} sig_type_e;

typedef struct sentinel_signature {
    char name[64];
    sig_type_e type;
    
    /* SIG_TYPE_HEX */
    uint8_t payload[MAX_SIG_PAYLOAD];
    uint16_t payload_len;
    
    /* SIG_TYPE_PORT_PROTO */
    uint8_t protocol;
    uint16_t port;      /* host byte order */
    
    double threat_boost; /* confidence boost if matched (0.0 .. 1.0) */
} sentinel_signature_t;

typedef struct sig_context sig_context_t;

/* Lifecycle */
sig_context_t *sig_init(void);
void sig_destroy(sig_context_t *ctx);

/* Loading */
uint32_t sig_load_from_json(sig_context_t *ctx, const char *path);

/* Matching */
typedef struct sig_match_result {
    int matched;
    char name[64];
    double boost;
} sig_match_result_t;

void sig_match_packet(sig_context_t *ctx, const fe_packet_t *pkt, sig_match_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_SIGNATURE_ENGINE_H */

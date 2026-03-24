/*
 * Sentinel DDoS Core - Signature Engine Implementation
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include "signature_engine.h"

struct sig_context {
    sentinel_signature_t signatures[MAX_SIGNATURES];
    uint32_t count;
};

sig_context_t *sig_init(void) {
    sig_context_t *ctx = calloc(1, sizeof(*ctx));
    return ctx;
}

void sig_destroy(sig_context_t *ctx) {
    free(ctx);
}

static uint8_t hex_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static uint16_t parse_hex_payload(const char *in, uint8_t *out, uint16_t max_len) {
    uint16_t len = 0;
    if (!in || !out) return 0;
    
    /* handle 0x prefix */
    if (in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) in += 2;
    
    size_t in_len = strlen(in);
    for (size_t i = 0; i + 1 < in_len && len < max_len; i += 2) {
        if (!isxdigit(in[i]) || !isxdigit(in[i+1])) break;
        out[len++] = (hex_to_byte(in[i]) << 4) | hex_to_byte(in[i+1]);
    }
    return len;
}

static int parse_port_proto(const char *value, uint8_t *proto, uint16_t *port) {
    if (!value || !proto || !port) return 0;

    const char *p = value;
    while (*p && isspace((unsigned char)*p)) p++;

    errno = 0;
    char *end = NULL;
    unsigned long proto_ul = strtoul(p, &end, 10);
    if (errno != 0 || end == p || proto_ul > UCHAR_MAX) return 0;

    p = end;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0') return 0;

    errno = 0;
    unsigned long port_ul = strtoul(p, &end, 10);
    if (errno != 0 || end == p || port_ul > USHRT_MAX) return 0;

    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0') return 0;

    *proto = (uint8_t)proto_ul;
    *port = (uint16_t)port_ul;
    return 1;
}

static void sig_parse_json_line(sig_context_t *ctx, const char *line) {
    if (!ctx || !line || ctx->count >= MAX_SIGNATURES) return;
    
    const char *q1, *q2, *q3, *q4, *colon;
    q1 = strchr(line, '"');
    if (!q1) return;
    q2 = strchr(q1 + 1, '"');
    if (!q2) return;

    colon = strchr(q2 + 1, ':');
    if (!colon) return;

    q3 = strchr(colon + 1, '"');
    if (!q3) return;
    q4 = strchr(q3 + 1, '"');
    if (!q4) return;
    
    sentinel_signature_t *sig = &ctx->signatures[ctx->count];
    memset(sig, 0, sizeof(*sig));
    
    /* Name */
    size_t name_len = q2 - (q1 + 1);
    if (name_len >= sizeof(sig->name)) name_len = sizeof(sig->name) - 1;
    memcpy(sig->name, q1 + 1, name_len);
    sig->name[name_len] = '\0';
    
    /* Value */
    char value[256];
    size_t val_len = q4 - (q3 + 1);
    if (val_len >= sizeof(value)) val_len = sizeof(value) - 1;
    memcpy(value, q3 + 1, val_len);
    value[val_len] = '\0';
    
    if (parse_port_proto(value, &sig->protocol, &sig->port)) {
        sig->type = SIG_TYPE_PORT_PROTO;
        sig->threat_boost = 0.50; /* Base boost for known reflection port patterns */
    } else {
        sig->payload_len = parse_hex_payload(value, sig->payload, MAX_SIG_PAYLOAD);
        if (sig->payload_len > 0) {
            sig->type = SIG_TYPE_HEX;
            /* Dynamic boost based on signature length (longer = more specific) */
            sig->threat_boost = 0.60 + (0.35 * (sig->payload_len > 16 ? 1.0 : (double)sig->payload_len / 16.0));
        }
    }
    
    if (sig->type != SIG_TYPE_OTHER) {
        ctx->count++;
    }
}

uint32_t sig_load_from_json(sig_context_t *ctx, const char *path) {
    if (!ctx || !path) return 0;
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    char line[1024];
    uint32_t start_count = ctx->count;
    while (fgets(line, sizeof(line), fp)) {
        sig_parse_json_line(ctx, line);
    }
    
    fclose(fp);
    return ctx->count - start_count;
}

void sig_match_packet(sig_context_t *ctx, const fe_packet_t *pkt, sig_match_result_t *out) {
    if (!ctx || !pkt || !out) return;
    
    memset(out, 0, sizeof(*out));
    
    for (uint32_t i = 0; i < ctx->count; i++) {
        sentinel_signature_t *sig = &ctx->signatures[i];
        int matched = 0;
        
        switch (sig->type) {
            case SIG_TYPE_HEX:
                if (pkt->payload && pkt->payload_len >= sig->payload_len) {
                    if (memcmp(pkt->payload, sig->payload, sig->payload_len) == 0) {
                        matched = 1;
                    }
                }
                break;
                
            case SIG_TYPE_PORT_PROTO:
                if (pkt->protocol == sig->protocol && ntohs(pkt->src_port) == sig->port) {
                    matched = 1;
                }
                break;
                
            default:
                break;
        }
        
        if (matched) {
            /* Keep the strongest match to avoid weaker early signatures masking stronger ones. */
            if (!out->matched || sig->threat_boost > out->boost) {
                out->matched = 1;
                strncpy(out->name, sig->name, sizeof(out->name)-1);
                out->boost = sig->threat_boost;
            }
        }
    }
}

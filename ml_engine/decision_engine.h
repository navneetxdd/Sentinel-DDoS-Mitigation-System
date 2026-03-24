/*
 * Sentinel DDoS Core - Decision Engine API
 *
 * Takes a sentinel_feature_vector_t and produces a
 * sentinel_threat_assessment_t with verdict, attack type classification,
 * and score breakdown.
 *
 * The engine uses multiple heuristic models:
 *   1. EWMA baseline comparison  (volume anomaly)
 *   2. Entropy analysis           (entropy anomaly)
 *   3. Protocol ratio analysis    (protocol anomaly)
 *   4. Behavioral profiling       (behavioral anomaly)
 *
 * These are combined into a weighted threat score and mapped to a verdict.
 *
 * Optional online anomaly model:
 *   Streaming multivariate anomaly score using EWMA mean/variance over
 *   global traffic features to improve sensitivity to evolving patterns.
 *
 * Additional models (from research integration):
 *   5. Chi-square concentration test (global traffic dominance detection)
 *
 * Per-source EWMA now uses Exponential Weighted Mean Absolute Deviation (EWMMD)
 * instead of variance — more robust against flood attacks that inflate squared
 * deviations and could suppress future anomaly signals.
 *
 * Rate-of-change (derivative) feature added to volume scoring for sudden-onset
 * flood detection before the EWMA baseline adapts.
 *
 * Dynamic entropy threshold: entropy low-threshold adapts to the recent network
 * entropy history to reduce false positives in low-entropy networks.
 */

#ifndef SENTINEL_DECISION_ENGINE_H
#define SENTINEL_DECISION_ENGINE_H

#include "../sentinel_core/sentinel_types.h"
#include "../l1_native/feature_extractor.h"
#include <stdint.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION (atomic verdict thresholds: written by feedback thread, read by classify)
 * ============================================================================ */

typedef struct de_thresholds {
    /* verdict thresholds: _Atomic so no torn reads between feedback thread and main. */
    _Atomic double score_allow_max;   /* <= this  -> ALLOW   (default 0.3)  */
    _Atomic double score_rate_limit; /* <= this  -> RATE_LIMIT (def 0.6)   */
    _Atomic double score_drop;       /* <= this  -> DROP       (def 0.85)  */
    /* above score_drop -> QUARANTINE */

    /* EWMA parameters */
    double   ewma_smoothing;       /* smoothing factor (default 0.1)     */
    double   ewma_volume_sigma;    /* # of std-devs for volume anomaly   */

    /* entropy thresholds */
    double   entropy_low_thresh;   /* entropy below this is suspicious   */
    double   entropy_high_thresh;  /* entropy above this is suspicious   */

    /* protocol-specific thresholds */
    double   syn_ratio_thresh;     /* SYN ratio above this -> SYN flood  */
    double   rst_ratio_thresh;     /* RST ratio above this -> anomaly    */
    double   icmp_pps_thresh;      /* ICMP pps above this -> ICMP flood  */
    double   udp_pps_thresh;       /* UDP pps above this -> UDP flood    */

    /* behavioral */
    double   port_scan_thresh;     /* unique dst ports above this -> scan */
    double   flow_count_thresh;    /* flows from one src above this       */

    /* L7 / Asymmetry config */
    double   l7_asymmetry_size_thresh; /* avg packet size below this -> HTTP GET flood */
    double   l7_asymmetry_count_thresh;/* packet count threshold for L7 evaluation */

    /* rate limit config */
    uint32_t default_rate_limit;   /* pps when RATE_LIMIT verdict        */
    uint32_t default_quarantine;   /* seconds when QUARANTINE verdict    */

    /* component weights (must sum to ~1.0) */
    double   weight_volume;
    double   weight_entropy;
    double   weight_protocol;
    double   weight_behavioral;
    double   weight_ml;
    double   weight_l7;
    double   weight_anomaly;
    double   weight_chi_square;   /* chi-square concentration model weight */
    double   weight_fanin;        /* distributed-source fan-in model weight */
    double   weight_signature;    /* reflection signature hint weight */

    /* chi-square thresholds */
    double   chi_square_thresh;   /* normalization divisor for chi stat (default 50.0) */
    double   fanin_distributed_thresh; /* unique src count where distributed fan-in saturates */

    /* online anomaly configuration */
    double   anomaly_smoothing;
    double   anomaly_sigma;
    uint32_t anomaly_warmup;
    double   anomaly_learn_max_threat;

    /* ML fail-safe gating */
    double   ml_max_isolation;              /* tolerated gap between ML and non-ML evidence */
    double   ml_reliability_floor;          /* below this, ML cannot drive hard enforcement */
    double   min_confidence_for_enforcement;/* below this, cap to RATE_LIMIT unless heuristics are strong */
    double   min_non_ml_score_for_hard_block; /* non-ML evidence needed for DROP/QUARANTINE */

    /* hard-enforcement safety guard (false-positive reduction) */
    double   min_src_flows_for_hard_enforcement;   /* below this, prefer RATE_LIMIT over hard block */
    double   min_packet_count_for_hard_enforcement;/* small samples should not hard-block by default */
} de_thresholds_t;

#define DE_THRESHOLDS_DEFAULT { \
    .score_allow_max    = 0.30, \
    .score_rate_limit   = 0.60, \
    .score_drop         = 0.85, \
    .ewma_smoothing     = 0.10, \
    .ewma_volume_sigma  = 3.0,  \
    .entropy_low_thresh = 0.20, \
    .entropy_high_thresh= 0.85, \
    .syn_ratio_thresh   = 0.80, \
    .rst_ratio_thresh   = 0.50, \
    .icmp_pps_thresh    = 100, \
    .udp_pps_thresh     = 500,\
    .port_scan_thresh   = 100,  \
    .flow_count_thresh  = 500,  \
    .l7_asymmetry_size_thresh = 80.0, \
    .l7_asymmetry_count_thresh = 50.0, \
    .default_rate_limit = 1000, \
    .default_quarantine = 300,  \
    .weight_volume      = 0.12, \
    .weight_entropy     = 0.08, \
    .weight_protocol    = 0.12, \
    .weight_behavioral  = 0.08, \
    .weight_ml          = 0.35, \
    .weight_l7          = 0.07, \
    .weight_anomaly     = 0.05, \
    .weight_chi_square  = 0.05, \
    .weight_fanin       = 0.03, \
    .weight_signature   = 0.05, \
    .chi_square_thresh  = 50.0, \
    .fanin_distributed_thresh = 16.0, \
    .anomaly_smoothing  = 0.02, \
    .anomaly_sigma      = 3.5,  \
    .anomaly_warmup     = 64,   \
    .anomaly_learn_max_threat = 0.35, \
    .ml_max_isolation   = 0.65, \
    .ml_reliability_floor = 0.40, \
    .min_confidence_for_enforcement = 0.50, \
    .min_non_ml_score_for_hard_block = 0.45, \
    .min_src_flows_for_hard_enforcement = 4.0, \
    .min_packet_count_for_hard_enforcement = 48.0 \
}

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct de_context de_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

de_context_t *de_init(const de_thresholds_t *cfg);
void          de_destroy(de_context_t *ctx);

/*  Load reflection signatures from JSON as bounded hints.
 *  Returns the number of signatures loaded. */
uint32_t      de_load_signatures(de_context_t *ctx, const char *json_path);

/*  Match a packet against loaded signatures.
 *  Returns the threat boost (0.0 to 1.0) if matched. */
double        de_match_packet(de_context_t *ctx, const fe_packet_t *pkt);

/*  Get current thresholds (for telemetry / feature importance). */
const de_thresholds_t *de_get_thresholds(const de_context_t *ctx);

/* ============================================================================
 * CLASSIFICATION
 * ============================================================================ */

/*  Classify a feature vector and produce a threat assessment.
 *  model_extension_enabled: if 1, ML activates only when baseline threat >= 0.30.
 *                           if 0, ML is disabled entirely (baseline-only mode).
 *  Returns 0 on success. */
int de_classify(de_context_t *ctx,
                const sentinel_feature_vector_t *features,
                sentinel_threat_assessment_t *out,
                int model_extension_enabled);

/* ============================================================================
 * BASELINE MANAGEMENT
 * ============================================================================ */

/*  Manually reset all learned baselines (useful after config change). */
void de_reset_baselines(de_context_t *ctx);

/*  Get the number of tracked baselines. */
uint32_t de_baseline_count(const de_context_t *ctx);

/*  Apply feedback-suggested threshold adjustments (closed-loop).
 *  adj must be a pointer to fb_adjustments_t (see feedback.h). */
void de_apply_adjustments(de_context_t *ctx, const void *adj);

/* ============================================================================
 * ALLOW/DENY LISTS
 * ============================================================================ */

int de_add_allowlist(de_context_t *ctx, uint32_t ip);
int de_add_denylist(de_context_t *ctx, uint32_t ip);
int de_remove_allowlist(de_context_t *ctx, uint32_t ip);
int de_remove_denylist(de_context_t *ctx, uint32_t ip);
void de_clear_denylist(de_context_t *ctx);

/* Set global rate limit thresholds (score_rate_limit, score_drop). */
void de_set_global_rate_limit(de_context_t *ctx, double score_rate_limit, double score_drop);

/* Dynamic threshold setters (Settings sync from UI). Values as received from frontend. */
void de_set_syn_threshold(de_context_t *ctx, double value);      /* UI pps -> syn_ratio 0-1 */
void de_set_conn_threshold(de_context_t *ctx, double value);     /* UI flows -> flow_count_thresh */
void de_set_flow_count_threshold(de_context_t *ctx, double value);
void de_set_pps_threshold(de_context_t *ctx, double value);      /* udp + icmp pps */
void de_set_entropy_threshold(de_context_t *ctx, double value);  /* UI 0-100 -> 0-1 */

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_DECISION_ENGINE_H */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../sentinel_core/sentinel_types.h"
#include "../l1_native/feature_extractor.h"
#include "../ml_engine/decision_engine.h"
#include "../feedback/feedback.h"
#include "../sdncontrol/sdn_controller.h"

static void test_feature_to_decision_path(void)
{
    fe_config_t fe_cfg = FE_CONFIG_DEFAULT;
    de_thresholds_t de_cfg = DE_THRESHOLDS_DEFAULT;

    fe_context_t *fe = fe_init(&fe_cfg);
    de_context_t *de = de_init(&de_cfg);
    assert(fe != NULL);
    assert(de != NULL);

    fe_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip = 0x01020304;
    pkt.dst_ip = 0x05060708;
    pkt.src_port = 0x3930; /* 12345 in network-byte-order literal */
    pkt.dst_port = 0x0050; /* 80 in network-byte-order literal */
    pkt.protocol = 6;
    pkt.payload_len = 60;
    pkt.ttl = 64;
    pkt.tcp_flags = FE_TCP_SYN;

    for (uint32_t i = 0; i < 64; i++) {
        pkt.packet_id = i + 1;
        pkt.timestamp_ns = 1000000000ULL + (uint64_t)i * 1000000ULL;
        assert(fe_ingest_packet(fe, &pkt) == 0);
    }

    sentinel_feature_vector_t fv;
    assert(fe_extract_last(fe, &fv) == 0);
    fe_top_flow_t top_flows[4];
    uint32_t nf = fe_get_top_flows(fe, top_flows, 4);
    assert(nf > 0);
    assert(top_flows[0].packets > 0);

    sentinel_threat_assessment_t ta;
    assert(de_classify(de, &fv, &ta) == 0);
    assert(ta.threat_score >= 0.0 && ta.threat_score <= 1.0);
    assert(ta.score_ml >= 0.0 && ta.score_ml <= 1.0);
    assert(ta.score_l7 >= 0.0 && ta.score_l7 <= 1.0);
    assert(ta.score_anomaly >= 0.0 && ta.score_anomaly <= 1.0);
    assert(ta.ml_reliability >= 0.0 && ta.ml_reliability <= 1.0);
    assert(ta.confidence >= 0.0 && ta.confidence <= 1.0);

    de_destroy(de);
    fe_destroy(fe);
}

static void test_online_anomaly_path(void)
{
    de_thresholds_t de_cfg = DE_THRESHOLDS_DEFAULT;
    de_cfg.weight_anomaly = 0.60;
    de_cfg.weight_volume = 0.10;
    de_cfg.weight_entropy = 0.10;
    de_cfg.weight_protocol = 0.10;
    de_cfg.weight_behavioral = 0.05;
    de_cfg.weight_ml = 0.03;
    de_cfg.weight_l7 = 0.02;
    de_cfg.anomaly_warmup = 32;
    de_cfg.anomaly_smoothing = 0.05;

    de_context_t *de = de_init(&de_cfg);
    assert(de != NULL);

    sentinel_feature_vector_t base;
    memset(&base, 0, sizeof(base));
    base.src_ip = 0x0A000001;
    base.dst_ip = 0x0A000002;
    base.src_port = 0x3930;
    base.dst_port = 0x0050;
    base.protocol = 6;
    base.packet_count = 64;
    base.window_duration_sec = 1.0;
    base.packets_per_second = 120.0;
    base.bytes_per_second = 12000.0;
    base.syn_ratio = 0.08;
    base.rst_ratio = 0.01;
    base.unique_dst_ports = 3;
    base.src_total_flows = 2;
    base.avg_packet_size = 100.0;
    base.avg_iat_us = 900.0;

    sentinel_threat_assessment_t ta = {0};
    for (int i = 0; i < 48; i++) {
        assert(de_classify(de, &base, &ta) == 0);
    }
    double baseline = ta.threat_score;

    sentinel_feature_vector_t burst = base;
    burst.packets_per_second = 90000.0;
    burst.bytes_per_second = 90000000.0;
    burst.syn_ratio = 0.90;
    burst.unique_dst_ports = 600;
    burst.src_total_flows = 1200;

    assert(de_classify(de, &burst, &ta) == 0);
    assert(ta.threat_score > baseline);
    assert((ta.threat_score - baseline) > 0.05);
    assert(ta.score_anomaly >= 0.0 && ta.score_anomaly <= 1.0);
    assert(ta.ml_reliability >= 0.0 && ta.ml_reliability <= 1.0);

    de_destroy(de);
}

static void test_feedback_adjustments(void)
{
    fb_config_t cfg = FB_CONFIG_DEFAULT;
    cfg.history_size = 256;
    cfg.evaluation_window_sec = 300;
    fb_context_t *fb = fb_init(&cfg);
    assert(fb != NULL);

    for (int i = 0; i < 32; i++) {
        assert(fb_record_action(fb, 0x0A000001, VERDICT_ALLOW, SENTINEL_ATTACK_NONE, 0.9) == 0);
        assert(fb_auto_detect_fn(fb, 0x0A000001, 0.9) >= 0);
    }

    fb_adjustments_t adj;
    assert(fb_suggest_adjustments(fb, &adj) == 0);
    assert(adj.should_adjust == 0 || adj.should_adjust == 1);

    fb_policy_stats_t ps;
    assert(fb_get_policy_stats(fb, &ps) == 0);
    assert(ps.active_arm <= 2);

    fb_destroy(fb);
}

static void test_anomaly_drift_resistance(void)
{
    de_thresholds_t de_cfg = DE_THRESHOLDS_DEFAULT;
    de_cfg.weight_anomaly = 0.70;
    de_cfg.weight_volume = 0.10;
    de_cfg.weight_entropy = 0.05;
    de_cfg.weight_protocol = 0.10;
    de_cfg.weight_behavioral = 0.03;
    de_cfg.weight_ml = 0.01;
    de_cfg.weight_l7 = 0.01;
    de_cfg.anomaly_warmup = 24;
    de_cfg.anomaly_smoothing = 0.05;
    de_cfg.anomaly_learn_max_threat = 0.30;

    de_context_t *de = de_init(&de_cfg);
    assert(de != NULL);

    sentinel_feature_vector_t base;
    memset(&base, 0, sizeof(base));
    base.src_ip = 0x0A000010;
    base.dst_ip = 0x0A000020;
    base.src_port = 0x3930;
    base.dst_port = 0x0050;
    base.protocol = 6;
    base.packet_count = 64;
    base.window_duration_sec = 1.0;
    base.packets_per_second = 150.0;
    base.bytes_per_second = 15000.0;
    base.syn_ratio = 0.06;
    base.rst_ratio = 0.01;
    base.unique_dst_ports = 4;
    base.src_total_flows = 3;
    base.avg_packet_size = 100.0;
    base.avg_iat_us = 850.0;

    sentinel_threat_assessment_t ta = {0};
    for (int i = 0; i < 40; i++) {
        assert(de_classify(de, &base, &ta) == 0);
    }
    double baseline = ta.threat_score;

    sentinel_feature_vector_t attack = base;
    attack.packets_per_second = 120000.0;
    attack.bytes_per_second = 120000000.0;
    attack.syn_ratio = 0.97;
    attack.unique_dst_ports = 900;
    attack.src_total_flows = 2000;

    double first = 0.0;
    double last = 0.0;
    for (int i = 0; i < 20; i++) {
        assert(de_classify(de, &attack, &ta) == 0);
        if (i == 0) first = ta.threat_score;
        if (i == 19) last = ta.threat_score;
    }
    assert(first > baseline + 0.05);
    assert(last > baseline + 0.05);
    assert(last >= first - 0.15);

    de_destroy(de);
}

static void test_sdn_rule_build(void)
{
    sdn_config_t cfg = SDN_CONFIG_DEFAULT;
    sdn_context_t *sdn = sdn_init(&cfg);
    assert(sdn != NULL);

    sentinel_threat_assessment_t a;
    memset(&a, 0, sizeof(a));
    a.src_ip = 0x0A000002;
    a.dst_ip = 0x0A000003;
    a.src_port = 0x04D2; /* 1234 in network-byte-order literal */
    a.dst_port = 0x0050; /* 80 in network-byte-order literal */
    a.protocol = 6;
    a.attack_type = SENTINEL_ATTACK_SYN_FLOOD;
    a.verdict = VERDICT_DROP;
    a.threat_score = 0.95;

    sentinel_sdn_rule_t r;
    assert(sdn_build_rule_from_assessment(sdn, &a, &r) == 0);
    assert(r.action == SDN_ACTION_DROP);
    assert(r.match_src_ip == a.src_ip);
    assert(r.match_dst_ip == a.dst_ip);
    assert(r.match_protocol == a.protocol);

    sdn_destroy(sdn);
}

int main(void)
{
    printf("=== Sentinel Integration Test Suite ===\n");
    test_feature_to_decision_path();
    test_online_anomaly_path();
    test_anomaly_drift_resistance();
    test_feedback_adjustments();
    test_sdn_rule_build();
    printf("=== All Tests Passed ===\n");
    return 0;
}

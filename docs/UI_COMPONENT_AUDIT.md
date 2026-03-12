# Sentinel UI Component Audit

Every UI component and its data source, wiring status, and verification notes.

## Page: Index (Overview)

| Component      | Data Source                    | Status   | Notes                                              |
|----------------|--------------------------------|----------|----------------------------------------------------|
| StatusBadge    | `riskScore` from `featureImportance` | Wired   | Reflects attack/observation/normal                 |
| KPICard x4     | `ws.metrics`, `ws.mitigationStatus` | Wired   | Traffic rate, connections, mitigation, uptime      |
| TrafficChart   | `ws.trafficHistory`            | Wired    | Packets over time from traffic_rate                |
| RiskGauge      | `riskScore` from `featureImportance` | Wired  | 0–100 risk from avg_threat_score                   |
| System Health  | `ws.metrics`, `ws.connected`   | Wired    | Network, ML engine, CPU, memory                    |

## Page: Traffic Analysis

| Component      | Data Source                    | Status   | Notes                                              |
|----------------|--------------------------------|----------|----------------------------------------------------|
| TrafficChart   | `ws.trafficHistory`            | Wired    | Same as Index                                      |
| ProtocolChart  | `ws.protocolDist`              | Wired    | TCP/UDP/ICMP/Other bytes                           |
| TopIPsTable    | `ws.topSources`, `ws.blockedIPs`, `ws.rateLimitedIPs` | Wired | IP, packets, threat %, status (blocked/rate-limited/normal) |
| StatusBadge    | `riskScore`                    | Wired    | Same as Index                                      |
| Footer stats   | `ws.trafficRate`, `ws.metrics` | Wired    | PPS, active IPs, flows, bandwidth                  |

## Page: Decision Engine

| Component          | Data Source                    | Status   | Notes                                              |
|--------------------|--------------------------------|----------|----------------------------------------------------|
| DecisionPanel      | `threatScore`, `attackProbability` | Wired  | From feature_importance.avg_threat_score           |
| FeatureImportanceChart | `ws.featureImportance`     | Wired    | Volume, entropy, protocol, behavioral, ML, L7, anomaly weights |
| ExplanationBox     | `featureImportance`, classification | Wired  | Contextual explanation per classification          |
| Model Performance  | `ws.metrics`, `ws.featureImportance` | Wired | Threat score, detections, policy arm/reward        |
| Pipeline Stats     | `ws.metrics`                   | Wired    | Active flows, sources, kernel drops                |
| Inference Stats    | `ws.metrics`                   | Wired    | ML ops, probability, CPU, memory                   |
| ModelBenchmarkPanel| `useModelBenchmarkReport`      | Wired    | RF/XGBoost/IsolationForest; shows top features or anomaly threshold for IF |

## Page: Mitigation Control

| Component          | Data Source                    | Status   | Notes                                              |
|--------------------|--------------------------------|----------|----------------------------------------------------|
| Stats cards        | `ws.mitigationStatus`          | Wired    | Blocked, rate-limited, monitored, whitelisted      |
| AutoMitigationToggle | `ws.mitigationStatus`, `ws.sendCommand` | Wired | enable/disable_auto_mitigation                     |
| MitigationTimeline | `ws.activityLog`               | Wired    | IP, attack type, protocol, threat score, enforced  |
| Quick Actions      | `ws.sendCommand`               | Wired    | block_all_flagged, apply_rate_limit, etc.          |
| Blocked IPs table  | `ws.blockedIPs`                | Wired    | Per-IP unblock via unblock_ip                      |
| Rate-Limited IPs   | `ws.rateLimitedIPs`            | Wired    | Per-IP clear via unblock_ip                        |
| View Details       | Scroll to timeline             | Wired    | Smooth scroll to mitigation log                    |

## Page: Settings

| Component       | Data Source                    | Status   | Notes                                              |
|-----------------|--------------------------------|----------|----------------------------------------------------|
| All sliders/toggles | localStorage               | Wired    | Persisted on save                                  |
| IP Whitelist    | localStorage + `ws.sendCommand`| Wired    | whitelist_ip / remove_whitelist for single IPv4    |
| IP Blacklist    | localStorage + `ws.sendCommand`| Wired    | block_ip / unblock_ip for single IPv4              |
| Model Version   | `benchmarks.report`            | Wired    | Dropdown from model_benchmark_report.json          |
| ModelBenchmarkPanel | `useModelBenchmarkReport`  | Wired    | Same as Decision Engine                            |

## Dashboard Components (shared)

| Component      | Usage                    | Status   | Notes                                              |
|----------------|---------------------------|----------|----------------------------------------------------|
| DashboardLayout| All pages                 | Wired    | Sidebar, connection status from `ws.connected`     |
| StatusBadge    | Index, TrafficAnalysis    | Wired    |                                                    |
| KPICard        | Index                     | Wired    |                                                    |
| RiskGauge      | Index                     | Wired    |                                                    |
| TrafficChart   | Index, TrafficAnalysis    | Wired    |                                                    |
| ProtocolChart  | TrafficAnalysis           | Wired    |                                                    |
| TopIPsTable    | TrafficAnalysis           | Wired    |                                                    |
| DecisionPanel  | DecisionEngine            | Wired    |                                                    |
| FeatureImportanceChart | DecisionEngine     | Wired    |                                                    |
| ExplanationBox | DecisionEngine            | Wired    |                                                    |
| ModelBenchmarkPanel | DecisionEngine, Settings | Wired  |                                                    |
| AutoMitigationToggle | MitigationControl      | Wired    |                                                    |
| MitigationTimeline | MitigationControl       | Wired    |                                                    |
| SettingsCard   | Settings                  | Wired    |                                                    |
| SliderSetting  | Settings                  | Wired    |                                                    |
| ToggleSetting  | Settings                  | Wired    |                                                    |
| SelectSetting  | Settings                  | Wired    |                                                    |
| IPListManager  | Settings                  | Wired    |                                                    |

## Not Used (present in codebase)

| Component        | Notes                                                        |
|------------------|--------------------------------------------------------------|
| SimulationToggle | Not rendered; would need backend support for simulation mode |

## WebSocket Streams → UI Mapping

| Stream               | Consumed By                                                   |
|----------------------|---------------------------------------------------------------|
| metrics              | Index, DecisionEngine, MitigationControl (stats)              |
| activity_logs        | MitigationControl (MitigationTimeline)                        |
| blocked_ips          | MitigationControl (Blocked IPs), TopIPsTable (status)         |
| rate_limited_ips     | MitigationControl (Rate-Limited IPs), TopIPsTable (status)    |
| monitored_ips        | Received but only reflected in mitigation_status totals       |
| whitelisted_ips      | Received but only reflected in mitigation_status totals       |
| traffic_rate         | TrafficChart, Index footer                                    |
| protocol_distribution| ProtocolChart                                                |
| top_sources          | TopIPsTable                                                   |
| feature_importance   | DecisionEngine (charts, explanation)                          |
| active_connections   | Received; no dedicated UI (could add connection table)        |
| mitigation_status   | MitigationControl, Index, AutoMitigationToggle                |

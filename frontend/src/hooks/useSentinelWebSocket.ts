import { useState, useEffect, useRef, useCallback } from "react";

/* ============================================================================
 * Type definitions matching the C backend's 12 JSON streams
 * ============================================================================ */

export interface SentinelMetrics {
  packets_per_sec: number;
  bytes_per_sec: number;
  active_flows: number;
  active_sources: number;
  ml_classifications_per_sec: number;
  cpu_usage_percent: number;
  memory_usage_mb: number;
  kernel_drops: number;
  userspace_drops: number;
  top_sources?: string[];
  protocol_distribution?: Record<string, number>;
}

export interface SentinelActivity {
  timestamp: number;
  src_ip: string;
  action: string;
  attack_type: string;
  threat_score: number;
  reason: string;
  enforced: boolean;
}

export interface SentinelBlockedIP {
  ip: string;
  rule_id: number;
  timestamp: number;
}

export interface SentinelRateLimitedIP {
  ip: string;
  limit_pps: number;
  rule_id: number;
}

export interface SentinelMonitoredIP {
  ip: string;
  rule_id: number;
  timestamp: number;
}

export interface SentinelWhitelistedIP {
  ip: string;
}

export interface SentinelTrafficRate {
  total_pps: number;
  total_bps: number;
  tcp_pps: number;
  udp_pps: number;
  icmp_pps: number;
  other_pps: number;
}

export interface SentinelProtocolDist {
  tcp_percent: number;
  udp_percent: number;
  icmp_percent: number;
  other_percent: number;
  tcp_bytes: number;
  udp_bytes: number;
  icmp_bytes: number;
  other_bytes: number;
}

export interface SentinelTopSource {
  ip: string;
  packets: number;
  bytes: number;
  flows: number;
  suspicious: number;
  threat_score: number;
}

export interface SentinelFeatureImportance {
  volume_weight: number;
  entropy_weight: number;
  protocol_weight: number;
  behavioral_weight: number;
  ml_weight: number;
  l7_weight: number;
  anomaly_weight: number;
  avg_threat_score: number;
  detections_last_10s: number;
  policy_arm: number;
  policy_updates: number;
  policy_last_reward: number;
}

export interface SentinelConnection {
  src: string;
  dst: string;
  proto: number;
  packets: number;
  bytes: number;
}

export interface SentinelMitigationStatus {
  total_blocked: number;
  total_rate_limited: number;
  total_monitored: number;
  total_whitelisted: number;
  kernel_verdict_cache_hits: number;
  kernel_verdict_cache_misses: number;
  active_sdn_rules: number;
  auto_mitigation_enabled: boolean;
  kernel_dropping_enabled?: boolean;
  sdn_connected?: number; /* 1=ok, 0=failed, -1=never probed */
  sdn_last_error?: string; /* Last SDN push error for ops debugging */
}

export interface TrafficDataPoint {
  time: string;
  packets: number;
}

export interface ShapContribution {
  name: string;
  value: number;
}

export const EXPLAIN_API_URL = "http://localhost:5001";

/* ============================================================================
 * Complete state exposed by the hook
 * ============================================================================ */

export interface SentinelState {
  connected: boolean;
  metrics: SentinelMetrics | null;
  activityLog: SentinelActivity[];
  blockedIPs: SentinelBlockedIP[];
  rateLimitedIPs: SentinelRateLimitedIP[];
  monitoredIPs: SentinelMonitoredIP[];
  whitelistedIPs: SentinelWhitelistedIP[];
  trafficRate: SentinelTrafficRate | null;
  protocolDist: SentinelProtocolDist | null;
  topSources: SentinelTopSource[];
  featureImportance: SentinelFeatureImportance | null;
  featureVector: number[] | null;
  shapContributions: ShapContribution[] | null;
  shapLoading: boolean;
  shapError: string | null;
  connections: SentinelConnection[];
  mitigationStatus: SentinelMitigationStatus | null;
  trafficHistory: TrafficDataPoint[];
  sendCommand: (command: string, params?: Record<string, string>) => void;
  requestShapContributions: () => Promise<void>;
}

const MAX_ACTIVITY_LOG = 100;
const MAX_TRAFFIC_HISTORY = 60;

const WS_URL = `ws://${window.location.hostname}:8765`;

export function useSentinelWebSocket(): SentinelState {
  const [connected, setConnected] = useState(false);
  const [metrics, setMetrics] = useState<SentinelMetrics | null>(null);
  const [activityLog, setActivityLog] = useState<SentinelActivity[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<SentinelBlockedIP[]>([]);
  const [rateLimitedIPs, setRateLimitedIPs] = useState<SentinelRateLimitedIP[]>([]);
  const [monitoredIPs, setMonitoredIPs] = useState<SentinelMonitoredIP[]>([]);
  const [whitelistedIPs, setWhitelistedIPs] = useState<SentinelWhitelistedIP[]>([]);
  const [trafficRate, setTrafficRate] = useState<SentinelTrafficRate | null>(null);
  const [protocolDist, setProtocolDist] = useState<SentinelProtocolDist | null>(null);
  const [topSources, setTopSources] = useState<SentinelTopSource[]>([]);
  const [featureImportance, setFeatureImportance] = useState<SentinelFeatureImportance | null>(null);
  const [featureVector, setFeatureVector] = useState<number[] | null>(null);
  const [shapContributions, setShapContributions] = useState<ShapContribution[] | null>(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapError, setShapError] = useState<string | null>(null);
  const [connections, setConnections] = useState<SentinelConnection[]>([]);
  const [mitigationStatus, setMitigationStatus] = useState<SentinelMitigationStatus | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const msg = JSON.parse(event.data);
      if (!msg.type || msg.data === undefined) return;

      switch (msg.type) {
        case "metrics":
          setMetrics(msg.data as SentinelMetrics);
          break;

        case "activity_logs":
          setActivityLog((prev) => {
            const entry = msg.data as SentinelActivity;
            const next = [entry, ...prev];
            return next.length > MAX_ACTIVITY_LOG ? next.slice(0, MAX_ACTIVITY_LOG) : next;
          });
          break;

        case "blocked_ips":
          setBlockedIPs(Array.isArray(msg.data) ? msg.data : []);
          break;

        case "rate_limited_ips":
          setRateLimitedIPs(Array.isArray(msg.data) ? msg.data : []);
          break;

        case "monitored_ips":
          setMonitoredIPs(Array.isArray(msg.data) ? msg.data : []);
          break;

        case "whitelisted_ips":
          setWhitelistedIPs(Array.isArray(msg.data) ? msg.data : []);
          break;

        case "traffic_rate": {
          const rate = msg.data as SentinelTrafficRate;
          setTrafficRate(rate);
          setTrafficHistory((prev) => {
            const point: TrafficDataPoint = {
              time: new Date().toLocaleTimeString("en-US", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              }),
              packets: rate.total_pps,
            };
            const next = [...prev, point];
            return next.length > MAX_TRAFFIC_HISTORY
              ? next.slice(next.length - MAX_TRAFFIC_HISTORY)
              : next;
          });
          break;
        }

        case "protocol_distribution":
          setProtocolDist(msg.data as SentinelProtocolDist);
          break;

        case "top_sources":
          setTopSources(Array.isArray(msg.data) ? msg.data : []);
          break;

        case "feature_importance":
          setFeatureImportance(msg.data as SentinelFeatureImportance);
          break;

        case "feature_vector":
          setFeatureVector(Array.isArray(msg.data) ? msg.data : null);
          break;

        case "active_connections":
          setConnections(Array.isArray(msg.data) ? msg.data : []);
          break;

        case "mitigation_status":
          setMitigationStatus(msg.data as SentinelMitigationStatus);
          break;
      }
    } catch {
      /* Silently ignore malformed messages */
    }
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setConnected(true);
        if (reconnectTimerRef.current) {
          clearTimeout(reconnectTimerRef.current);
          reconnectTimerRef.current = null;
        }
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        reconnectTimerRef.current = setTimeout(connect, 2000);
      };

      ws.onerror = () => {
        ws.close();
      };

      ws.onmessage = handleMessage;
      wsRef.current = ws;
    } catch {
      reconnectTimerRef.current = setTimeout(connect, 2000);
    }
  }, [handleMessage]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  }, [connect]);

  const sendCommand = useCallback((command: string, params?: Record<string, string>) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ command, ...params }));
    }
  }, []);

  const requestShapContributions = useCallback(async () => {
    const fv = featureVector ?? [];
    if (fv.length !== 20) {
      setShapError("No feature vector available. Wait for traffic and try again.");
      return;
    }
    setShapLoading(true);
    setShapError(null);
    try {
      const res = await fetch(`${EXPLAIN_API_URL}/shap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ samples: [fv] }),
      });
      const json = await res.json();
      if (!res.ok) {
        setShapError(json.error || `HTTP ${res.status}`);
        setShapContributions(null);
        return;
      }
      const contribs = json.contributions?.[0] ?? [];
      setShapContributions(contribs);
    } catch (e) {
      setShapError(e instanceof Error ? e.message : "Explain API unreachable");
      setShapContributions(null);
    } finally {
      setShapLoading(false);
    }
  }, [featureVector]);

  return {
    connected,
    metrics,
    activityLog,
    blockedIPs,
    rateLimitedIPs,
    monitoredIPs,
    whitelistedIPs,
    trafficRate,
    protocolDist,
    topSources,
    featureImportance,
    featureVector,
    shapContributions,
    shapLoading,
    shapError,
    connections,
    mitigationStatus,
    trafficHistory,
    sendCommand,
    requestShapContributions,
  };
}

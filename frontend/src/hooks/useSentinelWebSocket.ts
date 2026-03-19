import { createContext, createElement, useContext, useState, useEffect, useRef, useCallback, type ReactNode } from "react";
import { fetchExplainApi, isExplainApiConfigured, WS_URL_CANDIDATES, WS_API_KEY } from "@/lib/apiConfig";

/* ============================================================================
 * Lightweight validators for critical message shapes (avoid NaN/crashes)
 * ============================================================================ */

function isMetricsLike(d: unknown): d is SentinelMetrics {
  if (!d || typeof d !== "object") return false;
  const o = d as Record<string, unknown>;
  return (
    typeof o.packets_per_sec === "number" &&
    typeof o.bytes_per_sec === "number" &&
    typeof o.active_flows === "number" &&
    typeof o.active_sources === "number" &&
    typeof o.cpu_usage_percent === "number" &&
    typeof o.memory_usage_mb === "number"
  );
}

function isCommandResultLike(d: unknown): d is SentinelCommandResult {
  if (!d || typeof d !== "object") return false;
  const o = d as Record<string, unknown>;
  return (
    typeof o.timestamp === "number" &&
    typeof o.command === "string" &&
    typeof o.success === "boolean" &&
    typeof o.message === "string"
  );
}

function isMitigationStatusLike(d: unknown): d is SentinelMitigationStatus {
  if (!d || typeof d !== "object") return false;
  const o = d as Record<string, unknown>;
  return (
    typeof o.total_blocked === "number" &&
    typeof o.total_rate_limited === "number" &&
    typeof o.total_monitored === "number" &&
    typeof o.total_whitelisted === "number"
  );
}

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
  chi_square_weight?: number;
  fanin_weight?: number;
  signature_weight?: number;
  avg_threat_score: number;
  avg_fanin_score?: number;
  avg_signature_score?: number;
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

export interface SentinelIntegrationStatus {
  intel_feed_enabled: boolean;
  model_extension_enabled: boolean;
  controller_extension_enabled: boolean;
  signature_feed_enabled: boolean;
  dataplane_extension_enabled: boolean;
  gatekeeper_enabled?: boolean;
  gatekeeper_connected?: number;
  gatekeeper_failure_count?: number;
  gatekeeper_failure_threshold?: number;
  gatekeeper_circuit_open?: boolean;
  gatekeeper_next_retry_sec?: number;
  gatekeeper_last_error?: string;
  profile: string;
}

export interface SentinelCommandResult {
  timestamp: number;
  contract_version: number;
  request_id: string;
  command: string;
  success: boolean;
  message: string;
}

/** Pure helper: true if command_result should update lastCommandResult (request_id match or absent). */
export function shouldApplyCommandResult(
  data: SentinelCommandResult,
  lastSentRequestId: string | null,
): boolean {
  if (lastSentRequestId == null) return true;
  const rid = typeof data.request_id === "string" && data.request_id.length > 0 ? data.request_id : null;
  return rid == null || rid === lastSentRequestId;
}

export interface TrafficDataPoint {
  time: string;
  packets: number;
}

export interface ShapContribution {
  name: string;
  value: number;
}

/* ============================================================================
 * Complete state exposed by the hook
 * ============================================================================ */

export interface SentinelState {
  connected: boolean;
  telemetrySchemaVersion: number | null;
  telemetrySchemaMismatch: boolean;
  telemetrySchemaError: string | null;
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
  integrationStatus: SentinelIntegrationStatus | null;
  lastCommandResult: SentinelCommandResult | null;
  trafficHistory: TrafficDataPoint[];
  /** Activity events loaded from the persistent event log on mount. */
  persistedEvents: SentinelActivity[];
  /** True when Explain API was configured but /events fetch failed (e.g. API not running). */
  eventHistoryUnavailable: boolean;
  /** True when Explain API /events or /health succeeded; false on failure; null when not configured or not yet checked. */
  explainApiReachable: boolean | null;
  /** Count of failed activity-log POSTs to Explain API (best-effort sync); >0 can indicate API down or network issues. */
  activitySyncFailures: number;
  /** Count of malformed WebSocket messages ignored (parse errors); >0 can indicate protocol or backend issues. */
  parseErrorCount: number;
  sendCommand: (command: string, params?: Record<string, string>) => void;
  requestShapContributions: () => Promise<void>;
}

const MAX_ACTIVITY_LOG = 100;
const MAX_TRAFFIC_HISTORY = 60;
const COMMAND_CONTRACT_VERSION = 1;
const TELEMETRY_SCHEMA_VERSION = 1;
const SHAP_FEATURE_NAMES_20 = [
  "packets_per_second",
  "bytes_per_second",
  "syn_ratio",
  "rst_ratio",
  "dst_port_entropy",
  "payload_byte_entropy",
  "unique_dst_ports",
  "avg_packet_size",
  "stddev_packet_size",
  "http_request_count",
  "fin_ratio",
  "src_port_entropy",
  "unique_src_ports",
  "avg_ttl",
  "stddev_ttl",
  "avg_iat_us",
  "stddev_iat_us",
  "src_total_flows",
  "src_packets_per_second",
  "dns_query_count",
] as const;
const SHAP_FEATURE_NAMES_21 = [...SHAP_FEATURE_NAMES_20, "chi_square_score"] as const;

function generateRequestId(): string {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
  } catch {
    /* ignore and use fallback */
  }
  return `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

async function sha256Hex(value: string): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle || typeof TextEncoder === "undefined") {
    throw new Error("Browser does not support WebCrypto SHA-256");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function computeFeatureSchemaHash(featureNames: readonly string[]): Promise<string> {
  const normalized = featureNames.map((name) => name.trim().toLowerCase()).join("|");
  return sha256Hex(normalized);
}

function useSentinelWebSocketState(): SentinelState {
  const [connected, setConnected] = useState(false);
  const [telemetrySchemaVersion, setTelemetrySchemaVersion] = useState<number | null>(null);
  const [telemetrySchemaMismatch, setTelemetrySchemaMismatch] = useState(false);
  const [telemetrySchemaError, setTelemetrySchemaError] = useState<string | null>(null);
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
  const [integrationStatus, setIntegrationStatus] = useState<SentinelIntegrationStatus | null>(null);
  const [lastCommandResult, setLastCommandResult] = useState<SentinelCommandResult | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>([]);
  const [persistedEvents, setPersistedEvents] = useState<SentinelActivity[]>([]);
  const [eventHistoryUnavailable, setEventHistoryUnavailable] = useState(false);
  const [explainApiReachable, setExplainApiReachable] = useState<boolean | null>(null);
  const [activitySyncFailures, setActivitySyncFailures] = useState(0);
  const [parseErrorCount, setParseErrorCount] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectDelayRef = useRef<number>(1000);
  const wsCandidateIndexRef = useRef<number>(0);
  const explainHealthRef = useRef<{ feature_count?: number; feature_schema_hash?: string } | null>(null);
  const lastSentRequestIdRef = useRef<string | null>(null);
  const consecutiveConnectFailuresRef = useRef(0);
  const loggedMaxBackoffRef = useRef(false);
  const MAX_RECONNECT_DELAY_MS = 30000;
  const RECONNECT_FAILURES_BEFORE_LOG = 15;

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const msg = JSON.parse(event.data);
      if (!msg.type || msg.data === undefined) return;

      const schemaVersion = typeof msg.schema_version === "number" ? msg.schema_version : null;
      setTelemetrySchemaVersion(schemaVersion);
      if (schemaVersion !== TELEMETRY_SCHEMA_VERSION) {
        setTelemetrySchemaMismatch(true);
        setTelemetrySchemaError(
          `Unsupported telemetry schema_version=${schemaVersion ?? "missing"}. Expected ${TELEMETRY_SCHEMA_VERSION}.`,
        );
        return;
      }
      setTelemetrySchemaMismatch(false);
      setTelemetrySchemaError(null);

      switch (msg.type) {
        case "metrics":
          if (isMetricsLike(msg.data)) setMetrics(msg.data);
          break;

        case "activity_logs":
          setActivityLog((prev) => {
            const entry = msg.data as SentinelActivity;
            if (isExplainApiConfigured) {
              fetchExplainApi("/events", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(entry),
              }).catch(() => {
                setActivitySyncFailures((n) => n + 1);
              });
            }
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
          if (isMitigationStatusLike(msg.data)) setMitigationStatus(msg.data);
          break;

        case "integration_status":
          setIntegrationStatus(msg.data as SentinelIntegrationStatus);
          break;

        case "command_result": {
          if (!isCommandResultLike(msg.data)) break;
          const data = msg.data;
          if (shouldApplyCommandResult(data, lastSentRequestIdRef.current)) {
            setLastCommandResult(data);
          }
          break;
        }
      }
    } catch (err) {
      setParseErrorCount((n) => n + 1);
      if (import.meta.env.DEV) {
        const preview = typeof event?.data === "string" ? event.data.slice(0, 100) : "";
        console.warn("[Sentinel WS] Malformed message ignored", preview || err);
      }
    }
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    if (WS_URL_CANDIDATES.length === 0) return;

    try {
      const wsUrl = WS_URL_CANDIDATES[wsCandidateIndexRef.current % WS_URL_CANDIDATES.length];
      const protocols = WS_API_KEY ? [WS_API_KEY] : undefined;
      const ws = new WebSocket(wsUrl, protocols);

      ws.onopen = () => {
        setConnected(true);
        setTelemetrySchemaMismatch(false);
        setTelemetrySchemaError(null);
        reconnectDelayRef.current = 1000;
        wsCandidateIndexRef.current = 0;
        consecutiveConnectFailuresRef.current = 0;
        loggedMaxBackoffRef.current = false;
        if (reconnectTimerRef.current) {
          clearTimeout(reconnectTimerRef.current);
          reconnectTimerRef.current = null;
        }
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        consecutiveConnectFailuresRef.current += 1;
        wsCandidateIndexRef.current = (wsCandidateIndexRef.current + 1) % WS_URL_CANDIDATES.length;
        const delay = reconnectDelayRef.current;
        if (delay >= MAX_RECONNECT_DELAY_MS && consecutiveConnectFailuresRef.current >= RECONNECT_FAILURES_BEFORE_LOG && !loggedMaxBackoffRef.current) {
          loggedMaxBackoffRef.current = true;
          console.warn("[Sentinel WS] Reconnect backoff at 30s after repeated failures; will keep retrying.");
        }
        reconnectTimerRef.current = setTimeout(connect, delay);
        reconnectDelayRef.current = Math.min(delay * 2, MAX_RECONNECT_DELAY_MS);
      };

      ws.onerror = () => {
        ws.close();
      };

      ws.onmessage = handleMessage;
      wsRef.current = ws;
    } catch {
      consecutiveConnectFailuresRef.current += 1;
      const delay = reconnectDelayRef.current;
      if (delay >= MAX_RECONNECT_DELAY_MS && consecutiveConnectFailuresRef.current >= RECONNECT_FAILURES_BEFORE_LOG && !loggedMaxBackoffRef.current) {
        loggedMaxBackoffRef.current = true;
        console.warn("[Sentinel WS] Reconnect backoff at 30s after repeated failures; will keep retrying.");
      }
      reconnectTimerRef.current = setTimeout(connect, delay);
      reconnectDelayRef.current = Math.min(delay * 2, MAX_RECONNECT_DELAY_MS);
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

  // Restore activity history from the persistent SQLite event log on mount.
  // Runs once on mount; Explain API config is from env at load time.
  useEffect(() => {
    if (!isExplainApiConfigured) {
      setEventHistoryUnavailable(false);
      setExplainApiReachable(null);
      return;
    }
    setEventHistoryUnavailable(false);
    fetchExplainApi("/events?limit=200")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setExplainApiReachable(true);
        return r.json() as Promise<{ events: SentinelActivity[]; count: number }>;
      })
      .then(({ events }) => {
        if (Array.isArray(events) && events.length > 0) {
          setPersistedEvents(events);
        }
        setEventHistoryUnavailable(false);
      })
      .catch(() => {
        setEventHistoryUnavailable(true);
        setExplainApiReachable(false);
      });
  }, []);

      const sendCommand = useCallback((command: string, params?: Record<string, string>) => {
    const ws = wsRef.current;
    const requestId = generateRequestId();
    if (ws && ws.readyState === WebSocket.OPEN) {
      lastSentRequestIdRef.current = requestId;
      ws.send(JSON.stringify({
        command,
        contract_version: COMMAND_CONTRACT_VERSION,
        request_id: requestId,
        ...params,
      }));
      return;
    }

    lastSentRequestIdRef.current = null;
    setLastCommandResult({
      timestamp: Math.floor(Date.now() / 1000),
      contract_version: COMMAND_CONTRACT_VERSION,
      request_id: requestId,
      command,
      success: false,
      message: "websocket disconnected; command not sent",
    });
  }, []);

  const requestShapContributions = useCallback(async () => {
    const fv = featureVector ?? [];
    if (fv.length !== 20 && fv.length !== 21 && fv.length !== 22) {
      setShapError("No feature vector available. Wait for traffic and try again.");
      return;
    }
    if (!isExplainApiConfigured) {
      setShapError("Explain API endpoint discovery failed.");
      setShapContributions(null);
      return;
    }

    setShapLoading(true);
    setShapError(null);
    try {
      let health = explainHealthRef.current;
      if (!health) {
        const healthRes = await fetchExplainApi("/health");
        const healthJson = await healthRes.json();
        if (!healthRes.ok) {
          setShapError(healthJson.error || `Explain API health check failed (HTTP ${healthRes.status})`);
          setShapContributions(null);
          return;
        }
        health = {
          feature_count:
            typeof healthJson.feature_count === "number" && Number.isInteger(healthJson.feature_count)
              ? healthJson.feature_count
              : undefined,
          feature_schema_hash:
            typeof healthJson.feature_schema_hash === "string" ? healthJson.feature_schema_hash : undefined,
        };
        explainHealthRef.current = health;
      }

      const expectedFeatureCount = health.feature_count === 20 || health.feature_count === 21 ? health.feature_count : 21;
      const shapVectorBase = fv.length > 21 ? fv.slice(0, 21) : fv;
      const shapVector =
        expectedFeatureCount === 20
          ? shapVectorBase.slice(0, 20)
          : (shapVectorBase.length >= 21
              ? shapVectorBase.slice(0, 21)
              : [...shapVectorBase, 0.0]);

      const localFeatureNames = expectedFeatureCount === 20 ? SHAP_FEATURE_NAMES_20 : SHAP_FEATURE_NAMES_21;
      const localFeatureSchemaHash = await computeFeatureSchemaHash(localFeatureNames);
      if (health.feature_schema_hash && health.feature_schema_hash !== localFeatureSchemaHash) {
        setShapError(
          `Explain API schema hash mismatch (api=${health.feature_schema_hash}, ui=${localFeatureSchemaHash}).`,
        );
        setShapContributions(null);
        return;
      }

      const res = await fetchExplainApi("/shap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          samples: [shapVector],
          feature_count: expectedFeatureCount,
          feature_schema_hash: localFeatureSchemaHash,
        }),
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
    telemetrySchemaVersion,
    telemetrySchemaMismatch,
    telemetrySchemaError,
    metrics,
    activityLog,
    persistedEvents,
    eventHistoryUnavailable,
    explainApiReachable,
    activitySyncFailures,
    parseErrorCount,
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
    integrationStatus,
    lastCommandResult,
    trafficHistory,
    sendCommand,
    requestShapContributions,
  };
}

const SentinelWebSocketContext = createContext<SentinelState | null>(null);

interface SentinelWebSocketProviderProps {
  children: ReactNode;
}

export function SentinelWebSocketProvider({ children }: SentinelWebSocketProviderProps) {
  const state = useSentinelWebSocketState();
  return createElement(SentinelWebSocketContext.Provider, { value: state }, children);
}

export function useSentinelWebSocket(): SentinelState {
  const state = useContext(SentinelWebSocketContext);
  if (!state) {
    throw new Error("useSentinelWebSocket must be used within SentinelWebSocketProvider");
  }
  return state;
}

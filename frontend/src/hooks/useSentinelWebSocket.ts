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
  ip_family?: string;
  action: string;
  attack_type: string;
  threat_score: number;
  reason: string;
  enforced: boolean;
}

export interface SentinelBlockedIP {
  ip: string;
  ip_family?: string;
  rule_id: number;
  timestamp: number;
}

export interface SentinelRateLimitedIP {
  ip: string;
  ip_family?: string;
  limit_pps: number;
  rule_id: number;
}

export interface SentinelMonitoredIP {
  ip: string;
  ip_family?: string;
  rule_id: number;
  timestamp: number;
}

export interface SentinelWhitelistedIP {
  ip: string;
  ip_family?: string;
}

export interface SentinelTrafficRate {
  total_pps: number;
  total_bps: number;
  tcp_pps: number;
  udp_pps: number;
  icmp_pps: number;
  icmpv6_pps?: number;
  other_pps: number;
}

export interface SentinelProtocolDist {
  tcp_percent: number;
  udp_percent: number;
  icmp_percent: number;
  icmpv6_percent?: number;
  other_percent: number;
  tcp_bytes: number;
  udp_bytes: number;
  icmp_bytes: number;
  icmpv6_bytes?: number;
  other_bytes: number;
  other_top_proto?: number;
}

export interface SentinelTopSource {
  ip: string;
  ip_family?: string;
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

  /* Individual threat model component scores [0,1] */
  avg_score_volume: number;
  avg_score_entropy: number;
  avg_score_protocol: number;
  avg_score_behavioral: number;
  avg_score_ml: number;
  avg_score_l7: number;
  avg_score_anomaly: number;
  avg_score_chi_square: number;
  avg_score_fanin: number;
  avg_score_signature: number;
  avg_baseline_threat_score?: number;
  ml_activation_threshold?: number;
  classifications_last_10s?: number;
  ml_activated_last_10s?: number;
}

export interface SentinelConnection {
  src: string;
  dst: string;
  ip_family?: string;
  proto: number;
  packets: number;
  bytes: number;
}

export interface SentinelPacketEvent {
  timestamp: number;
  ip_family: string;
  src_ip: string;
  dst_ip: string;
  protocol: number;
  src_port: number;
  dst_port: number;
  packet_len: number;
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
  dataplane_mode?: string;
  sdn_connected?: number; /* 1=ok, 0=failed, -1=never probed */
  sdn_last_error?: string; /* Last SDN push error for ops debugging */
}

export interface SentinelIntegrationStatus {
  intel_feed_enabled: boolean;
  model_extension_enabled: boolean;
  controller_extension_enabled: boolean;
  signature_feed_enabled: boolean;
  dataplane_extension_enabled: boolean;
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
  packetEvents: SentinelPacketEvent[];
  sendCommand: (command: string, params?: Record<string, string>) => void;
  requestShapContributions: () => Promise<void>;
}

const MAX_ACTIVITY_LOG = 100;
const MAX_TRAFFIC_HISTORY = 60;
const MAX_PACKET_EVENTS = 200;
const COMMAND_CONTRACT_VERSION = 1;
const TELEMETRY_SCHEMA_VERSION = 1;
const ACTIVITY_BATCH_MAX = 50;
const ACTIVITY_BATCH_FLUSH_MS = 750;
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
  const [packetEvents, setPacketEvents] = useState<SentinelPacketEvent[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectDelayRef = useRef<number>(1000);
  const wsCandidateIndexRef = useRef<number>(0);
  const explainHealthRef = useRef<{ feature_count?: number; feature_schema_hash?: string; feature_names?: string[] } | null>(null);
  const pendingActivityBatchRef = useRef<SentinelActivity[]>([]);
  const activityFlushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastSentRequestIdRef = useRef<string | null>(null);
  const consecutiveConnectFailuresRef = useRef(0);
  const loggedMaxBackoffRef = useRef(false);
  const MAX_RECONNECT_DELAY_MS = 30000;
  const RECONNECT_FAILURES_BEFORE_LOG = 15;

  const flushActivityBatch = useCallback(async () => {
    if (!isExplainApiConfigured) return;
    if (pendingActivityBatchRef.current.length === 0) return;

    const batch = pendingActivityBatchRef.current.splice(0, ACTIVITY_BATCH_MAX);
    if (batch.length === 0) return;

    try {
      await fetchExplainApi("/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events: batch }),
      });
    } catch {
      setActivitySyncFailures((n) => n + batch.length);
    }

    if (pendingActivityBatchRef.current.length > 0) {
      if (activityFlushTimerRef.current) {
        clearTimeout(activityFlushTimerRef.current);
      }
      activityFlushTimerRef.current = setTimeout(() => {
        void flushActivityBatch();
      }, ACTIVITY_BATCH_FLUSH_MS);
    } else {
      activityFlushTimerRef.current = null;
    }
  }, []);

  const queueActivityForSync = useCallback((entry: SentinelActivity) => {
    if (!isExplainApiConfigured) return;

    pendingActivityBatchRef.current.push(entry);

    if (pendingActivityBatchRef.current.length >= ACTIVITY_BATCH_MAX) {
      if (activityFlushTimerRef.current) {
        clearTimeout(activityFlushTimerRef.current);
        activityFlushTimerRef.current = null;
      }
      void flushActivityBatch();
      return;
    }

    if (!activityFlushTimerRef.current) {
      activityFlushTimerRef.current = setTimeout(() => {
        void flushActivityBatch();
      }, ACTIVITY_BATCH_FLUSH_MS);
    }
  }, [flushActivityBatch]);

  /* ---- RAF-batched message processing ----
   * Instead of calling setState per WebSocket message (which at 5k+ PPS
   * causes hundreds of React renders per second), we buffer all messages
   * arriving within one animation frame (~16ms) and apply them in a single
   * batch.  Snapshot-type streams keep only the latest value; event-type
   * streams (activity_logs, packet_events) are accumulated into one setState. */
  const msgQueueRef = useRef<string[]>([]);
  const rafIdRef = useRef<number>(0);

  const flushMessageQueue = useCallback(() => {
    rafIdRef.current = 0;
    const queue = msgQueueRef.current;
    if (queue.length === 0) return;
    msgQueueRef.current = [];

    type ParsedMsg = { type: string; data: unknown; schema_version?: number };
    const valid: ParsedMsg[] = [];
    let parseErrors = 0;
    let sawMismatch = false;

    for (const raw of queue) {
      try {
        const msg = JSON.parse(raw);
        if (!msg.type || msg.data === undefined) continue;
        const sv = typeof msg.schema_version === "number" ? msg.schema_version : null;
        if (sv !== TELEMETRY_SCHEMA_VERSION) { sawMismatch = true; continue; }
        valid.push(msg);
      } catch {
        parseErrors++;
      }
    }

    if (parseErrors > 0) {
      setParseErrorCount(n => n + parseErrors);
      if (import.meta.env.DEV) console.warn(`[Sentinel WS] ${parseErrors} malformed message(s) ignored`);
    }
    if (sawMismatch) {
      setTelemetrySchemaMismatch(true);
      setTelemetrySchemaError(`Unsupported telemetry schema_version. Expected ${TELEMETRY_SCHEMA_VERSION}.`);
    }
    if (valid.length === 0) return;
    setTelemetrySchemaMismatch(false);
    setTelemetrySchemaError(null);
    const lastSV = typeof valid[valid.length - 1].schema_version === "number"
      ? valid[valid.length - 1].schema_version! : null;
    setTelemetrySchemaVersion(lastSV);

    const snapshots = new Map<string, unknown>();
    const activityBatch: SentinelActivity[] = [];
    const packetBatch: SentinelPacketEvent[] = [];
    const commandResults: SentinelCommandResult[] = [];

    for (const msg of valid) {
      switch (msg.type) {
        case "activity_logs":  activityBatch.push(msg.data as SentinelActivity); break;
        case "packet_events":  packetBatch.push(msg.data as SentinelPacketEvent); break;
        case "command_result":
          if (isCommandResultLike(msg.data)) commandResults.push(msg.data);
          break;
        default: snapshots.set(msg.type, msg.data); break;
      }
    }

    for (const [type, data] of snapshots) {
      switch (type) {
        case "metrics":
          if (isMetricsLike(data)) setMetrics(data);
          break;
        case "blocked_ips":
          setBlockedIPs(Array.isArray(data) ? data : []);
          break;
        case "rate_limited_ips":
          setRateLimitedIPs(Array.isArray(data) ? data : []);
          break;
        case "monitored_ips":
          setMonitoredIPs(Array.isArray(data) ? data : []);
          break;
        case "whitelisted_ips":
          setWhitelistedIPs(Array.isArray(data) ? data : []);
          break;
        case "traffic_rate": {
          const rate = data as SentinelTrafficRate;
          setTrafficRate(rate);
          setTrafficHistory(prev => {
            const point: TrafficDataPoint = {
              time: new Date().toLocaleTimeString("en-US", {
                hour: "2-digit", minute: "2-digit", second: "2-digit",
              }),
              packets: rate.total_pps,
            };
            const next = [...prev, point];
            return next.length > MAX_TRAFFIC_HISTORY
              ? next.slice(next.length - MAX_TRAFFIC_HISTORY) : next;
          });
          break;
        }
        case "protocol_distribution":
          setProtocolDist(data as SentinelProtocolDist);
          break;
        case "top_sources":
          setTopSources(Array.isArray(data) ? data : []);
          break;
        case "feature_importance":
          setFeatureImportance(data as SentinelFeatureImportance);
          break;
        case "feature_vector":
          setFeatureVector(Array.isArray(data) ? data : null);
          break;
        case "active_connections":
          setConnections(Array.isArray(data) ? data : []);
          break;
        case "mitigation_status":
          if (isMitigationStatusLike(data)) setMitigationStatus(data);
          break;
        case "integration_status":
          setIntegrationStatus(data as SentinelIntegrationStatus);
          break;
      }
    }

    if (activityBatch.length > 0) {
      for (const entry of activityBatch) queueActivityForSync(entry);
      setActivityLog(prev => {
        const next = [...[...activityBatch].reverse(), ...prev];
        return next.length > MAX_ACTIVITY_LOG ? next.slice(0, MAX_ACTIVITY_LOG) : next;
      });
    }

    if (packetBatch.length > 0) {
      setPacketEvents(prev => {
        const next = [...[...packetBatch].reverse(), ...prev];
        return next.length > MAX_PACKET_EVENTS ? next.slice(0, MAX_PACKET_EVENTS) : next;
      });
    }

    if (commandResults.length > 0) {
      const lastApplicable = [...commandResults].reverse().find(cr =>
        shouldApplyCommandResult(cr, lastSentRequestIdRef.current)
      );
      if (lastApplicable) setLastCommandResult(lastApplicable);
    }
  }, [queueActivityForSync]);

  const onWsMessage = useCallback((event: MessageEvent) => {
    msgQueueRef.current.push(event.data as string);
    if (!rafIdRef.current) {
      rafIdRef.current = requestAnimationFrame(flushMessageQueue);
    }
  }, [flushMessageQueue]);

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

      ws.onmessage = onWsMessage;
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
  }, [onWsMessage]);

  useEffect(() => {
    connect();

    return () => {
      if (rafIdRef.current) {
        cancelAnimationFrame(rafIdRef.current);
        rafIdRef.current = 0;
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
      if (activityFlushTimerRef.current) {
        clearTimeout(activityFlushTimerRef.current);
        activityFlushTimerRef.current = null;
      }
      void flushActivityBatch();
    };
  }, [connect, flushActivityBatch]);

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
    if (fv.length < 20) {
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
          feature_names:
            Array.isArray(healthJson.feature_names)
              ? healthJson.feature_names.filter((v: unknown): v is string => typeof v === "string")
              : undefined,
        };
        explainHealthRef.current = health;
      }

      const expectedFeatureCount = health.feature_count ?? 20;
      const shapVector = fv.slice(0, expectedFeatureCount);

      const backendFeatureNames =
        Array.isArray(health.feature_names) && health.feature_names.length >= expectedFeatureCount
          ? health.feature_names.slice(0, expectedFeatureCount)
          : Array.from(SHAP_FEATURE_NAMES_20).slice(0, expectedFeatureCount);
      const featureSchemaHash =
        health.feature_schema_hash ?? (await computeFeatureSchemaHash(backendFeatureNames));

      const res = await fetchExplainApi("/shap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          samples: [shapVector],
          feature_count: expectedFeatureCount,
          feature_schema_hash: featureSchemaHash,
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
    packetEvents,
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

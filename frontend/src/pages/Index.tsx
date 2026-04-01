import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { GridLayout, StatCard, Panel } from "@/components/layout/GridPanel";
import { StatusBadge, StatusType } from "@/components/dashboard/StatusBadge";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { RiskScoreBreakdown } from "@/components/dashboard/RiskScoreBreakdown";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { AIAnalystWidget } from "@/components/dashboard/AIAnalystWidget";
import { ActiveConnectionsTable } from "@/components/dashboard/ActiveConnectionsTable";
import { DefendedHostWidget } from "@/components/dashboard/DefendedHostWidget";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { selectPrimaryAttackerSourceIp } from "@/lib/primarySourceIp";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { useMemo } from "react";
import {
  Activity,
  Layers,
  Shield,
  TrendingUp,
  Wifi,
  Server,
  Cpu,
  HardDrive,
  Hexagon,
} from "lucide-react";

const Index = () => {
  const ws = useSentinelWebSocket();
  const primaryAttackerIp = useMemo(
    () => selectPrimaryAttackerSourceIp(ws.topSources, ws.activityLog),
    [ws.topSources, ws.activityLog],
  );
  const benchmarks = useModelBenchmarkReport();
  const runtimeModel = benchmarks.report?.models.find(
    (model) => model.name === benchmarks.report?.runtime_model,
  );
  const runtimeAccuracy = runtimeModel?.test_metrics?.accuracy;

  /* Real data from backend streams - NEVER mock */
  const pps = ws.trafficRate?.total_pps ?? ws.metrics?.packets_per_sec ?? 0;
  const flows = ws.metrics?.active_flows ?? 0;
  const threatScore = ws.featureImportance?.avg_threat_score ?? 0;
  const faninScore = ws.featureImportance?.avg_fanin_score ?? 0;
  const riskScore = Math.min(100, Math.round(threatScore * 100));
  const distributedEvidence = Math.min(100, Math.round(faninScore * 100));
  const totalBlocked = ws.mitigationStatus?.total_blocked ?? 0;
  const totalRateLimited = ws.mitigationStatus?.total_rate_limited ?? 0;
  const sdnStatus = ws.mitigationStatus?.sdn_connected;
  const mitigationActive = totalBlocked > 0 || totalRateLimited > 0;
  const cpuPercent = ws.metrics?.cpu_usage_percent ?? 0;
  const memMB = ws.metrics?.memory_usage_mb ?? 0;
  const mlOps = ws.metrics?.ml_classifications_per_sec ?? 0;
  const baselineThreatScore = ws.featureImportance?.avg_baseline_threat_score ?? 0;
  const mlActivationThreshold = ws.featureImportance?.ml_activation_threshold ?? 0.3;
  const classificationsLast10s = ws.featureImportance?.classifications_last_10s ?? 0;
  const mlActivatedLast10s = ws.featureImportance?.ml_activated_last_10s ?? 0;
  const mlGateOpen = mlActivatedLast10s > 0;

  const getStatus = (): StatusType => {
    if (riskScore >= 70) return "attack";
    if (riskScore >= 30) return "observation";
    return "normal";
  };

  const pd = ws.protocolDist;
  const topProtocol = (() => {
    if (!pd) return "Unknown";
    const entries: [string, number][] = [
      ["TCP", pd.tcp_percent],
      ["UDP", pd.udp_percent],
      ["ICMP", pd.icmp_percent],
    ];
    if (pd.icmpv6_percent != null) entries.push(["ICMPv6", pd.icmpv6_percent]);
    if (pd.other_percent > 0) entries.push(["Other", pd.other_percent]);
    const best = entries.reduce((a, b) => (b[1] > a[1] ? b : a), entries[0]);
    return best[1] > 0 ? best[0] : "Unknown";
  })();

  const formatPps = (value: number): string => {
    if (value >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
    return String(value);
  };

  const aiTelemetry = {
    timestamp: new Date().toISOString(),
    sourceIp: primaryAttackerIp,
    packetsPerSecond: pps,
    bytesPerSecond: ws.trafficRate?.total_bps ?? ws.metrics?.bytes_per_sec ?? 0,
    threatScore: threatScore,
    activeFlows: flows,
    topProtocol,
  };

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-8 animate-fade-in">
        {/* Page Header */}
        <PageHeader
          title="Sentinel"
          description="Behavior-Aware DDoS Detection & Adaptive Mitigation"
          icon={<Hexagon className="w-6 h-6 text-foreground" />}
          action={
            <div role="status" aria-label={`System status: ${getStatus()}`}>
              <StatusBadge status={getStatus()} />
            </div>
          }
        />

        <Panel
          title="Detection Mode"
          description="Baseline threshold gate for ML activation"
          variant={mlGateOpen ? "highlight" : "default"}
        >
          <div className="rounded-lg border border-border/60 bg-secondary/10 px-4 py-3 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Current mode:</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${mlGateOpen ? "bg-status-warning/15 text-status-warning" : "bg-status-success/15 text-status-success"}`}>
                  {mlGateOpen ? "ML Active" : "Baseline Only"}
                </span>
              </div>
              <span className="text-xs text-muted-foreground">
                {mlGateOpen ? "ML turns on after baseline threshold is crossed." : "Baseline threshold not crossed yet."}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
              <div className="rounded border border-border/40 px-3 py-2">
                <span className="text-xs text-muted-foreground">Baseline score</span>
                <div className="font-mono">{baselineThreatScore.toFixed(3)}</div>
              </div>
              <div className="rounded border border-border/40 px-3 py-2">
                <span className="text-xs text-muted-foreground">ML activation threshold</span>
                <div className="font-mono">{mlActivationThreshold.toFixed(2)}</div>
              </div>
              <div className="rounded border border-border/40 px-3 py-2">
                <span className="text-xs text-muted-foreground">ML-used classifications (last 10 sec)</span>
                <div className="font-mono">{mlActivatedLast10s} / {classificationsLast10s}</div>
              </div>
            </div>
          </div>
        </Panel>

        {/* Primary KPI Grid - 4 Columns */}
        <GridLayout cols={4} gap="md">
          <StatCard
            label="Traffic Rate"
            value={formatPps(pps)}
            unit="pps"
            icon={<Activity className="w-5 h-5" />}
            variant="default"
          />
          <StatCard
            label="Active Flows"
            value={flows.toLocaleString()}
            unit="sessions"
            icon={<Layers className="w-5 h-5" />}
            variant="success"
          />
          <StatCard
            label="Mitigation"
            value={mitigationActive ? "Active" : "Idle"}
            unit={mitigationActive ? `${totalBlocked + totalRateLimited} rules` : "-"}
            icon={<Shield className="w-5 h-5" />}
            variant={mitigationActive ? "danger" : "default"}
          />
          <StatCard
            label="Pipeline Status"
            value={ws.connected ? "Online" : "Offline"}
            unit={ws.connected ? "live" : "disconnected"}
            icon={<TrendingUp className="w-5 h-5" />}
            variant={ws.connected ? "success" : "danger"}
          />
        </GridLayout>

        {/* Main Monitoring Section - 3 Columns (Chart + Gauge + AI) */}
        <GridLayout cols={3} gap="lg">
          <Panel title="Traffic Trends" variant="default" className="h-full">
            <TrafficChart data={ws.trafficHistory} isAttack={riskScore >= 70} />
          </Panel>
          <Panel title="Risk Assessment" variant={riskScore >= 70 ? "highlight" : "default"} className="h-full">
            <RiskGauge value={riskScore} className="h-full" />
          </Panel>
          <div className="h-full">
            <AIAnalystWidget telemetry={aiTelemetry} className="h-full min-h-[420px]" />
          </div>
        </GridLayout>

        {/* Risk Score Component Breakdown */}
        <RiskScoreBreakdown
          threatScore={threatScore}
          weights={{
            volume_weight: ws.featureImportance?.volume_weight ?? 0,
            entropy_weight: ws.featureImportance?.entropy_weight ?? 0,
            protocol_weight: ws.featureImportance?.protocol_weight ?? 0,
            behavioral_weight: ws.featureImportance?.behavioral_weight ?? 0,
            ml_weight: ws.featureImportance?.ml_weight ?? 0,
            l7_weight: ws.featureImportance?.l7_weight ?? 0,
            anomaly_weight: ws.featureImportance?.anomaly_weight ?? 0,
            chi_square_weight: ws.featureImportance?.chi_square_weight ?? 0,
            fanin_weight: ws.featureImportance?.fanin_weight ?? 0,
            signature_weight: ws.featureImportance?.signature_weight ?? 0,
          }}
          scores={{
            score_volume: ws.featureImportance?.avg_score_volume ?? 0,
            score_entropy: ws.featureImportance?.avg_score_entropy ?? 0,
            score_protocol: ws.featureImportance?.avg_score_protocol ?? 0,
            score_behavioral: ws.featureImportance?.avg_score_behavioral ?? 0,
            score_ml: ws.featureImportance?.avg_score_ml ?? 0,
            score_l7: ws.featureImportance?.avg_score_l7 ?? 0,
            score_anomaly: ws.featureImportance?.avg_score_anomaly ?? 0,
            score_chi_square: ws.featureImportance?.avg_score_chi_square ?? 0,
            score_fanin: ws.featureImportance?.avg_score_fanin ?? 0,
            score_signature: ws.featureImportance?.avg_score_signature ?? 0,
          }}
        />

        {/* Threat Intelligence Section - Single ordered connection list */}
        <Panel
          title="Threat Intelligence"
          description="All active connections ordered by packet volume (highest first)"
          variant="default"
        >
          <ActiveConnectionsTable connections={ws.connections} />
        </Panel>

        {/* System Health Grid - 6 Columns */}
        <div>
          <h2 className="text-lg font-semibold mb-4">System Health</h2>
          <GridLayout cols={4} gap="md">
            <StatCard
              label="Network"
              value={ws.connected ? "Healthy" : "Disconnected"}
              icon={<Wifi className="w-5 h-5" />}
              variant={ws.connected ? "success" : "danger"}
            />
            <StatCard
              label="ML Engine"
              value={mlOps > 0 ? "Active" : "Idle"}
              unit={`${mlOps.toLocaleString()} ops/s`}
              icon={<Server className="w-5 h-5" />}
              variant={mlOps > 0 ? "success" : "warning"}
            />
            <StatCard
              label="Distributed Threat Evidence"
              value={`${distributedEvidence}%`}
              unit={distributedEvidence >= 70 ? "high fan-in" : distributedEvidence >= 30 ? "watching" : "low"}
              icon={<Layers className="w-5 h-5" />}
              variant={distributedEvidence >= 70 ? "danger" : distributedEvidence >= 30 ? "warning" : "success"}
            />
            <StatCard
              label="CPU Usage"
              value={`${cpuPercent.toFixed(1)}%`}
              icon={<Cpu className="w-5 h-5" />}
              variant={cpuPercent > 80 ? "danger" : cpuPercent > 50 ? "warning" : "success"}
            />
            <StatCard
              label="Memory"
              value={`${memMB.toFixed(1)}`}
              unit="MB"
              icon={<HardDrive className="w-5 h-5" />}
              variant="default"
            />
            <StatCard
              label="Kernel Drops"
              value={ws.mitigationStatus?.kernel_dropping_enabled ? "Active" : "Disabled"}
              unit={ws.mitigationStatus?.kernel_dropping_enabled ? "eBPF" : "fallback"}
              icon={<Shield className="w-5 h-5" />}
              variant={ws.mitigationStatus?.kernel_dropping_enabled ? "success" : "warning"}
            />
            <StatCard
              label="ML Model"
              value={benchmarks.report?.runtime_model ?? "Unknown"}
              unit={typeof runtimeAccuracy === "number" ? `${(runtimeAccuracy * 100).toFixed(1)}% runtime accuracy` : "runtime selection"}
              icon={<Server className="w-5 h-5" />}
              variant="success"
            />
            <StatCard
              label="SDN Controller"
              value={sdnStatus === 1 ? "Connected" : sdnStatus === 0 ? "Unreachable" : "Unknown"}
              unit={ws.mitigationStatus?.sdn_last_error ? "check controller" : "control plane"}
              icon={<Shield className="w-5 h-5" />}
              variant={sdnStatus === 1 ? "success" : sdnStatus === 0 ? "danger" : "warning"}
            />
          </GridLayout>
          <div className="mt-4">
            <DefendedHostWidget />
          </div>
        </div>

      </div>
    </DashboardLayout>
  );
};

export default Index;

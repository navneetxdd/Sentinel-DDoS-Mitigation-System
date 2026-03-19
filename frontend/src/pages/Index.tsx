import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { GridLayout, StatCard, Panel } from "@/components/layout/GridPanel";
import { StatusBadge, StatusType } from "@/components/dashboard/StatusBadge";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { AIAnalystWidget } from "@/components/dashboard/AIAnalystWidget";
import { TopIPsTable } from "@/components/dashboard/TopIPsTable";
import { ActiveConnectionsTable } from "@/components/dashboard/ActiveConnectionsTable";
import { SLOPanel } from "@/components/dashboard/SLOPanel";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
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
  const benchmarks = useModelBenchmarkReport();

  /* Real data from backend streams - NEVER mock */
  const pps = ws.metrics?.packets_per_sec ?? 0;
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
  const integrationEnabledCount = [
    ws.integrationStatus?.intel_feed_enabled,
    ws.integrationStatus?.model_extension_enabled,
    ws.integrationStatus?.controller_extension_enabled,
    ws.integrationStatus?.signature_feed_enabled,
    ws.integrationStatus?.dataplane_extension_enabled,
  ].filter(Boolean).length;

  const getStatus = (): StatusType => {
    if (riskScore >= 70) return "attack";
    if (riskScore >= 30) return "observation";
    return "normal";
  };

  const currentProtocols = ws.metrics?.protocol_distribution || {};
  let topProtocol = "Unknown";
  let maxProtoRate = -1;
  for (const [proto, count] of Object.entries(currentProtocols)) {
    const c = count as number;
    if (c > maxProtoRate) {
      maxProtoRate = c;
      topProtocol = proto;
    }
  }

  const formatPps = (value: number): string => {
    if (value >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
    return String(value);
  };

  const aiTelemetry = {
    timestamp: new Date().toISOString(),
    sourceIp: ws.topSources?.[0]?.ip ?? "Unknown",
    packetsPerSecond: pps,
    bytesPerSecond: ws.metrics?.bytes_per_sec ?? 0,
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

        <SLOPanel />

        {/* Main Monitoring Section - 3 Columns (Chart + Gauge + AI) */}
        <GridLayout cols={3} gap="lg">
          <Panel title="Traffic Trends" variant="default">
            <TrafficChart data={ws.trafficHistory} isAttack={riskScore >= 70} />
          </Panel>
          <Panel title="Risk Assessment" variant={riskScore >= 70 ? "highlight" : "default"}>
            <RiskGauge value={riskScore} />
          </Panel>
          <div className="h-full">
            <AIAnalystWidget telemetry={aiTelemetry} className="h-full min-h-[420px]" />
          </div>
        </GridLayout>

        {/* Threat Intelligence Section - 2 Columns */}
        <Panel
          title="Threat Intelligence"
          description="Real-time traffic analysis with ML-powered threat scoring"
          variant="default"
        >
          <GridLayout cols={2} gap="lg">
            <TopIPsTable
              isAttack={riskScore >= 70}
              sources={ws.topSources}
              blockedIPs={ws.blockedIPs}
              rateLimitedIPs={ws.rateLimitedIPs}
            />
            <ActiveConnectionsTable connections={ws.connections} />
          </GridLayout>
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
              value={mlOps > 0 ? `${mlOps.toLocaleString()}` : "Online"}
              unit={mlOps > 0 ? "ops/s" : ""}
              icon={<Server className="w-5 h-5" />}
              variant={mlOps > 0 ? "success" : "default"}
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
              value={benchmarks.report?.runtime_model ?? "Random Forest"}
              unit={benchmarks.report ? `${(benchmarks.report.accuracy * 100).toFixed(1)}%` : ""}
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
            <StatCard
              label="External Integrations"
              value={integrationEnabledCount}
              unit={ws.integrationStatus?.profile ?? "baseline"}
              icon={<Layers className="w-5 h-5" />}
              variant={integrationEnabledCount > 0 ? "warning" : "default"}
            />
          </GridLayout>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Index;

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { GridLayout, Panel, StatCard } from "@/components/layout/GridPanel";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { ProtocolChart } from "@/components/dashboard/ProtocolChart";
import { TopIPsTable } from "@/components/dashboard/TopIPsTable";
import { ActiveConnectionsTable } from "@/components/dashboard/ActiveConnectionsTable";
import { PacketEvidenceTable } from "@/components/dashboard/PacketEvidenceTable";
import { StatusBadge, StatusType } from "@/components/dashboard/StatusBadge";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { Activity, Layers, Shield, TrendingUp, Database, Gauge, Network } from "lucide-react";

const TrafficAnalysis = () => {
  const ws = useSentinelWebSocket();
  const benchmarks = useModelBenchmarkReport();

  /* Derive attack state from feature_importance */
  const threatScore = ws.featureImportance?.avg_threat_score ?? 0;
  const riskScore = threatScore * 100;
  const isAttack = riskScore >= 70;

  const getStatus = (): StatusType => {
    if (riskScore >= 70) return "attack";
    if (riskScore >= 30) return "observation";
    return "normal";
  };

  /* Real-time footer stats from backend streams */
  const pps = ws.trafficRate?.total_pps ?? 0;
  const activeSources = ws.metrics?.active_sources ?? 0;
  const activeFlows = ws.metrics?.active_flows ?? 0;
  const bps = ws.trafficRate?.total_bps ?? 0;
  const chiSquareWeight = ws.featureImportance?.chi_square_weight ?? 0;
  const faninWeight = ws.featureImportance?.fanin_weight ?? 0;
  const faninScore = ws.featureImportance?.avg_fanin_score ?? 0;
  const benchmarkAccuracy = benchmarks.report
    ? (() => {
        const model = benchmarks.report.models.find((m) => m.name === benchmarks.report?.runtime_model);
        return model?.test_metrics?.accuracy ?? null;
      })()
    : null;

  const formatPps = (value: number): string => {
    if (value >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
    return String(value);
  };

  const formatBandwidth = (bytes: number): string => {
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)}GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(0)}MB`;
    if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(0)}KB`;
    return `${bytes}B`;
  };

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-6 animate-fade-in">
        <PageHeader
          title="Live Traffic Analysis"
          description="Real-time network traffic monitoring and protocol behavior"
          icon={<Activity className="w-6 h-6 text-foreground" />}
          action={<StatusBadge status={getStatus()} />}
        />

        <Panel title="Traffic Throughput" description="Second-by-second packet volume and trend" variant="default">
          <TrafficChart isAttack={isAttack} data={ws.trafficHistory} />
        </Panel>

        <GridLayout cols={2} gap="lg">
          <ProtocolChart isAttack={isAttack} data={ws.protocolDist} />
          <TopIPsTable
            isAttack={isAttack}
            sources={ws.topSources}
            blockedIPs={ws.blockedIPs}
            rateLimitedIPs={ws.rateLimitedIPs}
          />
        </GridLayout>

        <Panel title="Connection Activity" description="Live flow-level sessions currently observed" variant="default">
          <ActiveConnectionsTable connections={ws.connections} />
        </Panel>

        <Panel
          title="Packet evidence"
          description="Sampled packets from the pipeline for parity checks (stream is rate-limited for UI stability)"
          variant="default"
        >
          <PacketEvidenceTable events={ws.packetEvents} />
        </Panel>

        <div>
          <h2 className="text-lg font-semibold mb-4">Traffic Telemetry</h2>
          <GridLayout cols={4} gap="md">
            <StatCard
              label="Packet Rate"
              value={formatPps(pps)}
              unit="pps"
              icon={<TrendingUp className="w-5 h-5" />}
              variant={isAttack ? "warning" : "success"}
            />
            <StatCard
              label="Bandwidth"
              value={formatBandwidth(bps)}
              unit="per second"
              icon={<Network className="w-5 h-5" />}
              variant="default"
            />
            <StatCard
              label="Active Sources"
              value={activeSources.toLocaleString()}
              unit="IPs"
              icon={<Database className="w-5 h-5" />}
              variant="default"
            />
            <StatCard
              label="Active Flows"
              value={activeFlows.toLocaleString()}
              unit="sessions"
              icon={<Layers className="w-5 h-5" />}
              variant={activeFlows > 5000 ? "warning" : "default"}
            />
            <StatCard
              label="Threat Score"
              value={threatScore.toFixed(3)}
              unit="0-1"
              icon={<Shield className="w-5 h-5" />}
              variant={threatScore >= 0.7 ? "danger" : threatScore >= 0.3 ? "warning" : "success"}
            />
            <StatCard
              label="Distributed Evidence"
              value={`${Math.round(faninScore * 100)}%`}
              unit={`weight ${Math.round(faninWeight * 100)}%`}
              icon={<Layers className="w-5 h-5" />}
              variant={faninScore >= 0.7 ? "danger" : faninScore >= 0.3 ? "warning" : "success"}
            />
            <StatCard
              label="Model Accuracy"
              value={benchmarkAccuracy !== null ? `${(benchmarkAccuracy * 100).toFixed(1)}%` : "N/A"}
              unit={benchmarks.report?.runtime_model ?? "runtime model"}
              icon={<Gauge className="w-5 h-5" />}
              variant={benchmarkAccuracy !== null && benchmarkAccuracy < 0.9 ? "warning" : "success"}
            />
            <StatCard
              label="Chi-Square Weight"
              value={`${Math.round(chiSquareWeight * 100)}%`}
              unit="heuristic"
              icon={<Gauge className="w-5 h-5" />}
              variant="default"
            />
          </GridLayout>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default TrafficAnalysis;

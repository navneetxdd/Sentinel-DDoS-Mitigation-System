import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { ProtocolChart } from "@/components/dashboard/ProtocolChart";
import { TopIPsTable } from "@/components/dashboard/TopIPsTable";
import { ActiveConnectionsTable } from "@/components/dashboard/ActiveConnectionsTable";
import { StatusBadge, StatusType } from "@/components/dashboard/StatusBadge";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { Activity } from "lucide-react";

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
        {/* Header — same as original */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-secondary">
              <Activity className="w-6 h-6 text-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Live Traffic Analysis</h1>
              <p className="text-sm text-muted-foreground">
                Real-time network traffic monitoring and analysis
              </p>
            </div>
          </div>
          <StatusBadge status={getStatus()} />
        </div>

        {/* Charts Grid — same layout as original */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <TrafficChart isAttack={isAttack} data={ws.trafficHistory} className="lg:col-span-2" />
          <ProtocolChart isAttack={isAttack} data={ws.protocolDist} />
          <TopIPsTable
            isAttack={isAttack}
            sources={ws.topSources}
            blockedIPs={ws.blockedIPs}
            rateLimitedIPs={ws.rateLimitedIPs}
          />
          <ActiveConnectionsTable connections={ws.connections} className="lg:col-span-2" />
        </div>

        {/* Live Stats Footer — same layout as original, real data from backend */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="cyber-card p-4 rounded-lg text-center">
            <p className="text-3xl font-bold font-mono text-foreground">
              {formatPps(pps)}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Packets/sec</p>
          </div>
          <div className="cyber-card p-4 rounded-lg text-center">
            <p className="text-3xl font-bold font-mono text-status-success">
              {activeSources.toLocaleString()}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Active IPs</p>
          </div>
          <div className="cyber-card p-4 rounded-lg text-center">
            <p className="text-3xl font-bold font-mono text-status-warning">
              {activeFlows.toLocaleString()}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Active Flows</p>
          </div>
          <div className="cyber-card p-4 rounded-lg text-center">
            <p className="text-3xl font-bold font-mono text-cyber-purple">
              {formatBandwidth(bps)}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Bandwidth</p>
          </div>
          <div className="cyber-card p-4 rounded-lg text-center">
            <p className="text-3xl font-bold font-mono text-status-success">
              {benchmarkAccuracy !== null ? `${(benchmarkAccuracy * 100).toFixed(1)}%` : "---"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Model Accuracy</p>
          </div>
          <div className="cyber-card p-4 rounded-lg text-center">
            <p className="text-3xl font-bold font-mono text-status-warning">
              {(chiSquareWeight * 100).toFixed(0)}%
            </p>
            <p className="text-xs text-muted-foreground mt-1">Chi-Square Weight</p>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default TrafficAnalysis;

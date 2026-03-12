import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { StatusBadge, StatusType } from "@/components/dashboard/StatusBadge";
import { KPICard } from "@/components/dashboard/KPICard";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { AIAnalystWidget } from "@/components/dashboard/AIAnalystWidget";
import { TopIPsTable } from "@/components/dashboard/TopIPsTable";
import { ActiveConnectionsTable } from "@/components/dashboard/ActiveConnectionsTable";

import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import {
  Activity,
  Layers,
  Shield,
  TrendingUp,
  Wifi,
  Server,
  Cpu,
  HardDrive
} from "lucide-react";

const Index = () => {
  const ws = useSentinelWebSocket();

  /* Real data from backend streams */
  const pps = ws.metrics?.packets_per_sec ?? 0;
  const flows = ws.metrics?.active_flows ?? 0;
  const threatScore = ws.featureImportance?.avg_threat_score ?? 0;
  const riskScore = Math.min(100, Math.round(threatScore * 100));
  const totalBlocked = ws.mitigationStatus?.total_blocked ?? 0;
  const totalRateLimited = ws.mitigationStatus?.total_rate_limited ?? 0;
  const mitigationActive = totalBlocked > 0 || totalRateLimited > 0;
  const cpuPercent = ws.metrics?.cpu_usage_percent ?? 0;
  const memMB = ws.metrics?.memory_usage_mb ?? 0;
  const mlOps = ws.metrics?.ml_classifications_per_sec ?? 0;

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
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight mb-1">
              <span className="neon-text">BAW2M</span>
            </h1>
            <p className="text-muted-foreground">
              Behavior-Aware DDoS Detection &amp; Adaptive Mitigation
            </p>
          </div>
          <StatusBadge status={getStatus()} />
        </div>

        {/* KPI Grid — same 4-card layout as original */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <KPICard
            title="Current Traffic Rate"
            value={formatPps(pps)}
            subtitle="packets per second"
            icon={Activity}
            variant="primary"
          />
          <KPICard
            title="Active Connections"
            value={flows.toLocaleString()}
            subtitle="concurrent sessions"
            icon={Layers}
            variant="success"
          />
          <KPICard
            title="Mitigation Status"
            value={mitigationActive ? "Active" : "Idle"}
            subtitle={mitigationActive ? `${totalBlocked} blocked, ${totalRateLimited} rate-limited` : "no active rules"}
            icon={Shield}
            variant={mitigationActive ? "danger" : "primary"}
          />
          <KPICard
            title="Uptime"
            value={ws.connected ? "Online" : "Offline"}
            subtitle={ws.connected ? "pipeline connected" : "pipeline disconnected"}
            icon={TrendingUp}
            variant="success"
          />
        </div>

        {/* Main Content Grid — Traffic Chart + Risk Gauge + AI Analyst (focal point) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <TrafficChart data={ws.trafficHistory} isAttack={riskScore >= 70} />
          </div>
          <div>
            <RiskGauge value={riskScore} />
          </div>
          <div>
            <AIAnalystWidget telemetry={aiTelemetry} />
          </div>
        </div>

        {/* Threat Intelligence — Top Sources + Active Connections (primary focus during attack) */}
        <div className="cyber-card glow-border rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/5">
            <h2 className="text-lg font-semibold tracking-wide flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              Threat Intelligence
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              Top traffic sources with ML threat scores • Active connections
            </p>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-4">
            <TopIPsTable
              isAttack={riskScore >= 70}
              sources={ws.topSources}
              blockedIPs={ws.blockedIPs}
              rateLimitedIPs={ws.rateLimitedIPs}
            />
            <ActiveConnectionsTable connections={ws.connections} />
          </div>
        </div>

        {/* System Health — same 4-card layout as original */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyber-green/10">
                <Wifi className="w-4 h-4 text-cyber-green" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Network</p>
                <p className={`font-semibold ${ws.connected ? "text-cyber-green" : "text-cyber-red"}`}>
                  {ws.connected ? "Healthy" : "Disconnected"}
                </p>
              </div>
            </div>
          </div>
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyber-green/10">
                <Server className="w-4 h-4 text-cyber-green" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">ML Engine</p>
                <p className="font-semibold text-cyber-green">
                  {mlOps > 0 ? `${mlOps.toLocaleString()}/s` : "Online"}
                </p>
              </div>
            </div>
          </div>
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyber-green/10">
                <Cpu className="w-4 h-4 text-cyber-green" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">CPU Usage</p>
                <p className="font-semibold font-mono text-sm">{cpuPercent.toFixed(1)}%</p>
              </div>
            </div>
          </div>
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <HardDrive className="w-4 h-4 text-primary" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Memory</p>
                <p className="font-semibold font-mono text-sm">{memMB.toFixed(1)} MB</p>
              </div>
            </div>
          </div>
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${ws.mitigationStatus?.kernel_dropping_enabled ? "bg-cyber-green/10" : "bg-cyber-orange/10"}`}>
                <Shield className={`w-4 h-4 ${ws.mitigationStatus?.kernel_dropping_enabled ? "text-cyber-green" : "text-cyber-orange"}`} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Kernel Drops</p>
                <p className={`font-semibold text-sm ${ws.mitigationStatus?.kernel_dropping_enabled ? "text-cyber-green" : "text-cyber-orange"}`}>
                  {ws.mitigationStatus?.kernel_dropping_enabled ? "Active" : "Disabled (fallback)"}
                </p>
              </div>
            </div>
          </div>
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${
                ws.mitigationStatus?.sdn_connected === 1 ? "bg-cyber-green/10" :
                ws.mitigationStatus?.sdn_connected === 0 ? "bg-cyber-red/10" : "bg-muted"
              }`}>
                <Server className={`w-4 h-4 ${
                  ws.mitigationStatus?.sdn_connected === 1 ? "text-cyber-green" :
                  ws.mitigationStatus?.sdn_connected === 0 ? "text-cyber-red" : "text-muted-foreground"
                }`} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">SDN Controller</p>
                <p className={`font-semibold text-sm ${
                  ws.mitigationStatus?.sdn_connected === 1 ? "text-cyber-green" :
                  ws.mitigationStatus?.sdn_connected === 0 ? "text-cyber-red" : "text-muted-foreground"
                }`}>
                  {ws.mitigationStatus?.sdn_connected === 1 ? "Connected" :
                   ws.mitigationStatus?.sdn_connected === 0 ? "Unreachable" : "Unknown"}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Index;

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { MitigationTimeline } from "@/components/dashboard/MitigationTimeline";
import { AutoMitigationToggle } from "@/components/dashboard/AutoMitigationToggle";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Ban,
  Gauge,
  Eye,
  Server,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useMemo, useRef } from "react";

const ATTACK_TYPE_TO_PROTOCOL: Record<string, string> = {
  SYN_FLOOD: "TCP",
  UDP_FLOOD: "UDP",
  ICMP_FLOOD: "ICMP",
  DNS_AMP: "UDP",
  NTP_AMP: "UDP",
  SLOWLORIS: "TCP",
  PORT_SCAN: "TCP/UDP",
  LAND: "TCP",
  SMURF: "ICMP",
  NONE: "-",
  UNKNOWN: "-",
};

const MitigationControl = () => {
  const ws = useSentinelWebSocket();
  const timelineRef = useRef<HTMLDivElement>(null);
  const mitigationStatusKnown = ws.mitigationStatus !== null;
  const autoMitigation = ws.mitigationStatus?.auto_mitigation_enabled ?? false;

  const stats = [
    { label: "Blocked IPs", value: ws.mitigationStatus?.total_blocked ?? 0, icon: Ban, color: "text-status-danger", bgColor: "bg-status-danger/10" },
    { label: "Rate Limited", value: ws.mitigationStatus?.total_rate_limited ?? 0, icon: Gauge, color: "text-cyber-orange", bgColor: "bg-cyber-orange/10" },
    { label: "Monitored", value: ws.mitigationStatus?.total_monitored ?? 0, icon: Eye, color: "text-status-warning", bgColor: "bg-status-warning/10" },
    { label: "Whitelisted", value: ws.mitigationStatus?.total_whitelisted ?? 0, icon: CheckCircle, color: "text-status-success", bgColor: "bg-status-success/10" },
  ];

  const kernelDrops = ws.mitigationStatus?.kernel_dropping_enabled ?? false;
  const sdnStatus = ws.mitigationStatus?.sdn_connected;

  // Merge live stream events with the persisted history loaded from the SQLite
  // event log on mount. Live events take precedence; persisted events fill in
  // the gaps after a page reload. Deduplication uses timestamp + source-ip.
  const mergedActivities = useMemo(() => {
    const seen = new Set<string>();
    return [...ws.activityLog, ...ws.persistedEvents].filter((e) => {
      const key = `${e.timestamp}-${e.src_ip}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [ws.activityLog, ws.persistedEvents]);

  const timelineEntries = useMemo(() => {
    return mergedActivities.slice(0, 20).map((activity, idx) => {
      const actionLower = activity.action.toLowerCase();
      let action: "block" | "rate_limit" | "monitor" = "monitor";
      if (activity.enforced && actionLower.includes("block")) action = "block";
      else if (activity.enforced && actionLower.includes("rate")) action = "rate_limit";

      const protocol = ATTACK_TYPE_TO_PROTOCOL[activity.attack_type] ?? "-";
      return {
        id: `${activity.timestamp}-${idx}`,
        timestamp: new Date(activity.timestamp * 1000).toLocaleString(),
        action,
        target: activity.src_ip,
        attackType: activity.attack_type,
        protocol,
        details: `${activity.attack_type} (${protocol}) — ${activity.reason} — threat: ${activity.threat_score.toFixed(2)}${activity.enforced ? "" : " [manual mode]"}`,
        status: "completed" as const,
      };
    });
  }, [mergedActivities]);

  const lastActionTime =
    mergedActivities.length > 0
      ? new Date(mergedActivities[0].timestamp * 1000).toLocaleTimeString()
      : "-";

  const activeThreats =
    (ws.mitigationStatus?.total_blocked ?? 0) +
    (ws.mitigationStatus?.total_rate_limited ?? 0);

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-6 animate-fade-in">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-secondary">
              <Shield className="w-6 h-6 text-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Mitigation Control</h1>
              <p className="text-sm text-muted-foreground">
                Manage and monitor threat mitigation actions
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-secondary border border-border">
            <Clock className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Last action: {lastActionTime}</span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {stats.map((stat) => (
            <div key={stat.label} className="cyber-card glow-border p-4 rounded-lg">
              <div className="flex items-center gap-3">
                <div className={cn("p-2 rounded-md", stat.bgColor)}>
                  <stat.icon className={cn("w-4 h-4", stat.color)} />
                </div>
                <div>
                  <p className="text-2xl font-bold font-mono">{stat.value}</p>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className={cn("cyber-card glow-border p-4 rounded-lg", kernelDrops ? "border-status-success/20" : "border-cyber-orange/30")}>
            <div className="flex items-center gap-3">
              <div className={cn("p-2 rounded-md", kernelDrops ? "bg-status-success/10" : "bg-cyber-orange/10")}>
                <Shield className={cn("w-4 h-4", kernelDrops ? "text-status-success" : "text-cyber-orange")} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Kernel Drops</p>
                <p className={cn("font-semibold text-sm", kernelDrops ? "text-status-success" : "text-cyber-orange")}>
                  {kernelDrops ? "Active" : "Disabled (fallback mode)"}
                </p>
              </div>
            </div>
          </div>
          <div className={cn(
            "cyber-card glow-border p-4 rounded-lg",
            sdnStatus === 1 ? "border-status-success/20" : sdnStatus === 0 ? "border-status-danger/20" : "border-border"
          )}>
            <div className="flex items-center gap-3">
              <div className={cn(
                "p-2 rounded-md",
                sdnStatus === 1 ? "bg-status-success/10" : sdnStatus === 0 ? "bg-status-danger/10" : "bg-muted"
              )}>
                <Server className={cn(
                  "w-4 h-4",
                  sdnStatus === 1 ? "text-status-success" : sdnStatus === 0 ? "text-status-danger" : "text-muted-foreground"
                )} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs text-muted-foreground">SDN Controller</p>
                <p className={cn(
                  "font-semibold text-sm",
                  sdnStatus === 1 ? "text-status-success" : sdnStatus === 0 ? "text-status-danger" : "text-muted-foreground"
                )}>
                  {sdnStatus === 1 ? "Connected" : sdnStatus === 0 ? "Unreachable" : "Unknown"}
                </p>
                {sdnStatus === 0 && ws.mitigationStatus?.sdn_last_error ? (
                  <p className="text-xs text-status-danger/90 mt-1 truncate" title={ws.mitigationStatus.sdn_last_error}>
                    {ws.mitigationStatus.sdn_last_error}
                  </p>
                ) : null}
              </div>
            </div>
          </div>
        </div>

        <AutoMitigationToggle
          isEnabled={autoMitigation}
          disabled={!mitigationStatusKnown}
          onToggle={() =>
            ws.sendCommand(autoMitigation ? "disable_auto_mitigation" : "enable_auto_mitigation")
          }
          autoBlocked={ws.mitigationStatus?.total_blocked ?? 0}
          rateLimited={ws.mitigationStatus?.total_rate_limited ?? 0}
          monitored={ws.mitigationStatus?.total_monitored ?? 0}
        />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div ref={timelineRef} className="lg:col-span-2">
            {timelineEntries.length > 0 ? (
              <MitigationTimeline entries={timelineEntries} />
            ) : (
              <div className="cyber-card glow-border p-8 rounded-lg text-center">
                <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-3 opacity-30" />
                <p className="text-muted-foreground text-sm">
                  No mitigation actions recorded yet.
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Activity will appear here when the pipeline takes action.
                </p>
              </div>
            )}
          </div>

          <div className="space-y-4">
            <div className="cyber-card glow-border p-5 rounded-lg">
              <h3 className="font-semibold mb-4">Quick Actions</h3>
              <div className="space-y-3">
                <button
                  onClick={() => ws.sendCommand("block_all_flagged")}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-status-danger/10 text-status-danger border border-status-danger/20 hover:bg-status-danger/15 transition-colors"
                >
                  <Ban className="w-4 h-4" />
                  <span className="font-medium text-sm">Block All Flagged IPs</span>
                </button>
                <button
                  onClick={() => ws.sendCommand("apply_rate_limit")}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-cyber-orange/10 text-cyber-orange border border-cyber-orange/20 hover:bg-cyber-orange/15 transition-colors"
                >
                  <Gauge className="w-4 h-4" />
                  <span className="font-medium text-sm">Apply Global Rate Limit</span>
                </button>
                <button
                  onClick={() => ws.sendCommand("enable_monitoring")}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-status-warning/10 text-status-warning border border-status-warning/20 hover:bg-status-warning/15 transition-colors"
                >
                  <Eye className="w-4 h-4" />
                  <span className="font-medium text-sm">Enable Enhanced Monitoring</span>
                </button>
                <button
                  onClick={() => ws.sendCommand("clear_all_blocks")}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-status-success/10 text-status-success border border-status-success/20 hover:bg-status-success/15 transition-colors"
                >
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-medium text-sm">Clear All Blocks</span>
                </button>
              </div>
            </div>

            {activeThreats > 0 ? (
              <div className="cyber-card p-5 rounded-lg border border-status-warning/20 bg-status-warning/5">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-status-warning flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-semibold text-status-warning text-sm mb-1">
                      Active Threat Detected
                    </h4>
                    <p className="text-xs text-muted-foreground mb-3">
                      {ws.mitigationStatus?.total_blocked ?? 0} blocked, {ws.mitigationStatus?.total_rate_limited ?? 0} rate-limited. Auto-mitigation is {autoMitigation ? "active" : "paused"}.
                    </p>
                    <button
                      type="button"
                      onClick={() => timelineRef.current?.scrollIntoView({ behavior: "smooth" })}
                      className="text-xs font-medium text-status-warning hover:underline"
                    >
                      View Details -&gt;
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="cyber-card p-5 rounded-lg border border-status-success/20 bg-status-success/5">
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-status-success flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-semibold text-status-success text-sm mb-1">
                      All Clear
                    </h4>
                    <p className="text-xs text-muted-foreground">
                      {autoMitigation
                        ? "No active threats detected. Pipeline is monitoring traffic."
                        : "Auto-mitigation is paused. Threats will remain monitored until you act manually."}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Blocked, Rate-Limited, Monitored, Whitelisted IPs — real data from backend */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="cyber-card glow-border p-5 rounded-lg">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Ban className="w-4 h-4 text-status-danger" />
              Blocked IPs
            </h3>
            <div className="overflow-x-auto max-h-48 overflow-y-auto">
              {ws.blockedIPs.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                      <th className="text-right text-xs text-muted-foreground py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ws.blockedIPs.map((entry, idx) => (
                      <tr key={`${entry.ip}-${idx}`} className="border-b border-border/50">
                        <td className="py-2 font-mono">{entry.ip}</td>
                        <td className="py-2 text-right">
                          <button
                            type="button"
                            onClick={() => ws.sendCommand("unblock_ip", { ip: entry.ip })}
                            className="text-xs text-status-success hover:underline"
                          >
                            Unblock
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-muted-foreground py-4">No blocked IPs</p>
              )}
            </div>
          </div>

          <div className="cyber-card glow-border p-5 rounded-lg">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Gauge className="w-4 h-4 text-cyber-orange" />
              Rate-Limited IPs
            </h3>
            <div className="overflow-x-auto max-h-48 overflow-y-auto">
              {ws.rateLimitedIPs.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                      <th className="text-left text-xs text-muted-foreground py-2">Limit (pps)</th>
                      <th className="text-right text-xs text-muted-foreground py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ws.rateLimitedIPs.map((entry, idx) => (
                      <tr key={`${entry.ip}-${idx}`} className="border-b border-border/50">
                        <td className="py-2 font-mono">{entry.ip}</td>
                        <td className="py-2 font-mono">{entry.limit_pps}</td>
                        <td className="py-2 text-right">
                          <button
                            type="button"
                            onClick={() => ws.sendCommand("clear_rate_limit", { ip: entry.ip })}
                            className="text-xs text-status-success hover:underline"
                          >
                            Clear
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-muted-foreground py-4">No rate-limited IPs</p>
              )}
            </div>
          </div>

          <div className="cyber-card glow-border p-5 rounded-lg">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Eye className="w-4 h-4 text-status-warning" />
              Monitored IPs
            </h3>
            <div className="overflow-x-auto max-h-48 overflow-y-auto">
              {ws.monitoredIPs.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ws.monitoredIPs.map((entry, idx) => (
                      <tr key={`${entry.ip}-${idx}`} className="border-b border-border/50">
                        <td className="py-2 font-mono">{entry.ip}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-muted-foreground py-4">No monitored IPs</p>
              )}
            </div>
          </div>

          <div className="cyber-card glow-border p-5 rounded-lg">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-status-success" />
              Whitelisted IPs
            </h3>
            <div className="overflow-x-auto max-h-48 overflow-y-auto">
              {ws.whitelistedIPs.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ws.whitelistedIPs.map((entry, idx) => (
                      <tr key={`${entry.ip}-${idx}`} className="border-b border-border/50">
                        <td className="py-2 font-mono">{entry.ip}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-muted-foreground py-4">No whitelisted IPs</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default MitigationControl;

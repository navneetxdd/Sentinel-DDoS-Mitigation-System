import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { GridLayout, StatCard } from "@/components/layout/GridPanel";
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
  Download,
  Upload,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useMemo, useRef, useEffect, useCallback, useState } from "react";
import { getMitigationIntegrationSettings } from "@/lib/settingsStorage";
import type { SentinelActivity } from "@/hooks/useSentinelWebSocket";
import { toast } from "@/hooks/use-toast";

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

function formatThreatScore(value: unknown): string {
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(2) : "N/A";
}

function prettyCommandName(command: string): string {
  switch (command) {
    case "block_all_flagged":
      return "Block All Flagged";
    case "apply_rate_limit":
      return "Apply Global Rate Limit";
    case "clear_all_blocks":
      return "Clear All Blocks";
    case "block_ip":
      return "Block IP";
    case "block_ip_port":
      return "Block IP:Port";
    case "unblock_ip":
      return "Unblock IP";
    case "enable_auto_mitigation":
      return "Enable Auto Mitigation";
    case "disable_auto_mitigation":
      return "Disable Auto Mitigation";
    default:
      return command.replace(/_/g, " ");
  }
}

const MitigationControl = () => {
  const ws = useSentinelWebSocket();
  const timelineRef = useRef<HTMLDivElement>(null);
  const mitigationStatusKnown = ws.mitigationStatus !== null;
  const autoMitigation = ws.mitigationStatus?.auto_mitigation_enabled ?? false;

  const stats = [
    { label: "Blocked IPs", value: ws.mitigationStatus?.total_blocked ?? 0, icon: Ban, variant: "danger" as const },
    { label: "Rate Limited", value: ws.mitigationStatus?.total_rate_limited ?? 0, icon: Gauge, variant: "warning" as const },
    { label: "Monitored", value: ws.mitigationStatus?.total_monitored ?? 0, icon: Eye, variant: "default" as const },
    { label: "Whitelisted", value: ws.mitigationStatus?.total_whitelisted ?? 0, icon: CheckCircle, variant: "success" as const },
  ];

  const kernelDrops = ws.mitigationStatus?.kernel_dropping_enabled ?? false;
  const sdnStatus = ws.mitigationStatus?.sdn_connected;
  const dataplaneMode = ws.mitigationStatus?.dataplane_mode ?? "Unknown";

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
      const threatScoreText = formatThreatScore(activity.threat_score);
      return {
        id: `${activity.timestamp}-${idx}`,
        timestamp: new Date(activity.timestamp * 1000).toLocaleString(),
        action,
        target: activity.src_ip,
        attackType: activity.attack_type,
        protocol,
        details: `${activity.attack_type} (${protocol}) — ${activity.reason} — threat: ${threatScoreText}${activity.enforced ? "" : " [manual mode]"}`,
        status: "completed" as const,
      };
    });
  }, [mergedActivities]);

  const [blockIpInput, setBlockIpInput] = useState("");

  const lastActionTime =
    mergedActivities.length > 0
      ? new Date(mergedActivities[0].timestamp * 1000).toLocaleTimeString()
      : "-";

  const handleBlockIp = useCallback(() => {
    const v = blockIpInput.trim();
    if (!v) return;
    if (v.includes(":")) {
      ws.sendCommand("block_ip_port", { value: v });
      toast({ title: "Block IP:Port", description: `Queued block for ${v}` });
    } else {
      ws.sendCommand("block_ip", { ip: v });
      toast({ title: "Block IP", description: `Queued block for ${v}` });
    }
    setBlockIpInput("");
  }, [blockIpInput, ws]);

  const activeThreats =
    (ws.mitigationStatus?.total_blocked ?? 0) +
    (ws.mitigationStatus?.total_rate_limited ?? 0);
  const lastCommandResult = ws.lastCommandResult;

  const lastAlertSentRef = useRef<string>("");
  const lastWebhookFailedToastRef = useRef(false);
  const postAlertWebhook = useCallback((payload: { timestamp: string; event: string; sourceIp?: string; blockedCount?: number; message?: string }) => {
    const { alertWebhookUrl, alertWebhookSecret } = getMitigationIntegrationSettings();
    const url = alertWebhookUrl.trim();
    if (!url) return;
    try {
      new URL(url);
    } catch {
      return;
    }
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (alertWebhookSecret.trim()) headers["Authorization"] = `Bearer ${alertWebhookSecret.trim()}`;
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 10000);
    fetch(url, { method: "POST", headers, body: JSON.stringify(payload), signal: controller.signal })
      .then((r) => { clearTimeout(t); if (!r.ok) throw new Error(`HTTP ${r.status}`); })
      .catch(() => {
        clearTimeout(t);
        if (!lastWebhookFailedToastRef.current) {
          lastWebhookFailedToastRef.current = true;
          toast({ title: "Alert webhook failed", description: "Check URL and network. Alerts may not have been delivered.", variant: "destructive" });
        }
      });
  }, []);

  useEffect(() => {
    const first = mergedActivities[0];
    if (!first) return;
    const key = `${first.timestamp}-${first.src_ip}`;
    if (lastAlertSentRef.current === key) return;
    const actionLower = first.action.toLowerCase();
    const isBlock = actionLower.includes("block") && first.enforced;
    const isRateLimit = actionLower.includes("rate") && first.enforced;
    if (!isBlock && !isRateLimit) return;
    lastAlertSentRef.current = key;
    postAlertWebhook({
      timestamp: new Date().toISOString(),
      event: isBlock ? "block" : "rate_limit",
      sourceIp: first.src_ip,
      message: `${first.action} — ${first.attack_type} (threat: ${formatThreatScore(first.threat_score)})`,
    });
  }, [mergedActivities, postAlertWebhook]);

  const handleExportCsv = useCallback(() => {
    const rows = mergedActivities.map((a: SentinelActivity) => [
      new Date(a.timestamp * 1000).toISOString(),
      a.src_ip,
      a.action,
      a.attack_type,
      String(a.threat_score),
      a.reason,
      a.enforced ? "yes" : "no",
    ]);
    const header = "Time,Source IP,Action,Attack Type,Threat Score,Reason,Enforced\n";
    const csv = header + rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-activity-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [mergedActivities]);

  const handleBlockAllFlagged = useCallback(() => {
    ws.sendCommand("block_all_flagged");
    const { alertWebhookUrl } = getMitigationIntegrationSettings();
    if (alertWebhookUrl.trim()) {
      postAlertWebhook({
        timestamp: new Date().toISOString(),
        event: "block_all_flagged",
        blockedCount: ws.mitigationStatus?.total_monitored ?? 0,
        message: "Block All Flagged triggered from dashboard",
      });
    }
  }, [ws, postAlertWebhook]);

  const handlePushBlockedToApi = useCallback(async () => {
    const { externalFirewallApiUrl } = getMitigationIntegrationSettings();
    const url = externalFirewallApiUrl.trim();
    if (!url) return;
    try {
      new URL(url);
    } catch {
      toast({ title: "Invalid API URL", description: "Check Settings → External firewall API URL.", variant: "destructive" });
      return;
    }
    const ips = (ws.blockedIPs ?? []).map((b) => b.ip);
    if (ips.length === 0) {
      toast({ title: "No blocked IPs", description: "Nothing to push.", variant: "default" });
      return;
    }
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 15000);
    try {
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips }),
        signal: controller.signal,
      });
      clearTimeout(t);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      toast({ title: "Pushed to API", description: `${ips.length} IP(s) sent.` });
    } catch (e) {
      clearTimeout(t);
      toast({
        title: "External API failed",
        description: e instanceof Error ? e.message : "Request failed or timed out.",
        variant: "destructive",
      });
    }
  }, [ws.blockedIPs]);

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-6 animate-fade-in">
        <PageHeader
          title="Mitigation Control"
          description="Manage and monitor threat mitigation actions"
          icon={<Shield className="w-6 h-6 text-foreground" />}
          action={
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-secondary border border-border">
              <Clock className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Last action: {lastActionTime}</span>
            </div>
          }
        />

        {ws.telemetrySchemaMismatch ? (
          <div className="rounded-md border border-status-danger/30 bg-status-danger/5 px-4 py-3">
            <p className="text-xs text-status-danger font-medium">Degraded mode: telemetry schema mismatch</p>
            <p className="text-xs text-muted-foreground mt-1">
              {ws.telemetrySchemaError ?? "Unsupported telemetry schema received from backend."}
            </p>
          </div>
        ) : null}

        {ws.eventHistoryUnavailable ? (
          <div className="rounded-md border border-status-warning/30 bg-status-warning/5 px-4 py-3">
            <p className="text-xs text-status-warning font-medium">Event history unavailable</p>
            <p className="text-xs text-muted-foreground mt-1">
              Is the Explain API running? Timeline history is loaded from the Explain API; without it only live events are shown.
            </p>
          </div>
        ) : null}

        {(ws.activitySyncFailures ?? 0) > 0 ? (
          <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2">
            <p className="text-xs text-amber-700 dark:text-amber-400 font-medium">
              Some activity events could not be synced to the Explain API ({ws.activitySyncFailures} failure{ws.activitySyncFailures !== 1 ? "s" : ""}). Check API and network.
            </p>
          </div>
        ) : null}

        <GridLayout cols={3} gap="md">
          {stats.map((stat) => (
            <StatCard
              key={stat.label}
              label={stat.label}
              value={stat.value}
              icon={<stat.icon className="w-5 h-5" />}
              variant={stat.variant}
            />
          ))}
          <StatCard
            label="Kernel Drops"
            value={kernelDrops ? "Active" : "Disabled"}
            unit={dataplaneMode}
            icon={<Shield className="w-5 h-5" />}
            variant={kernelDrops ? "success" : "warning"}
          />
          <StatCard
            label="SDN Controller"
            value={sdnStatus === 1 ? "Connected" : sdnStatus === 0 ? "Unreachable" : "Unknown"}
            unit={sdnStatus === 0 ? "controller error" : "control plane"}
            icon={<Server className="w-5 h-5" />}
            variant={sdnStatus === 1 ? "success" : sdnStatus === 0 ? "danger" : "default"}
          />
        </GridLayout>
        {sdnStatus === 0 && ws.mitigationStatus?.sdn_last_error ? (
          <p className="text-xs text-status-danger/90 -mt-2">SDN error: {ws.mitigationStatus.sdn_last_error}</p>
        ) : null}
        {sdnStatus === 0 ? (
          <p className="text-xs text-muted-foreground mt-1">If the SDN service shows Unreachable, ensure it is running and reachable from the pipeline host.</p>
        ) : null}

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

        <div className="grid grid-cols-1 gap-6">
          <div ref={timelineRef} className="space-y-2">
            {mergedActivities.length > 0 && (
              <button
                type="button"
                onClick={handleExportCsv}
                className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                Export activity log to CSV
              </button>
            )}
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
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="IP or IP:port"
                    value={blockIpInput}
                    onChange={(e) => setBlockIpInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleBlockIp()}
                    className="flex-1 min-w-0 rounded-md border border-border bg-background px-3 py-2 text-sm"
                    aria-label="Block IP or IP:port"
                  />
                  <button
                    type="button"
                    onClick={handleBlockIp}
                    disabled={!blockIpInput.trim()}
                    className="px-3 py-2 rounded-md bg-status-danger/10 text-status-danger border border-status-danger/20 hover:bg-status-danger/15 disabled:opacity-50 text-sm font-medium"
                  >
                    Block
                  </button>
                </div>
                <button
                  onClick={handleBlockAllFlagged}
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
                  onClick={() => ws.sendCommand("clear_all_blocks")}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-status-success/10 text-status-success border border-status-success/20 hover:bg-status-success/15 transition-colors"
                >
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-medium text-sm">Clear All Blocks</span>
                </button>
                {getMitigationIntegrationSettings().externalFirewallApiUrl.trim() && (
                  <button
                    type="button"
                    onClick={handlePushBlockedToApi}
                    className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-secondary border border-border hover:bg-secondary/80 transition-colors text-sm"
                  >
                    <Upload className="w-4 h-4" />
                    <span className="font-medium text-sm">Push blocked IPs to external API</span>
                  </button>
                )}
              </div>
              {lastCommandResult ? (
                <div
                  className={cn(
                    "mt-4 rounded-md border px-3 py-2 text-xs",
                    lastCommandResult.success
                      ? "border-status-success/30 bg-status-success/5 text-status-success"
                      : "border-status-danger/30 bg-status-danger/5 text-status-danger",
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{prettyCommandName(lastCommandResult.command)}</span>
                    <span className="text-[11px] opacity-80">
                      {new Date(lastCommandResult.timestamp * 1000).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="mt-1 text-muted-foreground">{lastCommandResult.message}</p>
                </div>
              ) : null}
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
              {(ws.blockedIPs ?? []).length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                      <th className="text-right text-xs text-muted-foreground py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(ws.blockedIPs ?? []).map((entry, idx) => (
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
              {(ws.rateLimitedIPs ?? []).length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                      <th className="text-left text-xs text-muted-foreground py-2">Limit (pps)</th>
                      <th className="text-right text-xs text-muted-foreground py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(ws.rateLimitedIPs ?? []).map((entry, idx) => (
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
              {(ws.monitoredIPs ?? []).length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(ws.monitoredIPs ?? []).map((entry, idx) => (
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
              {(ws.whitelistedIPs ?? []).length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-muted-foreground py-2">IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(ws.whitelistedIPs ?? []).map((entry, idx) => (
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

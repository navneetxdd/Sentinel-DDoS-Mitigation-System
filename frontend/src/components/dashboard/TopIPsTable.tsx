import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle, Shield } from "lucide-react";
import type { SentinelTopSource } from "@/hooks/useSentinelWebSocket";

interface TopIPsTableProps {
  className?: string;
  isAttack?: boolean;
  sources?: SentinelTopSource[];
  blockedIPs?: Array<{ ip: string }>;
  rateLimitedIPs?: Array<{ ip: string }>;
}

export function TopIPsTable({
  className,
  isAttack = false,
  sources,
  blockedIPs = [],
  rateLimitedIPs = [],
}: TopIPsTableProps) {
  const blockedSet = new Set(blockedIPs.map((e) => e.ip));
  const rateLimitedSet = new Set(rateLimitedIPs.map((e) => e.ip));

  const ips = (sources ?? []).map((s) => {
    let status: "blocked" | "rate-limited" | "normal" = "normal";
    if (blockedSet.has(s.ip)) status = "blocked";
    else if (rateLimitedSet.has(s.ip)) status = "rate-limited";
    else if (s.suspicious)
      status = s.threat_score >= 0.7 ? "blocked" : "rate-limited";

    return {
      ip: s.ip,
      requests: s.packets,
      bytes: s.bytes,
      flows: s.flows,
      threatScore: s.threat_score,
      status,
    };
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "blocked":
        return (
          <span 
            className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-status-danger/10 text-status-danger border border-status-danger/20"
            role="status"
            aria-label="IP is blocked"
          >
            <Shield className="w-3 h-3" />
            Blocked
          </span>
        );
      case "rate-limited":
        return (
          <span 
            className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-status-warning/10 text-status-warning border border-status-warning/20"
            role="status"
            aria-label="IP is rate limited"
          >
            <AlertTriangle className="w-3 h-3" />
            Rate Limited
          </span>
        );
      default:
        return (
          <span 
            className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-status-success/10 text-status-success border border-status-success/20"
            role="status"
            aria-label="IP is normal"
          >
            <CheckCircle className="w-3 h-3" />
            Normal
          </span>
        );
    }
  };

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <div className="mb-4">
        <h3 className="font-semibold">Top Source IPs</h3>
        <p className="text-xs text-muted-foreground">Highest traffic sources</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full" role="table" aria-label="Top source IPs">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Source IP</th>
              <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Packets</th>
              <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Threat %</th>
              <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {ips.length > 0 ? (
              ips.map((item, index) => (
                <tr
                  key={index}
                  className="border-b border-border/50 hover:bg-secondary/30 transition-colors"
                >
                  <td className="py-3">
                    <span className="font-mono text-sm">{item.ip}</span>
                  </td>
                  <td className="py-3">
                    <span className={cn(
                      "font-mono text-sm",
                      item.requests > 50000 && "text-status-danger font-bold"
                    )}>
                      {item.requests.toLocaleString()}
                    </span>
                  </td>
                  <td className="py-3">
                    <span className={cn(
                      "font-mono text-sm",
                      (item.threatScore ?? 0) >= 0.7 && "text-status-danger font-bold",
                      (item.threatScore ?? 0) >= 0.3 && (item.threatScore ?? 0) < 0.7 && "text-status-warning"
                    )}>
                      {((item.threatScore ?? 0) * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-3">{getStatusBadge(item.status)}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={4} className="py-6 text-center text-muted-foreground text-sm">
                  Waiting for source data...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

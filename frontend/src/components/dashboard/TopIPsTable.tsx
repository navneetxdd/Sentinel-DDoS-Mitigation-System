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
          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-cyber-red/10 text-cyber-red border border-cyber-red/20">
            <Shield className="w-3 h-3" />
            Blocked
          </span>
        );
      case "rate-limited":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20">
            <AlertTriangle className="w-3 h-3" />
            Rate Limited
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-cyber-green/10 text-cyber-green border border-cyber-green/20">
            <CheckCircle className="w-3 h-3" />
            Normal
          </span>
        );
    }
  };

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-xl", className)}>
      <div className="mb-4">
        <h3 className="font-semibold">Top Source IPs</h3>
        <p className="text-xs text-muted-foreground">Highest traffic sources</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left text-xs font-medium text-muted-foreground py-2">Source IP</th>
              <th className="text-left text-xs font-medium text-muted-foreground py-2">Packets</th>
              <th className="text-left text-xs font-medium text-muted-foreground py-2">Threat %</th>
              <th className="text-left text-xs font-medium text-muted-foreground py-2">Status</th>
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
                      item.requests > 50000 && "text-cyber-red font-bold"
                    )}>
                      {item.requests.toLocaleString()}
                    </span>
                  </td>
                  <td className="py-3">
                    <span className={cn(
                      "font-mono text-sm",
                      (item.threatScore ?? 0) >= 0.7 && "text-cyber-red font-bold",
                      (item.threatScore ?? 0) >= 0.3 && (item.threatScore ?? 0) < 0.7 && "text-cyber-yellow"
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

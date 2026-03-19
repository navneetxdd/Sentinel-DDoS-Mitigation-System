import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { cn } from "@/lib/utils";

export function HealthSummaryBar() {
  const ws = useSentinelWebSocket();
  const pipeline = ws.connected ? 1 : 0;
  const explainApi = ws.explainApiReachable === true ? 1 : ws.explainApiReachable === false ? 0 : -1;
  const sdn = ws.mitigationStatus?.sdn_connected ?? -1;
  const gatekeeper = ws.integrationStatus?.gatekeeper_enabled
    ? (ws.integrationStatus?.gatekeeper_connected ?? -1)
    : -1;

  const label = (name: string, status: number) => {
    const s = status === 1 ? "✓" : status === 0 ? "✗" : "−";
    const c = status === 1 ? "text-status-success" : status === 0 ? "text-status-danger" : "text-muted-foreground";
    return <span className={cn("font-mono text-xs", c)}>{name} {s}</span>;
  };

  const parseErrors = ws.parseErrorCount ?? 0;

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground">
      {label("Pipeline", pipeline)}
      <span className="text-muted-foreground/50">|</span>
      {label("Explain API", explainApi)}
      <span className="text-muted-foreground/50">|</span>
      {label("SDN", sdn)}
      <span className="text-muted-foreground/50">|</span>
      {label("Gatekeeper", gatekeeper)}
      {parseErrors > 0 && (
        <>
          <span className="text-muted-foreground/50">|</span>
          <span className="font-mono text-xs text-amber-600 dark:text-amber-400" title="Malformed WebSocket messages ignored">
            Parse err {parseErrors}
          </span>
        </>
      )}
    </div>
  );
}

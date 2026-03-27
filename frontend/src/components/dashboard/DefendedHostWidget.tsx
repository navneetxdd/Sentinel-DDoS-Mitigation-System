import { useEffect, useState, useCallback } from "react";
import { Globe, Copy, Check, Shield, Wifi } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";

/**
 * DefendedHostWidget — replaces the static SLOPanel.
 *
 * Shows the machine's public IP fetched at runtime from a safe, CORS-friendly
 * API (ipify.org). This is NOT a security risk — it only reveals the same IP
 * any external scanner would already see. The fetch happens once on mount.
 */
export function DefendedHostWidget() {
  const [publicIp, setPublicIp] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState(false);
  const ws = useSentinelWebSocket();

  const dataplaneMode = ws.mitigationStatus?.dataplane_mode ?? "unknown";
  const kernelDropping = ws.mitigationStatus?.kernel_dropping_enabled ?? false;

  useEffect(() => {
    let cancelled = false;
    const fetchIp = async () => {
      try {
        const resp = await fetch("https://api.ipify.org?format=json", {
          signal: AbortSignal.timeout(5000),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (!cancelled && typeof data.ip === "string") {
          setPublicIp(data.ip);
        }
      } catch {
        if (!cancelled) setError(true);
      }
    };
    fetchIp();
    return () => { cancelled = true; };
  }, []);

  const handleCopy = useCallback(() => {
    if (!publicIp) return;
    navigator.clipboard.writeText(publicIp).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [publicIp]);

  return (
    <div className="rounded-md border border-border bg-card/50 px-3 py-2 text-xs">
      <div className="flex items-center gap-2 text-muted-foreground font-medium mb-1.5">
        <Shield className="w-3.5 h-3.5" />
        Defended Host
      </div>

      {/* Public IP */}
      <div className="flex items-center gap-2 mb-1">
        <Globe className="w-3 h-3 flex-shrink-0 text-muted-foreground" />
        <span className="text-muted-foreground">Public IP:</span>
        {publicIp ? (
          <button
            onClick={handleCopy}
            className={cn(
              "font-mono text-xs px-1.5 py-0.5 rounded transition-colors inline-flex items-center gap-1",
              "bg-primary/10 text-primary hover:bg-primary/20"
            )}
            title="Click to copy"
          >
            {publicIp}
            {copied ? (
              <Check className="w-3 h-3 text-green-500" />
            ) : (
              <Copy className="w-3 h-3 opacity-50" />
            )}
          </button>
        ) : error ? (
          <span className="text-muted-foreground/60 italic">unavailable</span>
        ) : (
          <span className="text-muted-foreground/60 animate-pulse">fetching…</span>
        )}
      </div>

      {/* Dataplane info */}
      <div className="flex items-center gap-2">
        <Wifi className="w-3 h-3 flex-shrink-0 text-muted-foreground" />
        <span className="text-muted-foreground">Dataplane:</span>
        <span className={cn(
          "font-mono text-xs",
          kernelDropping ? "text-green-500" : "text-amber-500"
        )}>
          {kernelDropping ? "eBPF Hardware Offload" : dataplaneMode.replace(/_/g, " ")}
        </span>
      </div>
    </div>
  );
}

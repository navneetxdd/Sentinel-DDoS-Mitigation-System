import { cn } from "@/lib/utils";
import { Shield, ShieldCheck, ShieldOff } from "lucide-react";

interface AutoMitigationToggleProps {
  isEnabled: boolean;
  onToggle: () => void;
  autoBlocked?: number;
  rateLimited?: number;
  monitored?: number;
  disabled?: boolean;
  className?: string;
}

export function AutoMitigationToggle({
  isEnabled,
  onToggle,
  autoBlocked = 0,
  rateLimited = 0,
  monitored = 0,
  disabled = false,
  className,
}: AutoMitigationToggleProps) {
  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className={cn(
            "p-3 rounded-md transition-colors",
            isEnabled ? "bg-status-success/10" : "bg-secondary"
          )}>
            {isEnabled ? (
              <ShieldCheck className="w-6 h-6 text-status-success" />
            ) : (
              <ShieldOff className="w-6 h-6 text-muted-foreground" />
            )}
          </div>
          <div>
            <h3 className="font-semibold">Auto Mitigation</h3>
            <p className="text-xs text-muted-foreground">
              {isEnabled
                ? "System will automatically respond to threats"
                : "Manual approval required for all actions"}
            </p>
          </div>
        </div>

        <button
          onClick={onToggle}
          disabled={disabled}
          className={cn(
            "relative flex items-center gap-2 px-5 py-2.5 rounded-md font-medium text-sm transition-colors border",
            isEnabled
              ? "bg-status-success/10 text-status-success border-status-success/20"
              : "bg-secondary text-foreground hover:bg-secondary/80 border-border",
            disabled && "opacity-60 cursor-not-allowed hover:bg-secondary"
          )}
        >
          <Shield className="w-4 h-4" />
          <span>{isEnabled ? "Enabled" : "Disabled"}</span>
          <div className={cn(
            "w-10 h-5 rounded-full p-0.5 transition-colors ml-2",
            isEnabled ? "bg-status-success" : "bg-muted"
          )}>
            <div className={cn(
              "w-4 h-4 rounded-full bg-background transition-transform",
              isEnabled && "translate-x-5"
            )} />
          </div>
        </button>
      </div>

      {/* Status Details */}
      <div className="mt-4 grid grid-cols-3 gap-3">
        <div className={cn(
          "p-3 rounded-md text-center border",
          isEnabled ? "bg-status-success/5 border-status-success/20" : "bg-secondary/50 border-border"
        )}>
          <p className="text-2xl font-bold font-mono text-status-success">{autoBlocked}</p>
          <p className="text-xs text-muted-foreground">Auto Blocked</p>
        </div>
        <div className={cn(
          "p-3 rounded-md text-center border",
          isEnabled ? "bg-status-warning/5 border-status-warning/20" : "bg-secondary/50 border-border"
        )}>
          <p className="text-2xl font-bold font-mono text-status-warning">{rateLimited}</p>
          <p className="text-xs text-muted-foreground">Rate Limited</p>
        </div>
        <div className={cn(
          "p-3 rounded-md text-center border",
          isEnabled ? "bg-secondary border-border" : "bg-secondary/50 border-border"
        )}>
          <p className="text-2xl font-bold font-mono text-foreground">{monitored}</p>
          <p className="text-xs text-muted-foreground">Monitored</p>
        </div>
      </div>
    </div>
  );
}

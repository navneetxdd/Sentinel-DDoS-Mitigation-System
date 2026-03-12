import { cn } from "@/lib/utils";
import { 
  Eye, 
  Gauge, 
  Shield, 
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle 
} from "lucide-react";

interface MitigationLogEntry {
  id: string;
  timestamp: string;
  action: "monitor" | "rate_limit" | "block";
  target: string;
  details: string;
  status: "active" | "completed" | "failed";
}

interface MitigationTimelineProps {
  entries: MitigationLogEntry[];
  className?: string;
}

const actionConfig = {
  monitor: {
    icon: Eye,
    label: "Monitor",
    color: "text-cyber-yellow",
    bgColor: "bg-cyber-yellow/10",
    borderColor: "border-cyber-yellow/30",
    lineColor: "bg-cyber-yellow",
  },
  rate_limit: {
    icon: Gauge,
    label: "Rate Limit",
    color: "text-cyber-orange",
    bgColor: "bg-cyber-orange/10",
    borderColor: "border-cyber-orange/30",
    lineColor: "bg-cyber-orange",
  },
  block: {
    icon: Shield,
    label: "Block",
    color: "text-cyber-red",
    bgColor: "bg-cyber-red/10",
    borderColor: "border-cyber-red/30",
    lineColor: "bg-cyber-red",
  },
};

const statusIcons = {
  active: { icon: AlertTriangle, color: "text-cyber-yellow" },
  completed: { icon: CheckCircle, color: "text-cyber-green" },
  failed: { icon: XCircle, color: "text-cyber-red" },
};

export function MitigationTimeline({ entries, className }: MitigationTimelineProps) {
  return (
    <div className={cn("cyber-card glow-border p-5 rounded-xl", className)}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-semibold">Mitigation Log</h3>
          <p className="text-xs text-muted-foreground">Recent mitigation actions</p>
        </div>
        <Clock className="w-4 h-4 text-muted-foreground" />
      </div>

      <div className="space-y-0">
        {entries.map((entry, index) => {
          const config = actionConfig[entry.action];
          const StatusIcon = statusIcons[entry.status].icon;
          const Icon = config.icon;
          const isLast = index === entries.length - 1;

          return (
            <div key={entry.id} className="relative flex gap-4">
              {/* Timeline Line */}
              {!isLast && (
                <div className="absolute left-[17px] top-10 w-0.5 h-[calc(100%-20px)] bg-border" />
              )}

              {/* Icon */}
              <div className={cn(
                "relative z-10 p-2 rounded-lg shrink-0",
                config.bgColor,
                "border",
                config.borderColor
              )}>
                <Icon className={cn("w-4 h-4", config.color)} />
              </div>

              {/* Content */}
              <div className="flex-1 pb-6">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={cn("font-medium text-sm", config.color)}>
                        {config.label}
                      </span>
                      <StatusIcon className={cn("w-3 h-3", statusIcons[entry.status].color)} />
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {entry.timestamp}
                    </p>
                  </div>
                </div>
                <div className="mt-2 p-3 rounded-lg bg-secondary/50 border border-border">
                  <p className="text-xs font-mono text-muted-foreground mb-1">
                    Target: {entry.target}
                  </p>
                  <p className="text-sm">{entry.details}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

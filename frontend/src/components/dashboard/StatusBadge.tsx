import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle, ShieldAlert } from "lucide-react";

export type StatusType = "normal" | "observation" | "attack";

interface StatusBadgeProps {
  status: StatusType;
  className?: string;
}

const statusConfig = {
  normal: {
    label: "Traffic Normal",
    icon: CheckCircle,
    className: "bg-status-success/10 text-status-success border-status-success/20",
  },
  observation: {
    label: "Under Observation",
    icon: AlertTriangle,
    className: "bg-status-warning/10 text-status-warning border-status-warning/20",
  },
  attack: {
    label: "Attack Detected",
    icon: ShieldAlert,
    className: "bg-status-danger/10 text-status-danger border-status-danger/20",
  },
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 px-4 py-2 rounded-full border font-medium text-sm transition-all",
        config.className,
        className
      )}
    >
      <Icon className="w-4 h-4" />
      <span>{config.label}</span>
      <div className={cn(
        "w-2 h-2 rounded-full ml-1",
        status === "normal" && "bg-status-success pulse-glow",
        status === "observation" && "bg-status-warning pulse-glow",
        status === "attack" && "bg-status-danger pulse-glow"
      )} />
    </div>
  );
}

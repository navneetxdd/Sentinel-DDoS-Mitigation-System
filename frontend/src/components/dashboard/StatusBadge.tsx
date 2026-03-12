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
    className: "bg-cyber-green/10 text-cyber-green border-cyber-green/30",
    glowClass: "shadow-[0_0_20px_hsl(160_84%_45%/0.3)]",
  },
  observation: {
    label: "Under Observation",
    icon: AlertTriangle,
    className: "bg-cyber-yellow/10 text-cyber-yellow border-cyber-yellow/30",
    glowClass: "shadow-[0_0_20px_hsl(45_93%_58%/0.3)]",
  },
  attack: {
    label: "Attack Detected",
    icon: ShieldAlert,
    className: "bg-cyber-red/10 text-cyber-red border-cyber-red/30",
    glowClass: "shadow-[0_0_20px_hsl(0_72%_51%/0.3)]",
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
        config.glowClass,
        className
      )}
    >
      <Icon className="w-4 h-4" />
      <span>{config.label}</span>
      <div className={cn(
        "w-2 h-2 rounded-full ml-1",
        status === "normal" && "bg-cyber-green animate-pulse-glow",
        status === "observation" && "bg-cyber-yellow animate-pulse-glow",
        status === "attack" && "bg-cyber-red animate-pulse-glow"
      )} />
    </div>
  );
}

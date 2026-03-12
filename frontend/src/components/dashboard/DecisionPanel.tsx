import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle, ShieldAlert, TrendingUp } from "lucide-react";

type ClassificationType = "benign" | "flash_crowd" | "ddos";

interface DecisionPanelProps {
  attackProbability: number;
  classification: ClassificationType;
  className?: string;
}

const classificationConfig = {
  benign: {
    label: "Benign Traffic",
    icon: CheckCircle,
    color: "text-cyber-green",
    bgColor: "bg-cyber-green/10",
    borderColor: "border-cyber-green/30",
  },
  flash_crowd: {
    label: "Flash Crowd Event",
    icon: TrendingUp,
    color: "text-cyber-yellow",
    bgColor: "bg-cyber-yellow/10",
    borderColor: "border-cyber-yellow/30",
  },
  ddos: {
    label: "DDoS Attack",
    icon: ShieldAlert,
    color: "text-cyber-red",
    bgColor: "bg-cyber-red/10",
    borderColor: "border-cyber-red/30",
  },
};

export function DecisionPanel({
  attackProbability,
  classification,
  className,
}: DecisionPanelProps) {
  const config = classificationConfig[classification];
  const Icon = config.icon;

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <h3 className="font-semibold mb-4">Classification Result</h3>

      <div className="grid gap-4">
        {/* Attack Probability */}
        <div className="p-4 rounded-md bg-secondary/50 border border-border">
          <p className="text-xs text-muted-foreground mb-2">Attack Probability</p>
          <div className="flex items-center gap-3">
            <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full transition-all duration-1000",
                  attackProbability > 70
                    ? "bg-cyber-red"
                    : attackProbability > 40
                    ? "bg-cyber-yellow"
                    : "bg-cyber-green"
                )}
                style={{ width: `${attackProbability}%` }}
              />
            </div>
            <span
              className={cn(
                "font-mono font-bold text-xl min-w-[60px] text-right",
                attackProbability > 70
                  ? "text-cyber-red"
                  : attackProbability > 40
                  ? "text-cyber-yellow"
                  : "text-cyber-green"
              )}
            >
              {attackProbability}%
            </span>
          </div>
        </div>

        {/* Classification */}
        <div
          className={cn(
            "p-4 rounded-md border flex items-center gap-4",
            config.bgColor,
            config.borderColor
          )}
        >
          <div className={cn("p-3 rounded-md", config.bgColor)}>
            <Icon className={cn("w-6 h-6", config.color)} />
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Classification</p>
            <p className={cn("font-semibold text-lg", config.color)}>
              {config.label}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

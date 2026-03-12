import { cn } from "@/lib/utils";
import { AlertTriangle, Info, ShieldAlert, Zap } from "lucide-react";
import type { SentinelFeatureImportance } from "@/hooks/useSentinelWebSocket";

interface ExplanationBoxProps {
  isAttack: boolean;
  isFlashCrowd: boolean;
  featureImportance?: SentinelFeatureImportance | null;
  className?: string;
}

export function ExplanationBox({ isAttack, isFlashCrowd, featureImportance, className }: ExplanationBoxProps) {
  const fi = featureImportance;

  const getExplanation = () => {
    const avgScore = fi ? fi.avg_threat_score.toFixed(3) : "—";
    const volW = fi ? (fi.volume_weight * 100).toFixed(0) : "—";
    const entW = fi ? (fi.entropy_weight * 100).toFixed(0) : "—";
    const behW = fi ? (fi.behavioral_weight * 100).toFixed(0) : "—";
    const mlW = fi ? (fi.ml_weight * 100).toFixed(0) : "—";
    const protoW = fi ? (fi.protocol_weight * 100).toFixed(0) : "—";
    const det10s = fi ? fi.detections_last_10s : "—";

    if (isAttack) {
      return {
        icon: ShieldAlert,
        title: "DDoS Attack Detected",
        color: "text-status-danger",
        borderColor: "border-status-danger/20",
        bgColor: "bg-status-danger/5",
        points: [
          `Live threat score: ${avgScore}`,
          `Detections (last 10s): ${det10s}`,
          `Volume weight (configured): ${volW}%`,
          `IP entropy weight (configured): ${entW}%`,
          `ML weight (configured): ${mlW}%`,
          `Behavioral weight (configured): ${behW}%`,
        ],
        recommendation: "Immediate mitigation recommended. Auto-mitigation has been triggered.",
      };
    }

    if (isFlashCrowd) {
      return {
        icon: AlertTriangle,
        title: "Flash Crowd Event Detected",
        color: "text-status-warning",
        borderColor: "border-status-warning/20",
        bgColor: "bg-status-warning/5",
        points: [
          `Live threat score: ${avgScore}`,
          `Detections (last 10s): ${det10s}`,
          `Behavioral weight (configured): ${behW}%`,
          `Protocol weight (configured): ${protoW}%`,
        ],
        recommendation: "Scale infrastructure capacity. No blocking action required.",
      };
    }

    return {
      icon: Info,
      title: "Normal Traffic Pattern",
      color: "text-status-success",
      borderColor: "border-status-success/20",
      bgColor: "bg-status-success/5",
      points: [
        `Live threat score: ${avgScore}`,
        `IP entropy weight (configured): ${entW}%`,
        `Protocol weight (configured): ${protoW}%`,
        `ML weight (configured): ${mlW}%`,
      ],
      recommendation: "Continue monitoring. No action required.",
    };
  };

  const explanation = getExplanation();
  const Icon = explanation.icon;

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <div className="flex items-center gap-3 mb-4">
        <div className={cn("p-2 rounded-lg", explanation.bgColor)}>
          <Icon className={cn("w-5 h-5", explanation.color)} />
        </div>
        <h3 className={cn("font-semibold", explanation.color)}>{explanation.title}</h3>
      </div>

      <div className={cn(
        "p-4 rounded-md border mb-4",
        explanation.bgColor,
        explanation.borderColor
      )}>
        <p className="text-sm text-muted-foreground mb-3 font-medium">Heuristic Explanation (live metrics):</p>
        <ul className="space-y-2">
          {explanation.points.map((point, index) => (
            <li key={index} className="flex items-start gap-2 text-sm">
              <Zap className={cn("w-3 h-3 mt-1 flex-shrink-0", explanation.color)} />
              <span className="text-foreground/90">{point}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="p-3 rounded-md bg-secondary/50 border border-border">
        <p className="text-xs text-muted-foreground mb-1">Recommendation</p>
        <p className="text-sm font-medium">{explanation.recommendation}</p>
      </div>
    </div>
  );
}

import { cn } from "@/lib/utils";
import { Zap, Users } from "lucide-react";

interface SimulationToggleProps {
  isFlashCrowd: boolean;
  isDDoS: boolean;
  onFlashCrowdToggle: () => void;
  onDDoSToggle: () => void;
  className?: string;
}

export function SimulationToggle({
  isFlashCrowd,
  isDDoS,
  onFlashCrowdToggle,
  onDDoSToggle,
  className,
}: SimulationToggleProps) {
  return (
    <div className={cn("flex flex-wrap gap-3", className)}>
      <button
        onClick={onFlashCrowdToggle}
        className={cn(
          "flex items-center gap-2 px-4 py-2.5 rounded-md font-medium text-sm transition-colors border",
          isFlashCrowd
            ? "bg-status-warning/10 text-status-warning border-status-warning/20"
            : "bg-secondary text-muted-foreground hover:text-foreground hover:bg-secondary/80 border-border"
        )}
      >
        <Users className="w-4 h-4" />
        <span>Simulate Flash Crowd</span>
        <div className={cn(
          "w-8 h-4 rounded-full p-0.5 transition-colors",
          isFlashCrowd ? "bg-status-warning" : "bg-muted"
        )}>
          <div className={cn(
            "w-3 h-3 rounded-full bg-background transition-transform",
            isFlashCrowd && "translate-x-4"
          )} />
        </div>
      </button>

      <button
        onClick={onDDoSToggle}
        className={cn(
          "flex items-center gap-2 px-4 py-2.5 rounded-md font-medium text-sm transition-colors border",
          isDDoS
            ? "bg-status-danger/10 text-status-danger border-status-danger/20"
            : "bg-secondary text-muted-foreground hover:text-foreground hover:bg-secondary/80 border-border"
        )}
      >
        <Zap className="w-4 h-4" />
        <span>Simulate DDoS Attack</span>
        <div className={cn(
          "w-8 h-4 rounded-full p-0.5 transition-colors",
          isDDoS ? "bg-status-danger" : "bg-muted"
        )}>
          <div className={cn(
            "w-3 h-3 rounded-full bg-background transition-transform",
            isDDoS && "translate-x-4"
          )} />
        </div>
      </button>
    </div>
  );
}

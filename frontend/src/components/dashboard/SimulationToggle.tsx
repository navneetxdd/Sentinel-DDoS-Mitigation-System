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
          "flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium text-sm transition-all duration-300",
          isFlashCrowd
            ? "bg-cyber-yellow/20 text-cyber-yellow border border-cyber-yellow/40 shadow-[0_0_20px_hsl(45_93%_58%/0.3)]"
            : "bg-secondary text-muted-foreground hover:text-foreground hover:bg-secondary/80 border border-transparent"
        )}
      >
        <Users className="w-4 h-4" />
        <span>Simulate Flash Crowd</span>
        <div className={cn(
          "w-8 h-4 rounded-full p-0.5 transition-colors",
          isFlashCrowd ? "bg-cyber-yellow" : "bg-muted"
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
          "flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium text-sm transition-all duration-300",
          isDDoS
            ? "bg-cyber-red/20 text-cyber-red border border-cyber-red/40 shadow-[0_0_20px_hsl(0_72%_51%/0.3)]"
            : "bg-secondary text-muted-foreground hover:text-foreground hover:bg-secondary/80 border border-transparent"
        )}
      >
        <Zap className="w-4 h-4" />
        <span>Simulate DDoS Attack</span>
        <div className={cn(
          "w-8 h-4 rounded-full p-0.5 transition-colors",
          isDDoS ? "bg-cyber-red" : "bg-muted"
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

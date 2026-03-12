import { cn } from "@/lib/utils";

interface RiskGaugeProps {
  value: number;
  className?: string;
}

export function RiskGauge({ value, className }: RiskGaugeProps) {
  const clampedValue = Math.min(100, Math.max(0, value));
  const rotation = (clampedValue / 100) * 180 - 90;

  const getRiskLevel = (val: number) => {
    if (val < 30) return { label: "Low", color: "text-cyber-green" };
    if (val < 60) return { label: "Medium", color: "text-cyber-yellow" };
    if (val < 80) return { label: "High", color: "text-cyber-orange" };
    return { label: "Critical", color: "text-cyber-red" };
  };

  const risk = getRiskLevel(clampedValue);

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-xl", className)}>
      <p className="text-sm text-muted-foreground font-medium mb-4">Risk Score</p>
      
      <div className="relative w-full aspect-[2/1] max-w-[200px] mx-auto">
        {/* Background Arc */}
        <svg viewBox="0 0 200 100" className="w-full h-full">
          <defs>
            <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="hsl(160, 84%, 45%)" />
              <stop offset="40%" stopColor="hsl(45, 93%, 58%)" />
              <stop offset="70%" stopColor="hsl(25, 95%, 53%)" />
              <stop offset="100%" stopColor="hsl(0, 72%, 51%)" />
            </linearGradient>
          </defs>
          
          {/* Background Track */}
          <path
            d="M 20 90 A 80 80 0 0 1 180 90"
            fill="none"
            stroke="hsl(var(--secondary))"
            strokeWidth="12"
            strokeLinecap="round"
          />
          
          {/* Value Arc */}
          <path
            d="M 20 90 A 80 80 0 0 1 180 90"
            fill="none"
            stroke="url(#riskGradient)"
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${clampedValue * 2.51} 251`}
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Needle */}
        <div 
          className="absolute bottom-0 left-1/2 w-1 h-16 origin-bottom transition-transform duration-1000 ease-out"
          style={{ transform: `translateX(-50%) rotate(${rotation}deg)` }}
        >
          <div className="w-1 h-full bg-gradient-to-t from-foreground to-transparent rounded-full" />
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-3 h-3 bg-foreground rounded-full" />
        </div>

        {/* Center Value */}
        <div className="absolute bottom-2 left-1/2 -translate-x-1/2 text-center">
          <span className={cn("text-4xl font-bold font-mono", risk.color)}>
            {clampedValue}
          </span>
        </div>
      </div>

      {/* Risk Level */}
      <div className="text-center mt-4">
        <span className={cn("text-sm font-medium", risk.color)}>
          {risk.label} Risk
        </span>
      </div>

      {/* Scale Labels */}
      <div className="flex justify-between text-xs text-muted-foreground mt-2 px-4">
        <span>0</span>
        <span>50</span>
        <span>100</span>
      </div>
    </div>
  );
}

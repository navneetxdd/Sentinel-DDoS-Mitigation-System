import { cn } from "@/lib/utils";
import { BarChart3, Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface RiskScoreBreakdownProps {
  threatScore: number;
  weights?: {
    volume_weight?: number;
    entropy_weight?: number;
    protocol_weight?: number;
    behavioral_weight?: number;
    ml_weight?: number;
    l7_weight?: number;
    anomaly_weight?: number;
    chi_square_weight?: number;
    fanin_weight?: number;
    signature_weight?: number;
  };
  scores?: {
    score_volume?: number;
    score_entropy?: number;
    score_protocol?: number;
    score_behavioral?: number;
    score_ml?: number;
    score_l7?: number;
    score_anomaly?: number;
    score_chi_square?: number;
    score_fanin?: number;
    score_signature?: number;
  };
  className?: string;
}

const THREAT_COMPONENTS = [
  {
    name: "Volume Anomaly",
    description: "Unusual spike in packets or bytes per second (EWMA baseline comparison)",
    weight: 0.12,
    keyField: "volume_weight",
    scoreField: "score_volume",
  },
  {
    name: "Entropy Anomaly",
    description: "Low entropy (repeated patterns) in ports or payload data",
    weight: 0.08,
    keyField: "entropy_weight",
    scoreField: "score_entropy",
  },
  {
    name: "Protocol Anomaly",
    description: "SYN floods, UDP floods, DNS/NTP amplification, or reflection attacks",
    weight: 0.12,
    keyField: "protocol_weight",
    scoreField: "score_protocol",
  },
  {
    name: "Behavioral Anomaly",
    description: "Port scans, slowloris, LAND attacks, or unusual flow patterns",
    weight: 0.08,
    keyField: "behavioral_weight",
    scoreField: "score_behavioral",
  },
  {
    name: "ML Model",
    description: "Machine learning decision tree ensemble inference",
    weight: 0.35,
    keyField: "ml_weight",
    scoreField: "score_ml",
  },
  {
    name: "Layer 7 Asymmetry",
    description: "HTTP GET floods, request-response size imbalance, application-layer patterns",
    weight: 0.07,
    keyField: "l7_weight",
    scoreField: "score_l7",
  },
  {
    name: "Online Anomaly",
    description: "Streaming multivariate anomaly detection over global traffic baseline",
    weight: 0.05,
    keyField: "anomaly_weight",
    scoreField: "score_anomaly",
  },
  {
    name: "Chi-Square Concentration",
    description: "Single-source traffic dominance test (volumetric DDoS detector)",
    weight: 0.05,
    keyField: "chi_square_weight",
    scoreField: "score_chi_square",
  },
  {
    name: "Fan-in Distribution",
    description: "Distributed DDoS signature (many sources targeting one destination)",
    weight: 0.03,
    keyField: "fanin_weight",
    scoreField: "score_fanin",
  },
  {
    name: "Signature Match",
    description: "Known reflection attack signatures (DNS, NTP, SSDP, etc.)",
    weight: 0.05,
    keyField: "signature_weight",
    scoreField: "score_signature",
  },
];

export function RiskScoreBreakdown({
  threatScore,
  weights = {},
  scores = {},
  className,
}: RiskScoreBreakdownProps) {
  const riskPercent = Math.min(100, Math.round(threatScore * 100));

  // Get actual weights from props or use defaults
  const getWeight = (keyField: string): number => {
    const w = weights[keyField as keyof typeof weights];
    const defaultW = THREAT_COMPONENTS.find((c) => c.keyField === keyField)?.weight ?? 0;
    return w ?? defaultW;
  };

  return (
    <TooltipProvider>
      <div className={cn("cyber-card glow-border p-6 rounded-lg space-y-4", className)}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <BarChart3 className="w-5 h-5 text-muted-foreground" />
              <h3 className="text-sm font-semibold">Risk Score Calculation</h3>
            </div>
            <div className="text-xs text-muted-foreground flex items-center gap-2">
              <span>
                Final Risk: <span className="font-mono font-bold text-foreground">{riskPercent}%</span>
              </span>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Info className="w-3.5 h-3.5 text-muted-foreground/80 cursor-help" />
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs">
                  <p>Weighted final score from all threat models. Higher means stronger malicious evidence.</p>
                </TooltipContent>
              </Tooltip>
            </div>
          </div>
          <Tooltip>
            <TooltipTrigger asChild>
              <Info className="w-4 h-4 text-muted-foreground cursor-help flex-shrink-0 mt-1" />
            </TooltipTrigger>
            <TooltipContent side="left" className="max-w-xs">
              <p>
                Risk score is a weighted combination of 10 threat detection models. Each model evaluates different aspects of network
                traffic behavior. The final score (0-100%) determines whether traffic is allowed, rate-limited, or blocked.
              </p>
            </TooltipContent>
          </Tooltip>
        </div>

        {/* Component Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          {THREAT_COMPONENTS.map((component) => {
            const weight = getWeight(component.keyField);
            const componentScore = scores[component.scoreField as keyof typeof scores];
            const scoreBar = Math.max(0, Math.min(100, ((componentScore ?? 0) as number) * 100));

            return (
              <Tooltip key={component.name}>
                <TooltipTrigger asChild>
                  <div className="bg-secondary/20 hover:bg-secondary/30 rounded p-3 transition-colors cursor-help">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-1.5">
                          <p className="text-xs font-semibold leading-tight">{component.name}</p>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Info className="w-3.5 h-3.5 text-muted-foreground/80 cursor-help" />
                            </TooltipTrigger>
                            <TooltipContent side="top" className="max-w-xs">
                              <p>{component.description}</p>
                            </TooltipContent>
                          </Tooltip>
                        </div>
                        <div className="text-xs text-muted-foreground/70 mt-0.5 flex items-center gap-1.5">
                          <span>{weight.toFixed(0)}% weight</span>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Info className="w-3.5 h-3.5 text-muted-foreground/80 cursor-help" />
                            </TooltipTrigger>
                            <TooltipContent side="top" className="max-w-xs">
                              <p>How much this model contributes to the final risk score.</p>
                            </TooltipContent>
                          </Tooltip>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-xs font-mono font-bold text-foreground">{Math.round(scoreBar)}</p>
                        <div className="text-xs text-muted-foreground/70 flex items-center justify-end gap-1.5">
                          <span>score</span>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Info className="w-3.5 h-3.5 text-muted-foreground/80 cursor-help" />
                            </TooltipTrigger>
                            <TooltipContent side="top" className="max-w-xs">
                              <p>Current strength of this signal, normalized from 0 to 100.</p>
                            </TooltipContent>
                          </Tooltip>
                        </div>
                      </div>
                    </div>

                    {/* Mini bar chart */}
                    <div className="w-full h-1.5 bg-secondary rounded-full overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all duration-300",
                          scoreBar < 30 ? "bg-status-success" : scoreBar < 60 ? "bg-status-warning" : "bg-status-danger",
                        )}
                        style={{ width: `${scoreBar}%` }}
                      />
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs">
                  <div className="space-y-1">
                    <p className="font-semibold">{component.name}</p>
                    <p className="text-xs">{component.description}</p>
                    <p className="text-xs text-muted-foreground/80 mt-2">
                      {`Current score: ${(scoreBar).toFixed(1)}%`}
                    </p>
                  </div>
                </TooltipContent>
              </Tooltip>
            );
          })}
        </div>

        {/* Verdict Thresholds */}
        <div className="border-t border-secondary/30 pt-3 mt-4">
          <div className="flex items-center gap-1.5 mb-2">
            <p className="text-xs font-semibold text-muted-foreground">Verdict Thresholds</p>
            <Tooltip>
              <TooltipTrigger asChild>
                <Info className="w-3.5 h-3.5 text-muted-foreground/80 cursor-help" />
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                <p>Action policy bands used by the decision engine for allow, rate-limit, drop, and quarantine.</p>
              </TooltipContent>
            </Tooltip>
          </div>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">0 - 30%</span>
              <span className="px-2 py-0.5 rounded bg-status-success/20 text-status-success font-semibold">ALLOW</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">30 - 60%</span>
              <span className="px-2 py-0.5 rounded bg-status-warning/20 text-status-warning font-semibold">RATE LIMIT</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">60 - 85%</span>
              <span className="px-2 py-0.5 rounded bg-status-warning/20 text-status-warning font-semibold">DROP</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">85 - 100%</span>
              <span className="px-2 py-0.5 rounded bg-status-danger/20 text-status-danger font-semibold">QUARANTINE</span>
            </div>
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}

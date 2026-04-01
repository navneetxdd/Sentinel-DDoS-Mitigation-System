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
    info: "Compares per-source PPS and BPS against an EWMA baseline. Fires when traffic deviates beyond 3\u03C3 of the running mean. Always active.",
    weight: 0.12,
    keyField: "volume_weight",
    scoreField: "score_volume",
  },
  {
    name: "Entropy Anomaly",
    info: "Measures Shannon entropy of source/destination ports and payload bytes. Low port entropy (below dynamic threshold) indicates flood traffic using fixed ports. High payload entropy flags randomized attack payloads. Active after 5+ packets per flow.",
    weight: 0.08,
    keyField: "entropy_weight",
    scoreField: "score_entropy",
  },
  {
    name: "Protocol Anomaly",
    info: "Detects SYN floods (SYN ratio > 80%), RST storms, UDP/ICMP volumetric floods, and DNS/NTP amplification based on protocol-specific PPS thresholds. Always active.",
    weight: 0.10,
    keyField: "protocol_weight",
    scoreField: "score_protocol",
  },
  {
    name: "Behavioral Anomaly",
    info: "Identifies port scanning (100+ unique destination ports), excessive concurrent flows per source (500+), LAND attacks (src=dst), slowloris patterns (low PPS but many TCP flows), and flood tools (very low inter-arrival times). Always active.",
    weight: 0.08,
    keyField: "behavioral_weight",
    scoreField: "score_behavioral",
  },
  {
    name: "ML Model",
    info: "Random Forest classifier (compiled to C via m2cgen) trained on 20 engineered features. Outputs attack probability passed through a sigmoid sharpening curve. Only activates when the baseline heuristic threat score exceeds 15%, gating false positives during benign traffic.",
    weight: 0.15,
    keyField: "ml_weight",
    scoreField: "score_ml",
  },
  {
    name: "Layer 7 Asymmetry",
    info: "Detects application-layer abuse: HTTP GET floods (high request count with small average packet size) and DNS query floods. Scores request-response size imbalance characteristic of amplification. Always active when HTTP/DNS traffic is present.",
    weight: 0.07,
    keyField: "l7_weight",
    scoreField: "score_l7",
  },
  {
    name: "Online Anomaly",
    info: "Streaming multivariate anomaly detector using a 6-dimensional EWMA model over global traffic features (PPS, BPS, SYN ratio, RST ratio, unique ports, flow count). Requires 64 observations to warm up, then scores deviations beyond 3.5\u03C3. Only learns from traffic with threat score below 0.35 to avoid poisoning.",
    weight: 0.05,
    keyField: "anomaly_weight",
    scoreField: "score_anomaly",
  },
  {
    name: "Chi-Square Concentration",
    info: "Chi-square goodness-of-fit test comparing this source\u2019s PPS against the global average. High statistic means one IP dominates traffic \u2014 the signature of a single-source volumetric DDoS. Requires 8 classification samples to warm up.",
    weight: 0.05,
    keyField: "chi_square_weight",
    scoreField: "score_chi_square",
  },
  {
    name: "Fan-in Distribution",
    info: "Counts unique source IPs targeting each destination using a probabilistic sketch. High fan-in (many sources \u2192 one target) with elevated traffic is the defining signature of a distributed DDoS. Saturates at the configured threshold (default 16 unique sources). Always active.",
    weight: 0.20,
    keyField: "fanin_weight",
    scoreField: "score_fanin",
  },
  {
    name: "Signature Match",
    info: "Pattern-matches known reflection/amplification attack signatures (DNS open-resolver responses, NTP monlist, SSDP, Memcached, CHARGEN, CLDAP) by inspecting source port, protocol, and packet size. Provides an additive boost to the threat score. Always active.",
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
                            <TooltipContent side="top" className="max-w-sm text-xs leading-relaxed">
                              <p>{component.info}</p>
                            </TooltipContent>
                          </Tooltip>
                        </div>
                        <div className="text-xs text-muted-foreground/70 mt-0.5">
                          <span>{Math.round(weight * 100)}% weight</span>
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
                <TooltipContent side="top" className="max-w-sm">
                  <div className="space-y-1">
                    <p className="font-semibold">{component.name}</p>
                    <p className="text-xs leading-relaxed">{component.info}</p>
                    <p className="text-xs text-muted-foreground/80 mt-2">
                      {`Current score: ${(scoreBar).toFixed(1)}% · Weight: ${Math.round(weight * 100)}%`}
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
              <span className="text-muted-foreground">0 - 15%</span>
              <span className="px-2 py-0.5 rounded bg-status-success/20 text-status-success font-semibold">ALLOW</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">15 - 45%</span>
              <span className="px-2 py-0.5 rounded bg-status-warning/20 text-status-warning font-semibold">RATE LIMIT</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">45 - 75%</span>
              <span className="px-2 py-0.5 rounded bg-status-warning/20 text-status-warning font-semibold">DROP</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">75 - 100%</span>
              <span className="px-2 py-0.5 rounded bg-status-danger/20 text-status-danger font-semibold">QUARANTINE</span>
            </div>
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}

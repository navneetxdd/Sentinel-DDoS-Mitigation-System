import { useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, Bot, ShieldCheck } from "lucide-react";
import { ThreatTelemetry, analyzeThreat } from "@/services/geminiService";

interface AIAnalystWidgetProps {
  telemetry: ThreatTelemetry;
}

const ANALYSIS_INTERVAL_MS = 20000;

export const AIAnalystWidget = ({ telemetry }: AIAnalystWidgetProps) => {
  const [analysis, setAnalysis] = useState<string>("Waiting for telemetry...");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const telemetryRef = useRef<ThreatTelemetry>(telemetry);
  const inFlightRef = useRef(false);

  useEffect(() => {
    telemetryRef.current = telemetry;
  }, [telemetry]);

  useEffect(() => {
    let isMounted = true;

    const runAnalysis = async () => {
      if (inFlightRef.current) {
        return;
      }

      inFlightRef.current = true;
      if (isMounted) {
        setIsAnalyzing(true);
      }

      try {
        const result = await analyzeThreat(telemetryRef.current);
        if (isMounted) {
          setAnalysis(result);
        }
      } finally {
        inFlightRef.current = false;
        if (isMounted) {
          setIsAnalyzing(false);
        }
      }
    };

    void runAnalysis();
    const intervalId = setInterval(() => {
      void runAnalysis();
    }, ANALYSIS_INTERVAL_MS);

    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [analysis]);

  return (
    <div className="cyber-card glow-border p-6 rounded-xl flex flex-col h-[300px]">
      <div className="flex items-center gap-3 mb-4 pb-2 border-b border-white/5">
        <div className={`p-2 rounded-lg ${telemetry.threatScore > 0.5 ? "bg-cyber-red/20 text-cyber-red animate-pulse" : "bg-primary/20 text-primary"}`}>
          <Bot className="w-5 h-5" />
        </div>
        <div>
          <h3 className="font-semibold text-lg tracking-wide">Gemini XAI Analyst</h3>
          <p className="text-xs text-muted-foreground flex items-center gap-1">
            <Activity className="w-3 h-3" /> Continuous Monitoring Active
          </p>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto pr-2 space-y-4 font-mono text-sm leading-relaxed"
      >
        <div className={`relative p-4 rounded-lg bg-black/40 border-l-2 ${telemetry.threatScore > 0.5 ? "border-cyber-red" : "border-cyber-green"}`}>
          {isAnalyzing && (
            <div className="flex items-center gap-2 mb-2 text-cyber-blue animate-pulse">
              <span className="w-2 h-2 rounded-full bg-cyber-blue"></span>
              <span className="w-2 h-2 rounded-full bg-cyber-blue animation-delay-200"></span>
              <span className="w-2 h-2 rounded-full bg-cyber-blue animation-delay-400"></span>
            </div>
          )}

          <p className="whitespace-pre-wrap text-muted-foreground break-words">{analysis}</p>

          {!isAnalyzing && telemetry.threatScore <= 0.5 && (
            <div className="mt-4 flex items-center gap-2 text-cyber-green/70">
              <ShieldCheck className="w-4 h-4" />
              <span>Baseline normal. Risk Score: {(telemetry.threatScore * 100).toFixed(1)}%</span>
            </div>
          )}

          {!isAnalyzing && telemetry.threatScore > 0.5 && (
            <div className="mt-4 flex items-center gap-2 text-cyber-red/70">
              <AlertTriangle className="w-4 h-4" />
              <span>Threat active. Risk Score: {(telemetry.threatScore * 100).toFixed(1)}%</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

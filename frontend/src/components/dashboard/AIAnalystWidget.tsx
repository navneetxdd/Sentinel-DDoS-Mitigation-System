import { useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, Bot, ShieldCheck } from "lucide-react";
import { ThreatTelemetry, analyzeThreat } from "@/services/geminiService";
import { cn } from "@/lib/utils";

interface AIAnalystWidgetProps {
  telemetry: ThreatTelemetry;
  className?: string;
}

const ANALYSIS_INTERVAL_MS = 20000;

export const AIAnalystWidget = ({ telemetry, className }: AIAnalystWidgetProps) => {
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
    const abortController = new AbortController();

    const runAnalysis = async () => {
      if (inFlightRef.current) {
        return;
      }

      inFlightRef.current = true;
      if (isMounted) {
        setIsAnalyzing(true);
      }

      try {
        const result = await analyzeThreat(telemetryRef.current, abortController.signal);
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
      abortController.abort();
      clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [analysis]);

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg flex flex-col min-h-[320px] h-full", className)}>
      <div className="flex items-center gap-3 mb-4 pb-3 border-b border-border">
        <div className={`p-2 rounded-md ${telemetry.threatScore > 0.5 ? "bg-status-danger/15 text-status-danger" : "bg-secondary text-foreground"}`}>
          <Bot className="w-5 h-5" />
        </div>
        <div>
          <h3 className="font-semibold tracking-tight">Gemini XAI Analyst</h3>
          <p className="text-xs text-muted-foreground flex items-center gap-1">
            <Activity className="w-3 h-3" /> Continuous Monitoring Active
          </p>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto pr-2 space-y-4 font-mono text-sm leading-relaxed"
      >
        <div className={`relative p-4 rounded-md bg-secondary/40 border-l-2 ${telemetry.threatScore > 0.5 ? "border-status-danger" : "border-status-success"}`}>
          {isAnalyzing && (
            <div className="flex items-center gap-2 mb-2 text-foreground/70 pulse-glow">
              <span className="w-2 h-2 rounded-full bg-foreground/70"></span>
              <span className="w-2 h-2 rounded-full bg-foreground/70"></span>
              <span className="w-2 h-2 rounded-full bg-foreground/70"></span>
            </div>
          )}

          <p className="whitespace-pre-wrap text-muted-foreground break-words">{analysis}</p>

          {!isAnalyzing && telemetry.threatScore <= 0.5 && (
            <div className="mt-4 flex items-center gap-2 text-status-success/80">
              <ShieldCheck className="w-4 h-4" />
              <span>Baseline normal. Risk Score: {(telemetry.threatScore * 100).toFixed(1)}%</span>
            </div>
          )}

          {!isAnalyzing && telemetry.threatScore > 0.5 && (
            <div className="mt-4 flex items-center gap-2 text-status-danger/80">
              <AlertTriangle className="w-4 h-4" />
              <span>Threat active. Risk Score: {(telemetry.threatScore * 100).toFixed(1)}%</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

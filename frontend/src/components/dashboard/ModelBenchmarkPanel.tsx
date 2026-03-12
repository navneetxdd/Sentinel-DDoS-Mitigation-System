import { cn } from "@/lib/utils";
import type { BenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { BarChart3, BrainCircuit, RefreshCw, ShieldCheck } from "lucide-react";

interface ModelBenchmarkPanelProps {
  report: BenchmarkReport | null;
  loading?: boolean;
  error?: string | null;
  onRefetch?: () => void;
  className?: string;
}

const formatPercent = (value: number | null | undefined) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "n/a";
  return `${(value * 100).toFixed(2)}%`;
};

export function ModelBenchmarkPanel({
  report,
  loading = false,
  error = null,
  onRefetch,
  className,
}: ModelBenchmarkPanelProps) {
  return (
    <div className={cn("cyber-card glow-border p-5 rounded-xl", className)}>
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <BarChart3 className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold">Model Benchmark Comparison</h3>
            <p className="text-xs text-muted-foreground">
              Offline held-out and transfer results from the latest training run
            </p>
          </div>
        </div>
        {onRefetch && (
          <button
            type="button"
            onClick={onRefetch}
            disabled={loading}
            className="p-2 rounded-lg hover:bg-secondary/80 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
            title="Refresh benchmark data"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        )}
      </div>

      {loading ? (
        <div className="p-4 rounded-lg bg-secondary/40 border border-border text-sm text-muted-foreground">
          Loading latest benchmark artifact...
        </div>
      ) : error ? (
        <div className="p-4 rounded-lg bg-cyber-red/5 border border-cyber-red/20 text-sm text-muted-foreground">
          Benchmark artifact could not be loaded: {error}
        </div>
      ) : !report || report.models.length === 0 ? (
        <div className="p-4 rounded-lg bg-secondary/40 border border-border text-sm text-muted-foreground">
          No benchmark artifact found yet. Run the trainer to generate `model_benchmark_report.json`.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {report.models.map((model) => {
              const topFeature = model.top_features[0];
              const hasTopFeatures = model.top_features && model.top_features.length > 0;
              const isIsolationForest = model.name === "isolation_forest";
              return (
                <div
                  key={model.name}
                  className={cn(
                    "rounded-xl border p-4 bg-secondary/30",
                    model.exported ? "border-primary/30" : "border-border"
                  )}
                >
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <div className="flex items-center gap-2">
                      <BrainCircuit className={cn("w-4 h-4", model.exported ? "text-primary" : "text-muted-foreground")} />
                      <h4 className="font-semibold text-sm">{model.display_name}</h4>
                    </div>
                    {model.exported && (
                      <div className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                        <ShieldCheck className="w-3 h-3" />
                        Deployed
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <p className="text-xs text-muted-foreground">Test Macro-F1</p>
                      <p className="font-mono font-bold text-cyber-green">
                        {formatPercent(model.test_metrics.macro_f1)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Balanced Acc</p>
                      <p className="font-mono font-bold text-primary">
                        {formatPercent(model.test_metrics.balanced_accuracy)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Worst Family</p>
                      <p className="font-mono font-bold text-cyber-yellow">
                        {formatPercent(model.summary.worst_family_macro_f1)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Transfer Mean</p>
                      <p className="font-mono font-bold text-cyber-purple">
                        {formatPercent(model.summary.mean_transfer_macro_f1)}
                      </p>
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-border text-xs text-muted-foreground">
                    <p>
                      Trainer: <span className="font-mono">{report.trainer_version}</span>
                    </p>
                    {hasTopFeatures && (
                      <p>
                        Top feature: <span className="text-foreground/90">{topFeature?.name ?? "n/a"}</span>
                      </p>
                    )}
                    {isIsolationForest && model.threshold != null && (
                      <p>
                        Anomaly threshold: <span className="text-foreground/90 font-mono">{model.threshold.toFixed(4)}</span>
                      </p>
                    )}
                    {isIsolationForest && !hasTopFeatures && model.threshold == null && (
                      <p>
                        Score mode: <span className="text-foreground/90">anomaly (no feature importances)</span>
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="rounded-lg bg-secondary/30 border border-border px-4 py-3 text-xs text-muted-foreground">
            Runtime model: <span className="font-mono text-foreground/90">{report.runtime_model}</span>
            {" · "}
            Generated: <span className="font-mono text-foreground/90">{new Date(report.generated_at_utc).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

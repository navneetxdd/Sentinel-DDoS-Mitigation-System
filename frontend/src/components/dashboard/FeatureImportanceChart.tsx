import { useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { cn } from "@/lib/utils";
import type { SentinelFeatureImportance, ShapContribution } from "@/hooks/useSentinelWebSocket";
import { Zap } from "lucide-react";

interface FeatureImportanceChartProps {
  className?: string;
  data?: SentinelFeatureImportance | null;
  featureVector?: number[] | null;
  shapContributions?: ShapContribution[] | null;
  shapLoading?: boolean;
  shapError?: string | null;
  onRequestShap?: () => void;
}

interface FeatureChartDatum {
  name: string;
  importance: number;
  color: string;
  rawValue?: number;
}

interface FeatureTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: FeatureChartDatum }>;
}

/* Heuristic weights: backend model weights */
const FEATURE_META: { key: keyof SentinelFeatureImportance; name: string; color: string }[] = [
  { key: "volume_weight", name: "Volume", color: "hsl(0, 72%, 51%)" },
  { key: "entropy_weight", name: "IP Entropy", color: "hsl(25, 95%, 53%)" },
  { key: "protocol_weight", name: "Protocol Ratio", color: "hsl(45, 93%, 58%)" },
  { key: "behavioral_weight", name: "Behavioral", color: "hsl(160, 84%, 45%)" },
  { key: "ml_weight", name: "ML Score", color: "hsl(190, 100%, 50%)" },
  { key: "l7_weight", name: "Layer 7", color: "hsl(270, 76%, 60%)" },
  { key: "anomaly_weight", name: "Anomaly", color: "hsl(220, 70%, 60%)" },
  { key: "chi_square_weight", name: "Chi-Square", color: "hsl(340, 82%, 58%)" },
  { key: "fanin_weight", name: "Fan-In", color: "hsl(120, 70%, 42%)" },
  { key: "signature_weight", name: "Signatures", color: "hsl(280, 85%, 55%)" },
];

const SHAP_COLORS = [
  "hsl(0, 72%, 51%)",
  "hsl(25, 95%, 53%)",
  "hsl(45, 93%, 58%)",
  "hsl(80, 84%, 45%)",
  "hsl(120, 84%, 45%)",
  "hsl(160, 84%, 45%)",
  "hsl(190, 100%, 50%)",
  "hsl(220, 70%, 60%)",
  "hsl(250, 76%, 60%)",
  "hsl(280, 76%, 60%)",
];

export function FeatureImportanceChart({
  className,
  data,
  featureVector,
  shapContributions,
  shapLoading,
  shapError,
  onRequestShap,
}: FeatureImportanceChartProps) {
  const [showShap, setShowShap] = useState(false);

  const hasShap = shapContributions && shapContributions.length > 0;
  const canRequestShap = featureVector && featureVector.length >= 20 && onRequestShap;

  const heuristicFeatures = data
    ? FEATURE_META.map((f) => ({
        name: f.name,
        importance: Number(data[f.key]) || 0,
        color: f.color,
      })).sort((a, b) => b.importance - a.importance)
    : [];

  const shapFeatures =
    shapContributions && shapContributions.length > 0
      ? shapContributions
          .map((c, i) => ({
            name: c.name.replace(/_/g, " "),
            importance: Math.abs(c.value),
            rawValue: c.value,
            color: SHAP_COLORS[i % SHAP_COLORS.length],
          }))
          .sort((a, b) => b.importance - a.importance)
      : [];

  const features: FeatureChartDatum[] = showShap && hasShap ? shapFeatures : heuristicFeatures;
  const CustomTooltip = ({ active, payload }: FeatureTooltipProps) => {
    if (active && payload && payload.length) {
      const p = payload[0].payload;
      const label = showShap && hasShap ? `Contribution: ${(p.rawValue ?? p.importance).toFixed(4)}` : `Weight: ${(p.importance * 100).toFixed(0)}%`;
      return (
        <div className="chart-tooltip">
          <p className="font-medium mb-1">{p.name}</p>
          <p className="font-mono text-foreground">{label}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h3 className="font-semibold">
            {showShap && hasShap ? "SHAP Contributions (Per-Feature)" : "Signal Weights (Heuristic Stack)"}
          </h3>
          <p className="text-xs text-muted-foreground">
            {showShap && hasShap
              ? "Per-attack feature contributions from explain API"
              : "Configured detection weights — not per-attack SHAP values"}
          </p>
        </div>
        {canRequestShap && (
          <div className="flex items-center gap-2">
            {hasShap && (
              <button
                type="button"
                onClick={() => setShowShap((s) => !s)}
                className="text-xs text-foreground hover:underline"
              >
                {showShap ? "Show Heuristic" : "Show SHAP"}
              </button>
            )}
            <button
              type="button"
              onClick={onRequestShap}
              disabled={shapLoading}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors border",
                shapLoading
                  ? "bg-muted text-muted-foreground border-border cursor-not-allowed"
                  : "bg-secondary text-foreground border-border hover:bg-accent"
              )}
            >
              <Zap className="w-3.5 h-3.5" />
              {shapLoading ? "Requesting…" : "Request SHAP"}
            </button>
          </div>
        )}
      </div>

      {shapError && <p className="text-xs text-status-danger mb-2">{shapError}</p>}

      <div className="h-72">
        {features.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={features} layout="vertical">
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
                horizontal={false}
              />
              <XAxis
                type="number"
                domain={showShap && hasShap ? ["auto", "auto"] : [0, 1]}
                tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                axisLine={{ stroke: "hsl(var(--border))" }}
                tickLine={false}
                tickFormatter={(val) =>
                  showShap && hasShap ? val.toFixed(3) : `${(val * 100).toFixed(0)}%`
                }
              />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                axisLine={{ stroke: "hsl(var(--border))" }}
                tickLine={false}
                width={140}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "hsl(var(--muted) / 0.3)" }} />
              <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                {features.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-2">
            <p className="text-muted-foreground text-sm">
              {showShap && !hasShap ? "Click Request SHAP to get per-feature contributions" : "Waiting for feature data…"}
            </p>
            {canRequestShap && !showShap && (
              <p className="text-xs text-muted-foreground">
                Feature vector available. Click Request SHAP for per-attack contributions.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

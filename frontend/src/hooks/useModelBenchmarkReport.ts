import { useCallback, useEffect, useMemo, useState } from "react";

export interface BenchmarkClassMetrics {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface BenchmarkMetrics {
  accuracy: number;
  balanced_accuracy: number;
  attack_precision: number;
  attack_recall: number;
  attack_f1: number;
  macro_precision: number;
  macro_recall: number;
  macro_f1: number;
  weighted_f1: number;
  mcc: number;
  roc_auc: number | null;
  normal: BenchmarkClassMetrics;
  attack: BenchmarkClassMetrics;
  confusion_matrix: number[][];
}

export interface BenchmarkModelSummary {
  worst_family_macro_f1: number;
  mean_family_macro_f1: number;
  mean_transfer_macro_f1: number | null;
}

export interface BenchmarkModelReport {
  name: string;
  display_name: string;
  exported: boolean;
  threshold: number | null;
  params: Record<string, unknown>;
  selection_summary: {
    fit_gap: number;
    worst_family_macro_f1: number;
    mean_family_macro_f1: number;
    aggregate_macro_f1: number;
  };
  fit_metrics: BenchmarkMetrics;
  test_metrics: BenchmarkMetrics;
  family_test_metrics: Record<string, BenchmarkMetrics>;
  transfer_metrics: Record<string, Record<string, BenchmarkMetrics>>;
  top_features: Array<{ name: string; importance: number }>;
  summary: BenchmarkModelSummary;
}

export interface BenchmarkReport {
  trainer_version: string;
  generated_at_utc: string;
  runtime_model: string;
  dataset_family_coverage: Record<string, { rows: number; normal: number; attack: number }>;
  split_plan: Record<string, Record<string, { rows: number; normal: number; attack: number }>>;
  models: BenchmarkModelReport[];
}

interface BenchmarkReportState {
  report: BenchmarkReport | null;
  loading: boolean;
  error: string | null;
  modelsByName: Record<string, BenchmarkModelReport>;
  refetch: () => void;
}

const getReportUrl = () => {
  const base = (import.meta.env.BASE_URL || "/").replace(/\/$/, "") || "";
  return `${base}/model_benchmark_report.json`;
};

export function useModelBenchmarkReport(): BenchmarkReportState {
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(getReportUrl(), { cache: "no-store" });
      if (!response.ok) {
        if (response.status === 404) {
          setReport(null);
          setError(null);
          return;
        }
        throw new Error(`HTTP ${response.status}`);
      }
      
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
         setReport(null);
         setError(null);
         return;
      }

      const payload = (await response.json()) as BenchmarkReport;
      setReport(payload);
      setError(null);
    } catch (err) {
      setReport(null);
      setError(err instanceof Error ? err.message : "Unable to load benchmark report");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const modelsByName = useMemo(() => {
    const pairs = report?.models.map((model) => [model.name, model] as const) ?? [];
    return Object.fromEntries(pairs);
  }, [report]);

  return {
    report,
    loading,
    error,
    modelsByName,
    refetch: load,
  };
}

import { fetchExplainApi } from "@/lib/apiConfig";
import { getGeminiXAISettings } from "@/lib/settingsStorage";

export interface ThreatTelemetry {
  timestamp: string;
  sourceIp: string;
  packetsPerSecond: number;
  bytesPerSecond: number;
  threatScore: number;
  activeFlows: number;
  topProtocol: string;
}

interface AnalyzeResponse {
  analysis?: string;
  error?: string;
  degraded?: boolean;
  source?: string;
  reason?: string;
}

export interface AnalysisResult {
  analysis: string;
  degraded: boolean;
  source: string;
  reason?: string;
}

const ANALYZE_TIMEOUT_MS = 12000;
const RETRY_ENABLED = true;
const RETRY_INITIAL_DELAY_MS = 500;
const RETRY_MAX_DELAY_MS = 3000;
const RETRY_MAX_ATTEMPTS = 3;

/**
 * Exponential backoff calculator for retry logic
 */
const getBackoffDelay = (attemptNumber: number): number => {
  const delay = RETRY_INITIAL_DELAY_MS * Math.pow(2, attemptNumber);
  return Math.min(delay, RETRY_MAX_DELAY_MS);
};

/**
 * Core analysis call with built-in retry and error resilience
 * NEVER fails - returns meaningful fallback on all errors.
 * Pass optional abortSignal (e.g. from component cleanup) to cancel in-flight request.
 */
export const analyzeThreat = async (
  data: ThreatTelemetry,
  abortSignal?: AbortSignal,
): Promise<AnalysisResult> => {
  const buildLocalSummary = (reason: string, source = "frontend_fallback"): AnalysisResult => {
    const riskPct = (data.threatScore * 100).toFixed(1);
    const protocol = data.topProtocol && data.topProtocol !== "Unknown" ? `${data.topProtocol} traffic` : "no stable dominant protocol";

    if (data.packetsPerSecond <= 5 && data.bytesPerSecond <= 1024 && data.threatScore <= 0.1) {
      return {
        analysis:
          `Local telemetry assessment only: current traffic looks low-signal. ${data.activeFlows} concurrent flows are open, ` +
          `but throughput is near zero at ${Math.round(data.packetsPerSecond)} packets/sec and ${Math.round(data.bytesPerSecond)} bytes/sec ` +
          `with a risk score of ${riskPct}%. This looks closer to idle or background connections than an active attack${reason ? ` (${reason})` : ""}.`,
        degraded: source !== "telemetry_baseline",
        source,
        reason,
      };
    }

    if (data.threatScore > 0.5) {
      return {
        analysis:
          `Local telemetry assessment only: Sentinel sees elevated risk from ${data.sourceIp} at about ${Math.round(data.packetsPerSecond)} packets/sec ` +
          `and ${Math.round(data.bytesPerSecond)} bytes/sec with ${protocol}. Risk score is ${riskPct}% across ${data.activeFlows} concurrent flows${reason ? ` (${reason})` : ""}.`,
        degraded: true,
        source,
        reason,
      };
    }

    return {
      analysis:
        `Local telemetry assessment only: traffic from ${data.sourceIp} does not show a confirmed attack pattern. ` +
        `Current load is ${Math.round(data.packetsPerSecond)} packets/sec, ${Math.round(data.bytesPerSecond)} bytes/sec, ` +
        `${data.activeFlows} concurrent flows, and ${riskPct}% risk with ${protocol}. Treat this as observation-level traffic${reason ? ` (${reason})` : ""}.`,
      degraded: source !== "telemetry_baseline",
      source,
      reason,
    };
  };

  const defaultFallback = buildLocalSummary("frontend fallback");

  // Attempt analysis call with retry logic
  let lastError: unknown = null;
  for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), ANALYZE_TIMEOUT_MS);
      if (abortSignal?.aborted) {
        clearTimeout(timeoutId);
        return defaultFallback;
      }
      if (abortSignal) {
        abortSignal.addEventListener("abort", () => {
          clearTimeout(timeoutId);
          controller.abort();
        });
      }

      try {
        const { geminiApiKey } = getGeminiXAISettings();
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (geminiApiKey.trim()) {
          // Key is sent only to local Explain API for server-side proxying.
          headers["X-Gemini-Api-Key"] = geminiApiKey.trim();
        }

        const res = await fetchExplainApi("/analyze", {
          method: "POST",
          headers,
          body: JSON.stringify(data),
          signal: controller.signal,
        });

        let json: AnalyzeResponse = {};
        try {
          json = (await res.json()) as AnalyzeResponse;
        } catch {
          json = {};
        }

        // Backend returned successful response
        if (res.ok && json.analysis?.trim()) {
          return {
            analysis: json.analysis.trim(),
            degraded: Boolean(json.degraded),
            source: json.source || "gemini",
            reason: json.reason,
          };
        }

        // Backend returned structured error (API key missing, etc)
        if (res.ok && json.error) {
          // Don't retry on structured backend errors
          console.warn("[Gemini XAI] Backend error:", json.error);
          return buildLocalSummary(json.error);
        }

        // HTTP error responses - retry if eligible
        if (!res.ok) {
          lastError = new Error(`HTTP ${res.status}: ${json.error || "Analysis request failed"}`);
          if (attempt < RETRY_MAX_ATTEMPTS - 1 && RETRY_ENABLED) {
            const delay = getBackoffDelay(attempt);
            await new Promise((r) => setTimeout(r, delay));
            continue;
          }
          return defaultFallback;
        }

        // Unexpected response shape
        lastError = new Error("Analysis returned empty response");
        return defaultFallback;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      lastError = error;

      // Don't retry timeout on final attempt
      if (error instanceof DOMException && error.name === "AbortError") {
        if (attempt < RETRY_MAX_ATTEMPTS - 1 && RETRY_ENABLED) {
          const delay = getBackoffDelay(attempt);
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        console.warn("[Gemini XAI] Request timed out (after retries)");
        return buildLocalSummary("request timed out");
      }

      // Network errors: retry eligible attempts
      if (attempt < RETRY_MAX_ATTEMPTS - 1 && RETRY_ENABLED) {
        const delay = getBackoffDelay(attempt);
        console.debug(`[Gemini XAI] Retry ${attempt + 1}/${RETRY_MAX_ATTEMPTS} after ${delay}ms`, error);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      console.error("[Gemini XAI] Analysis unavailable after retries:", error);
      return buildLocalSummary("analysis unavailable after retries");
    }
  }

  // All retries exhausted
  console.error("[Gemini XAI] Failed after all retry attempts:", lastError);
  return buildLocalSummary("all retry attempts failed");
};


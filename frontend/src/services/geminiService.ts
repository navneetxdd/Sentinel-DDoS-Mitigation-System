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
): Promise<string> => {
  const isThreat = data.threatScore > 0.5;

  // Default fallback for analysis unavailability (graceful degradation)
  const defaultFallback = isThreat
    ? `Sentinel detected anomalous behavior from ${data.sourceIp}: ${Math.round(data.packetsPerSecond)} pps of ${data.topProtocol} traffic. Threat score: ${(data.threatScore * 100).toFixed(1)}%. Live rule enforcement active.`
    : `Baseline normal. Risk Score: ${(data.threatScore * 100).toFixed(1)}%. No threats detected. ${data.activeFlows} concurrent flows monitored.`;

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
          return json.analysis.trim();
        }

        // Backend returned structured error (API key missing, etc)
        if (res.ok && json.error) {
          // Don't retry on structured backend errors
          console.warn("[Gemini XAI] Backend error:", json.error);
          return `Analysis service notes: ${json.error}. Falling back to statistical assessment.`;
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
        return defaultFallback;
      }

      // Network errors: retry eligible attempts
      if (attempt < RETRY_MAX_ATTEMPTS - 1 && RETRY_ENABLED) {
        const delay = getBackoffDelay(attempt);
        console.debug(`[Gemini XAI] Retry ${attempt + 1}/${RETRY_MAX_ATTEMPTS} after ${delay}ms`, error);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      console.error("[Gemini XAI] Analysis unavailable after retries:", error);
      return defaultFallback;
    }
  }

  // All retries exhausted
  console.error("[Gemini XAI] Failed after all retry attempts:", lastError);
  return defaultFallback;
};


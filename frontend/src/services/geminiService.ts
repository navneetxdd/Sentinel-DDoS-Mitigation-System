import { EXPLAIN_API_URL, isExplainApiConfigured } from "@/lib/apiConfig";

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

export const analyzeThreat = async (data: ThreatTelemetry): Promise<string> => {
  if (!isExplainApiConfigured) {
    return "Explain API is not configured. Set VITE_EXPLAIN_API_URL to enable Gemini XAI insights.";
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), ANALYZE_TIMEOUT_MS);

  try {
    const res = await fetch(`${EXPLAIN_API_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      signal: controller.signal,
    });

    let json: AnalyzeResponse = {};
    try {
      json = (await res.json()) as AnalyzeResponse;
    } catch {
      json = {};
    }

    if (!res.ok) {
      return json.error || `AI analysis request failed (HTTP ${res.status}).`;
    }

    return json.analysis?.trim() || "AI analysis returned an empty response.";
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      return "AI analysis timed out. Retrying on next cycle.";
    }
    return "AI analysis is temporarily unavailable.";
  } finally {
    clearTimeout(timeoutId);
  }
};


const EXPLAIN_API_URL = import.meta.env.VITE_EXPLAIN_API_URL || "http://localhost:5001";

// Cooldown mechanism
let lastAnalysisTime = 0;
const COOLDOWN_MS = 15000; // Only analyze every 15 seconds max

export interface ThreatTelemetry {
  timestamp: string;
  sourceIp: string;
  packetsPerSecond: number;
  bytesPerSecond: number;
  threatScore: number;
  activeFlows: number;
  topProtocol: string;
}

export const analyzeThreat = async (data: ThreatTelemetry): Promise<string> => {
  const now = Date.now();
  if (now - lastAnalysisTime < COOLDOWN_MS) {
    return "Analysis skipped (cooldown active).";
  }

  lastAnalysisTime = now;

  try {
    const res = await fetch(`${EXPLAIN_API_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    const json = await res.json();
    return json.analysis || "AI Analysis returned an empty response.";
  } catch (error) {
    console.error("Gemini AI Analysis failed:", error);
    return "AI Analysis temporarily unavailable due to an API error.";
  }
};


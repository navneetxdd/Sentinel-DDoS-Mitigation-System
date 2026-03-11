import { GoogleGenerativeAI } from "@google/generative-ai";

// Ensure that environment variables exist in frontend/.env
const API_KEY = import.meta.env.VITE_GEMINI_API_KEY;

let genAI: GoogleGenerativeAI | null = null;
if (API_KEY) {
  genAI = new GoogleGenerativeAI(API_KEY);
}

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
  if (!genAI) {
    return "Gemini API key not configured. Please add VITE_GEMINI_API_KEY to your .env file.";
  }

  const now = Date.now();
  if (now - lastAnalysisTime < COOLDOWN_MS) {
    return "Analysis skipped (cooldown active).";
  }

  lastAnalysisTime = now;

  const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

  const prompt = `
You are an expert Security Operations Center (SOC) AI Analyst. 
A DDoS mitigation system (Sentinel) has just detected an anomaly.
Review the following real-time telemetry and write a concise, 2-3 sentence explanation 
of what is likely happening and why the system flagged it. Be direct and analytical.

Telemetry Data:
- Timestamp: ${data.timestamp}
- Attacker IP: ${data.sourceIp}
- Peak Packets/Sec: ${data.packetsPerSecond.toFixed(1)}
- Peak Bytes/Sec: ${data.bytesPerSecond.toFixed(1)}
- Threat Score: ${(data.threatScore * 100).toFixed(1)}%
- Active Concurrent Flows: ${data.activeFlows}
- Dominant Protocol: ${data.topProtocol}

Provide only the analysis and conclusion without extra pleasantries.
`;

  try {
    const result = await model.generateContent(prompt);
    const response = await result.response;
    return response.text();
  } catch (error) {
    console.error("Gemini AI Analysis failed:", error);
    return "AI Analysis temporarily unavailable due to an API error.";
  }
};

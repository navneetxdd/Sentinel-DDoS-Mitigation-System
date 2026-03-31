import type { SentinelActivity, SentinelTopSource } from "@/hooks/useSentinelWebSocket";

/**
 * Choose the best "primary" IPv4 source for analyst widgets: actual packet sources from the pipeline,
 * preferring recent high-threat activity over raw volume (top talker != always attacker).
 */
export function selectPrimaryAttackerSourceIp(
  topSources: SentinelTopSource[] | undefined,
  activityLog: SentinelActivity[] | undefined,
  options?: { recentWindowSec?: number },
): string {
  const window = options?.recentWindowSec ?? 120;
  const now = Math.floor(Date.now() / 1000);

  const activities = activityLog ?? [];
  const isSimulated = (a: SentinelActivity) =>
    typeof a.reason === "string" && a.reason.includes("[SIMULATED]");
  const nonSim = activities.filter((a) => !isSimulated(a));
  const pool = nonSim.length > 0 ? nonSim : activities;

  let bestFromActivity: { ip: string; threat: number; ts: number } | null = null;
  for (const a of pool) {
    const ip = typeof a.src_ip === "string" ? a.src_ip.trim() : "";
    if (!ip || ip === "Unknown" || ip === "0.0.0.0") continue;
    if (typeof a.timestamp !== "number" || typeof a.threat_score !== "number") continue;
    if (now - a.timestamp > window) continue;
    if (!bestFromActivity || a.threat_score > bestFromActivity.threat) {
      bestFromActivity = { ip, threat: a.threat_score, ts: a.timestamp };
    } else if (
      bestFromActivity &&
      a.threat_score === bestFromActivity.threat &&
      a.timestamp > bestFromActivity.ts
    ) {
      bestFromActivity = { ip, threat: a.threat_score, ts: a.timestamp };
    }
  }
  if (bestFromActivity) return bestFromActivity.ip;

  const sources = topSources ?? [];
  if (sources.length === 0) return "Unknown";

  const ranked = [...sources].sort((a, b) => {
    const ts = b.threat_score - a.threat_score;
    if (ts !== 0) return ts;
    return b.packets - a.packets;
  });
  const top = ranked[0];
  return top?.ip && top.ip.trim() ? top.ip.trim() : "Unknown";
}

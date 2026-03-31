import { describe, expect, it } from "vitest";
import { selectPrimaryAttackerSourceIp } from "./primarySourceIp";
import type { SentinelActivity, SentinelTopSource } from "@/hooks/useSentinelWebSocket";

describe("selectPrimaryAttackerSourceIp", () => {
  it("prefers recent high-threat activity over high-volume top source", () => {
    const now = Math.floor(Date.now() / 1000);
    const top: SentinelTopSource[] = [
      { ip: "10.0.0.1", packets: 1e9, bytes: 1, flows: 1, suspicious: 0, threat_score: 0.1 },
      { ip: "192.0.2.50", packets: 100, bytes: 1, flows: 1, suspicious: 1, threat_score: 0.2 },
    ];
    const activity: SentinelActivity[] = [
      {
        timestamp: now - 5,
        src_ip: "198.51.100.7",
        action: "DETECTED",
        attack_type: "SYN_FLOOD",
        threat_score: 0.92,
        reason: "test",
        enforced: false,
      },
    ];
    expect(selectPrimaryAttackerSourceIp(top, activity)).toBe("198.51.100.7");
  });

  it("falls back to highest threat_score in top sources when no recent activity", () => {
    const top: SentinelTopSource[] = [
      { ip: "10.0.0.1", packets: 1e6, bytes: 1, flows: 1, suspicious: 0, threat_score: 0.2 },
      { ip: "203.0.113.2", packets: 100, bytes: 1, flows: 1, suspicious: 1, threat_score: 0.88 },
    ];
    expect(selectPrimaryAttackerSourceIp(top, [])).toBe("203.0.113.2");
  });

  it("returns Unknown when empty", () => {
    expect(selectPrimaryAttackerSourceIp([], [])).toBe("Unknown");
  });

  it("prefers non-simulated activity over simulated when both exist", () => {
    const now = Math.floor(Date.now() / 1000);
    const activity: SentinelActivity[] = [
      {
        timestamp: now - 2,
        src_ip: "192.168.1.50",
        action: "DETECTED",
        attack_type: "X",
        threat_score: 0.99,
        reason: "[SIMULATED] test",
        enforced: false,
      },
      {
        timestamp: now - 10,
        src_ip: "198.51.100.9",
        action: "DETECTED",
        attack_type: "SYN_FLOOD",
        threat_score: 0.75,
        reason: "score=0.75",
        enforced: true,
      },
    ];
    expect(selectPrimaryAttackerSourceIp([], activity)).toBe("198.51.100.9");
  });
});

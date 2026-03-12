import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { DecisionPanel } from "@/components/dashboard/DecisionPanel";
import { FeatureImportanceChart } from "@/components/dashboard/FeatureImportanceChart";
import { ExplanationBox } from "@/components/dashboard/ExplanationBox";
import { ModelBenchmarkPanel } from "@/components/dashboard/ModelBenchmarkPanel";
import { SimulationToggle } from "@/components/dashboard/SimulationToggle";
import { AIAnalystWidget } from "@/components/dashboard/AIAnalystWidget";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { useState } from "react";
import { Brain, Cpu, Database, Network } from "lucide-react";

const DecisionEngine = () => {
  const ws = useSentinelWebSocket();
  const benchmarks = useModelBenchmarkReport();
  const [simulatingFlashCrowd, setSimulatingFlashCrowd] = useState(false);
  const [simulatingDDoS, setSimulatingDDoS] = useState(false);

  /* Derive classification from real feature_importance stream */
  const fi = ws.featureImportance;
  const threatScore = fi?.avg_threat_score ?? 0;
  const attackProbability = Math.min(100, Math.round(threatScore * 100));
  const isDDoS = attackProbability >= 70 || simulatingDDoS;
  const isFlashCrowd = (attackProbability >= 30 && attackProbability < 70) || simulatingFlashCrowd;

  const getClassification = () => {
    if (isDDoS) return "ddos" as const;
    if (isFlashCrowd) return "flash_crowd" as const;
    return "benign" as const;
  };

  /* Real stats from backend */
  const mlOps = ws.metrics?.ml_classifications_per_sec ?? 0;
  const detectionsLast10s = fi?.detections_last_10s ?? 0;
  const policyArm = fi?.policy_arm ?? 0;
  const policyUpdates = fi?.policy_updates ?? 0;
  const policyReward = fi?.policy_last_reward ?? 0;

  /* Derive telemetry for AI Analyst */
  const pps = ws.metrics?.packets_per_sec ?? 0;
  const currentProtocols = ws.metrics?.protocol_distribution || {};
  let topProtocol = "Unknown";
  let maxProtoRate = -1;
  for (const [proto, count] of Object.entries(currentProtocols)) {
    const c = count as number;
    if (c > maxProtoRate) {
      maxProtoRate = c;
      topProtocol = proto;
    }
  }

  const aiTelemetry = {
    timestamp: new Date().toISOString(),
    sourceIp: ws.metrics?.top_sources?.[0] || 'Unknown',
    packetsPerSecond: pps,
    bytesPerSecond: ws.metrics?.bytes_per_sec || 0,
    threatScore: threatScore,
    activeFlows: ws.metrics?.active_flows ?? 0,
    topProtocol: topProtocol
  };

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-6 animate-fade-in">
        {/* Header — same as original */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Brain className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Decision Engine</h1>
              <p className="text-sm text-muted-foreground">
                ML-powered threat classification and explainability
              </p>
            </div>
          </div>
          <SimulationToggle
            isFlashCrowd={simulatingFlashCrowd}
            isDDoS={simulatingDDoS}
            onFlashCrowdToggle={() => {
              setSimulatingFlashCrowd((prev) => !prev);
              ws.sendCommand(simulatingFlashCrowd ? "stop_simulation" : "simulate_flash_crowd");
            }}
            onDDoSToggle={() => {
              setSimulatingDDoS((prev) => !prev);
              ws.sendCommand(simulatingDDoS ? "stop_simulation" : "simulate_ddos");
            }}
          />
        </div>

        {/* Main Content Grid — same layout as original */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <DecisionPanel
            attackProbability={attackProbability}
            classification={getClassification()}
          />
          <FeatureImportanceChart
            data={fi}
            featureVector={ws.featureVector}
            shapContributions={ws.shapContributions}
            shapLoading={ws.shapLoading}
            shapError={ws.shapError}
            onRequestShap={ws.requestShapContributions}
          />
        </div>

        {/* Explanation — same component as original */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <ExplanationBox isAttack={isDDoS} isFlashCrowd={isFlashCrowd} featureImportance={fi} />
          </div>
          <div className="lg:col-span-1">
            <AIAnalystWidget telemetry={aiTelemetry} />
          </div>
        </div>

        {/* Model Stats — same 3-card layout as original, with real data where available */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Cpu className="w-4 h-4 text-primary" />
              </div>
              <h3 className="font-semibold text-sm">Model Performance</h3>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-xs text-muted-foreground">Threat Score</p>
                <p className="font-mono font-bold text-cyber-green">{threatScore.toFixed(3)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Detections (10s)</p>
                <p className="font-mono font-bold text-cyber-green">{detectionsLast10s}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Policy Arm</p>
                <p className="font-mono font-bold text-primary">{policyArm}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Last Reward</p>
                <p className="font-mono font-bold text-primary">{policyReward.toFixed(4)}</p>
              </div>
            </div>
          </div>

          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 rounded-lg bg-cyber-green/10">
                <Database className="w-4 h-4 text-cyber-green" />
              </div>
              <h3 className="font-semibold text-sm">Pipeline Stats</h3>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-xs text-muted-foreground">Active Flows</p>
                <p className="font-mono font-bold">{(ws.metrics?.active_flows ?? 0).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Active Sources</p>
                <p className="font-mono font-bold">{(ws.metrics?.active_sources ?? 0).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Kernel Drops</p>
                <p className="font-mono font-bold text-muted-foreground text-xs">{(ws.metrics?.kernel_drops ?? 0).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Policy Updates</p>
                <p className="font-mono font-bold">{policyUpdates.toLocaleString()}</p>
              </div>
            </div>
          </div>

          <div className="cyber-card glow-border p-4 rounded-xl">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 rounded-lg bg-cyber-yellow/10">
                <Network className="w-4 h-4 text-cyber-yellow" />
              </div>
              <h3 className="font-semibold text-sm">Inference Stats</h3>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-xs text-muted-foreground">Throughput</p>
                <p className="font-mono font-bold text-cyber-green">{mlOps > 0 ? `${mlOps.toLocaleString()}/s` : "Idle"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Probability</p>
                <p className="font-mono font-bold text-cyber-yellow">{attackProbability}%</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">CPU</p>
                <p className="font-mono font-bold">{(ws.metrics?.cpu_usage_percent ?? 0).toFixed(1)}%</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Memory</p>
                <p className="font-mono font-bold text-primary">{(ws.metrics?.memory_usage_mb ?? 0).toFixed(0)}MB</p>
              </div>
            </div>
          </div>
        </div>

        <ModelBenchmarkPanel
          report={benchmarks.report}
          loading={benchmarks.loading}
          error={benchmarks.error}
          onRefetch={benchmarks.refetch}
        />
      </div>
    </DashboardLayout>
  );
};

export default DecisionEngine;

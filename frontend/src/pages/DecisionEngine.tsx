import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { GridLayout, Panel, StatCard } from "@/components/layout/GridPanel";
import { DecisionPanel } from "@/components/dashboard/DecisionPanel";
import { FeatureImportanceChart } from "@/components/dashboard/FeatureImportanceChart";
import { ExplanationBox } from "@/components/dashboard/ExplanationBox";
import { ModelBenchmarkPanel } from "@/components/dashboard/ModelBenchmarkPanel";
import { SimulationToggle } from "@/components/dashboard/SimulationToggle";
import { AIAnalystWidget } from "@/components/dashboard/AIAnalystWidget";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { useState } from "react";
import { Brain, Cpu, Database, Network, Layers, Shield, Zap, Gauge } from "lucide-react";

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
  const faninScore = fi?.avg_fanin_score ?? 0;
  const faninWeight = fi?.fanin_weight ?? 0;
  const policyArm = fi?.policy_arm ?? 0;
  const policyUpdates = fi?.policy_updates ?? 0;
  const policyReward = fi?.policy_last_reward ?? 0;
  const activeFlows = ws.metrics?.active_flows ?? 0;
  const activeSources = ws.metrics?.active_sources ?? 0;
  const cpu = ws.metrics?.cpu_usage_percent ?? 0;
  const memory = ws.metrics?.memory_usage_mb ?? 0;

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
    sourceIp: ws.topSources?.[0]?.ip ?? "Unknown",
    packetsPerSecond: pps,
    bytesPerSecond: ws.metrics?.bytes_per_sec ?? 0,
    threatScore: threatScore,
    activeFlows: ws.metrics?.active_flows ?? 0,
    topProtocol,
  };

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-6 animate-fade-in">
        <PageHeader
          title="Decision Engine"
          description="ML-powered threat classification and explainability"
          icon={<Brain className="w-6 h-6 text-foreground" />}
          action={
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
          }
        />

        <Panel
          title="Classification And Explainability"
          description="Decision output, model weights, and SHAP-backed attribution"
          variant="default"
        >
          <GridLayout cols={2} gap="lg">
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
          </GridLayout>
        </Panel>

        <Panel
          title="Operational Context"
          description="Model rationale paired with live analyst interpretation"
          variant="default"
        >
          <GridLayout cols={3} gap="lg">
            <div className="md:col-span-2 lg:col-span-2">
              <ExplanationBox isAttack={isDDoS} isFlashCrowd={isFlashCrowd} featureImportance={fi} />
            </div>
            <div>
              <AIAnalystWidget telemetry={aiTelemetry} />
            </div>
          </GridLayout>
        </Panel>

        <div>
          <h2 className="text-lg font-semibold mb-4">Engine Health</h2>
          <GridLayout cols={4} gap="md">
            <StatCard
              label="Threat Score"
              value={threatScore.toFixed(3)}
              unit="0-1"
              icon={<Shield className="w-5 h-5" />}
              variant={threatScore >= 0.7 ? "danger" : threatScore >= 0.3 ? "warning" : "success"}
            />
            <StatCard
              label="Distributed Evidence"
              value={`${Math.round(faninScore * 100)}%`}
              unit={`weight ${(faninWeight * 100).toFixed(0)}%`}
              icon={<Layers className="w-5 h-5" />}
              variant={faninScore >= 0.7 ? "danger" : faninScore >= 0.3 ? "warning" : "success"}
            />
            <StatCard
              label="ML Throughput"
              value={mlOps > 0 ? mlOps.toLocaleString() : "0"}
              unit="ops/s"
              icon={<Cpu className="w-5 h-5" />}
              variant={mlOps > 0 ? "success" : "default"}
            />
            <StatCard
              label="Detections"
              value={detectionsLast10s}
              unit="last 10s"
              icon={<Zap className="w-5 h-5" />}
              variant={detectionsLast10s > 0 ? "warning" : "default"}
            />
            <StatCard
              label="Active Flows"
              value={activeFlows.toLocaleString()}
              unit="sessions"
              icon={<Network className="w-5 h-5" />}
              variant="default"
            />
            <StatCard
              label="Active Sources"
              value={activeSources.toLocaleString()}
              unit="IPs"
              icon={<Database className="w-5 h-5" />}
              variant="default"
            />
            <StatCard
              label="Policy State"
              value={`Arm ${policyArm}`}
              unit={`${policyUpdates.toLocaleString()} updates`}
              icon={<Gauge className="w-5 h-5" />}
              variant="default"
            />
            <StatCard
              label="Resource Use"
              value={`${cpu.toFixed(1)}%`}
              unit={`${memory.toFixed(0)} MB`}
              icon={<Cpu className="w-5 h-5" />}
              variant={cpu > 80 ? "danger" : cpu > 55 ? "warning" : "success"}
            />
          </GridLayout>
          <p className="text-xs text-muted-foreground mt-3">Latest policy reward: {policyReward.toFixed(4)}</p>
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

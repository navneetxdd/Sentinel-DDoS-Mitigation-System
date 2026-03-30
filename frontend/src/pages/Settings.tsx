import { useState, useMemo } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { SettingsCard } from "@/components/settings/SettingsCard";
import { SliderSetting } from "@/components/settings/SliderSetting";
import { ToggleSetting } from "@/components/settings/ToggleSetting";
import { SelectSetting } from "@/components/settings/SelectSetting";
import { IPListManager } from "@/components/settings/IPListManager";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import { clearVolatileSecretSettings, setVolatileSecretSettings } from "@/lib/settingsStorage";
import {
  Settings as SettingsIcon,
  Gauge,
  Shield,
  Database,
  Save,
  RotateCcw,
  AlertTriangle,
} from "lucide-react";
import { toast } from "@/hooks/use-toast";

type SettingsState = {
  synRateThreshold: number;
  connectionThreshold: number;
  packetRateThreshold: number;
  entropyThreshold: number;
  contributorThreshold: number;
  riskScoreThreshold: number;
  autoBlock: boolean;
  autoRateLimit: boolean;
  whitelist: string[];
  blacklist: string[];
  alertWebhookUrl: string;
  alertWebhookSecret: string;
  geminiApiKey: string;
  logRetention: string;
  analysisInterval: string;
  modelFocus: string;
};

const SETTINGS_STORAGE_KEY = "sentinel-ui-settings-v1";

const DEFAULT_SETTINGS: SettingsState = {
  synRateThreshold: 15000,
  connectionThreshold: 5000,
  packetRateThreshold: 50000,
  entropyThreshold: 75,
  contributorThreshold: 0,
  riskScoreThreshold: 70,
  autoBlock: true,
  autoRateLimit: true,
  whitelist: [],
  blacklist: [],
  alertWebhookUrl: "",
  alertWebhookSecret: "",
  geminiApiKey: "",
  logRetention: "30",
  analysisInterval: "1",
  modelFocus: "random_forest",
};

const loadStoredSettings = (): SettingsState => {
  if (typeof window === "undefined") {
    return DEFAULT_SETTINGS;
  }
  try {
    const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) {
      return DEFAULT_SETTINGS;
    }
    const parsed = JSON.parse(raw) as Partial<SettingsState>;
    if ("alertWebhookSecret" in parsed || "geminiApiKey" in parsed) {
      delete parsed.alertWebhookSecret;
      delete parsed.geminiApiKey;
      window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(parsed));
    }
    return {
      ...DEFAULT_SETTINGS,
      ...parsed,
      alertWebhookSecret: "",
      geminiApiKey: "",
      whitelist: Array.isArray(parsed.whitelist) ? parsed.whitelist : DEFAULT_SETTINGS.whitelist,
      blacklist: Array.isArray(parsed.blacklist) ? parsed.blacklist : DEFAULT_SETTINGS.blacklist,
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
};

const saveStoredSettings = (settings: SettingsState) => {
  if (typeof window === "undefined") return;
  const persisted: SettingsState = {
    ...settings,
    alertWebhookSecret: "",
    geminiApiKey: "",
  };
  window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(persisted));
};

const Settings = () => {
  const initialSettings = useMemo(loadStoredSettings, []);
  const ws = useSentinelWebSocket();

  const [synRateThreshold, setSynRateThreshold] = useState(initialSettings.synRateThreshold);
  const [connectionThreshold, setConnectionThreshold] = useState(initialSettings.connectionThreshold);
  const [packetRateThreshold, setPacketRateThreshold] = useState(initialSettings.packetRateThreshold);
  const [entropyThreshold, setEntropyThreshold] = useState(initialSettings.entropyThreshold);
  const [contributorThreshold, setContributorThreshold] = useState(initialSettings.contributorThreshold);
  const [riskScoreThreshold, setRiskScoreThreshold] = useState(initialSettings.riskScoreThreshold);

  const [autoBlock, setAutoBlock] = useState(initialSettings.autoBlock);
  const [autoRateLimit, setAutoRateLimit] = useState(initialSettings.autoRateLimit);

  const [whitelist, setWhitelist] = useState<string[]>(initialSettings.whitelist);
  const [blacklist, setBlacklist] = useState<string[]>(initialSettings.blacklist);

  const [alertWebhookUrl, setAlertWebhookUrl] = useState(initialSettings.alertWebhookUrl);
  const [alertWebhookSecret, setAlertWebhookSecret] = useState(initialSettings.alertWebhookSecret);
  const [geminiApiKey, setGeminiApiKey] = useState(initialSettings.geminiApiKey);

  const [logRetention, setLogRetention] = useState(initialSettings.logRetention);
  const [analysisInterval, setAnalysisInterval] = useState(initialSettings.analysisInterval);
  const [modelFocus, setModelFocus] = useState(initialSettings.modelFocus);

  const modelOptions = useMemo(
    () => [
      { value: "random_forest", label: "Random Forest" },
      { value: "xgboost", label: "XGBoost" },
      { value: "decision_tree", label: "Decision Tree" },
      { value: "knn", label: "KNN" },
      { value: "isolation_forest", label: "Isolation Forest" },
    ],
    []
  );

  const currentSettings: SettingsState = {
    synRateThreshold,
    connectionThreshold,
    packetRateThreshold,
    entropyThreshold,
    contributorThreshold,
    riskScoreThreshold,
    autoBlock,
    autoRateLimit,
    whitelist,
    blacklist,
    alertWebhookUrl,
    alertWebhookSecret,
    geminiApiKey,
    logRetention,
    analysisInterval,
    modelFocus,
  };

  const applySettings = (settings: SettingsState) => {
    setSynRateThreshold(settings.synRateThreshold);
    setConnectionThreshold(settings.connectionThreshold);
    setPacketRateThreshold(settings.packetRateThreshold);
    setEntropyThreshold(settings.entropyThreshold);
    setContributorThreshold(settings.contributorThreshold);
    setRiskScoreThreshold(settings.riskScoreThreshold);
    setAutoBlock(settings.autoBlock);
    setAutoRateLimit(settings.autoRateLimit);
    setWhitelist(settings.whitelist);
    setBlacklist(settings.blacklist);
    setAlertWebhookUrl(settings.alertWebhookUrl);
    setAlertWebhookSecret(settings.alertWebhookSecret);
    setGeminiApiKey(settings.geminiApiKey);
    setLogRetention(settings.logRetention);
    setAnalysisInterval(settings.analysisInterval);
    setModelFocus(settings.modelFocus);
  };

  const handleSave = () => {
    setVolatileSecretSettings({
      alertWebhookSecret,
      geminiApiKey,
    });
    saveStoredSettings(currentSettings);

    if (ws.connected && ws.sendCommand) {
      ws.sendCommand("set_syn_threshold", { value: String(synRateThreshold) });
      ws.sendCommand("set_conn_threshold", { value: String(connectionThreshold) });
      ws.sendCommand("set_pps_threshold", { value: String(packetRateThreshold) });
      ws.sendCommand("set_entropy_threshold", { value: String(entropyThreshold) });
      ws.sendCommand("set_contributor_threshold", { value: String(contributorThreshold) });
      const mitigationOn = autoBlock || autoRateLimit;
      if (mitigationOn) {
        ws.sendCommand("enable_auto_mitigation");
      } else {
        ws.sendCommand("disable_auto_mitigation");
      }
    }

    toast({
      title: "Settings Saved",
      description: ws.connected
        ? "Non-secret settings were saved locally, secrets stay in memory, and thresholds were synced to the backend."
        : "Non-secret settings were saved locally. Secrets stay in memory until refresh.",
    });
  };

  const handleReset = () => {
    clearVolatileSecretSettings();
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(SETTINGS_STORAGE_KEY);
    }
    applySettings({
      ...DEFAULT_SETTINGS,
    });
    toast({
      title: "Settings Reset",
      description: "Local settings were restored to defaults and in-memory secrets were cleared.",
      variant: "destructive",
    });
  };

  return (
    <DashboardLayout connected={ws.connected}>
      <div className="space-y-6 animate-fade-in">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-secondary">
              <SettingsIcon className="w-6 h-6 text-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
              <p className="text-sm text-muted-foreground">
                Configure detection, mitigation, and notification preferences
              </p>
            </div>
          </div>
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={handleReset}
              className="border-border hover:bg-destructive/10 hover:text-destructive hover:border-destructive/30"
            >
              <RotateCcw className="w-4 h-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button
              onClick={handleSave}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <Save className="w-4 h-4 mr-2" />
              Save Changes
            </Button>
          </div>
          {ws.lastCommandResult?.success && /^(set_|enable_auto_mitigation|disable_auto_mitigation)/.test(ws.lastCommandResult?.command ?? "") ? (
            <p className="text-xs text-muted-foreground">
              Last synced: <span className="font-medium text-foreground/80">{ws.lastCommandResult?.command ?? "—"}</span>
              {" "}
              at {new Date(ws.lastCommandResult.timestamp * 1000).toLocaleTimeString()}
            </p>
          ) : null}
        </div>

        <SettingsCard
          title="System Configuration"
          description="Advanced system settings"
          icon={Database}
          className="mb-6"
        >
          <p className="text-xs text-muted-foreground mb-4">
            Log retention, analysis interval, and benchmark focus are stored locally; the pipeline uses its own intervals. Runtime model deployment is still selected automatically by the training benchmark.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="space-y-4">
              <SelectSetting
                label="Log Retention"
                description="How long to keep logs"
                value={logRetention}
                onValueChange={setLogRetention}
                options={[
                  { value: "7", label: "7 days" },
                  { value: "14", label: "14 days" },
                  { value: "30", label: "30 days" },
                  { value: "90", label: "90 days" },
                  { value: "365", label: "1 year" },
                ]}
              />
            </div>
            <div className="space-y-4">
              <SelectSetting
                label="Analysis Interval"
                description="How often to analyze traffic"
                value={analysisInterval}
                onValueChange={setAnalysisInterval}
                options={[
                  { value: "1", label: "1 second" },
                  { value: "5", label: "5 seconds" },
                  { value: "10", label: "10 seconds" },
                  { value: "30", label: "30 seconds" },
                ]}
              />
            </div>
            <div className="space-y-4">
              <SelectSetting
                label="Benchmark Focus"
                description="Local UI preference only. Actual runtime deployment is selected automatically from measured benchmark accuracy and latency constraints."
                value={modelFocus}
                onValueChange={setModelFocus}
                options={modelOptions}
              />
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-border/60 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm font-medium">Gemini XAI API Key</p>
              <a
                href="https://aistudio.google.com/app/apikey"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:underline"
              >
                Get API key
              </a>
            </div>
            <p className="text-xs text-muted-foreground">
              Kept in memory only for this browser session. Sent only to the local Explain API when Gemini analysis is requested.
            </p>
            <div className="max-w-2xl space-y-2">
              <label className="text-xs text-muted-foreground">API Key</label>
              <Input
                type="password"
                value={geminiApiKey}
                onChange={(e) => setGeminiApiKey(e.target.value)}
                placeholder="AIza..."
                autoComplete="off"
                className="bg-secondary border-border font-mono text-xs"
              />
            </div>
          </div>
        </SettingsCard>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <SettingsCard
            title="Detection Thresholds"
            description="Configure sensitivity for attack detection. Click Save to push these values to the pipeline; until then the backend keeps its current or default thresholds."
            icon={Gauge}
            className="h-full"
          >
            <SliderSetting
              label="SYN Rate Threshold"
              description="Packets per second before triggering alert"
              value={synRateThreshold}
              onChange={setSynRateThreshold}
              min={1000}
              max={100000}
              step={1000}
              unit=" pps"
            />
            <SliderSetting
              label="Connection Threshold"
              description="Max concurrent connections per IP"
              value={connectionThreshold}
              onChange={setConnectionThreshold}
              min={100}
              max={50000}
              step={100}
              unit=""
            />
            <SliderSetting
              label="Packet Rate Threshold"
              description="Total packets per second threshold"
              value={packetRateThreshold}
              onChange={setPacketRateThreshold}
              min={10000}
              max={500000}
              step={5000}
              unit=" pps"
            />
          </SettingsCard>

          <SettingsCard
            title="Mitigation Rules"
            description="Configure automatic response actions"
            icon={Shield}
            className="h-full"
          >
            <p className="text-xs text-muted-foreground mb-4">
              Auto-Block and Auto Rate Limiting are synced to the backend on Save to control detection and mitigation behavior.
            </p>
            <ToggleSetting
              label="Auto-Block Malicious IPs"
              description="Automatically block detected malicious IPs"
              checked={autoBlock}
              onCheckedChange={setAutoBlock}
              variant="danger"
            />
            <ToggleSetting
              label="Auto Rate Limiting"
              description="Automatically rate limit detected attacks"
              checked={autoRateLimit}
              onCheckedChange={setAutoRateLimit}
              variant="warning"
            />

            <div className="mt-4 pt-4 border-t border-border/60 space-y-3">
              <p className="text-sm font-medium">Mitigation Alert Webhook</p>
              <p className="text-xs text-muted-foreground">
                Mitigation Control sends block/mitigation events to this URL when configured. The optional secret is kept in memory only until refresh.
              </p>
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground">Webhook URL</label>
                <Input
                  type="url"
                  value={alertWebhookUrl}
                  onChange={(e) => setAlertWebhookUrl(e.target.value)}
                  placeholder="https://your-server.com/alerts"
                  className="bg-secondary border-border font-mono text-xs"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground">Secret (optional)</label>
                <Input
                  type="password"
                  value={alertWebhookSecret}
                  onChange={(e) => setAlertWebhookSecret(e.target.value)}
                  placeholder="Optional signing secret"
                  className="bg-secondary border-border font-mono text-xs"
                />
              </div>
            </div>
          </SettingsCard>

          <SettingsCard
            title="IP Whitelist"
            description="IPs that bypass all security checks — synced to pipeline when connected"
            icon={Shield}
            className="h-full"
          >
            <IPListManager
              title="Trusted IP Addresses"
              description="These IPs will never be blocked or rate-limited"
              items={whitelist}
              onAdd={(ip) => {
                setWhitelist([...whitelist, ip]);
                if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                  ws.sendCommand("whitelist_ip", { ip });
                }
              }}
              onRemove={(ip) => {
                setWhitelist(whitelist.filter((item) => item !== ip));
                if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                  ws.sendCommand("remove_whitelist", { ip });
                }
              }}
              variant="whitelist"
            />
          </SettingsCard>

          <SettingsCard
            title="IP Blacklist"
            description="Permanently blocked IP addresses — synced to pipeline when connected"
            icon={AlertTriangle}
            className="h-full"
          >
            <IPListManager
              title="Blocked IP Addresses"
              description="These IPs are permanently denied access"
              items={blacklist}
              onAdd={(ip) => {
                setBlacklist([...blacklist, ip]);
                if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                  ws.sendCommand("block_ip", { ip });
                }
              }}
              onRemove={(ip) => {
                setBlacklist(blacklist.filter((item) => item !== ip));
                if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                  ws.sendCommand("unblock_ip", { ip });
                }
              }}
              variant="blacklist"
            />
          </SettingsCard>
        </div>

        <SettingsCard
          title="Advanced Detection Controls"
          description="Secondary tuning controls for anomaly heuristics and display threshold"
          icon={Gauge}
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <SliderSetting
              label="Entropy Threshold"
              description="IP entropy score for anomaly detection"
              value={entropyThreshold}
              onChange={setEntropyThreshold}
              min={0}
              max={100}
              step={5}
              unit="%"
              variant="warning"
            />
            <SliderSetting
              label="Contributor Threshold (%)"
              description="Only consider IPs that contribute at least this % of top-source traffic for Block top contributors. 0 = disabled."
              value={contributorThreshold}
              onChange={setContributorThreshold}
              min={0}
              max={100}
              step={5}
              unit="%"
            />
            <SliderSetting
              label="Risk Score Threshold (display)"
              description="Alert/display threshold only; mitigation thresholds are set via the pipeline."
              value={riskScoreThreshold}
              onChange={setRiskScoreThreshold}
              min={0}
              max={100}
              step={5}
              unit="%"
              variant="danger"
            />
          </div>
        </SettingsCard>
      </div>
    </DashboardLayout>
  );
};

export default Settings;

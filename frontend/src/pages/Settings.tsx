import { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { SettingsCard } from "@/components/settings/SettingsCard";
import { SliderSetting } from "@/components/settings/SliderSetting";
import { ToggleSetting } from "@/components/settings/ToggleSetting";
import { SelectSetting } from "@/components/settings/SelectSetting";
import { IPListManager } from "@/components/settings/IPListManager";
import { ModelBenchmarkPanel } from "@/components/dashboard/ModelBenchmarkPanel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useModelBenchmarkReport } from "@/hooks/useModelBenchmarkReport";
import { useSentinelWebSocket } from "@/hooks/useSentinelWebSocket";
import {
  Settings as SettingsIcon,
  Gauge,
  Shield,
  Bell,
  Database,
  Save,
  RotateCcw,
  AlertTriangle,
  Mail,
  Smartphone,
  Globe,
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
  blockDuration: string;
  rateLimitRequests: number;
  rateLimitWindow: string;
  escalationEnabled: boolean;
  geoBlocking: boolean;
  whitelist: string[];
  blacklist: string[];
  emailNotifications: boolean;
  smsNotifications: boolean;
  webhookNotifications: boolean;
  notifyOnAttack: boolean;
  notifyOnMitigation: boolean;
  notifyOnThreshold: boolean;
  emailAddress: string;
  webhookUrl: string;
  alertWebhookUrl: string;
  alertWebhookSecret: string;
  externalFirewallApiUrl: string;
  alertCooldown: string;
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
  blockDuration: "30",
  rateLimitRequests: 100,
  rateLimitWindow: "60",
  escalationEnabled: true,
  geoBlocking: false,
  // Whitelist and blacklist start empty — operators should add their own CIDRs.
  whitelist: [],
  blacklist: [],
  emailNotifications: false,
  smsNotifications: false,
  webhookNotifications: false,
  notifyOnAttack: true,
  notifyOnMitigation: true,
  notifyOnThreshold: false,
  emailAddress: "",
  webhookUrl: "",
  alertWebhookUrl: "",
  alertWebhookSecret: "",
  externalFirewallApiUrl: "",
  alertCooldown: "5",
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
    return {
      ...DEFAULT_SETTINGS,
      ...parsed,
      whitelist: Array.isArray(parsed.whitelist) ? parsed.whitelist : DEFAULT_SETTINGS.whitelist,
      blacklist: Array.isArray(parsed.blacklist) ? parsed.blacklist : DEFAULT_SETTINGS.blacklist,
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
};

const saveStoredSettings = (settings: SettingsState) => {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
};

const isValidEmail = (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

const isValidHttpUrl = (value: string) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
};

const Settings = () => {
  const initialSettings = useMemo(loadStoredSettings, []);
  const ws = useSentinelWebSocket();
  const benchmarks = useModelBenchmarkReport();

  const [synRateThreshold, setSynRateThreshold] = useState(initialSettings.synRateThreshold);
  const [connectionThreshold, setConnectionThreshold] = useState(initialSettings.connectionThreshold);
  const [packetRateThreshold, setPacketRateThreshold] = useState(initialSettings.packetRateThreshold);
  const [entropyThreshold, setEntropyThreshold] = useState(initialSettings.entropyThreshold);
  const [contributorThreshold, setContributorThreshold] = useState(initialSettings.contributorThreshold);
  const [riskScoreThreshold, setRiskScoreThreshold] = useState(initialSettings.riskScoreThreshold);

  const [autoBlock, setAutoBlock] = useState(initialSettings.autoBlock);
  const [autoRateLimit, setAutoRateLimit] = useState(initialSettings.autoRateLimit);
  const [blockDuration, setBlockDuration] = useState(initialSettings.blockDuration);
  const [rateLimitRequests, setRateLimitRequests] = useState(initialSettings.rateLimitRequests);
  const [rateLimitWindow, setRateLimitWindow] = useState(initialSettings.rateLimitWindow);
  const [escalationEnabled, setEscalationEnabled] = useState(initialSettings.escalationEnabled);
  const [geoBlocking, setGeoBlocking] = useState(initialSettings.geoBlocking);

  const [whitelist, setWhitelist] = useState<string[]>(initialSettings.whitelist);
  const [blacklist, setBlacklist] = useState<string[]>(initialSettings.blacklist);

  const [emailNotifications, setEmailNotifications] = useState(initialSettings.emailNotifications);
  const [smsNotifications, setSmsNotifications] = useState(initialSettings.smsNotifications);
  const [webhookNotifications, setWebhookNotifications] = useState(initialSettings.webhookNotifications);
  const [notifyOnAttack, setNotifyOnAttack] = useState(initialSettings.notifyOnAttack);
  const [notifyOnMitigation, setNotifyOnMitigation] = useState(initialSettings.notifyOnMitigation);
  const [notifyOnThreshold, setNotifyOnThreshold] = useState(initialSettings.notifyOnThreshold);
  const [emailAddress, setEmailAddress] = useState(initialSettings.emailAddress);
  const [webhookUrl, setWebhookUrl] = useState(initialSettings.webhookUrl);
  const [alertWebhookUrl, setAlertWebhookUrl] = useState(initialSettings.alertWebhookUrl);
  const [alertWebhookSecret, setAlertWebhookSecret] = useState(initialSettings.alertWebhookSecret);
  const [externalFirewallApiUrl, setExternalFirewallApiUrl] = useState(initialSettings.externalFirewallApiUrl);
  const [alertCooldown, setAlertCooldown] = useState(initialSettings.alertCooldown);

  const [logRetention, setLogRetention] = useState(initialSettings.logRetention);
  const [analysisInterval, setAnalysisInterval] = useState(initialSettings.analysisInterval);
  const [modelFocus, setModelFocus] = useState(initialSettings.modelFocus);

  useEffect(() => {
    if (!benchmarks.report) return;
    const available = new Set(benchmarks.report.models.map((model) => model.name));
    if (!available.has(modelFocus)) {
      setModelFocus(benchmarks.report.runtime_model);
    }
  }, [benchmarks.report, modelFocus]);

  const modelOptions = useMemo(() => {
    const fallback = [
      { value: "random_forest", label: "Random Forest (Deployed)" },
    ];
    if (!benchmarks.report) {
      return fallback;
    }
    return benchmarks.report.models.map((model) => ({
      value: model.name,
      label: model.exported ? `${model.display_name} (Deployed)` : model.display_name,
    }));
  }, [benchmarks.report]);

  const currentSettings: SettingsState = {
    synRateThreshold,
    connectionThreshold,
    packetRateThreshold,
    entropyThreshold,
    contributorThreshold,
    riskScoreThreshold,
    autoBlock,
    autoRateLimit,
    blockDuration,
    rateLimitRequests,
    rateLimitWindow,
    escalationEnabled,
    geoBlocking,
    whitelist,
    blacklist,
    emailNotifications,
    smsNotifications,
    webhookNotifications,
    notifyOnAttack,
    notifyOnMitigation,
    notifyOnThreshold,
    emailAddress,
    webhookUrl,
    alertWebhookUrl,
    alertWebhookSecret,
    externalFirewallApiUrl,
    alertCooldown,
    logRetention,
    analysisInterval,
    modelFocus,
  };

  const integrationFlags = [
    { label: "Intel Feed", enabled: ws.integrationStatus?.intel_feed_enabled ?? false },
    { label: "Model Extension", enabled: ws.integrationStatus?.model_extension_enabled ?? false },
    { label: "Controller Extension", enabled: ws.integrationStatus?.controller_extension_enabled ?? false },
    { label: "Signature Feed", enabled: ws.integrationStatus?.signature_feed_enabled ?? false },
    { label: "Dataplane Extension", enabled: ws.integrationStatus?.dataplane_extension_enabled ?? false },
    { label: "Gatekeeper Sidecar", enabled: ws.integrationStatus?.gatekeeper_enabled ?? false },
  ];

  const applySettings = (settings: SettingsState) => {
    setSynRateThreshold(settings.synRateThreshold);
    setConnectionThreshold(settings.connectionThreshold);
    setPacketRateThreshold(settings.packetRateThreshold);
    setEntropyThreshold(settings.entropyThreshold);
    setContributorThreshold(settings.contributorThreshold);
    setRiskScoreThreshold(settings.riskScoreThreshold);
    setAutoBlock(settings.autoBlock);
    setAutoRateLimit(settings.autoRateLimit);
    setBlockDuration(settings.blockDuration);
    setRateLimitRequests(settings.rateLimitRequests);
    setRateLimitWindow(settings.rateLimitWindow);
    setEscalationEnabled(settings.escalationEnabled);
    setGeoBlocking(settings.geoBlocking);
    setWhitelist(settings.whitelist);
    setBlacklist(settings.blacklist);
    setEmailNotifications(settings.emailNotifications);
    setSmsNotifications(settings.smsNotifications);
    setWebhookNotifications(settings.webhookNotifications);
    setNotifyOnAttack(settings.notifyOnAttack);
    setNotifyOnMitigation(settings.notifyOnMitigation);
    setNotifyOnThreshold(settings.notifyOnThreshold);
    setEmailAddress(settings.emailAddress);
    setWebhookUrl(settings.webhookUrl);
    setAlertWebhookUrl(settings.alertWebhookUrl);
    setAlertWebhookSecret(settings.alertWebhookSecret);
    setExternalFirewallApiUrl(settings.externalFirewallApiUrl);
    setAlertCooldown(settings.alertCooldown);
    setLogRetention(settings.logRetention);
    setAnalysisInterval(settings.analysisInterval);
    setModelFocus(settings.modelFocus);
  };

  const handleSave = () => {
    if (emailNotifications && !isValidEmail(emailAddress.trim())) {
      toast({
        title: "Invalid email address",
        description: "Enter a valid email address before enabling email notifications.",
        variant: "destructive",
      });
      return;
    }

    if (webhookNotifications && !isValidHttpUrl(webhookUrl.trim())) {
      toast({
        title: "Invalid webhook URL",
        description: "Webhook notifications require a valid http:// or https:// URL.",
        variant: "destructive",
      });
      return;
    }

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
        ? "Settings saved locally and synced to the backend."
        : "Settings saved locally. Connect to backend to sync runtime thresholds.",
    });
  };

  const handleReset = () => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(SETTINGS_STORAGE_KEY);
    }
    applySettings({
      ...DEFAULT_SETTINGS,
      modelFocus: benchmarks.report?.runtime_model ?? DEFAULT_SETTINGS.modelFocus,
    });
    toast({
      title: "Settings Reset",
      description: "Local settings were restored to defaults.",
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

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SettingsCard
            title="Integration Readiness"
            description="Backend integration flags detected from runtime telemetry"
            icon={Database}
            className="lg:col-span-2"
          >
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <span className="text-sm text-muted-foreground">Profile:</span>
              <span className="px-2 py-1 rounded bg-secondary text-sm font-mono">
                {ws.integrationStatus?.profile ?? "baseline"}
              </span>
              <span className="text-sm text-muted-foreground">
                {integrationFlags.filter((flag) => flag.enabled).length} / {integrationFlags.length} enabled
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-6 gap-2">
              {integrationFlags.map((flag) => (
                <div
                  key={flag.label}
                  className="rounded border border-border px-3 py-2 flex items-center justify-between"
                >
                  <span className="text-xs text-muted-foreground">{flag.label}</span>
                  <span className={flag.enabled ? "text-status-success text-xs font-semibold" : "text-status-warning text-xs font-semibold"}>
                    {flag.enabled ? "Enabled" : "Disabled"}
                  </span>
                </div>
              ))}
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              If an integration shows Disabled or Unreachable, enable it via your deployment environment (e.g. SENTINEL_ENABLE_* flags) or ensure the backing service is running.
            </p>
            <p className="text-xs text-muted-foreground mt-2">
              Flow collection: pipeline sends metrics every 1s and top sources every 5s. Adjust in pipeline config if needed.
            </p>
            {ws.integrationStatus?.gatekeeper_enabled ? (
              <p className="text-xs text-muted-foreground mt-3">
                Gatekeeper health: {ws.integrationStatus?.gatekeeper_connected === 1 ? "Connected" : ws.integrationStatus?.gatekeeper_connected === 0 ? "Unreachable" : "Unknown"}
                {ws.integrationStatus?.gatekeeper_connected === 0 && ws.integrationStatus?.gatekeeper_last_error
                  ? ` (${ws.integrationStatus.gatekeeper_last_error})`
                  : ""}
                {typeof ws.integrationStatus?.gatekeeper_failure_count === "number" && typeof ws.integrationStatus?.gatekeeper_failure_threshold === "number"
                  ? ` | Failures: ${ws.integrationStatus.gatekeeper_failure_count}/${ws.integrationStatus.gatekeeper_failure_threshold}`
                  : ""}
                {ws.integrationStatus?.gatekeeper_circuit_open
                  ? ` | Circuit open${ws.integrationStatus.gatekeeper_next_retry_sec ? ` (retry in ${ws.integrationStatus.gatekeeper_next_retry_sec}s)` : ""}`
                  : ""}
              </p>
            ) : null}
          </SettingsCard>

          <SettingsCard
            title="Detection Thresholds"
            description="Configure sensitivity for attack detection. Click Save to push these values to the pipeline; until then the backend keeps its current or default thresholds."
            icon={Gauge}
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
              description="Alert/display threshold only; mitigation thresholds are set via the pipeline. Use this to control when the UI shows high-risk state."
              value={riskScoreThreshold}
              onChange={setRiskScoreThreshold}
              min={0}
              max={100}
              step={5}
              unit="%"
              variant="danger"
            />
          </SettingsCard>

          <SettingsCard
            title="Mitigation Rules"
            description="Configure automatic response actions"
            icon={Shield}
          >
            <p className="text-xs text-muted-foreground mb-4">
              Block duration and rate limit window are stored locally; the pipeline uses its own timeouts. Use the thresholds above and Auto-Block / Auto Rate Limiting (synced on Save) to control backend behavior.
            </p>
            <ToggleSetting
              label="Auto-Block Malicious IPs"
              description="Persisted UI preference for aggressive response posture"
              checked={autoBlock}
              onCheckedChange={setAutoBlock}
              variant="danger"
            />
            <ToggleSetting
              label="Auto Rate Limiting"
              description="Persisted UI preference for rate-limit posture"
              checked={autoRateLimit}
              onCheckedChange={setAutoRateLimit}
              variant="warning"
            />
            <SelectSetting
              label="Block Duration"
              description="How long to block malicious IPs"
              value={blockDuration}
              onValueChange={setBlockDuration}
              options={[
                { value: "5", label: "5 minutes" },
                { value: "15", label: "15 minutes" },
                { value: "30", label: "30 minutes" },
                { value: "60", label: "1 hour" },
                { value: "1440", label: "24 hours" },
                { value: "0", label: "Permanent" },
              ]}
            />
            <SliderSetting
              label="Rate Limit (req/min)"
              description="Max requests per minute when rate limiting"
              value={rateLimitRequests}
              onChange={setRateLimitRequests}
              min={10}
              max={1000}
              step={10}
              unit=""
            />
            <SelectSetting
              label="Rate Limit Window"
              description="Time window for rate limiting"
              value={rateLimitWindow}
              onValueChange={setRateLimitWindow}
              options={[
                { value: "10", label: "10 seconds" },
                { value: "30", label: "30 seconds" },
                { value: "60", label: "1 minute" },
                { value: "300", label: "5 minutes" },
              ]}
            />
            <ToggleSetting
              label="Escalation Mode"
              description="Escalate from rate-limit to block on repeated violations"
              checked={escalationEnabled}
              onCheckedChange={setEscalationEnabled}
              variant="warning"
            />
            <ToggleSetting
              label="Geographic Blocking"
              description="Block traffic from high-risk countries"
              checked={geoBlocking}
              onCheckedChange={setGeoBlocking}
              variant="danger"
            />
          </SettingsCard>

          <SettingsCard
            title="IP Whitelist"
            description="IPs that bypass all security checks — synced to pipeline when connected"
            icon={Shield}
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

          <SettingsCard
            title="Notification Channels"
            description="Configure how you receive alerts"
            icon={Bell}
            className="lg:col-span-2"
          >
            <p className="text-xs text-muted-foreground mb-4">
              Email, SMS, and the generic Webhook URL below are stored as preferences only; no outbound sending is implemented. Use <strong>Mitigation alert webhook</strong> for real POSTs on block or mitigation events (from Mitigation Control).
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-medium text-sm flex items-center gap-2 text-muted-foreground">
                  <Mail className="w-4 h-4 text-primary" />
                  Email (preference only)
                </h4>
                <ToggleSetting
                  label="Enable Email Alerts"
                  description="Receive alerts via email"
                  checked={emailNotifications}
                  onCheckedChange={setEmailNotifications}
                  variant="success"
                />
                {emailNotifications && (
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground">Email Address</label>
                    <Input
                      type="email"
                      value={emailAddress}
                      onChange={(event) => setEmailAddress(event.target.value)}
                      placeholder="soc-team@example.com"
                      className="bg-secondary border-border"
                    />
                  </div>
                )}

                <h4 className="font-medium text-sm flex items-center gap-2 pt-4 text-muted-foreground">
                  <Smartphone className="w-4 h-4 text-primary" />
                  SMS (preference only)
                </h4>
                <ToggleSetting
                  label="Enable SMS Alerts"
                  description="Receive critical alerts via SMS"
                  checked={smsNotifications}
                  onCheckedChange={setSmsNotifications}
                  variant="success"
                />

                <h4 className="font-medium text-sm flex items-center gap-2 pt-4 text-muted-foreground">
                  <Globe className="w-4 h-4 text-primary" />
                  Webhook URL (preference only)
                </h4>
                <ToggleSetting
                  label="Enable Webhook Alerts"
                  description="Store a webhook URL for future use; not wired to sending. Use Mitigation alert webhook below for live POSTs."
                  checked={webhookNotifications}
                  onCheckedChange={setWebhookNotifications}
                  variant="success"
                />
                {webhookNotifications && (
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground">Webhook URL</label>
                    <Input
                      type="url"
                      value={webhookUrl}
                      onChange={(event) => setWebhookUrl(event.target.value)}
                      placeholder="https://alerts.example.com/sentinel"
                      className="bg-secondary border-border font-mono text-xs"
                    />
                  </div>
                )}

                <h4 className="font-medium text-sm flex items-center gap-2 pt-4">
                  <Bell className="w-4 h-4 text-primary" />
                  Mitigation alert webhook (active)
                </h4>
                <p className="text-xs text-muted-foreground">POSTs attack/mitigation events (on block or Block All Flagged) to this URL when configured.</p>
                <div className="space-y-2">
                  <label className="text-xs text-muted-foreground">Alert webhook URL</label>
                  <Input
                    type="url"
                    value={alertWebhookUrl}
                    onChange={(e) => setAlertWebhookUrl(e.target.value)}
                    placeholder="https://your-server.com/alerts"
                    className="bg-secondary border-border font-mono text-xs"
                  />
                  <label className="text-xs text-muted-foreground">Secret (optional, for signing or auth header)</label>
                  <Input
                    type="password"
                    value={alertWebhookSecret}
                    onChange={(e) => setAlertWebhookSecret(e.target.value)}
                    placeholder="Optional secret"
                    className="bg-secondary border-border font-mono text-xs"
                  />
                </div>

                <h4 className="font-medium text-sm flex items-center gap-2 pt-4">
                  <Globe className="w-4 h-4 text-primary" />
                  External firewall API (active)
                </h4>
                <p className="text-xs text-muted-foreground">Push blocked IPs to this API from Mitigation Control when you click &quot;Push blocked IPs to external API&quot;.</p>
                <div className="space-y-2">
                  <label className="text-xs text-muted-foreground">API URL</label>
                  <Input
                    type="url"
                    value={externalFirewallApiUrl}
                    onChange={(e) => setExternalFirewallApiUrl(e.target.value)}
                    placeholder="https://api.example.com/firewall/block"
                    className="bg-secondary border-border font-mono text-xs"
                  />
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="font-medium text-sm">Alert Types</h4>
                <ToggleSetting
                  label="Attack Detection"
                  description="Notify when DDoS attack is detected"
                  checked={notifyOnAttack}
                  onCheckedChange={setNotifyOnAttack}
                  variant="danger"
                />
                <ToggleSetting
                  label="Mitigation Actions"
                  description="Notify when IPs are blocked or rate-limited"
                  checked={notifyOnMitigation}
                  onCheckedChange={setNotifyOnMitigation}
                  variant="warning"
                />
                <ToggleSetting
                  label="Threshold Warnings"
                  description="Notify when traffic approaches thresholds"
                  checked={notifyOnThreshold}
                  onCheckedChange={setNotifyOnThreshold}
                  variant="success"
                />

                <SelectSetting
                  label="Alert Cooldown"
                  description="Minimum time between repeated alerts"
                  value={alertCooldown}
                  onValueChange={setAlertCooldown}
                  options={[
                    { value: "1", label: "1 minute" },
                    { value: "5", label: "5 minutes" },
                    { value: "15", label: "15 minutes" },
                    { value: "30", label: "30 minutes" },
                    { value: "60", label: "1 hour" },
                  ]}
                />
              </div>
            </div>
          </SettingsCard>

          <SettingsCard
            title="System Configuration"
            description="Advanced system settings"
            icon={Database}
            className="lg:col-span-2"
          >
            <p className="text-xs text-muted-foreground mb-4">
              Log retention, analysis interval, and model version are stored locally; the pipeline uses its own intervals. Model version affects which benchmark is shown in the UI.
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
                  label="Model Version"
                  description="Benchmark focus in the UI; deployed runtime model remains Random Forest."
                  value={modelFocus}
                  onValueChange={setModelFocus}
                  options={modelOptions}
                />
              </div>
            </div>
          </SettingsCard>

          <ModelBenchmarkPanel
            report={benchmarks.report}
            loading={benchmarks.loading}
            error={benchmarks.error}
            onRefetch={benchmarks.refetch}
            className="lg:col-span-2"
          />
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Settings;

/**
 * Read non-secret integration settings from localStorage.
 * Sensitive values stay in memory only for the current browser session.
 */
const STORAGE_KEY = "sentinel-ui-settings-v1";

type VolatileSecretSettings = {
  alertWebhookSecret: string;
  geminiApiKey: string;
};

const volatileSecrets: VolatileSecretSettings = {
  alertWebhookSecret: "",
  geminiApiKey: "",
};

export interface MitigationIntegrationSettings {
  alertWebhookUrl: string;
  alertWebhookSecret: string;
  externalFirewallApiUrl: string;
}

export interface GeminiXAISettings {
  geminiApiKey: string;
}

function readStoredSettings(): Record<string, unknown> {
  if (typeof window === "undefined") {
    return {};
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if ("alertWebhookSecret" in parsed || "geminiApiKey" in parsed) {
      delete parsed.alertWebhookSecret;
      delete parsed.geminiApiKey;
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
    }
    return parsed;
  } catch {
    return {};
  }
}

export function setVolatileSecretSettings(next: Partial<VolatileSecretSettings>) {
  if (typeof next.alertWebhookSecret === "string") {
    volatileSecrets.alertWebhookSecret = next.alertWebhookSecret;
  }
  if (typeof next.geminiApiKey === "string") {
    volatileSecrets.geminiApiKey = next.geminiApiKey;
  }
}

export function clearVolatileSecretSettings() {
  volatileSecrets.alertWebhookSecret = "";
  volatileSecrets.geminiApiKey = "";
}

export function getMitigationIntegrationSettings(): MitigationIntegrationSettings {
  const stored = readStoredSettings();
  return {
    alertWebhookUrl: typeof stored.alertWebhookUrl === "string" ? stored.alertWebhookUrl : "",
    alertWebhookSecret: volatileSecrets.alertWebhookSecret,
    externalFirewallApiUrl: typeof stored.externalFirewallApiUrl === "string" ? stored.externalFirewallApiUrl : "",
  };
}

export function getGeminiXAISettings(): GeminiXAISettings {
  return {
    geminiApiKey: volatileSecrets.geminiApiKey,
  };
}

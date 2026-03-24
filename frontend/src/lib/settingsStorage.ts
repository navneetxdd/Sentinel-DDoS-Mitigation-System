/**
 * Read mitigation-related integration settings from localStorage (same key as Settings page).
 * Used by Mitigation Control for alert webhook and external firewall API.
 */
const STORAGE_KEY = "sentinel-ui-settings-v1";

export interface MitigationIntegrationSettings {
  alertWebhookUrl: string;
  alertWebhookSecret: string;
  externalFirewallApiUrl: string;
}

export interface GeminiXAISettings {
  geminiApiKey: string;
}

export function getMitigationIntegrationSettings(): MitigationIntegrationSettings {
  if (typeof window === "undefined") {
    return { alertWebhookUrl: "", alertWebhookSecret: "", externalFirewallApiUrl: "" };
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return { alertWebhookUrl: "", alertWebhookSecret: "", externalFirewallApiUrl: "" };
    const p = JSON.parse(raw) as Record<string, unknown>;
    return {
      alertWebhookUrl: typeof p.alertWebhookUrl === "string" ? p.alertWebhookUrl : "",
      alertWebhookSecret: typeof p.alertWebhookSecret === "string" ? p.alertWebhookSecret : "",
      externalFirewallApiUrl: typeof p.externalFirewallApiUrl === "string" ? p.externalFirewallApiUrl : "",
    };
  } catch {
    return { alertWebhookUrl: "", alertWebhookSecret: "", externalFirewallApiUrl: "" };
  }
}

export function getGeminiXAISettings(): GeminiXAISettings {
  if (typeof window === "undefined") {
    return { geminiApiKey: "" };
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return { geminiApiKey: "" };
    const p = JSON.parse(raw) as Record<string, unknown>;
    return {
      geminiApiKey: typeof p.geminiApiKey === "string" ? p.geminiApiKey : "",
    };
  } catch {
    return { geminiApiKey: "" };
  }
}

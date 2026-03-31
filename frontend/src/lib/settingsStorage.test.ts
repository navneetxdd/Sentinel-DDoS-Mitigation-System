import { afterEach, describe, expect, it } from "vitest";
import {
  clearVolatileSecretSettings,
  getGeminiXAISettings,
  getMitigationIntegrationSettings,
  setVolatileSecretSettings,
} from "./settingsStorage";

const STORAGE_KEY = "sentinel-ui-settings-v1";

afterEach(() => {
  clearVolatileSecretSettings();
  window.localStorage.clear();
});

describe("settingsStorage", () => {
  it("keeps secrets in memory and scrubs persisted copies", () => {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        alertWebhookUrl: "https://example.test/hook",
        externalFirewallApiUrl: "https://example.test/fw",
        alertWebhookSecret: "persisted-secret",
        geminiApiKey: "persisted-gemini",
      }),
    );

    const integration = getMitigationIntegrationSettings();
    const gemini = getGeminiXAISettings();
    const scrubbed = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}") as Record<string, unknown>;

    expect(integration.alertWebhookUrl).toBe("https://example.test/hook");
    expect(integration.alertWebhookSecret).toBe("");
    expect(gemini.geminiApiKey).toBe("");
    expect(scrubbed.alertWebhookSecret).toBeUndefined();
    expect(scrubbed.geminiApiKey).toBeUndefined();
  });

  it("returns volatile secrets for the current browser session only", () => {
    setVolatileSecretSettings({
      alertWebhookSecret: "live-secret",
      geminiApiKey: "live-gemini",
    });

    expect(getMitigationIntegrationSettings().alertWebhookSecret).toBe("live-secret");
    expect(getGeminiXAISettings().geminiApiKey).toBe("live-gemini");

    clearVolatileSecretSettings();

    expect(getMitigationIntegrationSettings().alertWebhookSecret).toBe("");
    expect(getGeminiXAISettings().geminiApiKey).toBe("");
  });
});

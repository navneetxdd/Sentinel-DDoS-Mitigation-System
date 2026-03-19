import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { createElement } from "react";
import {
  useSentinelWebSocket,
  SentinelWebSocketProvider,
  shouldApplyCommandResult,
  type SentinelCommandResult,
} from "./useSentinelWebSocket";

vi.mock("@/lib/apiConfig", () => ({
  fetchExplainApi: vi.fn(),
  isExplainApiConfigured: false,
  WS_URL_CANDIDATES: ["ws://test"],
  WS_API_KEY: "",
}));

const noopWebSocket = vi.fn(() => ({
  readyState: 0,
  onopen: null,
  onclose: null,
  onmessage: null,
  onerror: null,
  send: vi.fn(),
  close: vi.fn(),
}));

describe("shouldApplyCommandResult", () => {
  it("returns true when request_id is null (backward compat)", () => {
    const data: SentinelCommandResult = {
      timestamp: 1,
      contract_version: 1,
      request_id: "",
      command: "block_ip",
      success: true,
      message: "ok",
    };
    expect(shouldApplyCommandResult(data, "any-id")).toBe(true);
  });

  it("returns true when request_id matches lastSentRequestId", () => {
    const data: SentinelCommandResult = {
      timestamp: 1,
      contract_version: 1,
      request_id: "req-123",
      command: "set_syn_threshold",
      success: true,
      message: "ok",
    };
    expect(shouldApplyCommandResult(data, "req-123")).toBe(true);
  });

  it("returns false when request_id does not match lastSentRequestId", () => {
    const data: SentinelCommandResult = {
      timestamp: 1,
      contract_version: 1,
      request_id: "other-id",
      command: "other",
      success: true,
      message: "ignored",
    };
    expect(shouldApplyCommandResult(data, "req-123")).toBe(false);
  });

  it("returns true when lastSentRequestId is null and data has request_id", () => {
    const data: SentinelCommandResult = {
      timestamp: 1,
      contract_version: 1,
      request_id: "req-456",
      command: "x",
      success: true,
      message: "ok",
    };
    expect(shouldApplyCommandResult(data, null)).toBe(true);
  });
});

describe("useSentinelWebSocket", () => {
  beforeEach(() => {
    vi.stubGlobal("WebSocket", noopWebSocket);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function TestConsumer() {
    const ws = useSentinelWebSocket();
    return createElement("div", { "data-testid": "consumer" }, [
      createElement("span", {
        key: "cmd",
        "data-testid": "lastCommand",
        "data-command": ws.lastCommandResult?.command ?? "",
      }),
      createElement("span", {
        key: "parse",
        "data-testid": "parseErrors",
        "data-count": String(ws.parseErrorCount ?? 0),
      }),
    ]);
  }

  it("provider renders and hook exposes state", async () => {
    render(createElement(SentinelWebSocketProvider, null, createElement(TestConsumer)));
    await waitFor(() => expect(screen.getByTestId("consumer")).toBeInTheDocument());
    expect(screen.getByTestId("lastCommand").getAttribute("data-command")).toBe("");
    expect(screen.getByTestId("parseErrors").getAttribute("data-count")).toBe("0");
  });
});

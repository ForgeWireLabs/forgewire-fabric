import { afterEach, describe, expect, it, vi } from "vitest";
import {
  dispatchDisabledReason,
  EMPTY_DISPATCH_DRAFT,
  HubApi,
  normalizeDispatchDraft,
  normalizeHubUrl,
  parseListField
} from "./api";
import { hubConfigFromContext } from "./storage";

describe("normalizeHubUrl", () => {
  it("adds http scheme and removes trailing slashes", () => {
    expect(normalizeHubUrl("127.0.0.1:8765///")).toBe("http://127.0.0.1:8765");
  });

  it("preserves explicit https scheme", () => {
    expect(normalizeHubUrl(" https://fabric.example.test/ ")).toBe("https://fabric.example.test");
  });
});

describe("HubApi", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends bearer authorization on reads", async () => {
    const fetchMock = vi.fn(async () => response({ status: "ok" }));
    vi.stubGlobal("fetch", fetchMock);

    const api = new HubApi({ hubUrl: "http://hub.local:8765", token: "secret-token" });
    await api.healthz();

    expect(fetchMock).toHaveBeenCalledWith(
      "http://hub.local:8765/healthz",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer secret-token",
          Accept: "application/json"
        })
      })
    );
  });

  it("reads task stream lines after the provided sequence", async () => {
    const fetchMock = vi.fn(async () => response({ lines: [{ seq: 4, channel: "stdout", line: "ready" }] }));
    vi.stubGlobal("fetch", fetchMock);

    const api = new HubApi({ hubUrl: "hub.local:8765", token: "token" });
    const result = await api.taskStream(12, 3, 50);

    expect(result.lines).toEqual([{ seq: 4, channel: "stdout", line: "ready" }]);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://hub.local:8765/tasks/12/stream?after_seq=3&limit=50",
      expect.any(Object)
    );
  });

  it("posts approval decisions as JSON", async () => {
    const fetchMock = vi.fn(async () => response({ approval_id: "ap-1", status: "approved" }));
    vi.stubGlobal("fetch", fetchMock);

    const api = new HubApi({ hubUrl: "hub.local:8765", token: "token" });
    await api.approveApproval("ap-1", { approver: "fabric-desktop", reason: "ok" });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://hub.local:8765/approvals/ap-1/approve",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ approver: "fabric-desktop", reason: "ok" }),
        headers: expect.objectContaining({
          "Content-Type": "application/json"
        })
      })
    );
  });
});

describe("dispatch brief normalization", () => {
  it("parses comma and newline separated lists", () => {
    expect(parseListField("core/**, crates/**\n desktop/** ")).toEqual(["core/**", "crates/**", "desktop/**"]);
  });

  it("normalizes signed agent dispatch briefs", () => {
    const brief = normalizeDispatchDraft({
      ...EMPTY_DISPATCH_DRAFT,
      title: " Ship UI ",
      branch: " agent/ui ",
      baseCommit: " abc123 ",
      scopeGlobs: "desktop/**\ncrates/fabric-client/**",
      prompt: " Build it ",
      tags: "windows, ui",
      capabilities: "tauri\nrust"
    });

    expect(brief).toMatchObject({
      title: "Ship UI",
      kind: "agent",
      dispatch: "prompt",
      branch: "agent/ui",
      base_commit: "abc123",
      scope_globs: ["desktop/**", "crates/fabric-client/**"],
      prompt: "Build it",
      required_tags: ["windows", "ui"],
      required_capabilities: ["tauri", "rust"]
    });
  });

  it("normalizes signed command dispatch path", () => {
    const brief = normalizeDispatchDraft({
      ...EMPTY_DISPATCH_DRAFT,
      kind: "command",
      title: "Run smoke",
      branch: "agent/smoke",
      baseCommit: "origin/main",
      scopeGlobs: "desktop/**",
      prompt: "Run desktop smoke",
      command: "npm,test"
    });

    expect(brief.kind).toBe("command");
    expect(brief.command).toEqual(["npm", "test"]);
  });

  it("disables dispatch until a dispatcher identity is loaded", () => {
    const reason = dispatchDisabledReason(
      {
        ...EMPTY_DISPATCH_DRAFT,
        title: "Ready",
        branch: "agent/ready",
        baseCommit: "origin/main",
        scopeGlobs: "desktop/**",
        prompt: "Do work"
      },
      null,
      { hubUrl: "http://127.0.0.1:8765", token: "token" }
    );

    expect(reason).toBe("Load a dispatcher identity first");
  });
});

describe("installed Fabric context", () => {
  it("hydrates the hub config from OOTB context without exposing token fallback", () => {
    expect(
      hubConfigFromContext(
        {
          hub_url: "http://127.0.0.1:8765",
          hub_source: "live hub discovery",
          token: "installed-token",
          token_path: "C:\\Users\\you\\.forgewire\\hub.token",
          token_source: "~/.forgewire",
          hub_candidates: [],
          warnings: []
        },
        { hubUrl: "http://fallback:8765", token: "fallback-token" }
      )
    ).toEqual({ hubUrl: "http://127.0.0.1:8765", token: "installed-token" });
  });

  it("keeps browser fallback token only when no installed token is present", () => {
    expect(
      hubConfigFromContext(
        {
          hub_url: "http://127.0.0.1:8765",
          hub_source: "gui.toml/default",
          token: null
        },
        { hubUrl: "http://fallback:8765", token: "browser-dev-token" }
      )
    ).toEqual({ hubUrl: "http://127.0.0.1:8765", token: "browser-dev-token" });
  });
});

function response(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body)
  } as Response;
}

import { describe, expect, it } from "vitest";
import {
  authBootstrapStatus,
  authLogin,
  disableAccount,
  dispatchDisabledReason,
  dispatchSignedTask,
  EMPTY_DISPATCH_DRAFT,
  HubApi,
  listAccounts,
  normalizeDispatchDraft,
  normalizeHubUrl,
  parseListField,
  revokeMembership,
  type DesktopTransport
} from "./api";
import { hubConfigFromContext } from "./storage";

class RecordingTransport implements DesktopTransport {
  readonly calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  private readonly responses = new Map<string, unknown[]>();

  respond(command: string, ...values: unknown[]) {
    this.responses.set(command, [...values]);
    return this;
  }

  async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push(args ? { command, args } : { command });
    const queue = this.responses.get(command) ?? [];
    if (queue.length === 0) throw new Error(`No recording response for ${command}`);
    const value = queue.shift();
    if (value instanceof Error) throw value;
    return value as T;
  }
}

const nativeSnapshot = (overrides: Record<string, unknown> = {}, errors: Record<string, string> = {}) => ({
  snapshot: {
    health: { status: "ok", version: "0.9.0", protocol_version: 4 },
    cluster: { backend: "rqlite" }, runners: [], agents: [], tasks: [], approvals: [],
    budget: null, cost: null, hosts: [], audit: { verified: true }, secrets: [], dispatchers: [],
    ...overrides
  },
  errors,
  restrictions: {},
  active_hub: "http://127.0.0.1:8765",
  refreshed_at_ms: 1_000
});

describe("native desktop transport", () => {
  it("loads dashboard data through an allowlisted Tauri command without a token argument", async () => {
    const transport = new RecordingTransport().respond("load_fabric_snapshot", nativeSnapshot());
    const result = await new HubApi(
      { hubUrl: "http://127.0.0.1:8765", tokenPresent: true },
      transport
    ).loadSnapshot();

    expect(result.sessionState).toBe("connected");
    expect(transport.calls).toEqual([{
      command: "load_fabric_snapshot",
      args: { hubUrl: "http://127.0.0.1:8765" }
    }]);
    expect(JSON.stringify(transport.calls)).not.toContain("token");
  });

  it("retains last-good resource data and marks a partial refresh", async () => {
    const transport = new RecordingTransport().respond(
      "load_fabric_snapshot",
      nativeSnapshot({ tasks: [{ id: 7, title: "kept", kind: "agent", status: "running" }] }),
      nativeSnapshot({ tasks: [] }, { tasks: "hub returned 503" })
    );
    const api = new HubApi({ hubUrl: "http://127.0.0.1:8765", tokenPresent: true }, transport);
    await api.loadSnapshot();
    const degraded = await api.loadSnapshot();

    expect(degraded.snapshot.tasks).toHaveLength(1);
    expect(degraded.snapshot.tasks[0]?.title).toBe("kept");
    expect(degraded.freshness.tasks?.source).toBe("last-good");
    expect(degraded.sessionState).toBe("partial");
  });

  it("keeps the session connected when a role-limited domain is restricted", async () => {
    const response = nativeSnapshot();
    response.restrictions = {
      secrets: "Requires reviewer role access. Current token roles: dispatcher, runner, observer."
    };
    const result = await new HubApi(
      { hubUrl: "http://127.0.0.1:8765", tokenPresent: true },
      new RecordingTransport().respond("load_fabric_snapshot", response)
    ).loadSnapshot();

    expect(result.sessionState).toBe("connected");
    expect(result.errors).toEqual({});
    expect(result.restrictions.secrets).toContain("reviewer");
  });

  it("still reports a genuinely rejected bearer as unauthorized", async () => {
    const result = await new HubApi(
      { hubUrl: "http://127.0.0.1:8765", tokenPresent: true },
      new RecordingTransport().respond(
        "load_fabric_snapshot",
        nativeSnapshot({}, { tasks: "hub returned 401: invalid bearer" })
      )
    ).loadSnapshot();

    expect(result.sessionState).toBe("unauthorized");
    expect(result.restrictions).toEqual({});
  });

  it("uses typed task stream and mutation commands", async () => {
    const transport = new RecordingTransport()
      .respond("load_task_stream", { lines: [{ seq: 4, line: "ready" }] })
      .respond("cancel_task", { id: 12, status: "cancelled" });
    const api = new HubApi({ hubUrl: "hub.local:8765", tokenPresent: true }, transport);
    expect((await api.taskStream(12, 3, 50)).lines[0]?.line).toBe("ready");
    await api.cancelTask(12);
    expect(transport.calls.map((call) => call.command)).toEqual(["load_task_stream", "cancel_task"]);
  });

  it("keeps domain detail and governed mutations on explicit native commands", async () => {
    const transport = new RecordingTransport()
      .respond("load_task_detail", { task: { id: 12, kind: "command", status: "done" } })
      .respond("load_approval_detail", { approval: { approval_id: "a-1", status: "pending" } })
      .respond("load_capability_detail", { kind: "tool", name: "inspect" })
      .respond("load_audit_day", { day: "2026-07-13", verified: true, events: [] })
      .respond("redispatch_task", { status: "queued", task_id: 13, message: "queued", body: {} })
      .respond("rename_fabric_entity", { status: "ok" })
      .respond("govern_secret", { status: "stored", name: "CI_TOKEN" });
    const api = new HubApi({ hubUrl: "http://hub:8765", tokenPresent: true }, transport);
    expect((await api.taskDetail(12)).kind).toBe("command");
    expect((await api.approvalDetail("a-1")).status).toBe("pending");
    await api.capabilityDetail("tool", "inspect");
    expect((await api.auditDay("2026-07-13")).verified).toBe(true);
    await api.redispatchTask(12);
    await api.renameEntity("runner", "r-1", "Builder");
    await api.governSecret("CI_TOKEN", "rotate", "transient-secret-value");
    expect(transport.calls.map((call) => call.command)).toEqual([
      "load_task_detail", "load_approval_detail", "load_capability_detail", "load_audit_day",
      "redispatch_task", "rename_fabric_entity", "govern_secret"
    ]);
    expect(transport.calls.at(-1)?.args).toEqual({
      request: { hub_url: "http://hub:8765", name: "CI_TOKEN", action: "rotate", value: "transient-secret-value" }
    });
  });

  it("keeps token removal and discovery pinning in native storage", async () => {
    const transport = new RecordingTransport()
      .respond("remove_hub_token", { present: false, path: "protected", source: "native" })
      .respond("set_hub_pin", { hub_pin: "http://hub:8765" });
    const api = new HubApi({ hubUrl: "http://hub:8765", tokenPresent: false }, transport);
    expect(await api.removeToken()).toMatchObject({ present: false });
    await api.setHubPin("http://hub:8765");
    expect(transport.calls.map((call) => call.command)).toEqual(["remove_hub_token", "set_hub_pin"]);
    expect(JSON.stringify(transport.calls)).not.toContain("bearer");
  });
});

describe("normalization and signed dispatch", () => {
  it("deduplicates the local alias at the URL boundary", () => {
    expect(normalizeHubUrl("localhost:8765///")).toBe("http://127.0.0.1:8765");
    expect(normalizeHubUrl(" https://fabric.example.test/ ")).toBe("https://fabric.example.test");
  });

  it("parses and normalizes agent and command briefs", () => {
    expect(parseListField("core/**, crates/**\n desktop/** ")).toEqual(["core/**", "crates/**", "desktop/**"]);
    const agent = normalizeDispatchDraft({
      ...EMPTY_DISPATCH_DRAFT, title: " Ship UI ", branch: " agent/ui ", baseCommit: " abc123 ",
      scopeGlobs: "desktop/**\ncrates/fabric-client/**", prompt: " Build it ",
      tags: "windows, ui", capabilities: "tauri\nrust"
    });
    expect(agent).toMatchObject({ title: "Ship UI", kind: "agent", branch: "agent/ui", scope_globs: ["desktop/**", "crates/fabric-client/**"] });
    const command = normalizeDispatchDraft({
      ...EMPTY_DISPATCH_DRAFT, kind: "command", title: "Smoke", prompt: "Run", branch: "agent/smoke",
      baseCommit: "origin/main", scopeGlobs: "desktop/**", command: "npm,test"
    });
    expect(command.command).toEqual(["npm", "test"]);
  });

  it("submits only hub URL and brief; token and private identity path remain native", async () => {
    const transport = new RecordingTransport().respond("dispatch_signed_task", { status: "queued", task_id: 9, message: "queued", body: {} });
    await dispatchSignedTask(
      { hubUrl: "http://hub:8765", tokenPresent: true },
      { id: "desktop", purpose: "dispatcher", public_key_hex: "public", path: "private-path" },
      { ...EMPTY_DISPATCH_DRAFT, title: "Work", prompt: "Do work", scopeGlobs: "desktop/**" },
      transport
    );
    const serialized = JSON.stringify(transport.calls[0]);
    expect(serialized).not.toContain("private-path");
    expect(serialized).not.toContain("token");
    expect(serialized).toContain("dispatch_signed_task");
  });

  it("fails closed when native credential or dispatcher identity is unavailable", () => {
    const draft = { ...EMPTY_DISPATCH_DRAFT, title: "Ready", prompt: "Do work", scopeGlobs: "desktop/**" };
    expect(dispatchDisabledReason(draft, null, { hubUrl: "http://hub:8765", tokenPresent: true })).toContain("identity");
    expect(dispatchDisabledReason(draft, { id: "d", purpose: "dispatcher", public_key_hex: "p", path: "x" }, { hubUrl: "http://hub:8765", tokenPresent: false })).toContain("token");
  });
});

describe("installed Fabric context", () => {
  it("hydrates only URL and token presence without exposing a credential value", () => {
    const config = hubConfigFromContext({
      hub_url: "http://127.0.0.1:8765", hub_source: "live hub discovery",
      token_present: true, token_path: "C:\\Users\\you\\.forgewire\\hub.token",
      token_source: "~/.forgewire", hub_candidates: [], warnings: []
    }, { hubUrl: "http://fallback:8765", tokenPresent: false });
    expect(config).toEqual({ hubUrl: "http://127.0.0.1:8765", tokenPresent: true });
    expect(JSON.stringify(config)).not.toContain("installed-token");
  });
});

// 114C.7 Slice 1: the walking-skeleton auth-route call, proving the
// AuthResult<T> shape end to end -- a real hub response (success or typed
// error) flows through as data, never as a thrown/rejected raw body.
describe("authBootstrapStatus", () => {
  it("passes the hub URL through and returns the data on success", async () => {
    const transport = new RecordingTransport().respond("auth_bootstrap_status", {
      ok: true,
      data: { bootstrap_open: true }
    });
    const result = await authBootstrapStatus("http://127.0.0.1:8765", transport);
    expect(result).toEqual({ ok: true, data: { bootstrap_open: true } });
    expect(transport.calls).toEqual([
      { command: "auth_bootstrap_status", args: { hubUrl: "http://127.0.0.1:8765" } }
    ]);
  });

  it("surfaces a typed error code and message without throwing", async () => {
    const transport = new RecordingTransport().respond("auth_bootstrap_status", {
      ok: false,
      code: "AuthServiceUnavailable",
      message: "the account service is temporarily unavailable"
    });
    const result = await authBootstrapStatus("http://127.0.0.1:8765", transport);
    expect(result.ok).toBe(false);
    expect(result.code).toBe("AuthServiceUnavailable");
    expect(result.data).toBeUndefined();
  });
});

// 114C.7 Slice 2: the remaining 23 free functions all share this exact
// shape (invoke a Tauri command, return AuthResult<T> unwrapped rather
// than thrown), proven once in Slice 1 -- these tests cover the
// dimensions that vary across them (a public route with no access secret,
// an authenticated route with one, query-parameter passthrough, and a
// typed-error response on a mutation), not every one of the 23 commands
// individually.
describe("authLogin", () => {
  it("passes username/password through with no access secret and returns the session on success", async () => {
    const transport = new RecordingTransport().respond("auth_login", {
      ok: true,
      data: {
        session_id: "sess-1", account_id: "acct-1", assurance_level: "aal1",
        access_secret: "a", refresh_secret: "r",
        idle_expires_at: "t1", absolute_expires_at: "t2"
      }
    });
    const result = await authLogin("http://127.0.0.1:8765", "operator1", "hunter2", "desktop", undefined, transport);
    expect(result.ok).toBe(true);
    expect(result.data?.session_id).toBe("sess-1");
    expect(transport.calls).toEqual([{
      command: "auth_login",
      args: {
        hubUrl: "http://127.0.0.1:8765", username: "operator1", password: "hunter2",
        clientKind: "desktop", clientLabel: undefined
      }
    }]);
  });
});

describe("listAccounts", () => {
  it("passes the access secret and pagination through as named args", async () => {
    const transport = new RecordingTransport().respond("list_accounts", { ok: true, data: { accounts: [] } });
    await listAccounts("http://127.0.0.1:8765", "human-session-secret", 25, 5, transport);
    expect(transport.calls).toEqual([{
      command: "list_accounts",
      args: { hubUrl: "http://127.0.0.1:8765", accessSecret: "human-session-secret", limit: 25, offset: 5 }
    }]);
  });

  it("defaults limit/offset when omitted", async () => {
    const transport = new RecordingTransport().respond("list_accounts", { ok: true, data: { accounts: [] } });
    await listAccounts("http://127.0.0.1:8765", "secret", undefined, undefined, transport);
    expect(transport.calls[0]?.args).toMatchObject({ limit: 200, offset: 0 });
  });
});

describe("revokeMembership and disableAccount", () => {
  it("revokeMembership passes account id and role as named args", async () => {
    const transport = new RecordingTransport().respond("revoke_membership", {
      ok: true, data: { account_id: "acct-1", roles: [] }
    });
    await revokeMembership("http://127.0.0.1:8765", "secret", "acct-1", "dispatcher", transport);
    expect(transport.calls).toEqual([{
      command: "revoke_membership",
      args: { hubUrl: "http://127.0.0.1:8765", accessSecret: "secret", accountId: "acct-1", role: "dispatcher" }
    }]);
  });

  it("disableAccount surfaces a typed error (e.g. last-admin protection) without throwing", async () => {
    const transport = new RecordingTransport().respond("disable_account", {
      ok: false, code: "LastAdministratorViolation", message: "cannot disable the last administrator"
    });
    const result = await disableAccount("http://127.0.0.1:8765", "secret", "acct-1", 3, transport);
    expect(result.ok).toBe(false);
    expect(result.code).toBe("LastAdministratorViolation");
    expect(transport.calls[0]?.args).toEqual({
      hubUrl: "http://127.0.0.1:8765", accessSecret: "secret", accountId: "acct-1", expectedRevision: 3
    });
  });
});

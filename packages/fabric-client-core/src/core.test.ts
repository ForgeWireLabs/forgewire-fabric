import { describe, expect, it } from "vitest";
import {
  COMMAND_IDS, DESKTOP_ROUTES, SESSION_STATES, VIEW_IDS, buildExplorerSections,
  COMMAND_DESCRIPTORS, REFERENCE_DOMAIN_FIXTURES, REFERENCE_FABRIC_FIXTURE,
  authoritiesFromWhoami, beginRefresh,
  dispatcherIdentityState, evaluateCommand, parseWhoami, resourceFreshnessToState,
  commandAvailability, completeRefresh, deriveSessionState, detectFabricFeatures,
  findCommandDescriptor, mergeLastGoodResource,
  isRefreshDue, normalizeFabricSnapshot, refreshDelay,
  sessionTransitionNotice,
  type CredentialStore, type IdentityStore, type PreferenceStore,
} from "./index.js";

class MemorySecrets implements CredentialStore {
  readonly values = new Map<string, string>();
  async get(id: string) { return this.values.get(id); }
  async set(id: string, value: string) { this.values.set(id, value); }
  async delete(id: string) { this.values.delete(id); }
}
class MemoryIdentities implements IdentityStore {
  readonly values = new Map<string, { id: string; purpose: "Dispatcher"; publicKey: string }>();
  async load(id: string) { return this.values.get(id); }
  async save(id: string, value: { id: string; purpose: "Dispatcher"; publicKey: string }) { this.values.set(id, value); }
}
class MemoryPreferences implements PreferenceStore {
  readonly values = new Map<string, unknown>();
  async get<T>(key: string) { return this.values.get(key) as T | undefined; }
  async set<T>(key: string, value: T) { this.values.set(key, value); }
  async delete(key: string) { this.values.delete(key); }
}

describe("canonical contracts", () => {
  it("freezes manifest and navigation counts", () => {
    expect(VIEW_IDS).toHaveLength(10); expect(new Set(VIEW_IDS).size).toBe(10);
    expect(COMMAND_IDS).toHaveLength(58); expect(new Set(COMMAND_IDS).size).toBe(58);
    expect(SESSION_STATES).toHaveLength(8); expect(DESKTOP_ROUTES).toHaveLength(16);
  });

  it("uses lightweight recording implementations without platform globals", async () => {
    const credentials = new MemorySecrets(); await credentials.set("primary", "protected"); expect(await credentials.get("primary")).toBe("protected");
    const identities = new MemoryIdentities(); await identities.save("primary", { id: "desktop", purpose: "Dispatcher", publicKey: "public" }); expect((await identities.load("primary"))?.purpose).toBe("Dispatcher");
    const preferences = new MemoryPreferences(); await preferences.set("refresh", 10); expect(await preferences.get("refresh")).toBe(10);
  });
});

describe("degradation and parity models", () => {
  it("detects the protocol-v4 feature floor without skin-specific payload checks", () => {
    expect([...detectFabricFeatures({ protocolVersion: 4 })]).toContain("signed_dispatch");
    expect([...detectFabricFeatures({ protocolVersion: 3, advertised: ["audit"] })]).toEqual(["audit"]);
  });

  it("retains last-good data and reports partial sessions", () => {
    const live = mergeLastGoodResource(undefined, { ok: true, data: ["runner"], observedAt: 10, receivedAt: 11, staleAfterMs: 100 });
    const failed = mergeLastGoodResource(live, { ok: false, error: "timeout", receivedAt: 20 });
    expect(failed.data).toEqual(["runner"]); expect(failed.freshness?.source).toBe("last-good");
    const recovered = mergeLastGoodResource(failed, { ok: true, data: ["runner", "runner-2"], observedAt: 30, receivedAt: 31, staleAfterMs: 100 });
    expect(recovered).toEqual({ data: ["runner", "runner-2"], freshness: { observedAt: 30, receivedAt: 31, staleAfterMs: 100, source: "live" } });
    expect(deriveSessionState({ configured: true, reachable: true, authorized: true, compatible: true, stale: false, failedResources: 1, successfulResources: 2 })).toBe("partial");
  });

  it("builds the nine stable explorer sections including empty states", () => {
    const sections = buildExplorerSections({ hub: { id: "h1", name: "Fabric", url: "https://hub", status: "ok" }, tasks: [{ id: "37", title: "agent work", kind: "agent", status: "claimed" }], secrets: [{ name: "registry", configured: true }] });
    expect(sections.map((section) => section.viewId)).toEqual(VIEW_IDS);
    expect(sections.flatMap((section) => section.nodes).map((node) => node.id)).toContain("tasks:agent");
    expect(JSON.stringify(sections)).not.toContain("secretValue");
  });

  it("normalizes raw Hub payloads into the nested VSIX agent and host hierarchy", () => {
    const snapshot = normalizeFabricSnapshot({
      health: { status: "ok", host: "hub-a", protocol_version: 4 },
      hosts: [{ hostname: "hub-a", roles: { hub_head: {} }, dispatchers: [{ dispatcher_id: "desktop", label: "Desktop on hub-a" }] }],
      runners: [{ runner_id: "runner-a", hostname: "hub-a", state: "online" }],
      agents: [{ runner_id: "agent-a", state: "online", mcp_manifest: { servers: [{ server_id: "tools", prompts: [{ name: "review" }], tools: [{ name: "exec" }], resources: [{ uri: "fabric://status" }] }] } }],
      tasks: [{
        id: 42, title: "provenance", kind: "agent", status: "done",
        dispatched_at: "2026-07-15T12:00:00Z", dispatched_by_user: "operator",
        dispatched_by_host: "desktop-a", dispatched_by_agent: "fabric-desktop",
        dispatcher_pubkey_fingerprint: "sha256:abc", claimed_by_runner: "runner-a",
        claimed_by_host: "hub-a", started_at: "2026-07-15T12:00:01Z",
        completed_at: "2026-07-15T12:00:03Z", wall_seconds: 2,
        runner_cpu_seconds: 1.5, policy_decisions: [{ stage: "dispatch", allowed: true }],
        approvals_required: 1, approvals_received: 1, exit_reason: "completed",
      }], approvals: [], secrets: [{ name: "registry", configured: true }],
    });
    const sections = buildExplorerSections(snapshot);
    const hosts = sections.find((section) => section.viewId === "forgewire.hosts");
    const agents = sections.find((section) => section.viewId === "forgewire.agents");
    expect(JSON.stringify(hosts)).toContain("hub_head");
    expect(JSON.stringify(hosts)).toContain("Desktop on hub-a");
    expect(JSON.stringify(agents)).toContain("MCP server");
    expect(JSON.stringify(agents)).toContain("Prompts");
    expect(JSON.stringify(agents)).toContain("exec");
    expect(snapshot.tasks?.[0]).toMatchObject({
      dispatchedAt: "2026-07-15T12:00:00Z",
      dispatchedByUser: "operator",
      claimedByRunner: "runner-a",
      wallSeconds: 2,
      runnerCpuSeconds: 1.5,
      approvalsRequired: 1,
      approvalsReceived: 1,
      exitReason: "completed",
    });
    expect(snapshot.tasks?.[0]?.policyDecisions).toHaveLength(1);
  });
});

describe("reference fixtures", () => {
  it("renders all ten domains and preserves task taxonomy and audit failure", () => {
    const sections = buildExplorerSections(REFERENCE_FABRIC_FIXTURE);
    expect(sections).toHaveLength(10);
    expect(sections.every((section) => section.nodes.length > 0)).toBe(true);
    const tasks = sections.find((section) => section.viewId === "forgewire.tasks");
    expect(tasks?.nodes.find((node) => node.id === "tasks:agent")?.children?.map((node) => node.id)).toContain("task:37");
    expect(tasks?.nodes.find((node) => node.id === "tasks:command")?.children?.map((node) => node.id)).toContain("task:38");
    expect(sections.find((section) => section.viewId === "forgewire.audit")?.nodes.find((node) => node.id === "audit:audit-bad")?.tone).toBe("danger");
  });

  it("provides a semantic fixture for every canonical view", () => {
    expect(Object.keys(REFERENCE_DOMAIN_FIXTURES)).toEqual(VIEW_IDS);
    for (const viewId of VIEW_IDS) {
      const fixture = REFERENCE_DOMAIN_FIXTURES[viewId];
      const section = buildExplorerSections(fixture.snapshot).find((candidate) => candidate.viewId === viewId);
      expect(section, viewId).toBeDefined();
      const serialized = JSON.stringify(section);
      for (const nodeId of fixture.expectedNodeIds) expect(serialized, `${viewId}:${nodeId}`).toContain(nodeId);
      for (const text of fixture.expectedText) expect(serialized, `${viewId}:${text}`).toContain(text);
    }
    expect(JSON.stringify(REFERENCE_DOMAIN_FIXTURES["forgewire.secrets"])).not.toMatch(/secretValue|bearer|privateKey/i);
  });
});

describe("command parity and fail-closed availability", () => {
  const live = {
    sessionState: "connected" as const,
    features: new Set(["disaster-recovery"]),
    authorities: new Set(["fabric.tasks.write", "fabric.approvals.write", "fabric.hosts.write", "fabric.hub.write", "fabric.connection.write", "fabric.dr.write"]),
    identity: "dispatcher" as const,
    freshness: "live" as const,
    platform: "desktop" as const,
  };

  it("classifies all commands and documents VS Code alternatives", () => {
    expect(COMMAND_DESCRIPTORS.map((item) => item.id)).toEqual(COMMAND_IDS);
    expect(COMMAND_DESCRIPTORS.filter((item) => item.parityClass === "core")).toHaveLength(20);
    expect(COMMAND_DESCRIPTORS.filter((item) => item.parityClass === "equivalent")).toHaveLength(32);
    expect(COMMAND_DESCRIPTORS.filter((item) => item.parityClass === "vscode_specific")).toHaveLength(6);
    expect(COMMAND_DESCRIPTORS.filter((item) => item.parityClass === "vscode_specific").every((item) => item.desktopAlternative !== undefined)).toBe(true);
    expect(COMMAND_DESCRIPTORS.every((item) => item.platforms.includes("vscode"))).toBe(true);
    expect(COMMAND_DESCRIPTORS.filter((item) => item.parityClass !== "vscode_specific").every((item) => item.platforms.includes("desktop"))).toBe(true);
  });

  it("has an enabled, fully-specified VSIX decision for every command", () => {
    for (const descriptor of COMMAND_DESCRIPTORS) {
      const availability = commandAvailability(descriptor, {
        sessionState: "connected",
        selection: descriptor.selectionKind === undefined ? undefined : {
          kind: descriptor.selectionKind,
          id: "fixture-selection",
          status: descriptor.selectionStatuses?.[0] ?? "online",
        },
        features: new Set(descriptor.feature === undefined ? [] : [descriptor.feature]),
        authorities: new Set(descriptor.authority === undefined ? [] : [descriptor.authority]),
        identity: "dispatcher",
        freshness: "live",
        platform: "vscode",
        humanRoles: new Set(descriptor.requiresHumanRole === undefined ? [] : [descriptor.requiresHumanRole]),
      });
      expect(availability, `${descriptor.id}: ${availability.reason ?? "enabled"}`).toEqual({ enabled: true });
    }
  });

  it("requires selection, supported status, authority and live freshness", () => {
    const cancel = findCommandDescriptor("forgewire.cancelTask");
    expect(commandAvailability(cancel, live).reason).toContain("Select a task");
    expect(commandAvailability(cancel, { ...live, selection: { kind: "task", id: "37", status: "succeeded" } }).reason).toContain("supported state");
    expect(commandAvailability(cancel, { ...live, selection: { kind: "task", id: "37", status: "running" }, authorities: new Set() }).reason).toContain("authority");
    expect(commandAvailability(cancel, { ...live, selection: { kind: "task", id: "37", status: "running" }, freshness: "stale" }).reason).toContain("Live");
    expect(commandAvailability(cancel, { ...live, selection: { kind: "task", id: "37", status: "running" } })).toEqual({ enabled: true });
  });

  it("fails closed for missing or wrong-purpose dispatcher identities", () => {
    const cancel = findCommandDescriptor("forgewire.cancelTask");
    const selection = { kind: "task" as const, id: "37", status: "running" };
    expect(commandAvailability(cancel, { ...live, selection, identity: "missing" }).reason).toContain("created or loaded");
    expect(commandAvailability(cancel, { ...live, selection, identity: "wrong-purpose" }).reason).toContain("wrong purpose");
    expect(commandAvailability(findCommandDescriptor("forgewire.showTask"), { ...live, selection, identity: "missing" })).toEqual({ enabled: true });
  });

  it("gates account-admin commands on a human account role, failing closed for automation credentials", () => {
    const create = findCommandDescriptor("forgewire.account.createAccount");
    // Feature satisfied so the human-role gate (not the feature gate) is what
    // this exercises; a fully-authorized *automation* context (every
    // fabric.*.write authority, live, connected) with no human session still
    // cannot create an account.
    const ctx = { ...live, features: new Set(["human_accounts"]) };
    expect(commandAvailability(create, ctx).reason).toContain("admin account role");
    // Explicit empty human roles: still closed.
    expect(commandAvailability(create, { ...ctx, humanRoles: new Set() }).reason).toContain("admin account role");
    // A human session carrying only a non-admin role: still closed.
    expect(commandAvailability(create, { ...ctx, humanRoles: new Set(["reviewer"]) }).reason).toContain("admin account role");
    // A signed-in admin: allowed.
    expect(commandAvailability(create, { ...ctx, humanRoles: new Set(["reviewer", "admin"]) })).toEqual({ enabled: true });
  });

  it("gates feature-dependent commands while retaining supported recovery actions", () => {
    const stream = findCommandDescriptor("forgewire.streamTask");
    expect(commandAvailability(stream, { ...live, features: new Set(), selection: { kind: "task", id: "37", status: "running" } }).reason).toContain("task_stream");
    expect(commandAvailability(findCommandDescriptor("forgewire.refresh"), { ...live, sessionState: "offline", freshness: "stale" })).toEqual({ enabled: true });
  });

  it("keeps offline last-good data read-only and names desktop alternatives", () => {
    expect(commandAvailability(findCommandDescriptor("forgewire.showTask"), { ...live, sessionState: "offline", selection: { kind: "task", id: "37", status: "running" }, freshness: "stale" }).reason).toContain("last-good");
    expect(commandAvailability(findCommandDescriptor("forgewire.installCli"), live).reason).toContain("installer");
    expect(commandAvailability(findCommandDescriptor("forgewire.connectHub"), { ...live, sessionState: "misconfigured", freshness: "missing" })).toEqual({ enabled: true });
    expect(commandAvailability(findCommandDescriptor("forgewire.setToken"), { ...live, sessionState: "unauthorized", freshness: "missing", authorities: new Set() })).toEqual({ enabled: true });
  });
});

describe("command context derivation helpers", () => {
  it("reduces a dispatcher-identity purpose to the three-state enum, failing closed", () => {
    expect(dispatcherIdentityState("Dispatcher")).toBe("dispatcher");
    expect(dispatcherIdentityState("  dispatcher ")).toBe("dispatcher");
    expect(dispatcherIdentityState(undefined)).toBe("missing");
    expect(dispatcherIdentityState(null)).toBe("missing");
    expect(dispatcherIdentityState("")).toBe("missing");
    expect(dispatcherIdentityState("Runner")).toBe("wrong-purpose");
  });

  it("reshapes per-resource freshness into the command-context tri-state", () => {
    const now = 1_000;
    expect(resourceFreshnessToState(undefined, now)).toBe("missing");
    expect(resourceFreshnessToState({ observedAt: 990, receivedAt: 990, staleAfterMs: 100, source: "last-good" }, now)).toBe("stale");
    expect(resourceFreshnessToState({ observedAt: 990, receivedAt: 990, staleAfterMs: 100, source: "live" }, now)).toBe("live");
    expect(resourceFreshnessToState({ observedAt: 800, receivedAt: 800, staleAfterMs: 100, source: "live" }, now)).toBe("stale");
  });

  it("parses a whoami payload defensively and fails closed on malformed input", () => {
    const parsed = parseWhoami({ subject: "token-1", roles: ["dispatcher", 7], authorities: ["fabric.tasks.write"], legacy_compat: false, human_principal: null });
    expect(parsed).toEqual({ subject: "token-1", roles: ["dispatcher"], authorities: ["fabric.tasks.write"], legacyCompat: false, humanPrincipal: null });
    expect([...authoritiesFromWhoami({ authorities: ["fabric.hub.write", "fabric.tasks.write"] })]).toEqual(["fabric.hub.write", "fabric.tasks.write"]);
    expect(parseWhoami(null)).toEqual({ subject: "", roles: [], authorities: [], legacyCompat: false, humanPrincipal: null });
    expect([...authoritiesFromWhoami("garbage")]).toEqual([]);
  });

  it("evaluates command availability by id through the shared entry point", () => {
    const permissive = {
      sessionState: "connected" as const,
      selection: { kind: "task" as const, id: "37", status: "running" },
      features: new Set<string>(),
      authorities: new Set(["fabric.tasks.write"]),
      identity: "dispatcher" as const,
      freshness: "live" as const,
      platform: "desktop" as const,
    };
    expect(evaluateCommand("forgewire.cancelTask", permissive)).toEqual({ enabled: true });
    expect(evaluateCommand("forgewire.cancelTask", { ...permissive, authorities: new Set() }).enabled).toBe(false);
    expect(() => evaluateCommand("forgewire.notACommand" as never, permissive)).toThrow();
  });
});

describe("bounded refresh and recovery policies", () => {
  it("uses background cadence, capped backoff and single-flight state", () => {
    const policy = { foregroundMs: 2_000, backgroundMs: 10_000, maximumBackoffMs: 60_000, backoffMultiplier: 2 };
    expect(refreshDelay(policy, 2, "foreground")).toBe(8_000);
    expect(refreshDelay(policy, 9, "background")).toBe(60_000);
    const started = beginRefresh({ inFlight: false, consecutiveFailures: 0 }, 100);
    expect(beginRefresh(started, 101)).toBe(started);
    const failed = completeRefresh(started, false, 110);
    expect(completeRefresh(beginRefresh(failed, 120), true, 130).consecutiveFailures).toBe(0);
    expect(isRefreshDue({ ...failed, lastCompletedAt: 110 }, 4_109, policy, "foreground")).toBe(false);
    expect(isRefreshDue({ ...failed, lastCompletedAt: 110 }, 4_110, policy, "foreground")).toBe(true);
    expect(isRefreshDue({ ...failed, inFlight: true, lastCompletedAt: 110 }, 60_110, policy, "background")).toBe(false);
    expect(() => refreshDelay({ ...policy, backgroundMs: 1_000 }, 0, "foreground")).toThrow("ordered");
  });

  it("labels outage, degradation and recovery", () => {
    expect(sessionTransitionNotice("connected", "offline")?.kind).toBe("offline");
    expect(sessionTransitionNotice("connected", "partial")?.kind).toBe("degraded");
    expect(sessionTransitionNotice("stale", "connected")?.kind).toBe("recovered");
    expect(sessionTransitionNotice("offline", "partial")?.kind).toBe("degraded");
    expect(sessionTransitionNotice("partial", "connected")?.kind).toBe("recovered");
  });

  it("distinguishes stale, partial, offline, and recovered live state", () => {
    const base = { configured: true, authorized: true, compatible: true, reachable: true, stale: false, failedResources: 0, successfulResources: 3 };
    expect(deriveSessionState({ ...base, stale: true })).toBe("stale");
    expect(deriveSessionState({ ...base, stale: true, failedResources: 1 })).toBe("partial");
    expect(deriveSessionState({ ...base, reachable: false, stale: true, failedResources: 3, successfulResources: 0 })).toBe("offline");
    expect(deriveSessionState(base)).toBe("connected");
  });
});

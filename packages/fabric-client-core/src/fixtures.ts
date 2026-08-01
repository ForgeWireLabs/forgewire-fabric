import type { FabricSnapshot } from "./contracts.js";
import type { ViewId } from "./constants.js";

/** Canonical non-secret fixture shared by both renderers for nine-domain parity. */
export const REFERENCE_FABRIC_FIXTURE: FabricSnapshot = {
  hub: { id: "hub-primary", name: "ClusterHealth Test", url: "https://fabric.example:8765", status: "ok", uptime: "23h 53m", version: "0.9.0", protocol: "v4" },
  hosts: [
    { id: "desktop-a", name: "desktop-a", status: "online", roles: ["hub", "runner"], dispatchers: [{ id: "dispatcher-a", name: "Desktop on desktop-a", status: "online" }] },
    { id: "desktop-b", name: "desktop-b", status: "online", roles: ["runner"] },
  ],
  runners: [
    { id: "runner-a", name: "desktop-a", hostId: "desktop-a", status: "online", local: true },
    { id: "runner-b", name: "desktop-b", hostId: "desktop-b", status: "draining" },
  ],
  tasks: [
    { id: "37", title: "Agent prompt", kind: "agent", status: "claimed" },
    { id: "38", title: "Loom command", kind: "command", status: "running" },
    { id: "36", title: "Completed command", kind: "command", status: "succeeded" },
  ],
  agents: [{ id: "agent-a", name: "desktop-a agent", status: "online", capabilities: ["prompt", "tools", "resources"] }],
  approvals: [
    { id: "approval-a", title: "Allow tool execution", status: "pending", envelopeHash: "sha256:approval-a" },
    { id: "approval-b", title: "Prior decision", status: "approved", envelopeHash: "sha256:approval-b" },
  ],
  cost: { today: 1.25, week: 8.75, currency: "USD", budget: 25 },
  audit: [
    { id: "audit-good", kind: "task.completed", timestamp: "2026-07-13T12:00:00Z", verified: true },
    { id: "audit-bad", kind: "chain.invalid", timestamp: "2026-07-13T12:01:00Z", verified: false },
  ],
  secrets: [{ name: "artifact-registry", configured: true, updatedAt: "2026-07-13T11:00:00Z" }],
  settings: [
    { id: "forgewire.hubUrl", label: "Hub URL", category: "connection", valueSummary: "fabric.example:8765" },
    { id: "forgewire.refreshIntervalSeconds", label: "Refresh interval", category: "tasks", valueSummary: "10 seconds" },
  ],
  account: {
    me: { accountId: "acct-fixture", username: "operator1", displayName: "Operator One", status: "active", roles: ["dispatcher", "reviewer"], revision: 3 },
    sessions: [
      { sessionId: "sess-fixture-a", accountId: "acct-fixture", clientKind: "vsix", clientLabel: "VS Code on desktop-a", assuranceLevel: "aal1", authenticatedAt: "2026-07-17T12:00:00Z", idleExpiresAt: "2026-07-17T13:00:00Z", absoluteExpiresAt: "2026-07-18T12:00:00Z", current: true },
      { sessionId: "sess-fixture-b", accountId: "acct-fixture", clientKind: "desktop", assuranceLevel: "aal2", authenticatedAt: "2026-07-16T09:00:00Z", idleExpiresAt: "2026-07-17T09:00:00Z", absoluteExpiresAt: "2026-07-17T09:00:00Z", current: false },
    ],
  },
};

export interface DomainFixture {
  readonly viewId: ViewId;
  readonly snapshot: FabricSnapshot;
  readonly expectedNodeIds: readonly string[];
  readonly expectedText: readonly string[];
}

/**
 * Per-domain slices used by both skins. These fixtures intentionally contain
 * no credential material: the Secrets slice is metadata-only, while the Audit
 * slice includes a failed verification state that must remain explicit.
 */
export const REFERENCE_DOMAIN_FIXTURES: Readonly<Record<ViewId, DomainFixture>> = {
  "forgewire.hub": {
    viewId: "forgewire.hub",
    snapshot: { hub: REFERENCE_FABRIC_FIXTURE.hub! },
    expectedNodeIds: ["hub:hub-primary:name", "hub:hub-primary:status", "hub:hub-primary:uptime", "hub:hub-primary:version", "hub:hub-primary:protocol"],
    expectedText: ["ClusterHealth Test", "23h 53m", "0.9.0", "v4"],
  },
  "forgewire.hosts": {
    viewId: "forgewire.hosts",
    snapshot: { hosts: REFERENCE_FABRIC_FIXTURE.hosts!, runners: REFERENCE_FABRIC_FIXTURE.runners! },
    expectedNodeIds: ["hosts:fabric", "host:desktop-a", "runner:runner-a", "dispatcher:dispatcher-a", "host:desktop-b", "runner:runner-b", "hosts:loom"],
    expectedText: ["Fabric", "Loom", "desktop-a", "Desktop on desktop-a", "desktop-b", "draining"],
  },
  "forgewire.tasks": {
    viewId: "forgewire.tasks",
    snapshot: { tasks: REFERENCE_FABRIC_FIXTURE.tasks! },
    expectedNodeIds: ["tasks:agent", "task:37", "tasks:command", "task:38", "tasks:history", "task-history:36"],
    expectedText: ["Agent tasks", "Command tasks", "History", "claimed", "running", "succeeded"],
  },
  "forgewire.agents": {
    viewId: "forgewire.agents",
    snapshot: {
      agents: [{
        id: "agent-a",
        name: "desktop-a agent",
        status: "online",
        servers: [{
          id: "mcp-a",
          name: "Forge tools",
          capabilities: [
            { kind: "prompt", name: "review" },
            { kind: "tool", name: "run" },
            { kind: "resource", name: "fabric://status" },
            { kind: "skill", name: "triage" },
          ],
        }],
      }],
    },
    expectedNodeIds: ["agent:agent-a", "agent:agent-a:server:mcp-a", "agent:agent-a:server:mcp-a:prompt:review", "agent:agent-a:server:mcp-a:tool:run", "agent:agent-a:server:mcp-a:resource:fabric://status", "agent:agent-a:server:mcp-a:skill:triage"],
    expectedText: ["desktop-a agent", "Forge tools", "Prompts", "Tools", "Resources", "Skills"],
  },
  "forgewire.approvals": {
    viewId: "forgewire.approvals",
    snapshot: { approvals: REFERENCE_FABRIC_FIXTURE.approvals! },
    expectedNodeIds: ["approvals:pending", "approval:approval-a", "approvals:deferred", "approvals:history", "approval:approval-b"],
    expectedText: ["Pending", "Snoozed", "History", "sha256:approval-a"],
  },
  "forgewire.cost": {
    viewId: "forgewire.cost",
    snapshot: { cost: REFERENCE_FABRIC_FIXTURE.cost! },
    expectedNodeIds: ["cost:today", "cost:week", "cost:budget"],
    expectedText: ["USD 1.25", "USD 8.75", "USD 25.00"],
  },
  "forgewire.audit": {
    viewId: "forgewire.audit",
    snapshot: { audit: REFERENCE_FABRIC_FIXTURE.audit! },
    expectedNodeIds: ["audit:audit-good", "audit:audit-bad"],
    expectedText: ["task.completed", "chain.invalid", "2026-07-13T12:01:00Z"],
  },
  "forgewire.secrets": {
    viewId: "forgewire.secrets",
    snapshot: { secrets: REFERENCE_FABRIC_FIXTURE.secrets! },
    expectedNodeIds: ["secret:artifact-registry"],
    expectedText: ["artifact-registry", "configured"],
  },
  "forgewire.settings": {
    viewId: "forgewire.settings",
    snapshot: { settings: REFERENCE_FABRIC_FIXTURE.settings! },
    expectedNodeIds: ["settings:connection", "setting:forgewire.hubUrl", "settings:tasks", "setting:forgewire.refreshIntervalSeconds"],
    expectedText: ["Hub URL", "fabric.example:8765", "Refresh interval", "10 seconds"],
  },
  "forgewire.account": {
    viewId: "forgewire.account",
    snapshot: { account: REFERENCE_FABRIC_FIXTURE.account! },
    expectedNodeIds: ["account:acct-fixture:profile", "account:acct-fixture:status", "account:acct-fixture:roles", "account:sessions", "account:session:sess-fixture-a", "account:session:sess-fixture-b"],
    expectedText: ["Operator One", "operator1", "active", "dispatcher, reviewer", "VS Code on desktop-a", "current", "aal2"],
  },
};

import type { EmptyState, FabricSnapshot, StatusIcon, StatusTone } from "./contracts.js";
import type { ViewId } from "./constants.js";

export interface ExplorerNode {
  readonly id: string;
  readonly label: string;
  readonly description?: string;
  readonly icon: StatusIcon;
  readonly tone?: StatusTone;
  readonly children?: readonly ExplorerNode[];
  readonly emptyState?: EmptyState;
  readonly route?: string;
}
export interface ExplorerSection { readonly viewId: ViewId; readonly label: string; readonly nodes: readonly ExplorerNode[]; readonly emptyState?: EmptyState; }

const empty = (title: string, description: string, actionId?: string): EmptyState =>
  actionId === undefined ? { title, description } : { title, description, actionId };
const statusTone = (status: string): StatusTone => status === "online" || status === "ok" || status === "healthy" ? "success" : status === "offline" || status === "failed" ? "danger" : "warning";

export function buildHubSection(snapshot: FabricSnapshot): ExplorerSection {
  const hub = snapshot.hub;
  if (hub === undefined) return { viewId: "forgewire.hub", label: "Hub", nodes: [], emptyState: empty("No hub connection", "Connect to a Hub to inspect Fabric.", "forgewire.connectHub") };
  return { viewId: "forgewire.hub", label: "Hub", nodes: [
    { id: `hub:${hub.id}:name`, label: hub.name, description: hub.url, icon: "hub", tone: statusTone(hub.status), route: `/hub/${hub.id}` },
    { id: `hub:${hub.id}:status`, label: "Status", description: hub.status, icon: hub.status === "ok" ? "online" : "warning", tone: statusTone(hub.status) },
    ...(hub.uptime === undefined ? [] : [{ id: `hub:${hub.id}:uptime`, label: "Uptime", description: hub.uptime, icon: "hub" as const }]),
    ...(hub.version === undefined ? [] : [{ id: `hub:${hub.id}:version`, label: "Hub version", description: hub.version, icon: "hub" as const }]),
    ...(hub.protocol === undefined ? [] : [{ id: `hub:${hub.id}:protocol`, label: "Protocol", description: hub.protocol, icon: "hub" as const }]),
  ] };
}

export function buildHostsSection(snapshot: FabricSnapshot): ExplorerSection {
  const hosts = snapshot.hosts ?? [];
  const runners = snapshot.runners ?? [];
  const hostNodes = hosts.map((host) => ({
    id: `host:${host.id}`, label: host.name, description: host.status,
    icon: "host" as const, tone: statusTone(host.status), route: `/hosts/${host.id}`,
    children: [
      ...(host.roles ?? []).map((role) => ({ id: `host:${host.id}:role:${role}`, label: role, description: "role", icon: "setting" as const, route: `/hosts/${host.id}` })),
      ...runners.filter((runner) => runner.hostId?.toLowerCase() === host.id.toLowerCase()).map((runner) => ({ id: `runner:${runner.id}`, label: runner.name, description: runner.status, icon: "runner" as const, tone: statusTone(runner.status), route: `/runners/${runner.id}` })),
      ...(host.dispatchers ?? []).map((dispatcher) => ({ id: `dispatcher:${dispatcher.id}`, label: dispatcher.name, ...(dispatcher.status === undefined ? {} : { description: dispatcher.status }), icon: "setting" as const, route: `/hosts/${host.id}` })),
    ],
  }));
  return { viewId: "forgewire.hosts", label: "Hosts", nodes: [
    { id: "hosts:fabric", label: "Fabric", icon: "host", children: hostNodes },
    { id: "hosts:loom", label: "Loom", description: "command compute", icon: "host", children: [] },
  ], ...(hosts.length === 0 ? { emptyState: empty("No Fabric hosts", "No hosts are advertising Fabric roles.") } : {}) };
}

export function buildTasksSection(snapshot: FabricSnapshot): ExplorerSection {
  const tasks = snapshot.tasks ?? [];
  const make = (kind: "agent" | "command", terminal: boolean) => tasks.filter((task) => task.kind === kind && (["succeeded", "failed", "cancelled", "timed_out"].includes(task.status)) === terminal).map((task) => ({ id: `task:${task.id}`, label: task.title, description: task.status, icon: "task" as const, tone: statusTone(task.status), route: `/tasks/${task.id}` }));
  const agent = make("agent", false); const command = make("command", false); const history = tasks.filter((task) => ["succeeded", "failed", "cancelled", "timed_out"].includes(task.status)).map((task) => ({ id: `task-history:${task.id}`, label: task.title, description: task.status, icon: "task" as const, tone: statusTone(task.status), route: `/tasks/${task.id}` }));
  return { viewId: "forgewire.tasks", label: "Tasks", nodes: [
    { id: "tasks:agent", label: "Agent tasks", description: String(agent.length), icon: "agent", children: agent, ...(agent.length === 0 ? { emptyState: empty("No agent tasks", "No agent tasks are queued or running.") } : {}) },
    { id: "tasks:command", label: "Command tasks", description: String(command.length), icon: "task", children: command, ...(command.length === 0 ? { emptyState: empty("No command tasks", "No command tasks are queued or running.") } : {}) },
    { id: "tasks:history", label: "History", description: String(history.length), icon: "audit", children: history },
  ] };
}

export function buildAgentsSection(snapshot: FabricSnapshot): ExplorerSection {
  const agents = snapshot.agents ?? [];
  return { viewId: "forgewire.agents", label: "Agents", nodes: agents.map((agent) => ({
    id: `agent:${agent.id}`, label: agent.name, description: agent.status, icon: "agent",
    tone: statusTone(agent.status), route: `/agents/${agent.id}`,
    children: (agent.servers ?? []).map((server) => ({
      id: `agent:${agent.id}:server:${server.id}`, label: server.name, description: "MCP server", icon: "setting",
      children: (["prompt", "tool", "resource", "skill"] as const).map((kind) => {
        const entries = server.capabilities.filter((capability) => capability.kind === kind);
        return {
          id: `agent:${agent.id}:server:${server.id}:${kind}`,
          label: `${kind[0]?.toUpperCase()}${kind.slice(1)}s`, description: String(entries.length), icon: "setting" as const,
          children: entries.map((capability) => ({
            id: `agent:${agent.id}:server:${server.id}:${kind}:${capability.name}`,
            label: capability.name, icon: "setting" as const,
            route: `/agents/${agent.id}/capabilities/${kind}/${encodeURIComponent(capability.name)}`,
          })),
        };
      }),
    })),
  })), ...(agents.length === 0 ? { emptyState: empty("No agents", "No Fabric agents are advertising capabilities.") } : {}) };
}

export function buildApprovalsSection(snapshot: FabricSnapshot): ExplorerSection {
  const approvals = snapshot.approvals ?? [];
  const group = (status: string) => approvals.filter((approval) => approval.status === status).map((approval) => ({ id: `approval:${approval.id}`, label: approval.title, ...(approval.envelopeHash === undefined ? {} : { description: approval.envelopeHash }), icon: "approval" as const, route: `/approvals/${approval.id}` }));
  return { viewId: "forgewire.approvals", label: "Approvals", nodes: [
    { id: "approvals:pending", label: "Pending", icon: "approval", children: group("pending") },
    { id: "approvals:deferred", label: "Snoozed", icon: "approval", children: group("deferred") },
    { id: "approvals:history", label: "History", icon: "audit", children: approvals.filter((item) => item.status !== "pending" && item.status !== "deferred").map((item) => ({ id: `approval:${item.id}`, label: item.title, description: item.status, icon: "approval", route: `/approvals/${item.id}` })) },
  ], ...(approvals.length === 0 ? { emptyState: empty("No pending approvals", "The approval queue is clear.") } : {}) };
}

export function buildCostSection(snapshot: FabricSnapshot): ExplorerSection {
  const cost = snapshot.cost;
  if (cost === undefined) return { viewId: "forgewire.cost", label: "Cost", nodes: [], emptyState: empty("Cost unavailable", "The Hub did not return cost information.", "forgewire.cost.refresh") };
  return { viewId: "forgewire.cost", label: "Cost", nodes: [
    { id: "cost:today", label: "Today", description: `${cost.currency} ${cost.today.toFixed(2)}`, icon: "cost", route: "/cost" },
    { id: "cost:week", label: "This week", description: `${cost.currency} ${cost.week.toFixed(2)}`, icon: "cost", route: "/cost" },
    ...(cost.budget === undefined ? [] : [{ id: "cost:budget", label: "Budget", description: `${cost.currency} ${cost.budget.toFixed(2)}`, icon: "cost" as const, route: "/cost" }]),
  ] };
}

export function buildAuditSection(snapshot: FabricSnapshot): ExplorerSection {
  const audit = snapshot.audit ?? [];
  return { viewId: "forgewire.audit", label: "Audit Log", nodes: audit.map((event) => ({ id: `audit:${event.id}`, label: event.kind, description: event.timestamp, icon: event.verified === false ? "error" : "audit", tone: event.verified === false ? "danger" : "neutral", route: "/audit" })), ...(audit.length === 0 ? { emptyState: empty("No audit events", "No audit events were returned by the Hub.") } : {}) };
}

export function buildSecretsSection(snapshot: FabricSnapshot): ExplorerSection {
  const secrets = snapshot.secrets ?? [];
  return { viewId: "forgewire.secrets", label: "Secrets", nodes: secrets.map((secret) => ({ id: `secret:${secret.name}`, label: secret.name, description: secret.configured ? "configured" : "not configured", icon: "secret", tone: secret.configured ? "success" : "warning", route: "/secrets" })), ...(secrets.length === 0 ? { emptyState: empty("No secret metadata", "Secret values are never displayed.") } : {}) };
}

export function buildSettingsSection(snapshot: FabricSnapshot): ExplorerSection {
  const settings = snapshot.settings ?? [];
  const categories = [...new Set(settings.map((setting) => setting.category))];
  return { viewId: "forgewire.settings", label: "Settings", nodes: categories.map((category) => ({ id: `settings:${category}`, label: category, icon: "setting", route: `/settings/${category}`, children: settings.filter((setting) => setting.category === category).map((setting) => ({ id: `setting:${setting.id}`, label: setting.label, ...(setting.valueSummary === undefined ? {} : { description: setting.valueSummary }), icon: "setting", route: `/settings/${category}` })) })) };
}

/** 114C.7 Slice 3: see `AccountSnapshotDto`'s doc comment for why this
 *  section, uniquely among these, treats "no data" as a normal signed-out
 *  state rather than a connection failure. */
export function buildAccountSection(snapshot: FabricSnapshot): ExplorerSection {
  const me = snapshot.account?.me;
  if (me === undefined) {
    return {
      viewId: "forgewire.account", label: "Account", nodes: [],
      emptyState: empty("Not signed in", "Sign in to manage sessions, passkeys, and recovery.", "forgewire.auth.signInWithPasskey"),
    };
  }
  const sessions = snapshot.account?.sessions ?? [];
  return { viewId: "forgewire.account", label: "Account", nodes: [
    { id: `account:${me.accountId}:profile`, label: me.displayName, description: me.username, icon: "account", route: "/account" },
    { id: `account:${me.accountId}:status`, label: "Status", description: me.status, icon: "account", tone: statusTone(me.status), route: "/account" },
    { id: `account:${me.accountId}:roles`, label: "Roles", description: me.roles.join(", "), icon: "account", route: "/account" },
    { id: "account:sessions", label: "Sessions", description: String(sessions.length), icon: "account", route: "/account", children: sessions.map((session) => ({
      id: `account:session:${session.sessionId}`, label: session.clientLabel ?? session.clientKind,
      description: session.current ? "current" : session.assuranceLevel, icon: "account" as const,
      tone: session.current ? "success" : "neutral", route: "/account",
    })) },
  ] };
}

export function buildExplorerSections(snapshot: FabricSnapshot): readonly ExplorerSection[] {
  return [buildHubSection(snapshot), buildHostsSection(snapshot), buildTasksSection(snapshot), buildAgentsSection(snapshot), buildApprovalsSection(snapshot), buildCostSection(snapshot), buildAuditSection(snapshot), buildSecretsSection(snapshot), buildSettingsSection(snapshot), buildAccountSection(snapshot)];
}

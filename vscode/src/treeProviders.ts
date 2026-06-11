import * as os from "os";
import * as vscode from "vscode";
import {
  AgentInfo,
  ApprovalInfo,
  AuditEvent,
  ClusterHealth,
  DispatcherInfo,
  HubClient,
  HostRoleName,
  HostRoleSummary,
  HostSummary,
  McpManifestServer,
  RunnerInfo,
  SecretInfo,
  TaskInfo,
} from "./hubClient";

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

export interface HubNode {
  key: string;
  label: string;
  description?: string;
  icon?: string;
  tooltip?: string;
  command?: vscode.Command;
  contextValue?: string;
}

export interface ProbeInfo {
  active: HubClient | undefined;
  activeUrl: string | undefined;
  pinned: boolean;
  probes: Array<{ url: string; label?: string; priority?: number; ok: boolean; uptime?: number; error?: string }>;
}

export class HubProvider implements vscode.TreeDataProvider<HubNode> {
  private readonly _onDidChange = new vscode.EventEmitter<HubNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(
    private readonly client: () => HubClient | undefined,
    private readonly probe: () => ProbeInfo | undefined = () => undefined
  ) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: HubNode): Promise<HubNode[]> {
    if (element) {
      return [];
    }
    const c = this.client();
    const cfg = vscode.workspace.getConfiguration("forgewire");
    let hubName = (cfg.get<string>("hubName") ?? "").trim();

    const renameCmd: vscode.Command = {
      command: "forgewire.renameHub",
      title: "Rename Hub",
    };

    if (!c) {
      return [
        {
          key: "name",
          label: "Name",
          description: hubName || "(unset)",
          icon: "tag",
          tooltip: "Click to set a friendly hub name.",
          command: renameCmd,
          contextValue: "hub.name",
        },
        {
          key: "state",
          label: "Not connected",
          icon: "debug-disconnect",
          description: "click to connect",
          command: {
            command: "forgewire.connectHub",
            title: "Connect to Hub",
          },
        },
      ];
    }

    const nodes: HubNode[] = [];

    try {
      const labels = await c.getLabels();
      if (labels.hub_name) {
        hubName = labels.hub_name;
      }
    } catch {
      /* ignore */
    }

    nodes.push(
      {
        key: "name",
        label: "Name",
        description: hubName || "(unset)",
        icon: "tag",
        tooltip: "Click to rename this hub fabric-wide.",
        command: renameCmd,
        contextValue: "hub.name",
      },
      {
        key: "url",
        label: "Active hub",
        description: c.url,
        icon: "link",
        tooltip: new vscode.MarkdownString(
          `Currently dispatching to **${c.url}**.\n\n` +
            (this.probe()?.pinned
              ? "_Pinned manually -- failover is disabled until you unpin._"
              : "_Auto-selected by probing the candidate list in priority order._")
        ).value,
        contextValue: this.probe()?.pinned ? "hub.url.pinned" : "hub.url.auto",
      }
    );

    // Join token — click to copy for adding new nodes. Shown masked.
    {
      const tok = (cfg.get<string>("hubToken") ?? "").trim();
      const masked =
        tok.length > 14 ? `${tok.slice(0, 6)}…${tok.slice(-4)}` : tok ? "••••••" : "(not set)";
      nodes.push({
        key: "jointoken",
        label: "Join token",
        description: `${masked}  — click to copy`,
        icon: "key",
        tooltip:
          "Copy the cluster join token to add a new node. On the new machine run install-fabric.ps1 -Token <paste>.",
        command: { command: "forgewire.copyJoinToken", title: "Copy Join Token" },
        contextValue: "hub.jointoken",
      });
    }

    // Failover candidate list (if configured) so the user can see at a glance
    // which peers are reachable and which one was elected.
    const probe = this.probe();
    if (probe && probe.probes.length > 1) {
      nodes.push({
        key: "candidates",
        label: probe.pinned ? "Pinned" : "Failover candidates",
        description: `${probe.probes.filter((p) => p.ok).length} / ${probe.probes.length} reachable`,
        icon: probe.pinned ? "pin" : "list-tree",
        tooltip: new vscode.MarkdownString(
          probe.probes
            .map((p) => {
              const tag = p.ok ? `up ${formatUptime(p.uptime)}` : `down: ${(p.error ?? "").slice(0, 80)}`;
              const star = p.url === probe.activeUrl ? " **(active)**" : "";
              const lab = p.label ? ` _${p.label}_` : "";
              return `- \`${p.url}\` (prio ${p.priority ?? 100})${lab} \u2014 ${tag}${star}`;
            })
            .join("\n")
        ).value,
        contextValue: "hub.candidates",
      });
    }

    try {
      const h = await c.healthz();
      const runners = await c.listRunners().catch(() => [] as RunnerInfo[]);
      const online = runners.filter((r) => r.state === "online").length;
      nodes.push(
        {
          key: "status",
          label: "Status",
          description: h.status,
          icon: h.status === "ok" ? "pass-filled" : "warning",
        },
        {
          key: "uptime",
          label: "Uptime",
          description: formatUptime(h.uptime_seconds),
          icon: "watch",
        },
        {
          key: "version",
          label: "Hub version",
          description: `${h.version}${(h as any).rust_hub ? " ⚡" : ""}`,
          icon: "versions",
          tooltip: (h as any).rust_hub
            ? `Native Rust hub · backend: ${(h as any).backend ?? "rqlite"} · sidecar_integrity: ${(h as any).sidecar_integrity ?? "unknown"}`
            : `Python hub`,
        },
        {
          key: "protocol",
          label: "Protocol",
          description: `v${h.protocol_version}`,
          icon: "symbol-numeric",
        },
        {
          key: "runners",
          label: "Runners",
          description: `${online} online / ${runners.length} total`,
          icon: "server-environment",
          command: { command: "forgewire.refresh", title: "Refresh" },
        }
      );
    } catch (err) {
      nodes.push({
        key: "status",
        label: "Status",
        description: "unreachable",
        icon: "error",
        tooltip: err instanceof Error ? err.message : String(err),
      });
    }

    return nodes;
  }

  getTreeItem(n: HubNode): vscode.TreeItem {
    const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
    item.id = `hub:${n.key}`;
    item.description = n.description;
    if (n.icon) {
      const color = hubIconColor(n.key, n.description, n.icon);
      item.iconPath = color ? new vscode.ThemeIcon(n.icon, color) : new vscode.ThemeIcon(n.icon);
    }
    if (n.tooltip) {
      item.tooltip = n.tooltip;
    }
    if (n.command) {
      item.command = n.command;
    }
    item.contextValue = n.contextValue ?? `hub.${n.key}`;
    return item;
  }
}

function hubIconColor(key: string, description: string | undefined, icon: string): vscode.ThemeColor | undefined {
  if (key === "status") {
    if (description === "ok") {
      return new vscode.ThemeColor("charts.green");
    }
    return new vscode.ThemeColor("charts.red");
  }
  if (key === "state" && icon === "debug-disconnect") {
    return new vscode.ThemeColor("charts.red");
  }
  if (key === "runners" && description) {
    // "<online> online / <total> total"
    const m = /^(\d+)\s+online\s+\/\s+(\d+)/.exec(description);
    if (m) {
      const online = Number(m[1]);
      const total = Number(m[2]);
      if (online === 0) return new vscode.ThemeColor("charts.red");
      if (online < total) return new vscode.ThemeColor("charts.yellow");
      return new vscode.ThemeColor("charts.green");
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Runners (hierarchical: kind group -> runner -> properties)
//
// Mirrors the Tasks pane taxonomy: every fabric host is expected to expose
// BOTH a command runner (always-on NSSM service, kind:command) and an
// agent runner (interactive Copilot-Chat MCP, kind:agent). The two groups
// are always shown so the architectural split is visible even when the
// agent bucket is empty (e.g. on a headless host with no logged-in VS Code).
// A runner is bucketed by its self-declared `kind:*` tag; runners that
// predate the taxonomy (no kind tag) default to 'command'.
// ---------------------------------------------------------------------------

function bucketRunner(r: RunnerInfo): "agent" | "command" {
  // M2.8.3+: runners send `kinds: ["agent"|"command"]` as a first-class field
  // instead of `kind:*` tags. The hub may serialize it as a JSON string or array.
  const kindsRaw = (r as Record<string, unknown>).kinds;
  let kinds: string[] | undefined;
  if (Array.isArray(kindsRaw)) {
    kinds = kindsRaw as string[];
  } else if (typeof kindsRaw === "string") {
    try { kinds = JSON.parse(kindsRaw) as string[]; } catch { /* ignore */ }
  }
  if (Array.isArray(kinds)) {
    if (kinds.includes("agent")) { return "agent"; }
    if (kinds.includes("command")) { return "command"; }
  }
  // Legacy fallback: runners predating M2.8.3 still use kind:* tags.
  const tags = r.tags ?? [];
  if (tags.includes("kind:agent")) { return "agent"; }
  // Default: treat unknown as command (always-on shell runner).
  return "command";
}

export type RunnerNode =
  | { kind: "group"; group: "agent" | "command"; count: number }
  | { kind: "runner"; runner: RunnerInfo; parent: "agent" | "command" }
  | { kind: "placeholder"; group: "agent" | "command"; label: string; icon: string; description?: string }
  | { kind: "prop"; runner: RunnerInfo; key: string; label: string; description: string; icon: string };

export class RunnersProvider implements vscode.TreeDataProvider<RunnerNode> {
  private readonly _onDidChange = new vscode.EventEmitter<RunnerNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private aliases: Record<string, string> = {};
  private hostAliases: Record<string, string> = {};
  private buckets: { agent: RunnerInfo[]; command: RunnerInfo[] } = { agent: [], command: [] };

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: RunnerNode): Promise<RunnerNode[]> {
    if (element?.kind === "runner") {
      return runnerProps(element.runner, this.aliases);
    }
    if (element?.kind === "prop" || element?.kind === "placeholder") {
      return [];
    }
    if (element?.kind === "group") {
      const bucket = this.buckets[element.group];
      if (bucket.length === 0) {
        const label = element.group === "agent"
          ? "No agent runners online"
          : "No command runners online";
        const description = element.group === "agent"
          ? "open the 'forgewire-runner' chat mode in VS Code"
          : "start the 'ForgeWireRunner' Windows service";
        return [
          {
            kind: "placeholder",
            group: element.group,
            label,
            icon: element.group === "agent" ? "hubot" : "terminal",
            description,
          },
        ];
      }
      return bucket.map((r) => ({
        kind: "runner" as const,
        runner: r,
        parent: element.group,
      }));
    }

    // Top level: load runners + aliases, populate the two buckets.
    const c = this.client();
    if (!c) {
      this.buckets = { agent: [], command: [] };
      return [
        { kind: "group", group: "agent", count: 0 },
        { kind: "group", group: "command", count: 0 },
      ];
    }
    try {
      const [runners, labels] = await Promise.all([
        c.listRunners(),
        c.getLabels().catch(() => ({ hub_name: "", runner_aliases: {}, host_aliases: {} })),
      ]);
      this.aliases = labels.runner_aliases ?? {};
      this.hostAliases = labels.host_aliases ?? {};
      this.buckets = { agent: [], command: [] };
      for (const r of runners) {
        this.buckets[bucketRunner(r)].push(r);
      }
    } catch {
      this.buckets = { agent: [], command: [] };
    }
    return [
      { kind: "group", group: "agent", count: this.buckets.agent.length },
      { kind: "group", group: "command", count: this.buckets.command.length },
    ];
  }

  getTreeItem(n: RunnerNode): vscode.TreeItem {
    if (n.kind === "group") {
      const label = n.group === "agent" ? "Agent runners" : "Command runners";
      const item = new vscode.TreeItem(
        label,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.id = `runners.group.${n.group}`;
      item.description = `${n.count}`;
      item.contextValue = `runners.group.${n.group}`;
      if (n.group === "agent") {
        item.iconPath = new vscode.ThemeIcon("hubot", new vscode.ThemeColor("charts.blue"));
        item.tooltip = new vscode.MarkdownString(
          "**Agent runners** — interactive Copilot-Chat MCP sessions. " +
          "Claim `kind:agent` tasks. Not a daemon; opened on demand in VS Code."
        );
      } else {
        item.iconPath = new vscode.ThemeIcon("terminal", new vscode.ThemeColor("charts.purple"));
        item.tooltip = new vscode.MarkdownString(
          "**Command runners** — always-on shell-exec services (NSSM `ForgeWireRunner`). " +
          "Claim `kind:command` tasks."
        );
      }
      return item;
    }

    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.id = `runners.${n.group}.placeholder`;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      if (n.description) item.description = n.description;
      item.contextValue = `runners.placeholder.${n.group}`;
      return item;
    }

    if (n.kind === "runner") {
      const r = n.runner;
      const alias = this.aliases[r.runner_id] || this.hostAliases[r.hostname] || r.host_alias;
      const label = alias || r.hostname || r.runner_id.slice(0, 8);
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `runner:${r.runner_id}`;
      const isLocal = !!r.hostname && r.hostname.toLowerCase() === os.hostname().toLowerCase();
      item.contextValue = runnerContext(r, isLocal);
      item.description = isLocal ? `${r.state} \u00b7 this host` : r.state;
      item.iconPath = runnerIcon(r.state, isLocal);
      const tags = (r.tags ?? []).join(", ") || "<no tags>";
      const scopes = (r.scope_prefixes ?? []).join(", ") || "<unscoped>";
      item.tooltip = new vscode.MarkdownString(
        (alias ? `**${alias}**  \u00b7  hostname: ${r.hostname}\n\n` : `**${r.hostname}**\n\n`) +
          (isLocal ? "_(this host)_\n\n" : "") +
          `- runner_id: \`${r.runner_id}\`\n- kind: \`${n.parent}\`\n- state: ${r.state}\n- os: ${r.os} (${r.arch})\n- tags: ${tags}\n- scope: ${scopes}\n` +
          `- last heartbeat: ${r.last_heartbeat ?? "?"}\n- load: ${r.current_load}/${r.max_concurrent}`
      );
      return item;
    }

    const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
    item.id = `runner:${n.runner.runner_id}:${n.key}`;
    item.description = n.description;
    item.iconPath = new vscode.ThemeIcon(n.icon);
    item.contextValue = `runnerProp.${n.key}`;
    return item;
  }
}

function runnerProps(r: RunnerInfo, aliases: Record<string, string>): RunnerNode[] {
  const alias = aliases[r.runner_id];
  const tags = (r.tags ?? []).join(", ") || "<none>";
  const scopes = (r.scope_prefixes ?? []).join(", ") || "<unscoped>";
  const props: RunnerNode[] = [];
  if (alias) {
    props.push({
      kind: "prop",
      runner: r,
      key: "hostname",
      label: "Hostname",
      description: r.hostname,
      icon: "device-desktop",
    });
  }
  props.push(
    {
      kind: "prop",
      runner: r,
      key: "id",
      label: "Runner ID",
      description: r.runner_id,
      icon: "key",
    },
    {
      kind: "prop",
      runner: r,
      key: "load",
      label: "Load",
      description: `${r.current_load}/${r.max_concurrent}`,
      icon: "pulse",
    },
    {
      kind: "prop",
      runner: r,
      key: "os",
      label: "OS / arch",
      description: `${r.os} / ${r.arch}`,
      icon: "device-desktop",
    },
    {
      kind: "prop",
      runner: r,
      key: "tags",
      label: "Tags",
      description: tags,
      icon: "tag",
    },
    {
      kind: "prop",
      runner: r,
      key: "scope",
      label: "Scope",
      description: scopes,
      icon: "folder",
    },
    {
      kind: "prop",
      runner: r,
      key: "heartbeat",
      label: "Last heartbeat",
      description: r.last_heartbeat ?? "?",
      icon: "history",
    }
  );
  if (r.workspace_root) {
    props.push({
      kind: "prop",
      runner: r,
      key: "workspace_root",
      label: "Workspace root",
      description: String(r.workspace_root),
      icon: "root-folder",
    });
  }
  if (r.tenant) {
    props.push({
      kind: "prop",
      runner: r,
      key: "tenant",
      label: "Tenant",
      description: String(r.tenant),
      icon: "organization",
    });
  }
  if (typeof r.poll_interval === "number") {
    props.push({
      kind: "prop",
      runner: r,
      key: "poll_interval",
      label: "Poll interval",
      description: `${r.poll_interval}s`,
      icon: "watch",
    });
  }
  props.push({
    kind: "prop",
    runner: r,
    key: "capacity",
    label: "Max concurrent",
    description: String(r.max_concurrent),
    icon: "dashboard",
  });
  return props;
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

export type TaskNode =
  | { kind: "group"; group: "agent" | "command"; count: number }
  | { kind: "task"; task: TaskInfo; parent: "agent" | "command"; stale: boolean }
  | { kind: "historyGroup"; count: number }
  | { kind: "historyTask"; task: TaskInfo }
  | { kind: "placeholder"; label: string; icon: string; description?: string };

export class TasksProvider implements vscode.TreeDataProvider<TaskNode> {
  private readonly _onDidChange = new vscode.EventEmitter<TaskNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private cache: { agent: TaskInfo[]; command: TaskInfo[]; history: TaskInfo[] } = {
    agent: [],
    command: [],
    history: [],
  };

  /** Task IDs dismissed by the user — excluded from history display. */
  private dismissed = new Set<number>();

  constructor(
    private readonly client: () => HubClient | undefined,
    private readonly historyLimit = 100,
    private readonly ctx?: vscode.ExtensionContext
  ) {
    if (ctx) {
      const saved = ctx.globalState.get<number[]>("forgewire.dismissedTaskIds", []);
      this.dismissed = new Set(saved);
    }
  }

  dismissTask(id: number): void {
    this.dismissed.add(id);
    this.ctx?.globalState.update("forgewire.dismissedTaskIds", [...this.dismissed]);
    this._onDidChange.fire();
  }

  clearDismissed(): void {
    this.dismissed.clear();
    this.ctx?.globalState.update("forgewire.dismissedTaskIds", []);
    this._onDidChange.fire();
  }

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: TaskNode): Promise<TaskNode[]> {
    if (
      element?.kind === "task" ||
      element?.kind === "historyTask" ||
      element?.kind === "placeholder"
    ) {
      return [];
    }
    const c = this.client();
    if (!c) {
      return [];
    }
    if (!element) {
      try {
        // Fetch a wider window so the history bucket has meaningful depth.
        const tasks = await c.listTasks(Math.max(this.historyLimit * 2, 200));
        this.cache = bucketTasks(tasks, this.historyLimit);
        if (tasks.length === 0) {
          return [
            {
              kind: "placeholder",
              label: "No tasks yet",
              description: "dispatch one to see it here",
              icon: "inbox",
            },
          ];
        }
        const nodes: TaskNode[] = [
          { kind: "group", group: "agent", count: this.cache.agent.length },
          { kind: "group", group: "command", count: this.cache.command.length },
        ];
        if (this.cache.history.length > 0) {
          nodes.push({ kind: "historyGroup", count: this.cache.history.length });
        }
        return nodes;
      } catch (err) {
        return [
          {
            kind: "placeholder",
            label: "Hub unreachable",
            description: err instanceof Error ? err.message : String(err),
            icon: "warning",
          },
        ];
      }
    }
    if (element.kind === "historyGroup") {
      if (this.cache.history.length === 0) {
        return [
          {
            kind: "placeholder",
            label: "No task history",
            description: "completed tasks will appear here",
            icon: "inbox",
          },
        ];
      }
      return this.cache.history
        .filter((t) => !this.dismissed.has(t.id))
        .map((t) => ({ kind: "historyTask" as const, task: t }));
    }
    // element is an agent/command group node — return its tasks.
    const bucket = this.cache[element.group];
    if (bucket.length === 0) {
      return [
        {
          kind: "placeholder",
          label: element.group === "agent" ? "No agent tasks" : "No command tasks",
          description: undefined,
          icon: "inbox",
        },
      ];
    }
    const staleMinutes = vscode.workspace
      .getConfiguration("forgewire")
      .get<number>("tasks.staleQueuedMinutes", 30);
    return bucket.map((t) => ({
      kind: "task" as const,
      task: t,
      parent: element.group,
      stale: isStaleQueued(t, staleMinutes),
    }));
  }

  getTreeItem(n: TaskNode): vscode.TreeItem {
    if (n.kind === "group") {
      const label = n.group === "agent" ? "Agent tasks" : "Command tasks";
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Expanded);
      item.id = `taskgroup:${n.group}`;
      item.description = `${n.count}`;
      item.iconPath = new vscode.ThemeIcon(
        n.group === "agent" ? "hubot" : "terminal",
        new vscode.ThemeColor(n.group === "agent" ? "charts.blue" : "charts.purple")
      );
      item.contextValue = `taskgroup.${n.group}`;
      item.tooltip = new vscode.MarkdownString(
        n.group === "agent"
          ? "Sealed briefs for Copilot-Chat agent runners (chatmode + MCP)."
          : "Shell/script payloads for non-agent (cmd) runners."
      );
      return item;
    }
    if (n.kind === "historyGroup") {
      const item = new vscode.TreeItem("History", vscode.TreeItemCollapsibleState.Collapsed);
      item.id = "taskgroup:history";
      item.description = `${n.count} terminal`;
      item.iconPath = new vscode.ThemeIcon("history");
      item.contextValue = "taskgroup.history";
      item.tooltip = new vscode.MarkdownString(
        "Recently completed tasks (`done`/`failed`/`cancelled`/`timed_out`) with origin tracing."
      );
      return item;
    }
    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = "task.placeholder";
      return item;
    }
    if (n.kind === "historyTask") {
      return renderHistoryTaskItem(n.task);
    }
    const t = n.task;
    const item = new vscode.TreeItem(`#${t.id}  ${t.title}`, vscode.TreeItemCollapsibleState.None);
    item.id = `task:${t.id}`;
    // contextValue encodes parent kind + status subtype for context menus.
    // Stale (queued too long) gets its own subtype so a distinct cancel button appears.
    const subtype = n.stale ? "stale" : t.status;
    item.contextValue = `task.${n.parent}.${subtype}`;
    const staleAgeLabel = n.stale ? ` \u00b7 ${staleAge(t.created_at)}` : "";
    const chip = kindChip(t);
    item.description = n.stale
      ? `${chip} queued (stale${staleAgeLabel}) \u00b7 ${t.branch}`
      : `${chip} ${t.status} \u00b7 ${t.branch}`;
    item.iconPath = statusThemeIcon(n.stale ? "stale" : t.status);
    item.tooltip = new vscode.MarkdownString(
      `**#${t.id} ${t.title}** \`${t.status}\`\n\n` +
        `- kind: \`${t.kind ?? "agent"}\`\n` +
        `- branch: \`${t.branch}\`\n- base: \`${t.base_commit?.slice(0, 12)}\`\n` +
        `- scope: \`${(t.scope_globs ?? []).join(", ")}\`\n` +
        `- worker: ${t.worker_id ?? "_unassigned_"}\n- created: ${t.created_at ?? "?"}\n` +
        (n.stale ? `\n\u26a0\ufe0f **Stale** \u2014 queued for ${staleAge(t.created_at)} with no runner claiming it.\n` : "") +
        (t.result?.error ? `\n**error:** ${t.result.error}\n` : "")
    );
    item.command = {
      command: "forgewire.showTask",
      title: "Show Task",
      arguments: [t.id],
    };
    return item;
  }
}

function bucketTasks(
  tasks: TaskInfo[],
  historyLimit: number
): { agent: TaskInfo[]; command: TaskInfo[]; history: TaskInfo[] } {
  const agent: TaskInfo[] = [];
  const command: TaskInfo[] = [];
  const history: TaskInfo[] = [];
  for (const t of tasks) {
    if (TASK_TERMINAL.has((t.status || "").toLowerCase())) {
      history.push(t);
      continue;
    }
    if (t.kind === "command") {
      command.push(t);
    } else {
      // Default bucket: missing/unknown kind is treated as 'agent' so legacy
      // tasks predating the taxonomy still appear under the agent group.
      agent.push(t);
    }
  }
  history.sort(
    (a, b) =>
      historyTimestamp(b.completed_at ?? b.created_at) - historyTimestamp(a.completed_at ?? a.created_at)
  );
  return { agent, command, history: history.slice(0, historyLimit) };
}

function renderHistoryTaskItem(t: TaskInfo): vscode.TreeItem {
  const item = new vscode.TreeItem(`#${t.id}  ${t.title}`, vscode.TreeItemCollapsibleState.None);
  item.id = `taskHistory:${t.id}`;
  item.contextValue = `taskHistory.${t.status}`;
  const ageLabel = historyAgeLabel(t.completed_at ?? t.created_at);
  const duration = computeRuntime(t);
  const isFailed = t.status === "failed" || t.status === "timed_out";
  // Put the status first and make it UPPERCASE for failed/timed_out so it
  // stands out at a glance even without the icon colour.
  const statusLabel = isFailed ? t.status.toUpperCase() : t.status;
  item.description = [
    statusLabel,
    kindChip(t),
    t.branch,
    duration ? `ran ${duration}` : undefined,
    ageLabel ? `${ageLabel} ago` : undefined,
  ]
    .filter(Boolean)
    .join(" \u00b7 ");
  item.iconPath = statusThemeIcon(t.status);
  const origin = readOriginBlock(t);
  const errorLine = t.result?.error ? `\n**error:** ${t.result.error}\n` : "";
  item.tooltip = new vscode.MarkdownString(
    `**#${t.id} ${t.title}** \`${t.status}\`\n\n` +
      `- kind: \`${t.kind ?? "agent"}\`\n` +
      `- branch: \`${t.branch}\`\n` +
      `- base: \`${t.base_commit?.slice(0, 12)}\`\n` +
      `- scope: \`${(t.scope_globs ?? []).join(", ") || "(none)"}\`\n` +
      `- worker: ${t.worker_id ?? "_unassigned_"}\n` +
      `- created: ${t.created_at ?? "?"}\n` +
      (t.claimed_at ? `- claimed: ${t.claimed_at}\n` : "") +
      (t.started_at ? `- started: ${t.started_at}\n` : "") +
      (t.completed_at ? `- completed: ${t.completed_at}\n` : "") +
      (duration ? `- runtime: ${duration}\n` : "") +
      errorLine +
      (origin ? `\n**origin**\n\n${origin}\n` : "")
  );
  item.command = {
    command: "forgewire.showTask",
    title: "Show Task",
    arguments: [t.id],
  };
  return item;
}

/**
 * Compact kind chip for a task row, e.g. `[command]`, `[agent]`, or
 * `[agent·skill]` when the agent dispatch variant is known. Missing kind
 * defaults to `agent` (legacy tasks predate the M2.8 kind column).
 */
function kindChip(t: TaskInfo): string {
  const kind = t.kind ?? "agent";
  const dispatch = typeof t.dispatch === "string" ? t.dispatch : undefined;
  if (kind === "agent" && dispatch) {
    return `[agent·${dispatch}]`;
  }
  return `[${kind}]`;
}

function statusThemeIcon(s: string): vscode.ThemeIcon {
  switch (s) {
    case "queued":
      return new vscode.ThemeIcon("clock");
    case "stale":
      return new vscode.ThemeIcon("clock", new vscode.ThemeColor("charts.yellow"));
    case "running":
      return new vscode.ThemeIcon("loading~spin", new vscode.ThemeColor("charts.blue"));
    case "done":
      return new vscode.ThemeIcon("pass", new vscode.ThemeColor("charts.green"));
    case "failed":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("charts.red"));
    case "timed_out":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("charts.red"));
    case "cancelled":
      return new vscode.ThemeIcon("circle-slash");
    default:
      return new vscode.ThemeIcon("circle-outline");
  }
}

/** True when a queued task has been waiting longer than the configured threshold. */
function isStaleQueued(t: TaskInfo, staleMinutes: number): boolean {
  if (staleMinutes <= 0 || t.status !== "queued") { return false; }
  const ts = t.created_at ? Date.parse(t.created_at) : 0;
  return ts > 0 && (Date.now() - ts) > staleMinutes * 60_000;
}

/** Human-readable age of a task's creation timestamp, e.g. "47m" or "2h 3m". */
function staleAge(created_at: string | undefined | null): string {
  if (!created_at) { return "?"; }
  const ms = Date.now() - Date.parse(created_at);
  const m = Math.floor(ms / 60_000);
  if (m < 60) { return `${m}m`; }
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function runnerIcon(state: string, isLocal: boolean): vscode.ThemeIcon {
  // Blue dot for "this host" trumps state-color so the user can spot
  // their own machine at a glance. The state still shows in the
  // description text + tooltip.
  if (isLocal) {
    return new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor("charts.blue"));
  }
  switch (state) {
    case "online":
      return new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor("charts.green"));
    case "draining":
      return new vscode.ThemeIcon("debug-pause", new vscode.ThemeColor("charts.yellow"));
    case "degraded":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("charts.orange"));
    case "offline":
      return new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor("charts.red"));
    default:
      return new vscode.ThemeIcon("circle-outline", new vscode.ThemeColor("charts.foreground"));
  }
}

function runnerContext(r: RunnerInfo, isLocal: boolean): string {
  // Drives `view/item/context` `when` clauses: e.g. viewItem == runner.online.local
  const state = r.state || "unknown";
  const where = isLocal ? "local" : "remote";
  return `runner.${state}.${where}`;
}

function formatUptime(seconds: number | undefined): string {
  if (seconds === undefined || seconds === null || !isFinite(seconds) || seconds < 0) return "?";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ---------------------------------------------------------------------------
// Agents (Fabric runner registry: agent_type + MCP manifest)
//
// M2.8.8: consumes GET /agents. Each agent is a Fabric runner ('agent' in
// kinds) that has introspected its local MCP servers and advertised a
// manifest. The tree exposes, per agent, the connected MCP servers and the
// tools / resources / prompts (skills) each one advertises — the same
// capability set the hub's capability router uses to route skill/tool dispatch.
// ---------------------------------------------------------------------------

type CapKind = "tools" | "resources" | "prompts";

export type AgentNode =
  | { kind: "agent"; agent: AgentInfo }
  | { kind: "server"; agent: AgentInfo; server: McpManifestServer }
  | { kind: "capGroup"; server: McpManifestServer; cap: CapKind }
  | { kind: "cap"; cap: CapKind; name: string; description?: string; detail?: string }
  | { kind: "placeholder"; label: string; description?: string; icon: string };

export class AgentsProvider implements vscode.TreeDataProvider<AgentNode> {
  private readonly _onDidChange = new vscode.EventEmitter<AgentNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private agents: AgentInfo[] = [];

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: AgentNode): Promise<AgentNode[]> {
    if (element?.kind === "cap" || element?.kind === "placeholder") {
      return [];
    }
    if (element?.kind === "capGroup") {
      return capLeaves(element.server, element.cap);
    }
    if (element?.kind === "server") {
      const groups: AgentNode[] = [];
      for (const cap of ["prompts", "tools", "resources"] as CapKind[]) {
        if (capCount(element.server, cap) > 0) {
          groups.push({ kind: "capGroup", server: element.server, cap });
        }
      }
      if (groups.length === 0) {
        return [
          { kind: "placeholder", label: "No capabilities advertised", icon: "circle-slash" },
        ];
      }
      return groups;
    }
    if (element?.kind === "agent") {
      const servers = element.agent.mcp_manifest?.servers ?? [];
      if (servers.length === 0) {
        return [
          {
            kind: "placeholder",
            label: "No MCP servers advertised",
            description: "agent reported an empty manifest",
            icon: "circle-slash",
          },
        ];
      }
      return servers.map((server) => ({ kind: "server" as const, agent: element.agent, server }));
    }

    // Top level: load agents.
    const c = this.client();
    if (!c) {
      this.agents = [];
      return [{ kind: "placeholder", label: "Not connected", icon: "debug-disconnect" }];
    }
    try {
      this.agents = await c.listAgents();
    } catch (err) {
      this.agents = [];
      return [
        {
          kind: "placeholder",
          label: "Hub unreachable",
          description: err instanceof Error ? err.message : String(err),
          icon: "warning",
        },
      ];
    }
    if (this.agents.length === 0) {
      return [
        {
          kind: "placeholder",
          label: "No agent runners registered",
          description: "start a Fabric runner with MCP servers wired up",
          icon: "hubot",
        },
      ];
    }
    return this.agents.map((agent) => ({ kind: "agent" as const, agent }));
  }

  getTreeItem(n: AgentNode): vscode.TreeItem {
    if (n.kind === "agent") {
      const a = n.agent;
      const label = a.alias || a.hostname || a.runner_id.slice(0, 8);
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `agent:${a.runner_id}`;
      const isLocal = !!a.hostname && a.hostname.toLowerCase() === os.hostname().toLowerCase();
      const typeTag = a.agent_type ? `${a.agent_type}` : "agent";
      item.description = `${typeTag} · ${a.state ?? "?"}${isLocal ? " · this host" : ""}`;
      item.iconPath = new vscode.ThemeIcon(
        "hubot",
        a.state === "online"
          ? new vscode.ThemeColor("charts.blue")
          : a.state === "offline"
            ? new vscode.ThemeColor("charts.red")
            : new vscode.ThemeColor("charts.yellow")
      );
      item.contextValue = "agent";
      const servers = a.mcp_manifest?.servers ?? [];
      const counts = servers.reduce(
        (acc, s) => {
          acc.tools += s.tools?.length ?? 0;
          acc.resources += s.resources?.length ?? 0;
          acc.prompts += s.prompts?.length ?? 0;
          return acc;
        },
        { tools: 0, resources: 0, prompts: 0 }
      );
      item.tooltip = new vscode.MarkdownString(
        `**${label}**\n\n` +
          `- runner_id: \`${a.runner_id}\`\n` +
          `- agent_type: \`${a.agent_type ?? "(unset)"}\`\n` +
          `- hostname: ${a.hostname ?? "?"}${isLocal ? " _(this host)_" : ""}\n` +
          `- state: ${a.state ?? "?"}${a.drain_requested ? " (draining)" : ""}\n` +
          `- last heartbeat: ${a.last_heartbeat ?? "?"}\n` +
          `- manifest v${a.mcp_manifest_version ?? 0}: ${servers.length} server(s), ` +
          `${counts.prompts} skill(s) / ${counts.tools} tool(s) / ${counts.resources} resource(s)\n` +
          (a.workspace_root ? `- workspace: \`${a.workspace_root}\`\n` : "") +
          (a.tenant ? `- tenant: \`${a.tenant}\`\n` : "")
      );
      return item;
    }

    if (n.kind === "server") {
      const s = n.server;
      const item = new vscode.TreeItem(s.server_id, vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `agent:${n.agent.runner_id}:server:${s.server_id}`;
      const parts: string[] = [];
      if ((s.prompts?.length ?? 0) > 0) parts.push(`${s.prompts!.length} skills`);
      if ((s.tools?.length ?? 0) > 0) parts.push(`${s.tools!.length} tools`);
      if ((s.resources?.length ?? 0) > 0) parts.push(`${s.resources!.length} resources`);
      item.description = parts.join(" · ") || "no capabilities";
      item.iconPath = new vscode.ThemeIcon("server-process");
      item.contextValue = "agent.server";
      item.tooltip = new vscode.MarkdownString(
        `MCP server **${s.server_id}** advertised by this agent's manifest.`
      );
      return item;
    }

    if (n.kind === "capGroup") {
      const label = n.cap === "prompts" ? "Skills" : n.cap === "tools" ? "Tools" : "Resources";
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `agent:server:${n.server.server_id}:${n.cap}`;
      item.description = `${capCount(n.server, n.cap)}`;
      item.iconPath = new vscode.ThemeIcon(
        n.cap === "prompts" ? "symbol-event" : n.cap === "tools" ? "tools" : "file-symlink-file"
      );
      item.contextValue = `agent.capGroup.${n.cap}`;
      return item;
    }

    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = "agent.placeholder";
      return item;
    }

    // n.kind === "cap"
    const item = new vscode.TreeItem(n.name, vscode.TreeItemCollapsibleState.None);
    item.id = `agent:cap:${n.cap}:${n.name}`;
    if (n.description) item.description = n.description;
    item.iconPath = new vscode.ThemeIcon(
      n.cap === "prompts" ? "symbol-event" : n.cap === "tools" ? "symbol-method" : "file"
    );
    item.contextValue = `agent.cap.${n.cap}`;
    if (n.detail) {
      item.tooltip = new vscode.MarkdownString(n.detail);
    }
    return item;
  }
}

function capCount(server: McpManifestServer, cap: CapKind): number {
  return (server[cap]?.length ?? 0) as number;
}

function capLeaves(server: McpManifestServer, cap: CapKind): AgentNode[] {
  if (cap === "prompts") {
    return (server.prompts ?? []).map((p) => {
      const args = (p.arguments ?? [])
        .map((a) => (a.required ? `${a.name}*` : a.name))
        .join(", ");
      return {
        kind: "cap" as const,
        cap,
        name: p.name,
        description: p.description,
        detail:
          `**${p.name}** _(skill / MCP prompt)_\n\n` +
          (p.description ? `${p.description}\n\n` : "") +
          (args ? `arguments: \`${args}\` _(\\* = required)_` : "_no arguments_"),
      };
    });
  }
  if (cap === "tools") {
    return (server.tools ?? []).map((t) => ({
      kind: "cap" as const,
      cap,
      name: t.name,
      description: t.description,
      detail:
        `**${t.name}** _(MCP tool)_\n\n` + (t.description ? `${t.description}` : "_no description_"),
    }));
  }
  return (server.resources ?? []).map((r) => ({
    kind: "cap" as const,
    cap,
    name: r.name || r.uri,
    description: r.mime_type,
    detail: `**${r.name || r.uri}** _(MCP resource)_\n\n- uri: \`${r.uri}\`\n- type: ${r.mime_type ?? "?"}`,
  }));
}

// ---------------------------------------------------------------------------
// Hosts (primary operational surface)
//
// A "host" is the physical/virtual machine. The hub now fuses runners,
// dispatchers, active hub-head identity, control role, and installer-reported
// role enablement into /hosts, so this pane is the operator view. Raw runner
// rows remain diagnostic data under each host role rather than a separate pane.
// ---------------------------------------------------------------------------

export type HostsNode =
  | { kind: "cluster"; cluster: "fabric" | "loom"; label: string; backend: string | null }
  | { kind: "host"; cluster: "fabric" | "loom"; host: HostSummary }
  | { kind: "role"; hostname: string; roleName: HostRoleName; role: HostRoleSummary; runner?: RunnerInfo; dispatchers?: DispatcherInfo[] }
  | { kind: "dispatcher"; hostname: string; dispatcher: DispatcherInfo }
  | { kind: "dispatcherProp"; dispatcher: DispatcherInfo; key: string; label: string; description: string; icon: string }
  | { kind: "health"; key: string; label: string; description: string; icon: string; tooltip?: string; color?: string; children?: HostsNode[] }
  | { kind: "placeholder"; label: string; description?: string; icon: string };

export class HostsProvider implements vscode.TreeDataProvider<HostsNode> {
  private readonly _onDidChange = new vscode.EventEmitter<HostsNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private hosts: HostSummary[] = [];
  private health: ClusterHealth | undefined;

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: HostsNode): Promise<HostsNode[]> {
    const c = this.client();
    if (!element) {
      // Top level: cluster groups
      return [
        { kind: "cluster", cluster: "fabric", label: "Fabric", backend: this.health?.backend ?? null },
        { kind: "cluster", cluster: "loom", label: "Loom", backend: null },
      ];
    }
    if (element.kind === "cluster") {
      if (element.cluster === "loom") {
        return [
          {
            kind: "placeholder",
            label: "No Loom cluster configured",
            description: "reserved for substrate backend",
            icon: "circle-slash",
          },
        ];
      }
      // Fabric: load runners + dispatchers + cluster health
      if (!c) {
        return [
          { kind: "placeholder", label: "Not connected", icon: "debug-disconnect" },
        ];
      }
      const nodes: HostsNode[] = [];
      try {
        const [hosts, health] = await Promise.all([
          c.listHosts().catch(() => [] as HostSummary[]),
          c.clusterHealth().catch(() => undefined as ClusterHealth | undefined),
        ]);
        this.health = health;
        this.hosts = hosts;
        // Cluster Health sub-section first (always visible).
        nodes.push(...healthNodes(health));
        // Then one node per discovered host.
        for (const host of this.hosts) {
          nodes.push({ kind: "host", cluster: "fabric", host });
        }
        if (this.hosts.length === 0) {
          nodes.push({
            kind: "placeholder",
            label: "No hosts registered",
            description: "no role facts, runners, or dispatchers reported in",
            icon: "inbox",
          });
        }
      } catch (err) {
        nodes.push({
          kind: "placeholder",
          label: "Hub unreachable",
          description: err instanceof Error ? err.message : String(err),
          icon: "warning",
        });
      }
      return nodes;
    }
    if (element.kind === "host") {
      const host = element.host;
      const order: HostRoleName[] = ["hub_head", "control", "dispatch", "command_runner", "agent_runner"];
      return order.map((roleName) => {
        const role = host.roles[roleName];
        const runner = firstRoleRunner(host, roleName, role);
        const dispatchers = roleName === "dispatch"
          ? host.dispatchers.filter((d) => role.dispatcher_ids.includes(d.dispatcher_id))
          : undefined;
        return { kind: "role" as const, hostname: host.hostname, roleName, role, runner, dispatchers };
      });
    }
    if (element.kind === "role" && element.roleName === "dispatch") {
      return (element.dispatchers ?? []).map((dispatcher) => ({
        kind: "dispatcher" as const,
        hostname: element.hostname,
        dispatcher,
      }));
    }
    if (element.kind === "health" && element.children) {
      return element.children;
    }
    if (element.kind === "dispatcher") {
      const d = element.dispatcher;
      const props: HostsNode[] = [
        { kind: "dispatcherProp", dispatcher: d, key: "id", label: "Dispatcher ID", description: d.dispatcher_id, icon: "key" },
        { kind: "dispatcherProp", dispatcher: d, key: "hostname", label: "Hostname", description: d.hostname ?? "?", icon: "device-desktop" },
        { kind: "dispatcherProp", dispatcher: d, key: "last_seen", label: "Last seen", description: d.last_seen ?? "?", icon: "history" },
        { kind: "dispatcherProp", dispatcher: d, key: "first_seen", label: "First seen", description: d.first_seen ?? "?", icon: "calendar" },
      ];
      for (const [key, value] of Object.entries(d.metadata ?? {})) {
        props.push({
          kind: "dispatcherProp",
          dispatcher: d,
          key: `meta.${key}`,
          label: key,
          description: typeof value === "string" ? value : JSON.stringify(value),
          icon: "info",
        });
      }
      return props;
    }
    return [];
  }

  getTreeItem(n: HostsNode): vscode.TreeItem {
    if (n.kind === "cluster") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.Expanded);
      item.id = `hosts:cluster:${n.cluster}`;
      item.iconPath = new vscode.ThemeIcon(n.cluster === "fabric" ? "circuit-board" : "globe");
      // Fabric row stays clean — backend identity lives inside the
      // expandable "Backend" child so it can carry full metadata. Loom
      // keeps its "n/a" badge until a substrate cluster is wired in.
      if (n.cluster === "loom") {
        item.description = n.backend ?? "n/a";
      }
      item.contextValue = `hosts.cluster.${n.cluster}`;
      item.tooltip =
        n.cluster === "fabric"
          ? `ForgeWire (rqlite/sqlite backend). Active: ${n.backend ?? "unknown"}.`
          : "Loom: substrate cluster (forgewire_core). Not yet wired into the hub.";
      return item;
    }
    if (n.kind === "host") {
      const host = n.host;
      const label = hostDisplayName(host);
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `hosts:host:${n.cluster}:${host.hostname}`;
      const isLocal = host.hostname.toLowerCase() === os.hostname().toLowerCase();
      const rawHost = label === host.hostname ? "" : `${host.hostname} \u00b7 `;
      item.description = rawHost + hostStatusBadge(host) + (isLocal ? " \u00b7 this host" : "");
      item.iconPath = new vscode.ThemeIcon(
        "device-desktop",
        host.is_active_hub ? new vscode.ThemeColor("charts.green") : isLocal ? new vscode.ThemeColor("charts.blue") : undefined
      );
      item.contextValue = `hosts.host.${n.cluster}`;
      item.tooltip = hostTooltip(host);
      return item;
    }
    if (n.kind === "role") {
      const collapsible = n.roleName === "dispatch" && (n.dispatchers?.length ?? 0) > 0
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None;
      const item = new vscode.TreeItem(roleLabel(n.roleName), collapsible);
      item.id = `hosts:role:${n.hostname}:${n.roleName}`;
      item.description = roleDescription(n.roleName, n.role);
      item.iconPath = new vscode.ThemeIcon(roleIcon(n.roleName), roleColor(n.roleName, n.role));
      const isLocal = n.hostname.toLowerCase() === os.hostname().toLowerCase();
      item.contextValue = n.runner ? runnerContext(n.runner, isLocal) : `hosts.role.${n.roleName}.${n.role.enabled ? "enabled" : "disabled"}`;
      item.tooltip = roleTooltip(n.roleName, n.role);
      return item;
    }
    if (n.kind === "dispatcher") {
      const d = n.dispatcher;
      const item = new vscode.TreeItem(d.label || d.dispatcher_id.slice(0, 8), vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `hosts:dispatcher:${n.hostname}:${d.dispatcher_id}`;
      item.description = d.last_seen ? `last seen ${d.last_seen}` : d.hostname ?? "";
      item.iconPath = new vscode.ThemeIcon("rocket", new vscode.ThemeColor("charts.green"));
      item.contextValue = "hosts.dispatcher";
      item.tooltip = `dispatcher_id: ${d.dispatcher_id}\nhost: ${d.hostname ?? "?"}\nlast_seen: ${d.last_seen ?? "?"}`;
      return item;
    }
    if (n.kind === "dispatcherProp") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.id = `hosts:dispatcher:${n.dispatcher.dispatcher_id}:${n.key}`;
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = `hosts.dispatcherProp.${n.key}`;
      return item;
    }
    if (n.kind === "health") {
      const collapsible = n.children && n.children.length > 0
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None;
      const item = new vscode.TreeItem(n.label, collapsible);
      item.id = `hosts:health:${n.key}`;
      item.description = n.description;
      item.iconPath = n.color
        ? new vscode.ThemeIcon(n.icon, new vscode.ThemeColor(n.color))
        : new vscode.ThemeIcon(n.icon);
      if (n.tooltip) item.tooltip = n.tooltip;
      item.contextValue = `hosts.health.${n.key}`;
      return item;
    }
    const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
    item.description = n.description;
    item.iconPath = new vscode.ThemeIcon(n.icon);
    item.contextValue = "hosts.placeholder";
    return item;
  }
}

function firstRoleRunner(host: HostSummary, roleName: HostRoleName, role: HostRoleSummary): RunnerInfo | undefined {
  if (roleName !== "command_runner" && roleName !== "agent_runner") return undefined;
  const id = role.runner_ids[0];
  return host.runners.find((r) => r.runner_id === id);
}

function hostDisplayName(host: HostSummary): string {
  return (host.display_name || host.label || host.hostname).trim() || host.hostname;
}

function hostStatusBadge(host: HostSummary): string {
  // Reduce the per-role status matrix to a single badge for the row.
  // Detailed metadata (hub/ctrl/cmd/agent/dispatch statuses) lives in the
  // expanded children, not crammed into the row label.
  const r = host.roles;
  const roles: HostRoleSummary[] = [r.hub_head, r.control, r.dispatch, r.command_runner, r.agent_runner];
  const enabled = roles.filter((role) => role.enabled);
  if (enabled.length === 0) return "idle";
  const healthy = new Set(["active", "online", "master", "slave", "registered", "ok", "ready"]);
  const bad = new Set(["offline", "failed", "error", "unreachable", "stopped"]);
  let hasBad = false;
  let hasUnknown = false;
  for (const role of enabled) {
    const s = (role.status || "").toLowerCase();
    if (bad.has(s)) {
      hasBad = true;
    } else if (!healthy.has(s)) {
      hasUnknown = true;
    }
  }
  if (hasBad) return "degraded";
  if (hasUnknown) return "degraded";
  return "online";
}

function hostTooltip(host: HostSummary): vscode.MarkdownString {
  const label = hostDisplayName(host);
  const title = label === host.hostname ? host.hostname : `${label} (${host.hostname})`;
  const labelLine = label === host.hostname ? "" : `- label: \`${label}\`\n`;
  return new vscode.MarkdownString(
    `**${title}**\n\n` +
      labelLine +
      `- hub head: \`${host.roles.hub_head.status}\`\n` +
      `- control: \`${host.roles.control.status}\`\n` +
      `- dispatch: \`${host.roles.dispatch.status}\`\n` +
      `- command runner: \`${host.roles.command_runner.status}\` (${host.roles.command_runner.runner_ids.length})\n` +
      `- agent runner: \`${host.roles.agent_runner.status}\` (${host.roles.agent_runner.runner_ids.length})\n` +
      `- raw runners: ${host.runners.length}\n` +
      `- dispatchers: ${host.dispatchers.length}`
  );
}

function roleLabel(roleName: HostRoleName): string {
  switch (roleName) {
    case "hub_head": return "Hub head";
    case "control": return "Control node";
    case "dispatch": return "Dispatch";
    case "command_runner": return "Command runner";
    case "agent_runner": return "Agent runner";
  }
}

function roleDescription(roleName: HostRoleName, role: HostRoleSummary): string {
  const count = roleName === "dispatch" ? role.dispatcher_ids.length : role.runner_ids.length;
  const suffix = count > 0 ? ` \u00b7 ${count}` : "";
  if (roleName === "hub_head" && role.address) return `${role.status} \u00b7 ${role.address}`;
  if (!role.enabled && role.status === "disabled") return "disabled";
  return `${role.enabled ? role.status : `disabled (${role.status})`}${suffix}`;
}

function roleIcon(roleName: HostRoleName): string {
  switch (roleName) {
    case "hub_head": return "broadcast";
    case "control": return "shield";
    case "dispatch": return "rocket";
    case "command_runner": return "terminal";
    case "agent_runner": return "hubot";
  }
}

function roleColor(roleName: HostRoleName, role: HostRoleSummary): vscode.ThemeColor | undefined {
  if (!role.enabled) return new vscode.ThemeColor("charts.foreground");
  if (role.status === "active" || role.status === "master" || role.status === "online" || role.status === "registered") {
    return new vscode.ThemeColor(roleName === "agent_runner" ? "charts.blue" : "charts.green");
  }
  if (role.status === "draining" || role.status === "standby" || role.status === "slave") return new vscode.ThemeColor("charts.yellow");
  if (role.status === "degraded") return new vscode.ThemeColor("charts.orange");
  if (role.status === "offline") return new vscode.ThemeColor("charts.red");
  return undefined;
}

function roleTooltip(roleName: HostRoleName, role: HostRoleSummary): vscode.MarkdownString {
  const lines = [
    `**${roleLabel(roleName)}**`,
    "",
    `- enabled: ${role.enabled}`,
    `- status: \`${role.status}\``,
    `- source: \`${role.source}\``,
  ];
  if (role.address) lines.push(`- address: \`${role.address}\``);
  if (role.updated_at) lines.push(`- updated: ${role.updated_at}`);
  if (role.runner_ids.length) lines.push(`- runners: ${role.runner_ids.map((id) => `\`${id}\``).join(", ")}`);
  if (role.dispatcher_ids.length) lines.push(`- dispatchers: ${role.dispatcher_ids.map((id) => `\`${id}\``).join(", ")}`);
  const metadata = Object.entries(role.metadata ?? {});
  if (metadata.length) {
    lines.push("", "**metadata**");
    for (const [key, value] of metadata) {
      lines.push(`- ${key}: \`${typeof value === "string" ? value : JSON.stringify(value)}\``);
    }
  }
  return new vscode.MarkdownString(lines.join("\n"));
}

function healthNodes(health: ClusterHealth | undefined): HostsNode[] {
  if (!health) {
    return [
      { kind: "health", key: "status", label: "Cluster health", description: "unknown", icon: "question" },
    ];
  }
  const nodes: HostsNode[] = [];
  const backendChildren: HostsNode[] = [
    {
      kind: "health",
      key: "backend.kind",
      label: "Type",
      description: health.backend,
      icon: health.backend === "rqlite" ? "broadcast" : "database",
      color: health.backend === "rqlite" ? "charts.green" : "charts.yellow",
      tooltip:
        health.backend === "rqlite"
          ? "Distributed rqlite backend (Raft-replicated SQLite)."
          : "Legacy single-node sqlite backend.",
    },
  ];
  if (health.rqlite) {
    backendChildren.push(
      {
        kind: "health",
        key: "backend.endpoint",
        label: "Endpoint",
        description: `${health.rqlite.host}:${health.rqlite.port}`,
        icon: "globe",
        tooltip: `rqlite HTTP endpoint: ${health.rqlite.host}:${health.rqlite.port}`,
      },
      {
        kind: "health",
        key: "backend.consistency",
        label: "Consistency",
        description: health.rqlite.consistency,
        icon: "shield",
        tooltip:
          `rqlite read consistency level: \`${health.rqlite.consistency}\`. ` +
        `"strong" routes reads through the Raft leader; "weak"/"none" trade ` +
        `freshness for latency.`,
      },
    );
  } else {
    backendChildren.push({
      kind: "health",
      key: "backend.endpoint",
      label: "Endpoint",
      description: "local sqlite",
      icon: "database",
      tooltip: "Single-node sqlite backend — no cluster endpoint.",
    });
  }
  nodes.push({
    kind: "health",
    key: "backend",
    label: "Backend",
    description: health.backend,
    icon: "database",
    color: health.backend === "rqlite" ? "charts.green" : "charts.yellow",
    tooltip:
      health.backend === "rqlite"
        ? `rqlite cluster ${health.rqlite?.host}:${health.rqlite?.port} (consistency=${health.rqlite?.consistency})`
        : "Legacy single-node sqlite backend.",
    children: backendChildren,
  });
  const s = health.labels_snapshot;
  const sidecarColor =
    s.status === "applied" || s.status === "seeded_from_db"
      ? "charts.green"
      : s.status === "absent" || s.status === "disabled"
        ? "charts.yellow"
        : "charts.red";
  const ageStr = s.mtime
    ? formatUptime(Math.max(0, Math.floor(Date.now() / 1000 - s.mtime)))
    : "n/a";
  nodes.push({
    kind: "health",
    key: "sidecar",
    label: "Labels sidecar",
    description: `${s.status ?? "?"} \u00b7 age ${ageStr}`,
    icon: s.exists ? "save" : "warning",
    color: sidecarColor,
    tooltip: new vscode.MarkdownString(
      `**Labels snapshot sidecar**\n\n` +
        `- path: \`${s.path ?? "(disabled)"}\`\n` +
        `- exists: ${s.exists}\n` +
        `- bytes: ${s.size_bytes ?? "n/a"}\n` +
        `- last applied: ${s.applied} row(s)\n` +
        `- status: \`${s.status ?? "?"}\``
    ).value,
  });
  return nodes;
}

// ---------------------------------------------------------------------------
// Dispatchers
// ---------------------------------------------------------------------------

export type DispatcherNode =
  | { kind: "dispatcher"; dispatcher: DispatcherInfo }
  | { kind: "prop"; dispatcher: DispatcherInfo; key: string; label: string; description: string; icon: string }
  | { kind: "placeholder"; label: string; description?: string; icon: string };

export class DispatchersProvider implements vscode.TreeDataProvider<DispatcherNode> {
  private readonly _onDidChange = new vscode.EventEmitter<DispatcherNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: DispatcherNode): Promise<DispatcherNode[]> {
    if (element?.kind === "dispatcher") {
      const d = element.dispatcher;
      const props: DispatcherNode[] = [
        { kind: "prop", dispatcher: d, key: "id", label: "Dispatcher ID", description: d.dispatcher_id, icon: "key" },
        { kind: "prop", dispatcher: d, key: "hostname", label: "Hostname", description: d.hostname ?? "?", icon: "device-desktop" },
        { kind: "prop", dispatcher: d, key: "last_seen", label: "Last seen", description: d.last_seen ?? "?", icon: "history" },
        { kind: "prop", dispatcher: d, key: "first_seen", label: "First seen", description: d.first_seen ?? "?", icon: "calendar" },
      ];
      for (const [k, v] of Object.entries(d.metadata ?? {})) {
        props.push({
          kind: "prop",
          dispatcher: d,
          key: `meta.${k}`,
          label: k,
          description: typeof v === "string" ? v : JSON.stringify(v),
          icon: "info",
        });
      }
      return props;
    }
    if (element?.kind === "prop" || element?.kind === "placeholder") {
      return [];
    }
    const c = this.client();
    if (!c) {
      return [{ kind: "placeholder", label: "Not connected", icon: "debug-disconnect" }];
    }
    try {
      const dispatchers = await c.listDispatchers();
      if (dispatchers.length === 0) {
        return [
          {
            kind: "placeholder",
            label: "No dispatchers registered",
            description: "dispatchers register on first dispatch",
            icon: "inbox",
          },
        ];
      }
      return dispatchers.map((d) => ({ kind: "dispatcher" as const, dispatcher: d }));
    } catch (err) {
      return [
        {
          kind: "placeholder",
          label: "Hub unreachable",
          description: err instanceof Error ? err.message : String(err),
          icon: "warning",
        },
      ];
    }
  }

  getTreeItem(n: DispatcherNode): vscode.TreeItem {
    if (n.kind === "dispatcher") {
      const d = n.dispatcher;
      const item = new vscode.TreeItem(d.label || d.dispatcher_id.slice(0, 8), vscode.TreeItemCollapsibleState.Collapsed);
      item.id = `dispatcher:${d.dispatcher_id}`;
      item.description = d.hostname ?? "";
      item.iconPath = new vscode.ThemeIcon("rocket");
      item.contextValue = "dispatcher";
      item.tooltip = `dispatcher_id: ${d.dispatcher_id}\nhost: ${d.hostname ?? "?"}\nlast_seen: ${d.last_seen ?? "?"}`;
      return item;
    }
    if (n.kind === "prop") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.id = `dispatcher:${n.dispatcher.dispatcher_id}:${n.key}`;
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = `dispatcherProp.${n.key}`;
      return item;
    }
    const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
    item.description = n.description;
    item.iconPath = new vscode.ThemeIcon(n.icon);
    item.contextValue = "dispatcher.placeholder";
    return item;
  }
}

// ---------------------------------------------------------------------------
// Approvals (M2.5.1 human-in-the-loop)
// ---------------------------------------------------------------------------

export type ApprovalNode =
  | { kind: "approval"; approval: ApprovalInfo }
  | { kind: "historyGroup" }
  | { kind: "historyApproval"; approval: ApprovalInfo }
  | { kind: "placeholder"; label: string; description?: string; icon: string; command?: vscode.Command; contextValue?: string };

export interface SnoozedApprovalInfo {
  approvalId: string;
  label: string;
  snoozedAt: number;
  expiresAt: number;
}

export class ApprovalsProvider implements vscode.TreeDataProvider<ApprovalNode> {
  private readonly _onDidChange = new vscode.EventEmitter<ApprovalNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(
    private readonly client: () => HubClient | undefined,
    private readonly getSnoozed: (approvalId: string) => SnoozedApprovalInfo | undefined = () => undefined,
    private readonly ageBadgeHours: () => number = () => 24,
    private readonly historyLimit = 100
  ) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: ApprovalNode): Promise<ApprovalNode[]> {
    const c = this.client();
    if (!c) return [{ kind: "placeholder", label: "Not connected", icon: "debug-disconnect" }];
    if (element?.kind === "historyGroup") {
      try {
        // No server-side multi-status filter -> fetch a wider window and
        // filter client-side to terminal statuses.
        const approvals = await c.listApprovals(undefined, Math.max(this.historyLimit * 2, 200));
        const history = approvals
          .filter((a) => APPROVAL_TERMINAL.has((a.status || "").toLowerCase()))
          .sort(
            (a, b) =>
              historyTimestamp(b.resolved_at ?? b.created_at) - historyTimestamp(a.resolved_at ?? a.created_at)
          )
          .slice(0, this.historyLimit);
        if (history.length === 0) {
          return [
            {
              kind: "placeholder",
              label: "No approval history",
              description: "resolved approvals will appear here",
              icon: "inbox",
            },
          ];
        }
        return history.map((a) => ({ kind: "historyApproval" as const, approval: a }));
      } catch (err) {
        return [
          {
            kind: "placeholder",
            label: "Hub unreachable",
            description: err instanceof Error ? err.message : String(err),
            icon: "warning",
          },
        ];
      }
    }
    if (element) return [];
    try {
      const approvals = await c.listApprovals("pending", 100);
      const visible = approvals.filter((a) => !this.getSnoozed(a.approval_id));
      const deferredCount = approvals.length - visible.length;
      const nodes: ApprovalNode[] = [];
      if (approvals.length === 0) {
        nodes.push({ kind: "placeholder", label: "No pending approvals", icon: "check", description: "queue is clear" });
      } else {
        for (const a of visible) {
          nodes.push({ kind: "approval", approval: a });
        }
        if (deferredCount > 0) {
          nodes.push({
            kind: "placeholder",
            label: `${deferredCount} deferred approval${deferredCount === 1 ? "" : "s"}`,
            description: "snoozed locally",
            icon: "debug-pause",
            command: { command: "forgewire.showDeferredApprovals", title: "Show Snoozed Approvals" },
            contextValue: "approval.deferred.placeholder",
          });
        }
      }
      // Always offer the History dropdown at the bottom; its expansion
      // triggers a lazy fetch (resolved-status approvals).
      nodes.push({ kind: "historyGroup" });
      return nodes;
    } catch (err) {
      return [
        {
          kind: "placeholder",
          label: "Hub unreachable",
          description: err instanceof Error ? err.message : String(err),
          icon: "warning",
        },
      ];
    }
  }

  getTreeItem(n: ApprovalNode): vscode.TreeItem {
    if (n.kind === "historyGroup") {
      const item = new vscode.TreeItem("History", vscode.TreeItemCollapsibleState.Collapsed);
      item.id = "approvalgroup:history";
      item.iconPath = new vscode.ThemeIcon("history");
      item.contextValue = "approval.historyGroup";
      item.tooltip = new vscode.MarkdownString(
        "Recently resolved approvals (`approved`/`denied`/`expired`/`consumed`/`revoked`) with origin tracing."
      );
      return item;
    }
    if (n.kind === "historyApproval") {
      return renderHistoryApprovalItem(n.approval);
    }
    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = n.contextValue ?? "approval.placeholder";
      if (n.command) item.command = n.command;
      return item;
    }
    const a = n.approval;
    const item = new vscode.TreeItem(a.task_label || a.approval_id.slice(0, 12), vscode.TreeItemCollapsibleState.None);
    item.id = `approval:${a.approval_id}`;
    const age = approvalAge(a.created_at);
    const thresholdMs = this.ageBadgeHours() * 60 * 60 * 1000;
    const isOld = a.status === "pending" && age !== undefined && age.ms >= thresholdMs;
    item.description = [a.status, a.branch, age ? `age ${age.label}` : undefined, isOld ? "needs review" : undefined]
      .filter(Boolean)
      .join(" \u00b7 ");
    item.iconPath = new vscode.ThemeIcon(
      isOld ? "warning" : a.status === "pending" ? "circle-large-outline" : a.status === "approved" ? "check" : "circle-slash",
      a.status === "pending" ? new vscode.ThemeColor(isOld ? "charts.orange" : "charts.yellow") : undefined
    );
    item.contextValue = `approval.${a.status}`;
    item.command = {
      command: "forgewire.examineApproval",
      title: "Examine Approval",
      arguments: [a],
    };
    const scopes = approvalScopes(a);
    const decision = approvalDecisionSummary(a);
    item.tooltip = new vscode.MarkdownString(
      `**${a.task_label ?? a.approval_id}**\n\n` +
        `- approval_id: \`${a.approval_id}\`\n` +
        `- status: \`${a.status}\`\n` +
        `- branch: \`${a.branch ?? "?"}\`\n` +
        `- scope: \`${scopes.join(", ")}\`\n` +
        (age ? `- age: ${age.label} (badge threshold ${this.ageBadgeHours()}h)\n` : "") +
        (decision ? `- decision: ${decision}\n` : "") +
        `- created: ${a.created_at ?? "?"}\n` +
        (a.resolved_at ? `- resolved: ${a.resolved_at} by ${a.approver ?? "?"}\n` : "") +
        (a.reason ? `- reason: ${a.reason}\n` : "")
    ).value;
    return item;
  }
}

function renderHistoryApprovalItem(a: ApprovalInfo): vscode.TreeItem {
  const label = a.task_label || a.approval_id.slice(0, 12);
  const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
  item.id = `approvalHistory:${a.approval_id}`;
  item.contextValue = `approvalHistory.${a.status}`;
  const ageLabel = historyAgeLabel(a.resolved_at ?? a.created_at);
  item.description = [
    a.status,
    a.branch,
    a.approver ? `by ${a.approver}` : undefined,
    ageLabel ? `${ageLabel} ago` : undefined,
  ]
    .filter(Boolean)
    .join(" \u00b7 ");
  item.iconPath = new vscode.ThemeIcon(approvalHistoryIcon(a.status));
  const origin = readOriginBlock(a);
  item.tooltip = new vscode.MarkdownString(
    `**${label}** \`${a.status}\`\n\n` +
      `- approval_id: \`${a.approval_id}\`\n` +
      `- branch: \`${a.branch ?? "?"}\`\n` +
      `- scope: \`${approvalScopes(a).join(", ") || "(none)"}\`\n` +
      (a.envelope_hash ? `- envelope: \`${String(a.envelope_hash).slice(0, 16)}\u2026\`\n` : "") +
      `- created: ${a.created_at ?? "?"}\n` +
      (a.resolved_at ? `- resolved: ${a.resolved_at}\n` : "") +
      (a.approver ? `- approver: ${a.approver}\n` : "") +
      (a.reason ? `- reason: ${a.reason}\n` : "") +
      (origin ? `\n**origin**\n\n${origin}\n` : "")
  );
  item.command = {
    command: "forgewire.examineApproval",
    title: "Examine Approval",
    arguments: [a],
  };
  return item;
}

function approvalScopes(a: ApprovalInfo): string[] {
  if (Array.isArray(a.scope_globs)) {
    return a.scope_globs.map(String);
  }
  if (typeof a.scope_globs_json === "string" && a.scope_globs_json.trim()) {
    try {
      const parsed = JSON.parse(a.scope_globs_json);
      if (Array.isArray(parsed)) {
        return parsed.map(String);
      }
    } catch {
      return [a.scope_globs_json];
    }
  }
  return [];
}

function approvalAge(createdAt: string | undefined): { ms: number; label: string } | undefined {
  if (!createdAt) return undefined;
  const parsed = Date.parse(createdAt.endsWith("Z") ? createdAt : `${createdAt}Z`);
  if (!Number.isFinite(parsed)) return undefined;
  const ms = Math.max(0, Date.now() - parsed);
  return { ms, label: formatDuration(ms / 1000) };
}

function formatDuration(totalSeconds: number): string {
  const seconds = Math.floor(totalSeconds);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${seconds}s`;
}

function approvalDecisionSummary(a: ApprovalInfo): string | undefined {
  if (typeof a.decision_json !== "string" || !a.decision_json.trim()) {
    return undefined;
  }
  try {
    const decision = JSON.parse(a.decision_json) as { decision?: string; reason?: string; violations?: Array<{ message?: string }> };
    const head = [decision.decision, decision.reason].filter(Boolean).join(" / ");
    const violation = decision.violations?.[0]?.message;
    return [head, violation].filter(Boolean).join(" - ");
  } catch {
    return a.decision_json.slice(0, 120);
  }
}

// ---------------------------------------------------------------------------
// History: terminal-state approvals and tasks with origin / tracing.
//
// History views read the same /approvals and /tasks endpoints, filter to
// resolved/terminal statuses client-side, and render the origin block
// (metadata.origin) plus approver / worker information so operators can
// audit "where did this come from" after the fact.
// ---------------------------------------------------------------------------

const APPROVAL_TERMINAL: ReadonlySet<string> = new Set([
  "approved",
  "denied",
  "expired",
  "consumed",
  "revoked",
]);

const TASK_TERMINAL: ReadonlySet<string> = new Set([
  "done",
  "failed",
  "cancelled",
  "timed_out",
]);

function historyTimestamp(ts: string | undefined | null): number {
  if (!ts) return 0;
  const parsed = Date.parse(ts.endsWith("Z") ? ts : `${ts}Z`);
  return Number.isFinite(parsed) ? parsed : 0;
}

function historyAgeLabel(ts: string | undefined | null): string | undefined {
  const t = historyTimestamp(ts);
  if (!t) return undefined;
  const ms = Math.max(0, Date.now() - t);
  return formatDuration(ms / 1000);
}

function approvalHistoryIcon(status: string): string {
  switch ((status || "").toLowerCase()) {
    case "approved":
      return "check";
    case "consumed":
      return "verified";
    case "denied":
      return "circle-slash";
    case "expired":
      return "clock";
    case "revoked":
      return "trash";
    default:
      return "history";
  }
}

function computeRuntime(t: TaskInfo): string | undefined {
  const start = historyTimestamp(t.started_at ?? t.claimed_at ?? t.created_at);
  const end = historyTimestamp(t.completed_at);
  if (!start || !end || end < start) return undefined;
  return formatDuration((end - start) / 1000);
}

function readOriginBlock(record: ApprovalInfo | TaskInfo): string | undefined {
  // Origin metadata may live under `metadata.origin` (harness convention),
  // or be inlined under top-level `origin`. Render whatever we find.
  const anyRecord = record as Record<string, unknown>;
  const candidates: unknown[] = [];
  const meta = anyRecord["metadata"];
  if (meta && typeof meta === "object") {
    candidates.push((meta as Record<string, unknown>)["origin"]);
  }
  candidates.push(anyRecord["origin"]);
  // Some endpoints serialize metadata as a JSON string.
  if (typeof anyRecord["metadata_json"] === "string") {
    try {
      const parsed = JSON.parse(anyRecord["metadata_json"] as string);
      if (parsed && typeof parsed === "object") {
        candidates.push((parsed as Record<string, unknown>)["origin"]);
      }
    } catch {
      // ignore
    }
  }
  for (const origin of candidates) {
    if (origin && typeof origin === "object" && !Array.isArray(origin)) {
      const entries = Object.entries(origin as Record<string, unknown>);
      if (entries.length === 0) continue;
      return entries
        .map(([k, v]) => `- ${k}: \`${formatOriginValue(v)}\``)
        .join("\n");
    }
  }
  return undefined;
}

function formatOriginValue(value: unknown): string {
  if (value === null || value === undefined) return "_null_";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

// ---------------------------------------------------------------------------
// Audit log (M2.5.3 hash-chained audit)
// ---------------------------------------------------------------------------

export type AuditNode =
  | { kind: "header"; label: string; description: string; icon: string; tooltip?: string }
  | { kind: "event"; event: AuditEvent }
  | { kind: "placeholder"; label: string; description?: string; icon: string };

export class AuditProvider implements vscode.TreeDataProvider<AuditNode> {
  private readonly _onDidChange = new vscode.EventEmitter<AuditNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: AuditNode): Promise<AuditNode[]> {
    if (element) return [];
    const c = this.client();
    if (!c) return [{ kind: "placeholder", label: "Not connected", icon: "debug-disconnect" }];
    try {
      const tail = await c.auditTail().catch(() => ({ chain_tail: null }));
      const today = new Date().toISOString().slice(0, 10);
      const day = await c.auditDay(today).catch(() => ({ day: today, events: [] as AuditEvent[], verified: false, error: "unavailable" }));
      const nodes: AuditNode[] = [
        {
          kind: "header",
          label: "Chain tail",
          description: typeof (tail as any).chain_tail === "string"
            ? ((tail as any).chain_tail as string).slice(0, 16) + "\u2026"
            : "n/a",
          icon: "key",
          tooltip: typeof (tail as any).chain_tail === "string" ? (tail as any).chain_tail : "no audit events yet",
        },
        {
          kind: "header",
          label: `Today (${today})`,
          description: `${day.events.length} event(s) \u00b7 verified=${day.verified}`,
          icon: day.verified ? "verified" : "warning",
          tooltip: day.error ? `verification error: ${day.error}` : `${day.events.length} events on ${today}`,
        },
      ];
      const recent = (day.events ?? []).slice(-25).reverse();
      for (const e of recent) {
        nodes.push({ kind: "event", event: e });
      }
      if (recent.length === 0) {
        nodes.push({ kind: "placeholder", label: "No events today", icon: "inbox" });
      }
      return nodes;
    } catch (err) {
      return [
        {
          kind: "placeholder",
          label: "Hub unreachable",
          description: err instanceof Error ? err.message : String(err),
          icon: "warning",
        },
      ];
    }
  }

  getTreeItem(n: AuditNode): vscode.TreeItem {
    if (n.kind === "header") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      if (n.tooltip) item.tooltip = n.tooltip;
      item.contextValue = "audit.header";
      return item;
    }
    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = "audit.placeholder";
      return item;
    }
    const e = n.event;
    const label = e.event_type ?? "event";
    const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
    item.id = `audit:${e.id ?? Math.random()}`;
    item.description = `task=${e.task_id ?? "-"} \u00b7 ${e.created_at ?? "?"}`;
    item.iconPath = new vscode.ThemeIcon("note");
    item.contextValue = "audit.event";
    item.tooltip = new vscode.MarkdownString(
      `**${label}**\n\n` +
        `- task_id: ${e.task_id ?? "?"}\n` +
        `- hash: \`${(e.hash ?? "").slice(0, 24)}\u2026\`\n` +
        `- prev: \`${(e.prev_hash ?? "").slice(0, 24)}\u2026\`\n` +
        `- created: ${e.created_at ?? "?"}\n` +
        (e.payload ? "\n```json\n" + JSON.stringify(e.payload, null, 2).slice(0, 800) + "\n```" : "")
    ).value;
    return item;
  }
}

// ---------------------------------------------------------------------------
// Secrets (M2.5.5a sealed broker -- metadata only, never values)
// ---------------------------------------------------------------------------

export type SecretNode =
  | { kind: "secret"; secret: SecretInfo }
  | { kind: "placeholder"; label: string; description?: string; icon: string };

export class SecretsProvider implements vscode.TreeDataProvider<SecretNode> {
  private readonly _onDidChange = new vscode.EventEmitter<SecretNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  async getChildren(element?: SecretNode): Promise<SecretNode[]> {
    if (element) return [];
    const c = this.client();
    if (!c) return [{ kind: "placeholder", label: "Not connected", icon: "debug-disconnect" }];
    try {
      const secrets = await c.listSecrets();
      if (secrets.length === 0) {
        return [{ kind: "placeholder", label: "No secrets stored", description: "use the CLI to seal one", icon: "lock" }];
      }
      return secrets.map((s) => ({ kind: "secret" as const, secret: s }));
    } catch (err) {
      return [
        {
          kind: "placeholder",
          label: "Hub unreachable",
          description: err instanceof Error ? err.message : String(err),
          icon: "warning",
        },
      ];
    }
  }

  getTreeItem(n: SecretNode): vscode.TreeItem {
    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.description = n.description;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = "secret.placeholder";
      return item;
    }
    const s = n.secret;
    const item = new vscode.TreeItem(s.name, vscode.TreeItemCollapsibleState.None);
    item.id = `secret:${s.name}`;
    item.description = `v${s.version ?? 1}`;
    item.iconPath = new vscode.ThemeIcon("lock", new vscode.ThemeColor("charts.green"));
    item.contextValue = "secret";
    item.tooltip = new vscode.MarkdownString(
      `**${s.name}** (sealed)\n\n` +
        `- version: ${s.version ?? 1}\n` +
        `- created: ${s.created_at ?? "?"}\n` +
        `- last_rotated: ${s.last_rotated_at ?? "never"}\n\n` +
        `_Values are never exposed via the API._`
    ).value;
    return item;
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
// A sidebar tree that exposes every ForgeWire VS Code setting grouped by
// category. Each leaf shows the current value as its description and opens
// the standard Settings editor focused on that exact key when clicked.

export type SettingNode =
  | { kind: "category"; id: string; label: string; icon: string }
  | { kind: "setting"; key: string; label: string; description: string; tooltip: string };

interface SettingDef {
  key: string;           // the forgewire.* key (without "forgewire." prefix)
  label: string;
  tooltip: string;
  sensitive?: boolean;   // mask the value in the description
}

const SETTING_CATEGORIES: Array<{ id: string; label: string; icon: string; settings: SettingDef[] }> = [
  {
    id: "connection",
    label: "Connection",
    icon: "plug",
    settings: [
      { key: "hubUrl",       label: "Hub URL",          tooltip: "Base URL of the active ForgeWire hub." },
      { key: "hubTokenFile", label: "Token file",       tooltip: "Path to a file containing the hub bearer token.", sensitive: true },
      { key: "hubToken",     label: "Token (inline)",   tooltip: "Bearer token stored in VS Code SecretStorage. Use 'Set Hub Token…' command instead of typing here.", sensitive: true },
      { key: "hubName",      label: "Hub name",         tooltip: "Friendly display name shown in the sidebar." },
      { key: "hubPin",       label: "Pinned hub URL",   tooltip: "When set, the extension always dispatches to this URL. Clear with 'Unpin Hub'." },
    ],
  },
  {
    id: "failover",
    label: "Failover candidates",
    icon: "server-environment",
    settings: [
      { key: "hubCandidates",     label: "Candidates",         tooltip: "Ordered list of hub URLs probed for failover." },
      { key: "runnerAliases",     label: "Runner aliases",     tooltip: "Map of runner_id → friendly display name." },
      { key: "refreshIntervalSeconds", label: "Refresh interval (s)", tooltip: "How often the sidebar refreshes runners and tasks." },
    ],
  },
  {
    id: "tasks",
    label: "Tasks",
    icon: "tasklist",
    settings: [
      { key: "tasks.staleQueuedMinutes", label: "Stale queue threshold (min)", tooltip: "Minutes before a queued task turns yellow and gets a Cancel button. Set to 0 to disable. Increase for long-running queues." },
      { key: "autoStartHubPort",         label: "Auto-start hub port",         tooltip: "Default port used by 'Start Hub Here'." },
    ],
  },
  {
    id: "approvals",
    label: "Approvals",
    icon: "verified",
    settings: [
      { key: "approvals.ageBadgeHours", label: "Age badge threshold (h)", tooltip: "Show a warning badge on approvals pending longer than this many hours." },
    ],
  },
  {
    id: "cluster",
    label: "Cluster & DR",
    icon: "database",
    settings: [
      { key: "cluster.repoRoot",              label: "Repo root",                    tooltip: "Path to the forgewire-fabric checkout containing config/cluster.yaml." },
      { key: "cluster.preferredNode",         label: "Preferred rqlite node",        tooltip: "Override cluster.yaml preferred_node for DR operations on this machine." },
      { key: "dr.backup.cadenceMinutes",      label: "Backup cadence (min)",         tooltip: "How often the rqlite backup task runs. 0 = use cluster.yaml default (5)." },
      { key: "dr.backup.retentionHours",      label: "Backup retention (h)",         tooltip: "How long to keep backup snapshots. 0 = use cluster.yaml default (24)." },
      { key: "dr.chaos.cadenceMinutes",       label: "Chaos drill cadence (min)",    tooltip: "How often chaos drills run. 0 = use cluster.yaml default (1440). ⚠ Lower values cause hub latency spikes." },
      { key: "dr.chaos.drills",               label: "Chaos drill set",              tooltip: "Comma-separated drills: kill-leader, lose-quorum, partition-recovery." },
      { key: "dr.chaos.retentionDays",        label: "Chaos log retention (days)",   tooltip: "Days of chaos JSONL logs to keep. 0 = use cluster.yaml default (30)." },
      { key: "dr.chaos.principal",            label: "Chaos task principal",         tooltip: "Windows principal the chaos scheduled task runs as (SYSTEM recommended)." },
    ],
  },
  {
    id: "python",
    label: "Python / CLI",
    icon: "terminal",
    settings: [
      { key: "pythonPath", label: "Python interpreter", tooltip: "Python used to install / launch the forgewire CLI. Empty = auto-detect." },
    ],
  },
];

export class SettingsProvider implements vscode.TreeDataProvider<SettingNode> {
  private readonly _onDidChange = new vscode.EventEmitter<SettingNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  refresh(): void { this._onDidChange.fire(); }

  getChildren(element?: SettingNode): SettingNode[] {
    if (!element) {
      return SETTING_CATEGORIES.map((c) => ({
        kind: "category" as const,
        id: c.id,
        label: c.label,
        icon: c.icon,
      }));
    }
    if (element.kind !== "category") { return []; }
    const cat = SETTING_CATEGORIES.find((c) => c.id === element.id);
    if (!cat) { return []; }
    const cfg = vscode.workspace.getConfiguration("forgewire");
    return cat.settings.map((s) => {
      const raw = cfg.get(s.key);
      let valueStr: string;
      if (s.sensitive) {
        valueStr = raw ? "••••••" : "(not set)";
      } else if (raw === undefined || raw === null || raw === "") {
        valueStr = "(not set)";
      } else if (typeof raw === "object") {
        const arr = Array.isArray(raw) ? raw : Object.keys(raw as object);
        valueStr = arr.length === 0 ? "(empty)" : `${arr.length} item${arr.length !== 1 ? "s" : ""}`;
      } else {
        valueStr = String(raw);
      }
      return {
        kind: "setting" as const,
        key: `forgewire.${s.key}`,
        label: s.label,
        description: valueStr,
        tooltip: `**${s.label}**\n\n${s.tooltip}\n\nKey: \`forgewire.${s.key}\``,
      };
    });
  }

  getTreeItem(n: SettingNode): vscode.TreeItem {
    if (n.kind === "category") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.Expanded);
      item.id = `settings:cat:${n.id}`;
      item.iconPath = new vscode.ThemeIcon(n.icon);
      item.contextValue = "settings.category";
      return item;
    }
    const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
    item.id = `settings:${n.key}`;
    item.description = n.description;
    item.iconPath = new vscode.ThemeIcon("gear");
    item.tooltip = new vscode.MarkdownString(n.tooltip);
    item.contextValue = "settings.item";
    item.command = {
      command: "workbench.action.openSettings",
      title: "Open Setting",
      arguments: [n.key],
    };
    return item;
  }
}

// ---------------------------------------------------------------------------
// Cost (M2.5.2) — spend summary + budget bars
// ---------------------------------------------------------------------------

export type CostNode =
  | { kind: "period"; label: string; spend: number; budget?: number; alert?: boolean; icon: string }
  | { kind: "modelRow"; model: string; cost: number; tokens: number }
  | { kind: "sectionHeader"; label: string }
  | { kind: "placeholder"; label: string; icon: string };

export class CostProvider implements vscode.TreeDataProvider<CostNode> {
  private readonly _onDidChange = new vscode.EventEmitter<CostNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(private readonly client: () => HubClient | undefined) {}

  refresh(): void { this._onDidChange.fire(); }

  getTreeItem(n: CostNode): vscode.TreeItem {
    if (n.kind === "placeholder") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(n.icon);
      return item;
    }
    if (n.kind === "sectionHeader") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon("list-unordered");
      item.contextValue = "cost.sectionHeader";
      return item;
    }
    if (n.kind === "period") {
      const pct = n.budget ? (n.spend / n.budget * 100).toFixed(1) : null;
      const bar = n.budget ? _budgetBar(n.spend, n.budget) : "";
      const label = n.budget
        ? `${n.label}  $${n.spend.toFixed(4)} / $${n.budget.toFixed(2)}${bar}`
        : `${n.label}  $${n.spend.toFixed(4)}`;
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(n.alert ? "warning" : n.icon);
      if (pct) item.description = `${pct}%${n.alert ? " ⚠" : ""}`;
      item.tooltip = n.budget
        ? `Spent $${n.spend.toFixed(6)} of $${n.budget.toFixed(4)} (${pct}%)`
        : `Spent $${n.spend.toFixed(6)}`;
      item.contextValue = n.alert ? "cost.period.alert" : "cost.period";
      return item;
    }
    // modelRow
    const item = new vscode.TreeItem(
      `${n.model || "(unknown)"}`,
      vscode.TreeItemCollapsibleState.None
    );
    item.description = `$${n.cost.toFixed(4)}  ${_fmtTokens(n.tokens)}`;
    item.iconPath = new vscode.ThemeIcon("symbol-misc");
    item.tooltip = `Model: ${n.model || "(unknown)"}\nCost: $${n.cost.toFixed(6)}\nTokens: ${n.tokens.toLocaleString()}`;
    item.contextValue = "cost.modelRow";
    return item;
  }

  async getChildren(element?: CostNode): Promise<CostNode[]> {
    if (element) return [];
    const c = this.client();
    if (!c) return [{ kind: "placeholder", label: "Not connected", icon: "plug" }];
    try {
      const [summary, budget] = await Promise.all([
        c.getCostSummary(7).catch(() => null),
        c.getCostBudget().catch(() => null),
      ]);
      const nodes: CostNode[] = [];

      // Period rows
      const dailySpend = budget?.daily_spend_usd ?? 0;
      const weeklySpend = budget?.weekly_spend_usd ?? 0;
      nodes.push({
        kind: "period",
        label: `Today (${budget?.today ?? "—"})`,
        spend: dailySpend,
        budget: budget?.daily_budget_usd,
        icon: "calendar",
      });
      nodes.push({
        kind: "period",
        label: `This week (${budget?.week ?? "—"})`,
        spend: weeklySpend,
        budget: budget?.weekly_budget_usd,
        alert: budget?.weekly_alert,
        icon: "graph",
      });

      // By-model breakdown from summary
      const byModel = summary?.by_model ?? {};
      const modelEntries = Object.entries(byModel as Record<string, { cost_usd: number; tokens: number }>)
        .sort((a, b) => b[1].cost_usd - a[1].cost_usd)
        .slice(0, 8);

      if (modelEntries.length > 0) {
        nodes.push({ kind: "sectionHeader", label: "By model (last 7d)" });
        for (const [model, agg] of modelEntries) {
          nodes.push({ kind: "modelRow", model, cost: agg.cost_usd, tokens: agg.tokens });
        }
      } else {
        nodes.push({ kind: "placeholder", label: "No cost records yet", icon: "info" });
      }

      return nodes;
    } catch {
      return [{ kind: "placeholder", label: "Failed to load cost data", icon: "error" }];
    }
  }
}

function _budgetBar(spend: number, budget: number): string {
  const pct = Math.min(spend / budget, 1);
  const filled = Math.round(pct * 8);
  return "  " + "█".repeat(filled) + "░".repeat(8 - filled);
}

function _fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M tok`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k tok`;
  return `${n} tok`;
}

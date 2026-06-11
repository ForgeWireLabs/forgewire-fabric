/**
 * ForgeWire VS Code extension entry point.
 *
 * Cross-platform, zero-native-deps. Drives the `forgewire` Python CLI for
 * "start hub here" / "start runner here" / "install CLI"; talks to the hub
 * REST API directly for read-side views and dispatch.
 */

import * as os from "os";
import * as path from "path";
import * as fs from "fs";
import * as vscode from "vscode";
import { ApprovalInfo, DispatcherSession, HubClient } from "./hubClient";
import {
  AgentsProvider,
  ApprovalNode,
  ApprovalsProvider,
  AuditProvider,
  CostProvider,
  HostsProvider,
  HubProvider,
  SecretsProvider,
  SettingsProvider,
  TaskNode,
  TasksProvider,
} from "./treeProviders";

const SECRET_TOKEN_KEY = "forgewire.hubToken";
const SNOOZED_APPROVALS_KEY = "forgewire.snoozedApprovals";

let outputChannel: vscode.OutputChannel;
let statusItem: vscode.StatusBarItem;
let hubProvider: HubProvider;
let hostsProvider: HostsProvider;
let approvalsProvider: ApprovalsProvider;
let costProvider: CostProvider;
let auditProvider: AuditProvider;
let secretsProvider: SecretsProvider;
let settingsProvider: SettingsProvider;
let tasksProvider: TasksProvider;
let agentsProvider: AgentsProvider;
let refreshTimer: NodeJS.Timeout | undefined;
let context: vscode.ExtensionContext;

// Active hub state: maintained by probeActiveHub() on every refresh tick.
let activeClient: HubClient | undefined;
let lastProbe: Awaited<ReturnType<typeof HubClient.probe>> | undefined;
const snoozedApprovals = new Map<string, SnoozedApproval>();

// Dispatcher identity for signed dispatch (protocol v3+ Rust hub).
// Loaded/generated on activation; may be undefined if Web Crypto is unavailable.
let dispatcherSession: DispatcherSession | undefined;

// ---------------------------------------------------------------------------
// activation
// ---------------------------------------------------------------------------

export async function activate(ctx: vscode.ExtensionContext): Promise<void> {
  context = ctx;
  outputChannel = vscode.window.createOutputChannel("ForgeWire");
  ctx.subscriptions.push(outputChannel);

  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusItem.command = "forgewire.connectHub";
  ctx.subscriptions.push(statusItem);
  updateStatus();

  // Migrate settings from the old forgewire-fabric extension (forgewireFabric.*)
  // to the new forgewire.* namespace. Runs once; does not overwrite existing values.
  await migrateSettingsFromFabric(ctx);

  // Hydrate token from SecretStorage into the live HubClient lookup.
  await hydrateTokenFromSecret();
  loadSnoozedApprovals();

  // Load or generate a dispatcher identity for signed dispatch (protocol v3+).
  dispatcherSession = await DispatcherSession.loadOrCreate(ctx.secrets);

  hubProvider = new HubProvider(getClient, getProbe);
  hostsProvider = new HostsProvider(getClient);
  approvalsProvider = new ApprovalsProvider(
    getClient,
    getSnoozedApproval,
    approvalAgeBadgeHours
  );
  costProvider = new CostProvider(getClient);
  auditProvider = new AuditProvider(getClient);
  secretsProvider = new SecretsProvider(getClient);
  settingsProvider = new SettingsProvider();
  tasksProvider = new TasksProvider(getClient, 100, ctx);
  agentsProvider = new AgentsProvider(getClient);
  ctx.subscriptions.push(
    vscode.window.registerTreeDataProvider("forgewire.hub", hubProvider),
    vscode.window.registerTreeDataProvider("forgewire.hosts", hostsProvider),
    vscode.window.registerTreeDataProvider("forgewire.agents", agentsProvider),
    vscode.window.registerTreeDataProvider("forgewire.approvals", approvalsProvider),
    vscode.window.registerTreeDataProvider("forgewire.cost", costProvider),
    vscode.window.registerTreeDataProvider("forgewire.audit", auditProvider),
    vscode.window.registerTreeDataProvider("forgewire.secrets", secretsProvider),
    vscode.window.registerTreeDataProvider("forgewire.tasks", tasksProvider),
    vscode.window.registerTreeDataProvider("forgewire.settings", settingsProvider)
  );

  ctx.subscriptions.push(
    vscode.commands.registerCommand("forgewire.installCli", installCli),
    vscode.commands.registerCommand("forgewire.connectHub", connectHub),
    vscode.commands.registerCommand("forgewire.setToken", setToken),
    vscode.commands.registerCommand("forgewire.copyJoinToken", copyJoinToken),
    vscode.commands.registerCommand("forgewire.disconnect", disconnect),
    vscode.commands.registerCommand("forgewire.startHubHere", startHubHere),
    vscode.commands.registerCommand("forgewire.startRunnerHere", startRunnerHere),
    vscode.commands.registerCommand("forgewire.dispatchTask", dispatchTask),
    vscode.commands.registerCommand("forgewire.refresh", refreshAll),
    vscode.commands.registerCommand("forgewire.cost.refresh", () => costProvider?.refresh()),
    vscode.commands.registerCommand("forgewire.streamTask", streamTaskCmd),
    vscode.commands.registerCommand("forgewire.cancelTask", cancelTaskCmd),
    vscode.commands.registerCommand("forgewire.showTask", showTaskCmd),
    vscode.commands.registerCommand("forgewire.redispatchTask", redispatchTaskCmd),
    vscode.commands.registerCommand("forgewire.dismissTask", dismissTaskCmd),
    vscode.commands.registerCommand("forgewire.cancelStaleTask", cancelStaleTaskCmd),
    vscode.commands.registerCommand("forgewire.approveApproval", approveApprovalCmd),
    vscode.commands.registerCommand("forgewire.denyApproval", denyApprovalCmd),
    vscode.commands.registerCommand("forgewire.deferApproval", deferApprovalCmd),
    vscode.commands.registerCommand("forgewire.showDeferredApprovals", showDeferredApprovalsCmd),
    vscode.commands.registerCommand("forgewire.examineApproval", examineApprovalCmd),
    vscode.commands.registerCommand("forgewire.copyApprovalReference", copyApprovalReferenceCmd),
    vscode.commands.registerCommand("forgewire.copyToken", copyToken),
    vscode.commands.registerCommand("forgewire.generateToken", generateToken),
    vscode.commands.registerCommand("forgewire.openSettings", openSettings),
    vscode.commands.registerCommand("forgewire.renameHub", renameHub),
    vscode.commands.registerCommand("forgewire.renameHost", renameHost),
    vscode.commands.registerCommand("forgewire.renameRunner", renameRunner),
    vscode.commands.registerCommand("forgewire.pauseRunner", pauseRunner),
    vscode.commands.registerCommand("forgewire.resumeRunner", resumeRunner),
    vscode.commands.registerCommand("forgewire.restartRunnerService", restartRunnerService),
    vscode.commands.registerCommand("forgewire.startRunnerService", startRunnerService),
    vscode.commands.registerCommand("forgewire.stopRunnerService", stopRunnerService),
    vscode.commands.registerCommand("forgewire.pinHub", pinHub),
    vscode.commands.registerCommand("forgewire.unpinHub", unpinHub),
    vscode.commands.registerCommand("forgewire.promoteHub", promoteHub),
    vscode.commands.registerCommand("forgewire.demoteHub", demoteHub),
    vscode.commands.registerCommand("forgewire.editHubCandidates", editHubCandidates),
    vscode.commands.registerCommand("forgewire.dr.installBackupTask", drInstallBackupTask),
    vscode.commands.registerCommand("forgewire.dr.installChaosTask", drInstallChaosTask),
    vscode.commands.registerCommand("forgewire.dr.provisionSshForSystem", drProvisionSshForSystem),
    vscode.commands.registerCommand("forgewire.dr.runChaosNow", drRunChaosNow),
    vscode.commands.registerCommand("forgewire.dr.tailLastChaosLog", drTailLastChaosLog),
    vscode.commands.registerCommand("forgewire.dr.openClusterYaml", drOpenClusterYaml),
    vscode.commands.registerCommand("forgewire.dr.openSettings", drOpenSettings)
  );

  ctx.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("forgewire")) {
        updateStatus();
        scheduleRefresh();
        refreshAll();
        settingsProvider.refresh();
      }
    })
  );

  scheduleRefresh();
  refreshAll();
}

export function deactivate(): void {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function getClient(): HubClient | undefined {
  // Once a probe has run, trust its election: activeClient is the hub that was
  // actually reachable, or undefined if none were. Do NOT fall back to the
  // static config in that case -- otherwise the UI would display a stale,
  // unreachable hub URL as the "active" hub. Only before the first probe do we
  // fall back to config so the very first tick renders something useful.
  if (lastProbe) {
    return activeClient;
  }
  return activeClient ?? HubClient.fromConfig();
}

function getProbe(): typeof lastProbe {
  return lastProbe;
}

function updateStatus(): void {
  pruneExpiredSnoozes();
  const c = getClient();
  vscode.commands.executeCommand("setContext", "forgewire.connected", !!c);
  vscode.commands.executeCommand("setContext", "forgewire.hasDeferredApprovals", snoozedApprovals.size > 0);
  if (c) {
    const cfg = vscode.workspace.getConfiguration("forgewire");
    const name = (cfg.get<string>("hubName") ?? "").trim();
    const tag = name ? `${name} (${labelForUrl(c.url)})` : labelForUrl(c.url);
    const prefix = lastProbe?.pinned ? "$(pin)" : "$(plug)";
    statusItem.text = `${prefix} ForgeWire: ${tag}`;
    const pinNote = lastProbe?.pinned ? "\n\n_(pinned -- failover disabled until you unpin)_" : "";
    statusItem.tooltip = new vscode.MarkdownString(
      `Connected to **${c.url}**.${pinNote}\n\nClick to reconnect.`
    );
  } else {
    statusItem.text = "$(debug-disconnect) ForgeWire";
    statusItem.tooltip = "Click to connect to a ForgeWire hub.";
  }
  statusItem.show();
}

function labelForUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.host;
  } catch {
    return url;
  }
}

function scheduleRefresh(): void {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const seconds = Math.max(2, cfg.get<number>("refreshIntervalSeconds") ?? 10);
  refreshTimer = setInterval(refreshAll, seconds * 1000);
}

function refreshAll(): void {
  // Re-probe candidates first; HubProvider/RunnersProvider/TasksProvider all
  // read activeClient via getClient() so they need probe to settle first.
  void probeAndRefresh();
}

async function probeAndRefresh(): Promise<void> {
  try {
    const probe = await HubClient.probe();
    const prevUrl = activeClient?.url;
    activeClient = probe.active;
    lastProbe = probe;
    // Register dispatcher identity whenever we connect to a new hub URL.
    if (activeClient && dispatcherSession && activeClient.url !== prevUrl) {
      void dispatcherSession.register(activeClient, os.hostname());
    }
  } catch (err) {
    outputChannel.appendLine(`probe failed: ${err}`);
  }
  updateStatus();
  hubProvider?.refresh();
  tasksProvider?.refresh();
  agentsProvider?.refresh();
  hostsProvider?.refresh();
  approvalsProvider?.refresh();
  costProvider?.refresh();
  auditProvider?.refresh();
  secretsProvider?.refresh();
}

async function hydrateTokenFromSecret(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  if ((cfg.get<string>("hubToken") ?? "").trim().length > 0) {
    return;
  }
  const stored = await context.secrets.get(SECRET_TOKEN_KEY);
  if (stored) {
    await cfg.update("hubToken", stored, vscode.ConfigurationTarget.Global);
  }
}

function pythonCommand(): string {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const explicit = (cfg.get<string>("pythonPath") ?? "").trim();
  if (explicit) {
    return quoteIfNeeded(explicit);
  }
  // Try the official Python extension's selection first.
  const pyCfg = vscode.workspace.getConfiguration("python");
  const fromPy = (pyCfg.get<string>("defaultInterpreterPath") ?? "").trim();
  if (fromPy) {
    return quoteIfNeeded(fromPy);
  }
  return process.platform === "win32" ? "python" : "python3";
}

function quoteIfNeeded(p: string): string {
  return p.includes(" ") && !p.startsWith('"') ? `"${p}"` : p;
}

function getOrCreateTerminal(name: string, env?: Record<string, string>): vscode.Terminal {
  const existing = vscode.window.terminals.find((t) => t.name === name);
  if (existing) {
    return existing;
  }
  return vscode.window.createTerminal({ name, env });
}

// ---------------------------------------------------------------------------
// commands: bootstrap + connection
// ---------------------------------------------------------------------------

async function installCli(): Promise<void> {
  const term = getOrCreateTerminal("ForgeWire: install");
  term.show();
  term.sendText(`${pythonCommand()} -m pip install --upgrade forgewire`);
  vscode.window.showInformationMessage(
    "Running `pip install --upgrade forgewire` in a terminal. Watch progress there."
  );
}

async function connectHub(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const currentUrl = cfg.get<string>("hubUrl") ?? "";
  const url = await vscode.window.showInputBox({
    title: "ForgeWire Hub URL",
    prompt: "e.g. http://hub.local:8765",
    value: currentUrl,
    ignoreFocusOut: true,
    validateInput: (v) => (/^https?:\/\/.+/i.test(v.trim()) ? null : "Must start with http:// or https://"),
  });
  if (!url) {
    return;
  }
  const token = await vscode.window.showInputBox({
    title: "ForgeWire Hub Token",
    prompt: "Paste the bearer token (32+ hex chars). Stored in VS Code SecretStorage.",
    password: true,
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim().length >= 16 ? null : "Token must be at least 16 characters"),
  });
  if (!token) {
    return;
  }
  await cfg.update("hubUrl", url.trim(), vscode.ConfigurationTarget.Global);
  await cfg.update("hubToken", token.trim(), vscode.ConfigurationTarget.Global);
  await context.secrets.store(SECRET_TOKEN_KEY, token.trim());

  const client = HubClient.fromConfig();
  if (!client) {
    vscode.window.showErrorMessage("ForgeWire: failed to construct client.");
    return;
  }
  try {
    const h = await client.healthz();
    vscode.window.showInformationMessage(
      `ForgeWire: connected (protocol v${h.protocol_version}, hub v${h.version}).`
    );
  } catch (err) {
    vscode.window.showWarningMessage(
      `Saved settings but healthz failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  updateStatus();
  refreshAll();
}

async function setToken(): Promise<void> {
  const token = await vscode.window.showInputBox({
    title: "ForgeWire Hub Token",
    password: true,
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim().length >= 16 ? null : "Token must be at least 16 characters"),
  });
  if (!token) {
    return;
  }
  await vscode.workspace
    .getConfiguration("forgewire")
    .update("hubToken", token.trim(), vscode.ConfigurationTarget.Global);
  await context.secrets.store(SECRET_TOKEN_KEY, token.trim());
  vscode.window.showInformationMessage("ForgeWire: hub token updated.");
  updateStatus();
  refreshAll();
}

async function copyJoinToken(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  let token = (cfg.get<string>("hubToken") ?? "").trim();
  if (!token) {
    token = ((await context.secrets.get(SECRET_TOKEN_KEY)) ?? "").trim();
  }
  if (!token) {
    vscode.window.showWarningMessage(
      "ForgeWire: no hub token stored. Set one with 'ForgeWire: Set Hub Token', then copy it to add nodes."
    );
    return;
  }
  await vscode.env.clipboard.writeText(token);
  const masked =
    token.length > 14 ? `${token.slice(0, 6)}…${token.slice(-4)}` : "(stored)";
  vscode.window.showInformationMessage(
    `ForgeWire: join token copied (${masked}). On a new machine run the installer with -Token <paste> to join this cluster.`
  );
}

async function disconnect(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  await cfg.update("hubUrl", "", vscode.ConfigurationTarget.Global);
  await cfg.update("hubToken", "", vscode.ConfigurationTarget.Global);
  await context.secrets.delete(SECRET_TOKEN_KEY);
  updateStatus();
  refreshAll();
  vscode.window.showInformationMessage("ForgeWire: disconnected.");
}

async function copyToken(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const t = (cfg.get<string>("hubToken") ?? "").trim();
  if (!t) {
    vscode.window.showWarningMessage("ForgeWire: no hub token configured.");
    return;
  }
  await vscode.env.clipboard.writeText(t);
  vscode.window.showInformationMessage("ForgeWire: hub token copied to clipboard.");
}

async function generateToken(): Promise<void> {
  // 32 hex chars (128 bits) via Web Crypto.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const tok = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  await vscode.env.clipboard.writeText(tok);
  vscode.window.showInformationMessage(
    "ForgeWire: generated hub token copied to clipboard. Use 'Set Hub Token\u2026' to save it."
  );
}

// ---------------------------------------------------------------------------
// commands: local hub / runner
// ---------------------------------------------------------------------------

async function startHubHere(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const port = await vscode.window.showInputBox({
    title: "Hub port",
    value: String(cfg.get<number>("autoStartHubPort") ?? 8765),
    validateInput: (v) => (/^\d{2,5}$/.test(v) ? null : "Must be a port number"),
  });
  if (!port) {
    return;
  }

  const cfgUrl = (cfg.get<string>("hubUrl") ?? "").trim();
  const cfgToken = (cfg.get<string>("hubToken") ?? "").trim();
  let token = cfgToken;
  if (!token) {
    const ans = await vscode.window.showQuickPick(
      [
        { label: "Generate a new token", value: "gen" },
        { label: "I'll paste one", value: "paste" },
      ],
      { title: "No token configured. How do you want to set one?" }
    );
    if (!ans) {
      return;
    }
    if (ans.value === "gen") {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      token = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      await vscode.env.clipboard.writeText(token);
      vscode.window.showInformationMessage(
        "ForgeWire: generated token copied to clipboard. Save it somewhere safe."
      );
    } else {
      const t = await vscode.window.showInputBox({
        title: "Hub token",
        password: true,
        validateInput: (v) => (v.trim().length >= 16 ? null : "Min 16 characters"),
      });
      if (!t) {
        return;
      }
      token = t.trim();
    }
  }

  const dbDefault = path.join(os.homedir(), ".forgewire", "hub.sqlite3");
  const dbPath = await vscode.window.showInputBox({
    title: "Hub SQLite path",
    value: dbDefault,
  });
  if (!dbPath) {
    return;
  }

  // Save URL/token so the same VS Code instance can talk to the local hub.
  if (!cfgUrl) {
    await cfg.update(
      "hubUrl",
      `http://127.0.0.1:${port}`,
      vscode.ConfigurationTarget.Global
    );
  }
  await cfg.update("hubToken", token, vscode.ConfigurationTarget.Global);
  await context.secrets.store(SECRET_TOKEN_KEY, token);

  const term = getOrCreateTerminal("ForgeWire: hub", { FORGEWIRE_HUB_TOKEN: token });
  term.show();
  const py = pythonCommand();
  term.sendText(
    `${py} -m forgewire_fabric.cli hub start --host 0.0.0.0 --port ${port} --db-path "${dbPath}"`
  );
  updateStatus();
  setTimeout(refreshAll, 2500);
}

async function startRunnerHere(): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first (or use 'Start Hub Here').");
    return;
  }
  const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir();
  const workspace = await vscode.window.showInputBox({
    title: "Runner workspace root",
    value: wsRoot,
  });
  if (!workspace) {
    return;
  }
  const tags = await vscode.window.showInputBox({
    title: "Capability tags (comma-separated, optional)",
    placeHolder: "linux,gpu:nvidia,python:3.11",
    value: "",
  });
  const scope = await vscode.window.showInputBox({
    title: "Scope prefixes (comma-separated)",
    placeHolder: "src/,tests/",
    value: "",
  });

  const cfg = vscode.workspace.getConfiguration("forgewire");
  const env: Record<string, string> = {
    FORGEWIRE_HUB_URL: c.url,
    FORGEWIRE_HUB_TOKEN: (cfg.get<string>("hubToken") ?? "").trim(),
  };
  const term = getOrCreateTerminal("ForgeWire: runner", env);
  term.show();
  const py = pythonCommand();
  const parts = [`${py} -m forgewire_fabric.cli runner start`, `--workspace-root "${workspace}"`];
  if (tags?.trim()) {
    parts.push(`--tags "${tags.trim()}"`);
  }
  if (scope?.trim()) {
    parts.push(`--scope-prefixes "${scope.trim()}"`);
  }
  term.sendText(parts.join(" "));
  setTimeout(refreshAll, 4000);
}

// ---------------------------------------------------------------------------
// commands: dispatch / inspect
// ---------------------------------------------------------------------------

async function dispatchTask(): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first.");
    return;
  }
  const prompt = await vscode.window.showInputBox({
    title: "ForgeWire \u00b7 Dispatch \u00b7 prompt",
    prompt: "Shell command (default executor) or sealed brief",
    ignoreFocusOut: true,
  });
  if (!prompt) {
    return;
  }
  const scope = await vscode.window.showInputBox({
    title: "Scope globs (comma-separated)",
    placeHolder: "tests/**,src/foo/**",
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim() ? null : "At least one glob is required"),
  });
  if (!scope) {
    return;
  }
  const branch = await vscode.window.showInputBox({
    title: "Per-task branch",
    value: `agent/${os.hostname().toLowerCase()}/dispatch-${Date.now()}`,
    ignoreFocusOut: true,
  });
  if (!branch) {
    return;
  }
  const baseCommit = await vscode.window.showInputBox({
    title: "Base commit (40-char SHA, or 0\u00d740 for no-op)",
    value: "0".repeat(40),
    ignoreFocusOut: true,
    validateInput: (v) => (/^[0-9a-f]{7,64}$/i.test(v.trim()) ? null : "7\u201364 hex chars"),
  });
  if (!baseCommit) {
    return;
  }
  const title = prompt.length > 60 ? `${prompt.slice(0, 57)}\u2026` : prompt;
  const payload = {
    title,
    prompt,
    scope_globs: scope.split(",").map((s) => s.trim()).filter(Boolean),
    branch: branch.trim(),
    base_commit: baseCommit.trim(),
    // M2.8.9: kind is mandatory on dispatch. This quick-pick dispatches agent
    // briefs; Loom command briefs go through the forgewire-loom MCP server.
    kind: "agent" as const,
  };
  try {
    const t = dispatcherSession
      ? await c.dispatchSigned(payload, dispatcherSession)
      : await c.dispatch(payload);
    vscode.window
      .showInformationMessage(`Dispatched task #${t.id}.`, "Tail Stream")
      .then((sel) => {
        if (sel === "Tail Stream") {
          streamTaskCmd(t.id);
        }
      });
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Dispatch failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}


type TaskCommandArg = number | string | { id?: unknown; task?: { id?: unknown } } | TaskNode | undefined;

function resolveTaskId(arg: TaskCommandArg): number | undefined {
  if (typeof arg === "number") {
    return Number.isFinite(arg) && arg > 0 ? Math.trunc(arg) : undefined;
  }
  if (typeof arg === "string") {
    return parseTaskId(arg);
  }
  if (!arg || typeof arg !== "object") {
    return undefined;
  }

  // VS Code tree item context menu commands receive the tree element, not the
  // TreeItem.command arguments. ForgeWire task elements keep the id nested under
  // `task`, while direct invocations and existing Show Task commands pass `id`.
  const direct = "id" in arg ? parseTaskId(arg.id) : undefined;
  if (direct) {
    return direct;
  }
  return "task" in arg ? parseTaskId(arg.task?.id) : undefined;
}

function parseTaskId(value: unknown): number | undefined {
  if (typeof value === "number") {
    return Number.isFinite(value) && value > 0 ? Math.trunc(value) : undefined;
  }
  if (typeof value === "string") {
    const match = /^(?:task(?:History)?:)?(\d+)$/.exec(value.trim());
    if (!match) {
      return undefined;
    }
    const parsed = Number(match[1]);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
  }
  return undefined;
}

async function streamTaskCmd(arg: TaskCommandArg): Promise<void> {
  const c = getClient();
  if (!c) {
    return;
  }
  const id = resolveTaskId(arg);
  if (!id) {
    vscode.window.showWarningMessage("Select a task first.");
    return;
  }
  outputChannel.show(true);
  outputChannel.appendLine(`\n--- streaming task #${id} ---`);
  const ctrl = new AbortController();
  const sub = vscode.workspace.onDidChangeConfiguration(() => {});
  try {
    for await (const ev of c.streamEvents(id, ctrl.signal)) {
      if (ev.event === "stream_line") {
        // Polling fallback format (Rust hub): {seq, channel, line, worker_id?}
        try {
          const obj = JSON.parse(ev.data) as { channel?: string; line?: string };
          const prefix = obj.channel === "stderr" ? "[ERR]" : "[OUT]";
          outputChannel.appendLine(`${prefix} ${obj.line ?? ev.data}`);
        } catch {
          outputChannel.appendLine(ev.data);
        }
      } else if (ev.event === "progress") {
        // SSE progress event (Python hub): {message, seq, files_touched?}
        try {
          const obj = JSON.parse(ev.data) as { message?: string };
          outputChannel.appendLine(`[progress] ${obj.message ?? ev.data}`);
        } catch {
          outputChannel.appendLine(`[progress] ${ev.data}`);
        }
      } else if (ev.event === "task") {
        try {
          const obj = JSON.parse(ev.data);
          if (obj?.status && ["done", "failed", "cancelled", "timed_out"].includes(obj.status)) {
            outputChannel.appendLine(`--- task #${id} terminal: ${obj.status} ---`);
            break;
          }
        } catch {
          // ignore parse errors; just keep streaming
        }
      } else {
        outputChannel.appendLine(`[${ev.event}] ${ev.data}`);
      }
    }
  } catch (err) {
    outputChannel.appendLine(
      `--- stream error: ${err instanceof Error ? err.message : String(err)} ---`
    );
  } finally {
    sub.dispose();
  }
}

async function cancelTaskCmd(arg: TaskCommandArg): Promise<void> {
  const c = getClient();
  if (!c) {
    return;
  }
  const id = resolveTaskId(arg);
  if (!id) {
    vscode.window.showWarningMessage("Select a task first.");
    return;
  }
  const ok = await vscode.window.showWarningMessage(
    `Cancel task #${id}?`,
    { modal: true },
    "Cancel Task"
  );
  if (ok !== "Cancel Task") {
    return;
  }
  try {
    await c.cancel(id);
    vscode.window.showInformationMessage(`Cancelled task #${id}.`);
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Cancel failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// ---- Redispatch a failed/cancelled task ----------------------------------------
// Reads the original task params and submits a fresh dispatch with the same
// title, prompt, scope_globs, base_commit, branch, kind, priority, and timeout.

async function redispatchTaskCmd(arg: TaskCommandArg): Promise<void> {
  const c = getClient();
  if (!c) { return; }
  const id = resolveTaskId(arg);
  if (!id) {
    vscode.window.showWarningMessage("Select a task first.");
    return;
  }
  try {
    const t = await c.getTask(id);
    const payload = {
      title: t.title,
      prompt: t.prompt,
      scope_globs: t.scope_globs ?? [],
      base_commit: t.base_commit,
      branch: t.branch,
      kind: t.kind,
      priority: t["priority"] as number | undefined,
      timeout_minutes: t["timeout_minutes"] as number | undefined,
    };
    const newTask = dispatcherSession
      ? await c.dispatchSigned(payload, dispatcherSession)
      : await c.dispatch(payload);
    vscode.window.showInformationMessage(
      `Redispatched as task #${newTask.id}.`
    );
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Redispatch failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// ---- Dismiss a history task from the VSIX view --------------------------------
// Does NOT delete the task from the hub — it is hidden from the history panel
// and the dismissal is persisted in extension globalState.

function dismissTaskCmd(arg: TaskCommandArg): void {
  const id = resolveTaskId(arg);
  if (!id) {
    vscode.window.showWarningMessage("Select a task first.");
    return;
  }
  tasksProvider.dismissTask(id);
}

// ---- Cancel a stale queued task -----------------------------------------------

async function cancelStaleTaskCmd(arg: TaskCommandArg): Promise<void> {
  const c = getClient();
  if (!c) { return; }
  const id = resolveTaskId(arg);
  if (!id) {
    vscode.window.showWarningMessage("Select a task first.");
    return;
  }
  try {
    await c.cancel(id);
    vscode.window.showInformationMessage(`Cancelled stale task #${id}.`);
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Cancel failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function showTaskCmd(arg: TaskCommandArg): Promise<void> {
  const c = getClient();
  if (!c) {
    return;
  }
  const id = resolveTaskId(arg);
  if (!id) {
    vscode.window.showWarningMessage("Select a task first.");
    return;
  }
  try {
    const t = await c.getTask(id);
    const doc = await vscode.workspace.openTextDocument({
      content: JSON.stringify(t, null, 2),
      language: "json",
    });
    vscode.window.showTextDocument(doc, { preview: true });
  } catch (err) {
    vscode.window.showErrorMessage(
      `Show failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function approveApprovalCmd(arg: ApprovalCommandArg): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first.");
    return;
  }
  const approval = await resolveApprovalArg(arg, c);
  if (!approval) return;
  const label = approval.task_label || approval.approval_id;
  const ok = await vscode.window.showWarningMessage(
    `Approve ${label}?`,
    { modal: true },
    "Approve",
    "Examine"
  );
  if (ok === "Examine") {
    await examineApprovalCmd(approval);
    return;
  }
  if (ok !== "Approve") return;
  const reason = await vscode.window.showInputBox({
    title: "Approval note (optional)",
    placeHolder: "Approved from VS Code",
    ignoreFocusOut: true,
  });
  try {
    await c.approveApproval(approval.approval_id, defaultApprover(), reason ?? "Approved from VS Code");
    await removeSnoozedApproval(approval.approval_id);
    vscode.window.showInformationMessage(`Approved ${label}.`);
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(`Approve failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function denyApprovalCmd(arg: ApprovalCommandArg): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first.");
    return;
  }
  const approval = await resolveApprovalArg(arg, c);
  if (!approval) return;
  const label = approval.task_label || approval.approval_id;
  const reason = await vscode.window.showInputBox({
    title: `Deny ${label}`,
    prompt: "Reason for denial",
    ignoreFocusOut: true,
    validateInput: (value) => (value.trim() ? null : "A denial reason is required"),
  });
  if (!reason) return;
  try {
    await c.denyApproval(approval.approval_id, defaultApprover(), reason.trim());
    await removeSnoozedApproval(approval.approval_id);
    vscode.window.showInformationMessage(`Denied ${label}.`);
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(`Deny failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function deferApprovalCmd(arg: ApprovalCommandArg): Promise<void> {
  const c = getClient();
  const approval = await resolveApprovalArg(arg, c);
  if (!approval) return;
  const snooze = await pickSnoozeDuration(approval);
  if (!snooze) return;
  await setSnoozedApproval(approval, snooze.expiresAt);
  updateStatus();
  approvalsProvider?.refresh();
  vscode.window.showInformationMessage(
    `Snoozed ${approval.task_label || approval.approval_id} until ${formatLocalDateTime(snooze.expiresAt)}.`,
    "Show Snoozed"
  ).then((selection) => {
    if (selection === "Show Snoozed") {
      showDeferredApprovalsCmd();
    }
  });
}

async function showDeferredApprovalsCmd(): Promise<void> {
  snoozedApprovals.clear();
  await persistSnoozedApprovals();
  updateStatus();
  approvalsProvider?.refresh();
}

async function examineApprovalCmd(arg: ApprovalCommandArg): Promise<void> {
  const c = getClient();
  const approval = await resolveApprovalArg(arg, c);
  if (!approval) return;
  let fresh = approval;
  if (c) {
    fresh = await c.getApproval(approval.approval_id).catch(() => approval);
  }
  const doc = await vscode.workspace.openTextDocument({
    content: JSON.stringify(expandApprovalForDisplay(fresh), null, 2),
    language: "json",
  });
  await vscode.window.showTextDocument(doc, { preview: true });
}

async function copyApprovalReferenceCmd(arg: ApprovalCommandArg): Promise<void> {
  const c = getClient();
  const approval = await resolveApprovalArg(arg, c);
  if (!approval) return;
  const picks: Array<{ label: string; description: string; value: string }> = [
    { label: "Approval ID", description: approval.approval_id, value: approval.approval_id },
  ];
  if (approval.envelope_hash) {
    picks.push({ label: "Envelope hash", description: approval.envelope_hash, value: approval.envelope_hash });
  }
  const selected = picks.length === 1
    ? picks[0]
    : await vscode.window.showQuickPick(picks, {
        title: "Copy approval reference",
        placeHolder: "Choose the value to copy",
        ignoreFocusOut: true,
      });
  if (!selected) return;
  await vscode.env.clipboard.writeText(selected.value);
  vscode.window.showInformationMessage(`Copied ${selected.label.toLowerCase()}.`);
}

type ApprovalCommandArg = string | ApprovalInfo | ApprovalNode | undefined;

interface SnoozedApproval {
  approvalId: string;
  label: string;
  snoozedAt: number;
  expiresAt: number;
}

async function resolveApprovalArg(arg: ApprovalCommandArg, client?: HubClient): Promise<ApprovalInfo | undefined> {
  if (!arg) return undefined;
  if (typeof arg === "string") {
    return client?.getApproval(arg).catch(() => undefined);
  }
  if (isApprovalNode(arg)) {
    return arg.approval;
  }
  if ("approval_id" in arg) {
    return arg;
  }
  return undefined;
}

function isApprovalNode(arg: ApprovalInfo | ApprovalNode): arg is Extract<ApprovalNode, { kind: "approval" }> {
  return "kind" in arg && arg.kind === "approval";
}

function defaultApprover(): string {
  const username = os.userInfo().username || "vscode";
  return `${username}@${os.hostname()}`;
}

function approvalAgeBadgeHours(): number {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  return Math.max(1, cfg.get<number>("approvals.ageBadgeHours") ?? 24);
}

function getSnoozedApproval(approvalId: string): SnoozedApproval | undefined {
  pruneExpiredSnoozes();
  return snoozedApprovals.get(approvalId);
}

function loadSnoozedApprovals(): void {
  const stored = context.globalState.get<SnoozedApproval[]>(SNOOZED_APPROVALS_KEY, []);
  snoozedApprovals.clear();
  const now = Date.now();
  for (const item of stored) {
    if (!item?.approvalId || !Number.isFinite(item.expiresAt) || item.expiresAt <= now) {
      continue;
    }
    snoozedApprovals.set(item.approvalId, item);
  }
  void persistSnoozedApprovals();
}

function pruneExpiredSnoozes(): void {
  const now = Date.now();
  let changed = false;
  for (const [approvalId, item] of snoozedApprovals) {
    if (item.expiresAt <= now) {
      snoozedApprovals.delete(approvalId);
      changed = true;
    }
  }
  if (changed) {
    void persistSnoozedApprovals();
  }
}

async function setSnoozedApproval(approval: ApprovalInfo, expiresAt: number): Promise<void> {
  snoozedApprovals.set(approval.approval_id, {
    approvalId: approval.approval_id,
    label: approval.task_label || approval.approval_id,
    snoozedAt: Date.now(),
    expiresAt,
  });
  await persistSnoozedApprovals();
}

async function removeSnoozedApproval(approvalId: string): Promise<void> {
  if (snoozedApprovals.delete(approvalId)) {
    await persistSnoozedApprovals();
  }
}

async function persistSnoozedApprovals(): Promise<void> {
  await context.globalState.update(SNOOZED_APPROVALS_KEY, Array.from(snoozedApprovals.values()));
}

async function pickSnoozeDuration(approval: ApprovalInfo): Promise<{ expiresAt: number } | undefined> {
  const now = Date.now();
  const selection = await vscode.window.showQuickPick(
    [
      { label: "1 hour", expiresAt: now + 60 * 60 * 1000 },
      { label: "4 hours", expiresAt: now + 4 * 60 * 60 * 1000 },
      { label: "Tomorrow", expiresAt: now + 24 * 60 * 60 * 1000 },
      { label: "1 week", expiresAt: now + 7 * 24 * 60 * 60 * 1000 },
      { label: "Custom...", expiresAt: 0 },
    ],
    {
      title: `Snooze ${approval.task_label || approval.approval_id}`,
      placeHolder: "Hide this approval locally until...",
      ignoreFocusOut: true,
    }
  );
  if (!selection) return undefined;
  if (selection.expiresAt > 0) {
    return { expiresAt: selection.expiresAt };
  }
  const hours = await vscode.window.showInputBox({
    title: "Custom snooze duration",
    prompt: "Hours to hide this approval locally",
    value: "8",
    ignoreFocusOut: true,
    validateInput: (value) => {
      const parsed = Number(value.trim());
      if (!Number.isFinite(parsed) || parsed <= 0) return "Enter a positive number of hours";
      if (parsed > 24 * 30) return "Maximum snooze is 30 days";
      return null;
    },
  });
  if (!hours) return undefined;
  return { expiresAt: now + Number(hours.trim()) * 60 * 60 * 1000 };
}

function formatLocalDateTime(timestamp: number): string {
  return new Date(timestamp).toLocaleString();
}

function expandApprovalForDisplay(approval: ApprovalInfo): Record<string, unknown> {
  const expanded: Record<string, unknown> = { ...approval };
  if (typeof approval.scope_globs_json === "string") {
    try {
      expanded.scope_globs = JSON.parse(approval.scope_globs_json);
    } catch {
      expanded.scope_globs = approval.scope_globs_json;
    }
  }
  if (typeof approval.decision_json === "string") {
    try {
      expanded.decision = JSON.parse(approval.decision_json);
    } catch {
      expanded.decision = approval.decision_json;
    }
  }
  return expanded;
}

// ---------------------------------------------------------------------------
// commands: settings panel (role / hub url / token / port / workspace)
// ---------------------------------------------------------------------------

let settingsPanel: vscode.WebviewPanel | undefined;

async function renameHub(): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first \u2014 hub names are stored on the hub and propagate to all connected nodes.");
    return;
  }
  let current = "";
  try {
    current = (await c.getLabels()).hub_name ?? "";
  } catch {
    /* ignore; allow rename anyway */
  }
  const name = await vscode.window.showInputBox({
    title: "Hub display name (fabric-wide)",
    prompt: "Friendly name for this hub. Leave blank to clear.",
    value: current,
    ignoreFocusOut: true,
    validateInput: (v) => (v.length <= 80 ? null : "Max 80 chars"),
  });
  if (name === undefined) {
    return;
  }
  const trimmed = name.trim();
  const verb = trimmed === "" ? "clear the hub name" : `rename this hub to "${trimmed}"`;
  const ok = await vscode.window.showWarningMessage(
    `This will ${verb} for every node connected to ${labelForUrl(c.url)}.\n\n` +
      `The change is stored on the hub and propagates to all clients on their next refresh. Continue?`,
    { modal: true },
    "Apply Fabric-Wide"
  );
  if (ok !== "Apply Fabric-Wide") {
    return;
  }
  try {
    await c.setHubName(trimmed, os.hostname());
    vscode.window.showInformationMessage(
      trimmed === ""
        ? "Hub name cleared fabric-wide."
        : `Hub renamed to "${trimmed}" fabric-wide.`
    );
    updateStatus();
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Hub rename failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function renameHost(arg?: unknown): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first -- host labels are stored on the hub and propagate to all connected nodes.");
    return;
  }
  let hostname: string | undefined;
  if (typeof arg === "string") {
    hostname = arg;
  } else if (arg && typeof arg === "object") {
    const candidate = arg as Record<string, unknown>;
    const host = candidate.host as Record<string, unknown> | undefined;
    hostname = typeof host?.hostname === "string" ? host.hostname : undefined;
    if (!hostname && typeof candidate.hostname === "string") {
      hostname = candidate.hostname;
    }
  }

  let hosts: Array<{ hostname: string; display_name?: string; label?: string }> = [];
  try {
    hosts = await c.listHosts();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Could not list hosts: ${err instanceof Error ? err.message : String(err)}`
    );
    return;
  }

  if (!hostname) {
    const pick = await vscode.window.showQuickPick(
      hosts.map((h) => ({
        label: h.display_name || h.label || h.hostname,
        description: h.hostname,
        hostname: h.hostname,
      })),
      { title: "Pick a host to rename (fabric-wide)" }
    );
    if (!pick) {
      return;
    }
    hostname = pick.hostname;
  }

  const labels = await c.getLabels().catch(() => ({
    hub_name: "",
    runner_aliases: {} as Record<string, string>,
    host_aliases: {} as Record<string, string>,
  }));
  const currentAlias = labels.host_aliases?.[hostname] ?? "";
  const next = await vscode.window.showInputBox({
    title: `Label for host ${hostname} (fabric-wide)`,
    prompt: "Friendly machine name. Leave blank to clear.",
    value: currentAlias,
    ignoreFocusOut: true,
    validateInput: (v) => (v.length <= 80 ? null : "Max 80 chars"),
  });
  if (next === undefined) {
    return;
  }
  const trimmed = next.trim();
  const verb = trimmed === "" ? `clear the label for ${hostname}` : `label ${hostname} as "${trimmed}"`;
  const ok = await vscode.window.showWarningMessage(
    `This will ${verb} for every node connected to ${labelForUrl(c.url)}.\n\n` +
      `The change is stored on the hub and propagates to all clients on their next refresh. Continue?`,
    { modal: true },
    "Apply Fabric-Wide"
  );
  if (ok !== "Apply Fabric-Wide") {
    return;
  }
  try {
    await c.setHostAlias(hostname, trimmed, os.hostname());
    vscode.window.showInformationMessage(
      trimmed === ""
        ? `Cleared label for ${hostname} fabric-wide.`
        : `Labeled ${hostname} as "${trimmed}" fabric-wide.`
    );
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Host rename failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function renameRunner(arg?: unknown): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first \u2014 runner aliases are stored on the hub and propagate to all connected nodes.");
    return;
  }
  let runnerId: string | undefined;
  let runnerHost: string | undefined;
  if (typeof arg === "string") {
    runnerId = arg;
  } else if (arg && typeof arg === "object") {
    const a = arg as Record<string, unknown>;
    // Direct runner_id at top level (command-palette or old call shapes).
    if (typeof a.runner_id === "string") {
      runnerId = a.runner_id;
      runnerHost = typeof a.hostname === "string" ? a.hostname : undefined;
    }
    // Hosts-panel role node: { kind: "role", runner: RunnerInfo, ... }
    // or runner node: { kind: "runner", runner: RunnerInfo }
    const nested = a.runner as Record<string, unknown> | undefined;
    if (!runnerId && nested && typeof nested === "object" && typeof nested.runner_id === "string") {
      runnerId = nested.runner_id;
      runnerHost = typeof nested.hostname === "string" ? nested.hostname : undefined;
    }
  }

  let runners: { runner_id: string; hostname: string }[] = [];
  try {
    runners = (await c.listRunners()) as { runner_id: string; hostname: string }[];
  } catch (err) {
    vscode.window.showErrorMessage(
      `Could not list runners: ${err instanceof Error ? err.message : String(err)}`
    );
    return;
  }
  let labels: { runner_aliases: Record<string, string>; host_aliases: Record<string, string> } = {
    runner_aliases: {},
    host_aliases: {},
  };
  try {
    const payload = await c.getLabels();
    labels = {
      runner_aliases: payload.runner_aliases ?? {},
      host_aliases: payload.host_aliases ?? {},
    };
  } catch {
    /* ignore */
  }

  if (!runnerId) {
    const pick = await vscode.window.showQuickPick(
      runners.map((r) => ({
        label: labels.runner_aliases[r.runner_id] || labels.host_aliases[r.hostname] || r.hostname || r.runner_id.slice(0, 8),
        description: r.hostname,
        detail: r.runner_id,
        runner_id: r.runner_id,
        hostname: r.hostname,
      })),
      { title: "Pick a runner to rename (fabric-wide)" }
    );
    if (!pick) {
      return;
    }
    runnerId = pick.runner_id;
    runnerHost = pick.hostname;
  } else if (!runnerHost) {
    runnerHost = runners.find((r) => r.runner_id === runnerId)?.hostname;
  }

  const isThisHost = !!runnerHost && runnerHost.toLowerCase() === os.hostname().toLowerCase();
  const currentAlias = labels.runner_aliases[runnerId] ?? "";
  const next = await vscode.window.showInputBox({
    title: `Alias for runner ${runnerHost ?? runnerId.slice(0, 8)} (fabric-wide)`,
    prompt: "Friendly name for this runner. Leave blank to clear.",
    value: currentAlias,
    ignoreFocusOut: true,
    validateInput: (v) => (v.length <= 80 ? null : "Max 80 chars"),
  });
  if (next === undefined) {
    return;
  }
  const trimmed = next.trim();
  const target = runnerHost ?? runnerId.slice(0, 8);
  const verb = trimmed === "" ? `clear the alias for ${target}` : `alias ${target} as "${trimmed}"`;
  const sameNodeNote = isThisHost
    ? ""
    : `\n\nNote: you are renaming a runner on a different node (${target}). `;
  const ok = await vscode.window.showWarningMessage(
    `This will ${verb} for every node connected to ${labelForUrl(c.url)}.${sameNodeNote}\n\n` +
      `The change is stored on the hub and propagates to all clients on their next refresh. Continue?`,
    { modal: true },
    "Apply Fabric-Wide"
  );
  if (ok !== "Apply Fabric-Wide") {
    return;
  }
  try {
    await c.setRunnerAlias(runnerId, trimmed, os.hostname());
    vscode.window.showInformationMessage(
      trimmed === ""
        ? `Cleared alias for ${target} fabric-wide.`
        : `Aliased ${target} as "${trimmed}" fabric-wide.`
    );
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Rename failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// ---------------------------------------------------------------------------
// commands: runner control (pause/resume via hub; start/stop/restart local)
// ---------------------------------------------------------------------------

interface RunnerArg {
  runner_id?: string;
  hostname?: string;
  state?: string;
}

function extractRunnerArg(arg: unknown): RunnerArg | undefined {
  if (!arg) return undefined;
  if (typeof arg === "string") return { runner_id: arg };
  if (typeof arg !== "object") return undefined;
  const a = arg as Record<string, unknown>;
  // Tree node may wrap the runner under .runner.
  if (a.kind === "runner" && a.runner && typeof a.runner === "object") {
    return a.runner as RunnerArg;
  }
  if (a.runner && typeof a.runner === "object") {
    return a.runner as RunnerArg;
  }
  return a as RunnerArg;
}

async function pickRunnerIfMissing(arg: unknown): Promise<RunnerArg | undefined> {
  const ra = extractRunnerArg(arg);
  if (ra?.runner_id) return ra;
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first.");
    return undefined;
  }
  let runners: RunnerArg[] = [];
  try {
    runners = (await c.listRunners()) as RunnerArg[];
  } catch (err) {
    vscode.window.showErrorMessage(
      `Could not list runners: ${err instanceof Error ? err.message : String(err)}`
    );
    return undefined;
  }
  const labels = await c.getLabels().catch(() => ({
    hub_name: "",
    runner_aliases: {} as Record<string, string>,
    host_aliases: {} as Record<string, string>,
  }));
  const aliases = labels.runner_aliases ?? {};
  const hostAliases = labels.host_aliases ?? {};
  const pick = await vscode.window.showQuickPick(
    runners.map((r) => ({
      label: aliases[r.runner_id ?? ""] || hostAliases[r.hostname ?? ""] || r.hostname || (r.runner_id ?? "").slice(0, 8),
      description: r.hostname,
      detail: `${r.runner_id} \u00b7 ${r.state}`,
      runner: r,
    })),
    { title: "Pick a runner" }
  );
  return pick?.runner;
}

async function pauseRunner(arg?: unknown): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first.");
    return;
  }
  const r = await pickRunnerIfMissing(arg);
  if (!r?.runner_id) return;
  const target = r.hostname ?? r.runner_id.slice(0, 8);
  const ok = await vscode.window.showWarningMessage(
    `Pause runner ${target}? It will finish current tasks but stop accepting new ones.`,
    { modal: true },
    "Pause"
  );
  if (ok !== "Pause") return;
  try {
    await c.drainRunner(r.runner_id);
    vscode.window.showInformationMessage(`Pause requested for ${target}.`);
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Pause failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function resumeRunner(arg?: unknown): Promise<void> {
  const c = getClient();
  if (!c) {
    vscode.window.showWarningMessage("Connect to a hub first.");
    return;
  }
  const r = await pickRunnerIfMissing(arg);
  if (!r?.runner_id) return;
  const target = r.hostname ?? r.runner_id.slice(0, 8);
  try {
    await c.undrainRunner(r.runner_id);
    vscode.window.showInformationMessage(`Resumed ${target}.`);
    refreshAll();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Resume failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function localServiceAction(action: "start" | "stop" | "restart", arg?: unknown): Promise<void> {
  const r = extractRunnerArg(arg);
  // For local actions we ignore the picker — only act on this host.
  if (r && r.hostname && r.hostname.toLowerCase() !== os.hostname().toLowerCase()) {
    vscode.window.showWarningMessage(
      `Cannot ${action} runner on remote host ${r.hostname} from here. ${action === "start" ? "Start" : action === "stop" ? "Stop" : "Restart"} it on that machine, or use SSH.`
    );
    return;
  }
  if (process.platform !== "win32") {
    vscode.window.showWarningMessage(
      `Local service control is currently only wired for Windows (NSSM). On macOS/Linux, manage the systemd/launchd unit directly.`
    );
    return;
  }
  const verb = action === "restart" ? "Restart" : action === "start" ? "Start" : "Stop";
  const ok = await vscode.window.showWarningMessage(
    `${verb} the local ForgeWireRunner Windows service? You'll get a UAC prompt.`,
    { modal: true },
    verb
  );
  if (ok !== verb) return;
  // Use a self-elevating PowerShell one-liner so the user only sees one UAC.
  const ps = `Start-Process -Verb RunAs -Wait -FilePath nssm.exe -ArgumentList '${action}','ForgeWireRunner'`;
  const term = getOrCreateTerminal(`ForgeWire: runner ${action}`);
  term.show();
  term.sendText(`powershell -NoProfile -Command "${ps}"`);
  setTimeout(refreshAll, 4000);
}

async function restartRunnerService(arg?: unknown): Promise<void> {
  return localServiceAction("restart", arg);
}

async function startRunnerService(arg?: unknown): Promise<void> {
  return localServiceAction("start", arg);
}

async function stopRunnerService(arg?: unknown): Promise<void> {
  return localServiceAction("stop", arg);
}

// ---------------------------------------------------------------------------
// commands: failover (pin / unpin / promote / demote / edit candidates)
// ---------------------------------------------------------------------------

async function pinHub(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const candidates = (cfg.get<Array<{ url: string; label?: string }>>("hubCandidates") ?? []);
  const items: vscode.QuickPickItem[] = [
    ...candidates.map((c) => ({ label: c.url, description: c.label || "" })),
    { label: "Other URL\u2026", description: "Type a hub URL manually" },
  ];
  const pick = await vscode.window.showQuickPick(items, {
    title: "Pin to which hub URL?",
    placeHolder: "Pinning disables auto-failover until you unpin.",
  });
  if (!pick) return;
  let url = pick.label;
  if (url === "Other URL\u2026") {
    const typed = await vscode.window.showInputBox({
      title: "Pin to hub URL",
      placeHolder: "http://hub-host:8765",
      validateInput: (v) => (/^https?:\/\//i.test(v.trim()) ? null : "Must start with http:// or https://"),
    });
    if (!typed) return;
    url = typed.trim();
  }
  await cfg.update("hubPin", url, vscode.ConfigurationTarget.Global);
  vscode.window.showInformationMessage(`Pinned to ${url}. Failover is now disabled.`);
  refreshAll();
}

async function unpinHub(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  await cfg.update("hubPin", "", vscode.ConfigurationTarget.Global);
  vscode.window.showInformationMessage("Unpinned. Failover re-enabled.");
  refreshAll();
}

async function editHubCandidates(): Promise<void> {
  // Open the JSON settings UI focused on the candidates array.
  await vscode.commands.executeCommand(
    "workbench.action.openSettings",
    "forgewire.hubCandidates"
  );
}

async function promoteHub(): Promise<void> {
  const ok = await vscode.window.showWarningMessage(
    "Promote this node to active hub?\n\n" +
      "This will start the local hub service. If another hub is already serving on the candidate list, promotion will be refused (split-brain guard) -- demote that one first, or pass --force from the CLI.",
    { modal: true },
    "Promote"
  );
  if (ok !== "Promote") return;
  if (process.platform !== "win32") {
    vscode.window.showWarningMessage(
      "Promote currently launches NSSM via PowerShell on Windows. On macOS/Linux, run `forgewire hub promote` manually."
    );
    return;
  }
  const term = getOrCreateTerminal("ForgeWire: promote");
  term.show();
  // Use the bundled python exe; setup wizard wires PYTHONHOME automatically.
  term.sendText(
    'powershell -NoProfile -Command "Start-Process -Verb RunAs -Wait -FilePath python -ArgumentList \'-m\',\'forgewire_fabric.cli\',\'hub\',\'promote\'"'
  );
  setTimeout(refreshAll, 6000);
}

async function demoteHub(): Promise<void> {
  const probe = lastProbe;
  const target = probe?.activeUrl ?? "(active hub)";
  const ok = await vscode.window.showWarningMessage(
    `Demote ${target}?\n\n` +
      "This drains all runners, pushes a final SQLite snapshot to peers in the candidate list, then stops the hub service. After this, the next-priority candidate should be Promoted.",
    { modal: true },
    "Demote"
  );
  if (ok !== "Demote") return;
  if (process.platform !== "win32") {
    vscode.window.showWarningMessage(
      "Demote currently launches NSSM via PowerShell on Windows. On macOS/Linux, run `forgewire hub demote` manually."
    );
    return;
  }
  const term = getOrCreateTerminal("ForgeWire: demote");
  term.show();
  term.sendText(
    'powershell -NoProfile -Command "Start-Process -Verb RunAs -Wait -FilePath python -ArgumentList \'-m\',\'forgewire_fabric.cli\',\'hub\',\'demote\'"'
  );
  setTimeout(refreshAll, 6000);
}

async function openSettings(): Promise<void> {
  if (settingsPanel) {
    settingsPanel.reveal(vscode.ViewColumn.Active);
    return;
  }
  const panel = vscode.window.createWebviewPanel(
    "forgewire.settingsWebview",
    "ForgeWire Settings",
    vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: true }
  );
  settingsPanel = panel;
  panel.onDidDispose(() => {
    settingsPanel = undefined;
  });

  const cfg = vscode.workspace.getConfiguration("forgewire");
  const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir();
  const initial = {
    hubUrl: cfg.get<string>("hubUrl") ?? "",
    hubToken: cfg.get<string>("hubToken") ?? "",
    hubTokenFile: cfg.get<string>("hubTokenFile") ?? "",
    pythonPath: cfg.get<string>("pythonPath") ?? "",
    refreshIntervalSeconds: cfg.get<number>("refreshIntervalSeconds") ?? 10,
    autoStartHubPort: cfg.get<number>("autoStartHubPort") ?? 8765,
    workspaceRoot: wsRoot,
    staleQueuedMinutes: cfg.get<number>("tasks.staleQueuedMinutes") ?? 30,
    approvalAgeBadgeHours: cfg.get<number>("approvals.ageBadgeHours") ?? 24,
    clusterRepoRoot: cfg.get<string>("cluster.repoRoot") ?? "",
    clusterPreferredNode: cfg.get<string>("cluster.preferredNode") ?? "",
  };

  panel.webview.html = settingsHtml(initial);

  panel.webview.onDidReceiveMessage(async (msg) => {
    try {
      if (msg?.type === "save") {
        const c = vscode.workspace.getConfiguration("forgewire");
        await c.update("hubUrl", String(msg.hubUrl ?? "").trim(), vscode.ConfigurationTarget.Global);
        await c.update("hubTokenFile", String(msg.hubTokenFile ?? "").trim(), vscode.ConfigurationTarget.Global);
        await c.update("pythonPath", String(msg.pythonPath ?? "").trim(), vscode.ConfigurationTarget.Global);
        await c.update("refreshIntervalSeconds", Number(msg.refreshIntervalSeconds) || 10, vscode.ConfigurationTarget.Global);
        await c.update("autoStartHubPort", Number(msg.autoStartHubPort) || 8765, vscode.ConfigurationTarget.Global);
        await c.update("tasks.staleQueuedMinutes", Number(msg.staleQueuedMinutes) ?? 30, vscode.ConfigurationTarget.Global);
        await c.update("approvals.ageBadgeHours", Number(msg.approvalAgeBadgeHours) || 24, vscode.ConfigurationTarget.Global);
        await c.update("cluster.repoRoot", String(msg.clusterRepoRoot ?? "").trim(), vscode.ConfigurationTarget.Global);
        await c.update("cluster.preferredNode", String(msg.clusterPreferredNode ?? "").trim(), vscode.ConfigurationTarget.Global);
        const tok = String(msg.hubToken ?? "").trim();
        if (tok) {
          await c.update("hubToken", tok, vscode.ConfigurationTarget.Global);
          await context.secrets.store(SECRET_TOKEN_KEY, tok);
        }
        vscode.window.showInformationMessage("ForgeWire: settings saved.");
        updateStatus();
        scheduleRefresh();
        refreshAll();
      } else if (msg?.type === "test") {
        const c = HubClient.fromConfig();
        if (!c) {
          panel.webview.postMessage({ type: "testResult", ok: false, error: "no hub configured" });
          return;
        }
        try {
          const h = await c.healthz();
          panel.webview.postMessage({
            type: "testResult",
            ok: true,
            url: c.url,
            status: h.status,
            version: h.version,
            protocol: h.protocol_version,
          });
        } catch (err) {
          panel.webview.postMessage({
            type: "testResult",
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      } else if (msg?.type === "applySetup") {
        const role = String(msg.role ?? "runner");
        const wsr = String(msg.workspaceRoot ?? "").trim() || (vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir());
        const url = String(msg.hubUrl ?? "").trim();
        const tok = String(msg.hubToken ?? "").trim();
        const port = Number(msg.autoStartHubPort) || 8765;
        const parts = [
          `${pythonCommand()} -m forgewire_fabric.cli setup`,
          `--role ${role}`,
          `--port ${port}`,
          `--workspace-root "${wsr}"`,
        ];
        if (url) {
          parts.push(`--hub-url "${url}"`);
        }
        if (tok) {
          parts.push(`--hub-token "${tok}"`);
        }
        const term = getOrCreateTerminal("ForgeWire: setup");
        term.show();
        term.sendText(parts.join(" "));
        vscode.window.showInformationMessage(
          "ForgeWire: running 'setup' in terminal. Watch for the UAC prompt on Windows."
        );
      } else if (msg?.type === "generateToken") {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        const tok = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
        panel.webview.postMessage({ type: "generatedToken", token: tok });
      }
    } catch (err) {
      vscode.window.showErrorMessage(
        `Settings action failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  });
}

function settingsHtml(init: Record<string, unknown>): string {
  const json = JSON.stringify(init).replace(/</g, "\\u003c");
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px; max-width: 720px; }
  h1 { font-size: 1.4em; margin-top: 0; }
  h2 { font-size: 1.05em; margin-top: 24px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 4px; }
  label { display: block; margin: 12px 0 4px; font-weight: 600; }
  .hint { font-size: 0.85em; color: var(--vscode-descriptionForeground); margin-bottom: 4px; }
  input[type=text], input[type=password], input[type=number], select {
    width: 100%; padding: 6px 8px;
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, transparent);
    border-radius: 2px;
    box-sizing: border-box;
  }
  .row { display: flex; gap: 8px; }
  .row > * { flex: 1; }
  button {
    margin-top: 12px; padding: 6px 14px;
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none; border-radius: 2px; cursor: pointer;
  }
  button.secondary {
    background: var(--vscode-button-secondaryBackground);
    color: var(--vscode-button-secondaryForeground);
  }
  button:hover { background: var(--vscode-button-hoverBackground); }
  .actions { margin-top: 20px; display: flex; gap: 8px; flex-wrap: wrap; }
  #result { margin-top: 12px; padding: 8px; border-radius: 2px; white-space: pre-wrap; font-family: var(--vscode-editor-font-family); display: none; }
  #result.ok { background: var(--vscode-testing-iconPassed, #387a3833); }
  #result.err { background: var(--vscode-testing-iconFailed, #aa000033); }
  fieldset { border: 1px solid var(--vscode-panel-border); border-radius: 2px; padding: 8px 12px; }
  fieldset legend { padding: 0 6px; font-weight: 600; }
  .role-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; }
  .role-grid label { font-weight: 400; display: flex; align-items: center; gap: 6px; margin: 0; }
</style>
</head>
<body>
<h1>ForgeWire Settings</h1>
<p class="hint">These settings are saved to your VS Code user settings. The token is also written to SecretStorage when you click <strong>Save</strong>.</p>

<h2>Connection</h2>
<label for="hubUrl">Hub URL</label>
<div class="hint">e.g. <code>http://hub-host:8765</code></div>
<input type="text" id="hubUrl" />

<label for="hubToken">Hub token</label>
<div class="hint">32+ hex chars. Saved to SecretStorage. Leave blank to keep the existing one or to read from a token file.</div>
<div class="row">
  <input type="password" id="hubToken" placeholder="(unchanged)" />
  <button class="secondary" id="genBtn" type="button">Generate</button>
</div>

<label for="hubTokenFile">Token file (optional)</label>
<div class="hint">Path read when the token field is empty. Default: <code>~/.forgewire/hub.token</code>.</div>
<input type="text" id="hubTokenFile" />

<h2>Install / role (one-shot setup)</h2>
<p class="hint">Drives <code>forgewire setup</code> in a terminal. On Windows the installer self-elevates (UAC).</p>
<fieldset>
  <legend>Role</legend>
  <div class="role-grid">
    <label><input type="radio" name="role" value="hub" /> Hub only</label>
    <label><input type="radio" name="role" value="runner" checked /> Runner only</label>
    <label><input type="radio" name="role" value="hub-and-runner" /> Hub + Runner</label>
  </div>
</fieldset>

<label for="workspaceRoot">Runner workspace root</label>
<input type="text" id="workspaceRoot" />

<label for="autoStartHubPort">Hub port</label>
<input type="number" id="autoStartHubPort" min="1" max="65535" />

<h2>Tasks</h2>
<label for="staleQueuedMinutes">Stale queue threshold (minutes)</label>
<div class="hint">Tasks queued longer than this turn yellow with a Cancel button. Set to <code>0</code> to disable — useful for long-running queues.</div>
<input type="number" id="staleQueuedMinutes" min="0" max="10080" />

<label for="approvalAgeBadgeHours">Approval age badge (hours)</label>
<div class="hint">Show a warning badge on approvals pending longer than this many hours.</div>
<input type="number" id="approvalAgeBadgeHours" min="1" max="720" />

<h2>Cluster &amp; DR</h2>
<label for="clusterRepoRoot">Repo root (optional)</label>
<div class="hint">Path to the forgewire-fabric checkout containing <code>config/cluster.yaml</code>. Auto-detected from open workspace if empty.</div>
<input type="text" id="clusterRepoRoot" />

<label for="clusterPreferredNode">Preferred rqlite node (optional)</label>
<div class="hint">Override <code>cluster.yaml preferred_node</code> for DR operations on this machine. Empty = use cluster.yaml.</div>
<input type="text" id="clusterPreferredNode" />

<h2>Other</h2>
<label for="pythonPath">Python interpreter (optional)</label>
<div class="hint">Empty = auto-detect (uses python.defaultInterpreterPath, then python3, then python).</div>
<input type="text" id="pythonPath" />

<label for="refreshIntervalSeconds">Sidebar refresh interval (seconds)</label>
<input type="number" id="refreshIntervalSeconds" min="2" max="600" />

<div class="actions">
  <button id="saveBtn" type="button">Save settings</button>
  <button id="testBtn" class="secondary" type="button">Test connection</button>
  <button id="applyBtn" type="button">Run setup\u2026</button>
</div>

<div id="result"></div>

<script>
  const vscode = acquireVsCodeApi();
  const init = ${json};
  const f = (id) => document.getElementById(id);
  f('hubUrl').value = init.hubUrl || '';
  f('hubTokenFile').value = init.hubTokenFile || '';
  f('pythonPath').value = init.pythonPath || '';
  f('refreshIntervalSeconds').value = init.refreshIntervalSeconds || 10;
  f('autoStartHubPort').value = init.autoStartHubPort || 8765;
  f('workspaceRoot').value = init.workspaceRoot || '';
  f('staleQueuedMinutes').value = init.staleQueuedMinutes ?? 30;
  f('approvalAgeBadgeHours').value = init.approvalAgeBadgeHours || 24;
  f('clusterRepoRoot').value = init.clusterRepoRoot || '';
  f('clusterPreferredNode').value = init.clusterPreferredNode || '';

  function payload() {
    return {
      hubUrl: f('hubUrl').value,
      hubToken: f('hubToken').value,
      hubTokenFile: f('hubTokenFile').value,
      pythonPath: f('pythonPath').value,
      refreshIntervalSeconds: f('refreshIntervalSeconds').value,
      autoStartHubPort: f('autoStartHubPort').value,
      workspaceRoot: f('workspaceRoot').value,
      staleQueuedMinutes: f('staleQueuedMinutes').value,
      approvalAgeBadgeHours: f('approvalAgeBadgeHours').value,
      clusterRepoRoot: f('clusterRepoRoot').value,
      clusterPreferredNode: f('clusterPreferredNode').value,
      role: (document.querySelector('input[name=role]:checked') || {}).value || 'runner',
    };
  }

  f('saveBtn').onclick = () => vscode.postMessage(Object.assign({ type: 'save' }, payload()));
  f('testBtn').onclick = () => vscode.postMessage({ type: 'test' });
  f('applyBtn').onclick = () => vscode.postMessage(Object.assign({ type: 'applySetup' }, payload()));
  f('genBtn').onclick = () => vscode.postMessage({ type: 'generateToken' });

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    const r = f('result');
    if (m.type === 'testResult') {
      r.style.display = 'block';
      if (m.ok) {
        r.className = 'ok';
        r.textContent = 'OK \u2014 ' + m.url + '\\nstatus: ' + m.status + '\\nversion: ' + m.version + '\\nprotocol: v' + m.protocol;
      } else {
        r.className = 'err';
        r.textContent = 'Failed: ' + m.error;
      }
    } else if (m.type === 'generatedToken') {
      f('hubToken').value = m.token;
      r.style.display = 'block';
      r.className = 'ok';
      r.textContent = 'Generated 128-bit token. Click Save to persist.';
    }
  });
</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// commands: DR + chaos automation (Windows-first)
// ---------------------------------------------------------------------------

function findClusterRepoRoot(): string | undefined {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const explicit = (cfg.get<string>("cluster.repoRoot") ?? "").trim();
  const candidates: string[] = [];
  if (explicit) {
    candidates.push(explicit);
  }
  for (const f of vscode.workspace.workspaceFolders ?? []) {
    candidates.push(f.uri.fsPath);
  }
  for (const start of candidates) {
    let cur = start;
    for (let i = 0; i < 6; i++) {
      const yaml = path.join(cur, "config", "cluster.yaml");
      const drDir = path.join(cur, "scripts", "dr");
      if (fs.existsSync(yaml) && fs.existsSync(drDir)) {
        return cur;
      }
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  }
  return undefined;
}

async function requireRepoRoot(): Promise<string | undefined> {
  const root = findClusterRepoRoot();
  if (root) return root;
  const pick = await vscode.window.showErrorMessage(
    "Could not locate config/cluster.yaml under any open workspace folder. " +
      "Set forgewire.cluster.repoRoot or open the forgewire checkout.",
    "Open Settings"
  );
  if (pick === "Open Settings") {
    void vscode.commands.executeCommand(
      "workbench.action.openSettings",
      "forgewire.cluster.repoRoot"
    );
  }
  return undefined;
}

function pwshArgEscape(s: string): string {
  // Single-quote for PowerShell; escape internal single quotes by doubling.
  return `'${s.replace(/'/g, "''")}'`;
}

function runDrScriptInTerminal(
  termName: string,
  repoRoot: string,
  scriptRel: string,
  params: Record<string, string | number | boolean | undefined>
): vscode.Terminal {
  const term = getOrCreateTerminal(termName);
  term.show();
  const scriptPath = path.join(repoRoot, scriptRel);
  const parts: string[] = [
    "pwsh",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    pwshArgEscape(scriptPath),
  ];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === 0) continue;
    if (typeof v === "boolean") {
      if (v) parts.push(`-${k}`);
    } else {
      parts.push(`-${k}`, pwshArgEscape(String(v)));
    }
  }
  term.sendText(parts.join(" "));
  return term;
}

function ensureWindows(): boolean {
  if (process.platform === "win32") return true;
  vscode.window.showWarningMessage(
    "This command targets the Windows ForgeWire DR/chaos pipeline (Task Scheduler + Stop-Service). On macOS/Linux, run the equivalent scripts/dr/*.ps1 manually."
  );
  return false;
}

async function drInstallBackupTask(): Promise<void> {
  if (!ensureWindows()) return;
  const root = await requireRepoRoot();
  if (!root) return;
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const ok = await vscode.window.showInformationMessage(
    "Install the rqlite DR backup scheduled task on this host?\n\n" +
      "A UAC prompt will appear (Task Scheduler registration requires Administrator).",
    { modal: true },
    "Install"
  );
  if (ok !== "Install") return;
  runDrScriptInTerminal(
    "ForgeWire: install backup task",
    root,
    "scripts\\dr\\install_rqlite_backup_task.ps1",
    {
      PreferredNode: cfg.get<string>("cluster.preferredNode") ?? "",
      CadenceMinutes: cfg.get<number>("dr.backup.cadenceMinutes") ?? 0,
      RetentionHours: cfg.get<number>("dr.backup.retentionHours") ?? 0,
    }
  );
}

async function drInstallChaosTask(): Promise<void> {
  if (!ensureWindows()) return;
  const root = await requireRepoRoot();
  if (!root) return;
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const ok = await vscode.window.showWarningMessage(
    "Install the chaos drill scheduled task on this host?\n\n" +
      "Drills cause real, observable Raft re-elections and brief write-refusal windows. " +
      "Default cadence is 24h. Only the configured driver_node should run this task — " +
      "the installer enforces the single-driver rule unless you set forgewire.dr.chaos.force.",
    { modal: true },
    "Install"
  );
  if (ok !== "Install") return;
  runDrScriptInTerminal(
    "ForgeWire: install chaos task",
    root,
    "scripts\\dr\\install_rqlite_chaos_task.ps1",
    {
      CadenceMinutes: cfg.get<number>("dr.chaos.cadenceMinutes") ?? 0,
      Drills: cfg.get<string>("dr.chaos.drills") ?? "",
      RetentionDays: cfg.get<number>("dr.chaos.retentionDays") ?? 0,
      Principal: cfg.get<string>("dr.chaos.principal") ?? "SYSTEM",
      Force: cfg.get<boolean>("dr.chaos.force") ?? false,
    }
  );
}

async function drProvisionSshForSystem(): Promise<void> {
  if (!ensureWindows()) return;
  const root = await requireRepoRoot();
  if (!root) return;
  const ok = await vscode.window.showInformationMessage(
    "Provision an SSH identity into the SYSTEM principal so chaos drills can " +
      "Stop-Service across hosts?\n\n" +
      "Reads cfg.chaos.ssh from cluster.yaml, copies the private key into " +
      "%WINDIR%\\System32\\config\\systemprofile\\.ssh, writes a Host config, " +
      "and (optionally) verifies SSH-as-SYSTEM with a one-shot scheduled task.",
    { modal: true },
    "Provision",
    "Provision + Test"
  );
  if (!ok) return;
  runDrScriptInTerminal(
    "ForgeWire: provision SSH for SYSTEM",
    root,
    "scripts\\dr\\install_ssh_for_system.ps1",
    { Test: ok === "Provision + Test" }
  );
}

async function drRunChaosNow(): Promise<void> {
  if (!ensureWindows()) return;
  const root = await requireRepoRoot();
  if (!root) return;
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const ok = await vscode.window.showWarningMessage(
    "Trigger a chaos drill against the live cluster now?\n\n" +
      "If the scheduled task ForgeWireRqliteChaos is registered on this host, " +
      "it will be started (preferred path — runs as SYSTEM). Otherwise the " +
      "script is invoked interactively and will UAC-prompt for elevation.",
    { modal: true },
    "Run"
  );
  if (ok !== "Run") return;
  const term = getOrCreateTerminal("ForgeWire: chaos");
  term.show();
  // Try the scheduled task first; fall back to the script if missing.
  const scriptPath = path.join(root, "scripts", "dr", "chaos_drills.ps1");
  const drills = (cfg.get<string>("dr.chaos.drills") ?? "").trim();
  const cmd =
    `if (Get-ScheduledTask -TaskName ForgeWireRqliteChaos -ErrorAction SilentlyContinue) { ` +
    `  Start-ScheduledTask -TaskName ForgeWireRqliteChaos; ` +
    `  Write-Host 'Triggered ForgeWireRqliteChaos. Tail with: forgewire.dr.tailLastChaosLog' -ForegroundColor Cyan ` +
    `} else { ` +
    `  pwsh -NoProfile -ExecutionPolicy Bypass -File ${pwshArgEscape(scriptPath)}` +
    (drills ? ` -Drills ${pwshArgEscape(drills)}` : "") +
    ` }`;
  term.sendText(`pwsh -NoProfile -Command ${pwshArgEscape(cmd)}`);
}

async function drTailLastChaosLog(): Promise<void> {
  if (!ensureWindows()) return;
  const root = await requireRepoRoot();
  if (!root) return;
  // Default chaos log root is C:\ProgramData\forgewire\rqlite-chaos.
  // Allow override via the cluster.yaml chaos.log_root by parsing it
  // best-effort; if we can't, fall back to the documented default.
  let logRoot = "C:\\ProgramData\\forgewire\\rqlite-chaos";
  try {
    const yaml = fs.readFileSync(path.join(root, "config", "cluster.yaml"), "utf8");
    const m = yaml.match(/^\s*log_root:\s*['"]?([^'"\r\n]+)['"]?/m);
    if (m) logRoot = m[1].trim();
  } catch {
    /* ignore — fall through */
  }
  if (!fs.existsSync(logRoot)) {
    vscode.window.showWarningMessage(
      `No chaos log directory at ${logRoot}. Run a drill first.`
    );
    return;
  }
  const files = fs
    .readdirSync(logRoot)
    .filter((f) => f.startsWith("chaos.") && f.endsWith(".jsonl"))
    .map((f) => ({ f, m: fs.statSync(path.join(logRoot, f)).mtimeMs }))
    .sort((a, b) => b.m - a.m);
  if (files.length === 0) {
    vscode.window.showWarningMessage(`No chaos.*.jsonl files in ${logRoot}.`);
    return;
  }
  const latest = path.join(logRoot, files[0].f);
  const doc = await vscode.workspace.openTextDocument(latest);
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function drOpenClusterYaml(): Promise<void> {
  const root = await requireRepoRoot();
  if (!root) return;
  const yaml = path.join(root, "config", "cluster.yaml");
  const doc = await vscode.workspace.openTextDocument(yaml);
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function drOpenSettings(): Promise<void> {
  await vscode.commands.executeCommand(
    "workbench.action.openSettings",
    "forgewire.cluster forgewire.dr"
  );
}



// ---------------------------------------------------------------------------
// Settings migration: forgewire-fabric (v0.2.x) → forgewire (v0.3+)
// ---------------------------------------------------------------------------
// Old extension ID was "forgewire-fabric" with settings prefix "forgewireFabric".
// New extension ID is "forgewire" with settings prefix "forgewire".
// We copy old values to new keys on first activation; the old keys are left
// intact so a rollback to the old extension still works.

async function migrateSettingsFromFabric(ctx: vscode.ExtensionContext): Promise<void> {
  const MIGRATED_KEY = "forgewire.migratedFromFabric";
  if (ctx.globalState.get<boolean>(MIGRATED_KEY)) { return; }

  const oldCfg = vscode.workspace.getConfiguration("forgewireFabric");
  const newCfg = vscode.workspace.getConfiguration("forgewire");

  // Settings keys that existed under forgewireFabric.*
  const keys = [
    "hubUrl", "hubCandidates", "hubPin", "hubName", "hubToken", "hubTokenFile",
    "runnerAliases", "pythonPath", "refreshIntervalSeconds",
    "approvals.ageBadgeHours", "autoStartHubPort",
    "cluster.repoRoot", "cluster.preferredNode",
    "dr.backup.cadenceMinutes", "dr.backup.retentionHours",
    "dr.chaos.cadenceMinutes", "dr.chaos.drills", "dr.chaos.retentionDays",
    "dr.chaos.principal", "dr.chaos.force",
  ];

  let migrated = 0;
  for (const key of keys) {
    const oldVal = oldCfg.inspect<unknown>(key);
    if (!oldVal) { continue; }
    // Copy workspace value if present and new key is empty
    if (oldVal.workspaceValue !== undefined) {
      const newVal = newCfg.inspect<unknown>(key);
      if (newVal?.workspaceValue === undefined) {
        await newCfg.update(key, oldVal.workspaceValue, vscode.ConfigurationTarget.Workspace);
        migrated++;
      }
    }
    // Copy global/user value
    if (oldVal.globalValue !== undefined) {
      const newVal = newCfg.inspect<unknown>(key);
      if (newVal?.globalValue === undefined) {
        await newCfg.update(key, oldVal.globalValue, vscode.ConfigurationTarget.Global);
        migrated++;
      }
    }
  }

  // Migrate SecretStorage token
  const oldToken = await ctx.secrets.get("forgewireFabric.hubToken");
  if (oldToken) {
    const newToken = await ctx.secrets.get("forgewire.hubToken");
    if (!newToken) {
      await ctx.secrets.store("forgewire.hubToken", oldToken);
      migrated++;
    }
  }

  if (migrated > 0) {
    outputChannel.appendLine(`[migrate] Copied ${migrated} setting(s) from forgewireFabric → forgewire.`);
  }
  await ctx.globalState.update(MIGRATED_KEY, true);
}

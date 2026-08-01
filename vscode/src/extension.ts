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
import {
  beginRefresh,
  completeRefresh,
  COMMAND_DESCRIPTORS,
  DEFAULT_REFRESH_POLICY,
  VIEW_IDS,
  detectFabricFeatures,
  isRefreshDue,
  type AccountSummaryWireDto,
  type CommandId,
  type DispatcherIdentityState,
  type RefreshPolicy,
  type RefreshState,
  type SessionSecrets,
  type SessionState,
  type ViewId,
} from "@forgewire/fabric-client-core";
import { vscodeCommandAvailability, type VscodeGatingState, type VscodeSelection } from "./commandGating";
import { ApprovalInfo, DispatcherSession, HubClient } from "./hubClient";
import { DEFAULT_SESSION_PROFILE_ID, VscodeSessionCredentialStore } from "./humanSession";
import { WebauthnBridgeFlowError, runWebauthnBridgeFlow } from "./webauthnBridgeClient";
import {
  AccountNode,
  AccountProvider,
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
let accountProvider: AccountProvider;
let refreshTimer: NodeJS.Timeout | undefined;
// 114C.7 Slice 6d (AC-114B-5): single-flight + backoff-on-failure state for
// the periodic refresh ticker only -- see tickRefresh()'s own doc comment.
let refreshState: RefreshState = { inFlight: false, consecutiveFailures: 0 };
let context: vscode.ExtensionContext;
let sessionHubToken = "";
let humanSessionStore: VscodeSessionCredentialStore;

// Active hub state: maintained by probeActiveHub() on every refresh tick.
let activeClient: HubClient | undefined;
let lastProbe: Awaited<ReturnType<typeof HubClient.probe>> | undefined;
const snoozedApprovals = new Map<string, SnoozedApproval>();

// Dispatcher identity for signed dispatch (protocol v3+ Rust hub).
// Loaded/generated on activation; may be undefined if Web Crypto is unavailable.
let dispatcherSession: DispatcherSession | undefined;

// Live command-gating inputs, refreshed each probe tick (see refreshGatingState).
// These drive commandAvailability() at handler entry and the forgewire.can.*
// context keys, replacing the previous ad hoc getClient()-truthiness guards.
let commandAuthorities: ReadonlySet<string> = new Set();
let commandFeatures: ReadonlySet<string> = new Set();
// 114C.7 Slice 4c: the signed-in human's account roles (empty when no human
// session), fed to command gating so requiresHumanRole commands (account
// administration) fail closed for automation credentials.
let commandHumanRoles: ReadonlySet<string> = new Set();
let commandSessionState: SessionState = "misconfigured";
let commandFreshness: "missing" | "stale" | "live" = "missing";
let everConnected = false;

// ---------------------------------------------------------------------------
// activation
// ---------------------------------------------------------------------------

export async function activate(ctx: vscode.ExtensionContext): Promise<void> {
  context = ctx;
  outputChannel = vscode.window.createOutputChannel("ForgeWire");
  ctx.subscriptions.push(outputChannel);
  reportCommandContract();

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

  humanSessionStore = new VscodeSessionCredentialStore(ctx.secrets);

  hubProvider = new HubProvider(getClient, getProbe, () => sessionHubToken.length > 0);
  hostsProvider = new HostsProvider(getClient);
  approvalsProvider = new ApprovalsProvider(
    getClient,
    getSnoozedApproval,
    approvalAgeBadgeHours
  );
  costProvider = new CostProvider(getClient);
  auditProvider = new AuditProvider(getClient);
  secretsProvider = new SecretsProvider(getClient);
  settingsProvider = new SettingsProvider(() => sessionHubToken.length > 0);
  tasksProvider = new TasksProvider(getClient, 100, ctx);
  agentsProvider = new AgentsProvider(getClient);
  accountProvider = new AccountProvider(
    getClient,
    () => humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID),
    () => commandFeatures.has("human_accounts"),
  );
  const viewProviders: Record<ViewId, vscode.TreeDataProvider<any>> = {
    "forgewire.hub": hubProvider,
    "forgewire.hosts": hostsProvider,
    "forgewire.tasks": tasksProvider,
    "forgewire.agents": agentsProvider,
    "forgewire.approvals": approvalsProvider,
    "forgewire.cost": costProvider,
    "forgewire.audit": auditProvider,
    "forgewire.secrets": secretsProvider,
    "forgewire.settings": settingsProvider,
    "forgewire.account": accountProvider,
  };
  ctx.subscriptions.push(
    ...VIEW_IDS.map((viewId) =>
      vscode.window.registerTreeDataProvider(viewId, viewProviders[viewId])
    )
  );

  const commandHandlers: Record<CommandId, (...args: any[]) => unknown> = {
    "forgewire.installAgentSuite": () => installAgentSuite(ctx),
    "forgewire.installCli": installCli,
    "forgewire.connectHub": connectHub,
    "forgewire.setToken": setToken,
    "forgewire.auth.signInWithPasskey": signInWithPasskeyCmd,
    "forgewire.auth.registerPasskey": registerPasskeyCmd,
    "forgewire.auth.stepUp": stepUpCmd,
    "forgewire.auth.signOut": signOutCmd,
    "forgewire.account.revokeSession": revokeSessionCmd,
    "forgewire.account.createAccount": createAccountCmd,
    "forgewire.account.disableAccount": disableAccountCmd,
    "forgewire.account.enableAccount": enableAccountCmd,
    "forgewire.account.grantRole": grantRoleCmd,
    "forgewire.account.revokeRole": revokeRoleCmd,
    "forgewire.account.deleteAccount": deleteAccountCmd,
    "forgewire.account.completeDeletion": completeDeletionCmd,
    "forgewire.copyJoinToken": copyJoinToken,
    "forgewire.disconnect": disconnect,
    "forgewire.startHubHere": startHubHere,
    "forgewire.startRunnerHere": startRunnerHere,
    "forgewire.dispatchTask": dispatchTask,
    "forgewire.refresh": refreshAll,
    "forgewire.cost.refresh": () => costProvider?.refresh(),
    "forgewire.streamTask": streamTaskCmd,
    "forgewire.cancelTask": cancelTaskCmd,
    "forgewire.showTask": showTaskCmd,
    "forgewire.redispatchTask": redispatchTaskCmd,
    "forgewire.dismissTask": dismissTaskCmd,
    "forgewire.cancelStaleTask": cancelStaleTaskCmd,
    "forgewire.approveApproval": approveApprovalCmd,
    "forgewire.denyApproval": denyApprovalCmd,
    "forgewire.deferApproval": deferApprovalCmd,
    "forgewire.showDeferredApprovals": showDeferredApprovalsCmd,
    "forgewire.examineApproval": examineApprovalCmd,
    "forgewire.copyApprovalReference": copyApprovalReferenceCmd,
    "forgewire.copyToken": copyToken,
    "forgewire.generateToken": generateToken,
    "forgewire.openSettings": openSettings,
    "forgewire.renameHub": renameHub,
    "forgewire.renameHost": renameHost,
    "forgewire.renameRunner": renameRunner,
    "forgewire.pauseRunner": pauseRunner,
    "forgewire.resumeRunner": resumeRunner,
    "forgewire.restartRunnerService": restartRunnerService,
    "forgewire.startRunnerService": startRunnerService,
    "forgewire.stopRunnerService": stopRunnerService,
    "forgewire.pinHub": pinHub,
    "forgewire.unpinHub": unpinHub,
    "forgewire.promoteHub": promoteHub,
    "forgewire.demoteHub": demoteHub,
    "forgewire.editHubCandidates": editHubCandidates,
    "forgewire.dr.installBackupTask": drInstallBackupTask,
    "forgewire.dr.installChaosTask": drInstallChaosTask,
    "forgewire.dr.provisionSshForSystem": drProvisionSshForSystem,
    "forgewire.dr.runChaosNow": drRunChaosNow,
    "forgewire.dr.tailLastChaosLog": drTailLastChaosLog,
    "forgewire.dr.openClusterYaml": drOpenClusterYaml,
    "forgewire.dr.openSettings": drOpenSettings,
  };
  ctx.subscriptions.push(
    ...COMMAND_DESCRIPTORS.map(({ id }) =>
      vscode.commands.registerCommand(id, commandHandlers[id])
    )
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

function reportCommandContract(): void {
  const counts = { core: 0, equivalent: 0, vscode_specific: 0 };
  for (const descriptor of COMMAND_DESCRIPTORS) {
    counts[descriptor.parityClass]++;
  }
  outputChannel.appendLine(
    `[command-contract] ${COMMAND_DESCRIPTORS.length} commands: ` +
      `${counts.core} core, ${counts.equivalent} equivalent, ` +
      `${counts.vscode_specific} VS Code-specific.`
  );
  for (const descriptor of COMMAND_DESCRIPTORS) {
    if (descriptor.parityClass === "vscode_specific") {
      outputChannel.appendLine(
        `[command-contract] ${descriptor.id} desktop alternative: ` +
          `${descriptor.desktopAlternative ?? "not documented"}`
      );
    }
  }
}

const AGENT_SUITE_FILES = {
  chatmodes: [
    "forgewire-dispatcher.chatmode.md",
    "forgewire-runner.chatmode.md",
    "forgewire-approver.chatmode.md",
    "forgewire-observer.chatmode.md",
  ],
  skills: [
    "dispatch-test-fix.prompt.md",
    "dispatch-docs-sync.prompt.md",
    "bisect-regression.prompt.md",
    "triage-pending-approvals.prompt.md",
    "replay-with-cheaper-model.prompt.md",
    "enroll-runner.prompt.md",
    "dispatch-cost-aware.prompt.md",
  ],
} as const;

async function installAgentSuite(ctx: vscode.ExtensionContext): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    void vscode.window.showErrorMessage(
      "Open a workspace before installing the ForgeWire agent suite."
    );
    return;
  }

  const selected = folders.length === 1
    ? folders[0]
    : await vscode.window.showWorkspaceFolderPick({
        placeHolder: "Choose the workspace that will receive the ForgeWire agent suite",
      });
  if (!selected) return;

  const copies = [
    ...AGENT_SUITE_FILES.chatmodes.map((name) => ({
      source: path.join(ctx.extensionPath, "chatmodes", name),
      target: path.join(selected.uri.fsPath, ".github", "chatmodes", name),
    })),
    ...AGENT_SUITE_FILES.skills.map((name) => ({
      source: path.join(ctx.extensionPath, "skills", name),
      target: path.join(selected.uri.fsPath, ".github", "prompts", name),
    })),
  ];

  const conflicts: string[] = [];
  for (const copy of copies) {
    if (!fs.existsSync(copy.target)) continue;
    const [sourceBody, targetBody] = await Promise.all([
      fs.promises.readFile(copy.source, "utf8"),
      fs.promises.readFile(copy.target, "utf8"),
    ]);
    if (sourceBody !== targetBody) conflicts.push(path.basename(copy.target));
  }

  let replace = false;
  if (conflicts.length) {
    const choice = await vscode.window.showWarningMessage(
      `${conflicts.length} ForgeWire agent-suite file(s) have local changes.`,
      "Install missing only",
      "Replace ForgeWire files",
      "Cancel"
    );
    if (!choice || choice === "Cancel") return;
    replace = choice === "Replace ForgeWire files";
  }

  let written = 0;
  let preserved = 0;
  for (const copy of copies) {
    if (fs.existsSync(copy.target) && conflicts.includes(path.basename(copy.target)) && !replace) {
      preserved++;
      continue;
    }
    await fs.promises.mkdir(path.dirname(copy.target), { recursive: true });
    await fs.promises.copyFile(copy.source, copy.target);
    written++;
  }

  void vscode.window.showInformationMessage(
    `ForgeWire agent suite installed: ${written} file(s) updated, ${preserved} local file(s) preserved.`
  );
}

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

function refreshPolicyFromConfig(): RefreshPolicy {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const configuredMs = Math.max(2, cfg.get<number>("refreshIntervalSeconds") ?? 10) * 1000;
  // No foreground/background distinction is tracked today (no reliable
  // "panel is visible" signal), so both use the same configured cadence;
  // maximumBackoffMs stays >= that cadence so validateRefreshPolicy's
  // ordering invariant always holds regardless of the configured value.
  return {
    foregroundMs: configuredMs,
    backgroundMs: configuredMs,
    maximumBackoffMs: Math.max(configuredMs, DEFAULT_REFRESH_POLICY.maximumBackoffMs),
    backoffMultiplier: DEFAULT_REFRESH_POLICY.backoffMultiplier,
  };
}

/**
 * 114C.7 Slice 6d (AC-114B-5): adopts resilience.ts's single-flight +
 * backoff-on-failure state machine for the periodic ticker specifically.
 * Before this, a bare `setInterval(refreshAll, seconds*1000)` had no overlap
 * guard at all -- a slow `probeAndRefresh()` could still be running when the
 * next tick fired, stacking concurrent hub probes
 * (known_reference_defects: vsix-overlapping-refresh). The ticker still
 * fires at the same configured cadence as before; `isRefreshDue` decides
 * whether *this* tick should actually refresh, which only differs from
 * "always yes" once consecutive failures push the backoff delay beyond that
 * cadence, at which point some ticks are correctly skipped instead of
 * hammering an unreachable hub every single tick forever. The many explicit
 * `refreshAll()` call sites elsewhere (after a mutation completes) are
 * deliberately NOT routed through this gate -- those reflect "show the
 * result of what I just did" and must keep refreshing unconditionally, not
 * silently no-op because a periodic tick happens to be in flight.
 */
function scheduleRefresh(): void {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  const policy = refreshPolicyFromConfig();
  refreshTimer = setInterval(() => void tickRefresh(policy), policy.foregroundMs);
}

async function tickRefresh(policy: RefreshPolicy): Promise<void> {
  const now = Date.now();
  if (!isRefreshDue(refreshState, now, policy, "foreground")) {
    return;
  }
  refreshState = beginRefresh(refreshState, now);
  const reachable = await probeAndRefresh();
  refreshState = completeRefresh(refreshState, reachable, Date.now());
}

function refreshAll(): void {
  // Re-probe candidates first; HubProvider/RunnersProvider/TasksProvider all
  // read activeClient via getClient() so they need probe to settle first.
  void probeAndRefresh();
}

async function probeAndRefresh(): Promise<boolean> {
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
  if (activeClient) {
    const [settings, history] = await Promise.allSettled([
      activeClient.getSettings(),
      activeClient.getHistoryStatus(),
    ]);
    settingsProvider?.setHubState(
      settings.status === "fulfilled" ? settings.value : null,
      history.status === "fulfilled" ? history.value : null,
    );
  } else {
    settingsProvider?.setHubState(null, null);
  }
  await refreshGatingState();
  updateStatus();
  hubProvider?.refresh();
  tasksProvider?.refresh();
  agentsProvider?.refresh();
  hostsProvider?.refresh();
  approvalsProvider?.refresh();
  costProvider?.refresh();
  auditProvider?.refresh();
  secretsProvider?.refresh();
  // Isolated like secretsProvider: its own getChildren catches account-fetch
  // failures and never feeds the global status computation.
  accountProvider?.refresh();
  return Boolean(activeClient);
}

/**
 * Recompute the command-gating inputs from the active hub. VS Code has no
 * per-resource freshness cache (it reads live each tick), so freshness is a
 * single tri-state: reachable-now / last-known / never. Authorities are the
 * hub's authoritative answer (GET /whoami); an older hub without the route, or
 * an unauthorized credential, yields no authorities and every authority-gated
 * command fails closed -- the correct fail-safe posture.
 */
async function refreshGatingState(): Promise<void> {
  const client = getClient();
  if (!client) {
    commandAuthorities = new Set();
    commandFeatures = new Set();
    commandHumanRoles = new Set();
    commandSessionState = sessionHubToken.length > 0 ? "offline" : "misconfigured";
    commandFreshness = everConnected ? "stale" : "missing";
    applyLocalFeatures();
    void publishCommandContextKeys();
    return;
  }
  const [health, who, authPolicy] = await Promise.allSettled([
    client.healthz(),
    client.whoami(),
    // 114C.7 Slice 6e (AC-114B-5 follow-up, discovered while adopting
    // auth.ts): `human_accounts` is deliberately advertisement-only in
    // detectFabricFeatures (see features.ts) -- it can never be inferred
    // from protocol version alone. Without this probe, `commandFeatures`
    // never contained "human_accounts" at all, which made every
    // `feature: "human_accounts"` command (including every admin account
    // command, via `guardCommand`) fail closed with "Required feature is
    // unavailable" regardless of hub support or role -- a real, live bug,
    // not a hypothetical one. `GET /auth-policy` is public and exists only
    // on a hub with 114C's human-accounts routes at all, so a fulfilled
    // result (any body, including bootstrap_open: false) is exactly the
    // "this hub supports human accounts" signal.
    client.authPolicy(),
  ]);
  if (health.status === "fulfilled") {
    everConnected = true;
    commandFeatures = detectFabricFeatures({
      protocolVersion: health.value.protocol_version,
      advertised: authPolicy.status === "fulfilled" ? ["human_accounts"] : [],
    });
    commandFreshness = "live";
    // whoami rejects with the hub's typed auth error message on 401/403.
    if (who.status === "fulfilled") {
      commandAuthorities = new Set(who.value.authorities);
      commandSessionState = "connected";
    } else {
      commandAuthorities = new Set();
      const message = String(who.reason ?? "").toLowerCase();
      commandSessionState = message.includes("401") || message.includes("403") || message.includes("unauthor")
        ? "unauthorized"
        : "connected";
    }
    commandHumanRoles = await loadHumanRoles(client);
  } else {
    commandAuthorities = new Set();
    commandFeatures = new Set();
    commandHumanRoles = new Set();
    commandSessionState = "offline";
    commandFreshness = everConnected ? "stale" : "missing";
  }
  applyLocalFeatures();
  void publishCommandContextKeys();
}

/**
 * The signed-in human's own account roles (whoami above reports the *hub
 * token*'s roles, an automation credential -- a human's account roles come
 * from their session via GET /auth/me). Empty when no human session is
 * stored or the fetch fails, so requiresHumanRole account-admin commands fail
 * closed. This is the only place human roles enter command gating.
 */
async function loadHumanRoles(client: HubClient): Promise<ReadonlySet<string>> {
  const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
  if (!session) return new Set();
  try {
    const me = await client.authMe(session.accessSecret);
    return new Set(me.roles);
  } catch {
    return new Set();
  }
}

/**
 * Merge client-local capabilities into the hub-derived feature set. The
 * `disaster-recovery` capability is *not* a hub protocol feature (the hub has
 * no such concept) -- it is local tooling: the DR commands drive PowerShell
 * scripts from a `config/cluster.yaml` + `scripts/dr` checkout. So it is
 * present exactly when that checkout is locatable, independent of hub state.
 */
function applyLocalFeatures(): void {
  if (findClusterRepoRoot()) {
    commandFeatures = new Set([...commandFeatures, "disaster-recovery"]);
  }
}

/** The dispatcher identity is a Dispatcher-purpose key or nothing (VS Code has
 *  no other identity kind), so the three-state reduces to two here. */
function dispatcherIdentityStateForVscode(): DispatcherIdentityState {
  return dispatcherSession ? "dispatcher" : "missing";
}

function gatingState(): VscodeGatingState {
  return {
    sessionState: commandSessionState,
    features: commandFeatures,
    authorities: commandAuthorities,
    identity: dispatcherIdentityStateForVscode(),
    freshness: commandFreshness,
    humanRoles: commandHumanRoles,
  };
}

/**
 * Evaluate a command and, if it is unavailable, surface the hub-aligned reason
 * and return false so the handler can no-op. The single guard every wired
 * handler calls after resolving its selection.
 */
/** The active hub as a `{kind:"hub"}` selection. Hub-scoped commands
 *  (rename/promote/demote) act on the active hub rather than a picked tree
 *  node, so the "selection" is synthesized from the active client. */
function hubSelection(): VscodeSelection | undefined {
  const client = getClient();
  return client ? { kind: "hub", id: client.url } : undefined;
}

function guardCommand(id: CommandId, selection?: VscodeSelection): boolean {
  const availability = vscodeCommandAvailability(id, gatingState(), selection);
  if (!availability.enabled) {
    void vscode.window.showWarningMessage(availability.reason ?? "This action is currently unavailable.");
    return false;
  }
  return true;
}

/**
 * Publish `forgewire.can.<id>` context keys for the authority/session/feature/
 * identity/freshness gate of each command, so package.json `when` clauses can
 * hide or disable menu items. Selection-status is intentionally *not* folded
 * in here (it is per-invocation and belongs to the `viewItem` match in the
 * `when` clause); this key reflects the credential/session capability, and the
 * handler guard applies the full check including selection status.
 */
async function publishCommandContextKeys(): Promise<void> {
  const state = gatingState();
  await Promise.all(
    COMMAND_DESCRIPTORS.map((descriptor) => {
      // Evaluate with a synthetic satisfying selection so the key reflects only
      // the credential/session gate, not whether something is selected.
      const selection: VscodeSelection | undefined = descriptor.selectionKind === undefined
        ? undefined
        : { kind: descriptor.selectionKind, id: "context-probe", status: descriptor.selectionStatuses?.[0] };
      const availability = vscodeCommandAvailability(descriptor.id, state, selection);
      return vscode.commands.executeCommand("setContext", `forgewire.can.${descriptor.id}`, availability.enabled);
    }),
  );
}

async function hydrateTokenFromSecret(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("forgewire");
  const configured = (cfg.get<string>("hubToken") ?? "").trim();
  const stored = ((await context.secrets.get(SECRET_TOKEN_KEY)) ?? "").trim();
  // An explicitly configured legacy token wins once, then is moved into the
  // secret store and removed from plaintext configuration.
  const token = configured || stored;
  if (token) {
    await storeSecretToken(token);
  }
  if (configured) {
    await clearPlaintextTokenConfiguration(cfg);
  }
}

async function storeSecretToken(token: string): Promise<void> {
  sessionHubToken = token.trim();
  HubClient.setSecretStorageToken(sessionHubToken);
  if (sessionHubToken) {
    await context.secrets.store(SECRET_TOKEN_KEY, sessionHubToken);
  } else {
    await context.secrets.delete(SECRET_TOKEN_KEY);
  }
}

async function clearPlaintextTokenConfiguration(
  cfg: vscode.WorkspaceConfiguration
): Promise<void> {
  const value = cfg.inspect<string>("hubToken");
  if (value?.workspaceFolderValue !== undefined) {
    await cfg.update("hubToken", undefined, vscode.ConfigurationTarget.WorkspaceFolder);
  }
  if (value?.workspaceValue !== undefined) {
    await cfg.update("hubToken", undefined, vscode.ConfigurationTarget.Workspace);
  }
  if (value?.globalValue !== undefined) {
    await cfg.update("hubToken", undefined, vscode.ConfigurationTarget.Global);
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
  await storeSecretToken(token);

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
  await storeSecretToken(token);
  vscode.window.showInformationMessage("ForgeWire: hub token updated.");
  updateStatus();
  refreshAll();
}

/**
 * Runs a bridge flow (114C.6 Slice 5c) inside a cancellable progress
 * notification and reports the result. `onOk` handles only the success case;
 * the ceremony-failed and flow-never-completed cases are handled once, here,
 * so both commands report failures the same way rather than each re-deriving
 * "was this a cancel, a timeout, or a real error."
 */
async function runBridgeCommand(
  title: string,
  mode: "login" | "register",
  onOk: (outcome: Extract<Awaited<ReturnType<typeof runWebauthnBridgeFlow>>, { status: "ok" }>) => Promise<void>
): Promise<void> {
  const client = getClient();
  if (!client) {
    vscode.window.showWarningMessage("ForgeWire: connect to a hub first.");
    return;
  }
  try {
    const outcome = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title, cancellable: true },
      (_progress, token) => runWebauthnBridgeFlow(client.url, mode, token)
    );
    if (outcome.status === "error") {
      vscode.window.showErrorMessage(`ForgeWire: ${outcome.message}`);
      return;
    }
    await onOk(outcome);
  } catch (err) {
    // A user-initiated cancel is not a failure worth a red toast.
    if (err instanceof WebauthnBridgeFlowError && err.message === "Cancelled.") return;
    vscode.window.showErrorMessage(
      `ForgeWire: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function signInWithPasskeyCmd(): Promise<void> {
  await runBridgeCommand("ForgeWire: waiting for the browser…", "login", async (outcome) => {
    if (outcome.mode !== "login") return;
    await humanSessionStore.set(DEFAULT_SESSION_PROFILE_ID, {
      sessionId: outcome.session.sessionId,
      accessSecret: outcome.session.accessSecret,
      refreshSecret: outcome.session.refreshSecret,
    });
    accountProvider?.refresh();
    vscode.window.showInformationMessage("ForgeWire: signed in with a passkey.");
  });
}

async function registerPasskeyCmd(): Promise<void> {
  await runBridgeCommand("ForgeWire: waiting for the browser…", "register", async (outcome) => {
    if (outcome.mode !== "register") return;
    // Registration signs in inside the browser page itself and does not
    // return a session (see webauthn_bridge.js's runRegister) -- nothing to
    // store here, only to report.
    vscode.window.showInformationMessage("ForgeWire: passkey registered.");
  });
}

/**
 * 114C.7 Slice 4c-3: run the true in-place step-up ceremony and return the
 * elevated session, or `undefined` on cancel/failure (already surfaced to the
 * user). Credential relay: the VSIX holds the session bearer and makes the
 * step_up_options/verify calls itself; the browser only runs
 * navigator.credentials.get on the public challenge and returns the assertion,
 * so the access secret never enters the browser. On success the hub elevates
 * the session to aal2 in place and rotates its access secret, which is
 * persisted here (keeping the same sessionId/refreshSecret). Returned so a
 * caller (e.g. account deletion in 4c-3b) can chain a sensitive action on a
 * freshly-stepped-up session.
 */
async function stepUp(): Promise<SessionSecrets | undefined> {
  const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
  const client = getClient();
  if (!session || !client) {
    vscode.window.showWarningMessage("ForgeWire: sign in first.");
    return undefined;
  }
  let options: { challenge_id: string; options_token: string; public_key: unknown };
  try {
    // The client makes this authenticated call itself (it has the bearer);
    // AssuranceTooLow (no passkey to step up with) surfaces here via the
    // typed-auth boundary, never a raw body.
    options = await client.stepUpOptions(session.accessSecret);
  } catch (err) {
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
  let outcome: Awaited<ReturnType<typeof runWebauthnBridgeFlow>>;
  try {
    outcome = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "ForgeWire: verify with your passkey…", cancellable: true },
      // Only the public request challenge crosses to the browser.
      (_progress, token) => runWebauthnBridgeFlow(client.url, "step-up", token, JSON.stringify(options.public_key)),
    );
  } catch (err) {
    if (err instanceof WebauthnBridgeFlowError && err.message === "Cancelled.") return undefined;
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
  if (outcome.status === "error") {
    vscode.window.showErrorMessage(`ForgeWire: ${outcome.message}`);
    return undefined;
  }
  if (outcome.mode !== "step-up") return undefined;
  let verified: { access_secret: string };
  try {
    // The client completes verification itself with the relayed assertion.
    verified = await client.stepUpVerify(session.accessSecret, options.challenge_id, options.options_token, outcome.credential);
  } catch (err) {
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
  const elevated: SessionSecrets = {
    sessionId: session.sessionId,
    accessSecret: verified.access_secret,
    refreshSecret: session.refreshSecret,
  };
  await humanSessionStore.set(DEFAULT_SESSION_PROFILE_ID, elevated);
  accountProvider?.refresh();
  return elevated;
}

async function stepUpCmd(): Promise<void> {
  const elevated = await stepUp();
  if (elevated) vscode.window.showInformationMessage("ForgeWire: verified — your session is elevated.");
}

/**
 * 114C.7 Slice 4a: sign out the stored human session. Best-effort hub revoke
 * (POST /auth/logout via HubClient.authLogout) followed by an *unconditional*
 * clear of the platform credential store -- the local credential is removed
 * even if the hub is unreachable or the revoke fails, so "sign out" always
 * leaves this machine signed out. The session's own access secret is the
 * bearer for its revoke, matching every other self-service auth route.
 */
async function signOutCmd(): Promise<void> {
  const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
  if (!session) {
    vscode.window.showInformationMessage("ForgeWire: not signed in.");
    return;
  }
  const client = getClient();
  if (client) {
    try {
      await client.authLogout(session.accessSecret, session.sessionId);
    } catch (err) {
      // Non-fatal: the local credential is cleared regardless below, so the
      // machine ends up signed out even if the hub revoke could not be
      // delivered. Surface it without a raw body (authLogout throws the
      // typed-auth boundary's generic/typed message, never the raw response).
      outputChannel.appendLine(`sign-out: hub revoke failed (clearing local session anyway): ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  await humanSessionStore.delete(DEFAULT_SESSION_PROFILE_ID);
  accountProvider?.refresh();
  vscode.window.showInformationMessage("ForgeWire: signed out.");
}

/**
 * 114C.7 Slice 4b: revoke one of the caller's *other* sessions from the
 * Account view's per-session context menu. Invoked with the session tree
 * node; the current session is excluded by the menu `when` clause
 * (contextValue `account.session.current`, not `account.session`), and this
 * re-checks it defensively -- ending the window's own session is what Sign
 * Out is for. The caller's own access secret authorizes the revoke (the hub's
 * revoke_session allows owner-or-admin).
 */
async function revokeSessionCmd(node?: AccountNode): Promise<void> {
  if (!node || node.kind !== "session") {
    vscode.window.showWarningMessage("ForgeWire: revoke a session from the Account view.");
    return;
  }
  if (node.session.current) {
    vscode.window.showWarningMessage("ForgeWire: use Sign Out to end the current session.");
    return;
  }
  if (!guardCommand("forgewire.account.revokeSession")) return;
  const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
  const client = getClient();
  if (!session || !client) {
    vscode.window.showWarningMessage("ForgeWire: sign in and connect to a hub first.");
    return;
  }
  const label = node.session.client_label ?? node.session.client_kind;
  const ok = await vscode.window.showWarningMessage(
    `Revoke the session "${label}"? That client will be signed out.`,
    { modal: true },
    "Revoke",
  );
  if (ok !== "Revoke") return;
  try {
    await client.revokeAuthSession(session.accessSecret, node.session.session_id);
    accountProvider?.refresh();
    vscode.window.showInformationMessage("ForgeWire: session revoked.");
  } catch (err) {
    // authLogout/revokeAuthSession throw through the Slice-1 typed-auth
    // boundary -- never a raw response body.
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * 114C.7 Slice 4c: create a human account (admin-only). Gated through the
 * shared commandAvailability() humanRole mechanism (guardCommand →
 * requiresHumanRole:"admin" against the signed-in human's roles), the same
 * decision the account tree uses to show its Administration section, so an
 * automation credential can never reach this. Collects username / display
 * name / password / role, then POST /accounts with the admin's own session
 * secret as bearer.
 */
async function createAccountCmd(): Promise<void> {
  if (!guardCommand("forgewire.account.createAccount")) return;
  const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
  const client = getClient();
  if (!session || !client) {
    vscode.window.showWarningMessage("ForgeWire: sign in as an administrator first.");
    return;
  }
  const username = await vscode.window.showInputBox({ prompt: "New account username", ignoreFocusOut: true });
  if (!username) return;
  const displayName = await vscode.window.showInputBox({ prompt: `Display name for "${username}"`, ignoreFocusOut: true });
  if (!displayName) return;
  const password = await vscode.window.showInputBox({ prompt: "Initial password", password: true, ignoreFocusOut: true });
  if (!password) return;
  // The authoritative assignable-role list comes from the hub (auth-policy),
  // not a hardcoded copy that could drift from what the hub accepts.
  let roles: string[];
  try {
    roles = (await client.authPolicy()).roles;
  } catch {
    vscode.window.showErrorMessage("ForgeWire: could not load the role list from the hub.");
    return;
  }
  const role = await vscode.window.showQuickPick(roles, { placeHolder: `Role for "${username}"`, ignoreFocusOut: true });
  if (!role) return;
  try {
    await client.createAccount(session.accessSecret, username, displayName, password, role);
    accountProvider?.refresh();
    vscode.window.showInformationMessage(`ForgeWire: created account "${username}" (${role}).`);
  } catch (err) {
    // createAccount throws through the Slice-1 typed-auth boundary -- e.g. a
    // UsernameConflict surfaces as its typed message, never a raw body.
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * 114C.7 Slice 4c-2: shared preamble for the per-account admin mutations
 * invoked from the Administration section's account context menu. Narrows the
 * invoked node, applies the shared requiresHumanRole:"admin" gate
 * (guardCommand), resolves the admin's own session secret + client, runs the
 * specific mutation, and refreshes the view. Errors (including typed-auth
 * ones such as LastAdministratorViolation) surface via the boundary, never a
 * raw body. `run` owns its own confirmation/role-pick and success message so
 * a cancelled interaction reports nothing.
 */
async function withAdminAccount(
  node: AccountNode | undefined,
  id: CommandId,
  run: (client: HubClient, secret: string, account: AccountSummaryWireDto) => Promise<void>,
): Promise<void> {
  if (!node || node.kind !== "adminAccount") {
    vscode.window.showWarningMessage("ForgeWire: run this from an account in the Administration section.");
    return;
  }
  if (!guardCommand(id)) return;
  const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
  const client = getClient();
  if (!session || !client) {
    vscode.window.showWarningMessage("ForgeWire: sign in as an administrator first.");
    return;
  }
  try {
    await run(client, session.accessSecret, node.account);
    accountProvider?.refresh();
  } catch (err) {
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function disableAccountCmd(node?: AccountNode): Promise<void> {
  await withAdminAccount(node, "forgewire.account.disableAccount", async (client, secret, a) => {
    const ok = await vscode.window.showWarningMessage(
      `Disable "${a.username}"? Their sessions are revoked and they can no longer sign in.`,
      { modal: true },
      "Disable",
    );
    if (ok !== "Disable") return;
    // expected_revision is a compare-and-set token: the tree node's revision.
    await client.disableAccount(secret, a.account_id, a.revision);
    vscode.window.showInformationMessage(`ForgeWire: disabled "${a.username}".`);
  });
}

async function enableAccountCmd(node?: AccountNode): Promise<void> {
  await withAdminAccount(node, "forgewire.account.enableAccount", async (client, secret, a) => {
    await client.enableAccount(secret, a.account_id, a.revision);
    vscode.window.showInformationMessage(`ForgeWire: enabled "${a.username}".`);
  });
}

async function grantRoleCmd(node?: AccountNode): Promise<void> {
  await withAdminAccount(node, "forgewire.account.grantRole", async (client, secret, a) => {
    // Offer only roles the account does not already hold, from the hub's
    // authoritative assignable-role list (not a hardcoded copy).
    const roles = (await client.authPolicy()).roles.filter((r) => !a.roles.includes(r));
    if (roles.length === 0) {
      vscode.window.showInformationMessage(`ForgeWire: "${a.username}" already holds every assignable role.`);
      return;
    }
    const role = await vscode.window.showQuickPick(roles, { placeHolder: `Grant a role to "${a.username}"`, ignoreFocusOut: true });
    if (!role) return;
    await client.grantMembership(secret, a.account_id, role);
    vscode.window.showInformationMessage(`ForgeWire: granted "${role}" to "${a.username}".`);
  });
}

async function revokeRoleCmd(node?: AccountNode): Promise<void> {
  await withAdminAccount(node, "forgewire.account.revokeRole", async (client, secret, a) => {
    if (a.roles.length === 0) {
      vscode.window.showInformationMessage(`ForgeWire: "${a.username}" holds no roles to revoke.`);
      return;
    }
    const role = await vscode.window.showQuickPick([...a.roles], { placeHolder: `Revoke a role from "${a.username}"`, ignoreFocusOut: true });
    if (!role) return;
    // The hub's revoke_membership protects the realm's last administrator;
    // that rejection surfaces as its typed LastAdministratorViolation message.
    await client.revokeMembership(secret, a.account_id, role);
    vscode.window.showInformationMessage(`ForgeWire: revoked "${role}" from "${a.username}".`);
  });
}

/**
 * 114C.7 Slice 4c-3b: shared preamble for the two account-deletion actions.
 * Beyond the admin role gate, the client REQUIRES a fresh in-place step-up
 * (`stepUp()`) before either deletion action -- even though the hub does not
 * yet enforce step-up on the deletion routes -- so the client is never laxer
 * than the documented security intent. `run` is called with the *rotated*
 * access secret from step-up (the pre-step-up secret is now invalid, so order
 * matters). Only the modal confirmation is `run`'s own.
 */
async function withDeletionStepUp(
  node: AccountNode | undefined,
  id: CommandId,
  run: (client: HubClient, elevatedSecret: string, account: AccountSummaryWireDto) => Promise<void>,
): Promise<void> {
  if (!node || node.kind !== "adminAccount") {
    vscode.window.showWarningMessage("ForgeWire: run this from an account in the Administration section.");
    return;
  }
  if (!guardCommand(id)) return;
  // Fresh step-up first. On cancel/failure stepUp() has already told the user
  // and we stop -- deletion never proceeds without a completed step-up.
  const elevated = await stepUp();
  if (!elevated) return;
  const client = getClient();
  if (!client) {
    vscode.window.showWarningMessage("ForgeWire: connect to a hub first.");
    return;
  }
  try {
    await run(client, elevated.accessSecret, node.account);
    accountProvider?.refresh();
  } catch (err) {
    // e.g. LastAdministratorViolation surfaces as its typed message.
    vscode.window.showErrorMessage(`ForgeWire: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function deleteAccountCmd(node?: AccountNode): Promise<void> {
  await withDeletionStepUp(node, "forgewire.account.deleteAccount", async (client, secret, a) => {
    const ok = await vscode.window.showWarningMessage(
      `Delete "${a.username}"? Their sessions are revoked and the account is marked for deletion (a second, permanent step completes it).`,
      { modal: true },
      "Delete",
    );
    if (ok !== "Delete") return;
    await client.initiateAccountDeletion(secret, a.account_id, a.revision);
    vscode.window.showInformationMessage(`ForgeWire: "${a.username}" marked for deletion.`);
  });
}

async function completeDeletionCmd(node?: AccountNode): Promise<void> {
  await withDeletionStepUp(node, "forgewire.account.completeDeletion", async (client, secret, a) => {
    const ok = await vscode.window.showWarningMessage(
      `Permanently delete "${a.username}"? This is irreversible.`,
      { modal: true },
      "Permanently delete",
    );
    if (ok !== "Permanently delete") return;
    await client.completeAccountDeletion(secret, a.account_id, a.revision);
    vscode.window.showInformationMessage(`ForgeWire: "${a.username}" permanently deleted.`);
  });
}

async function copyJoinToken(): Promise<void> {
  let token = sessionHubToken;
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
  await clearPlaintextTokenConfiguration(cfg);
  await storeSecretToken("");
  updateStatus();
  refreshAll();
  vscode.window.showInformationMessage("ForgeWire: disconnected.");
}

async function copyToken(): Promise<void> {
  const t = sessionHubToken;
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
  let token = sessionHubToken;
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
  await storeSecretToken(token);

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

  const env: Record<string, string> = {
    FORGEWIRE_HUB_URL: c.url,
    FORGEWIRE_HUB_TOKEN: sessionHubToken,
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
  if (!guardCommand("forgewire.dispatchTask")) return;
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

/**
 * Resolve a `{kind:"task"}` selection (id + status) from a command argument for
 * the gating check. A stale task reports status `"stale"` (matching
 * cancelStaleTask's requirement) rather than its underlying lifecycle status;
 * a bare id (palette invocation) has no status and the handler's own
 * "Select a task first" path already covers the no-target case.
 */
function taskSelection(arg: TaskCommandArg): VscodeSelection | undefined {
  const id = resolveTaskId(arg);
  if (!id) return undefined;
  let status: string | undefined;
  if (arg && typeof arg === "object") {
    const node = arg as { kind?: string; stale?: boolean; task?: { status?: string }; status?: unknown };
    if (node.kind === "task" || node.kind === "historyTask") {
      status = node.stale ? "stale" : node.task?.status;
    } else if (typeof node.status === "string") {
      status = node.status;
    } else if (node.task?.status) {
      status = node.task.status;
    }
  }
  return { kind: "task", id: String(id), status };
}

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
  if (!guardCommand("forgewire.cancelTask", taskSelection(arg))) return;
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
  if (!guardCommand("forgewire.redispatchTask", taskSelection(arg))) return;
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
  if (!guardCommand("forgewire.cancelStaleTask", taskSelection(arg))) return;
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
  if (!guardCommand("forgewire.approveApproval", { kind: "approval", id: approval.approval_id, status: approval.status })) return;
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
  if (!guardCommand("forgewire.denyApproval", { kind: "approval", id: approval.approval_id, status: approval.status })) return;
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
  if (!guardCommand("forgewire.renameHub", hubSelection())) return;
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

  if (!guardCommand("forgewire.renameHost", { kind: "host", id: hostname })) return;

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

  if (!guardCommand("forgewire.renameRunner", { kind: "runner", id: runnerId })) return;

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
  drain_requested?: boolean;
}

/** A `{kind:"runner"}` selection with the descriptor status vocabulary. A
 *  drain-requested runner reports `"draining"` (matching resumeRunner's
 *  requirement) regardless of its underlying lifecycle state; otherwise its
 *  `state` (e.g. `"online"`) is used. */
function runnerSelection(r: RunnerArg): VscodeSelection {
  return {
    kind: "runner",
    id: r.runner_id ?? "",
    status: r.drain_requested ? "draining" : (r.state ?? "online"),
  };
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
  if (!guardCommand("forgewire.pauseRunner", runnerSelection(r))) return;
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
  if (!guardCommand("forgewire.resumeRunner", runnerSelection(r))) return;
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
  if (!guardCommand("forgewire.promoteHub", hubSelection())) return;
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
  if (!guardCommand("forgewire.demoteHub", hubSelection())) return;
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
    hubToken: "",
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
          await storeSecretToken(tok);
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
  if (!guardCommand("forgewire.dr.installBackupTask")) return;
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
  if (!guardCommand("forgewire.dr.installChaosTask")) return;
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
  if (!guardCommand("forgewire.dr.provisionSshForSystem")) return;
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
  if (!guardCommand("forgewire.dr.runChaosNow")) return;
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
  if (!guardCommand("forgewire.dr.tailLastChaosLog")) return;
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
  if (!guardCommand("forgewire.dr.openClusterYaml")) return;
  const root = await requireRepoRoot();
  if (!root) return;
  const yaml = path.join(root, "config", "cluster.yaml");
  const doc = await vscode.workspace.openTextDocument(yaml);
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function drOpenSettings(): Promise<void> {
  // Deliberately NOT routed through guardCommand: this is the escape hatch for
  // configuring DR itself (it opens forgewire.cluster.repoRoot). Gating it on
  // the disaster-recovery capability would be a chicken-and-egg lock -- you
  // could not open the settings needed to make cluster.yaml locatable in the
  // first place.
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
    "hubUrl", "hubCandidates", "hubPin", "hubName", "hubTokenFile",
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

  // Migrate tokens into SecretStorage only. Never copy a secret back into
  // user/workspace settings, where it would be stored as plaintext JSON.
  const oldToken = await ctx.secrets.get("forgewireFabric.hubToken");
  const oldConfiguredToken = (oldCfg.get<string>("hubToken") ?? "").trim();
  const newToken = await ctx.secrets.get("forgewire.hubToken");
  const tokenToMigrate = oldToken || oldConfiguredToken;
  if (tokenToMigrate && !newToken) {
    await ctx.secrets.store("forgewire.hubToken", tokenToMigrate);
    migrated++;
  }

  if (migrated > 0) {
    outputChannel.appendLine(`[migrate] Copied ${migrated} setting(s) from forgewireFabric → forgewire.`);
  }
  await ctx.globalState.update(MIGRATED_KEY, true);
}

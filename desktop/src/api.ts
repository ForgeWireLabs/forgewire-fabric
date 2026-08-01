import { invoke } from "@tauri-apps/api/core";
import {
  deriveSessionState,
  mergeLastGoodResource,
  type ResourceState,
  type SessionState,
  type TypedAuthErrorCode
} from "@forgewire/fabric-client-core";
import type {
  ApprovalDecision,
  ApprovalInfo,
  AuditDayResult,
  CapabilityDetail,
  DispatchBrief,
  DispatchDraft,
  DesktopUpdateStatus,
  DispatcherIdentitySummary,
  HubConfig,
  HubDiscoveryCandidate,
  HubSnapshot,
  FabricEntityKind,
  PasskeyBridgeResult,
  RunnerInfo,
  SignedDispatchResult,
  SnapshotResult,
  TaskAudit,
  TaskInfo,
  TaskStreamResult,
  TokenStorageSummary
} from "./types";

const STALE_AFTER_MS = 30_000;
const RESOURCE_KEYS = [
  "health", "cluster", "runners", "agents", "tasks", "approvals", "budget",
  "cost", "hosts", "audit", "secrets", "dispatchers", "hub_settings", "history"
] as const;
type ResourceKey = (typeof RESOURCE_KEYS)[number];

interface NativeSnapshotResult {
  snapshot: HubSnapshot;
  errors: Record<string, string>;
  restrictions?: Record<string, string>;
  active_hub: string;
  refreshed_at_ms: number;
  authorities?: string[];
}

/**
 * Result shape for 114C auth-route Tauri commands (`AuthResult` in
 * `main.rs`). Deliberately not a thrown/rejected error: the raw hub
 * response body must never become the string a rejected promise carries
 * (see `fabric_client::ClientError::typed_auth_error`'s doc comment on the
 * Rust side) -- `code` is set only when the Rust side has already validated
 * it against the known set, so it is safe to type as `TypedAuthErrorCode`
 * here rather than a bare `string`.
 */
export interface AuthResult<T> {
  ok: boolean;
  data?: T;
  code?: TypedAuthErrorCode;
  message?: string;
}

export interface DesktopTransport {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
}

const tauriTransport: DesktopTransport = {
  invoke: <T>(command: string, args?: Record<string, unknown>) => invoke<T>(command, args)
};

export const EMPTY_DISPATCH_DRAFT: DispatchDraft = {
  title: "",
  kind: "agent",
  dispatch: "prompt",
  branch: "agent/fabric-desktop/task",
  baseCommit: "origin/main",
  scopeGlobs: "",
  prompt: "",
  tags: "",
  capabilities: "",
  skill: "",
  tool: "",
  command: ""
};

const EMPTY_SNAPSHOT: HubSnapshot = {
  health: null,
  cluster: null,
  runners: [],
  agents: [],
  tasks: [],
  approvals: [],
  budget: null,
  hosts: [],
  audit: null,
  cost: null,
  secrets: [],
  dispatchers: [],
  hub_settings: null,
  history: null
};

export class HubApiError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: string) {
    super(message);
    this.name = "HubApiError";
  }
}

export class HubApi {
  readonly baseUrl: string;
  private readonly resources: Partial<Record<ResourceKey, ResourceState<unknown>>> = {};
  private lastSnapshot: HubSnapshot = EMPTY_SNAPSHOT;

  constructor(readonly config: HubConfig, private readonly transport: DesktopTransport = tauriTransport) {
    this.baseUrl = normalizeHubUrl(config.hubUrl);
  }

  async healthz() { return (await this.loadSnapshot()).snapshot.health; }
  async clusterHealth() { return (await this.loadSnapshot()).snapshot.cluster; }
  async listRunners() { return (await this.loadSnapshot()).snapshot.runners; }
  async listAgents() { return (await this.loadSnapshot()).snapshot.agents; }
  async listTasks() { return (await this.loadSnapshot()).snapshot.tasks; }
  async listApprovals() { return (await this.loadSnapshot()).snapshot.approvals; }
  async costBudget() { return (await this.loadSnapshot()).snapshot.budget; }
  async listHosts() { return (await this.loadSnapshot()).snapshot.hosts; }
  async auditTail() { return (await this.loadSnapshot()).snapshot.audit; }

  async taskStream(taskId: number, afterSeq = 0, limit = 200): Promise<TaskStreamResult> {
    const body = await this.transport.invoke<{ lines?: TaskStreamResult["lines"] }>("load_task_stream", {
      hubUrl: this.baseUrl,
      taskId,
      afterSeq,
      limit
    });
    return { lines: body.lines ?? [] };
  }

  async taskAudit(taskId: number): Promise<TaskAudit> {
    const body = await this.transport.invoke<Partial<TaskAudit>>("load_task_audit", {
      hubUrl: this.baseUrl,
      taskId
    });
    return { events: body.events ?? [], verified: body.verified ?? false, error: body.error ?? null };
  }

  async taskDetail(taskId: number): Promise<TaskInfo> {
    const body = await this.transport.invoke<TaskInfo | { task?: TaskInfo }>("load_task_detail", {
      hubUrl: this.baseUrl,
      taskId
    });
    return (body as { task?: TaskInfo }).task ?? body as TaskInfo;
  }

  async approvalDetail(approvalId: string): Promise<ApprovalInfo> {
    const body = await this.transport.invoke<ApprovalInfo | { approval?: ApprovalInfo }>("load_approval_detail", {
      hubUrl: this.baseUrl,
      approvalId
    });
    return (body as { approval?: ApprovalInfo }).approval ?? body as ApprovalInfo;
  }

  async capabilityDetail(kind: string, name: string): Promise<CapabilityDetail> {
    return this.transport.invoke<CapabilityDetail>("load_capability_detail", {
      hubUrl: this.baseUrl,
      kind,
      name
    });
  }

  async auditDay(day: string): Promise<AuditDayResult> {
    return this.transport.invoke<AuditDayResult>("load_audit_day", { hubUrl: this.baseUrl, day });
  }

  async redispatchTask(taskId: number): Promise<SignedDispatchResult> {
    return this.transport.invoke<SignedDispatchResult>("redispatch_task", { hubUrl: this.baseUrl, taskId });
  }

  async renameEntity(target: FabricEntityKind, targetId: string | null, label: string): Promise<unknown> {
    return this.transport.invoke("rename_fabric_entity", {
      request: { hub_url: this.baseUrl, target, target_id: targetId, label }
    });
  }

  async governSecret(name: string, action: "put" | "rotate" | "delete", value?: string): Promise<unknown> {
    return this.transport.invoke("govern_secret", {
      request: { hub_url: this.baseUrl, name, action, value: value || null }
    });
  }

  async removeToken(): Promise<TokenStorageSummary> {
    return this.transport.invoke<TokenStorageSummary>("remove_hub_token");
  }

  async setHubPin(pin: string | null): Promise<{ hub_pin?: string | null }> {
    return this.transport.invoke<{ hub_pin?: string | null }>("set_hub_pin", { pin });
  }

  async cancelTask(taskId: number): Promise<TaskInfo> {
    return this.transport.invoke<TaskInfo>("cancel_task", { hubUrl: this.baseUrl, taskId });
  }

  async requestRunnerDrain(runnerId: string): Promise<RunnerInfo> {
    return this.transport.invoke<RunnerInfo>("set_runner_drain", {
      hubUrl: this.baseUrl,
      runnerId,
      drain: true
    });
  }

  async requestRunnerUndrain(runnerId: string): Promise<RunnerInfo> {
    return this.transport.invoke<RunnerInfo>("set_runner_drain", {
      hubUrl: this.baseUrl,
      runnerId,
      drain: false
    });
  }

  async approveApproval(approvalId: string, decision: ApprovalDecision): Promise<ApprovalInfo> {
    return this.decideApproval(approvalId, true, decision);
  }

  async denyApproval(approvalId: string, decision: ApprovalDecision): Promise<ApprovalInfo> {
    return this.decideApproval(approvalId, false, decision);
  }

  private async decideApproval(
    approvalId: string,
    approve: boolean,
    decision: ApprovalDecision
  ): Promise<ApprovalInfo> {
    return this.transport.invoke<ApprovalInfo>("decide_approval", {
      request: {
        hub_url: this.baseUrl,
        approval_id: approvalId,
        approve,
        approver: decision.approver ?? "fabric-desktop",
        reason: decision.reason ?? ""
      }
    });
  }

  async loadSnapshot(): Promise<SnapshotResult> {
    const receivedAt = Date.now();
    let native: NativeSnapshotResult;
    try {
      native = await this.transport.invoke<NativeSnapshotResult>("load_fabric_snapshot", {
        hubUrl: this.baseUrl
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      for (const key of RESOURCE_KEYS) {
        this.resources[key] = mergeLastGoodResource(this.resources[key], {
          ok: false,
          error: message,
          receivedAt
        });
      }
      return this.snapshotResult({ hub: message }, {}, receivedAt, this.baseUrl);
    }

    const restrictions = native.restrictions ?? {};
    for (const key of RESOURCE_KEYS) {
      const issue = native.errors[key] ?? restrictions[key];
      this.resources[key] = issue
        ? mergeLastGoodResource(this.resources[key], { ok: false, error: issue, receivedAt })
        : mergeLastGoodResource(this.resources[key], {
            ok: true,
            data: native.snapshot[key as keyof HubSnapshot],
            observedAt: native.refreshed_at_ms,
            receivedAt,
            staleAfterMs: STALE_AFTER_MS
          });
    }
    this.lastSnapshot = snapshotFromResources(this.resources, native.snapshot);
    return this.snapshotResult(native.errors, restrictions, native.refreshed_at_ms, native.active_hub, native.authorities ?? []);
  }

  private snapshotResult(
    errors: Record<string, string>,
    restrictions: Record<string, string>,
    refreshedAtMs: number,
    activeHub: string,
    authorities: string[] = []
  ): SnapshotResult {
    const restrictionKeys = new Set(Object.keys(restrictions));
    const values = Object.entries(this.resources)
      .filter(([key]) => !restrictionKeys.has(key))
      .map(([, resource]) => resource);
    const successfulResources = values.filter((resource) => resource?.data !== undefined).length;
    const messages = Object.values(errors).join(" ").toLowerCase();
    const stale = values.some((resource) => resource?.freshness?.source === "last-good");
    const sessionState: SessionState = deriveSessionState({
      configured: Boolean(this.baseUrl && this.config.tokenPresent),
      authorized: !messages.includes("401") && !messages.includes("403") && !messages.includes("token is not installed"),
      compatible: !messages.includes("426") && !messages.includes("incompatible"),
      reachable: successfulResources > 0,
      stale,
      failedResources: Object.keys(errors).length,
      successfulResources
    });
    return {
      snapshot: this.lastSnapshot,
      errors,
      restrictions,
      freshness: Object.fromEntries(RESOURCE_KEYS.map((key) => [key, this.resources[key]?.freshness])),
      sessionState,
      activeHub,
      refreshedAtMs,
      authorities
    };
  }
}

function snapshotFromResources(
  resources: Partial<Record<ResourceKey, ResourceState<unknown>>>,
  fallback: HubSnapshot
): HubSnapshot {
  const value = <K extends keyof HubSnapshot>(key: K): HubSnapshot[K] =>
    (resources[key as ResourceKey]?.data as HubSnapshot[K] | undefined) ?? fallback[key];
  return {
    health: value("health"), cluster: value("cluster"), runners: value("runners"),
    agents: value("agents"), tasks: value("tasks"), approvals: value("approvals"),
    budget: value("budget"), hosts: value("hosts"), audit: value("audit"),
    cost: value("cost"), secrets: value("secrets"), dispatchers: value("dispatchers"),
    hub_settings: value("hub_settings"), history: value("history")
  };
}

export function normalizeHubUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  return withScheme
    .replace(/^http:\/\/localhost(?=[:/]|$)/i, "http://127.0.0.1")
    .replace(/^https:\/\/localhost(?=[:/]|$)/i, "https://127.0.0.1")
    .replace(/\/+$/, "");
}

export function parseListField(value: string): string[] {
  return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
}

export function normalizeDispatchDraft(draft: DispatchDraft): DispatchBrief {
  const brief: DispatchBrief = {
    title: draft.title.trim(), kind: draft.kind, dispatch: draft.dispatch,
    branch: draft.branch.trim(), base_commit: draft.baseCommit.trim(),
    scope_globs: parseListField(draft.scopeGlobs), prompt: draft.prompt.trim(),
    required_tags: parseListField(draft.tags),
    required_capabilities: parseListField(draft.capabilities)
  };
  if (draft.skill.trim()) brief.skill = draft.skill.trim();
  if (draft.tool.trim()) brief.tool = draft.tool.trim();
  if (draft.kind === "command") brief.command = parseListField(draft.command);
  return brief;
}

export function dispatchDisabledReason(
  draft: DispatchDraft,
  identity: DispatcherIdentitySummary | null,
  config: HubConfig
): string | null {
  const brief = normalizeDispatchDraft(draft);
  if (!config.hubUrl.trim()) return "Hub URL is required";
  if (!config.tokenPresent) return "Install a hub token in Settings";
  if (!identity) return "Desktop dispatcher identity is unavailable";
  if (!brief.title) return "Title is required";
  if (!brief.prompt) return "Prompt/brief is required";
  if (!brief.branch) return "Branch is required";
  if (!brief.base_commit) return "Base commit is required";
  if (brief.scope_globs.length === 0) return "At least one scope glob is required";
  if (brief.kind === "command" && (!brief.command || brief.command.length === 0)) {
    return "Command dispatch requires command tokens";
  }
  return null;
}

export async function loadDispatcherIdentity(
  path: string,
  transport: DesktopTransport = tauriTransport
): Promise<DispatcherIdentitySummary> {
  return transport.invoke<DispatcherIdentitySummary>("load_dispatcher_identity", { path });
}

export async function loadOrCreateDispatcherIdentity(
  transport: DesktopTransport = tauriTransport
): Promise<DispatcherIdentitySummary> {
  return transport.invoke<DispatcherIdentitySummary>("load_or_create_dispatcher_identity");
}

export async function dispatchSignedTask(
  config: HubConfig,
  _identity: DispatcherIdentitySummary,
  draft: DispatchDraft,
  transport: DesktopTransport = tauriTransport
): Promise<SignedDispatchResult> {
  return transport.invoke<SignedDispatchResult>("dispatch_signed_task", {
    request: { hub_url: normalizeHubUrl(config.hubUrl), brief: normalizeDispatchDraft(draft) }
  });
}

export async function discoverHubs(
  seedUrls: string[],
  transport: DesktopTransport = tauriTransport
): Promise<HubDiscoveryCandidate[]> {
  return transport.invoke<HubDiscoveryCandidate[]>("discover_hubs", { seedUrls });
}

export async function saveHubToken(
  token: string,
  transport: DesktopTransport = tauriTransport
): Promise<TokenStorageSummary> {
  return transport.invoke<TokenStorageSummary>("save_hub_token", { token });
}

export async function removeHubToken(
  transport: DesktopTransport = tauriTransport
): Promise<TokenStorageSummary> {
  return transport.invoke<TokenStorageSummary>("remove_hub_token");
}

export async function persistHubPin(
  pin: string | null,
  transport: DesktopTransport = tauriTransport
): Promise<{ hub_pin?: string | null }> {
  return transport.invoke<{ hub_pin?: string | null }>("set_hub_pin", { pin });
}

export async function checkForDesktopUpdate(
  transport: DesktopTransport = tauriTransport
): Promise<DesktopUpdateStatus> {
  return transport.invoke<DesktopUpdateStatus>("check_for_desktop_update");
}

export async function installVerifiedDesktopUpdate(
  transport: DesktopTransport = tauriTransport
): Promise<string> {
  return transport.invoke<string>("install_verified_desktop_update");
}

// 114C.6 Slice 5d: WebAuthn bridge (`webauthn_bridge.rs`). PasskeyBridgeResult
// carries no session -- a login writes straight into the OS keyring from the
// Rust command, so there is nothing here to adapt beyond the wire shape.

/** Wire shape of the two bridge commands (snake_case), distinct from the
 *  camelCase `PasskeyBridgeResult` the rest of the app consumes -- same
 *  reason `NativeSessionSecrets`/`SessionSecrets` are kept separate in
 *  desktop/src/session.ts. */
interface NativePasskeyBridgeResult {
  ok: boolean;
  message: string | null;
  credential_id: string | null;
}

function fromNativeBridgeResult(native: NativePasskeyBridgeResult): PasskeyBridgeResult {
  return { ok: native.ok, message: native.message, credentialId: native.credential_id };
}

export async function signInWithPasskey(
  hubUrl: string,
  transport: DesktopTransport = tauriTransport
): Promise<PasskeyBridgeResult> {
  return fromNativeBridgeResult(
    await transport.invoke<NativePasskeyBridgeResult>("sign_in_with_passkey", { hubUrl })
  );
}

export async function registerPasskey(
  hubUrl: string,
  transport: DesktopTransport = tauriTransport
): Promise<PasskeyBridgeResult> {
  return fromNativeBridgeResult(
    await transport.invoke<NativePasskeyBridgeResult>("register_passkey", { hubUrl })
  );
}

/**
 * 114C.7 Slice 5b: the step-up ceremony. Unlike `signInWithPasskey`/
 * `registerPasskey` above, this does not go through `PasskeyBridgeResult` --
 * the Rust `step_up` command reads the stored session itself (no
 * `accessSecret` param), makes both authenticated step-up hub calls itself,
 * and persists the rotated access secret to the OS keyring before
 * returning. It reports through `AuthResult` like every other auth-route
 * wrapper below because, unlike a brand-new login session, an already
 * signed-in session's secret already round-trips through the webview on
 * every account-page call (see `TauriSessionCredentialStore`) -- there is no
 * extra secrecy to preserve by hiding this one too.
 */
export async function stepUp(
  hubUrl: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ session_id: string; assurance_level: string; access_secret: string; stepped_up_at?: string }>> {
  return transport.invoke("step_up", { hubUrl });
}

// 114C.7: the first real auth-route transport call. Proves the AuthResult
// shape (see main.rs's own doc comment on why it exists) end to end before
// the remaining 29 auth routes are wired the same way.

export async function authBootstrapStatus(
  hubUrl: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ bootstrap_open: boolean }>> {
  return transport.invoke<AuthResult<{ bootstrap_open: boolean }>>("auth_bootstrap_status", { hubUrl });
}

// ---- 114C.7 Slice 2: the remaining 23 directly-wireable auth/account -----
// routes, following `authBootstrapStatus`'s own shape exactly: a free
// function (not a `HubApi` method -- most of these are called before any
// `HubConfig`/token-bearing session exists), taking `hubUrl` plus whatever
// the route needs, returning `AuthResult<T>` rather than throwing. The
// other 6 of the 30 total routes (passkey/step-up ceremonies) are not
// wired here -- see the equivalent note in `vscode/src/hubClient.ts` and
// `crates/fabric-client/src/lib.rs`.

export interface AccountSummaryResult {
  account_id: string;
  username: string;
  display_name: string;
  status: string;
  roles: string[];
  revision: number;
}

export interface SessionSummaryResult {
  session_id: string;
  account_id: string;
  client_kind: string;
  client_label?: string;
  assurance_level: string;
  authenticated_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  current: boolean;
}

export async function authBootstrap(
  hubUrl: string,
  username: string,
  displayName: string,
  password: string,
  bootstrapSecret: string | undefined,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("auth_bootstrap", {
    hubUrl, username, displayName, password, bootstrapSecret
  });
}

export async function authLogin(
  hubUrl: string,
  username: string,
  password: string,
  clientKind: string | undefined,
  clientLabel: string | undefined,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{
  session_id: string; account_id: string; assurance_level: string;
  access_secret: string; refresh_secret: string;
  idle_expires_at: string; absolute_expires_at: string;
  // 114E: the backend mints + binds a per-session Ed25519 keypair and returns
  // the private key here so the renderer can persist it in the keyring and sign
  // subsequent requests (proof-of-possession) instead of replaying the bearer.
  session_signing_key?: string;
}>> {
  return transport.invoke("auth_login", { hubUrl, username, password, clientKind, clientLabel });
}

export async function authRefresh(
  hubUrl: string,
  sessionId: string,
  refreshSecret: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ session_id: string; refresh_secret: string; idle_expires_at: string; absolute_expires_at: string }>> {
  return transport.invoke("auth_refresh", { hubUrl, sessionId, refreshSecret });
}

export async function authLogout(
  hubUrl: string,
  accessSecret: string,
  sessionId: string,
  sessionSigningKey: string | undefined = undefined,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ session_id: string; revoked: boolean }>> {
  return transport.invoke("auth_logout", { hubUrl, accessSecret, sessionId, sessionSigningKey });
}

export async function authLogoutAll(
  hubUrl: string,
  accessSecret: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ account_id: string; revoked_count: number }>> {
  return transport.invoke("auth_logout_all", { hubUrl, accessSecret });
}

export async function authMe(
  hubUrl: string,
  accessSecret: string,
  sessionId: string | undefined = undefined,
  sessionSigningKey: string | undefined = undefined,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("auth_me", { hubUrl, accessSecret, sessionId, sessionSigningKey });
}

export async function authRemovePasskey(
  hubUrl: string,
  accessSecret: string,
  credentialId: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ credential_id: string; revoked: boolean }>> {
  return transport.invoke("auth_remove_passkey", { hubUrl, accessSecret, credentialId });
}

export async function authPolicy(
  hubUrl: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ realm_id: string; bootstrap_open: boolean; roles: string[] }>> {
  return transport.invoke("auth_policy", { hubUrl });
}

export async function listAuthSessions(
  hubUrl: string,
  accessSecret: string,
  accountId: string | undefined,
  sessionId: string | undefined = undefined,
  sessionSigningKey: string | undefined = undefined,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ sessions: SessionSummaryResult[] }>> {
  return transport.invoke("list_auth_sessions", { hubUrl, accessSecret, accountId, sessionId, sessionSigningKey });
}

export async function revokeAuthSession(
  hubUrl: string,
  accessSecret: string,
  sessionId: string,
  authSessionId: string | undefined = undefined,
  sessionSigningKey: string | undefined = undefined,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ session_id: string; revoked: boolean }>> {
  return transport.invoke("revoke_auth_session", { hubUrl, accessSecret, sessionId, authSessionId, sessionSigningKey });
}

export async function listAccounts(
  hubUrl: string,
  accessSecret: string,
  limit = 200,
  offset = 0,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ accounts: AccountSummaryResult[] }>> {
  return transport.invoke("list_accounts", { hubUrl, accessSecret, limit, offset });
}

export async function createAccount(
  hubUrl: string,
  accessSecret: string,
  username: string,
  displayName: string,
  password: string,
  role: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("create_account", { hubUrl, accessSecret, username, displayName, password, role });
}

export async function getAccount(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("get_account", { hubUrl, accessSecret, accountId });
}

export async function updateAccountStatus(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  status: "active" | "locked" | "recovery_required",
  expectedRevision: number,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("update_account_status", { hubUrl, accessSecret, accountId, status, expectedRevision });
}

export async function grantMembership(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  role: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("grant_membership", { hubUrl, accessSecret, accountId, role });
}

export async function revokeMembership(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  role: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("revoke_membership", { hubUrl, accessSecret, accountId, role });
}

export async function disableAccount(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  expectedRevision: number,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("disable_account", { hubUrl, accessSecret, accountId, expectedRevision });
}

export async function enableAccount(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  expectedRevision: number,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("enable_account", { hubUrl, accessSecret, accountId, expectedRevision });
}

export async function generateRecoveryCodes(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  count = 5,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{ account_id: string; codes: string[] }>> {
  return transport.invoke("generate_recovery_codes", { hubUrl, accessSecret, accountId, count });
}

export async function completeRecovery(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  code: string,
  newPassword: string,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("complete_recovery", { hubUrl, accessSecret, accountId, code, newPassword });
}

export async function initiateAccountDeletion(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  expectedRevision: number,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("initiate_account_deletion", { hubUrl, accessSecret, accountId, expectedRevision });
}

export async function completeAccountDeletion(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  expectedRevision: number,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<AccountSummaryResult>> {
  return transport.invoke("complete_account_deletion", { hubUrl, accessSecret, accountId, expectedRevision });
}

export async function accountSecurityHistory(
  hubUrl: string,
  accessSecret: string,
  accountId: string,
  limit = 50,
  transport: DesktopTransport = tauriTransport
): Promise<AuthResult<{
  account_id: string;
  login_attempts: Array<{ attempted_at: string; successful: boolean }>;
  sessions: SessionSummaryResult[];
}>> {
  return transport.invoke("account_security_history", { hubUrl, accessSecret, accountId, limit });
}

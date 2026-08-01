import { COMMAND_IDS, type CommandId, type SessionState } from "./constants.js";

export type CommandParityClass = "core" | "equivalent" | "vscode_specific";
export type CommandDomain = "bootstrap" | "connection" | "tasks" | "session" | "cost" | "approvals" | "settings" | "hub" | "hosts" | "dr" | "auth";
export type SelectionKind = "hub" | "host" | "runner" | "task" | "approval";
export type FreshnessRequirement = "none" | "present" | "live";
export type ClientPlatform = "vscode" | "desktop";
export type DispatcherIdentityState = "dispatcher" | "missing" | "wrong-purpose";

export interface CommandDescriptor {
  readonly id: CommandId;
  readonly parityClass: CommandParityClass;
  readonly domain: CommandDomain;
  readonly platforms: readonly ClientPlatform[];
  readonly consequential: boolean;
  readonly selectionKind?: SelectionKind;
  readonly selectionStatuses?: readonly string[];
  readonly authority?: string;
  readonly feature?: string;
  readonly requiresDispatcherIdentity?: boolean;
  /**
   * 114C.7: a human *account* role (e.g. "admin") the signed-in human must
   * hold for this command. Distinct from {@link authority}, a dispatcher/
   * automation `fabric.*.write` capability from `GET /whoami` -- a role token
   * can carry those but never a human-account role like "admin" (which the
   * hub's own `required_roles` gates the `/accounts/*` routes on, and which
   * `VALID_ROLES` deliberately excludes from the automation vocabulary).
   * Checked against {@link CommandContext.humanRoles}, populated only from a
   * signed-in human session, so an automation credential can never satisfy it.
   */
  readonly requiresHumanRole?: string;
  readonly freshness: FreshnessRequirement;
  readonly desktopAlternative?: string;
}

type DescriptorOptions = Omit<CommandDescriptor, "id" | "parityClass" | "domain" | "platforms">;

const both = (
  id: CommandId,
  parityClass: Exclude<CommandParityClass, "vscode_specific">,
  domain: CommandDomain,
  options: DescriptorOptions,
): CommandDescriptor => ({ id, parityClass, domain, platforms: ["vscode", "desktop"], ...options });

const vscodeOnly = (
  id: CommandId,
  domain: CommandDomain,
  desktopAlternative: string,
  options: Omit<DescriptorOptions, "desktopAlternative">,
): CommandDescriptor => ({
  id,
  parityClass: "vscode_specific",
  domain,
  platforms: ["vscode"],
  desktopAlternative,
  ...options,
});

const signed = (authority: string, options: Omit<DescriptorOptions, "authority" | "requiresDispatcherIdentity" | "consequential" | "freshness"> = {}): DescriptorOptions => ({
  consequential: true,
  freshness: "live",
  authority,
  requiresDispatcherIdentity: true,
  ...options,
});

/**
 * Canonical command ledger. Keep this explicit: deriving policy from an
 * identifier made additions silently inherit the wrong authority, freshness,
 * or platform semantics.
 */
export const COMMAND_DESCRIPTORS: readonly CommandDescriptor[] = [
  vscodeOnly("forgewire.installAgentSuite", "bootstrap", "No desktop equivalent: this installs VS Code chatmodes and prompt files into a workspace.", { consequential: true, freshness: "none" }),
  vscodeOnly("forgewire.installCli", "bootstrap", "Use the signed desktop installer or Settings > Runtime.", { consequential: true, freshness: "none" }),
  both("forgewire.connectHub", "core", "connection", { consequential: false, freshness: "none" }),
  both("forgewire.setToken", "equivalent", "connection", { consequential: true, freshness: "none" }),
  // 114C.6 Slice 5c/5d: both platforms open the hub-served WebAuthn bridge in
  // the system browser (neither has an in-process WebAuthn-eligible, hub-
  // reachable context of its own -- see webauthnBridge.ts). "equivalent"
  // rather than "core": same underlying mechanism on both platforms, but not
  // the identical in-app flow a "core" command implies. feature-gated because
  // an older hub that never advertises human_accounts has nothing to bridge
  // to. freshness "none" and in SESSION_RECOVERY below, matching setToken:
  // this is itself a way to establish credentials, so it must stay available
  // while the session is unauthorized/misconfigured, not only once one
  // already exists.
  both("forgewire.auth.signInWithPasskey", "equivalent", "auth", { consequential: true, freshness: "none", feature: "human_accounts" }),
  // Register mode's browser page collects the password itself and signs in
  // independently (see webauthn_bridge.js's runRegister), so this also does
  // not depend on the extension already holding a session -- it is a second,
  // primitive entry point, not the same thing as the future signed_in +
  // step_up "auth.addPasskey" operation in auth.ts, which governs
  // adding a passkey from within an already-established session.
  both("forgewire.auth.registerPasskey", "equivalent", "auth", { consequential: true, freshness: "none", feature: "human_accounts" }),
  // 114C.7 Slice 4c-3: elevate the signed-in human's own session to aal2 via
  // the true in-place step-up ceremony. Self-service (no role gate);
  // freshness "live" (a real ceremony against a live authorized session,
  // unlike sign-in which establishes one). The handler no-ops if not signed
  // in; AssuranceTooLow (no passkey) surfaces through the typed-auth boundary.
  both("forgewire.auth.stepUp", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts" }),
  // 114C.7 Slice 4a: sign out the stored human session (best-effort hub
  // revoke + clear the platform credential store). Self-service, no role
  // gate; freshness "none" and in SESSION_RECOVERY so it stays available to
  // clear local credentials even when the hub is offline/unauthorized --
  // signing out must never itself require a healthy session.
  both("forgewire.auth.signOut", "equivalent", "auth", { consequential: true, freshness: "none", feature: "human_accounts" }),
  // 114C.7 Slice 4b: revoke one of the caller's *own* other sessions
  // (DELETE /auth/sessions/{id}). Self-service -- the hub's revoke_session
  // authorizes owner-or-admin, so no dispatcher authority or human-role gate
  // here. freshness "live" (a real mutation against live session state,
  // unlike sign-out which only clears local credentials). Invoked from the
  // Account view's per-session context menu; the current session is excluded
  // there, so this never revokes the caller's own active session.
  both("forgewire.account.revokeSession", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts" }),
  // 114C.7 Slice 4c: create a human account (POST /accounts). Admin-only --
  // the first consumer of requiresHumanRole, mirroring the hub's own
  // required_roles gate on /accounts. freshness "live" (a real mutation
  // needing a live authorized connection).
  both("forgewire.account.createAccount", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  // 114C.7 Slice 4c-2: per-account admin mutations, all admin-gated through
  // the same requiresHumanRole:"admin" mechanism as createAccount. disable/
  // enable are compare-and-set (the account's own revision, read from the
  // admin account tree node); grant/revoke operate on memberships. All
  // freshness "live".
  both("forgewire.account.disableAccount", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  both("forgewire.account.enableAccount", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  both("forgewire.account.grantRole", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  both("forgewire.account.revokeRole", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  // 114C.7 Slice 4c-3b: two-step account deletion. Both admin-gated; the
  // client additionally requires a fresh in-place step-up (handler-side)
  // before either, even though the hub does not yet enforce it -- the client
  // must not be laxer than the documented security intent. deleteAccount
  // initiates (marks deletion_pending); completeDeletion tombstones
  // (irreversible).
  both("forgewire.account.deleteAccount", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  both("forgewire.account.completeDeletion", "equivalent", "auth", { consequential: true, freshness: "live", feature: "human_accounts", requiresHumanRole: "admin" }),
  both("forgewire.copyJoinToken", "equivalent", "connection", { consequential: true, freshness: "live", authority: "fabric.connection.read-secret" }),
  both("forgewire.disconnect", "core", "connection", { consequential: true, freshness: "none" }),
  both("forgewire.startHubHere", "equivalent", "bootstrap", { consequential: true, freshness: "none" }),
  both("forgewire.startRunnerHere", "equivalent", "bootstrap", { consequential: true, freshness: "none" }),
  both("forgewire.dispatchTask", "core", "tasks", signed("fabric.tasks.write", { feature: "signed_dispatch" })),
  both("forgewire.refresh", "core", "session", { consequential: false, freshness: "none" }),
  both("forgewire.cost.refresh", "core", "cost", { consequential: false, freshness: "none", feature: "cost" }),
  both("forgewire.streamTask", "core", "tasks", { consequential: false, freshness: "live", feature: "task_stream", selectionKind: "task", selectionStatuses: ["claimed", "running", "reporting"] }),
  both("forgewire.cancelTask", "core", "tasks", signed("fabric.tasks.write", { selectionKind: "task", selectionStatuses: ["queued", "claimed", "running", "reporting"] })),
  both("forgewire.showTask", "equivalent", "tasks", { consequential: false, freshness: "present", selectionKind: "task" }),
  both("forgewire.approveApproval", "core", "approvals", signed("fabric.approvals.write", { feature: "approval_decisions", selectionKind: "approval", selectionStatuses: ["pending"] })),
  both("forgewire.denyApproval", "core", "approvals", signed("fabric.approvals.write", { feature: "approval_decisions", selectionKind: "approval", selectionStatuses: ["pending"] })),
  both("forgewire.deferApproval", "equivalent", "approvals", { consequential: true, freshness: "present", selectionKind: "approval", selectionStatuses: ["pending"] }),
  both("forgewire.showDeferredApprovals", "equivalent", "approvals", { consequential: false, freshness: "none" }),
  both("forgewire.examineApproval", "equivalent", "approvals", { consequential: false, freshness: "live", selectionKind: "approval" }),
  both("forgewire.copyApprovalReference", "equivalent", "approvals", { consequential: false, freshness: "present", selectionKind: "approval" }),
  both("forgewire.copyToken", "equivalent", "connection", { consequential: true, freshness: "none" }),
  both("forgewire.generateToken", "equivalent", "connection", { consequential: true, freshness: "none" }),
  both("forgewire.openSettings", "equivalent", "settings", { consequential: false, freshness: "none" }),
  both("forgewire.renameHub", "core", "hub", signed("fabric.hub.write", { selectionKind: "hub" })),
  both("forgewire.renameHost", "core", "hosts", signed("fabric.hosts.write", { selectionKind: "host" })),
  both("forgewire.renameRunner", "core", "hosts", signed("fabric.hosts.write", { selectionKind: "runner" })),
  both("forgewire.pauseRunner", "core", "hosts", signed("fabric.hosts.write", { feature: "runner_drain", selectionKind: "runner", selectionStatuses: ["online"] })),
  both("forgewire.resumeRunner", "core", "hosts", signed("fabric.hosts.write", { feature: "runner_drain", selectionKind: "runner", selectionStatuses: ["draining"] })),
  both("forgewire.restartRunnerService", "equivalent", "hosts", { consequential: true, freshness: "live", authority: "fabric.hosts.service", selectionKind: "runner" }),
  both("forgewire.startRunnerService", "equivalent", "hosts", { consequential: true, freshness: "live", authority: "fabric.hosts.service", selectionKind: "runner", selectionStatuses: ["offline", "stopped"] }),
  both("forgewire.stopRunnerService", "equivalent", "hosts", { consequential: true, freshness: "live", authority: "fabric.hosts.service", selectionKind: "runner", selectionStatuses: ["online", "draining"] }),
  both("forgewire.pinHub", "core", "hub", { consequential: true, freshness: "none" }),
  both("forgewire.unpinHub", "core", "hub", { consequential: true, freshness: "none" }),
  both("forgewire.promoteHub", "core", "hub", signed("fabric.hub.write", { feature: "cluster_health", selectionKind: "hub" })),
  both("forgewire.demoteHub", "core", "hub", signed("fabric.hub.write", { feature: "cluster_health", selectionKind: "hub" })),
  both("forgewire.editHubCandidates", "equivalent", "hub", { consequential: true, freshness: "none" }),
  vscodeOnly("forgewire.dr.installBackupTask", "dr", "Use the governed DR setup workflow outside the WebView.", { consequential: true, freshness: "none", feature: "disaster-recovery", authority: "fabric.dr.write" }),
  vscodeOnly("forgewire.dr.installChaosTask", "dr", "Use the governed DR setup workflow outside the WebView.", { consequential: true, freshness: "none", feature: "disaster-recovery", authority: "fabric.dr.write" }),
  vscodeOnly("forgewire.dr.provisionSshForSystem", "dr", "Use the privileged host provisioning workflow.", { consequential: true, freshness: "none", feature: "disaster-recovery", authority: "fabric.dr.write" }),
  both("forgewire.dr.runChaosNow", "equivalent", "dr", signed("fabric.dr.write", { feature: "disaster-recovery" })),
  both("forgewire.dr.tailLastChaosLog", "equivalent", "dr", { consequential: false, freshness: "present", feature: "disaster-recovery" }),
  vscodeOnly("forgewire.dr.openClusterYaml", "dr", "Open the cluster configuration through Settings diagnostics.", { consequential: false, freshness: "none", feature: "disaster-recovery" }),
  both("forgewire.dr.openSettings", "equivalent", "dr", { consequential: false, freshness: "none", feature: "disaster-recovery" }),
  both("forgewire.redispatchTask", "core", "tasks", signed("fabric.tasks.write", { feature: "signed_dispatch", selectionKind: "task", selectionStatuses: ["failed", "cancelled", "timed_out"] })),
  both("forgewire.dismissTask", "equivalent", "tasks", { consequential: true, freshness: "present", selectionKind: "task", selectionStatuses: ["succeeded", "failed", "cancelled", "timed_out"] }),
  both("forgewire.cancelStaleTask", "core", "tasks", signed("fabric.tasks.write", { selectionKind: "task", selectionStatuses: ["stale"] })),
] as const;

if (COMMAND_DESCRIPTORS.length !== COMMAND_IDS.length || COMMAND_DESCRIPTORS.some((descriptor, index) => descriptor.id !== COMMAND_IDS[index])) {
  throw new Error("Command descriptors must exactly match the canonical command order.");
}

export interface CommandContext {
  readonly sessionState: SessionState;
  readonly selection?: { readonly kind: SelectionKind; readonly status?: string; readonly id: string };
  readonly features: ReadonlySet<string>;
  readonly authorities: ReadonlySet<string>;
  readonly identity: DispatcherIdentityState;
  readonly freshness: "missing" | "stale" | "live";
  readonly platform: ClientPlatform;
  /**
   * 114C.7: the human *account* roles of the signed-in human session (empty
   * when no human is signed in). Optional so a client that has not yet wired a
   * human session -- e.g. Desktop before its Slice 5 account UI -- omits it,
   * and every {@link CommandDescriptor.requiresHumanRole} gate then fails
   * closed. Populated only from a human session, never an automation role
   * token, so it can never grant an account-admin command to a non-human
   * credential.
   */
  readonly humanRoles?: ReadonlySet<string>;
}

export interface CommandAvailability { readonly enabled: boolean; readonly reason?: string; }

const SESSION_RECOVERY = new Set<CommandId>([
  "forgewire.installAgentSuite", "forgewire.installCli", "forgewire.connectHub", "forgewire.setToken",
  "forgewire.auth.signInWithPasskey", "forgewire.auth.registerPasskey",
  "forgewire.auth.signOut",
  "forgewire.disconnect", "forgewire.startHubHere", "forgewire.startRunnerHere",
  "forgewire.refresh", "forgewire.cost.refresh", "forgewire.copyToken",
  "forgewire.generateToken", "forgewire.openSettings", "forgewire.pinHub",
  "forgewire.unpinHub", "forgewire.editHubCandidates", "forgewire.dr.openClusterYaml",
  "forgewire.dr.openSettings",
]);

const unavailable = (reason: string): CommandAvailability => ({ enabled: false, reason });

export function commandAvailability(descriptor: CommandDescriptor, context: CommandContext): CommandAvailability {
  if (!descriptor.platforms.includes(context.platform)) return unavailable(descriptor.desktopAlternative ?? `This action is unavailable on ${context.platform}.`);
  if (context.sessionState === "bootstrapping" && !SESSION_RECOVERY.has(descriptor.id)) return unavailable("The Fabric session is still bootstrapping.");
  if (context.sessionState === "misconfigured" && !SESSION_RECOVERY.has(descriptor.id)) return unavailable("Configure a Fabric Hub before using this action.");
  if (context.sessionState === "unauthorized" && !SESSION_RECOVERY.has(descriptor.id)) return unavailable("The active profile is not authorized for this action.");
  if (context.sessionState === "incompatible" && !SESSION_RECOVERY.has(descriptor.id)) return unavailable("The active Hub protocol does not support this action.");
  if (context.sessionState === "offline" && descriptor.freshness !== "none") return unavailable("The active Hub is offline; last-good data is read-only.");
  if (descriptor.feature !== undefined && !context.features.has(descriptor.feature)) return unavailable(`Required feature is unavailable: ${descriptor.feature}.`);
  if (descriptor.requiresDispatcherIdentity === true && context.identity !== "dispatcher") {
    return unavailable(context.identity === "wrong-purpose"
      ? "A Dispatcher-purpose identity is required; the loaded identity has the wrong purpose."
      : "A Dispatcher-purpose identity must be created or loaded first.");
  }
  if (descriptor.authority !== undefined && !context.authorities.has(descriptor.authority)) return unavailable(`Required authority is unavailable: ${descriptor.authority}.`);
  if (descriptor.requiresHumanRole !== undefined && !(context.humanRoles?.has(descriptor.requiresHumanRole) ?? false)) return unavailable(`Requires the ${descriptor.requiresHumanRole} account role.`);
  if (descriptor.freshness === "live" && context.freshness !== "live") return unavailable("Live authorization and target state are required.");
  if (descriptor.freshness === "present" && context.freshness === "missing") return unavailable("No resource state is available.");
  if (descriptor.selectionKind !== undefined) {
    if (context.selection === undefined) return unavailable(`Select a ${descriptor.selectionKind} first.`);
    if (context.selection.kind !== descriptor.selectionKind) return unavailable(`This action requires a ${descriptor.selectionKind} selection.`);
    if (descriptor.selectionStatuses !== undefined && (context.selection.status === undefined || !descriptor.selectionStatuses.includes(context.selection.status))) return unavailable(`The selected ${descriptor.selectionKind} is not in a supported state.`);
  }
  return { enabled: true };
}

export function findCommandDescriptor(id: CommandId): CommandDescriptor {
  const descriptor = COMMAND_DESCRIPTORS.find((candidate) => candidate.id === id);
  if (descriptor === undefined) throw new Error(`Unknown command: ${id}`);
  return descriptor;
}

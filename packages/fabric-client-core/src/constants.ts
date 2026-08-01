export const VIEW_IDS = [
  "forgewire.hub",
  "forgewire.hosts",
  "forgewire.tasks",
  "forgewire.agents",
  "forgewire.approvals",
  "forgewire.cost",
  "forgewire.audit",
  "forgewire.secrets",
  "forgewire.settings",
  "forgewire.account",
] as const;

export const COMMAND_IDS = [
  "forgewire.installAgentSuite", "forgewire.installCli", "forgewire.connectHub", "forgewire.setToken",
  "forgewire.auth.signInWithPasskey", "forgewire.auth.registerPasskey",
  "forgewire.auth.stepUp",
  "forgewire.auth.signOut", "forgewire.account.revokeSession",
  "forgewire.account.createAccount", "forgewire.account.disableAccount",
  "forgewire.account.enableAccount", "forgewire.account.grantRole",
  "forgewire.account.revokeRole", "forgewire.account.deleteAccount",
  "forgewire.account.completeDeletion",
  "forgewire.copyJoinToken", "forgewire.disconnect", "forgewire.startHubHere",
  "forgewire.startRunnerHere", "forgewire.dispatchTask", "forgewire.refresh",
  "forgewire.cost.refresh", "forgewire.streamTask", "forgewire.cancelTask",
  "forgewire.showTask", "forgewire.approveApproval", "forgewire.denyApproval",
  "forgewire.deferApproval", "forgewire.showDeferredApprovals",
  "forgewire.examineApproval", "forgewire.copyApprovalReference",
  "forgewire.copyToken", "forgewire.generateToken", "forgewire.openSettings",
  "forgewire.renameHub", "forgewire.renameHost", "forgewire.renameRunner",
  "forgewire.pauseRunner", "forgewire.resumeRunner",
  "forgewire.restartRunnerService", "forgewire.startRunnerService",
  "forgewire.stopRunnerService", "forgewire.pinHub", "forgewire.unpinHub",
  "forgewire.promoteHub", "forgewire.demoteHub", "forgewire.editHubCandidates",
  "forgewire.dr.installBackupTask", "forgewire.dr.installChaosTask",
  "forgewire.dr.provisionSshForSystem", "forgewire.dr.runChaosNow",
  "forgewire.dr.tailLastChaosLog", "forgewire.dr.openClusterYaml",
  "forgewire.dr.openSettings", "forgewire.redispatchTask",
  "forgewire.dismissTask", "forgewire.cancelStaleTask",
] as const;

export const SESSION_STATES = [
  "bootstrapping", "connected", "partial", "stale", "offline",
  "unauthorized", "incompatible", "misconfigured",
] as const;

export const NAVIGATION_DOMAINS = [
  "dashboard", "explorer", "hub", "tasks", "agents", "approvals", "cost",
  "audit", "secrets", "settings", "account",
] as const;

/**
 * 114C's operator-auth state machine, additive to and independent of
 * {@link SESSION_STATES} (hub/transport health). "unavailable" is not one of
 * the eleven states the human-accounts plan names directly -- it is this
 * package's answer to 114C.1's acceptance requirement that "older
 * protocol-v4 hubs produce a supported 'feature unavailable' state, not a
 * generic failure": a hub that never advertises the `human_accounts`
 * feature is not an error condition, it is a hub that predates 114C.
 */
export const AUTH_STATES = [
  "unknown", "unavailable", "bootstrap_required", "signed_out", "authenticating",
  "signed_in", "refresh_required", "step_up_required", "recovery_required",
  "session_expired", "account_disabled", "auth_degraded",
] as const;

export const DESKTOP_ROUTES = [
  "/dashboard", "/explorer", "/hub/:hubId", "/cluster/:clusterId",
  "/hosts/:hostId", "/runners/:runnerId", "/tasks/:taskId",
  "/agents/:agentId", "/agents/:agentId/capabilities/:kind/:name",
  "/approvals/:approvalId", "/cost", "/audit", "/audit/tasks/:taskId",
  "/secrets", "/settings/:section?", "/account",
] as const;

export type ViewId = (typeof VIEW_IDS)[number];
export type CommandId = (typeof COMMAND_IDS)[number];
export type SessionState = (typeof SESSION_STATES)[number];
export type AuthState = (typeof AUTH_STATES)[number];
export type NavigationDomain = (typeof NAVIGATION_DOMAINS)[number];
export type DesktopRoute = (typeof DESKTOP_ROUTES)[number];

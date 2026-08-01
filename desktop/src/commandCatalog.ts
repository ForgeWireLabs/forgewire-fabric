export type DesktopCommandAvailability = "supported" | "contextual" | "platform-alternative";

export interface DesktopCommand {
  id: string;
  label: string;
  category: string;
  availability: DesktopCommandAvailability;
  route?: string;
  action?: "refresh" | "dispatch" | "discover" | "cancel-task" | "redispatch-task" | "approve" | "deny" | "defer" | "pause-runner" | "resume-runner" | "sign-in-with-passkey" | "register-passkey";
  alternative?: string;
  keywords?: string;
}

const command = (
  id: string,
  label: string,
  category: string,
  availability: DesktopCommandAvailability,
  options: Pick<DesktopCommand, "route" | "action" | "alternative" | "keywords"> = {}
): DesktopCommand => ({ id, label, category, availability, ...options });

export const DESKTOP_COMMANDS: readonly DesktopCommand[] = [
  command("forgewire.installAgentSuite", "Install VS Code Agent Suite", "Bootstrap", "platform-alternative", { alternative: "No desktop equivalent: this installs VS Code chatmodes and prompt files into a workspace." }),
  command("forgewire.installCli", "Install ForgeWire CLI", "Bootstrap", "platform-alternative", { alternative: "Use the signed desktop installer or run the documented CLI installer outside the WebView." }),
  command("forgewire.connectHub", "Connect to Hub", "Connection", "supported", { route: "/settings/connection" }),
  command("forgewire.setToken", "Install Hub Token", "Connection", "supported", { route: "/settings/connection" }),
  // 114C.6 Slice 5d: opens the hub-served WebAuthn bridge (Slice 5b) in the
  // system browser via the sign_in_with_passkey/register_passkey Tauri
  // commands (webauthn_bridge.rs). "supported", not "contextual": neither
  // needs a selection, matching refresh/dispatch above.
  command("forgewire.auth.signInWithPasskey", "Sign In with Passkey", "Auth", "supported", { action: "sign-in-with-passkey" }),
  command("forgewire.auth.registerPasskey", "Register a Passkey", "Auth", "supported", { action: "register-passkey" }),
  // 114C.7 Slice 5b: the Desktop Account page's Step Up button. "contextual"
  // (not "supported"): matches every other /account-routed command --
  // selecting this in the palette navigates there rather than dispatching
  // standalone.
  command("forgewire.auth.stepUp", "Step Up (verify with passkey)", "Auth", "contextual", { route: "/account" }),
  // 114C.7 Slice 5a: the Desktop Account page's Sign Out button. "contextual"
  // (not "supported"): the actual action is a button on /account, not a
  // standalone palette dispatch -- selecting this in the palette navigates
  // there, matching every other /account-routed command.
  command("forgewire.auth.signOut", "Sign Out", "Auth", "contextual", { route: "/account" }),
  // 114C.7 Slice 5a: per-session Revoke button on the Account page's session
  // list -- inherently contextual (needs a specific non-current session row).
  command("forgewire.account.revokeSession", "Revoke Session", "Auth", "contextual", { route: "/account" }),
  // 114C.7 Slice 5c: the Account page's Administration section (visible only
  // to a signed-in admin). "contextual", matching every other /account-
  // routed command: the palette navigates there rather than dispatching
  // standalone.
  command("forgewire.account.createAccount", "Create Account", "Auth", "contextual", { route: "/account" }),
  command("forgewire.account.disableAccount", "Disable Account", "Auth", "contextual", { route: "/account" }),
  command("forgewire.account.enableAccount", "Enable Account", "Auth", "contextual", { route: "/account" }),
  command("forgewire.account.grantRole", "Grant Role", "Auth", "contextual", { route: "/account" }),
  command("forgewire.account.revokeRole", "Revoke Role", "Auth", "contextual", { route: "/account" }),
  // 114C.7 Slice 5d: two-step account deletion, each running a fresh step-up
  // first. "contextual", matching every other /account-routed command.
  command("forgewire.account.deleteAccount", "Delete Account", "Auth", "contextual", { route: "/account" }),
  command("forgewire.account.completeDeletion", "Complete Account Deletion", "Auth", "contextual", { route: "/account" }),
  command("forgewire.copyJoinToken", "Copy Join Token", "Connection", "platform-alternative", { alternative: "Use the protected CLI token workflow; desktop never exposes installed token values." }),
  command("forgewire.disconnect", "Disconnect Hub", "Connection", "platform-alternative", { route: "/settings/connection", alternative: "Change the active profile or remove the protected token with the CLI credential command." }),
  command("forgewire.startHubHere", "Start Hub Here", "Bootstrap", "platform-alternative", { alternative: "Use the installed ForgeWire Hub service controls; WebView process launch is intentionally unavailable." }),
  command("forgewire.startRunnerHere", "Start Runner Here", "Bootstrap", "platform-alternative", { alternative: "Use the installed ForgeWire Runner service controls." }),
  command("forgewire.dispatchTask", "Dispatch Task", "Tasks", "supported", { action: "dispatch", route: "/tasks/all", keywords: "new agent command prompt skill tool" }),
  command("forgewire.refresh", "Refresh Fabric", "Session", "supported", { action: "refresh" }),
  command("forgewire.cost.refresh", "Refresh Cost", "Cost", "supported", { action: "refresh", route: "/cost" }),
  command("forgewire.streamTask", "Open Task Stream", "Tasks", "contextual", { route: "/tasks/all" }),
  command("forgewire.cancelTask", "Cancel Selected Task", "Tasks", "contextual", { action: "cancel-task", route: "/tasks/all" }),
  command("forgewire.showTask", "Show Selected Task", "Tasks", "contextual", { route: "/tasks/all" }),
  command("forgewire.approveApproval", "Approve Selected Approval", "Approvals", "contextual", { action: "approve", route: "/approvals/all" }),
  command("forgewire.denyApproval", "Deny Selected Approval", "Approvals", "contextual", { action: "deny", route: "/approvals/all" }),
  command("forgewire.deferApproval", "Defer Approval", "Approvals", "contextual", { route: "/approvals/all", action: "defer", alternative: "Defers the item in the current desktop review while leaving hub state pending." }),
  command("forgewire.showDeferredApprovals", "Show Deferred Approvals", "Approvals", "supported", { route: "/approvals/all" }),
  command("forgewire.examineApproval", "Examine Approval", "Approvals", "contextual", { route: "/approvals/all" }),
  command("forgewire.copyApprovalReference", "Copy Approval Reference", "Approvals", "contextual", { route: "/approvals/all" }),
  command("forgewire.copyToken", "Copy Hub Token", "Connection", "platform-alternative", { alternative: "Unavailable by design: protected token values never return to the WebView." }),
  command("forgewire.generateToken", "Generate Hub Token", "Connection", "platform-alternative", { route: "/settings/connection", alternative: "Desktop installs a token issued by the cluster bootstrap path; it never creates a disconnected credential that would break hub authentication." }),
  command("forgewire.openSettings", "Open Settings", "Settings", "supported", { route: "/settings/connection" }),
  command("forgewire.renameHub", "Rename Hub", "Hub", "supported", { route: "/hub/active" }),
  command("forgewire.renameHost", "Rename Host", "Hosts", "contextual", { route: "/hub/active" }),
  command("forgewire.renameRunner", "Rename Runner", "Hosts", "contextual", { route: "/hub/active" }),
  command("forgewire.pauseRunner", "Request Runner Drain", "Hosts", "contextual", { action: "pause-runner", route: "/hub/active" }),
  command("forgewire.resumeRunner", "Clear Runner Drain", "Hosts", "contextual", { action: "resume-runner", route: "/hub/active" }),
  command("forgewire.restartRunnerService", "Restart Runner Service", "Hosts", "platform-alternative", { alternative: "Use the installed OS service manager; desktop does not spawn privileged processes." }),
  command("forgewire.startRunnerService", "Start Runner Service", "Hosts", "platform-alternative", { alternative: "Use the installed OS service manager." }),
  command("forgewire.stopRunnerService", "Stop Runner Service", "Hosts", "platform-alternative", { alternative: "Use the installed OS service manager." }),
  command("forgewire.pinHub", "Pin Hub", "Hub", "supported", { route: "/settings/connection" }),
  command("forgewire.unpinHub", "Unpin Hub", "Hub", "supported", { route: "/settings/connection" }),
  command("forgewire.promoteHub", "Promote Hub Candidate", "Hub", "platform-alternative", { alternative: "Use the authenticated failover CLI; promotion remains an explicit operational action." }),
  command("forgewire.demoteHub", "Demote Hub Candidate", "Hub", "platform-alternative", { alternative: "Use the authenticated failover CLI." }),
  command("forgewire.editHubCandidates", "Edit Hub Candidates", "Hub", "supported", { route: "/settings/connection", action: "discover" }),
  command("forgewire.dr.installBackupTask", "Install DR Backup Task", "Disaster Recovery", "platform-alternative", { alternative: "Use the signed installer/CLI workflow; VS Code terminal task has no safe WebView equivalent." }),
  command("forgewire.dr.installChaosTask", "Install DR Chaos Task", "Disaster Recovery", "platform-alternative", { alternative: "Use the signed installer/CLI workflow." }),
  command("forgewire.dr.provisionSshForSystem", "Provision SYSTEM SSH", "Disaster Recovery", "platform-alternative", { alternative: "Use the privileged installer workflow outside the WebView." }),
  command("forgewire.dr.runChaosNow", "Run DR Chaos Exercise", "Disaster Recovery", "platform-alternative", { alternative: "Use the audited DR CLI with explicit operator confirmation." }),
  command("forgewire.dr.tailLastChaosLog", "Open Latest Chaos Log", "Disaster Recovery", "platform-alternative", { route: "/audit", alternative: "Inspect the host log or audited CLI output." }),
  command("forgewire.dr.openClusterYaml", "Open Cluster YAML", "Disaster Recovery", "platform-alternative", { alternative: "Open the profile file in the system editor; desktop does not expose arbitrary files." }),
  command("forgewire.dr.openSettings", "Open DR Settings", "Disaster Recovery", "supported", { route: "/settings/diagnostics" }),
  command("forgewire.redispatchTask", "Redispatch Selected Task", "Tasks", "contextual", { route: "/tasks/all", action: "redispatch-task", alternative: "Creates a new signed dispatch from the selected task without persisting its prompt in the WebView." }),
  command("forgewire.dismissTask", "Dismiss Task from View", "Tasks", "supported", { route: "/tasks/all", alternative: "Use the task filter; dismissal remains local presentation state." }),
  command("forgewire.cancelStaleTask", "Cancel Stale Task", "Tasks", "contextual", { action: "cancel-task", route: "/tasks/all" })
] as const;

export function searchDesktopCommands(query: string): DesktopCommand[] {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [...DESKTOP_COMMANDS];
  return DESKTOP_COMMANDS.filter((item) => {
    const haystack = `${item.id} ${item.label} ${item.category} ${item.keywords ?? ""} ${item.alternative ?? ""}`.toLowerCase();
    return terms.every((term) => haystack.includes(term));
  });
}

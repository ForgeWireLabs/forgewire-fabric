import { useState } from "react";
import { PlusCircle, RefreshCw, ShieldCheck, Trash2, UserCircle, XCircle } from "lucide-react";
import { isAuthOperationOfferedInState } from "@forgewire/fabric-client-core";
import type { AccountSummaryResult, AuthResult } from "../api";
import { AuthorizationOrFailure, EmptyState, InfoLine, Panel, StatusPill } from "../components/primitives";
import type { WorkbenchProps } from "../main";

/**
 * 114C.7 Slice 5a/5b/5c/5d: self-service Account page -- profile, roles, active
 * sessions (with Sign Out / Revoke Session), Step Up, an Administration
 * section for a signed-in admin (Create Account, per-account Disable/
 * Enable, Grant/Revoke Role, two-step deletion), or a sign-in affordance
 * when no human session is stored. Mirrors the VSIX Account tree view's
 * scope exactly (114C.7 Slice 4a/4b/4c/4c-3a).
 *
 * Extracted into its own module (114C.7 Slice 6b) so it can be imported by
 * a test without triggering main.tsx's module-scope `createRoot(...)
 * .render(<App/>)` side effect.
 */
export function AccountPage({
  accountMe, accountSessions, accountError, accountLoading, accountsAdmin, accountRoles, authState,
  onAccountRefresh, onSignOut, onRevokeSession, onSignInWithPasskey, onSignInWithPassword, onStepUp,
  onCreateAccount, onDisableAccount, onEnableAccount, onGrantRole, onRevokeRole,
  onDeleteAccount, onCompleteDeletion
}: WorkbenchProps) {
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const signIn = async () => {
    setBusy("sign-in"); setNotice(null);
    try { await onSignInWithPasskey(); }
    finally { setBusy(null); }
  };
  // 114E: password sign-in -- the first-session on-ramp, and it establishes a
  // proof-of-possession (key-bound) session under the hood. The password stays
  // in component state only until native IPC accepts it, then it is cleared.
  const signInPassword = async () => {
    setBusy("sign-in-password"); setNotice(null);
    try {
      const result = await onSignInWithPassword(username.trim(), password);
      if (!result.ok) setNotice(result.message ?? "Sign-in failed.");
      setPassword("");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };
  const signOut = async () => {
    setBusy("sign-out"); setNotice(null);
    try { await onSignOut(); setNotice("Signed out."); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setBusy(null); }
  };
  const revoke = async (sessionId: string, label: string) => {
    if (!window.confirm(`Revoke the session "${label}"? That client will be signed out.`)) return;
    setBusy(`revoke-${sessionId}`); setNotice(null);
    try { await onRevokeSession(sessionId); setNotice("Session revoked."); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setBusy(null); }
  };
  const stepUpNow = async () => {
    setBusy("step-up"); setNotice(null);
    try {
      const ok = await onStepUp();
      setNotice(ok ? "Verified — your session is elevated." : "Step-up verification failed.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  if (!accountMe) {
    // 114C.7 Slice 6e: single shared gate (auth.ts's isAuthOperationOfferedInState)
    // for whether sign-in is even offered in the current authState, rather
    // than always rendering the button -- false when the connected hub
    // doesn't advertise human_accounts support (see App()'s
    // humanAccountsAdvertised probe).
    const signInOffered = isAuthOperationOfferedInState("auth.signIn", authState);
    return (
      <div className="page-stack">
        <Panel title="Account" action={accountLoading ? "loading…" : "not signed in"}>
          <div className="security-notice">
            <UserCircle size={24} />
            <div>
              <strong>Sign in to manage your account</strong>
              <p>
                {signInOffered
                  ? "Sessions, passkeys, and (for administrators) account management become available once you sign in."
                  : "The connected hub does not currently offer human-account sign-in."}
              </p>
            </div>
          </div>
          {accountError && <AuthorizationOrFailure message={accountError} />}
          {signInOffered && (
            <div className="settings-form">
              <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" placeholder="operator" /></label>
              <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>
              <button className="primary-command" onClick={() => void signInPassword()} disabled={busy === "sign-in-password" || !username.trim() || !password}>
                <UserCircle size={16} />Sign in
              </button>
            </div>
          )}
          <div className="button-row">
            {signInOffered && (
              <button onClick={() => void signIn()} disabled={busy === "sign-in"}>
                <UserCircle size={16} />Sign in with a passkey
              </button>
            )}
            <button onClick={() => void onAccountRefresh()} disabled={accountLoading}><RefreshCw size={15} />Refresh</button>
          </div>
          {notice && <span role="status" className="inline-error">{notice}</span>}
        </Panel>
      </div>
    );
  }

  // 114C.7 Slice 6e: same shared gate for the signed-in self-service actions.
  // With authState always "signed_in" here (accountMe is non-null), each of
  // these is always true today per auth.ts's descriptors -- the value is in
  // having one source of truth for "is this offered," not a behavior change.
  const stepUpOffered = isAuthOperationOfferedInState("auth.stepUp", authState);
  const signOutOffered = isAuthOperationOfferedInState("auth.signOut", authState);
  const revokeOffered = isAuthOperationOfferedInState("auth.revokeSession", authState);

  return (
    <div className="page-stack">
      <Panel title="Account" action={accountMe.status}>
        <div className="doctor-grid">
          <InfoLine label="name" value={accountMe.display_name} />
          <InfoLine label="username" value={accountMe.username} />
          <InfoLine label="status" value={accountMe.status} />
          <InfoLine label="roles" value={accountMe.roles.length > 0 ? accountMe.roles.join(", ") : "none"} />
        </div>
        <div className="button-row">
          {stepUpOffered && (
            <button onClick={() => void stepUpNow()} disabled={busy === "step-up"}>
              <ShieldCheck size={16} />Step Up
            </button>
          )}
          {signOutOffered && (
            <button className="danger-action" onClick={() => void signOut()} disabled={busy === "sign-out"}>
              <XCircle size={16} />Sign out
            </button>
          )}
          <button onClick={() => void onAccountRefresh()} disabled={accountLoading}><RefreshCw size={15} />Refresh</button>
        </div>
      </Panel>
      <Panel title="Sessions" action={String(accountSessions.length)}>
        <section className="secret-list">
          {accountSessions.map((session) => (
            <article key={session.session_id}>
              <UserCircle size={16} />
              <div>
                <strong>{session.client_label ?? session.client_kind}</strong>
                <small>{session.current ? "current session" : session.assurance_level} · authenticated {session.authenticated_at}</small>
              </div>
              {session.current
                ? <StatusPill status="current" compact />
                : revokeOffered && (
                  <button
                    className="danger-action"
                    onClick={() => void revoke(session.session_id, session.client_label ?? session.client_kind)}
                    disabled={busy === `revoke-${session.session_id}`}
                  >
                    <Trash2 size={14} />Revoke
                  </button>
                )}
            </article>
          ))}
          {accountSessions.length === 0 && <EmptyState label="No active sessions were returned." />}
        </section>
        {notice && <div className={notice.includes("revoked") || notice.includes("Signed out") || notice.startsWith("Verified") ? "inline-success" : "inline-error"} role="status">{notice}</div>}
      </Panel>
      {accountsAdmin !== null && (
        <AccountAdminSection
          accounts={accountsAdmin}
          roles={accountRoles}
          onCreateAccount={onCreateAccount}
          onDisableAccount={onDisableAccount}
          onEnableAccount={onEnableAccount}
          onGrantRole={onGrantRole}
          onRevokeRole={onRevokeRole}
          onDeleteAccount={onDeleteAccount}
          onCompleteDeletion={onCompleteDeletion}
        />
      )}
    </div>
  );
}

/**
 * 114C.7 Slice 5c: the Administration section of the Account page, shown
 * only when the signed-in human holds the "admin" role (`AccountPage`
 * renders this exclusively off `accountsAdmin !== null`). Mirrors VSIX's
 * `AccountProvider` Administration tree + `createAccountCmd`/
 * `withAdminAccount`-gated command handlers: the assignable-role vocabulary
 * comes from the hub's own `authPolicy()`, never a hardcoded copy, and every
 * mutation resolves the hub's own message on failure rather than a generic
 * one.
 */
export function AccountAdminSection({
  accounts, roles, onCreateAccount, onDisableAccount, onEnableAccount, onGrantRole, onRevokeRole,
  onDeleteAccount, onCompleteDeletion
}: Pick<WorkbenchProps, "onCreateAccount" | "onDisableAccount" | "onEnableAccount" | "onGrantRole" | "onRevokeRole" | "onDeleteAccount" | "onCompleteDeletion"> & {
  accounts: AccountSummaryResult[];
  roles: string[];
}) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const create = async () => {
    const selectedRole = role || roles[0];
    if (!username.trim() || !displayName.trim() || !password || !selectedRole) return;
    setBusy("create"); setNotice(null);
    try {
      const result = await onCreateAccount(username.trim(), displayName.trim(), password, selectedRole);
      if (result.ok) {
        setNotice(`Created "${username.trim()}".`);
        setUsername(""); setDisplayName(""); setRole("");
      } else {
        setNotice(result.message ?? "Could not create the account.");
      }
    } finally {
      setPassword("");
      setBusy(null);
    }
  };
  const disable = async (account: AccountSummaryResult) => {
    if (!window.confirm(`Disable "${account.username}"? Their sessions are revoked and they can no longer sign in.`)) return;
    setBusy(`disable-${account.account_id}`); setNotice(null);
    const result = await onDisableAccount(account.account_id, account.revision);
    setNotice(result.ok ? `Disabled "${account.username}".` : result.message ?? "Could not disable the account.");
    setBusy(null);
  };
  const enable = async (account: AccountSummaryResult) => {
    setBusy(`enable-${account.account_id}`); setNotice(null);
    const result = await onEnableAccount(account.account_id, account.revision);
    setNotice(result.ok ? `Enabled "${account.username}".` : result.message ?? "Could not enable the account.");
    setBusy(null);
  };
  const grant = async (account: AccountSummaryResult, roleToGrant: string) => {
    setBusy(`grant-${account.account_id}`); setNotice(null);
    const result = await onGrantRole(account.account_id, roleToGrant);
    setNotice(result.ok ? `Granted "${roleToGrant}" to "${account.username}".` : result.message ?? "Could not grant the role.");
    setBusy(null);
  };
  const revoke = async (account: AccountSummaryResult, roleToRevoke: string) => {
    setBusy(`revoke-role-${account.account_id}`); setNotice(null);
    const result = await onRevokeRole(account.account_id, roleToRevoke);
    setNotice(result.ok ? `Revoked "${roleToRevoke}" from "${account.username}".` : result.message ?? "Could not revoke the role.");
    setBusy(null);
  };
  /**
   * 114C.7 Slice 5d: both deletion actions run a fresh step-up first (inside
   * `onDeleteAccount`/`onCompleteDeletion` -- opens the system browser for a
   * WebAuthn ceremony), so the "verifying" busy state covers that too, not
   * just the mutation itself. Mirrors VSIX's `withDeletionStepUp` +
   * `deleteAccountCmd`/`completeDeletionCmd` modal-confirmation text exactly.
   */
  const deleteAccount = async (account: AccountSummaryResult) => {
    if (!window.confirm(`Delete "${account.username}"? Their sessions are revoked and the account is marked for deletion (a second, permanent step completes it). You will be asked to verify with your passkey first.`)) return;
    setBusy(`delete-${account.account_id}`); setNotice(null);
    const result = await onDeleteAccount(account.account_id, account.revision);
    setNotice(result.ok ? `"${account.username}" marked for deletion.` : result.message ?? "Could not delete the account.");
    setBusy(null);
  };
  const completeDeletion = async (account: AccountSummaryResult) => {
    if (!window.confirm(`Permanently delete "${account.username}"? This is irreversible. You will be asked to verify with your passkey first.`)) return;
    setBusy(`complete-deletion-${account.account_id}`); setNotice(null);
    const result = await onCompleteDeletion(account.account_id, account.revision);
    setNotice(result.ok ? `"${account.username}" permanently deleted.` : result.message ?? "Could not complete the deletion.");
    setBusy(null);
  };

  return (
    <Panel title="Administration" action={String(accounts.length)}>
      <div className="secret-grid">
        <section className="secret-list">
          {accounts.map((account) => {
            const grantable = roles.filter((candidate) => !account.roles.includes(candidate));
            return (
              <article key={account.account_id}>
                <UserCircle size={16} />
                <div>
                  <strong>{account.display_name}</strong>
                  <small>{account.username} · {account.status} · {account.roles.length > 0 ? account.roles.join(", ") : "no roles"}</small>
                </div>
                <div className="button-row">
                  {account.status === "active" && (
                    <button className="danger-action" onClick={() => void disable(account)} disabled={busy === `disable-${account.account_id}`}>
                      Disable
                    </button>
                  )}
                  {account.status === "disabled" && (
                    <button onClick={() => void enable(account)} disabled={busy === `enable-${account.account_id}`}>
                      Enable
                    </button>
                  )}
                  {grantable.length > 0 && (
                    <select
                      aria-label={`Grant a role to ${account.username}`}
                      value=""
                      onChange={(event) => { const value = event.target.value; if (value) void grant(account, value); }}
                      disabled={busy === `grant-${account.account_id}`}
                    >
                      <option value="">Grant role…</option>
                      {grantable.map((candidate) => <option key={candidate} value={candidate}>{candidate}</option>)}
                    </select>
                  )}
                  {account.roles.length > 0 && (
                    <select
                      aria-label={`Revoke a role from ${account.username}`}
                      value=""
                      onChange={(event) => { const value = event.target.value; if (value) void revoke(account, value); }}
                      disabled={busy === `revoke-role-${account.account_id}`}
                    >
                      <option value="">Revoke role…</option>
                      {account.roles.map((candidate) => <option key={candidate} value={candidate}>{candidate}</option>)}
                    </select>
                  )}
                  {account.status === "deletion_pending"
                    ? (
                      <button className="danger-action" onClick={() => void completeDeletion(account)} disabled={busy === `complete-deletion-${account.account_id}`}>
                        <Trash2 size={14} />Complete Deletion
                      </button>
                    )
                    : (
                      <button className="danger-action" onClick={() => void deleteAccount(account)} disabled={busy === `delete-${account.account_id}`}>
                        <Trash2 size={14} />Delete
                      </button>
                    )}
                </div>
              </article>
            );
          })}
          {accounts.length === 0 && <EmptyState label="No other accounts were returned." />}
        </section>
        <section className="governance-form">
          <h4>Create account</h4>
          <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></label>
          <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} autoComplete="off" /></label>
          <label>Initial password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></label>
          <label>
            Role
            <select value={role || roles[0] || ""} onChange={(event) => setRole(event.target.value)}>
              {roles.map((candidate) => <option key={candidate} value={candidate}>{candidate}</option>)}
            </select>
          </label>
          <button
            className="primary-command"
            onClick={() => void create()}
            disabled={busy === "create" || !username.trim() || !displayName.trim() || !password || roles.length === 0}
          >
            <PlusCircle size={16} />Create
          </button>
        </section>
      </div>
      {notice && <div className={notice.startsWith("Could not") ? "inline-error" : "inline-success"} role="status">{notice}</div>}
    </Panel>
  );
}

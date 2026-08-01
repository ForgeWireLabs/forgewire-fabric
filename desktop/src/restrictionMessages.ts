/**
 * Every entry in a snapshot's `restrictions` map (`role_policy_restriction`
 * in main.rs) reports the *installed automation token's* granted roles -- a
 * categorically different credential from the signed-in human's own account
 * role (see `accountMe`'s doc comment in main.tsx: account data deliberately
 * never flows through `HubApi.loadSnapshot()`, so these two role lists can
 * genuinely differ, e.g. an `admin` account behind a legacy `dispatcher/
 * runner/observer` automation token). Discovered live 2026-07-28: an admin
 * reading "Current token roles: dispatcher, runner, observer" reasonably
 * read that as describing them, not a separate machine credential -- this
 * note exists so the same confusion doesn't recur.
 *
 * Extracted into its own module (mirroring the `AccountPage` extraction) so
 * it can be imported by a test without triggering main.tsx's module-scope
 * `createRoot(...).render(<App/>)` side effect.
 */
export function accountRoleContextNote(accountRoles: readonly string[] | null): string {
  if (accountRoles === null) return "";
  const roleText = accountRoles.length > 0 ? accountRoles.join(", ") : "none";
  return ` Your signed-in account role (${roleText}) is a separate credential from the installed automation token and does not itself grant this view -- install a role token with the required role to grant it.`;
}

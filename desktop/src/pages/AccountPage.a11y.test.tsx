/**
 * @vitest-environment jsdom
 *
 * 114C.7 Slice 6b: accessibility, keyboard/focus, and redaction coverage for
 * the Account page -- the master plan's 114C.7 deliverable this repo never
 * had automated tests for. Uses a per-file jsdom environment pragma so the
 * other 46+ pure-logic desktop tests keep running in vitest's default `node`
 * environment untouched (no global vite.config.ts change).
 *
 * `AccountPage`'s prop type is the full `WorkbenchProps` "god object" shared
 * by every routed page, even though this component only reads ~18 of its
 * fields -- the fixtures below are cast rather than fully populated, which
 * is safe because `AccountPage` never reads anything outside the fields it
 * destructures.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { deriveAuthState } from "@forgewire/fabric-client-core";
import { AccountPage } from "./AccountPage";
import type { WorkbenchProps } from "../main";
import type { AccountSummaryResult, AuthResult, SessionSummaryResult } from "../api";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// color-contrast is disabled for every axe.run below: jsdom has no real
// paint/layout engine, so computed-style-based contrast checks are
// unreliable there -- a standard, documented caveat of running axe outside
// a real browser, not a scope dodge around this component's actual styling.
async function axeCheck(container: Element): Promise<void> {
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations, JSON.stringify(results.violations, null, 2)).toHaveLength(0);
}

const ok = <T,>(data?: T): Promise<AuthResult<T>> => Promise.resolve({ ok: true, data });

function baseProps(overrides: Partial<WorkbenchProps>): WorkbenchProps {
  const accountMe = overrides.accountMe ?? null;
  const merged = {
    accountMe,
    accountSessions: [],
    accountError: null,
    accountLoading: false,
    accountsAdmin: null,
    accountRoles: [],
    // Simulates the common case (hub advertises human_accounts) -- App()
    // itself derives this from a real probe (main.tsx's humanAccountsAdvertised
    // state), not a hardcoded value.
    authState: deriveAuthState({ humanAccountsSupported: true, signedIn: accountMe !== null }),
    onAccountRefresh: () => Promise.resolve(),
    onSignOut: () => Promise.resolve(),
    onRevokeSession: () => Promise.resolve(),
    onSignInWithPasskey: () => Promise.resolve(),
    onStepUp: () => Promise.resolve(true),
    onCreateAccount: () => ok<AccountSummaryResult>(),
    onDisableAccount: () => ok<AccountSummaryResult>(),
    onEnableAccount: () => ok<AccountSummaryResult>(),
    onGrantRole: () => ok<AccountSummaryResult>(),
    onRevokeRole: () => ok<AccountSummaryResult>(),
    onDeleteAccount: () => ok<AccountSummaryResult>(),
    onCompleteDeletion: () => ok<AccountSummaryResult>(),
    ...overrides
  };
  return merged as unknown as WorkbenchProps;
}

const selfServiceMe: AccountSummaryResult = {
  account_id: "acct-1", username: "operator1", display_name: "Operator One",
  status: "active", roles: ["reviewer"], revision: 4
};

const sessions: SessionSummaryResult[] = [
  { session_id: "sess-current", account_id: "acct-1", client_kind: "desktop", client_label: "This machine", assurance_level: "aal1", authenticated_at: "2026-07-01T00:00:00Z", idle_expires_at: "", absolute_expires_at: "", current: true },
  { session_id: "sess-other", account_id: "acct-1", client_kind: "vscode", client_label: "Laptop", assurance_level: "aal1", authenticated_at: "2026-07-02T00:00:00Z", idle_expires_at: "", absolute_expires_at: "", current: false }
];

const adminMe: AccountSummaryResult = { ...selfServiceMe, roles: ["reviewer", "admin"] };

const adminAccounts: AccountSummaryResult[] = [
  { account_id: "acct-2", username: "reviewer1", display_name: "Reviewer One", status: "active", roles: ["reviewer"], revision: 1 },
  { account_id: "acct-3", username: "pending1", display_name: "Pending Deletion", status: "deletion_pending", roles: [], revision: 2 }
];

describe("AccountPage accessibility", () => {
  it("not-signed-in state has no axe violations", async () => {
    const { container } = render(<AccountPage {...baseProps({})} />);
    await axeCheck(container);
  });

  it("signed-in self-service state has no axe violations", async () => {
    const { container } = render(
      <AccountPage {...baseProps({ accountMe: selfServiceMe, accountSessions: sessions })} />
    );
    await axeCheck(container);
  });

  it("signed-in admin state has no axe violations", async () => {
    const { container } = render(
      <AccountPage {...baseProps({
        accountMe: adminMe,
        accountSessions: sessions,
        accountsAdmin: adminAccounts,
        accountRoles: ["reviewer", "admin"]
      })} />
    );
    await axeCheck(container);
  });
});

describe("AccountPage keyboard/focus", () => {
  it("reaches every interactive element via sequential Tab presses (no keyboard trap)", async () => {
    const user = userEvent.setup();
    render(
      <AccountPage {...baseProps({
        accountMe: adminMe,
        accountSessions: sessions,
        accountsAdmin: adminAccounts,
        accountRoles: ["reviewer", "admin"]
      })} />
    );

    // Disabled controls are correctly excluded from tab order (e.g. "Create"
    // starts disabled until every required field is filled) -- only enabled
    // elements are expected to be Tab-reachable here.
    const isEnabled = (element: Element) => !(element as HTMLButtonElement | HTMLSelectElement | HTMLInputElement).disabled;
    const interactive = [
      ...screen.getAllByRole("button"),
      ...screen.getAllByRole("combobox"),
      ...screen.getAllByRole("textbox")
    ].filter(isEnabled);
    expect(interactive.length).toBeGreaterThan(0);

    const reached = new Set<Element>();
    document.body.focus();
    for (let i = 0; i < interactive.length + 2; i += 1) {
      await user.tab();
      if (document.activeElement && document.activeElement !== document.body) {
        reached.add(document.activeElement);
      }
    }
    for (const element of interactive) {
      expect(reached.has(element), `${element.tagName} "${element.textContent ?? ""}" was never reachable via Tab`).toBe(true);
    }
  });

  it("Enter on a focused button fires its click handler (real <button> semantics, not a div)", async () => {
    const user = userEvent.setup();
    const onAccountRefresh = vi.fn().mockResolvedValue(undefined);
    render(<AccountPage {...baseProps({ onAccountRefresh })} />);

    const refreshButton = screen.getByRole("button", { name: /refresh/i });
    refreshButton.focus();
    await user.keyboard("{Enter}");
    expect(onAccountRefresh).toHaveBeenCalledTimes(1);
  });
});

describe("AccountPage redaction", () => {
  // These fixtures simulate an upstream bug (a DTO accidentally carrying
  // secret fields, or an admin-list row leaking session material) rather
  // than today's real data flow: AccountSummaryResult/SessionSummaryResult's
  // own type shapes have no secret fields at all, so the *type system*
  // already forbids this in the real app. Casting a poisoned object past
  // that guard is exactly how this test still catches a future regression
  // -- e.g. a careless `<InfoLine value={JSON.stringify(accountMe)} />` --
  // that the type system alone wouldn't.
  const SECRET_SENTINEL = "sentinel-access-secret-must-never-render-6f3a1c";

  it("never renders a secret-bearing field smuggled onto the signed-in profile or session list", () => {
    const poisonedMe = { ...selfServiceMe, access_secret: SECRET_SENTINEL, refresh_secret: SECRET_SENTINEL } as unknown as AccountSummaryResult;
    const poisonedSessions = [
      { ...sessions[0], access_secret: SECRET_SENTINEL } as unknown as SessionSummaryResult,
      sessions[1]
    ];
    const { container } = render(
      <AccountPage {...baseProps({ accountMe: poisonedMe, accountSessions: poisonedSessions })} />
    );
    expect(container.textContent).not.toContain(SECRET_SENTINEL);
  });

  it("never renders a secret-bearing field smuggled onto an admin account row", () => {
    const poisonedAccounts = [
      { ...adminAccounts[0], access_secret: SECRET_SENTINEL } as unknown as AccountSummaryResult,
      adminAccounts[1]
    ];
    const { container } = render(
      <AccountPage {...baseProps({
        accountMe: adminMe,
        accountSessions: sessions,
        accountsAdmin: poisonedAccounts,
        accountRoles: ["reviewer", "admin"]
      })} />
    );
    expect(container.textContent).not.toContain(SECRET_SENTINEL);
  });

  it("never renders whatever a step-up/mutation callback resolves, even if it carries a secret", async () => {
    // onStepUp's real type is () => Promise<boolean> -- the App()-level
    // caller already strips the rotated access secret down to a boolean
    // before AccountPage ever sees it (see runStepUp in main.tsx). This
    // proves the component's own rendering never bypasses that by somehow
    // stringifying the full resolved value.
    const user = userEvent.setup();
    const onStepUp = vi.fn().mockResolvedValue(true) as unknown as () => Promise<boolean>;
    (onStepUp as unknown as { mockResolvedValueOnce: (value: unknown) => void }).mockResolvedValueOnce({
      ok: true,
      access_secret: SECRET_SENTINEL
    });
    const { container } = render(
      <AccountPage {...baseProps({ accountMe: selfServiceMe, onStepUp })} />
    );
    await user.click(screen.getByRole("button", { name: /step up/i }));
    expect(container.textContent).not.toContain(SECRET_SENTINEL);
  });
});

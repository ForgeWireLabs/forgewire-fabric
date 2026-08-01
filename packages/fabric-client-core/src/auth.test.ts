import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AUTH_OPERATION_DESCRIPTORS, AUTH_STATES, deriveAuthState, detectFabricFeatures,
  findAuthOperationDescriptor, isAuthOperationOfferedInState, isTypedAuthErrorCode,
  normalizeAccountSummary, normalizeSessionSummary,
  supportsFabricFeature, TYPED_AUTH_ERROR_CODES,
  type AccountSessionFixture, type AuthOperationId, type AuthState,
  type SessionCredentialStore, type SessionSecrets,
} from "./index.js";

class MemorySessionSecrets implements SessionCredentialStore {
  readonly values = new Map<string, SessionSecrets>();
  async get(profileId: string) { return this.values.get(profileId); }
  async set(profileId: string, secrets: SessionSecrets) { this.values.set(profileId, secrets); }
  async delete(profileId: string) { this.values.delete(profileId); }
}

// packages/fabric-client-core/src/ -> packages/fabric-client-core -> packages -> repo root
const FIXTURE_PATH = fileURLToPath(
  new URL("../../../tests/fixtures/accounts/account_session_summary.json", import.meta.url),
);

function loadFixture(): AccountSessionFixture {
  return JSON.parse(readFileSync(FIXTURE_PATH, "utf-8")) as AccountSessionFixture;
}

describe("human_accounts feature negotiation", () => {
  it("an older protocol-v4 hub that never advertises human_accounts does not support it", () => {
    const supported = detectFabricFeatures({ protocolVersion: 4, advertised: [] });
    expect(supported.has("human_accounts")).toBe(false);
    // Every other v4-era feature still falls under the protocol>=4 floor --
    // this is specifically about human_accounts, not a general v4 regression.
    expect(supported.has("cost")).toBe(true);
    expect(supported.has("cluster_health")).toBe(true);
  });

  it("a hub that explicitly advertises human_accounts supports it regardless of protocol number", () => {
    expect(supportsFabricFeature({ protocolVersion: 4, advertised: ["human_accounts"] }, "human_accounts")).toBe(true);
    expect(supportsFabricFeature({ protocolVersion: 3, advertised: ["human_accounts"] }, "human_accounts")).toBe(true);
  });

  it("advertisement is case/whitespace-insensitive, matching the existing normalization", () => {
    expect(supportsFabricFeature({ protocolVersion: 4, advertised: [" Human_Accounts "] }, "human_accounts")).toBe(true);
  });
});

describe("deriveAuthState", () => {
  it("an unsupported hub always resolves to 'unavailable', not a generic failure state", () => {
    const state = deriveAuthState({ humanAccountsSupported: false, signedIn: true, bootstrapRequired: true });
    expect(state).toBe("unavailable");
  });

  it("unavailable outranks every other signal", () => {
    const state: AuthState = deriveAuthState({
      humanAccountsSupported: false,
      authServiceDegraded: true,
      accountDisabled: true,
    });
    expect(state).toBe("unavailable");
  });

  it("bootstrap_required is the default supported state with no session yet", () => {
    expect(deriveAuthState({ humanAccountsSupported: true, bootstrapRequired: true })).toBe("bootstrap_required");
  });

  it("signed_out is the floor when nothing else applies", () => {
    expect(deriveAuthState({ humanAccountsSupported: true })).toBe("signed_out");
  });

  it("account_disabled outranks session_expired and step_up_required", () => {
    expect(
      deriveAuthState({ humanAccountsSupported: true, accountDisabled: true, sessionExpired: true, stepUpRequired: true }),
    ).toBe("account_disabled");
  });

  it("signed_in only when no higher-precedence signal is set", () => {
    expect(deriveAuthState({ humanAccountsSupported: true, signedIn: true })).toBe("signed_in");
  });

  it("every AUTH_STATES value is reachable by at least one signal combination", () => {
    const reachable = new Set<AuthState>([
      deriveAuthState({ humanAccountsSupported: false }),
      deriveAuthState({ humanAccountsSupported: true }),
      deriveAuthState({ humanAccountsSupported: true, authenticating: true }),
      deriveAuthState({ humanAccountsSupported: true, bootstrapRequired: true }),
      deriveAuthState({ humanAccountsSupported: true, signedIn: true }),
      deriveAuthState({ humanAccountsSupported: true, refreshRequired: true }),
      deriveAuthState({ humanAccountsSupported: true, stepUpRequired: true }),
      deriveAuthState({ humanAccountsSupported: true, recoveryRequired: true }),
      deriveAuthState({ humanAccountsSupported: true, sessionExpired: true }),
      deriveAuthState({ humanAccountsSupported: true, accountDisabled: true }),
      deriveAuthState({ humanAccountsSupported: true, authServiceDegraded: true }),
    ]);
    // "unknown" is the machine's initial/pre-signal state, not something any
    // signal combination derives -- it is the caller's starting value before
    // the first signal is known, so it is deliberately excluded here.
    const expected = new Set(AUTH_STATES.filter((s) => s !== "unknown"));
    expect(reachable).toEqual(expected);
  });
});

describe("auth operation descriptors", () => {
  it("every operation id maps to exactly one descriptor", () => {
    for (const descriptor of AUTH_OPERATION_DESCRIPTORS) {
      expect(findAuthOperationDescriptor(descriptor.id)).toBe(descriptor);
    }
  });

  it("sensitive operations are all marked requiresStepUp, matching the plan's step-up list", () => {
    const sensitive: AuthOperationId[] = [
      "auth.revokeAllSessions", "auth.addPasskey", "auth.removePasskey", "auth.regenerateRecoveryCodes",
    ];
    for (const id of sensitive) {
      expect(findAuthOperationDescriptor(id)?.requiresStepUp).toBe(true);
    }
    // And a routine operation is not accidentally gated behind step-up.
    expect(findAuthOperationDescriptor("auth.signIn")?.requiresStepUp).toBe(false);
  });

  it("bootstrap is only offered in bootstrap_required, never in signed_out", () => {
    expect(isAuthOperationOfferedInState("auth.bootstrap", "bootstrap_required")).toBe(true);
    expect(isAuthOperationOfferedInState("auth.bootstrap", "signed_out")).toBe(false);
  });

  it("session management is only offered while signed in", () => {
    expect(isAuthOperationOfferedInState("auth.listSessions", "signed_in")).toBe(true);
    expect(isAuthOperationOfferedInState("auth.listSessions", "unavailable")).toBe(false);
    expect(isAuthOperationOfferedInState("auth.listSessions", "signed_out")).toBe(false);
  });
});

describe("SessionCredentialStore (114C.3 protected session storage adapter interface)", () => {
  it("round-trips session secrets through a get/set/delete implementation", async () => {
    const store = new MemorySessionSecrets();
    const secrets: SessionSecrets = { sessionId: "sess-1", accessSecret: "access-xyz", refreshSecret: "refresh-xyz" };

    expect(await store.get("profile-a")).toBeUndefined();
    await store.set("profile-a", secrets);
    expect(await store.get("profile-a")).toEqual(secrets);

    await store.delete("profile-a");
    expect(await store.get("profile-a")).toBeUndefined();
  });

  it("keeps separate profiles isolated", async () => {
    const store = new MemorySessionSecrets();
    await store.set("profile-a", { sessionId: "a", accessSecret: "aa", refreshSecret: "ar" });
    await store.set("profile-b", { sessionId: "b", accessSecret: "ba", refreshSecret: "br" });
    await store.delete("profile-a");
    expect(await store.get("profile-a")).toBeUndefined();
    expect(await store.get("profile-b")).toEqual({ sessionId: "b", accessSecret: "ba", refreshSecret: "br" });
  });
});

describe("cross-language fixture parity (114C.1 acceptance)", () => {
  it("parses the shared fixture with the expected safe fields", () => {
    const fixture = loadFixture();
    expect(fixture.account_summary.account_id).toBe("acct-01hxfixture0000000000000");
    expect(fixture.account_summary.username).toBe("operator1");
    expect(fixture.account_summary.roles).toEqual(["dispatcher", "reviewer"]);
    expect(fixture.session_summary.session_id).toBe("sess-01hxfixture0000000000000");
    expect(fixture.session_summary.assurance_level).toBe("aal1");
    expect(fixture.session_summary.current).toBe(true);
  });

  it("the fixture's typed_error_codes exactly match TYPED_AUTH_ERROR_CODES (same members, same order)", () => {
    const fixture = loadFixture();
    expect(fixture.typed_error_codes).toEqual([...TYPED_AUTH_ERROR_CODES]);
  });

  it("every code in the fixture is recognized by isTypedAuthErrorCode", () => {
    const fixture = loadFixture();
    for (const code of fixture.typed_error_codes) {
      expect(isTypedAuthErrorCode(code)).toBe(true);
    }
  });

  it("isTypedAuthErrorCode rejects an unknown code", () => {
    expect(isTypedAuthErrorCode("NotARealCode")).toBe(false);
  });
});

describe("wire DTO -> view-model normalization (114C.7 Slice 2)", () => {
  it("normalizeAccountSummary maps every snake_case field to its camelCase counterpart", () => {
    const fixture = loadFixture();
    expect(normalizeAccountSummary(fixture.account_summary)).toEqual({
      accountId: "acct-01hxfixture0000000000000",
      username: "operator1",
      displayName: "Operator One",
      status: "active",
      roles: ["dispatcher", "reviewer"],
      revision: 3,
    });
  });

  it("normalizeSessionSummary maps every snake_case field to its camelCase counterpart", () => {
    const fixture = loadFixture();
    expect(normalizeSessionSummary(fixture.session_summary)).toEqual({
      sessionId: "sess-01hxfixture0000000000000",
      accountId: "acct-01hxfixture0000000000000",
      clientKind: "vsix",
      clientLabel: "VS Code on desktop-a",
      assuranceLevel: "aal1",
      authenticatedAt: "2026-07-17T12:00:00Z",
      idleExpiresAt: "2026-07-17T13:00:00Z",
      absoluteExpiresAt: "2026-07-18T12:00:00Z",
      current: true,
    });
  });

  it("normalizeSessionSummary omits clientLabel entirely, not as undefined, when absent from the wire DTO", () => {
    const fixture = loadFixture();
    const { client_label: _clientLabel, ...withoutLabel } = fixture.session_summary;
    const normalized = normalizeSessionSummary(withoutLabel as typeof fixture.session_summary);
    expect("clientLabel" in normalized).toBe(false);
  });
});

/**
 * Safe account/session wire DTOs and the typed-error baseline from the
 * human-accounts plan's "Typed error baseline" and "Safe shared models"
 * sections. Field names are the wire/JSON shape (snake_case), matching the
 * fixture in `tests/fixtures/accounts/account_session_summary.json` and the
 * existing fabric-hub HTTP JSON convention -- not this package's usual
 * camelCase view-model shape (see {@link HubDto} etc. in contracts.ts),
 * which a normalization step (114C.7) will map these onto.
 *
 * No field below can hold a secret. There is no client-side type here that
 * a login/refresh result is stored into other than these -- the plan's rule
 * that "secret-bearing login/refresh results terminate in the platform
 * credential adapter" means the actual access/refresh secrets never reach
 * this package's state at all, so there is nothing to redact here: the
 * absence of a field is the enforcement mechanism, the same way
 * `SecretString`'s missing `Serialize` impl is the enforcement mechanism on
 * the Rust side.
 */

export const TYPED_AUTH_ERROR_CODES = [
  "AuthenticationRequired",
  "InvalidCredentials",
  "SessionExpired",
  "SessionRevoked",
  "RefreshReplayDetected",
  "AccountDisabled",
  "AccountLocked",
  "RecoveryRequired",
  "StepUpRequired",
  "AssuranceTooLow",
  "AccountPolicyViolation",
  "LastAdministratorViolation",
  "UsernameConflict",
  "CredentialConflict",
  "BootstrapClosed",
  "BootstrapLocalOnly",
  "AuthServiceUnavailable",
  "RolePolicyViolation",
  "ChallengeInvalid",
  "CredentialReplaySuspected",
  "RealmAlreadyEstablished",
] as const;

export type TypedAuthErrorCode = (typeof TYPED_AUTH_ERROR_CODES)[number];

export interface TypedAuthError {
  readonly code: TypedAuthErrorCode;
  readonly message: string;
}

export type AccountStatusWire =
  | "invited" | "active" | "disabled" | "locked"
  | "recovery_required" | "deletion_pending" | "deleted_tombstone";

export type AssuranceLevelWire = "aal1" | "aal2" | "recovery_limited";

export interface AccountSummaryWireDto {
  readonly account_id: string;
  readonly username: string;
  readonly display_name: string;
  readonly status: AccountStatusWire | string;
  readonly roles: readonly string[];
  /** Compare-and-set token required by `expected_revision` on every
   *  account-mutation route (update status, disable, enable, initiate/
   *  complete deletion). Callers must re-fetch the account (or use the
   *  revision echoed back in a prior mutation's own response) before a
   *  follow-up mutation -- there is no other way to learn the current
   *  value. */
  readonly revision: number;
}

export interface SessionSummaryWireDto {
  readonly session_id: string;
  readonly account_id: string;
  readonly client_kind: string;
  readonly client_label?: string;
  readonly assurance_level: AssuranceLevelWire | string;
  readonly authenticated_at: string;
  readonly idle_expires_at: string;
  readonly absolute_expires_at: string;
  readonly current: boolean;
}

/** Shape of `tests/fixtures/accounts/account_session_summary.json`. */
export interface AccountSessionFixture {
  readonly account_summary: AccountSummaryWireDto;
  readonly session_summary: SessionSummaryWireDto;
  readonly typed_error_codes: readonly string[];
}

export function isTypedAuthErrorCode(value: string): value is TypedAuthErrorCode {
  return (TYPED_AUTH_ERROR_CODES as readonly string[]).includes(value);
}

// ---- 114C.7 Slice 2: wire DTO -> view-model normalization -----------------
// Pure, DTO-in/view-model-out functions turning the snake_case wire shapes
// above into the camelCase shape the rest of this package (and both UI
// layers) use -- same division of labor as `normalizeFabricSnapshot` in
// normalize.ts, kept in this file instead since it's a direct 1:1 mapping
// of the two DTOs declared just above, not a multi-domain snapshot.

export interface AccountSummary {
  readonly accountId: string;
  readonly username: string;
  readonly displayName: string;
  readonly status: AccountStatusWire | string;
  readonly roles: readonly string[];
  readonly revision: number;
}

export interface SessionSummary {
  readonly sessionId: string;
  readonly accountId: string;
  readonly clientKind: string;
  readonly clientLabel?: string;
  readonly assuranceLevel: AssuranceLevelWire | string;
  readonly authenticatedAt: string;
  readonly idleExpiresAt: string;
  readonly absoluteExpiresAt: string;
  readonly current: boolean;
}

export function normalizeAccountSummary(dto: AccountSummaryWireDto): AccountSummary {
  return {
    accountId: dto.account_id,
    username: dto.username,
    displayName: dto.display_name,
    status: dto.status,
    roles: dto.roles,
    revision: dto.revision,
  };
}

export function normalizeSessionSummary(dto: SessionSummaryWireDto): SessionSummary {
  return {
    sessionId: dto.session_id,
    accountId: dto.account_id,
    clientKind: dto.client_kind,
    ...(dto.client_label === undefined ? {} : { clientLabel: dto.client_label }),
    assuranceLevel: dto.assurance_level,
    authenticatedAt: dto.authenticated_at,
    idleExpiresAt: dto.idle_expires_at,
    absoluteExpiresAt: dto.absolute_expires_at,
    current: dto.current,
  };
}

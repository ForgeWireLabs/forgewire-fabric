/**
 * The shared operator-auth state machine and operation descriptors from the
 * human-accounts plan's "Shared auth state machine" section (114C.1
 * deliverable: "Add `fabric-client-core` auth state machine and operation
 * descriptors without enabling routes"). Nothing here calls a network
 * transport -- {@link AUTH_OPERATION_DESCRIPTORS} is a catalog VSIX/Desktop
 * drive against their own concrete HTTP clients (`hubClient.ts`/`api.ts`),
 * not a shared abstract transport (the `FabricTransport` interface this
 * comment once pointed at was speculative scaffold, never adopted by either
 * client, and was deleted in 114C.7 Slice 6c's AC-114B-5 cleanup).
 */

import type { AuthState } from "./constants.js";

/**
 * Inputs to {@link deriveAuthState}. Mirrors the shape of
 * {@link SessionSignals} in session.ts: independent booleans in, one state
 * out, so the precedence order lives in exactly one function instead of
 * being re-derived at every call site.
 */
export interface AuthSignals {
  /** From `supportsFabricFeature(signals, "human_accounts")` -- see features.ts. */
  readonly humanAccountsSupported: boolean;
  readonly authServiceDegraded?: boolean;
  readonly accountDisabled?: boolean;
  readonly recoveryRequired?: boolean;
  readonly sessionExpired?: boolean;
  readonly stepUpRequired?: boolean;
  readonly refreshRequired?: boolean;
  readonly authenticating?: boolean;
  readonly signedIn?: boolean;
  readonly bootstrapRequired?: boolean;
}

/**
 * Precedence, most urgent first: a hub that cannot support accounts at all
 * overrides every other signal (there is nothing else truthful to say); a
 * degraded auth service and a disabled account are reported before any
 * session-freshness state, because they are broader failures than "this
 * particular session went stale."
 */
export function deriveAuthState(signals: AuthSignals): AuthState {
  if (!signals.humanAccountsSupported) return "unavailable";
  if (signals.authServiceDegraded) return "auth_degraded";
  if (signals.accountDisabled) return "account_disabled";
  if (signals.recoveryRequired) return "recovery_required";
  if (signals.sessionExpired) return "session_expired";
  if (signals.stepUpRequired) return "step_up_required";
  if (signals.refreshRequired) return "refresh_required";
  if (signals.signedIn) return "signed_in";
  if (signals.authenticating) return "authenticating";
  if (signals.bootstrapRequired) return "bootstrap_required";
  return "signed_out";
}

export const AUTH_OPERATION_IDS = [
  "auth.bootstrap",
  "auth.signIn",
  "auth.signOut",
  "auth.refresh",
  "auth.stepUp",
  "auth.listSessions",
  "auth.revokeSession",
  "auth.revokeAllSessions",
  "auth.addPasskey",
  "auth.removePasskey",
  "auth.regenerateRecoveryCodes",
  "auth.changePassword",
  "auth.recoveryStart",
  "auth.recoveryComplete",
] as const;

export type AuthOperationId = (typeof AUTH_OPERATION_IDS)[number];

export interface AuthOperationDescriptor {
  readonly id: AuthOperationId;
  /** States the operation may be invoked from. Anything else: not offered. */
  readonly requiresState: readonly AuthState[];
  /** Sensitive-action step-up, per the plan's own list under that heading. */
  readonly requiresStepUp: boolean;
}

export const AUTH_OPERATION_DESCRIPTORS: readonly AuthOperationDescriptor[] = [
  { id: "auth.bootstrap", requiresState: ["bootstrap_required"], requiresStepUp: false },
  { id: "auth.signIn", requiresState: ["signed_out", "session_expired"], requiresStepUp: false },
  { id: "auth.signOut", requiresState: ["signed_in", "refresh_required", "step_up_required"], requiresStepUp: false },
  { id: "auth.refresh", requiresState: ["refresh_required"], requiresStepUp: false },
  { id: "auth.stepUp", requiresState: ["step_up_required", "signed_in"], requiresStepUp: false },
  { id: "auth.listSessions", requiresState: ["signed_in"], requiresStepUp: false },
  { id: "auth.revokeSession", requiresState: ["signed_in"], requiresStepUp: false },
  { id: "auth.revokeAllSessions", requiresState: ["signed_in"], requiresStepUp: true },
  // Named auth.addPasskey, not auth.registerPasskey: the latter would collide
  // in name (though not in meaning) with the already-shipped VSIX/Desktop
  // *command* forgewire.auth.registerPasskey (114C.6 Slices 5c/5d) -- a
  // bridge flow that collects a fresh username+password and works with no
  // session at all, no step-up. This operation is the opposite shape: adding
  // a second passkey from *within* an already-signed-in session, which is
  // exactly why it requires signed_in and a fresh step-up.
  { id: "auth.addPasskey", requiresState: ["signed_in"], requiresStepUp: true },
  { id: "auth.removePasskey", requiresState: ["signed_in"], requiresStepUp: true },
  { id: "auth.regenerateRecoveryCodes", requiresState: ["signed_in"], requiresStepUp: true },
  { id: "auth.changePassword", requiresState: ["signed_in"], requiresStepUp: false },
  { id: "auth.recoveryStart", requiresState: ["signed_out"], requiresStepUp: false },
  { id: "auth.recoveryComplete", requiresState: ["recovery_required"], requiresStepUp: false },
];

export function findAuthOperationDescriptor(id: AuthOperationId): AuthOperationDescriptor | undefined {
  return AUTH_OPERATION_DESCRIPTORS.find((descriptor) => descriptor.id === id);
}

/** Client visibility only -- advisory, per the plan's "the hub always enforces." */
export function isAuthOperationOfferedInState(id: AuthOperationId, state: AuthState): boolean {
  const descriptor = findAuthOperationDescriptor(id);
  return descriptor !== undefined && descriptor.requiresState.includes(state);
}

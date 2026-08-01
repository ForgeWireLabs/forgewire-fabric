import type { SessionState } from "./constants.js";

export interface RefreshPolicy {
  readonly foregroundMs: number;
  readonly backgroundMs: number;
  readonly maximumBackoffMs: number;
  readonly backoffMultiplier: number;
}
export interface RefreshState { readonly inFlight: boolean; readonly consecutiveFailures: number; readonly lastStartedAt?: number; readonly lastCompletedAt?: number; }
export type RefreshVisibility = "foreground" | "background";

export const DEFAULT_REFRESH_POLICY: RefreshPolicy = {
  foregroundMs: 10_000,
  backgroundMs: 30_000,
  maximumBackoffMs: 120_000,
  backoffMultiplier: 2,
};

function validateRefreshPolicy(policy: RefreshPolicy): void {
  if (
    !Number.isFinite(policy.foregroundMs) || policy.foregroundMs < 1 ||
    !Number.isFinite(policy.backgroundMs) || policy.backgroundMs < policy.foregroundMs ||
    !Number.isFinite(policy.maximumBackoffMs) || policy.maximumBackoffMs < policy.backgroundMs ||
    !Number.isFinite(policy.backoffMultiplier) || policy.backoffMultiplier < 1
  ) throw new Error("Refresh policy must use positive, ordered, finite intervals and a multiplier of at least one.");
}

export function refreshDelay(policy: RefreshPolicy, failures: number, visibility: RefreshVisibility): number {
  validateRefreshPolicy(policy);
  if (!Number.isInteger(failures) || failures < 0) throw new Error("Refresh failure count must be a non-negative integer.");
  const base = visibility === "foreground" ? policy.foregroundMs : policy.backgroundMs;
  const backedOff = base * policy.backoffMultiplier ** Math.max(0, failures);
  return Math.min(policy.maximumBackoffMs, backedOff);
}

export function isRefreshDue(state: RefreshState, now: number, policy: RefreshPolicy, visibility: RefreshVisibility): boolean {
  if (state.inFlight) return false;
  if (state.lastCompletedAt === undefined) return true;
  return now - state.lastCompletedAt >= refreshDelay(policy, state.consecutiveFailures, visibility);
}

export function beginRefresh(state: RefreshState, now: number): RefreshState {
  if (state.inFlight) return state;
  return { ...state, inFlight: true, lastStartedAt: now };
}

export function completeRefresh(state: RefreshState, succeeded: boolean, now: number): RefreshState {
  return { ...state, inFlight: false, consecutiveFailures: succeeded ? 0 : state.consecutiveFailures + 1, lastCompletedAt: now };
}

export interface SessionNotice { readonly kind: "degraded" | "offline" | "recovered"; readonly message: string; }
export function sessionTransitionNotice(previous: SessionState, next: SessionState): SessionNotice | undefined {
  if (previous === next) return undefined;
  if ((previous === "offline" || previous === "partial" || previous === "stale") && next === "connected") return { kind: "recovered", message: "Live Fabric state recovered." };
  if (next === "offline") return { kind: "offline", message: "Fabric is offline; showing labeled last-good state." };
  if (next === "partial" || next === "stale") return { kind: "degraded", message: "Some Fabric state is unavailable or stale." };
  return undefined;
}

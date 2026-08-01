import type { ResourceFreshness, ResourceState } from "./contracts.js";
import type { SessionState } from "./constants.js";

export type ResourceUpdate<T> =
  | { readonly ok: true; readonly data: T; readonly observedAt: number; readonly receivedAt: number; readonly staleAfterMs: number }
  | { readonly ok: false; readonly error: string; readonly receivedAt: number };

export function mergeLastGoodResource<T>(previous: ResourceState<T> | undefined, update: ResourceUpdate<T>): ResourceState<T> {
  if (update.ok) {
    const freshness: ResourceFreshness = {
      observedAt: update.observedAt,
      receivedAt: update.receivedAt,
      staleAfterMs: update.staleAfterMs,
      source: "live",
    };
    return { data: update.data, freshness };
  }
  if (previous?.data !== undefined && previous.freshness !== undefined) {
    return {
      data: previous.data,
      freshness: { ...previous.freshness, receivedAt: update.receivedAt, source: "last-good" },
      error: update.error,
    };
  }
  return { error: update.error };
}

export interface SessionSignals {
  readonly configured: boolean;
  readonly authorized: boolean;
  readonly compatible: boolean;
  readonly reachable: boolean;
  readonly stale: boolean;
  readonly failedResources: number;
  readonly successfulResources: number;
}

export function deriveSessionState(signals: SessionSignals): SessionState {
  if (!signals.configured) return "misconfigured";
  if (!signals.reachable) return "offline";
  if (!signals.authorized) return "unauthorized";
  if (!signals.compatible) return "incompatible";
  if (signals.failedResources > 0 && signals.successfulResources > 0) return "partial";
  if (signals.stale) return "stale";
  return "connected";
}

export function isResourceStale(freshness: ResourceFreshness | undefined, now: number): boolean {
  return freshness === undefined || now - freshness.observedAt >= freshness.staleAfterMs;
}

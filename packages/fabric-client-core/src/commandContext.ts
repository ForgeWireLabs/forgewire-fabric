import type { CommandId } from "./constants.js";
import type { ResourceFreshness } from "./contracts.js";
import { isResourceStale } from "./session.js";
import {
  commandAvailability,
  findCommandDescriptor,
  type CommandAvailability,
  type CommandContext,
  type DispatcherIdentityState,
} from "./commands.js";

/**
 * Reduce a dispatcher-identity purpose string to the three-state enum
 * {@link CommandContext.identity} expects. Both clients construct their
 * `CommandContext` from a platform-specific identity shape (VS Code's
 * `dispatcherSession`, Desktop's `DispatcherIdentitySummary.purpose`); this is
 * the single reduction they share so "what counts as a Dispatcher identity"
 * cannot drift between them.
 *
 * - absent identity -> `"missing"`
 * - purpose is (case-insensitively) `"Dispatcher"` -> `"dispatcher"`
 * - any other purpose -> `"wrong-purpose"` (fail closed: an identity loaded
 *   for some other role must not be treated as a dispatcher).
 */
export function dispatcherIdentityState(purpose?: string | null): DispatcherIdentityState {
  const normalized = purpose?.trim().toLowerCase();
  if (normalized === undefined || normalized === "") return "missing";
  return normalized === "dispatcher" ? "dispatcher" : "wrong-purpose";
}

/**
 * Reshape a per-resource {@link ResourceFreshness} into the single tri-state
 * {@link CommandContext.freshness} uses. Desktop already tracks freshness
 * per-resource; VS Code builds it per-resource too. For a given command the
 * client picks its target domain's resource freshness and passes it here.
 *
 * - no freshness recorded -> `"missing"`
 * - last-good (retained after a failed refresh) -> `"stale"` (read-only)
 * - live but past its `staleAfterMs` horizon -> `"stale"`
 * - live and within that horizon -> `"live"`
 */
export function resourceFreshnessToState(
  freshness: ResourceFreshness | undefined,
  now: number = Date.now(),
): "missing" | "stale" | "live" {
  if (freshness === undefined) return "missing";
  if (freshness.source === "last-good") return "stale";
  return isResourceStale(freshness, now) ? "stale" : "live";
}

/**
 * The hub's `GET /whoami` payload (see `crates/fabric-hub/src/routes/whoami.rs`),
 * normalized from its wire (snake_case) shape. `authorities` is the
 * authoritative `fabric.*.write` capability set for the active credential --
 * clients trust it rather than deriving capabilities from roles themselves.
 */
export interface WhoamiResult {
  readonly subject: string;
  readonly roles: readonly string[];
  readonly authorities: readonly string[];
  readonly legacyCompat: boolean;
  readonly humanPrincipal: string | null;
}

const stringArray = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

/**
 * Parse a raw `GET /whoami` response defensively. Unknown/malformed fields
 * fail closed (empty roles/authorities, no human principal) rather than
 * throwing -- a hub that answers oddly must degrade to "no capabilities", not
 * crash the client's refresh cycle.
 */
export function parseWhoami(raw: unknown): WhoamiResult {
  const record = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  return {
    subject: typeof record.subject === "string" ? record.subject : "",
    roles: stringArray(record.roles),
    authorities: stringArray(record.authorities),
    legacyCompat: record.legacy_compat === true,
    humanPrincipal: typeof record.human_principal === "string" ? record.human_principal : null,
  };
}

/** The authorities from a `GET /whoami` response as the `ReadonlySet<string>`
 *  {@link CommandContext.authorities} expects. */
export function authoritiesFromWhoami(raw: unknown): ReadonlySet<string> {
  return new Set(parseWhoami(raw).authorities);
}

/**
 * Evaluate a command's live availability by id -- the single entry point both
 * clients call to gate a dispatch or compute a menu-enablement flag, so
 * neither re-implements the descriptor lookup. Throws only for an unknown
 * command id (a programming error), never for a normal disabled result.
 */
export function evaluateCommand(id: CommandId, context: CommandContext): CommandAvailability {
  return commandAvailability(findCommandDescriptor(id), context);
}

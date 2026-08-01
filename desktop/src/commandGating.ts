import {
  dispatcherIdentityState,
  evaluateCommand,
  resourceFreshnessToState,
  type CommandAvailability,
  type CommandDescriptor,
  type CommandId,
  type ResourceFreshness,
  type SelectionKind,
  type SessionState,
  findCommandDescriptor,
} from "@forgewire/fabric-client-core";

/**
 * The live signals the desktop app already tracks, gathered into the shape the
 * shared `commandAvailability()` gate consumes. Desktop is the richer of the
 * two clients here -- it already holds `sessionState`, per-resource
 * `freshness`, the dispatcher identity, and per-kind selections -- so this is a
 * reshape, not new tracking.
 */
export interface DesktopGatingSources {
  readonly sessionState: SessionState;
  readonly features: ReadonlySet<string>;
  readonly authorities: ReadonlySet<string>;
  readonly identityPurpose?: string | null;
  readonly freshness: Record<string, ResourceFreshness | undefined>;
  readonly selections: Partial<Record<SelectionKind, { readonly id: string; readonly status?: string }>>;
  /** 114C.7 Slice 5c: the signed-in human's account roles (empty when no
   *  human session), for {@link CommandDescriptor.requiresHumanRole} gating
   *  -- mirrors VSIX's `commandGating.ts`. Required, not optional: an
   *  omitted field reads the same as "not signed in" to the shared gate
   *  either way, so requiring it here keeps every call site honest about
   *  which state it means. */
  readonly humanRoles: ReadonlySet<string>;
}

/**
 * The snapshot resource whose freshness governs a command. `commandAvailability`
 * only consults freshness for descriptors whose own `freshness` is `live` or
 * `present`, and those all carry a selection kind or a resource-backed domain,
 * so this resolves the correct key for exactly the commands that need it and
 * falls back to `health` (the connection heartbeat) otherwise.
 */
function freshnessKeyFor(descriptor: CommandDescriptor): string {
  switch (descriptor.selectionKind) {
    case "task": return "tasks";
    case "runner": return "runners";
    case "host": return "hosts";
    case "approval": return "approvals";
    case "hub": return "cluster";
    default: break;
  }
  switch (descriptor.domain) {
    case "tasks": return "tasks";
    case "hosts": return "hosts";
    case "hub": return "cluster";
    case "approvals": return "approvals";
    case "cost": return "cost";
    default: return "health";
  }
}

/**
 * Live availability for one command, built from the desktop's current state.
 * The single entry point the app uses both to gate a dispatch (show the reason,
 * do nothing) and to disable/annotate an action control.
 */
export function desktopCommandAvailabilityFor(
  id: CommandId,
  sources: DesktopGatingSources,
  now: number = Date.now(),
): CommandAvailability {
  const descriptor = findCommandDescriptor(id);
  const selected = descriptor.selectionKind === undefined
    ? undefined
    : sources.selections[descriptor.selectionKind];
  return evaluateCommand(id, {
    sessionState: sources.sessionState,
    selection: descriptor.selectionKind === undefined || selected === undefined
      ? undefined
      : { kind: descriptor.selectionKind, id: selected.id, status: selected.status },
    features: sources.features,
    authorities: sources.authorities,
    identity: dispatcherIdentityState(sources.identityPurpose),
    freshness: resourceFreshnessToState(sources.freshness[freshnessKeyFor(descriptor)], now),
    platform: "desktop",
    humanRoles: sources.humanRoles,
  });
}

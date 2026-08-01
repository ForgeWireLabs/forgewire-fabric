import {
  evaluateCommand,
  type CommandAvailability,
  type CommandId,
  type DispatcherIdentityState,
  type SelectionKind,
  type SessionState,
} from "@forgewire/fabric-client-core";

/**
 * The live command-gating signals the extension derives each refresh tick.
 * Unlike Desktop (which tracks freshness per resource), VS Code always reads
 * live from the active hub with no last-good retention, so a single tri-state
 * freshness -- reachable now vs. last-known vs. never -- is the honest model.
 */
export interface VscodeGatingState {
  readonly sessionState: SessionState;
  readonly features: ReadonlySet<string>;
  readonly authorities: ReadonlySet<string>;
  readonly identity: DispatcherIdentityState;
  readonly freshness: "missing" | "stale" | "live";
  /** 114C.7 Slice 4c: the signed-in human's account roles (empty when no
   *  human session), for {@link CommandDescriptor.requiresHumanRole} gating. */
  readonly humanRoles: ReadonlySet<string>;
}

/** A resolved selection for a command, derived from the invoked tree item. */
export interface VscodeSelection {
  readonly kind: SelectionKind;
  readonly id: string;
  readonly status?: string;
}

/**
 * Evaluate a command's live availability from the extension's current gating
 * state and (optionally) the selection the command was invoked on. The single
 * entry point every guarded handler and every `forgewire.can.*` context key
 * goes through, so VS Code and Desktop share one gating decision.
 */
export function vscodeCommandAvailability(
  id: CommandId,
  state: VscodeGatingState,
  selection?: VscodeSelection,
): CommandAvailability {
  return evaluateCommand(id, {
    sessionState: state.sessionState,
    selection,
    features: state.features,
    authorities: state.authorities,
    identity: state.identity,
    freshness: state.freshness,
    platform: "vscode",
    humanRoles: state.humanRoles,
  });
}

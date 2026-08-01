import type { AccountSummary, SessionSummary } from "./authContracts.js";

export type StatusTone = "neutral" | "info" | "success" | "warning" | "danger";
export type StatusIcon =
  | "hub" | "host" | "runner" | "task" | "agent" | "approval" | "cost"
  | "audit" | "secret" | "setting" | "online" | "offline" | "warning"
  | "error" | "empty" | "account";

export interface EmptyState {
  readonly title: string;
  readonly description: string;
  readonly actionId?: string;
}

export interface ResourceFreshness {
  readonly observedAt: number;
  readonly receivedAt: number;
  readonly staleAfterMs: number;
  readonly source: "live" | "last-good";
}

export interface ResourceState<T> {
  readonly data?: T;
  readonly freshness?: ResourceFreshness;
  readonly error?: string;
}

export interface HubDto {
  readonly id: string;
  readonly name: string;
  readonly url: string;
  readonly status: string;
  readonly uptime?: string;
  readonly version?: string;
  readonly protocol?: string;
}

export interface DispatcherDto { readonly id: string; readonly name: string; readonly status?: string; }
export interface HostDto {
  readonly id: string;
  readonly name: string;
  readonly status: string;
  readonly roles?: readonly string[];
  readonly runnerIds?: readonly string[];
  readonly dispatchers?: readonly DispatcherDto[];
}
export interface RunnerDto { readonly id: string; readonly name: string; readonly hostId?: string; readonly status: string; readonly local?: boolean; }
export interface TaskDto {
  readonly id: string;
  readonly title: string;
  readonly kind: "agent" | "command";
  readonly status: string;
  readonly dispatchedAt?: string;
  readonly dispatchedByUser?: string;
  readonly dispatchedByHost?: string;
  readonly dispatchedByAgent?: string;
  readonly dispatcherPubkeyFingerprint?: string;
  readonly claimedByRunner?: string;
  readonly claimedByHost?: string;
  readonly startedAt?: string;
  readonly completedAt?: string;
  readonly wallSeconds?: number;
  readonly runnerCpuSeconds?: number;
  readonly policyDecisions?: readonly Readonly<Record<string, unknown>>[];
  readonly approvalsRequired?: number;
  readonly approvalsReceived?: number;
  readonly exitReason?: string;
}
export interface CapabilityDto { readonly kind: "prompt" | "tool" | "resource" | "skill"; readonly name: string; }
export interface McpServerDto { readonly id: string; readonly name: string; readonly capabilities: readonly CapabilityDto[]; }
export interface AgentDto { readonly id: string; readonly name: string; readonly status: string; readonly servers?: readonly McpServerDto[]; readonly capabilities?: readonly string[]; }
export interface ApprovalDto { readonly id: string; readonly title: string; readonly status: string; readonly envelopeHash?: string; }
export interface CostDto { readonly today: number; readonly week: number; readonly currency: string; readonly budget?: number; }
export interface AuditDto { readonly id: string; readonly kind: string; readonly timestamp: string; readonly verified?: boolean; }
export interface SecretMetadataDto { readonly name: string; readonly configured: boolean; readonly updatedAt?: string; }
export interface SettingDto { readonly id: string; readonly label: string; readonly category: string; readonly valueSummary?: string; }

/**
 * 114C.7 Slice 3: the signed-in human's own account state, already
 * normalized to view-model shape (see `normalizeAccountSummary`/
 * `normalizeSessionSummary` in authContracts.ts) -- unlike every other
 * `FabricSnapshot` field, this one is not populated by the general
 * automation-token snapshot poll: it requires a human session's own access
 * secret as bearer, fetched and merged in separately by whichever caller
 * holds that credential (Slices 4/5). `undefined` (or `me: undefined`)
 * means "not signed in," not "unknown" -- there is no loading/error
 * distinction here because, unlike hub/tasks/etc., a signed-out state is a
 * normal, common, non-error condition.
 */
export interface AccountSnapshotDto {
  readonly me?: AccountSummary;
  readonly sessions?: readonly SessionSummary[];
}

export interface FabricSnapshot {
  readonly hub?: HubDto;
  readonly hosts?: readonly HostDto[];
  readonly runners?: readonly RunnerDto[];
  readonly tasks?: readonly TaskDto[];
  readonly agents?: readonly AgentDto[];
  readonly approvals?: readonly ApprovalDto[];
  readonly cost?: CostDto;
  readonly audit?: readonly AuditDto[];
  readonly secrets?: readonly SecretMetadataDto[];
  readonly settings?: readonly SettingDto[];
  readonly account?: AccountSnapshotDto;
}

export interface SnapshotNormalizationContext {
  readonly hubUrl?: string;
  readonly hubName?: string;
  readonly settings?: readonly SettingDto[];
}

export interface CredentialStore {
  get(profileId: string): Promise<string | undefined>;
  set(profileId: string, credential: string): Promise<void>;
  delete(profileId: string): Promise<void>;
}

/**
 * 114C.3 deliverable: "Add protected session storage adapters for VSIX and
 * Desktop without yet shipping the full account UI." This is the interface
 * only -- VS Code `SecretStorage` and a scoped Tauri native protected-
 * storage command are the real implementations, both outside this package's
 * scope (114C.7). The point of this type existing here, ahead of any
 * concrete implementation, is the same as {@link CredentialStore}'s: a
 * renderer/view-model layer programs against this interface and never
 * touches `SessionSecrets` fields directly, so there is no code path in
 * shared view-model logic that could hold or forward a raw session secret.
 */
export interface SessionSecrets {
  readonly sessionId: string;
  readonly accessSecret: string;
  readonly refreshSecret: string;
  /** 114E proof-of-possession: the session's bound Ed25519 private key (hex),
   *  present only for key-bound sessions. When set, the client signs requests
   *  with it instead of replaying `accessSecret`; when absent the session is
   *  bearer-only (and pre-114E stored sessions deserialize with it undefined). */
  readonly sessionSigningKey?: string;
}
export interface SessionCredentialStore {
  get(profileId: string): Promise<SessionSecrets | undefined>;
  set(profileId: string, secrets: SessionSecrets): Promise<void>;
  delete(profileId: string): Promise<void>;
}

export interface DispatcherIdentity { readonly id: string; readonly purpose: "Dispatcher"; readonly publicKey: string; }
export interface IdentityStore { load(profileId: string): Promise<DispatcherIdentity | undefined>; save(profileId: string, identity: DispatcherIdentity): Promise<void>; }
export interface PreferenceStore { get<T>(key: string): Promise<T | undefined>; set<T>(key: string, value: T): Promise<void>; delete(key: string): Promise<void>; }


import type { ResourceFreshness, SessionState } from "@forgewire/fabric-client-core";

export interface HubConfig {
  hubUrl: string;
  tokenPresent: boolean;
}

export interface HubCandidate {
  url: string;
  label?: string | null;
  priority?: number | null;
}

export interface GuiConfig {
  hub_url: string;
  hub_candidates?: HubCandidate[];
  hub_pin?: string | null;
  refresh_interval_seconds?: number;
}

export interface DispatcherIdentitySummary {
  id: string;
  purpose: string;
  public_key_hex: string;
  path: string;
}

export interface FabricContext {
  hub_url: string;
  hub_source: string;
  token_present: boolean;
  token_path?: string | null;
  token_source?: string | null;
  dispatcher_identity?: DispatcherIdentitySummary | null;
  identity_path?: string | null;
  identity_source?: string | null;
  hub_candidates?: HubDiscoveryCandidate[];
  warnings?: string[];
}

export type DispatchKind = "agent" | "command";
export type DispatchMode = "prompt" | "skill" | "tool";

export interface DispatchDraft {
  title: string;
  kind: DispatchKind;
  dispatch: DispatchMode;
  branch: string;
  baseCommit: string;
  scopeGlobs: string;
  prompt: string;
  tags: string;
  capabilities: string;
  skill: string;
  tool: string;
  command: string;
}

export interface DispatchBrief {
  title: string;
  kind: DispatchKind;
  dispatch: DispatchMode;
  branch: string;
  base_commit: string;
  scope_globs: string[];
  prompt: string;
  required_tags: string[];
  required_capabilities: string[];
  skill?: string;
  tool?: string;
  command?: string[];
}

export interface SignedDispatchResult {
  status: "queued" | "held" | "denied" | "submitted" | "error";
  task_id?: number | null;
  approval_id?: string | null;
  message: string;
  body: unknown;
}

export interface HubDiscoveryCandidate {
  url: string;
  label: string;
  status: string;
  version?: string | null;
  priority: number;
  reachable: boolean;
  error?: string | null;
}

export interface Healthz {
  status?: string;
  protocol_version?: number;
  version?: string;
  package_version?: string;
  uptime_seconds?: number;
  started_at?: number;
  host?: string;
  port?: number;
  backend?: string;
  [key: string]: unknown;
}

export interface RunnerInfo {
  runner_id: string;
  hostname?: string;
  os?: string;
  arch?: string;
  state?: string;
  kinds?: string[];
  tags?: string[];
  scope_prefixes?: string[];
  current_load?: number;
  max_concurrent?: number;
  last_heartbeat?: string;
  drain_requested?: boolean;
  workspace_root?: string | null;
  tenant?: string | null;
  alias?: string | null;
  host_alias?: string | null;
  [key: string]: unknown;
}

export interface McpManifestPrompt {
  name: string;
  description?: string;
  arguments?: Array<{ name: string; required?: boolean; description?: string }>;
}

export interface McpManifestTool {
  name: string;
  description?: string;
  input_schema?: unknown;
}

export interface McpManifestResource {
  uri: string;
  name?: string;
  mime_type?: string;
}

export interface McpManifestServer {
  server_id: string;
  tools?: McpManifestTool[];
  resources?: McpManifestResource[];
  prompts?: McpManifestPrompt[];
}

export interface McpManifest {
  schema_version?: number;
  servers?: McpManifestServer[];
}

export interface AgentInfo {
  runner_id: string;
  agent_type?: string | null;
  hostname?: string | null;
  alias?: string | null;
  state?: string;
  drain_requested?: boolean;
  last_heartbeat?: string | null;
  mcp_manifest?: McpManifest | null;
  mcp_manifest_version?: number;
  kinds?: string[];
  max_concurrent?: number;
  tenant?: string | null;
  workspace_root?: string | null;
  [key: string]: unknown;
}

export interface TaskInfo {
  id?: number;
  task_id?: number;
  title?: string;
  status?: string;
  kind?: string;
  dispatch?: string | null;
  branch?: string | null;
  base_commit?: string | null;
  runner_id?: string | null;
  worker_id?: string | null;
  created_at?: string;
  dispatched_at?: string;
  dispatched_by_user?: string | null;
  dispatched_by_host?: string | null;
  dispatched_by_agent?: string | null;
  dispatcher_pubkey_fingerprint?: string | null;
  claimed_by_runner?: string | null;
  claimed_by_host?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  wall_seconds?: number | null;
  runner_cpu_seconds?: number | null;
  policy_decisions?: Array<Record<string, unknown>>;
  approvals_required?: number;
  approvals_received?: number;
  approval_id?: string | null;
  exit_reason?: string | null;
  priority?: number;
  prompt?: string | null;
  result?: unknown;
  error?: string | null;
  exit_code?: number | null;
  timeout_minutes?: number;
  required_tags?: string[];
  required_capabilities?: string[];
  scope_globs?: string[];
  scope_globs_json?: string;
  [key: string]: unknown;
}

export interface TaskStreamLine {
  seq?: number;
  task_id?: number;
  worker_id?: string | null;
  channel?: string | null;
  line?: string | null;
  message?: string | null;
  created_at?: string | null;
  ts?: string | null;
  [key: string]: unknown;
}

export interface TaskStreamResult {
  lines: TaskStreamLine[];
}

export interface ApprovalInfo {
  approval_id: string;
  status: string;
  task_label?: string;
  branch?: string;
  scope_globs?: string[];
  scope_globs_json?: string;
  created_at?: string;
  resolved_at?: string | null;
  approver?: string | null;
  reason?: string | null;
  prompt?: string | null;
  requested_by?: string | null;
  risk?: string | null;
  [key: string]: unknown;
}

export interface ApprovalDecision {
  approver?: string;
  reason?: string;
}

export interface DesktopUpdateStatus {
  configured: boolean;
  current_version: string;
  available: boolean;
  version?: string | null;
  published_at?: string | null;
  notes?: string | null;
  message: string;
}

export interface AuditEvent {
  id?: number;
  task_id?: number | null;
  kind?: string;
  event_type?: string;
  payload?: unknown;
  hash?: string;
  prev_hash?: string | null;
  created_at?: string;
  ts?: string;
  [key: string]: unknown;
}

export interface TaskAudit {
  events: AuditEvent[];
  verified: boolean;
  error?: string | null;
}

export interface CostBudget {
  today?: string;
  week?: string;
  daily_spend_usd?: number;
  weekly_spend_usd?: number;
  daily_budget_usd?: number;
  weekly_budget_usd?: number;
  daily_pct?: number;
  weekly_pct?: number;
  daily_remaining_usd?: number;
  weekly_remaining_usd?: number;
  weekly_alert?: boolean;
  [key: string]: unknown;
}

export interface ClusterHealth {
  backend?: string;
  rqlite?: { host?: string; port?: number; consistency?: string } | null;
  labels_snapshot?: {
    status?: string | null;
    applied?: number;
    path?: string | null;
    exists?: boolean;
    size_bytes?: number | null;
    mtime?: number | null;
  };
  [key: string]: unknown;
}

export interface HostSummary {
  hostname: string;
  label?: string;
  display_name?: string;
  is_active_hub?: boolean;
  roles?: Record<string, unknown>;
  runners?: RunnerInfo[];
  dispatchers?: unknown[];
  [key: string]: unknown;
}

export interface AuditTail {
  chain_tail?: unknown;
  verified?: boolean;
  [key: string]: unknown;
}

export interface HubSnapshot {
  health: Healthz | null;
  cluster: ClusterHealth | null;
  runners: RunnerInfo[];
  agents: AgentInfo[];
  tasks: TaskInfo[];
  approvals: ApprovalInfo[];
  budget: CostBudget | null;
  hosts: HostSummary[];
  audit: AuditTail | null;
  cost?: Record<string, unknown> | null;
  secrets?: Array<Record<string, unknown>>;
  dispatchers?: Array<Record<string, unknown>>;
  hub_settings?: Record<string, unknown> | null;
  history?: Record<string, unknown> | null;
}

export interface SnapshotResult {
  snapshot: HubSnapshot;
  errors: Record<string, string>;
  restrictions: Record<string, string>;
  freshness: Record<string, ResourceFreshness | undefined>;
  sessionState: SessionState;
  activeHub: string;
  refreshedAtMs: number;
  /** The active credential's `fabric.*.write` authorities from `GET /whoami`
   *  (via the native snapshot). Empty when the hub predates `/whoami` or the
   *  credential is unauthorized -- the UI fails closed. */
  authorities: string[];
}

export interface TokenStorageSummary {
  present: boolean;
  path: string;
  source: string;
}

/**
 * Result of a WebAuthn bridge flow (114C.6 Slice 5d). Deliberately carries no
 * session data: a successful sign-in writes straight into the OS keyring
 * from the Rust backend (see webauthn_bridge.rs), so the webview is told
 * only whether it worked, never given the session secrets themselves.
 */
export interface PasskeyBridgeResult {
  ok: boolean;
  message: string | null;
  credentialId: string | null;
}

export interface CapabilityDetail {
  kind?: string;
  name?: string;
  description?: string | null;
  input_schema?: unknown;
  arguments?: unknown;
  uri?: string;
  server_id?: string;
  agents?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface AuditDayResult {
  day?: string;
  events?: AuditEvent[];
  verified?: boolean;
  verification_error?: string | null;
  [key: string]: unknown;
}

export type FabricEntityKind = "hub" | "host" | "runner";
export type SecretGovernanceAction = "put" | "rotate" | "delete";

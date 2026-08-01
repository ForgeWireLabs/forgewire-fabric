/**
 * Tiny async client for the ForgeWire hub HTTP API.
 *
 * The Python CLI is the canonical client; the extension only reproduces the
 * read-side surface (list runners / tasks, dispatch, stream tail, cancel).
 * We deliberately use Node's built-in fetch (Node 18+) instead of pulling in
 * a runtime dependency so the published .vsix stays small.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as dgram from "dgram";
import * as crypto from "crypto";
import * as vscode from "vscode";
import {
  isTypedAuthErrorCode,
  type AccountSummaryWireDto,
  type SessionSummaryWireDto,
  type TypedAuthErrorCode,
} from "@forgewire/fabric-client-core";

let secretStorageToken = "";

/**
 * Thrown by {@link HubClient.requestAuth} when the hub's response body
 * parses as a known typed auth error. `code` is exactly the wire value from
 * `TYPED_AUTH_ERROR_CODES` -- callers switch on this, matching the plan's own
 * "clients must not infer these states by parsing prose" rule -- `message`
 * is the hub's own human-readable text for that code, safe to show as-is
 * (it comes from the same hand-written `ApiError::account` mapping that
 * already backs every 114C error response, never from user input echoed
 * back).
 */
export class TypedAuthHttpError extends Error {
  constructor(public readonly code: TypedAuthErrorCode, message: string) {
    super(message);
    this.name = "TypedAuthHttpError";
  }
}

/**
 * Turns a non-ok auth-route response into an error, without ever surfacing
 * the raw response body. The hub's error shape (`crates/fabric-hub/src/
 * error.rs`'s `ApiError::into_response`) is always `{error:{code,message,
 * remediation}}` -- if the body doesn't parse that way, or `code` isn't one
 * of the known typed codes, this is exactly the case the boundary exists
 * for: something unexpected happened, and printing it verbatim to the user
 * is the thing being deliberately avoided here.
 */
async function typedAuthErrorFrom(res: Response): Promise<Error> {
  try {
    const body = (await res.json()) as { error?: { code?: unknown; message?: unknown } };
    const code = body?.error?.code;
    if (typeof code === "string" && isTypedAuthErrorCode(code)) {
      const message = typeof body.error?.message === "string" ? body.error.message : code;
      return new TypedAuthHttpError(code, message);
    }
  } catch {
    /* body was not JSON, or not the expected shape -- fall through */
  }
  return new Error("The hub returned an unexpected error. Try again.");
}

// LAN discovery beacon (matches crates/fabric-beacon). Zero dependencies — Node
// has dgram + crypto built in.
const BEACON_MAGIC = "FWBEACON";
const BEACON_VERSION = 1;
const DEFAULT_BEACON_PORT = 48765;

/** sha256(token)[..16] — same cluster fingerprint the hub advertises. */
function beaconTokenHash(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);
}

interface DiscoveredBeaconHub {
  url: string;
  name: string;
  proto: number;
  tokenHash: string;
}

/**
 * Discover ForgeWire hubs on the LAN by broadcasting a query and collecting
 * beacon replies. The hub URL is built from the *source address* of each reply,
 * so it always reflects the hub's current address — no pinned config, immune to
 * DHCP/subnet changes. If `wantTokenHash` is given, only same-cluster hubs are
 * returned.
 */
function discoverBeacons(
  port: number,
  timeoutMs: number,
  wantTokenHash?: string
): Promise<DiscoveredBeaconHub[]> {
  return new Promise((resolve) => {
    const found = new Map<string, DiscoveredBeaconHub>();
    let sock: dgram.Socket;
    try {
      sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
    } catch {
      resolve([]);
      return;
    }
    const done = () => {
      try {
        sock.close();
      } catch {
        /* ignore */
      }
      resolve([...found.values()]);
    };
    const query = Buffer.from(
      JSON.stringify({ magic: BEACON_MAGIC, v: BEACON_VERSION, role: "query" })
    );
    sock.on("error", () => done());
    sock.on("message", (msg, rinfo) => {
      try {
        const b = JSON.parse(msg.toString("utf8"));
        if (b.magic !== BEACON_MAGIC || b.v !== BEACON_VERSION || b.role !== "hub" || !b.port) {
          return;
        }
        if (wantTokenHash && b.token_hash && b.token_hash !== wantTokenHash) {
          return; // different cluster
        }
        const url = `http://${rinfo.address}:${b.port}`;
        if (!found.has(url)) {
          found.set(url, {
            url,
            name: String(b.name ?? ""),
            proto: Number(b.proto ?? 0),
            tokenHash: String(b.token_hash ?? ""),
          });
        }
      } catch {
        /* ignore malformed */
      }
    });
    sock.bind(() => {
      try {
        sock.setBroadcast(true);
        sock.send(query, port, "255.255.255.255");
      } catch {
        /* ignore */
      }
    });
    setTimeout(done, timeoutMs);
  });
}

export interface RunnerInfo {
  runner_id: string;
  hostname: string;
  os: string;
  arch: string;
  state: string;
  tags: string[];
  scope_prefixes: string[];
  current_load: number;
  max_concurrent: number;
  last_heartbeat?: string;
  drain_requested?: boolean;
  workspace_root?: string;
  tenant?: string;
  poll_interval?: number;
  alias?: string;
  host_alias?: string;
  [key: string]: unknown;
}

// ---- M2.8: Fabric agent manifest (mirrors the hub /agents shape) -----------

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
  servers: McpManifestServer[];
}

/** A Fabric runner ('agent' ∈ kinds) as returned by GET /agents. */
export interface AgentInfo {
  runner_id: string;
  agent_type?: string | null;
  hostname?: string;
  alias?: string;
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

/** A runner reference echoed by GET /capabilities/{kind}/{name}. */
export interface CapabilityRunnerRef {
  runner_id: string;
  agent_type?: string | null;
  hostname?: string;
  state?: string;
  drain_requested?: boolean;
}

export interface DispatcherInfo {
  dispatcher_id: string;
  label: string;
  hostname?: string | null;
  metadata: Record<string, unknown>;
  first_seen?: string;
  last_seen?: string;
  [key: string]: unknown;
}

export interface ApprovalInfo {
  approval_id: string;
  status: string;
  envelope_hash?: string;
  task_label?: string;
  branch?: string;
  scope_globs?: string[];
  scope_globs_json?: string;
  decision_json?: string;
  created_at?: string;
  resolved_at?: string | null;
  approver?: string | null;
  reason?: string | null;
  [key: string]: unknown;
}

export interface SecretInfo {
  name: string;
  version?: number;
  created_at?: string;
  last_rotated_at?: string | null;
  [key: string]: unknown;
}

export interface AuditEvent {
  id?: number;
  task_id?: number | null;
  event_type?: string;
  hash?: string;
  prev_hash?: string;
  created_at?: string;
  payload?: unknown;
  [key: string]: unknown;
}

export interface ClusterHealth {
  backend: string;
  rqlite: { host: string; port: number; consistency: string } | null;
  labels_snapshot: {
    status: string | null;
    applied: number;
    path: string | null;
    exists: boolean;
    size_bytes: number | null;
    mtime: number | null;
  };
}

export type HostRoleName = "hub_head" | "control" | "dispatch" | "command_runner" | "agent_runner";

export interface HostRoleSummary {
  enabled: boolean;
  status: string;
  source: string;
  updated_at?: string | null;
  address?: string;
  runner_ids: string[];
  dispatcher_ids: string[];
  metadata: Record<string, unknown>;
}

export interface HostSummary {
  hostname: string;
  label?: string;
  display_name?: string;
  is_active_hub: boolean;
  roles: Record<HostRoleName, HostRoleSummary>;
  runners: RunnerInfo[];
  dispatchers: DispatcherInfo[];
}

export interface LabelsInfo {
  hub_name: string;
  runner_aliases: Record<string, string>;
  host_aliases: Record<string, string>;
}

export interface TaskInfo {
  id: number;
  title: string;
  status: string;
  branch: string;
  base_commit: string;
  prompt: string;
  scope_globs: string[];
  worker_id?: string | null;
  todo_id?: string | null;
  created_at?: string;
  claimed_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  dispatched_at?: string;
  dispatched_by_user?: string | null;
  dispatched_by_host?: string | null;
  dispatched_by_agent?: string | null;
  dispatcher_pubkey_fingerprint?: string | null;
  claimed_by_runner?: string | null;
  claimed_by_host?: string | null;
  wall_seconds?: number | null;
  runner_cpu_seconds?: number | null;
  policy_decisions?: Array<Record<string, unknown>>;
  approvals_required?: number;
  approvals_received?: number;
  approval_id?: string | null;
  exit_reason?: string | null;
  required_tags?: string[];
  required_tools?: string[];
  kind?: "agent" | "command";
  dispatch?: "skill" | "tool" | "prompt";
  result?: { status?: string; log_tail?: string; error?: string | null };
  [key: string]: unknown;
}

export interface DispatchPayload {
  title: string;
  prompt: string;
  scope_globs: string[];
  branch: string;
  base_commit: string;
  todo_id?: string;
  timeout_minutes?: number;
  priority?: number;
  required_tags?: string[];
  required_tools?: string[];
  tenant?: string;
  kind?: "agent" | "command";
  metadata?: Record<string, unknown>;
}

export class HubClient {
  constructor(private readonly baseUrl: string, private readonly token: string) {}

  /** Supply the activation-scoped SecretStorage token without persisting it in settings. */
  static setSecretStorageToken(token: string): void {
    secretStorageToken = token.trim();
  }

  static fromConfig(): HubClient | undefined {
    const cfg = vscode.workspace.getConfiguration("forgewire");
    const baseUrl = (cfg.get<string>("hubUrl") ?? "").trim();
    const token = readToken(cfg);
    if (!baseUrl || !token) {
      return undefined;
    }
    return new HubClient(baseUrl.replace(/\/+$/, ""), token);
  }

  /**
   * Probe each candidate URL in priority order (lowest priority first) and
   * return the first reachable one, plus all probe results for UI display.
   * Candidates are iterated in already-priority-sorted order and the first
   * reachable one wins -- there is no uptime-based tiebreak (114C.7 Slice
   * 6c: corrected this doc comment, which previously claimed one that the
   * code has never implemented).
   *
   * If `forgewire.hubPin` is set, that URL is returned directly without
   * probing -- this is the manual-override path.
   */
  static async probe(): Promise<{
    active: HubClient | undefined;
    activeUrl: string | undefined;
    pinned: boolean;
    probes: Array<{ url: string; label?: string; priority?: number; ok: boolean; uptime?: number; error?: string }>;
  }> {
    const cfg = vscode.workspace.getConfiguration("forgewire");
    const token = readToken(cfg);
    const pin = (cfg.get<string>("hubPin") ?? "").trim();
    if (pin) {
      const c = token ? new HubClient(pin.replace(/\/+$/, ""), token) : undefined;
      let probe = { url: pin, ok: false } as any;
      if (c) {
        try {
          const h = await c.healthz();
          probe = { url: pin, ok: true, uptime: h.uptime_seconds };
        } catch (err) {
          probe = { url: pin, ok: false, error: String(err) };
        }
      }
      return { active: probe.ok ? c : undefined, activeUrl: probe.ok ? pin : undefined, pinned: true, probes: [probe] };
    }
    const candidates = (cfg.get<Array<{ url: string; label?: string; priority?: number }>>("hubCandidates") ?? []).slice();
    // Back-compat: include hubUrl as an implicit highest-priority candidate.
    const legacy = (cfg.get<string>("hubUrl") ?? "").trim();
    if (legacy && !candidates.find((c) => (c.url ?? "").trim() === legacy)) {
      candidates.push({ url: legacy, label: "default", priority: 100 });
    }
    // Discover hubs on the LAN via the UDP beacon and add them as top-priority
    // candidates. The hub address comes from the beacon's source IP, so this is
    // immune to DHCP/subnet changes -- the "correct hub" is found with no config.
    try {
      const wantHash = token ? beaconTokenHash(token) : undefined;
      const beaconPort = cfg.get<number>("beaconPort") ?? DEFAULT_BEACON_PORT;
      const discovered = await discoverBeacons(beaconPort, 1500, wantHash);
      for (const d of discovered) {
        const u = d.url.replace(/\/+$/, "");
        if (!candidates.find((c) => (c.url ?? "").trim().replace(/\/+$/, "") === u)) {
          candidates.push({ url: u, label: d.name ? `discovered (${d.name})` : "discovered", priority: 50 });
        }
      }
    } catch {
      /* discovery is best-effort */
    }

    // Always probe the local hub as a low-priority fallback so the extension
    // discovers a hub running on this machine even when every configured
    // candidate is stale or unreachable. The display follows whatever is
    // actually elected, so a locally-running hub is found automatically.
    const autoPort = cfg.get<number>("autoStartHubPort") ?? 8765;
    const localUrl = `http://127.0.0.1:${autoPort}`;
    if (!candidates.find((c) => (c.url ?? "").trim().replace(/\/+$/, "") === localUrl)) {
      candidates.push({ url: localUrl, label: "local", priority: 500 });
    }
    candidates.sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
    const probes: Array<any> = [];
    let active: HubClient | undefined;
    let activeUrl: string | undefined;
    for (const cand of candidates) {
      const url = (cand.url ?? "").trim().replace(/\/+$/, "");
      if (!url || !token) continue;
      const c = new HubClient(url, token);
      try {
        const h = await c.healthz();
        probes.push({ url, label: cand.label, priority: cand.priority, ok: true, uptime: h.uptime_seconds });
        if (!active) {
          active = c;
          activeUrl = url;
        }
      } catch (err) {
        probes.push({ url, label: cand.label, priority: cand.priority, ok: false, error: String(err) });
      }
    }
    return { active, activeUrl, pinned: false, probes };
  }

  get url(): string {
    return this.baseUrl;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const init: RequestInit = {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
      },
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const res = await fetch(`${this.baseUrl}${path}`, init);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`hub HTTP ${res.status}: ${text || res.statusText}`);
    }
    if (res.status === 204) {
      return undefined as T;
    }
    return (await res.json()) as T;
  }

  // 114C.7: 30 auth/account routes, none of them going through `request()`
  // above. Hub errors for those are hand-written stable typed codes (the
  // plan: "stable typed codes without credential enumeration or
  // secret-bearing debug strings"), but `request()`'s catch-all path throws
  // the *raw response body verbatim* as the error message -- fine for
  // existing routes with hand-written safe JSON bodies, but a real leak path
  // the moment any hub-side bug (a panic message, a validation error
  // echoing partial input) puts something unintended in that body. This
  // helper is narrower on purpose: it recognizes only `{error:{code,
  // message}}` matching a known TypedAuthErrorCode and rejects with that;
  // anything else -- a body that fails to parse, a code not in the known
  // set -- becomes a fixed generic string, never the raw body. Scoped to
  // auth routes only; `request()` above is unchanged for everything else.
  private async requestAuth<T>(
    method: string,
    path: string,
    body?: unknown,
    bearer?: string,
    extraHeaders?: Record<string, string>
  ): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json", ...extraHeaders };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const res = await fetch(`${this.baseUrl}${path}`, init);
    if (!res.ok) {
      throw await typedAuthErrorFrom(res);
    }
    if (res.status === 204) {
      return undefined as T;
    }
    return (await res.json()) as T;
  }

  async healthz(): Promise<{ status: string; protocol_version: number; version: string; uptime_seconds?: number; started_at?: number; host?: string; port?: number }> {
    return this.request("GET", "/healthz");
  }

  /** `GET /whoami`: the installed credential's subject, roles, and the
   *  `fabric.*.write` capability set the operator UI gates on. Authoritative
   *  source for {@link CommandContext.authorities}; see
   *  `crates/fabric-hub/src/routes/whoami.rs`. Uses the installed hub token. */
  async whoami(): Promise<{ subject: string; roles: string[]; authorities: string[]; legacy_compat: boolean; human_principal: string | null }> {
    return this.request("GET", "/whoami");
  }

  /** `GET /auth/bootstrap/status`: true while the realm has no administrator
   *  yet. Public route -- no bearer sent, matching the hub's own contract
   *  (there is no credential to send before the first admin exists). */
  async authBootstrapStatus(): Promise<{ bootstrap_open: boolean }> {
    return this.requestAuth("GET", "/auth/bootstrap/status");
  }

  // ---- 114C.7 Slice 2: the remaining 23 directly-wireable auth/account -----
  // routes (Slice 1 proved the shape on bootstrap/status). The other 6 of
  // the 30 total routes -- register/login passkey options+verify and
  // step-up options+verify -- are deliberately NOT wired here: they carry a
  // live WebAuthn ceremony (`navigator.credentials`), which only a browser
  // context has access to. That ceremony is already fully handled end to
  // end by the hub-served bridge page (114C.6 Slice 5b) driven via
  // `runWebauthnBridgeFlow` below -- the bridge page itself calls those 6
  // routes directly over fetch from the browser, never through this class.
  // Adding pass-through wrappers here for routes nothing in this extension
  // can ever legitimately call would be dead code, not transport shape.
  //
  // Every authenticated method below takes an explicit `accessSecret`
  // parameter rather than using `this.token`: `this.token` is the
  // automation/dispatcher hub token this class was constructed with, a
  // structurally different credential from a human session's access secret
  // (returned by login/passkey-login, persisted by the caller in platform
  // secure storage per the plan's "secret-bearing login/refresh results
  // terminate in the platform credential adapter" rule). The hub accepts
  // both as `Authorization: Bearer <value>` and resolves human sessions
  // first (`resolve_human_session` in `crates/fabric-hub/src/auth.rs`), so
  // passing a session's access secret here is correct and is the only way
  // any `/accounts/*` admin route (gated on the `admin` role, which a role
  // token can never carry) is reachable at all.

  /** `POST /auth/bootstrap`: create the realm's first administrator. Public
   *  route, gated on source address / an optional one-time secret rather
   *  than a bearer -- see `bootstrap_source_allowed` in `authn.rs`.
   *  `bootstrapSecret` is sent as `x-forgewire-bootstrap-secret` only when
   *  the hub is configured to require one. */
  async authBootstrap(
    username: string,
    displayName: string,
    password: string,
    bootstrapSecret?: string
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      "/auth/bootstrap",
      { username, display_name: displayName, password },
      undefined,
      bootstrapSecret ? { "x-forgewire-bootstrap-secret": bootstrapSecret } : undefined
    );
  }

  /** `POST /auth/login`: username+password sign-in. Public route -- the
   *  returned `access_secret`/`refresh_secret` are the credential the
   *  caller must then persist in platform secure storage, never in this
   *  package's own state. */
  async authLogin(
    username: string,
    password: string,
    clientKind?: string,
    clientLabel?: string
  ): Promise<{
    session_id: string; account_id: string; assurance_level: string;
    access_secret: string; refresh_secret: string;
    idle_expires_at: string; absolute_expires_at: string;
  }> {
    return this.requestAuth("POST", "/auth/login", {
      username, password, client_kind: clientKind, client_label: clientLabel,
    });
  }

  /** `POST /auth/refresh`: rotate a session's refresh secret. Public route
   *  (the refresh secret itself is the credential). */
  async authRefresh(
    sessionId: string,
    refreshSecret: string
  ): Promise<{ session_id: string; refresh_secret: string; idle_expires_at: string; absolute_expires_at: string }> {
    return this.requestAuth("POST", "/auth/refresh", { session_id: sessionId, refresh_secret: refreshSecret });
  }

  /** `POST /auth/logout`: revoke one session. Self-service (any signed-in
   *  human may revoke their own session; an admin may revoke another's --
   *  the handler enforces ownership, not this method). */
  async authLogout(accessSecret: string, sessionId: string): Promise<{ session_id: string; revoked: boolean }> {
    return this.requestAuth("POST", "/auth/logout", { session_id: sessionId }, accessSecret);
  }

  /** `POST /auth/logout-all`: revoke every session for the caller's own
   *  account. */
  async authLogoutAll(accessSecret: string): Promise<{ account_id: string; revoked_count: number }> {
    return this.requestAuth("POST", "/auth/logout-all", undefined, accessSecret);
  }

  /** `GET /auth/me`: the caller's own account summary. */
  async authMe(accessSecret: string): Promise<AccountSummaryWireDto> {
    return this.requestAuth("GET", "/auth/me", undefined, accessSecret);
  }

  /** `DELETE /auth/passkeys/{id}`: remove one of the caller's own passkeys.
   *  Registering a passkey is not wired here -- see the ceremony-routes
   *  note above; use the existing `forgewire.auth.registerPasskey` bridge
   *  command for that. */
  async authRemovePasskey(
    accessSecret: string,
    credentialId: string
  ): Promise<{ credential_id: string; revoked: boolean }> {
    return this.requestAuth("DELETE", `/auth/passkeys/${encodeURIComponent(credentialId)}`, undefined, accessSecret);
  }

  /** `GET /auth-policy`: realm id, whether bootstrap is still open, and the
   *  full role vocabulary. NOT public -- `required_roles` in
   *  `fabric-hub/src/auth.rs` gates it on `observer`/`reviewer` like any
   *  other authenticated route. (Discovered live 2026-07-22: this method
   *  previously called `requestAuth` with no bearer at all, so it always
   *  401'd; every caller's "does this hub advertise human_accounts" probe
   *  silently failed regardless of hub support.) Uses the installed
   *  automation token via `request`, same as {@link healthz}/{@link whoami}
   *  -- any credential holding at least `observer` satisfies it. */
  async authPolicy(): Promise<{ realm_id: string; bootstrap_open: boolean; roles: string[] }> {
    return this.request("GET", "/auth-policy");
  }

  /** `GET /auth/sessions`: the caller's own sessions, or (admin only)
   *  another account's when `accountId` is supplied. */
  async listAuthSessions(accessSecret: string, accountId?: string): Promise<{ sessions: SessionSummaryWireDto[] }> {
    const query = accountId ? `?account_id=${encodeURIComponent(accountId)}` : "";
    return this.requestAuth("GET", `/auth/sessions${query}`, undefined, accessSecret);
  }

  /** `DELETE /auth/sessions/{id}`: revoke a session by id (self-service or
   *  admin -- ownership enforced handler-side). */
  async revokeAuthSession(accessSecret: string, sessionId: string): Promise<{ session_id: string; revoked: boolean }> {
    return this.requestAuth("DELETE", `/auth/sessions/${encodeURIComponent(sessionId)}`, undefined, accessSecret);
  }

  // ---- Step-up (114C.7 Slice 4c-3). The two authenticated ends of the
  // in-place step-up ceremony; the client calls both itself (it holds the
  // session bearer) and only relays the WebAuthn `credentials.get` through
  // the hub-served bridge page. `public_key` is the WebAuthn request options
  // the bridge page runs the authenticator on; `credential` is the assertion
  // it returns. On verify the hub elevates the session to aal2 in place and
  // returns a freshly rotated `access_secret` the caller must persist. ------

  /** `POST /auth/step-up/options`: start a step-up ceremony for the caller's
   *  current session. No body; returns the WebAuthn request challenge. */
  async stepUpOptions(accessSecret: string): Promise<{ challenge_id: string; options_token: string; public_key: unknown }> {
    return this.requestAuth("POST", "/auth/step-up/options", {}, accessSecret);
  }

  /** `POST /auth/step-up/verify`: complete step-up with the relayed
   *  assertion. Returns the elevated session's new (rotated) access secret. */
  async stepUpVerify(
    accessSecret: string,
    challengeId: string,
    optionsToken: string,
    credential: unknown
  ): Promise<{ session_id: string; assurance_level: string; access_secret: string; stepped_up_at?: string }> {
    return this.requestAuth(
      "POST",
      "/auth/step-up/verify",
      { challenge_id: challengeId, options_token: optionsToken, credential },
      accessSecret
    );
  }

  // ---- Account administration (all `admin`-role-gated; `accessSecret` must
  // be an admin's own human-session access secret) --------------------------

  /** `GET /accounts`: paginated account list. Readable by `admin` or
   *  `reviewer`. */
  async listAccounts(
    accessSecret: string,
    limit = 200,
    offset = 0
  ): Promise<{ accounts: AccountSummaryWireDto[] }> {
    return this.requestAuth("GET", `/accounts?limit=${limit}&offset=${offset}`, undefined, accessSecret);
  }

  /** `POST /accounts`: create a new account with an initial password and
   *  role. `admin` only. */
  async createAccount(
    accessSecret: string,
    username: string,
    displayName: string,
    password: string,
    role: string
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      "/accounts",
      { username, display_name: displayName, password, role },
      accessSecret
    );
  }

  /** `GET /accounts/{id}`. Readable by `admin` or `reviewer`. */
  async getAccount(accessSecret: string, accountId: string): Promise<AccountSummaryWireDto> {
    return this.requestAuth("GET", `/accounts/${encodeURIComponent(accountId)}`, undefined, accessSecret);
  }

  /** `PATCH /accounts/{id}`: the narrow status-transition route -- unlock
   *  (`locked` -> `active`) or admin-forced recovery toggling, per
   *  `transition_allowed` in `accounts.rs`. Not for `active` <-> `disabled`
   *  (use `disableAccount`/`enableAccount`). `expectedRevision` must be the
   *  account's current `revision` (from a prior `getAccount`/`listAccounts`
   *  call) -- the route is a compare-and-set. */
  async updateAccountStatus(
    accessSecret: string,
    accountId: string,
    status: "active" | "locked" | "recovery_required",
    expectedRevision: number
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "PATCH",
      `/accounts/${encodeURIComponent(accountId)}`,
      { status, expected_revision: expectedRevision },
      accessSecret
    );
  }

  /** `POST /accounts/{id}/membership`: grant a role. `admin` only. */
  async grantMembership(accessSecret: string, accountId: string, role: string): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/membership`,
      { role },
      accessSecret
    );
  }

  /** `DELETE /accounts/{id}/membership/{role}`: revoke a role, protecting
   *  the realm's last enabled administrator. `admin` only. */
  async revokeMembership(accessSecret: string, accountId: string, role: string): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "DELETE",
      `/accounts/${encodeURIComponent(accountId)}/membership/${encodeURIComponent(role)}`,
      undefined,
      accessSecret
    );
  }

  /** `POST /accounts/{id}/disable`: protects the last enabled admin.
   *  `expectedRevision` is a compare-and-set token, see `updateAccountStatus`. */
  async disableAccount(
    accessSecret: string,
    accountId: string,
    expectedRevision: number
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/disable`,
      { expected_revision: expectedRevision },
      accessSecret
    );
  }

  /** `POST /accounts/{id}/enable`: only valid from `disabled`. */
  async enableAccount(
    accessSecret: string,
    accountId: string,
    expectedRevision: number
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/enable`,
      { expected_revision: expectedRevision },
      accessSecret
    );
  }

  /** `POST /accounts/{id}/recovery-codes`: generates and returns plaintext
   *  recovery codes exactly once -- caller must display and discard, never
   *  cache or log them. `admin` only. */
  async generateRecoveryCodes(
    accessSecret: string,
    accountId: string,
    count = 5
  ): Promise<{ account_id: string; codes: string[] }> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/recovery-codes`,
      { count },
      accessSecret
    );
  }

  /** `POST /accounts/{id}/recovery/complete`: redeem a recovery code and
   *  set a new password. Same OBSERVE role gate as the other self-service
   *  `/auth/*` routes (see `required_roles` in `auth.rs`) -- but note the
   *  account is typically `recovery_required`, not necessarily holding a
   *  normal session; this call still requires *some* authenticated bearer
   *  today, a known constraint on the pure-recovery flow this slice does
   *  not change. */
  async completeRecovery(
    accessSecret: string,
    accountId: string,
    code: string,
    newPassword: string
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/recovery/complete`,
      { code, new_password: newPassword },
      accessSecret
    );
  }

  /** `POST /accounts/{id}/delete`: step one of two-step deletion -- marks
   *  `deletion_pending`, revokes sessions, protects the last admin. `admin`
   *  only. */
  async initiateAccountDeletion(
    accessSecret: string,
    accountId: string,
    expectedRevision: number
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/delete`,
      { expected_revision: expectedRevision },
      accessSecret
    );
  }

  /** `POST /accounts/{id}/tombstone`: step two, irreversible. Requires the
   *  account already be `deletion_pending`. `admin` only. */
  async completeAccountDeletion(
    accessSecret: string,
    accountId: string,
    expectedRevision: number
  ): Promise<AccountSummaryWireDto> {
    return this.requestAuth(
      "POST",
      `/accounts/${encodeURIComponent(accountId)}/tombstone`,
      { expected_revision: expectedRevision },
      accessSecret
    );
  }

  /** `GET /accounts/{id}/security-history`: bounded recent login attempts
   *  and sessions. Readable by `admin` or `reviewer`. */
  async accountSecurityHistory(
    accessSecret: string,
    accountId: string,
    limit = 50
  ): Promise<{
    account_id: string;
    login_attempts: Array<{ attempted_at: string; successful: boolean }>;
    sessions: SessionSummaryWireDto[];
  }> {
    return this.requestAuth(
      "GET",
      `/accounts/${encodeURIComponent(accountId)}/security-history?limit=${limit}`,
      undefined,
      accessSecret
    );
  }

  async getLabels(): Promise<LabelsInfo> {
    try {
      return await this.request<LabelsInfo>("GET", "/labels");
    } catch {
      return { hub_name: "", runner_aliases: {}, host_aliases: {} };
    }
  }

  async setHubName(name: string, updatedBy?: string): Promise<void> {
    await this.request("PUT", "/labels/hub", { name, updated_by: updatedBy ?? "" });
  }

  async setRunnerAlias(runnerId: string, alias: string, updatedBy?: string): Promise<void> {
    await this.request("PUT", `/labels/runners/${encodeURIComponent(runnerId)}`, {
      alias,
      updated_by: updatedBy ?? "",
    });
  }

  async setHostAlias(hostname: string, alias: string, updatedBy?: string): Promise<void> {
    await this.request("PUT", `/labels/hosts/${encodeURIComponent(hostname)}`, {
      alias,
      updated_by: updatedBy ?? "",
    });
  }

  async drainRunner(runnerId: string): Promise<RunnerInfo> {
    return this.request<RunnerInfo>("POST", `/runners/${encodeURIComponent(runnerId)}/drain-by-dispatcher`, {});
  }

  async undrainRunner(runnerId: string): Promise<RunnerInfo> {
    return this.request<RunnerInfo>("POST", `/runners/${encodeURIComponent(runnerId)}/undrain-by-dispatcher`, {});
  }

  async listRunners(): Promise<RunnerInfo[]> {
    const j = await this.request<{ runners: RunnerInfo[] }>("GET", "/runners");
    return j.runners ?? [];
  }

  async listDispatchers(): Promise<DispatcherInfo[]> {
    const j = await this.request<{ dispatchers: DispatcherInfo[] }>("GET", "/dispatchers");
    return j.dispatchers ?? [];
  }

  // ---- M2.8: Fabric agents + capability index --------------------------------

  /** GET /agents — every runner with 'agent' in kinds, plus its mcp_manifest. */
  async listAgents(): Promise<AgentInfo[]> {
    const j = await this.request<{ agents: AgentInfo[] }>("GET", "/agents");
    return j.agents ?? [];
  }

  /**
   * GET /capabilities/{kind}/{name} — runners advertising the given
   * tool/resource/prompt. Used to preview where a skill/tool would route.
   */
  async queryCapability(
    kind: "tool" | "resource" | "prompt",
    name: string
  ): Promise<CapabilityRunnerRef[]> {
    const j = await this.request<{ runners: CapabilityRunnerRef[] }>(
      "GET",
      `/capabilities/${encodeURIComponent(kind)}/${encodeURIComponent(name)}`
    );
    return j.runners ?? [];
  }

  // ---- M2.5.2: cost ledger --------------------------------------------------

  async getCostSummary(sinceDays = 7): Promise<Record<string, unknown>> {
    return this.request("GET", `/cost/summary?since_days=${sinceDays}`);
  }

  async getCostBudget(): Promise<{
    today: string; week: string;
    daily_spend_usd: number; weekly_spend_usd: number;
    daily_budget_usd?: number; weekly_budget_usd?: number;
    daily_pct?: number; weekly_pct?: number;
    daily_remaining_usd?: number; weekly_remaining_usd?: number;
    weekly_alert?: boolean;
  }> {
    return this.request("GET", "/cost/budget");
  }

  // ---- approvals ------------------------------------------------------------

  async listApprovals(status?: string, limit = 200): Promise<ApprovalInfo[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (status) {
      params.set("status", status);
    }
    const j = await this.request<{ approvals: ApprovalInfo[] }>(
      "GET",
      `/approvals?${params.toString()}`
    );
    return j.approvals ?? [];
  }

  async getApproval(id: string): Promise<ApprovalInfo> {
    return this.request<ApprovalInfo>("GET", `/approvals/${encodeURIComponent(id)}`);
  }

  async approveApproval(id: string, approver: string, reason?: string): Promise<void> {
    await this.request("POST", `/approvals/${encodeURIComponent(id)}/approve`, {
      approver,
      reason: reason ?? "",
    });
  }

  async denyApproval(id: string, approver: string, reason?: string): Promise<void> {
    await this.request("POST", `/approvals/${encodeURIComponent(id)}/deny`, {
      approver,
      reason: reason ?? "",
    });
  }

  async listSecrets(): Promise<SecretInfo[]> {
    const j = await this.request<{ secrets: SecretInfo[] }>("GET", "/secrets");
    return j.secrets ?? [];
  }

  async auditTail(): Promise<{ chain_tail: unknown }> {
    return this.request("GET", "/audit/tail");
  }

  async getSettings(): Promise<Record<string, unknown>> {
    return this.request("GET", "/settings");
  }

  async getHistoryStatus(): Promise<Record<string, unknown>> {
    return this.request("GET", "/history/status");
  }

  async auditDay(day: string): Promise<{ day: string; events: AuditEvent[]; verified: boolean; error: string | null }> {
    return this.request("GET", `/audit/day/${encodeURIComponent(day)}`);
  }

  async clusterHealth(): Promise<ClusterHealth> {
    return this.request<ClusterHealth>("GET", "/cluster/health");
  }

  async listHosts(): Promise<HostSummary[]> {
    const j = await this.request<{ hosts: HostSummary[] }>("GET", "/hosts");
    return j.hosts ?? [];
  }

  async listTasks(limit = 50, status?: string): Promise<TaskInfo[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (status) {
      params.set("status", status);
    }
    const j = await this.request<{ tasks: TaskInfo[] }>("GET", `/tasks?${params.toString()}`);
    return j.tasks ?? [];
  }

  async getTask(id: number): Promise<TaskInfo> {
    return this.request<TaskInfo>("GET", `/tasks/${id}`);
  }

  /**
   * Unsigned dispatch — accepted by Python hub (when require_signed_dispatch=false)
   * but rejected 426 by the Rust hub. Kept for backward-compat; callers should
   * prefer `dispatchSigned` when a dispatcher session is available.
   */
  async dispatch(payload: DispatchPayload): Promise<TaskInfo> {
    return this.request<TaskInfo>("POST", "/tasks", payload);
  }

  /**
   * Signed dispatch via POST /tasks/v2. Requires a pre-registered dispatcher
   * identity. Works on both the Python and Rust hubs (protocol v3+).
   */
  async dispatchSigned(
    payload: DispatchPayload,
    session: DispatcherSession
  ): Promise<TaskInfo> {
    const ts = Math.floor(Date.now() / 1000);
    const nonce = randomHex(16);
    const signed: Record<string, unknown> = {
      op: "dispatch",
      dispatcher_id: session.dispatcherId,
      title: payload.title,
      prompt: payload.prompt,
      scope_globs: payload.scope_globs,
      base_commit: payload.base_commit,
      branch: payload.branch,
      todo_id: payload.todo_id ?? null,
      timeout_minutes: payload.timeout_minutes ?? 60,
      priority: payload.priority ?? 100,
      metadata: payload.metadata ?? {},
      required_tools: payload.required_tools ?? null,
      required_tags: payload.required_tags ?? null,
      required_capabilities: null,
      secrets_needed: null,
      network_egress: null,
      tenant: null,
      workspace_root: null,
      require_base_commit: false,
      kind: payload.kind ?? "agent",
      max_cost_usd: null,
      timestamp: ts,
      nonce,
    };
    const signature = await session.sign(signed);
    // M2.8.9: kind is mandatory on dispatch (missing -> 400). The signed
    // envelope above already pins it; the POST body must carry the same value.
    return this.request<TaskInfo>("POST", "/tasks/v2", {
      ...payload,
      kind: payload.kind ?? "agent",
      dispatcher_id: session.dispatcherId,
      timestamp: ts,
      nonce,
      signature,
    });
  }

  async cancel(id: number): Promise<void> {
    await this.request("POST", `/tasks/${id}/cancel`, {});
  }

  /**
   * Stream task output, yielding `{event, data}` events until the task reaches
   * a terminal state or the signal fires.
   *
   * Strategy: try the Python-hub SSE endpoint (`/tasks/{id}/events`) first.
   * If the hub returns 404 / 405 (Rust hub only has the polling endpoint),
   * fall back to polling `GET /tasks/{id}/stream` every ~1.5 s and emitting
   * `stream_line` events instead of the raw SSE `progress` events.
   *
   * Callers that render output should handle both `progress` and `stream_line`
   * event types.
   */
  async *streamEvents(
    id: number,
    signal: AbortSignal
  ): AsyncGenerator<{ event: string; data: string }> {
    // Attempt SSE (Python hub, or future Rust hub with the endpoint added).
    let res: Response | undefined;
    try {
      res = await fetch(`${this.baseUrl}/tasks/${id}/events`, {
        headers: { Authorization: `Bearer ${this.token}`, Accept: "text/event-stream" },
        signal,
      });
    } catch {
      // Network error before even getting a response — fall through to polling.
    }

    if (res && res.ok && res.body) {
      // SSE path (Python hub).
      yield* this._streamSse(res);
      return;
    }

    if (res && res.status !== 404 && res.status !== 405) {
      // Unexpected error (not "endpoint doesn't exist") — surface it.
      throw new Error(`stream HTTP ${res.status}`);
    }

    // Polling fallback (Rust hub).
    yield* this._pollStream(id, signal);
  }

  /** Parse a live SSE response body, yielding `{event, data}` tuples. */
  private async *_streamSse(
    res: Response
  ): AsyncGenerator<{ event: string; data: string }> {
    const reader = res.body!.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let event = "message";
    let data: string[] = [];
    while (true) {
      const { value, done } = await reader.read();
      if (done) { return; }
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, idx).replace(/\r$/, "");
        buffer = buffer.slice(idx + 1);
        if (line === "") {
          if (data.length > 0) {
            yield { event, data: data.join("\n") };
          }
          event = "message";
          data = [];
        } else if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          data.push(line.slice(5).replace(/^\s/, ""));
        }
      }
    }
  }

  /**
   * Polling fallback for hubs that expose `GET /tasks/{id}/stream` (JSON) but
   * not an SSE endpoint. Polls every ~1.5 s, emitting `stream_line` events for
   * each buffered output line and a `task` event on every status poll so the
   * caller can detect terminal state.
   */
  private async *_pollStream(
    id: number,
    signal: AbortSignal
  ): AsyncGenerator<{ event: string; data: string }> {
    const TERMINAL = new Set(["done", "failed", "cancelled", "timed_out"]);
    let seq = 0;
    let lastStatus = "";

    while (!signal.aborted) {
      // Fetch new stream lines since last seen seq.
      try {
        const r = await this.request<{
          lines: Array<{ seq: number; channel?: string; line: string; worker_id?: string }>
        }>("GET", `/tasks/${id}/stream?after_seq=${seq}&limit=100`);
        for (const ln of r.lines ?? []) {
          if (ln.seq > seq) { seq = ln.seq; }
          yield { event: "stream_line", data: JSON.stringify(ln) };
        }
      } catch {
        // Network blip — keep trying until signal fires.
      }

      // Poll task row for status changes.
      try {
        const task = await this.request<TaskInfo>("GET", `/tasks/${id}`);
        if (task.status !== lastStatus) {
          lastStatus = task.status;
          yield { event: "task", data: JSON.stringify(task) };
          if (TERMINAL.has(task.status)) { return; }
        }
      } catch {
        return;
      }

      if (signal.aborted) { return; }
      // 1.5 s poll interval — fast enough to feel live without hammering the hub.
      await sleep(1500);
    }
  }
}

// ---------------------------------------------------------------------------
// Dispatcher identity + signed dispatch
// ---------------------------------------------------------------------------

/**
 * Lightweight dispatcher identity for the VS Code extension.
 *
 * Uses the Web Crypto API (available in VS Code's Node 18+ host) to generate
 * an ed25519 key pair. The key pair is persisted to SecretStorage so it
 * survives VS Code restarts without re-registration.
 *
 * The dispatcher registers with the hub on first use and re-registers when
 * the hub is unreachable on activation (hub restart / reconnect).
 */
export class DispatcherSession {
  private constructor(
    public readonly dispatcherId: string,
    private readonly privateKey: CryptoKey,
    public readonly publicKeyHex: string
  ) {}

  /** Sign the canonical JSON of `envelope` and return the hex signature. */
  async sign(envelope: Record<string, unknown>): Promise<string> {
    const canonical = canonicalJson(envelope);
    const buf = await globalThis.crypto.subtle.sign(
      "Ed25519",
      this.privateKey,
      new TextEncoder().encode(canonical)
    );
    return hexEncode(new Uint8Array(buf));
  }

  /**
   * Load an existing session from SecretStorage or generate a new one.
   * Returns `undefined` if Web Crypto Ed25519 is not available (old Node).
   */
  static async loadOrCreate(
    secrets: vscode.SecretStorage
  ): Promise<DispatcherSession | undefined> {
    const KEY = "forgewire.dispatcherIdentity";
    try {
      const stored = await secrets.get(KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as {
          id: string;
          publicKeyHex: string;
          privateKeyJwk: JsonWebKey;
        };
        const privateKey = await globalThis.crypto.subtle.importKey(
          "jwk",
          parsed.privateKeyJwk,
          "Ed25519",
          false,
          ["sign"]
        );
        return new DispatcherSession(parsed.id, privateKey, parsed.publicKeyHex);
      }
    } catch {
      // Corrupted storage — generate fresh.
    }

    // Generate a new key pair.
    let keyPair: CryptoKeyPair;
    try {
      keyPair = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign"]);
    } catch {
      return undefined; // Ed25519 not supported (Node < 17).
    }

    const pubRaw = new Uint8Array(
      await globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey)
    );
    const publicKeyHex = hexEncode(pubRaw);
    const privateKeyJwk = await globalThis.crypto.subtle.exportKey("jwk", keyPair.privateKey);
    const id = `vscode-dispatcher-${randomHex(8)}`;

    try {
      await secrets.store(
        KEY,
        JSON.stringify({ id, publicKeyHex, privateKeyJwk })
      );
    } catch {
      // SecretStorage failure is non-fatal; session still works for this run.
    }

    return new DispatcherSession(id, keyPair.privateKey, publicKeyHex);
  }

  /**
   * Register this dispatcher with the hub. Safe to call on every connect; the
   * hub upserts by `dispatcher_id` so re-registration is idempotent.
   * Returns `true` if registration succeeded, `false` otherwise.
   */
  async register(client: HubClient, hostname: string): Promise<boolean> {
    const ts = Math.floor(Date.now() / 1000);
    const nonce = randomHex(16);
    const envelope: Record<string, unknown> = {
      op: "register-dispatcher",
      dispatcher_id: this.dispatcherId,
      public_key: this.publicKeyHex,
      timestamp: ts,
      nonce,
    };
    const signature = await this.sign(envelope);
    try {
      await client["request"](
        "POST",
        "/dispatchers/register",
        {
          dispatcher_id: this.dispatcherId,
          public_key: this.publicKeyHex,
          label: `vscode@${hostname}`,
          hostname,
          metadata: { source: "vscode-extension" },
          timestamp: ts,
          nonce,
          signature,
        }
      );
      return true;
    } catch {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return hexEncode(buf);
}

function hexEncode(buf: Uint8Array): string {
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Produce a canonical JSON string: object keys sorted, compact separators.
 * Matches Python `json.dumps(obj, sort_keys=True, separators=(",",":"))`.
 */
function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) { return "null"; }
  if (typeof value === "boolean") { return value ? "true" : "false"; }
  if (typeof value === "number") { return JSON.stringify(value); }
  if (typeof value === "string") { return JSON.stringify(value); }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object") {
    const sorted = Object.keys(value as Record<string, unknown>).sort();
    const parts = sorted.map(
      (k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`
    );
    return "{" + parts.join(",") + "}";
  }
  return JSON.stringify(value);
}

function readToken(cfg: vscode.WorkspaceConfiguration): string {
  if (secretStorageToken) {
    return secretStorageToken;
  }
  const configured = (cfg.get<string>("hubToken") ?? "").trim();
  if (configured) {
    return configured;
  }

  const tokenFile = resolveTokenFile((cfg.get<string>("hubTokenFile") ?? "").trim());
  if (!tokenFile) {
    return "";
  }
  try {
    return fs.readFileSync(tokenFile, "utf8").trim();
  } catch {
    return "";
  }
}

function resolveTokenFile(configured: string): string | undefined {
  const candidates = [
    configured,
    process.env.FORGEWIRE_HUB_TOKEN_FILE ?? "",
    path.join(os.homedir(), ".forgewire", "hub.token"),
  ];
  for (const candidate of candidates) {
    const resolved = expandHome(candidate.trim());
    if (resolved && fs.existsSync(resolved)) {
      return resolved;
    }
  }
  return undefined;
}

function expandHome(value: string): string {
  if (!value) {
    return "";
  }
  if (value === "~") {
    return os.homedir();
  }
  if (value.startsWith(`~${path.sep}`) || value.startsWith("~/") || value.startsWith("~\\")) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}


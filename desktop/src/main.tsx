import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  BadgeDollarSign,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  CircleDollarSign,
  Clock3,
  Command,
  Cpu,
  Database,
  Gauge,
  FileClock,
  GitBranch,
  HardDrive,
  History,
  KeyRound,
  LayoutDashboard,
  ListTree,
  LockKeyhole,
  Network,
  PlusCircle,
  PauseCircle,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Square,
  Undo2,
  TerminalSquare,
  UserCircle,
  Wifi,
  XCircle
} from "lucide-react";
import {
  authLogin,
  authLogout,
  authMe,
  authPolicy,
  checkForDesktopUpdate,
  createAccount,
  disableAccount,
  dispatchDisabledReason,
  dispatchSignedTask,
  completeAccountDeletion,
  discoverHubs,
  enableAccount,
  EMPTY_DISPATCH_DRAFT,
  grantMembership,
  HubApi,
  initiateAccountDeletion,
  installVerifiedDesktopUpdate,
  listAccounts,
  listAuthSessions,
  loadDispatcherIdentity,
  loadOrCreateDispatcherIdentity,
  persistHubPin,
  registerPasskey,
  removeHubToken,
  revokeAuthSession,
  revokeMembership,
  saveHubToken,
  signInWithPasskey,
  stepUp,
  normalizeHubUrl,
  type AccountSummaryResult,
  type AuthResult,
  type SessionSummaryResult
} from "./api";
import {
  hubConfigFromContext,
  loadFabricContext,
  loadHubConfig,
  loadInitialHubConfig,
  saveHubConfig
} from "./storage";
import { DEFAULT_SESSION_PROFILE_ID, TauriSessionCredentialStore } from "./session";
import type {
  AgentInfo,
  ApprovalInfo,
  DispatchDraft,
  DispatcherIdentitySummary,
  FabricContext,
  HubDiscoveryCandidate,
  HubConfig,
  HubSnapshot,
  RunnerInfo,
  SignedDispatchResult,
  TaskAudit,
  TaskInfo,
  TaskStreamLine
} from "./types";
import {
  beginRefresh,
  buildExplorerSections,
  completeRefresh,
  DEFAULT_REFRESH_POLICY,
  deriveAuthState,
  detectFabricFeatures,
  isAuthOperationOfferedInState,
  isRefreshDue,
  normalizeFabricSnapshot,
  type AuthState,
  type CommandId,
  type ExplorerNode,
  type RefreshPolicy,
  type RefreshState,
  type ResourceFreshness,
  type SelectionKind,
  type SessionState
} from "@forgewire/fabric-client-core";
import { desktopCommandAvailabilityFor } from "./commandGating";
import { ACTIVITY_ROUTES, type ActivityId, useHashRoute } from "./routing/hashRoute";
import { CommandPalette } from "./components/CommandPalette";
import {
  AuthorizationOrFailure,
  AuthorizationState,
  EmptyState,
  InfoLine,
  Panel,
  StatusDot,
  StatusPill,
  Tombstone,
  authorizationDenied,
  statusClass
} from "./components/primitives";
import { AccountPage } from "./pages/AccountPage";
import { accountRoleContextNote } from "./restrictionMessages";
import type { DesktopCommand } from "./commandCatalog";
import "./styles.css";

// 114C.7 Slice 5a: one shared credential-store instance, matching how
// `tauriTransport` is a module-level singleton in api.ts/session.ts. Account
// mutation handlers read the secret fresh from it on every call (never
// cached in React state) -- the same discipline VSIX's extension.ts uses
// (`humanSessionStore.get(...)` inside every command handler), so a stale
// secret never outlives the OS keychain's own copy of it.
const humanSessionStore = new TauriSessionCredentialStore();

const EMPTY_SNAPSHOT: HubSnapshot = {
  health: null,
  cluster: null,
  runners: [],
  agents: [],
  tasks: [],
  approvals: [],
  budget: null,
  hosts: [],
  audit: null
};

function App() {
  const [config, setConfig] = useState<HubConfig>(() => loadInitialHubConfig());
  const [draft, setDraft] = useState<HubConfig>(() => loadInitialHubConfig());
  const [tokenInput, setTokenInput] = useState("");
  const [snapshot, setSnapshot] = useState<HubSnapshot>(EMPTY_SNAPSHOT);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [restrictions, setRestrictions] = useState<Record<string, string>>({});
  const [sessionState, setSessionState] = useState<SessionState>("bootstrapping");
  const [freshness, setFreshness] = useState<Record<string, ResourceFreshness | undefined>>({});
  const [authorities, setAuthorities] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [selectedTaskId, setSelectedTaskId] = useState<number | null>(null);
  const [filter, setFilter] = useState(() => readPreference("taskFilter", ""));
  const [taskStream, setTaskStream] = useState<TaskStreamLine[]>([]);
  const [taskAudit, setTaskAudit] = useState<TaskAudit | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [identityPath, setIdentityPath] = useState("");
  const [dispatcherIdentity, setDispatcherIdentity] = useState<DispatcherIdentitySummary | null>(null);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [dispatchOpen, setDispatchOpen] = useState(false);
  const [dispatchDraft, setDispatchDraft] = useState<DispatchDraft>(EMPTY_DISPATCH_DRAFT);
  const [dispatchResult, setDispatchResult] = useState<SignedDispatchResult | null>(null);
  const [hubCandidates, setHubCandidates] = useState<HubDiscoveryCandidate[]>([]);
  const [fabricContext, setFabricContext] = useState<FabricContext | null>(null);
  const { route, activity, navigate } = useHashRoute();
  const [explorerCollapsed, setExplorerCollapsed] = useState(() => readPreference("explorerCollapsed", false));
  const [explorerWidth, setExplorerWidth] = useState(() => readPreference("explorerWidth", 300));
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(
    () => new Set(readPreference<string[]>("expandedNodes", ["hub", "hosts", "tasks", "agents", "approvals"]))
  );
  const [explorerFilter, setExplorerFilter] = useState(() => readPreference("explorerFilter", ""));
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [commandNotice, setCommandNotice] = useState<string | null>(null);
  const refreshInFlight = useRef(false);
  // 114C.7 Slice 6d (AC-114B-5): single-flight + backoff-on-failure state for
  // the periodic refresh ticker only -- see the periodic useEffect below.
  // Distinct from `refreshInFlight` above, which already guards every caller
  // of `refresh()` (manual button, command palette, post-mutation calls) and
  // is untouched by this.
  const periodicRefreshState = useRef<RefreshState>({ inFlight: false, consecutiveFailures: 0 });

  // 114C.7 Slice 5a: the signed-in human's own account state. Deliberately
  // NOT merged into `snapshot`/`errors`/`sessionState` above -- account data
  // needs a human session's own access secret as bearer, a categorically
  // different credential from the installed automation hub token every
  // other resource fetches with (see the plan's correction note: `admin` can
  // never be an automation role, so this can never go through
  // `HubApi.loadSnapshot()`). Kept in its own state so an account-fetch
  // failure can never affect the main connection health computation, exactly
  // mirroring the VSIX AccountProvider's isolation from
  // `updateStatus()`/`probeAndRefresh()`.
  const [accountMe, setAccountMe] = useState<AccountSummaryResult | null>(null);
  const [accountSessions, setAccountSessions] = useState<SessionSummaryResult[]>([]);
  const [accountError, setAccountError] = useState<string | null>(null);
  const [accountLoading, setAccountLoading] = useState(false);
  const accountLoadInFlight = useRef(false);
  // 114C.7 Slice 5c: the admin-only account list + assignable-role vocabulary.
  // `null` (not `[]`) distinguishes "not an admin" from "an admin with zero
  // other accounts" -- AccountPage renders the Administration section only
  // when this is non-null, mirroring VSIX AccountProvider's `accounts?:`
  // omission-on-non-admin pattern.
  const [accountsAdmin, setAccountsAdmin] = useState<AccountSummaryResult[] | null>(null);
  const [accountRoles, setAccountRoles] = useState<string[]>([]);
  // 114C.7 Slice 6e (AC-114B-5 follow-up, discovered while adopting auth.ts):
  // `human_accounts` is deliberately advertisement-only in detectFabricFeatures
  // (features.ts) -- never inferred from protocol version alone. Without this
  // probe, `gatingFeatures` never contained "human_accounts" at all. `GET
  // /auth-policy` is public and exists only on a hub with 114C's
  // human-accounts routes, so a successful call (any body) is exactly the
  // "this hub supports human accounts" signal -- probed independent of
  // sign-in state (unlike `loadAccount`, which only reaches an authPolicy
  // call for a signed-in admin).
  const [humanAccountsAdvertised, setHumanAccountsAdvertised] = useState(false);

  const api = useMemo(() => {
    if (!config.hubUrl) {
      return null;
    }
    return new HubApi(config);
  }, [config]);

  const refresh = useCallback(async (): Promise<boolean> => {
    if (!api || refreshInFlight.current) {
      return false;
    }
    refreshInFlight.current = true;
    setLoading(true);
    try {
      const result = await api.loadSnapshot();
      setSnapshot(result.snapshot);
      setErrors(result.errors);
      setRestrictions(result.restrictions);
      setSessionState(result.sessionState);
      setFreshness(result.freshness);
      setAuthorities(result.authorities);
      setLastRefresh(new Date(result.refreshedAtMs));
      const firstTaskId = getTaskId(result.snapshot.tasks[0]);
      setSelectedTaskId((current) => current ?? firstTaskId ?? null);
      return true;
    } catch (error) {
      setErrors({ hub: error instanceof Error ? error.message : String(error) });
      setRestrictions({});
      setSessionState(config.tokenPresent ? "offline" : "misconfigured");
      return false;
    } finally {
      refreshInFlight.current = false;
      setLoading(false);
    }
  }, [api, config.tokenPresent]);

  // 114C.7 Slice 5a: independent read path for the signed-in human's own
  // account. Reads the session secret fresh from the credential store each
  // call (never cached), matching every mutation handler below. Absence of a
  // stored session is a normal "signed out" state, not an error -- mirrors
  // `AccountProvider.getChildren()` on VSIX.
  const loadAccount = useCallback(async () => {
    if (!config.hubUrl || accountLoadInFlight.current) {
      return;
    }
    const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
    if (!session) {
      setAccountMe(null);
      setAccountSessions([]);
      setAccountError(null);
      setAccountsAdmin(null);
      setAccountRoles([]);
      return;
    }
    accountLoadInFlight.current = true;
    setAccountLoading(true);
    try {
      const [me, sessions] = await Promise.all([
        // 114E: a key-bound session signs these self-service reads (PoP); a
        // bearer-only session passes undefined and replays the access secret.
        authMe(config.hubUrl, session.accessSecret, session.sessionId, session.sessionSigningKey),
        listAuthSessions(config.hubUrl, session.accessSecret, undefined, session.sessionId, session.sessionSigningKey)
      ]);
      if (me.ok && me.data) {
        setAccountMe(me.data);
        setAccountError(null);
      } else {
        setAccountMe(null);
        setAccountError(me.message ?? "The account could not be loaded.");
      }
      setAccountSessions(sessions.ok && sessions.data ? sessions.data.sessions : []);
      // 114C.7 Slice 5c: Administration section only for a signed-in admin.
      // The account list is fetched with the admin's own session secret; a
      // non-admin (or a list failure) simply omits the section rather than
      // erroring the whole page -- mirrors VSIX AccountProvider exactly.
      if (me.ok && me.data && me.data.roles.includes("admin")) {
        const [accounts, policy] = await Promise.all([
          listAccounts(config.hubUrl, session.accessSecret),
          authPolicy(config.hubUrl)
        ]);
        setAccountsAdmin(accounts.ok && accounts.data ? accounts.data.accounts : null);
        setAccountRoles(policy.ok && policy.data ? policy.data.roles : []);
      } else {
        setAccountsAdmin(null);
        setAccountRoles([]);
      }
    } catch (error) {
      setAccountMe(null);
      setAccountSessions([]);
      setAccountsAdmin(null);
      setAccountRoles([]);
      setAccountError(error instanceof Error ? error.message : String(error));
    } finally {
      accountLoadInFlight.current = false;
      setAccountLoading(false);
    }
  }, [config.hubUrl]);

  /** 114E: password sign-in. Establishes a human session and, because the hub
   *  binds a per-session Ed25519 key at login, a proof-of-possession session:
   *  the returned private key is persisted in the OS keyring so subsequent
   *  self-service requests are signed rather than replaying the bearer. This is
   *  the first-session on-ramp -- passkey enrolment requires a session, so a
   *  passkey-only client could never establish its first one. */
  const signInWithPassword = useCallback(
    async (username: string, password: string): Promise<AuthResult<unknown>> => {
      if (!config.hubUrl) {
        return { ok: false, message: "Configure a hub connection first." };
      }
      const result = await authLogin(config.hubUrl, username, password, "desktop", "desktop-password");
      if (result.ok && result.data) {
        await humanSessionStore.set(DEFAULT_SESSION_PROFILE_ID, {
          sessionId: result.data.session_id,
          accessSecret: result.data.access_secret,
          refreshSecret: result.data.refresh_secret,
          sessionSigningKey: result.data.session_signing_key
        });
        await loadAccount();
      }
      return result;
    },
    [config.hubUrl, loadAccount]
  );

  /** Sign out: best-effort hub revoke, then an UNCONDITIONAL local clear --
   *  matching VSIX's `signOutCmd` exactly, including the reasoning: this
   *  machine ends up signed out even if the hub revoke could not be
   *  delivered. */
  const signOut = useCallback(async () => {
    const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
    if (!session || !config.hubUrl) {
      return;
    }
    try {
      await authLogout(config.hubUrl, session.accessSecret, session.sessionId, session.sessionSigningKey);
    } catch {
      // Non-fatal: the local credential is cleared regardless below.
    }
    await humanSessionStore.delete(DEFAULT_SESSION_PROFILE_ID);
    await loadAccount();
  }, [config.hubUrl, loadAccount]);

  /** Revoke one of the caller's OTHER sessions. The current session is never
   *  offered this action in the UI (Sign Out covers that) -- mirrors VSIX's
   *  `revokeSessionCmd`. */
  const revokeSession = useCallback(async (sessionId: string) => {
    const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
    if (!session || !config.hubUrl) {
      return;
    }
    // 114E: authenticate the revoke via PoP (auth session = our own session)
    // when key-bound; the target `sessionId` is a different session.
    await revokeAuthSession(config.hubUrl, session.accessSecret, sessionId, session.sessionId, session.sessionSigningKey);
    await loadAccount();
  }, [config.hubUrl, loadAccount]);

  /**
   * 114C.7 Slice 5b: run the true in-place step-up ceremony. Mirrors VSIX's
   * `stepUp()` exactly: the Rust backend holds the session bearer and calls
   * both step-up hub routes itself; the bridge page only relays
   * `navigator.credentials.get` on the public challenge, so the access
   * secret never enters the browser. The backend persists the rotated
   * access secret to the OS keyring itself before this resolves. Returns
   * whether it succeeded so a caller can gate a sensitive follow-up action
   * (account deletion, Slice 5d).
   */
  const runStepUp = useCallback(async (): Promise<boolean> => {
    if (!config.hubUrl) {
      return false;
    }
    const result = await stepUp(config.hubUrl);
    if (!result.ok) {
      setAccountError(result.message ?? "Step-up verification failed.");
      return false;
    }
    void loadAccount();
    return true;
  }, [config.hubUrl, loadAccount]);

  /**
   * 114C.7 Slice 5c: shared preamble for the five admin account mutations
   * below -- reads the session secret fresh (never cached), runs `mutate`,
   * and reloads the independent account read path on success so the
   * Administration list reflects the change. Mirrors VSIX's
   * `withAdminAccount` helper, minus the tree-node narrowing that helper
   * does (Desktop passes the target account id directly instead).
   */
  const runAccountAdminMutation = useCallback(async <T,>(
    mutate: (hubUrl: string, accessSecret: string) => Promise<AuthResult<T>>
  ): Promise<AuthResult<T>> => {
    const session = await humanSessionStore.get(DEFAULT_SESSION_PROFILE_ID);
    if (!session || !config.hubUrl) {
      return { ok: false, message: "Sign in as an administrator first." };
    }
    const result = await mutate(config.hubUrl, session.accessSecret);
    if (result.ok) {
      void loadAccount();
    }
    return result;
  }, [config.hubUrl, loadAccount]);

  const createAccountAdmin = useCallback(
    (username: string, displayName: string, password: string, role: string) =>
      runAccountAdminMutation((hubUrl, secret) => createAccount(hubUrl, secret, username, displayName, password, role)),
    [runAccountAdminMutation]
  );
  const disableAccountAdmin = useCallback(
    (accountId: string, expectedRevision: number) =>
      runAccountAdminMutation((hubUrl, secret) => disableAccount(hubUrl, secret, accountId, expectedRevision)),
    [runAccountAdminMutation]
  );
  const enableAccountAdmin = useCallback(
    (accountId: string, expectedRevision: number) =>
      runAccountAdminMutation((hubUrl, secret) => enableAccount(hubUrl, secret, accountId, expectedRevision)),
    [runAccountAdminMutation]
  );
  const grantRoleAdmin = useCallback(
    (accountId: string, role: string) =>
      runAccountAdminMutation((hubUrl, secret) => grantMembership(hubUrl, secret, accountId, role)),
    [runAccountAdminMutation]
  );
  const revokeRoleAdmin = useCallback(
    (accountId: string, role: string) =>
      runAccountAdminMutation((hubUrl, secret) => revokeMembership(hubUrl, secret, accountId, role)),
    [runAccountAdminMutation]
  );

  /**
   * 114C.7 Slice 5d: shared preamble for the two account-deletion mutations.
   * Beyond the admin role gate, the client REQUIRES a fresh in-place step-up
   * before either deletion action -- even though the hub does not yet
   * enforce step-up on the deletion routes -- so the client is never laxer
   * than the documented security intent. `mutate` runs with the *rotated*
   * access secret step-up returns (the pre-step-up secret is now invalid, so
   * order matters), never a separately re-read stored session. Mirrors
   * VSIX's `withDeletionStepUp` exactly.
   */
  const runAccountDeletion = useCallback(async <T,>(
    mutate: (hubUrl: string, elevatedSecret: string) => Promise<AuthResult<T>>
  ): Promise<AuthResult<T>> => {
    if (!config.hubUrl) {
      return { ok: false, message: "Connect to a hub first." };
    }
    const elevated = await stepUp(config.hubUrl);
    if (!elevated.ok || !elevated.data) {
      return { ok: false, message: elevated.message ?? "Step-up verification failed." };
    }
    const result = await mutate(config.hubUrl, elevated.data.access_secret);
    if (result.ok) {
      void loadAccount();
    }
    return result;
  }, [config.hubUrl, loadAccount]);

  const deleteAccountAdmin = useCallback(
    (accountId: string, expectedRevision: number) =>
      runAccountDeletion((hubUrl, secret) => initiateAccountDeletion(hubUrl, secret, accountId, expectedRevision)),
    [runAccountDeletion]
  );
  const completeDeletionAdmin = useCallback(
    (accountId: string, expectedRevision: number) =>
      runAccountDeletion((hubUrl, secret) => completeAccountDeletion(hubUrl, secret, accountId, expectedRevision)),
    [runAccountDeletion]
  );

  useEffect(() => {
    let cancelled = false;
    const bootstrap = async () => {
      const fallback = loadInitialHubConfig();
      const context = await loadFabricContext();
      if (cancelled) {
        return;
      }
      if (context) {
        const loaded = hubConfigFromContext(context, fallback);
        setFabricContext(context);
        setConfig(loaded);
        setDraft(loaded);
        setHubCandidates(context.hub_candidates ?? []);
        if (context.identity_path) {
          setIdentityPath(context.identity_path);
        }
        if (context.dispatcher_identity) {
          setDispatcherIdentity(context.dispatcher_identity);
          setIdentityError(null);
        } else {
          try {
            const identity = await loadOrCreateDispatcherIdentity();
            if (!cancelled) {
              setDispatcherIdentity(identity);
              setIdentityPath(identity.path);
              setIdentityError(null);
            }
          } catch (error) {
            if (!cancelled) {
              setIdentityError(error instanceof Error ? error.message : String(error));
            }
          }
        }
        return;
      }

      const loaded = await loadHubConfig();
      if (!cancelled) {
        setConfig(loaded);
        setDraft(loaded);
      }
      try {
        const identity = await loadOrCreateDispatcherIdentity();
        if (!cancelled) {
          setDispatcherIdentity(identity);
          setIdentityPath(identity.path);
          setIdentityError(null);
        }
      } catch (error) {
        if (!cancelled) {
          setIdentityError(error instanceof Error ? error.message : String(error));
        }
      }
    };
    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void refresh();
    // Independent of `refresh()` -- runs alongside it, on the same tick, but
    // its own try/catch means an account-fetch failure never touches
    // `sessionState`/`errors` above.
    void loadAccount();
    // Independent of both -- probes whether this hub advertises human
    // accounts at all (see the humanAccountsAdvertised state comment above),
    // regardless of sign-in state. A failure (older hub, offline) just means
    // "not advertised," never an error surfaced elsewhere.
    if (config.hubUrl) {
      authPolicy(config.hubUrl).then(
        (result) => setHumanAccountsAdvertised(result.ok),
        () => setHumanAccountsAdvertised(false)
      );
    }
    const configuredSeconds = (fabricContext as (FabricContext & { refresh_interval_seconds?: number }) | null)
      ?.refresh_interval_seconds;
    const seconds = Math.min(300, Math.max(2, configuredSeconds ?? 10));
    // 114C.7 Slice 6d (AC-114B-5): adopts resilience.ts's backoff-on-failure
    // state machine for this periodic tick specifically -- before this, a
    // bare setInterval retried on the fixed configured cadence forever, even
    // after repeated failures, hammering an unreachable hub at full rate
    // indefinitely. The ticker still fires at the same configured cadence as
    // before; isRefreshDue only differs from "always yes" once consecutive
    // failures push the backoff delay beyond that cadence, at which point
    // some ticks are correctly skipped instead. `refresh()`'s own
    // `refreshInFlight` guard (single-flight for every caller, manual
    // clicks included) is untouched -- this adds backoff on top of it for
    // the periodic path only, mirroring the VSIX-side adoption exactly.
    const policy: RefreshPolicy = {
      foregroundMs: seconds * 1000,
      backgroundMs: seconds * 1000,
      maximumBackoffMs: Math.max(seconds * 1000, DEFAULT_REFRESH_POLICY.maximumBackoffMs),
      backoffMultiplier: DEFAULT_REFRESH_POLICY.backoffMultiplier
    };
    const interval = window.setInterval(() => {
      const now = Date.now();
      if (isRefreshDue(periodicRefreshState.current, now, policy, "foreground")) {
        periodicRefreshState.current = beginRefresh(periodicRefreshState.current, now);
        void refresh().then((succeeded) => {
          periodicRefreshState.current = completeRefresh(periodicRefreshState.current, succeeded, Date.now());
        });
      }
      void loadAccount();
      if (config.hubUrl) {
        authPolicy(config.hubUrl).then(
          (result) => setHumanAccountsAdvertised(result.ok),
          () => setHumanAccountsAdvertised(false)
        );
      }
    }, seconds * 1000);
    return () => window.clearInterval(interval);
  }, [refresh, loadAccount, fabricContext, config.hubUrl]);

  const selectedTask = selectedTaskId === null
    ? snapshot.tasks[0] ?? null
    : snapshot.tasks.find((task) => getTaskId(task) === selectedTaskId) ?? null;

  const visibleTasks = snapshot.tasks.filter((task) => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return true;
    }
    return `${task.title ?? ""} ${task.status ?? ""} ${task.kind ?? ""} ${task.runner_id ?? ""}`
      .toLowerCase()
      .includes(needle);
  });

  const saveConnection = async () => {
    setBusyAction("save-connection");
    setActionError(null);
    try {
      const next: HubConfig = { hubUrl: normalizeHubUrl(draft.hubUrl), tokenPresent: config.tokenPresent };
      await saveHubConfig(next);
      if (tokenInput.trim()) {
        const stored = await saveHubToken(tokenInput.trim());
        next.tokenPresent = stored.present;
        setTokenInput("");
      }
      setConfig(next);
      setDraft(next);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusyAction(null);
    }
  };

  const loadIdentity = async () => {
    setIdentityError(null);
    setDispatcherIdentity(null);
    try {
      setDispatcherIdentity(await loadDispatcherIdentity(identityPath));
    } catch (error) {
      setIdentityError(error instanceof Error ? error.message : String(error));
    }
  };

  const runDiscovery = async () => {
    setBusyAction("discover-hubs");
    setActionError(null);
    try {
      const candidates = await discoverHubs([draft.hubUrl, config.hubUrl]);
      setHubCandidates(candidates);
      if (candidates[0]) {
        setDraft((current) => ({ ...current, hubUrl: candidates[0].url }));
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusyAction(null);
    }
  };

  useEffect(() => {
    if (!api || selectedTaskId === null) {
      setTaskStream([]);
      setTaskAudit(null);
      setStreamError(null);
      return;
    }

    let cancelled = false;
    let lastSeq = 0;
    const poll = async () => {
      try {
        const result = await api.taskStream(selectedTaskId, lastSeq, 200);
        if (cancelled) {
          return;
        }
        setStreamError(null);
        if (result.lines.length > 0) {
          lastSeq = result.lines.reduce((max, line) => Math.max(max, typeof line.seq === "number" ? line.seq : max), lastSeq);
          setTaskStream((current) => [...current, ...result.lines].slice(-500));
        }
      } catch (error) {
        if (!cancelled) {
          setStreamError(error instanceof Error ? error.message : String(error));
        }
      }
    };

    setTaskStream([]);
    setTaskAudit(null);
    setStreamError(null);
    void poll();
    void api.taskAudit(selectedTaskId).then((audit) => {
      if (!cancelled) {
        setTaskAudit(audit);
      }
    }).catch((error) => {
      if (!cancelled) {
        setTaskAudit({ events: [], verified: false, error: error instanceof Error ? error.message : String(error) });
      }
    });
    const interval = window.setInterval(() => void poll(), 1500);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [api, selectedTaskId]);

  const runAction = async (name: string, action: () => Promise<unknown>) => {
    setBusyAction(name);
    setActionError(null);
    try {
      await action();
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusyAction(null);
    }
  };

  // 114C.6 Slice 5d: opens the hub-served WebAuthn bridge in the system
  // browser. Not routed through `runAction`: neither command's Tauri
  // signature can reject (both return PasskeyBridgeResult directly, never
  // Result<_, String>), so `ok: false` is the only failure signal there is,
  // and a sign-in does not itself change fabric snapshot state the way
  // runAction's post-action refresh() assumes.
  const runPasskeyBridge = async (
    verb: string,
    invoke: (hubUrl: string) => ReturnType<typeof signInWithPasskey>,
    successMessage: string
  ) => {
    if (!config.hubUrl) {
      setCommandNotice("Configure a hub connection first.");
      return;
    }
    setCommandNotice(`${verb}… complete the prompt in your browser.`);
    const result = await invoke(config.hubUrl);
    setCommandNotice(result.ok ? successMessage : `${verb} failed: ${result.message ?? "unknown error"}`);
    // A successful login writes the session straight into the OS keyring
    // from the Rust command (never through this state) -- reload the
    // independent account read path so the Account page reflects it.
    if (result.ok) {
      void loadAccount();
    }
  };

  const cancelSelectedTask = async (taskId: number) => {
    if (!api) {
      return;
    }
    const target = snapshot.tasks.find((task) => getTaskId(task) === taskId);
    if (!window.confirm(`Cancel task #${taskId}${target?.title ? ` “${target.title}”` : ""}? This action is recorded by the hub audit path.`)) {
      return;
    }
    await runAction(`cancel-task-${taskId}`, () => api.cancelTask(taskId));
  };

  const toggleRunnerDrain = async (runner: RunnerInfo) => {
    if (!api) {
      return;
    }
    const runnerId = runner.runner_id;
    const verb = runner.drain_requested ? "clear the drain request for" : "request drain for";
    if (!window.confirm(`Confirm ${verb} runner ${runner.alias ?? runnerId} (${runnerId}).`)) {
      return;
    }
    await runAction(
      `${runner.drain_requested ? "undrain" : "drain"}-${runnerId}`,
      () => runner.drain_requested ? api.requestRunnerUndrain(runnerId) : api.requestRunnerDrain(runnerId)
    );
  };

  const decideApproval = async (approval: ApprovalInfo, status: "approve" | "deny") => {
    if (!api) {
      return;
    }
    if (!window.confirm(`${status === "approve" ? "Approve" : "Deny"} ${approval.task_label ?? approval.approval_id}? The decision is written to the hub audit trail.`)) {
      return;
    }
    await runAction(`approval-${status}-${approval.approval_id}`, () => {
      const decision = {
        approver: "fabric-desktop",
        reason: status === "approve" ? "approved in Fabric desktop UI" : "denied in Fabric desktop UI"
      };
      return status === "approve"
        ? api.approveApproval(approval.approval_id, decision)
        : api.denyApproval(approval.approval_id, decision);
    });
  };

  const submitDispatch = async () => {
    if (!dispatcherIdentity) {
      return;
    }
    setBusyAction("dispatch-submit");
    setActionError(null);
    try {
      const result = await dispatchSignedTask(config, dispatcherIdentity, dispatchDraft);
      setDispatchResult(result);
      const refreshed = api ? await api.loadSnapshot() : null;
      if (refreshed) {
        setSnapshot(refreshed.snapshot);
        setErrors(refreshed.errors);
        setRestrictions(refreshed.restrictions);
        setSessionState(refreshed.sessionState);
        setFreshness(refreshed.freshness);
        setAuthorities(refreshed.authorities);
        setLastRefresh(new Date(refreshed.refreshedAtMs));
      }
      if (typeof result.task_id === "number") {
        setSelectedTaskId(result.task_id);
      }
      if (result.status === "queued" || result.status === "submitted") {
        setDispatchOpen(false);
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusyAction(null);
    }
  };

  const onlineRunners = snapshot.runners.filter((runner) => runner.state === "online").length;
  const degradedRunners = snapshot.runners.filter((runner) =>
    ["degraded", "draining", "offline"].includes(String(runner.state ?? ""))
  ).length;
  const pendingApprovals = snapshot.approvals.filter((approval) => approval.status === "pending").length;
  const runningTasks = snapshot.tasks.filter((task) => task.status === "running").length;
  const queuedTasks = snapshot.tasks.filter((task) => task.status === "queued").length;
  const failedTasks = snapshot.tasks.filter((task) => ["failed", "timed_out"].includes(String(task.status))).length;

  useEffect(() => {
    writePreference("explorerCollapsed", explorerCollapsed);
    writePreference("explorerWidth", explorerWidth);
    writePreference("expandedNodes", [...expandedNodes]);
    writePreference("explorerFilter", explorerFilter);
    writePreference("taskFilter", filter);
  }, [explorerCollapsed, explorerWidth, expandedNodes, explorerFilter, filter]);

  useEffect(() => {
    const match = route.match(/^\/tasks\/(\d+)$/);
    if (match) {
      setSelectedTaskId(Number(match[1]));
    }
  }, [route]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === "p") {
        event.preventDefault();
        setCommandPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const toggleExpanded = (id: string) => {
    setExpandedNodes((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Hub feature floor + the credential's authoritative capabilities feed the
  // shared command gate. Features derive from the advertised protocol version
  // (all currently-gated operator domains sit on the protocol-v4 floor) plus
  // the explicit human_accounts advertisement probe above; authorities come
  // from GET /whoami via the native snapshot.
  const gatingFeatures = useMemo(
    () => detectFabricFeatures({
      protocolVersion: snapshot.health?.protocol_version,
      advertised: humanAccountsAdvertised ? ["human_accounts"] : []
    }),
    [snapshot.health?.protocol_version, humanAccountsAdvertised]
  );
  const authoritySet = useMemo(() => new Set(authorities), [authorities]);
  // 114C.7 Slice 5c: mirrors VSIX's commandHumanRoles -- empty when no human
  // session is signed in, so every requiresHumanRole gate fails closed for
  // automation-only credentials. Derived straight from the Slice 5a account
  // read path rather than a second fetch: `accountMe` already comes from the
  // caller's own `GET /auth/me`.
  const humanRoleSet = useMemo(() => new Set(accountMe?.roles ?? []), [accountMe]);
  // 114C.7 Slice 6e (AC-114B-5): adopts auth.ts's shared state machine as the
  // single source of truth for which self-service Account-page actions are
  // offered, replacing the page's own ad hoc `!accountMe` check.
  // `humanAccountsSupported` is fed from `gatingFeatures` (the real
  // `humanAccountsAdvertised` probe above), not hardcoded -- discovered
  // while wiring this that `gatingFeatures` never actually contained
  // "human_accounts" before that probe existed, which would otherwise have
  // made this collapse to permanently "unavailable" and hidden every
  // self-service Account action against every hub, sign-in included.
  const authState: AuthState = useMemo(
    () => deriveAuthState({ humanAccountsSupported: gatingFeatures.has("human_accounts"), signedIn: accountMe !== null }),
    [gatingFeatures, accountMe]
  );
  const commandAvailabilityFor = useCallback(
    (id: CommandId, selections: Partial<Record<SelectionKind, { id: string; status?: string }>> = {}) =>
      desktopCommandAvailabilityFor(id, {
        sessionState,
        features: gatingFeatures,
        authorities: authoritySet,
        identityPurpose: dispatcherIdentity?.purpose,
        freshness,
        selections,
        humanRoles: humanRoleSet,
      }),
    [sessionState, gatingFeatures, authoritySet, dispatcherIdentity, freshness, humanRoleSet]
  );
  const dispatchAvailability = commandAvailabilityFor("forgewire.dispatchTask");

  const executeCommand = (command: DesktopCommand) => {
    setCommandNotice(null);
    if (command.route) navigate(command.route);
    if (command.availability === "platform-alternative") {
      setCommandNotice(`${command.label}: ${command.alternative}`);
      return;
    }
    const selectedApproval = snapshot.approvals.find((approval) => route === `/approvals/${encodeURIComponent(approval.approval_id)}`)
      ?? snapshot.approvals.find((approval) => approval.status === "pending");
    const selectedRunner = snapshot.runners.find((runner) => route === `/runners/${encodeURIComponent(runner.runner_id)}`);

    // Route every authority-/selection-gated command through the shared
    // commandAvailability() decision before acting, so the reason shown matches
    // the hub's real gating (a missing authority, a stale session, the wrong
    // selection status) instead of the previous ad hoc, connection-blind
    // messages. Selection state is supplied per command kind; commands with no
    // selection kind ignore it.
    const selectionsFor = (kind: SelectionKind | undefined): Partial<Record<SelectionKind, { id: string; status?: string }>> => {
      if (kind === "task" && selectedTaskId !== null) return { task: { id: String(selectedTaskId), status: selectedTask?.status } };
      if (kind === "approval" && selectedApproval) return { approval: { id: selectedApproval.approval_id, status: selectedApproval.status } };
      if (kind === "runner" && selectedRunner) return { runner: { id: selectedRunner.runner_id, status: selectedRunner.drain_requested ? "draining" : (selectedRunner.state ?? "online") } };
      return {};
    };
    const gate = (kind: SelectionKind | undefined): boolean => {
      const availability = commandAvailabilityFor(command.id as CommandId, selectionsFor(kind));
      if (!availability.enabled) {
        setCommandNotice(`${command.label}: ${availability.reason ?? "unavailable."}`);
        return false;
      }
      return true;
    };

    switch (command.action) {
      case "refresh": void refresh(); break;
      case "dispatch": if (gate(undefined)) setDispatchOpen(true); break;
      case "discover": void runDiscovery(); break;
      case "cancel-task": if (gate("task") && selectedTaskId !== null) void cancelSelectedTask(selectedTaskId); break;
      case "redispatch-task": if (gate("task") && selectedTaskId !== null && api) void runAction(`redispatch-${selectedTaskId}`, () => api.redispatchTask(selectedTaskId)); break;
      case "approve": if (gate("approval") && selectedApproval) void decideApproval(selectedApproval, "approve"); break;
      case "deny": if (gate("approval") && selectedApproval) void decideApproval(selectedApproval, "deny"); break;
      case "defer": setCommandNotice(selectedApproval ? "Use Defer review in the approval examination panel to keep the hub item pending." : "Select a pending approval first."); break;
      case "pause-runner": if (gate("runner") && selectedRunner) void toggleRunnerDrain(selectedRunner); break;
      case "resume-runner": if (gate("runner") && selectedRunner) void toggleRunnerDrain(selectedRunner); break;
      case "sign-in-with-passkey": void runPasskeyBridge("Signing in", signInWithPasskey, "Signed in with a passkey."); break;
      case "register-passkey": void runPasskeyBridge("Registering passkey", registerPasskey, "Passkey registered."); break;
      default:
        if (command.availability === "contextual") setCommandNotice(`${command.label} is available after selecting its target.`);
    }
  };

  return (
    <main
      className={`app-shell ${explorerCollapsed ? "explorer-is-collapsed" : ""}`}
      style={{ "--explorer-width": `${explorerWidth}px` } as React.CSSProperties}
    >
      <ActivityRail activity={activity} onNavigate={navigate} />
      <ExplorerPane
        activity={activity}
        route={route}
        snapshot={snapshot}
        collapsed={explorerCollapsed}
        filter={explorerFilter}
        width={explorerWidth}
        expanded={expandedNodes}
        onFilter={setExplorerFilter}
        onToggle={() => setExplorerCollapsed((value) => !value)}
        onToggleNode={toggleExpanded}
        onNavigate={navigate}
        onResize={setExplorerWidth}
      />

      <section className="workspace">
        <header className="workbench-toolbar">
          <div className="history-controls" aria-label="Navigation history">
            <button onClick={() => window.history.back()} title="Back" aria-label="Back"><ChevronLeft size={17} /></button>
            <button onClick={() => window.history.forward()} title="Forward" aria-label="Forward"><ChevronRight size={17} /></button>
          </div>
          <div className="workbench-heading">
            <p className="eyebrow">{activityLabel(activity)}</p>
            <h1>{pageTitle(route)}</h1>
          </div>
          <div className="topbar-actions">
            <button className="secondary-command command-trigger" onClick={() => setCommandPaletteOpen(true)} title="Commands (Ctrl+Shift+P)">
              <Command size={16} />
              Commands
            </button>
            <button className="secondary-command" onClick={() => void refresh()} disabled={!api || loading}>
              <RefreshCw size={16} className={loading ? "spin" : ""} />
              Refresh
            </button>
            <button className="primary-command" onClick={() => setDispatchOpen(true)}>
              <PlusCircle size={16} />
              Dispatch
            </button>
          </div>
        </header>

        <div className="workbench-scroll">
          {Object.keys(restrictions).length > 0 && <RestrictionStrip restrictions={restrictions} accountRoles={accountMe?.roles ?? null} />}
          {Object.keys(errors).length > 0 && <ErrorStrip errors={errors} />}
          {actionError && <ErrorStrip errors={{ action: actionError }} />}
          {commandNotice && <div className="command-notice" role="status"><Command size={17} /><span>{commandNotice}</span><button onClick={() => setCommandNotice(null)} aria-label="Dismiss command notice"><XCircle size={15} /></button></div>}
          {dispatchResult && <DispatchResultStrip result={dispatchResult} />}

          <Workbench
            api={api}
            route={route}
            snapshot={snapshot}
            errors={errors}
            restrictions={restrictions}
            sessionState={sessionState}
            freshness={freshness}
            config={config}
            draft={draft}
            tokenInput={tokenInput}
            fabricContext={fabricContext}
            hubCandidates={hubCandidates}
            dispatcherIdentity={dispatcherIdentity}
            identityPath={identityPath}
            identityError={identityError}
            busyAction={busyAction}
            visibleTasks={visibleTasks}
            selectedTask={selectedTask}
            selectedTaskId={selectedTaskId}
            filter={filter}
            taskStream={taskStream}
            taskAudit={taskAudit}
            streamError={streamError}
            onNavigate={navigate}
            onRefresh={async () => { await refresh(); }}
            onTokenStorageChange={(present) => {
              setConfig((current) => ({ ...current, tokenPresent: present }));
              setDraft((current) => ({ ...current, tokenPresent: present }));
            }}
            onDraft={setDraft}
            onTokenInput={setTokenInput}
            onConnect={() => void saveConnection()}
            onDiscover={() => void runDiscovery()}
            onIdentityPath={setIdentityPath}
            onLoadIdentity={() => void loadIdentity()}
            onSelectCandidate={(url) => setDraft((current) => ({ ...current, hubUrl: url }))}
            onFilter={setFilter}
            onSelectTask={(id) => {
              setSelectedTaskId(id);
              if (id !== null) navigate(`/tasks/${id}`);
            }}
            onCancel={cancelSelectedTask}
            onToggleDrain={toggleRunnerDrain}
            onApproval={decideApproval}
            accountMe={accountMe}
            accountSessions={accountSessions}
            accountError={accountError}
            accountLoading={accountLoading}
            accountsAdmin={accountsAdmin}
            accountRoles={accountRoles}
            authState={authState}
            onAccountRefresh={loadAccount}
            onSignOut={signOut}
            onRevokeSession={revokeSession}
            onSignInWithPasskey={() => runPasskeyBridge("Signing in", signInWithPasskey, "Signed in with a passkey.")}
            onSignInWithPassword={signInWithPassword}
            onStepUp={runStepUp}
            onCreateAccount={createAccountAdmin}
            onDisableAccount={disableAccountAdmin}
            onEnableAccount={enableAccountAdmin}
            onGrantRole={grantRoleAdmin}
            onRevokeRole={revokeRoleAdmin}
            onDeleteAccount={deleteAccountAdmin}
            onCompleteDeletion={completeDeletionAdmin}
          />
        </div>
      </section>

      <StatusBar
        snapshot={snapshot}
        sessionState={sessionState}
        freshness={freshness}
        apiHost={api ? new URL(api.baseUrl).host : null}
        lastRefresh={lastRefresh}
        loading={loading}
        readErrorCount={Object.keys(errors).length}
        restrictedCount={Object.keys(restrictions).length}
        actionError={Boolean(actionError)}
        pendingApprovals={pendingApprovals}
        runningTasks={runningTasks}
      />

      {dispatchOpen && (
        <DispatchModal
          draft={dispatchDraft}
          config={config}
          identity={dispatcherIdentity}
          gateReason={dispatchAvailability.enabled ? null : (dispatchAvailability.reason ?? "Dispatch is unavailable.")}
          busy={busyAction === "dispatch-submit"}
          onChange={setDispatchDraft}
          onClose={() => setDispatchOpen(false)}
          onSubmit={() => void submitDispatch()}
        />
      )}
      <CommandPalette open={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} onExecute={executeCommand} />
    </main>
  );
}

const ACTIVITIES: Array<{ id: ActivityId; label: string; icon: React.ReactNode }> = [
  { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={22} /> },
  { id: "explorer", label: "Fabric Explorer", icon: <ListTree size={22} /> },
  { id: "fleet", label: "Hub / Fleet", icon: <Network size={22} /> },
  { id: "tasks", label: "Tasks", icon: <TerminalSquare size={22} /> },
  { id: "agents", label: "Agents", icon: <Bot size={22} /> },
  { id: "approvals", label: "Approvals", icon: <ShieldCheck size={22} /> },
  { id: "cost", label: "Cost", icon: <BadgeDollarSign size={22} /> },
  { id: "audit", label: "Audit", icon: <FileClock size={22} /> },
  { id: "secrets", label: "Secrets", icon: <LockKeyhole size={22} /> },
  { id: "settings", label: "Settings", icon: <Settings size={22} /> },
  { id: "account", label: "Account", icon: <UserCircle size={22} /> }
];

function ActivityRail({ activity, onNavigate }: { activity: ActivityId; onNavigate: (route: string) => void }) {
  return (
    <aside className="activity-rail" aria-label="Primary navigation">
      <div className="rail-brand" aria-label="ForgeWire Fabric">FW</div>
      <nav>
        {ACTIVITIES.map((item) => (
          <button
            key={item.id}
            className={activity === item.id ? "active" : ""}
            onClick={() => onNavigate(ACTIVITY_ROUTES[item.id])}
            aria-current={activity === item.id ? "page" : undefined}
            aria-label={item.label}
            title={item.label}
          >
            {item.icon}
          </button>
        ))}
      </nav>
    </aside>
  );
}

function ExplorerPane({
  activity,
  route,
  snapshot,
  collapsed,
  filter,
  width,
  expanded,
  onFilter,
  onToggle,
  onToggleNode,
  onNavigate,
  onResize
}: {
  activity: ActivityId;
  route: string;
  snapshot: HubSnapshot;
  collapsed: boolean;
  filter: string;
  width: number;
  expanded: Set<string>;
  onFilter: (value: string) => void;
  onToggle: () => void;
  onToggleNode: (id: string) => void;
  onNavigate: (route: string) => void;
  onResize: (width: number) => void;
}) {
  const domains = activity === "explorer"
    ? ["hub", "hosts", "tasks", "agents", "approvals", "cost", "audit", "secrets", "settings"]
    : activity === "dashboard" ? ["overview"] : [activity];
  const resize = (event: React.PointerEvent) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    const startX = event.clientX;
    const startWidth = event.currentTarget.parentElement?.getBoundingClientRect().width ?? 300;
    const move = (next: PointerEvent) => onResize(Math.min(520, Math.max(220, startWidth + next.clientX - startX)));
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <aside className="context-explorer" aria-label={`${activityLabel(activity)} explorer`}>
      <header>
        <div><span>FORGEWIRE</span><strong>{activityLabel(activity)}</strong></div>
        <button onClick={onToggle} title={collapsed ? "Expand explorer" : "Collapse explorer"} aria-label={collapsed ? "Expand explorer" : "Collapse explorer"}>
          <ChevronsLeft size={16} />
        </button>
      </header>
      {!collapsed && (
        <>
          <label className="explorer-search">
            <Search size={14} />
            <input value={filter} onChange={(event) => onFilter(event.target.value)} placeholder="Filter explorer" aria-label="Filter explorer" />
          </label>
          <div className="tree" role="tree" aria-label="Fabric objects">
            {domains.map((domain) => (
              <ExplorerDomain
                key={domain}
                domain={domain}
                route={route}
                snapshot={snapshot}
                filter={filter}
                expanded={expanded}
                onToggle={onToggleNode}
                onNavigate={onNavigate}
              />
            ))}
          </div>
          <div
            className="explorer-resizer"
            onPointerDown={resize}
            onKeyDown={(event) => {
              if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
                event.preventDefault();
                onResize(Math.min(520, Math.max(220, width + (event.key === "ArrowLeft" ? -16 : 16))));
              }
            }}
            role="separator"
            tabIndex={0}
            aria-orientation="vertical"
            aria-label="Resize explorer"
            aria-valuemin={220}
            aria-valuemax={520}
            aria-valuenow={Math.round(width)}
          />
        </>
      )}
    </aside>
  );
}

function ExplorerDomain({ domain, route, snapshot, filter, expanded, onToggle, onNavigate }: {
  domain: string;
  route: string;
  snapshot: HubSnapshot;
  filter: string;
  expanded: Set<string>;
  onToggle: (id: string) => void;
  onNavigate: (route: string) => void;
}) {
  const normalized = normalizeFabricSnapshot(snapshot);
  const sharedSection = buildExplorerSections(normalized).find((section) => section.viewId === `forgewire.${domain}`);
  const label = sharedSection?.label ?? (domain === "audit" ? "Audit Log" : domain === "overview" ? "Overview" : titleCase(domain));
  const open = expanded.has(domain) || domain === "overview";
  const sharedNodes = sharedSection?.nodes ?? [];
  const fallbackNodes = explorerNodes(domain, snapshot);
  const nodes = filterExplorerNodes(sharedNodes.length > 0 ? sharedNodes : fallbackNodes, filter);
  return (
    <section className="tree-section" role="treeitem" aria-expanded={open}>
      <button className="tree-heading" onClick={() => onToggle(domain)}>
        <ChevronDown size={15} className={open ? "" : "closed"} />
        <strong>{label}</strong>
        <span>{nodes.length || ""}</span>
      </button>
      {open && (
        <div className="tree-children" role="group">
          {nodes.map((node) => (
            <ExplorerNodeRow key={node.id} node={node} route={route} expanded={expanded} onToggle={onToggle} onNavigate={onNavigate} />
          ))}
          {nodes.length === 0 && <span className="tree-empty">{sharedSection?.emptyState?.title ?? "No matching items"}</span>}
        </div>
      )}
    </section>
  );
}

type ExplorerRenderable = ExplorerNode | { id: string; label: string; route: string; meta?: string; icon: React.ReactNode };

function filterExplorerNodes(nodes: readonly ExplorerRenderable[], filter: string): ExplorerRenderable[] {
  const needle = filter.trim().toLowerCase();
  if (!needle) return [...nodes];
  return nodes.flatMap((node) => {
    const children = "children" in node && node.children ? filterExplorerNodes(node.children, filter) : [];
    if (node.label.toLowerCase().includes(needle) || children.length > 0) {
      return [{ ...node, ...(children.length > 0 ? { children } : {}) } as ExplorerRenderable];
    }
    return [];
  });
}

function ExplorerNodeRow({ node, route, expanded, onToggle, onNavigate }: {
  node: ExplorerRenderable;
  route: string;
  expanded: Set<string>;
  onToggle: (id: string) => void;
  onNavigate: (route: string) => void;
}) {
  const children = "children" in node ? node.children ?? [] : [];
  const nodeRoute = node.route;
  const open = expanded.has(node.id);
  const description = "description" in node && typeof node.description === "string"
    ? node.description
    : "meta" in node ? node.meta : undefined;
  return (
    <div className="explorer-node">
      <button
        className={nodeRoute && route === nodeRoute ? "selected" : ""}
        onClick={() => {
          if (children.length > 0) onToggle(node.id);
          if (nodeRoute) onNavigate(nodeRoute);
        }}
        role="treeitem"
        aria-expanded={children.length > 0 ? open : undefined}
      >
        {children.length > 0 ? <ChevronDown size={13} className={open ? "" : "closed"} /> : iconForExplorerNode(node)}
        <span>{node.label}</span>{description && <small>{description}</small>}
      </button>
      {children.length > 0 && open && (
        <div className="tree-nested" role="group">
          {children.map((child) => <ExplorerNodeRow key={child.id} node={child} route={route} expanded={expanded} onToggle={onToggle} onNavigate={onNavigate} />)}
        </div>
      )}
    </div>
  );
}

function iconForExplorerNode(node: ExplorerRenderable): React.ReactNode {
  if (!("icon" in node) || React.isValidElement(node.icon)) return "icon" in node ? node.icon : <ListTree size={15} />;
  const icons: Record<string, React.ReactNode> = {
    hub: <Wifi size={15} />, host: <Server size={15} />, runner: <Cpu size={15} />,
    task: <TerminalSquare size={15} />, agent: <Bot size={15} />, approval: <ShieldCheck size={15} />,
    cost: <CircleDollarSign size={15} />, audit: <FileClock size={15} />, secret: <LockKeyhole size={15} />,
    setting: <Settings size={15} />, online: <CheckCircle2 size={15} />, warning: <AlertTriangle size={15} />,
    error: <XCircle size={15} />, empty: <ListTree size={15} />, offline: <XCircle size={15} />
  };
  return icons[String(node.icon)] ?? <ListTree size={15} />;
}

function explorerNodes(domain: string, snapshot: HubSnapshot): Array<{ id: string; label: string; route: string; meta?: string; icon: React.ReactNode }> {
  if (domain === "overview") return [{ id: "dashboard", label: "Fabric dashboard", route: "/dashboard", icon: <Gauge size={15} /> }];
  if (domain === "hub") return [
    { id: "hub-active", label: String(snapshot.health?.host ?? "Active hub"), route: "/hub/active", meta: snapshot.health?.status ?? "unknown", icon: <Wifi size={15} /> },
    { id: "cluster-active", label: "Cluster", route: "/cluster/active", meta: snapshot.cluster?.backend ?? "unknown", icon: <Database size={15} /> }
  ];
  if (domain === "hosts" || domain === "fleet") return [
    ...snapshot.hosts.flatMap((host) => {
      const hostRoute = `/hosts/${encodeURIComponent(host.hostname)}`;
      const roles = Object.keys(host.roles ?? {}).map((role) => ({ id: `host-${host.hostname}-role-${role}`, label: role, route: hostRoute, meta: "role", icon: <HardDrive size={15} /> }));
      const dispatchers = (host.dispatchers ?? []).map((dispatcher, index) => { const record = isRecord(dispatcher) ? dispatcher : {}; const id = recordId(record) || `${host.hostname}-${index + 1}`; return { id: `host-${host.hostname}-dispatcher-${index}`, label: objectLabel(dispatcher, `Dispatcher ${index + 1}`), route: `/dispatchers/${encodeURIComponent(id)}`, meta: "dispatcher", icon: <KeyRound size={15} /> }; });
      return [{ id: `host-${host.hostname}`, label: host.display_name ?? host.label ?? host.hostname, route: hostRoute, meta: host.is_active_hub ? "hub" : "host", icon: <Server size={15} /> }, ...roles, ...dispatchers];
    }),
    ...snapshot.runners.map((runner) => ({ id: `runner-${runner.runner_id}`, label: runner.alias ?? runner.runner_id, route: `/runners/${encodeURIComponent(runner.runner_id)}`, meta: `${runner.state ?? "unknown"} · runner`, icon: <Cpu size={15} /> }))
  ];
  if (domain === "tasks") {
    const grouped = [
      { id: "tasks-agent", label: "Agent Tasks", route: "/tasks/all", meta: String(snapshot.tasks.filter((task) => (task.kind ?? "agent") === "agent").length), icon: <Bot size={15} /> },
      { id: "tasks-command", label: "Command Tasks", route: "/tasks/all", meta: String(snapshot.tasks.filter((task) => task.kind === "command").length), icon: <TerminalSquare size={15} /> },
      { id: "tasks-history", label: "History", route: "/tasks/all", meta: String(snapshot.tasks.filter((task) => ["done", "failed", "cancelled", "timed_out"].includes(String(task.status))).length), icon: <History size={15} /> }
    ];
    return [...grouped, ...snapshot.tasks.slice(0, 20).map((task) => ({ id: `task-${getTaskId(task)}`, label: `#${getTaskId(task) ?? "?"} ${task.title ?? "Untitled"}`, route: `/tasks/${getTaskId(task) ?? "all"}`, meta: task.status, icon: <TerminalSquare size={15} /> }))];
  }
  if (domain === "agents") return snapshot.agents.flatMap((agent) => {
    const agentId = encodeURIComponent(agent.runner_id);
    const base = [{ id: `agent-${agent.runner_id}`, label: agent.alias ?? agent.runner_id, route: `/agents/${agentId}`, meta: agent.state, icon: <Bot size={15} /> }];
    const capabilities = (agent.mcp_manifest?.servers ?? []).flatMap((server) => [
      { id: `server-${agent.runner_id}-${server.server_id}`, label: server.server_id, route: `/agents/${agentId}`, meta: "MCP server", icon: <Network size={15} /> },
      ...(server.prompts ?? []).map((prompt) => ({ id: `prompt-${agent.runner_id}-${server.server_id}-${prompt.name}`, label: prompt.name, route: `/agents/${agentId}/capabilities/prompt/${encodeURIComponent(prompt.name)}`, meta: "prompt", icon: <Bot size={15} /> })),
      ...(server.tools ?? []).map((tool) => ({ id: `tool-${agent.runner_id}-${server.server_id}-${tool.name}`, label: tool.name, route: `/agents/${agentId}/capabilities/tool/${encodeURIComponent(tool.name)}`, meta: "tool", icon: <TerminalSquare size={15} /> })),
      ...(server.resources ?? []).map((resource) => ({ id: `resource-${agent.runner_id}-${server.server_id}-${resource.uri}`, label: resource.name ?? resource.uri, route: `/agents/${agentId}/capabilities/resource/${encodeURIComponent(resource.uri)}`, meta: "resource", icon: <Database size={15} /> }))
    ]);
    return base.concat(capabilities);
  });
  if (domain === "approvals") return snapshot.approvals.length ? snapshot.approvals.map((approval) => ({ id: `approval-${approval.approval_id}`, label: approval.task_label ?? approval.approval_id, route: `/approvals/${encodeURIComponent(approval.approval_id)}`, meta: approval.status, icon: <ShieldCheck size={15} /> })) : [{ id: "approvals-all", label: "No pending approvals", route: "/approvals/all", meta: "queue is clear", icon: <CheckCircle2 size={15} /> }];
  if (domain === "cost") return [{ id: "cost-today", label: "Today", route: "/cost", meta: money(snapshot.budget?.daily_spend_usd), icon: <CircleDollarSign size={15} /> }, { id: "cost-week", label: "This week", route: "/cost", meta: money(snapshot.budget?.weekly_spend_usd), icon: <BadgeDollarSign size={15} /> }];
  if (domain === "audit") return [{ id: "audit-tail", label: "Chain tail", route: "/audit", meta: snapshot.audit ? "available" : "not loaded", icon: <FileClock size={15} /> }, { id: "audit-tasks", label: "Task history", route: "/audit", icon: <History size={15} /> }];
  if (domain === "secrets") return [{ id: "secrets-metadata", label: "Secret metadata", route: "/secrets", meta: "values hidden", icon: <LockKeyhole size={15} /> }];
  if (domain === "settings") return [{ id: "settings-connection", label: "Connection", route: "/settings/connection", icon: <Wifi size={15} /> }, { id: "settings-identity", label: "Dispatcher identity", route: "/settings/identity", icon: <KeyRound size={15} /> }, { id: "settings-diagnostics", label: "Diagnostics", route: "/settings/diagnostics", icon: <Gauge size={15} /> }];
  return [];
}

export type WorkbenchProps = {
  api: HubApi | null; route: string; snapshot: HubSnapshot; errors: Record<string, string>; restrictions: Record<string, string>; sessionState: SessionState; freshness: Record<string, ResourceFreshness | undefined>; config: HubConfig; draft: HubConfig; tokenInput: string; fabricContext: FabricContext | null;
  hubCandidates: HubDiscoveryCandidate[]; dispatcherIdentity: DispatcherIdentitySummary | null; identityPath: string;
  identityError: string | null; busyAction: string | null; visibleTasks: TaskInfo[]; selectedTask: TaskInfo | null;
  selectedTaskId: number | null; filter: string; taskStream: TaskStreamLine[]; taskAudit: TaskAudit | null; streamError: string | null;
  onNavigate: (route: string) => void; onRefresh: () => Promise<void>; onTokenStorageChange: (present: boolean) => void; onDraft: (config: HubConfig) => void; onTokenInput: (token: string) => void; onConnect: () => void; onDiscover: () => void;
  onIdentityPath: (value: string) => void; onLoadIdentity: () => void; onSelectCandidate: (url: string) => void;
  onFilter: (value: string) => void; onSelectTask: (id: number | null) => void; onCancel: (id: number) => Promise<void>;
  onToggleDrain: (runner: RunnerInfo) => Promise<void>; onApproval: (approval: ApprovalInfo, status: "approve" | "deny") => Promise<void>;
  // 114C.7 Slice 5a: the signed-in human's own account -- see the isolation
  // note on `loadAccount` in `App()`.
  accountMe: AccountSummaryResult | null; accountSessions: SessionSummaryResult[]; accountError: string | null; accountLoading: boolean;
  onAccountRefresh: () => Promise<void>; onSignOut: () => Promise<void>; onRevokeSession: (sessionId: string) => Promise<void>;
  onSignInWithPasskey: () => Promise<void>;
  onSignInWithPassword: (username: string, password: string) => Promise<AuthResult<unknown>>;
  // 114C.7 Slice 5b: the step-up ceremony -- resolves true/false rather than
  // throwing, so a caller (a future sensitive action) can gate on the result
  // without its own try/catch.
  onStepUp: () => Promise<boolean>;
  // 114C.7 Slice 5c: admin account list + assignable-role vocabulary (`null`/
  // `[]` for a non-admin), and the five admin mutations. Each resolves an
  // `AuthResult` rather than throwing/no-op-ing, so the Administration
  // section can show the hub's own typed message on failure.
  accountsAdmin: AccountSummaryResult[] | null;
  accountRoles: string[];
  onCreateAccount: (username: string, displayName: string, password: string, role: string) => Promise<AuthResult<AccountSummaryResult>>;
  onDisableAccount: (accountId: string, expectedRevision: number) => Promise<AuthResult<AccountSummaryResult>>;
  onEnableAccount: (accountId: string, expectedRevision: number) => Promise<AuthResult<AccountSummaryResult>>;
  onGrantRole: (accountId: string, role: string) => Promise<AuthResult<AccountSummaryResult>>;
  onRevokeRole: (accountId: string, role: string) => Promise<AuthResult<AccountSummaryResult>>;
  // 114C.7 Slice 5d: two-step account deletion. Each runs a fresh step-up
  // ceremony first (opens the system browser) and uses the rotated secret
  // for the mutation itself -- see `runAccountDeletion` in `App()`.
  onDeleteAccount: (accountId: string, expectedRevision: number) => Promise<AuthResult<AccountSummaryResult>>;
  onCompleteDeletion: (accountId: string, expectedRevision: number) => Promise<AuthResult<AccountSummaryResult>>;
  // 114C.7 Slice 6e (AC-114B-5): the shared auth.ts state machine's derived
  // state, computed once in App() from the real human_accounts advertisement
  // probe -- see its own comment there.
  authState: AuthState;
};

function Workbench(props: WorkbenchProps) {
  const { route, snapshot } = props;
  if (route === "/dashboard" || route === "/explorer") return <DashboardPage {...props} />;
  if (route.startsWith("/settings")) return <SettingsPage {...props} />;
  if (route.startsWith("/tasks/")) return <TasksPage {...props} />;
  if (route.startsWith("/agents/")) return <AgentsPage {...props} />;
  if (route.startsWith("/approvals/")) return <ApprovalsPage {...props} />;
  if (route === "/cost") return <CostPage snapshot={snapshot} />;
  if (route.startsWith("/audit")) return <AuditPage {...props} />;
  if (route === "/secrets") return <SecretsPage {...props} />;
  if (route.startsWith("/account")) return <AccountPage {...props} />;
  return <FleetPage {...props} />;
}

function DashboardPage({ snapshot, onNavigate }: WorkbenchProps) {
  const online = snapshot.runners.filter((runner) => runner.state === "online").length;
  const running = snapshot.tasks.filter((task) => task.status === "running").length;
  const queued = snapshot.tasks.filter((task) => task.status === "queued").length;
  const failed = snapshot.tasks.filter((task) => ["failed", "timed_out"].includes(String(task.status))).length;
  const approvals = snapshot.approvals.filter((approval) => approval.status === "pending").length;
  const metrics = [
    { route: "/hub/active", icon: <Wifi />, label: "Hub", value: snapshot.health?.status ?? "unknown", detail: versionLabel(snapshot) },
    { route: "/hub/active", icon: <Cpu />, label: "Runners online", value: `${online}/${snapshot.runners.length}`, detail: `${snapshot.hosts.length} hosts` },
    { route: "/agents/all", icon: <Bot />, label: "Agents", value: String(snapshot.agents.length), detail: agentCapabilityCount(snapshot.agents) },
    { route: "/tasks/all", icon: <TerminalSquare />, label: "Tasks", value: `${running} running`, detail: `${queued} queued, ${failed} failed` },
    { route: "/approvals/all", icon: <AlertTriangle />, label: "Approvals", value: String(approvals), detail: "pending operator decisions" },
    { route: "/cost", icon: <CircleDollarSign />, label: "Budget", value: money(snapshot.budget?.daily_spend_usd), detail: budgetDetail(snapshot) }
  ];
  return (
    <div className="page-stack">
      <section className="metric-grid" aria-label="Fabric overview">
        {metrics.map((metric) => <button className="metric-button" key={metric.label} onClick={() => onNavigate(metric.route)}><Metric {...metric} /></button>)}
      </section>
      <section className="split-layout">
        <Panel title="Operator exceptions" action={`${failed + approvals} need attention`}>
          <div className="exception-list">
            {failed > 0 && <button onClick={() => onNavigate("/tasks/all")}><XCircle size={17} /><span><strong>{failed} failed tasks</strong><small>Inspect failures and audit evidence</small></span></button>}
            {approvals > 0 && <button onClick={() => onNavigate("/approvals/all")}><AlertTriangle size={17} /><span><strong>{approvals} pending approvals</strong><small>Operator decision required</small></span></button>}
            {failed + approvals === 0 && <EmptyState label="No high-priority operator exceptions." />}
          </div>
        </Panel>
        <Panel title="Audit and cluster" action={snapshot.cluster?.backend ?? "backend unknown"}>
          <div className="audit-grid">
            <InfoLine label="rqlite" value={snapshot.cluster?.rqlite ? `${snapshot.cluster.rqlite.host}:${snapshot.cluster.rqlite.port}` : "not reported"} />
            <InfoLine label="audit tail" value={snapshot.audit ? "available" : "not loaded"} />
            <InfoLine label="labels" value={snapshot.cluster?.labels_snapshot?.status ?? "unknown"} />
            <InfoLine label="hub host" value={String(snapshot.health?.host ?? "unknown")} />
          </div>
        </Panel>
      </section>
    </div>
  );
}

function FleetPage({ api, snapshot, route, busyAction, onToggleDrain, onNavigate, onRefresh }: WorkbenchProps) {
  const selectedRunnerId = route.startsWith("/runners/") ? decodeURIComponent(route.slice(9)) : null;
  const selectedHostId = route.startsWith("/hosts/") ? decodeURIComponent(route.slice(7)) : null;
  const selectedDispatcherId = route.startsWith("/dispatchers/") ? decodeURIComponent(route.slice(13)) : null;
  const selectedRunner = snapshot.runners.find((runner) => runner.runner_id === selectedRunnerId);
  const selectedHost = snapshot.hosts.find((host) => host.hostname === selectedHostId);
  const dispatchers = collectDispatchers(snapshot);
  const selectedDispatcher = dispatchers.find((dispatcher) => recordId(dispatcher) === selectedDispatcherId);
  const [label, setLabel] = useState("");
  const [mutation, setMutation] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  useEffect(() => {
    setLabel(selectedRunner?.alias ?? selectedHost?.display_name ?? selectedHost?.label ?? "");
    setMutationError(null);
  }, [selectedRunnerId, selectedHostId]);

  const renameTarget = selectedRunner ? { kind: "runner" as const, id: selectedRunner.runner_id }
    : selectedHost ? { kind: "host" as const, id: selectedHost.hostname }
      : route === "/hub/active" ? { kind: "hub" as const, id: null } : null;
  const rename = async () => {
    if (!api || !renameTarget) return;
    setMutation("rename"); setMutationError(null);
    try { await api.renameEntity(renameTarget.kind, renameTarget.id, label); await onRefresh(); }
    catch (error) { setMutationError(error instanceof Error ? error.message : String(error)); }
    finally { setMutation(null); }
  };

  return <div className="page-stack"><section className="split-layout fleet-layout">
    <Panel title="Fabric topology" action={`${snapshot.hosts.length} hosts · ${snapshot.runners.length} runners`}>
      <div className="topology-list">
        <button className={route === "/hub/active" ? "selected" : ""} onClick={() => onNavigate("/hub/active")}><Wifi size={16} /><span><strong>{String(snapshot.health?.host ?? "Active hub")}</strong><small>{snapshot.health?.status ?? "unknown"} · {versionLabel(snapshot)}</small></span></button>
        <button className={route === "/cluster/active" ? "selected" : ""} onClick={() => onNavigate("/cluster/active")}><Database size={16} /><span><strong>Cluster</strong><small>{snapshot.cluster?.backend ?? "unknown backend"}</small></span></button>
        {snapshot.hosts.map((host) => <button key={host.hostname} className={selectedHostId === host.hostname ? "selected" : ""} onClick={() => onNavigate(`/hosts/${encodeURIComponent(host.hostname)}`)}><Server size={16} /><span><strong>{host.display_name ?? host.label ?? host.hostname}</strong><small>{host.hostname} · {Object.keys(host.roles ?? {}).join(", ") || "no roles"}</small></span></button>)}
        {snapshot.runners.map((runner) => <button key={runner.runner_id} className={selectedRunnerId === runner.runner_id ? "selected" : ""} onClick={() => onNavigate(`/runners/${encodeURIComponent(runner.runner_id)}`)}><Cpu size={16} /><span><strong>{runner.alias ?? runner.runner_id}</strong><small>{runner.hostname ?? "unknown host"} · {runner.state ?? "unknown"}</small></span></button>)}
        {dispatchers.map((dispatcher, index) => { const id = recordId(dispatcher) || `dispatcher-${index + 1}`; return <button key={id} className={selectedDispatcherId === id ? "selected" : ""} onClick={() => onNavigate(`/dispatchers/${encodeURIComponent(id)}`)}><KeyRound size={16} /><span><strong>{objectLabel(dispatcher, id)}</strong><small>{stringField(dispatcher, "source") || "dispatcher"}</small></span></button>; })}
      </div>
    </Panel>
    <Panel title={fleetDetailTitle(route, selectedRunner, selectedHost, selectedDispatcher)} action={selectedRunner?.state ?? snapshot.health?.status ?? "unknown"}>
      {selectedRunner ? <div className="detail-stack"><div className="audit-grid"><InfoLine label="runner id" value={selectedRunner.runner_id} /><InfoLine label="state" value={selectedRunner.state ?? "unknown"} /><InfoLine label="host" value={selectedRunner.hostname ?? "unknown"} /><InfoLine label="load" value={`${selectedRunner.current_load ?? 0}/${selectedRunner.max_concurrent ?? "?"}`} /><InfoLine label="heartbeat" value={formatMaybeDate(selectedRunner.last_heartbeat)} /><InfoLine label="workspace" value={selectedRunner.workspace_root ?? "not reported"} /><InfoLine label="tenant" value={selectedRunner.tenant ?? "default"} /><InfoLine label="scope prefixes" value={(selectedRunner.scope_prefixes ?? []).join(", ") || "none reported"} /></div><button className="secondary-command" onClick={() => void onToggleDrain(selectedRunner)} disabled={Boolean(busyAction)}>{selectedRunner.drain_requested ? <Undo2 size={15} /> : <PauseCircle size={15} />}{selectedRunner.drain_requested ? "Clear drain" : "Request drain"}</button></div>
        : selectedHost ? <div className="detail-stack"><div className="audit-grid"><InfoLine label="hostname" value={selectedHost.hostname} /><InfoLine label="display" value={selectedHost.display_name ?? selectedHost.label ?? "not labeled"} /><InfoLine label="active hub" value={selectedHost.is_active_hub ? "yes" : "no"} /><InfoLine label="roles" value={Object.keys(selectedHost.roles ?? {}).join(", ") || "none reported"} /><InfoLine label="runners" value={String(selectedHost.runners?.length ?? snapshot.runners.filter((runner) => runner.hostname === selectedHost.hostname).length)} /><InfoLine label="dispatchers" value={String(selectedHost.dispatchers?.length ?? 0)} /></div></div>
          : selectedDispatcher ? <RecordDetail value={selectedDispatcher} empty="No dispatcher fields were returned." />
            : route === "/cluster/active" ? <RecordDetail value={snapshot.cluster as Record<string, unknown> | null} empty="Cluster detail is unavailable." />
              : <div className="audit-grid"><InfoLine label="version" value={versionLabel(snapshot)} /><InfoLine label="protocol" value={String(snapshot.health?.protocol_version ?? "unknown")} /><InfoLine label="backend" value={snapshot.cluster?.backend ?? "unknown"} /><InfoLine label="uptime" value={formatDuration(snapshot.health?.uptime_seconds)} /><InfoLine label="started" value={typeof snapshot.health?.started_at === "number" ? new Date(snapshot.health.started_at * 1000).toLocaleString() : "not reported"} /></div>}
      {renameTarget && <div className="governance-form"><label>Display label<input value={label} maxLength={80} onChange={(event) => setLabel(event.target.value)} /></label><button className="primary-command" onClick={() => void rename()} disabled={!api || mutation === "rename"}>Rename</button><small>Authenticated label mutation; the hub records the desktop actor.</small>{mutationError && <span className="inline-error">{mutationError}</span>}</div>}
    </Panel>
  </section></div>;
}

function TasksPage(props: WorkbenchProps) {
  const { api, visibleTasks, selectedTask, selectedTaskId, filter, taskStream, taskAudit, streamError, busyAction, onFilter, onSelectTask, onCancel, onRefresh } = props;
  const [detail, setDetail] = useState<TaskInfo | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [redispatching, setRedispatching] = useState(false);
  useEffect(() => {
    let cancelled = false;
    setDetail(null); setDetailError(null);
    if (!api || selectedTaskId === null) return;
    void api.taskDetail(selectedTaskId).then((value) => { if (!cancelled) setDetail(value); }).catch((error) => { if (!cancelled) setDetailError(error instanceof Error ? error.message : String(error)); });
    return () => { cancelled = true; };
  }, [api, selectedTaskId]);
  const redispatch = async () => {
    if (!api || selectedTaskId === null || !window.confirm(`Redispatch task #${selectedTaskId} as a new signed task?`)) return;
    setRedispatching(true); setDetailError(null);
    try { await api.redispatchTask(selectedTaskId); await onRefresh(); }
    catch (error) { setDetailError(error instanceof Error ? error.message : String(error)); }
    finally { setRedispatching(false); }
  };
  const agentTasks = visibleTasks.filter((task) => (task.kind ?? "agent") === "agent");
  const commandTasks = visibleTasks.filter((task) => task.kind === "command");
  const history = visibleTasks.filter((task) => ["done", "failed", "cancelled", "timed_out"].includes(String(task.status)));
  return <div className="page-stack"><section className="task-layout">
    <Panel title="Task collections" action={<label className="search"><Search size={15} /><input value={filter} onChange={(event) => onFilter(event.target.value)} placeholder="Filter" /></label>}><div className="task-collections"><TaskCollection label="Agent Tasks" contract="Signed prompt / skill / tool brief" tasks={agentTasks} selectedTaskId={selectedTaskId} onSelect={onSelectTask} /><TaskCollection label="Command Tasks" contract="Explicit Loom command-token contract" tasks={commandTasks} selectedTaskId={selectedTaskId} onSelect={onSelectTask} /><TaskCollection label="History" contract="Terminal tasks from both integrity paths" tasks={history} selectedTaskId={selectedTaskId} onSelect={onSelectTask} />{visibleTasks.length === 0 && <EmptyState label="No tasks match the current filter." />}</div></Panel>
    <Panel title="Task Detail" action={selectedTaskId !== null ? `#${selectedTaskId}` : "none"}>{detailError && <div className="inline-error" role="alert">Detail read: {detailError}</div>}{selectedTask ? <TaskDetail task={{ ...selectedTask, ...detail }} stream={taskStream} audit={taskAudit} streamError={streamError} busyCancel={busyAction === `cancel-task-${getTaskId(selectedTask)}`} onCancel={onCancel} onRedispatch={() => void redispatch()} redispatching={redispatching} /> : selectedTaskId !== null ? <Tombstone label={`Task #${selectedTaskId} is no longer present in the current snapshot.`} /> : <EmptyState label="Select a task to inspect its routing and provenance." />}</Panel>
  </section></div>;
}

function TaskCollection({ label, contract, tasks, selectedTaskId, onSelect }: { label: string; contract: string; tasks: TaskInfo[]; selectedTaskId: number | null; onSelect: (id: number | null) => void }) {
  return <section className="task-collection"><header><div><strong>{label}</strong><small>{contract}</small></div><span>{tasks.length}</span></header><div className="task-table" role="table">{tasks.map((task) => { const id = getTaskId(task); return <button className={`task-row ${id === selectedTaskId ? "selected" : ""}`} key={`${label}-${id ?? task.title}`} onClick={() => onSelect(id)}><span className="task-id">#{id ?? "?"}</span><span className="task-title">{task.title ?? "Untitled task"}</span><span className="task-kind">{task.kind ?? "agent"}</span><StatusPill status={task.status ?? "unknown"} compact /></button>; })}{tasks.length === 0 && <span className="collection-empty">No {label.toLowerCase()} in this view.</span>}</div></section>;
}

function AgentsPage({ api, snapshot, route, onNavigate }: WorkbenchProps) {
  const parts = route.split("/").filter(Boolean).map(decodeURIComponent);
  const selected = snapshot.agents.find((agent) => agent.runner_id === parts[1]);
  const capabilityKind = parts[3];
  const capabilityName = parts[4];
  const [capability, setCapability] = useState<Record<string, unknown> | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false; setCapability(null); setDetailError(null);
    if (!api || !capabilityKind || !capabilityName) return;
    void api.capabilityDetail(capabilityKind, capabilityName).then((value) => { if (!cancelled) setCapability(value); }).catch((error) => { if (!cancelled) setDetailError(error instanceof Error ? error.message : String(error)); });
    return () => { cancelled = true; };
  }, [api, capabilityKind, capabilityName]);
  return <div className="page-stack"><section className="split-layout"><Panel title="Fabric agents" action={`${snapshot.agents.length} registered`}><div className="agent-grid">{snapshot.agents.map((agent) => <button className={`agent-button ${selected?.runner_id === agent.runner_id ? "selected" : ""}`} key={agent.runner_id} onClick={() => onNavigate(`/agents/${encodeURIComponent(agent.runner_id)}`)}><AgentCard agent={agent} /></button>)}{snapshot.agents.length === 0 && <EmptyState label="No Fabric agents are advertising MCP manifests." />}</div></Panel><Panel title={capabilityName ?? selected?.alias ?? selected?.runner_id ?? "Agent detail"} action={capabilityKind ?? selected?.state ?? "select an agent"}>{selected ? <div className="detail-stack"><div className="audit-grid"><InfoLine label="agent type" value={selected.agent_type ?? "agent"} /><InfoLine label="host" value={selected.hostname ?? "unknown"} /><InfoLine label="state" value={selected.state ?? "unknown"} /><InfoLine label="MCP version" value={String(selected.mcp_manifest_version ?? "not reported")} /><InfoLine label="MCP servers" value={String(selected.mcp_manifest?.servers?.length ?? 0)} /><InfoLine label="tenant" value={selected.tenant ?? "default"} /><InfoLine label="workspace" value={selected.workspace_root ?? "not reported"} /></div>{capabilityName && <section className="capability-detail"><header><Network size={17} /><div><strong>{capabilityName}</strong><small>{capabilityKind} · advertised MCP manifest</small></div></header>{detailError ? <AuthorizationOrFailure message={detailError} /> : capability ? <RecordDetail value={capability} empty="Capability returned no detail fields." /> : <EmptyState label="Loading capability detail…" />}</section>}{!capabilityName && <McpManifestDetail agent={selected} onNavigate={onNavigate} />}</div> : parts[1] && parts[1] !== "all" ? <Tombstone label={`Agent ${parts[1]} is no longer advertising in the current snapshot.`} /> : <EmptyState label="Choose an agent or advertised MCP capability in the explorer." />}</Panel></section></div>;
}

function ApprovalsPage({ api, snapshot, route, errors, restrictions, accountMe, onApproval, onNavigate, onRefresh }: WorkbenchProps) {
  const selectedId = route.startsWith("/approvals/") && !route.endsWith("/all") ? decodeURIComponent(route.slice(11)) : null;
  const selected = snapshot.approvals.find((approval) => approval.approval_id === selectedId);
  const approvalIssue = restrictions.approvals
    ? `${restrictions.approvals}${accountRoleContextNote(accountMe?.roles ?? null)}`
    : errors.approvals;
  const denied = Boolean(restrictions.approvals) || authorizationDenied(approvalIssue);
  const [detail, setDetail] = useState<ApprovalInfo | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [deferred, setDeferred] = useState<Set<string>>(() => new Set());
  const [deciding, setDeciding] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false; setDetail(null); setDetailError(null); setReason("");
    if (!api || !selectedId) return;
    void api.approvalDetail(selectedId).then((value) => { if (!cancelled) setDetail(value); }).catch((error) => { if (!cancelled) setDetailError(error instanceof Error ? error.message : String(error)); });
    return () => { cancelled = true; };
  }, [api, selectedId]);
  const decide = async (approve: boolean) => {
    const target = detail ?? selected;
    if (!api || !target) return;
    if (!approve && !reason.trim()) { setDetailError("A denial reason is required."); return; }
    if (!window.confirm(`${approve ? "Approve" : "Deny"} ${target.task_label ?? target.approval_id}? This decision is audited.`)) return;
    setDeciding(approve ? "approve" : "deny"); setDetailError(null);
    try {
      const decision = { approver: "fabric-desktop", reason: reason.trim() || "approved after desktop examination" };
      if (approve) await api.approveApproval(target.approval_id, decision); else await api.denyApproval(target.approval_id, decision);
      await onRefresh();
    } catch (error) { setDetailError(error instanceof Error ? error.message : String(error)); }
    finally { setDeciding(null); }
  };
  const deferSelected = () => {
    if (!selectedId) return;
    setDeferred((current) => new Set(current).add(selectedId));
    onNavigate("/approvals/all");
  };
  const visible = snapshot.approvals.filter((approval) => !deferred.has(approval.approval_id));
  return <div className="page-stack"><section className="split-layout"><Panel title="Approvals" action={`${snapshot.approvals.filter((approval) => approval.status === "pending").length} pending`}><div className="approval-list">{visible.map((approval) => <button className={`approval-row approval-select ${selectedId === approval.approval_id ? "selected" : ""}`} key={approval.approval_id} onClick={() => onNavigate(`/approvals/${encodeURIComponent(approval.approval_id)}`)}><div><strong>{approval.task_label ?? approval.approval_id}</strong><span>{approval.branch ?? "no branch"}</span></div><StatusPill status={approval.status} compact /></button>)}{deferred.size > 0 && <button className="deferred-summary" onClick={() => setDeferred(new Set())}><Clock3 size={15} />{deferred.size} deferred for this review · restore</button>}{denied ? <AuthorizationState message={approvalIssue} /> : visible.length === 0 && <EmptyState label="No active approvals in this review." />}</div></Panel><Panel title="Decision examination" action={(detail ?? selected)?.status ?? "select an approval"}>{selected ? <div className="detail-stack"><div className="audit-grid"><InfoLine label="approval id" value={selected.approval_id} /><InfoLine label="task" value={(detail ?? selected).task_label ?? "not reported"} /><InfoLine label="requested by" value={(detail ?? selected).requested_by ?? "not reported"} /><InfoLine label="branch" value={(detail ?? selected).branch ?? "not reported"} /><InfoLine label="scope" value={approvalScope(detail ?? selected)} /><InfoLine label="created" value={formatMaybeDate((detail ?? selected).created_at)} /><InfoLine label="risk" value={(detail ?? selected).risk ?? "not classified"} /></div>{(detail ?? selected).prompt && <div className="payload-box"><span>requested operation</span><pre>{(detail ?? selected).prompt}</pre></div>}<label className="decision-reason">Decision reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Required for denial; recommended for approval" /></label><div className="approval-decision-row"><button onClick={deferSelected}><Clock3 size={15} />Defer review</button><button className="danger-action" onClick={() => void decide(false)} disabled={Boolean(deciding)}>Deny</button><button className="primary-command" onClick={() => void decide(true)} disabled={Boolean(deciding)}>Approve</button></div>{detailError && <AuthorizationOrFailure message={detailError} />}</div> : selectedId ? <Tombstone label={`Approval ${selectedId} is no longer present in the current snapshot.`} /> : <EmptyState label="Select an approval to examine provenance, scope, and risk before deciding." />}</Panel></section></div>;
}

function CostPage({ snapshot }: { snapshot: HubSnapshot }) {
  return <div className="page-stack"><section className="metric-grid"><Metric icon={<CircleDollarSign />} label="Today" value={money(snapshot.budget?.daily_spend_usd)} detail={typeof snapshot.budget?.daily_budget_usd === "number" ? `${money(snapshot.budget.daily_budget_usd)} budget` : "daily cap not set"} /><Metric icon={<BadgeDollarSign />} label="This week" value={money(snapshot.budget?.weekly_spend_usd)} detail={typeof snapshot.budget?.weekly_budget_usd === "number" ? `${money(snapshot.budget.weekly_budget_usd)} budget` : "weekly cap not set"} /><Metric icon={<AlertTriangle />} label="Posture" value={snapshot.budget?.weekly_alert ? "Alert" : "Normal"} detail={budgetDetail(snapshot)} /></section><section className="split-layout"><Panel title="Budget envelope" action={snapshot.budget?.weekly_alert ? "attention" : "within posture"}><div className="audit-grid"><InfoLine label="daily spend" value={money(snapshot.budget?.daily_spend_usd)} /><InfoLine label="daily remaining" value={money(snapshot.budget?.daily_remaining_usd)} /><InfoLine label="daily utilization" value={percent(snapshot.budget?.daily_pct)} /><InfoLine label="weekly spend" value={money(snapshot.budget?.weekly_spend_usd)} /><InfoLine label="weekly remaining" value={money(snapshot.budget?.weekly_remaining_usd)} /><InfoLine label="weekly utilization" value={percent(snapshot.budget?.weekly_pct)} /></div></Panel><Panel title="Attribution breakdown" action="hub-reported"><RecordDetail value={snapshot.cost ?? null} empty="The hub did not return a provider, model, agent, or task cost breakdown." /></Panel></section></div>;
}

function AuditPage({ api, snapshot, taskAudit, errors, restrictions, accountMe, route }: WorkbenchProps) {
  const routeDay = route.match(/^\/audit\/(\d{4}-\d{2}-\d{2})$/)?.[1];
  const [day, setDay] = useState(routeDay ?? new Date().toISOString().slice(0, 10));
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const load = useCallback(async () => {
    if (!api) return;
    setFailure(null);
    try { setResult(await api.auditDay(day)); }
    catch (error) { setResult(null); setFailure(error instanceof Error ? error.message : String(error)); }
  }, [api, day]);
  useEffect(() => { void load(); }, [load]);
  const tailVerified = snapshot.audit?.verified;
  const dayVerified = typeof result?.verified === "boolean" ? result.verified : undefined;
  const events = Array.isArray(result?.events) ? result.events as Array<Record<string, unknown>> : [];
  const readFailure = restrictions.audit
    ? `${restrictions.audit}${accountRoleContextNote(accountMe?.roles ?? null)}`
    : errors.audit ?? failure;
  return <div className="page-stack"><section className="audit-verification-banner"><ShieldCheck size={22} /><div><strong>{readFailure ? "Audit read failed" : tailVerified === false || dayVerified === false ? "Audit verification failed" : tailVerified || dayVerified ? "Audit chain verified" : "Audit verification unavailable"}</strong><span>{readFailure ? "No success is implied; inspect authorization or transport failure below." : "Verification state is reported explicitly and never inferred from a non-empty event list."}</span></div></section>{readFailure && <AuthorizationOrFailure message={readFailure} />}<section className="split-layout"><Panel title="Verification posture" action={tailVerified === true ? "verified" : tailVerified === false ? "failed" : "unknown"}><div className="audit-grid"><InfoLine label="chain tail" value={snapshot.audit ? "loaded" : "not loaded"} /><InfoLine label="tail verification" value={tailVerified === true ? "verified" : tailVerified === false ? "FAILED" : "not reported"} /><InfoLine label="selected task" value={taskAudit ? auditSummary(taskAudit) : "select a task"} /><InfoLine label="labels snapshot" value={snapshot.cluster?.labels_snapshot?.status ?? "unknown"} /><InfoLine label="backend" value={snapshot.cluster?.backend ?? "unknown"} /></div></Panel><Panel title="Audit day" action={dayVerified === true ? "verified" : dayVerified === false ? "failed" : `${events.length} events`}><div className="audit-day-controls"><label>UTC day<input type="date" value={day} onChange={(event) => setDay(event.target.value)} /></label><button onClick={() => void load()}><RefreshCw size={15} />Load</button></div><div className="audit-day-events">{events.map((event, index) => <article key={String(event.hash ?? event.id ?? index)}><strong>{String(event.kind ?? event.event_type ?? "event")}</strong><span>{formatMaybeDate(String(event.created_at ?? event.ts ?? ""))}</span><code>{String(event.hash ?? "no event hash")}</code></article>)}{events.length === 0 && !readFailure && <EmptyState label="No events returned for this UTC day." />}</div></Panel></section></div>;
}

function SecretsPage({ api, snapshot, errors, restrictions, accountMe, onRefresh }: WorkbenchProps) {
  const [name, setName] = useState("");
  const [action, setAction] = useState<"put" | "rotate" | "delete">("put");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const submit = async () => {
    if (!api || !name.trim()) return;
    if (action !== "delete" && !value) { setNotice("A transient secret value is required."); return; }
    if (action === "delete" && !window.confirm(`Delete governed secret metadata and value for ${name.trim()}?`)) return;
    setBusy(true); setNotice(null);
    try { await api.governSecret(name.trim(), action, value); setValue(""); setNotice(`${name.trim()} ${action === "delete" ? "deleted" : action === "rotate" ? "rotated" : "stored"}; value cleared from the form.`); await onRefresh(); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setValue(""); setBusy(false); }
  };
  const secretIssue = restrictions.secrets
    ? `${restrictions.secrets}${accountRoleContextNote(accountMe?.roles ?? null)}`
    : errors.secrets;
  return <div className="page-stack"><Panel title="Secrets" action="governed metadata"><div className="security-notice"><LockKeyhole size={24} /><div><strong>Secret values are never rendered or persisted</strong><p>Only metadata crosses the read path. Mutation values remain in component memory until native IPC accepts or rejects them, then the field is cleared.</p></div></div>{secretIssue && <AuthorizationOrFailure message={secretIssue} />}<div className="secret-grid"><section className="secret-list">{(snapshot.secrets ?? []).map((secret, index) => <article key={recordId(secret) || index}><KeyRound size={16} /><div><strong>{objectLabel(secret, `Secret ${index + 1}`)}</strong><small>{stringField(secret, "provider") || stringField(secret, "source") || "protected store"} · {stringField(secret, "updated_at") || "rotation not reported"}</small></div><StatusPill status={stringField(secret, "status") || "available"} compact /></article>)}{(snapshot.secrets ?? []).length === 0 && !secretIssue && <EmptyState label="No secret metadata was returned by the current desktop API." />}</section><section className="governance-form"><h4>Govern secret</h4><label>Secret name<input value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" /></label><label>Action<select value={action} onChange={(event) => { setAction(event.target.value as typeof action); setValue(""); }}><option value="put">Store</option><option value="rotate">Rotate</option><option value="delete">Delete</option></select></label>{action !== "delete" && <label>Transient value<input type="password" value={value} onChange={(event) => setValue(event.target.value)} autoComplete="new-password" /></label>}<button className={action === "delete" ? "danger-action" : "primary-command"} onClick={() => void submit()} disabled={busy || !name.trim()}>{action === "delete" ? "Delete secret" : action === "rotate" ? "Rotate secret" : "Store secret"}</button>{notice && <span role="status" className={notice.includes("cleared") ? "inline-success" : "inline-error"}>{notice}</span>}</section></div></Panel></div>;
}

/**
 * 114C.7 Slice 5a/5b/5c: self-service Account page -- profile, roles, active
 * sessions (with Sign Out / Revoke Session), Step Up, an Administration
 * section for a signed-in admin (Create Account, per-account Disable/
 * Enable, Grant/Revoke Role), or a sign-in affordance when no human session
 * is stored. Mirrors the VSIX Account tree view's scope exactly (114C.7
 * Slice 4a/4b/4c/4c-3a).
 */
function SettingsPage({ api, snapshot, draft, config, tokenInput, fabricContext, hubCandidates, dispatcherIdentity, identityPath, identityError, busyAction, errors, restrictions, freshness, sessionState, onDraft, onTokenInput, onConnect, onDiscover, onIdentityPath, onLoadIdentity, onSelectCandidate, onRefresh, onTokenStorageChange }: WorkbenchProps) {
  const [pin, setPin] = useState(config.hubUrl);
  const [governanceBusy, setGovernanceBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [update, setUpdate] = useState<import("./types").DesktopUpdateStatus | null>(null);
  const removeToken = async () => {
    if (!window.confirm("Remove the installed desktop hub token? The value cannot be recovered from the UI.")) return;
    setGovernanceBusy("remove"); setNotice(null);
    try { const result = await removeHubToken(); onTokenStorageChange(result.present); setNotice("Protected token removed."); await onRefresh(); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setGovernanceBusy(null); }
  };
  const applyPin = async (value: string | null) => {
    setGovernanceBusy("pin"); setNotice(null);
    try { await persistHubPin(value); setNotice(value ? `Pinned hub discovery to ${normalizeHubUrl(value)}.` : "Hub pin cleared; ranked discovery is active."); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setGovernanceBusy(null); }
  };
  const checkUpdate = async () => {
    setGovernanceBusy("update-check"); setNotice(null);
    try { const result = await checkForDesktopUpdate(); setUpdate(result); setNotice(result.message); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setGovernanceBusy(null); }
  };
  const installUpdate = async () => {
    if (!update?.available || !window.confirm(`Install signed ForgeWire Fabric Desktop ${update.version}? The signature is verified before installation. Keep the previous signed installer for rollback.`)) return;
    setGovernanceBusy("update-install"); setNotice(null);
    try { setNotice(await installVerifiedDesktopUpdate()); }
    catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setGovernanceBusy(null); }
  };
  return <div className="page-stack settings-grid">
    <Panel title="Hub connection" action={config.hubUrl || "not configured"}><div className="settings-form"><div className="context-summary"><strong>{fabricContext ? "Installed Fabric context" : "Manual/browser context"}</strong><span>Hub: {fabricContext?.hub_source ?? "local settings"}</span><span>Token: {fabricContext?.token_source ?? (config.tokenPresent ? "installed in protected storage" : "not loaded")}</span><span>Identity: {fabricContext?.identity_source ?? (dispatcherIdentity ? "desktop dedicated identity" : "not loaded")}</span></div><label>Install cluster-issued bearer token<input value={tokenInput} onChange={(event) => onTokenInput(event.target.value)} placeholder={config.tokenPresent ? "Protected token is installed" : "Enter token from cluster bootstrap"} type="password" autoComplete="new-password" /></label><span className="credential-note">Token input remains transient and is cleared after native protected storage accepts it. Desktop does not generate disconnected credentials: create or rotate the cluster token through the service bootstrap workflow, then install that value here.</span><label>Hub URL<input value={draft.hubUrl} onChange={(event) => onDraft({ ...draft, hubUrl: event.target.value })} placeholder="http://127.0.0.1:8765" /></label><div className="button-row"><button className="primary" onClick={onConnect} disabled={busyAction === "save-connection"}><KeyRound size={16} />Save connection</button><button onClick={onDiscover} disabled={busyAction === "discover-hubs"}><Wifi size={16} />Discover</button><button className="danger-action" onClick={() => void removeToken()} disabled={!config.tokenPresent || Boolean(governanceBusy)}>Remove token</button></div>{hubCandidates.length > 0 && <div className="candidate-list">{hubCandidates.map((candidate) => <button key={candidate.url} onClick={() => onSelectCandidate(candidate.url)}><strong>{candidate.label}</strong><span>{candidate.version ?? "version unknown"} · {candidate.reachable ? "reachable" : candidate.error ?? "unreachable"}</span></button>)}</div>}{(fabricContext?.warnings ?? []).length > 0 && <div className="context-warnings">{fabricContext?.warnings?.map((warning) => <span key={warning}>{warning}</span>)}</div>}</div></Panel>
    <Panel title="Dispatcher identity" action={dispatcherIdentity?.id ?? "not loaded"}><div className="settings-form"><label>Dispatcher identity file<input value={identityPath} onChange={(event) => onIdentityPath(event.target.value)} placeholder="C:\\Users\\you\\.forgewire\\dispatcher.json" /></label><button className="primary-command" onClick={onLoadIdentity} disabled={!identityPath.trim()}><KeyRound size={16} />Load identity</button>{dispatcherIdentity && <div className="identity-summary"><strong>{dispatcherIdentity.id}</strong><span>purpose: {dispatcherIdentity.purpose}</span><span>{dispatcherIdentity.public_key_hex.slice(0, 16)}...</span></div>}{identityError && <span className="inline-error">{identityError}</span>}</div></Panel>
    <Panel title="Discovery pin" action="explicit failover preference"><div className="settings-form"><label>Hub URL to pin<input value={pin} onChange={(event) => setPin(event.target.value)} placeholder="http://host:8765" /></label><div className="button-row"><button className="primary-command" onClick={() => void applyPin(pin)} disabled={!pin.trim() || Boolean(governanceBusy)}>Pin hub</button><button onClick={() => void applyPin(null)} disabled={Boolean(governanceBusy)}>Clear pin</button></div><span className="credential-note">Pinning changes discovery preference only; it does not weaken authorization or health checks.</span></div></Panel>
    <Panel title="Doctor diagnostics" action={sessionState}><div className="doctor-grid"><InfoLine label="session" value={sessionState} /><InfoLine label="native token" value={config.tokenPresent ? "installed" : "missing"} /><InfoLine label="dispatcher identity" value={dispatcherIdentity ? "ready" : "unavailable"} />{Object.keys(freshness).sort().map((resource) => <InfoLine key={resource} label={resource} value={restrictions[resource] ? `RESTRICTED: ${restrictions[resource]}` : errors[resource] ? `FAILED: ${errors[resource]}` : freshness[resource]?.source === "last-good" ? "stale · last-good" : freshness[resource] ? "fresh" : "not read"} />)}</div><button onClick={() => void onRefresh()}><RefreshCw size={15} />Run diagnostics now</button></Panel>
    <Panel title="Hub-wide settings" action={`revision ${String(snapshot.hub_settings?.revision ?? 0)}`}><div className="settings-form"><span className="credential-note">These are the schema-validated hub settings after defaults and the rqlite overlay are merged. Sensitive keys are redacted by the hub. Mutations require reviewer authority and revision compare-and-swap through the native CLI.</span>{errors.hub_settings ? <AuthorizationOrFailure message={errors.hub_settings} /> : <pre className="payload-box">{JSON.stringify(snapshot.hub_settings?.effective ?? {}, null, 2)}</pre>}<div className="doctor-grid"><InfoLine label="history mode" value={String(snapshot.history?.mode ?? "thin")} /><InfoLine label="history health" value={String(snapshot.history?.health ?? "disabled")} /><InfoLine label="exported this tick" value={String(snapshot.history?.exported ?? 0)} /></div></div></Panel>
    <Panel title="Desktop updates" action={update?.configured ? "signed stable channel" : "not checked"}><div className="settings-form"><span className="credential-note">Updates are checked only when requested. Installation requires confirmation and the native updater verifies the release signature before running an installer.</span>{update && <div className="doctor-grid"><InfoLine label="current" value={update.current_version} /><InfoLine label="available" value={update.available ? update.version ?? "new release" : "none"} /><InfoLine label="updater key" value={update.configured ? "embedded" : "missing in this build"} />{update.published_at && <InfoLine label="published" value={update.published_at} />}</div>}<div className="button-row"><button onClick={() => void checkUpdate()} disabled={Boolean(governanceBusy)}><RefreshCw size={15} />Check signed channel</button><button className="primary-command" onClick={() => void installUpdate()} disabled={!update?.available || Boolean(governanceBusy)}>Install verified update</button></div><span className="credential-note">Rollback: uninstall only the desktop client, install the previous signed desktop artifact, and retain Fabric service data, tokens, and dispatcher identities.</span></div></Panel>
    {notice && <div className={notice.includes("not returned") || notice.includes("cleared") || notice.includes("removed") ? "inline-success" : "inline-error"} role="status">{notice}</div>}
  </div>;
}

function McpManifestDetail({ agent, onNavigate }: { agent: AgentInfo; onNavigate: (route: string) => void }) {
  const agentId = encodeURIComponent(agent.runner_id);
  const servers = agent.mcp_manifest?.servers ?? [];
  return <div className="mcp-manifest-detail">{servers.map((server) => <section key={server.server_id}><header><Network size={16} /><div><strong>{server.server_id}</strong><small>{(server.prompts?.length ?? 0)} prompts · {(server.tools?.length ?? 0)} tools · {(server.resources?.length ?? 0)} resources</small></div></header><div className="capability-links">{(server.prompts ?? []).map((item) => <button key={`prompt-${item.name}`} onClick={() => onNavigate(`/agents/${agentId}/capabilities/prompt/${encodeURIComponent(item.name)}`)}><Bot size={14} />Prompt · {item.name}</button>)}{(server.tools ?? []).map((item) => <button key={`tool-${item.name}`} onClick={() => onNavigate(`/agents/${agentId}/capabilities/tool/${encodeURIComponent(item.name)}`)}><TerminalSquare size={14} />Tool · {item.name}</button>)}{(server.resources ?? []).map((item) => <button key={`resource-${item.uri}`} onClick={() => onNavigate(`/agents/${agentId}/capabilities/resource/${encodeURIComponent(item.uri)}`)}><Database size={14} />Resource · {item.name ?? item.uri}</button>)}</div></section>)}{servers.length === 0 && <EmptyState label="This agent has not advertised an MCP server manifest." />}</div>;
}

function RecordDetail({ value, empty }: { value: Record<string, unknown> | null; empty: string }) {
  if (!value || Object.keys(value).length === 0) return <EmptyState label={empty} />;
  return <div className="record-detail">{Object.entries(value).filter(([key]) => !sensitiveKey(key)).slice(0, 30).map(([key, item]) => <div key={key}><span>{key.replaceAll("_", " ")}</span>{item !== null && typeof item === "object" ? <pre>{formatStructured(item)}</pre> : <strong>{item == null || item === "" ? "not reported" : String(item)}</strong>}</div>)}</div>;
}


function collectDispatchers(snapshot: HubSnapshot): Array<Record<string, unknown>> {
  const top = (snapshot.dispatchers ?? []).filter(isRecord);
  const nested = snapshot.hosts.flatMap((host) => (host.dispatchers ?? []).filter(isRecord));
  const byId = new Map<string, Record<string, unknown>>();
  [...top, ...nested].forEach((item, index) => byId.set(recordId(item) || `dispatcher-${index}`, item));
  return [...byId.values()];
}

function fleetDetailTitle(route: string, runner?: RunnerInfo, host?: HubSnapshot["hosts"][number], dispatcher?: Record<string, unknown>) {
  if (runner) return runner.alias ?? runner.runner_id;
  if (host) return host.display_name ?? host.label ?? host.hostname;
  if (dispatcher) return objectLabel(dispatcher, "Dispatcher detail");
  if (route === "/cluster/active") return "Cluster detail";
  return "Hub detail";
}

function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function recordId(value: Record<string, unknown>): string { return ["dispatcher_id", "runner_id", "name", "id"].map((key) => value[key]).find((item): item is string => typeof item === "string") ?? ""; }
function stringField(value: Record<string, unknown>, key: string): string { return typeof value[key] === "string" ? value[key] as string : ""; }
function approvalScope(approval: ApprovalInfo): string { if (approval.scope_globs?.length) return approval.scope_globs.join(", "); if (approval.scope_globs_json) { try { const value = JSON.parse(approval.scope_globs_json); return Array.isArray(value) ? value.join(", ") : approval.scope_globs_json; } catch { return approval.scope_globs_json; } } return "not reported"; }
function sensitiveKey(key: string): boolean { return /(token|secret_value|password|private_key|credential)/i.test(key); }
function formatStructured(value: unknown): string { return JSON.stringify(value, (key, item) => sensitiveKey(key) ? "[redacted]" : item, 2); }
function percent(value?: number): string { return typeof value === "number" ? `${Math.round(value)}%` : "not reported"; }

function StatusBar({ snapshot, sessionState, freshness, apiHost, lastRefresh, loading, readErrorCount, restrictedCount, actionError, pendingApprovals, runningTasks }: { snapshot: HubSnapshot; sessionState: SessionState; freshness: Record<string, ResourceFreshness | undefined>; apiHost: string | null; lastRefresh: Date | null; loading: boolean; readErrorCount: number; restrictedCount: number; actionError: boolean; pendingApprovals: number; runningTasks: number }) {
  const staleResources = Object.values(freshness).filter((item) => item?.source === "last-good" || (item && Date.now() - item.receivedAt > item.staleAfterMs)).length;
  const issueLabel = actionError
    ? "Action failed"
    : readErrorCount
      ? `${readErrorCount} read error${readErrorCount === 1 ? "" : "s"}`
      : restrictedCount
        ? `Healthy · ${restrictedCount} restricted view${restrictedCount === 1 ? "" : "s"}`
        : "Healthy";
  const issueTone = actionError || readErrorCount ? "bad" : restrictedCount ? "warn" : "good";
  return <footer className="status-bar" aria-label="Fabric status"><span className={statusClass(sessionState)}><StatusDot status={sessionState} />{apiHost ?? "No active hub"} · {sessionState}</span><span>{loading ? "Refreshing…" : lastRefresh ? `Updated ${formatTime(lastRefresh)}` : "Not refreshed"}{staleResources ? ` · ${staleResources} stale` : ""}</span><span>{versionLabel(snapshot)}</span><span><TerminalSquare size={13} />{runningTasks} running</span><span><ShieldCheck size={13} />{pendingApprovals} approvals</span><span className={issueTone}>{issueLabel}</span></footer>;
}

function DispatchModal({
  draft,
  config,
  identity,
  gateReason,
  busy,
  onChange,
  onClose,
  onSubmit
}: {
  draft: DispatchDraft;
  config: HubConfig;
  identity: DispatcherIdentitySummary | null;
  gateReason: string | null;
  busy: boolean;
  onChange: (draft: DispatchDraft) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  // The shared commandAvailability() gate (session/identity/authority/feature/
  // freshness) takes precedence and is the authoritative "may this credential
  // dispatch at all" check; dispatchDisabledReason then supplies the
  // form-completeness reasons (title/prompt/branch/scope) the gate does not
  // model.
  const disabledReason = gateReason ?? dispatchDisabledReason(draft, identity, config);
  const update = <K extends keyof DispatchDraft>(key: K, value: DispatchDraft[K]) => {
    onChange({ ...draft, [key]: value });
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Dispatch Fabric task">
      <section className="dispatch-modal">
        <header>
          <div>
            <p className="eyebrow">Signed dispatch</p>
            <h3>New Fabric Task</h3>
          </div>
          <button className="icon-action" onClick={onClose} title="Close">
            <XCircle size={16} />
          </button>
        </header>

        <div className="dispatch-grid">
          <label>
            Title
            <input value={draft.title} onChange={(event) => update("title", event.target.value)} />
          </label>
          <label>
            Kind
            <select value={draft.kind} onChange={(event) => update("kind", event.target.value as DispatchDraft["kind"])}>
              <option value="agent">agent</option>
              <option value="command">command</option>
            </select>
          </label>
          <label>
            Dispatch
            <select value={draft.dispatch} onChange={(event) => update("dispatch", event.target.value as DispatchDraft["dispatch"])}>
              <option value="prompt">prompt</option>
              <option value="skill">skill</option>
              <option value="tool">tool</option>
            </select>
          </label>
          <label>
            Branch
            <input value={draft.branch} onChange={(event) => update("branch", event.target.value)} />
          </label>
          <label>
            Base commit
            <input value={draft.baseCommit} onChange={(event) => update("baseCommit", event.target.value)} />
          </label>
          <label>
            Scope globs
            <textarea value={draft.scopeGlobs} onChange={(event) => update("scopeGlobs", event.target.value)} />
          </label>
          <label className="wide">
            Prompt / brief
            <textarea value={draft.prompt} onChange={(event) => update("prompt", event.target.value)} />
          </label>
          <label>
            Tags
            <input value={draft.tags} onChange={(event) => update("tags", event.target.value)} placeholder="windows, ui" />
          </label>
          <label>
            Capabilities
            <input value={draft.capabilities} onChange={(event) => update("capabilities", event.target.value)} placeholder="tauri, rust" />
          </label>
          <label>
            Skill
            <input value={draft.skill} onChange={(event) => update("skill", event.target.value)} disabled={draft.dispatch !== "skill"} />
          </label>
          <label>
            Tool
            <input value={draft.tool} onChange={(event) => update("tool", event.target.value)} disabled={draft.dispatch !== "tool"} />
          </label>
          <label className="wide">
            Command tokens
            <input value={draft.command} onChange={(event) => update("command", event.target.value)} disabled={draft.kind !== "command"} />
          </label>
        </div>

        <footer>
          <span>{disabledReason ?? `Signing as ${identity?.id}`}</span>
          <div className="modal-actions">
            <button onClick={onClose}>Cancel</button>
            <button className="primary-command" onClick={onSubmit} disabled={Boolean(disabledReason) || busy}>
              <KeyRound size={15} />
              Sign and submit
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}

function Metric({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: string; detail: string }) {
  return (
    <article className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

function RunnerRow({
  runner,
  busy,
  onToggleDrain
}: {
  runner: RunnerInfo;
  busy: boolean;
  onToggleDrain: () => void;
}) {
  const load = `${runner.current_load ?? 0}/${runner.max_concurrent ?? "?"}`;
  return (
    <article className="runner-row">
      <StatusDot status={runner.state} />
      <div>
        <strong>{runner.alias ?? runner.runner_id}</strong>
        <span>{runner.hostname ?? "unknown host"} · {load} load</span>
      </div>
      <div className="tag-row">
        {(runner.kinds ?? []).map((kind) => (
          <span key={kind}>{kind}</span>
        ))}
        {runner.drain_requested && <span className="warn">drain</span>}
      </div>
      <button className="icon-action" onClick={onToggleDrain} disabled={busy} title={runner.drain_requested ? "Clear drain" : "Request drain"}>
        {runner.drain_requested ? <Undo2 size={15} /> : <PauseCircle size={15} />}
      </button>
    </article>
  );
}

function AgentCard({ agent }: { agent: AgentInfo }) {
  const servers = agent.mcp_manifest?.servers ?? [];
  const prompts = servers.reduce((sum, server) => sum + (server.prompts?.length ?? 0), 0);
  const tools = servers.reduce((sum, server) => sum + (server.tools?.length ?? 0), 0);
  return (
    <article className="agent-card">
      <div className="agent-head">
        <StatusDot status={agent.state} />
        <strong>{agent.alias ?? agent.runner_id}</strong>
      </div>
      <span>{agent.agent_type ?? "agent"} · {agent.hostname ?? "unknown host"}</span>
      <div className="agent-stats">
        <span>{servers.length} servers</span>
        <span>{prompts} prompts</span>
        <span>{tools} tools</span>
      </div>
    </article>
  );
}

function TaskDetail({
  task,
  stream,
  audit,
  streamError,
  busyCancel,
  onCancel,
  onRedispatch,
  redispatching
}: {
  task: TaskInfo;
  stream: TaskStreamLine[];
  audit: TaskAudit | null;
  streamError: string | null;
  busyCancel: boolean;
  onCancel: (taskId: number) => void;
  onRedispatch: () => void;
  redispatching: boolean;
}) {
  const scope = parseScope(task);
  const taskId = getTaskId(task);
  const terminal = ["done", "failed", "cancelled", "timed_out"].includes(String(task.status ?? ""));
  return (
    <div className="detail-stack">
      <div className="detail-title">
        <TerminalSquare size={22} />
        <div>
          <h3>{task.title ?? "Untitled task"}</h3>
          <span>{task.kind ?? "agent"} {task.dispatch ? `· ${task.dispatch}` : ""}</span>
        </div>
        <div className="detail-actions"><button className="secondary-command" disabled={taskId === null || redispatching} onClick={onRedispatch}><Undo2 size={14} />Redispatch</button><button className="danger-action" disabled={taskId === null || terminal || busyCancel} onClick={() => taskId !== null && onCancel(taskId)}><Square size={14} />Cancel</button></div>
      </div>
      <InfoLine label="status" value={task.status ?? "unknown"} />
      <InfoLine label="runner" value={task.claimed_by_runner ?? task.runner_id ?? task.worker_id ?? "not claimed"} />
      <InfoLine label="claimed host" value={task.claimed_by_host ?? "not claimed"} />
      <InfoLine label="dispatched by" value={[task.dispatched_by_user, task.dispatched_by_agent, task.dispatched_by_host].filter(Boolean).join(" · ") || "not recorded"} />
      <InfoLine label="dispatcher key" value={task.dispatcher_pubkey_fingerprint ?? "not recorded"} />
      <InfoLine label="branch" value={task.branch ?? "not recorded"} icon={<GitBranch size={15} />} />
      <InfoLine label="dispatched" value={formatMaybeDate(task.dispatched_at ?? task.created_at)} icon={<Clock3 size={15} />} />
      <InfoLine label="started" value={formatMaybeDate(task.started_at)} icon={<Clock3 size={15} />} />
      <InfoLine label="completed" value={formatMaybeDate(task.completed_at)} icon={<CheckCircle2 size={15} />} />
      <InfoLine label="runtime" value={task.wall_seconds == null ? "not recorded" : `${task.wall_seconds.toFixed(2)}s wall · ${(task.runner_cpu_seconds ?? 0).toFixed(2)}s CPU`} />
      <InfoLine label="approvals" value={`${task.approvals_received ?? 0}/${task.approvals_required ?? 0}${task.approval_id ? ` · ${task.approval_id}` : ""}`} />
      <InfoLine label="exit reason" value={task.exit_reason ?? "not terminal"} />
      <InfoLine label="integrity path" value={(task.kind ?? "agent") === "command" ? "Command task · explicit Loom token contract" : `Agent task · signed ${task.dispatch ?? "prompt"} brief`} icon={(task.kind ?? "agent") === "command" ? <TerminalSquare size={15} /> : <Bot size={15} />} />
      {Array.isArray(task.policy_decisions) && task.policy_decisions.length > 0 && <div className="payload-box"><span>policy decisions</span><pre>{formatStructured(task.policy_decisions)}</pre></div>}
      {task.prompt && <div className="payload-box"><span>reviewed brief</span><pre>{task.prompt}</pre></div>}
      <div className="scope-box">
        <span>scope</span>
        {scope.length > 0 ? scope.map((item) => <code key={item}>{item}</code>) : <em>No scope globs reported</em>}
      </div>
      <div className="result-box">
        <div className="stream-head"><span>result</span><em>{task.exit_code == null ? "no exit code" : `exit ${task.exit_code}`}</em></div>
        {task.error && <p className="inline-error">{task.error}</p>}
        {task.result !== undefined && task.result !== null ? <pre>{formatStructured(task.result)}</pre> : <em>No terminal result has been reported.</em>}
      </div>
      <div className="stream-box">
        <div className="stream-head">
          <span>stream tail</span>
          <em>{streamError ? streamError : `${stream.length} buffered lines`}</em>
        </div>
        <div className="stream-lines" aria-live="polite">
          {stream.map((line, index) => (
            <div className="stream-line" key={`${line.seq ?? index}-${index}`}>
              <span>{line.channel ?? "info"}</span>
              <code>{line.line ?? line.message ?? JSON.stringify(line)}</code>
            </div>
          ))}
          {stream.length === 0 && <em>No stream lines loaded for this task.</em>}
        </div>
      </div>
      <div className="audit-box">
        <div className="stream-head">
          <span>audit chain</span>
          <em>{audit ? auditSummary(audit) : "loading"}</em>
        </div>
        <div className="audit-events">
          {(audit?.events ?? []).slice(-8).map((event, index) => (
            <div className="audit-event" key={`${event.hash ?? event.id ?? index}-${index}`}>
              <strong>{event.kind ?? event.event_type ?? "event"}</strong>
              <span>{formatMaybeDate(event.created_at ?? event.ts)}</span>
              <code>{event.hash ?? "no hash"}</code>
            </div>
          ))}
          {audit && audit.events.length === 0 && <em>No audit events returned for this task.</em>}
        </div>
      </div>
    </div>
  );
}

function ErrorStrip({ errors }: { errors: Record<string, string> }) {
  return (
    <div className="error-strip">
      <XCircle size={18} />
      <div>
        <strong>Some hub reads failed</strong>
        <span>{Object.entries(errors).map(([key, value]) => `${key}: ${value}`).join(" · ")}</span>
      </div>
    </div>
  );
}

function RestrictionStrip({ restrictions, accountRoles }: { restrictions: Record<string, string>; accountRoles: readonly string[] | null }) {
  return (
    <div className="error-strip restriction-strip" role="status">
      <LockKeyhole size={18} />
      <div>
        <strong>Some views are limited by the installed automation token's role</strong>
        <span>{Object.entries(restrictions).map(([key, value]) => `${key}: ${value}`).join(" · ")}{accountRoleContextNote(accountRoles)}</span>
      </div>
    </div>
  );
}

function DispatchResultStrip({ result }: { result: SignedDispatchResult }) {
  const detail =
    result.approval_id ? `approval ${result.approval_id}` : typeof result.task_id === "number" ? `task #${result.task_id}` : result.message;
  return (
    <div className={`dispatch-result ${statusClass(result.status)}`}>
      <ShieldCheck size={18} />
      <div>
        <strong>{result.status}</strong>
        <span>{detail}</span>
      </div>
    </div>
  );
}


function getTaskId(task?: TaskInfo | null): number | null {
  if (!task) {
    return null;
  }
  return typeof task.id === "number" ? task.id : typeof task.task_id === "number" ? task.task_id : null;
}

function parseScope(task: TaskInfo): string[] {
  if (Array.isArray(task.scope_globs)) {
    return task.scope_globs;
  }
  if (typeof task.scope_globs_json === "string") {
    try {
      const parsed = JSON.parse(task.scope_globs_json);
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function formatMaybeDate(value?: string | null): string {
  if (!value) {
    return "not recorded";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatTime(value: Date): string {
  return value.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function money(value?: number): string {
  if (typeof value !== "number") {
    return "$0.00";
  }
  return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(value);
}

function budgetDetail(snapshot: HubSnapshot): string {
  const budget = snapshot.budget;
  if (!budget) {
    return "budget unavailable";
  }
  const pct = typeof budget.daily_pct === "number" ? `${Math.round(budget.daily_pct)}% daily` : "daily cap not set";
  return budget.weekly_alert ? `${pct}, weekly alert` : pct;
}

function versionLabel(snapshot: HubSnapshot): string {
  const health = snapshot.health;
  if (!health) {
    return "no health response";
  }
  return `v${health.package_version ?? health.version ?? "?"} · proto ${health.protocol_version ?? "?"}`;
}

function agentCapabilityCount(agents: AgentInfo[]): string {
  const counts = agents.reduce(
    (acc, agent) => {
      for (const server of agent.mcp_manifest?.servers ?? []) {
        acc.prompts += server.prompts?.length ?? 0;
        acc.tools += server.tools?.length ?? 0;
      }
      return acc;
    },
    { prompts: 0, tools: 0 }
  );
  return `${counts.prompts} prompts, ${counts.tools} tools`;
}

function auditSummary(audit: TaskAudit): string {
  if (audit.error) {
    return audit.error;
  }
  return `${audit.verified ? "verified" : "not verified"} · ${audit.events.length} events`;
}

function activityLabel(activity: ActivityId): string {
  return ACTIVITIES.find((item) => item.id === activity)?.label ?? "Dashboard";
}

function pageTitle(route: string): string {
  if (route === "/dashboard") return "Fabric dashboard";
  if (route === "/explorer") return "Fabric explorer";
  if (route.startsWith("/settings")) return "Settings";
  if (route.startsWith("/tasks/")) return "Tasks";
  if (route.startsWith("/agents/")) return "Agents and capabilities";
  if (route.startsWith("/approvals/")) return "Approvals";
  if (route === "/cost") return "Cost and budget";
  if (route.startsWith("/audit")) return "Audit log";
  if (route === "/secrets") return "Secret metadata";
  if (route.startsWith("/runners/")) return "Runner detail";
  if (route.startsWith("/hosts/")) return "Host detail";
  if (route.startsWith("/cluster/")) return "Cluster detail";
  return "Hub and fleet";
}

function titleCase(value: string): string {
  return value.replace(/(^|[-_])\w/g, (match) => match.replace(/[-_]/, "").toUpperCase());
}

function objectLabel(value: unknown, fallback: string): string {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const candidate = record.label ?? record.alias ?? record.dispatcher_id ?? record.id;
    if (typeof candidate === "string") return candidate;
  }
  return fallback;
}

function formatDuration(seconds?: number): string {
  if (typeof seconds !== "number") return "not reported";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

const PREF_PREFIX = "forgewire.fabric.desktop.ui.v1.";

function readPreference<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(`${PREF_PREFIX}${key}`);
    return raw === null ? fallback : JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writePreference(key: string, value: boolean | number | string | string[]) {
  try {
    window.localStorage.setItem(`${PREF_PREFIX}${key}`, JSON.stringify(value));
  } catch {
    // Layout preferences are best effort and never contain credentials or task payloads.
  }
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

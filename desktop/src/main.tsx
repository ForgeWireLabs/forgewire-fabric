import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Cpu,
  FileClock,
  GitBranch,
  KeyRound,
  PlusCircle,
  PauseCircle,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Square,
  Undo2,
  TerminalSquare,
  Wifi,
  XCircle
} from "lucide-react";
import {
  dispatchDisabledReason,
  dispatchSignedTask,
  discoverHubs,
  EMPTY_DISPATCH_DRAFT,
  HubApi,
  loadDispatcherIdentity,
  normalizeHubUrl
} from "./api";
import {
  hubConfigFromContext,
  loadFabricContext,
  loadHubConfig,
  loadInitialHubConfig,
  saveHubConfig
} from "./storage";
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
import "./styles.css";

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
  const [snapshot, setSnapshot] = useState<HubSnapshot>(EMPTY_SNAPSHOT);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [selectedTaskId, setSelectedTaskId] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
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

  const api = useMemo(() => {
    if (!config.hubUrl || !config.token) {
      return null;
    }
    return new HubApi(config);
  }, [config]);

  const refresh = useCallback(async () => {
    if (!api) {
      return;
    }
    setLoading(true);
    try {
      const result = await api.loadSnapshot();
      setSnapshot(result.snapshot);
      setErrors(result.errors);
      setLastRefresh(new Date());
      const firstTaskId = getTaskId(result.snapshot.tasks[0]);
      setSelectedTaskId((current) => current ?? firstTaskId ?? null);
    } catch (error) {
      setErrors({ hub: error instanceof Error ? error.message : String(error) });
    } finally {
      setLoading(false);
    }
  }, [api]);

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
        } else if (context.warnings?.some((warning) => warning.toLowerCase().includes("identity"))) {
          setIdentityError("No installed dispatcher identity is loaded.");
        }
        return;
      }

      const loaded = await loadHubConfig();
      if (!cancelled) {
        setConfig(loaded);
        setDraft(loaded);
      }
    };
    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selectedTask =
    snapshot.tasks.find((task) => getTaskId(task) === selectedTaskId) ?? snapshot.tasks[0] ?? null;

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
    const next = { hubUrl: normalizeHubUrl(draft.hubUrl), token: draft.token.trim() };
    await saveHubConfig(next);
    setConfig(next);
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

  const cancelSelectedTask = async (taskId: number) => {
    if (!api) {
      return;
    }
    await runAction(`cancel-task-${taskId}`, () => api.cancelTask(taskId));
  };

  const toggleRunnerDrain = async (runner: RunnerInfo) => {
    if (!api) {
      return;
    }
    const runnerId = runner.runner_id;
    await runAction(
      `${runner.drain_requested ? "undrain" : "drain"}-${runnerId}`,
      () => runner.drain_requested ? api.requestRunnerUndrain(runnerId) : api.requestRunnerDrain(runnerId)
    );
  };

  const decideApproval = async (approval: ApprovalInfo, status: "approve" | "deny") => {
    if (!api) {
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
        setLastRefresh(new Date());
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

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">FW</div>
          <div>
            <h1>ForgeWire Fabric</h1>
            <p>Desktop control panel</p>
          </div>
        </div>

        <section className="connection-panel" aria-label="Hub connection">
          <div className="context-summary" aria-label="Installed Fabric context">
            <strong>{fabricContext ? "Installed Fabric context" : "Manual/browser context"}</strong>
            <span>Hub: {fabricContext?.hub_source ?? "local settings"}</span>
            <span>Token: {fabricContext?.token_source ?? (config.token ? "manual entry" : "not loaded")}</span>
            <span>Identity: {fabricContext?.identity_source ?? (dispatcherIdentity ? "manual path" : "not loaded")}</span>
          </div>
          <label>
            Hub URL
            <input
              value={draft.hubUrl}
              onChange={(event) => setDraft({ ...draft, hubUrl: event.target.value })}
              placeholder="http://127.0.0.1:8765"
            />
          </label>
          <label>
            Bearer token
            <input
              value={draft.token}
              onChange={(event) => setDraft({ ...draft, token: event.target.value })}
              placeholder="Paste hub token"
              type="password"
            />
          </label>
          <div className="button-row">
            <button className="primary" onClick={() => void saveConnection()}>
              <KeyRound size={16} />
              Connect
            </button>
            <button onClick={() => void refresh()} disabled={!api || loading}>
              <RefreshCw size={16} className={loading ? "spin" : ""} />
              Refresh
            </button>
          </div>
          <button className="secondary-command" onClick={() => void runDiscovery()} disabled={busyAction === "discover-hubs"}>
            <Wifi size={16} />
            Discover hubs
          </button>
          {hubCandidates.length > 0 && (
            <div className="candidate-list">
              {hubCandidates.map((candidate) => (
                <button
                  key={candidate.url}
                  onClick={() => setDraft((current) => ({ ...current, hubUrl: candidate.url }))}
                >
                  <strong>{candidate.label}</strong>
                  <span>{candidate.version ?? "version unknown"}</span>
                </button>
              ))}
            </div>
          )}
          {(fabricContext?.warnings ?? []).length > 0 && (
            <div className="context-warnings">
              {fabricContext?.warnings?.map((warning) => <span key={warning}>{warning}</span>)}
            </div>
          )}
        </section>

        <section className="identity-panel" aria-label="Dispatcher identity">
          <label>
            Dispatcher identity file
            <input
              value={identityPath}
              onChange={(event) => setIdentityPath(event.target.value)}
              placeholder="C:\\Users\\you\\.forgewire\\dispatcher.json"
            />
          </label>
          <button onClick={() => void loadIdentity()} disabled={!identityPath.trim()}>
            <KeyRound size={16} />
            Load identity
          </button>
          {dispatcherIdentity && (
            <div className="identity-summary">
              <strong>{dispatcherIdentity.id}</strong>
              <span>{dispatcherIdentity.public_key_hex.slice(0, 16)}...</span>
            </div>
          )}
          {identityError && <span className="inline-error">{identityError}</span>}
        </section>

        <nav className="nav-stack" aria-label="Workspace sections">
          <a href="#fleet">
            <Server size={16} />
            Fleet
          </a>
          <a href="#tasks">
            <TerminalSquare size={16} />
            Tasks
          </a>
          <a href="#audit">
            <ShieldCheck size={16} />
            Audit
          </a>
        </nav>

        <div className="sidebar-footer">
          <span>{lastRefresh ? `Updated ${formatTime(lastRefresh)}` : "Not refreshed yet"}</span>
          <span>{api ? new URL(api.baseUrl).host : "No hub"}</span>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Operations</p>
            <h2>{snapshot.health?.status ? "Hub connected" : "Connect a hub"}</h2>
          </div>
          <div className="topbar-actions">
            <button className="primary-command" onClick={() => setDispatchOpen(true)}>
              <PlusCircle size={16} />
              Dispatch
            </button>
            <StatusPill status={snapshot.health?.status ?? (api ? "unknown" : "idle")} />
          </div>
        </header>

        {Object.keys(errors).length > 0 && <ErrorStrip errors={errors} />}
        {actionError && <ErrorStrip errors={{ action: actionError }} />}
        {dispatchResult && <DispatchResultStrip result={dispatchResult} />}

        <section className="metric-grid" aria-label="Fabric overview">
          <Metric icon={<Wifi />} label="Hub" value={snapshot.health?.status ?? "unknown"} detail={versionLabel(snapshot)} />
          <Metric icon={<Cpu />} label="Runners online" value={`${onlineRunners}/${snapshot.runners.length}`} detail={`${degradedRunners} need attention`} />
          <Metric icon={<Bot />} label="Agents" value={snapshot.agents.length.toString()} detail={agentCapabilityCount(snapshot.agents)} />
          <Metric icon={<TerminalSquare />} label="Tasks" value={`${runningTasks} running`} detail={`${queuedTasks} queued, ${failedTasks} failed`} />
          <Metric icon={<AlertTriangle />} label="Approvals" value={pendingApprovals.toString()} detail="pending operator decisions" />
          <Metric icon={<CircleDollarSign />} label="Budget" value={money(snapshot.budget?.daily_spend_usd)} detail={budgetDetail(snapshot)} />
        </section>

        <section className="split-layout" id="fleet">
          <Panel title="Runners" action={`${snapshot.hosts.length} hosts`}>
            <div className="runner-list">
              {snapshot.runners.map((runner) => (
                <RunnerRow
                  key={runner.runner_id}
                  runner={runner}
                  busy={busyAction === `drain-${runner.runner_id}` || busyAction === `undrain-${runner.runner_id}`}
                  onToggleDrain={() => void toggleRunnerDrain(runner)}
                />
              ))}
              {snapshot.runners.length === 0 && <EmptyState label="No runners returned by the hub." />}
            </div>
          </Panel>

          <Panel title="Agents" action={`${snapshot.agents.length} registered`}>
            <div className="agent-grid">
              {snapshot.agents.map((agent) => (
                <AgentCard key={agent.runner_id} agent={agent} />
              ))}
              {snapshot.agents.length === 0 && <EmptyState label="No Fabric agents are advertising MCP manifests." />}
            </div>
          </Panel>
        </section>

        <section className="task-layout" id="tasks">
          <Panel
            title="Task Queue"
            action={
              <label className="search">
                <Search size={15} />
                <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter" />
              </label>
            }
          >
            <div className="task-table" role="table">
              {visibleTasks.map((task) => {
                const id = getTaskId(task);
                return (
                  <button
                    className={`task-row ${id === selectedTaskId ? "selected" : ""}`}
                    key={id ?? task.title}
                    onClick={() => setSelectedTaskId(id ?? null)}
                  >
                    <span className="task-id">#{id ?? "?"}</span>
                    <span className="task-title">{task.title ?? "Untitled task"}</span>
                    <span className="task-kind">{task.kind ?? "agent"}</span>
                    <StatusPill status={task.status ?? "unknown"} compact />
                  </button>
                );
              })}
              {visibleTasks.length === 0 && <EmptyState label="No tasks match the current filter." />}
            </div>
          </Panel>

          <Panel title="Task Detail" action={selectedTask ? `#${getTaskId(selectedTask)}` : "none"}>
            {selectedTask ? (
              <TaskDetail
                task={selectedTask}
                stream={taskStream}
                audit={taskAudit}
                streamError={streamError}
                busyCancel={busyAction === `cancel-task-${getTaskId(selectedTask)}`}
                onCancel={cancelSelectedTask}
              />
            ) : (
              <EmptyState label="Select a task to inspect its routing and provenance." />
            )}
          </Panel>
        </section>

        <section className="split-layout" id="audit">
          <Panel title="Approvals" action={`${pendingApprovals} pending`}>
            <div className="approval-list">
              {snapshot.approvals.map((approval) => (
                <div className="approval-row" key={approval.approval_id}>
                  <div>
                    <strong>{approval.task_label ?? approval.approval_id}</strong>
                    <span>{approval.branch ?? "no branch"}</span>
                  </div>
                  <StatusPill status={approval.status} compact />
                  {approval.status === "pending" && (
                    <div className="approval-actions">
                      <button
                        onClick={() => void decideApproval(approval, "deny")}
                        disabled={busyAction === `approval-deny-${approval.approval_id}`}
                      >
                        Deny
                      </button>
                      <button
                        className="primary"
                        onClick={() => void decideApproval(approval, "approve")}
                        disabled={busyAction === `approval-approve-${approval.approval_id}`}
                      >
                        Approve
                      </button>
                    </div>
                  )}
                </div>
              ))}
              {snapshot.approvals.length === 0 && <EmptyState label="No pending approvals." />}
            </div>
          </Panel>

          <Panel title="Audit and Cluster" action={snapshot.cluster?.backend ?? "backend unknown"}>
            <div className="audit-grid">
              <InfoLine label="rqlite" value={snapshot.cluster?.rqlite ? `${snapshot.cluster.rqlite.host}:${snapshot.cluster.rqlite.port}` : "not reported"} />
              <InfoLine label="audit tail" value={snapshot.audit ? "available" : "not loaded"} />
              <InfoLine label="selected audit" value={taskAudit ? auditSummary(taskAudit) : "select task"} />
              <InfoLine label="labels" value={snapshot.cluster?.labels_snapshot?.status ?? "unknown"} />
              <InfoLine label="hub host" value={String(snapshot.health?.host ?? "unknown")} />
            </div>
          </Panel>
        </section>
      </section>

      {dispatchOpen && (
        <DispatchModal
          draft={dispatchDraft}
          config={config}
          identity={dispatcherIdentity}
          busy={busyAction === "dispatch-submit"}
          onChange={setDispatchDraft}
          onClose={() => setDispatchOpen(false)}
          onSubmit={() => void submitDispatch()}
        />
      )}
    </main>
  );
}

function DispatchModal({
  draft,
  config,
  identity,
  busy,
  onChange,
  onClose,
  onSubmit
}: {
  draft: DispatchDraft;
  config: HubConfig;
  identity: DispatcherIdentitySummary | null;
  busy: boolean;
  onChange: (draft: DispatchDraft) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  const disabledReason = dispatchDisabledReason(draft, identity, config);
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

function Panel({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="panel">
      <header>
        <h3>{title}</h3>
        {action && <div className="panel-action">{action}</div>}
      </header>
      {children}
    </section>
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
  onCancel
}: {
  task: TaskInfo;
  stream: TaskStreamLine[];
  audit: TaskAudit | null;
  streamError: string | null;
  busyCancel: boolean;
  onCancel: (taskId: number) => void;
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
        <button
          className="danger-action"
          disabled={taskId === null || terminal || busyCancel}
          onClick={() => taskId !== null && onCancel(taskId)}
        >
          <Square size={14} />
          Cancel
        </button>
      </div>
      <InfoLine label="status" value={task.status ?? "unknown"} />
      <InfoLine label="runner" value={task.runner_id ?? task.worker_id ?? "not claimed"} />
      <InfoLine label="branch" value={task.branch ?? "not recorded"} icon={<GitBranch size={15} />} />
      <InfoLine label="created" value={formatMaybeDate(task.created_at)} icon={<Clock3 size={15} />} />
      <InfoLine label="completed" value={formatMaybeDate(task.completed_at)} icon={<CheckCircle2 size={15} />} />
      <div className="scope-box">
        <span>scope</span>
        {scope.length > 0 ? scope.map((item) => <code key={item}>{item}</code>) : <em>No scope globs reported</em>}
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

function StatusPill({ status, compact = false }: { status: string; compact?: boolean }) {
  const normalized = status.toLowerCase();
  return <span className={`status-pill ${compact ? "compact" : ""} ${statusClass(normalized)}`}>{status}</span>;
}

function StatusDot({ status }: { status?: string }) {
  return <span className={`status-dot ${statusClass(String(status ?? "unknown").toLowerCase())}`} />;
}

function InfoLine({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <div className="info-line">
      <span>{icon}{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return <div className="empty-state"><FileClock size={18} />{label}</div>;
}

function statusClass(status: string) {
  if (["ok", "online", "done", "approved", "healthy"].includes(status)) {
    return "good";
  }
  if (["queued", "running", "pending", "held"].includes(status)) {
    return "work";
  }
  if (["degraded", "draining", "warning"].includes(status)) {
    return "warn";
  }
  if (["failed", "offline", "cancelled", "timed_out", "denied"].includes(status)) {
    return "bad";
  }
  return "neutral";
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

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

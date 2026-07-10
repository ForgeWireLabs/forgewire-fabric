import { invoke } from "@tauri-apps/api/core";
import type {
  AgentInfo,
  ApprovalDecision,
  ApprovalInfo,
  AuditTail,
  ClusterHealth,
  CostBudget,
  Healthz,
  HostSummary,
  HubConfig,
  DispatchBrief,
  DispatchDraft,
  HubDiscoveryCandidate,
  DispatcherIdentitySummary,
  RunnerInfo,
  SignedDispatchResult,
  SnapshotResult,
  TaskAudit,
  TaskInfo,
  TaskStreamResult
} from "./types";

const DEFAULT_TIMEOUT_MS = 8000;

export const EMPTY_DISPATCH_DRAFT: DispatchDraft = {
  title: "",
  kind: "agent",
  dispatch: "prompt",
  branch: "agent/fabric-desktop/task",
  baseCommit: "origin/main",
  scopeGlobs: "",
  prompt: "",
  tags: "",
  capabilities: "",
  skill: "",
  tool: "",
  command: ""
};

export class HubApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly body?: string
  ) {
    super(message);
    this.name = "HubApiError";
  }
}

export class HubApi {
  readonly baseUrl: string;
  private readonly token: string;

  constructor(config: HubConfig) {
    this.baseUrl = normalizeHubUrl(config.hubUrl);
    this.token = config.token.trim();
  }

  async healthz(): Promise<Healthz> {
    return this.request<Healthz>("/healthz");
  }

  async clusterHealth(): Promise<ClusterHealth> {
    return this.request<ClusterHealth>("/cluster/health");
  }

  async listRunners(): Promise<RunnerInfo[]> {
    const body = await this.request<{ runners?: RunnerInfo[] }>("/runners");
    return body.runners ?? [];
  }

  async listAgents(): Promise<AgentInfo[]> {
    const body = await this.request<{ agents?: AgentInfo[] }>("/agents");
    return body.agents ?? [];
  }

  async listTasks(limit = 80): Promise<TaskInfo[]> {
    const body = await this.request<{ tasks?: TaskInfo[] }>(`/tasks?limit=${limit}`);
    return body.tasks ?? [];
  }

  async taskStream(taskId: number, afterSeq = 0, limit = 200): Promise<TaskStreamResult> {
    const params = new URLSearchParams({ after_seq: String(afterSeq), limit: String(limit) });
    const body = await this.request<{ lines?: TaskStreamResult["lines"] }>(
      `/tasks/${taskId}/stream?${params}`
    );
    return { lines: body.lines ?? [] };
  }

  async cancelTask(taskId: number): Promise<TaskInfo> {
    return this.request<TaskInfo>(`/tasks/${taskId}/cancel`, { method: "POST" });
  }

  async requestRunnerDrain(runnerId: string): Promise<RunnerInfo> {
    return this.request<RunnerInfo>(`/runners/${encodeURIComponent(runnerId)}/drain-by-dispatcher`, {
      method: "POST"
    });
  }

  async requestRunnerUndrain(runnerId: string): Promise<RunnerInfo> {
    return this.request<RunnerInfo>(`/runners/${encodeURIComponent(runnerId)}/undrain-by-dispatcher`, {
      method: "POST"
    });
  }

  async listApprovals(status = "pending", limit = 80): Promise<ApprovalInfo[]> {
    const params = new URLSearchParams({ status, limit: String(limit) });
    const body = await this.request<{ approvals?: ApprovalInfo[] }>(`/approvals?${params}`);
    return body.approvals ?? [];
  }

  async approveApproval(approvalId: string, decision: ApprovalDecision): Promise<ApprovalInfo> {
    return this.request<ApprovalInfo>(`/approvals/${encodeURIComponent(approvalId)}/approve`, {
      method: "POST",
      body: JSON.stringify(decision),
      headers: { "Content-Type": "application/json" }
    });
  }

  async denyApproval(approvalId: string, decision: ApprovalDecision): Promise<ApprovalInfo> {
    return this.request<ApprovalInfo>(`/approvals/${encodeURIComponent(approvalId)}/deny`, {
      method: "POST",
      body: JSON.stringify(decision),
      headers: { "Content-Type": "application/json" }
    });
  }

  async costBudget(): Promise<CostBudget> {
    return this.request<CostBudget>("/cost/budget");
  }

  async listHosts(): Promise<HostSummary[]> {
    const body = await this.request<{ hosts?: HostSummary[] }>("/hosts");
    return body.hosts ?? [];
  }

  async auditTail(): Promise<AuditTail> {
    return this.request<AuditTail>("/audit/tail");
  }

  async taskAudit(taskId: number): Promise<TaskAudit> {
    const body = await this.request<Partial<TaskAudit>>(`/audit/tasks/${taskId}`);
    return {
      events: body.events ?? [],
      verified: body.verified ?? false,
      error: body.error ?? null
    };
  }

  async loadSnapshot(): Promise<SnapshotResult> {
    const errors: Record<string, string> = {};
    const capture = async <T>(name: string, loader: () => Promise<T>, fallback: T): Promise<T> => {
      try {
        return await loader();
      } catch (error) {
        errors[name] = error instanceof Error ? error.message : String(error);
        return fallback;
      }
    };

    const [health, cluster, runners, agents, tasks, approvals, budget, hosts, audit] =
      await Promise.all([
        capture("health", () => this.healthz(), null),
        capture("cluster", () => this.clusterHealth(), null),
        capture("runners", () => this.listRunners(), []),
        capture("agents", () => this.listAgents(), []),
        capture("tasks", () => this.listTasks(), []),
        capture("approvals", () => this.listApprovals(), []),
        capture("budget", () => this.costBudget(), null),
        capture("hosts", () => this.listHosts(), []),
        capture("audit", () => this.auditTail(), null)
      ]);

    return {
      snapshot: { health, cluster, runners, agents, tasks, approvals, budget, hosts, audit },
      errors
    };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (!this.token) {
      throw new HubApiError("Hub token is required");
    }

    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: init.method ?? "GET",
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: "application/json",
          ...init.headers
        },
        body: init.body,
        signal: controller.signal
      });
      const text = await response.text();
      if (!response.ok) {
        throw new HubApiError(`Hub returned ${response.status}`, response.status, text);
      }
      if (!text) {
        return undefined as T;
      }
      return JSON.parse(text) as T;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new HubApiError("Hub request timed out");
      }
      throw error;
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}

export function normalizeHubUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  return withScheme.replace(/\/+$/, "");
}

export function parseListField(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function normalizeDispatchDraft(draft: DispatchDraft): DispatchBrief {
  const brief: DispatchBrief = {
    title: draft.title.trim(),
    kind: draft.kind,
    dispatch: draft.dispatch,
    branch: draft.branch.trim(),
    base_commit: draft.baseCommit.trim(),
    scope_globs: parseListField(draft.scopeGlobs),
    prompt: draft.prompt.trim(),
    required_tags: parseListField(draft.tags),
    required_capabilities: parseListField(draft.capabilities)
  };
  const skill = draft.skill.trim();
  const tool = draft.tool.trim();
  const command = parseListField(draft.command);
  if (skill) {
    brief.skill = skill;
  }
  if (tool) {
    brief.tool = tool;
  }
  if (draft.kind === "command") {
    brief.command = command;
  }
  return brief;
}

export function dispatchDisabledReason(
  draft: DispatchDraft,
  identity: DispatcherIdentitySummary | null,
  config: HubConfig
): string | null {
  const brief = normalizeDispatchDraft(draft);
  if (!config.hubUrl.trim()) {
    return "Hub URL is required";
  }
  if (!config.token.trim()) {
    return "Hub token is required";
  }
  if (!identity) {
    return "Load a dispatcher identity first";
  }
  if (!brief.title) {
    return "Title is required";
  }
  if (!brief.prompt) {
    return "Prompt/brief is required";
  }
  if (!brief.branch) {
    return "Branch is required";
  }
  if (!brief.base_commit) {
    return "Base commit is required";
  }
  if (brief.scope_globs.length === 0) {
    return "At least one scope glob is required";
  }
  if (brief.kind === "command" && (!brief.command || brief.command.length === 0)) {
    return "Command dispatch requires command tokens";
  }
  return null;
}

export async function loadDispatcherIdentity(path: string): Promise<DispatcherIdentitySummary> {
  return invoke<DispatcherIdentitySummary>("load_dispatcher_identity", { path });
}

export async function dispatchSignedTask(
  config: HubConfig,
  identity: DispatcherIdentitySummary,
  draft: DispatchDraft
): Promise<SignedDispatchResult> {
  return invoke<SignedDispatchResult>("dispatch_signed_task", {
    request: {
      hub_url: normalizeHubUrl(config.hubUrl),
      token: config.token,
      identity_path: identity.path,
      brief: normalizeDispatchDraft(draft)
    }
  });
}

export async function discoverHubs(seedUrls: string[]): Promise<HubDiscoveryCandidate[]> {
  return invoke<HubDiscoveryCandidate[]>("discover_hubs", { seedUrls });
}

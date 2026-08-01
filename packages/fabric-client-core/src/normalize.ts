import type {
  AgentDto, ApprovalDto, AuditDto, CapabilityDto, CostDto, FabricSnapshot,
  HostDto, McpServerDto, RunnerDto, SecretMetadataDto, SnapshotNormalizationContext,
  TaskDto,
} from "./contracts.js";

type Row = Readonly<Record<string, unknown>>;
const row = (value: unknown): Row => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const rows = (value: unknown): readonly Row[] => Array.isArray(value) ? value.map(row) : [];
const text = (value: unknown, fallback = ""): string => typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value);
const number = (value: unknown, fallback = 0): number => typeof value === "number" && Number.isFinite(value) ? value : fallback;
const optionalText = (value: unknown): string | undefined => text(value) || undefined;
const optionalNumber = (value: unknown): number | undefined => typeof value === "number" && Number.isFinite(value) ? value : undefined;

export function normalizeFabricSnapshot(raw: unknown, context: SnapshotNormalizationContext = {}): FabricSnapshot {
  const source = row(raw);
  const health = row(source.health);
  const runners: RunnerDto[] = rows(source.runners).map((runner) => ({
    id: text(runner.runner_id ?? runner.id, "unknown-runner"),
    name: text(runner.alias ?? runner.runner_id ?? runner.id, "Unknown runner"),
    ...(text(runner.hostname) ? { hostId: text(runner.hostname) } : {}),
    status: text(runner.state ?? runner.status, "unknown"),
  }));
  const hosts: HostDto[] = rows(source.hosts).map((host) => {
    const id = text(host.hostname ?? host.id, "unknown-host");
    return {
      id,
      name: text(host.display_name ?? host.label ?? host.hostname ?? host.id, "Unknown host"),
      status: host.is_active_hub === true ? "active hub" : "online",
      roles: Object.keys(row(host.roles)),
      runnerIds: runners.filter((runner) => runner.hostId?.toLowerCase() === id.toLowerCase()).map((runner) => runner.id),
      dispatchers: rows(host.dispatchers).map((dispatcher) => ({
        id: text(dispatcher.dispatcher_id ?? dispatcher.id, "unknown-dispatcher"),
        name: text(dispatcher.label ?? dispatcher.dispatcher_id ?? dispatcher.id, "Dispatcher"),
        status: text(dispatcher.status, "registered"),
      })),
    };
  });
  const tasks: TaskDto[] = rows(source.tasks).map((task) => {
    const dispatchedAt = optionalText(task.dispatched_at);
    const dispatchedByUser = optionalText(task.dispatched_by_user);
    const dispatchedByHost = optionalText(task.dispatched_by_host);
    const dispatchedByAgent = optionalText(task.dispatched_by_agent);
    const dispatcherPubkeyFingerprint = optionalText(task.dispatcher_pubkey_fingerprint);
    const claimedByRunner = optionalText(task.claimed_by_runner);
    const claimedByHost = optionalText(task.claimed_by_host);
    const startedAt = optionalText(task.started_at);
    const completedAt = optionalText(task.completed_at);
    const wallSeconds = optionalNumber(task.wall_seconds);
    const runnerCpuSeconds = optionalNumber(task.runner_cpu_seconds);
    const approvalsRequired = optionalNumber(task.approvals_required);
    const approvalsReceived = optionalNumber(task.approvals_received);
    const exitReason = optionalText(task.exit_reason);
    return {
      id: text(task.id ?? task.task_id, "unknown-task"),
      title: text(task.title, "Untitled task"),
      kind: task.kind === "command" ? "command" : "agent",
      status: text(task.status, "unknown"),
      ...(dispatchedAt ? { dispatchedAt } : {}),
      ...(dispatchedByUser ? { dispatchedByUser } : {}),
      ...(dispatchedByHost ? { dispatchedByHost } : {}),
      ...(dispatchedByAgent ? { dispatchedByAgent } : {}),
      ...(dispatcherPubkeyFingerprint ? { dispatcherPubkeyFingerprint } : {}),
      ...(claimedByRunner ? { claimedByRunner } : {}),
      ...(claimedByHost ? { claimedByHost } : {}),
      ...(startedAt ? { startedAt } : {}),
      ...(completedAt ? { completedAt } : {}),
      ...(wallSeconds === undefined ? {} : { wallSeconds }),
      ...(runnerCpuSeconds === undefined ? {} : { runnerCpuSeconds }),
      ...(Array.isArray(task.policy_decisions) ? { policyDecisions: rows(task.policy_decisions) } : {}),
      ...(approvalsRequired === undefined ? {} : { approvalsRequired }),
      ...(approvalsReceived === undefined ? {} : { approvalsReceived }),
      ...(exitReason ? { exitReason } : {}),
    };
  });
  const agents: AgentDto[] = rows(source.agents).map((agent) => {
    const manifest = row(agent.mcp_manifest);
    const servers: McpServerDto[] = rows(manifest.servers).map((server) => {
      const capabilities: CapabilityDto[] = [
        ...rows(server.prompts).map((item) => ({ kind: "prompt" as const, name: text(item.name, "prompt") })),
        ...rows(server.tools).map((item) => ({ kind: "tool" as const, name: text(item.name, "tool") })),
        ...rows(server.resources).map((item) => ({ kind: "resource" as const, name: text(item.name ?? item.uri, "resource") })),
      ];
      return {
        id: text(server.server_id ?? server.id, "unknown-server"),
        name: text(server.name ?? server.server_id ?? server.id, "MCP server"),
        capabilities,
      };
    });
    return {
      id: text(agent.runner_id ?? agent.id, "unknown-agent"),
      name: text(agent.alias ?? agent.runner_id ?? agent.id, "Unknown agent"),
      status: text(agent.state ?? agent.status, "unknown"),
      servers,
    };
  });
  const approvals: ApprovalDto[] = rows(source.approvals).map((approval) => ({
    id: text(approval.approval_id ?? approval.id, "unknown-approval"),
    title: text(approval.task_label ?? approval.title ?? approval.approval_id, "Approval"),
    status: text(approval.status, "pending"),
    ...(text(approval.envelope_hash) ? { envelopeHash: text(approval.envelope_hash) } : {}),
  }));
  const budget = row(source.budget);
  const costSummary = row(source.cost);
  const cost: CostDto | undefined = source.budget === null && source.cost === null ? undefined : {
    today: number(budget.daily_spend_usd ?? costSummary.today),
    week: number(budget.weekly_spend_usd ?? costSummary.week),
    currency: text(costSummary.currency, "USD"),
    ...(typeof budget.weekly_budget_usd === "number" ? { budget: budget.weekly_budget_usd } : {}),
  };
  const auditSource = row(source.audit);
  const audit: AuditDto[] = rows(auditSource.events ?? auditSource.items).map((event, index) => ({
    id: text(event.id ?? event.hash, String(index)),
    kind: text(event.kind ?? event.event_type, "event"),
    timestamp: text(event.created_at ?? event.ts, "unknown time"),
    ...(typeof event.verified === "boolean" ? { verified: event.verified } : {}),
  }));
  const secrets: SecretMetadataDto[] = rows(source.secrets).map((secret) => ({
    name: text(secret.name ?? secret.secret_name ?? secret.id, "secret"),
    configured: secret.configured !== false,
    ...(text(secret.updated_at) ? { updatedAt: text(secret.updated_at) } : {}),
  }));

  return {
    ...(Object.keys(health).length === 0 ? {} : { hub: {
      id: text(health.cluster_id ?? health.host, "active"),
      name: context.hubName ?? text(health.name ?? health.host, "Fabric Hub"),
      url: context.hubUrl ?? "",
      status: text(health.status, "unknown"),
      ...(health.uptime_seconds === undefined ? {} : { uptime: `${number(health.uptime_seconds)}s` }),
      ...(text(health.package_version ?? health.version) ? { version: text(health.package_version ?? health.version) } : {}),
      ...(health.protocol_version === undefined ? {} : { protocol: text(health.protocol_version) }),
    } }),
    hosts, runners, tasks, agents, approvals, ...(cost === undefined ? {} : { cost }),
    audit, secrets, settings: context.settings ?? [],
  };
}

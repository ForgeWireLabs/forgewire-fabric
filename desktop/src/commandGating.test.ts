import { describe, expect, it } from "vitest";
import type { ResourceFreshness } from "@forgewire/fabric-client-core";
import { desktopCommandAvailabilityFor, type DesktopGatingSources } from "./commandGating";

const liveTasks: ResourceFreshness = { observedAt: 1000, receivedAt: 1000, staleAfterMs: 60_000, source: "live" };

const base: DesktopGatingSources = {
  sessionState: "connected",
  features: new Set(["signed_dispatch"]),
  authorities: new Set(["fabric.tasks.write"]),
  identityPurpose: "Dispatcher",
  freshness: { tasks: liveTasks },
  selections: {},
  humanRoles: new Set(),
};

describe("desktopCommandAvailabilityFor", () => {
  const now = 1000;

  it("enables dispatchTask with a dispatcher identity, the authority, the feature and live task data", () => {
    expect(desktopCommandAvailabilityFor("forgewire.dispatchTask", base, now)).toEqual({ enabled: true });
  });

  it("fails closed when the credential lacks the task-write authority", () => {
    const availability = desktopCommandAvailabilityFor("forgewire.dispatchTask", { ...base, authorities: new Set() }, now);
    expect(availability.enabled).toBe(false);
    expect(availability.reason).toContain("fabric.tasks.write");
  });

  it("requires a matching task selection and status for cancelTask", () => {
    expect(desktopCommandAvailabilityFor("forgewire.cancelTask", base, now).reason).toContain("Select a task");
    const succeeded = desktopCommandAvailabilityFor("forgewire.cancelTask", { ...base, selections: { task: { id: "37", status: "succeeded" } } }, now);
    expect(succeeded.reason).toContain("supported state");
    expect(desktopCommandAvailabilityFor("forgewire.cancelTask", { ...base, selections: { task: { id: "37", status: "running" } } }, now)).toEqual({ enabled: true });
  });

  it("treats last-good task data as read-only (freshness stale) for a live-freshness command", () => {
    const stale = { ...liveTasks, source: "last-good" as const };
    const availability = desktopCommandAvailabilityFor("forgewire.cancelTask", {
      ...base,
      freshness: { tasks: stale },
      selections: { task: { id: "37", status: "running" } },
    }, now);
    expect(availability.enabled).toBe(false);
    expect(availability.reason).toContain("Live");
  });

  it("gates approvals and runner drain on their own authorities and selection status", () => {
    const approver: DesktopGatingSources = {
      ...base,
      authorities: new Set(["fabric.approvals.write"]),
      features: new Set(["approval_decisions"]),
      freshness: { approvals: liveTasks, runners: liveTasks },
    };
    expect(desktopCommandAvailabilityFor("forgewire.approveApproval", { ...approver, selections: { approval: { id: "a-1", status: "pending" } } }, now)).toEqual({ enabled: true });
    // A dispatcher-only credential cannot approve.
    expect(desktopCommandAvailabilityFor("forgewire.approveApproval", { ...base, features: new Set(["approval_decisions"]), selections: { approval: { id: "a-1", status: "pending" } } }, now).enabled).toBe(false);
    // pauseRunner needs an online runner + runner_drain feature + hosts.write.
    const hostOps: DesktopGatingSources = { ...base, authorities: new Set(["fabric.hosts.write"]), features: new Set(["runner_drain"]), freshness: { runners: liveTasks } };
    expect(desktopCommandAvailabilityFor("forgewire.pauseRunner", { ...hostOps, selections: { runner: { id: "r-1", status: "online" } } }, now)).toEqual({ enabled: true });
    expect(desktopCommandAvailabilityFor("forgewire.pauseRunner", { ...hostOps, selections: { runner: { id: "r-1", status: "draining" } } }, now).reason).toContain("supported state");
  });

  // 114C.7 Slice 5c: mirrors core.test.ts's identical VSIX-side test.
  it("gates account-admin commands on a human account role, failing closed for automation credentials", () => {
    // createAccount's descriptor has no selectionKind, so freshnessKeyFor
    // falls back to "health" -- must be live too, or the freshness gate
    // (not the human-role gate this test targets) is what rejects it.
    const ctx: DesktopGatingSources = { ...base, features: new Set(["human_accounts"]), freshness: { ...base.freshness, health: liveTasks } };
    // No human session at all: closed.
    expect(desktopCommandAvailabilityFor("forgewire.account.createAccount", ctx, now).reason).toContain("admin account role");
    // A human session carrying only a non-admin role: still closed.
    expect(desktopCommandAvailabilityFor("forgewire.account.createAccount", { ...ctx, humanRoles: new Set(["reviewer"]) }, now).reason).toContain("admin account role");
    // A signed-in admin: allowed.
    expect(desktopCommandAvailabilityFor("forgewire.account.createAccount", { ...ctx, humanRoles: new Set(["reviewer", "admin"]) }, now)).toEqual({ enabled: true });
  });
});

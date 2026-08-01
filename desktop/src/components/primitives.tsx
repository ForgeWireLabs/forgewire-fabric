import { FileClock, XCircle } from "lucide-react";

/** Shared presentational primitives used across every routed page in
 *  main.tsx. Extracted (114C.7 Slice 6b) so pages that need to be
 *  independently importable in a test -- without triggering main.tsx's
 *  module-scope `createRoot(...).render(<App/>)` side effect -- have
 *  something to import these from. Pure, prop-driven, no app state. */

export function Panel({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
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

export function statusClass(status: string) {
  if (["ok", "online", "done", "approved", "healthy", "connected"].includes(status)) {
    return "good";
  }
  if (["queued", "running", "pending", "held", "bootstrapping"].includes(status)) {
    return "work";
  }
  if (["degraded", "draining", "warning", "partial", "stale"].includes(status)) {
    return "warn";
  }
  if (["failed", "offline", "cancelled", "timed_out", "denied", "unauthorized", "incompatible", "misconfigured"].includes(status)) {
    return "bad";
  }
  return "neutral";
}

export function StatusPill({ status, compact = false }: { status: string; compact?: boolean }) {
  const normalized = status.toLowerCase();
  return <span className={`status-pill ${compact ? "compact" : ""} ${statusClass(normalized)}`}>{status}</span>;
}

export function StatusDot({ status }: { status?: string }) {
  return <span className={`status-dot ${statusClass(String(status ?? "unknown").toLowerCase())}`} />;
}

export function InfoLine({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <div className="info-line">
      <span>{icon}{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function EmptyState({ label }: { label: string }) {
  return <div className="empty-state"><FileClock size={18} />{label}</div>;
}

export function authorizationDenied(message?: string): boolean { return /\b(401|403|unauthori[sz]ed|forbidden|permission denied)\b|requires .+ role access/i.test(message ?? ""); }

export function AuthorizationOrFailure({ message }: { message: string }) {
  const denied = authorizationDenied(message);
  return <div className={`explicit-failure ${denied ? "authorization" : "transport"}`} role="alert"><XCircle size={18} /><div><strong>{denied ? "Authorization denied" : "Read or mutation failed"}</strong><span>{message}</span></div></div>;
}

export function AuthorizationState({ message }: { message: string | undefined }) {
  return <AuthorizationOrFailure message={message ?? "Approval authorization was denied."} />;
}

export function Tombstone({ label }: { label: string }) {
  return <div className="tombstone"><FileClock size={20} /><div><strong>Selection retained</strong><span>{label}</span><small>The route remains stable so returning objects can be reselected after refresh.</small></div></div>;
}

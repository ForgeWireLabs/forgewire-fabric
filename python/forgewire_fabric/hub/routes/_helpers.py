"""Shared route helpers for the ForgeWire Fabric hub."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

import httpx
from fastapi import HTTPException

from forgewire_fabric.hub._crypto import verify_signature
from forgewire_fabric.hub.server import Blackboard, SIGNATURE_MAX_SKEW_SECONDS

from ._deps import HubContext


def signed_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check_skew(timestamp: int) -> None:
    now = int(time.time())
    if abs(now - int(timestamp)) > SIGNATURE_MAX_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="timestamp out of skew window")


def _fire_generic_webhook(url: str, payload: dict[str, Any]) -> None:
    with httpx.Client(timeout=5.0) as client:
        client.post(url, json=payload)


def _fire_ntfy(url: str, payload: dict[str, Any]) -> None:
    approval_id = payload.get("approval_id", "?")
    task_label = payload.get("task_label", "?")
    event = payload.get("event", "approval")
    title = f"ForgeWire approval required: {task_label}"
    body = (
        f"Event: {event}\n"
        f"Approval ID: {approval_id}\n"
        f"Run: forgewire-fabric approvals approve {approval_id}"
    )
    with httpx.Client(timeout=5.0) as client:
        client.post(
            url,
            content=body.encode(),
            headers={
                "Title": title,
                "Priority": "high",
                "Tags": "warning,forgewire",
            },
        )


def _fire_slack(url: str, payload: dict[str, Any]) -> None:
    approval_id = payload.get("approval_id", "?")
    task_label = payload.get("task_label", "?")
    event = payload.get("event", "approval")
    decision = payload.get("decision", {})
    reason = decision.get("reason", "") if isinstance(decision, dict) else ""
    text = (
        f":warning: *ForgeWire approval required*\n"
        f"*Task:* `{task_label}`  |  *Event:* `{event}`\n"
        f"*Reason:* {reason or 'policy gate'}\n"
        f"*Approve:* `forgewire-fabric approvals approve {approval_id}`\n"
        f"*Deny:* `forgewire-fabric approvals deny {approval_id} --reason \"...\"``"
    )
    with httpx.Client(timeout=5.0) as client:
        client.post(url, json={"text": text})


def fire_approval_webhook(ctx: HubContext, payload: dict[str, Any]) -> None:
    log = logging.getLogger(__name__)
    config = ctx.config

    if config.approval_webhook_url:
        try:
            _fire_generic_webhook(config.approval_webhook_url, payload)
        except Exception as exc:  # noqa: BLE001
            log.warning("approval webhook to %s failed: %s", config.approval_webhook_url, exc)

    if config.approval_ntfy_url:
        try:
            _fire_ntfy(config.approval_ntfy_url, payload)
        except Exception as exc:  # noqa: BLE001
            log.warning("ntfy notification to %s failed: %s", config.approval_ntfy_url, exc)

    if config.approval_slack_url:
        try:
            _fire_slack(config.approval_slack_url, payload)
        except Exception as exc:  # noqa: BLE001
            log.warning("Slack notification to %s failed: %s", config.approval_slack_url, exc)


def enforce_dispatch_gate(
    ctx: HubContext,
    *,
    task_id: str,
    scope_globs: list[str],
    branch: str | None,
    dispatcher_id: str | None = None,
    approval_id: str | None = None,
) -> None:
    from forgewire_fabric.policy import DispatchRequest

    blackboard = ctx.blackboard
    decision = ctx.gate.evaluate_dispatch(
        DispatchRequest(
            task_id=str(task_id),
            scope_globs=list(scope_globs),
            target_branch=branch,
            dispatcher_id=dispatcher_id,
        )
    )
    if decision.allowed:
        return
    if decision.denied:
        raise HTTPException(status_code=403, detail=decision.to_dict())

    env_hash = blackboard.envelope_hash(
        scope_globs=list(scope_globs),
        branch=branch,
        task_label=str(task_id),
    )
    if approval_id and blackboard.consume_approval(approval_id, env_hash):
        return
    approval_id_new, created = blackboard.create_or_get_pending_approval(
        envelope_hash=env_hash,
        decision=decision.to_dict(),
        task_label=str(task_id),
        branch=branch,
        scope_globs=list(scope_globs),
        dispatcher_id=dispatcher_id,
    )
    detail = decision.to_dict()
    detail["approval_id"] = approval_id_new
    detail["envelope_hash"] = env_hash
    detail["hint"] = (
        "re-POST the same brief with approval_id=<id> after an operator "
        f"runs `forgewire-fabric approvals approve {approval_id_new}`"
    )
    if created:
        fire_approval_webhook(
            ctx,
            {
                "event": "approval.created",
                "approval_id": approval_id_new,
                "task_label": str(task_id),
                "branch": branch,
                "scope_globs": list(scope_globs),
                "decision": decision.to_dict(),
            },
        )
    raise HTTPException(status_code=428, detail=detail)


def enforce_intent_gate(
    ctx: HubContext,
    *,
    task_id: str,
    kind: str,
    paths: list[str],
    hosts: list[str],
    command: str | None,
    workspace_root: str | None,
    branch: str | None,
    approval_id: str | None = None,
) -> None:
    from forgewire_fabric.policy import IntentKind, TaskIntent

    try:
        intent_kind = IntentKind(kind)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"unknown intent kind: {kind!r}; valid: {[k.value for k in IntentKind]}",
        ) from exc

    intent = TaskIntent(
        kind=intent_kind,
        paths=tuple(paths),
        hosts=tuple(hosts),
        command=command,
        workspace_root=workspace_root,
        branch=branch,
    )
    decision = ctx.gate.evaluate_intent(intent)
    if decision.allowed:
        return
    if decision.denied:
        raise HTTPException(status_code=403, detail=decision.to_dict())

    blackboard = ctx.blackboard
    env_hash = blackboard.envelope_hash(
        scope_globs=list(paths) or [f"intent:{kind}"],
        branch=branch,
        task_label=f"intent:{task_id}:{kind}",
    )
    if approval_id and blackboard.consume_approval(approval_id, env_hash):
        return
    approval_id_new, created = blackboard.create_or_get_pending_approval(
        envelope_hash=env_hash,
        decision=decision.to_dict(),
        task_label=f"intent:{task_id}:{kind}",
        branch=branch,
        scope_globs=list(paths) or [f"intent:{kind}"],
        dispatcher_id=None,
    )
    detail = decision.to_dict()
    detail["approval_id"] = approval_id_new
    detail["envelope_hash"] = env_hash
    detail["hint"] = (
        "runner must pause and re-POST with approval_id=<id> after "
        f"`forgewire-fabric approvals approve {approval_id_new}`"
    )
    if created:
        fire_approval_webhook(
            ctx,
            {
                "event": "approval.created",
                "approval_id": approval_id_new,
                "task_id": task_id,
                "intent_kind": kind,
                "paths": paths,
                "hosts": hosts,
                "decision": decision.to_dict(),
            },
        )
    raise HTTPException(status_code=428, detail=detail)


def enforce_completion_gate(
    ctx: HubContext,
    *,
    task_id: str,
    changed_paths: list[str],
) -> None:
    from forgewire_fabric.policy import CompletionRequest

    decision = ctx.gate.evaluate_completion(
        CompletionRequest(
            task_id=str(task_id),
            changed_paths=list(changed_paths or ()),
            diff_lines=0,
        )
    )
    if decision.allowed or decision.needs_approval:
        return
    raise HTTPException(status_code=403, detail=decision.to_dict())


def sealed_brief_hash(
    *,
    title: str,
    prompt: str,
    scope_globs: list[str],
    base_commit: str,
    branch: str,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "title": title,
                "prompt": prompt,
                "scope_globs": sorted(scope_globs),
                "base_commit": base_commit,
                "branch": branch,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def audit_dispatch(
    ctx: HubContext,
    task: dict[str, Any],
    *,
    signed: bool,
    dispatcher_id: str | None,
    approval_id: str | None,
) -> None:
    try:
        sealed = sealed_brief_hash(
            title=task.get("title", ""),
            prompt=task.get("prompt", ""),
            scope_globs=list(task.get("scope_globs") or []),
            base_commit=task.get("base_commit", ""),
            branch=task.get("branch", ""),
        )
        ctx.blackboard.append_audit_event(
            kind="dispatch",
            task_id=int(task["id"]),
            payload={
                "task_id": int(task["id"]),
                "todo_id": task.get("todo_id"),
                "title": task.get("title"),
                "branch": task.get("branch"),
                "base_commit": task.get("base_commit"),
                "scope_globs": list(task.get("scope_globs") or []),
                "sealed_brief_hash": sealed,
                "dispatcher_id": dispatcher_id,
                "signed": signed,
                "approval_id": approval_id,
                "tenant": task.get("tenant"),
                "workspace_root": task.get("workspace_root"),
                "required_tools": list(task.get("required_tools") or []),
                "required_tags": list(task.get("required_tags") or []),
                "secrets_needed": list(task.get("secrets_needed") or []),
                "network_egress": task.get("network_egress"),
                "timeout_minutes": task.get("timeout_minutes"),
                "priority": task.get("priority"),
            },
        )
    except Exception as exc:  # noqa: BLE001 - audit must never block dispatch
        logging.getLogger(__name__).warning(
            "audit append failed for dispatch task=%s: %s", task.get("id"), exc
        )


def audit_claim(
    ctx: HubContext,
    task: dict[str, Any] | None,
    *,
    worker_id: str,
    secrets_dispatched: list[str] | None = None,
) -> None:
    if task is None:
        return
    try:
        ctx.blackboard.append_audit_event(
            kind="claim",
            task_id=int(task["id"]),
            payload={
                "task_id": int(task["id"]),
                "worker_id": worker_id,
                "claimed_at": task.get("claimed_at"),
                "secrets_dispatched": list(secrets_dispatched or []),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).warning(
            "audit append failed for claim task=%s: %s", task.get("id"), exc
        )


def audit_result(ctx: HubContext, task: dict[str, Any], *, worker_id: str) -> None:
    try:
        result = task.get("result") or {}
        ctx.blackboard.append_audit_event(
            kind="result",
            task_id=int(task["id"]),
            payload={
                "task_id": int(task["id"]),
                "worker_id": worker_id,
                "status": result.get("status"),
                "head_commit": result.get("head_commit"),
                "commits": list(result.get("commits") or []),
                "files_touched": list(result.get("files_touched") or []),
                "test_summary": result.get("test_summary"),
                "error": result.get("error"),
                "reported_at": result.get("reported_at"),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).warning(
            "audit append failed for result task=%s: %s", task.get("id"), exc
        )


def verify_runner_signature(
    ctx: HubContext,
    *,
    op: str,
    runner_id: str,
    timestamp: int,
    nonce: str,
    signature: str,
    extra: dict[str, Any] | None = None,
) -> None:
    check_skew(timestamp)
    public_key = ctx.blackboard.runner_public_key(runner_id)
    if public_key is None:
        raise HTTPException(status_code=404, detail="runner not registered")
    body = {
        "op": op,
        "runner_id": runner_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }
    if extra:
        body.update(extra)
    if not verify_signature(public_key, signed_payload(body), signature):
        raise HTTPException(status_code=403, detail="invalid runner signature")


def verify_audit_events(events: list[dict[str, Any]]) -> tuple[bool, str | None]:
    return Blackboard.verify_audit_chain(events)

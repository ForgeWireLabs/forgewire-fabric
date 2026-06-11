"""Dispatcher, runner registry, label, and claim routes."""

from __future__ import annotations

import json
import socket
from typing import Any

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from forgewire_fabric.hub._crypto import verify_signature
from forgewire_fabric.hub.server import (
    ClaimV2Request,
    DispatchTaskSignedRequest,
    DrainRequest,
    HeartbeatRequest,
    HostRoleRequest,
    MIN_COMPATIBLE_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
    RegisterDispatcherRequest,
    RegisterRequest,
    _build_host_summaries,
    _normalize_hostname,
    _parse_version,
)

from ._deps import get_context, require_auth, require_scope
from ._helpers import (
    audit_claim,
    audit_dispatch,
    check_skew,
    dispatch_v3_signed_payload,
    enforce_dispatch_gate,
    signed_payload,
    verify_runner_signature,
)

router = APIRouter()


@router.post("/hosts/roles", dependencies=[Depends(require_auth)])
def set_host_role(request: Request, payload: HostRoleRequest) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    return {
        "role": blackboard.set_host_role(
            hostname=payload.hostname,
            role=payload.role,
            enabled=payload.enabled,
            status=payload.status,
            metadata=payload.metadata or {},
        )
    }


@router.get("/hosts", dependencies=[Depends(require_auth)])
def list_hosts(request: Request) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    labels = blackboard.get_labels()
    runners = blackboard.list_runners()
    aliases = labels.get("runner_aliases") or {}
    host_aliases = labels.get("host_aliases") or {}
    for runner in runners:
        hostname = _normalize_hostname(runner.get("hostname"))
        runner["host_alias"] = host_aliases.get(hostname, "")
        runner["alias"] = aliases.get(runner.get("runner_id"), "") or runner["host_alias"]
    active_address = str(request.base_url).rstrip("/")
    hosts = _build_host_summaries(
        runners=runners,
        dispatchers=blackboard.list_dispatchers(),
        host_roles=blackboard.list_host_roles(),
        host_aliases=host_aliases,
        active_hub_hostname=socket.gethostname(),
        active_hub_address=active_address,
    )
    return {
        "hub_protocol_version": PROTOCOL_VERSION,
        "hub_name": labels.get("hub_name", ""),
        "active_hub_hostname": socket.gethostname(),
        "active_hub_address": active_address,
        "hosts": hosts,
    }


@router.post("/dispatchers/register", dependencies=[Depends(require_auth)])
def register_dispatcher(request: Request, payload: RegisterDispatcherRequest) -> dict[str, Any]:
    ctx = get_context(request)
    blackboard = ctx.blackboard
    check_skew(payload.timestamp)
    signed = signed_payload(
        {
            "op": "register-dispatcher",
            "dispatcher_id": payload.dispatcher_id,
            "public_key": payload.public_key,
            "timestamp": payload.timestamp,
            "nonce": payload.nonce,
        }
    )
    if not verify_signature(payload.public_key, signed, payload.signature):
        raise HTTPException(status_code=403, detail="invalid dispatcher self-attestation")
    try:
        record = blackboard.upsert_dispatcher(
            dispatcher_id=payload.dispatcher_id,
            public_key=payload.public_key,
            label=payload.label,
            hostname=payload.hostname,
            metadata=payload.metadata,
        )
        if payload.hostname:
            blackboard.set_host_role(
                hostname=payload.hostname,
                role="dispatch",
                enabled=True,
                status="registered",
                metadata={"dispatcher_id": payload.dispatcher_id, "label": payload.label},
            )
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"hub_protocol_version": PROTOCOL_VERSION, "dispatcher": record}


@router.get("/dispatchers", dependencies=[Depends(require_auth)])
def list_dispatchers(request: Request) -> dict[str, Any]:
    return {
        "hub_protocol_version": PROTOCOL_VERSION,
        "dispatchers": get_context(request).blackboard.list_dispatchers(),
    }


@router.post("/tasks/v2", dependencies=[Depends(require_auth)])
def dispatch_task_signed(request: Request, payload: DispatchTaskSignedRequest) -> dict[str, Any]:
    ctx = get_context(request)
    blackboard = ctx.blackboard
    check_skew(payload.timestamp)
    # M2.8.9: kind is mandatory — reject a missing value with 400 before any
    # signature/queue work (the legacy "absent → agent" default is gone).
    if not payload.kind:
        raise HTTPException(
            status_code=400,
            detail="kind is required (one of: agent, command)",
        )
    public_key = blackboard.dispatcher_public_key(payload.dispatcher_id)
    if public_key is None:
        raise HTTPException(status_code=404, detail="dispatcher not registered")
    signed = dispatch_v3_signed_payload(payload)
    if not verify_signature(public_key, signed, payload.signature):
        raise HTTPException(status_code=403, detail="invalid dispatch signature")
    # M2.9.7 legacy flip: command-kind briefs where loom_command was not covered
    # by the dispatcher signature are hard-rejected. The deprecation window is closed.
    if payload.kind == "command" and payload.loom_command is None:
        blackboard.append_audit_event(
            kind="legacy_loom_unsigned_command",
            task_id=None,
            payload={
                "dispatcher_id": payload.dispatcher_id,
                "title": payload.title,
                "warning": "command/cwd/env not covered by dispatcher signature; rejected",
            },
        )
        raise HTTPException(
            status_code=403,
            detail="unsigned Loom command brief rejected: dispatcher must sign command/cwd/env fields (upgrade to M2.9.1+)",
        )
    try:
        blackboard.consume_dispatcher_nonce(payload.dispatcher_id, payload.nonce)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="dispatcher not registered") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    dispatcher = blackboard.get_dispatcher(payload.dispatcher_id)
    dispatcher_hostname = dispatcher.get("hostname")
    if dispatcher_hostname:
        dispatch_role = blackboard.get_host_role(hostname=str(dispatcher_hostname), role="dispatch")
        if dispatch_role is not None and not dispatch_role.get("enabled"):
            raise HTTPException(
                status_code=403,
                detail=f"dispatch disabled for host {dispatcher_hostname}",
            )
    enforce_dispatch_gate(
        ctx,
        task_id=(payload.todo_id or payload.title),
        scope_globs=payload.scope_globs,
        branch=payload.branch,
        dispatcher_id=payload.dispatcher_id,
        approval_id=payload.approval_id,
    )
    try:
        task = blackboard.create_task(
            title=payload.title,
            prompt=payload.prompt,
            scope_globs=payload.scope_globs,
            base_commit=payload.base_commit,
            branch=payload.branch,
            todo_id=payload.todo_id,
            timeout_minutes=payload.timeout_minutes,
            priority=payload.priority,
            metadata=payload.metadata,
            required_tools=payload.required_tools,
            required_tags=payload.required_tags,
            tenant=payload.tenant,
            workspace_root=payload.workspace_root,
            require_base_commit=payload.require_base_commit,
            dispatcher_id=payload.dispatcher_id,
            required_capabilities=payload.required_capabilities,
            secrets_needed=payload.secrets_needed,
            network_egress=payload.network_egress,
            kind=payload.kind,
        )
        audit_dispatch(
            ctx,
            task,
            signed=True,
            dispatcher_id=payload.dispatcher_id,
            approval_id=payload.approval_id,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"rqlite unreachable: {exc}") from exc
    return task


@router.post("/runners/register", dependencies=[Depends(require_auth)])
def register_runner(request: Request, payload: RegisterRequest) -> dict[str, Any]:
    ctx = get_context(request)
    config = ctx.config
    blackboard = ctx.blackboard
    if payload.protocol_version != PROTOCOL_VERSION:
        if payload.protocol_version < MIN_COMPATIBLE_PROTOCOL_VERSION:
            raise HTTPException(
                status_code=426,
                detail=(
                    f"runner protocol_version={payload.protocol_version} "
                    f"is older than the hub's minimum {MIN_COMPATIBLE_PROTOCOL_VERSION}"
                ),
            )
        if payload.protocol_version > PROTOCOL_VERSION:
            raise HTTPException(
                status_code=426,
                detail=(
                    f"runner protocol_version={payload.protocol_version} "
                    f"is newer than the hub's {PROTOCOL_VERSION}"
                ),
            )
    if _parse_version(payload.runner_version) < _parse_version(config.min_runner_version):
        raise HTTPException(
            status_code=426,
            detail=(
                f"runner_version={payload.runner_version} is below the "
                f"hub's minimum {config.min_runner_version}"
            ),
        )
    check_skew(payload.timestamp)
    signed = signed_payload(
        {
            "op": "register",
            "runner_id": payload.runner_id,
            "public_key": payload.public_key,
            "protocol_version": payload.protocol_version,
            "timestamp": payload.timestamp,
            "nonce": payload.nonce,
        }
    )
    if not verify_signature(payload.public_key, signed, payload.signature):
        raise HTTPException(status_code=403, detail="invalid registration signature")
    try:
        record = blackboard.upsert_runner(
            {
                "runner_id": payload.runner_id,
                "public_key": payload.public_key,
                "hostname": payload.hostname,
                "os": payload.os,
                "arch": payload.arch,
                "cpu_model": payload.cpu_model,
                "cpu_count": payload.cpu_count,
                "ram_mb": payload.ram_mb,
                "gpu": payload.gpu,
                "tools": payload.tools,
                "tags": payload.tags,
                "scope_prefixes": payload.scope_prefixes,
                "tenant": payload.tenant,
                "workspace_root": payload.workspace_root,
                "runner_version": payload.runner_version,
                "protocol_version": payload.protocol_version,
                "max_concurrent": payload.max_concurrent,
                "metadata": payload.metadata or {},
                "capabilities": payload.capabilities or {},
                "kinds": payload.kinds,
                "agent_type": payload.agent_type,
                "mcp_manifest": payload.mcp_manifest,
            }
        )
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"hub_protocol_version": PROTOCOL_VERSION, "runner": record}


@router.get("/runners", dependencies=[Depends(require_auth)])
def list_runners(request: Request) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    labels = blackboard.get_labels()
    aliases = labels.get("runner_aliases") or {}
    host_aliases = labels.get("host_aliases") or {}
    runners = blackboard.list_runners()
    for runner in runners:
        hostname = _normalize_hostname(runner.get("hostname"))
        runner["host_alias"] = host_aliases.get(hostname, "")
        runner["alias"] = aliases.get(runner.get("runner_id"), "") or runner["host_alias"]
    return {
        "hub_protocol_version": PROTOCOL_VERSION,
        "hub_name": labels.get("hub_name", ""),
        "runners": runners,
    }


@router.get("/labels", dependencies=[Depends(require_auth)])
def get_labels(request: Request) -> dict[str, Any]:
    return get_context(request).blackboard.get_labels()


@router.put("/labels/hub", dependencies=[Depends(require_auth)])
def set_hub_label(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    name = str(payload.get("name", "")).strip()
    if len(name) > 80:
        raise HTTPException(status_code=400, detail="hub name max 80 chars")
    updated_by = str(payload.get("updated_by", "") or "")[:80] or None
    blackboard.set_hub_name(name, updated_by=updated_by)
    return blackboard.get_labels()


@router.put("/labels/runners/{runner_id}", dependencies=[Depends(require_auth)])
def set_runner_label(request: Request, runner_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    alias = str(payload.get("alias", "")).strip()
    if len(alias) > 80:
        raise HTTPException(status_code=400, detail="runner alias max 80 chars")
    updated_by = str(payload.get("updated_by", "") or "")[:80] or None
    blackboard.set_runner_alias(runner_id, alias, updated_by=updated_by)
    return blackboard.get_labels()


@router.put("/labels/hosts/{hostname}", dependencies=[Depends(require_auth)])
def set_host_label(request: Request, hostname: str, payload: dict[str, Any]) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    alias = str(payload.get("alias", "")).strip()
    if len(alias) > 80:
        raise HTTPException(status_code=400, detail="host alias max 80 chars")
    updated_by = str(payload.get("updated_by", "") or "")[:80] or None
    blackboard.set_host_alias(hostname, alias, updated_by=updated_by)
    return blackboard.get_labels()


@router.post("/runners/{runner_id}/heartbeat", dependencies=[Depends(require_auth)])
def heartbeat_runner(request: Request, runner_id: str, payload: HeartbeatRequest) -> dict[str, Any]:
    ctx = get_context(request)
    if runner_id != payload.runner_id:
        raise HTTPException(status_code=400, detail="runner_id mismatch")
    verify_runner_signature(
        ctx,
        op="heartbeat",
        runner_id=payload.runner_id,
        timestamp=payload.timestamp,
        nonce=payload.nonce,
        signature=payload.signature,
    )
    try:
        return ctx.blackboard.heartbeat_runner(
            runner_id=payload.runner_id,
            cpu_load_pct=payload.cpu_load_pct,
            ram_free_mb=payload.ram_free_mb,
            battery_pct=payload.battery_pct,
            on_battery=payload.on_battery,
            last_known_commit=payload.last_known_commit,
            nonce=payload.nonce,
            claim_failures_total=payload.claim_failures_total,
            claim_failures_consecutive=payload.claim_failures_consecutive,
            last_claim_error=payload.last_claim_error,
            heartbeat_failures_total=payload.heartbeat_failures_total,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/runners/{runner_id}/drain", dependencies=[Depends(require_scope("runner:control"))])
def drain_runner(request: Request, runner_id: str, payload: DrainRequest) -> dict[str, Any]:
    ctx = get_context(request)
    if runner_id != payload.runner_id:
        raise HTTPException(status_code=400, detail="runner_id mismatch")
    verify_runner_signature(
        ctx,
        op="drain",
        runner_id=payload.runner_id,
        timestamp=payload.timestamp,
        nonce=payload.nonce,
        signature=payload.signature,
    )
    try:
        return ctx.blackboard.request_drain(payload.runner_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc


@router.post("/runners/{runner_id}/drain-by-dispatcher", dependencies=[Depends(require_scope("runner:control"))])
def drain_runner_by_dispatcher(request: Request, runner_id: str) -> dict[str, Any]:
    try:
        return get_context(request).blackboard.request_drain(runner_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc


@router.post("/runners/{runner_id}/undrain-by-dispatcher", dependencies=[Depends(require_scope("runner:control"))])
def undrain_runner_by_dispatcher(request: Request, runner_id: str) -> dict[str, Any]:
    try:
        return get_context(request).blackboard.request_undrain(runner_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc


@router.delete("/runners/{runner_id}", dependencies=[Depends(require_scope("runner:control"))])
def deregister_runner(request: Request, runner_id: str) -> dict[str, Any]:
    """Remove a runner row from the registry.

    Idempotent: returns 404 if the runner is unknown, 200 with the
    deleted record otherwise. Used by ephemeral test harnesses (e.g. the
    live approval smoke) so probe identities do not accumulate as ghost
    host rows in the /hosts pane.
    """
    try:
        return get_context(request).blackboard.delete_runner(runner_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc


@router.delete("/dispatchers/{dispatcher_id}", dependencies=[Depends(require_auth)])
def deregister_dispatcher(request: Request, dispatcher_id: str) -> dict[str, Any]:
    """Remove a dispatcher row from the registry.

    Idempotent: returns 404 if unknown, 200 with the deleted record
    otherwise. Also retires the matching dispatch host_role row when no
    other dispatcher remains on that hostname.
    """
    try:
        return get_context(request).blackboard.delete_dispatcher(dispatcher_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="dispatcher not registered") from exc


# ── POST /tasks/claim-loom (M2.8.2) ──────────────────────────────────────────
# Loom queue: command-kind tasks only. Verifies runner has "command" in kinds.

@router.post("/tasks/claim-loom", dependencies=[Depends(require_auth)])
def claim_task_loom(request: Request, payload: ClaimV2Request) -> JSONResponse:
    ctx = get_context(request)
    verify_runner_signature(
        ctx,
        op="claim",
        runner_id=payload.runner_id,
        timestamp=payload.timestamp,
        nonce=payload.nonce,
        signature=payload.signature,
    )
    try:
        runner = ctx.blackboard.get_runner(payload.runner_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc

    runner_kinds = _runner_kinds(runner)
    if "command" not in runner_kinds:
        raise HTTPException(
            status_code=403,
            detail="runner is not registered as a Loom (command) runner",
        )

    task, info = ctx.blackboard.claim_next_task_v2(
        runner_id=payload.runner_id,
        scope_prefixes=payload.scope_prefixes,
        tools=payload.tools,
        tags=payload.tags,
        tenant=payload.tenant,
        workspace_root=payload.workspace_root,
        last_known_commit=payload.last_known_commit,
        cpu_load_pct=payload.cpu_load_pct,
        ram_free_mb=payload.ram_free_mb,
        battery_pct=payload.battery_pct,
        on_battery=payload.on_battery,
    )
    secrets_dispatched: list[str] = []
    if task is not None:
        requested = list(task.get("secrets_needed") or [])
        if requested:
            resolved = ctx.blackboard.resolve_secrets(requested)
            if resolved:
                task = dict(task)
                task["secrets"] = resolved
                secrets_dispatched = list(resolved.keys())
    audit_claim(ctx, task, worker_id=payload.runner_id, secrets_dispatched=secrets_dispatched)
    return JSONResponse(content={"task": task, "info": info})


# ── POST /tasks/claim-fabric (M2.8.2) ─────────────────────────────────────────
# Fabric queue: agent-kind tasks only. For skill/tool dispatch, requires
# matching runner_capabilities rows. Prompt dispatch skips capability filter.

@router.post("/tasks/claim-fabric", dependencies=[Depends(require_auth)])
def claim_task_fabric(request: Request, payload: ClaimV2Request) -> JSONResponse:
    ctx = get_context(request)
    verify_runner_signature(
        ctx,
        op="claim",
        runner_id=payload.runner_id,
        timestamp=payload.timestamp,
        nonce=payload.nonce,
        signature=payload.signature,
    )
    try:
        runner = ctx.blackboard.get_runner(payload.runner_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runner not registered") from exc

    runner_kinds = _runner_kinds(runner)
    if "agent" not in runner_kinds:
        raise HTTPException(
            status_code=403,
            detail="runner is not registered as a Fabric (agent) runner",
        )

    task, info = ctx.blackboard.claim_next_task_v2(
        runner_id=payload.runner_id,
        scope_prefixes=payload.scope_prefixes,
        tools=payload.tools,
        tags=payload.tags,
        tenant=payload.tenant,
        workspace_root=payload.workspace_root,
        last_known_commit=payload.last_known_commit,
        cpu_load_pct=payload.cpu_load_pct,
        ram_free_mb=payload.ram_free_mb,
        battery_pct=payload.battery_pct,
        on_battery=payload.on_battery,
    )
    secrets_dispatched: list[str] = []
    if task is not None:
        requested = list(task.get("secrets_needed") or [])
        if requested:
            resolved = ctx.blackboard.resolve_secrets(requested)
            if resolved:
                task = dict(task)
                task["secrets"] = resolved
                secrets_dispatched = list(resolved.keys())
    audit_claim(ctx, task, worker_id=payload.runner_id, secrets_dispatched=secrets_dispatched)
    return JSONResponse(content={"task": task, "info": info})


# ── GET /agents (M2.8.2) ──────────────────────────────────────────────────────
# Fabric runner registry: runners whose kinds array contains "agent".

@router.get("/agents", dependencies=[Depends(require_auth)])
def list_agents(request: Request) -> dict[str, Any]:
    blackboard = get_context(request).blackboard
    labels = blackboard.get_labels()
    runner_aliases = labels.get("runner_aliases") or {}
    host_aliases = labels.get("host_aliases") or {}
    runners = blackboard.list_runners()
    agents = []
    for r in runners:
        if "agent" not in _runner_kinds(r):
            continue
        hostname = _normalize_hostname(r.get("hostname") or "")
        host_alias = host_aliases.get(hostname, "")
        alias = runner_aliases.get(r.get("runner_id", ""), "") or host_alias
        # Parse mcp_manifest from stored JSON string if needed.
        mcp_manifest = r.get("mcp_manifest")
        if isinstance(mcp_manifest, str):
            try:
                mcp_manifest = json.loads(mcp_manifest)
            except (ValueError, TypeError):
                mcp_manifest = None
        agents.append({
            "runner_id": r.get("runner_id"),
            "agent_type": r.get("agent_type"),
            "hostname": r.get("hostname"),
            "alias": alias,
            "state": r.get("state"),
            "drain_requested": r.get("drain_requested"),
            "last_heartbeat": r.get("last_heartbeat"),
            "mcp_manifest": mcp_manifest,
            "mcp_manifest_version": r.get("mcp_manifest_version", 0),
            "kinds": _runner_kinds(r),
            "max_concurrent": r.get("max_concurrent"),
            "tenant": r.get("tenant"),
            "workspace_root": r.get("workspace_root"),
        })
    return {"agents": agents}


# ── GET /capabilities/{kind}/{name} (M2.8.2) ─────────────────────────────────

@router.get("/capabilities/{capability_kind}/{name}", dependencies=[Depends(require_auth)])
def get_capability(request: Request, capability_kind: str, name: str) -> dict[str, Any]:
    if capability_kind not in ("tool", "resource", "prompt"):
        raise HTTPException(
            status_code=400,
            detail=f"capability kind must be 'tool', 'resource', or 'prompt'; got '{capability_kind}'",
        )
    blackboard = get_context(request).blackboard
    runner_ids = blackboard.query_runners_by_capability(capability_kind, name)
    runners_out = []
    for rid in runner_ids:
        try:
            r = blackboard.get_runner(rid)
            runners_out.append({
                "runner_id": r.get("runner_id"),
                "agent_type": r.get("agent_type"),
                "hostname": r.get("hostname"),
                "state": r.get("state"),
                "drain_requested": r.get("drain_requested"),
            })
        except KeyError:
            pass
    return {"capability_kind": capability_kind, "name": name, "runners": runners_out}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _runner_kinds(runner: dict[str, Any]) -> list[str]:
    """Return the runner's kinds list, parsing JSON if needed."""
    kinds = runner.get("kinds")
    if isinstance(kinds, list):
        return kinds
    if isinstance(kinds, str):
        try:
            parsed = json.loads(kinds)
            if isinstance(parsed, list):
                return parsed
        except (ValueError, TypeError):
            pass
    return ["agent"]  # backward-compat default

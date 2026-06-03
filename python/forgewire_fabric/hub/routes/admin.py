"""Administrative snapshot/import routes (rqlite only)."""

from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response as FastAPIResponse

from ._deps import get_context, require_auth

router = APIRouter()


@router.get("/state/snapshot", dependencies=[Depends(require_auth)])
def state_snapshot(request: Request) -> FastAPIResponse:
    """Download a rqlite database backup."""
    ctx = get_context(request)
    config = ctx.config
    try:
        with httpx.Client(
            base_url=f"http://{config.rqlite_host}:{config.rqlite_port}",
            timeout=60.0,
            follow_redirects=True,
        ) as client:
            resp = client.get("/db/backup")
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"rqlite /db/backup failed: {resp.status_code} {resp.text[:200]}",
                )
            data = resp.content
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"rqlite unreachable: {exc}") from exc
    return FastAPIResponse(
        content=data,
        media_type="application/octet-stream",
        headers={
            "X-Snapshot-Generated-At": str(time.time()),
            "X-Hub-Started-At": str(request.app.state.started_at),
            "X-Snapshot-Source": "rqlite",
        },
    )


@router.post("/state/import", dependencies=[Depends(require_auth)])
async def state_import(request: Request) -> dict[str, Any]:
    """Load a rqlite database backup."""
    ctx = get_context(request)
    config = ctx.config
    blackboard = ctx.blackboard
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty body")
    force = request.headers.get("x-force", "").strip() == "1"
    if not force:
        count = blackboard.count_tasks()
        if count > 0:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"refusing to import over a non-empty hub "
                    f"({count} tasks); send X-Force: 1 to override"
                ),
            )
    try:
        with httpx.Client(
            base_url=f"http://{config.rqlite_host}:{config.rqlite_port}",
            timeout=120.0,
            follow_redirects=True,
        ) as client:
            resp = client.post(
                "/db/load",
                content=body,
                headers={"Content-Type": "application/octet-stream"},
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"rqlite /db/load failed: {resp.status_code} {resp.text[:200]}",
                )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"rqlite unreachable: {exc}") from exc
    return {"status": "imported", "bytes": len(body), "backend": "rqlite"}

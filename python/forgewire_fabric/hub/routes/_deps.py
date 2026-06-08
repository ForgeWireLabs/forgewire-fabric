"""Shared FastAPI dependencies for hub route modules."""

from __future__ import annotations

import secrets as secrets_lib
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Request, status


@dataclass(slots=True)
class HubContext:
    config: Any
    blackboard: Any
    gate: Any


def _token_scopes(request: Request, presented: str) -> set[str]:
    if secrets_lib.compare_digest(presented, request.app.state.token):
        return {"*"}
    scoped_tokens = getattr(request.app.state, "scoped_tokens", {}) or {}
    for token, scopes in scoped_tokens.items():
        if secrets_lib.compare_digest(presented, str(token)):
            return {str(scope) for scope in scopes}
    return set()


def _has_scope(granted: set[str], required: str) -> bool:
    if "*" in granted or required in granted:
        return True
    head = required.split(":", 1)[0]
    return head in granted or f"{head}:*" in granted


def get_context(request: Request) -> HubContext:
    return request.app.state.hub_context


async def require_auth(request: Request) -> None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
        )
    presented = header.split(" ", 1)[1].strip()
    scopes = _token_scopes(request, presented)
    if not scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid bearer token",
        )
    request.state.auth_scopes = scopes


def require_scope(scope: str):
    async def _dependency(request: Request, _auth: None = Depends(require_auth)) -> None:
        scopes = getattr(request.state, "auth_scopes", set())
        if not _has_scope(set(scopes), scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "insufficient token scope", "required_scope": scope},
            )

    return _dependency

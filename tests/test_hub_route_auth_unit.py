from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from forgewire_fabric.hub.routes import tasks
from forgewire_fabric.hub.routes._deps import require_scope


def test_tasks_claim_route_registered_before_task_id_route() -> None:
    paths = [getattr(route, "path", "") for route in tasks.router.routes]
    assert paths.index("/tasks/claim") < paths.index("/tasks/{task_id}")


def test_operation_scoped_token_allows_matching_scope_only() -> None:
    app = FastAPI()
    app.state.token = "primary-token-aaaaaaaa"
    app.state.scoped_tokens = {
        "secret-token-aaaaaaaaa": {"secrets"},
        "approval-token-aaaaaaa": {"approvals:write"},
    }

    @app.get("/secrets", dependencies=[Depends(require_scope("secrets"))])
    def secrets_route() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/approvals", dependencies=[Depends(require_scope("approvals:write"))])
    def approvals_route() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        secret_auth = {"authorization": "Bearer secret-token-aaaaaaaaa"}
        assert client.get("/secrets", headers=secret_auth).status_code == 200
        denied = client.post("/approvals", headers=secret_auth)
        assert denied.status_code == 403
        assert denied.json()["detail"]["required_scope"] == "approvals:write"

        primary_auth = {"authorization": "Bearer primary-token-aaaaaaaa"}
        assert client.post("/approvals", headers=primary_auth).status_code == 200

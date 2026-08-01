from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SYNC_SCRIPT = REPO_ROOT / "scripts" / "install" / "sync-deployment-clone.ps1"


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("pwsh") is None,
    reason="requires real git and PowerShell",
)
def test_dirty_deployment_clone_is_archived_and_fast_forwarded(tmp_path: Path) -> None:
    """Exercise the real preservation workflow; no Git operations are mocked."""
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    deployed = tmp_path / "deployed"
    backups = tmp_path / "backups"

    _run("git", "init", "--bare", str(origin), cwd=tmp_path)
    _run("git", "init", "-b", "main", str(seed), cwd=tmp_path)
    _run("git", "config", "user.name", "ForgeWire Test", cwd=seed)
    _run("git", "config", "user.email", "test@forgewire.invalid", cwd=seed)
    (seed / "service.txt").write_text("v1\n", encoding="utf-8")
    _run("git", "add", "service.txt", cwd=seed)
    _run("git", "commit", "-m", "initial", cwd=seed)
    _run("git", "remote", "add", "origin", str(origin), cwd=seed)
    _run("git", "push", "-u", "origin", "main", cwd=seed)
    _run("git", "symbolic-ref", "HEAD", "refs/heads/main", cwd=origin)

    _run("git", "clone", str(origin), str(deployed), cwd=tmp_path)
    _run("git", "config", "user.name", "ForgeWire Test", cwd=deployed)
    _run("git", "config", "user.email", "test@forgewire.invalid", cwd=deployed)

    (seed / "service.txt").write_text("v2 upstream\n", encoding="utf-8")
    _run("git", "commit", "-am", "upstream", cwd=seed)
    _run("git", "push", cwd=seed)

    (deployed / "service.txt").write_text("operator edit\n", encoding="utf-8")
    (deployed / "operator-note.txt").write_text("retain me\n", encoding="utf-8")

    result = _run(
        "pwsh",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SYNC_SCRIPT),
        "-RepoRoot",
        str(deployed),
        "-BackupRoot",
        str(backups),
        cwd=deployed,
    )

    assert "ARCHIVE_BRANCH=operator/" in result.stdout
    assert "DEPLOYMENT_HEAD=" in result.stdout
    assert (deployed / "service.txt").read_text(encoding="utf-8") == "v2 upstream\n"
    assert not (deployed / "operator-note.txt").exists()
    assert _run("git", "status", "--porcelain", cwd=deployed).stdout == ""

    branches = _run("git", "branch", "--list", "operator/*", cwd=deployed).stdout
    archive = next(line.strip().lstrip("* ") for line in branches.splitlines() if line.strip())
    archived_note = _run("git", "show", f"{archive}:operator-note.txt", cwd=deployed).stdout
    assert archived_note == "retain me\n"
    bundles = list(backups.glob("*.bundle"))
    assert len(bundles) == 1
    _run("git", "bundle", "verify", str(bundles[0]), cwd=deployed)

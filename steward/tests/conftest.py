from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from coquic_steward.core.config import StewardConfig, StewardLimits
from coquic_steward.core.subprocesses import run_command


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.fail("git executable is required for steward tests")
    return str(Path(executable).resolve(strict=True))


def _run_git(cwd: Path, *args: str) -> None:
    run_command([_git_executable(), *args], cwd=cwd, check=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _run_git(path, "init", "-b", "main")
    _run_git(path, "config", "user.email", "steward@example.test")
    _run_git(path, "config", "user.name", "Steward Test")
    (path / "README.md").write_text("hello\n", encoding="utf-8")
    _run_git(path, "add", "README.md")
    _run_git(path, "commit", "-m", "initial")
    return path


@pytest.fixture(autouse=True)
def coquic_home(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "coquic-home"
    monkeypatch.setenv("COQUIC_HOME", str(path))
    return path


@pytest.fixture
def config(repo: Path) -> StewardConfig:
    cfg = StewardConfig(
        repo_root=repo,
        limits=StewardLimits(worker_timeout_minutes=1),
    )
    cfg.ensure_dirs()
    return cfg

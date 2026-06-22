from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from coquic_steward.core.config import StewardConfig, StewardLimits


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "steward@example.test"], cwd=path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Steward Test"], cwd=path, check=True)
    (path / "README.md").write_text("hello\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
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

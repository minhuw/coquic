from __future__ import annotations

import importlib.util
import importlib.machinery
import os
from pathlib import Path
import signal
import subprocess
import sys


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "qdrant-dev"


def _make_repo_root(tmp_path: Path, name: str = "repo") -> Path:
    repo_root = tmp_path / name
    (repo_root / "docs" / "rfc").mkdir(parents=True)
    (repo_root / "build.zig").write_text("", encoding="utf-8")
    return repo_root


def _load_qdrant_dev_module():
    loader = importlib.machinery.SourceFileLoader(
        "test_qdrant_dev_script",
        str(SCRIPT_PATH),
    )
    spec = importlib.util.spec_from_loader("test_qdrant_dev_script", loader)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_cli(
    repo_root: Path,
    *args: str,
    dry_run: bool = True,
    env_updates: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if dry_run:
        env["COQUIC_QDRANT_DEV_DRY_RUN"] = "1"
    else:
        env.pop("COQUIC_QDRANT_DEV_DRY_RUN", None)
    if env_updates:
        env.update(env_updates)
    cwd = repo_root / "nested" / "workdir"
    cwd.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_start_writes_localhost_only_config(tmp_path: Path) -> None:
    repo_root = _make_repo_root(tmp_path)

    result = _run_cli(repo_root, "start")

    assert result.returncode == 0, result.stderr
    config_path = repo_root / ".rag" / "dev" / "qdrant.yaml"
    assert config_path.is_file()
    config_text = config_path.read_text(encoding="utf-8")
    assert "host: 127.0.0.1" in config_text
    assert "grpc_port: null" in config_text


def test_start_quotes_repo_paths_in_generated_config(tmp_path: Path) -> None:
    repo_root = _make_repo_root(tmp_path, name="repo with spaces:colon")

    result = _run_cli(repo_root, "start")

    assert result.returncode == 0, result.stderr
    config_text = (repo_root / ".rag" / "dev" / "qdrant.yaml").read_text(
        encoding="utf-8"
    )
    assert f'storage_path: "{repo_root / ".rag" / "qdrant-server" / "storage"}"' in config_text
    assert (
        f'snapshots_path: "{repo_root / ".rag" / "qdrant-server" / "snapshots"}"'
        in config_text
    )


def test_status_reports_pid_log_and_config_paths(tmp_path: Path) -> None:
    repo_root = _make_repo_root(tmp_path)
    start_result = _run_cli(repo_root, "start")
    assert start_result.returncode == 0, start_result.stderr

    result = _run_cli(repo_root, "status")

    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert str(repo_root / ".rag" / "dev" / "qdrant.pid") in output
    assert str(repo_root / ".rag" / "dev" / "qdrant.log") in output
    assert str(repo_root / ".rag" / "dev" / "qdrant.yaml") in output


def test_start_fails_cleanly_when_qdrant_exits_immediately(tmp_path: Path) -> None:
    repo_root = _make_repo_root(tmp_path)
    fake_binary = tmp_path / "fake-qdrant"
    fake_binary.write_text("#!/usr/bin/env bash\nexit 23\n", encoding="utf-8")
    fake_binary.chmod(0o755)

    result = _run_cli(
        repo_root,
        "start",
        dry_run=False,
        env_updates={"COQUIC_QDRANT_BINARY": str(fake_binary)},
    )

    assert result.returncode == 1
    assert "exited" in result.stderr
    assert not (repo_root / ".rag" / "dev" / "qdrant.pid").exists()


def test_stop_refuses_to_signal_unrelated_pid(tmp_path: Path) -> None:
    repo_root = _make_repo_root(tmp_path)
    pid_path = repo_root / ".rag" / "dev" / "qdrant.pid"
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")

    result = _run_cli(repo_root, "stop")

    assert result.returncode == 1
    assert "does not belong" in result.stderr
    assert pid_path.is_file()


def test_status_handles_unreadable_proc_cmdline(tmp_path: Path, monkeypatch) -> None:
    repo_root = _make_repo_root(tmp_path)
    module = _load_qdrant_dev_module()

    monkeypatch.setattr(module, "read_pid", lambda _path: 123)
    monkeypatch.setattr(module, "pid_is_alive", lambda _pid: True)
    monkeypatch.setattr(
        module.Path,
        "read_bytes",
        lambda _self: (_ for _ in ()).throw(PermissionError("denied")),
    )

    assert module.read_cmdline(123) is None
    status_lines = module.status_lines(repo_root)

    assert "pid file points to unrelated live process" in status_lines[1]


def test_stop_rechecks_ownership_before_sigkill(tmp_path: Path, monkeypatch) -> None:
    repo_root = _make_repo_root(tmp_path)
    pid_path = repo_root / ".rag" / "dev" / "qdrant.pid"
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text("123\n", encoding="utf-8")
    module = _load_qdrant_dev_module()

    ownership_checks = iter([True, False])
    signals_sent: list[signal.Signals] = []

    monkeypatch.setattr(module, "STOP_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(module, "pid_is_alive", lambda _pid: True)
    monkeypatch.setattr(
        module,
        "is_expected_qdrant_process",
        lambda _pid, _config_path: next(ownership_checks),
    )
    monkeypatch.setattr(
        module,
        "send_signal",
        lambda _pid, sig: signals_sent.append(sig) or True,
    )

    result = module.stop(repo_root)

    assert result == 1
    assert signals_sent == [signal.SIGTERM]
    assert pid_path.is_file()

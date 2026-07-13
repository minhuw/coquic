from __future__ import annotations

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.config import load_config
from coquic_steward.storage import TaskStore


def _invoke_tick(repo, monkeypatch, *args: str):
    monkeypatch.chdir(repo)
    return CliRunner().invoke(app, ["tick", *args])


def test_tick_requests_default_scheduler_wakeup(repo, monkeypatch) -> None:
    result = _invoke_tick(repo, monkeypatch)

    assert result.exit_code == 0, result.output
    fields = result.output.strip().split()
    assert fields[0] == "requested"
    wakeup_id = fields[1]
    assert fields[2:] == ["plan=true", "dispatch=true", "max_dispatch=-"]

    wakeup = TaskStore(load_config().db_path).pending_wakeups()[0]
    assert wakeup.id == wakeup_id
    assert wakeup.reason == "scheduler.manual"
    assert wakeup.data == {"plan": True, "dispatch": True, "max_dispatch": None}


def test_tick_persists_normalized_options_and_prints_them(repo, monkeypatch) -> None:
    result = _invoke_tick(
        repo,
        monkeypatch,
        "--plan",
        "--no-dispatch",
        "--max-dispatch",
        "3",
    )

    assert result.exit_code == 0, result.output
    assert "plan=true dispatch=false max_dispatch=3" in result.output

    wakeup = TaskStore(load_config().db_path).pending_wakeups()[0]
    assert wakeup.data == {"plan": True, "dispatch": False, "max_dispatch": 3}


@pytest.mark.parametrize("value", ["0", "-1", "not-an-integer"])
def test_tick_rejects_invalid_max_dispatch(repo, monkeypatch, value: str) -> None:
    result = _invoke_tick(repo, monkeypatch, "--max-dispatch", value)

    assert result.exit_code == 2
    assert "Invalid value for '--max-dispatch'" in result.output
    assert TaskStore(load_config().db_path).pending_wakeups() == []


def test_tick_does_not_run_a_cycle_or_acquire_daemon_lock(repo, monkeypatch) -> None:
    def fail_lock(*_args, **_kwargs):
        raise AssertionError("tick must not acquire the daemon lock")

    def fail_cycle(*_args, **_kwargs):
        raise AssertionError("tick must only request a durable wakeup")

    monkeypatch.setattr("coquic_steward.cli.acquire_daemon_lock", fail_lock)
    monkeypatch.setattr("coquic_steward.cli.StewardDaemon.tick", fail_cycle)

    result = _invoke_tick(repo, monkeypatch, "--no-plan", "--no-dispatch")

    assert result.exit_code == 0, result.output
    wakeup = TaskStore(load_config().db_path).pending_wakeups()[0]
    assert wakeup.data == {"plan": False, "dispatch": False, "max_dispatch": None}

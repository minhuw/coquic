from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

import coquic_steward.cli as cli
from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import ExecutionMode, TaskKind, TaskSpec, WorkerKind
from coquic_steward.storage import TaskStore


@pytest.fixture
def health_store(tmp_path, monkeypatch):
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()
    store = TaskStore.create(config.db_path, dry_run=False)
    monkeypatch.setattr(cli, "load_config", lambda: config)
    yield config, store
    store.engine.dispose()


def _invoke(*arguments):
    result = CliRunner().invoke(cli.app, ["health", *arguments])
    return result, json.loads(result.stdout)


def _claim(store, config, **overrides):
    state = {
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        "runtime_protocol": config.runtime_protocol,
        "release_id": config.deployment.release_id,
    }
    state.update(overrides)
    store.claim_daemon_instance("daemon-health-test", lifecycle="running", state=state)


def test_store_readiness_does_not_claim_runtime_liveness(health_store):
    _config, store = health_store
    result, payload = _invoke()
    assert result.exit_code == 1
    assert payload["store"] == "ok"
    assert payload["lifecycle"] == "absent"
    assert payload["runtimeHealthy"] is False
    assert payload["quiescent"] is False
    assert payload["pressure"] == "unknown"
    result, payload = _invoke("--store-only")
    assert result.exit_code == 0
    assert payload == {"mode": "store-only", "store": "ok"}
    assert store.get_daemon_state() is None


@pytest.mark.parametrize("lifecycle", ["starting", "reconciling", "stopping", "stopped"])
def test_nonrunning_daemon_is_unhealthy_even_with_fresh_heartbeat(health_store, lifecycle):
    config, store = health_store
    _claim(store, config)
    store.set_daemon_lifecycle(lifecycle, instance_id="daemon-health-test")
    result, payload = _invoke()
    assert result.exit_code == 1
    assert payload["lifecycle"] == lifecycle
    assert payload["quiescent"] is False
    assert _invoke("--store-only")[0].exit_code == 0


@pytest.mark.parametrize("heartbeat", [None, "invalid", "2025-01-01T00:00:00", -91, 120])
def test_missing_invalid_stale_or_future_heartbeat_is_unhealthy(health_store, heartbeat):
    config, store = health_store
    if isinstance(heartbeat, int):
        heartbeat = (datetime.now(timezone.utc) + timedelta(seconds=heartbeat)).isoformat()
    _claim(store, config, heartbeat_at=heartbeat)
    # Claiming the row just updated updated_at; it is not a heartbeat substitute.
    result, payload = _invoke()
    assert result.exit_code == 1
    assert payload["heartbeat"] != "ok"


def test_ambiguous_owner_is_unhealthy(health_store):
    config, store = health_store
    _claim(store, config)
    store.claim_daemon_instance("unknown", lifecycle="running", state={
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        "runtime_protocol": config.runtime_protocol,
    })
    result, payload = _invoke()
    assert result.exit_code == 1
    assert payload["lifecycle"] == "ambiguous"
    assert payload["daemonInstanceId"] is None


def test_fresh_daemon_reports_progress_separately_and_pressure_is_not_death(health_store):
    config, store = health_store
    _claim(store, config)
    result, payload = _invoke()
    assert result.exit_code == 0
    assert payload["heartbeat"] == "ok"
    assert payload["runtimeHealthy"] is True
    assert payload["quiescent"] is False  # Missing cycle evidence is not idle proof.
    store.set_daemon_lifecycle("running", instance_id="daemon-health-test", state={
        "current_cycle_started_at": None,
    })
    assert _invoke()[1]["quiescent"] is True
    assert payload["cycleProgress"] == {"currentStartedAt": None, "lastCompletedAt": None}
    completed = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    started = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    store.set_daemon_lifecycle("running", instance_id="daemon-health-test", state={
        "last_completed_cycle_at": completed, "current_cycle_started_at": started,
    })
    store.record_resource_pressure(state="resource_pressure", home_free_bytes=10,
                                   owned_docker_bytes=100)
    result, payload = _invoke()
    assert result.exit_code == 0
    assert payload["cycleProgress"] == {"currentStartedAt": started, "lastCompletedAt": completed}
    assert payload["quiescent"] is False
    assert payload["pressure"] == "resource_pressure"
    assert payload["resourceObservedAt"] is not None
    assert payload["publicationHealth"] is not None


@pytest.mark.parametrize("release,protocol,healthy", [
    ("selected-release", "task-container-v1", True),
    ("old-release", "task-container-v1", False),
    (None, "task-container-v1", False),
    ("selected-release", "wrong-protocol", False),
])
def test_release_identity_comes_from_daemon_not_selected_config(
    health_store, monkeypatch, release, protocol, healthy,
):
    config, store = health_store
    deployment = replace(
        config.deployment, enabled=True, release_id="selected-release",
        home=config.coquic_home, repository=config.coquic_home / "repository",
        min_free_bytes=1, recovery_free_bytes=2,
        max_owned_docker_bytes=2, recovery_owned_docker_bytes=1,
    )
    config = replace(config, deployment=deployment)
    monkeypatch.setattr(cli, "load_config", lambda: config)
    _claim(store, config, release_id=release, runtime_protocol=protocol)
    result, payload = _invoke()
    assert result.exit_code == (0 if healthy else 1)
    assert payload["release"] == release
    assert payload["runtimeProtocol"] == protocol
    assert payload["releaseMatches"] is (release == "selected-release")


@pytest.mark.parametrize("arguments", [(), ("--store-only",)])
def test_health_preserves_live_execution_mode_under_dry_run_config(health_store, arguments):
    config, store = health_store
    assert config.dry_run is True
    task, _ = store.add_task(TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom,
                                     title="live task", prompt="inspect"))
    _claim(store, config)
    before = store.get_daemon_state()
    assert store.task_execution_mode(task.id) is ExecutionMode.live
    assert _invoke(*arguments)[0].exit_code == 0
    assert store.get_daemon_state() == before
    assert store.task_execution_mode(task.id) is ExecutionMode.live


@pytest.mark.parametrize("arguments", [(), ("--store-only",)])
@pytest.mark.parametrize("contents", [None, b"not sqlite"])
def test_missing_or_corrupt_store_is_unhealthy_without_creation(
    tmp_path, monkeypatch, arguments, contents,
):
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()
    if contents is not None:
        config.db_path.write_bytes(contents)
    before = {path: path.read_bytes() for path in config.coquic_home.rglob("*") if path.is_file()}
    monkeypatch.setattr(cli, "load_config", lambda: config)
    result, payload = _invoke(*arguments)
    assert result.exit_code == 1
    assert payload["store"] == "unavailable"
    assert {path: path.read_bytes() for path in config.coquic_home.rglob("*") if path.is_file()} == before

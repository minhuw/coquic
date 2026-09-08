from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

import coquic_steward.cli as cli
import coquic_steward.orchestration.daemon as daemon_module
from coquic_steward.core.models import EffectActionKind, ExecutionMode
from coquic_steward.orchestration.daemon import StewardDaemon, TickResult
from coquic_steward.storage import TaskStore


@pytest.fixture
def running_daemon(config, monkeypatch):
    config = replace(
        config, dry_run=False,
        deployment=replace(config.deployment, release_id="health-release"),
    )
    store = TaskStore.create(config.db_path, dry_run=False)
    logs = []
    daemon = StewardDaemon(config, store, logger=logs.append)
    # Keep the actual startup/recovery/claim and local test session boundary;
    # external credential/remote validation is not under test.
    monkeypatch.setattr(daemon_module, "preflight_remote_push", lambda *_: False)
    monkeypatch.setattr(daemon_module, "run_preflight", lambda *a, **kw: daemon_module.PreflightReport())
    monkeypatch.setattr(cli, "load_config", lambda: config)
    daemon.startup_reconcile()
    yield daemon, store, logs
    daemon.shutdown(force=True)
    store.engine.dispose()


def _health():
    result = CliRunner().invoke(cli.app, ["health"])
    return result.exit_code, json.loads(result.stdout)


def _update(store, owner, timestamp, **progress):
    return store.update_daemon_health(
        owner, heartbeat_at=timestamp,
        current_cycle_started_at=progress.get("current_cycle_started_at"),
        last_completed_cycle_at=progress.get("last_completed_cycle_at"),
    )


def test_real_startup_heartbeat_and_cycle_feed_cli_health(running_daemon, monkeypatch):
    daemon, store, _logs = running_daemon
    initial = store.get_daemon_state()
    authority = store.get_daemon_publication_authority(daemon.runtime.instance_id)
    assert authority is not None and authority.mode is ExecutionMode.live
    assert initial["current_cycle_started_at"] is None
    assert initial["last_completed_cycle_at"] is None
    code, payload = _health()
    assert code == 0
    assert payload["release"] == "health-release"
    assert payload["releaseMatches"] is True
    assert payload["daemonInstanceId"] == daemon.runtime.instance_id
    assert payload["cycleProgress"] == {"currentStartedAt": None, "lastCompletedAt": None}

    original_update = store.update_daemon_health

    def unlocked_update(*args, **kwargs):
        assert daemon._runtime_lock.acquire(blocking=False)
        daemon._runtime_lock.release()
        return original_update(*args, **kwargs)

    monkeypatch.setattr(store, "update_daemon_health", unlocked_update)
    daemon._touch_heartbeat()
    assert store.get_daemon_state()["heartbeat_at"] > initial["heartbeat_at"]
    assert store.get_daemon_publication_authority() == authority
    daemon._begin_cycle("health-canary")
    code, payload = _health()
    assert code == 0 and payload["quiescent"] is False
    assert payload["cycleProgress"]["currentStartedAt"] is not None
    assert store.get_daemon_publication_authority() == authority
    daemon._complete_cycle(TickResult(), "health-canary")
    completed = store.get_daemon_state()["last_completed_cycle_at"]
    assert completed is not None
    assert store.get_daemon_publication_authority() == authority
    daemon.run_cycle(plan=False, dispatch=False, reason="health-canary-next")
    code, payload = _health()
    assert code == 0
    assert payload["cycleProgress"]["currentStartedAt"] is None
    assert payload["cycleProgress"]["lastCompletedAt"] > completed
    daemon._touch_heartbeat()
    assert store.get_daemon_publication_authority() == authority
    daemon.shutdown(force=True)
    code, payload = _health()
    assert code == 1 and payload["lifecycle"] == "stopped"


@pytest.mark.parametrize("transition", ["stop", "successor"])
def test_paused_heartbeat_cannot_revive_stop_or_overwrite_successor(
    running_daemon, monkeypatch, transition,
):
    daemon, store, _logs = running_daemon
    entered = threading.Event()
    resume = threading.Event()
    original_update = store.update_daemon_health

    def delayed_update(*args, **kwargs):
        entered.set()
        assert resume.wait(3)
        return original_update(*args, **kwargs)

    monkeypatch.setattr(store, "update_daemon_health", delayed_update)
    thread = threading.Thread(target=daemon._touch_heartbeat)
    thread.start()
    try:
        assert entered.wait(2)
        if transition == "stop":
            daemon.shutdown(force=True)
            assert store.get_daemon_state()["lifecycle"] == "stopped"
        else:
            store.claim_daemon_instance("successor", lifecycle="running", state={
                "heartbeat_at": datetime.now(timezone.utc).isoformat(),
                "release_id": "successor-release",
            })
        protected = store.get_daemon_state()
    finally:
        resume.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert store.get_daemon_state() == protected


def test_failed_heartbeat_ages_stale_and_thread_retries(running_daemon, monkeypatch):
    daemon, store, logs = running_daemon
    stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    store.set_daemon_lifecycle("running", instance_id=daemon.runtime.instance_id,
                               state={"heartbeat_at": stale})
    before = store.get_daemon_state()
    original_update = store.update_daemon_health
    failures = 2
    succeeded = threading.Event()

    def flaky_update(*args, **kwargs):
        nonlocal failures
        if failures:
            failures -= 1
            raise sqlite3.OperationalError("private-health-canary")
        result = original_update(*args, **kwargs)
        succeeded.set()
        return result

    monkeypatch.setattr(store, "update_daemon_health", flaky_update)
    daemon._touch_heartbeat()
    assert store.get_daemon_state() == before
    code, payload = _health()
    assert code == 1 and payload["heartbeat"] == "stale"
    monkeypatch.setattr(daemon, "_heartbeat_interval_seconds", lambda: 0.01)
    daemon._start_heartbeat_thread()
    try:
        assert succeeded.wait(2)
        assert daemon._heartbeat_thread.is_alive()
        assert _health()[0] == 0
    finally:
        daemon._stop_heartbeat_thread()
    assert sum("daemon health persistence failed error=OperationalError" in line for line in logs) == 2
    assert all("private-health-canary" not in line for line in logs)


def test_sqlite_contention_has_bounded_heartbeat_wait(running_daemon):
    daemon, store, logs = running_daemon
    before = store.get_daemon_state()
    with sqlite3.connect(store.path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        daemon._touch_heartbeat()
        assert time.monotonic() - started < 1
    assert store.get_daemon_state() == before
    assert any("daemon health persistence failed error=OperationalError" in line for line in logs)
    daemon._touch_heartbeat()
    assert store.get_daemon_state()["heartbeat_at"] > before["heartbeat_at"]


@pytest.mark.parametrize("lifecycle", [None, "starting", "reconciling", "stopping", "stopped"])
def test_store_health_never_creates_or_revives_claim(config, lifecycle):
    store = TaskStore.create(config.db_path)
    if lifecycle is not None:
        store.claim_daemon_instance("owner", lifecycle=lifecycle)
    before = store.get_daemon_state()
    assert not _update(store, "owner", datetime.now(timezone.utc))
    assert store.get_daemon_state() == before
    store.engine.dispose()


def test_store_health_rejects_older_snapshot_and_preserves_tightened_mode(running_daemon):
    daemon, store, _logs = running_daemon
    owner = daemon.runtime.instance_id
    older = datetime.now(timezone.utc)
    newer = older + timedelta(seconds=1)
    assert _update(store, owner, newer, last_completed_cycle_at=newer)
    before = store.get_daemon_state()
    assert not _update(store, owner, older, current_cycle_started_at=older)
    assert not _update(store, owner, newer, current_cycle_started_at=older)
    assert store.get_daemon_state() == before
    tightened = TaskStore.open(store.path, dry_run=True)
    try:
        state = tightened.get_daemon_state()
        assert state["publication_execution_mode"] == ExecutionMode.dry_run.value
        assert "publication_claim_id" not in state
        assert _update(store, owner, newer + timedelta(seconds=1))
        updated = store.get_daemon_state()
        assert updated["publication_execution_mode"] == ExecutionMode.dry_run.value
        assert "publication_claim_id" not in updated
        assert store.get_daemon_publication_authority() is None
    finally:
        tightened.engine.dispose()


def test_heartbeat_does_not_wait_for_provider_admission(running_daemon):
    daemon, store, _logs = running_daemon
    authority = store.get_daemon_publication_authority()
    admitted = threading.Event()
    release = threading.Event()

    def provider():
        with store.daemon_publication_admission(
            authority, action=EffectActionKind.publication_overhead.value,
            action_id="publication-overhead:health", target="cloudflare-d1",
        ) as decision:
            assert decision.allowed
            admitted.set()
            assert release.wait(3)

    thread = threading.Thread(target=provider)
    thread.start()
    try:
        assert admitted.wait(2)
        before = store.get_daemon_state()
        started = time.monotonic()
        daemon._touch_heartbeat()
        assert time.monotonic() - started < 1
        after = store.get_daemon_state()
        assert after["heartbeat_at"] > before["heartbeat_at"]
        assert after["publication_claim_id"] == before["publication_claim_id"]
    finally:
        release.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert store.get_daemon_publication_authority() == authority


@pytest.mark.parametrize("timestamp", [None, "invalid", datetime(2026, 1, 1)])
def test_invalid_health_timestamp_does_not_mutate_owner(running_daemon, timestamp):
    daemon, store, _logs = running_daemon
    before = store.get_daemon_state()
    with pytest.raises(ValueError, match="timestamp"):
        _update(store, daemon.runtime.instance_id, timestamp)
    assert store.get_daemon_state() == before

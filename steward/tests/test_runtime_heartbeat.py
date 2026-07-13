from __future__ import annotations

import json
import time
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import (
    DaemonRuntime,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
)
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.public_mirror import (
    public_mirror_digest,
    public_mirror_payload,
)
from coquic_steward.storage import TaskStore


def test_runtime_instance_and_heartbeat_interval_are_bounded() -> None:
    first = DaemonRuntime()
    second = DaemonRuntime()

    assert first.instance_id != second.instance_id
    assert first.instance_id.startswith("steward-")
    assert "/" not in first.instance_id
    assert 5 <= first.heartbeat_interval_seconds <= 60

    with pytest.raises(ValidationError):
        DaemonRuntime(heartbeat_interval_seconds=4)
    with pytest.raises(ValidationError):
        DaemonRuntime(heartbeat_interval_seconds=61)


def test_cycle_runtime_records_start_completion_reason_and_counts(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    daemon = StewardDaemon(config, store)

    result = daemon.run_cycle(
        plan=False,
        dispatch=False,
        reason="manual-tick",
    )
    runtime = public_mirror_payload(config, store, runtime=daemon.runtime)["runtime"]

    assert runtime["state"] == "idle"
    assert runtime["current_cycle_started_at"] is None
    assert runtime["current_cycle_reason"] is None
    assert runtime["started_at"].endswith("Z")
    assert runtime["heartbeat_at"].endswith("Z")
    assert runtime["last_completed_cycle"]["reason"] == "manual-tick"
    assert runtime["last_completed_cycle"]["result"] == vars(result)
    assert store.list_tasks() == []
    assert store.events("daemon") == []


def test_runtime_heartbeat_is_part_of_mirror_digest(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    runtime = DaemonRuntime()

    before = public_mirror_digest(config, store, runtime=runtime)
    runtime.heartbeat_at += timedelta(seconds=30)
    after = public_mirror_digest(config, store, runtime=runtime)

    assert before != after


def test_heartbeat_publishes_without_store_changes(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                enabled=True,
                publish=False,
                output_path=Path("public/steward/status.json"),
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon, "_heartbeat_interval_seconds", lambda: 0.01)
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.PUBLIC_MIRROR_DEBOUNCE_SECONDS",
        0.001,
    )

    daemon._start_public_mirror_sync()
    path = config.state_dir / "public" / "steward" / "status.json"
    try:
        deadline = time.monotonic() + 2
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert path.exists()
        first = json.loads(path.read_text(encoding="utf-8"))["runtime"]["heartbeat_at"]

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = json.loads(path.read_text(encoding="utf-8"))["runtime"][
                "heartbeat_at"
            ]
            if current != first:
                break
            time.sleep(0.01)
        assert current != first
        assert store.list_tasks() == []
    finally:
        daemon._stop_public_mirror_sync()


def test_mirror_failure_does_not_stop_daemon_work(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                enabled=True,
                publish=True,
                output_path=Path("public/steward/status.json"),
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="runtime heartbeat test",
            prompt="run the task",
        )
    )
    daemon = StewardDaemon(config, store)

    def fail_publish(*_args, **_kwargs):
        raise RuntimeError("publisher unavailable")

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.publish_public_mirror",
        fail_publish,
    )

    def run_task(task_id: str) -> bool:
        active = public_mirror_payload(config, store, runtime=daemon.runtime)["runtime"]
        assert active["state"] == "active"
        assert active["current_cycle_started_at"] is not None
        store.update_status(task_id, TaskStatus.running, "running")
        store.finish_task(task_id, TaskStatus.succeeded, "done")
        return True

    monkeypatch.setattr(daemon.executor, "run_task", run_task)

    result = daemon.run_cycle(
        plan=False,
        dispatch=True,
        max_dispatch=1,
        reason="scheduled",
    )

    assert result.dispatched == 1
    assert store.get(task.id).status == TaskStatus.succeeded
    assert daemon.runtime.last_completed_cycle is not None
    assert daemon.runtime.last_completed_cycle.result.dispatched == 1

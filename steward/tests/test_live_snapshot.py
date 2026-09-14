from __future__ import annotations

import json
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.core.config import StewardPublicationConfig, load_config
from coquic_steward.core.models import (
    SchedulerStoreSnapshot,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
    new_signal_fetch_id,
)
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.publication.live import (
    LiveSnapshotClient,
    LiveSnapshotError,
    LiveSnapshotWorker,
    build_live_snapshot,
)
from coquic_steward.storage import TaskStore


def _token(tmp_path: Path, value: str = "live-token-value") -> Path:
    path = tmp_path / "live-write-token"
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _live_config(tmp_path: Path, **overrides: object) -> StewardPublicationConfig:
    values: dict[str, object] = {
        "live_snapshot_enabled": True,
        "live_snapshot_url": "https://live.example.test/api/steward/live",
        "live_snapshot_token_path": _token(tmp_path),
        "live_snapshot_interval_seconds": 60,
    }
    values.update(overrides)
    return StewardPublicationConfig(**values)


def test_live_snapshot_config_is_disabled_by_default_and_validates_enabled_pair(
    repo: Path, tmp_path: Path
) -> None:
    config_path = tmp_path / "live.toml"
    config_path.write_text(
        """
[steward.publication]
live_snapshot_enabled = true
live_snapshot_url = "https://live.example.test/api/steward/live"
live_snapshot_token_path = "/missing/live-write-token"
live_snapshot_interval_seconds = 60
""",
        encoding="utf-8",
    )

    assert StewardPublicationConfig().live_snapshot_enabled is False
    with pytest.raises(ValueError, match="live_snapshot_token_path"):
        load_config(repo_root=repo, config_path=config_path)

    token = _token(tmp_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            '"/missing/live-write-token"', json.dumps(str(token))
        ),
        encoding="utf-8",
    )
    loaded = load_config(repo_root=repo, config_path=config_path)
    assert loaded.publication.live_snapshot_url.endswith("/api/steward/live")
    assert loaded.publication.live_snapshot_token_path == token


@pytest.mark.parametrize("interval", (29, 3601, True, 30.5))
def test_live_snapshot_config_rejects_invalid_interval(
    tmp_path: Path, interval: object
) -> None:
    with pytest.raises(ValueError, match="live_snapshot_interval_seconds"):
        _live_config(tmp_path, live_snapshot_interval_seconds=interval)


@pytest.mark.parametrize(
    "url",
    (
        "http://live.example.test/api/steward/live",
        "https://user@live.example.test/api/steward/live",
        "https://live.example.test/api/steward/live?token=bad",
    ),
)
def test_live_snapshot_config_rejects_unsafe_url(tmp_path: Path, url: str) -> None:
    with pytest.raises(ValueError, match="live_snapshot_url"):
        _live_config(tmp_path, live_snapshot_url=url)


def test_live_snapshot_requires_a_separate_credential(tmp_path: Path) -> None:
    token = _token(tmp_path)
    with pytest.raises(ValueError, match="separate"):
        StewardPublicationConfig(
            live_snapshot_enabled=True,
            live_snapshot_url="https://live.example.test/api/steward/live",
            live_snapshot_token_path=token,
            d1_token_path=token,
        )


def test_live_snapshot_payload_uses_exact_store_facts(config) -> None:
    store = TaskStore.create(config.db_path)
    for ordinal in range(2):
        store.ingest_signal_collection(
            SignalFetchRun(
                id=new_signal_fetch_id(),
                provider="synthetic",
                status=SignalFetchStatus.ok,
            ),
            [
                SignalItem(
                    id=f"signal-{ordinal}",
                    provider="synthetic",
                    kind="synthetic.alert",
                    fingerprint=f"fingerprint-{ordinal}",
                    title=f"Signal {ordinal}",
                    summary="exact pending signal",
                )
            ],
        )
    source_queued = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="SQ", prompt="P")
    )[0]
    source_active = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="SA", prompt="P")
    )[0]
    store.update_status(source_active.id, TaskStatus.running, "started")
    integration_queued = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="IQ",
            prompt="P",
        )
    )[0]
    integration_active = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="IA",
            prompt="P",
        )
    )[0]
    store.update_status(integration_active.id, TaskStatus.running, "started")
    signal_id = store.control_loop.canonical_signal_id("synthetic", "fingerprint-0")
    assert signal_id is not None
    store.control_loop.claim_planner_run(
        "planner-live-state", [signal_id], [source_active.id]
    )

    snapshot = store.scheduler_snapshot()
    payload = build_live_snapshot(
        config,
        snapshot,
        observed_at=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        stale_after_seconds=60,
    )

    assert payload == {
        "schemaVersion": "1.0",
        "observedAt": "2026-08-01T12:00:00.000000Z",
        "staleAfterSeconds": 60,
        "daemon": {"mode": "dry-run"},
        "signals": {"pending": 2},
        "planning": {"state": "active"},
        "tasks": {"active": 1, "queued": 1},
        "integration": {"active": 1, "queued": 1},
    }
    assert source_queued.id and integration_queued.id

    store.record_resource_pressure(
        state="resource_pressure",
        home_free_bytes=None,
        owned_docker_bytes=None,
        reason="test",
    )
    paused = build_live_snapshot(
        config,
        store.scheduler_snapshot(),
        observed_at=datetime(2026, 8, 1, 12, 1, tzinfo=timezone.utc),
        stale_after_seconds=60,
    )
    assert paused["planning"] == {"state": "paused"}


class _Response:
    status = 204

    def __init__(self, body: bytes = b"") -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def test_live_snapshot_client_posts_bearer_json_with_bounded_io(tmp_path: Path) -> None:
    token = "live-token-value"
    token_path = _token(tmp_path, token)
    seen: list[tuple[object, float]] = []

    def open_request(request, *, timeout: float):
        seen.append((request, timeout))
        return _Response()

    client = LiveSnapshotClient(
        "https://live.example.test/api/steward/live",
        token_path,
        open_request=open_request,
    )
    payload = build_live_snapshot(
        SimpleNamespace(dry_run=False),
        SchedulerStoreSnapshot(),
        observed_at=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        stale_after_seconds=60,
    )

    client.publish(payload)

    request, timeout = seen[0]
    assert request.full_url == "https://live.example.test/api/steward/live"
    assert request.method == "POST"
    assert request.get_header("Authorization") == f"Bearer {token}"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("User-agent") == "coquic-steward/0.1"
    assert json.loads(request.data) == payload
    assert 0 < timeout <= 15

    token_path.unlink()
    with pytest.raises(LiveSnapshotError) as error:
        client.publish(payload)
    assert token not in str(error.value)
    assert str(token_path) not in str(error.value)


def test_live_snapshot_client_rejects_oversized_response_without_echo(
    tmp_path: Path,
) -> None:
    response_secret = b"private-response-value"
    client = LiveSnapshotClient(
        "https://live.example.test/api/steward/live",
        _token(tmp_path),
        open_request=lambda *_args, **_kwargs: _Response(response_secret * 1024),
    )

    with pytest.raises(LiveSnapshotError, match="response_too_large") as error:
        client.publish({"schemaVersion": "1.0"})
    assert response_secret.decode() not in str(error.value)


def test_live_snapshot_worker_isolates_failures_and_joins() -> None:
    attempts = 0
    payloads: list[dict[str, object]] = []
    first = threading.Event()
    second = threading.Event()
    logs: list[str] = []

    class Store:
        def scheduler_snapshot(self):
            return SchedulerStoreSnapshot()

    class Client:
        def publish(self, payload):
            nonlocal attempts
            attempts += 1
            payloads.append(payload)
            if attempts == 1:
                first.set()
                raise LiveSnapshotError("request_failed")
            second.set()

    worker = LiveSnapshotWorker(
        SimpleNamespace(dry_run=False),
        Store(),
        Client(),
        interval_seconds=30,
        logger=logs.append,
    )
    worker.start()
    assert first.wait(timeout=1)
    worker.wake()
    assert second.wait(timeout=1)
    assert worker.stop(timeout=1)
    assert not worker.is_alive
    assert attempts == 2
    assert [payload["staleAfterSeconds"] for payload in payloads] == [90, 90]
    assert logs == ["live snapshot publication failed error=LiveSnapshotError"]


def test_live_snapshot_worker_stop_before_clear_does_not_publish_or_sleep() -> None:
    published = threading.Event()

    class Store:
        def scheduler_snapshot(self):
            return SchedulerStoreSnapshot()

    class Client:
        def publish(self, _payload):
            published.set()

    worker = LiveSnapshotWorker(
        SimpleNamespace(dry_run=False),
        Store(),
        Client(),
        interval_seconds=3600,
    )
    worker.request_stop()
    worker._run()
    assert not published.is_set()


def test_heartbeat_persistence_never_wakes_live_snapshot_network(
    config, tmp_path: Path
) -> None:
    publication = _live_config(tmp_path, live_snapshot_interval_seconds=30)
    configured = replace(config, publication=publication)
    store = TaskStore.create(configured.db_path)
    calls = threading.Event()
    count = 0

    class Client:
        def publish(self, _payload):
            nonlocal count
            count += 1
            calls.set()

    daemon = StewardDaemon(configured, store)
    daemon._live_snapshot_worker.client = Client()
    daemon._start_live_snapshot_worker()
    assert calls.wait(timeout=1)
    daemon._touch_heartbeat()
    time.sleep(0.05)
    assert count == 1
    assert daemon._stop_live_snapshot_worker(deadline=time.monotonic() + 1)

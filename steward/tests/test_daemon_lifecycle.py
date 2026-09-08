from __future__ import annotations

import ast
import hashlib
import gc
import httpx
import json
import signal
import socket
import sqlite3
import shutil
import subprocess
import threading
import time
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from botocore.awsrequest import AWSHTTPConnection, AWSHTTPSConnection
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.agents.invocation import InvocationOutcome
from coquic_steward.agents.runner import CodexRunner
from coquic_steward.control_loop.models import StewardOverheadUsage
from coquic_steward.core.models import (
    CodexRunState,
    CleanupStatus,
    DaemonLifecycleState,
    CodexStage,
    ExecutionMode,
    PipelineCursorPhase,
    TaskKind,
    TaskSpec,
    TaskStatus,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    WorkerResult,
    WorkerKind,
)
from coquic_steward.planning import (
    PlannerRun as SchedulerPlannerRun,
    run_planner as execute_scheduler_planner,
)
from coquic_steward.core.config import (
    StewardConfig,
    StewardContainerConfig,
)
from coquic_steward.execution.container import (
    ContainerInspection,
    ExecIdentity,
    SubprocessDockerClient,
    TaskContainerRuntime,
)
from coquic_steward.execution.container_config import TaskContainerConfig
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.session import (
    FreshPlannerSession,
    InvocationStatus,
    ResumeCategory,
    ResumeResult,
    LocalSessionInvoker,
    SessionResult,
    SessionSupervisor,
    runtime_factory_for_config,
    worktree_checkpoint,
)
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.cli import _run_until_stopped
from coquic_steward.orchestration import daemon as daemon_module
from coquic_steward.orchestration.contracts import PublicationTransportSetupError
from coquic_steward.orchestration.daemon import (
    BotocoreR2TransportAdapter,
    HttpxD1TransportAdapter,
    StewardDaemon,
    TickResult,
)
from coquic_steward.publication.atif import AtifSource
from coquic_steward.publication.d1 import (
    D1Error,
    D1PublicationClient,
    OverheadReceipt,
    UsageBackfillReceipt,
)
from coquic_steward.publication.models import PublicationError, RunIdentity, RunMetadata
from coquic_steward.publication.generation import compose_publication_generation
from coquic_steward.publication.outbox import (
    CleanupState,
    GenerationIdentity,
    PublicationGeneration,
    PublicationHideFence,
    PublicationOperationResult,
    PublicationOperationStatus,
    PublicationRetryPolicy,
    PublicationState,
)
from coquic_steward.publication.publisher import (
    CloudPublisher,
    PublicationHideResult,
    PublicationHideStatus,
    PublicationResult,
    PublicationStatus,
)
from coquic_steward.orchestration.preflight import (
    StewardPreflightError,
    run_preflight,
)
from coquic_steward.storage import TaskStore
from coquic_steward.storage.sqlite import TaskLedgerOwnershipError
from publication_harness import enabled_publication_config as _enabled_publication_config


IMAGE = "sha256:" + "a" * 64


def _test_runtime_config(config: StewardConfig, task_id: str, suffix: str) -> TaskContainerConfig:
    root = config.private_dir / "test-runtimes" / f"{task_id}-{suffix}"
    paths = {
        name: root / name
        for name in ("archive", "sessions", "git", "common", "scratch")
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return TaskContainerConfig(
        task_id=task_id,
        image="coquic-steward-task",
        image_digest=IMAGE,
        worktree=config.repo_root,
        archive=paths["archive"],
        private_sessions=paths["sessions"],
        git_dir=paths["git"],
        git_common_dir=paths["common"],
        repo_root=config.repo_root,
        scratch=paths["scratch"],
    )


class _TestAWSHTTPConnection(AWSHTTPConnection):
    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None


class _TestAWSHTTPSConnection(AWSHTTPSConnection):
    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None


def _botocore_connection(
    *, sock=None, https=False
) -> AWSHTTPConnection | AWSHTTPSConnection:
    connection_type = _TestAWSHTTPSConnection if https else _TestAWSHTTPConnection
    connection = connection_type("publication.example.test", 443)
    connection.sock = sock
    return connection


def _d1_transport_double(
    on_close=None, *, http_client: httpx.Client | None = None
) -> D1PublicationClient:
    client = D1PublicationClient(
        account_id="a" * 32,
        database_id="00000000-0000-4000-8000-000000000000",
        token="test-token",
        http_client=http_client if http_client is not None else httpx.Client(),
    )
    original_close = client.close

    def close() -> None:
        if on_close is not None:
            on_close()
        original_close()

    client.close = close
    return client


def _botocore_transport_double(*, https=False) -> SimpleNamespace:
    connection = _botocore_connection(https=https)
    pool = SimpleNamespace()
    pool._get_conn = lambda timeout=None: connection
    pool._put_conn = lambda _connection: None
    manager = SimpleNamespace()
    manager.connection_from_url = lambda _url, _pool_kwargs=None: pool
    session = SimpleNamespace()
    session._get_connection_manager = lambda _url, _proxy_url=None: manager
    scheme = "https" if https else "http"
    endpoint = SimpleNamespace(
        host=f"{scheme}://publication.example.test", http_session=session
    )
    provider_client = SimpleNamespace(_endpoint=endpoint, close=lambda: None)
    return SimpleNamespace(_client=provider_client)


def _task(store: TaskStore, title: str = "lifecycle"):
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title=title,
            prompt=f"complete {title}",
        )
    )
    return task, store.list_pipelines(task.id)[0]


def _publication_generation(
    task_id: str,
    *,
    run_id: str | None = None,
    state: PublicationState = PublicationState.queued,
    reason: str | None = None,
) -> PublicationGeneration:
    boundary = f"boundary-{task_id}"
    identity = GenerationIdentity(task_id, boundary)
    now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
    return PublicationGeneration(
        publication_id=identity.publication_id,
        task_id=task_id,
        metadata_digest="f" * 64,
        idempotency_key=identity.idempotency_key,
        created_at=now,
        updated_at=now,
        run_id=run_id or f"run-{task_id}",
        generation_boundary=boundary,
        state=state,
        reason=reason,
    )


def _worker_composed_generation(task_id: str):
    pipeline_id = f"pipeline-{task_id}"
    run_id = f"run-{task_id}"
    documents = {
        "codex.jsonl": b'{"type":"item.completed","item":{"id":"message-1","type":"agent_message","text":"safe"}}\n',
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"event","schema_version":1,"sequence":1,"source_event_id":"activity-1","activity":"investigate","summary":"Complete the task","recorded_at":"2026-07-28T12:00:00.100Z"}\n'
            b'{"record_type":"summary","schema_version":1,"capture_state":"complete","recorded":1,"invalid":0,"duplicate":0,"omitted":0,"truncated":false}\n'
        ),
        "telemetry.json": b'{"schema_version":1,"provenance":"codex_exec","completeness":"complete","aggregate":{},"cost":{"status":"unavailable"}}',
        "run.json": (
            f'{{"taskId":"{task_id}","pipelineId":"{pipeline_id}","runId":"{run_id}","role":"planning","state":"succeeded","startedAt":"2026-07-28T12:00:00.000Z","completedAt":"2026-07-28T12:00:01.000Z"}}\n'
        ).encode(),
    }
    graph = {
        "task": {
            "taskId": task_id,
            "title": "worker publication",
            "lifecycleState": "active",
            "createdAt": "2026-07-28T12:00:00Z",
            "completedAt": None,
        },
        "pipelines": [
            {
                "pipelineId": pipeline_id,
                "taskId": task_id,
                "name": "Planning pipeline",
                "createdAt": "2026-07-28T12:00:00Z",
            }
        ],
        "runs": [
            AtifSource(
                run={
                    "taskId": task_id,
                    "pipelineId": pipeline_id,
                    "runId": run_id,
                    "role": "planning",
                    "state": "succeeded",
                    "startedAt": "2026-07-28T12:00:00.000Z",
                    "completedAt": "2026-07-28T12:00:01.000Z",
                    "durationMs": 1_000,
                },
                documents=documents,
            )
        ],
        "events": [
            {
                "taskId": task_id,
                "sequence": 1,
                "eventType": "completed",
                "occurredAt": "2026-07-28T12:00:01Z",
                "summary": "Planning completed",
            }
        ],
        "artifacts": [],
    }
    result = compose_publication_generation(
        graph,
        task_id=task_id,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b"",
        ),
    )
    assert result.status == "publishable"
    return result


def _force_task_pages(monkeypatch, store: TaskStore) -> list[int]:
    """Exercise detached lifecycle enumeration with a deliberately tiny page."""

    calls: list[int] = []
    original = store.list_tasks_page

    def page(**kwargs):
        calls.append(2)
        store._task_page_active = True
        try:
            kwargs["limit"] = 2
            return original(**kwargs)
        finally:
            store._task_page_active = False

    monkeypatch.setattr(store, "list_tasks_page", page)
    return calls


def _planner_signal(store: TaskStore, suffix: str = "retry") -> SignalItem:
    item = SignalItem(
        id=f"signal-item-{suffix}",
        provider="synthetic-provider",
        kind="synthetic.alert",
        fingerprint=f"fingerprint-{suffix}",
        title=f"Synthetic {suffix}",
    )
    store.ingest_signal_collection(
        SignalFetchRun(
            id=f"fetch-{suffix}",
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
    )
    return item


def test_publication_worker_wakes_from_committed_change_and_waits_for_retry():
    generation = _publication_generation("task-worker")

    class Store:
        def __init__(self):
            self.on_change = None
            self.list_calls = 0

        def list_pending_publication_hides(self):
            return []

        def expire_publication_leases(self):
            return []

        def list_publication_generations(self, **_kwargs):
            self.list_calls += 1
            return [generation]

    class Publisher:
        def __init__(self):
            self.calls: list[tuple[object, ...]] = []

        def publish(self, *args, **_kwargs):
            self.calls.append(args)
            return PublicationResult(
                PublicationStatus.retry_wait,
                publication_id=generation.publication_id,
            )

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.executor = SimpleNamespace()
    daemon.config = SimpleNamespace(
        dry_run=False,
        publication=SimpleNamespace(
            enabled=True,
            d1_token_path=None,
            r2_access_key_id_path=None,
            r2_secret_access_key_path=None,
        )
    )
    daemon._publication_wakeup = threading.Event()
    daemon._publication_lock = threading.RLock()
    daemon._publication_callback = None
    daemon._publication_previous_callback = None
    daemon.logger = None
    daemon._publication_source = lambda _generation: {}

    publisher = Publisher()
    assert daemon._publish_next_generation(publisher) is False
    assert publisher.calls == [(generation.publication_id,)]

    daemon._install_publication_change_callback()
    assert callable(daemon.store.on_change)
    daemon.store.on_change()
    assert daemon._publication_wakeup.is_set()


def test_publication_worker_waits_after_queued_generation_listing_failure():
    class Store:
        def list_pending_publication_hides(self) -> list[PublicationHideFence]:
            return []

        def expire_publication_leases(self) -> list[PublicationGeneration]:
            return []

        def list_publication_generations(
            self,
            *,
            states: set[PublicationState | str] | None = None,
            limit: int | None = None,
        ) -> list[PublicationGeneration]:
            raise sqlite3.OperationalError("database is locked")

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(dry_run=False)
    daemon._log = lambda *_args, **_kwargs: None

    assert daemon._publish_next_generation(object()) is False


def test_publication_worker_waits_after_blocked_generation_listing_failure():
    class Store:
        def __init__(self) -> None:
            self.list_calls = 0

        def list_pending_publication_hides(self) -> list[PublicationHideFence]:
            return []

        def expire_publication_leases(self) -> list[PublicationGeneration]:
            return []

        def list_publication_generations(
            self,
            *,
            states: set[PublicationState | str] | None = None,
            limit: int | None = None,
        ) -> list[PublicationGeneration]:
            self.list_calls += 1
            if self.list_calls == 1:
                return []
            raise sqlite3.OperationalError("database is locked")

    store = Store()
    daemon = object.__new__(StewardDaemon)
    daemon.store = store
    daemon.config = SimpleNamespace(dry_run=False)
    daemon._log = lambda *_args, **_kwargs: None

    assert daemon._publish_next_generation(object()) is False
    assert store.list_calls == 2


def test_publication_worker_drains_pending_hides_before_exposure_claim():
    events: list[str] = []

    class Store:
        def list_pending_publication_hides(self):
            events.append("list-hides")
            return [PublicationHideFence("task-hidden", "unsafe_content")]

        def list_publication_generations(self, **_kwargs):
            events.append("list-generations")
            return [_publication_generation("task-queued")]

        def expire_publication_leases(self):
            events.append("expire-leases")
            return []

    class Publisher:
        def hide_task(self, task_id: str, reason: str):
            events.append(f"hide:{task_id}:{reason}")
            return PublicationHideResult(
                PublicationHideStatus.hidden,
                task_id=task_id,
                reason=reason,
                changed=True,
            )

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(dry_run=False)
    daemon.logger = None

    assert daemon._publish_next_generation(Publisher()) is True
    assert events == ["list-hides", "hide:task-hidden:unsafe_content"]


def test_publication_worker_keeps_exposure_queued_when_hide_reconciliation_fails():
    events: list[str] = []

    class Store:
        def list_pending_publication_hides(self):
            events.append("list-hides")
            return [PublicationHideFence("task-hidden", "unsafe_content")]

        def list_publication_generations(self, **_kwargs):
            events.append("list-generations")
            return [_publication_generation("task-queued")]

    class Publisher:
        def hide_task(self, task_id: str, reason: str):
            events.append(f"hide:{task_id}:{reason}")
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason="network",
            )

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(dry_run=False)
    daemon.logger = None

    assert daemon._publish_next_generation(Publisher()) is False
    assert events == ["list-hides", "hide:task-hidden:unsafe_content"]


def _publication_callback_daemon(store: object) -> StewardDaemon:
    daemon = object.__new__(StewardDaemon)
    daemon.store = store
    daemon.config = SimpleNamespace(
        dry_run=False, publication=SimpleNamespace(enabled=True)
    )
    daemon._publication_stop = threading.Event()
    daemon._publication_wakeup = threading.Event()
    daemon._publication_thread = None
    daemon._publication_cancel = None
    daemon._publication_lock = threading.RLock()
    daemon._publication_callback = None
    daemon._publication_previous_callback = None
    return daemon


def test_publication_worker_stop_restores_callback_and_releases_daemon_reference():
    class Store:
        on_change = None

    store = Store()
    daemon = _publication_callback_daemon(store)
    daemon._install_publication_change_callback()
    installed = store.on_change
    reference = weakref.ref(daemon)

    assert callable(installed)
    assert daemon._stop_publication_worker() is True
    assert store.on_change is None
    assert daemon._publication_callback is None
    assert daemon._publication_previous_callback is None

    installed = None
    daemon = None
    gc.collect()
    assert reference() is None


def test_publication_worker_stop_preserves_external_callback_replacement():
    class Store:
        on_change = None

    store = Store()
    daemon = _publication_callback_daemon(store)
    daemon._install_publication_change_callback()

    replacement = lambda: None
    store.on_change = replacement

    assert daemon._stop_publication_worker() is True
    assert store.on_change is replacement
    assert daemon._publication_callback is None
    assert daemon._publication_previous_callback is None


def test_sequential_publication_daemons_do_not_chain_stale_callbacks():
    observed: list[str] = []

    def previous() -> None:
        observed.append("previous")

    class Store:
        def __init__(self):
            self.on_change = previous

    store = Store()
    first = _publication_callback_daemon(store)
    first._install_publication_change_callback()
    first_callback = store.on_change
    assert first._stop_publication_worker() is True
    assert store.on_change is previous

    second = _publication_callback_daemon(store)
    second._install_publication_change_callback()
    second_callback = store.on_change
    assert second_callback is not first_callback
    assert second._publication_previous_callback is previous
    assert second._stop_publication_worker() is True
    assert store.on_change is previous

    store.on_change()
    assert observed == ["previous"]


def test_shutdown_keeps_stopping_while_publication_worker_is_live(config, tmp_path):
    object.__setattr__(config, "publication", _enabled_publication_config(tmp_path, "stubborn"))
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    started = threading.Event()
    release = threading.Event()

    def stubborn_worker() -> None:
        started.set()
        release.wait()

    worker = threading.Thread(target=stubborn_worker, daemon=True)
    daemon._publication_thread = worker
    daemon._install_publication_change_callback()
    worker.start()
    assert started.wait(timeout=1.0)

    result = daemon.shutdown(force=True)

    assert result.state.value == "stopping"
    assert daemon.lifecycle_state.value == "stopping"
    assert store.get_daemon_state()["publication_worker_stopped"] is False
    assert store.get_daemon_state()["lifecycle"] == "stopping"
    assert daemon._publication_thread is worker

    release.set()
    worker.join(timeout=1.0)
    assert not worker.is_alive()
    assert daemon._stop_publication_worker(deadline=time.monotonic() + 1.0) is True
    assert store.on_change is None


def test_shutdown_revokes_publication_authority_before_worker_join(config):
    object.__setattr__(config, "dry_run", False)
    store = TaskStore.create(config.db_path, dry_run=False)
    daemon = StewardDaemon(config, store)
    store.claim_daemon_instance(
        daemon.runtime.instance_id,
        lifecycle=DaemonLifecycleState.running.value,
    )
    authority = store.get_daemon_publication_authority(daemon.runtime.instance_id)
    assert authority is not None

    started = threading.Event()
    release = threading.Event()

    def stubborn_worker() -> None:
        started.set()
        release.wait()

    worker = threading.Thread(target=stubborn_worker, daemon=True)
    daemon._publication_thread = worker
    worker.start()
    assert started.wait(timeout=1.0)

    provider_calls: list[object] = []

    class D1:
        def upsert_overhead(self, source: object, *, digest: str | None = None):
            provider_calls.append((source, digest))
            return OverheadReceipt()

    publisher = CloudPublisher(
        store,
        object(),
        D1(),
        retry_policy=PublicationRetryPolicy(),
    )
    shutdown_done = threading.Event()

    def shutdown() -> None:
        daemon.shutdown()
        shutdown_done.set()

    shutdown_thread = threading.Thread(target=shutdown, daemon=True)
    shutdown_thread.start()
    try:
        assert daemon._publication_stop.wait(timeout=1.0)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            state = store.get_daemon_state()
            if (
                state is not None
                and state["lifecycle"] == DaemonLifecycleState.stopping.value
            ):
                break
            time.sleep(0.01)
        else:
            pytest.fail("shutdown did not revoke durable publication authority")

        assert worker.is_alive()
        assert not shutdown_done.is_set()
        with pytest.raises(PublicationError):
            publisher.reconcile_overhead(
                {},
                digest="row-digest",
                authority=authority,
            )
        assert provider_calls == []
    finally:
        release.set()
        assert shutdown_done.wait(timeout=2.0)
        shutdown_thread.join(timeout=1.0)
        worker.join(timeout=1.0)


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("use_proxy", [False, True])
def test_shutdown_pre_socket_connection_revokes_authority_before_join(
    config, force: bool, use_proxy: bool, monkeypatch
):
    object.__setattr__(config, "dry_run", False)
    object.__setattr__(config, "shutdown_grace_seconds", 1.0)
    store = TaskStore.create(config.db_path, dry_run=False)
    daemon = StewardDaemon(config, store)
    store.claim_daemon_instance(
        daemon.runtime.instance_id,
        lifecycle=DaemonLifecycleState.running.value,
    )
    authority = store.get_daemon_publication_authority(daemon.runtime.instance_id)
    assert authority is not None

    admission_entered = threading.Event()
    connect_started = threading.Event()
    release_connect = threading.Event()
    stream_closed = threading.Event()
    request_bytes: list[bytes] = []
    errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            request_bytes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            return b""

        def close(self) -> None:
            stream_closed.set()

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            connect_started.set()
            release_connect.wait(timeout=3.0)
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    if use_proxy:
        direct = httpx.HTTPTransport(trust_env=False)
        proxy = httpx.HTTPTransport(
            proxy="http://proxy.example.test:8080", trust_env=False
        )
        proxy._pool._network_backend = Backend()
        http_client = httpx.Client(
            transport=direct,
            mounts={"https://": proxy},
            trust_env=False,
        )
        endpoint = "https://publication.example.test/query"
    else:
        http_client = httpx.Client(trust_env=False)
        http_client._transport._pool._network_backend = Backend()
        endpoint = "http://publication.example.test/query"
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: endpoint),
    )
    adapter = HttpxD1TransportAdapter(d1)

    def publish() -> None:
        try:
            with store.daemon_publication_admission(
                authority,
                action="publication.overhead",
                action_id="shutdown-pre-socket",
                target="cloudflare-d1",
            ) as decision:
                assert decision.allowed
                admission_entered.set()
                d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=publish, daemon=True)
    daemon._publication_thread = worker
    daemon._publication_cancel = adapter
    worker.start()
    assert admission_entered.wait(timeout=1.0)
    assert connect_started.wait(timeout=1.0)

    started = time.monotonic()
    try:
        result = daemon.shutdown(force=force)
        elapsed = time.monotonic() - started
        assert elapsed < 2.0
        assert result.state is DaemonLifecycleState.stopping
        state = store.get_daemon_state()
        assert state is not None
        assert state["lifecycle"] == DaemonLifecycleState.stopping.value
        assert state["publication_worker_stopped"] is False
        assert "publication_claim_id" not in state
        assert request_bytes == []
    finally:
        release_connect.set()
        worker.join(timeout=2.0)
        adapter.close()
        d1.close()

    assert not worker.is_alive()
    assert stream_closed.wait(timeout=1.0)
    assert errors
    assert isinstance(errors[0], daemon_module._PublicationTransportCancelled)


@pytest.mark.parametrize("force", [False, True])
def test_shutdown_bounds_active_d1_operation_without_revocation(
    config, force: bool, monkeypatch
):
    object.__setattr__(config, "dry_run", False)
    object.__setattr__(config, "shutdown_grace_seconds", 1.0)
    store = TaskStore.create(config.db_path, dry_run=False)
    daemon = StewardDaemon(config, store)
    store.claim_daemon_instance(
        daemon.runtime.instance_id,
        lifecycle=DaemonLifecycleState.running.value,
    )
    authority = store.get_daemon_publication_authority(daemon.runtime.instance_id)
    assert authority is not None

    write_entered = threading.Event()
    release_write = threading.Event()
    stream_closed = threading.Event()
    shutdown_done = threading.Event()
    revocation_committed = threading.Event()
    writes: list[bytes] = []
    post_revocation_writes: list[bytes] = []
    errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            del timeout
            write_entered.set()
            release_write.wait(timeout=3.0)
            writes.append(data)
            if revocation_committed.is_set():
                post_revocation_writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            del timeout
            return b""

        def close(self) -> None:
            stream_closed.set()

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    http_client = httpx.Client(trust_env=False)
    http_client._transport._pool._network_backend = Backend()
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)
    daemon._publication_thread = None
    daemon._publication_cancel = adapter

    original_revoke = store.revoke_daemon_publication_authority

    def revoke(*args: object, **kwargs: object):
        result = original_revoke(*args, **kwargs)
        if result.revoked:
            revocation_committed.set()
        return result

    monkeypatch.setattr(store, "revoke_daemon_publication_authority", revoke)

    def publish() -> None:
        try:
            with store.daemon_publication_admission(
                authority,
                action="publication.overhead",
                action_id="bounded-d1-operation",
                target="cloudflare-d1",
            ) as decision:
                assert decision.allowed
                d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=publish, daemon=True)
    daemon._publication_thread = worker
    worker.start()
    assert write_entered.wait(timeout=1.0)

    result: list[object] = []

    def shutdown() -> None:
        result.append(daemon.shutdown(force=force))
        shutdown_done.set()

    shutdown_thread = threading.Thread(target=shutdown, daemon=True)
    started = time.monotonic()
    shutdown_thread.start()
    try:
        assert stream_closed.wait(timeout=1.0)
        assert shutdown_done.wait(timeout=1.75)
        assert time.monotonic() - started < 2.0
        assert result
        assert result[0].state is DaemonLifecycleState.stopping
        state = store.get_daemon_state()
        assert state is not None
        assert state["lifecycle"] == DaemonLifecycleState.running.value
        assert state["publication_claim_id"] == authority.claim_id
        assert not revocation_committed.is_set()
        assert writes == []
    finally:
        release_write.set()
        worker.join(timeout=2.0)
        shutdown_thread.join(timeout=1.0)
        adapter.close()
        d1.close()

    assert not worker.is_alive()
    assert not shutdown_thread.is_alive()
    assert errors
    assert not post_revocation_writes


def test_shutdown_waits_for_active_d1_quiescence_before_revocation(
    config, monkeypatch
):
    object.__setattr__(config, "dry_run", False)
    object.__setattr__(config, "shutdown_grace_seconds", 1.0)
    store = TaskStore.create(config.db_path, dry_run=False)
    daemon = StewardDaemon(config, store)
    store.claim_daemon_instance(
        daemon.runtime.instance_id,
        lifecycle=DaemonLifecycleState.running.value,
    )
    authority = store.get_daemon_publication_authority(daemon.runtime.instance_id)
    assert authority is not None

    write_entered = threading.Event()
    release_write = threading.Event()
    stream_closed = threading.Event()
    revocation_committed = threading.Event()
    shutdown_done = threading.Event()
    writes: list[bytes] = []
    post_revocation_writes: list[bytes] = []
    errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            del timeout
            write_entered.set()
            release_write.wait(timeout=2.0)
            writes.append(data)
            if revocation_committed.is_set():
                post_revocation_writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            del timeout
            return b""

        def close(self) -> None:
            stream_closed.set()

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    http_client = httpx.Client(trust_env=False)
    http_client._transport._pool._network_backend = Backend()
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)
    daemon._publication_cancel = adapter

    original_revoke = store.revoke_daemon_publication_authority

    def revoke(*args: object, **kwargs: object):
        result = original_revoke(*args, **kwargs)
        if result.revoked:
            revocation_committed.set()
        return result

    monkeypatch.setattr(store, "revoke_daemon_publication_authority", revoke)

    def publish() -> None:
        try:
            with store.daemon_publication_admission(
                authority,
                action="publication.overhead",
                action_id="quiescent-d1-operation",
                target="cloudflare-d1",
            ) as decision:
                assert decision.allowed
                d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=publish, daemon=True)
    daemon._publication_thread = worker
    worker.start()
    assert write_entered.wait(timeout=1.0)

    result: list[object] = []

    def shutdown() -> None:
        result.append(daemon.shutdown(force=True))
        shutdown_done.set()

    shutdown_thread = threading.Thread(target=shutdown, daemon=True)
    shutdown_thread.start()
    try:
        assert stream_closed.wait(timeout=1.0)
        assert not shutdown_done.is_set()
        release_write.set()
        assert shutdown_done.wait(timeout=1.5)
        assert result
        assert result[0].state is DaemonLifecycleState.stopped
        state = store.get_daemon_state()
        assert state is not None
        assert state["lifecycle"] == DaemonLifecycleState.stopped.value
        assert "publication_claim_id" not in state
        assert revocation_committed.is_set()
    finally:
        release_write.set()
        worker.join(timeout=1.0)
        shutdown_thread.join(timeout=1.0)
        adapter.close()
        d1.close()

    assert not worker.is_alive()
    assert not shutdown_thread.is_alive()
    assert errors
    assert not post_revocation_writes


def test_shutdown_reports_stopping_when_authority_revocation_expires(config):
    object.__setattr__(config, "dry_run", False)
    store = TaskStore.create(config.db_path, dry_run=False)
    daemon = StewardDaemon(config, store)
    store.claim_daemon_instance(
        daemon.runtime.instance_id,
        lifecycle=DaemonLifecycleState.running.value,
    )
    lock = sqlite3.connect(store.path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    shutdown_done = threading.Event()
    result: list[object] = []

    def shutdown() -> None:
        result.append(daemon.shutdown(force=True))
        shutdown_done.set()

    worker = threading.Thread(target=shutdown, daemon=True)
    started = time.monotonic()
    worker.start()
    try:
        assert shutdown_done.wait(timeout=1.75)
        assert time.monotonic() - started < 1.75
        assert result
        assert result[0].state is DaemonLifecycleState.stopping
        state = store.get_daemon_state()
        assert state is not None
        assert state["lifecycle"] == DaemonLifecycleState.running.value
        assert state["publication_claim_id"]
    finally:
        lock.rollback()
        lock.close()
        worker.join(timeout=1.0)
    assert not worker.is_alive()


def test_shutdown_bounds_control_loop_lock_drain(config):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    lock_entered = threading.Event()
    release_lock = threading.Event()

    def hold_control_loop_lock() -> None:
        with daemon._control_loop_lock:
            lock_entered.set()
            release_lock.wait(timeout=3.0)

    control_loop_writer = threading.Thread(
        target=hold_control_loop_lock,
        daemon=True,
    )
    daemon._control_loop_thread = control_loop_writer
    control_loop_writer.start()
    assert lock_entered.wait(timeout=1.0)

    result: list[object] = []
    shutdown_done = threading.Event()

    def shutdown() -> None:
        result.append(daemon.shutdown(force=True))
        shutdown_done.set()

    shutdown_thread = threading.Thread(target=shutdown, daemon=True)
    started = time.monotonic()
    shutdown_thread.start()
    try:
        assert shutdown_done.wait(timeout=1.75)
        assert time.monotonic() - started < 1.75
        assert result
        assert result[0].state is DaemonLifecycleState.stopping
    finally:
        release_lock.set()
        control_loop_writer.join(timeout=1.0)
        shutdown_thread.join(timeout=1.0)
    assert not control_loop_writer.is_alive()
    assert not shutdown_thread.is_alive()


def test_shutdown_does_not_start_fixed_timeout_ledger_write_after_revocation(
    config, monkeypatch
):
    object.__setattr__(config, "dry_run", False)
    store = TaskStore.create(config.db_path, dry_run=False)
    daemon = StewardDaemon(config, store)
    instance_id = daemon.runtime.instance_id
    store.claim_daemon_instance(instance_id, lifecycle=DaemonLifecycleState.running.value)

    original_revoke = store.revoke_daemon_publication_authority
    original_record_runtime = daemon._control_loop_ledger.record_runtime
    lock = sqlite3.connect(
        store.path, isolation_level=None, check_same_thread=False
    )
    revocation_lock_ready = threading.Event()
    shutdown_done = threading.Event()
    revoke_calls = 0
    record_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    result: list[object] = []

    def revoke(
        expected_instance_id: str,
        lifecycle: str,
        *,
        deadline: float,
        state: dict[str, object] | None = None,
    ):
        nonlocal revoke_calls
        outcome = original_revoke(
            expected_instance_id,
            lifecycle,
            deadline=deadline,
            state=state,
        )
        revoke_calls += 1
        if revoke_calls == 1:
            # The real revocation has committed and closed its connection.  A
            # second connection can now hold the write lock while the wrapper
            # returns, reproducing a race with the secondary ledger writer.
            lock.execute("BEGIN IMMEDIATE")
            revocation_lock_ready.set()
        return outcome

    def record_runtime(*args: object, **kwargs: object):
        record_calls.append((args, kwargs))
        return original_record_runtime(*args, **kwargs)

    monkeypatch.setattr(store, "revoke_daemon_publication_authority", revoke)
    monkeypatch.setattr(daemon._control_loop_ledger, "record_runtime", record_runtime)

    def shutdown() -> None:
        result.append(daemon.shutdown(force=True))
        shutdown_done.set()

    worker = threading.Thread(target=shutdown, daemon=True)
    started = time.monotonic()
    worker.start()
    try:
        assert revocation_lock_ready.wait(timeout=1.0)
        state = store.get_daemon_state()
        assert state is not None
        assert state["lifecycle"] == DaemonLifecycleState.stopping.value
        assert "publication_claim_id" not in state

        # Keep the post-revocation lock held past the one-second force budget.
        time.sleep(max(0.0, started + 1.1 - time.monotonic()))
        assert shutdown_done.is_set()
        assert result
        assert result[0].state is DaemonLifecycleState.stopping
        assert time.monotonic() - started < 1.75
        assert record_calls == []
    finally:
        lock.rollback()
        lock.close()
        assert shutdown_done.wait(timeout=2.0)
        worker.join(timeout=1.0)

    successor = store.claim_daemon_instance(
        "daemon-successor", lifecycle=DaemonLifecycleState.running.value
    )
    assert successor["instance_id"] == "daemon-successor"
    assert store.get_daemon_state()["instance_id"] == "daemon-successor"


def test_shutdown_leaves_pending_control_loop_outbox_for_ordinary_drain(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    event = store.control_loop.record_runtime("deferred")
    drain_calls: list[dict[str, object]] = []

    def forbidden_drain(**kwargs: object) -> dict[str, object]:
        drain_calls.append(kwargs)
        raise AssertionError("shutdown must not run a synchronous final drain")

    monkeypatch.setattr(daemon, "_drain_control_loop_once", forbidden_drain)

    daemon.shutdown(force=True)

    assert drain_calls == []
    pending = store.control_loop.outbox()
    assert [row["event_id"] for row in pending] == [event.event_id]
    assert pending[0]["materialized_at"] is None

    monkeypatch.undo()
    recovered = daemon._drain_control_loop_once()
    assert recovered["materialized"] >= 1
    assert store.control_loop.outbox() == []


def test_shutdown_does_not_drain_behind_live_control_loop_writer(
    config,
):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    reconcile_entered = threading.Event()
    release_reconcile = threading.Event()

    def blocked_reconcile(*_args: object, **_kwargs: object) -> dict[str, object]:
        reconcile_entered.set()
        release_reconcile.wait(timeout=3.0)
        return {"materialized": 0, "conflicts": 0}

    daemon._control_loop_archive.reconcile = blocked_reconcile
    daemon._start_control_loop_writer()
    assert reconcile_entered.wait(timeout=1.0)
    event = store.control_loop.record_runtime("after-snapshot")

    worker = daemon._control_loop_thread
    assert worker is not None
    started = time.monotonic()
    try:
        result = daemon.shutdown(force=True)
        assert result.state is DaemonLifecycleState.stopping
        assert time.monotonic() - started < 1.75
        assert worker.is_alive()
        pending = store.control_loop.outbox()
        assert [row["event_id"] for row in pending] == [event.event_id]
        assert pending[0]["materialized_at"] is None
    finally:
        release_reconcile.set()
        assert daemon._stop_control_loop_writer(deadline=time.monotonic() + 1.0)


def test_shutdown_cancels_publication_before_lifecycle_transition(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    events: list[str] = []

    monkeypatch.setattr(
        daemon,
        "_request_publication_worker_stop",
        lambda **_kwargs: events.append("publication-cancel"),
    )
    monkeypatch.setattr(
        daemon,
        "_enter_stopping",
        lambda **_kwargs: events.append("lifecycle") or None,
    )
    monkeypatch.setattr(
        daemon,
        "_join_publication_worker",
        lambda **_kwargs: events.append("publication-join") or True,
    )

    daemon.shutdown(force=True)

    assert events[:3] == ["publication-cancel", "lifecycle", "publication-join"]


def test_shutdown_after_ownership_loss_completes_local_cleanup(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    daemon.runtime.instance_id = "daemon-a"
    store.claim_daemon_instance("daemon-a", lifecycle=DaemonLifecycleState.running.value)
    store.claim_daemon_instance("daemon-b", lifecycle=DaemonLifecycleState.running.value)
    before = store.get_daemon_state()
    assert before is not None

    cleanup: list[str] = []
    monkeypatch.setattr(
        daemon,
        "_join_publication_worker",
        lambda **_kwargs: cleanup.append("publication") or True,
    )

    result = daemon.shutdown(force=True)

    after = store.get_daemon_state()
    assert result.state is DaemonLifecycleState.stopped
    assert cleanup == ["publication"]
    assert after is not None
    assert after["instance_id"] == before["instance_id"] == "daemon-b"
    assert after["lifecycle"] == before["lifecycle"] == DaemonLifecycleState.running.value
    assert after["publication_claim_id"] == before["publication_claim_id"]


def test_publication_worker_reconciles_credential_free_staging_identity(
    tmp_path: Path,
) -> None:
    config = _enabled_publication_config(tmp_path, "synthetic-worker-credential")
    generation = _publication_generation("task-credential-staging")

    class Store:
        def list_pending_publication_hides(self):
            return []

        def expire_publication_leases(self):
            return []

        def list_publication_generations(self, **_kwargs):
            return [generation]

    class Publisher:
        def __init__(self):
            self.publish_calls: list[dict[str, object]] = []
            self.enqueue_calls: list[dict[str, object]] = []
            self.composed_generation = None

        def compose(self, _source, *, task_id, **_kwargs):
            self.composed_generation = _worker_composed_generation(task_id)
            return self.composed_generation

        def publish(self, publication_id, *, source, compose_kwargs):
            self.publish_calls.append(
                {
                    "publication_id": publication_id,
                    "source": source,
                    "compose_kwargs": compose_kwargs,
                }
            )
            return PublicationResult(
                PublicationStatus.blocked,
                publication_id=publication_id,
                reason="integrity",
                phase="authenticate",
            )

        def _enqueue_precomposed_repair(self, publication_id, generation):
            self.enqueue_calls.append(
                {
                    "publication_id": publication_id,
                    "generation": generation,
                }
            )
            return PublicationResult(
                PublicationStatus.queued,
                publication_id="pub-repaired-staging",
            )

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(dry_run=False, publication=config)
    daemon.logger = None
    daemon._publication_source = lambda _generation: {"canonical": True}
    publisher = Publisher()

    assert daemon._publish_next_generation(publisher) is True
    assert len(publisher.publish_calls) == 1
    assert len(publisher.enqueue_calls) == 1
    assert publisher.enqueue_calls[0]["generation"] is publisher.composed_generation
    expected_sources = (
        config.d1_token_path,
        config.r2_access_key_id_path,
        config.r2_secret_access_key_path,
    )
    assert publisher.publish_calls[0]["compose_kwargs"] == {
        "credential_sources": expected_sources,
        "staging_root": config.staging_root,
    }


def test_publication_worker_reconciles_blocked_identity_after_restart(
    tmp_path: Path,
) -> None:
    config = _enabled_publication_config(tmp_path, "synthetic-restart-credential")
    generation = _publication_generation(
        "task-credential-restart",
        state=PublicationState.blocked,
        reason="integrity",
    )

    class Store:
        def list_pending_publication_hides(self):
            return []

        def expire_publication_leases(self):
            return []

        def list_publication_generations(self, **_kwargs):
            return [generation]

    class Publisher:
        def __init__(self):
            self.publish_calls = 0
            self.enqueue_calls: list[object] = []
            self.composed_generation = None

        def compose(self, _source, *, task_id, **_kwargs):
            self.composed_generation = _worker_composed_generation(task_id)
            return self.composed_generation

        def publish(self, *_args, **_kwargs):
            self.publish_calls += 1
            return PublicationResult(PublicationStatus.blocked)

        def _enqueue_precomposed_repair(self, publication_id, generation):
            self.enqueue_calls.append((publication_id, generation))
            return PublicationResult(
                PublicationStatus.queued,
                publication_id="pub-repaired-restart",
            )

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(dry_run=False, publication=config)
    daemon.logger = None
    daemon._publication_source = lambda _generation: {"canonical": True}
    publisher = Publisher()

    assert daemon._publish_next_generation(publisher) is True
    assert publisher.publish_calls == 0
    assert len(publisher.enqueue_calls) == 1
    assert publisher.enqueue_calls[0][1] is publisher.composed_generation


def test_terminal_publication_gate_retains_state_until_exposed(monkeypatch):
    task = SimpleNamespace(id="task-terminal-publication")
    run = SimpleNamespace(
        id="run-terminal-publication",
        state="succeeded",
        completed_at=datetime.now(timezone.utc),
    )
    generation = _publication_generation(
        task.id,
        run_id=run.id,
    )

    class Store:
        def __init__(self):
            self._events: list[SimpleNamespace] = []

        def events(self, _task_id):
            return list(self._events)

        def add_event(self, task_id, kind, message, data=None):
            self._events.append(
                SimpleNamespace(task_id=task_id, kind=kind, message=message, data=data or {})
            )

        def list_runs(self, _task_id):
            return [run]

        def get_publication_generation(self, _publication_id):
            return generation

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(
        dry_run=False, publication=SimpleNamespace(enabled=True)
    )
    daemon.logger = None
    daemon._terminal_publication_receipts_verified = lambda *_args: (True, "verified")
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.enqueue_materialized_publication",
        lambda *_args: PublicationOperationResult(
            PublicationOperationStatus.enqueued,
            generation=generation,
        ),
    )

    assert daemon._terminal_publication_gate(task) is False
    assert any(
        event.kind == "cleanup_blocked"
        and event.data["reason"] == "final_generation_queued"
        for event in daemon.store.events(task.id)
    )

    exposed_at = datetime.now(timezone.utc)
    generation = replace(
        generation,
        state=PublicationState.exposed,
        updated_at=exposed_at,
        exposed_at=exposed_at,
    )
    assert daemon._terminal_publication_gate(task) is True
    assert len(daemon.store.events(task.id)) == 1


def test_publication_worker_reclaims_expired_lease_on_recurring_cycle():
    generation = _publication_generation("task-expired")
    events: list[str] = []

    class Store:
        def __init__(self) -> None:
            now = datetime.now(timezone.utc)
            self.generation = replace(
                generation,
                state=PublicationState.claimed,
                updated_at=now - timedelta(seconds=2),
                lease_owner="publication-worker",
                lease_expires_at=now - timedelta(seconds=1),
            )
            self.expire_calls = 0

        def list_pending_publication_hides(self) -> list[PublicationHideFence]:
            events.append("list-hides")
            return []

        def expire_publication_leases(self) -> list[PublicationGeneration]:
            events.append("expire-leases")
            self.expire_calls += 1
            assert self.generation.state is PublicationState.claimed
            now = datetime.now(timezone.utc)
            self.generation = replace(
                self.generation,
                state=PublicationState.retry_wait,
                updated_at=now,
                lease_owner=None,
                lease_expires_at=None,
                retry_at=now,
                reason="lease_expired",
            )
            return [self.generation]

        def list_publication_generations(
            self,
            *,
            states: set[PublicationState | str] | None = None,
            limit: int | None = None,
        ) -> list[PublicationGeneration]:
            events.append("list-generations")
            assert states == {PublicationState.queued, PublicationState.retry_wait}
            assert limit == 1
            if self.generation.state not in states:
                return []
            return [self.generation]

    class Publisher:
        def __init__(self, store: Store) -> None:
            self.store = store
            self.calls: list[str] = []

        def publish(
            self,
            publication_id: str,
            *,
            source: object,
            compose_kwargs: dict[str, object],
        ) -> PublicationResult:
            del source, compose_kwargs
            events.append("publish")
            assert self.store.generation.state is PublicationState.retry_wait
            self.calls.append(publication_id)
            return PublicationResult(
                PublicationStatus.exposed,
                publication_id=publication_id,
            )

    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon.config = SimpleNamespace(dry_run=False)
    daemon.logger = None
    daemon._publication_source = lambda _generation: {}

    publisher = Publisher(daemon.store)
    assert daemon._publish_next_generation(publisher) is True
    assert daemon.store.expire_calls == 1
    assert publisher.calls == [generation.publication_id]
    assert events == ["list-hides", "expire-leases", "list-generations", "publish"]


def test_publication_worker_shutdown_cancels_clients_before_deadline():
    closed = threading.Event()
    release = threading.Event()

    class Client:
        def close(self):
            closed.set()
            release.set()

    client = Client()
    worker = threading.Thread(target=release.wait, daemon=True)
    worker.start()
    daemon = object.__new__(StewardDaemon)
    daemon._publication_thread = worker
    daemon._publication_stop = threading.Event()
    daemon._publication_wakeup = threading.Event()
    daemon._publication_cancel = daemon_module._CallbackDaemonCancellation(
        client.close
    )

    deadline = time.monotonic() + 2.0
    daemon._stop_publication_worker(deadline=deadline)

    assert closed.is_set()
    assert not worker.is_alive()
    assert daemon._publication_thread is None


def test_publication_worker_shutdown_closes_nested_r2_transport_before_deadline():
    started = threading.Event()
    released = threading.Event()
    r2_closed = threading.Event()
    d1_closed = threading.Event()

    class Pool:
        def __init__(self):
            self.connection = _botocore_connection()

        def _get_conn(self, timeout=None):
            del timeout
            return self.connection

        def _put_conn(self, connection):
            self.connection = connection

    class Manager:
        def __init__(self):
            self.pool = Pool()

        def connection_from_url(self, url, pool_kwargs=None):
            del url, pool_kwargs
            return self.pool

    class Session:
        def __init__(self):
            self.manager = Manager()

        def _get_connection_manager(self, url, proxy_url=None):
            del url, proxy_url
            return self.manager

    class Endpoint:
        host = "http://publication.example.test"

        def __init__(self):
            self.http_session = Session()

    class ProviderClient:
        def __init__(self):
            self._endpoint = Endpoint()

        def close(self):
            r2_closed.set()
            released.set()

    class ConcreteR2:
        def __init__(self):
            self._client = ProviderClient()

    publisher = SimpleNamespace(
        r2=ConcreteR2(),
        d1=_d1_transport_double(d1_closed.set),
    )
    daemon = object.__new__(StewardDaemon)
    daemon._publication_stop = threading.Event()
    daemon._publication_wakeup = threading.Event()
    daemon._publication_cancel = None
    daemon._publication_thread = None
    daemon._publication_retry_interval = lambda: 0.01
    daemon._build_publication_publisher = lambda: publisher
    daemon._publish_next_generation = lambda _publisher: (
        started.set(), released.wait(timeout=2.0), False
    )[-1]
    daemon._log = lambda _message: None

    worker = threading.Thread(target=daemon._publication_worker_loop, daemon=True)
    daemon._publication_thread = worker
    worker.start()
    assert started.wait(timeout=1.0)

    deadline = time.monotonic() + 1.0
    assert daemon._stop_publication_worker(deadline=deadline) is False
    assert not r2_closed.is_set()
    assert not d1_closed.is_set()
    assert worker.is_alive()

    released.set()
    worker.join(timeout=1.0)
    assert not worker.is_alive()
    assert r2_closed.is_set()
    assert d1_closed.is_set()
    assert daemon._stop_publication_worker(deadline=time.monotonic() + 1.0) is True
    assert daemon._publication_thread is None


def test_publication_worker_shutdown_interrupts_inflight_botocore_request():
    import boto3
    from botocore.config import Config as BotoConfig

    from coquic_steward.publication.r2 import R2Client, public_object_key

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}"
    accepted = threading.Event()
    connection_closed = threading.Event()
    server_stop = threading.Event()
    connection: socket.socket | None = None

    def serve() -> None:
        nonlocal connection
        try:
            while not server_stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                accepted.set()
                connection.settimeout(0.1)
                while not server_stop.is_set():
                    try:
                        if not connection.recv(65536):
                            connection_closed.set()
                            return
                    except socket.timeout:
                        continue
                    except OSError:
                        connection_closed.set()
                        return
                return
        except OSError:
            return

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    client = None
    worker = None
    try:
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id="test-access-key",
            aws_secret_access_key="test-secret-key",
            region_name="auto",
            config=BotoConfig(
                connect_timeout=1,
                read_timeout=60,
                retries={"max_attempts": 0, "mode": "standard"},
            ),
        )
        r2 = R2Client(
            endpoint="https://r2.example.test",
            public_bucket="publication-public",
            private_bucket="publication-private",
            client=client,
        )
        publisher = SimpleNamespace(r2=r2, d1=_d1_transport_double())
        daemon = object.__new__(StewardDaemon)
        daemon.config = SimpleNamespace(
            publication=SimpleNamespace(enabled=True)
        )
        daemon._publication_stop = threading.Event()
        daemon._publication_wakeup = threading.Event()
        daemon._publication_cancel = None
        daemon._publication_thread = None
        daemon._publication_retry_interval = lambda: 0.01
        daemon._build_publication_publisher = lambda: publisher
        daemon._log = lambda _message: None
        content = b"in-flight publication"
        key = public_object_key("task", hashlib.sha256(content).hexdigest())
        started = threading.Event()
        outcomes: list[object] = []

        def publish(_publisher: object) -> bool:
            started.set()
            try:
                r2.put_object(key, content)
            except Exception as error:
                outcomes.append(error)
            return False

        daemon._publish_next_generation = publish
        worker = threading.Thread(
            target=daemon._publication_worker_loop,
            daemon=True,
        )
        daemon._publication_thread = worker
        worker.start()
        assert started.wait(timeout=1.0)
        assert accepted.wait(timeout=1.0)

        deadline = time.monotonic() + 0.25
        daemon._stop_publication_worker(deadline=deadline)

        assert not worker.is_alive()
        assert daemon._publication_thread is None
        assert connection_closed.wait(timeout=1.0)
        assert outcomes
    finally:
        server_stop.set()
        daemon = locals().get("daemon")
        if daemon is not None:
            daemon._publication_stop.set()
            daemon._publication_wakeup.set()
        if worker is not None and worker.is_alive():
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            worker.join(timeout=1.0)
        if client is not None:
            client.close()
        if connection is not None:
            connection.close()
        listener.close()
        server.join(timeout=1.0)


def test_publication_worker_shutdown_linearizes_connection_checkout(monkeypatch):
    import boto3
    from botocore.awsrequest import AWSHTTPConnectionPool
    from botocore.config import Config as BotoConfig

    from coquic_steward.publication.r2 import R2Client, public_object_key

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}"
    checkout_returned = threading.Event()
    release_checkout = threading.Event()
    connected = threading.Event()
    server_stop = threading.Event()
    connection: socket.socket | None = None

    def serve() -> None:
        nonlocal connection
        try:
            while not server_stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                connected.set()
                connection.settimeout(0.1)
                while not server_stop.is_set():
                    try:
                        if not connection.recv(65536):
                            return
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                return
        except OSError:
            return

    original_get_conn = AWSHTTPConnectionPool._get_conn

    def paused_get_conn(pool, *args, **kwargs):
        connection = original_get_conn(pool, *args, **kwargs)
        if kwargs.get("timeout") == 0.0 or (args and args[0] == 0.0):
            return connection
        checkout_returned.set()
        release_checkout.wait(timeout=2.0)
        return connection

    monkeypatch.setattr(AWSHTTPConnectionPool, "_get_conn", paused_get_conn)
    server = threading.Thread(target=serve, daemon=True)
    server.start()
    client = None
    worker = None
    stop_thread = None
    daemon = None
    try:
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id="test-access-key",
            aws_secret_access_key="test-secret-key",
            region_name="auto",
            config=BotoConfig(
                connect_timeout=1,
                read_timeout=60,
                retries={"max_attempts": 0, "mode": "standard"},
            ),
        )
        r2 = R2Client(
            endpoint="https://r2.example.test",
            public_bucket="publication-public",
            private_bucket="publication-private",
            client=client,
        )
        publisher = SimpleNamespace(r2=r2, d1=_d1_transport_double())
        daemon = object.__new__(StewardDaemon)
        daemon.config = SimpleNamespace(publication=SimpleNamespace(enabled=True))
        daemon._publication_stop = threading.Event()
        daemon._publication_wakeup = threading.Event()
        daemon._publication_cancel = None
        daemon._publication_thread = None
        daemon._publication_retry_interval = lambda: 0.01
        daemon._build_publication_publisher = lambda: publisher
        daemon._log = lambda _message: None
        content = b"checkout cancellation boundary"
        key = public_object_key("task", hashlib.sha256(content).hexdigest())

        def publish(_publisher: object) -> bool:
            try:
                r2.put_object(key, content)
            except Exception:
                # Cancellation is expected to interrupt the in-flight request.
                pass
            return False

        daemon._publish_next_generation = publish
        worker = threading.Thread(target=daemon._publication_worker_loop, daemon=True)
        daemon._publication_thread = worker
        worker.start()
        assert checkout_returned.wait(timeout=1.0)

        cancellation_called = threading.Event()
        cancel = daemon._publication_cancel
        assert cancel is not None

        def cancel_and_signal() -> None:
            cancel.cancel()
            cancellation_called.set()

        daemon._publication_cancel = daemon_module._CallbackDaemonCancellation(
            cancel_and_signal
        )
        deadline = time.monotonic() + 0.25
        stop_thread = threading.Thread(
            target=daemon._stop_publication_worker,
            kwargs={"deadline": deadline},
            daemon=True,
        )
        stop_thread.start()
        assert cancellation_called.wait(timeout=1.0)
        release_checkout.set()
        stop_thread.join(timeout=1.0)

        assert not stop_thread.is_alive()
        assert not worker.is_alive()
        assert daemon._publication_thread is None
        assert not connected.is_set()
    finally:
        release_checkout.set()
        server_stop.set()
        if daemon is not None:
            daemon._publication_stop.set()
            daemon._publication_wakeup.set()
        if worker is not None and worker.is_alive():
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            worker.join(timeout=1.0)
        if stop_thread is not None and stop_thread.is_alive():
            stop_thread.join(timeout=1.0)
        if client is not None:
            client.close()
        if connection is not None:
            connection.close()
        listener.close()
        server.join(timeout=1.0)


def test_publication_worker_shutdown_cancels_registered_connection_handoff(
    monkeypatch,
):
    import boto3
    from botocore.config import Config as BotoConfig

    from coquic_steward.orchestration.daemon import BotocoreR2TransportAdapter
    from coquic_steward.publication.r2 import R2Client, public_object_key

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}"
    connection_registered = threading.Event()
    release_handoff = threading.Event()
    connected = threading.Event()
    server_stop = threading.Event()
    connection: socket.socket | None = None

    def serve() -> None:
        nonlocal connection
        try:
            while not server_stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                connected.set()
                connection.settimeout(0.1)
                while not server_stop.is_set():
                    try:
                        if not connection.recv(65536):
                            return
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                return
        except OSError:
            return

    original_track_connection = BotocoreR2TransportAdapter._track_connection

    def paused_track_connection(tracker, transport_connection):
        accepted = original_track_connection(tracker, transport_connection)
        if accepted:
            connection_registered.set()
            release_handoff.wait(timeout=2.0)
        return accepted

    monkeypatch.setattr(
        BotocoreR2TransportAdapter,
        "_track_connection",
        paused_track_connection,
    )
    server = threading.Thread(target=serve, daemon=True)
    server.start()
    client = None
    worker = None
    stop_thread = None
    daemon = None
    try:
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id="test-access-key",
            aws_secret_access_key="test-secret-key",
            region_name="auto",
            config=BotoConfig(
                connect_timeout=1,
                read_timeout=60,
                retries={"max_attempts": 0, "mode": "standard"},
            ),
        )
        r2 = R2Client(
            endpoint="https://r2.example.test",
            public_bucket="publication-public",
            private_bucket="publication-private",
            client=client,
        )
        publisher = SimpleNamespace(r2=r2, d1=_d1_transport_double())
        daemon = object.__new__(StewardDaemon)
        daemon.config = SimpleNamespace(publication=SimpleNamespace(enabled=True))
        daemon._publication_stop = threading.Event()
        daemon._publication_wakeup = threading.Event()
        daemon._publication_cancel = None
        daemon._publication_thread = None
        daemon._publication_retry_interval = lambda: 0.01
        daemon._build_publication_publisher = lambda: publisher
        daemon._log = lambda _message: None
        content = b"registered checkout cancellation boundary"
        key = public_object_key("task", hashlib.sha256(content).hexdigest())

        def publish(_publisher: object) -> bool:
            try:
                r2.put_object(key, content)
            except Exception:
                pass
            return False

        daemon._publish_next_generation = publish
        worker = threading.Thread(target=daemon._publication_worker_loop, daemon=True)
        daemon._publication_thread = worker
        worker.start()
        assert connection_registered.wait(timeout=1.0)

        cancellation_called = threading.Event()
        cancel = daemon._publication_cancel
        assert cancel is not None

        def cancel_and_signal() -> None:
            cancel.cancel()
            cancellation_called.set()

        daemon._publication_cancel = daemon_module._CallbackDaemonCancellation(
            cancel_and_signal
        )
        deadline = time.monotonic() + 0.25
        stop_thread = threading.Thread(
            target=daemon._stop_publication_worker,
            kwargs={"deadline": deadline},
            daemon=True,
        )
        stop_thread.start()
        assert cancellation_called.wait(timeout=1.0)
        release_handoff.set()
        stop_thread.join(timeout=1.0)

        assert not stop_thread.is_alive()
        assert not worker.is_alive()
        assert daemon._publication_thread is None
        assert not connected.is_set()
    finally:
        release_handoff.set()
        server_stop.set()
        if daemon is not None:
            daemon._publication_stop.set()
            daemon._publication_wakeup.set()
        if worker is not None and worker.is_alive():
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            worker.join(timeout=1.0)
        if stop_thread is not None and stop_thread.is_alive():
            stop_thread.join(timeout=1.0)
        if client is not None:
            client.close()
        if connection is not None:
            connection.close()
        listener.close()
        server.join(timeout=1.0)


@pytest.mark.parametrize("https", [False, True])
def test_botocore_transport_adapter_accepts_pinned_connection_classes(https):
    r2 = _botocore_transport_double(https=https)
    adapter = BotocoreR2TransportAdapter(r2)
    adapter.close()


@pytest.mark.parametrize(
    "missing_hook",
    ["session", "manager", "pool_get", "pool_put"],
)
def test_botocore_transport_adapter_rejects_missing_shape(missing_hook):
    r2 = _botocore_transport_double()
    session = r2._client._endpoint.http_session
    manager = session._get_connection_manager("http://publication.example.test")
    pool = manager.connection_from_url("http://publication.example.test")
    if missing_hook == "session":
        del session._get_connection_manager
    elif missing_hook == "manager":
        del manager.connection_from_url
    elif missing_hook == "pool_get":
        del pool._get_conn
    else:
        del pool._put_conn

    with pytest.raises(PublicationTransportSetupError) as error:
        BotocoreR2TransportAdapter(r2)
    assert str(error.value) == "unsupported publication transport shape"


def test_botocore_transport_adapter_rejects_missing_connection_hook():
    r2 = _botocore_transport_double()
    session = r2._client._endpoint.http_session
    manager = session._get_connection_manager("http://publication.example.test")
    pool = manager.connection_from_url("http://publication.example.test")
    pool._get_conn = lambda timeout=None: SimpleNamespace(
        sock=None,
        close=lambda: None,
    )

    with pytest.raises(PublicationTransportSetupError) as error:
        BotocoreR2TransportAdapter(r2)
    assert str(error.value) == "unsupported publication transport shape"


@pytest.mark.parametrize("connect", [None, object()])
def test_botocore_transport_adapter_rejects_non_callable_connection_hook(connect):
    r2 = _botocore_transport_double()
    session = r2._client._endpoint.http_session
    manager = session._get_connection_manager("http://publication.example.test")
    pool = manager.connection_from_url("http://publication.example.test")
    pool._get_conn = lambda timeout=None: SimpleNamespace(
        sock=None,
        connect=connect,
        close=lambda: None,
    )

    with pytest.raises(PublicationTransportSetupError) as error:
        BotocoreR2TransportAdapter(r2)
    assert str(error.value) == "unsupported publication transport shape"


def test_botocore_transport_adapter_instruments_proxy_manager():
    direct_connection = _botocore_connection()
    proxy_socket = SimpleNamespace(
        shutdown_calls=[],
        close_calls=0,
    )

    def shutdown(how):
        proxy_socket.shutdown_calls.append(how)

    def close_socket():
        proxy_socket.close_calls += 1

    proxy_socket.shutdown = shutdown
    proxy_socket.close = close_socket
    proxy_connection = _botocore_connection(sock=proxy_socket)
    direct_pool = SimpleNamespace(
        _get_conn=lambda timeout=None: direct_connection,
        _put_conn=lambda _connection: None,
    )
    proxy_pool = SimpleNamespace(
        _get_conn=lambda timeout=None: proxy_connection,
        _put_conn=lambda _connection: None,
    )
    direct_manager = SimpleNamespace(
        connection_from_url=lambda _url, _pool_kwargs=None: direct_pool,
    )
    proxy_manager = SimpleNamespace(
        connection_from_url=lambda _url, _pool_kwargs=None: proxy_pool,
    )
    session = SimpleNamespace()
    session._get_connection_manager = (
        lambda _url, proxy_url=None: proxy_manager
        if proxy_url is not None
        else direct_manager
    )
    endpoint = SimpleNamespace(
        host="https://publication.example.test",
        http_session=session,
    )
    provider_client = SimpleNamespace(_endpoint=endpoint, close=lambda: None)
    r2 = SimpleNamespace(_client=provider_client)
    adapter = BotocoreR2TransportAdapter(r2)

    try:
        selected_manager = session._get_connection_manager(
            endpoint.host,
            "http://proxy.example.test:8080",
        )
        selected_pool = selected_manager.connection_from_url(endpoint.host)
        selected_pool._get_conn(timeout=0.0)

        adapter.cancel()

        assert proxy_socket.shutdown_calls == [socket.SHUT_RDWR]
        assert proxy_socket.close_calls == 1
    finally:
        adapter.close()


def test_botocore_transport_adapter_bounds_concurrent_cancellation():
    r2 = _botocore_transport_double()
    adapter = BotocoreR2TransportAdapter(r2)
    session = r2._client._endpoint.http_session
    manager = session._get_connection_manager("http://publication.example.test")
    pool = manager.connection_from_url("http://publication.example.test")
    pool._get_conn(timeout=0.0)

    abort_started = threading.Event()
    release_abort = threading.Event()
    first_returned = threading.Event()
    second_returned = threading.Event()
    first_result: list[bool] = []
    second_result: list[bool] = []
    errors: list[BaseException] = []

    def gated_abort(_connection: object) -> None:
        abort_started.set()
        release_abort.wait(timeout=2.0)

    adapter._abort_connection = gated_abort

    def first_cancel() -> None:
        try:
            first_result.append(adapter.cancel().quiescent)
        except BaseException as error:
            errors.append(error)
        finally:
            first_returned.set()

    def second_cancel() -> None:
        try:
            second_result.append(
                adapter.cancel(deadline=time.monotonic() + 0.1).quiescent
            )
        except BaseException as error:
            errors.append(error)
        finally:
            second_returned.set()

    first = threading.Thread(target=first_cancel, daemon=True)
    second = threading.Thread(target=second_cancel, daemon=True)
    first.start()
    assert abort_started.wait(timeout=1.0)
    second.start()

    try:
        assert second_returned.wait(timeout=1.0)
        assert second_result == [False]
        assert not first_returned.is_set()
        release_abort.set()
        assert first_returned.wait(timeout=1.0)
        first.join(timeout=1.0)
        second.join(timeout=1.0)
        assert not first.is_alive()
        assert not second.is_alive()
        assert first_result == [True]
        assert errors == []
    finally:
        release_abort.set()
        first.join(timeout=1.0)
        second.join(timeout=1.0)
        adapter.close()


@pytest.mark.parametrize("failure", ["r2", "d1"])
def test_publication_transport_cancellation_closes_clients_on_setup_failure(failure):
    r2 = _botocore_transport_double()
    r2_closed = threading.Event()
    r2._client.close = r2_closed.set
    d1_closed = threading.Event()
    d1 = _d1_transport_double(d1_closed.set)

    if failure == "r2":
        session = r2._client._endpoint.http_session
        manager = session._get_connection_manager("http://publication.example.test")
        pool = manager.connection_from_url("http://publication.example.test")
        del pool._get_conn
    else:
        pool = d1._client._transport._pool
        del pool._connections

    try:
        with pytest.raises(PublicationTransportSetupError) as error:
            daemon_module._PublicationTransportCancellation(r2, d1)
        assert str(error.value) == "unsupported publication transport shape"
        assert r2_closed.is_set()
        assert d1_closed.is_set()
    finally:
        d1.close()


@pytest.mark.parametrize("missing_hook", ["transport", "pool", "connections"])
def test_httpx_transport_adapter_rejects_missing_shape(missing_hook):
    d1 = _d1_transport_double()
    try:
        http_client = d1._client
        transport = http_client._transport
        pool = transport._pool
        if missing_hook == "transport":
            del http_client._transport
        elif missing_hook == "pool":
            del transport._pool
        else:
            del pool._connections

        with pytest.raises(PublicationTransportSetupError) as error:
            HttpxD1TransportAdapter(d1)
        assert str(error.value) == "unsupported publication transport shape"
    finally:
        d1.close()


@pytest.mark.parametrize(
    "connection",
    [
        SimpleNamespace(close=lambda: None),
        SimpleNamespace(
            _connection=SimpleNamespace(
                _network_stream=SimpleNamespace(_socket=object())
            ),
            close=lambda: None,
        ),
    ],
)
def test_httpx_transport_adapter_rejects_unsupported_connection_shape(connection):
    d1 = _d1_transport_double()
    try:
        d1._client._transport._pool._connections.append(connection)
        with pytest.raises(PublicationTransportSetupError) as error:
            HttpxD1TransportAdapter(d1)
        assert str(error.value) == "unsupported publication transport shape"
    finally:
        d1.close()


def test_httpx_transport_adapter_rejects_unsupported_connection_during_cancellation():
    d1 = _d1_transport_double()
    adapter = HttpxD1TransportAdapter(d1)
    d1._client._transport._pool._connections.append(
        SimpleNamespace(
            _connection=SimpleNamespace(
                _network_stream=SimpleNamespace(_socket=object())
            ),
            close=lambda: None,
        )
    )
    try:
        with pytest.raises(PublicationTransportSetupError) as error:
            adapter.cancel()
        assert str(error.value) == "unsupported publication transport shape"
        assert not adapter.cancel().quiescent
    finally:
        d1.close()


def test_httpx_transport_adapter_fences_existing_established_connection(
    monkeypatch,
):
    import httpcore
    from httpcore._backends.sync import SyncStream

    from coquic_steward.orchestration.transport import _HttpxD1HandoffStream

    http_client = httpx.Client(transport=httpx.HTTPTransport(trust_env=False))
    pool = http_client._transport._pool
    origin = httpcore.Origin(b"http", b"publication.example.test", 80)
    connection = pool.create_connection(origin)
    left, right = socket.socketpair()
    connection._connection = httpcore.HTTP11Connection(
        origin=origin, stream=SyncStream(left)
    )
    pool._connections.append(connection)
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    try:
        stream = connection._connection._network_stream
        assert isinstance(stream, _HttpxD1HandoffStream)
        read_started = threading.Event()
        read_done = threading.Event()
        read_errors: list[BaseException] = []

        def read() -> None:
            read_started.set()
            try:
                stream.read(1)
            except BaseException as error:
                read_errors.append(error)
            finally:
                read_done.set()

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        assert read_started.wait(timeout=1.0)
        adapter.cancel()
        assert read_done.wait(timeout=1.0)
        reader.join(timeout=1.0)
        assert not reader.is_alive()
        assert read_errors
        with pytest.raises(OSError):
            stream.write(b"GET /after-revocation HTTP/1.1\r\n\r\n")
        right.settimeout(1.0)
        assert right.recv(1) == b""
    finally:
        adapter.close()
        d1.close()
        right.close()


def test_httpx_transport_adapter_preserves_uncancelled_d1_publication(
    monkeypatch,
):
    response_body = (
        b'{"success":true,"errors":[],"result":[{"success":true,'
        b'"errors":[],"results":[],"meta":{}}]}'
    )
    writes: list[bytes] = []

    class Stream:
        def __init__(self) -> None:
            self._response = (
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(response_body)}\r\n"
                .encode()
                + b"Content-Type: application/json\r\n\r\n"
                + response_body
            )

        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)

        def read(self, maximum: int, timeout: float | None = None) -> bytes:
            response = self._response[:maximum]
            self._response = self._response[maximum:]
            return response

        def close(self) -> None:
            return None

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    http_client = httpx.Client(trust_env=False)
    http_client._transport._pool._network_backend = Backend()
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    try:
        result = d1._post([("SELECT 1", ())])
        assert result == [
            {"success": True, "errors": [], "results": [], "meta": {}}
        ]
        assert any(data.startswith(b"POST ") for data in writes)
    finally:
        adapter.close()
        d1.close()


def test_httpx_transport_adapter_fences_existing_established_proxy_connection(
    monkeypatch,
):
    import httpcore
    from httpcore._backends.sync import SyncStream

    from coquic_steward.orchestration.transport import _HttpxD1HandoffStream

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    pool = proxy._pool
    origin = httpcore.Origin(b"https", b"publication.example.test", 443)
    connection = pool.create_connection(origin)
    left, right = socket.socketpair()
    connection._connection = httpcore.HTTP11Connection(
        origin=origin, stream=SyncStream(left)
    )
    connection._connected = True
    pool._connections.append(connection)
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "https://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    try:
        stream = connection._connection._network_stream
        assert isinstance(stream, _HttpxD1HandoffStream)
        adapter.cancel()
        with pytest.raises(OSError):
            stream.write(b"POST /after-revocation HTTP/1.1\r\n\r\n")
        right.settimeout(1.0)
        assert right.recv(1) == b""
    finally:
        adapter.close()
        d1.close()
        right.close()


def test_httpx_transport_adapter_rejects_https_forward_origin_before_publication(
    monkeypatch,
):
    import httpcore
    from httpcore._backends.sync import SyncStream
    from httpcore._sync.http_proxy import ForwardHTTPConnection

    writes: list[bytes] = []

    class RecordingStream(SyncStream):
        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)
            super().write(data, timeout=timeout)

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    pool = proxy._pool
    proxy_origin = pool._proxy_url.origin
    forward = ForwardHTTPConnection(
        proxy_origin=proxy_origin,
        remote_origin=httpcore.Origin(
            b"https", b"publication.example.test", 443
        ),
        network_backend=pool._network_backend,
    )
    left, right = socket.socketpair()
    forward._connection._connection = httpcore.HTTP11Connection(
        origin=proxy_origin,
        stream=RecordingStream(left),
    )
    pool._connections.append(forward)
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "https://publication.example.test/query"),
    )

    try:
        with pytest.raises(PublicationTransportSetupError) as error:
            HttpxD1TransportAdapter(d1)
        assert str(error.value) == "unsupported publication transport shape"
        assert writes == []
    finally:
        d1.close()
        right.close()
        left.close()


def test_httpx_transport_adapter_rejects_mutated_forward_origin_during_cancellation():
    import httpcore
    from httpcore._backends.sync import SyncStream

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    pool = proxy._pool
    forward = pool.create_connection(
        httpcore.Origin(b"http", b"forward.example.test", 80)
    )
    tunnel = pool.create_connection(
        httpcore.Origin(b"https", b"publication.example.test", 443)
    )
    left, right = socket.socketpair()
    tunnel._connection = httpcore.HTTP11Connection(
        origin=httpcore.Origin(b"https", b"publication.example.test", 443),
        stream=SyncStream(left),
    )
    tunnel._connected = False
    pool._connections.extend([forward, tunnel])
    d1 = _d1_transport_double(http_client=http_client)
    adapter = HttpxD1TransportAdapter(d1)
    forward._remote_origin = httpcore.Origin(
        b"https", b"publication.example.test", 443
    )

    try:
        with pytest.raises(PublicationTransportSetupError) as error:
            adapter.cancel()
        assert str(error.value) == "unsupported publication transport shape"
        assert not adapter.cancel().quiescent
        right.settimeout(1.0)
        assert right.recv(1) == b""
    finally:
        adapter.close()
        d1.close()
        right.close()
        left.close()


@pytest.mark.parametrize("bounded", [False, True])
def test_httpx_transport_adapter_interrupts_mutated_forward_handoff(
    bounded: bool,
):
    import httpcore
    from httpcore._backends.sync import SyncStream

    read_entered = threading.Event()
    read_done = threading.Event()
    read_errors: list[BaseException] = []

    class BlockingStream(SyncStream):
        def read(self, maximum: int, timeout: float | None = None) -> bytes:
            read_entered.set()
            return super().read(maximum, timeout=timeout)

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    pool = proxy._pool
    forward = pool.create_connection(
        httpcore.Origin(b"http", b"forward.example.test", 80)
    )
    left, right = socket.socketpair()
    forward._connection._connection = httpcore.HTTP11Connection(
        origin=pool._proxy_url.origin,
        stream=BlockingStream(left),
    )
    pool._connections.append(forward)
    d1 = _d1_transport_double(http_client=http_client)
    adapter = HttpxD1TransportAdapter(d1)
    stream = forward._connection._connection._network_stream

    def read() -> None:
        try:
            stream.read(1)
        except BaseException as error:
            read_errors.append(error)
        finally:
            read_done.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    assert read_entered.wait(timeout=1.0)
    forward._remote_origin = httpcore.Origin(
        b"https", b"publication.example.test", 443
    )

    cancellation_done = threading.Event()
    cancellation_errors: list[BaseException] = []
    deadline = time.monotonic() + 0.25 if bounded else None

    def cancel() -> None:
        try:
            adapter.cancel(deadline=deadline)
        except BaseException as error:
            cancellation_errors.append(error)
        finally:
            cancellation_done.set()

    cancellation = threading.Thread(target=cancel, daemon=True)
    cancellation.start()
    try:
        assert cancellation_done.wait(timeout=1.0)
        cancellation.join(timeout=1.0)
        assert cancellation_errors
        assert isinstance(cancellation_errors[0], PublicationTransportSetupError)
        assert str(cancellation_errors[0]) == "unsupported publication transport shape"
        assert read_done.wait(timeout=1.0)
        reader.join(timeout=1.0)
        assert not reader.is_alive()
        assert read_errors
        right.settimeout(1.0)
        assert right.recv(1) == b""
        assert not adapter.cancel(deadline=time.monotonic() + 0.25).quiescent
    finally:
        if not read_done.is_set() or not cancellation_done.is_set():
            try:
                right.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        right.close()
        cancellation.join(timeout=1.0)
        adapter.close()
        d1.close()
        reader.join(timeout=1.0)
        left.close()


def test_httpx_transport_adapter_accepts_mixed_proxy_pool_and_tunnel_transition(
    monkeypatch,
):
    import httpcore
    from httpcore._backends.sync import SyncStream

    from coquic_steward.orchestration.transport import _HttpxD1HandoffStream

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    pool = proxy._pool
    forward = pool.create_connection(
        httpcore.Origin(b"http", b"forward.example.test", 80)
    )
    tunnel = pool.create_connection(
        httpcore.Origin(b"https", b"publication.example.test", 443)
    )
    left, right = socket.socketpair()
    tunnel._connection = httpcore.HTTP11Connection(
        origin=httpcore.Origin(b"https", b"publication.example.test", 443),
        stream=SyncStream(left),
    )
    tunnel._connected = False
    pool._connections.extend([forward, tunnel])
    d1 = _d1_transport_double(http_client=http_client)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "https://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    try:
        assert adapter._proxy_connections[id(forward)] is forward._connection
        assert tunnel._connection is not None
        assert isinstance(
            tunnel._connection._network_stream, _HttpxD1HandoffStream
        )
        assert adapter.cancel().quiescent
        right.settimeout(1.0)
        assert right.recv(1) == b""
    finally:
        adapter.close()
        d1.close()
        right.close()


@pytest.mark.parametrize("endpoint_scheme", ["http", "https"])
def test_httpx_transport_adapter_fences_selected_proxy_before_connect(
    endpoint_scheme: str, monkeypatch
):
    import httpcore

    started = threading.Event()
    release = threading.Event()
    stream_closed = threading.Event()
    writes: list[bytes] = []
    errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            return b""

        def close(self) -> None:
            stream_closed.set()

        def start_tls(self, *_args: object, **_kwargs: object) -> "Stream":
            return self

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            started.set()
            release.wait(timeout=2.0)
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    proxy._pool._network_backend = Backend()
    http_client = httpx.Client(
        transport=direct,
        mounts={f"{endpoint_scheme}://": proxy},
        trust_env=False,
    )
    d1 = D1PublicationClient(
        account_id="a" * 32,
        database_id="00000000-0000-4000-8000-000000000000",
        token="test-token",
        http_client=http_client,
    )
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(
            lambda _client: f"{endpoint_scheme}://publication.example.test/query"
        ),
    )
    adapter = HttpxD1TransportAdapter(d1)
    assert adapter._pool is proxy._pool
    assert type(adapter._pool) is httpcore.HTTPProxy

    def request() -> None:
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    assert started.wait(timeout=1.0)
    adapter.cancel()
    adapter.cancel()
    release.set()
    worker.join(timeout=1.0)

    try:
        assert not worker.is_alive()
        assert stream_closed.wait(timeout=1.0)
        assert writes == []
        assert errors
        assert isinstance(errors[0], daemon_module._PublicationTransportCancelled)
    finally:
        release.set()
        adapter.close()
        d1.close()


def test_httpx_transport_adapter_fences_active_proxy_write_before_cancel_returns(
    monkeypatch,
):
    write_entered = threading.Event()
    release_write = threading.Event()
    stream_closed = threading.Event()
    cancel_returned = threading.Event()
    writes: list[bytes] = []
    request_errors: list[BaseException] = []
    cancel_errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            write_entered.set()
            release_write.wait(timeout=2.0)
            writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            return b""

        def close(self) -> None:
            stream_closed.set()

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    proxy._pool._network_backend = Backend()
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    d1 = D1PublicationClient(
        account_id="a" * 32,
        database_id="00000000-0000-4000-8000-000000000000",
        token="test-token",
        http_client=http_client,
    )
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "https://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    def request() -> None:
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            request_errors.append(error)

    def cancel() -> None:
        try:
            adapter.cancel()
        except BaseException as error:
            cancel_errors.append(error)
        finally:
            cancel_returned.set()

    worker = threading.Thread(target=request, daemon=True)
    cancellation = threading.Thread(target=cancel, daemon=True)
    worker.start()
    assert write_entered.wait(timeout=1.0)
    cancellation.start()

    try:
        assert stream_closed.wait(timeout=1.0)
        assert not cancel_returned.is_set()
        assert writes == []
        release_write.set()
        assert cancel_returned.wait(timeout=1.0)
        cancellation.join(timeout=1.0)
        worker.join(timeout=1.0)
        assert not cancellation.is_alive()
        assert not worker.is_alive()
        assert cancel_errors == []
        assert len(writes) == 1
        assert writes[0].startswith(b"CONNECT ")
        assert request_errors
        assert isinstance(request_errors[0], D1Error)
        assert request_errors[0].code.value == "network"
    finally:
        release_write.set()
        cancellation.join(timeout=1.0)
        worker.join(timeout=1.0)
        adapter.close()
        d1.close()


@pytest.mark.parametrize("selected_route", ["mock", "custom-pool", "socks"])
def test_httpx_transport_adapter_rejects_unsupported_selected_route(
    monkeypatch, selected_route: str
):
    import httpcore

    direct = httpx.HTTPTransport(trust_env=False)
    if selected_route == "mock":
        selected = httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"ok": True})
        )
    elif selected_route == "custom-pool":
        class CustomPool(httpcore.ConnectionPool):
            pass

        selected = httpx.HTTPTransport(trust_env=False)
        selected._pool = CustomPool()
    else:
        selected = httpx.HTTPTransport(trust_env=False)
        selected._pool = object.__new__(httpcore.SOCKSProxy)
        selected._pool.close = lambda: None
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": selected},
        trust_env=False,
    )
    d1 = D1PublicationClient(
        account_id="a" * 32,
        database_id="00000000-0000-4000-8000-000000000000",
        token="test-token",
        http_client=http_client,
    )
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "https://publication.example.test/query"),
    )

    try:
        with pytest.raises(PublicationTransportSetupError) as error:
            HttpxD1TransportAdapter(d1)
        assert str(error.value) == "unsupported publication transport shape"
    finally:
        d1.close()
        http_client.close()


def test_httpx_transport_adapter_fences_selected_proxy_tls_before_d1_write(
    monkeypatch,
):
    tls_started = threading.Event()
    release_tls = threading.Event()
    stream_closed = threading.Event()
    cancel_returned = threading.Event()
    writes: list[bytes] = []
    errors: list[BaseException] = []
    cancel_errors: list[BaseException] = []
    post_revocation_tls: list[bool] = []

    class Stream:
        def __init__(self) -> None:
            self._response = b"HTTP/1.1 200 Connection Established\r\n\r\n"

        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)

        def read(self, maximum: int, timeout: float | None = None) -> bytes:
            response = self._response[:maximum]
            self._response = self._response[maximum:]
            return response

        def close(self) -> None:
            stream_closed.set()

        def start_tls(self, *_args: object, **_kwargs: object) -> "Stream":
            tls_started.set()
            release_tls.wait(timeout=2.0)
            if cancel_returned.is_set():
                post_revocation_tls.append(True)
            return self

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    direct = httpx.HTTPTransport(trust_env=False)
    proxy = httpx.HTTPTransport(
        proxy="http://proxy.example.test:8080", trust_env=False
    )
    proxy._pool._network_backend = Backend()
    http_client = httpx.Client(
        transport=direct,
        mounts={"https://": proxy},
        trust_env=False,
    )
    d1 = D1PublicationClient(
        account_id="a" * 32,
        database_id="00000000-0000-4000-8000-000000000000",
        token="test-token",
        http_client=http_client,
    )
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "https://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    def request() -> None:
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    def cancel() -> None:
        try:
            adapter.cancel()
        except BaseException as error:
            cancel_errors.append(error)
        finally:
            cancel_returned.set()

    worker = threading.Thread(target=request, daemon=True)
    cancellation = threading.Thread(target=cancel, daemon=True)
    worker.start()
    assert tls_started.wait(timeout=1.0)
    cancellation.start()

    try:
        assert stream_closed.wait(timeout=1.0)
        assert not cancel_returned.is_set()
        release_tls.set()
        assert cancel_returned.wait(timeout=1.0)
        cancellation.join(timeout=1.0)
        worker.join(timeout=1.0)
        assert not cancellation.is_alive()
        assert not worker.is_alive()
        assert cancel_errors == []
        assert stream_closed.is_set()
        assert errors
        assert isinstance(errors[0], D1Error)
        assert errors[0].code.value == "network"
        assert post_revocation_tls == []
        assert not any(b"POST " in data for data in writes)
    finally:
        release_tls.set()
        cancellation.join(timeout=1.0)
        worker.join(timeout=1.0)
        adapter.close()
        d1.close()


def test_httpx_transport_adapter_fences_pre_socket_connection_after_cancellation(
    monkeypatch,
):
    started = threading.Event()
    release = threading.Event()
    stream_closed = threading.Event()
    writes: list[bytes] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            return b""

        def close(self) -> None:
            stream_closed.set()

        def start_tls(self, **_kwargs: object) -> "Stream":
            return self

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            started.set()
            release.wait(timeout=2.0)
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    d1 = _d1_transport_double()
    d1._client._transport._pool._network_backend = Backend()
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)
    errors: list[BaseException] = []

    def request() -> None:
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    assert started.wait(timeout=1.0)
    adapter.cancel()
    adapter.cancel()
    release.set()
    worker.join(timeout=1.0)

    try:
        assert not worker.is_alive()
        assert stream_closed.wait(timeout=1.0)
        assert writes == []
        assert errors
        assert isinstance(errors[0], daemon_module._PublicationTransportCancelled)
    finally:
        adapter.close()
        d1.close()


def test_httpx_transport_adapter_fences_post_connect_stream_handoff(monkeypatch):
    extra_info_entered = threading.Event()
    release_extra_info = threading.Event()
    stream_closed = threading.Event()
    cancel_returned = threading.Event()
    writes: list[bytes] = []
    errors: list[BaseException] = []
    cancel_errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            return b""

        def close(self) -> None:
            stream_closed.set()

        def get_extra_info(self, _name: str) -> object | None:
            extra_info_entered.set()
            release_extra_info.wait(timeout=2.0)
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    d1 = _d1_transport_double()
    d1._client._transport._pool._network_backend = Backend()
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    def request() -> None:
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    def cancel() -> None:
        try:
            adapter.cancel()
        except BaseException as error:
            cancel_errors.append(error)
        finally:
            cancel_returned.set()

    worker = threading.Thread(target=request, daemon=True)
    cancellation = threading.Thread(target=cancel, daemon=True)
    worker.start()
    assert extra_info_entered.wait(timeout=1.0)
    cancellation.start()

    try:
        assert stream_closed.wait(timeout=1.0)
        assert not cancel_returned.is_set()
        release_extra_info.set()
        assert cancel_returned.wait(timeout=1.0)
        cancellation.join(timeout=1.0)
        worker.join(timeout=1.0)
        assert not cancellation.is_alive()
        assert not worker.is_alive()
        assert cancel_errors == []
        assert writes == []
        assert errors
        assert isinstance(errors[0], daemon_module._PublicationTransportCancelled)
    finally:
        release_extra_info.set()
        cancellation.join(timeout=1.0)
        worker.join(timeout=1.0)
        adapter.close()
        d1.close()


def test_httpx_transport_adapter_fences_protocol_assignment_after_cancellation(
    monkeypatch,
):
    import httpcore._sync.connection as httpcore_connection
    from httpcore._sync.http11 import HTTP11Connection as RealHTTP11Connection

    constructor_entered = threading.Event()
    release_constructor = threading.Event()
    stream_closed = threading.Event()
    writes: list[bytes] = []
    errors: list[BaseException] = []

    class Stream:
        def write(self, data: bytes, timeout: float | None = None) -> None:
            writes.append(data)

        def read(self, _maximum: int, timeout: float | None = None) -> bytes:
            return b""

        def close(self) -> None:
            stream_closed.set()

        def get_extra_info(self, _name: str) -> object | None:
            return None

    class Backend:
        def connect_tcp(self, **_kwargs: object) -> Stream:
            return Stream()

        def connect_unix_socket(self, **_kwargs: object) -> Stream:
            raise AssertionError("D1 must use TCP")

    class PausedHTTP11Connection(RealHTTP11Connection):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)
            constructor_entered.set()
            release_constructor.wait(timeout=2.0)

    d1 = _d1_transport_double()
    d1._client._transport._pool._network_backend = Backend()
    monkeypatch.setattr(httpcore_connection, "HTTP11Connection", PausedHTTP11Connection)
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: "http://publication.example.test/query"),
    )
    adapter = HttpxD1TransportAdapter(d1)

    def request() -> None:
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    assert constructor_entered.wait(timeout=1.0)
    adapter.cancel()
    assert stream_closed.is_set()
    release_constructor.set()
    worker.join(timeout=1.0)

    try:
        assert not worker.is_alive()
        assert writes == []
        assert errors
        assert isinstance(errors[0], daemon_module._PublicationTransportCancelled)
    finally:
        adapter.close()
        d1.close()


def test_publication_worker_shutdown_interrupts_inflight_httpx_d1_request(monkeypatch):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}/query"
    accepted = threading.Event()
    connection_closed = threading.Event()
    server_stop = threading.Event()
    connection: socket.socket | None = None

    def serve() -> None:
        nonlocal connection
        try:
            while not server_stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                accepted.set()
                connection.settimeout(0.1)
                while not server_stop.is_set():
                    try:
                        if not connection.recv(65536):
                            connection_closed.set()
                            return
                    except socket.timeout:
                        continue
                    except OSError:
                        connection_closed.set()
                        return
                return
        except OSError:
            return

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    d1 = D1PublicationClient(
        account_id="a" * 32,
        database_id="00000000-0000-4000-8000-000000000000",
        token="test-token",
        http_client=httpx.Client(timeout=60.0),
    )
    monkeypatch.setattr(
        D1PublicationClient,
        "endpoint",
        property(lambda _client: endpoint),
    )
    r2 = _botocore_transport_double()
    publisher = SimpleNamespace(r2=r2, d1=d1)
    daemon = object.__new__(StewardDaemon)
    daemon._publication_stop = threading.Event()
    daemon._publication_wakeup = threading.Event()
    daemon._publication_cancel = None
    daemon._publication_thread = None
    daemon._publication_retry_interval = lambda: 0.01
    daemon._build_publication_publisher = lambda: publisher
    daemon._log = lambda _message: None
    started = threading.Event()
    outcomes: list[BaseException] = []

    def publish(_publisher: object) -> bool:
        started.set()
        try:
            d1._post([("SELECT 1", ())])
        except BaseException as error:
            outcomes.append(error)
        return False

    daemon._publish_next_generation = publish
    worker = threading.Thread(target=daemon._publication_worker_loop, daemon=True)
    daemon._publication_thread = worker
    try:
        worker.start()
        assert started.wait(timeout=1.0)
        assert accepted.wait(timeout=1.0)
        cancellation = daemon._publication_cancel
        assert cancellation is not None
        deadline = time.monotonic() + 0.5
        started_stopping = time.monotonic()
        assert daemon._stop_publication_worker(deadline=deadline) is True
        assert time.monotonic() - started_stopping < 0.5
        assert not worker.is_alive()
        assert daemon._publication_thread is None
        assert connection_closed.wait(timeout=1.0)
        assert outcomes
        assert isinstance(outcomes[0], D1Error)
        cancellation.cancel()
        cancellation.cancel()
    finally:
        server_stop.set()
        daemon._publication_stop.set()
        daemon._publication_wakeup.set()
        if worker.is_alive():
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            worker.join(timeout=1.0)
        d1.close()
        if connection is not None:
            connection.close()
        listener.close()
        server.join(timeout=1.0)


def test_planner_retry_defers_unchanged_input_and_success_resets_state(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _planner_signal(store)
    signal_id = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert signal_id is not None
    store.control_loop.claim_planner_run("planner-run-failed-retry", [signal_id])
    store.control_loop.complete_planner_run(
        "planner-run-failed-retry", [], state="failed"
    )
    store.control_loop.schedule_retry("planner")
    daemon = StewardDaemon(config, store)
    calls = 0

    def successful_no_work(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.private_dir / "missing-planner.jsonl",
            thread_id=None,
            consumed_item_ids=[item.id],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", successful_no_work
    )
    daemon._plan_until_idle(TickResult())
    assert calls == 0
    assert store.control_loop.pending_retry("planner") is not None

    daemon._plan(TickResult(), [item])
    assert calls == 1
    assert store.control_loop.pending_retry("planner") is None


def test_planner_context_keeps_all_active_tasks_and_bounds_terminal_history(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    oldest_active, _ = _task(store, "oldest active planner context")
    store.start_worker(oldest_active.id, "running")
    queued_active, _ = _task(store, "queued active planner context")
    active_tasks = [oldest_active, queued_active]
    for index in range(13):
        active_task, _ = _task(store, f"additional active planner context {index}")
        active_tasks.append(active_task)
    terminal_tasks = []
    for index in range(205):
        terminal, _ = _task(store, f"terminal planner context {index}")
        store.finish_task(terminal.id, TaskStatus.succeeded, "terminal")
        terminal_tasks.append(terminal)
    item = _planner_signal(store, "complete-context")
    captured: list[list[object]] = []

    def fake_run_planner(_config, _signals, tasks, **_kwargs):
        captured.append(list(tasks))
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.private_dir / "planner-context.jsonl",
            thread_id=None,
            consumed_item_ids=[item.id],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", fake_run_planner
    )
    monkeypatch.setattr(
        store,
        "list_tasks",
        lambda **_kwargs: pytest.fail("planner used a capped task listing"),
    )

    daemon = StewardDaemon(config, store)
    daemon._plan(TickResult(), [item])

    assert len(captured) == 1
    context = captured[0]
    active_ids = {task.id for task in active_tasks}
    assert {task.id for task in context[: len(active_tasks)]} == active_ids
    assert len(context) == len(active_tasks) + 200
    terminal_context = [
        task for task in context if TaskStatus(task.status).terminal
    ]
    assert len(terminal_context) == 200
    expected_terminal = sorted(
        terminal_tasks,
        key=lambda task: (task.created_at, task.id),
        reverse=True,
    )[:200]
    assert [task.id for task in terminal_context] == [
        task.id for task in expected_terminal
    ]

    planner_run = store.control_loop.list_planner_runs()[-1]
    assert planner_run.active_task_ids == [
        task.id for task in context[: len(active_tasks)]
    ]
    assert planner_run.prompt is not None
    assert planner_run.prompt["activeTaskCount"] == len(active_ids)


def test_planner_admission_cap_blocks_new_work_at_boundary(config, monkeypatch) -> None:
    config = replace(config, limits=replace(config.limits, max_active_tasks=32))
    store = TaskStore.create(config.db_path)
    for index in range(16):
        _task(store, f"admission boundary active {index}")
    item = _planner_signal(store, "admission-boundary")
    calls: list[object] = []

    def fake_run_planner(*args, **kwargs):
        calls.append((args, kwargs))
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.private_dir / "admission-boundary.jsonl",
            thread_id=None,
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", fake_run_planner
    )
    monkeypatch.setattr(
        store,
        "iter_tasks",
        lambda **_kwargs: pytest.fail("over-cap planning rendered active context"),
    )
    daemon = StewardDaemon(config, store)

    daemon._plan(TickResult(), [item])

    assert calls == []
    assert store.pending_signal_items(limit=1)[0].id == item.id


def test_planner_admission_resumes_after_active_task_drains(config, monkeypatch) -> None:
    config = replace(config, limits=replace(config.limits, max_active_tasks=32))
    store = TaskStore.create(config.db_path)
    active = []
    for index in range(16):
        task, _ = _task(store, f"admission drain active {index}")
        store.start_worker(task.id, "running")
        active.append(task)
    item = _planner_signal(store, "admission-drain")
    calls: list[object] = []

    def fake_run_planner(planner_config, *_args, **_kwargs):
        calls.append(planner_config)
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.private_dir / "admission-drain.jsonl",
            thread_id=None,
            consumed_item_ids=[item.id],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", fake_run_planner
    )
    daemon = StewardDaemon(config, store)

    daemon._plan_until_idle(TickResult())
    assert calls == []

    store.finish_task(active[0].id, TaskStatus.succeeded, "drained")
    daemon._plan_until_idle(TickResult())

    assert len(calls) == 1
    assert calls[0].limits.max_active_tasks == 16


def test_startup_reconstructs_terminal_planner_publication(config) -> None:
    store = TaskStore.create(config.db_path)
    item = _planner_signal(store, "publication")
    signal_id = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert signal_id is not None
    run_id = "planner-run-publication"
    source_root = config.private_dir / "planner-publication-source"
    source_root.mkdir(parents=True)
    artifacts = {
        "prompt.md": b"synthetic prompt\n",
        "codex.jsonl": b'{"type":"failed"}\n',
        "last-message.md": b"synthetic failure\n",
    }
    for name, value in artifacts.items():
        (source_root / name).write_bytes(value)
    store.control_loop.claim_planner_run(run_id, [signal_id])
    store.control_loop.complete_planner_run(
        run_id,
        [],
        state="failed",
        artifact_sources={
            name: (str(source_root / name), True) for name in artifacts
        },
    )

    daemon = StewardDaemon(config, store)
    daemon._startup_reconcile_control_loop()

    published = config.control_loop_dir / "planner-runs" / run_id
    assert daemon._control_loop_archive.verify_planner_run(run_id)
    assert (published / "prompt.md").read_bytes() == artifacts["prompt.md"]
    assert run_id not in daemon._planner_publication_queue


def test_startup_finalizes_claimed_planner_as_interrupted_and_publishes(
    config,
) -> None:
    store = TaskStore.create(config.db_path)
    item = _planner_signal(store, "restart-claimed")
    signal_id = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert signal_id is not None
    run_id = "planner-run-restart-claimed"
    store.control_loop.claim_planner_run(
        run_id,
        [signal_id],
        prompt={"signalIds": [signal_id]},
    )

    daemon = StewardDaemon(config, store)
    daemon._startup_reconcile_control_loop()

    recovered = store.control_loop.list_planner_runs()[-1]
    assert recovered.state == "interrupted"
    assert recovered.diagnostics["reason_code"] == "daemon_restart_interrupted_planner"
    assert store.control_loop.pending_retry("planner") is not None
    assert daemon._control_loop_archive.verify_planner_run(run_id)
    assert not store.control_loop.planning_blocked


def test_planner_retry_is_not_committed_before_failed_completion(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _planner_signal(store, "completion-failure")
    daemon = StewardDaemon(config, store)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args, **_kwargs: SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=False,
            exit_code=1,
            prompt_path=None,
            transcript_path=config.private_dir / "failed-completion.jsonl",
            thread_id=None,
        ),
    )
    monkeypatch.setattr(
        store,
        "commit_planner_decision",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("injected completion failure")
        ),
    )

    daemon._plan(TickResult(), [item])

    assert store.control_loop.pending_retry("planner") is None
    assert store.control_loop.list_planner_runs()[-1].state == "claimed"


def test_signal_shutdown_interrupts_active_planner_and_persists_interruption(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _planner_signal(store, "signal-interrupt")
    started = threading.Event()
    released = threading.Event()

    class BlockingPlannerSession(FreshPlannerSession):
        def __init__(self):
            self.interrupt_calls: list[bool] = []

        def interrupt(self, *, force=False):
            self.interrupt_calls.append(force)
            released.set()

    planner_session = BlockingPlannerSession()
    daemon = StewardDaemon(config, store, planner_session=planner_session)

    def blocked_planner(*_args, **_kwargs):
        started.set()
        released.wait(timeout=2)
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=False,
            exit_code=143,
            prompt_path=None,
            transcript_path=config.private_dir / "interrupted-planner.jsonl",
            thread_id=None,
            diagnostics={"interrupted": True},
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", blocked_planner
    )
    planning = threading.Thread(target=lambda: daemon._plan(TickResult(), [item]))
    planning.start()
    assert started.wait(timeout=1)

    daemon.request_shutdown_from_signal()
    planning.join(timeout=2)

    assert not planning.is_alive()
    assert planner_session.interrupt_calls == [False]
    completed = store.control_loop.list_planner_runs()[-1]
    assert completed.state == "interrupted"
    assert completed.diagnostics["reason_code"] == "planner_interrupted"
    assert store.control_loop.pending_retry("planner") is not None
    assert store.pending_signal_items(limit=10)[0].id == item.id


def test_shutdown_after_planner_claim_prevents_launch_and_preserves_signal(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _planner_signal(store, "claim-window-interrupt")

    class RecordingInvoker(LocalSessionInvoker):
        def __init__(self):
            super().__init__()
            self.requests: list[object] = []
            self.interrupt_calls: list[bool] = []

        def interrupt(self, *, force=False):
            self.interrupt_calls.append(force)

        def invoke(
            self,
            request,
            *,
            api_key,
            append,
            observe=None,
            on_started=None,
            timeout_seconds,
            interrupt_grace_seconds,
            launch_gate=None,
        ):
            self.requests.append(request)
            return InvocationOutcome(
                exit_code=0,
                stdout=b"",
                stderr=b"",
                incomplete_suffix=b"",
                events=(),
                provider_session_id=None,
            )

    invoker = RecordingInvoker()
    planner_session = FreshPlannerSession(config, invoker=invoker)
    daemon = StewardDaemon(config, store, planner_session=planner_session)

    def interrupt_after_claim(*args, **kwargs):
        assert daemon._active_planner_run_id == kwargs["run_id"]
        daemon.request_shutdown_from_signal()
        return execute_scheduler_planner(*args, **kwargs)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", interrupt_after_claim
    )

    daemon._plan(TickResult(), [item])

    assert invoker.interrupt_calls == [False]
    assert invoker.requests == []
    completed = store.control_loop.list_planner_runs()[-1]
    assert completed.state == "interrupted"
    assert completed.diagnostics["reason_code"] == "planner_interrupted"
    assert store.pending_signal_items(limit=10)[0].id == item.id


def test_control_loop_epoch_conflict_blocks_planning_without_aborting_preflight(
    config,
) -> None:
    store = TaskStore.create(config.db_path)
    task_epoch = config.ensure_epoch()
    config.control_loop_dir.mkdir(parents=True, exist_ok=True)
    (config.control_loop_dir / "epoch.json").write_text(
        json.dumps(
            {
                "epochId": "epoch-conflicting-control-loop",
                "formatVersion": "1.0",
                "taskFormatVersion": task_epoch["formatVersion"],
                "policy": task_epoch["policy"],
                "startedAt": task_epoch["startedAt"],
            }
        ),
        encoding="utf-8",
    )

    report = run_preflight(config, store, check_remote_push=False)

    assert "planning-blocked" in report.warnings
    assert store.control_loop.planning_blocked
    task, created = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="Task pipeline remains available",
            prompt="Run independently from control-loop planning.",
        )
    )
    assert created
    assert task.status == TaskStatus.queued


def test_startup_blocks_planning_when_required_archive_audit_errors(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(
        daemon,
        "_drain_control_loop_once",
        lambda **_kwargs: {
            "materialized": 0,
            "conflicts": 0,
            "error": "OSError",
            "auditIncomplete": True,
        },
    )

    daemon._startup_reconcile_control_loop()

    assert store.control_loop.planning_blocked
    task, created = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="Task pipeline remains available after audit failure",
            prompt="Run independently from control-loop planning.",
        )
    )
    assert created
    assert task.status == TaskStatus.queued


def test_control_loop_writer_waits_when_idle_and_preserves_drain_wakeup(
    monkeypatch,
) -> None:
    daemon = object.__new__(StewardDaemon)
    daemon._control_loop_stop = threading.Event()
    daemon._control_loop_wakeup = threading.Event()
    daemon._planner_publication_queue = {}
    drained = threading.Event()
    calls: list[int] = []

    def drain() -> dict[str, object]:
        calls.append(len(calls) + 1)
        if len(calls) == 1:
            drained.set()
        elif len(calls) == 2:
            # This models a ledger mutation racing with the archive drain.
            daemon._control_loop_wakeup.set()
        else:
            daemon._control_loop_stop.set()
        return {"pending": False, "conflicts": 0}

    monkeypatch.setattr(daemon, "_drain_control_loop_once", drain)
    writer = threading.Thread(target=daemon._control_loop_writer_loop, daemon=True)
    writer.start()
    assert drained.wait(timeout=1)
    assert calls == [1]
    daemon._control_loop_wakeup.set()
    writer.join(timeout=1)

    assert not writer.is_alive()
    assert calls == [1, 2, 3]


def test_locked_daemon_routes_scheduler_planning_through_fresh_boundary(
    config, monkeypatch
) -> None:
    configured = replace(
        config,
        local_codex_test_harness=False,
        task_image_digest=IMAGE,
    )
    store = TaskStore.create(configured.db_path)
    item = _planner_signal(store, "isolated-boundary")
    seen: list[object] = []

    def fake_run_planner(_config, _signals, _active, **kwargs):
        seen.append(kwargs.get("invocation"))
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=configured.private_dir / "missing-planner.jsonl",
            thread_id=None,
            consumed_item_ids=[item.id],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", fake_run_planner
    )
    daemon = StewardDaemon(configured, store)
    daemon.startup_reconcile()
    daemon._plan(TickResult(), [item])

    assert isinstance(daemon.planner_session, FreshPlannerSession)
    assert seen == [daemon.planner_session]
    assert store.list_tasks() == []


def _interrupted_run(config, store, *, role="implementation", checkpoint=None):
    task, pipeline = _task(store, role)
    action = f"{task.id}:{pipeline.id}:implementation-0"
    checkpoint_id = checkpoint or worktree_checkpoint(config, config.repo_root)
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "implementation",
        {
            "pipeline_id": pipeline.id,
            "phase": "implementation",
            "action_id": action,
            "input": {"payload": {"iteration": 0}},
        },
    )
    private_home = config.private_sessions_dir / task.id / "session-original"
    session, run = store.create_session_with_run(
        task.id,
        pipeline.id,
        session_id="session-original",
        private_home_path=private_home,
        private_home_relative_path=f"{task.id}/session-original",
        image_digest=IMAGE,
        codex_identity="codex-test",
        cwd=config.repo_root,
        checkpoint_id=checkpoint_id,
        provider_store_identity="codex-sessions-v1",
        owner_role=role,
        session_idempotency_key=action,
        role=role,
        model=None,
        reasoning=None,
        image_version=IMAGE,
        runtime_version="task-runtime-v1",
        run_checkpoint_id=checkpoint_id,
        run_provider_store_identity="codex-sessions-v1",
    )
    private_home.mkdir(parents=True, exist_ok=True)
    (private_home / "sessions").mkdir()
    (private_home / "sessions" / "provider.json").write_text(
        "{}\n", encoding="utf-8"
    )
    store.update_session(session.id, provider_session_id="private-provider-id")
    store.mark_run_interrupted(run.id, reason="test interruption")
    return task, pipeline, store.get_run(run.id)


def test_session_completion_ownership_loss_propagates_without_evidence(config):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "completion ownership loss")

    session_before_loss = []

    class ClearingInvoker(LocalSessionInvoker):
        def invoke(
            self,
            request,
            *,
            api_key,
            append,
            observe,
            on_started,
            timeout_seconds,
            interrupt_grace_seconds,
            launch_gate=None,
        ):
            on_started(
                ExecIdentity(
                    "fake",
                    request.run_id,
                    4321,
                    request.session_uid,
                )
            )
            session_before_loss.append(store.get_session(request.session_id))
            with store.engine.begin() as connection:
                connection.exec_driver_sql(
                    "UPDATE task_executions "
                    "SET owning_pipeline_id = NULL, active_session_id = NULL, "
                    "active_run_id = NULL WHERE task_id = ?",
                    (task.id,),
                )
            return InvocationOutcome(
                exit_code=0,
                stdout=b"",
                stderr=b"",
                incomplete_suffix=b"",
                events=(),
                provider_session_id="provider-after-loss",
            )

    supervisor = SessionSupervisor(
        config,
        store,
        invoker=ClearingInvoker(),
        image_digest=IMAGE,
    )

    with pytest.raises(TaskLedgerOwnershipError, match="owning pipeline"):
        supervisor.start(
            task.id,
            pipeline.id,
            role="implementation",
            prompt="complete",
            cwd=config.repo_root,
        )

    run = store.list_runs(task.id)[0]
    assert run.state == "running"
    assert session_before_loss
    assert store.get_session(session_before_loss[0].id) == session_before_loss[0]
    assert not (
        config.tasks_dir
        / task.id
        / "pipelines"
        / pipeline.id
        / "runs"
        / run.id
        / "result.json"
    ).exists()


def test_session_start_validates_ownership_before_runtime_factory(config):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "start ownership preflight")
    execution = store.get_execution(task.id)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_executions SET owning_pipeline_id = NULL WHERE id = ?",
            (execution.id,),
        )

    factory_calls = []
    marker = config.private_dir / "runtime-factory-called"

    def factory(record):
        factory_calls.append(record.id)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("created\n", encoding="utf-8")
        return SimpleNamespace()

    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=factory,
        image_digest=IMAGE,
    )

    with pytest.raises(TaskLedgerOwnershipError, match="owning pipeline"):
        supervisor.start(
            task.id,
            pipeline.id,
            role="implementation",
            prompt="start",
            cwd=config.repo_root,
        )

    assert factory_calls == []
    assert not marker.exists()
    assert store.list_sessions(task.id) == []
    assert store.list_runs(task.id) == []


class FakeSupervisor(SessionSupervisor):
    def __init__(self, config, store, *, live=False, resume=ResumeCategory.success):
        self.config = config
        self.store = store
        self.live = live
        self.resume_category = resume
        self.calls = []
        self.remove_failures = 0

    def reconcile_container(self, task_id, *, ensure_running=True):
        self.calls.append(("reconcile-container", task_id, ensure_running))
        return SimpleNamespace(container_id=f"container-{task_id}", running=True)

    def inspect(self, run_id):
        self.calls.append(("inspect", run_id))
        return SimpleNamespace(
            live=self.live,
            container=SimpleNamespace(container_id="container-test"),
        )

    def build_recovery_packet(self, run_id):
        return SimpleNamespace(prompt=lambda: '{"recovery":"bounded"}')

    def resume_with_retries(self, run_id, **kwargs):
        self.calls.append(("resume", run_id, kwargs["max_attempts"]))
        if self.resume_category is not ResumeCategory.success:
            return ResumeResult(self.resume_category)
        predecessor = self.store.get_run(run_id)
        resumed = self.store.create_run(
            predecessor.task_id,
            predecessor.pipeline_id,
            predecessor.session_id,
            role=predecessor.role,
            resume_of_run_id=predecessor.id,
            image_version=predecessor.image_version,
            runtime_version=predecessor.runtime_version,
            checkpoint_id=predecessor.checkpoint_id,
            provider_store_identity=predecessor.provider_store_identity,
        )
        return ResumeResult(
            ResumeCategory.success,
            result=self._complete(resumed),
        )

    def recover(self, run_id, **_kwargs):
        self.calls.append(("recover", run_id))
        predecessor = self.store.get_run(run_id)
        session = self.store.create_session(
            predecessor.task_id,
            predecessor.pipeline_id,
            private_home_path=(
                self.config.private_sessions_dir
                / predecessor.task_id
                / "session-recovery"
            ),
            private_home_relative_path=(
                f"{predecessor.task_id}/session-recovery"
            ),
            image_digest=predecessor.image_version,
            codex_identity="codex-test",
            cwd=self.config.repo_root,
            checkpoint_id=predecessor.checkpoint_id,
            provider_store_identity="codex-sessions-v1",
            owner_role=predecessor.role,
            idempotency_key=f"fresh-recovery:{predecessor.id}",
        )
        recovered = self.store.create_run(
            predecessor.task_id,
            predecessor.pipeline_id,
            session.id,
            role=predecessor.role,
            retry_of_run_id=predecessor.id,
            image_version=predecessor.image_version,
            runtime_version=predecessor.runtime_version,
            checkpoint_id=predecessor.checkpoint_id,
            provider_store_identity=predecessor.provider_store_identity,
        )
        return ResumeResult(
            ResumeCategory.success,
            result=self._complete(recovered),
            evidence={"recovery": True},
        )

    def _complete(self, run):
        self.store.transition_run(
            run.id,
            CodexRunState.succeeded.value,
            expected_state=CodexRunState.running.value,
            exit_code=0,
            result_summary="completed",
        )
        run_dir = (
            self.config.tasks_dir
            / run.task_id
            / "pipelines"
            / run.pipeline_id
            / "runs"
            / run.id
        )
        run_dir.mkdir(parents=True, exist_ok=True)
        transcript = run_dir / "codex.jsonl"
        last_message = run_dir / "last-message.md"
        transcript.write_text("{}\n", encoding="utf-8")
        last_message.write_text("done\n", encoding="utf-8")
        return SessionResult(
            run.task_id,
            run.pipeline_id,
            run.session_id,
            run.id,
            InvocationStatus.succeeded,
            0,
            None,
            transcript,
            last_message,
        )

    def interrupt(self, run_id, **kwargs):
        self.calls.append(("interrupt", run_id, kwargs["force"]))
        try:
            self.store.mark_run_interrupted(run_id, reason="daemon shutdown")
        except ValueError:
            pass

    def stop_container(self, task_id, **_kwargs):
        self.calls.append(("stop", task_id))

    def remove_container(self, task_id):
        self.calls.append(("remove", task_id))
        if self.remove_failures:
            self.remove_failures -= 1
            raise RuntimeError("injected remove failure")


def test_persisted_push_reconciliation_authenticates_fetch_only(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    task = SimpleNamespace(id="persisted-task")
    commit = "a" * 40
    events = [
        SimpleNamespace(
            kind="pipeline.commit", data={"commit": commit, "tree": "tree-id"}
        ),
        SimpleNamespace(kind="pipeline.push", data={"commit": commit}),
    ]
    monkeypatch.setattr(store, "events", lambda _task_id: events)
    monkeypatch.setattr(
        store, "task_execution_mode", lambda _task_id: ExecutionMode.live
    )
    commands: list[tuple[list[str], dict[str, str] | None]] = []
    ssh_command = "ssh -i /tmp/strict-ssh"

    def fake_run_command(command, cwd, *, env=None, **_kwargs):
        commands.append((command, env))
        stdout = "tree-id\n" if command[1:2] == ["rev-parse"] else ""
        return SimpleNamespace(ok=True, stdout=stdout)

    monkeypatch.setattr(
        daemon_module,
        "git_remote_environment",
        lambda _config: {
            "GIT_SSH_COMMAND": ssh_command,
            "GCM_INTERACTIVE": "never",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    monkeypatch.setattr(daemon_module, "run_command", fake_run_command)

    assert daemon._reconcile_commit_and_remote(task, config.repo_root) is None

    fetch_env = next(
        env for command, env in commands if command[:2] == ["git", "fetch"]
    )
    assert fetch_env == {
        "GIT_SSH_COMMAND": ssh_command,
        "GCM_INTERACTIVE": "never",
        "GIT_TERMINAL_PROMPT": "0",
    }
    assert [
        env
        for command, env in commands
        if command[:2] in (["git", "cat-file"], ["git", "rev-parse"], ["git", "merge-base"])
    ] == [None, None, None]


def test_config_preflight_launch_has_epoch_and_bounded_no_init_status(config):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)

    assert daemon.preflight_report is None
    assert store.get_daemon_state() is None
    daemon.startup_reconcile()

    assert daemon.preflight_report is not None
    assert "epoch" in daemon.preflight_report.checks
    assert "private" not in daemon.preflight_report.summary
    assert store.get_daemon_state()["lifecycle"] == "running"
    assert config.epoch_path.exists()


def test_daemon_construction_does_not_run_startup_effects(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    for name in (
        "get_resource_pressure",
        "claim_daemon_instance",
        "recover",
    ):
        monkeypatch.setattr(
            store,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"{_name} must not run during construction"
            ),
        )
    monkeypatch.setattr(
        daemon_module,
        "run_preflight",
        lambda *_args, **_kwargs: pytest.fail("preflight must not run during construction"),
    )
    monkeypatch.setattr(
        daemon_module,
        "preflight_remote_push",
        lambda *_args, **_kwargs: pytest.fail(
            "remote preflight must not run during construction"
        ),
    )

    daemon = StewardDaemon(config, store)

    assert daemon.preflight_report is None
    assert store.get_daemon_state() is None


def test_startup_execution_mode_is_resolved_once_per_construction(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    calls: list[bool] = []
    original = store.set_startup_execution_mode

    def record(dry_run: bool) -> None:
        calls.append(dry_run)
        original(dry_run)

    monkeypatch.setattr(store, "set_startup_execution_mode", record)

    StewardExecutor(config, store, runner=SimpleNamespace())
    assert calls == [config.dry_run]

    calls.clear()
    StewardDaemon(config, store)
    assert calls == [config.dry_run]


def test_startup_orders_validation_recovery_reconciliation_claim_and_running(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    events: list[str] = []
    monkeypatch.setattr(
        daemon_module,
        "run_preflight",
        lambda *_args, **_kwargs: events.append("validation")
        or daemon_module.PreflightReport(),
    )
    monkeypatch.setattr(
        store,
        "recover",
        lambda: events.append("store") or SimpleNamespace(),
    )
    monkeypatch.setattr(
        daemon,
        "_startup_reconcile_control_loop",
        lambda: events.append("archive"),
    )
    monkeypatch.setattr(
        daemon.executor,
        "retry_validation_cleanup_pending",
        lambda: None,
    )
    monkeypatch.setattr(daemon, "_reconcile_docker_resources", lambda: None)
    monkeypatch.setattr(
        store,
        "iter_tasks",
        lambda: events.append("tasks") or [],
    )
    authority_requests: list[str | None] = []
    monkeypatch.setattr(
        store,
        "get_daemon_publication_authority",
        lambda *, instance_id=None: authority_requests.append(instance_id) or None,
    )
    monkeypatch.setattr(
        daemon,
        "_restore_resource_pressure",
        lambda: None,
    )
    monkeypatch.setattr(
        store,
        "claim_daemon_instance",
        lambda *_args, **_kwargs: events.append("claim") or {},
    )
    monkeypatch.setattr(
        store,
        "set_daemon_lifecycle",
        lambda lifecycle, **_kwargs: events.append(lifecycle) or {},
    )
    monkeypatch.setattr(daemon, "_enqueue_materialized_publications", lambda: None)
    monkeypatch.setattr(daemon, "_start_publication_worker", lambda: None)

    daemon.startup_reconcile()

    assert events == ["validation", "store", "archive", "tasks", "claim", "running"]
    assert authority_requests == [daemon.runtime.instance_id]
    assert daemon.lifecycle_state is DaemonLifecycleState.running


def test_startup_failure_before_claim_clears_existing_claim(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    store.claim_daemon_instance(
        "previous-daemon", lifecycle=DaemonLifecycleState.running.value
    )
    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(
        daemon_module, "run_preflight", lambda *_args, **_kwargs: daemon_module.PreflightReport()
    )
    monkeypatch.setattr(
        store,
        "recover",
        lambda: (_ for _ in ()).throw(RuntimeError("recovery failed")),
    )

    with pytest.raises(RuntimeError, match="recovery failed"):
        daemon.startup_reconcile()

    state = store.get_daemon_state()
    assert state["instance_id"] == "previous-daemon"
    assert state["lifecycle"] == DaemonLifecycleState.stopped.value
    assert state["startup_failed"] is True
    assert daemon.lifecycle_state is DaemonLifecycleState.stopped


def test_startup_failure_after_claim_clears_running_claim(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    original_set_lifecycle = store.set_daemon_lifecycle
    monkeypatch.setattr(
        daemon_module, "run_preflight", lambda *_args, **_kwargs: daemon_module.PreflightReport()
    )
    monkeypatch.setattr(store, "recover", lambda: SimpleNamespace())
    monkeypatch.setattr(daemon, "_restore_resource_pressure", lambda: None)
    monkeypatch.setattr(daemon, "_startup_reconcile_control_loop", lambda: None)
    monkeypatch.setattr(daemon.executor, "retry_validation_cleanup_pending", lambda: None)
    monkeypatch.setattr(daemon, "_reconcile_docker_resources", lambda: None)
    monkeypatch.setattr(store, "iter_tasks", lambda: [])

    def fail_running(lifecycle, **kwargs):
        if lifecycle == DaemonLifecycleState.running.value:
            raise RuntimeError("running publication failed")
        return original_set_lifecycle(lifecycle, **kwargs)

    monkeypatch.setattr(store, "set_daemon_lifecycle", fail_running)
    with pytest.raises(RuntimeError, match="running publication"):
        daemon.startup_reconcile()

    assert store.get_daemon_state()["lifecycle"] != DaemonLifecycleState.running.value


def test_startup_claim_callback_failure_clears_starting_claim(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(
        daemon_module, "run_preflight", lambda *_args, **_kwargs: daemon_module.PreflightReport()
    )
    monkeypatch.setattr(store, "recover", lambda: SimpleNamespace())
    monkeypatch.setattr(daemon, "_restore_resource_pressure", lambda: None)
    monkeypatch.setattr(daemon, "_startup_reconcile_control_loop", lambda: None)
    monkeypatch.setattr(daemon.executor, "retry_validation_cleanup_pending", lambda: None)
    monkeypatch.setattr(daemon, "_reconcile_docker_resources", lambda: None)
    monkeypatch.setattr(store, "iter_tasks", lambda: [])

    callbacks = 0

    def fail_claim_notification():
        nonlocal callbacks
        callbacks += 1
        if callbacks == 1:
            raise RuntimeError("claim notification failed")

    store.on_change = fail_claim_notification
    with pytest.raises(RuntimeError, match="claim notification failed"):
        daemon.startup_reconcile()

    state = store.get_daemon_state()
    assert callbacks == 2
    assert state["instance_id"] == daemon.runtime.instance_id
    assert state["lifecycle"] == DaemonLifecycleState.stopped.value
    assert state["startup_failed"] is True
    assert daemon.lifecycle_state is DaemonLifecycleState.stopped


def test_daemon_rejects_unsupported_collaborators(config):
    with pytest.raises(TypeError, match="SQLiteTaskStore"):
        StewardDaemon(config, object())

    store = TaskStore.create(config.db_path)
    with pytest.raises(TypeError, match="SessionSupervisor"):
        StewardDaemon(config, store, session_supervisor=object())
    with pytest.raises(TypeError, match="FreshPlannerSession"):
        StewardDaemon(config, store, planner_session=object())


def _task_image_labels(*, runtime_protocol="task-container-v1"):
    return {
        "org.opencontainers.image.source-revision": "a" * 32,
        "coquic.steward.runtime-protocol": runtime_protocol,
        "coquic.steward.codex-version": "0.144.6",
        "coquic.steward.closure": "b" * 32,
    }


def test_preflight_rejects_unrelated_task_image_metadata(config, monkeypatch):
    key = config.coquic_home / "codex-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    docker = config.coquic_home / "bin" / "docker"
    docker.parent.mkdir()
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    container = StewardContainerConfig(
        enabled=True,
        image_digest=IMAGE,
        repository_host_path=config.repo_root,
        state_host_path=config.coquic_home,
        codex_api_key_path=key,
        docker_bin=str(docker),
    )
    nested = StewardConfig(
        repo_root=config.repo_root,
        container=container,
        local_codex_test_harness=True,
    )

    def command(args, **_kwargs):
        stdout = (
            json.dumps([{"Config": {"Labels": {"unrelated": "image"}}}])
            if args[1:3] == ["image", "inspect"]
            else ""
        )
        return SimpleNamespace(ok=True, stdout=stdout)

    monkeypatch.setattr(
        "coquic_steward.orchestration.preflight.run_command", command
    )

    with pytest.raises(StewardPreflightError, match="task image identity"):
        run_preflight(nested, check_remote_push=False)


def test_preflight_rejects_unlocked_docker(config, monkeypatch):
    key = config.coquic_home / "codex-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    container = StewardContainerConfig(
        enabled=True,
        image_digest=IMAGE,
        repository_host_path=config.repo_root,
        state_host_path=config.coquic_home,
        codex_api_key_path=key,
        docker_bin="/bin/true",
    )
    nested = StewardConfig(
        repo_root=config.repo_root,
        container=container,
        local_codex_test_harness=True,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.preflight.run_command",
        lambda *_args, **_kwargs: SimpleNamespace(
            ok=True,
            stdout=json.dumps(
                [{"Config": {"Labels": _task_image_labels()}}]
            ),
        ),
    )

    with pytest.raises(StewardPreflightError, match="Docker executable identity"):
        run_preflight(nested, check_remote_push=False)


def test_startup_reconcile_orders_task_identity_before_dispatch(config):
    store = TaskStore.create(config.db_path)
    second, _ = _task(store, "z-second")
    first, _ = _task(store, "a-first")
    daemon = StewardDaemon(config, store)

    outcomes = daemon.startup_reconcile()

    assert [item.task_id for item in outcomes] == sorted([first.id, second.id])
    assert daemon.runtime.reconciliation_complete


def test_reconcile_blocks_missing_pipeline_owner_without_finalization(config):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "missing owner")
    execution = store.get_execution(task.id)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_executions SET owning_pipeline_id = NULL WHERE id = ?",
            (execution.id,),
        )
    events_before = store.events(task.id)
    daemon = StewardDaemon(config, store, session_supervisor=None)

    outcome = daemon._reconcile_task(task)

    assert outcome.disposition == "blocked"
    assert "ownership" in outcome.detail
    assert store.get(task.id).status == TaskStatus.queued
    assert store.events(task.id) == events_before
    assert store.get_pipeline(pipeline.id).id == pipeline.id


def test_startup_reconciles_oldest_active_run_after_detached_pages(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    oldest, pipeline = _task(store, "oldest active")
    store.start_worker(oldest.id, "running")
    session = store.create_session(oldest.id, pipeline.id)
    run = store.create_run(oldest.id, pipeline.id, session.id, role="implementation")
    for index in range(4):
        newer, _ = _task(store, f"newer terminal {index}")
        store.finish_task(newer.id, TaskStatus.succeeded, "terminal")

    page_calls = _force_task_pages(monkeypatch, store)
    daemon = StewardDaemon(config, store, session_supervisor=None)
    reconciled: list[str] = []
    original = daemon._reconcile_task

    def reconcile(task):
        assert not getattr(store, "_task_page_active", False)
        reconciled.append(task.id)
        return original(task)

    monkeypatch.setattr(daemon, "_reconcile_task", reconcile)

    daemon.startup_reconcile()

    assert len(page_calls) >= 3
    assert oldest.id in reconciled
    assert store.get_run(run.id).state != CodexRunState.running.value


def test_publication_recovery_enqueues_oldest_run_after_detached_pages(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    oldest, pipeline = _task(store, "oldest publication")
    session = store.create_session(oldest.id, pipeline.id)
    run = store.create_run(oldest.id, pipeline.id, session.id, role="implementation")
    for index in range(4):
        _task(store, f"newer publication {index}")
    page_calls = _force_task_pages(monkeypatch, store)
    queued: list[tuple[str, str]] = []

    def enqueue(_config, _store, task, materialized_run):
        assert not getattr(store, "_task_page_active", False)
        queued.append((task.id, materialized_run.id))

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.enqueue_materialized_publication",
        enqueue,
    )
    daemon = object.__new__(StewardDaemon)
    daemon.store = store
    daemon.config = SimpleNamespace(
        dry_run=False,
        publication=SimpleNamespace(enabled=True),
    )

    daemon._enqueue_materialized_publications()

    assert len(page_calls) >= 3
    assert queued == [(oldest.id, run.id)]


@pytest.mark.parametrize("opening_kind", ["cleanup_pending", "cleanup_retryable"])
def test_cleanup_retry_uses_complete_obligation_predicate(
    config, monkeypatch, opening_kind
):
    store = TaskStore.create(config.db_path)
    oldest, _ = _task(store, "oldest cleanup")
    store.finish_task(oldest.id, TaskStatus.failed, "terminal")
    store.add_event(oldest.id, opening_kind, "retry")
    completed, _ = _task(store, "completed cleanup")
    store.finish_task(completed.id, TaskStatus.failed, "terminal")
    store.add_event(completed.id, opening_kind, "completed retry")
    store.add_event(completed.id, "cleanup_complete", "complete")
    for index in range(4):
        newer, _ = _task(store, f"newer cleanup {index}")
        store.finish_task(newer.id, TaskStatus.failed, "terminal")
    monkeypatch.setattr(
        store,
        "list_tasks",
        lambda **_kwargs: pytest.fail("cleanup retry used a capped task listing"),
    )
    daemon = object.__new__(StewardDaemon)
    daemon.store = store
    daemon.executor = SimpleNamespace(retry_validation_cleanup_pending=lambda: None)
    finalized: list[str] = []

    def finalize(task_id):
        assert not getattr(store, "_cleanup_query_active", False)
        finalized.append(task_id)
        return True

    def pending_tasks():
        store._cleanup_query_active = True
        try:
            return TaskStore.cleanup_pending_tasks(store)
        finally:
            store._cleanup_query_active = False

    monkeypatch.setattr(store, "cleanup_pending_tasks", pending_tasks)
    daemon.finalize_terminal_task = finalize

    daemon._retry_cleanup_pending_tasks()

    assert finalized == [oldest.id]


def test_reconcile_retries_retryable_terminal_cleanup(config):
    store = TaskStore.create(config.db_path)
    task, _ = _task(store, "retryable cleanup")
    task = store.finish_task(task.id, TaskStatus.failed, "terminal")
    store.add_event(
        task.id,
        "cleanup_retryable",
        "container stop incomplete",
        {"step": "container-stop", "error": "TimeoutError"},
    )
    daemon = StewardDaemon(config, store, session_supervisor=None)
    finalized: list[str] = []

    def finalize(task_id):
        finalized.append(task_id)
        return True

    daemon.finalize_terminal_task = finalize

    outcome = daemon._reconcile_task(task)

    assert finalized == [task.id]
    assert outcome.disposition == "cleaned"
    assert outcome.detail == "pending terminal cleanup converged"


def test_shutdown_interrupts_oldest_running_run_from_direct_query(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    oldest, pipeline = _task(store, "oldest running")
    session = store.create_session(oldest.id, pipeline.id)
    run = store.create_run(oldest.id, pipeline.id, session.id, role="implementation")
    for index in range(4):
        _task(store, f"newer running {index}")
    page_calls = _force_task_pages(monkeypatch, store)
    original_running = store.running_runs

    def running_runs(**kwargs):
        store._running_query_active = True
        try:
            return original_running(**kwargs)
        finally:
            store._running_query_active = False

    monkeypatch.setattr(store, "running_runs", running_runs)

    class Supervisor(SessionSupervisor):
        def __init__(self):
            self.interrupted: list[str] = []
            self.stopped: list[str] = []

        def interrupt(self, run_id, **_kwargs):
            assert not getattr(store, "_running_query_active", False)
            self.interrupted.append(run_id)
            store.mark_run_interrupted(run_id, reason="shutdown test")

        def stop_container(self, task_id, **_kwargs):
            assert not getattr(store, "_task_page_active", False)
            self.stopped.append(task_id)
            return True

    supervisor = Supervisor()
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert len(page_calls) >= 3
    assert result.interrupted_runs == 1
    assert supervisor.interrupted
    assert set(supervisor.interrupted) == {run.id}
    assert set(supervisor.stopped) == {task.id for task in store.list_tasks()}


def test_reconcile_adopts_matching_live_wrapper_without_duplicate(config):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    store.restart_run = lambda *_args, **_kwargs: None
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?",
            (run.id,),
        )
    supervisor = FakeSupervisor(config, store, live=True)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    outcome = daemon.startup_reconcile()[0]
    daemon.run_cycle(plan=False, dispatch=False)

    assert outcome.disposition == "adopted"
    assert not any(call[0] == "resume" for call in supervisor.calls)
    assert store.get_run(run.id).state == "running"
    assert outcome.task_id == task.id
    assert sum(call[0] == "inspect" for call in supervisor.calls) == 2


def test_complete_atomic_result_is_ingested_once(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    task.worktree_path = config.repo_root
    store.save(task)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?",
            (run.id,),
        )
    archive = TaskArchiveWriter(config)
    pipeline = store.get_pipeline(run.pipeline_id)
    archive.materialize_ledger(task, pipeline, [store.get_run(run.id)])
    archive.write_run_file(task.id, pipeline.id, run.id, "last-message.md", "done\n")
    archive.write_run_file(
        task.id,
        pipeline.id,
        run.id,
        "result.json",
        {"status": "available", "summary": "complete", "path": None,
         "task_id": task.id, "pipeline_id": pipeline.id, "session_id": run.session_id,
         "run_id": run.id, "output_checkpoint": worktree_checkpoint(config, config.repo_root)},
    )
    archive.write_run_file(task.id, pipeline.id, run.id, "codex.jsonl", "{}\n")
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    ingested = []
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda predecessor, result: (
            ingested.append((predecessor, result.run_id))
            or SimpleNamespace(status="ingested")
        ),
    )

    first = daemon.startup_reconcile()[0]
    second = daemon.startup_reconcile()[0]

    assert first.disposition == "ingested"
    assert second.disposition == "ingested"
    assert ingested == [(run.id, run.id)]
    assert store.get_run(run.id).state == "succeeded"


def test_exact_id_resume_is_wired_and_persisted_without_private_identity(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda *_: SimpleNamespace(status="ingested"),
    )

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "resumed"
    assert ("resume", run.id, 2) in supervisor.calls
    decisions = [
        event
        for event in store.events(task.id)
        if event.kind == "session.recovery.decision"
    ]
    assert decisions[-1].data["decision"] == "resume"
    assert "private-provider-id" not in json.dumps(decisions[-1].data)


def test_shutdown_interrupts_blocking_startup_resume(config):
    store = TaskStore.create(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)

    class BlockingSupervisor(FakeSupervisor):
        def __init__(self, config, store):
            super().__init__(config, store)
            self.resume_started = threading.Event()
            self.release_resume = threading.Event()

        def resume_with_retries(self, run_id, **_kwargs):
            self.resume_started.set()
            self.release_resume.wait(timeout=2)
            return ResumeResult(ResumeCategory.unavailable_store)

        def interrupt(self, run_id, **kwargs):
            self.calls.append(("interrupt", run_id, kwargs["force"]))
            self.release_resume.set()

    supervisor = BlockingSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    outcomes = []
    recovery = threading.Thread(
        target=lambda: outcomes.append(
            daemon._resume_or_recover(task, predecessor, store.list_runs(task.id))
        )
    )
    recovery.start()
    assert supervisor.resume_started.wait(timeout=1)

    daemon.request_shutdown(force=True)
    recovery.join(timeout=1)
    still_blocking = recovery.is_alive()
    supervisor.release_resume.set()
    recovery.join(timeout=2)

    assert still_blocking is False
    assert ("interrupt", predecessor.id, True) in supervisor.calls
    assert outcomes and outcomes[0].disposition == "interrupted"


def test_corrupt_resume_falls_back_to_fresh_recovery_packet(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = FakeSupervisor(
        config,
        store,
        resume=ResumeCategory.corrupt_store,
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda *_: SimpleNamespace(status="ingested"),
    )

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "resumed"
    assert any(call[0] == "recover" for call in supervisor.calls)
    recovery = next(
        event
        for event in reversed(store.events(task.id))
        if event.kind == "session.recovery.decision"
        and event.data.get("decision") == "fresh-recovery"
    )
    assert recovery.data["resume_category"] == "corrupt-store"
    assert store.get_run(outcome.run_id).retry_of_run_id == run.id


def test_recovery_ownership_preflight_preserves_archive_evidence(config):
    store = TaskStore.create(config.db_path)
    task, pipeline, predecessor = _interrupted_run(config, store)
    (config.repo_root / "README.md").write_text(
        "changed before recovery\n", encoding="utf-8"
    )
    execution = store.get_execution(task.id)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_executions SET owning_pipeline_id = NULL, "
            "active_session_id = NULL, active_run_id = NULL WHERE id = ?",
            (execution.id,),
        )

    supervisor = SessionSupervisor(
        config,
        store,
        invoker=LocalSessionInvoker(),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    recovery_path = (
        config.tasks_dir
        / task.id
        / "pipelines"
        / pipeline.id
        / "runs"
        / predecessor.id
        / "recovery"
        / "current.diff"
    )

    with pytest.raises(TaskLedgerOwnershipError, match="owning pipeline"):
        supervisor.recover(predecessor.id, cwd=config.repo_root)

    assert not recovery_path.exists()


def test_fresh_recovery_lineage_is_durable_before_process_returns(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=LocalSessionInvoker(),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    allocated = []

    def prepare_home(session):
        assert session.private_home_path is not None
        session.private_home_path.mkdir(parents=True, exist_ok=True)

    def crash_before_process_returns(_task, _session, run, _request, **_kwargs):
        allocated.append(store.get_run(run.id))
        raise KeyboardInterrupt

    monkeypatch.setattr(supervisor, "_prepare_home", prepare_home)
    monkeypatch.setattr(supervisor, "_execute", crash_before_process_returns)

    with pytest.raises(KeyboardInterrupt):
        supervisor.recover(predecessor.id, cwd=config.repo_root)

    assert len(allocated) == 1
    recovery = allocated[0]
    assert recovery.retry_of_run_id == predecessor.id
    store.mark_run_interrupted(recovery.id, reason="daemon crashed during recovery")
    runs = store.list_runs(task.id)
    root = StewardDaemon._interrupted_recovery_root(runs)
    assert root is not None and root.id == predecessor.id

    daemon = StewardDaemon(
        config,
        store,
        session_supervisor=FakeSupervisor(config, store),
    )
    outcome = daemon._resume_or_recover(task, root, runs)

    assert outcome.disposition == "blocked"
    assert outcome.run_id == recovery.id
    assert outcome.detail == "fresh recovery was interrupted; evidence is preserved"


def test_checkpoint_identity_conflict_blocks_without_resume(config):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    store.update_session(run.session_id, checkpoint_id="different-checkpoint")
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "blocked"
    assert "checkpoint" in outcome.detail
    assert not any(call[0] in {"resume", "recover"} for call in supervisor.calls)
    assert store.get(task.id).status != TaskStatus.failed


def test_resume_rejects_worktree_mutation_after_interruption(config):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=LocalSessionInvoker(),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    checkpoint = run.checkpoint_id
    assert checkpoint is not None
    tracked = config.repo_root / "README.md"
    tracked.write_text("changed after interruption\n", encoding="utf-8")

    resumed = supervisor.resume(
        run.id,
        prompt="continue",
        cwd=config.repo_root,
        checkpoint_id=checkpoint,
    )

    assert resumed.category is ResumeCategory.checkpoint_drift
    assert len(store.list_runs(task.id)) == 1


def test_commit_and_remote_ancestry_identity_conflict_blocks(config):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "commit identity")
    task.worktree_path = config.repo_root
    store.save(task)
    store.add_event(
        task.id,
        "pipeline.commit",
        "missing commit",
        {"pipeline_id": pipeline.id, "commit": "f" * 40},
    )
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "blocked"
    assert "commit" in outcome.detail


def test_validation_crash_releases_exact_phase_claim_for_deterministic_rerun(
    config,
):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "validation crash")
    action = f"{task.id}:{pipeline.id}:validation"
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "validation",
        {
            "pipeline_id": pipeline.id,
            "phase": "validation",
            "action_id": action,
            "input": {"payload": {}},
        },
    )
    daemon = StewardDaemon(config, store)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "interrupted"
    assert "released" in outcome.detail
    assert daemon.executor._in_progress_action(
        task.id,
        pipeline.id,
        PipelineCursorPhase.validation,
    ) is None
    assert any(
        event.kind == "pipeline.phase.interrupted"
        and event.data.get("action_id") == action
        for event in store.events(task.id)
    )


def test_commit_crash_adopts_exact_tree_once_before_manifest(config):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "commit crash")
    task.worktree_path = config.repo_root
    store.save(task)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_pipelines SET base_identity = ? WHERE id = ?",
            (head, pipeline.id),
        )
        connection.exec_driver_sql(
            "UPDATE task_executions SET base_commit = ?, worktree_path = ? WHERE task_id = ?",
            (head, str(config.repo_root), task.id),
        )
    action = f"{task.id}:{pipeline.id}:commit"
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "commit",
        {
            "pipeline_id": pipeline.id,
            "phase": "commit",
            "action_id": action,
            "input": {"payload": {"expected_tree": tree}},
        },
    )
    daemon = StewardDaemon(config, store)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "ingested"
    assert store.get(task.id).status == TaskStatus.no_changes
    finishes = [
        event
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("action_id") == action
    ]
    assert len(finishes) == 1


def test_worker_pool_capacity_max_dispatch_and_heartbeat_remain_responsive(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    _task(store, "pool one")
    _task(store, "pool two")
    snapshot_calls = []
    original_snapshot = store.dispatch_snapshot

    def snapshot(**kwargs):
        snapshot_calls.append(kwargs)
        return original_snapshot(**kwargs)

    monkeypatch.setattr(store, "dispatch_snapshot", snapshot)
    monkeypatch.setattr(
        store,
        "queued_tasks",
        lambda **_kwargs: pytest.fail("pool dispatch used a legacy queue read"),
    )
    monkeypatch.setattr(
        store,
        "iter_tasks",
        lambda **_kwargs: pytest.fail("pool dispatch used a legacy resumable read"),
    )
    monkeypatch.setattr(
        store,
        "source_active_count",
        lambda: pytest.fail("pool dispatch used a legacy source count"),
    )
    daemon = StewardDaemon(config, store)
    release = threading.Event()
    started = threading.Event()

    def worker(_task_id):
        started.set()
        release.wait(2)
        return True

    daemon._run_task_worker = worker
    pool = ThreadPoolExecutor(max_workers=2)
    result = TickResult()
    before = time.monotonic()
    daemon._dispatch_queued_pool(result, pool, max_dispatch=1)
    elapsed = time.monotonic() - before

    assert started.wait(1)
    assert result.dispatched == 1
    assert elapsed < 0.5
    assert len(snapshot_calls) == 1
    daemon._begin_cycle("heartbeat")
    assert daemon.runtime.heartbeat_at is not None
    daemon._complete_cycle(TickResult(), "heartbeat")
    release.set()
    pool.shutdown(wait=True)


def test_worker_pool_recovers_older_active_task_after_future_deduplication(
    config, monkeypatch
):
    config = replace(config, limits=replace(config.limits, max_active_tasks=2))
    store = TaskStore.create(config.db_path)
    older, _ = _task(store, "older active pool task")
    store.start_worker(older.id, "running")
    newer, _ = _task(store, "newer active pool task")
    store.start_worker(newer.id, "running")
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE tasks SET created_at = ? WHERE id = ?",
            ("2026-01-01T00:00:00+00:00", older.id),
        )
        connection.exec_driver_sql(
            "UPDATE tasks SET created_at = ? WHERE id = ?",
            ("2026-01-02T00:00:00+00:00", newer.id),
        )

    snapshot_calls = []
    original_snapshot = store.dispatch_snapshot

    def snapshot(**kwargs):
        snapshot_calls.append(kwargs)
        return original_snapshot(**kwargs)

    monkeypatch.setattr(store, "dispatch_snapshot", snapshot)
    daemon = StewardDaemon(config, store)
    release = threading.Event()
    started = threading.Event()
    scheduled: list[str] = []
    pool = ThreadPoolExecutor(max_workers=2)
    existing_future = pool.submit(release.wait, 30)
    daemon._active_futures[newer.id] = existing_future

    def worker(task_id):
        scheduled.append(task_id)
        started.set()
        release.wait(2)
        return True

    daemon._run_task_worker = worker
    try:
        result = TickResult()
        daemon._dispatch_queued_pool(result, pool, max_dispatch=1)

        assert started.wait(1)
        assert scheduled == [older.id]
        assert result.dispatched == 1
        assert snapshot_calls == [
            {"source_limit": 1, "integration_limit": 1, "resumable_limit": 2}
        ]
        assert set(daemon._active_futures) == {newer.id, older.id}
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_worker_pool_dispatches_old_active_task_beyond_legacy_window(
    config, monkeypatch
):
    store = TaskStore.create(config.db_path)
    oldest_active, _ = _task(store, "oldest active pool task")
    store.start_worker(oldest_active.id, "running")
    for index in range(4):
        terminal, _ = _task(store, f"newer pool history {index}")
        store.finish_task(terminal.id, TaskStatus.succeeded, "terminal")
    monkeypatch.setattr(
        store,
        "list_tasks",
        lambda **_kwargs: pytest.fail("pool dispatch used a capped task listing"),
    )
    daemon = StewardDaemon(config, store)
    scheduled: list[str] = []
    release = threading.Event()

    def worker(task_id):
        scheduled.append(task_id)
        release.wait(1)
        return True

    daemon._run_task_worker = worker
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        result = TickResult()
        daemon._dispatch_queued_pool(result, pool, max_dispatch=1)
        assert scheduled == [oldest_active.id]
        assert result.dispatched == 1
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_shutdown_grace_bounds_blocked_worker_pool(config):
    object.__setattr__(config, "shutdown_grace_seconds", 5.0)
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    release = threading.Event()
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(release.wait, 30)
    daemon._worker_pool = pool
    daemon._active_futures["blocked"] = future

    started = time.monotonic()
    result = daemon.shutdown()
    elapsed = time.monotonic() - started
    release.set()
    future.result(timeout=1)

    assert result.forced
    assert elapsed < config.shutdown_grace_seconds + 1


@pytest.mark.parametrize("phase", ["planning", "implementation", "review", "formality"])
@pytest.mark.parametrize("interruption", ["interrupted", "forced"])
def test_shutdown_interrupted_phase_preserves_restart_state(config, phase, interruption):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "interrupted " + phase)
    task.worktree_path = config.repo_root
    if phase == "planning":
        task.spec.workflow = "feature"
    store.save(task)
    store.start_worker(task.id, "test phase")
    store.add_event(task.id, "pipeline.phase.finished", "provisioned", {
        "pipeline_id": pipeline.id,
        "output": {"action_id": "provisioned", "next_phase": phase},
    })
    review = {"verdict": "approve", "summary": "ok", "findings": [], "validation_gaps": [], "remaining_risk": ""}
    if phase == "formality":
        store.add_event(task.id, "pipeline.review.raw", "review", {"pipeline_id": pipeline.id, "review": review})
    if phase == "review":
        store.add_event(task.id, "pipeline.validation.result", "passed", {
            "pipeline_id": pipeline.id, "output_tree": StewardExecutor(config, store).worktrees.tree(config.repo_root), "validations": [],
        })
    role = {"planning": "planner", "implementation": "implementation", "review": "reviewer", "formality": "formality"}[phase]
    calls = []

    class InterruptedRunner(CodexRunner):
        def run(self, task, _prompt, cwd, **kwargs):
            calls.append(kwargs["idempotency_key"])
            checkpoint = worktree_checkpoint(config, cwd)
            session, run = store.create_session_with_run(
                task.id, pipeline.id, owner_role=role, role=role,
                session_id="interrupted-session",
                private_home_path=config.private_sessions_dir / task.id / "interrupted-session",
                private_home_relative_path=f"{task.id}/interrupted-session",
                image_digest=IMAGE, codex_identity="test", provider_store_identity="codex-sessions-v1",
                model=None, reasoning=None, image_version=IMAGE, runtime_version="task-runtime-v1",
                run_provider_store_identity="codex-sessions-v1",
                cwd=cwd, checkpoint_id=checkpoint, run_checkpoint_id=checkpoint,
                session_idempotency_key=kwargs["idempotency_key"],
            )
            store.mark_run_interrupted(run.id, reason="daemon shutdown")
            daemon.request_shutdown(force=interruption == "forced")
            transcript, message = self.paths(task, name=kwargs["name"])
            return WorkerResult(
                completed=False, command=["fake-codex"], cwd=cwd, exit_code=143,
                transcript_path=transcript, last_message_path=message,
                diagnostics={"status": interruption}, run_id=run.id,
                session_id=session.id, pipeline_id=pipeline.id,
            )

    executor = StewardExecutor(config, store, runner=InterruptedRunner(config))
    executor.MAX_RUNS = 1  # Interruption at the budget boundary still preserves its claim.
    daemon = StewardDaemon(config, store)
    daemon.executor = executor
    finalized = []
    daemon.finalize_terminal_task = finalized.append
    assert daemon._run_task_worker(task.id) is False
    assert not TaskStatus(store.get(task.id).status).terminal, store.get(task.id).summary
    assert store.get_execution(task.id).state == "active"
    assert store.get_pipeline(pipeline.id).state == "active"
    assert executor.advance_once(task.id).status == "in_progress"
    assert len(calls) == 1
    assert finalized == []
    daemon.shutdown()

    class CompletingSupervisor(FakeSupervisor):
        def _complete(self, run):
            result = super()._complete(run)
            message = {
                "planning": json.dumps({"summary": "plan", "assumptions": [], "steps": [{"title": "edit", "detail": "edit readme", "files": ["README.md"]}], "validation": ["test"], "risks": [], "non_goals": []}),
                "implementation": "done",
                "review": json.dumps(review),
                "formality": '{"dispositions": []}',
            }[phase]
            result.last_message_path.write_text(message, encoding="utf-8")
            if phase == "implementation":
                (config.repo_root / "README.md").write_text("recovered\n", encoding="utf-8")
            return result

    supervisor = CompletingSupervisor(config, store)
    restarted = StewardDaemon(config, TaskStore.open(config.db_path), session_supervisor=supervisor)
    outcome = restarted.startup_reconcile()[0]
    assert outcome.disposition == "resumed"
    assert not TaskStatus(store.get(task.id).status).terminal, store.get(task.id).summary
    expected = {"planning": "implementation", "implementation": "validation", "review": "integration", "formality": "integration"}[phase]
    assert restarted.executor._pipeline_cursor(task.id, pipeline.id).value == expected
    if phase == "planning":
        assert store.get_plan_run(task.id, 0).completed
    restarted.startup_reconcile()
    assert len([call for call in supervisor.calls if call[0] in {"resume", "recover"}]) == 1
    assert len(calls) == 1


def test_once_dispatch_drives_durable_progress_and_bounds_tasks(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    first, _ = _task(store, "once progress")
    second, _ = _task(store, "once max dispatch")
    snapshot_calls = []
    original_snapshot = store.dispatch_snapshot

    def snapshot(**kwargs):
        snapshot_calls.append(kwargs)
        return original_snapshot(**kwargs)

    monkeypatch.setattr(store, "dispatch_snapshot", snapshot)
    monkeypatch.setattr(
        store,
        "queued_tasks",
        lambda **_kwargs: pytest.fail("serial dispatch used a legacy queue read"),
    )
    monkeypatch.setattr(
        store,
        "source_active_count",
        lambda: pytest.fail("serial dispatch used a legacy source count"),
    )
    daemon = StewardDaemon(config, store)
    outcomes = {
        first.id: iter(
            [
                SimpleNamespace(
                    status="in_progress",
                    progressed=True,
                    next_phase=None,
                ),
                SimpleNamespace(
                    status="ready_to_seal",
                    progressed=True,
                    next_phase=None,
                ),
            ]
        ),
        second.id: iter(
            [SimpleNamespace(status="terminal", progressed=True, next_phase=None)]
        ),
    }
    calls: list[str] = []
    serialized_calls: list[str] = []
    finalized: list[str] = []
    planned: list[TickResult] = []

    def advance(task_id: str) -> SimpleNamespace:
        calls.append(task_id)
        if daemon._integration_lock.locked():
            serialized_calls.append(task_id)
        return next(outcomes[task_id])

    daemon.executor = SimpleNamespace(advance_once=advance)
    daemon.finalize_terminal_task = lambda task_id: finalized.append(task_id) or True
    daemon._plan_until_idle = planned.append
    daemon._task_phase_requires_serialization = lambda _task_id: True

    result = TickResult()
    daemon._dispatch_queued(result, plan=True, max_dispatch=1)

    assert result.dispatched == 1
    assert result.skipped == 0
    assert len(snapshot_calls) == 1
    assert calls == [first.id, first.id]
    assert serialized_calls == calls
    assert finalized == [first.id]
    assert planned == [result]
    assert store.get(second.id).status == TaskStatus.queued
    assert daemon._worker_pool is None
    assert daemon._active_futures == {}


def test_once_dispatch_counts_terminal_and_nonprogress_outcomes(config):
    store = TaskStore.create(config.db_path)
    terminal, _ = _task(store, "once terminal")
    blocked, _ = _task(store, "once blocked")
    interrupted, _ = _task(store, "once interrupted")
    stalled, _ = _task(store, "once stalled")
    daemon = StewardDaemon(config, store)
    statuses = {
        terminal.id: "terminal",
        blocked.id: "blocked",
        interrupted.id: "interrupted",
        stalled.id: "stalled",
    }
    calls: list[str] = []
    finalized: list[str] = []

    def advance(task_id: str) -> SimpleNamespace:
        calls.append(task_id)
        return SimpleNamespace(
            status=statuses[task_id],
            progressed=False,
            next_phase=None,
        )

    daemon.executor = SimpleNamespace(advance_once=advance)
    daemon.finalize_terminal_task = lambda task_id: finalized.append(task_id) or True

    result = TickResult()
    daemon._dispatch_queued(result, plan=False, max_dispatch=None)

    assert result.dispatched == 1
    assert result.skipped == 3
    assert calls == [terminal.id, blocked.id, interrupted.id, stalled.id]
    assert finalized == [blocked.id]


def test_once_dispatch_stops_without_counting_shutdown_interruption(config):
    store = TaskStore.create(config.db_path)
    task, _ = _task(store, "once shutdown")
    daemon = StewardDaemon(config, store)
    calls: list[str] = []

    def advance(task_id: str) -> SimpleNamespace:
        calls.append(task_id)
        daemon.request_shutdown()
        return SimpleNamespace(status="interrupted", progressed=False, next_phase=None)

    daemon.executor = SimpleNamespace(advance_once=advance)

    result = TickResult()
    daemon._dispatch_queued(result, plan=False, max_dispatch=1)

    assert calls == [task.id]
    assert result.dispatched == 0
    assert result.skipped == 0
    assert store.get(task.id).status == TaskStatus.queued
    assert daemon._active_futures == {}


def test_session_runner_preserves_interrupted_run_identity(config):
    store = TaskStore.create(config.db_path)
    task, pipeline = _task(store, "session interruption")
    task.worktree_path = config.repo_root
    store.save(task)
    transcript = config.logs_dir / task.id / "codex.jsonl"
    message = config.logs_dir / task.id / "last-message.md"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text("{}\n", encoding="utf-8")
    message.write_text("interrupted\n", encoding="utf-8")

    class InterruptedSupervisor(SessionSupervisor):
        def __init__(self):
            pass

        def start(self, *_args, **_kwargs):
            return SessionResult(
                task.id,
                pipeline.id,
                "session-test",
                "run-test",
                InvocationStatus.interrupted,
                143,
                None,
                transcript,
                message,
            )

    executor = StewardExecutor(
        config,
        store,
        session_supervisor=InterruptedSupervisor(),
    )

    result = executor.runner.run(task, "implement", config.repo_root)

    assert result.session_id == "session-test"
    assert result.run_id == "run-test"
    assert result.pipeline_id == pipeline.id
    assert result.diagnostics["status"] == "interrupted"


def test_enabled_nested_container_config_drives_runtime_fields(config):
    state = config.repo_root.parent / "container-state"
    state.mkdir()
    key = config.repo_root.parent / "codex-api-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    container = StewardContainerConfig(
        enabled=True,
        image="nested-task-image",
        image_digest=IMAGE,
        repository_host_path=config.repo_root,
        state_host_path=state,
        codex_api_key_path=key,
        docker_bin="/bin/true",
    )
    nested = StewardConfig(repo_root=config.repo_root, container=container)
    nested.ensure_dirs()

    executor = StewardExecutor(nested, TaskStore.create(nested.db_path))

    assert nested.task_image == container.image
    assert nested.task_image_digest == container.image_digest
    assert executor.session_supervisor is not None

    with pytest.raises(ValueError, match="conflicts"):
        StewardConfig(
            repo_root=config.repo_root,
            task_image_digest="sha256:" + "b" * 64,
            container=container,
        )


@pytest.mark.parametrize(
    "container_enabled,digest,harness,injected,runner,expected",
    [
        (False, None, True, False, False, "local"),
        (False, None, False, False, False, "rejected"),
        (False, IMAGE, True, False, False, "local"),
        (True, None, True, False, False, "rejected"),
        (True, IMAGE, False, False, False, "supervisor"),
        (True, None, False, True, False, "injected"),
        (True, None, False, False, True, "runner"),
    ],
)
def test_executor_task_session_eligibility(
    config,
    container_enabled,
    digest,
    harness,
    injected,
    runner,
    expected,
):
    state = config.repo_root.parent / "container-state"
    state.mkdir()
    key = config.repo_root.parent / "codex-api-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    container = StewardContainerConfig(
        enabled=container_enabled,
        image="nested-task-image",
        image_digest=digest,
        repository_host_path=config.repo_root if container_enabled else None,
        state_host_path=state if container_enabled else None,
        codex_api_key_path=key if container_enabled else None,
        docker_bin="/bin/true",
    )
    configured = replace(
        config,
        container=container,
        task_image_digest=digest if not container_enabled else None,
        local_codex_test_harness=harness,
    )
    store = TaskStore.create(configured.db_path)
    kwargs = {}
    if injected:
        kwargs["session_supervisor"] = SessionSupervisor(
            configured, store, require_boundary=False
        )
    elif runner:
        kwargs["runner"] = object()

    if expected == "rejected":
        error = "task_image_digest" if container_enabled else "task-container"
        with pytest.raises(ValueError, match=error):
            StewardExecutor(configured, store, **kwargs)
        return

    executor = StewardExecutor(configured, store, **kwargs)
    if expected == "supervisor":
        assert executor.session_supervisor is not None
    elif expected == "injected":
        assert executor.session_supervisor is kwargs["session_supervisor"]
    elif expected == "runner":
        assert executor.session_supervisor is None
        assert executor.runner is kwargs["runner"]
    else:
        assert executor.session_supervisor is None
        assert executor.runner is not None


def test_sigint_sigterm_second_signal_stops_not_removes_restart_state(config):
    store = TaskStore.create(config.db_path)
    task, _, run = _interrupted_run(config, store)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?",
            (run.id,),
        )
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    daemon.request_shutdown()
    daemon.request_shutdown(force=True)
    result = daemon.shutdown(force=True)

    assert result.forced
    assert daemon.lifecycle_state.value == "stopped"
    assert any(call[0] == "interrupt" for call in supervisor.calls)
    assert any(call[0] == "stop" for call in supervisor.calls)
    assert not any(call[0] == "remove" for call in supervisor.calls)
    assert config.private_sessions_dir.joinpath(task.id).exists()
    assert store.get(task.id).status != TaskStatus.failed


def test_cli_signal_handler_only_sets_shutdown_intent(monkeypatch):
    installed = {}
    requests = []

    class SignalSafeDaemon:
        lifecycle_state = SimpleNamespace(value="stopped")

        def request_shutdown_from_signal(self, *, force=False):
            requests.append(force)

        def request_shutdown(self, **_kwargs):
            raise AssertionError("signal handler performed full shutdown work")

        def run_forever(self):
            installed[signal.SIGTERM](signal.SIGTERM, None)
            installed[signal.SIGINT](signal.SIGINT, None)

    monkeypatch.setattr(signal, "getsignal", lambda _selected: signal.SIG_DFL)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda selected, handler: installed.__setitem__(selected, handler),
    )

    _run_until_stopped(SignalSafeDaemon())

    assert requests == [False, True]


def test_shutdown_request_is_lock_free(config):
    daemon = StewardDaemon(config, TaskStore.create(config.db_path))

    with daemon._runtime_lock:
        daemon.request_shutdown()

    assert daemon.stopping
    assert daemon.shutdown(force=True).state.value == "stopped"


def test_shutdown_does_not_claim_failed_container_stop(config):
    store = TaskStore.create(config.db_path)
    task, _ = _task(store, "container stop failure")

    class StopFailure(FakeSupervisor):
        def stop_container(self, task_id, **_kwargs):
            self.calls.append(("stop", task_id))
            raise RuntimeError("Docker unavailable")

    supervisor = StopFailure(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert result.state.value == "stopping"
    assert daemon.lifecycle_state.value == "stopping"
    assert result.stopped_containers == 0
    assert ("stop", task.id) in supervisor.calls


def test_shutdown_discovers_and_stops_uncached_owned_container(config):
    store = TaskStore.create(config.db_path)
    task, _ = _task(store, "uncached owned container")
    task.worktree_path = config.repo_root
    store.save(task)
    task_dir = TaskArchiveWriter(config).task_dir(task.id)
    task_dir.mkdir(parents=True)
    (task_dir / "task.json").write_text(
        json.dumps({"taskId": "different-task"}), encoding="utf-8"
    )

    class ExistingRuntime(TaskContainerRuntime):
        def __init__(self):
            super().__init__(
                _test_runtime_config(config, task.id, "uncached-owned"),
                client=SubprocessDockerClient(),
            )
            self.running = True
            self.stop_calls = 0

        def stop(self, container_id=None, *, timeout=None):
            self.stop_calls += 1
            self.running = False

        def inspect(self):
            return ContainerInspection(
                container_id=self.config.container_name,
                name=self.config.container_name,
                state="running" if self.running else "exited",
                running=self.running,
                labels=self.config.labels,
            )

    runtime = ExistingRuntime()
    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=lambda _task: runtime,
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    reconciliation = daemon.startup_reconcile()[0]
    result = daemon.shutdown(force=True)

    assert reconciliation.disposition == "blocked"
    assert runtime.running is False
    assert runtime.stop_calls == 1
    assert result.stopped_containers == 1
    assert daemon.lifecycle_state.value == "stopped"


def test_shutdown_treats_queued_task_without_container_as_noop(config):
    configured = replace(config, task_image_digest=IMAGE)
    store = TaskStore.create(configured.db_path)
    task, _ = _task(store, "queued without container")
    supervisor = SessionSupervisor(
        configured,
        store,
        runtime_factory=runtime_factory_for_config(configured),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(configured, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert store.get(task.id).status == TaskStatus.queued
    assert result.stopped_containers == 0
    assert result.state.value == "stopped"
    assert daemon.lifecycle_state.value == "stopped"


@pytest.mark.parametrize(
    "cleanup_events",
    [
        ("cleanup.container_removed", "cleanup_complete"),
        ("cleanup_complete",),
    ],
    ids=["container-removed", "cleanup-complete"],
)
def test_shutdown_skips_uncached_cleaned_terminal_container(
    config, cleanup_events
):
    store = TaskStore.create(config.db_path)
    task, _ = _task(store, "cleaned terminal container")
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    worktree = config.worktrees_dir / task.id
    private_home = config.private_sessions_dir / task.id
    worktree.mkdir(parents=True)
    private_home.mkdir(parents=True)
    shutil.rmtree(worktree)
    shutil.rmtree(private_home)
    task = store.get(task.id)
    task.worktree_path = worktree
    store.save(task)
    for kind in cleanup_events:
        store.add_event(task.id, kind, "terminal cleanup evidence")

    factory_calls = []

    class RecreatedRuntime(TaskContainerRuntime):
        def __init__(self):
            super().__init__(
                _test_runtime_config(config, task.id, "cleaned-terminal"),
                client=SubprocessDockerClient(),
            )
            self.running = True
            self.stop_calls = 0

        def stop(self, container_id=None, *, timeout=None):
            self.stop_calls += 1
            self.running = False

        def inspect(self):
            return ContainerInspection(
                container_id=self.config.container_name,
                name=self.config.container_name,
                state="running" if self.running else "exited",
                running=self.running,
                labels=self.config.labels,
            )

    runtime = RecreatedRuntime()

    def factory(record):
        factory_calls.append(record.id)
        worktree.mkdir(parents=True, exist_ok=True)
        private_home.mkdir(parents=True, exist_ok=True)
        return runtime

    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=factory,
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert result.state.value == "stopped"
    assert daemon.lifecycle_state.value == "stopped"
    assert factory_calls == []
    assert runtime.stop_calls == 0
    assert not worktree.exists()
    assert not private_home.exists()


def test_shutdown_discovers_terminal_container_without_cleanup_proof(config):
    store = TaskStore.create(config.db_path)
    task, _ = _task(store, "unproven terminal container")
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    worktree = config.worktrees_dir / task.id
    worktree.mkdir(parents=True)
    task = store.get(task.id)
    task.worktree_path = worktree
    store.save(task)

    factory_calls = []

    class ExistingRuntime(TaskContainerRuntime):
        def __init__(self):
            super().__init__(
                _test_runtime_config(config, task.id, "unproven-terminal"),
                client=SubprocessDockerClient(),
            )
            self.running = True
            self.stop_calls = 0

        def stop(self, container_id=None, *, timeout=None):
            self.stop_calls += 1
            self.running = False

        def inspect(self):
            return ContainerInspection(
                container_id=self.config.container_name,
                name=self.config.container_name,
                state="running" if self.running else "exited",
                running=self.running,
                labels=self.config.labels,
            )

    runtime = ExistingRuntime()

    def factory(record):
        factory_calls.append(record.id)
        return runtime

    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=factory,
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert result.state.value == "stopped"
    assert factory_calls == [task.id]
    assert runtime.stop_calls == 1


def test_recovery_waits_for_live_wrapper_before_adoption(config, monkeypatch):
    store = TaskStore.create(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)

    class SlowLaunchSupervisor(FakeSupervisor):
        def __init__(self, config, store):
            super().__init__(config, store)
            self.successor_created = threading.Event()
            self.inspection_attempted = threading.Event()
            self.release_launch = threading.Event()
            self.launch_completed = threading.Event()
            self.successor_id = None

        def resume_with_retries(self, run_id, **_kwargs):
            predecessor = self.store.get_run(run_id)
            successor = self.store.create_run(
                predecessor.task_id,
                predecessor.pipeline_id,
                predecessor.session_id,
                role=predecessor.role,
                resume_of_run_id=predecessor.id,
                image_version=predecessor.image_version,
                runtime_version=predecessor.runtime_version,
                checkpoint_id=predecessor.checkpoint_id,
                provider_store_identity=predecessor.provider_store_identity,
            )
            self.successor_id = successor.id
            self.successor_created.set()
            self.release_launch.wait(timeout=2)
            result = ResumeResult(
                ResumeCategory.success,
                result=self._complete(successor),
            )
            self.launch_completed.set()
            return result

        def inspect(self, run_id):
            self.calls.append(("inspect", run_id))
            self.inspection_attempted.set()
            return SimpleNamespace(live=False, container=None)

    supervisor = SlowLaunchSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda *_: SimpleNamespace(status="ingested"),
    )
    outcomes = []
    recovery = threading.Thread(
        target=lambda: outcomes.append(
            daemon._resume_or_recover(task, predecessor, store.list_runs(task.id))
        )
    )
    recovery.start()
    assert supervisor.successor_created.wait(timeout=1)

    inspection_attempted = supervisor.inspection_attempted.wait(timeout=1)
    finished_before_wrapper = not recovery.is_alive()
    adopted_before_wrapper = daemon._adopted_runs.get(task.id)
    supervisor.release_launch.set()
    recovery.join(timeout=2)
    assert supervisor.launch_completed.wait(timeout=1)

    assert inspection_attempted is True
    assert finished_before_wrapper is False
    assert adopted_before_wrapper is None
    assert outcomes and outcomes[0].disposition == "resumed"


def test_recovery_does_not_adopt_before_wrapper_is_published(config):
    store = TaskStore.create(config.db_path)
    task, pipeline, predecessor = _interrupted_run(config, store)

    class SlowRuntime(TaskContainerRuntime):
        def __init__(self):
            super().__init__(
                _test_runtime_config(config, task.id, "slow-launch"),
                client=SubprocessDockerClient(),
            )
            self.entered = threading.Event()
            self.release = threading.Event()

        def ensure_started(self):
            self.entered.set()
            self.release.wait(timeout=3)
            raise RuntimeError("launch stopped before wrapper creation")

        def inspect(self):
            return ContainerInspection(
                container_id=self.config.container_name,
                name=self.config.container_name,
                state="running",
                running=True,
                labels=self.config.labels,
            )

    runtime = SlowRuntime()
    supervisor = SessionSupervisor(
        config,
        store,
        runtime=runtime,
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    def launch():
        return supervisor.start(
            task.id,
            pipeline.id,
            role="implementation",
            prompt="recover",
            cwd=config.repo_root,
            checkpoint_id=predecessor.checkpoint_id,
            retry_of_run_id=predecessor.id,
        )

    outcomes = []
    recovery = threading.Thread(
        target=lambda: outcomes.append(
            daemon._await_recovery_operation(task, predecessor, launch)
        )
    )
    recovery.start()
    try:
        assert runtime.entered.wait(timeout=1)
        recovery.join(timeout=0.2)
        successors = [
            run
            for run in store.list_runs(task.id)
            if run.retry_of_run_id == predecessor.id
        ]
        assert successors
        successor = successors[-1]

        inspection = supervisor.inspect(successor.id)

        assert recovery.is_alive()
        assert inspection.live is False
        assert inspection.identity is None
        assert daemon._adopted_runs.get(task.id) is None
    finally:
        runtime.release.set()
        recovery.join(timeout=2)

    assert not recovery.is_alive()
    assert outcomes and outcomes[0].status == "unavailable"
    assert store.get_run(successor.id).state == "failed"


def test_recovered_result_without_durable_phase_advance_stays_blocked(config):
    store = TaskStore.create(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)
    supervisor = FakeSupervisor(config, store)
    recovered = store.create_run(
        predecessor.task_id,
        predecessor.pipeline_id,
        predecessor.session_id,
        role=predecessor.role,
        resume_of_run_id=predecessor.id,
        image_version=predecessor.image_version,
        runtime_version=predecessor.runtime_version,
        checkpoint_id=predecessor.checkpoint_id,
        provider_store_identity=predecessor.provider_store_identity,
    )
    result = supervisor._complete(recovered)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    daemon.executor = SimpleNamespace(reconcile_session_result=lambda *_args: None)

    outcome = daemon._ingest_recovered_result(
        task,
        predecessor,
        store.get_run(recovered.id),
        result=result,
    )

    assert outcome.disposition == "blocked"
    assert not any(
        event.kind == "session.recovery.completed" for event in store.events(task.id)
    )


def test_recovered_result_advances_exact_interrupted_phase_once(config):
    store = TaskStore.create(config.db_path)
    task, pipeline, predecessor = _interrupted_run(config, store)
    task.worktree_path = config.repo_root
    store.save(task)
    action = store.get_session(predecessor.session_id).idempotency_key
    assert action is not None
    store.add_event(
        task.id,
        "pipeline.phase.finished",
        "provisioned",
        {
            "pipeline_id": pipeline.id,
            "phase": "provisioned",
            "output": {
                "action_id": f"{task.id}:{pipeline.id}:provisioned",
                "next_phase": "implementation",
            },
        },
    )
    store.add_event(
        task.id,
        "pipeline.phase.interrupted",
        "implementation interrupted",
        {
            "pipeline_id": pipeline.id,
            "phase": "implementation",
            "action_id": action,
            "run_id": predecessor.id,
        },
    )
    transcript = config.logs_dir / task.id / "implementation.jsonl"
    message = config.logs_dir / task.id / "implementation.md"
    store.begin_iteration(
        task.id,
        0,
        "Initial implementation",
        worker_name="implementation",
        worker_prompt_path=None,
        worker_transcript_path=transcript,
        worker_last_message_path=message,
    )
    (config.repo_root / "README.md").write_text(
        "recovered implementation\n", encoding="utf-8"
    )
    supervisor = FakeSupervisor(config, store)
    recovered = store.create_run(
        predecessor.task_id,
        predecessor.pipeline_id,
        predecessor.session_id,
        role=predecessor.role,
        resume_of_run_id=predecessor.id,
        image_version=predecessor.image_version,
        runtime_version=predecessor.runtime_version,
        checkpoint_id=predecessor.checkpoint_id,
        provider_store_identity=predecessor.provider_store_identity,
    )
    result = supervisor._complete(recovered)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    first = daemon._ingest_recovered_result(
        task,
        predecessor,
        store.get_run(recovered.id),
        result=result,
    )
    second = daemon._ingest_recovered_result(
        task,
        predecessor,
        store.get_run(recovered.id),
        result=result,
    )

    events = store.events(task.id)
    matching_finishes = [
        event
        for event in events
        if event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("action_id") == action
    ]
    matching_completions = [
        event
        for event in events
        if event.kind == "session.recovery.completed"
        and event.data.get("predecessor_run_id") == predecessor.id
    ]
    assert first.disposition == "resumed"
    assert second.disposition == "resumed"
    assert len(matching_finishes) == 1
    assert len(matching_completions) == 1


def test_terminal_seal_uses_canonical_utc_timestamp(config):
    config = config.__class__(**{**config.__dict__, "dry_run": False})
    store = TaskStore.create(config.db_path, dry_run=False)
    task, pipeline = _task(store, "canonical terminal timestamp")
    _, run = store.create_session_with_run(
        task.id,
        pipeline.id,
        session_id="session-terminal",
        private_home_path=config.private_sessions_dir / task.id / "session-terminal",
        private_home_relative_path=f"{task.id}/session-terminal",
        image_digest=IMAGE,
        codex_identity="codex-test",
        cwd=config.repo_root,
        checkpoint_id="terminal-checkpoint",
        provider_store_identity="codex-sessions-v1",
        owner_role="implementation",
        session_idempotency_key=f"{task.id}:{pipeline.id}:implementation",
        role="implementation",
        model=None,
        reasoning=None,
        image_version=IMAGE,
        runtime_version="task-runtime-v1",
        run_checkpoint_id="terminal-checkpoint",
        run_provider_store_identity="codex-sessions-v1",
    )
    store.transition_run(
        run.id,
        CodexRunState.failed.value,
        expected_state=CodexRunState.running.value,
        exit_code=1,
        result_summary="terminal",
    )
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "failed",
        {"pipeline_id": pipeline.id, "terminal_status": "failed"},
    )
    store.transition_pipeline(pipeline.id, "failed", phase="complete")
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    daemon = StewardDaemon(config, store)

    assert daemon.finalize_terminal_task(task.id) is True

    manifest = json.loads(
        (config.tasks_dir / task.id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["completedAt"].endswith("Z")
    assert "+00:00" not in manifest["completedAt"]


def test_terminal_publication_lifecycle_delegates_and_fails_closed(monkeypatch):
    calls = []

    def sentinel(status):
        calls.append(status)
        return "sentinel"

    monkeypatch.setattr(daemon_module, "task_publication_lifecycle", sentinel)
    daemon = object.__new__(StewardDaemon)

    assert (
        daemon._terminal_publication_lifecycle(
            SimpleNamespace(status=TaskStatus.succeeded.value)
        )
        == "sentinel"
    )
    assert calls == [TaskStatus.succeeded]

    for task in (
        SimpleNamespace(status=TaskStatus.queued.value),
        SimpleNamespace(),
        SimpleNamespace(status="invalid"),
    ):
        calls.clear()
        assert daemon._terminal_publication_lifecycle(task) == "failed"
        assert calls == []


@pytest.mark.parametrize(
    ("api", "failure"),
    [
        pytest.param("generations", "missing", id="missing-generations"),
        pytest.param("generations", "failing", id="failing-generations"),
        pytest.param("receipts", "missing", id="missing-receipts"),
        pytest.param("receipts", "failing", id="failing-receipts"),
    ],
)
def test_durable_publication_exposure_requires_generation_and_receipt_apis(
    api, failure
):
    task = SimpleNamespace(id="task-publication-evidence")
    exposed_at = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
    generation = replace(
        _publication_generation(task.id),
        state=PublicationState.exposed,
        updated_at=exposed_at,
        exposed_at=exposed_at,
    )
    store = SimpleNamespace()

    if api == "generations":
        if failure == "failing":
            def list_publication_generations(**_kwargs):
                raise RuntimeError("generation query failed")

            store.list_publication_generations = list_publication_generations
    else:
        store.list_publication_generations = lambda **_kwargs: [generation]
        if failure == "failing":
            def list_publication_receipts(_publication_id):
                raise RuntimeError("receipt query failed")

            store.list_publication_receipts = list_publication_receipts

    daemon = object.__new__(StewardDaemon)
    daemon.store = store

    assert daemon._durable_publication_exposure(task) == (False, None)


@pytest.mark.parametrize("reconciliation", ["missing", "failing"])
def test_terminal_publication_effect_requires_reconciliation_api(reconciliation):
    task = SimpleNamespace(id="task-publication-effect")
    generation = _publication_generation(task.id)
    events = []
    generic_calls = []
    store = SimpleNamespace(
        add_event=lambda task_id, kind, message, data=None: events.append(
            (task_id, kind, message, data)
        ),
        record_effect_applied=lambda *args, **kwargs: generic_calls.append(
            (args, kwargs)
        ),
    )
    if reconciliation == "failing":
        def record_publication_exposure_reconciled(*_args, **_kwargs):
            raise ValueError("reconciliation failed")

        store.record_publication_exposure_reconciled = (
            record_publication_exposure_reconciled
        )

    daemon = object.__new__(StewardDaemon)
    daemon.store = store

    assert daemon._record_terminal_publication_effect(task, generation) is False
    assert generic_calls == []
    assert events[-1][1] == "cleanup_blocked"
    assert events[-1][3]["reason"] == "publication_effect_invalid"


def test_completed_cleanup_intent_reconciles_missing_completion_event(config):
    config = config.__class__(**{**config.__dict__, "dry_run": False})
    store = TaskStore.create(config.db_path, dry_run=False)
    task, pipeline = _task(store, "completed cleanup intent")
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "failed",
        {"pipeline_id": pipeline.id, "terminal_status": "failed"},
    )
    store.transition_pipeline(pipeline.id, "failed", phase="complete")
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    store.add_event(task.id, "cleanup_pending", "terminal manifest verified")

    daemon = StewardDaemon(config, store)
    daemon._cleanup_intent_for_task = lambda _task_id: SimpleNamespace(
        state=CleanupState.completed
    )

    assert daemon.finalize_terminal_task(task.id) is True
    assert store.cleanup_obligation_state(task.id) is CleanupStatus.complete
    assert [
        event.kind
        for event in store.events(task.id)
        if event.kind in {"cleanup_pending", "cleanup_complete"}
    ] == ["cleanup_pending", "cleanup_complete"]

    assert daemon.finalize_terminal_task(task.id) is True
    assert [
        event.kind
        for event in store.events(task.id)
        if event.kind == "cleanup_complete"
    ] == ["cleanup_complete"]


def test_terminal_seal_rejects_unresolved_external_action(config, monkeypatch):
    config = config.__class__(**{**config.__dict__, "dry_run": False})
    store = TaskStore.create(config.db_path, dry_run=False)
    task, pipeline = _task(store, "unresolved terminal action")
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "push",
        {
            "pipeline_id": pipeline.id,
            "phase": "push",
            "action_id": f"{task.id}:{pipeline.id}:push",
        },
    )
    store.finish_task(task.id, TaskStatus.blocked, "push unresolved")
    archive_calls = []

    class RecordingArchive:
        def __init__(self, _config):
            archive_calls.append("created")

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.TaskArchiveWriter",
        RecordingArchive,
    )
    daemon = StewardDaemon(config, store)

    assert daemon.finalize_terminal_task(task.id) is False
    assert store.effect_result(task.id) is None
    assert archive_calls == []
    kinds = [event.kind for event in store.events(task.id)]
    assert "cleanup_blocked" in kinds
    assert "cleanup_pending" not in kinds
    assert "cleanup_complete" not in kinds


def test_terminal_manifest_cleanup_container_worktree_home_crash_retry(
    config, monkeypatch
):
    config = config.__class__(**{**config.__dict__, "dry_run": False})
    store = TaskStore.create(config.db_path, dry_run=False)
    task, pipeline = _task(store, "terminal cleanup")
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "failed",
        {"pipeline_id": pipeline.id, "terminal_status": "failed"},
    )
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    task = store.get(task.id)
    worktree = config.worktrees_dir / task.id
    worktree.mkdir(parents=True)
    task.worktree_path = worktree
    store.save(task)
    private_home = config.private_sessions_dir / task.id
    private_home.mkdir(parents=True)
    (private_home / "history").write_text("private", encoding="utf-8")
    supervisor = FakeSupervisor(config, store)
    supervisor.remove_failures = 2
    calls = supervisor.calls

    class FakeArchive:
        def __init__(self, _config):
            self.root = config.tasks_dir

        def task_dir(self, task_id):
            return self.root / task_id

        def create_task_from_record(self, record, **_kwargs):
            path = self.task_dir(record.id)
            path.mkdir(parents=True, exist_ok=True)
            (path / "task.json").write_text("{}", encoding="utf-8")
            return path / "task.json"

        def materialize_run(self, *_args, **_kwargs):
            return None

        def materialize_pipeline(self, *_args, **_kwargs):
            return None

        def materialize_effects(self, task_id, *_args, **_kwargs):
            calls.append(("materialize_effects", task_id))

        def seal(self, task_id, *_args, **_kwargs):
            calls.append(("seal", task_id))
            manifest = self.task_dir(task_id) / "manifest.json"
            manifest.write_bytes(b"sealed-public-bytes")
            return manifest

        def verify_or_raise(self, task_id):
            assert (self.task_dir(task_id) / "manifest.json").read_bytes() == (
                b"sealed-public-bytes"
            )
            return True

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.TaskArchiveWriter",
        FakeArchive,
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "clean_finished_task_worktree",
        lambda record: shutil.rmtree(record.worktree_path),
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.preflight_remote_push",
        lambda _config: True,
    )

    assert daemon.finalize_terminal_task(task.id) is False
    assert any(event.kind == "cleanup_pending" for event in store.events(task.id))
    store.add_event(task.id, "cleanup_complete", "previous cleanup completed")
    store.add_event(task.id, "cleanup_pending", "cleanup reopened")
    assert worktree.exists() and private_home.exists()
    daemon.startup_reconcile()
    assert worktree.exists() and private_home.exists()
    daemon.run_cycle(plan=False, dispatch=False)

    kinds = [event.kind for event in store.events(task.id)]
    assert [
        kind
        for kind in kinds
        if kind in {"cleanup_pending", "cleanup_complete"}
    ] == [
        "cleanup_pending",
        "cleanup_complete",
        "cleanup_pending",
        "cleanup_complete",
    ]
    assert kinds.index("cleanup_pending") < kinds.index("cleanup.container_removed")
    assert kinds.index("cleanup.container_removed") < kinds.index(
        "cleanup.worktree_removed"
    )
    assert kinds[-1] == "cleanup_complete"
    assert calls.count(("remove", task.id)) == 3
    assert not worktree.exists()
    assert not private_home.exists()
    materialize_effects_call = ("materialize_effects", task.id)
    assert calls.count(materialize_effects_call) == 1
    assert calls.index(materialize_effects_call) < calls.index(("seal", task.id))
    assert (config.tasks_dir / task.id / "manifest.json").read_bytes() == (
        b"sealed-public-bytes"
    )


def test_terminal_container_remove_requires_stopped_identity(config):
    task, _ = _task(TaskStore.create(config.db_path), "container remove")
    root = config.repo_root
    runtime_config = TaskContainerConfig(
        task_id=task.id,
        image="task-image",
        image_digest=IMAGE,
        worktree=root,
        archive=config.tasks_dir / task.id,
        private_sessions=config.private_sessions_dir / task.id,
        git_dir=root / ".git",
        git_common_dir=root / ".git",
        repo_root=root,
    )
    runtime_config.archive.mkdir(parents=True, exist_ok=True)
    runtime_config.private_sessions.mkdir(parents=True, exist_ok=True)
    calls = []

    class Client(SubprocessDockerClient):
        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            calls.append(argv)
            if argv[0] == "inspect":
                value = {
                    "Id": "container-id",
                    "State": {"Status": "exited", "Running": False},
                    "Config": {
                        "Image": IMAGE,
                        "Labels": runtime_config.labels,
                    },
                }
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    TaskContainerRuntime(runtime_config, client=Client()).remove()

    assert [call[0] for call in calls] == ["inspect", "rm"]


def test_daemon_publication_dispatch_is_static() -> None:
    source = Path(daemon_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    helper_names = {
        "_repair_staged_generation",
        "_publication_source",
        "_publication_overhead_rows",
        "_reconcile_publication_usage",
        "_drain_pending_publication_hides",
        "_publish_next_generation",
        "_terminal_publication_run",
        "_prepare_terminal_publication_snapshot",
        "_terminal_publication_receipts_verified",
        "_terminal_publication_gate",
        "_terminal_publication_generation_for_cleanup",
        "_cleanup_intents_for_task",
        "_create_terminal_cleanup_intent",
        "_delete_terminal_archive",
    }
    failures: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node.name not in helper_names:
                return
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                    if child.func.id in {"hasattr", "callable"}:
                        failures.append(f"{node.name}:{child.lineno}:{child.func.id}")
                    elif child.func.id == "getattr" and child.args:
                        target = ast.unparse(child.args[0])
                        if target in {"self.store", "publisher", "self.executor"}:
                            failures.append(f"{node.name}:{child.lineno}:getattr({target})")
                if isinstance(child, ast.ExceptHandler):
                    if isinstance(child.type, ast.Name) and child.type.id == "TypeError":
                        failures.append(f"{node.name}:{child.lineno}:TypeError retry")
            self.generic_visit(node)

    Visitor().visit(tree)
    assert failures == []


class _DaemonSerializerLookalike:
    def __init__(self) -> None:
        self.as_dict_called = False
        self.public_dict_called = False

    def as_dict(self) -> dict[str, object]:
        self.as_dict_called = True
        raise AssertionError("unsupported serializer executed")

    def public_dict(self) -> dict[str, object]:
        self.public_dict_called = True
        raise AssertionError("unsupported serializer executed")


class _DaemonRunAsDictLookalike:
    def __init__(self) -> None:
        self.called = False

    def as_dict(self) -> dict[str, object]:
        self.called = True
        raise AssertionError("unsupported serializer executed")


def _terminal_run_metadata() -> RunMetadata:
    started = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
    return RunMetadata(
        RunIdentity("task-terminal", "pipeline-terminal", "run-original"),
        "implementation",
        "succeeded",
        started,
        started.replace(second=1),
        1_000,
    )


def test_terminal_publication_graph_statistically_detaches_run_metadata() -> None:
    daemon = object.__new__(StewardDaemon)
    task = SimpleNamespace(
        id="task-terminal",
        status=TaskStatus.succeeded.value,
        updated_at=datetime(2026, 7, 28, 12, 0, 1, tzinfo=timezone.utc),
    )
    source = AtifSource(
        run=_terminal_run_metadata(),
        documents={"run.json": b'{"runId":"run-original"}\n'},
    )
    graph = {"task": {"taskId": task.id}, "runs": [source]}

    result = daemon._terminal_publication_graph(task, SimpleNamespace(id="run-original"), graph, "run-terminal")

    assert result is not None
    replaced = result["runs"][0]
    assert isinstance(replaced, AtifSource)
    assert isinstance(replaced.run, dict)
    assert replaced.run["runId"] == "run-terminal"
    assert json.loads(replaced.documents["run.json"].decode())["runId"] == "run-terminal"


def test_terminal_publication_graph_rejects_run_serializer_lookalikes() -> None:
    daemon = object.__new__(StewardDaemon)
    task = SimpleNamespace(
        id="task-terminal",
        status=TaskStatus.succeeded.value,
        updated_at=datetime(2026, 7, 28, 12, 0, 1, tzinfo=timezone.utc),
    )
    lookalike = _DaemonRunAsDictLookalike()
    source = AtifSource(run=lookalike, documents={})
    graph = {"task": {"taskId": task.id}, "runs": [source]}

    result = daemon._terminal_publication_graph(task, SimpleNamespace(id="run-original"), graph, "run-terminal")

    assert result is None
    assert lookalike.called is False


def test_terminal_publication_graph_rejects_nested_serializer_subtypes() -> None:
    daemon = object.__new__(StewardDaemon)
    task = SimpleNamespace(
        id="task-terminal",
        status=TaskStatus.succeeded.value,
        updated_at=datetime(2026, 7, 28, 12, 0, 1, tzinfo=timezone.utc),
    )
    executed = False

    class ArmedIdentity(RunIdentity):
        def as_dict(self) -> dict[str, object]:
            nonlocal executed
            executed = True
            raise AssertionError("unsupported nested serializer executed")

    base = _terminal_run_metadata()
    run = replace(
        base,
        identity=ArmedIdentity("task-terminal", "pipeline-terminal", "run-original"),
    )
    source = AtifSource(run=run, documents={})
    graph = {"task": {"taskId": task.id}, "runs": [source]}

    result = daemon._terminal_publication_graph(task, SimpleNamespace(id="run-original"), graph, "run-terminal")

    assert result is None
    assert executed is False


def test_publication_usage_mapping_uses_only_the_current_overhead_value() -> None:
    daemon = object.__new__(StewardDaemon)
    row = StewardOverheadUsage(date="2026-07-28", model="gpt-test")

    mapped = daemon._publication_usage_mapping(row)

    assert mapped == row.public_dict()


def test_publication_usage_mapping_rejects_serializer_lookalikes() -> None:
    daemon = object.__new__(StewardDaemon)
    lookalike = _DaemonSerializerLookalike()

    assert daemon._publication_usage_mapping(lookalike) is None
    assert lookalike.as_dict_called is False
    assert lookalike.public_dict_called is False


def test_publication_usage_mapping_rejects_overhead_subtypes_without_execution() -> None:
    daemon = object.__new__(StewardDaemon)
    executed = False

    class ArmedOverhead(StewardOverheadUsage):
        def model_dump(self, *args, **kwargs):
            nonlocal executed
            executed = True
            raise AssertionError("unsupported overhead serializer executed")

    row = ArmedOverhead(date="2026-07-28", model="gpt-test")

    assert daemon._publication_usage_mapping(row) is None
    assert executed is False


def test_reconcile_publication_usage_passes_store_authority_to_publisher(
    tmp_path,
) -> None:
    store = TaskStore.create(tmp_path / "daemon-authority.sqlite", dry_run=False)
    store.claim_daemon_instance("daemon-authority", lifecycle="running")
    authority = store.get_daemon_publication_authority()
    assert authority is not None
    daemon = object.__new__(StewardDaemon)
    row = StewardOverheadUsage(date="2026-07-28", model="gpt-test")
    daemon._control_loop_ledger = SimpleNamespace(
        list_overhead_usage=lambda: [row]
    )
    daemon._control_loop_usage = SimpleNamespace(
        catalog=SimpleNamespace(digest="catalog-digest")
    )
    daemon._publication_authority = authority
    daemon._publication_overhead_digest = None
    daemon._publication_overhead_position = 0
    daemon._publication_backfill_catalog_digest = "catalog-digest"
    daemon._publication_backfill_cursor = "cursor-before"
    daemon._publication_backfill_blocked = False
    daemon._log = lambda *_args, **_kwargs: None
    received: list[tuple[str, object]] = []

    class Publisher:
        def reconcile_overhead(
            self,
            source: object,
            *,
            digest: str | None = None,
            authority: object | None = None,
        ):
            del source, digest
            received.append(("overhead", authority))
            return OverheadReceipt()

        def backfill_usage(
            self,
            catalog: object,
            *,
            cursor: str | None,
            limit: int,
            authority: object | None = None,
        ):
            del catalog, cursor, limit
            received.append(("backfill", authority))
            return UsageBackfillReceipt()

    publisher = Publisher()
    assert daemon._reconcile_publication_usage(publisher) is True
    daemon._control_loop_ledger = SimpleNamespace(list_overhead_usage=lambda: [])
    assert daemon._reconcile_publication_usage(publisher) is False
    assert received == [("overhead", authority), ("backfill", authority)]


def test_reconcile_publication_usage_passes_detached_mapping_to_publisher() -> None:
    daemon = object.__new__(StewardDaemon)
    daemon._publication_authority = object()
    row = StewardOverheadUsage(date="2026-07-28", model="gpt-test")
    daemon._control_loop_ledger = SimpleNamespace(list_overhead_usage=lambda: [row])
    daemon._publication_overhead_digest = None
    daemon._publication_overhead_position = 0
    daemon._log = lambda *_args, **_kwargs: None
    received: list[object] = []

    class Publisher:
        def reconcile_overhead(
            self,
            source: object,
            *,
            digest: str | None = None,
            authority: object | None = None,
        ):
            assert authority is daemon._publication_authority
            received.append(source)
            return OverheadReceipt()

    assert daemon._reconcile_publication_usage(Publisher()) is True
    assert received == [row.public_dict()]
    assert received[0] is not row


def test_reconcile_publication_usage_waits_after_overhead_provider_failure() -> None:
    daemon = object.__new__(StewardDaemon)
    daemon._publication_authority = object()
    row = StewardOverheadUsage(date="2026-07-28", model="gpt-test")
    daemon._control_loop_ledger = SimpleNamespace(list_overhead_usage=lambda: [row])
    daemon._publication_overhead_digest = None
    daemon._publication_overhead_position = 0
    daemon._log = lambda *_args, **_kwargs: None

    class Publisher:
        def reconcile_overhead(
            self,
            source: object,
            *,
            digest: str | None = None,
            authority: object | None = None,
        ) -> OverheadReceipt:
            assert authority is daemon._publication_authority
            del source, digest
            raise D1Error("network")

    assert daemon._reconcile_publication_usage(Publisher()) is False
    assert daemon._publication_overhead_digest is None
    assert daemon._publication_overhead_position == 0


def test_reconcile_publication_usage_waits_after_backfill_provider_failure() -> None:
    daemon = object.__new__(StewardDaemon)
    daemon._publication_authority = object()
    daemon._control_loop_ledger = SimpleNamespace(list_overhead_usage=lambda: [])
    daemon._control_loop_usage = SimpleNamespace(
        catalog=SimpleNamespace(digest="catalog-digest")
    )
    daemon._publication_backfill_catalog_digest = "catalog-digest"
    daemon._publication_backfill_cursor = "cursor-before"
    daemon._publication_backfill_blocked = False
    daemon._log = lambda *_args, **_kwargs: None

    class Publisher:
        def backfill_usage(
            self,
            catalog: object,
            *,
            cursor: str | None,
            limit: int,
            authority: object | None = None,
        ) -> UsageBackfillReceipt:
            assert authority is daemon._publication_authority
            del catalog, cursor, limit
            raise D1Error("network")

    assert daemon._reconcile_publication_usage(Publisher()) is False
    assert daemon._publication_backfill_cursor == "cursor-before"
    assert daemon._publication_backfill_blocked is False


@pytest.mark.parametrize("mode", ["normal", "resume", "fresh", "adopted-resume"])
@pytest.mark.parametrize("crash_at", ["success", "phase-finish", "receipt"])
def test_successful_unconsumed_result_converges_after_restart(config, monkeypatch, mode, crash_at):
    store = TaskStore.create(config.db_path)
    task, pipeline, original = _interrupted_run(config, store)
    task.worktree_path = config.repo_root
    store.save(task)
    store.start_worker(task.id, "implementation")
    store.begin_iteration(task.id, 0, "implementation", worker_name="implementation", worker_prompt_path=config.prompts_dir / "test.md", worker_transcript_path=config.logs_dir / "test.jsonl", worker_last_message_path=config.logs_dir / "test.md")
    store.add_event(task.id, "pipeline.phase.finished", "provisioned", {
        "pipeline_id": pipeline.id,
        "output": {"action_id": "provisioned", "next_phase": "implementation"},
    })
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    if mode == "normal":
        with store.engine.begin() as connection:
            connection.exec_driver_sql("UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?", (original.id,))
        completed = original
    elif mode in {"resume", "adopted-resume"}:
        completed = store.create_run(task.id, pipeline.id, original.session_id, role="implementation", resume_of_run_id=original.id, image_version=original.image_version, runtime_version=original.runtime_version, checkpoint_id=original.checkpoint_id, provider_store_identity=original.provider_store_identity)
    else:
        session = store.create_session(
            task.id, pipeline.id, cwd=config.repo_root,
            owner_role="implementation", idempotency_key=f"fresh-recovery:{original.id}",
        )
        completed = store.create_run(task.id, pipeline.id, session.id, role="implementation", retry_of_run_id=original.id)
    if mode == "adopted-resume":
        supervisor.live = True
        assert daemon.startup_reconcile()[0].disposition == "adopted"
        assert daemon._adopted_runs[task.id] == completed.id
    (config.repo_root / "README.md").write_text("completed patch\n", encoding="utf-8")
    result = supervisor._complete(completed)
    completed = store.get_run(completed.id)
    archive = TaskArchiveWriter(config)
    archive.materialize_ledger(store.get(task.id), pipeline, store.list_runs(task.id))
    (result.last_message_path.parent / "result.json").write_text(json.dumps({
        "status": "available", "summary": "completed", "path": None,
        "task_id": task.id, "pipeline_id": pipeline.id, "session_id": completed.session_id,
        "run_id": completed.id, "output_checkpoint": worktree_checkpoint(config, config.repo_root),
    }), encoding="utf-8")
    if crash_at != "success":
        target, method = (daemon.executor, "_phase_finish") if crash_at == "phase-finish" else (daemon, "_add_recovery_event_once")
        with monkeypatch.context() as patch:
            patch.setattr(target, method, lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit("crash")))
            with pytest.raises(SystemExit):
                daemon._complete_atomic_run_result(store.get(task.id), completed)
    if mode == "adopted-resume" and crash_at == "success":
        daemon._poll_adopted_runs()
        assert task.id not in daemon._adopted_runs
    restarted = StewardDaemon(config, TaskStore.open(config.db_path), session_supervisor=supervisor)
    for _ in range(3):
        outcome = restarted._reconcile_task(store.get(task.id))
        assert outcome.disposition in {"ingested", "unchanged"}, outcome
    assert restarted.executor._pipeline_cursor(task.id, pipeline.id) == PipelineCursorPhase.validation
    finishes = [event for event in store.events(task.id) if event.kind == "pipeline.phase.finished" and event.data.get("phase") == "implementation"]
    assert len(finishes) == 1
    assert len(store.list_runs(task.id)) == (1 if mode == "normal" else 2)
    assert not any(call[0] in {"resume", "recover"} for call in supervisor.calls)
    assert result.last_message_path.read_text() == "done\n"
    assert (config.repo_root / "README.md").read_text() == "completed patch\n"


@pytest.mark.parametrize("damage", ["missing-result", "missing-message", "missing-transcript", "wrong-run", "changed-tree"])
def test_unconsumed_success_fails_closed_without_exact_artifacts(config, damage):
    store = TaskStore.create(config.db_path)
    task, pipeline, run = _interrupted_run(config, store)
    task.worktree_path = config.repo_root
    store.save(task)
    with store.engine.begin() as connection:
        connection.exec_driver_sql("UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?", (run.id,))
    supervisor = FakeSupervisor(config, store)
    result = supervisor._complete(run)
    archive = TaskArchiveWriter(config)
    archive.materialize_ledger(task, pipeline, store.list_runs(task.id))
    if damage != "missing-result":
        (result.last_message_path.parent / "result.json").write_text(json.dumps({
            "status": "available", "task_id": task.id, "pipeline_id": pipeline.id,
            "session_id": run.session_id, "run_id": "wrong" if damage == "wrong-run" else run.id,
            "output_checkpoint": worktree_checkpoint(config, config.repo_root),
        }), encoding="utf-8")
    if damage == "missing-message":
        result.last_message_path.unlink()
    if damage == "missing-transcript":
        result.transcript_path.unlink()
    if damage == "changed-tree":
        (config.repo_root / "README.md").write_text("unowned edit\n", encoding="utf-8")
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    for _ in range(2):
        outcome = daemon._reconcile_task(store.get(task.id))
        assert outcome.disposition == "blocked"
        assert "incomplete result artifacts" in outcome.detail
    assert len(store.list_runs(task.id)) == 1
    assert not any(call[0] in {"resume", "recover"} for call in supervisor.calls)


@pytest.mark.parametrize("phase", ["planning", "review", "formality"])
def test_readonly_success_ingestion_does_not_duplicate_phase_evidence(config, monkeypatch, phase):
    role = {"planning": "planner", "review": "reviewer", "formality": "formality"}[phase]
    store = TaskStore.create(config.db_path)
    task, pipeline, original = _interrupted_run(config, store, role=role)
    task.worktree_path = config.repo_root
    if phase == "planning":
        task.spec.workflow = "feature"
    store.save(task)
    store.start_worker(task.id, "started")
    action = store.get_session(original.session_id).idempotency_key
    store.add_event(task.id, "pipeline.phase.finished", "provisioned", {"pipeline_id": pipeline.id, "output": {"action_id": "provisioned", "next_phase": phase}})
    store.add_event(task.id, "pipeline.phase.started", phase, {"pipeline_id": pipeline.id, "phase": phase, "action_id": action, "input": {"payload": {"attempt": 0}}})
    review = {"verdict": "approve", "summary": "ok", "findings": [], "validation_gaps": [], "remaining_risk": ""}
    if phase == "planning":
        store.begin_plan_run(task.id, 0, prompt_path=config.prompts_dir / "plan.md", transcript_path=config.logs_dir / "plan.jsonl", last_message_path=config.logs_dir / "plan.md", model=None, reasoning_effort=None)
    if phase == "formality":
        store.add_event(task.id, "pipeline.review.raw", "review", {"pipeline_id": pipeline.id, "review": review})
    with store.engine.begin() as connection:
        connection.exec_driver_sql("UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?", (original.id,))
    supervisor = FakeSupervisor(config, store)
    result = supervisor._complete(original)
    message = {
        "planning": {"summary": "plan", "assumptions": [], "steps": [{"title": "edit", "detail": "edit readme", "files": ["README.md"]}], "validation": ["test"], "risks": [], "non_goals": []},
        "review": review,
        "formality": {"dispositions": []},
    }[phase]
    result.last_message_path.write_text(json.dumps(message))
    archive = TaskArchiveWriter(config)
    archive.materialize_ledger(task, pipeline, store.list_runs(task.id))
    (result.last_message_path.parent / "result.json").write_text(json.dumps({
        "status": "available", "task_id": task.id, "pipeline_id": pipeline.id,
        "session_id": original.session_id, "run_id": original.id,
        "output_checkpoint": worktree_checkpoint(config, config.repo_root),
    }))
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    with monkeypatch.context() as patch:
        patch.setattr(daemon.executor, "_phase_finish", lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit("crash before receipt")))
        with pytest.raises(SystemExit):
            daemon._complete_atomic_run_result(task, store.get_run(original.id))
    restarted = StewardDaemon(config, TaskStore.open(config.db_path), session_supervisor=supervisor)
    assert restarted._reconcile_task(store.get(task.id)).disposition == "ingested"
    assert restarted._reconcile_task(store.get(task.id)).disposition == "unchanged"
    kind = {"planning": "pipeline.plan.result", "review": "pipeline.review.raw", "formality": "pipeline.formality.effective"}[phase]
    assert len(store.events(task.id, kinds=(kind,))) == 1
    assert len(store.list_runs(task.id)) == 1


@pytest.mark.parametrize("mode", ["start", "resume", "fresh"])
@pytest.mark.parametrize("crash_at", [None, "before-result", "after-result", "checkpoint", "changed-tree", "wrong-session"])
def test_real_session_result_recovers_once_or_fails_closed(config, monkeypatch, mode, crash_at):
    from coquic_steward.execution import session as session_module

    store = TaskStore.create(config.db_path)
    if mode == "start":
        task, pipeline = _task(store, "real completion recovery")
        original = None
        action = f"{task.id}:{pipeline.id}:implementation-0"
        store.add_event(task.id, "pipeline.phase.started", "implementation", {
            "pipeline_id": pipeline.id, "phase": "implementation", "action_id": action,
            "input": {"payload": {"iteration": 0}},
        })
    else:
        task, pipeline, original = _interrupted_run(config, store)
        action = store.get_session(original.session_id).idempotency_key
    task.worktree_path = config.repo_root
    store.save(task)
    store.start_worker(task.id, "implementation")
    store.begin_iteration(task.id, 0, "implementation", worker_name="implementation", worker_prompt_path=config.prompts_dir / "test.md", worker_transcript_path=config.logs_dir / "test.jsonl", worker_last_message_path=config.logs_dir / "test.md")
    store.add_event(task.id, "pipeline.phase.finished", "provisioned", {
        "pipeline_id": pipeline.id,
        "output": {"action_id": "provisioned", "next_phase": "implementation"},
    })
    calls = []

    class Invoker(LocalSessionInvoker):
        def invoke(self, request, *, append, observe, on_started, **kwargs):
            calls.append(request.run_id)
            on_started(ExecIdentity("fake", request.run_id, 4321, request.session_uid))
            (request.cwd / "README.md").write_text("completed real producer patch\n")
            request.output_last_message.write_text("done\n")
            append(b'{"type":"thread.started","thread_id":"private-provider-id"}\n')
            return InvocationOutcome(exit_code=0, stdout=b"", stderr=b"", incomplete_suffix=b"", events=(), provider_session_id="private-provider-id")

    supervisor = SessionSupervisor(config, store, invoker=Invoker(), image_digest=IMAGE, codex_identity="codex-test")
    if original is not None:
        supervisor.archive.materialize_ledger(task, pipeline, [original])
    before = worktree_checkpoint(config, config.repo_root)
    write = supervisor.archive.write_run_file

    def crash_write(task_id, pipeline_id, run_id, name, value):
        if name == "result.json" and crash_at == "before-result":
            raise SystemExit("crash before result")
        result = write(task_id, pipeline_id, run_id, name, value)
        if name == "result.json" and crash_at == "after-result":
            raise SystemExit("crash after result")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(supervisor.archive, "write_run_file", crash_write)
        if crash_at == "checkpoint":
            def checkpoint(*args):
                if calls:
                    raise SystemExit("checkpoint crash")
                return worktree_checkpoint(*args)
            patch.setattr(session_module, "worktree_checkpoint", checkpoint)

        def invoke():
            if mode == "resume":
                result = supervisor.resume(original.id, prompt="continue", checkpoint_id=before)
                assert result.category is ResumeCategory.success
                return result.result
            return supervisor.start(task.id, pipeline.id, role="implementation", prompt="complete", cwd=config.repo_root, checkpoint_id=before, idempotency_key=action if mode == "start" else f"fresh-recovery:{original.id}", retry_of_run_id=original.id if original else None)

        if crash_at in {"before-result", "after-result", "checkpoint"}:
            with pytest.raises(SystemExit):
                invoke()
        else:
            assert invoke().status is InvocationStatus.succeeded

    run = store.get_run(calls[0])
    assert run.state == "succeeded"
    result_path = supervisor.archive.task_path(task.id, f"pipelines/{pipeline.id}/runs/{run.id}/result.json")
    if crash_at not in {"before-result", "checkpoint"}:
        metadata = json.loads(result_path.read_text())
        assert (metadata["task_id"], metadata["pipeline_id"], metadata["session_id"], metadata["run_id"]) == (task.id, pipeline.id, run.session_id, run.id)
        assert metadata["output_checkpoint"] == worktree_checkpoint(config, config.repo_root) != before
        if crash_at == "wrong-session":
            metadata["session_id"] = "unowned-session"
            result_path.write_text(json.dumps(metadata))
    else:
        assert not result_path.exists()
    if crash_at == "changed-tree":
        (config.repo_root / "README.md").write_text("unowned edit\n")

    reopened = TaskStore.open(config.db_path)
    restarted_supervisor = SessionSupervisor(config, reopened, invoker=supervisor.invoker, image_digest=IMAGE, codex_identity="codex-test")
    restarted = StewardDaemon(config, reopened, session_supervisor=restarted_supervisor)
    blocked = crash_at in {"before-result", "checkpoint", "changed-tree", "wrong-session"}
    outcomes = [restarted._reconcile_task(reopened.get(task.id)) for _ in range(3)]
    assert [outcome.disposition for outcome in outcomes] == (["blocked"] * 3 if blocked else ["ingested", "unchanged", "unchanged"]), [(outcome.detail, outcome.evidence) for outcome in outcomes]
    assert restarted.executor._pipeline_cursor(task.id, pipeline.id) == (PipelineCursorPhase.implementation if blocked else PipelineCursorPhase.validation)
    finishes = [event for event in reopened.events(task.id) if event.kind == "pipeline.phase.finished" and event.data.get("phase") == "implementation"]
    assert len(finishes) == (0 if blocked else 1)
    assert len(calls) == 1
    assert len(reopened.list_runs(task.id)) == (1 if mode == "start" else 2)


@pytest.mark.parametrize("phase", ["compose", "transport"])
def test_daemon_built_publisher_cancels_admitted_work(config, tmp_path, monkeypatch, phase):
    import sys
    from coquic_steward.core.subprocesses import ProcessGroupCancellationOwner
    from coquic_steward.publication.cancellation import run_publication_process
    from coquic_steward.publication.generation import PublicationComposer
    from publication_harness import enabled_publication_config
    from test_cloud_publisher import _composed, _sqlite_generation, _sqlite_store, _SQLitePublicationProvider, IDENTITY

    config = replace(config, dry_run=False, publication=enabled_publication_config(tmp_path, "synthetic-token"))
    store = _sqlite_store(config.db_path)
    store.enqueue_publication(_sqlite_generation())
    daemon = StewardDaemon(config, store)
    entered = threading.Event()
    closed = threading.Event()
    owners = []
    registered = ProcessGroupCancellationOwner.register

    def register(owner, process):
        registered(owner, process)
        owners.append(owner)
        entered.set()

    class Stream:
        def write(self, data, timeout=None):
            pass

        def read(self, maximum, timeout=None):
            entered.set()
            assert closed.wait(5), "daemon must close the blocked transport"
            raise OSError("closed")

        def close(self):
            closed.set()

        def get_extra_info(self, name):
            return None

    class Backend:
        def connect_tcp(self, **kwargs):
            return Stream()

    r2 = _botocore_transport_double()
    provider = _SQLitePublicationProvider()
    r2.put_object = provider.put_object
    d1 = _d1_transport_double()
    d1._client._transport._pool._network_backend = Backend()
    monkeypatch.setattr(D1PublicationClient, "endpoint", property(lambda _: "http://publication.example.test/query"))
    d1.stage = lambda payload: d1._post([("SELECT 1", ())])
    d1.expose = lambda payload: pytest.fail("cancelled publication must never expose")
    monkeypatch.setattr(daemon_module, "R2Client", lambda **kwargs: r2)
    monkeypatch.setattr(daemon_module, "D1PublicationClient", lambda **kwargs: d1)
    monkeypatch.setattr(daemon, "_publication_source", lambda generation: {"stable": True})
    monkeypatch.setattr(daemon, "_reconcile_publication_usage", lambda publisher: False)
    if phase == "compose":
        monkeypatch.setattr(ProcessGroupCancellationOwner, "register", register)

    def compose(source, **kwargs):
        if phase == "compose":
            run_publication_process([sys.executable, "-c", "import time; time.sleep(60)"], capture_output=True, text=False, timeout=60, check=False, pass_fds=(), env={})
        return _composed()

    build = daemon._build_publication_publisher
    publishers = []

    def configured_builder():
        publisher = build()  # Exercise the actual daemon -> CloudPublisher wiring.
        publishers.append(publisher)
        publisher.compose = PublicationComposer(compose)
        return publisher

    monkeypatch.setattr(daemon, "_build_publication_publisher", configured_builder)
    previous_callback = store.on_change
    daemon.start_publication_worker()
    worker = daemon._publication_thread
    try:
        assert entered.wait(3)
        assert publishers[0].cancel_event is daemon._publication_stop
        before = store.get_publication_generation(IDENTITY.publication_id)
        receipts = store.list_publication_receipts(IDENTITY.publication_id)
        assert daemon.stop_publication_worker(deadline=time.monotonic() + 3)
        assert not worker.is_alive()
        assert store.on_change is previous_callback
        assert daemon._publication_cancel is None
        assert store.get_publication_generation(IDENTITY.publication_id) == before
        assert store.list_publication_receipts(IDENTITY.publication_id) == receipts
        assert provider.hide_attempts == 0
        if phase == "compose":
            assert owners and all(owner.active_count == 0 for owner in owners)
            assert provider.put_attempts == 0
        else:
            assert closed.is_set()
            assert provider.put_attempts == 1
    finally:
        closed.set()
        daemon.stop_publication_worker(deadline=time.monotonic() + 3)
        d1.close()
        store.engine.dispose()

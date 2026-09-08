from __future__ import annotations

import json
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.agents.invocation import InvocationOutcome
from coquic_steward.core.models import EffectActionKind
import coquic_steward.execution.session as session_module
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.session import LocalSessionInvoker, load_publication_snapshot
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.publication.atif import AtifSource
from coquic_steward.publication.generation import PublicationComposer, PublicationGeneration
from coquic_steward.publication.outbox import (
    CleanupIntent,
    CleanupState,
    PublicationOperationResult,
    PublicationOperationStatus,
    PublicationReceipt,
    PublicationRetryPolicy,
    ReceiptClass,
)
from coquic_steward.publication.publisher import (
    CloudPublisher,
    PublicationResult,
    PublicationStatus,
)
from coquic_steward.publication.r2 import private_original_key
from coquic_steward.storage import TaskStore
from publication_harness import enabled_publication_config as _enabled_publication_config
from publication_harness import enqueue_publication as _enqueue_publication


def test_missing_task_publication_effect_never_reaches_provider(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "missing-task.sqlite", dry_run=False)
    provider_calls: list[str] = []
    publisher = CloudPublisher(
        store,
        object(),
        object(),
        retry_policy=PublicationRetryPolicy(),
    )

    allowed, result = publisher._effect_call(
        "missing-task",
        action=EffectActionKind.publication_transport,
        action_id="publication-missing-task",
        target="publication",
        operation=lambda: provider_calls.append("provider") or object(),
    )

    assert allowed is False
    assert result is None
    assert provider_calls == []


class _EventStore:
    def __init__(self) -> None:
        self.items: list[SimpleNamespace] = []

    def add_event(self, task_id: str, kind: str, message: str, data: dict) -> None:
        self.items.append(SimpleNamespace(task_id=task_id, kind=kind, message=message, data=data))

    def events(self, task_id: str) -> list[SimpleNamespace]:
        return [item for item in self.items if item.task_id == task_id]

class _Worktrees:
    def __init__(self) -> None:
        self.removed = False

    def tree(self, _path: Path) -> str:
        return "validated-tree"

    def diff(self, _path: Path) -> str:
        if self.removed:
            raise RuntimeError("integration worktree removed")
        return "patch"

def _publication_graph(title: str) -> dict[str, object]:
    task_id = "task-publication-preflight"
    pipeline_id = "pipeline-publication-preflight"
    run_id = "run-publication-preflight"
    documents = {
        "codex.jsonl": (
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "message-1",
                        "type": "agent_message",
                        "text": "safe",
                    },
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        ),
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"event","schema_version":1,"sequence":1,'
            b'"source_event_id":"activity-1","activity":"investigate",'
            b'"summary":"Complete the task",'
            b'"recorded_at":"2026-07-28T12:00:00.100Z"}\n'
            b'{"record_type":"summary","schema_version":1,'
            b'"capture_state":"complete","recorded":1,"invalid":0,'
            b'"duplicate":0,"omitted":0,"truncated":false}\n'
        ),
        "telemetry.json": (
            b'{"schema_version":1,"provenance":"codex_exec",'
            b'"completeness":"complete","aggregate":{},'
            b'"cost":{"status":"unavailable"}}'
        ),
        "run.json": (
            b'{"taskId":"task-publication-preflight",'
            b'"pipelineId":"pipeline-publication-preflight",'
            b'"runId":"run-publication-preflight","role":"planning",'
            b'"state":"succeeded","startedAt":"2026-07-28T12:00:00.000Z",'
            b'"completedAt":"2026-07-28T12:00:01.000Z"}\n'
        ),
    }
    source = AtifSource(
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
    return {
        "task": {
            "taskId": task_id,
            "title": title,
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
        "runs": [source],
        "events": [
            {
                "taskId": task_id,
                "sequence": 1,
                "eventType": "completed",
                "occurredAt": "2026-07-28T12:00:01Z",
                "summary": "Planning completed",
            }
        ],
    }

def _scanner_composer(scanner: object) -> PublicationComposer:
    def compose(
        source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
        staging_root: Path | None = None,
        scanner_runner: object = None,
        scanner_timeout: float = 30.0,
        max_repair_passes: int = 2,
        ocr_runner: object = None,
        ocr_timeout: float = 30.0,
        price_catalog: object = None,
        generation_boundary: str | None = None,
        publication_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> object:
        del scanner_runner
        return session_module.compose_publication_generation(
            source,
            task=task,
            completed_runs=completed_runs,
            task_id=task_id,
            run_builder=run_builder,
            builder=builder,
            credential_sources=credential_sources,
            known_secrets=known_secrets,
            staging_root=staging_root,
            scanner_runner=scanner,
            scanner_timeout=scanner_timeout,
            max_repair_passes=max_repair_passes,
            ocr_runner=ocr_runner,
            ocr_timeout=ocr_timeout,
            price_catalog=price_catalog,
            generation_boundary=generation_boundary,
            publication_id=publication_id,
            idempotency_key=idempotency_key,
        )

    return PublicationComposer(compose)

def test_terminal_publication_receipts_match_immutable_generation(
    monkeypatch,
) -> None:
    graph = _publication_graph("terminal-receipts")
    graph["task"]["lifecycleState"] = "completed"
    graph["task"]["completedAt"] = "2026-07-28T12:00:01Z"
    from coquic_steward.publication.generation import compose_publication_generation

    composed = compose_publication_generation(
        graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(composed, PublicationGeneration)
    now = datetime.now(timezone.utc)
    durable = replace(
        composed.to_outbox(),
        state="exposed",
        updated_at=now,
        exposed_at=now,
    )
    receipts = [
        PublicationReceipt.public_receipt(
            item.sha256,
            item.byte_size,
            item.public_key,
            now,
            item.logical_path,
        )
        for item in composed.objects
    ]
    receipts.extend(
        PublicationReceipt.private_receipt(
            item.sha256,
            item.byte_size,
            private_original_key(item.task_id, item.run_id, item.sha256),
            now,
        )
        for item in composed.private_originals
    )

    class Store:
        def list_publication_receipts(self, _publication_id):
            return list(receipts)

    task = SimpleNamespace(id=durable.task_id, status="succeeded")
    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon._publication_source = lambda _generation: graph
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.compose_publication_generation",
        lambda *_args, **_kwargs: composed,
    )

    assert daemon._terminal_publication_receipts_verified(task, durable) == (
        True,
        "verified",
    )
    receipts.pop()
    assert daemon._terminal_publication_receipts_verified(task, durable) == (
        False,
        "receipt_mismatch",
    )

def test_terminal_verification_uses_daemon_credentials_for_canonical_identity(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.publication.generation import compose_publication_generation

    credential = "synthetic-credential-value"
    config = _enabled_publication_config(tmp_path, credential)
    graph = _publication_graph("terminal-credential")
    graph["task"]["lifecycleState"] = "completed"
    graph["task"]["completedAt"] = "2026-07-28T12:00:01Z"
    source = graph["runs"][0]
    source.documents["codex.jsonl"] = source.documents["codex.jsonl"].replace(
        b'"safe"', json.dumps(credential).encode("utf-8")
    )
    scanner = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b"")
    aware = compose_publication_generation(
        graph,
        scanner_runner=scanner,
        credential_sources=(config.d1_token_path,),
    )
    free = compose_publication_generation(
        graph,
        scanner_runner=scanner,
        credential_sources=(),
    )
    assert isinstance(aware, PublicationGeneration)
    assert isinstance(free, PublicationGeneration)
    assert len(aware.private_originals) == 1
    assert credential not in repr(aware.payload)
    assert aware.publication_id != free.publication_id

    now = datetime.now(timezone.utc)
    durable = replace(
        aware.to_outbox(),
        state="exposed",
        updated_at=now,
        exposed_at=now,
    )
    receipts = [
        PublicationReceipt.public_receipt(
            item.sha256,
            item.byte_size,
            item.public_key,
            now,
            item.logical_path,
        )
        for item in aware.objects
    ]
    receipts.extend(
        PublicationReceipt.private_receipt(
            item.sha256,
            item.byte_size,
            private_original_key(item.task_id, item.run_id, item.sha256),
            now,
        )
        for item in aware.private_originals
    )

    class Store:
        def list_publication_receipts(self, _publication_id):
            return list(receipts)

    daemon = object.__new__(StewardDaemon)
    daemon.config = SimpleNamespace(dry_run=False, publication=config)
    daemon.store = Store()
    daemon._publication_source = lambda _generation: graph
    calls: list[object] = []

    def compose(source: object, **kwargs: object) -> object:
        calls.append(kwargs.get("credential_sources"))
        kwargs["scanner_runner"] = scanner
        return compose_publication_generation(source, **kwargs)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.compose_publication_generation",
        compose,
    )

    assert daemon._terminal_publication_receipts_verified(
        SimpleNamespace(id=aware.task_id, status="succeeded"), durable
    ) == (True, "verified")
    assert calls == [
        (
            config.d1_token_path,
            config.r2_access_key_id_path,
            config.r2_secret_access_key_path,
        )
    ]

    free_durable = replace(
        free.to_outbox(),
        state="exposed",
        updated_at=now,
        exposed_at=now,
    )
    assert daemon._terminal_publication_receipts_verified(
        SimpleNamespace(id=free.task_id, status="succeeded"), free_durable
    ) == (False, "generation_mismatch")

def test_daemon_worker_rekeys_staging_before_remote_exposure(tmp_path: Path) -> None:
    from coquic_steward.publication.generation import compose_publication_generation

    credential = "synthetic-worker-credential"
    config = _enabled_publication_config(tmp_path, credential)
    graph = _publication_graph("worker-credential")
    graph["runs"][0].documents["codex.jsonl"] = graph["runs"][0].documents[
        "codex.jsonl"
    ].replace(b'"safe"', json.dumps(credential).encode("utf-8"))
    scanner = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b"")
    free = compose_publication_generation(
        graph,
        scanner_runner=scanner,
        credential_sources=(),
    )
    aware = compose_publication_generation(
        graph,
        scanner_runner=scanner,
        credential_sources=(
            config.d1_token_path,
            config.r2_access_key_id_path,
            config.r2_secret_access_key_path,
        ),
    )
    assert isinstance(free, PublicationGeneration)
    assert isinstance(aware, PublicationGeneration)
    assert free.publication_id != aware.publication_id

    store = TaskStore.create(tmp_path / "publication.sqlite")
    _enqueue_publication(store, free.to_outbox())

    class R2:
        def put_object(
            self, key, _content, _object_class, *, expected_sha256, expected_size
        ):
            return SimpleNamespace(
                key=key,
                sha256=expected_sha256,
                byte_size=expected_size,
            )

    class D1:
        def __init__(self) -> None:
            self.exposed_payload: object | None = None

        def stage(self, payload):
            return SimpleNamespace(
                publication_id=payload["publicationId"],
                task_id=payload["taskId"],
            )

        def expose(self, payload):
            self.exposed_payload = payload
            return SimpleNamespace(
                state="visible",
                publication_id=payload["publicationId"],
                task_id=payload["taskId"],
            )

    d1 = D1()
    compose_calls: list[object] = []
    scanner_composer = _scanner_composer(scanner)

    def counted_compose(source: object, **kwargs: object) -> object:
        result = scanner_composer(source, **kwargs)
        compose_calls.append(result)
        return result

    publisher = CloudPublisher(
        store,
        R2(),
        d1,
        worker_id="publication-test",
        compose=PublicationComposer(counted_compose),
        retry_policy=PublicationRetryPolicy(config.max_retries),
    )
    enqueued_candidates: list[object] = []
    enqueue_precomposed = publisher._enqueue_precomposed_repair

    def capture_enqueue(publication_id: str, generation: object) -> PublicationResult:
        enqueued_candidates.append(generation)
        return enqueue_precomposed(publication_id, generation)

    publisher._enqueue_precomposed_repair = capture_enqueue
    daemon = object.__new__(StewardDaemon)
    daemon.config = SimpleNamespace(dry_run=False, publication=config)
    daemon.store = store
    daemon.logger = None
    daemon._publication_source = lambda _generation: graph

    assert daemon._publish_next_generation(publisher) is True
    assert len(compose_calls) == 2
    assert len(enqueued_candidates) == 1
    assert enqueued_candidates[0] is compose_calls[1]
    queued = store.list_publication_generations()
    assert len(queued) == 1
    assert queued[0].publication_id == aware.publication_id
    assert store.get_publication_generation(free.publication_id) is None

    assert daemon._publish_next_generation(publisher) is True
    assert len(compose_calls) == 3
    exposed = store.get_publication_generation(aware.publication_id)
    assert exposed is not None
    assert exposed.state.value == "exposed"
    assert d1.exposed_payload is not None
    assert d1.exposed_payload["publicationId"] == aware.publication_id
    assert d1.exposed_payload["headIntent"]["publicationId"] == aware.publication_id
    assert len(store.list_publication_receipts(aware.publication_id)) == (
        len(aware.objects) + len(aware.private_originals)
    )

@pytest.mark.parametrize("older_reason", ("operator_blocked", "integrity"))
def test_daemon_restart_rekeys_later_staging_after_unrelated_blocked(
    tmp_path: Path, older_reason: str
) -> None:
    credential = "synthetic-restart-ordering-credential"
    config = _enabled_publication_config(tmp_path, credential)
    base_graph = _publication_graph("restart-ordering")

    def rewrite(value: object, replacements: dict[str, str]) -> object:
        if isinstance(value, AtifSource):
            return replace(
                value,
                run=rewrite(value.run, replacements),
                documents=rewrite(value.documents, replacements),
                artifacts=tuple(
                    rewrite(item, replacements) for item in value.artifacts
                ),
            )
        if isinstance(value, dict):
            return {
                key: rewrite(item, replacements) for key, item in value.items()
            }
        if isinstance(value, list):
            return [rewrite(item, replacements) for item in value]
        if isinstance(value, tuple):
            return tuple(rewrite(item, replacements) for item in value)
        if isinstance(value, bytes):
            for old, new in replacements.items():
                value = value.replace(old.encode(), new.encode())
            return value
        if isinstance(value, str):
            for old, new in replacements.items():
                value = value.replace(old, new)
            return value
        return value

    older_graph = rewrite(
        base_graph,
        {
            "task-publication-preflight": "task-older-unrelated",
            "pipeline-publication-preflight": "pipeline-older-unrelated",
            "run-publication-preflight": "run-older-unrelated",
        },
    )
    assert isinstance(older_graph, dict)
    later_graph = rewrite(base_graph, {})
    assert isinstance(later_graph, dict)
    source = later_graph["runs"][0]
    assert isinstance(source, AtifSource)
    credential_bytes = source.documents["codex.jsonl"].replace(
        b'"safe"', json.dumps(credential).encode("utf-8")
    )
    later_graph["runs"][0] = replace(
        source,
        documents={**source.documents, "codex.jsonl": credential_bytes},
    )

    scanner = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b"")
    older = session_module.compose_publication_generation(
        older_graph,
        scanner_runner=scanner,
        credential_sources=(),
    )
    later_free = session_module.compose_publication_generation(
        later_graph,
        scanner_runner=scanner,
        credential_sources=(),
    )
    later_aware = session_module.compose_publication_generation(
        later_graph,
        scanner_runner=scanner,
        credential_sources=(
            config.d1_token_path,
            config.r2_access_key_id_path,
            config.r2_secret_access_key_path,
        ),
    )
    assert isinstance(older, PublicationGeneration)
    assert isinstance(later_free, PublicationGeneration)
    assert isinstance(later_aware, PublicationGeneration)
    assert later_free.publication_id != later_aware.publication_id

    database = tmp_path / "publication-restart-ordering.sqlite"
    store = TaskStore.create(database)
    first_created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    _enqueue_publication(store,
        replace(older.to_outbox(), created_at=first_created, updated_at=first_created)
    )
    store.block_publication(
        older.publication_id,
        expected_state="queued",
        reason=older_reason,
        now=first_created,
    )
    later_created = first_created.replace(second=1)
    _enqueue_publication(store,
        replace(
            later_free.to_outbox(),
            created_at=later_created,
            updated_at=later_created,
        )
    )
    store.block_publication(
        later_free.publication_id,
        expected_state="queued",
        reason="integrity",
        now=later_created,
    )

    restarted = TaskStore.open(database)

    class Publisher:
        def __init__(self) -> None:
            self.publish_calls: list[object] = []
            self.enqueue_calls: list[tuple[object, object]] = []

        def compose(self, source: object, *, task_id: str, **kwargs: object):
            return session_module.compose_publication_generation(
                source,
                task_id=task_id,
                scanner_runner=scanner,
                **kwargs,
            )

        def publish(self, *args: object, **_kwargs: object) -> PublicationResult:
            self.publish_calls.append(args)
            return PublicationResult(PublicationStatus.blocked)

        def _enqueue_precomposed_repair(
            self,
            publication_id: object,
            generation: object,
        ) -> PublicationResult:
            self.enqueue_calls.append((publication_id, generation))
            if publication_id == older.publication_id:
                return PublicationResult(PublicationStatus.blocked)
            return PublicationResult(
                PublicationStatus.queued,
                publication_id=later_aware.publication_id,
            )

    daemon = object.__new__(StewardDaemon)
    daemon.config = SimpleNamespace(dry_run=False, publication=config)
    daemon.store = restarted
    daemon.logger = None
    source_calls: list[str] = []
    source_by_task = {
        older.task_id: older_graph,
        later_free.task_id: later_graph,
    }

    def publication_source(generation: object) -> object:
        source_calls.append(generation.publication_id)
        return source_by_task[generation.task_id]

    daemon._publication_source = publication_source
    publisher = Publisher()

    assert daemon._publish_next_generation(publisher) is True
    assert publisher.publish_calls == []
    expected_enqueue_ids = [later_free.publication_id]
    assert [call[0] for call in publisher.enqueue_calls] == expected_enqueue_ids
    assert publisher.enqueue_calls[0][1].publication_id == later_aware.publication_id
    expected_source_ids = (
        [older.publication_id, later_free.publication_id]
        if older_reason == "integrity"
        else [later_free.publication_id]
    )
    assert source_calls == expected_source_ids

    untouched = restarted.get_publication_generation(older.publication_id)
    assert untouched is not None
    assert untouched.state.value == "blocked"
    assert untouched.reason == older_reason
    later = restarted.get_publication_generation(later_free.publication_id)
    assert later is not None
    assert later.state.value == "blocked"
    assert later.reason == "integrity"

def test_daemon_restart_skips_unchanged_integrity_head_before_credential_rekey(
    tmp_path: Path,
) -> None:
    credential = "synthetic-restart-provider-credential"
    config = _enabled_publication_config(tmp_path, credential)
    base_graph = _publication_graph("restart-provider-ordering")

    def rewrite(value: object, replacements: dict[str, str]) -> object:
        if isinstance(value, AtifSource):
            return replace(
                value,
                run=rewrite(value.run, replacements),
                documents=rewrite(value.documents, replacements),
                artifacts=tuple(
                    rewrite(item, replacements) for item in value.artifacts
                ),
            )
        if isinstance(value, dict):
            return {
                key: rewrite(item, replacements) for key, item in value.items()
            }
        if isinstance(value, list):
            return [rewrite(item, replacements) for item in value]
        if isinstance(value, tuple):
            return tuple(rewrite(item, replacements) for item in value)
        if isinstance(value, bytes):
            for old, new in replacements.items():
                value = value.replace(old.encode(), new.encode())
            return value
        if isinstance(value, str):
            for old, new in replacements.items():
                value = value.replace(old, new)
            return value
        return value

    older_graph = rewrite(
        base_graph,
        {
            "task-publication-preflight": "task-restart-provider-older",
            "pipeline-publication-preflight": "pipeline-restart-provider-older",
            "run-publication-preflight": "run-restart-provider-older",
        },
    )
    assert isinstance(older_graph, dict)
    later_graph = rewrite(base_graph, {})
    assert isinstance(later_graph, dict)
    source = later_graph["runs"][0]
    assert isinstance(source, AtifSource)
    later_graph["runs"][0] = replace(
        source,
        documents={
            **source.documents,
            "codex.jsonl": source.documents["codex.jsonl"].replace(
                b'"safe"', json.dumps(credential).encode()
            ),
        },
    )

    scanner = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b"")
    older = session_module.compose_publication_generation(
        older_graph,
        scanner_runner=scanner,
        credential_sources=(),
    )
    later_free = session_module.compose_publication_generation(
        later_graph,
        scanner_runner=scanner,
        credential_sources=(),
    )
    later_aware = session_module.compose_publication_generation(
        later_graph,
        scanner_runner=scanner,
        credential_sources=(
            config.d1_token_path,
            config.r2_access_key_id_path,
            config.r2_secret_access_key_path,
        ),
    )
    assert isinstance(older, PublicationGeneration)
    assert isinstance(later_free, PublicationGeneration)
    assert isinstance(later_aware, PublicationGeneration)
    assert later_free.publication_id != later_aware.publication_id

    database = tmp_path / "publication-restart-provider.sqlite"
    store = TaskStore.create(database)
    first_created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    _enqueue_publication(store,
        replace(older.to_outbox(), created_at=first_created, updated_at=first_created)
    )
    store.block_publication(
        older.publication_id,
        expected_state="queued",
        reason="integrity",
        now=first_created,
    )
    later_created = first_created.replace(second=1)
    _enqueue_publication(store,
        replace(
            later_free.to_outbox(),
            created_at=later_created,
            updated_at=later_created,
        )
    )
    store.block_publication(
        later_free.publication_id,
        expected_state="queued",
        reason="integrity",
        now=later_created,
    )
    restarted = TaskStore.open(database)
    older_before = restarted.get_publication_generation(older.publication_id)
    assert older_before is not None

    class R2Recorder:
        def __init__(self) -> None:
            self.calls: list[object] = []

        def put_object(self, *args: object, **kwargs: object) -> object:
            self.calls.append(("put_object", args, kwargs))
            raise AssertionError("unexpected R2 publication call")

    class D1Recorder:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str]] = []
            self.heads = {older.task_id: older.publication_id}

        def hide_task(self, task_id: str, reason: str) -> object:
            self.calls.append(("hide_task", task_id, reason))
            previous = self.heads.pop(task_id, None)
            return SimpleNamespace(
                task_id=task_id,
                publication_id=previous,
                state="hidden",
                changed=previous is not None,
            )

    r2 = R2Recorder()
    d1 = D1Recorder()
    source_by_task = {
        older.task_id: older_graph,
        later_free.task_id: later_graph,
    }
    daemon = object.__new__(StewardDaemon)
    daemon.config = SimpleNamespace(dry_run=False, publication=config)
    daemon.store = restarted
    daemon.logger = None
    daemon._publication_source = lambda generation: source_by_task[generation.task_id]
    publisher = CloudPublisher(
        restarted,
        r2,
        d1,
        worker_id="publication-restart-provider",
        compose=_scanner_composer(scanner),
        retry_policy=PublicationRetryPolicy(config.max_retries),
    )

    assert daemon._publish_next_generation(publisher) is True
    assert r2.calls == []
    assert d1.calls == []
    assert d1.heads == {older.task_id: older.publication_id}
    assert restarted.get_publication_generation(older.publication_id) == older_before
    assert restarted.get_publication_generation(later_free.publication_id) is None
    later = restarted.get_publication_generation(later_aware.publication_id)
    assert later is not None
    assert later.state.value == "queued"

def test_terminal_gate_rejects_exposed_active_snapshot_until_terminal_generation(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.publication.generation import compose_publication_generation

    active_graph = _publication_graph("active-snapshot")
    active_composed = compose_publication_generation(
        active_graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(active_composed, PublicationGeneration)
    task = SimpleNamespace(
        id=active_composed.task_id,
        status="failed",
        updated_at=datetime(2026, 7, 28, 12, 1, tzinfo=timezone.utc),
    )
    run = SimpleNamespace(
        id=active_composed.run_id,
        state="succeeded",
        completed_at=datetime(2026, 7, 28, 12, 0, 1, tzinfo=timezone.utc),
    )
    daemon = object.__new__(StewardDaemon)
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    archive = session_module.TaskArchiveWriter(SimpleNamespace(tasks_dir=tasks_dir))
    archive.ensure_epoch()
    archive.task_dir(task.id).mkdir()
    assert session_module._write_publication_snapshot(
        SimpleNamespace(tasks_dir=tasks_dir),
        task.id,
        run.id,
        active_graph,
    )
    daemon.config = SimpleNamespace(
        dry_run=False,
        tasks_dir=tasks_dir,
        publication=SimpleNamespace(enabled=True),
    )
    daemon.executor = SimpleNamespace(
        _integration_publication_graph=lambda _task: active_graph,
    )
    terminal_run_id = daemon._terminal_publication_run_alias(task, run)
    assert terminal_run_id is not None and terminal_run_id != run.id
    assert daemon._prepare_terminal_publication_snapshot(task, run)
    terminal_graph = session_module.load_publication_snapshot(
        SimpleNamespace(tasks_dir=tasks_dir),
        task.id,
        terminal_run_id,
    )
    assert terminal_graph is not None
    assert session_module.load_publication_snapshot(
        SimpleNamespace(tasks_dir=tasks_dir), task.id, run.id
    )["task"]["lifecycleState"] == "active"
    terminal_composed = compose_publication_generation(
        terminal_graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(terminal_composed, PublicationGeneration)
    assert terminal_composed.publication_id != active_composed.publication_id

    now = datetime.now(timezone.utc)

    def receipts_for(composed: PublicationGeneration) -> list[PublicationReceipt]:
        values = [
            PublicationReceipt.public_receipt(
                item.sha256,
                item.byte_size,
                item.public_key,
                now,
                item.logical_path,
            )
            for item in composed.objects
        ]
        values.extend(
            PublicationReceipt.private_receipt(
                item.sha256,
                item.byte_size,
                private_original_key(item.task_id, item.run_id, item.sha256),
                now,
            )
            for item in composed.private_originals
        )
        return values

    active = replace(
        active_composed.to_outbox(),
        state="exposed",
        updated_at=now,
        exposed_at=now,
    )
    terminal = replace(
        terminal_composed.to_outbox(),
        state="queued",
        updated_at=now,
    )
    current = {"generation": terminal}
    receipts = {
        active.publication_id: receipts_for(active_composed),
        terminal.publication_id: receipts_for(terminal_composed),
    }

    class Store:
        def __init__(self) -> None:
            self.events_value: list[SimpleNamespace] = []

        def list_runs(self, _task_id):
            return [run]

        def get_publication_generation(self, _publication_id):
            return current["generation"]

        def list_publication_receipts(self, publication_id):
            return list(receipts[publication_id])

        def events(self, _task_id):
            return list(self.events_value)

        def add_event(self, task_id, kind, message, data=None):
            self.events_value.append(
                SimpleNamespace(
                    task_id=task_id,
                    kind=kind,
                    message=message,
                    data=data or {},
                )
            )

    store = Store()
    daemon.store = store
    daemon.logger = None
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.enqueue_materialized_publication",
        lambda _config, _store, _task, enqueue_run: _enqueue_terminal(
            enqueue_run, terminal.run_id, current["generation"]
        ),
    )
    daemon._publication_source = lambda generation: (
        active_graph
        if generation.publication_id == active.publication_id
        else terminal_graph
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.compose_publication_generation",
        lambda source, **_kwargs: (
            active_composed if source is active_graph else terminal_composed
        ),
    )

    assert daemon._terminal_publication_receipts_verified(task, active) == (
        False,
        "terminal_lifecycle_mismatch",
    )
    assert daemon._terminal_publication_gate(task) is False
    assert any(
        event.data.get("reason") == "final_generation_queued"
        for event in store.events_value
    )

    current["generation"] = replace(terminal, state="exposed", exposed_at=now)
    assert daemon._terminal_publication_gate(task) is True

def _enqueue_terminal(
    run: object, expected: str, generation: object
) -> PublicationOperationResult:
    assert getattr(run, "id", None) == expected
    return PublicationOperationResult(
        PublicationOperationStatus.enqueued,
        generation=generation,
    )

def test_materialized_success_enqueues_deterministically_without_transport(
    tmp_path: Path, monkeypatch,
) -> None:
    graph = _publication_graph("completion-boundary")
    # Build the valid immutable generation through the existing pure contract;
    # the session hook itself must only hand its outbox record to the store.
    from coquic_steward.publication.generation import compose_publication_generation

    scanner = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b"")
    generation = compose_publication_generation(graph, scanner_runner=scanner)
    assert isinstance(generation, PublicationGeneration)
    compose_calls: list[dict[str, object]] = []

    def compose(*_args, **kwargs: object) -> object:
        compose_calls.append(kwargs)
        return generation

    monkeypatch.setattr(session_module, "publication_graph_for_task", lambda *_args: graph)
    monkeypatch.setattr(session_module, "compose_publication_generation", compose)

    queued: list[object] = []
    store = SimpleNamespace(enqueue_publication=lambda value: queued.append(value) or value)
    staging_root = tmp_path / "publication-staging"
    staging_root.mkdir(mode=0o700)
    config = SimpleNamespace(
        dry_run=False,
        publication=SimpleNamespace(enabled=True, staging_root=staging_root),
    )
    task = SimpleNamespace(id="task-publication-preflight")
    run = SimpleNamespace(
        state="succeeded", completed_at=datetime.now(timezone.utc)
    )

    first = session_module.enqueue_materialized_publication(config, store, task, run)
    second = session_module.enqueue_materialized_publication(config, store, task, run)

    assert first.publication_id == generation.publication_id
    assert second.publication_id == generation.publication_id
    assert [item.publication_id for item in queued] == [
        generation.publication_id,
        generation.publication_id,
    ]
    assert [call["staging_root"] for call in compose_calls] == [
        staging_root,
        staging_root,
    ]

    run.state = "running"
    assert session_module.enqueue_materialized_publication(config, store, task, run) is None

def test_materialized_publication_uses_immutable_snapshot_after_graph_changes(
    tmp_path: Path, monkeypatch
) -> None:
    graph = _publication_graph("original-title")
    from coquic_steward.publication.generation import compose_publication_generation

    generation = compose_publication_generation(
        graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(generation, PublicationGeneration)
    observed_titles: list[str] = []

    def compose(source: object, **_kwargs: object) -> object:
        assert isinstance(source, dict)
        if source["task"]["title"] != "original-title":
            raise AssertionError("mutable graph was used for publication")
        observed_titles.append(source["task"]["title"])
        return generation

    monkeypatch.setattr(session_module, "publication_graph_for_task", lambda *_args: graph)
    monkeypatch.setattr(session_module, "compose_publication_generation", compose)
    queued: list[object] = []
    config = SimpleNamespace(
        dry_run=False,
        tasks_dir=tmp_path / "tasks",
        publication=SimpleNamespace(enabled=True),
    )
    store = SimpleNamespace(enqueue_publication=lambda value: queued.append(value) or value)
    task = SimpleNamespace(id="task-publication-preflight")
    run = SimpleNamespace(
        id="run-publication-preflight",
        state="succeeded",
        completed_at=datetime.now(timezone.utc),
    )

    first = session_module.enqueue_materialized_publication(config, store, task, run)
    graph["task"]["title"] = "mutated-title"
    second = session_module.enqueue_materialized_publication(config, store, task, run)

    assert first.publication_id == generation.publication_id
    assert second.publication_id == generation.publication_id
    assert observed_titles == ["original-title", "original-title"]
    snapshot = load_publication_snapshot(
        config, task.id, run.id
    )
    assert snapshot is not None
    assert snapshot["task"]["title"] == "original-title"

    daemon = object.__new__(StewardDaemon)
    daemon.config = config
    daemon.store = SimpleNamespace(get=lambda _task_id: task)
    daemon.executor = SimpleNamespace(_integration_publication_graph=lambda _task: graph)
    daemon.logger = None
    source = daemon._publication_source(queued[0])
    assert source["task"]["title"] == "original-title"

def test_verified_cleanup_intent_rejects_replaced_archive_before_delete(tmp_path: Path) -> None:
    task_id = "task-cleanup-replacement"
    tasks_dir = tmp_path / "tasks"
    archive = TaskArchiveWriter(SimpleNamespace(tasks_dir=tasks_dir))

    def build_sealed_archive(completion_identity: str) -> str:
        archive.create_task(task_id, "prompt", pipeline_id="pipeline-cleanup")
        archive.materialize_pipeline(
            task_id,
            {
                "pipelineId": "pipeline-cleanup",
                "taskId": task_id,
                "runs": [
                    {
                        "runId": "run-cleanup",
                        "role": "implementation",
                        "roleOrdinal": 1,
                        "state": "succeeded",
                        "path": "pipelines/pipeline-cleanup/runs/run-cleanup/run.json",
                    }
                ],
            },
        )
        archive.materialize_run(
            task_id,
            "pipeline-cleanup",
            {
                "runId": "run-cleanup",
                "taskId": task_id,
                "pipelineId": "pipeline-cleanup",
                "role": "implementation",
                "roleOrdinal": 1,
                "state": "succeeded",
                "completedAt": "2026-07-22T00:00:02Z",
            },
        )
        pipeline_path = archive.task_path(
            task_id, "pipelines/pipeline-cleanup/pipeline.json"
        )
        pipeline = json.loads(pipeline_path.read_text())
        pipeline.update(state="succeeded", completedAt="2026-07-22T00:00:03Z")
        archive.write_json(task_id, "pipelines/pipeline-cleanup/pipeline.json", pipeline)
        task_path = archive.task_path(task_id, "task.json")
        task = json.loads(task_path.read_text())
        task["status"] = "succeeded"
        archive.write_json(task_id, "task.json", task)
        archive.seal(
            task_id,
            "succeeded",
            completion_identity=completion_identity,
            completed_at="2026-07-22T00:00:04Z",
            external_actions_complete=True,
            writer_final=True,
        )
        return archive.manifest_digest(task_id)

    expected_digest = build_sealed_archive("completion-cleanup-a")
    archive.task_dir(task_id).rename(tmp_path / "archive-a")
    replacement_digest = build_sealed_archive("completion-cleanup-b")
    assert replacement_digest != expected_digest

    class CleanupStore:
        def __init__(self) -> None:
            self.blocked: list[tuple[str, str]] = []
            self.completed: list[str] = []

        def verify_cleanup_intent(self, *_args: object, **_kwargs: object):
            raise AssertionError("verified cleanup intent must not be re-verified")

        def block_cleanup_intent(self, intent_id: str, *, reason: str):
            self.blocked.append((intent_id, reason))
            return PublicationOperationResult(PublicationOperationStatus.blocked)

        def complete_cleanup_intent(self, intent_id: str, **_kwargs: object):
            self.completed.append(intent_id)
            return PublicationOperationResult(PublicationOperationStatus.completed)

    store = CleanupStore()
    daemon = object.__new__(StewardDaemon)
    daemon.store = store
    daemon._log = lambda _message: None
    now = datetime.now(timezone.utc)
    intent = CleanupIntent(
        task_id=task_id,
        publication_id="publication-cleanup-replacement",
        manifest_digest=expected_digest,
        exact_path=str(archive.task_dir(task_id)),
        requested_at=now,
        state=CleanupState.pending,
        verified_at=now,
    )

    assert daemon._delete_terminal_archive(
        SimpleNamespace(id=task_id),
        archive,
        intent,
    ) is False
    assert archive.task_dir(task_id).is_dir()
    assert store.blocked == [(intent.intent_id, "cleanup_failed")]
    assert store.completed == []

def test_session_completion_enqueues_every_materialized_revision(config, tmp_path: Path) -> None:
    completed_ids: list[str] = []

    class Archive:
        def task_path(self, _task_id: str, relative: str) -> Path:
            return tmp_path / relative

        def append_run_jsonl(self, *_args: object, **_kwargs: object) -> None:
            return None

        def write_run_file(
            self,
            _task_id: str,
            _pipeline_id: str,
            run_id: str,
            name: str,
            value: object,
        ) -> Path:
            path = tmp_path / "archive" / run_id / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, dict):
                path.write_text(json.dumps(value), encoding="utf-8")
            elif isinstance(value, str):
                path.write_text(value, encoding="utf-8")
            else:
                path.write_bytes(value)
            return path

        def materialize_run(self, *_args: object, **_kwargs: object) -> None:
            return None

    class Store:
        def __init__(self, run: SimpleNamespace) -> None:
            self.run = run

        def transition_run(self, _run_id: str, state: str, **_kwargs: object) -> None:
            self.run.state = state
            self.run.completed_at = datetime.now(timezone.utc)

        def get_run(self, _run_id: str) -> SimpleNamespace:
            return self.run

    class Invoker(LocalSessionInvoker):
        def __init__(self) -> None:
            super().__init__()

        def invoke(
            self,
            _request: object,
            *,
            api_key,
            append,
            observe=None,
            on_started=None,
            timeout_seconds,
            interrupt_grace_seconds,
            launch_gate=None,
        ) -> InvocationOutcome:
            return InvocationOutcome(
                provider_session_id=None,
                interrupted=False,
                forced=False,
                exit_code=0,
                stdout=b"",
                stderr=b"",
                events=(),
                incomplete_suffix=b"",
                malformed_lines=0,
            )

    for role in ("implementation", "review", "validation", "integration"):
        run_id = f"run-{role}"
        run = SimpleNamespace(
            id=run_id,
            pipeline_id="pipeline-revisions",
            state="running",
            completed_at=None,
            exit_reason=None,
        )
        store = Store(run)
        supervisor = object.__new__(session_module.SessionSupervisor)
        supervisor.archive = Archive()
        supervisor.store = store
        supervisor.config = config
        supervisor._active = {}
        supervisor._active_lock = threading.RLock()
        supervisor._enqueue_completed_run = lambda _task, saved: completed_ids.append(
            saved.id
        )
        task = SimpleNamespace(id=f"task-{role}")
        session = SimpleNamespace(id=f"session-{role}", checkpoint_id=None, private_home_path=None)
        request = SimpleNamespace(cwd=config.repo_root, output_last_message=tmp_path / f"private-{role}.md")

        supervisor._execute(
            task,
            session,
            run,
            request,
            runtime=None,
            invoker=Invoker(),
            api_key=None,
            timeout_seconds=1.0,
        )

    assert completed_ids == ["run-implementation", "run-review", "run-validation", "run-integration"]

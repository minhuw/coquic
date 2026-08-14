from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from typer.testing import CliRunner

from coquic_steward import cli
from coquic_steward.cli import app
from coquic_steward.publication.d1 import HideReceipt
from coquic_steward.publication.models import FailClosed, ReasonCode
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    PublicationGeneration,
    PublicationOperationStatus,
    PublicationState,
    ReceiptClass,
)
from coquic_steward.publication.publisher import (
    CloudPublisher,
    PublicationHideResult,
    PublicationHideStatus,
    PublicationResult,
    PublicationStatus,
    publication_generation_views,
    publication_health_view,
)
from coquic_steward.storage import TaskStore


NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _generation(*, publication_id: str = "pub-current", state: str = "blocked"):
    return SimpleNamespace(
        publication_id=publication_id,
        task_id="task-current",
        run_id="run-current",
        state=state,
        reason="unsafe_content" if state == "blocked" else None,
        metadata_digest="a" * 64,
        attempt=2,
        rows=5,
        objects=2,
        tasks=1,
        pipelines=1,
        runs=1,
        events=1,
        artifacts=1,
        updated_at=NOW - timedelta(minutes=2),
        lease_owner=None,
    )


def _blocked_store(tmp_path):
    store = TaskStore(tmp_path / "steward.sqlite")
    identity = GenerationIdentity("task-retry-hide", "boundary-retry-hide")
    generation = PublicationGeneration(
        publication_id=identity.publication_id,
        task_id="task-retry-hide",
        run_id="run-retry-hide",
        generation_boundary="boundary-retry-hide",
        metadata_digest="a" * 64,
        idempotency_key=identity.idempotency_key,
        created_at=NOW,
        updated_at=NOW,
    )
    assert store.enqueue_publication(generation).status is PublicationOperationStatus.enqueued
    assert store.claim_publication("worker-1", publication_id=generation.publication_id, now=NOW).status is PublicationOperationStatus.claimed
    assert store.block_publication(
        generation.publication_id,
        expected_state=PublicationState.claimed,
        lease_owner="worker-1",
        reason="unsafe_content",
        now=NOW + timedelta(seconds=1),
    ).status is PublicationOperationStatus.blocked
    return store, generation


def test_status_and_list_are_bounded_and_public_safe(monkeypatch) -> None:
    health = SimpleNamespace(
        queued_count=1,
        blocked_count=2,
        cleanup_pending_count=3,
        cleanup_pending_bytes=4,
        oldest_queued_at=NOW - timedelta(seconds=30),
        updated_at=NOW - timedelta(seconds=10),
        reason=None,
        last_category="success",
    )
    generation = _generation()

    class Store:
        def get_publication_health(self, *, now: datetime | None = None):
            return health

        def list_publication_generations(
            self,
            *,
            task_id: str | None = None,
            states: set[PublicationState | str] | None = None,
            limit: int | None = None,
        ):
            assert limit == 1
            return [generation]

        def list_publication_receipts(self, publication_id):
            assert publication_id == generation.publication_id
            return [
                SimpleNamespace(receipt_class=ReceiptClass.public),
                SimpleNamespace(
                    receipt_class=ReceiptClass.private,
                    content_key="private/locator-must-not-print",
                ),
            ]

    monkeypatch.setattr(cli, "_context", lambda: (Store(), SimpleNamespace()))
    status = CliRunner().invoke(app, ["publication", "status"])
    assert status.exit_code == 0, status.output
    status_payload = json.loads(status.output)
    assert status_payload["queuedCount"] == 1
    assert status_payload["blockedCount"] == 2
    assert status_payload["cleanupPendingCount"] == 3
    assert status_payload["cleanupPendingBytes"] == 4
    assert status_payload["oldestQueuedAgeSeconds"] >= 0
    assert status_payload["updatedAgeSeconds"] >= 0
    assert status_payload["reason"] is None
    assert status_payload["reasonCodes"] == []
    listed = CliRunner().invoke(app, ["publication", "list", "--limit", "1"])
    assert listed.exit_code == 0, listed.output
    payload = json.loads(listed.output)[0]
    assert payload["receiptClasses"] == ["private", "public"]
    assert "private/locator" not in listed.output
    assert "generationBoundary" not in listed.output


def test_retry_enqueues_changed_generation_and_refuses_unchanged() -> None:
    current = _generation()
    replaced: list[tuple[str, object]] = []

    class Store:
        def get_publication_generation(self, publication_id):
            return current if publication_id == current.publication_id else None

        def replace_blocked_publication(self, publication_id, value):
            replaced.append((publication_id, value))
            return SimpleNamespace(status="enqueued")

    changed = SimpleNamespace(
        publication_id="pub-repaired",
        task_id=current.task_id,
        metadata_digest="b" * 64,
        outbox_record=SimpleNamespace(publication_id="pub-repaired"),
        generation={},
        payload={},
        objects=(),
        private_originals=(),
        run_id="run-current",
        generation_boundary="boundary-repaired",
        idempotency_key="gen-repaired",
    )
    publisher = CloudPublisher(Store(), object(), object(), compose=lambda *_a, **_k: changed)
    result = publisher.retry_publication(current.publication_id, {"fresh": True})
    assert result.status is PublicationStatus.queued
    assert replaced == [(current.publication_id, changed.outbox_record)]

    unchanged = SimpleNamespace(**{**changed.__dict__, "publication_id": current.publication_id, "metadata_digest": "a" * 64})
    publisher = CloudPublisher(Store(), object(), object(), compose=lambda *_a, **_k: unchanged)
    result = publisher.retry_publication(current.publication_id, {"fresh": True})
    assert result.status is PublicationStatus.blocked
    assert result.reason == "unchanged"


def test_retry_result_carries_confirmed_hide_and_cli_closes_d1(monkeypatch) -> None:
    current = _generation()
    closed: list[bool] = []
    calls: list[tuple[str, object, object]] = []

    class Store:
        def get_publication_generation(self, publication_id):
            return current if publication_id == current.publication_id else None

    class Client:
        def close(self):
            closed.append(True)

    hidden = PublicationHideResult(
        PublicationHideStatus.hidden,
        task_id=current.task_id,
        publication_id=current.publication_id,
        reason="unsafe_content",
        changed=True,
    )
    publisher = SimpleNamespace(
        retry_publication=lambda publication_id, source, *, compose_kwargs: (
            calls.append((publication_id, source, compose_kwargs))
            or PublicationResult(
                PublicationStatus.blocked,
                publication_id=publication_id,
                reason="unsafe_content",
                reason_codes=(ReasonCode.unsafe_content,),
                hide_result=hidden,
            )
        )
    )
    config = SimpleNamespace(publication=SimpleNamespace(enabled=True))
    monkeypatch.setattr(cli, "_context", lambda: (Store(), config))
    monkeypatch.setattr(cli, "_current_publication_source", lambda *_args: {"fresh": True})
    monkeypatch.setattr(cli, "_build_cli_hide_publisher", lambda *_args: (publisher, Client()))

    result = CliRunner().invoke(app, ["publication", "retry", current.publication_id])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "blocked"
    assert payload["hide"] == {
        "status": "hidden",
        "taskId": current.task_id,
        "publicationId": current.publication_id,
        "reason": "unsafe_content",
        "changed": True,
    }
    assert calls and calls[0][0] == current.publication_id
    assert closed == [True]


def test_retry_hide_provider_failure_is_typed_and_pending(tmp_path) -> None:
    store, generation = _blocked_store(tmp_path)

    class D1:
        def hide_task(self, _task_id, _reason):
            raise RuntimeError("private provider detail")

    publisher = CloudPublisher(
        store,
        object(),
        D1(),
        now=NOW + timedelta(seconds=2),
        compose=lambda *_args, **_kwargs: FailClosed((ReasonCode.unsafe_content,)),
    )
    result = publisher.retry_publication(generation.publication_id, {"fresh": True})

    assert result.status is PublicationStatus.blocked
    assert result.hide_result is not None
    assert result.hide_result.status is PublicationHideStatus.blocked
    assert result.hide_result.reason == "provider"
    assert store.get_publication_hide(generation.task_id).state.value == "pending"
    assert "private provider detail" not in json.dumps(result.as_dict())


def test_retry_hide_invalid_receipt_is_typed_and_pending(tmp_path) -> None:
    store, generation = _blocked_store(tmp_path)

    class D1:
        def hide_task(self, task_id, _reason):
            return SimpleNamespace(
                task_id=task_id,
                publication_id=generation.publication_id,
                state="visible",
                changed=True,
            )

    publisher = CloudPublisher(
        store,
        object(),
        D1(),
        now=NOW + timedelta(seconds=2),
        compose=lambda *_args, **_kwargs: FailClosed((ReasonCode.unsafe_content,)),
    )
    result = publisher.retry_publication(generation.publication_id, {"fresh": True})

    assert result.hide_result is not None
    assert result.hide_result.status is PublicationHideStatus.blocked
    assert result.hide_result.reason == "integrity"
    assert store.get_publication_hide(generation.task_id).state.value == "pending"


def test_retry_missing_publication_configuration_is_bounded(monkeypatch) -> None:
    current = _generation()

    class Store:
        def get_publication_generation(self, publication_id):
            return current if publication_id == current.publication_id else None

        def begin_publication_hide(
            self,
            task_id,
            reason="operator_blocked",
            *,
            now=None,
            generation_boundary=None,
        ):
            assert task_id == current.task_id
            return SimpleNamespace(
                status=PublicationOperationStatus.enqueued,
                fence=SimpleNamespace(state="pending"),
            )

    config = SimpleNamespace(publication=SimpleNamespace(enabled=False))
    monkeypatch.setattr(cli, "_context", lambda: (Store(), config))
    monkeypatch.setattr(cli, "_current_publication_source", lambda *_args: {"fresh": True})

    result = CliRunner().invoke(app, ["publication", "retry", current.publication_id])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload == {
        "status": "blocked",
        "publicationId": current.publication_id,
        "reason": "precondition",
        "reasonCodes": ["precondition"],
        "hide": {
            "status": "blocked",
            "taskId": current.task_id,
            "publicationId": None,
            "reason": "precondition",
            "changed": False,
        },
    }


def test_retry_without_provider_fences_all_same_task_generations(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    generations = []
    for index in range(2):
        identity = GenerationIdentity("task-disabled", f"boundary-disabled-{index}")
        generation = PublicationGeneration(
            publication_id=identity.publication_id,
            task_id="task-disabled",
            run_id=f"run-disabled-{index}",
            generation_boundary=identity.generation_boundary,
            metadata_digest=f"{index:064x}",
            idempotency_key=identity.idempotency_key,
            created_at=NOW + timedelta(seconds=index),
            updated_at=NOW + timedelta(seconds=index),
        )
        assert store.enqueue_publication(generation).status is PublicationOperationStatus.enqueued
        generations.append(generation)

    assert store.claim_publication(
        "worker-1",
        publication_id=generations[0].publication_id,
        now=NOW,
    ).status is PublicationOperationStatus.claimed
    assert store.block_publication(
        generations[0].publication_id,
        expected_state=PublicationState.claimed,
        lease_owner="worker-1",
        reason="missing",
        now=NOW + timedelta(seconds=1),
    ).status is PublicationOperationStatus.blocked

    result = CloudPublisher(
        store,
        None,
        None,
        now=NOW + timedelta(seconds=2),
    ).retry_publication(generations[0].publication_id, None)

    assert result.status is PublicationStatus.blocked
    assert result.reason == "missing"
    assert result.hide_result is not None
    assert result.hide_result.reason == "precondition"
    fence = store.get_publication_hide("task-disabled")
    assert fence is not None
    assert fence.state.value == "pending"
    persisted = store.list_publication_generations(task_id="task-disabled", limit=None)
    assert [item.state for item in persisted] == [PublicationState.blocked, PublicationState.blocked]
    assert store.claim_publication(
        "worker-2",
        now=NOW + timedelta(seconds=3),
    ).status is PublicationOperationStatus.empty


def test_retry_real_store_replaces_changed_same_run_evidence(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    old_identity = GenerationIdentity("task-retry", "boundary-old")
    old = PublicationGeneration(
        publication_id=old_identity.publication_id,
        task_id="task-retry",
        run_id="run-retry",
        generation_boundary="boundary-old",
        metadata_digest="a" * 64,
        idempotency_key=old_identity.idempotency_key,
        created_at=NOW,
        updated_at=NOW,
    )
    assert store.enqueue_publication(old).status is PublicationOperationStatus.enqueued
    assert store.claim_publication("worker-1", publication_id=old.publication_id, now=NOW).status is PublicationOperationStatus.claimed
    assert store.block_publication(
        old.publication_id,
        expected_state=PublicationState.claimed,
        lease_owner="worker-1",
        reason="scanner_failure",
        now=NOW + timedelta(seconds=1),
    ).status is PublicationOperationStatus.blocked

    new_identity = GenerationIdentity("task-retry", "boundary-new")
    repaired = PublicationGeneration(
        publication_id=new_identity.publication_id,
        task_id="task-retry",
        run_id="run-retry",
        generation_boundary="boundary-new",
        metadata_digest="b" * 64,
        idempotency_key=new_identity.idempotency_key,
        created_at=NOW + timedelta(seconds=2),
        updated_at=NOW + timedelta(seconds=2),
    )
    composed = SimpleNamespace(
        publication_id=repaired.publication_id,
        task_id=repaired.task_id,
        run_id=repaired.run_id,
        generation_boundary=repaired.generation_boundary,
        metadata_digest=repaired.metadata_digest,
        idempotency_key=repaired.idempotency_key,
        generation={},
        payload={},
        objects=(),
        private_originals=(),
        outbox_record=repaired,
    )
    publisher = CloudPublisher(
        store,
        object(),
        object(),
        compose=lambda *_args, **_kwargs: composed,
    )
    result = publisher.retry_publication(old.publication_id, {"fresh": True})
    assert result.status is PublicationStatus.queued
    assert result.publication_id == repaired.publication_id
    assert store.get_publication_generation(old.publication_id) is None
    assert store.get_publication_generation(repaired.publication_id).state is PublicationState.queued


def test_hide_real_store_blocks_101_queued_generations_and_replays(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    generations = []
    for index in range(101):
        boundary = f"boundary-hide-{index}"
        identity = GenerationIdentity("task-hide", boundary)
        generation = PublicationGeneration(
            publication_id=identity.publication_id,
            task_id="task-hide",
            run_id=f"run-hide-{index}",
            generation_boundary=boundary,
            metadata_digest=f"{index:064x}",
            idempotency_key=identity.idempotency_key,
            created_at=NOW,
            updated_at=NOW,
        )
        assert store.enqueue_publication(generation).status is PublicationOperationStatus.enqueued
        generations.append(generation)

    class D1:
        changed = True

        def hide_task(self, task_id, reason):
            result = HideReceipt(
                task_id,
                generations[0].publication_id,
                changed=self.changed,
            )
            self.changed = False
            return result

    publisher = CloudPublisher(store, object(), D1(), now=NOW + timedelta(seconds=1))
    hidden = publisher.hide_task(generation.task_id, "unsafe_content")
    assert hidden.status is PublicationHideStatus.hidden
    assert hidden.changed is True
    persisted = store.list_publication_generations(task_id="task-hide", limit=None)
    assert len(persisted) == 101
    assert all(item.state is PublicationState.blocked for item in persisted)
    assert all(item.reason == "unsafe_content" for item in persisted)
    assert (
        store.claim_publication(
            "worker-1",
            now=NOW + timedelta(seconds=2),
        ).status
        is PublicationOperationStatus.empty
    )

    replay = publisher.hide_task("task-hide", "unsafe_content")
    assert replay.status is PublicationHideStatus.unchanged
    assert replay.changed is False
    replayed = store.list_publication_generations(task_id="task-hide", limit=None)
    assert len(replayed) == 101
    assert all(item.state is PublicationState.blocked for item in replayed)


def test_retry_fail_closed_and_hide_are_safe_and_idempotent() -> None:
    current = _generation()

    class Store:
        def get_publication_generation(self, _publication_id):
            return current

        def list_publication_generations(
            self,
            *,
            task_id: str | None = None,
            states: set[PublicationState | str] | None = None,
            limit: int | None = None,
        ):
            assert task_id == current.task_id
            return [current]

        def begin_publication_hide(
            self,
            task_id,
            reason="operator_blocked",
            *,
            now=None,
            generation_boundary=None,
        ):
            return SimpleNamespace(
                status=PublicationOperationStatus.enqueued,
                fence=SimpleNamespace(state="pending"),
            )

        def confirm_publication_hide(
            self,
            task_id,
            *,
            reason=None,
            confirmed_at=None,
            now=None,
        ):
            return SimpleNamespace(status=PublicationOperationStatus.verified)

        def block_publication(self, *_args, **_kwargs):
            return SimpleNamespace(status="blocked")

    publisher = CloudPublisher(
        Store(),
        object(),
        SimpleNamespace(
            hide_task=lambda task_id, reason: HideReceipt(
                task_id,
                current.publication_id,
                changed=True,
            )
        ),
        compose=lambda *_a, **_k: FailClosed((ReasonCode.unsafe_content,)),
    )
    result = publisher.retry_publication(current.publication_id, {"fresh": True})
    assert result.status is PublicationStatus.blocked
    assert result.reason == ReasonCode.unsafe_content.value

    hidden = publisher.hide_task(current.task_id, "unsafe_content")
    assert hidden.status is PublicationHideStatus.hidden
    assert hidden.changed is True

    publisher.d1.hide_task = lambda task_id, reason: HideReceipt(
        task_id,
        current.publication_id,
        changed=False,
    )
    replay = publisher.hide_task(current.task_id, "unsafe_content")
    assert replay.status is PublicationHideStatus.unchanged
    assert replay.changed is False


def test_invalid_reason_and_identifier_do_not_echo_input(monkeypatch) -> None:
    result = CliRunner().invoke(
        app,
        ["publication", "hide", "/private/path", "--reason", "not-allowed"],
    )
    assert result.exit_code == 2
    assert "/private/path" not in result.output
    assert "not-allowed" not in result.output


def test_view_helpers_accept_empty_store() -> None:
    class Store:
        def get_publication_health(self, *, now: datetime | None = None):
            return SimpleNamespace(updated_at=NOW, oldest_queued_at=None)

        def list_publication_generations(
            self,
            *,
            task_id: str | None = None,
            states: set[PublicationState | str] | None = None,
            limit: int | None = None,
        ):
            return []

    assert publication_health_view(Store(), now=NOW)["queuedCount"] == 0
    assert publication_generation_views(Store(), limit=0, now=NOW) == []

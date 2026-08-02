from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from typer.testing import CliRunner

from coquic_steward import cli
from coquic_steward.cli import app
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
    PublicationHideStatus,
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
        def get_publication_health(self):
            return health

        def list_publication_generations(self, *, limit):
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


def test_hide_real_store_blocks_queued_generation_and_replays(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    identity = GenerationIdentity("task-hide", "boundary-hide")
    generation = PublicationGeneration(
        publication_id=identity.publication_id,
        task_id="task-hide",
        run_id="run-hide",
        generation_boundary="boundary-hide",
        metadata_digest="a" * 64,
        idempotency_key=identity.idempotency_key,
        created_at=NOW,
        updated_at=NOW,
    )
    second_identity = GenerationIdentity("task-hide", "boundary-hide-second")
    second_generation = PublicationGeneration(
        publication_id=second_identity.publication_id,
        task_id="task-hide",
        run_id="run-hide-second",
        generation_boundary="boundary-hide-second",
        metadata_digest="b" * 64,
        idempotency_key=second_identity.idempotency_key,
        created_at=NOW,
        updated_at=NOW,
    )
    assert store.enqueue_publication(generation).status is PublicationOperationStatus.enqueued
    assert store.enqueue_publication(second_generation).status is PublicationOperationStatus.enqueued

    class D1:
        changed = True

        def hide_task(self, task_id, reason):
            result = SimpleNamespace(
                task_id=task_id,
                publication_id=generation.publication_id,
                state="hidden",
                changed=self.changed,
            )
            self.changed = False
            return result

    publisher = CloudPublisher(store, object(), D1(), now=NOW + timedelta(seconds=1))
    hidden = publisher.hide_task(generation.task_id, "unsafe_content")
    assert hidden.status is PublicationHideStatus.hidden
    assert hidden.changed is True
    for item in (generation, second_generation):
        persisted = store.get_publication_generation(item.publication_id)
        assert persisted is not None
        assert persisted.state is PublicationState.blocked
        assert persisted.reason == "unsafe_content"
        assert (
            store.claim_publication(
                "worker-1",
                publication_id=item.publication_id,
                now=NOW + timedelta(seconds=2),
            ).status
            is PublicationOperationStatus.empty
        )

    replay = publisher.hide_task(generation.task_id, "unsafe_content")
    assert replay.status is PublicationHideStatus.unchanged
    assert replay.changed is False
    assert store.get_publication_generation(generation.publication_id).state is PublicationState.blocked
    assert store.get_publication_generation(second_generation.publication_id).state is PublicationState.blocked


def test_retry_fail_closed_and_hide_are_safe_and_idempotent() -> None:
    current = _generation()

    class Store:
        def get_publication_generation(self, _publication_id):
            return current

        def list_publication_generations(self, *, task_id, limit):
            assert task_id == current.task_id
            return [current]

        def block_publication(self, *_args, **_kwargs):
            return SimpleNamespace(status="blocked")

    publisher = CloudPublisher(
        Store(),
        object(),
        SimpleNamespace(
            hide_task=lambda task_id, reason: SimpleNamespace(
                task_id=task_id,
                publication_id=current.publication_id,
                state="hidden",
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

    publisher.d1.hide_task = lambda task_id, reason: SimpleNamespace(
        task_id=task_id,
        publication_id=current.publication_id,
        state="hidden",
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
        def get_publication_health(self):
            return SimpleNamespace(updated_at=NOW, oldest_queued_at=None)

        def list_publication_generations(self, *, limit):
            return []

    assert publication_health_view(Store(), now=NOW)["queuedCount"] == 0
    assert publication_generation_views(Store(), limit=0, now=NOW) == []

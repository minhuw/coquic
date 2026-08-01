from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from typer.testing import CliRunner

from coquic_steward import cli
from coquic_steward.cli import app
from coquic_steward.publication.models import FailClosed, ReasonCode
from coquic_steward.publication.outbox import PublicationState, ReceiptClass
from coquic_steward.publication.publisher import (
    CloudPublisher,
    PublicationHideStatus,
    PublicationStatus,
    publication_generation_views,
    publication_health_view,
)


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
    queued: list[object] = []

    class Store:
        def get_publication_generation(self, publication_id):
            return current if publication_id == current.publication_id else None

        def enqueue_publication(self, value):
            queued.append(value)
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
    assert queued == [changed.outbox_record]

    unchanged = SimpleNamespace(**{**changed.__dict__, "publication_id": current.publication_id, "metadata_digest": "a" * 64})
    publisher = CloudPublisher(Store(), object(), object(), compose=lambda *_a, **_k: unchanged)
    result = publisher.retry_publication(current.publication_id, {"fresh": True})
    assert result.status is PublicationStatus.blocked
    assert result.reason == "unchanged"


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

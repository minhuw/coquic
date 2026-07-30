from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from coquic_steward.publication.outbox import (
    CleanupIntent,
    GenerationIdentity,
    OutboxValidationError,
    PublicationGeneration,
    PublicationReceipt,
    PublicationState,
    ReceiptClass,
    allowed_transition,
    deterministic_publication_id,
)
from coquic_steward.storage.schema import Base


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
PUBLIC_KEY = f"v1/tasks/task-1/objects/sha256/{DIGEST[:2]}/{DIGEST}"
PRIVATE_KEY = f"v1/originals/task-1/run-1/sha256/{DIGEST}.jsonl"


def _generation(**overrides: object) -> PublicationGeneration:
    values: dict[str, object] = {
        "publication_id": "pub-1",
        "task_id": "task-1",
        "run_id": "run-1",
        "generation_boundary": "boundary-1",
        "metadata_digest": DIGEST,
        "idempotency_key": "gen-1",
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(overrides)
    return PublicationGeneration(**values)


def test_identity_is_deterministic_from_task_and_boundary() -> None:
    first = GenerationIdentity("task-1", "boundary-1")
    second = GenerationIdentity("task-1", "boundary-1")
    changed = GenerationIdentity("task-1", "boundary-2")

    assert first == second
    assert first.publication_id == second.publication_id
    assert first.idempotency_key == second.idempotency_key
    assert first.publication_id != changed.publication_id
    assert deterministic_publication_id("task-1", "boundary-1") == first.publication_id


def test_every_legal_transition_is_explicit_and_immutable() -> None:
    generation = _generation()
    building = generation.transition_to(
        PublicationState.building,
        now=NOW + timedelta(seconds=1),
        lease_owner="worker-1",
    )
    uploading = building.transition_to(PublicationState.uploading, now=NOW + timedelta(seconds=2))
    staged = uploading.transition_to(PublicationState.d1_staged, now=NOW + timedelta(seconds=3))
    exposed = staged.transition_to(PublicationState.exposed, now=NOW + timedelta(seconds=4))
    cleaned = exposed.transition_to(PublicationState.terminal_cleaned, now=NOW + timedelta(seconds=5))

    assert generation.state is PublicationState.queued
    assert building.lease_owner == "worker-1"
    assert uploading.lease_owner is None
    assert staged.state is PublicationState.d1_staged
    assert exposed.exposed_at == NOW + timedelta(seconds=4)
    assert cleaned.state is PublicationState.terminal_cleaned
    assert not allowed_transition(PublicationState.queued, PublicationState.exposed)
    assert not cleaned.can_transition_to(PublicationState.queued)


def test_retry_and_blocked_recovery_are_bounded() -> None:
    building = _generation().transition_to(
        "building", now=NOW + timedelta(seconds=1), lease_owner="worker-1"
    )
    retry = building.transition_to(
        "retry_wait", now=NOW + timedelta(seconds=2), retry_at=NOW + timedelta(seconds=10)
    )
    reclaimed = retry.transition_to(
        "building", now=NOW + timedelta(seconds=11), lease_owner="worker-2"
    )
    blocked = reclaimed.transition_to(
        "blocked", now=NOW + timedelta(seconds=12), reason="scanner_failure"
    )
    queued = blocked.transition_to("queued", now=NOW + timedelta(seconds=13))

    assert retry.retry_at == NOW + timedelta(seconds=10)
    assert reclaimed.lease_owner == "worker-2"
    assert blocked.reason == "scanner_failure"
    assert queued.state is PublicationState.queued

    with pytest.raises(OutboxValidationError):
        _generation(state="unknown")
    with pytest.raises(OutboxValidationError):
        blocked.transition_to("queued", now=NOW + timedelta(seconds=13), reason="raw provider detail")


def test_private_receipts_and_cleanup_paths_are_not_public_locators() -> None:
    public = PublicationReceipt.public_receipt(
        DIGEST, 4, PUBLIC_KEY, NOW, "runs/run-1/trajectory.json"
    )
    private = PublicationReceipt.private_receipt(DIGEST, 4, PRIVATE_KEY, NOW)
    intent = CleanupIntent("task-1", "pub-1", DIGEST, "/var/lib/coquic/tasks/task-1", NOW)

    assert public.as_dict()["contentKey"] == PUBLIC_KEY
    assert private.as_dict() == {
        "class": "private",
        "sha256": DIGEST,
        "byteSize": 4,
        "verifiedAt": "2026-07-28T12:00:00.000Z",
    }
    assert "contentKey" not in intent.as_public_dict()
    assert "exactPath" not in intent.as_public_dict()
    assert intent.as_dict(include_private=True)["exactPath"] == "/var/lib/coquic/tasks/task-1"

    with pytest.raises(OutboxValidationError):
        PublicationReceipt(ReceiptClass.private, DIGEST, 4, PRIVATE_KEY, NOW, "private/file.jsonl")
    with pytest.raises(OutboxValidationError):
        CleanupIntent("task-1", "pub-1", DIGEST, "/var/lib/tasks/*", NOW)


def test_clean_schema_has_constrained_publication_tables_and_indexes() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    tables = set(inspect(engine).get_table_names())
    assert {
        "publication_generations",
        "publication_receipts",
        "publication_health",
        "publication_cleanup_intents",
    } <= tables
    indexes = {
        index["name"]
        for index in inspect(engine).get_indexes("publication_generations")
    }
    assert "ix_publication_generations_task_state_created" in indexes
    assert "ix_publication_generations_active_lease" in indexes

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO publication_generations "
                "(publication_id,task_id,run_id,generation_boundary,metadata_digest,idempotency_key,state,attempt,"
                "expected_row_count,expected_object_count,expected_task_count,expected_pipeline_count,expected_run_count,"
                "expected_event_count,expected_artifact_count,created_at,updated_at) "
                "VALUES ('pub-1','task-1','run-1','boundary-1',:digest,'gen-1','queued',0,1,1,1,0,1,0,1,"
                "'2026-07-28T12:00:00Z','2026-07-28T12:00:00Z')"
            ),
            {"digest": DIGEST},
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    "INSERT INTO publication_generations "
                    "(publication_id,task_id,run_id,generation_boundary,metadata_digest,idempotency_key,state,attempt,"
                    "expected_row_count,expected_object_count,expected_task_count,expected_pipeline_count,expected_run_count,"
                    "expected_event_count,expected_artifact_count,created_at,updated_at) "
                    "VALUES ('pub-2','task-1','run-2','boundary-2',:digest,'gen-1','queued',0,0,0,1,0,0,0,0,"
                    "'2026-07-28T12:00:00Z','2026-07-28T12:00:00Z')"
                ),
                {"digest": DIGEST},
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    "INSERT INTO publication_cleanup_intents "
                    "(intent_id,publication_id,task_id,manifest_digest,exact_path,state,requested_at) "
                    "VALUES ('cleanup-1','pub-1','task-1',:digest,'/var/lib/tasks/*','pending',"
                    "'2026-07-28T12:00:00Z')"
                ),
                {"digest": DIGEST},
            )

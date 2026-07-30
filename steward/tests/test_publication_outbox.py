from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from itertools import product

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from coquic_steward.publication.outbox import (
    CleanupIntent,
    CleanupState,
    GenerationIdentity,
    MAX_LEASE_SECONDS,
    OutboxValidationError,
    PublicationGeneration,
    PublicationOperationStatus,
    PublicationReceipt,
    PublicationState,
    ReceiptClass,
    allowed_transition,
    deterministic_publication_id,
)
from coquic_steward.storage import TaskStore
from coquic_steward.storage.schema import Base


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
PUBLIC_KEY = f"v1/tasks/task-1/objects/sha256/{DIGEST[:2]}/{DIGEST}"
PRIVATE_KEY = f"v1/originals/task-1/run-1/sha256/{DIGEST}.jsonl"
EXPECTED_LEGAL_EDGES = frozenset(
    {
        (PublicationState.queued, PublicationState.claimed),
        (PublicationState.queued, PublicationState.building),
        (PublicationState.claimed, PublicationState.building),
        (PublicationState.claimed, PublicationState.retry_wait),
        (PublicationState.claimed, PublicationState.blocked),
        (PublicationState.building, PublicationState.uploading),
        (PublicationState.building, PublicationState.retry_wait),
        (PublicationState.building, PublicationState.blocked),
        (PublicationState.uploading, PublicationState.d1_staged),
        (PublicationState.uploading, PublicationState.retry_wait),
        (PublicationState.uploading, PublicationState.blocked),
        (PublicationState.d1_staged, PublicationState.exposed),
        (PublicationState.d1_staged, PublicationState.retry_wait),
        (PublicationState.d1_staged, PublicationState.blocked),
        (PublicationState.exposed, PublicationState.terminal_cleaned),
        (PublicationState.retry_wait, PublicationState.building),
        (PublicationState.retry_wait, PublicationState.blocked),
        (PublicationState.blocked, PublicationState.queued),
    }
)


def _generation(**overrides: object) -> PublicationGeneration:
    identity = GenerationIdentity("task-1", "boundary-1")
    values: dict[str, object] = {
        "publication_id": identity.publication_id,
        "task_id": "task-1",
        "run_id": "run-1",
        "generation_boundary": "boundary-1",
        "metadata_digest": DIGEST,
        "idempotency_key": identity.idempotency_key,
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(overrides)
    return PublicationGeneration(**values)


def _generation_for_state(state: PublicationState) -> PublicationGeneration:
    values: dict[str, object] = {"state": state}
    if state in {PublicationState.claimed, PublicationState.building}:
        values.update(
            lease_owner="worker-1",
            lease_expires_at=NOW + timedelta(days=1),
        )
    if state is PublicationState.retry_wait:
        values["retry_at"] = NOW + timedelta(seconds=10)
    if state is PublicationState.blocked:
        values["reason"] = "scanner_failure"
    if state in {PublicationState.exposed, PublicationState.terminal_cleaned}:
        values["exposed_at"] = NOW
    return _generation(**values)


def _insert_generation_row(connection: object, **overrides: object) -> None:
    values: dict[str, object] = {
        "task_id": "task-schema",
        "run_id": "run-schema",
        "generation_boundary": "boundary-schema",
        "metadata_digest": DIGEST,
        "state": "queued",
        "attempt": 0,
        "lease_owner": None,
        "lease_expires_at": None,
        "retry_at": None,
        "reason": None,
        "expected_row_count": 0,
        "expected_object_count": 0,
        "expected_task_count": 1,
        "expected_pipeline_count": 0,
        "expected_run_count": 0,
        "expected_event_count": 0,
        "expected_artifact_count": 0,
        "created_at": "2026-07-28T12:00:00.000Z",
        "updated_at": "2026-07-28T12:00:00.000Z",
        "exposed_at": None,
    }
    values.update(overrides)
    identity = GenerationIdentity(
        str(values["task_id"]), str(values["generation_boundary"])
    )
    if "publication_id" not in overrides:
        values["publication_id"] = identity.publication_id
    if "idempotency_key" not in overrides:
        values["idempotency_key"] = identity.idempotency_key
    connection.execute(
        text(
            "INSERT INTO publication_generations "
            "(publication_id,task_id,run_id,generation_boundary,metadata_digest,idempotency_key,state,attempt,"
            "lease_owner,lease_expires_at,retry_at,reason,expected_row_count,expected_object_count,expected_task_count,"
            "expected_pipeline_count,expected_run_count,expected_event_count,expected_artifact_count,created_at,updated_at,exposed_at) "
            "VALUES (:publication_id,:task_id,:run_id,:generation_boundary,:metadata_digest,:idempotency_key,:state,:attempt,"
            ":lease_owner,:lease_expires_at,:retry_at,:reason,:expected_row_count,:expected_object_count,:expected_task_count,"
            ":expected_pipeline_count,:expected_run_count,:expected_event_count,:expected_artifact_count,:created_at,:updated_at,:exposed_at)"
        ),
        values,
    )


def test_identity_is_deterministic_from_task_and_boundary() -> None:
    first = GenerationIdentity("task-1", "boundary-1")
    second = GenerationIdentity("task-1", "boundary-1")
    changed = GenerationIdentity("task-1", "boundary-2")

    assert first == second
    assert first.publication_id == second.publication_id
    assert first.idempotency_key == second.idempotency_key
    assert first.publication_id != changed.publication_id
    assert deterministic_publication_id("task-1", "boundary-1") == first.publication_id
    with pytest.raises(OutboxValidationError):
        _generation(publication_id="pub-arbitrary")
    with pytest.raises(OutboxValidationError):
        _generation(idempotency_key="gen-arbitrary")


@pytest.mark.parametrize("source,target", product(PublicationState, PublicationState))
def test_every_state_pair_matches_the_expected_transition_table(
    source: PublicationState, target: PublicationState
) -> None:
    generation = _generation_for_state(source)
    expected = (source, target) in EXPECTED_LEGAL_EDGES
    assert allowed_transition(source, target) is expected
    assert generation.can_transition_to(target) is expected

    transition_values: dict[str, object] = {}
    if target in {PublicationState.claimed, PublicationState.building}:
        transition_values["lease_owner"] = "worker-2"
    if target is PublicationState.retry_wait:
        transition_values["retry_at"] = NOW + timedelta(seconds=10)
    if target is PublicationState.blocked:
        transition_values["reason"] = "scanner_failure"
    if expected:
        result = generation.transition_to(
            target,
            now=NOW + timedelta(seconds=1),
            **transition_values,
        )
        assert result.state is target
    else:
        with pytest.raises(OutboxValidationError):
            generation.transition_to(
                target,
                now=NOW + timedelta(seconds=1),
                **transition_values,
            )


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

    with engine.connect() as connection:
        connection.execute(text("PRAGMA foreign_keys=ON"))
        connection.commit()
    with engine.begin() as connection:
        identity = GenerationIdentity("task-1", "boundary-1")
        connection.execute(
            text(
                "INSERT INTO publication_generations "
                "(publication_id,task_id,run_id,generation_boundary,metadata_digest,idempotency_key,state,attempt,"
                "expected_row_count,expected_object_count,expected_task_count,expected_pipeline_count,expected_run_count,"
                "expected_event_count,expected_artifact_count,created_at,updated_at) "
                "VALUES (:publication_id,'task-1','run-1','boundary-1',:digest,:idempotency_key,'queued',0,1,1,1,0,1,0,1,"
                "'2026-07-28T12:00:00.000Z','2026-07-28T12:00:00.000Z')"
            ),
            {
                "digest": DIGEST,
                "publication_id": identity.publication_id,
                "idempotency_key": identity.idempotency_key,
            },
        )
        conflicting = GenerationIdentity("task-1", "boundary-2")
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    "INSERT INTO publication_generations "
                    "(publication_id,task_id,run_id,generation_boundary,metadata_digest,idempotency_key,state,attempt,"
                    "expected_row_count,expected_object_count,expected_task_count,expected_pipeline_count,expected_run_count,"
                    "expected_event_count,expected_artifact_count,created_at,updated_at) "
                    "VALUES (:publication_id,'task-1','run-2','boundary-2',:digest,:idempotency_key,'queued',0,0,0,1,0,0,0,0,"
                    "'2026-07-28T12:00:00.000Z','2026-07-28T12:00:00.000Z')"
                ),
                {
                    "digest": DIGEST,
                    "publication_id": conflicting.publication_id,
                    "idempotency_key": identity.idempotency_key,
                },
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    "INSERT INTO publication_cleanup_intents "
                    "(intent_id,publication_id,task_id,manifest_digest,exact_path,state,requested_at) "
                    "VALUES ('cleanup-1',:publication_id,'task-1',:digest,'/var/lib/tasks/*','pending',"
                    "'2026-07-28T12:00:00.000Z')"
                ),
                {"digest": DIGEST, "publication_id": identity.publication_id},
            )


def test_schema_rejects_malformed_receipts_and_cross_task_ownership() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(text("PRAGMA foreign_keys=ON"))
        connection.commit()
    with engine.begin() as connection:
        identity = GenerationIdentity("task-1", "boundary-receipts")
        _insert_generation_row(
            connection,
            task_id="task-1",
            run_id="run-1",
            generation_boundary="boundary-receipts",
        )
        connection.execute(
            text(
                "INSERT INTO publication_receipts "
                "(receipt_id,publication_id,task_id,receipt_class,sha256,byte_size,content_key,logical_path,verified_at) "
                "VALUES ('receipt-public',:publication_id,'task-1','public',:digest,4,:public_key,"
                "'runs/run-1/trajectory.json','2026-07-28T12:00:00.000Z')"
            ),
            {
                "digest": DIGEST,
                "public_key": PUBLIC_KEY,
                "publication_id": identity.publication_id,
            },
        )
        connection.execute(
            text(
                "INSERT INTO publication_receipts "
                "(receipt_id,publication_id,task_id,receipt_class,sha256,byte_size,content_key,logical_path,verified_at) "
                "VALUES ('receipt-private',:publication_id,'task-1','private',:digest,4,:private_key,NULL,"
                "'2026-07-28T12:00:00.000Z')"
            ),
            {
                "digest": DIGEST,
                "private_key": PRIVATE_KEY,
                "publication_id": identity.publication_id,
            },
        )
        assert connection.execute(
            text(
                "SELECT logical_path FROM publication_receipts "
                "WHERE receipt_id = 'receipt-public'"
            )
        ).scalar_one() == "runs/run-1/trajectory.json"
        invalid_receipts = (
            {
                "receipt_id": "receipt-public-key",
                "task_id": "task-1",
                "receipt_class": "public",
                "content_key": PUBLIC_KEY.replace("/aa/", "/bb/"),
                "logical_path": "runs/run-1/trajectory.json",
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
            {
                "receipt_id": "receipt-private-task",
                "task_id": "task-1",
                "receipt_class": "private",
                "content_key": PRIVATE_KEY.replace("task-1", "task-other"),
                "logical_path": None,
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
            {
                "receipt_id": "receipt-private-wildcard-run",
                "task_id": "task-1",
                "receipt_class": "private",
                "content_key": PRIVATE_KEY.replace("run-1", "_run"),
                "logical_path": None,
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
            {
                "receipt_id": "receipt-digest",
                "task_id": "task-1",
                "receipt_class": "private",
                "content_key": PRIVATE_KEY.replace(DIGEST, "b" * 64),
                "logical_path": None,
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
            {
                "receipt_id": "receipt-path",
                "task_id": "task-1",
                "receipt_class": "public",
                "content_key": PUBLIC_KEY,
                "logical_path": "../secret",
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
            {
                "receipt_id": "receipt-private-locator",
                "task_id": "task-1",
                "receipt_class": "public",
                "content_key": PUBLIC_KEY,
                "logical_path": "runs/private/trajectory.json",
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
            {
                "receipt_id": "receipt-time",
                "task_id": "task-1",
                "receipt_class": "public",
                "content_key": PUBLIC_KEY,
                "logical_path": "runs/run-1/trajectory.json",
                "verified_at": "not-a-timestamp",
            },
            {
                "receipt_id": "receipt-owner",
                "task_id": "task-other",
                "receipt_class": "public",
                "content_key": PUBLIC_KEY.replace("task-1", "task-other"),
                "logical_path": None,
                "verified_at": "2026-07-28T12:00:00.000Z",
            },
        )
        for receipt in invalid_receipts:
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO publication_receipts "
                        "(receipt_id,publication_id,task_id,receipt_class,sha256,byte_size,content_key,logical_path,verified_at) "
                        "VALUES (:receipt_id,:publication_id,:task_id,:receipt_class,:digest,4,:content_key,:logical_path,:verified_at)"
                    ),
                    {"digest": DIGEST, "publication_id": identity.publication_id, **receipt},
                )

        private_locator_paths = (
            "runs/PRIVATE/trajectory.json",
            "runs/PrIvAtE/trajectory.json",
            "runs/Credential/trajectory.json",
            "runs/CREDENTIAL/trajectory.json",
            "runs/CREDENTIALS/trajectory.json",
            "runs/CrEdEnTiAlS/trajectory.json",
            "runs/SeCrEt/trajectory.json",
            "runs/SECRET/trajectory.json",
            "runs/ToKeN/trajectory.json",
            "runs/TOKEN/trajectory.json",
            "PRIVATE-BUCKET",
            "pRiVaTe_Object",
            "PRIVATE-OBJECT-KEY",
            "PrIvAtE_object_key",
            "PRIVATE-URL",
            "pRiVaTe_PaTh",
            "INTERNAL-BUCKET",
            "iNtErNaL_Object",
            "INTERNAL-OBJECT-KEY",
            "InTeRnAl_object_key",
            "INTERNAL-URL",
            "iNtErNaL_PaTh",
            "SECRET-BUCKET",
            "sEcReT_Object",
            "SECRET-OBJECT-KEY",
            "SeCrEt_object_key",
            "SECRET-URL",
            "sEcReT_PaTh",
        )
        for index, logical_path in enumerate(private_locator_paths):
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO publication_receipts "
                        "(receipt_id,publication_id,task_id,receipt_class,sha256,byte_size,content_key,logical_path,verified_at) "
                        "VALUES (:receipt_id,:publication_id,'task-1','public',:digest,4,:public_key,:logical_path,:verified_at)"
                    ),
                    {
                        "digest": DIGEST,
                        "public_key": PUBLIC_KEY,
                        "publication_id": identity.publication_id,
                        "receipt_id": f"receipt-private-locator-case-{index}",
                        "logical_path": logical_path,
                        "verified_at": "2026-07-28T12:00:00.000Z",
                    },
                )


def test_schema_rejects_invalid_generation_state_rules_and_timestamps() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(text("PRAGMA foreign_keys=ON"))
        connection.commit()
    with engine.begin() as connection:
        invalid_rows = (
            {
                "publication_id": "pub-claimed-without-lease",
                "task_id": "task-claimed-without-lease",
                "run_id": "run-claimed-without-lease",
                "generation_boundary": "boundary-claimed-without-lease",
                "idempotency_key": "gen-claimed-without-lease",
                "state": "claimed",
            },
            {
                "publication_id": "pub-queued-with-lease",
                "task_id": "task-queued-with-lease",
                "run_id": "run-queued-with-lease",
                "generation_boundary": "boundary-queued-with-lease",
                "idempotency_key": "gen-queued-with-lease",
                "lease_owner": "worker-1",
                "lease_expires_at": "2026-07-28T13:00:00.000Z",
            },
            {
                "publication_id": "pub-secret-reason",
                "task_id": "task-secret-reason",
                "run_id": "run-secret-reason",
                "generation_boundary": "boundary-secret-reason",
                "idempotency_key": "gen-secret-reason",
                "state": "blocked",
                "reason": "secret_access_key",
            },
            {
                "publication_id": "pub-blocked-without-reason",
                "task_id": "task-blocked-without-reason",
                "run_id": "run-blocked-without-reason",
                "generation_boundary": "boundary-blocked-without-reason",
                "idempotency_key": "gen-blocked-without-reason",
                "state": "blocked",
            },
            {
                "publication_id": "pub-invalid-time",
                "task_id": "task-invalid-time",
                "run_id": "run-invalid-time",
                "generation_boundary": "boundary-invalid-time",
                "idempotency_key": "gen-invalid-time",
                "created_at": "not-a-timestamp",
            },
            {
                "publication_id": GenerationIdentity(
                    "task-invalid-hour", "boundary-invalid-hour"
                ).publication_id,
                "task_id": "task-invalid-hour",
                "run_id": "run-invalid-hour",
                "generation_boundary": "boundary-invalid-hour",
                "idempotency_key": GenerationIdentity(
                    "task-invalid-hour", "boundary-invalid-hour"
                ).idempotency_key,
                "updated_at": "2026-07-28T24:00:00.000Z",
            },
            {
                "publication_id": "pub-reversed-time",
                "task_id": "task-reversed-time",
                "run_id": "run-reversed-time",
                "generation_boundary": "boundary-reversed-time",
                "idempotency_key": "gen-reversed-time",
                "created_at": "2026-07-28T12:00:01.000Z",
            },
            {
                "publication_id": "pub-exposed-time",
                "task_id": "task-exposed-time",
                "run_id": "run-exposed-time",
                "generation_boundary": "boundary-exposed-time",
                "idempotency_key": "gen-exposed-time",
                "state": "exposed",
            },
        )
        for row in invalid_rows:
            with pytest.raises(IntegrityError):
                _insert_generation_row(connection, **row)

        _insert_generation_row(
            connection,
            task_id="task-active-lease",
            run_id="run-active-lease-1",
            generation_boundary="boundary-active-lease-1",
            state="claimed",
            lease_owner="worker-1",
            lease_expires_at="2026-07-28T13:00:00.000Z",
        )
        with pytest.raises(IntegrityError):
            _insert_generation_row(
                connection,
                task_id="task-active-lease",
                run_id="run-active-lease-2",
                generation_boundary="boundary-active-lease-2",
                state="building",
                lease_owner="worker-2",
                lease_expires_at="2026-07-28T13:00:00.000Z",
            )

        _insert_generation_row(
            connection,
            task_id="task-valid-hour",
            run_id="run-valid-hour",
            generation_boundary="boundary-valid-hour",
            created_at="2026-07-28T23:59:59.999Z",
            updated_at="2026-07-28T23:59:59.999Z",
        )


def test_schema_requires_matching_publication_and_idempotency_identity() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        identity = GenerationIdentity("task-id", "boundary-id")
        _insert_generation_row(
            connection,
            task_id="task-id",
            run_id="run-id",
            generation_boundary="boundary-id",
        )
        with pytest.raises(IntegrityError):
            _insert_generation_row(
                connection,
                publication_id=identity.publication_id,
                idempotency_key="gen-b",
                task_id="task-id",
                run_id="run-mismatched-ids",
                generation_boundary="boundary-mismatched-ids",
            )
        wrong_digest = "b" * 64
        with pytest.raises(IntegrityError):
            _insert_generation_row(
                connection,
                publication_id=f"pub-{wrong_digest}",
                idempotency_key=identity.idempotency_key,
                task_id="task-id",
                run_id="run-mismatched-digest",
                generation_boundary="boundary-mismatched-digest",
            )
        wrong_identity = GenerationIdentity("task-other", "boundary-other")
        with pytest.raises(IntegrityError):
            _insert_generation_row(
                connection,
                publication_id=wrong_identity.publication_id,
                idempotency_key=wrong_identity.idempotency_key,
                task_id="task-id",
                run_id="run-wrong-task-boundary-digest",
                generation_boundary="boundary-wrong-task-boundary-digest",
            )


def test_schema_rejects_broad_or_unverified_cleanup_authority() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(text("PRAGMA foreign_keys=ON"))
        connection.commit()
    with engine.begin() as connection:
        cleanup_identity = GenerationIdentity("task-cleanup", "boundary-cleanup")
        _insert_generation_row(
            connection,
            task_id="task-cleanup",
            run_id="run-cleanup",
            generation_boundary="boundary-cleanup",
        )
        invalid_cleanups = (
            {
                "intent_id": "cleanup-root",
                "publication_id": cleanup_identity.publication_id,
                "task_id": "task-cleanup",
                "exact_path": "/var/lib/coquic/tasks",
                "state": "pending",
                "verified_at": None,
                "completed_at": None,
            },
            {
                "intent_id": "cleanup-cross-task",
                "publication_id": cleanup_identity.publication_id,
                "task_id": "task-other",
                "exact_path": "/var/lib/coquic/tasks/task-other",
                "state": "pending",
                "verified_at": None,
                "completed_at": None,
            },
            {
                "intent_id": "cleanup-unverified",
                "publication_id": cleanup_identity.publication_id,
                "task_id": "task-cleanup",
                "exact_path": "/var/lib/coquic/tasks/task-cleanup",
                "state": "completed",
                "verified_at": None,
                "completed_at": "2026-07-28T12:01:00.000Z",
            },
        )
        for cleanup in invalid_cleanups:
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO publication_cleanup_intents "
                        "(intent_id,publication_id,task_id,manifest_digest,exact_path,state,requested_at,verified_at,completed_at) "
                        "VALUES (:intent_id,:publication_id,:task_id,:digest,:exact_path,:state,"
                        "'2026-07-28T12:00:00.000Z',:verified_at,:completed_at)"
                    ),
                    {"digest": DIGEST, **cleanup},
                )
        connection.execute(
            text(
                "INSERT INTO publication_cleanup_intents "
                "(intent_id,publication_id,task_id,manifest_digest,exact_path,state,requested_at,verified_at,completed_at) "
                "VALUES ('cleanup-valid',:publication_id,'task-cleanup',:digest,'/var/lib/coquic/tasks/task-cleanup',"
                "'completed','2026-07-28T12:00:00.000Z','2026-07-28T12:00:01.000Z',"
                "'2026-07-28T12:00:02.000Z')"
            ),
            {"digest": DIGEST, "publication_id": cleanup_identity.publication_id},
        )


def test_store_enqueue_is_idempotent_and_notifies_after_commit(tmp_path) -> None:
    path = tmp_path / "steward.sqlite"
    store = TaskStore(path)
    observed: list[PublicationState | None] = []
    store.on_change = lambda: observed.append(
        store.get_publication_generation(_generation().publication_id).state
    )

    created = store.enqueue_publication(_generation())
    assert created.status is PublicationOperationStatus.enqueued
    assert observed == [PublicationState.queued]

    replay = store.enqueue_publication(
        _generation(
            created_at=NOW + timedelta(seconds=1),
            updated_at=NOW + timedelta(seconds=1),
        )
    )
    assert replay.status is PublicationOperationStatus.existing
    assert observed == [PublicationState.queued]

    with pytest.raises(OutboxValidationError):
        store.enqueue_publication(_generation(objects=1))


def test_store_claim_cas_and_concurrent_callers_have_one_lease(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    generation = _generation()
    store.enqueue_publication(generation)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda worker: store.claim_publication(worker, now=NOW),
                ("worker-1", "worker-2"),
            )
        )
    assert sorted(result.status.value for result in results) == ["claimed", "empty"]
    claimed = next(result for result in results if result.status is PublicationOperationStatus.claimed)
    assert claimed.generation is not None
    assert claimed.generation.attempt == 1
    assert claimed.generation.lease_owner in {"worker-1", "worker-2"}

    wrong_owner = store.renew_publication_lease(
        "other-worker",
        publication_id=generation.publication_id,
        now=NOW + timedelta(seconds=1),
    )
    assert wrong_owner.status is PublicationOperationStatus.lost_claim
    renewed = store.renew_publication_lease(
        claimed.generation.lease_owner,
        publication_id=generation.publication_id,
        now=NOW + timedelta(seconds=1),
    )
    assert renewed.status is PublicationOperationStatus.renewed

    building = store.advance_publication(
        generation.publication_id,
        PublicationState.claimed,
        PublicationState.building,
        lease_owner=claimed.generation.lease_owner,
        now=NOW + timedelta(seconds=2),
    )
    assert building.status is PublicationOperationStatus.advanced
    illegal = store.advance_publication(
        generation.publication_id,
        PublicationState.claimed,
        PublicationState.exposed,
        lease_owner=claimed.generation.lease_owner,
        now=NOW + timedelta(seconds=3),
    )
    assert illegal.status is PublicationOperationStatus.illegal_transition


def test_store_expiry_retry_and_block_are_restart_safe(tmp_path) -> None:
    path = tmp_path / "steward.sqlite"
    store = TaskStore(path)
    generation = _generation()
    store.enqueue_publication(generation)
    first = store.claim_publication("worker-1", now=NOW)
    assert first.status is PublicationOperationStatus.claimed

    expired = store.expire_publication_leases(
        now=NOW + timedelta(seconds=MAX_LEASE_SECONDS)
    )
    assert store.get_publication_generation(generation.publication_id).state is PublicationState.retry_wait
    assert any(item.publication_id == generation.publication_id for item in expired)
    resumed = store.claim_publication(
        "worker-2", publication_id=generation.publication_id, now=NOW + timedelta(seconds=MAX_LEASE_SECONDS)
    )
    assert resumed.status is PublicationOperationStatus.claimed
    assert resumed.generation.attempt == 2

    retry_at = NOW + timedelta(seconds=MAX_LEASE_SECONDS + 10)
    retry = store.schedule_publication_retry(
        generation.publication_id,
        expected_state=PublicationState.building,
        lease_owner="worker-2",
        retry_at=retry_at,
        reason="network",
        now=NOW + timedelta(seconds=MAX_LEASE_SECONDS + 1),
    )
    assert retry.status is PublicationOperationStatus.retry_wait
    assert (
        store.claim_publication(
            "worker-3", publication_id=generation.publication_id, now=retry_at - timedelta(seconds=1)
        ).status
        is PublicationOperationStatus.empty
    )
    resumed_again = store.claim_publication(
        "worker-3", publication_id=generation.publication_id, now=retry_at
    )
    assert resumed_again.status is PublicationOperationStatus.claimed

    blocked = store.block_publication(
        generation.publication_id,
        expected_state=PublicationState.building,
        lease_owner="worker-3",
        reason="scanner_failure",
        now=retry_at + timedelta(seconds=1),
    )
    assert blocked.status is PublicationOperationStatus.blocked
    assert blocked.generation.reason == "scanner_failure"

    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE publication_generations SET state='queued',attempt=:attempt,"
            "reason=NULL,updated_at=:updated_at WHERE publication_id=:publication_id",
            {
                "attempt": 32,
                "updated_at": "2026-07-28T12:00:00.000Z",
                "publication_id": generation.publication_id,
            },
        )
    exhausted = store.claim_publication(
        "worker-4", publication_id=generation.publication_id, now=NOW
    )
    assert exhausted.status is PublicationOperationStatus.retry_exhausted
    assert store.get_publication_generation(generation.publication_id).state is PublicationState.blocked

    store.engine.dispose()
    restarted = TaskStore(path)
    assert restarted.get_publication_generation(generation.publication_id).state is PublicationState.blocked


def test_store_receipts_cleanup_intents_and_health_converge(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    generation = _generation()
    store.enqueue_publication(generation)
    owner = "worker-1"
    store.claim_publication(owner, now=NOW)
    for offset, expected, target in (
        (1, PublicationState.claimed, PublicationState.building),
        (2, PublicationState.building, PublicationState.uploading),
        (3, PublicationState.uploading, PublicationState.d1_staged),
        (4, PublicationState.d1_staged, PublicationState.exposed),
    ):
        result = store.advance_publication(
            generation.publication_id,
            expected,
            target,
            lease_owner=owner if expected in {PublicationState.claimed, PublicationState.building} else None,
            now=NOW + timedelta(seconds=offset),
        )
        assert result.status is PublicationOperationStatus.advanced

    receipt = PublicationReceipt.public_receipt(
        DIGEST,
        17,
        PUBLIC_KEY,
        NOW + timedelta(seconds=2),
        "runs/run-1/trajectory.json",
    )
    recorded = store.record_publication_receipt(generation.publication_id, receipt)
    assert recorded.status is PublicationOperationStatus.recorded
    replayed = store.record_publication_receipt(
        generation.publication_id,
        replace(receipt, verified_at=NOW + timedelta(seconds=3)),
    )
    assert replayed.status is PublicationOperationStatus.existing

    intent = CleanupIntent(
        "task-1",
        generation.publication_id,
        DIGEST,
        "/var/lib/coquic/tasks/task-1",
        NOW + timedelta(seconds=4),
    )
    created = store.create_cleanup_intent(intent)
    assert created.status is PublicationOperationStatus.enqueued
    health = store.get_publication_health()
    assert health.cleanup_pending_count == 1
    assert health.cleanup_pending_bytes == 17

    verified = store.verify_cleanup_intent(
        intent.intent_id,
        manifest_digest=DIGEST,
        verified_at=NOW + timedelta(seconds=5),
    )
    assert verified.status is PublicationOperationStatus.verified
    assert store.verify_cleanup_intent(
        intent.intent_id,
        manifest_digest=DIGEST,
        verified_at=NOW + timedelta(seconds=6),
    ).status is PublicationOperationStatus.existing

    completed = store.complete_cleanup_intent(
        intent.intent_id,
        manifest_digest=DIGEST,
        completed_at=NOW + timedelta(seconds=7),
    )
    assert completed.status is PublicationOperationStatus.completed
    assert completed.cleanup is not None
    assert completed.cleanup.state is CleanupState.completed
    assert (
        store.get_publication_generation(generation.publication_id).state
        is PublicationState.terminal_cleaned
    )
    health = store.get_publication_health()
    assert health.cleanup_pending_count == 0
    assert health.cleanup_pending_bytes == 0

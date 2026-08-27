from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

import coquic_steward.storage.schema as schema_module
from coquic_steward.core.models import ExecutionMode, TaskKind, TaskSpec, WorkerKind
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    OutboxValidationError,
    PublicationCounts,
    PublicationOperationResult,
    PublicationOperationStatus,
)
from coquic_steward.storage import TaskStore


NOW = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def _enqueue_counts(
    tmp_path: Path,
    counts: PublicationCounts | dict[str, object] | None,
    **fallbacks: int,
) -> PublicationOperationResult:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=False)
    store.add_task(
        TaskSpec(
            id="task-counts",
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="publication fixture",
            prompt="publication fixture",
        )
    )
    try:
        return store.enqueue_publication(
            task_id="task-counts",
            run_id="run-counts",
            generation_boundary="boundary-counts",
            metadata_digest=DIGEST,
            counts=counts,
            created_at=NOW,
            updated_at=NOW,
            **fallbacks,
        )
    finally:
        store.engine.dispose()


def test_sqlite_digest_registration_uses_the_concrete_two_argument_contract() -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    identity = GenerationIdentity("task-identity", "boundary-identity")
    try:
        with engine.connect() as connection:
            digest = connection.exec_driver_sql(
                "SELECT coquic_publication_digest(?, ?)",
                (identity.task_id, identity.stable_boundary),
            ).scalar_one()
            assert digest == identity.digest
            with pytest.raises(OperationalError):
                connection.exec_driver_sql(
                    "SELECT coquic_publication_digest(?)",
                    (identity.task_id,),
                )
    finally:
        engine.dispose()


def test_sqlite_digest_registration_rejects_a_non_sqlite_connection() -> None:
    with pytest.raises(TypeError, match="SQLite"):
        schema_module._register_publication_identity_digest(object(), object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("counts", "fallbacks", "expected"),
    (
        (
            PublicationCounts(
                rows=2,
                objects=3,
                tasks=1,
                pipelines=4,
                runs=5,
                events=6,
                artifacts=7,
            ),
            {},
            (2, 3, 1, 4, 5, 6, 7),
        ),
        (
            {
                "rows": 8,
                "objects": 9,
                "tasks": 1,
                "pipelines": 10,
                "runs": 11,
                "events": 12,
                "artifacts": 13,
            },
            {},
            (8, 9, 1, 10, 11, 12, 13),
        ),
        (
            None,
            {
                "rows": 14,
                "objects": 15,
                "tasks": 1,
                "pipelines": 16,
                "runs": 17,
                "events": 18,
                "artifacts": 19,
            },
            (14, 15, 1, 16, 17, 18, 19),
        ),
    ),
)
def test_publication_count_contract_persists_declared_inputs(
    tmp_path: Path,
    counts: PublicationCounts | dict[str, object] | None,
    fallbacks: dict[str, int],
    expected: tuple[int, int, int, int, int, int, int],
) -> None:
    result = _enqueue_counts(tmp_path, counts, **fallbacks)

    assert result.status is PublicationOperationStatus.enqueued
    assert result.generation is not None
    generation = result.generation
    assert (
        generation.rows,
        generation.objects,
        generation.tasks,
        generation.pipelines,
        generation.runs,
        generation.events,
        generation.artifacts,
    ) == expected


class _MethodBearingCounts:
    def as_dict(self) -> dict[str, int]:
        raise AssertionError("lookalike method must not be invoked")


class _FieldBearingCounts:
    rows = 1
    objects = 2
    tasks = 1
    pipelines = 3
    runs = 4
    events = 5
    artifacts = 6


@pytest.mark.parametrize("counts", (_MethodBearingCounts(), _FieldBearingCounts()))
def test_publication_count_contract_rejects_lookalike_objects(
    tmp_path: Path, counts: object
) -> None:
    with pytest.raises(OutboxValidationError):
        _enqueue_counts(tmp_path, counts)  # type: ignore[arg-type]


def test_publication_count_contract_preserves_mapping_range_validation(
    tmp_path: Path,
) -> None:
    with pytest.raises(OutboxValidationError):
        _enqueue_counts(tmp_path, {"rows": -1})


@pytest.mark.parametrize("value", (True, "1", 1.5))
def test_publication_count_contract_rejects_non_integer_mapping_values(
    tmp_path: Path, value: object
) -> None:
    with pytest.raises(OutboxValidationError):
        _enqueue_counts(tmp_path, {"rows": value})


_DAEMON_AUTHORITY_KEYS = (
    "publication_execution_mode",
    "execution_mode",
    "publication_claim_id",
    "claim_id",
    "publication_mode",
    "aggregate_publication_mode",
    "daemon_publication_mode",
    "aggregate_publication_authority",
)


@pytest.mark.parametrize("key", _DAEMON_AUTHORITY_KEYS)
def test_daemon_claim_filters_store_owned_state(
    tmp_path: Path, key: str
) -> None:
    store = TaskStore.create(tmp_path / "daemon-claim.sqlite", dry_run=False)
    try:
        state = store.claim_daemon_instance(
            "daemon-one",
            lifecycle="running",
            state={
                key: "caller-selected",
                "ordinary": "kept",
                "provider_session_id": "private-provider",
                "private_home_path": "private/home",
            },
        )

        assert state["publication_execution_mode"] == ExecutionMode.live.value
        assert state["publication_claim_id"] != "caller-selected"
        assert state["ordinary"] == "kept"
        assert "provider_session_id" not in state
        assert "private_home_path" not in state
        assert all(
            state.get(candidate) != "caller-selected"
            for candidate in _DAEMON_AUTHORITY_KEYS
        )
    finally:
        store.engine.dispose()


@pytest.mark.parametrize("key", _DAEMON_AUTHORITY_KEYS)
def test_daemon_lifecycle_filters_caller_authority_state(
    tmp_path: Path, key: str
) -> None:
    store = TaskStore.create(tmp_path / "daemon-lifecycle.sqlite", dry_run=False)
    try:
        claimed = store.claim_daemon_instance(
            "daemon-one", lifecycle="running", state={"ordinary": "before"}
        )
        state = store.set_daemon_lifecycle(
            "running",
            instance_id="daemon-one",
            state={
                key: "caller-selected",
                "ordinary": "kept",
                "instance_id": "spoofed",
                "lifecycle": "spoofed",
                "updated_at": "spoofed",
            },
        )

        assert state["instance_id"] == "daemon-one"
        assert state["lifecycle"] == "running"
        assert state["publication_execution_mode"] == claimed[
            "publication_execution_mode"
        ]
        assert state["publication_claim_id"] == claimed["publication_claim_id"]
        assert state["ordinary"] == "kept"
        assert state["updated_at"] != "spoofed"
        assert all(
            state.get(candidate) != "caller-selected"
            for candidate in _DAEMON_AUTHORITY_KEYS
        )
    finally:
        store.engine.dispose()


@pytest.mark.parametrize("key", _DAEMON_AUTHORITY_KEYS)
def test_daemon_revocation_filters_authority_state_and_removes_claim(
    tmp_path: Path, key: str
) -> None:
    store = TaskStore.create(tmp_path / "daemon-revocation.sqlite", dry_run=False)
    try:
        store.claim_daemon_instance(
            "daemon-one", lifecycle="running", state={"ordinary": "before"}
        )
        result = store.revoke_daemon_publication_authority(
            "daemon-one",
            "stopping",
            deadline=time.monotonic() + 1.0,
            state={
                key: "caller-selected",
                "ordinary": "kept",
                "instance_id": "spoofed",
                "lifecycle": "spoofed",
                "updated_at": "spoofed",
            },
        )
        state = store.get_daemon_state()

        assert result.revoked
        assert state is not None
        assert state["instance_id"] == "daemon-one"
        assert state["lifecycle"] == "stopping"
        assert state["publication_execution_mode"] == ExecutionMode.live.value
        assert "publication_claim_id" not in state
        assert state["ordinary"] == "kept"
        assert state["updated_at"] != "spoofed"
        assert all(
            state.get(candidate) != "caller-selected"
            for candidate in _DAEMON_AUTHORITY_KEYS
        )
    finally:
        store.engine.dispose()

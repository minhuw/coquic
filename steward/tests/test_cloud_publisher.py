from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace

import pytest

from coquic_steward.core.models import (
    EffectDecision,
    EffectDecisionKind,
    ExecutionMode,
    TaskKind,
    TaskSpec,
    WorkerKind,
)
from coquic_steward.publication import (
    FailClosed,
    PublicationError,
    ReasonCode,
    RepairRequired,
)
from coquic_steward.publication.d1 import (
    D1Error,
    D1ErrorCode,
    ExposureReceipt,
    HideReceipt,
    OverheadReceipt,
    StageReceipt,
    UsageBackfillReceipt,
)
from coquic_steward.publication.generation import (
    GenerationObject,
    GenerationOriginal,
    PublicationComposer,
    PublicationGeneration as ComposedGeneration,
    compose_publication_generation,
)
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    MAX_ATTEMPTS,
    MAX_LEASE_SECONDS,
    PublicationOperationStatus,
    PublicationGeneration,
    PublicationReceipt,
    PublicationRetryPolicy,
    PublicationState,
    ReceiptClass,
)
from coquic_steward.publication.publisher import (
    CloudPublisher,
    PublicationHideStatus,
    PublicationStatus,
    _call_composer,
)
from coquic_steward.publication.r2 import (
    R2Error,
    R2ErrorCategory,
    R2ObjectClass,
    R2PutResult,
    R2PutStatus,
)
from coquic_steward.storage import TaskStore
from coquic_steward.storage.sqlite import DaemonPublicationAuthority
from publication_harness import returning_composer as _returning_composer


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
POLICY = PublicationRetryPolicy()
IDENTITY = GenerationIdentity("task-1", "3f0b90c7ade7e39f4eeaa5153d417bb8500c93fc65301205de26b3057fea2e03")


def _composed(
    *,
    private: bool = False,
    private_count: int = 1,
    metadata_digest: str = "a" * 64,
):
    public_content = b"public object"
    public_digest = __import__("hashlib").sha256(public_content).hexdigest()
    public_key = f"v1/tasks/task-1/objects/sha256/{public_digest[:2]}/{public_digest}"
    public = GenerationObject(
        "artifact-1",
        "task-1",
        "run-1",
        "runs/run-1/trajectory.json",
        public_key,
        "application/json",
        public_content,
    )
    originals = (
        tuple(
            GenerationOriginal("task-1", "run-1", f"private original {index}".encode())
            for index in range(private_count)
        )
        if private
        else ()
    )
    counts = {"tasks": 1, "pipelines": 1, "runs": 1, "events": 1, "artifacts": 1}
    payload = {
        "taskId": "task-1",
        "publicationId": IDENTITY.publication_id,
        "task": {"taskId": "task-1"},
        "pipelines": [{"pipelineId": "pipeline-1"}],
        "generation": {
            "runId": "run-1",
            "publicationId": IDENTITY.publication_id,
            "taskId": "task-1",
            "idempotencyKey": IDENTITY.idempotency_key,
            "metadataDigest": metadata_digest,
            "expectedCounts": counts,
            "createdAt": NOW.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        },
        "headIntent": {
            "publicationId": IDENTITY.publication_id,
            "taskId": "task-1",
            "updatedAt": NOW.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        },
        "runs": [{"runId": "run-1"}],
        "events": [{"sequence": 1}],
        "artifacts": [{"artifactId": "artifact-1"}],
    }
    return ComposedGeneration(
        payload=payload,
        objects=(public,),
        private_originals=originals,
    )


@dataclass
class _FakeStore:
    with_private: bool = False
    object_count: int | None = None

    def __post_init__(self) -> None:
        self.generation = SimpleNamespace(
            publication_id=IDENTITY.publication_id,
            task_id="task-1",
            run_id="run-1",
            generation_boundary=IDENTITY.generation_boundary,
            metadata_digest="a" * 64,
            idempotency_key=IDENTITY.idempotency_key,
            state=PublicationState.queued,
            lease_owner=None,
            lease_expires_at=None,
            retry_at=None,
            reason=None,
            updated_at=NOW,
            rows=5,
            objects=self.object_count or (2 if self.with_private else 1),
            tasks=1,
            pipelines=1,
            runs=1,
            events=1,
            artifacts=1,
        )
        self.receipts: list[PublicationReceipt] = []
        self.events: list[str] = []
        self.renew_lost = False
        self.block_lost = False
        self.hide_fence = SimpleNamespace(state="pending", reason=None)

    @contextmanager
    def effect_admission(self, *_args, **_kwargs):
        yield EffectDecision(EffectDecisionKind.allow)

    @contextmanager
    def daemon_publication_admission(self, *_args, **_kwargs):
        yield EffectDecision(EffectDecisionKind.allow)

    def get_publication_generation(self, publication_id: str):
        return self.generation if publication_id == self.generation.publication_id else None

    def get_publication_health(self, *, now: datetime | None = None):
        return SimpleNamespace(
            queued_count=1,
            blocked_count=0,
            cleanup_pending_count=0,
            cleanup_pending_bytes=0,
            oldest_queued_at=None,
            updated_at=now or NOW,
            reason=None,
            last_category="success",
        )

    def list_publication_generations(
        self,
        *,
        task_id: str | None = None,
        states: set[PublicationState | str] | None = None,
        limit: int | None = None,
    ):
        values = [self.generation]
        if task_id is not None:
            values = [item for item in values if item.task_id == task_id]
        if states:
            normalized = {PublicationState(item).value for item in states}
            values = [item for item in values if item.state.value in normalized]
        return values if limit is None else values[:limit]

    def begin_publication_hide(
        self,
        task_id: str,
        reason: str = "operator_blocked",
        *,
        now: datetime | None = None,
        generation_boundary: str | None = None,
    ):
        assert task_id == self.generation.task_id
        self.events.append("begin_hide")
        self.generation.state = PublicationState.blocked
        self.generation.reason = reason
        self.generation.retry_at = None
        self.generation.lease_owner = None
        self.generation.lease_expires_at = None
        self.hide_fence.state = "pending"
        self.hide_fence.reason = reason
        return SimpleNamespace(status=PublicationOperationStatus.enqueued, fence=self.hide_fence)

    def confirm_publication_hide(
        self,
        task_id: str,
        *,
        reason: str | None = None,
        confirmed_at: datetime | None = None,
        now: datetime | None = None,
    ):
        assert task_id == self.generation.task_id
        self.events.append("confirm_hide")
        self.hide_fence.state = "confirmed"
        return SimpleNamespace(status=PublicationOperationStatus.verified, fence=self.hide_fence)

    def claim_publication(
        self,
        worker_id: str,
        *,
        retry_policy: PublicationRetryPolicy,
        publication_id: str | None = None,
        now: datetime,
        lease_seconds: int = MAX_LEASE_SECONDS,
    ):
        self.events.append("claim")
        self.generation.state = (
            PublicationState.building
            if self.generation.state is PublicationState.retry_wait
            else PublicationState.claimed
        )
        self.generation.reason = None
        self.generation.retry_at = None
        self.generation.lease_owner = worker_id
        self.generation.lease_expires_at = now + timedelta(seconds=lease_seconds)
        return SimpleNamespace(status=PublicationOperationStatus.claimed, generation=self.generation)

    def renew_publication_lease(
        self,
        worker_id: str | None = None,
        *,
        lease_owner: str | None = None,
        publication_id: str,
        now: datetime,
        lease_seconds: int = MAX_LEASE_SECONDS,
    ):
        assert (lease_owner or worker_id) == "worker-1"
        self.events.append("renew")
        if self.renew_lost:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.lease_expires_at = now + timedelta(seconds=lease_seconds)
        self.generation.updated_at = now
        return SimpleNamespace(status=PublicationOperationStatus.renewed, generation=self.generation)

    def advance_publication(
        self,
        publication_id: str,
        expected_state: PublicationState | str,
        target_state: PublicationState | str,
        *,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        now: datetime | None = None,
        lease_expires_at: datetime | None = None,
        retry_at: datetime | None = None,
        reason: str | None = None,
    ):
        expected_state = PublicationState(expected_state)
        target_state = PublicationState(target_state)
        self.events.append(target_state.value)
        if self.generation.state is not expected_state:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.state = target_state
        self.generation.updated_at = now or NOW
        if target_state is PublicationState.exposed:
            self.generation.lease_owner = None
            self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.advanced, generation=self.generation)

    def list_publication_receipts(
        self,
        publication_id: str,
        *,
        receipt_class: ReceiptClass | str | None = None,
    ):
        values = list(self.receipts)
        if receipt_class is not None:
            normalized = ReceiptClass(receipt_class)
            values = [item for item in values if item.receipt_class is normalized]
        return values

    def record_publication_receipt(
        self,
        publication_id: str,
        receipt: PublicationReceipt,
        *,
        receipt_id: str | None = None,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        owner: str | None = None,
        now: datetime | None = None,
    ):
        assert (lease_owner or worker_id or owner) == "worker-1"
        assert now == NOW
        self.events.append(f"receipt:{receipt.receipt_class.value}")
        self.receipts.append(receipt)
        return SimpleNamespace(status=PublicationOperationStatus.recorded, generation=self.generation, receipt=receipt)

    def replace_blocked_publication(self, old_publication_id: str, generation: object):
        return SimpleNamespace(status=PublicationOperationStatus.enqueued, generation=generation)

    def schedule_publication_retry(
        self,
        publication_id: str,
        *,
        expected_state: PublicationState | str | None = None,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        retry_policy: PublicationRetryPolicy,
        retry_at: datetime | None = None,
        backoff_seconds: int | None = None,
        reason: str = "network",
        now: datetime | None = None,
    ):
        self.events.append("retry_wait")
        self.generation.state = PublicationState.retry_wait
        self.generation.reason = reason
        self.generation.retry_at = retry_at or NOW
        self.generation.lease_owner = None
        self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.retry_wait, generation=self.generation)

    def block_publication(
        self,
        publication_id: str,
        *,
        expected_state: PublicationState | str | None = None,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        reason: str = "operator_blocked",
        now: datetime | None = None,
    ):
        self.events.append("blocked")
        if self.block_lost:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.state = PublicationState.blocked
        self.generation.reason = reason
        self.generation.retry_at = None
        self.generation.lease_owner = None
        self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.blocked, generation=self.generation)


class _FakeProvider:
    def __init__(self, store: _FakeStore, *, fail: BaseException | None = None) -> None:
        self.store = store
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def put_object(
        self,
        key: str,
        content: bytes,
        object_class: R2ObjectClass = R2ObjectClass.public,
        *,
        metadata: object | None = None,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> R2PutResult:
        self.calls.append(("private" if object_class is R2ObjectClass.private else "public", key))
        self.store.events.append(f"r2:{self.calls[-1][0]}")
        if self.fail is not None:
            raise self.fail
        return R2PutResult(
            R2PutStatus.uploaded,
            key,
            object_class,
            len(content),
            hashlib.sha256(content).hexdigest(),
        )

    def stage(self, payload: object) -> StageReceipt:
        self.store.events.append("d1:stage")
        return StageReceipt(IDENTITY.publication_id, "task-1", "run-1")

    def expose(self, payload: object) -> ExposureReceipt:
        self.store.events.append("d1:expose")
        return ExposureReceipt(IDENTITY.publication_id, "task-1")

    def hide_task(self, task_id: str, reason: str) -> HideReceipt:
        self.store.events.append("d1:hide")
        return HideReceipt(
            task_id,
            self.store.generation.publication_id,
            changed=True,
        )


class _TransientHideProvider(_FakeProvider):
    def __init__(self, store: _FakeStore) -> None:
        super().__init__(store)
        self.hide_attempts = 0
        self.head_visible = True

    def hide_task(self, task_id: str, reason: str) -> HideReceipt:
        self.hide_attempts += 1
        self.store.events.append("d1:hide-attempt")
        if self.hide_attempts == 1:
            raise D1Error(D1ErrorCode.transient)
        self.head_visible = False
        return HideReceipt(
            task_id,
            self.store.generation.publication_id,
            changed=True,
        )


class _SQLitePublicationProvider:
    def __init__(
        self,
        *,
        hide_failures: int = 0,
        put_failure: BaseException | None = None,
    ) -> None:
        self.hide_failures = hide_failures
        self.put_failure = put_failure
        self.hide_attempts = 0
        self.put_attempts = 0
        self.head_visible = True

    def hide_task(self, task_id: str, reason: str) -> HideReceipt:
        self.hide_attempts += 1
        if self.hide_attempts <= self.hide_failures:
            raise D1Error(D1ErrorCode.transient)
        changed = self.head_visible
        self.head_visible = False
        return HideReceipt(task_id, None, changed=changed)

    def put_object(
        self,
        key: str,
        content: bytes,
        object_class: R2ObjectClass = R2ObjectClass.public,
        *,
        metadata: object | None = None,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> R2PutResult:
        self.put_attempts += 1
        if self.put_failure is not None:
            raise self.put_failure
        return R2PutResult(
            R2PutStatus.uploaded,
            key,
            object_class,
            len(content),
            hashlib.sha256(content).hexdigest(),
        )

    def stage(self, payload: object) -> StageReceipt:
        return StageReceipt(IDENTITY.publication_id, "task-1", "run-1")

    def expose(self, payload: object) -> ExposureReceipt:
        return ExposureReceipt(IDENTITY.publication_id, "task-1")


class _StageBarrierProvider(_SQLitePublicationProvider):
    def __init__(self) -> None:
        super().__init__()
        self.stage_entered = threading.Event()
        self.release_stage = threading.Event()
        self.expose_calls = 0

    def stage(self, payload: object):
        self.stage_entered.set()
        assert self.release_stage.wait(timeout=2.0)
        return super().stage(payload)

    def expose(self, payload: object):
        self.expose_calls += 1
        return super().expose(payload)


def _composer(callback) -> PublicationComposer:
    return callback if isinstance(callback, PublicationComposer) else PublicationComposer(callback)


def _publisher(store: _FakeStore, provider: _FakeProvider, *, compose=None) -> CloudPublisher:
    return CloudPublisher(
        store,
        provider,
        provider,
        "worker-1",
        compose=_composer(compose or compose_publication_generation),
        now=lambda: NOW,
        retry_policy=POLICY,
    )


def _blocked_store(identity: GenerationIdentity) -> _FakeStore:
    store = _FakeStore()
    store.generation.publication_id = identity.publication_id
    store.generation.task_id = identity.task_id
    store.generation.generation_boundary = identity.generation_boundary
    store.generation.idempotency_key = identity.idempotency_key
    store.generation.state = PublicationState.blocked
    store.generation.reason = "integrity"
    return store


def test_usage_delegates_use_canonical_d1_operations() -> None:
    overhead = OverheadReceipt("2026-07-28", "model", "digest")
    backfill = UsageBackfillReceipt(
        task_id="task-1",
        old_usage_generation_id="usage-old",
        usage_generation_id="usage-new",
        processed_turns=2,
        changed=True,
        next_cursor="cursor-next",
    )
    calls: list[tuple[str, object, object]] = []

    class D1:
        def upsert_overhead(
            self,
            source: object,
            *,
            digest: str | None = None,
            archive_digest: str | None = None,
            updated_at: str | None = None,
        ) -> OverheadReceipt:
            calls.append(("overhead", source, digest))
            return overhead

        def backfill_na_costs(
            self,
            catalog: object,
            *,
            cursor: str | None = None,
            limit: int = 64,
        ) -> UsageBackfillReceipt:
            calls.append(("backfill", catalog, cursor))
            assert limit == 8
            return backfill

    publisher = CloudPublisher(
        _FakeStore(), object(), D1(), retry_policy=POLICY
    )
    authority = object()
    assert publisher.reconcile_overhead(
        {"model": "model"}, digest="row-digest", authority=authority
    ) is overhead
    assert publisher.backfill_usage(
        "catalog", cursor="cursor", limit=8, authority=authority
    ) is backfill
    assert calls == [
        ("overhead", {"model": "model"}, "row-digest"),
        ("backfill", "catalog", "cursor"),
    ]


def test_live_daemon_authority_reaches_d1_without_task_attribution(tmp_path) -> None:
    store = TaskStore.create(tmp_path / "live-aggregate.sqlite", dry_run=False)
    store.claim_daemon_instance(
        "daemon-live",
        lifecycle="running",
        state={"execution_mode": ExecutionMode.dry_run.value},
    )
    state = store.get_daemon_state()
    assert state is not None
    assert state.get("execution_mode") is None
    assert state["publication_execution_mode"] == ExecutionMode.live.value
    authority = store.get_daemon_publication_authority("daemon-live")
    assert authority is not None

    calls: list[tuple[str, object, object]] = []
    overhead = OverheadReceipt(date="2026-07-28", model="model", digest="digest")
    backfill = UsageBackfillReceipt(
        processed_turns=2,
        changed=True,
        next_cursor="cursor-next",
    )

    class D1:
        def upsert_overhead(self, source: object, *, digest: str | None = None, **_kwargs):
            calls.append(("overhead", source, digest))
            return overhead

        def backfill_na_costs(
            self,
            catalog: object,
            *,
            cursor: str | None = None,
            limit: int = 64,
        ):
            calls.append(("backfill", catalog, cursor))
            assert limit == 64
            return backfill

    publisher = CloudPublisher(store, object(), D1(), retry_policy=POLICY)
    aggregate = {"model": "model", "ownershipClass": "steward-overhead"}
    assert publisher.reconcile_overhead(
        aggregate, digest="row-digest", authority=authority
    ) is overhead
    assert publisher.backfill_usage(
        "catalog", cursor="cursor", authority=authority
    ) is backfill
    assert calls == [
        ("overhead", aggregate, "row-digest"),
        ("backfill", "catalog", "cursor"),
    ]


def test_stale_foreign_stopped_and_dry_run_authority_never_reaches_provider(
    tmp_path,
) -> None:
    store = TaskStore.create(tmp_path / "authority-revocation.sqlite", dry_run=False)
    store.claim_daemon_instance("daemon-one", lifecycle="running")
    authority = store.get_daemon_publication_authority()
    assert authority is not None
    foreign = DaemonPublicationAuthority("foreign", authority.claim_id, authority.mode)
    calls: list[str] = []

    class D1:
        def upsert_overhead(self, *_args, **_kwargs):
            calls.append("overhead")
            raise AssertionError("revoked overhead reached D1")

        def backfill_na_costs(self, *_args, **_kwargs):
            calls.append("backfill")
            raise AssertionError("revoked backfill reached D1")

    publisher = CloudPublisher(store, object(), D1(), retry_policy=POLICY)
    successor = TaskStore.open(store.path, dry_run=False)
    successor.claim_daemon_instance("daemon-two", lifecycle="running")
    for candidate in (authority, foreign):
        with pytest.raises(PublicationError):
            publisher.reconcile_overhead({}, authority=candidate)
    successor_authority = successor.get_daemon_publication_authority()
    assert successor_authority is not None
    successor.set_daemon_lifecycle("stopped", instance_id="daemon-two")
    with pytest.raises(PublicationError):
        publisher.backfill_usage("catalog", authority=successor_authority)
    assert calls == []

    dry_store = TaskStore.open(store.path, dry_run=True)
    assert dry_store.get_daemon_publication_authority() is None
    assert dry_store.get_daemon_state()["publication_execution_mode"] == ExecutionMode.dry_run.value
    with pytest.raises(PublicationError):
        publisher.reconcile_overhead({}, authority=authority)
    assert calls == []


def test_taskless_aggregate_effects_never_reach_provider(tmp_path) -> None:
    store = TaskStore.create(tmp_path / "taskless-aggregate.sqlite", dry_run=False)
    calls: list[str] = []

    class D1:
        def upsert_overhead(self, *_args, **_kwargs):
            calls.append("overhead")
            raise AssertionError("taskless overhead reached D1")

        def backfill_na_costs(self, *_args, **_kwargs):
            calls.append("backfill")
            raise AssertionError("taskless backfill reached D1")

    publisher = CloudPublisher(store, object(), D1(), retry_policy=POLICY)
    with pytest.raises(PublicationError):
        publisher.reconcile_overhead({"model": "model"}, digest="row-digest")
    with pytest.raises(PublicationError):
        publisher.backfill_usage("catalog", cursor="cursor", limit=8)
    assert calls == []


def _compose_generation(
    *,
    private: bool = False,
    private_count: int = 1,
    metadata_digest: str = "a" * 64,
):
    def compose(
        _source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
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
        return _composed(
            private=private,
            private_count=private_count,
            metadata_digest=metadata_digest,
        )

    return _composer(compose)


def test_partial_composer_is_rejected_at_canonical_boundary() -> None:
    calls = 0

    def partial(_source: object, *, task_id: str) -> object:
        nonlocal calls
        calls += 1
        return task_id

    with pytest.raises(TypeError, match="PublicationComposer"):
        _call_composer(partial, {"stable": True}, task_id="task-1", kwargs={})
    assert calls == 0

    with pytest.raises(TypeError):
        _call_composer(PublicationComposer(partial), {"stable": True}, task_id="task-1", kwargs={})
    assert calls == 0


def _sqlite_store(path) -> TaskStore:
    store = TaskStore.create(path, dry_run=False)
    store.add_task(
        TaskSpec(
            id="task-1",
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="publication fixture",
            prompt="publication fixture",
        )
    )
    return store


def test_missing_task_identity_blocks_before_provider_request() -> None:
    store = _FakeStore()
    store.generation.task_id = None
    provider = _FakeProvider(store)

    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id,
        source={"stable": True},
    )

    assert result.status is PublicationStatus.blocked
    assert provider.calls == []


def _sqlite_generation() -> PublicationGeneration:
    return PublicationGeneration(
        publication_id=IDENTITY.publication_id,
        task_id="task-1",
        run_id="run-1",
        generation_boundary=IDENTITY.generation_boundary,
        metadata_digest="a" * 64,
        idempotency_key=IDENTITY.idempotency_key,
        created_at=NOW,
        updated_at=NOW,
        rows=5,
        objects=1,
        tasks=1,
        pipelines=1,
        runs=1,
        events=1,
        artifacts=1,
    )


def test_clean_generation_has_no_private_request_and_preserves_order() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)
    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.exposed
    assert [kind for kind, _ in provider.calls] == ["public"]
    assert store.events.index("d1:stage") < store.events.index("d1:expose")
    assert "d1:hide" not in store.events


def test_private_original_follows_all_public_objects() -> None:
    store = _FakeStore(with_private=True)
    provider = _FakeProvider(store)
    result = _publisher(store, provider, compose=_compose_generation(private=True)).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.exposed
    assert [kind for kind, _ in provider.calls] == ["public", "private"]
    assert store.events.index("r2:public") < store.events.index("r2:private") < store.events.index("d1:stage")
    assert "private original" not in repr(result)


def test_multiple_private_originals_follow_public_objects() -> None:
    store = _FakeStore(with_private=True, object_count=3)
    provider = _FakeProvider(store)
    result = _publisher(
        store,
        provider,
        compose=_compose_generation(private=True, private_count=2),
    ).publish(IDENTITY.publication_id, source={"stable": True})

    assert result.exposed
    assert [kind for kind, _ in provider.calls] == ["public", "private", "private"]
    assert store.events.index("r2:public") < store.events.index("r2:private")
    assert store.events.index("r2:private") < store.events.index("d1:stage")


def test_identity_mismatch_is_blocked_without_provider_request() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)
    result = _publisher(store, provider, compose=_compose_generation(metadata_digest="b" * 64)).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.blocked
    assert result.reason == "integrity"
    assert provider.calls == []
    assert "d1:hide" not in store.events


def test_precomposed_repair_enqueues_without_provider_access() -> None:
    old_identity = GenerationIdentity("task-1", "boundary-old")
    store = _blocked_store(old_identity)
    replacements: list[tuple[str, object]] = []

    def replace_blocked_publication(old_publication_id: str, generation: object):
        replacements.append((old_publication_id, generation))
        return SimpleNamespace(status=PublicationOperationStatus.enqueued)

    store.replace_blocked_publication = replace_blocked_publication
    provider = _FakeProvider(store)
    candidate = _composed()

    result = _publisher(store, provider)._enqueue_precomposed_repair(
        old_identity.publication_id,
        candidate,
    )

    assert result.status is PublicationStatus.queued
    assert result.publication_id == candidate.publication_id
    assert replacements == [(old_identity.publication_id, candidate.to_outbox())]
    assert provider.calls == []
    assert store.events == []


def test_precomposed_repair_rejects_invalid_candidates() -> None:
    candidate = _composed()
    lookalike = SimpleNamespace(
        **{
            name: getattr(candidate, name)
            for name in (
                "publication_id",
                "task_id",
                "run_id",
                "generation_boundary",
                "metadata_digest",
                "idempotency_key",
                "generation",
                "payload",
                "objects",
                "private_originals",
            )
        }
    )
    cases = (
        (GenerationIdentity("task-1", "boundary-old"), lookalike, "invalid_metadata"),
        (GenerationIdentity("task-2", "boundary-old"), candidate, "integrity"),
        (GenerationIdentity("task-1", IDENTITY.generation_boundary), candidate, "unchanged"),
    )

    for identity, value, reason in cases:
        store = _blocked_store(identity)
        replacements: list[tuple[str, object]] = []

        def replace_blocked_publication(old_publication_id: str, generation: object):
            replacements.append((old_publication_id, generation))
            return SimpleNamespace(status=PublicationOperationStatus.enqueued)

        store.replace_blocked_publication = replace_blocked_publication
        provider = _FakeProvider(store)
        result = _publisher(store, provider)._enqueue_precomposed_repair(
            identity.publication_id,
            value,
        )

        assert result.status is PublicationStatus.blocked
        assert result.reason == reason
        assert replacements == []
        assert provider.calls == []
        assert store.events == []


def test_receipt_logical_path_mismatch_blocks_before_provider_request() -> None:
    store = _FakeStore()
    composed = _composed()
    item = composed.objects[0]
    store.receipts.append(
        PublicationReceipt.public_receipt(
            item.sha256,
            item.byte_size,
            item.public_key,
            NOW,
            "runs/run-1/wrong.json",
        )
    )
    provider = _FakeProvider(store)

    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.blocked
    assert result.reason == "integrity"
    assert provider.calls == []


def test_reused_public_object_key_is_uploaded_once() -> None:
    store = _FakeStore(object_count=2)
    provider = _FakeProvider(store)

    def compose(
        _source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
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
        generated = _composed()
        return ComposedGeneration(
            payload=generated.payload,
            objects=(generated.objects[0], generated.objects[0]),
            private_originals=generated.private_originals,
        )

    result = _publisher(store, provider, compose=compose).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.exposed
    assert [kind for kind, _ in provider.calls] == ["public"]


def test_repair_required_keeps_claim_and_does_not_hide() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)

    def repair(
        _source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
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
        return RepairRequired((ReasonCode.source_finding,), ())

    result = _publisher(store, provider, compose=repair).publish(IDENTITY.publication_id, source={"task": {}})

    assert result.status is PublicationStatus.repair_required
    assert result.reason_codes == (ReasonCode.source_finding,)
    assert store.generation.state is PublicationState.building
    assert provider.calls == []
    assert "d1:hide" not in store.events


def test_composer_type_error_is_reduced_after_one_invocation() -> None:
    calls = 0

    def compose(
        _source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
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
        nonlocal calls
        calls += 1
        raise TypeError("composer body failed")

    store = _FakeStore()
    provider = _FakeProvider(store)
    result = _publisher(store, provider, compose=compose).publish(
        IDENTITY.publication_id,
        source={"stable": True},
    )

    assert result.status is PublicationStatus.blocked
    assert result.reason == ReasonCode.invalid_metadata.value
    assert calls == 1
    assert provider.calls == []


def test_transient_provider_failure_is_retry_wait_without_hiding() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store, fail=R2Error(R2ErrorCategory.network))
    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.retry_wait
    assert result.reason == "network"
    assert store.generation.state is PublicationState.retry_wait
    assert "d1:hide" not in store.events


def test_lost_claim_stops_before_remote_activity() -> None:
    store = _FakeStore()
    store.renew_lost = True
    provider = _FakeProvider(store)
    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.lost_claim
    assert provider.calls == []


def test_fail_closed_composition_is_blocked_and_hides() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)

    def fail(
        _source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
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
        return FailClosed((ReasonCode.unsafe_content,), ())

    result = _publisher(store, provider, compose=fail).publish(IDENTITY.publication_id, source={"task": {}})

    assert result.status is PublicationStatus.blocked
    assert result.reason_codes == (ReasonCode.unsafe_content,)
    assert provider.calls == []
    assert "d1:hide" in store.events


def test_transient_hide_failure_replays_before_blocking() -> None:
    store = _FakeStore()
    provider = _TransientHideProvider(store)
    compose_calls: list[object] = []

    def fail(
        _source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: object = None,
        builder: object = None,
        credential_sources: object = None,
        known_secrets: object = None,
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
        compose_calls.append(_source)
        return FailClosed((ReasonCode.unsafe_content,), ())

    publisher = _publisher(store, provider, compose=fail)
    first = publisher.publish(IDENTITY.publication_id, source={"task": {}})

    assert first.status is PublicationStatus.retry_wait
    assert first.reason == "network"
    assert store.generation.state is PublicationState.blocked
    assert store.generation.reason == "unsafe_content"
    assert provider.head_visible is True
    assert provider.hide_attempts == 1
    assert store.events[:5] == ["claim", "building", "renew", "renew", "renew"]
    assert store.events[5:7] == ["begin_hide", "d1:hide-attempt"]

    # The pending hide fence is durable; the next worker unit retries the
    # provider boundary without composing or changing the public state.
    second = publisher.hide_task("task-1", "unsafe_content")

    assert second.status is PublicationHideStatus.hidden
    assert store.generation.state is PublicationState.blocked
    assert provider.head_visible is False
    assert provider.hide_attempts == 2
    assert compose_calls == [{"task": {}}]
    assert store.events[-3:] == ["begin_hide", "d1:hide-attempt", "confirm_hide"]


def test_sqlite_hide_retry_at_attempt_ceiling_stays_reconcilable(tmp_path) -> None:
    store = _sqlite_store(tmp_path / "steward.sqlite")
    store.enqueue_publication(_sqlite_generation())
    provider = _SQLitePublicationProvider(hide_failures=MAX_ATTEMPTS)
    clock = [NOW]
    publisher = CloudPublisher(
        store,
        provider,
        provider,
        "worker-1",
        compose=_returning_composer(FailClosed((ReasonCode.unsafe_content,), ())),
        now=lambda: clock[0],
        retry_policy=POLICY,
    )

    first = publisher.publish(IDENTITY.publication_id, source={"task": {}})
    current = store.get_publication_generation(IDENTITY.publication_id)
    assert first.status is PublicationStatus.retry_wait
    assert current is not None
    assert current.state is PublicationState.blocked
    assert current.reason == "unsafe_content"
    assert store.get_publication_hide("task-1").state.value == "pending"

    for attempt in range(1, MAX_ATTEMPTS):
        clock[0] = NOW + timedelta(seconds=attempt * 2)
        replay = publisher.hide_task("task-1", "unsafe_content")
        assert replay.status.value == "blocked"
        current = store.get_publication_generation(IDENTITY.publication_id)
        assert current is not None
        assert current.state is PublicationState.blocked

    assert provider.head_visible is True
    assert provider.hide_attempts == MAX_ATTEMPTS

    clock[0] = NOW + timedelta(seconds=MAX_ATTEMPTS * 2 + 2)
    replay = publisher.hide_task("task-1", "unsafe_content")
    current = store.get_publication_generation(IDENTITY.publication_id)
    assert replay.status.value == "hidden"
    assert current is not None
    assert current.state is PublicationState.blocked
    assert provider.head_visible is False
    assert provider.hide_attempts == MAX_ATTEMPTS + 1
    assert store.get_publication_hide("task-1").state.value == "confirmed"


def test_sqlite_precondition_hide_failure_replays_and_blocks(tmp_path) -> None:
    store = _sqlite_store(tmp_path / "steward.sqlite")
    store.enqueue_publication(_sqlite_generation())
    provider = _SQLitePublicationProvider(
        put_failure=R2Error(R2ErrorCategory.precondition),
        hide_failures=1,
    )
    clock = [NOW]
    publisher = CloudPublisher(
        store,
        provider,
        provider,
        "worker-1",
        compose=_returning_composer(_composed()),
        now=lambda: clock[0],
        retry_policy=POLICY,
    )

    first = publisher.publish(IDENTITY.publication_id, source={"stable": True})
    current = store.get_publication_generation(IDENTITY.publication_id)

    assert first.status is PublicationStatus.retry_wait
    assert first.reason == "network"
    assert current is not None
    assert current.state is PublicationState.blocked
    assert current.reason == "integrity"
    assert current.lease_owner is None
    assert store.get_publication_hide("task-1").state.value == "pending"
    assert provider.put_attempts == 1
    assert provider.hide_attempts == 1
    assert provider.head_visible is True

    clock[0] = NOW + timedelta(seconds=2)
    replay = publisher.hide_task("task-1", "integrity")
    current = store.get_publication_generation(IDENTITY.publication_id)

    assert replay.status.value == "hidden"
    assert current is not None
    assert current.state is PublicationState.blocked
    assert current.reason == "integrity"
    assert current.lease_owner is None
    assert provider.put_attempts == 1
    assert provider.hide_attempts == 2
    assert provider.head_visible is False


def test_hide_fence_blocks_stage_release_before_exposure(tmp_path) -> None:
    store = _sqlite_store(tmp_path / "steward.sqlite")
    store.enqueue_publication(_sqlite_generation())
    provider = _StageBarrierProvider()
    publisher = CloudPublisher(
        store,
        provider,
        provider,
        "worker-1",
        compose=_returning_composer(_composed()),
        now=lambda: NOW,
        retry_policy=POLICY,
    )
    results: list[object] = []
    worker = threading.Thread(
        target=lambda: results.append(
            publisher.publish(IDENTITY.publication_id, source={"stable": True})
        )
    )
    worker.start()
    assert provider.stage_entered.wait(timeout=2.0)

    hidden = publisher.hide_task("task-1", "unsafe_content")
    provider.release_stage.set()
    worker.join(timeout=2.0)

    assert hidden.ok
    assert results and getattr(results[0], "status", None) is PublicationStatus.lost_claim
    assert provider.expose_calls == 0
    current = store.get_publication_generation(IDENTITY.publication_id)
    assert current is not None
    assert current.state is PublicationState.blocked
    fence = store.get_publication_hide("task-1")
    assert fence is not None
    assert fence.state.value == "confirmed"


def test_pending_hide_survives_restart_before_provider_retry(tmp_path) -> None:
    path = tmp_path / "steward.sqlite"
    store = _sqlite_store(path)
    store.enqueue_publication(_sqlite_generation())
    failing = _SQLitePublicationProvider(hide_failures=1)
    first = CloudPublisher(
        store,
        failing,
        failing,
        "worker-1",
        now=lambda: NOW,
        retry_policy=POLICY,
    ).hide_task("task-1", "unsafe_content")

    assert first.status.value == "blocked"
    assert first.reason == "network"
    assert store.get_publication_hide("task-1").state.value == "pending"
    store.engine.dispose()

    restarted = TaskStore.open(path)
    healthy = _SQLitePublicationProvider()
    second = CloudPublisher(
        restarted,
        healthy,
        healthy,
        "worker-2",
        now=lambda: NOW + timedelta(seconds=1),
        retry_policy=POLICY,
    ).hide_task("task-1", "unsafe_content")

    assert second.status.value == "hidden"
    assert restarted.get_publication_hide("task-1").state.value == "confirmed"


def test_sqlite_lease_expiry_reclaims_and_composes_without_hiding(tmp_path) -> None:
    store = _sqlite_store(tmp_path / "steward.sqlite")
    store.enqueue_publication(_sqlite_generation())
    store.claim_publication("worker-1", retry_policy=POLICY, now=NOW)
    assert store.advance_publication(
        IDENTITY.publication_id,
        PublicationState.claimed,
        PublicationState.building,
        lease_owner="worker-1",
        now=NOW,
    ).status is PublicationOperationStatus.advanced
    expired_at = NOW + timedelta(seconds=MAX_LEASE_SECONDS)
    store.expire_publication_leases(now=expired_at)
    expired = store.get_publication_generation(IDENTITY.publication_id)
    assert expired is not None
    assert expired.state is PublicationState.retry_wait
    assert expired.reason == "lease_expired"

    provider = _SQLitePublicationProvider()
    compose_calls: list[object] = []

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
        compose_calls.append(source)
        return _composed()

    result = CloudPublisher(
        store,
        provider,
        provider,
        "worker-2",
        compose=_composer(compose),
        now=expired_at,
        retry_policy=POLICY,
    ).publish(IDENTITY.publication_id, source={"stable": True})

    current = store.get_publication_generation(IDENTITY.publication_id)
    assert result.status is PublicationStatus.exposed
    assert compose_calls == [{"stable": True}]
    assert provider.hide_attempts == 0
    assert current is not None
    assert current.state is PublicationState.exposed


def test_composer_lookalike_is_rejected_before_provider_request() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)
    generated = _composed()
    lookalike = SimpleNamespace(
        **{
            name: getattr(generated, name)
            for name in (
                "publication_id",
                "task_id",
                "run_id",
                "generation_boundary",
                "metadata_digest",
                "idempotency_key",
                "generation",
                "payload",
                "objects",
                "private_originals",
            )
        }
    )
    result = _publisher(store, provider, compose=_returning_composer(lookalike)).publish(
        IDENTITY.publication_id, source={"stable": True}
    )
    assert result.status is PublicationStatus.blocked
    assert result.reason == "invalid_metadata"
    assert provider.calls == []

def test_prebuilt_transport_generation_is_not_a_composition_bypass() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)

    result = _publisher(store, provider).publish(
        IDENTITY.publication_id,
        generation=_composed(),
    )

    assert result.status is PublicationStatus.blocked
    assert result.reason == "invalid_metadata"
    assert provider.calls == []


def test_permanent_failure_revalidates_before_hiding() -> None:
    store = _FakeStore()
    store.renew_lost = True
    provider = _FakeProvider(store, fail=R2Error(R2ErrorCategory.auth))

    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.lost_claim
    assert "d1:hide" not in store.events
    assert "blocked" not in store.events


def test_failed_block_compare_and_set_never_reports_blocked() -> None:
    store = _FakeStore()
    store.block_lost = True
    provider = _FakeProvider(store, fail=R2Error(R2ErrorCategory.auth))

    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.lost_claim
    assert result.reason == "lease_expired"


def test_http_5xx_is_retryable_without_hiding() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store, fail=D1Error(D1ErrorCode.transient))

    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.retry_wait
    assert result.reason == "network"
    assert "d1:hide" not in store.events


def test_r2_conflict_is_permanent_and_hides_after_block() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store, fail=R2Error(R2ErrorCategory.precondition))

    result = _publisher(store, provider, compose=_compose_generation()).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.blocked
    assert result.reason == "precondition"
    assert "d1:hide" in store.events


class _LeaseClock:
    def __init__(self) -> None:
        self.seconds = 0
        self.renewed = threading.Condition()
        self.renewals = 0

    def now(self) -> datetime:
        return NOW + timedelta(seconds=self.seconds)

    def tick(self, seconds: int = 4) -> None:
        with self.renewed:
            previous = self.renewals
            self.seconds += seconds
            assert self.renewed.wait_for(lambda: self.renewals > previous, timeout=3)


@pytest.fixture
def lease_operation(tmp_path, monkeypatch):
    from coquic_steward.publication import publisher as publisher_module
    from coquic_steward.publication.cancellation import check_publication_active

    store = _sqlite_store(tmp_path / "lease.sqlite")
    store.enqueue_publication(_sqlite_generation())
    clock = _LeaseClock()
    renew = store.renew_publication_lease

    def observed_renew(worker_id, **kwargs):
        before = store.get_publication_generation(IDENTITY.publication_id)
        result = renew(worker_id, **kwargs)
        if result.status is PublicationOperationStatus.renewed:
            assert worker_id == "worker-1"
            assert before.lease_owner == worker_id
            assert before.lease_expires_at > kwargs["now"]
            with clock.renewed:
                clock.renewals += 1
                clock.renewed.notify_all()
        return result

    monkeypatch.setattr(store, "renew_publication_lease", observed_renew)
    stopped = threading.Event()
    work_renew = publisher_module._LeaseWork._renew

    def observe_stop(work, generation):
        work_renew(work, generation)
        if work.failure is not None:
            stopped.set()

    monkeypatch.setattr(publisher_module._LeaseWork, "_renew", observe_stop)
    cancel = threading.Event()
    entered = threading.Event()
    release = threading.Event()
    results = []
    errors = []
    paused = ["compose"]
    composer_error = [False]
    composer_action = [None]

    def pause(phase):
        if paused[0] == phase:
            entered.set()
            assert release.wait(5), "test must release admitted work"
        check_publication_active()

    class Provider(_SQLitePublicationProvider):
        expose_calls = 0
        stage_calls = 0

        def put_object(self, key, content, *args, **kwargs):
            pause("public")
            assert content == _composed().objects[0].content
            return super().put_object(key, content, *args, **kwargs)

        def stage(self, payload):
            pause("stage")
            self.stage_calls += 1
            return super().stage(payload)

        def expose(self, payload):
            pause("expose")
            self.expose_calls += 1
            return super().expose(payload)

    provider = Provider()

    def compose(source, **kwargs):
        pause("compose")
        if composer_action[0] is not None:
            composer_action[0]()
        if composer_error[0]:
            raise ValueError("composer failed")
        return _composed()

    publisher = CloudPublisher(
        store, provider, provider, "worker-1",
        compose=PublicationComposer(compose), now=clock.now,
        lease_seconds=9, retry_policy=POLICY, cancel_event=cancel,
    )
    source = {"stable": True}

    def publish():
        try:
            results.append(publisher.publish(IDENTITY.publication_id, source=source))
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=publish)
    fixture = SimpleNamespace(
        store=store, clock=clock, provider=provider, cancel=cancel,
        entered=entered, release=release, results=results, errors=errors, stopped=stopped,
        paused=paused, composer_error=composer_error, composer_action=composer_action, thread=thread,
        publisher=publisher,
    )
    yield fixture
    release.set()
    if thread.ident is not None:
        thread.join(5)
        assert not thread.is_alive()
    assert not errors
    assert source == {"stable": True}
    assert not any(t.name.startswith("publication-work") for t in threading.enumerate())
    store.engine.dispose()


@pytest.mark.parametrize("phase", ["compose", "public", "stage", "expose"])
def test_live_work_renews_multiple_times_past_original_lease(lease_operation, phase):
    op = lease_operation
    op.paused[0] = phase
    op.thread.start()
    assert op.entered.wait(3)
    for _ in range(3):
        op.clock.tick()
        row = op.store.get_publication_generation(IDENTITY.publication_id)
        assert row.lease_owner == "worker-1"
        assert row.attempt == 1
        assert row.lease_expires_at > op.clock.now()
    assert op.clock.now() > NOW + timedelta(seconds=9)
    op.release.set()
    op.thread.join(3)
    assert op.results[0].status is PublicationStatus.exposed
    assert op.provider.put_attempts == op.provider.stage_calls == op.provider.expose_calls == 1
    assert len(op.store.list_publication_receipts(IDENTITY.publication_id)) == 1
    row = op.store.get_publication_generation(IDENTITY.publication_id)
    assert row.state is PublicationState.exposed
    assert row.lease_owner is None


@pytest.mark.parametrize("phase", ["compose", "public", "stage", "expose"])
@pytest.mark.parametrize("loss", ["hide", "cancel", "other-worker", "same-worker"])
def test_long_work_stops_on_fence_without_resurrection(lease_operation, phase, loss):
    op = lease_operation
    op.paused[0] = phase
    op.thread.start()
    assert op.entered.wait(3)
    op.clock.tick()
    receipts = op.store.list_publication_receipts(IDENTITY.publication_id)
    if loss == "hide":
        op.store.begin_publication_hide("task-1", "operator_blocked", now=op.clock.now())
    elif loss == "cancel":
        op.cancel.set()
    else:
        op.clock.seconds += 10
        op.store.expire_publication_leases(now=op.clock.now())
        result = op.store.claim_publication(
            "worker-1" if loss == "same-worker" else "worker-2",
            publication_id=IDENTITY.publication_id,
            now=op.clock.now(), lease_seconds=9, retry_policy=POLICY,
        )
        assert result.status is PublicationOperationStatus.claimed
    before = op.store.get_publication_generation(IDENTITY.publication_id)
    op.clock.seconds += 4
    assert op.stopped.wait(3)
    renewals = op.clock.renewals
    op.clock.seconds += 4
    op.release.set()
    op.thread.join(3)
    expected = PublicationStatus.blocked if loss == "cancel" else PublicationStatus.lost_claim
    assert op.results[0].status is expected
    assert op.clock.renewals == renewals
    assert op.provider.expose_calls == 0
    assert op.store.list_publication_receipts(IDENTITY.publication_id) == receipts
    assert op.store.get_publication_generation(IDENTITY.publication_id) == before


def test_composer_exception_after_renewals_joins_before_blocking(lease_operation):
    op = lease_operation
    op.composer_error[0] = True
    op.thread.start()
    assert op.entered.wait(3)
    for _ in range(3):
        op.clock.tick()
    op.release.set()
    op.thread.join(3)
    assert op.results[0].status is PublicationStatus.blocked
    assert op.results[0].reason == "invalid_metadata"
    assert op.provider.put_attempts == op.provider.expose_calls == 0
    row = op.store.get_publication_generation(IDENTITY.publication_id)
    assert row.state is PublicationState.blocked
    assert row.lease_owner is None


def test_cancel_drains_composer_subprocess_and_scoped_worker(lease_operation, monkeypatch):
    import sys
    from coquic_steward.core.subprocesses import ProcessGroupCancellationOwner
    from coquic_steward.publication.cancellation import run_publication_process

    op = lease_operation
    registered = threading.Event()
    owners = []
    original = ProcessGroupCancellationOwner.register

    def register(owner, process):
        original(owner, process)
        owners.append(owner)
        registered.set()

    monkeypatch.setattr(ProcessGroupCancellationOwner, "register", register)
    op.paused[0] = None
    op.composer_action[0] = lambda: run_publication_process(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        capture_output=True, text=False, timeout=60, check=False, pass_fds=(), env={},
    )
    op.thread.start()
    assert registered.wait(3)
    op.cancel.set()
    op.thread.join(3)
    assert not op.thread.is_alive()
    assert op.results[0].status is PublicationStatus.blocked
    assert owners and all(owner.active_count == 0 for owner in owners)
    assert op.provider.put_attempts == op.provider.expose_calls == 0


def test_exposed_replay_authenticates_without_reacquiring_lease(lease_operation):
    op = lease_operation
    op.release.set()
    op.thread.start()
    op.thread.join(3)
    assert op.results[0].status is PublicationStatus.exposed
    count = op.clock.renewals
    result = op.publisher.publish(IDENTITY.publication_id, source={"stable": True})
    assert result.status is PublicationStatus.exposed
    assert op.provider.expose_calls == 1
    assert op.clock.renewals == count


def test_dry_run_admission_stops_live_composition_renewal(lease_operation):
    op = lease_operation
    op.thread.start()
    assert op.entered.wait(3)
    op.clock.tick()
    op.store.resolve_execution_modes(True)
    before = op.store.get_publication_generation(IDENTITY.publication_id)
    op.clock.seconds += 4
    assert op.stopped.wait(3)
    renewals = op.clock.renewals
    op.release.set()
    op.thread.join(3)
    assert op.results[0].status is PublicationStatus.blocked
    assert op.clock.renewals == renewals
    assert op.provider.put_attempts == op.provider.expose_calls == 0
    assert op.store.get_publication_generation(IDENTITY.publication_id) == before


def test_owned_scanner_process_preserves_descriptor_bytes_and_timeout_cleanup(tmp_path):
    import os
    import subprocess
    import sys
    from coquic_steward.core.subprocesses import ProcessGroupCancellationOwner, use_subprocess_owner
    from coquic_steward.publication.cancellation import publication_checkpoint, run_publication_process

    source = tmp_path / "scanner-input"
    source.write_bytes(b"\xff\x00source\n")
    owner = ProcessGroupCancellationOwner("publication-test")
    token = publication_checkpoint.set(lambda: None)
    kwargs = dict(capture_output=True, text=False, check=False, env=os.environ.copy())
    try:
        with use_subprocess_owner(owner), source.open("rb") as handle:
            result = run_publication_process(
                [sys.executable, "-c", f"import os; os.write(1, os.read({handle.fileno()}, 1024))"],
                pass_fds=(handle.fileno(),), timeout=3, **kwargs,
            )
            assert result.stdout == source.read_bytes() == b"\xff\x00source\n"
            assert result.stderr == b""
            assert result.returncode == 0
            with pytest.raises(subprocess.TimeoutExpired):
                run_publication_process(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    pass_fds=(), timeout=0.05, **kwargs,
                )
    finally:
        publication_checkpoint.reset(token)
    assert owner.active_count == 0

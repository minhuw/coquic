from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from coquic_steward.publication import (
    FailClosed,
    ReasonCode,
    RepairRequired,
)
from coquic_steward.publication.d1 import D1Error, D1ErrorCode
from coquic_steward.publication.generation import (
    GenerationObject,
    GenerationOriginal,
    compose_publication_generation,
)
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    MAX_ATTEMPTS,
    MAX_LEASE_SECONDS,
    PublicationOperationStatus,
    PublicationGeneration,
    PublicationReceipt,
    PublicationState,
    ReceiptClass,
)
from coquic_steward.publication.publisher import CloudPublisher, PublicationStatus
from coquic_steward.publication.r2 import R2Error, R2ErrorCategory, R2ObjectClass
from coquic_steward.storage import TaskStore


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
IDENTITY = GenerationIdentity("task-1", "boundary-1")


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
        },
        "runs": [{"runId": "run-1"}],
        "events": [{"sequence": 1}],
        "artifacts": [{"artifactId": "artifact-1"}],
    }
    return SimpleNamespace(
        publication_id=IDENTITY.publication_id,
        task_id="task-1",
        run_id="run-1",
        generation_boundary="boundary-1",
        metadata_digest=metadata_digest,
        idempotency_key=IDENTITY.idempotency_key,
        generation=payload["generation"],
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
            generation_boundary="boundary-1",
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

    def get_publication_generation(self, publication_id: str):
        return self.generation if publication_id == self.generation.publication_id else None

    def claim_publication(self, worker_id: str, *, publication_id: str, now: datetime, lease_seconds: int):
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

    def renew_publication_lease(self, worker_id: str, *, publication_id: str, now: datetime, lease_seconds: int):
        self.events.append("renew")
        if self.renew_lost:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.lease_expires_at = now + timedelta(seconds=lease_seconds)
        self.generation.updated_at = now
        return SimpleNamespace(status=PublicationOperationStatus.renewed, generation=self.generation)

    def advance_publication(self, publication_id: str, expected_state: PublicationState, target_state: PublicationState, *, lease_owner: str, now: datetime):
        self.events.append(target_state.value)
        if self.generation.state is not expected_state:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.state = target_state
        self.generation.updated_at = now
        if target_state is PublicationState.exposed:
            self.generation.lease_owner = None
            self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.advanced, generation=self.generation)

    def list_publication_receipts(self, publication_id: str):
        return list(self.receipts)

    def record_publication_receipt(
        self,
        publication_id: str,
        receipt: PublicationReceipt,
        *,
        lease_owner: str,
        now: datetime,
    ):
        assert lease_owner == "worker-1"
        assert now == NOW
        self.events.append(f"receipt:{receipt.receipt_class.value}")
        self.receipts.append(receipt)
        return SimpleNamespace(status=PublicationOperationStatus.recorded, generation=self.generation, receipt=receipt)

    def schedule_publication_retry(self, publication_id: str, **kwargs):
        self.events.append("retry_wait")
        self.generation.state = PublicationState.retry_wait
        self.generation.reason = kwargs.get("reason")
        self.generation.retry_at = kwargs.get("retry_at", NOW)
        self.generation.lease_owner = None
        self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.retry_wait, generation=self.generation)

    def block_publication(self, publication_id: str, **kwargs):
        self.events.append("blocked")
        if self.block_lost:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.state = PublicationState.blocked
        self.generation.reason = kwargs.get("reason")
        self.generation.retry_at = None
        self.generation.lease_owner = None
        self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.blocked, generation=self.generation)


class _FakeProvider:
    def __init__(self, store: _FakeStore, *, fail: BaseException | None = None) -> None:
        self.store = store
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def put_object(self, key: str, content: bytes, object_class: R2ObjectClass, **kwargs: object):
        self.calls.append(("private" if object_class is R2ObjectClass.private else "public", key))
        self.store.events.append(f"r2:{self.calls[-1][0]}")
        if self.fail is not None:
            raise self.fail

    def stage(self, payload: object):
        self.store.events.append("d1:stage")

    def expose(self, payload: object):
        self.store.events.append("d1:expose")
        return SimpleNamespace(state="visible")

    def hide_task(self, task_id: str, reason: str):
        self.store.events.append("d1:hide")


class _TransientHideProvider(_FakeProvider):
    def __init__(self, store: _FakeStore) -> None:
        super().__init__(store)
        self.hide_attempts = 0
        self.head_visible = True

    def hide_task(self, task_id: str, reason: str):
        self.hide_attempts += 1
        self.store.events.append("d1:hide-attempt")
        if self.hide_attempts == 1:
            raise D1Error(D1ErrorCode.transient)
        self.head_visible = False


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

    def hide_task(self, task_id: str, reason: str) -> None:
        self.hide_attempts += 1
        if self.hide_attempts <= self.hide_failures:
            raise D1Error(D1ErrorCode.transient)
        self.head_visible = False

    def put_object(self, key: str, content: bytes, object_class: R2ObjectClass, **kwargs: object):
        self.put_attempts += 1
        if self.put_failure is not None:
            raise self.put_failure
        return SimpleNamespace(
            key=key,
            sha256=kwargs.get("expected_sha256"),
            byte_size=kwargs.get("expected_size"),
        )

    def stage(self, payload: object):
        return SimpleNamespace(publication_id=IDENTITY.publication_id, task_id="task-1")

    def expose(self, payload: object):
        return SimpleNamespace(
            state="visible",
            publication_id=IDENTITY.publication_id,
            task_id="task-1",
        )


def _publisher(store: _FakeStore, provider: _FakeProvider, *, compose=None) -> CloudPublisher:
    return CloudPublisher(
        store,
        provider,
        provider,
        "worker-1",
        compose=compose or compose_publication_generation,
        now=lambda: NOW,
    )


def _compose_generation(
    *,
    private: bool = False,
    private_count: int = 1,
    metadata_digest: str = "a" * 64,
):
    def compose(_source: object, **_kwargs: object):
        return _composed(
            private=private,
            private_count=private_count,
            metadata_digest=metadata_digest,
        )

    return compose


def _sqlite_generation() -> PublicationGeneration:
    return PublicationGeneration(
        publication_id=IDENTITY.publication_id,
        task_id="task-1",
        run_id="run-1",
        generation_boundary="boundary-1",
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

    def compose(_source: object, **_kwargs: object):
        generated = _composed()
        generated.objects = (generated.objects[0], generated.objects[0])
        return generated

    result = _publisher(store, provider, compose=compose).publish(
        IDENTITY.publication_id, source={"stable": True}
    )

    assert result.status is PublicationStatus.exposed
    assert [kind for kind, _ in provider.calls] == ["public"]


def test_repair_required_keeps_claim_and_does_not_hide() -> None:
    store = _FakeStore()
    provider = _FakeProvider(store)

    def repair(_source: object, **kwargs: object):
        return RepairRequired((ReasonCode.source_finding,), ())

    result = _publisher(store, provider, compose=repair).publish(IDENTITY.publication_id, source={"task": {}})

    assert result.status is PublicationStatus.repair_required
    assert result.reason_codes == (ReasonCode.source_finding,)
    assert store.generation.state is PublicationState.building
    assert provider.calls == []
    assert "d1:hide" not in store.events


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

    def fail(_source: object, **kwargs: object):
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

    def fail(_source: object, **kwargs: object):
        compose_calls.append(_source)
        return FailClosed((ReasonCode.unsafe_content,), ())

    publisher = _publisher(store, provider, compose=fail)
    first = publisher.publish(IDENTITY.publication_id, source={"task": {}})

    assert first.status is PublicationStatus.retry_wait
    assert first.reason == "network"
    assert store.generation.state is PublicationState.retry_wait
    assert store.generation.reason == "unsafe_content"
    assert provider.head_visible is True
    assert provider.hide_attempts == 1
    assert store.events[:5] == ["claim", "building", "renew", "d1:hide-attempt", "retry_wait"]

    # The retry boundary is durable; once it is due, the next worker attempt
    # reclaims and hides before composing or changing the public state.
    store.generation.retry_at = NOW
    second = publisher.publish(IDENTITY.publication_id, source={"task": {}})

    assert second.status is PublicationStatus.blocked
    assert store.generation.state is PublicationState.blocked
    assert provider.head_visible is False
    assert provider.hide_attempts == 2
    assert compose_calls == [{"task": {}}]
    assert store.events[-4:] == ["claim", "renew", "d1:hide-attempt", "blocked"]


def test_sqlite_hide_retry_at_attempt_ceiling_stays_reconcilable(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    store.enqueue_publication(_sqlite_generation())
    provider = _SQLitePublicationProvider(hide_failures=MAX_ATTEMPTS)
    clock = [NOW]
    publisher = CloudPublisher(
        store,
        provider,
        provider,
        "worker-1",
        compose=lambda _source, **_kwargs: FailClosed((ReasonCode.unsafe_content,), ()),
        now=lambda: clock[0],
    )

    for attempt in range(MAX_ATTEMPTS):
        clock[0] = NOW + timedelta(seconds=attempt * 2)
        result = publisher.publish(IDENTITY.publication_id, source={"task": {}})
        current = store.get_publication_generation(IDENTITY.publication_id)
        assert result.status is PublicationStatus.retry_wait
        assert current is not None
        assert current.state is PublicationState.retry_wait
        assert current.reason == "unsafe_content"
        assert current.attempt == min(attempt + 1, MAX_ATTEMPTS)

    current = store.get_publication_generation(IDENTITY.publication_id)
    assert current is not None
    assert current.state is PublicationState.retry_wait
    assert provider.head_visible is True
    assert provider.hide_attempts == MAX_ATTEMPTS

    clock[0] = NOW + timedelta(seconds=MAX_ATTEMPTS * 2 + 2)
    replay = publisher.publish(IDENTITY.publication_id, source={"task": {}})
    current = store.get_publication_generation(IDENTITY.publication_id)
    assert replay.status is PublicationStatus.blocked
    assert current is not None
    assert current.state is PublicationState.blocked
    assert provider.head_visible is False
    assert provider.hide_attempts == MAX_ATTEMPTS + 1


def test_sqlite_precondition_hide_failure_replays_and_blocks(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
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
        compose=lambda _source, **_kwargs: _composed(),
        now=lambda: clock[0],
    )

    first = publisher.publish(IDENTITY.publication_id, source={"stable": True})
    current = store.get_publication_generation(IDENTITY.publication_id)

    assert first.status is PublicationStatus.retry_wait
    assert first.reason == "network"
    assert current is not None
    assert current.state is PublicationState.retry_wait
    assert current.reason == "integrity"
    assert current.lease_owner is None
    assert provider.put_attempts == 1
    assert provider.hide_attempts == 1
    assert provider.head_visible is True

    clock[0] = NOW + timedelta(seconds=2)
    replay = publisher.publish(IDENTITY.publication_id, source={"stable": True})
    current = store.get_publication_generation(IDENTITY.publication_id)

    assert replay.status is PublicationStatus.blocked
    assert replay.reason == "integrity"
    assert current is not None
    assert current.state is PublicationState.blocked
    assert current.reason == "integrity"
    assert current.lease_owner is None
    assert provider.put_attempts == 1
    assert provider.hide_attempts == 2
    assert provider.head_visible is False


def test_sqlite_lease_expiry_reclaims_and_composes_without_hiding(tmp_path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    store.enqueue_publication(_sqlite_generation())
    store.claim_publication("worker-1", now=NOW)
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

    def compose(source: object, **_kwargs: object):
        compose_calls.append(source)
        return _composed()

    result = CloudPublisher(
        store,
        provider,
        provider,
        "worker-2",
        compose=compose,
        now=expired_at,
    ).publish(IDENTITY.publication_id, source={"stable": True})

    current = store.get_publication_generation(IDENTITY.publication_id)
    assert result.status is PublicationStatus.exposed
    assert compose_calls == [{"stable": True}]
    assert provider.hide_attempts == 0
    assert current is not None
    assert current.state is PublicationState.exposed


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

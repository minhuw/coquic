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
    PublicationOperationStatus,
    PublicationReceipt,
    PublicationState,
    ReceiptClass,
)
from coquic_steward.publication.publisher import CloudPublisher, PublicationStatus
from coquic_steward.publication.r2 import R2Error, R2ErrorCategory, R2ObjectClass


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
        self.generation.state = PublicationState.claimed
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
        self.generation.lease_owner = None
        self.generation.lease_expires_at = None
        return SimpleNamespace(status=PublicationOperationStatus.retry_wait, generation=self.generation)

    def block_publication(self, publication_id: str, **kwargs):
        self.events.append("blocked")
        if self.block_lost:
            return SimpleNamespace(status=PublicationOperationStatus.lost_claim, generation=self.generation)
        self.generation.state = PublicationState.blocked
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

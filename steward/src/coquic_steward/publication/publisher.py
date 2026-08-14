"""Coordinate one claimed publication generation across R2 and D1.

This module is deliberately small and daemon-facing.  Composition is kept
transport-free in :mod:`generation`; this boundary only authenticates the
durable outbox row, performs the fixed remote protocol, and records one local
receipt or phase after each verified remote boundary.  No provider operation
is performed while a local SQLite transaction is open.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from ..storage import TaskStore
from .d1 import (
    D1Error,
    D1PublicationClient,
    HideReceipt,
    OverheadReceipt,
    UsageBackfillReceipt,
)
from .generation import (
    GenerationOutcome,
    GenerationObject,
    GenerationOriginal,
    PUBLICATION_SCHEMA_VERSION,
    PublicationComposer,
    PublicationGeneration as ComposedGeneration,
    compose_publication_generation,
)
from .models import FailClosed, PublicationError, ReasonCode, RepairRequired
from .outbox import (
    GenerationIdentity,
    MAX_LEASE_SECONDS,
    PublicationCounts,
    PublicationOperationStatus,
    PublicationReceipt,
    PublicationState,
    ReceiptClass,
)
from .r2 import R2Client, R2Error, R2ErrorCategory, R2ObjectClass, private_original_key


_DEFAULT_COMPOSER = PublicationComposer(compose_publication_generation)


class PublicationStatus(StrEnum):
    """The closed outcomes of one publication attempt."""

    queued = "queued"
    exposed = "exposed"
    retry_wait = "retry_wait"
    repair_required = "repair_required"
    blocked = "blocked"
    lost_claim = "lost_claim"


# Descriptive aliases make the result discoverable without introducing a
# second status vocabulary for callers.
PublishStatus = PublicationStatus
PublisherStatus = PublicationStatus
CloudPublishStatus = PublicationStatus


class PublicationHideStatus(StrEnum):
    """The closed outcomes of one operator hide request."""

    hidden = "hidden"
    unchanged = "unchanged"
    blocked = "blocked"
    missing = "missing"


_TRANSIENT_REASONS: Final[frozenset[str]] = frozenset(
    {"network", "quota", "timeout", "transient"}
)
_SAFE_REASONS: Final[frozenset[str]] = frozenset(
    {item.value for item in ReasonCode}
    | {
        "network",
        "quota",
        "authentication",
        "permission",
        "timeout",
        "transient",
        "provider",
        "integrity",
        "lease_expired",
        "retry_exhausted",
        "cleanup_failed",
        "operator_blocked",
        "precondition",
        "unchanged",
        "missing_evidence",
        "unavailable",
    }
)
_HIDE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "missing",
        "partial",
        "invalid_metadata",
        "source_finding",
        "patch_finding",
        "staging_unsafe",
        "scanner_failure",
        "ocr_failure",
        "unsafe_content",
        "irreparable",
        "integrity",
        "operator_blocked",
    }
)
_MAX_VIEW_LIMIT: Final[int] = 100
_MAX_VIEW_AGE_SECONDS: Final[int] = 10 * 365 * 24 * 60 * 60
_HIDE_RECONCILIATION_REASONS: Final[frozenset[str]] = frozenset(
    _SAFE_REASONS
    - {
        "network",
        "quota",
        "timeout",
        "transient",
        "lease_expired",
        "retry_exhausted",
        "cleanup_failed",
        "operator_blocked",
    }
)
_ACTIVE_STATES: Final[frozenset[PublicationState]] = frozenset(
    {
        PublicationState.claimed,
        PublicationState.building,
        PublicationState.uploading,
        PublicationState.d1_staged,
    }
)


def _reason(value: object, default: str = "provider") -> str:
    """Normalize an arbitrary provider/local failure to one safe category."""

    if isinstance(value, ReasonCode):
        return value.value
    if isinstance(value, StrEnum):
        value = value.value
    if isinstance(value, str) and value in _SAFE_REASONS:
        return value
    return default


def _reason_codes(values: Sequence[object]) -> tuple[ReasonCode, ...]:
    result: list[ReasonCode] = []
    for value in values:
        try:
            normalized = ReasonCode(value)
        except (TypeError, ValueError):
            continue
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _identifier(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    if not value[0].isalnum() or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in value
    ):
        return None
    return value


def _status(value: object) -> str:
    if isinstance(value, StrEnum):
        return str(value.value)
    return str(value)


def _generation_from(result: object) -> object | None:
    return getattr(result, "generation", None)


def _publication_id_from(value: object) -> object | None:
    candidate = getattr(value, "publication_id", None)
    if candidate is not None:
        return candidate
    if isinstance(value, Mapping):
        return value.get("publication_id", value.get("publicationId"))
    return None


def _is_composed_generation(value: object) -> bool:
    """Accept the immutable envelope and bounded test doubles alike."""

    if isinstance(value, ComposedGeneration):
        return True
    return all(
        hasattr(value, name)
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
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class PublicationResult:
    """A bounded, public-safe outcome from the coordinator.

    The composed generation and provider responses are intentionally absent.
    Callers receive only the durable publication identity, a closed status,
    bounded categories, and (when retry reconciliation attempted a hide) the
    typed hide outcome that is safe for logs and health rows.
    """

    status: PublicationStatus | str
    publication_id: str | None = None
    reason: str | None = None
    reason_codes: tuple[ReasonCode, ...] = ()
    phase: str | None = None
    hide_result: PublicationHideResult | None = None

    def __post_init__(self) -> None:
        try:
            status = PublicationStatus(self.status)
        except (TypeError, ValueError):
            status = PublicationStatus.blocked
        object.__setattr__(self, "status", status)
        publication_id = self.publication_id
        if publication_id is not None:
            publication_id = _identifier(publication_id)
            if publication_id is None:
                publication_id = None
        object.__setattr__(self, "publication_id", publication_id)
        normalized_reason = None if self.reason is None else _reason(self.reason)
        object.__setattr__(self, "reason", normalized_reason)
        object.__setattr__(self, "reason_codes", _reason_codes(self.reason_codes))
        if self.phase is not None:
            phase = self.phase if isinstance(self.phase, str) and len(self.phase) <= 64 else None
            object.__setattr__(self, "phase", phase)
        hide_result = self.hide_result
        if hide_result is not None and not isinstance(hide_result, PublicationHideResult):
            hide_result = None
        object.__setattr__(self, "hide_result", hide_result)

    @property
    def ok(self) -> bool:
        return self.status in {PublicationStatus.exposed, PublicationStatus.queued}

    @property
    def exposed(self) -> bool:
        return self.status is PublicationStatus.exposed

    @property
    def retryable(self) -> bool:
        return self.status is PublicationStatus.retry_wait

    @property
    def queued(self) -> bool:
        return self.status is PublicationStatus.queued

    @property
    def lost(self) -> bool:
        return self.status is PublicationStatus.lost_claim

    @property
    def outcome(self) -> str:
        return self.status.value

    @property
    def state(self) -> str:
        return self.status.value

    @property
    def category(self) -> str | None:
        return self.reason

    @property
    def reasons(self) -> tuple[ReasonCode, ...]:
        return self.reason_codes

    @property
    def hide(self) -> PublicationHideResult | None:
        """Return the hide reconciliation outcome, when retry attempted one."""

        return self.hide_result

    def as_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "status": self.status.value,
            "publicationId": self.publication_id,
            "reason": self.reason,
            "reasonCodes": [item.value for item in self.reason_codes],
        }
        if self.phase is not None:
            value["phase"] = self.phase
        if self.hide_result is not None:
            value["hide"] = self.hide_result.as_dict()
        return value


@dataclass(frozen=True, slots=True)
class PublicationHideResult:
    """A public-safe result from a task-head hide request."""

    status: PublicationHideStatus | str
    task_id: str | None = None
    publication_id: str | None = None
    reason: str | None = None
    changed: bool = False

    def __post_init__(self) -> None:
        try:
            status = PublicationHideStatus(self.status)
        except (TypeError, ValueError):
            status = PublicationHideStatus.blocked
        object.__setattr__(self, "status", status)
        task_id = _identifier(self.task_id) if self.task_id is not None else None
        publication_id = (
            _identifier(self.publication_id) if self.publication_id is not None else None
        )
        object.__setattr__(self, "task_id", task_id)
        object.__setattr__(self, "publication_id", publication_id)
        object.__setattr__(
            self,
            "reason",
            None if self.reason is None else _reason(self.reason),
        )
        object.__setattr__(self, "changed", bool(self.changed))

    @property
    def ok(self) -> bool:
        return self.status in {
            PublicationHideStatus.hidden,
            PublicationHideStatus.unchanged,
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "taskId": self.task_id,
            "publicationId": self.publication_id,
            "reason": self.reason,
            "changed": self.changed,
        }


PublisherResult = PublicationResult
CloudPublicationResult = PublicationResult
PublicationOutcomeResult = PublicationResult


def _result(
    status: PublicationStatus,
    publication_id: str | None,
    *,
    reason: object | None = None,
    reason_codes: Sequence[object] = (),
    phase: str | None = None,
    hide_result: PublicationHideResult | None = None,
) -> PublicationResult:
    return PublicationResult(
        status,
        publication_id,
        None if reason is None else _reason(reason),
        _reason_codes(reason_codes),
        phase,
        hide_result,
    )


def _view_int(value: object, *, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(value, maximum))


def _view_age(value: object, now: datetime) -> int:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return 0
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return 0
    try:
        seconds = int((now - value.astimezone(timezone.utc)).total_seconds())
    except (OverflowError, TypeError, ValueError):
        return 0
    return max(0, min(seconds, _MAX_VIEW_AGE_SECONDS))


def _view_reason(value: object | None) -> str | None:
    if value is None or value == "success":
        return None
    normalized = _reason(value, "integrity")
    return normalized


def _view_value(value: object, *names: str, default: object = None) -> object:
    if isinstance(value, Mapping):
        for name in names:
            if name in value:
                return value[name]
    else:
        for name in names:
            selected = getattr(value, name, None)
            if selected is not None:
                return selected
    return default


def _view_identifier(value: object) -> str | None:
    try:
        return _identifier(value)
    except Exception:
        return None


def publication_health_view(
    store: TaskStore,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Return only bounded queue, block, cleanup, age, and reason facts."""

    health = store.get_publication_health(now=now)
    timestamp = _timestamp(now, _now()) if now is not None else _now()
    updated_at = _view_value(health, "updated_at", "updatedAt")
    oldest = _view_value(health, "oldest_queued_at", "oldestQueuedAt")
    reason = _view_reason(_view_value(health, "reason", "last_category", "lastCategory"))
    return {
        "queuedCount": _view_int(
            _view_value(health, "queued_count", "queue_count", "queuedCount")
        ),
        "blockedCount": _view_int(_view_value(health, "blocked_count", "blockedCount")),
        "cleanupPendingCount": _view_int(
            _view_value(
                health,
                "cleanup_pending_count",
                "cleanup_count",
                "cleanupPendingCount",
            )
        ),
        "cleanupPendingBytes": _view_int(
            _view_value(
                health,
                "cleanup_pending_bytes",
                "cleanup_bytes",
                "cleanupPendingBytes",
            )
        ),
        "oldestQueuedAgeSeconds": _view_age(oldest, timestamp),
        "updatedAgeSeconds": _view_age(updated_at, timestamp),
        "reason": reason,
        "reasonCodes": [reason] if reason is not None else [],
    }


def publication_generation_views(
    store: TaskStore,
    *,
    limit: int = 20,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Return bounded generation summaries without private locators or paths."""

    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= _MAX_VIEW_LIMIT:
        raise ValueError("invalid publication view limit")
    generations = store.list_publication_generations(limit=limit)
    timestamp = _timestamp(now, _now()) if now is not None else _now()
    values: list[dict[str, object]] = []
    for generation in list(generations)[:limit]:
        publication_id = _view_identifier(
            _view_value(generation, "publication_id", "publicationId")
        )
        task_id = _view_identifier(_view_value(generation, "task_id", "taskId"))
        run_id = _view_identifier(_view_value(generation, "run_id", "runId"))
        state_value = _status(_view_value(generation, "state", default="blocked"))
        try:
            state = PublicationState(state_value).value
        except (TypeError, ValueError):
            state = PublicationState.blocked.value
        reason = _view_reason(_view_value(generation, "reason"))
        counts = _view_value(generation, "counts", default=None)
        if not isinstance(counts, (PublicationCounts, Mapping)):
            counts = None
        count_view = {
            "rows": _view_int(_view_value(generation, "rows", "row_count", default=_view_value(counts, "rows", default=0))),
            "objects": _view_int(_view_value(generation, "objects", "object_count", default=_view_value(counts, "objects", default=0))),
            "tasks": _view_int(_view_value(generation, "tasks", default=_view_value(counts, "tasks", default=0))),
            "pipelines": _view_int(_view_value(generation, "pipelines", default=_view_value(counts, "pipelines", default=0))),
            "runs": _view_int(_view_value(generation, "runs", default=_view_value(counts, "runs", default=0))),
            "events": _view_int(_view_value(generation, "events", default=_view_value(counts, "events", default=0))),
            "artifacts": _view_int(_view_value(generation, "artifacts", default=_view_value(counts, "artifacts", default=0))),
        }
        receipt_classes: set[str] = set()
        if publication_id is not None:
            try:
                receipts = store.list_publication_receipts(publication_id)
            except Exception:
                receipts = ()
            for receipt in receipts:
                selected = _view_value(receipt, "receipt_class", "object_class", "class")
                if isinstance(selected, StrEnum):
                    selected = selected.value
                if selected in {ReceiptClass.public.value, ReceiptClass.private.value}:
                    receipt_classes.add(selected)
        updated_at = _view_value(generation, "updated_at", "updatedAt")
        values.append(
            {
                "publicationId": publication_id,
                "taskId": task_id,
                "runId": run_id,
                "state": state,
                "ageSeconds": _view_age(updated_at, timestamp),
                "counts": count_view,
                "receiptClasses": sorted(receipt_classes),
                "reason": reason,
                "reasonCodes": [reason] if reason is not None else [],
            }
        )
    return values


def _operation_is(result: object, status: PublicationOperationStatus | str) -> bool:
    return _status(getattr(result, "status", result)) == _status(status)


def _is_lost(result: object) -> bool:
    return _operation_is(result, PublicationOperationStatus.lost_claim)


def _record_generation(result: object, fallback: object) -> object:
    return _generation_from(result) or fallback


def _timestamp(value: datetime | None, fallback: datetime) -> datetime:
    selected = value or fallback
    if selected.tzinfo is None or selected.utcoffset() is None:
        return fallback
    return selected.astimezone(timezone.utc)


def _provider_category(error: BaseException) -> str:
    """Reduce R2/D1 and injected fake errors to the shared safe vocabulary."""

    if isinstance(error, R2Error):
        category = error.category.value
        return {
            "auth": "authentication",
            "validation": "integrity",
        }.get(category, category)
    if isinstance(error, D1Error):
        category = error.code.value
        return {
            "authentication": "authentication",
            "invalid_request": "integrity",
            "private_value": "integrity",
            "malformed_response": "integrity",
            "response_too_large": "integrity",
            "result_limit": "integrity",
            "generation_conflict": "integrity",
            "generation_state": "integrity",
            "count_mismatch": "integrity",
            "digest_mismatch": "integrity",
            "transient": "network",
        }.get(category, category)
    for name in ("category", "code", "kind", "reason_code"):
        value = getattr(error, name, None)
        if isinstance(value, StrEnum):
            value = value.value
        if isinstance(value, str):
            return _reason(value)
    return "provider"


def _is_transient(category: str) -> bool:
    return category in _TRANSIENT_REASONS or category == R2ErrorCategory.network.value


def _hide_reconciliation_reason(generation: object | None, now: datetime) -> str | None:
    """Identify a due retry which still needs its public head reconciled.

    Ordinary transport retries persist one of the transient categories.  A
    hide retry instead persists the original bounded block category, giving a
    restart-safe marker without adding another outbox field.
    """

    state = _status(getattr(generation, "state", ""))
    if state == PublicationState.retry_wait.value:
        retry_at = getattr(generation, "retry_at", None)
        try:
            if retry_at is not None and retry_at > now:
                return None
        except TypeError:
            return None
    elif state not in {item.value for item in _ACTIVE_STATES}:
        return None
    reason = getattr(generation, "reason", None)
    if not isinstance(reason, str) or reason not in _HIDE_RECONCILIATION_REASONS:
        return None
    return _reason(reason, "integrity")


def _call_composer(
    composer: PublicationComposer,
    source: object,
    *,
    task_id: str,
    kwargs: Mapping[str, object],
) -> GenerationOutcome | object:
    """Call one composer once through the canonical composition contract."""

    if not isinstance(composer, PublicationComposer):
        raise TypeError("composer must be a PublicationComposer")
    selected = dict(kwargs)
    selected["task_id"] = task_id
    return composer(source, **selected)


class CloudPublisher:
    """Publish one claimed generation through the fixed R2/D1 protocol."""

    def __init__(
        self,
        store: TaskStore,
        r2: R2Client,
        d1: D1PublicationClient,
        worker_id: str = "publication-worker",
        *,
        compose: PublicationComposer = _DEFAULT_COMPOSER,
        now: Callable[[], datetime] | datetime | None = None,
        lease_seconds: int = MAX_LEASE_SECONDS,
        retry_backoff_seconds: int = 1,
    ) -> None:
        if _identifier(worker_id) is None:
            raise PublicationError(ReasonCode.invalid_identifier)
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 0 < lease_seconds <= MAX_LEASE_SECONDS:
            raise PublicationError(ReasonCode.invalid_metadata)
        if isinstance(retry_backoff_seconds, bool) or not isinstance(retry_backoff_seconds, int) or not 0 < retry_backoff_seconds <= 30 * 24 * 60 * 60:
            raise PublicationError(ReasonCode.invalid_metadata)
        self.store = store
        self.r2 = r2
        self.d1 = d1
        self.worker_id = worker_id
        self.compose = compose
        self._clock = (lambda: now) if isinstance(now, datetime) else (now or _now)
        self.lease_seconds = lease_seconds
        self.retry_backoff_seconds = retry_backoff_seconds

    def _time(self) -> datetime:
        return _timestamp(self._clock(), _now())

    def _get(self, publication_id: str) -> object | None:
        return self.store.get_publication_generation(publication_id)

    def status_view(self, *, now: datetime | None = None) -> dict[str, object]:
        """Return the bounded local health view used by operator commands."""

        return publication_health_view(self.store, now=now)

    def list_view(
        self,
        *,
        limit: int = 20,
        now: datetime | None = None,
    ) -> list[dict[str, object]]:
        """Return bounded generation summaries used by operator commands."""

        return publication_generation_views(self.store, limit=limit, now=now)

    def reconcile_overhead(
        self,
        source: object,
        *,
        digest: str | None = None,
    ) -> OverheadReceipt:
        """Reconcile one aggregate-only Steward overhead row in D1."""

        return self.d1.upsert_overhead(source, digest=digest)

    def backfill_usage(
        self,
        catalog: object,
        *,
        cursor: str | None = None,
        limit: int = 64,
    ) -> UsageBackfillReceipt:
        """Fill newly priceable cached-D1 usage turns through D1."""

        return self.d1.backfill_na_costs(catalog, cursor=cursor, limit=limit)

    publication_status = status_view
    publication_list = list_view

    def _claim(self, publication_id: str, current: object | None) -> tuple[object | None, PublicationResult | None]:
        if current is None:
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="integrity")
        state = _status(getattr(current, "state", ""))
        owner = getattr(current, "lease_owner", None)
        expires = getattr(current, "lease_expires_at", None)
        timestamp = self._time()
        if state in {item.value for item in _ACTIVE_STATES} and owner == self.worker_id and expires is not None and expires > timestamp:
            return current, None
        if state in {PublicationState.queued.value, PublicationState.retry_wait.value}:
            if state == PublicationState.retry_wait.value:
                retry_at = getattr(current, "retry_at", None)
                if retry_at is not None and retry_at > timestamp:
                    return None, _result(PublicationStatus.retry_wait, publication_id, reason=getattr(current, "reason", "network"))
            claimed = self.store.claim_publication(
                self.worker_id,
                publication_id=publication_id,
                now=timestamp,
                lease_seconds=self.lease_seconds,
            )
            if _operation_is(claimed, PublicationOperationStatus.claimed):
                return _record_generation(claimed, current), None
            if _is_lost(claimed):
                return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
            if _operation_is(claimed, PublicationOperationStatus.empty) or _operation_is(claimed, PublicationOperationStatus.missing):
                return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
            if _operation_is(claimed, PublicationOperationStatus.retry_exhausted):
                return None, _result(PublicationStatus.blocked, publication_id, reason="retry_exhausted")
            return None, _result(PublicationStatus.blocked, publication_id, reason=getattr(claimed, "reason", "integrity"))
        if state in {PublicationState.exposed.value, PublicationState.terminal_cleaned.value}:
            return current, None
        if state == PublicationState.blocked.value:
            return None, _result(PublicationStatus.blocked, publication_id, reason=getattr(current, "reason", "operator_blocked"))
        return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")

    def _renew(self, generation: object) -> tuple[object | None, PublicationResult | None]:
        publication_id = getattr(generation, "publication_id", None)
        if not isinstance(publication_id, str):
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        try:
            renewed = self.store.renew_publication_lease(
                self.worker_id,
                publication_id=publication_id,
                now=self._time(),
                lease_seconds=self.lease_seconds,
            )
        except Exception:
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        if _operation_is(renewed, PublicationOperationStatus.renewed):
            return _record_generation(renewed, generation), None
        if _is_lost(renewed):
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        return None, _result(PublicationStatus.lost_claim, publication_id, reason=getattr(renewed, "reason", "lease_expired"))

    def _advance(
        self,
        generation: object,
        expected: PublicationState,
        target: PublicationState,
    ) -> tuple[object | None, PublicationResult | None]:
        publication_id = getattr(generation, "publication_id", None)
        if not isinstance(publication_id, str):
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        try:
            changed = self.store.advance_publication(
                publication_id,
                expected,
                target,
                lease_owner=self.worker_id,
                now=self._time(),
            )
        except Exception:
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        if _operation_is(changed, PublicationOperationStatus.advanced):
            return _record_generation(changed, generation), None
        if _is_lost(changed):
            return None, _result(PublicationStatus.lost_claim, publication_id, reason=getattr(changed, "reason", "lease_expired"))
        return None, _result(PublicationStatus.blocked, publication_id, reason=getattr(changed, "reason", "integrity"))

    def _hide(
        self,
        generation: object,
        category: str,
        *,
        phase: str,
    ) -> tuple[object | None, PublicationResult | None]:
        """Hide the task head under a current lease, or durably replay it.

        ``begin_publication_hide`` is the local half of the cross-boundary
        protocol.  It retires the generation before the provider call, so a
        transient provider failure leaves a pending hide fence rather than a
        claimable publication row.
        """

        renewed, lost = self._renew(generation)
        if lost is not None:
            return None, lost
        if renewed is None:
            return None, _result(
                PublicationStatus.lost_claim,
                getattr(generation, "publication_id", None),
                reason="lease_expired",
                phase=phase,
            )
        task_id = getattr(renewed, "task_id", None)
        if not isinstance(task_id, str):
            return None, self._retry(
                renewed,
                "provider",
                phase=phase,
                hide_pending=True,
                durable_reason=category,
            )

        hide_reason = category if category in _HIDE_REASONS else "integrity"
        hidden = self.hide_task(task_id, hide_reason)
        if hidden.ok:
            return renewed, None
        result_reason = _reason(hidden.reason, "integrity")
        if _is_transient(result_reason):
            return None, _result(
                PublicationStatus.retry_wait,
                getattr(renewed, "publication_id", None),
                reason=result_reason,
                phase=phase,
            )
        return None, _result(
            PublicationStatus.blocked,
            getattr(renewed, "publication_id", None),
            reason=result_reason,
            phase=phase,
        )

    def _block(self, generation: object, reason: object, *, hide: bool, phase: str) -> PublicationResult:
        publication_id = getattr(generation, "publication_id", None)
        category = _reason(reason, "integrity")

        if hide:
            renewed, hidden = self._hide(generation, category, phase=phase)
            if hidden is not None:
                return hidden
            if renewed is None:
                return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
            generation = renewed
        if not isinstance(publication_id, str):
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
        try:
            block_result = self.store.block_publication(
                publication_id,
                lease_owner=self.worker_id,
                reason=category,
                now=self._time(),
            )
        except Exception:
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
        if _is_lost(block_result):
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
        if _operation_is(block_result, PublicationOperationStatus.existing):
            # A local hide fence retires the generation before the provider
            # call.  ``block_publication`` therefore reports an idempotent
            # existing result after a successful hide.
            blocked_generation = _generation_from(block_result)
            if blocked_generation is None or _status(getattr(blocked_generation, "state", "")) != PublicationState.blocked.value:
                return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
            return _result(PublicationStatus.blocked, publication_id, reason=category, phase=phase)
        if not _operation_is(block_result, PublicationOperationStatus.blocked):
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
        codes = (ReasonCode(category),) if category in {item.value for item in ReasonCode} else ()
        return _result(PublicationStatus.blocked, publication_id, reason=category, reason_codes=codes, phase=phase)

    def _retry(
        self,
        generation: object,
        category: str,
        *,
        phase: str,
        hide_pending: bool = False,
        durable_reason: object | None = None,
    ) -> PublicationResult:
        publication_id = getattr(generation, "publication_id", None)
        if not isinstance(publication_id, str):
            if hide_pending:
                return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
            return self._block(generation, "integrity", hide=False, phase=phase)
        persisted_reason = (
            _reason(durable_reason, "integrity")
            if durable_reason is not None
            else ("network" if category == "precondition" else category)
        )
        # ``precondition`` is a provider operation outcome, not one of the
        # durable outbox reason values.  Keep the provider category in the
        # returned result, but persist the hide obligation as the bounded
        # integrity category accepted by the local model.
        if persisted_reason == "precondition":
            persisted_reason = "integrity"
        try:
            scheduled = self.store.schedule_publication_retry(
                publication_id,
                expected_state=getattr(generation, "state", None),
                lease_owner=self.worker_id,
                retry_at=self._time() + timedelta(seconds=self.retry_backoff_seconds),
                reason=persisted_reason,
                now=self._time(),
            )
        except Exception:
            if hide_pending:
                return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
            return self._block(generation, "integrity", hide=False, phase=phase)
        if _operation_is(scheduled, PublicationOperationStatus.retry_wait):
            result_reason = "network" if category == "precondition" else category
            return _result(PublicationStatus.retry_wait, publication_id, reason=result_reason, phase=phase)
        if _is_lost(scheduled):
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
        if _operation_is(scheduled, PublicationOperationStatus.retry_exhausted):
            if hide_pending:
                return _result(PublicationStatus.lost_claim, publication_id, reason="retry_exhausted", phase=phase)
            durable = _generation_from(scheduled)
            if durable is not None and _status(getattr(durable, "state", "")) == PublicationState.blocked.value:
                return _result(
                    PublicationStatus.blocked,
                    publication_id,
                    reason="retry_exhausted",
                    phase=phase,
                )
            return self._block(generation, "retry_exhausted", hide=False, phase=phase)
        if hide_pending:
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase=phase)
        return self._block(generation, "integrity", hide=False, phase=phase)

    def _reconcile_hide(self, generation: object, reason: str, *, phase: str) -> PublicationResult:
        renewed, hidden = self._hide(generation, reason, phase=phase)
        if hidden is not None:
            return hidden
        if renewed is None:
            return _result(
                PublicationStatus.lost_claim,
                getattr(generation, "publication_id", None),
                reason="lease_expired",
                phase=phase,
            )
        return self._block(renewed, reason, hide=False, phase=phase)

    def _provider_failure(self, generation: object, error: BaseException, *, phase: str) -> PublicationResult:
        category = _provider_category(error)
        if _is_transient(category):
            return self._retry(generation, category, phase=phase)
        return self._block(generation, category, hide=True, phase=phase)

    def retry_publication(
        self,
        publication_id: str,
        source: object | None = None,
        *,
        compose_kwargs: Mapping[str, object] | None = None,
    ) -> PublicationResult:
        """Rescan current evidence and replace only a changed generation.

        The existing row remains blocked when composition returns the same
        deterministic identity, a repair outcome, or a fail-closed outcome.
        A successful retry is local and durable; the normal publication worker
        performs transport I/O for the newly queued row.
        """

        if _view_identifier(publication_id) is None:
            return _result(
                PublicationStatus.blocked,
                None,
                reason="invalid_metadata",
                reason_codes=(ReasonCode.invalid_metadata,),
                phase="retry",
            )
        try:
            current = self._get(publication_id)
        except Exception:
            return _result(
                PublicationStatus.blocked,
                publication_id,
                reason="integrity",
                phase="retry",
            )
        if current is None:
            return _result(PublicationStatus.blocked, publication_id, reason="missing", phase="retry")
        state = _status(getattr(current, "state", ""))
        if state != PublicationState.blocked.value:
            return _result(
                PublicationStatus.blocked,
                publication_id,
                reason="precondition",
                phase="retry",
            )
        if source is None:
            hide_result = self._retry_hide_head(current, "missing")
            return _result(
                PublicationStatus.blocked,
                publication_id,
                reason="missing",
                phase="retry",
                hide_result=hide_result,
            )
        try:
            composed_value = _call_composer(
                self.compose,
                source,
                task_id=str(getattr(current, "task_id", "")),
                kwargs=compose_kwargs or {},
            )
        except Exception:
            return _result(
                PublicationStatus.blocked,
                publication_id,
                reason="invalid_metadata",
                reason_codes=(ReasonCode.invalid_metadata,),
                phase="retry",
            )
        if isinstance(composed_value, RepairRequired):
            return _result(
                PublicationStatus.repair_required,
                publication_id,
                reason_codes=composed_value.reason_codes,
                phase="retry",
            )
        if isinstance(composed_value, FailClosed):
            reason = (
                composed_value.reason_codes[0]
                if composed_value.reason_codes
                else ReasonCode.unsafe_content
            )
            hide_result = self._retry_hide_head(current, _reason(reason, "integrity"))
            return _result(
                PublicationStatus.blocked,
                publication_id,
                reason=reason,
                reason_codes=composed_value.reason_codes,
                phase="retry",
                hide_result=hide_result,
            )
        if not _is_composed_generation(composed_value):
            return _result(
                PublicationStatus.blocked,
                publication_id,
                reason="invalid_metadata",
                reason_codes=(ReasonCode.invalid_metadata,),
                phase="retry",
            )
        composed = composed_value
        if composed.task_id != getattr(current, "task_id", None):
            return _result(PublicationStatus.blocked, publication_id, reason="integrity", phase="retry")
        if composed.publication_id == publication_id:
            if composed.metadata_digest == getattr(current, "metadata_digest", None):
                existing_reason = getattr(current, "reason", None)
                hide_result = None
                if isinstance(existing_reason, str) and existing_reason in _HIDE_REASONS:
                    hide_result = self._retry_hide_head(current, existing_reason)
                return _result(
                    PublicationStatus.blocked,
                    publication_id,
                    reason="unchanged",
                    phase="retry",
                    hide_result=hide_result,
                )
            return _result(PublicationStatus.blocked, publication_id, reason="integrity", phase="retry")
        record = getattr(composed, "outbox_record", None)
        if record is None:
            record = getattr(composed, "outbox", None)
        if record is None or _view_identifier(_publication_id_from(record)) != composed.publication_id:
            return _result(PublicationStatus.blocked, publication_id, reason="integrity", phase="retry")
        try:
            operation = self.store.replace_blocked_publication(publication_id, record)
        except Exception:
            return _result(PublicationStatus.blocked, publication_id, reason="integrity", phase="retry")
        operation_status = _status(getattr(operation, "status", operation))
        if operation_status not in {
            PublicationOperationStatus.enqueued.value,
            PublicationOperationStatus.existing.value,
        }:
            reason = _reason(getattr(operation, "reason", None), "integrity")
            if operation_status == PublicationOperationStatus.missing.value:
                reason = "missing"
            return _result(PublicationStatus.blocked, publication_id, reason=reason, phase="retry")
        queued_id = _view_identifier(getattr(composed, "publication_id", None))
        if queued_id is None:
            return _result(PublicationStatus.blocked, publication_id, reason="integrity", phase="retry")
        return _result(PublicationStatus.queued, queued_id, phase="retry")

    retry = retry_publication
    retry_generation = retry_publication
    rescan_retry = retry_publication

    def _retry_hide_head(self, generation: object, reason: str) -> PublicationHideResult:
        task_id = getattr(generation, "task_id", None)
        if not isinstance(task_id, str):
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                reason="integrity",
            )
        selected = reason if reason in _HIDE_REASONS else "integrity"
        try:
            result = self.hide_task(task_id, selected)
        except Exception as error:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason=_provider_category(error),
            )
        if isinstance(result, PublicationHideResult):
            return result
        try:
            return PublicationHideResult(
                getattr(result, "status", PublicationHideStatus.blocked),
                task_id=getattr(result, "task_id", task_id),
                publication_id=getattr(result, "publication_id", None),
                reason=getattr(result, "reason", "integrity"),
                changed=getattr(result, "changed", False),
            )
        except Exception:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason="integrity",
            )

    def hide_task(
        self,
        task_id: str,
        reason: str = "operator_blocked",
    ) -> PublicationHideResult:
        """Fence locally, hide atomically in D1, then confirm the fence.

        The local fence is committed before the provider request and remains
        pending when that request fails.  This gives restart reconciliation a
        durable obligation without holding SQLite across the D1 boundary.
        """

        try:
            task_id = _identifier(task_id)
        except Exception:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                reason="invalid_metadata",
            )
        if task_id is None:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                reason="invalid_metadata",
            )
        if not isinstance(reason, str) or reason not in _HIDE_REASONS:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason="invalid_metadata",
            )
        try:
            started = self.store.begin_publication_hide(
                task_id,
                reason,
                now=self._time(),
            )
        except Exception as error:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason=_provider_category(error),
            )
        started_status = _status(getattr(started, "status", started))
        if started_status not in {
            PublicationOperationStatus.enqueued.value,
            PublicationOperationStatus.existing.value,
        }:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason=_reason(getattr(started, "reason", None), "integrity"),
            )
        fence = getattr(started, "fence", None)
        fence_state = _status(getattr(fence, "state", ""))
        if fence_state == "confirmed":
            # The durable confirmation is already the validated receipt
            # boundary.  Do not issue an unnecessary provider request.
            publication_id: str | None = None
            try:
                generations = self.store.list_publication_generations(
                    task_id=task_id,
                    limit=None,
                )
                for generation in generations:
                    state = _status(getattr(generation, "state", ""))
                    candidate = getattr(generation, "publication_id", None)
                    if state in {
                        PublicationState.exposed.value,
                        PublicationState.terminal_cleaned.value,
                    } and isinstance(candidate, str):
                        publication_id = candidate
            except Exception:
                publication_id = None
            return PublicationHideResult(
                PublicationHideStatus.unchanged,
                task_id=task_id,
                publication_id=publication_id,
                reason=reason,
                changed=False,
            )

        if self.d1 is None:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason="precondition",
            )

        try:
            receipt = self.d1.hide_task(task_id, reason)
        except Exception as error:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason=_provider_category(error),
            )
        if not isinstance(receipt, HideReceipt):
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason="integrity",
            )
        if receipt.task_id != task_id or receipt.state != "hidden":
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                reason="integrity",
            )
        publication_id = receipt.publication_id
        if publication_id is not None:
            try:
                publication_id = _identifier(publication_id)
            except Exception:
                return PublicationHideResult(
                    PublicationHideStatus.blocked,
                    task_id=task_id,
                    reason="integrity",
                )
            if publication_id is None:
                return PublicationHideResult(
                    PublicationHideStatus.blocked,
                    task_id=task_id,
                    reason="integrity",
                )
        changed = receipt.changed
        try:
            confirmed = self.store.confirm_publication_hide(
                task_id,
                reason=reason,
                confirmed_at=self._time(),
            )
        except Exception:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                publication_id=publication_id,
                reason="integrity",
            )
        confirmed_status = _status(getattr(confirmed, "status", confirmed))
        if confirmed_status not in {
            PublicationOperationStatus.verified.value,
            PublicationOperationStatus.existing.value,
        }:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                publication_id=publication_id,
                reason=_reason(getattr(confirmed, "reason", None), "integrity"),
            )

        try:
            # Hide reconciliation is an internal safety operation, not a
            # bounded operator view.  Read the complete typed task scope
            # so an older queued generation cannot remain claimable after
            # a successful remote hide.
            generations = list(
                self.store.list_publication_generations(
                    task_id=task_id,
                    limit=None,
                )
            )
        except Exception:
            return PublicationHideResult(
                PublicationHideStatus.blocked,
                task_id=task_id,
                publication_id=publication_id,
                reason="integrity",
            )
        for generation in generations:
            if getattr(generation, "task_id", task_id) != task_id:
                continue
            generation_id = getattr(generation, "publication_id", None)
            state = _status(getattr(generation, "state", ""))
            if not isinstance(generation_id, str) or state in {
                PublicationState.exposed.value,
                PublicationState.terminal_cleaned.value,
                PublicationState.blocked.value,
            }:
                continue
            try:
                operation = self.store.block_publication(
                    generation_id,
                    expected_state=state,
                    lease_owner=getattr(generation, "lease_owner", None),
                    reason=reason,
                    now=self._time(),
                )
            except Exception:
                return PublicationHideResult(
                    PublicationHideStatus.blocked,
                    task_id=task_id,
                    publication_id=publication_id,
                    reason="integrity",
                )
            if _status(getattr(operation, "status", operation)) not in {
                PublicationOperationStatus.blocked.value,
                PublicationOperationStatus.existing.value,
            }:
                return PublicationHideResult(
                    PublicationHideStatus.blocked,
                    task_id=task_id,
                    publication_id=publication_id,
                    reason="integrity",
                )
        return PublicationHideResult(
            PublicationHideStatus.hidden if changed else PublicationHideStatus.unchanged,
            task_id=task_id,
            publication_id=publication_id,
            reason=reason,
            changed=changed,
        )

    hide = hide_task
    hide_publication = hide_task

    def _receipts(self, publication_id: str) -> dict[tuple[ReceiptClass, str], PublicationReceipt]:
        values = self.store.list_publication_receipts(publication_id)
        result: dict[tuple[ReceiptClass, str], PublicationReceipt] = {}
        for value in values:
            if not isinstance(value, PublicationReceipt):
                raise ValueError("invalid receipt")
            key = (value.receipt_class, value.content_key)
            previous = result.get(key)
            if previous is not None and (
                previous.sha256 != value.sha256
                or previous.byte_size != value.byte_size
                or previous.logical_path != value.logical_path
            ):
                raise ValueError("conflicting receipt")
            result[key] = value
        return result

    def _save_receipt(
        self,
        generation: object,
        receipt: PublicationReceipt,
    ) -> tuple[object | None, PublicationResult | None]:
        publication_id = getattr(generation, "publication_id", None)
        if not isinstance(publication_id, str):
            return None, self._block(generation, "integrity", hide=False, phase="receipt")
        try:
            saved = self.store.record_publication_receipt(
                publication_id,
                receipt,
                lease_owner=self.worker_id,
                now=self._time(),
            )
        except Exception:
            return None, self._block(generation, "integrity", hide=False, phase="receipt")
        if _operation_is(saved, PublicationOperationStatus.recorded) or _operation_is(saved, PublicationOperationStatus.existing):
            saved_receipt = getattr(saved, "receipt", None)
            if saved_receipt is not None and (
                not isinstance(saved_receipt, PublicationReceipt)
                or saved_receipt.receipt_class is not receipt.receipt_class
                or saved_receipt.sha256 != receipt.sha256
                or saved_receipt.byte_size != receipt.byte_size
                or saved_receipt.content_key != receipt.content_key
                or saved_receipt.logical_path != receipt.logical_path
            ):
                return None, self._block(generation, "integrity", hide=False, phase="receipt")
            return _record_generation(saved, generation), None
        if _is_lost(saved):
            return None, _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired", phase="receipt")
        return None, self._block(generation, "integrity", hide=False, phase="receipt")

    def _authenticate(self, durable: object, composed: ComposedGeneration) -> str | None:
        """Compare all identity and count fields before any provider request."""

        task_id = getattr(durable, "task_id", None)
        if not isinstance(task_id, str) or composed.task_id != task_id:
            return "integrity"
        boundary = getattr(durable, "generation_boundary", None)
        if not isinstance(boundary, str) or composed.generation_boundary != boundary:
            return "integrity"
        try:
            durable_identity = GenerationIdentity(task_id, boundary)
        except Exception:
            return "integrity"
        if (
            durable_identity.publication_id != getattr(durable, "publication_id", None)
            or durable_identity.idempotency_key != getattr(durable, "idempotency_key", None)
        ):
            return "integrity"
        if composed.publication_id != getattr(durable, "publication_id", None):
            return "integrity"
        if composed.idempotency_key != getattr(durable, "idempotency_key", None):
            return "integrity"
        if composed.run_id != getattr(durable, "run_id", None):
            return "integrity"
        if composed.metadata_digest != getattr(durable, "metadata_digest", None):
            return "integrity"
        payload = composed.payload
        generation_payload = composed.generation
        if not isinstance(payload, Mapping) or not isinstance(generation_payload, Mapping):
            return "integrity"
        schema_version = payload.get("schemaVersion")
        if schema_version is not None and schema_version != PUBLICATION_SCHEMA_VERSION:
            return "integrity"
        if (
            payload.get("publicationId") != composed.publication_id
            or payload.get("taskId") != composed.task_id
            or generation_payload.get("publicationId") != composed.publication_id
            or generation_payload.get("taskId") != composed.task_id
            or generation_payload.get("idempotencyKey") != composed.idempotency_key
            or generation_payload.get("metadataDigest") != composed.metadata_digest
        ):
            return "integrity"
        head_intent = payload.get("headIntent")
        if head_intent is not None:
            if not isinstance(head_intent, Mapping):
                return "integrity"
            if (
                head_intent.get("publicationId") != composed.publication_id
                or head_intent.get("taskId") != composed.task_id
            ):
                return "integrity"
        counts = generation_payload.get("expectedCounts")
        if not isinstance(counts, Mapping):
            return "integrity"
        count_names = ("tasks", "pipelines", "runs", "events", "artifacts")
        for name in count_names:
            value = counts.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return "integrity"
            if value != getattr(durable, name, None):
                return "integrity"
        expected_rows = sum(int(counts[name]) for name in count_names)
        if expected_rows != getattr(durable, "rows", None):
            return "integrity"
        expected_objects = len(composed.objects) + len(composed.private_originals)
        if expected_objects != getattr(durable, "objects", None):
            return "integrity"
        collections = {
            "tasks": payload.get("task"),
            "pipelines": payload.get("pipelines"),
            "runs": payload.get("runs"),
            "events": payload.get("events"),
            "artifacts": payload.get("artifacts"),
        }
        if not isinstance(collections["tasks"], Mapping):
            return "integrity"
        if collections["tasks"].get("taskId", composed.task_id) != composed.task_id:
            return "integrity"
        for name in ("pipelines", "runs", "events", "artifacts"):
            values = collections[name]
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
                return "integrity"
            if len(values) != counts[name]:
                return "integrity"
        pipeline_ids: set[str] = set()
        for row in collections["pipelines"]:
            if not isinstance(row, Mapping) or row.get("taskId", composed.task_id) != composed.task_id:
                return "integrity"
            pipeline_id = row.get("pipelineId")
            if pipeline_id is not None:
                if not isinstance(pipeline_id, str) or pipeline_id in pipeline_ids:
                    return "integrity"
                pipeline_ids.add(pipeline_id)
        run_ids: set[str] = set()
        for row in collections["runs"]:
            if not isinstance(row, Mapping) or row.get("taskId", composed.task_id) != composed.task_id:
                return "integrity"
            run_id = row.get("runId")
            if run_id is not None:
                if not isinstance(run_id, str) or run_id in run_ids:
                    return "integrity"
                run_ids.add(run_id)
            pipeline_id = row.get("pipelineId")
            if pipeline_id is not None and pipeline_ids and pipeline_id not in pipeline_ids:
                return "integrity"
        event_sequences: set[int] = set()
        for row in collections["events"]:
            if not isinstance(row, Mapping) or row.get("taskId", composed.task_id) != composed.task_id:
                return "integrity"
            sequence = row.get("sequence")
            if sequence is not None:
                if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1 or sequence in event_sequences:
                    return "integrity"
                event_sequences.add(sequence)
        artifact_ids: set[str] = set()
        logical_paths: set[str] = set()
        for row in collections["artifacts"]:
            if not isinstance(row, Mapping) or row.get("taskId", composed.task_id) != composed.task_id:
                return "integrity"
            artifact_id = row.get("artifactId")
            if artifact_id is not None:
                if not isinstance(artifact_id, str) or artifact_id in artifact_ids:
                    return "integrity"
                artifact_ids.add(artifact_id)
            logical_path = row.get("logicalPath")
            if logical_path is not None:
                if not isinstance(logical_path, str) or logical_path in logical_paths:
                    return "integrity"
                logical_paths.add(logical_path)
            run_id = row.get("runId")
            if run_id is not None and run_ids and run_id not in run_ids:
                return "integrity"
        if counts["tasks"] != 1:
            return "integrity"
        represented_runs = {
            row.get("runId")
            for row in collections["runs"]
            if isinstance(row, Mapping)
        }
        represented_runs.add(composed.run_id)
        if run_ids and composed.run_id not in run_ids:
            return "integrity"
        for item in composed.objects:
            if (
                not isinstance(item, GenerationObject)
                or item.task_id != composed.task_id
                or item.run_id not in represented_runs
            ):
                return "integrity"
        private_keys: set[tuple[str, str]] = set()
        for item in composed.private_originals:
            if (
                not isinstance(item, GenerationOriginal)
                or item.task_id != composed.task_id
                or item.run_id not in represented_runs
                or (item.run_id, item.sha256) in private_keys
            ):
                return "integrity"
            private_keys.add((item.run_id, item.sha256))
        return None

    def publish(
        self,
        publication_id: str | None = None,
        source: object | None = None,
        *,
        graph: object | None = None,
        generation: object | None = None,
        claimed_generation: object | None = None,
        compose_kwargs: Mapping[str, object] | None = None,
    ) -> PublicationResult:
        """Publish one durable generation, resuming from recorded receipts."""

        if graph is not None:
            source = graph
        if claimed_generation is not None:
            if publication_id is None:
                publication_id = _publication_id_from(claimed_generation)
        # ``generation`` and ``claimed_generation`` identify the durable
        # outbox row only.  A caller-supplied transport envelope is never
        # trusted as a shortcut around composition and source inspection.
        for durable_candidate in (generation, claimed_generation):
            if publication_id is None and durable_candidate is not None:
                publication_id = _publication_id_from(durable_candidate)
        generation = None
        if publication_id is not None and _identifier(publication_id) is None:
            return _result(PublicationStatus.blocked, None, reason="invalid_metadata", reason_codes=(ReasonCode.invalid_metadata,))
        if publication_id is None:
            return _result(PublicationStatus.blocked, None, reason="invalid_metadata", reason_codes=(ReasonCode.invalid_metadata,))
        try:
            current = self._get(publication_id)
            hide_reason = _hide_reconciliation_reason(current, self._time())
            durable, early = self._claim(publication_id, current)
        except Exception:
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        if early is not None:
            return early
        if durable is None:
            return _result(PublicationStatus.lost_claim, publication_id, reason="lease_expired")
        if hide_reason is not None:
            return self._reconcile_hide(durable, hide_reason, phase="hide")
        state = _status(getattr(durable, "state", ""))
        if state in {PublicationState.exposed.value, PublicationState.terminal_cleaned.value} and source is None and generation is None:
            return _result(PublicationStatus.exposed, publication_id)
        if state == PublicationState.claimed.value:
            durable, early = self._advance(durable, PublicationState.claimed, PublicationState.building)
            if early is not None:
                return early
            assert durable is not None
            state = PublicationState.building.value
        if generation is None:
            if source is None:
                return self._block(durable, "invalid_metadata", hide=False, phase="compose")
            try:
                composed_value = _call_composer(
                    self.compose,
                    source,
                    task_id=str(getattr(durable, "task_id", "")),
                    kwargs=compose_kwargs or {},
                )
            except Exception:
                return self._block(durable, "invalid_metadata", hide=False, phase="compose")
            generation = composed_value if _is_composed_generation(composed_value) else None
            if isinstance(composed_value, RepairRequired):
                return _result(
                    PublicationStatus.repair_required,
                    publication_id,
                    reason_codes=composed_value.reason_codes,
                    phase="compose",
                )
            if isinstance(composed_value, FailClosed):
                return self._block(
                    durable,
                    composed_value.reason_codes[0] if composed_value.reason_codes else "integrity",
                    hide=True,
                    phase="compose",
                )
            if generation is None:
                return self._block(durable, "invalid_metadata", hide=False, phase="compose")
        try:
            mismatch = self._authenticate(durable, generation)
        except Exception:
            mismatch = "integrity"
        if mismatch is not None:
            return self._block(durable, mismatch, hide=False, phase="authenticate")
        if state in {PublicationState.exposed.value, PublicationState.terminal_cleaned.value}:
            return _result(PublicationStatus.exposed, publication_id)

        try:
            receipts = self._receipts(publication_id)
        except Exception:
            return self._block(durable, "integrity", hide=False, phase="receipts")
        # A receipt is trusted only if its immutable descriptor matches the
        # composed bytes and key exactly.  Conflicting local state fails closed
        # before any new provider request.
        try:
            for item in (*generation.objects, *generation.private_originals):
                klass = ReceiptClass.public if isinstance(item, GenerationObject) else ReceiptClass.private
                key = item.public_key if isinstance(item, GenerationObject) else private_original_key(item.task_id, item.run_id, item.sha256)
                existing = receipts.get((klass, key))
                if existing is not None and (
                    existing.sha256 != item.sha256
                    or existing.byte_size != item.byte_size
                    or existing.logical_path
                    != (item.logical_path if isinstance(item, GenerationObject) else None)
                ):
                    return self._block(durable, "integrity", hide=False, phase="receipts")
        except Exception:
            return self._block(durable, "integrity", hide=False, phase="receipts")

        if state == PublicationState.building.value:
            durable, early = self._advance(durable, PublicationState.building, PublicationState.uploading)
            if early is not None:
                return early
            assert durable is not None
            state = PublicationState.uploading.value
        if state == PublicationState.uploading.value:
            for item in generation.objects:
                key = item.public_key
                if (ReceiptClass.public, key) in receipts:
                    continue
                durable, early = self._renew(durable)
                if early is not None:
                    return early
                assert durable is not None
                try:
                    verified = self.r2.put_object(
                        key,
                        item.content,
                        R2ObjectClass.public,
                        expected_sha256=item.sha256,
                        expected_size=item.byte_size,
                    )
                    if verified is not None and (
                        getattr(verified, "key", key) != key
                        or getattr(verified, "sha256", item.sha256) != item.sha256
                        or getattr(verified, "byte_size", item.byte_size) != item.byte_size
                    ):
                        return self._block(durable, "integrity", hide=True, phase="public")
                except Exception as error:
                    return self._provider_failure(durable, error, phase="public")
                durable, early = self._renew(durable)
                if early is not None:
                    return early
                assert durable is not None
                verified_at = max(self._time(), getattr(durable, "updated_at", self._time()))
                receipt = PublicationReceipt.public_receipt(item.sha256, item.byte_size, key, verified_at, item.logical_path)
                durable, early = self._save_receipt(durable, receipt)
                if early is not None:
                    return early
                assert durable is not None
                receipts[(ReceiptClass.public, key)] = receipt
            for item in generation.private_originals:
                key = private_original_key(item.task_id, item.run_id, item.sha256)
                if (ReceiptClass.private, key) in receipts:
                    continue
                durable, early = self._renew(durable)
                if early is not None:
                    return early
                assert durable is not None
                try:
                    verified = self.r2.put_object(
                        key,
                        item.content,
                        R2ObjectClass.private,
                        expected_sha256=item.sha256,
                        expected_size=item.byte_size,
                    )
                    if verified is not None and (
                        getattr(verified, "key", key) != key
                        or getattr(verified, "sha256", item.sha256) != item.sha256
                        or getattr(verified, "byte_size", item.byte_size) != item.byte_size
                    ):
                        return self._block(durable, "integrity", hide=True, phase="private")
                except Exception as error:
                    return self._provider_failure(durable, error, phase="private")
                durable, early = self._renew(durable)
                if early is not None:
                    return early
                assert durable is not None
                verified_at = max(self._time(), getattr(durable, "updated_at", self._time()))
                receipt = PublicationReceipt.private_receipt(item.sha256, item.byte_size, key, verified_at)
                durable, early = self._save_receipt(durable, receipt)
                if early is not None:
                    return early
                assert durable is not None
                receipts[(ReceiptClass.private, key)] = receipt
            durable, early = self._renew(durable)
            if early is not None:
                return early
            assert durable is not None
            try:
                staged = self.d1.stage(generation.payload)
                if staged is not None and (
                    getattr(staged, "publication_id", publication_id) != publication_id
                    or getattr(staged, "task_id", generation.task_id) != generation.task_id
                ):
                    return self._block(durable, "integrity", hide=True, phase="stage")
            except Exception as error:
                return self._provider_failure(durable, error, phase="stage")
            durable, early = self._renew(durable)
            if early is not None:
                return early
            assert durable is not None
            durable, early = self._advance(durable, PublicationState.uploading, PublicationState.d1_staged)
            if early is not None:
                return early
            assert durable is not None
            state = PublicationState.d1_staged.value
        if state == PublicationState.d1_staged.value:
            durable, early = self._renew(durable)
            if early is not None:
                return early
            assert durable is not None
            try:
                exposed = self.d1.expose(generation.payload)
                if (
                    getattr(exposed, "state", "visible") != "visible"
                    or getattr(exposed, "publication_id", publication_id) != publication_id
                    or getattr(exposed, "task_id", generation.task_id) != generation.task_id
                ):
                    return self._block(durable, "integrity", hide=True, phase="expose")
            except Exception as error:
                return self._provider_failure(durable, error, phase="expose")
            durable, early = self._renew(durable)
            if early is not None:
                return early
            assert durable is not None
            durable, early = self._advance(durable, PublicationState.d1_staged, PublicationState.exposed)
            if early is not None:
                return early
            return _result(PublicationStatus.exposed, publication_id, phase="expose")
        if state == PublicationState.exposed.value:
            return _result(PublicationStatus.exposed, publication_id)
        return self._block(durable, "integrity", hide=False, phase="state")

    publish_claimed = publish
    publish_generation = publish
    run = publish


PublicationPublisher = CloudPublisher
GenerationPublisher = CloudPublisher
CloudPublicationPublisher = CloudPublisher
Publisher = CloudPublisher


def publish_generation(
    store: TaskStore,
    source: object | None = None,
    *,
    publication_id: str | None = None,
    r2: R2Client,
    d1: D1PublicationClient,
    worker_id: str = "publication-worker",
    compose: PublicationComposer = _DEFAULT_COMPOSER,
    now: Callable[[], datetime] | datetime | None = None,
    lease_seconds: int = MAX_LEASE_SECONDS,
    retry_backoff_seconds: int = 1,
    generation: object | None = None,
    claimed_generation: object | None = None,
    compose_kwargs: Mapping[str, object] | None = None,
) -> PublicationResult:
    """Functional wrapper for :class:`CloudPublisher`."""

    return CloudPublisher(
        store,
        r2,
        d1,
        worker_id,
        compose=compose,
        now=now,
        lease_seconds=lease_seconds,
        retry_backoff_seconds=retry_backoff_seconds,
    ).publish(
        publication_id,
        source,
        generation=generation,
        claimed_generation=claimed_generation,
        compose_kwargs=compose_kwargs,
    )


def retry_publication(
    store: TaskStore,
    publication_id: str,
    source: object | None = None,
    *,
    compose: PublicationComposer = _DEFAULT_COMPOSER,
    compose_kwargs: Mapping[str, object] | None = None,
    now: Callable[[], datetime] | datetime | None = None,
) -> PublicationResult:
    """Compose, inspect, and enqueue one changed deterministic generation."""

    return CloudPublisher(
        store,
        object(),
        object(),
        compose=compose,
        now=now,
    ).retry_publication(
        publication_id,
        source,
        compose_kwargs=compose_kwargs,
    )


def hide_publication(
    store: TaskStore,
    task_id: str,
    reason: str = "operator_blocked",
    *,
    d1: D1PublicationClient,
    now: Callable[[], datetime] | datetime | None = None,
) -> PublicationHideResult:
    """Hide one task head through typed D1 and local durable state."""

    return CloudPublisher(store, object(), d1, now=now).hide_task(task_id, reason)


publish_claimed_generation = publish_generation
publish_publication_generation = publish_generation


__all__ = [
    "CloudPublicationPublisher",
    "CloudPublicationResult",
    "CloudPublishStatus",
    "CloudPublisher",
    "GenerationPublisher",
    "PublicationPublisher",
    "PublicationResult",
    "PublicationOutcomeResult",
    "PublicationHideResult",
    "PublicationHideStatus",
    "PublicationStatus",
    "PublishStatus",
    "Publisher",
    "PublisherResult",
    "PublisherStatus",
    "publish_claimed_generation",
    "publish_generation",
    "publish_publication_generation",
    "publication_generation_views",
    "publication_health_view",
    "retry_publication",
    "hide_publication",
]

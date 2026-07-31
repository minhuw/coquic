"""Immutable values for the durable Steward publication outbox.

The outbox is deliberately transport-free.  It describes a publication that
can be resumed after a process crash, but it does not enqueue work, perform a
claim, or talk to D1/R2.  Values in this module are safe to pass across the
publication boundary: private object locators and local filesystem paths are
never included in their default serialization.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import PurePath
from typing import Final

from .models import PublicationError, ReasonCode


MAX_IDENTIFIER_LENGTH: Final = 128
MAX_DIGEST_LENGTH: Final = 64
MAX_CONTENT_KEY_LENGTH: Final = 1024
MAX_REASON_LENGTH: Final = 64
MAX_ATTEMPTS: Final = 32
MAX_COUNT: Final = 2**31 - 1
MAX_OBJECT_BYTES: Final = 64 * 1024 * 1024
MAX_LEASE_SECONDS: Final = 24 * 60 * 60
MAX_RETRY_DELAY_SECONDS: Final = 30 * 24 * 60 * 60
MAX_CLEANUP_PATH_LENGTH: Final = 4096

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_KEY_RE = re.compile(
    r"^v1/tasks/(?P<task>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/"
    r"objects/sha256/(?P<prefix>[0-9a-f]{2})/(?P<digest>[0-9a-f]{64})$"
)
_PRIVATE_KEY_RE = re.compile(
    r"^v1/originals/(?P<task>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/"
    r"(?P<run>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/sha256/"
    r"(?P<digest>[0-9a-f]{64})\.jsonl$"
)
_LOGICAL_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
_PRIVATE_LOCATOR_RE = re.compile(
    r"(?:^|[/\\])(?:private|credential|credentials|secret|token)(?:[/\\]|$)|"
    r"(?:^|[-_])(?:private|internal|secret)[-_](?:bucket|object(?:[-_]key)?|url|path)(?:$|[-_])",
    re.IGNORECASE,
)
_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


class OutboxValidationError(PublicationError):
    """A bounded validation failure which never echoes an input value."""

    def __init__(self, code: ReasonCode | str = ReasonCode.invalid_metadata) -> None:
        super().__init__(code)


class PublicationState(StrEnum):
    """The complete local publication state machine."""

    queued = "queued"
    claimed = "claimed"
    building = "building"
    uploading = "uploading"
    d1_staged = "d1_staged"
    exposed = "exposed"
    retry_wait = "retry_wait"
    blocked = "blocked"
    terminal_cleaned = "terminal_cleaned"


# ``GenerationState`` and ``OutboxState`` are descriptive names used by later
# callers.  Keeping them as aliases prevents callers from inventing a second
# state vocabulary.
GenerationState = PublicationState
OutboxState = PublicationState
PublicationOutboxState = PublicationState
GenerationStatus = PublicationState


class ReceiptClass(StrEnum):
    public = "public"
    private = "private"


PublicationReceiptClass = ReceiptClass
ReceiptKind = ReceiptClass


class CleanupState(StrEnum):
    pending = "pending"
    completed = "completed"
    blocked = "blocked"


class PublicationOperationStatus(StrEnum):
    """Bounded outcomes returned by local outbox mutations.

    A failed compare-and-set is a normal recovery outcome, rather than an
    exception.  Keeping it in a closed vocabulary prevents callers from
    accidentally persisting SQL/provider detail in health or public payloads.
    """

    enqueued = "enqueued"
    existing = "existing"
    claimed = "claimed"
    empty = "empty"
    renewed = "renewed"
    advanced = "advanced"
    recorded = "recorded"
    verified = "verified"
    completed = "completed"
    blocked = "blocked"
    retry_wait = "retry_wait"
    missing = "missing"
    lost_claim = "lost_claim"
    illegal_transition = "illegal_transition"
    conflict = "conflict"
    retry_exhausted = "retry_exhausted"
    precondition = "precondition"


_SAFE_REASON_VALUES: Final[frozenset[str]] = frozenset(
    {item.value for item in ReasonCode}
    | {
        "network",
        "quota",
        "authentication",
        "permission",
        "timeout",
        "provider",
        "integrity",
        "lease_expired",
        "retry_exhausted",
        "cleanup_failed",
        "operator_blocked",
    }
)


_LEGAL_TRANSITIONS: Final[dict[PublicationState, frozenset[PublicationState]]] = {
    PublicationState.queued: frozenset({PublicationState.claimed, PublicationState.building}),
    PublicationState.claimed: frozenset(
        {PublicationState.building, PublicationState.retry_wait, PublicationState.blocked}
    ),
    PublicationState.building: frozenset(
        {PublicationState.uploading, PublicationState.retry_wait, PublicationState.blocked}
    ),
    PublicationState.uploading: frozenset(
        {PublicationState.d1_staged, PublicationState.retry_wait, PublicationState.blocked}
    ),
    PublicationState.d1_staged: frozenset(
        {PublicationState.exposed, PublicationState.retry_wait, PublicationState.blocked}
    ),
    PublicationState.exposed: frozenset({PublicationState.terminal_cleaned}),
    PublicationState.retry_wait: frozenset(
        {PublicationState.building, PublicationState.blocked}
    ),
    PublicationState.blocked: frozenset({PublicationState.queued}),
    PublicationState.terminal_cleaned: frozenset(),
}


def _fail(code: ReasonCode | str = ReasonCode.invalid_metadata) -> None:
    raise OutboxValidationError(code) from None


def _identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        _fail(ReasonCode.invalid_identifier)
    return value


def _bounded_text(value: object, maximum: int = MAX_REASON_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        _fail()
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _fail(ReasonCode.invalid_digest)
    return value


def _count(value: object, *, maximum: int = MAX_COUNT) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        _fail()
    return value


def _timestamp(value: object) -> datetime:
    if isinstance(value, str):
        if _TIMESTAMP_RE.fullmatch(value) is None:
            _fail()
        try:
            value = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            _fail()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _state(value: object) -> PublicationState:
    try:
        return PublicationState(value)
    except (TypeError, ValueError):
        _fail()
    raise AssertionError("unreachable")


def _reason(value: object | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, StrEnum):
        value = value.value
    if not isinstance(value, str) or value not in _SAFE_REASON_VALUES:
        _fail()
    return value


def _health_category(value: object | None) -> str | None:
    if value is None or value == "success":
        return value
    return _reason(value)


def _content_key(value: object, receipt_class: ReceiptClass) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_CONTENT_KEY_LENGTH:
        _fail(ReasonCode.invalid_path)
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        _fail(ReasonCode.invalid_path)
    pattern = _PUBLIC_KEY_RE if receipt_class is ReceiptClass.public else _PRIVATE_KEY_RE
    match = pattern.fullmatch(value)
    if match is None or (
        receipt_class is ReceiptClass.public and match.group("prefix") != match.group("digest")[:2]
    ):
        _fail(ReasonCode.invalid_path)
    return value


def _logical_path(value: object | None) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or _LOGICAL_PATH_RE.fullmatch(value) is None
        or _PRIVATE_LOCATOR_RE.search(value) is not None
    ):
        _fail(ReasonCode.invalid_path)
    return value


def _lease(value: object | None) -> datetime | None:
    if value is None:
        return None
    return _timestamp(value)


def _within(value: datetime | None, anchor: datetime, maximum_seconds: int) -> bool:
    return value is None or abs((value - anchor).total_seconds()) <= maximum_seconds


def allowed_transition(current: PublicationState | str, target: PublicationState | str) -> bool:
    """Return whether one state edge is legal."""

    try:
        source = PublicationState(current)
        destination = PublicationState(target)
    except (TypeError, ValueError):
        return False
    return destination in _LEGAL_TRANSITIONS[source]


def legal_transition(current: PublicationState | str, target: PublicationState | str) -> bool:
    return allowed_transition(current, target)


def transition_state(current: PublicationState | str, target: PublicationState | str) -> PublicationState:
    """Validate and return a state transition without mutating a value."""

    source = _state(current)
    destination = _state(target)
    if destination not in _LEGAL_TRANSITIONS[source]:
        _fail()
    return destination


@dataclass(frozen=True, slots=True)
class GenerationIdentity:
    """Stable identity derived from a task and immutable generation boundary."""

    task_id: str
    stable_boundary: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _identifier(self.task_id))
        boundary = _bounded_text(self.stable_boundary, maximum=MAX_IDENTIFIER_LENGTH)
        if "/" in boundary or "\\" in boundary:
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "stable_boundary", boundary)

    @property
    def generation_boundary(self) -> str:
        return self.stable_boundary

    @property
    def digest(self) -> str:
        seed = f"coquic-publication-v1\0{self.task_id}\0{self.stable_boundary}".encode()
        return hashlib.sha256(seed).hexdigest()

    @property
    def publication_id(self) -> str:
        return f"pub-{self.digest}"

    @property
    def idempotency_key(self) -> str:
        return f"gen-{self.digest}"

    def as_dict(self) -> dict[str, str]:
        return {
            "publicationId": self.publication_id,
            "taskId": self.task_id,
            "generationBoundary": self.stable_boundary,
            "idempotencyKey": self.idempotency_key,
        }


def deterministic_publication_id(task_id: str, stable_boundary: str) -> str:
    return GenerationIdentity(task_id, stable_boundary).publication_id


publication_id_for = deterministic_publication_id
generation_id_for = deterministic_publication_id


@dataclass(frozen=True, slots=True)
class PublicationCounts:
    """Bounded expected local row/object counts for one generation."""

    rows: int = 0
    objects: int = 0
    tasks: int = 1
    pipelines: int = 0
    runs: int = 0
    events: int = 0
    artifacts: int = 0

    def __post_init__(self) -> None:
        for name in ("rows", "objects", "tasks", "pipelines", "runs", "events", "artifacts"):
            object.__setattr__(self, name, _count(getattr(self, name)))
        if self.tasks != 1:
            _fail()

    @property
    def row_count(self) -> int:
        return self.rows

    @property
    def object_count(self) -> int:
        return self.objects

    def as_dict(self) -> dict[str, int]:
        return {
            "rows": self.rows,
            "objects": self.objects,
            "tasks": self.tasks,
            "pipelines": self.pipelines,
            "runs": self.runs,
            "events": self.events,
            "artifacts": self.artifacts,
        }


ExpectedCounts = PublicationCounts


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    """A verified object receipt; private locators are local-only fields."""

    receipt_class: ReceiptClass | str
    sha256: str
    byte_size: int
    content_key: str
    verified_at: datetime
    logical_path: str | None = None

    def __post_init__(self) -> None:
        try:
            receipt_class = ReceiptClass(self.receipt_class)
        except (TypeError, ValueError):
            _fail()
        object.__setattr__(self, "receipt_class", receipt_class)
        digest = _digest(self.sha256)
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "byte_size", _count(self.byte_size, maximum=MAX_OBJECT_BYTES))
        key = _content_key(self.content_key, receipt_class)
        match = (_PUBLIC_KEY_RE if receipt_class is ReceiptClass.public else _PRIVATE_KEY_RE).fullmatch(key)
        assert match is not None
        if match.group("digest") != digest:
            _fail(ReasonCode.digest_mismatch)
        object.__setattr__(self, "content_key", key)
        object.__setattr__(self, "verified_at", _timestamp(self.verified_at))
        logical_path = _logical_path(self.logical_path)
        if receipt_class is ReceiptClass.private and logical_path is not None:
            _fail(ReasonCode.invalid_path)
        object.__setattr__(self, "logical_path", logical_path)

    @property
    def object_class(self) -> ReceiptClass:
        return self.receipt_class

    @property
    def digest(self) -> str:
        return self.sha256

    @property
    def size(self) -> int:
        return self.byte_size

    @property
    def public(self) -> bool:
        return self.receipt_class is ReceiptClass.public

    def as_dict(self, *, include_private: bool = False) -> dict[str, object]:
        """Serialize safely; private object keys are opt-in for local recovery."""

        value: dict[str, object] = {
            "class": self.receipt_class.value,
            "sha256": self.sha256,
            "byteSize": self.byte_size,
            "verifiedAt": _timestamp_text(self.verified_at),
        }
        if self.receipt_class is ReceiptClass.public:
            value["contentKey"] = self.content_key
            if self.logical_path is not None:
                value["logicalPath"] = self.logical_path
        elif include_private:
            value["contentKey"] = self.content_key
        return value

    def as_public_dict(self) -> dict[str, object]:
        return self.as_dict()

    @classmethod
    def public_receipt(
        cls,
        sha256: str,
        byte_size: int,
        content_key: str,
        verified_at: datetime,
        logical_path: str | None = None,
    ) -> "PublicationReceipt":
        return cls(ReceiptClass.public, sha256, byte_size, content_key, verified_at, logical_path)

    @classmethod
    def private_receipt(
        cls,
        sha256: str,
        byte_size: int,
        content_key: str,
        verified_at: datetime,
    ) -> "PublicationReceipt":
        return cls(ReceiptClass.private, sha256, byte_size, content_key, verified_at)


Receipt = PublicationReceipt
OutboxReceipt = PublicationReceipt
PublicationReceiptValue = PublicationReceipt


@dataclass(frozen=True, slots=True)
class PublicationGeneration:
    """One immutable generation record and its resumable state."""

    publication_id: str
    task_id: str
    metadata_digest: str
    idempotency_key: str
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime | None = None
    run_id: str = "run-unknown"
    generation_boundary: str = "boundary-unknown"
    state: PublicationState | str = PublicationState.queued
    attempt: int = 0
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    retry_at: datetime | None = None
    reason: str | None = None
    rows: int = 0
    objects: int = 0
    tasks: int = 1
    pipelines: int = 0
    runs: int = 0
    events: int = 0
    artifacts: int = 0
    exposed_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "publication_id", _identifier(self.publication_id))
        object.__setattr__(self, "task_id", _identifier(self.task_id))
        object.__setattr__(self, "run_id", _identifier(self.run_id))
        object.__setattr__(self, "generation_boundary", _bounded_text(self.generation_boundary, MAX_IDENTIFIER_LENGTH))
        object.__setattr__(self, "metadata_digest", _digest(self.metadata_digest))
        object.__setattr__(self, "idempotency_key", _identifier(self.idempotency_key))
        identity = GenerationIdentity(self.task_id, self.generation_boundary)
        if (
            self.publication_id != identity.publication_id
            or self.idempotency_key != identity.idempotency_key
        ):
            _fail(ReasonCode.invalid_metadata)
        state = _state(self.state)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "attempt", _count(self.attempt, maximum=MAX_ATTEMPTS))
        counts = PublicationCounts(
            rows=self.rows,
            objects=self.objects,
            tasks=self.tasks,
            pipelines=self.pipelines,
            runs=self.runs,
            events=self.events,
            artifacts=self.artifacts,
        )
        for name in ("rows", "objects", "tasks", "pipelines", "runs", "events", "artifacts"):
            object.__setattr__(self, name, getattr(counts, name))
        created = _timestamp(self.created_at)
        updated = created if self.updated_at is None else _timestamp(self.updated_at)
        if updated < created:
            _fail()
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)
        lease_owner = None if self.lease_owner is None else _identifier(self.lease_owner)
        lease_expires = _lease(self.lease_expires_at)
        if (lease_owner is None) != (lease_expires is None):
            _fail()
        if state in {PublicationState.claimed, PublicationState.building} and lease_owner is None:
            _fail()
        if state not in {PublicationState.claimed, PublicationState.building} and lease_owner is not None:
            _fail()
        if lease_owner is not None:
            if lease_expires is None or lease_expires < updated:
                _fail()
            if not _within(lease_expires, updated, MAX_LEASE_SECONDS):
                _fail()
        object.__setattr__(self, "lease_owner", lease_owner)
        object.__setattr__(self, "lease_expires_at", lease_expires)
        retry_at = _lease(self.retry_at)
        if state is PublicationState.retry_wait:
            if (
                retry_at is None
                or retry_at < updated
                or not _within(retry_at, updated, MAX_RETRY_DELAY_SECONDS)
            ):
                _fail()
        elif retry_at is not None:
            _fail()
        object.__setattr__(self, "retry_at", retry_at)
        reason = _reason(self.reason)
        if state is PublicationState.blocked and reason is None:
            _fail()
        object.__setattr__(self, "reason", reason)
        exposed_at = None if self.exposed_at is None else _timestamp(self.exposed_at)
        if state is PublicationState.exposed and exposed_at is None:
            exposed_at = updated
        if state in {PublicationState.exposed, PublicationState.terminal_cleaned}:
            if exposed_at is None:
                _fail()
        elif exposed_at is not None:
            _fail()
        if exposed_at is not None and (exposed_at < created or exposed_at > updated):
            _fail()
        object.__setattr__(self, "exposed_at", exposed_at)

    @property
    def identity(self) -> GenerationIdentity:
        return GenerationIdentity(self.task_id, self.generation_boundary)

    @property
    def generation_id(self) -> str:
        return self.publication_id

    @property
    def metadata_digest_hex(self) -> str:
        return self.metadata_digest

    @property
    def row_count(self) -> int:
        return self.rows

    @property
    def object_count(self) -> int:
        return self.objects

    @property
    def retry_at_timestamp(self) -> datetime | None:
        return self.retry_at

    def counts(self) -> PublicationCounts:
        return PublicationCounts(
            rows=self.rows,
            objects=self.objects,
            tasks=self.tasks,
            pipelines=self.pipelines,
            runs=self.runs,
            events=self.events,
            artifacts=self.artifacts,
        )

    def can_transition_to(self, target: PublicationState | str) -> bool:
        return allowed_transition(self.state, target)

    def transition_to(
        self,
        target: PublicationState | str,
        *,
        now: datetime | None = None,
        lease_owner: str | None = None,
        lease_expires_at: datetime | None = None,
        retry_at: datetime | None = None,
        reason: str | None = None,
    ) -> "PublicationGeneration":
        destination = transition_state(self.state, target)
        updated = _timestamp(now or _now())
        if updated < self.updated_at:
            _fail()
        if destination in {PublicationState.claimed, PublicationState.building}:
            lease_owner = lease_owner or self.lease_owner
            lease_expires_at = lease_expires_at or self.lease_expires_at
            if lease_owner is None:
                _fail()
            lease_expires_at = lease_expires_at or updated + timedelta(seconds=MAX_LEASE_SECONDS)
        elif destination not in {PublicationState.claimed, PublicationState.building}:
            lease_owner = None
            lease_expires_at = None
        if destination is PublicationState.retry_wait:
            retry_at = retry_at or updated + timedelta(seconds=1)
        else:
            retry_at = None
        if destination is PublicationState.blocked and reason is None:
            _fail()
        return replace(
            self,
            state=destination,
            updated_at=updated,
            lease_owner=lease_owner,
            lease_expires_at=lease_expires_at,
            retry_at=retry_at,
            reason=reason,
            exposed_at=updated if destination is PublicationState.exposed else self.exposed_at,
        )

    transition = transition_to

    def as_dict(self) -> dict[str, object]:
        return {
            "publicationId": self.publication_id,
            "taskId": self.task_id,
            "runId": self.run_id,
            "generationBoundary": self.generation_boundary,
            "metadataDigest": self.metadata_digest,
            "idempotencyKey": self.idempotency_key,
            "state": self.state.value,
            "attempt": self.attempt,
            "leaseOwner": self.lease_owner,
            "leaseExpiresAt": _timestamp_text(self.lease_expires_at) if self.lease_expires_at else None,
            "retryAt": _timestamp_text(self.retry_at) if self.retry_at else None,
            "reason": self.reason,
            "counts": self.counts().as_dict(),
            "createdAt": _timestamp_text(self.created_at),
            "updatedAt": _timestamp_text(self.updated_at),
            "exposedAt": _timestamp_text(self.exposed_at) if self.exposed_at else None,
        }


Generation = PublicationGeneration
OutboxGeneration = PublicationGeneration
GenerationRecord = PublicationGeneration


@dataclass(frozen=True, slots=True)
class PublicationHealth:
    """Bounded operational counters; no provider or filesystem details."""

    queued_count: int = 0
    blocked_count: int = 0
    cleanup_pending_count: int = 0
    cleanup_pending_bytes: int = 0
    updated_at: datetime = field(default_factory=_now)
    reason: str | None = None
    oldest_queued_at: datetime | None = None
    last_category: str | None = None

    def __post_init__(self) -> None:
        for name in ("queued_count", "blocked_count", "cleanup_pending_count", "cleanup_pending_bytes"):
            object.__setattr__(self, name, _count(getattr(self, name)))
        object.__setattr__(self, "updated_at", _timestamp(self.updated_at))
        reason = _reason(self.reason)
        object.__setattr__(self, "reason", reason)
        oldest = None if self.oldest_queued_at is None else _timestamp(self.oldest_queued_at)
        if oldest is not None and oldest > self.updated_at:
            _fail()
        object.__setattr__(self, "oldest_queued_at", oldest)
        category = _health_category(self.last_category)
        if category is None:
            category = reason or "success"
        if (category == "success") != (reason is None) or (
            reason is not None and category != reason
        ):
            _fail()
        object.__setattr__(self, "last_category", category)

    @property
    def cleanup_bytes(self) -> int:
        return self.cleanup_pending_bytes

    @property
    def queue_count(self) -> int:
        return self.queued_count

    @property
    def oldest_queued_age_seconds(self) -> int:
        if self.oldest_queued_at is None:
            return 0
        return max(0, int((self.updated_at - self.oldest_queued_at).total_seconds()))

    def as_dict(self) -> dict[str, object]:
        return {
            "queuedCount": self.queued_count,
            "blockedCount": self.blocked_count,
            "cleanupPendingCount": self.cleanup_pending_count,
            "cleanupPendingBytes": self.cleanup_pending_bytes,
            "updatedAt": _timestamp_text(self.updated_at),
            "reason": self.reason,
            "oldestQueuedAt": _timestamp_text(self.oldest_queued_at) if self.oldest_queued_at else None,
            "oldestQueuedAgeSeconds": self.oldest_queued_age_seconds,
            "lastCategory": self.last_category,
        }


Health = PublicationHealth
OutboxHealth = PublicationHealth
HealthSnapshot = PublicationHealth


def _exact_path(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_CLEANUP_PATH_LENGTH:
        _fail(ReasonCode.invalid_path)
    if (
        not value.startswith("/")
        or "\\" in value
        or "//" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        _fail(ReasonCode.invalid_path)
    if any(token in value for token in ("*", "?", "[", "]")) or value.endswith(("/", "\\")):
        _fail(ReasonCode.invalid_path)
    try:
        path = PurePath(value)
    except (TypeError, ValueError):
        _fail(ReasonCode.invalid_path)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        _fail(ReasonCode.invalid_path)
    if str(path) != value:
        _fail(ReasonCode.invalid_path)
    return value


def _task_archive_path(value: str, task_id: str) -> str:
    """Require the path to name one exact task archive, not its root."""

    if PurePath(value).name != task_id:
        _fail(ReasonCode.invalid_path)
    return value


@dataclass(frozen=True, slots=True)
class CleanupIntent:
    """Durable authority to remove one exact task archive path."""

    task_id: str
    publication_id: str
    manifest_digest: str
    exact_path: str
    requested_at: datetime = field(default_factory=_now)
    state: CleanupState | str = CleanupState.pending
    verified_at: datetime | None = None
    completed_at: datetime | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _identifier(self.task_id))
        object.__setattr__(self, "publication_id", _identifier(self.publication_id))
        object.__setattr__(self, "manifest_digest", _digest(self.manifest_digest))
        object.__setattr__(self, "exact_path", _exact_path(self.exact_path))
        object.__setattr__(self, "requested_at", _timestamp(self.requested_at))
        try:
            state = CleanupState(self.state)
        except (TypeError, ValueError):
            _fail()
        object.__setattr__(self, "state", state)
        verified = None if self.verified_at is None else _timestamp(self.verified_at)
        completed = None if self.completed_at is None else _timestamp(self.completed_at)
        if verified is not None and verified < self.requested_at:
            _fail()
        if completed is not None and (verified is None or completed < verified):
            _fail()
        if state is CleanupState.completed and (verified is None or completed is None):
            _fail()
        if state is not CleanupState.completed and completed is not None:
            _fail()
        if state is CleanupState.blocked and self.reason is None:
            _fail()
        _task_archive_path(self.exact_path, self.task_id)
        object.__setattr__(self, "verified_at", verified)
        object.__setattr__(self, "completed_at", completed)
        object.__setattr__(self, "reason", _reason(self.reason))

    @property
    def intent_id(self) -> str:
        seed = f"cleanup-v1\0{self.task_id}\0{self.publication_id}\0{self.manifest_digest}".encode()
        return f"cleanup-{hashlib.sha256(seed).hexdigest()}"

    @property
    def path(self) -> str:
        return self.exact_path

    @property
    def archive_path(self) -> str:
        return self.exact_path

    def as_dict(self, *, include_private: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "intentId": self.intent_id,
            "taskId": self.task_id,
            "publicationId": self.publication_id,
            "manifestDigest": self.manifest_digest,
            "state": self.state.value,
            "requestedAt": _timestamp_text(self.requested_at),
            "verifiedAt": _timestamp_text(self.verified_at) if self.verified_at else None,
            "completedAt": _timestamp_text(self.completed_at) if self.completed_at else None,
            "reason": self.reason,
        }
        if include_private:
            value["exactPath"] = self.exact_path
        return value

    def as_public_dict(self) -> dict[str, object]:
        return self.as_dict()


PublicationCleanupIntent = CleanupIntent
OutboxCleanupIntent = CleanupIntent
CleanupIntentValue = CleanupIntent


@dataclass(frozen=True, slots=True)
class PublicationOperationResult:
    """A bounded result for one transactional outbox operation."""

    status: PublicationOperationStatus | str
    generation: PublicationGeneration | None = None
    receipt: PublicationReceipt | None = None
    cleanup: CleanupIntent | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        try:
            status = PublicationOperationStatus(self.status)
        except (TypeError, ValueError):
            _fail()
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason", _reason(self.reason))

    @property
    def ok(self) -> bool:
        return self.status in {
            PublicationOperationStatus.enqueued,
            PublicationOperationStatus.existing,
            PublicationOperationStatus.claimed,
            PublicationOperationStatus.renewed,
            PublicationOperationStatus.advanced,
            PublicationOperationStatus.recorded,
            PublicationOperationStatus.verified,
            PublicationOperationStatus.completed,
            PublicationOperationStatus.blocked,
            PublicationOperationStatus.retry_wait,
        }

    @property
    def applied(self) -> bool:
        return self.status in {
            PublicationOperationStatus.enqueued,
            PublicationOperationStatus.claimed,
            PublicationOperationStatus.renewed,
            PublicationOperationStatus.advanced,
            PublicationOperationStatus.recorded,
            PublicationOperationStatus.verified,
            PublicationOperationStatus.completed,
            PublicationOperationStatus.blocked,
            PublicationOperationStatus.retry_wait,
        }

    @property
    def created(self) -> bool:
        return self.status is PublicationOperationStatus.enqueued

    @property
    def replayed(self) -> bool:
        return self.status is PublicationOperationStatus.existing

    @property
    def lost(self) -> bool:
        return self.status is PublicationOperationStatus.lost_claim

    @property
    def lost_claim(self) -> bool:
        return self.lost

    @property
    def illegal(self) -> bool:
        return self.status is PublicationOperationStatus.illegal_transition

    @property
    def illegal_transition(self) -> bool:
        return self.illegal

    @property
    def exhausted(self) -> bool:
        return self.status is PublicationOperationStatus.retry_exhausted

    def __bool__(self) -> bool:
        return self.ok

    def with_status(self, status: PublicationOperationStatus | str) -> "PublicationOperationResult":
        return replace(self, status=status)

    def __getattr__(self, name: str) -> object:
        # Successful claim/transition callers often need the immutable value
        # directly.  Delegation keeps the result typed while preserving that
        # ergonomic access without duplicating the generation fields.
        generation = object.__getattribute__(self, "generation")
        if generation is not None and hasattr(generation, name):
            return getattr(generation, name)
        receipt = object.__getattribute__(self, "receipt")
        if receipt is not None and hasattr(receipt, name):
            return getattr(receipt, name)
        cleanup = object.__getattribute__(self, "cleanup")
        if cleanup is not None and hasattr(cleanup, name):
            return getattr(cleanup, name)
        raise AttributeError(name)

    def as_dict(self) -> dict[str, object]:
        value: dict[str, object] = {"status": self.status.value, "reason": self.reason}
        if self.generation is not None:
            value["generation"] = self.generation.as_dict()
        if self.receipt is not None:
            value["receipt"] = self.receipt.as_public_dict()
        if self.cleanup is not None:
            value["cleanup"] = self.cleanup.as_public_dict()
        return value


# Descriptive aliases keep the result discoverable for callers that name the
# operation rather than the shared mutation boundary.
PublicationMutationStatus = PublicationOperationStatus
PublicationResultStatus = PublicationOperationStatus
PublicationMutationResult = PublicationOperationResult
PublicationTransitionResult = PublicationOperationResult
PublicationClaimResult = PublicationOperationResult
PublicationLeaseResult = PublicationOperationResult
PublicationReceiptResult = PublicationOperationResult
PublicationCleanupResult = PublicationOperationResult
OutboxOperationResult = PublicationOperationResult


__all__ = [
    "CleanupIntent",
    "CleanupState",
    "ExpectedCounts",
    "Generation",
    "GenerationIdentity",
    "GenerationState",
    "GenerationRecord",
    "GenerationStatus",
    "Health",
    "MAX_ATTEMPTS",
    "MAX_CLEANUP_PATH_LENGTH",
    "MAX_CONTENT_KEY_LENGTH",
    "MAX_COUNT",
    "MAX_LEASE_SECONDS",
    "MAX_OBJECT_BYTES",
    "MAX_REASON_LENGTH",
    "MAX_RETRY_DELAY_SECONDS",
    "OutboxCleanupIntent",
    "OutboxGeneration",
    "OutboxHealth",
    "OutboxReceipt",
    "OutboxState",
    "PublicationOutboxState",
    "OutboxValidationError",
    "PublicationCleanupIntent",
    "PublicationCounts",
    "PublicationGeneration",
    "PublicationHealth",
    "PublicationOperationResult",
    "PublicationOperationStatus",
    "PublicationMutationResult",
    "PublicationMutationStatus",
    "PublicationResultStatus",
    "PublicationTransitionResult",
    "PublicationClaimResult",
    "PublicationLeaseResult",
    "PublicationReceiptResult",
    "PublicationCleanupResult",
    "OutboxOperationResult",
    "PublicationReceipt",
    "PublicationReceiptClass",
    "PublicationReceiptValue",
    "PublicationState",
    "Receipt",
    "ReceiptClass",
    "ReceiptKind",
    "CleanupIntentValue",
    "HealthSnapshot",
    "allowed_transition",
    "deterministic_publication_id",
    "generation_id_for",
    "legal_transition",
    "publication_id_for",
    "transition_state",
]

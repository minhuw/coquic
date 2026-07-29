"""Immutable, transport-free values for a Steward publication.

This module deliberately stops at the input boundary.  It does not know about
archives, scanners, D1, R2, or the daemon.  Callers hand later stages bytes
which have already passed the checks here, and receive only bounded failure
categories when a source cannot be trusted.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Final, NoReturn


MAX_IDENTIFIER_LENGTH: Final = 128
MAX_LOGICAL_PATH_LENGTH: Final = 1024
MAX_MEDIA_TYPE_LENGTH: Final = 128
MAX_MODEL_LENGTH: Final = 256
MAX_REASONING_LENGTH: Final = 64
MAX_REASON_CODE_LENGTH: Final = 64
MAX_FINDINGS: Final = 128
MAX_DOCUMENTS: Final = 4_096
MAX_ARTIFACTS: Final = 4_096
MAX_RUN_BYTES: Final = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
MAX_PUBLICATION_BYTES: Final = 256 * 1024 * 1024
MAX_JSONL_RECORDS: Final = 100_000
MAX_COUNTER: Final = 2**31 - 1
MAX_DURATION_MS: Final = 365 * 24 * 60 * 60 * 1000

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MEDIA_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,128}$")
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ReasonCode(StrEnum):
    """The public failure vocabulary.

    Values are intentionally categories, rather than exception text or scanner
    output.  Adding a category is a contract change; callers must not invent
    arbitrary values at runtime.
    """

    missing = "missing"
    running = "running"
    partial = "partial"
    invalid_identifier = "invalid_identifier"
    invalid_path = "invalid_path"
    invalid_media_type = "invalid_media_type"
    invalid_digest = "invalid_digest"
    invalid_metadata = "invalid_metadata"
    symlink = "symlink"
    non_regular = "non_regular"
    hardlink = "hardlink"
    oversized = "oversized"
    size_mismatch = "size_mismatch"
    digest_mismatch = "digest_mismatch"
    changing = "changing"
    invalid_utf8 = "invalid_utf8"
    invalid_jsonl = "invalid_jsonl"
    source_finding = "source_finding"
    patch_finding = "patch_finding"
    staging_unsafe = "staging_unsafe"
    scanner_failure = "scanner_failure"
    ocr_failure = "ocr_failure"
    unsafe_content = "unsafe_content"
    irreparable = "irreparable"


class PublicationError(ValueError):
    """A bounded validation error which never contains the offending value."""

    def __init__(self, code: ReasonCode | str):
        try:
            reason = ReasonCode(code)
        except (TypeError, ValueError):
            reason = ReasonCode.invalid_metadata
        self.code = reason
        super().__init__(reason.value)


def _fail(code: ReasonCode) -> NoReturn:
    # Keep OS/parser details out of normal exception formatting.
    raise PublicationError(code) from None


def _bounded_int(value: object, *, code: ReasonCode, maximum: int = MAX_COUNTER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        _fail(code)
    return value


def _bounded_text(value: object, *, code: ReasonCode, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value) > maximum:
        _fail(code)
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        _fail(code)
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or len(value) > MAX_IDENTIFIER_LENGTH or not _IDENTIFIER_RE.fullmatch(value):
        _fail(ReasonCode.invalid_identifier)
    return value


def _logical_path(value: object) -> str:
    if isinstance(value, PurePosixPath):
        value = value.as_posix()
    if not isinstance(value, str) or len(value) == 0 or len(value) > MAX_LOGICAL_PATH_LENGTH:
        _fail(ReasonCode.invalid_path)
    if (
        "\x00" in value
        or "\\" in value
        or "://" in value
        or value.startswith("/")
        or value.endswith("/")
    ):
        _fail(ReasonCode.invalid_path)
    parts = value.split("/")
    if any(not part or part in {".", ".."} or not _COMPONENT_RE.fullmatch(part) for part in parts):
        _fail(ReasonCode.invalid_path)
    return value


def _media_type(value: object) -> str:
    if not isinstance(value, str) or not _MEDIA_RE.fullmatch(value):
        _fail(ReasonCode.invalid_media_type)
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        _fail(ReasonCode.invalid_digest)
    return value


def _timestamp(value: object) -> datetime:
    if isinstance(value, str):
        parse_error = False
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parse_error = True
        if parse_error:
            _fail(ReasonCode.invalid_metadata)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail(ReasonCode.invalid_metadata)
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _tuple(value: object, *, code: ReasonCode) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail(code)
    return tuple(value)


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """The stat facts used to prove that one opened file stayed stable."""

    device: int
    inode: int
    byte_size: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(
            device=int(value.st_dev),
            inode=int(value.st_ino),
            byte_size=int(value.st_size),
            mtime_ns=int(value.st_mtime_ns),
        )


@dataclass(frozen=True, slots=True)
class StableRead:
    """Bytes and immutable evidence returned by a stable read."""

    content: bytes = field(repr=False)
    identity: FileIdentity
    byte_size: int
    sha256: str
    records: tuple[Any, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            _fail(ReasonCode.invalid_metadata)
        _bounded_int(self.byte_size, code=ReasonCode.invalid_metadata, maximum=MAX_RUN_BYTES)
        if self.byte_size != len(self.content):
            _fail(ReasonCode.size_mismatch)
        if _digest(self.sha256) != hashlib.sha256(self.content).hexdigest():
            _fail(ReasonCode.digest_mismatch)
        if not isinstance(self.identity, FileIdentity):
            _fail(ReasonCode.invalid_metadata)
        records = _tuple(self.records, code=ReasonCode.invalid_metadata)
        object.__setattr__(self, "records", tuple(_freeze(item) for item in records))

    @property
    def data(self) -> bytes:
        """A short name for callers that call file contents ``data``."""

        return self.content

    def as_document(self, logical_path: str, media_type: str = "application/octet-stream") -> "SourceDocument":
        return SourceDocument(logical_path, self.content, media_type)


@dataclass(frozen=True, slots=True)
class RunIdentity:
    task_id: str
    pipeline_id: str
    run_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _identifier(self.task_id))
        object.__setattr__(self, "pipeline_id", _identifier(self.pipeline_id))
        object.__setattr__(self, "run_id", _identifier(self.run_id))

    def as_dict(self) -> dict[str, str]:
        return {"taskId": self.task_id, "pipelineId": self.pipeline_id, "runId": self.run_id}


@dataclass(frozen=True, slots=True)
class RunLineage:
    parent_run_id: str | None = None
    retry_of_run_id: str | None = None
    resume_of_run_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("parent_run_id", "retry_of_run_id", "resume_of_run_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value))

    def as_dict(self) -> dict[str, str | None]:
        return {
            "parentRunId": self.parent_run_id,
            "retryOfRunId": self.retry_of_run_id,
            "resumeOfRunId": self.resume_of_run_id,
        }


@dataclass(frozen=True, slots=True)
class UsageSummary:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cached_input_tokens: int | None = None
    reasoning_output_tokens: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "cached_input_tokens",
            "reasoning_output_tokens",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _bounded_int(value, code=ReasonCode.invalid_metadata))

    def as_dict(self) -> dict[str, int | None]:
        return {
            "promptTokens": self.prompt_tokens,
            "completionTokens": self.completion_tokens,
            "totalTokens": self.total_tokens,
            "cachedInputTokens": self.cached_input_tokens,
            "reasoningOutputTokens": self.reasoning_output_tokens,
        }


_TERMINAL_STATES = frozenset({"completed", "succeeded", "failed", "cancelled", "blocked", "no_changes", "pushed"})


@dataclass(frozen=True, slots=True)
class RunMetadata:
    identity: RunIdentity
    role: str
    state: str
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    model: str | None = None
    reasoning: str | None = None
    lineage: RunLineage = field(default_factory=RunLineage)
    usage: UsageSummary | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, RunIdentity):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "role", _bounded_text(self.role, code=ReasonCode.invalid_metadata, maximum=128))
        object.__setattr__(self, "state", _bounded_text(self.state, code=ReasonCode.invalid_metadata, maximum=32))
        if self.state not in _TERMINAL_STATES:
            _fail(ReasonCode.running if self.state == "running" else ReasonCode.invalid_metadata)
        started = _timestamp(self.started_at)
        completed = _timestamp(self.completed_at)
        if completed < started:
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        object.__setattr__(self, "duration_ms", _bounded_int(self.duration_ms, code=ReasonCode.invalid_metadata, maximum=MAX_DURATION_MS))
        if self.model is not None:
            object.__setattr__(self, "model", _bounded_text(self.model, code=ReasonCode.invalid_metadata, maximum=MAX_MODEL_LENGTH))
        if self.reasoning is not None:
            object.__setattr__(self, "reasoning", _bounded_text(self.reasoning, code=ReasonCode.invalid_metadata, maximum=MAX_REASONING_LENGTH))
        if not isinstance(self.lineage, RunLineage) or (self.usage is not None and not isinstance(self.usage, UsageSummary)):
            _fail(ReasonCode.invalid_metadata)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            **self.identity.as_dict(),
            "role": self.role,
            "state": self.state,
            "startedAt": _timestamp_text(self.started_at),
            "completedAt": _timestamp_text(self.completed_at),
            "durationMs": self.duration_ms,
            "model": self.model,
            "reasoning": self.reasoning,
            "lineage": self.lineage.as_dict(),
            "usage": self.usage.as_dict() if self.usage is not None else None,
        }
        return value


@dataclass(frozen=True, slots=True)
class SourceDocument:
    """A bounded logical document; no host filesystem path is retained."""

    logical_path: str
    content: bytes = field(repr=False)
    media_type: str = "application/octet-stream"
    byte_size: int = field(init=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "logical_path", _logical_path(self.logical_path))
        object.__setattr__(self, "media_type", _media_type(self.media_type))
        if not isinstance(self.content, bytes):
            _fail(ReasonCode.invalid_metadata)
        size = _bounded_int(len(self.content), code=ReasonCode.oversized, maximum=MAX_ARTIFACT_BYTES)
        object.__setattr__(self, "byte_size", size)
        object.__setattr__(self, "sha256", hashlib.sha256(self.content).hexdigest())

    @property
    def data(self) -> bytes:
        return self.content

    @property
    def canonical_bytes(self) -> bytes:
        return self.content

    @property
    def trajectory(self) -> Mapping[str, Any]:
        return self.document

    def as_dict(self) -> dict[str, Any]:
        return {
            "logicalPath": self.logical_path,
            "mediaType": self.media_type,
            "byteSize": self.byte_size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class LogicalArtifact:
    artifact_id: str
    logical_path: str
    media_type: str
    byte_size: int
    sha256: str
    owner_step_id: int | str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _identifier(self.artifact_id))
        object.__setattr__(self, "logical_path", _logical_path(self.logical_path))
        object.__setattr__(self, "media_type", _media_type(self.media_type))
        object.__setattr__(self, "byte_size", _bounded_int(self.byte_size, code=ReasonCode.oversized, maximum=MAX_ARTIFACT_BYTES))
        object.__setattr__(self, "sha256", _digest(self.sha256))
        if self.owner_step_id is not None:
            if isinstance(self.owner_step_id, bool) or (not isinstance(self.owner_step_id, (int, str))):
                _fail(ReasonCode.invalid_metadata)
            if isinstance(self.owner_step_id, int):
                _bounded_int(self.owner_step_id, code=ReasonCode.invalid_metadata)
            else:
                object.__setattr__(self, "owner_step_id", _identifier(self.owner_step_id))

    @classmethod
    def from_document(cls, artifact_id: str, document: SourceDocument, *, owner_step_id: int | str | None = None) -> "LogicalArtifact":
        return cls(artifact_id, document.logical_path, document.media_type, document.byte_size, document.sha256, owner_step_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifactId": self.artifact_id,
            "logicalPath": self.logical_path,
            "mediaType": self.media_type,
            "byteSize": self.byte_size,
            "sha256": self.sha256,
            "ownerStepId": self.owner_step_id,
        }


@dataclass(frozen=True, slots=True)
class PublicBundleComponent:
    artifact: LogicalArtifact
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, LogicalArtifact) or not isinstance(self.content, bytes):
            _fail(ReasonCode.invalid_metadata)
        if len(self.content) != self.artifact.byte_size:
            _fail(ReasonCode.size_mismatch)
        if hashlib.sha256(self.content).hexdigest() != self.artifact.sha256:
            _fail(ReasonCode.digest_mismatch)

    def as_dict(self) -> dict[str, Any]:
        return self.artifact.as_dict()


@dataclass(frozen=True, slots=True)
class PublicBundle:
    components: tuple[PublicBundleComponent, ...] = ()

    def __post_init__(self) -> None:
        components = _tuple(self.components, code=ReasonCode.invalid_metadata)
        if len(components) > MAX_ARTIFACTS or any(not isinstance(item, PublicBundleComponent) for item in components):
            _fail(ReasonCode.invalid_metadata)
        ids = [item.artifact.artifact_id for item in components]
        paths = [item.artifact.logical_path for item in components]
        if len(set(ids)) != len(ids) or len(set(paths)) != len(paths):
            _fail(ReasonCode.invalid_metadata)
        if sum(item.artifact.byte_size for item in components) > MAX_PUBLICATION_BYTES:
            _fail(ReasonCode.oversized)
        object.__setattr__(self, "components", components)

    def as_dict(self) -> dict[str, Any]:
        return {"components": [item.as_dict() for item in self.components]}


@dataclass(frozen=True, slots=True)
class PrivateOriginal:
    """The optional original bytes; no private path or locator is stored."""

    content: bytes = field(repr=False)
    byte_size: int = field(init=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "byte_size", _bounded_int(len(self.content), code=ReasonCode.oversized, maximum=MAX_RUN_BYTES))
        object.__setattr__(self, "sha256", hashlib.sha256(self.content).hexdigest())

    def as_dict(self) -> dict[str, Any]:
        return {"retained": True, "byteSize": self.byte_size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class FindingSummary:
    code: ReasonCode | str
    count: int

    def __post_init__(self) -> None:
        code: ReasonCode | None = None
        try:
            code = ReasonCode(self.code)
        except (TypeError, ValueError):
            code = None
        if code is None:
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "count", _bounded_int(self.count, code=ReasonCode.invalid_metadata, maximum=MAX_FINDINGS))

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "count": self.count}


@dataclass(frozen=True, slots=True)
class PublicationSnapshot:
    run: RunMetadata
    documents: tuple[SourceDocument, ...] = ()
    artifacts: tuple[LogicalArtifact, ...] = ()
    public_bundle: PublicBundle = field(default_factory=PublicBundle)
    private_original: PrivateOriginal | None = None
    findings: tuple[FindingSummary, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.run, RunMetadata) or not isinstance(self.public_bundle, PublicBundle):
            _fail(ReasonCode.invalid_metadata)
        documents = _tuple(self.documents, code=ReasonCode.invalid_metadata)
        artifacts = _tuple(self.artifacts, code=ReasonCode.invalid_metadata)
        findings = _tuple(self.findings, code=ReasonCode.invalid_metadata)
        if not documents or not artifacts:
            _fail(ReasonCode.partial)
        if len(documents) > MAX_DOCUMENTS or any(not isinstance(item, SourceDocument) for item in documents):
            _fail(ReasonCode.invalid_metadata)
        if len(artifacts) > MAX_ARTIFACTS or any(not isinstance(item, LogicalArtifact) for item in artifacts):
            _fail(ReasonCode.invalid_metadata)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, FindingSummary) for item in findings):
            _fail(ReasonCode.invalid_metadata)
        if len({item.logical_path for item in documents}) != len(documents):
            _fail(ReasonCode.invalid_metadata)
        if len({item.artifact_id for item in artifacts}) != len(artifacts) or len({item.logical_path for item in artifacts}) != len(artifacts):
            _fail(ReasonCode.invalid_metadata)
        artifact_by_id = {item.artifact_id: item for item in artifacts}
        if len(self.public_bundle.components) != len(artifacts):
            _fail(ReasonCode.partial)
        for component in self.public_bundle.components:
            if artifact_by_id.get(component.artifact.artifact_id) != component.artifact:
                _fail(ReasonCode.invalid_metadata)
        if sum(item.byte_size for item in documents) + sum(item.byte_size for item in artifacts) > MAX_PUBLICATION_BYTES:
            _fail(ReasonCode.oversized)
        if self.private_original is not None and not isinstance(self.private_original, PrivateOriginal):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "documents", documents)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "findings", findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run": self.run.as_dict(),
            "documents": [item.as_dict() for item in self.documents],
            "artifacts": [item.as_dict() for item in self.artifacts],
            "publicBundle": self.public_bundle.as_dict(),
            "privateOriginal": self.private_original.as_dict() if self.private_original is not None else None,
            "findings": [item.as_dict() for item in self.findings],
        }


def _reasons(value: Sequence[ReasonCode | str]) -> tuple[ReasonCode, ...]:
    value = _tuple(value, code=ReasonCode.invalid_metadata)
    values: list[ReasonCode] = []
    for item in value:
        reason: ReasonCode | None = None
        try:
            reason = ReasonCode(item)
        except (TypeError, ValueError):
            reason = None
        if reason is None:
            _fail(ReasonCode.invalid_metadata)
        if reason not in values:
            values.append(reason)
    if not values or len(values) > MAX_FINDINGS:
        _fail(ReasonCode.invalid_metadata)
    return tuple(values)


_REPAIRABLE_REASONS = frozenset(
    {
        ReasonCode.source_finding,
        ReasonCode.patch_finding,
    }
)
_FAIL_CLOSED_REASONS = frozenset(
    {
        ReasonCode.unsafe_content,
        ReasonCode.invalid_metadata,
        ReasonCode.scanner_failure,
        ReasonCode.ocr_failure,
        ReasonCode.irreparable,
    }
)


@dataclass(frozen=True, slots=True)
class Publishable:
    snapshot: PublicationSnapshot
    status: str = field(init=False, default="publishable")

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, PublicationSnapshot):
            _fail(ReasonCode.invalid_metadata)
        if self.snapshot.findings:
            _fail(ReasonCode.invalid_metadata)

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "snapshot": self.snapshot.as_dict()}


@dataclass(frozen=True, slots=True)
class RepairRequired:
    reason_codes: tuple[ReasonCode, ...]
    findings: tuple[FindingSummary, ...] = ()
    status: str = field(init=False, default="repair_required")

    def __post_init__(self) -> None:
        reasons = _reasons(self.reason_codes)
        if any(reason in _FAIL_CLOSED_REASONS or reason not in _REPAIRABLE_REASONS for reason in reasons):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "reason_codes", reasons)
        findings = _tuple(self.findings, code=ReasonCode.invalid_metadata)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, FindingSummary) for item in findings):
            _fail(ReasonCode.invalid_metadata)
        if any(item.code in _FAIL_CLOSED_REASONS or item.code not in _REPAIRABLE_REASONS for item in findings):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "findings", findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reasonCodes": [item.value for item in self.reason_codes],
            "findings": [item.as_dict() for item in self.findings],
        }


@dataclass(frozen=True, slots=True)
class FailClosed:
    reason_codes: tuple[ReasonCode, ...]
    findings: tuple[FindingSummary, ...] = ()
    status: str = field(init=False, default="fail_closed")

    def __post_init__(self) -> None:
        reasons = _reasons(self.reason_codes)
        if any(reason in _REPAIRABLE_REASONS for reason in reasons):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "reason_codes", reasons)
        findings = _tuple(self.findings, code=ReasonCode.invalid_metadata)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, FindingSummary) for item in findings):
            _fail(ReasonCode.invalid_metadata)
        if any(item.code in _REPAIRABLE_REASONS for item in findings):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "findings", findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reasonCodes": [item.value for item in self.reason_codes],
            "findings": [item.as_dict() for item in self.findings],
        }


PublicationOutcome = Publishable | RepairRequired | FailClosed


@dataclass(frozen=True, slots=True)
class AtifDocument:
    """Canonical ATIF bytes and their detached structured representation.

    The mapper owns schema and semantic validation.  This value is deliberately
    transport-free: it contains no filesystem path, bucket, URL, or uploader
    handle and is safe to pass to a later publication stage only after the
    mapper has completed validation.
    """

    document: Mapping[str, Any] = field(repr=False)
    content: bytes = field(repr=False)
    # Image payloads decoded by the mapper are carried alongside their
    # descriptors for the later transport stage.  They are deliberately kept
    # out of the canonical ATIF JSON envelope.
    artifacts: tuple[PublicBundleComponent, ...] = field(default_factory=tuple, repr=False)
    sha256: str = field(init=False)
    byte_size: int = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.document, Mapping) or not isinstance(self.content, bytes):
            _fail(ReasonCode.invalid_metadata)
        artifacts = _tuple(self.artifacts, code=ReasonCode.invalid_metadata)
        if (
            len(artifacts) > MAX_ARTIFACTS
            or any(not isinstance(item, PublicBundleComponent) for item in artifacts)
            or len({item.artifact.artifact_id for item in artifacts}) != len(artifacts)
            or sum(item.artifact.byte_size for item in artifacts) > MAX_PUBLICATION_BYTES
        ):
            _fail(ReasonCode.invalid_metadata)
        if (
            len(self.content) > MAX_PUBLICATION_BYTES
            or not self.content.endswith(b"\n")
            or self.content[:-1].endswith(b"\n")
        ):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "document", _freeze(dict(self.document)))
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "byte_size", len(self.content))
        object.__setattr__(self, "sha256", hashlib.sha256(self.content).hexdigest())

    @property
    def bytes(self) -> bytes:
        return self.content

    @property
    def data(self) -> bytes:
        return self.content

    @property
    def artifact_contents(self) -> Mapping[str, bytes]:
        """Return retained payloads keyed by their logical artifact IDs."""

        return MappingProxyType({item.artifact.artifact_id: item.content for item in self.artifacts})

    def as_dict(self) -> dict[str, Any]:
        def thaw(value: Any) -> Any:
            if isinstance(value, Mapping):
                return {str(key): thaw(item) for key, item in value.items()}
            if isinstance(value, tuple):
                return [thaw(item) for item in value]
            return value

        value = thaw(self.document)
        return value if isinstance(value, dict) else {}


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    """Bounded result from the public-text sanitization stage.

    The cleaned document is intentionally optional.  A document is exposed
    only for a clean result; repair and fail-closed outcomes carry categories
    and counts, never scanner records, paths, or matched values.
    """

    status: str
    document: AtifDocument | None = field(default=None, repr=False)
    reason_codes: tuple[ReasonCode, ...] = ()
    findings: tuple[FindingSummary, ...] = ()
    replacement_count: int = 0
    redaction_applied: bool = False

    def __post_init__(self) -> None:
        if self.status not in {"clean", "repair_required", "fail_closed"}:
            _fail(ReasonCode.invalid_metadata)
        reasons = _tuple(self.reason_codes, code=ReasonCode.invalid_metadata)
        if any(not isinstance(item, ReasonCode) for item in reasons):
            _fail(ReasonCode.invalid_metadata)
        if len(reasons) > MAX_FINDINGS or len(set(reasons)) != len(reasons):
            _fail(ReasonCode.invalid_metadata)
        findings = _tuple(self.findings, code=ReasonCode.invalid_metadata)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, FindingSummary) for item in findings):
            _fail(ReasonCode.invalid_metadata)
        if self.status == "clean":
            if self.document is None or reasons or findings:
                _fail(ReasonCode.invalid_metadata)
        elif self.document is not None:
            _fail(ReasonCode.invalid_metadata)
        if self.status == "repair_required":
            if not reasons or any(item not in _REPAIRABLE_REASONS for item in reasons):
                _fail(ReasonCode.invalid_metadata)
            if any(item.code not in _REPAIRABLE_REASONS for item in findings):
                _fail(ReasonCode.invalid_metadata)
        elif self.status == "fail_closed":
            if not reasons or any(item in _REPAIRABLE_REASONS for item in reasons):
                _fail(ReasonCode.invalid_metadata)
            if any(item.code in _REPAIRABLE_REASONS for item in findings):
                _fail(ReasonCode.invalid_metadata)
        else:
            if self.replacement_count < 0 or self.redaction_applied != (self.replacement_count > 0):
                _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "reason_codes", tuple(reasons))
        object.__setattr__(self, "findings", tuple(findings))
        object.__setattr__(self, "replacement_count", _bounded_int(self.replacement_count, code=ReasonCode.invalid_metadata, maximum=MAX_COUNTER))
        if self.status != "clean" and (self.replacement_count != 0 or self.redaction_applied):
            _fail(ReasonCode.invalid_metadata)

    @classmethod
    def clean(cls, document: AtifDocument, *, replacement_count: int = 0) -> "SanitizationResult":
        if not isinstance(document, AtifDocument):
            _fail(ReasonCode.invalid_metadata)
        count = _bounded_int(replacement_count, code=ReasonCode.invalid_metadata, maximum=MAX_COUNTER)
        return cls("clean", document=document, replacement_count=count, redaction_applied=count > 0)

    @classmethod
    def repair(cls, reason: ReasonCode, *, count: int = 1) -> "SanitizationResult":
        if reason not in _REPAIRABLE_REASONS:
            _fail(ReasonCode.invalid_metadata)
        finding = FindingSummary(reason, _bounded_int(count, code=ReasonCode.invalid_metadata, maximum=MAX_FINDINGS))
        return cls("repair_required", reason_codes=(reason,), findings=(finding,))

    @classmethod
    def failed(cls, reason: ReasonCode, *, count: int = 1) -> "SanitizationResult":
        if reason in _REPAIRABLE_REASONS:
            _fail(ReasonCode.invalid_metadata)
        finding = FindingSummary(reason, _bounded_int(count, code=ReasonCode.invalid_metadata, maximum=MAX_FINDINGS))
        return cls("fail_closed", reason_codes=(reason,), findings=(finding,))

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "reasonCodes": [item.value for item in self.reason_codes],
            "findings": [item.as_dict() for item in self.findings],
        }
        if self.status == "clean":
            value.update(
                {
                    "redactionApplied": self.redaction_applied,
                    "replacementCount": self.replacement_count,
                }
            )
        return value

    @property
    def content(self) -> bytes | None:
        """Return clean canonical bytes without exposing them in reports."""

        return self.document.content if self.document is not None else None

    @property
    def atif(self) -> AtifDocument | None:
        return self.document


# Descriptive aliases for callers that name this stage redaction rather than
# sanitization; all aliases retain the same bounded result contract.
RedactionResult = SanitizationResult
SanitizerResult = SanitizationResult


# ``AtifTrajectory`` is a descriptive compatibility name used by callers that
# model the structured Harbor object rather than its canonical byte envelope.
AtifTrajectory = AtifDocument
AtifResult = AtifDocument


@dataclass(frozen=True, slots=True)
class _DirectoryLink:
    parent_fd: int
    name: str
    identity: FileIdentity


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _close_fds(descriptors: Sequence[int]) -> None:
    for descriptor in reversed(tuple(descriptors)):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _path_parts(path: Path) -> tuple[str, tuple[str, ...]]:
    path_error = False
    value: Path | None = None
    parts: tuple[str, ...] = ()
    try:
        value = Path(path)
        parts = tuple(value.parts)
    except (OSError, RuntimeError, TypeError, ValueError):
        path_error = True
    if path_error or value is None:
        _fail(ReasonCode.invalid_path)
    if value.is_absolute():
        anchor = value.anchor or os.sep
        components = parts[1:]
    else:
        anchor = "."
        components = parts
    if any(component in {"", ".", ".."} or "\x00" in component for component in components):
        _fail(ReasonCode.invalid_path)
    return anchor, tuple(components)


def _coerce_path(value: object, code: ReasonCode) -> Path:
    path: Path | None = None
    try:
        path = value if isinstance(value, Path) else Path(value)  # type: ignore[arg-type]
    except (OSError, RuntimeError, TypeError, ValueError):
        path = None
    if path is None:
        _fail(code)
    return path


def _validate_path_components(path: Path) -> None:
    """Validate path syntax before opening its descriptor-relative chain."""

    _path_parts(path)


def _open_directory_chain(
    anchor: str,
    components: Sequence[str],
    *,
    failure_code: ReasonCode,
    symlink_code: ReasonCode,
) -> tuple[int, list[_DirectoryLink], list[int]]:
    descriptors: list[int] = []
    links: list[_DirectoryLink] = []
    try:
        anchor_error: ReasonCode | None = None
        current_fd: int | None = None
        try:
            current_fd = os.open(anchor, _DIRECTORY_FLAGS)
        except OSError as exc:
            anchor_error = symlink_code if exc.errno == errno.ELOOP else failure_code
        if anchor_error is not None:
            _fail(anchor_error)
        assert current_fd is not None
        descriptors.append(current_fd)
        for name in components:
            stat_error: ReasonCode | None = None
            before: os.stat_result | None = None
            try:
                before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            except OSError as exc:
                stat_error = symlink_code if exc.errno == errno.ELOOP else failure_code
            if stat_error is not None:
                _fail(stat_error)
            assert before is not None
            if stat.S_ISLNK(before.st_mode):
                _fail(symlink_code)
            if not stat.S_ISDIR(before.st_mode):
                _fail(failure_code)
            open_error: ReasonCode | None = None
            child_fd: int | None = None
            try:
                child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=current_fd)
            except OSError as exc:
                open_error = symlink_code if exc.errno == errno.ELOOP else failure_code
            if open_error is not None:
                _fail(open_error)
            assert child_fd is not None
            descriptors.append(child_fd)
            opened: os.stat_result | None = None
            stat_error = None
            try:
                opened = os.fstat(child_fd)
            except OSError:
                stat_error = ReasonCode.changing
            if stat_error is not None:
                _fail(stat_error)
            assert opened is not None
            identity = FileIdentity.from_stat(opened)
            if identity != FileIdentity.from_stat(before) or not stat.S_ISDIR(opened.st_mode):
                _fail(ReasonCode.changing)
            links.append(_DirectoryLink(current_fd, name, identity))
            current_fd = child_fd
        return current_fd, links, descriptors
    except BaseException:
        _close_fds(descriptors)
        raise


def _verify_directory_chain(links: Sequence[_DirectoryLink]) -> ReasonCode | None:
    for link in links:
        failure: ReasonCode | None = None
        current: os.stat_result | None = None
        try:
            current = os.stat(link.name, dir_fd=link.parent_fd, follow_symlinks=False)
        except OSError:
            failure = ReasonCode.changing
        if failure is not None:
            return failure
        assert current is not None
        if stat.S_ISLNK(current.st_mode):
            return ReasonCode.symlink
        if (
            current.st_dev != link.identity.device
            or current.st_ino != link.identity.inode
            or not stat.S_ISDIR(current.st_mode)
        ):
            return ReasonCode.changing
    return None


def _file_failure(exc: OSError) -> ReasonCode:
    if exc.errno == errno.ELOOP:
        return ReasonCode.symlink
    if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
        return ReasonCode.missing
    return ReasonCode.non_regular


def _open_stable(
    path: Path,
    *,
    max_bytes: int,
    expected_size: int | None,
    expected_sha256: str | None,
    require_private: bool = False,
) -> StableRead:
    path = _coerce_path(path, ReasonCode.invalid_path)
    _validate_path_components(path)
    anchor, components = _path_parts(path)
    if not components:
        _fail(ReasonCode.non_regular)
    limit = _bounded_int(max_bytes, code=ReasonCode.oversized, maximum=MAX_RUN_BYTES)
    parent_fd, links, descriptors = _open_directory_chain(
        anchor,
        components[:-1],
        failure_code=ReasonCode.missing,
        symlink_code=ReasonCode.symlink,
    )
    final_name = components[-1]
    descriptor: int | None = None
    try:
        stat_error: ReasonCode | None = None
        before_path: os.stat_result | None = None
        try:
            chain_error = _verify_directory_chain(links)
            if chain_error is None:
                before_path = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            else:
                stat_error = chain_error
        except OSError as exc:
            stat_error = _file_failure(exc)
        if stat_error is not None:
            _fail(stat_error)
        assert before_path is not None
        if stat.S_ISLNK(before_path.st_mode):
            _fail(ReasonCode.symlink)
        if not stat.S_ISREG(before_path.st_mode):
            _fail(ReasonCode.non_regular)
        if before_path.st_nlink != 1:
            _fail(ReasonCode.hardlink)
        if require_private and stat.S_IMODE(before_path.st_mode) & 0o077:
            _fail(ReasonCode.unsafe_content)
        if before_path.st_size > limit:
            _fail(ReasonCode.oversized)
        open_error: ReasonCode | None = None
        try:
            descriptor = os.open(final_name, _FILE_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            open_error = _file_failure(exc)
        if open_error is not None:
            _fail(open_error)
        opened: os.stat_result | None = None
        stat_error = None
        try:
            opened = os.fstat(descriptor)
        except OSError:
            stat_error = ReasonCode.changing
        if stat_error is not None:
            _fail(stat_error)
        assert opened is not None
        first = FileIdentity.from_stat(opened)
        if (
            first != FileIdentity.from_stat(before_path)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (require_private and stat.S_IMODE(opened.st_mode) & 0o077)
        ):
            _fail(ReasonCode.changing)
        chunks: list[bytes] = []
        total = 0
        read_error = False
        try:
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    _fail(ReasonCode.oversized)
                chunks.append(chunk)
        except OSError:
            read_error = True
        if read_error:
            _fail(ReasonCode.changing)
        content = b"".join(chunks)
        after: os.stat_result | None = None
        stat_error = None
        try:
            after = os.fstat(descriptor)
        except OSError:
            stat_error = ReasonCode.changing
        if stat_error is not None:
            _fail(stat_error)
        assert after is not None
        after_path: os.stat_result | None = None
        path_error = False
        try:
            after_path = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            path_error = True
        if path_error:
            _fail(ReasonCode.changing)
        assert after_path is not None
        if stat.S_ISLNK(after_path.st_mode):
            _fail(ReasonCode.symlink)
        if (
            FileIdentity.from_stat(after) != first
            or FileIdentity.from_stat(after_path) != first
            or after.st_size != len(content)
            or after.st_nlink != 1
            or after_path.st_nlink != 1
            or (require_private and (stat.S_IMODE(after.st_mode) & 0o077 or stat.S_IMODE(after_path.st_mode) & 0o077))
        ):
            _fail(ReasonCode.changing)
        chain_error = _verify_directory_chain(links)
        if chain_error is not None:
            _fail(chain_error)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _close_fds(descriptors)
    digest = hashlib.sha256(content).hexdigest()
    if expected_size is not None:
        if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
            _fail(ReasonCode.size_mismatch)
        if expected_size != len(content):
            _fail(ReasonCode.size_mismatch)
    if expected_sha256 is not None and (_digest(expected_sha256) != digest):
        _fail(ReasonCode.digest_mismatch)
    return StableRead(content, first, len(content), digest)


def read_stable_file(
    path: Path,
    *,
    max_bytes: int = MAX_RUN_BYTES,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
    require_private: bool = False,
) -> StableRead:
    """Read one regular file while proving identity, size, and mtime stability."""

    return _open_stable(
        path,
        max_bytes=max_bytes,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        require_private=require_private,
    )


def _json_records(content: bytes) -> tuple[Any, ...]:
    if not content or not content.endswith(b"\n"):
        _fail(ReasonCode.partial)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        _fail(ReasonCode.invalid_utf8)
    records: list[Any] = []
    for line in text.splitlines(keepends=False):
        if not line.strip():
            _fail(ReasonCode.invalid_jsonl)
        parse_error = False
        try:
            value = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
                parse_float=_parse_json_float,
            )
        except PublicationError:
            raise
        except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
            parse_error = True
        if parse_error:
            _fail(ReasonCode.invalid_jsonl)
        if not isinstance(value, Mapping):
            _fail(ReasonCode.invalid_jsonl)
        freeze_error = False
        try:
            records.append(_freeze(value))
        except (MemoryError, RecursionError, TypeError, ValueError):
            freeze_error = True
        if freeze_error:
            _fail(ReasonCode.invalid_jsonl)
        if len(records) > MAX_JSONL_RECORDS:
            _fail(ReasonCode.oversized)
    if not records:
        _fail(ReasonCode.partial)
    return tuple(records)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(ReasonCode.invalid_jsonl)
        value[key] = item
    return value


def _reject_json_constant(value: str) -> float:
    del value
    raise ValueError


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError
    return parsed


def read_stable_jsonl(
    path: Path,
    *,
    max_bytes: int = MAX_RUN_BYTES,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> StableRead:
    """Read complete UTF-8 JSONL records through the stable-file boundary."""

    value = _open_stable(path, max_bytes=max_bytes, expected_size=expected_size, expected_sha256=expected_sha256)
    object.__setattr__(value, "records", _json_records(value.content))
    return value


def _verify_directory_entry(
    parent_fd: int,
    name: str,
    expected: FileIdentity,
    *,
    directory: bool | None = None,
) -> os.stat_result | None:
    info: os.stat_result | None = None
    failure = False
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        failure = True
    if failure or info is None:
        return None
    if stat.S_ISLNK(info.st_mode):
        return None
    if directory is True and (
        not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
    ):
        return None
    if directory is False and not stat.S_ISREG(info.st_mode):
        return None
    current_identity = FileIdentity.from_stat(info)
    if directory is True:
        same_identity = current_identity.device == expected.device and current_identity.inode == expected.inode
    else:
        same_identity = current_identity == expected
    if not same_identity:
        return None
    return info


def _validate_private_tree_fd(root_fd: int) -> ReasonCode | None:
    pending = [root_fd]
    opened: list[int] = []
    try:
        while pending:
            current_fd = pending.pop()
            names: list[str] | None = None
            try:
                names = os.listdir(current_fd)
            except OSError:
                return ReasonCode.staging_unsafe
            assert names is not None
            for name in names:
                info: os.stat_result | None = None
                try:
                    info = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                except OSError:
                    return ReasonCode.staging_unsafe
                assert info is not None
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)
                    or (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) != 0o700)
                ):
                    return ReasonCode.staging_unsafe
                if stat.S_ISDIR(info.st_mode):
                    child_fd: int | None = None
                    try:
                        child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=current_fd)
                    except OSError:
                        return ReasonCode.staging_unsafe
                    assert child_fd is not None
                    opened.append(child_fd)
                    child_info: os.stat_result | None = None
                    try:
                        child_info = os.fstat(child_fd)
                    except OSError:
                        return ReasonCode.staging_unsafe
                    assert child_info is not None
                    if FileIdentity.from_stat(child_info) != FileIdentity.from_stat(info):
                        return ReasonCode.staging_unsafe
                    pending.append(child_fd)
    finally:
        _close_fds(opened)
    return None


def _remove_private_tree_fd(root_fd: int) -> ReasonCode | None:
    directories: list[tuple[int, int | None, str | None, FileIdentity | None]] = [(root_fd, None, None, None)]
    pending = [root_fd]
    opened: list[int] = []
    try:
        while pending:
            current_fd = pending.pop()
            names: list[str] | None = None
            try:
                names = os.listdir(current_fd)
            except OSError:
                return ReasonCode.staging_unsafe
            assert names is not None
            for name in names:
                info: os.stat_result | None = None
                try:
                    info = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                except OSError:
                    return ReasonCode.staging_unsafe
                assert info is not None
                identity = FileIdentity.from_stat(info)
                if stat.S_ISLNK(info.st_mode):
                    unlink_error = False
                    try:
                        os.unlink(name, dir_fd=current_fd)
                    except OSError:
                        unlink_error = True
                    if unlink_error:
                        return ReasonCode.staging_unsafe
                    continue
                if stat.S_ISREG(info.st_mode):
                    if _verify_directory_entry(current_fd, name, identity, directory=False) is None:
                        return ReasonCode.staging_unsafe
                    unlink_error = False
                    try:
                        os.unlink(name, dir_fd=current_fd)
                    except OSError:
                        unlink_error = True
                    if unlink_error:
                        return ReasonCode.staging_unsafe
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    return ReasonCode.staging_unsafe
                child_fd: int | None = None
                try:
                    child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=current_fd)
                except OSError:
                    return ReasonCode.staging_unsafe
                assert child_fd is not None
                opened.append(child_fd)
                child_info: os.stat_result | None = None
                try:
                    child_info = os.fstat(child_fd)
                except OSError:
                    return ReasonCode.staging_unsafe
                assert child_info is not None
                if FileIdentity.from_stat(child_info) != identity:
                    return ReasonCode.staging_unsafe
                directories.append((child_fd, current_fd, name, identity))
                pending.append(child_fd)
        for child_fd, parent_fd, name, identity in reversed(directories[1:]):
            assert parent_fd is not None and name is not None and identity is not None
            if _verify_directory_entry(parent_fd, name, identity, directory=True) is None:
                return ReasonCode.staging_unsafe
            remove_error = False
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                remove_error = True
            if remove_error:
                return ReasonCode.staging_unsafe
    finally:
        _close_fds(opened)
    return None


def _discard_private_child(root_fd: int, name: str, descriptor: int | None = None) -> None:
    if descriptor is not None:
        _close_fds([descriptor])
    try:
        os.rmdir(name, dir_fd=root_fd)
    except OSError:
        pass


def _create_private_child(root_fd: int) -> tuple[str, FileIdentity, int] | None:
    for _ in range(32):
        name = f".publication-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
        except FileExistsError:
            continue
        except OSError:
            return None
        chmod_error = False
        try:
            os.chmod(name, 0o700, dir_fd=root_fd, follow_symlinks=False)
        except OSError:
            chmod_error = True
        if chmod_error:
            _discard_private_child(root_fd, name)
            return None
        info: os.stat_result | None = None
        child_fd: int | None = None
        stat_error = False
        try:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root_fd)
        except OSError:
            stat_error = True
        if stat_error or info is None or child_fd is None:
            _discard_private_child(root_fd, name, child_fd)
            return None
        chmod_error = False
        try:
            os.fchmod(child_fd, 0o700)
        except OSError:
            chmod_error = True
        if chmod_error:
            _discard_private_child(root_fd, name, child_fd)
            return None
        created_identity = FileIdentity.from_stat(info)
        opened: os.stat_result | None = None
        stat_error = False
        try:
            opened = os.fstat(child_fd)
        except OSError:
            stat_error = True
        if stat_error or opened is None:
            _discard_private_child(root_fd, name, child_fd)
            return None
        identity = FileIdentity.from_stat(opened)
        if (
            stat.S_IMODE(opened.st_mode) != 0o700
            or not stat.S_ISDIR(opened.st_mode)
            or identity.device != created_identity.device
            or identity.inode != created_identity.inode
        ):
            _discard_private_child(root_fd, name, child_fd)
            return None
        return name, identity, child_fd
    return None


def _staging_components(value: object) -> tuple[str, ...]:
    path = _coerce_path(value, ReasonCode.staging_unsafe)
    path_error = False
    anchor = "."
    components: tuple[str, ...] = ()
    try:
        anchor, components = _path_parts(path)
    except PublicationError:
        path_error = True
    if path_error:
        _fail(ReasonCode.staging_unsafe)
    if anchor != "." or not components:
        _fail(ReasonCode.staging_unsafe)
    if sum(len(component) + 1 for component in components) > MAX_LOGICAL_PATH_LENGTH:
        _fail(ReasonCode.staging_unsafe)
    if any(not _COMPONENT_RE.fullmatch(component) for component in components):
        _fail(ReasonCode.staging_unsafe)
    return components


def _staging_open_flags(mode: object) -> tuple[int, str]:
    if not isinstance(mode, str) or not mode or mode.count("+") > 1 or any(char not in "rwa+bxt" for char in mode):
        _fail(ReasonCode.staging_unsafe)
    normalized = mode
    if normalized.count("b") > 1 or normalized.count("x") > 1 or normalized.count("t") > 1:
        _fail(ReasonCode.staging_unsafe)
    access = [char for char in normalized if char in "rwax"]
    if len(access) != 1 or ("b" in normalized and "t" in normalized):
        _fail(ReasonCode.staging_unsafe)
    access_mode = access[0]
    plus = "+" in normalized
    if access_mode == "r":
        flags = os.O_RDWR if plus else os.O_RDONLY
    elif access_mode == "w":
        flags = os.O_RDWR if plus else os.O_WRONLY
        flags |= os.O_CREAT
    elif access_mode == "a":
        flags = os.O_RDWR if plus else os.O_WRONLY
        flags |= os.O_CREAT | os.O_APPEND
    else:
        flags = os.O_RDWR if plus else os.O_WRONLY
        flags |= os.O_CREAT | os.O_EXCL
    return flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), access_mode


def _open_staging_file(root_fd: int, components: Sequence[str], mode: str) -> Any:
    flags, access_mode = _staging_open_flags(mode)
    parent_fd = root_fd
    descriptors: list[int] = []
    try:
        for name in components[:-1]:
            info: os.stat_result | None = None
            stat_error = False
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                stat_error = True
            if (
                stat_error
                or info is None
                or stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                _fail(ReasonCode.staging_unsafe)
            child_fd: int | None = None
            open_error = False
            try:
                child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            except OSError:
                open_error = True
            if open_error or child_fd is None:
                _fail(ReasonCode.staging_unsafe)
            descriptors.append(child_fd)
            opened: os.stat_result | None = None
            stat_error = False
            try:
                opened = os.fstat(child_fd)
            except OSError:
                stat_error = True
            if stat_error or opened is None or FileIdentity.from_stat(opened) != FileIdentity.from_stat(info):
                _fail(ReasonCode.staging_unsafe)
            parent_fd = child_fd

        final_name = components[-1]
        final_before: os.stat_result | None = None
        final_missing = False
        stat_error = False
        try:
            final_before = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                final_missing = True
            else:
                stat_error = True
        if stat_error:
            _fail(ReasonCode.staging_unsafe)
        if final_before is not None and (
            stat.S_ISLNK(final_before.st_mode)
            or not stat.S_ISREG(final_before.st_mode)
            or final_before.st_nlink != 1
        ):
            _fail(ReasonCode.staging_unsafe)
        if access_mode == "r" and final_missing:
            _fail(ReasonCode.staging_unsafe)
        if final_missing:
            flags |= os.O_EXCL
        if access_mode == "x" and final_before is not None:
            _fail(ReasonCode.staging_unsafe)
        descriptor: int | None = None
        open_error = False
        try:
            descriptor = os.open(final_name, flags, 0o600, dir_fd=parent_fd)
        except OSError:
            open_error = True
        if open_error or descriptor is None:
            _fail(ReasonCode.staging_unsafe)
        opened = None
        stat_error = False
        try:
            opened = os.fstat(descriptor)
        except OSError:
            stat_error = True
        if (
            stat_error
            or opened is None
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (final_before is not None and FileIdentity.from_stat(opened) != FileIdentity.from_stat(final_before))
        ):
            _close_fds([descriptor])
            _fail(ReasonCode.staging_unsafe)
        if access_mode == "w":
            truncate_error = False
            try:
                os.ftruncate(descriptor, 0)
            except OSError:
                truncate_error = True
            if truncate_error:
                _close_fds([descriptor])
                _fail(ReasonCode.staging_unsafe)
        file_object: Any = None
        fdopen_error = False
        try:
            file_object = os.fdopen(descriptor, mode)
        except (OSError, TypeError, ValueError):
            fdopen_error = True
        if fdopen_error or file_object is None:
            _close_fds([descriptor])
            _fail(ReasonCode.staging_unsafe)
        descriptor = None
        return file_object
    finally:
        _close_fds(descriptors)


class PrivateStaging:
    """Descriptor-anchored temporary workspace with no exposed path."""

    __slots__ = ("_fd", "_links")

    def __init__(self, descriptor: int, links: Sequence[_DirectoryLink]) -> None:
        self._fd: int | None = descriptor
        self._links = tuple(links)

    def __repr__(self) -> str:
        return "PrivateStaging()"

    def _ensure_open(self) -> int:
        descriptor = self._fd
        if descriptor is None:
            _fail(ReasonCode.staging_unsafe)
        chain_error = _verify_directory_chain(self._links)
        if chain_error is not None:
            _fail(chain_error)
        return descriptor

    def open(self, name: str, mode: str = "rb") -> Any:
        """Open one contained file relative to the held directory descriptor."""

        return _open_staging_file(self._ensure_open(), _staging_components(name), mode)

    def write_bytes(self, name: str, content: bytes) -> None:
        """Write bytes through a descriptor-relative file open."""

        if not isinstance(content, bytes):
            _fail(ReasonCode.staging_unsafe)
        write_error = False
        try:
            with self.open(name, "wb") as handle:
                handle.write(content)
                handle.flush()
        except PublicationError:
            raise
        except (OSError, TypeError, ValueError):
            write_error = True
        if write_error:
            _fail(ReasonCode.staging_unsafe)


@contextmanager
def private_staging(root: Path) -> Iterator[PrivateStaging]:
    """Yield descriptor-anchored mode-0700 temporary storage below ``root``."""

    if not isinstance(root, Path):
        root = _coerce_path(root, ReasonCode.staging_unsafe)
    path_error = False
    try:
        _validate_path_components(root)
    except PublicationError:
        path_error = True
    if path_error:
        _fail(ReasonCode.staging_unsafe)
    anchor, components = _path_parts(root)
    root_fd, links, descriptors = _open_directory_chain(
        anchor,
        components,
        failure_code=ReasonCode.staging_unsafe,
        symlink_code=ReasonCode.staging_unsafe,
    )
    child_name: str | None = None
    child_identity: FileIdentity | None = None
    child_fd: int | None = None
    staging: PrivateStaging | None = None
    try:
        root_info: os.stat_result | None = None
        root_error = False
        try:
            root_info = os.fstat(root_fd)
        except OSError:
            root_error = True
        if root_error or root_info is None:
            _fail(ReasonCode.staging_unsafe)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o700:
            _fail(ReasonCode.staging_unsafe)
        chain_error = _verify_directory_chain(links)
        if chain_error is not None:
            _fail(chain_error)
        created = _create_private_child(root_fd)
        if created is None:
            _fail(ReasonCode.staging_unsafe)
        child_name, child_identity, child_fd = created
        staging = PrivateStaging(child_fd, links)
        body_error: BaseException | None = None
        body_traceback = None
        try:
            yield staging
        except BaseException as exc:
            body_error = exc
            body_traceback = exc.__traceback__
        validation_code: ReasonCode | None = _verify_directory_chain(links)
        current_root: os.stat_result | None = None
        root_error = False
        try:
            current_root = os.fstat(root_fd)
        except OSError:
            root_error = True
        if root_error or current_root is None:
            validation_code = ReasonCode.staging_unsafe
        elif (
            current_root.st_dev != root_info.st_dev
            or current_root.st_ino != root_info.st_ino
            or stat.S_IMODE(current_root.st_mode) != 0o700
        ):
            validation_code = ReasonCode.staging_unsafe
        if _verify_directory_entry(root_fd, child_name, child_identity, directory=True) is None:
            validation_code = ReasonCode.staging_unsafe
        tree_code = _validate_private_tree_fd(child_fd)
        if tree_code is not None:
            validation_code = tree_code

        cleanup_code = _remove_private_tree_fd(child_fd)
        if cleanup_code is None and _verify_directory_entry(root_fd, child_name, child_identity, directory=True) is None:
            cleanup_code = ReasonCode.staging_unsafe
        remove_error = False
        if cleanup_code is None:
            try:
                os.rmdir(child_name, dir_fd=root_fd)
            except OSError:
                remove_error = True
            if remove_error:
                cleanup_code = ReasonCode.staging_unsafe
        if body_error is not None:
            raise body_error.with_traceback(body_traceback)
        if validation_code is not None:
            _fail(validation_code)
        if cleanup_code is not None:
            _fail(cleanup_code)
    finally:
        if staging is not None:
            staging._fd = None
        _close_fds([child_fd] if child_fd is not None else [])
        _close_fds(descriptors)


__all__ = [
    "FailClosed",
    "FileIdentity",
    "FindingSummary",
    "LogicalArtifact",
    "MAX_ARTIFACT_BYTES",
    "MAX_DOCUMENTS",
    "MAX_FINDINGS",
    "MAX_IDENTIFIER_LENGTH",
    "MAX_LOGICAL_PATH_LENGTH",
    "MAX_PUBLICATION_BYTES",
    "MAX_RUN_BYTES",
    "PrivateOriginal",
    "PrivateStaging",
    "PublicationError",
    "PublicationOutcome",
    "PublicationSnapshot",
    "PublicBundle",
    "PublicBundleComponent",
    "Publishable",
    "ReasonCode",
    "RepairRequired",
    "RedactionResult",
    "RunIdentity",
    "RunLineage",
    "RunMetadata",
    "SanitizationResult",
    "SanitizerResult",
    "SourceDocument",
    "StableRead",
    "UsageSummary",
    "private_staging",
    "read_stable_file",
    "read_stable_jsonl",
]

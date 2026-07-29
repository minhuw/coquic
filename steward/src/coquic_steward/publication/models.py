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
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Final


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


def _fail(code: ReasonCode) -> None:
    raise PublicationError(code)


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
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
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

    content: bytes
    identity: FileIdentity
    byte_size: int
    sha256: str
    records: tuple[Any, ...] = ()

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
    content: bytes
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
    content: bytes

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

    content: bytes
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
        try:
            code = ReasonCode(self.code)
        except (TypeError, ValueError):
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
        try:
            reason = ReasonCode(item)
        except (TypeError, ValueError):
            _fail(ReasonCode.invalid_metadata)
        if reason not in values:
            values.append(reason)
    if not values or len(values) > MAX_FINDINGS:
        _fail(ReasonCode.invalid_metadata)
    return tuple(values)


@dataclass(frozen=True, slots=True)
class Publishable:
    snapshot: PublicationSnapshot
    status: str = field(init=False, default="publishable")

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, PublicationSnapshot):
            _fail(ReasonCode.invalid_metadata)

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "snapshot": self.snapshot.as_dict()}


@dataclass(frozen=True, slots=True)
class RepairRequired:
    reason_codes: tuple[ReasonCode, ...]
    findings: tuple[FindingSummary, ...] = ()
    status: str = field(init=False, default="repair_required")

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", _reasons(self.reason_codes))
        findings = _tuple(self.findings, code=ReasonCode.invalid_metadata)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, FindingSummary) for item in findings):
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
        object.__setattr__(self, "reason_codes", _reasons(self.reason_codes))
        findings = _tuple(self.findings, code=ReasonCode.invalid_metadata)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, FindingSummary) for item in findings):
            _fail(ReasonCode.invalid_metadata)
        object.__setattr__(self, "findings", findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reasonCodes": [item.value for item in self.reason_codes],
            "findings": [item.as_dict() for item in self.findings],
        }


PublicationOutcome = Publishable | RepairRequired | FailClosed


def _validate_path_components(path: Path) -> None:
    """Reject symlink traversal before opening a caller-supplied path."""

    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current /= component
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode):
                _fail(ReasonCode.symlink)
    except (OSError, RuntimeError):
        _fail(ReasonCode.missing)


def _open_stable(path: Path, *, max_bytes: int, expected_size: int | None, expected_sha256: str | None) -> StableRead:
    if not isinstance(path, Path):
        path = Path(path)
    _validate_path_components(path)
    try:
        before_path = os.lstat(path)
    except OSError as exc:
        _fail(ReasonCode.missing if exc.errno in {errno.ENOENT, errno.ENOTDIR} else ReasonCode.non_regular)
    if stat.S_ISLNK(before_path.st_mode):
        _fail(ReasonCode.symlink)
    if not stat.S_ISREG(before_path.st_mode):
        _fail(ReasonCode.non_regular)
    if before_path.st_nlink != 1:
        _fail(ReasonCode.hardlink)
    limit = _bounded_int(max_bytes, code=ReasonCode.oversized, maximum=MAX_RUN_BYTES)
    if before_path.st_size > limit:
        _fail(ReasonCode.oversized)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        _fail(ReasonCode.symlink if exc.errno == errno.ELOOP else ReasonCode.missing)
    try:
        opened = os.fstat(descriptor)
        first = FileIdentity.from_stat(opened)
        if first != FileIdentity.from_stat(before_path) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            _fail(ReasonCode.changing)
        chunks: list[bytes] = []
        total = 0
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
            _fail(ReasonCode.changing)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            after_path = os.lstat(path)
        except OSError:
            _fail(ReasonCode.changing)
        if (
            FileIdentity.from_stat(after) != first
            or FileIdentity.from_stat(after_path) != first
            or after.st_size != len(content)
            or after.st_nlink != 1
            or after_path.st_nlink != 1
        ):
            _fail(ReasonCode.changing)
    finally:
        os.close(descriptor)
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
) -> StableRead:
    """Read one regular file while proving identity, size, and mtime stability."""

    return _open_stable(path, max_bytes=max_bytes, expected_size=expected_size, expected_sha256=expected_sha256)


def _json_records(content: bytes) -> tuple[Any, ...]:
    if not content or not content.endswith(b"\n"):
        _fail(ReasonCode.partial)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        _fail(ReasonCode.invalid_utf8)
    records: list[Any] = []
    for line in text.splitlines(keepends=False):
        if not line.strip():
            _fail(ReasonCode.invalid_jsonl)
        try:
            value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (TypeError, ValueError, json.JSONDecodeError):
            _fail(ReasonCode.invalid_jsonl)
        if not isinstance(value, Mapping):
            _fail(ReasonCode.invalid_jsonl)
        records.append(_freeze(value))
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


def _validate_private_directory(path: Path) -> None:
    _validate_path_components(path)
    try:
        info = path.lstat()
    except OSError:
        _fail(ReasonCode.staging_unsafe)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(ReasonCode.staging_unsafe)
    if stat.S_IMODE(info.st_mode) != 0o700:
        _fail(ReasonCode.staging_unsafe)


def _validate_private_tree(path: Path) -> None:
    try:
        for child in path.rglob("*"):
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or (not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode)):
                _fail(ReasonCode.staging_unsafe)
    except OSError:
        _fail(ReasonCode.staging_unsafe)


@contextmanager
def private_staging(root: Path) -> Iterator[Path]:
    """Yield a mode-0700 temporary directory contained by ``root``."""

    if not isinstance(root, Path):
        root = Path(root)
    _validate_private_directory(root)
    try:
        child = Path(tempfile.mkdtemp(prefix=".publication-", dir=root))
    except OSError:
        _fail(ReasonCode.staging_unsafe)
    try:
        if child.parent != root or child.is_symlink() or stat.S_IMODE(child.lstat().st_mode) != 0o700:
            _fail(ReasonCode.staging_unsafe)
        yield child
        _validate_private_tree(child)
    finally:
        try:
            if child.is_symlink():
                child.unlink()
            elif child.exists():
                shutil.rmtree(child)
        except OSError:
            # Cleanup failure is not allowed to turn into an unsafe public
            # result, but it remains a caller-visible bounded staging error.
            raise PublicationError(ReasonCode.staging_unsafe)


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
    "PublicationError",
    "PublicationOutcome",
    "PublicationSnapshot",
    "PublicBundle",
    "PublicBundleComponent",
    "Publishable",
    "ReasonCode",
    "RepairRequired",
    "RunIdentity",
    "RunLineage",
    "RunMetadata",
    "SourceDocument",
    "StableRead",
    "UsageSummary",
    "private_staging",
    "read_stable_file",
    "read_stable_jsonl",
]

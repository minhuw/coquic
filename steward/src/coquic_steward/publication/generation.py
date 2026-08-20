"""Compose deterministic, transport-free task publication generations.

The run publication pipeline deliberately stops at one inspected completed
run.  This module is the next pure boundary: it takes an already stable task
graph, invokes that pipeline once per eligible run, and returns a detached D1
staging envelope together with the exact bytes that later transports may use.

There is intentionally no archive, database, cloud, clock, or subprocess
operation here.  Callers own the stable archive view and may inject the run
builder for tests or for a daemon's already configured publication policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, TypeAlias

from .envelope import (
    EnvelopeError,
    publication_metadata_digest,
    usage_metadata_digest,
    validate_publication_envelope,
)
from .atif import AtifSource
from .media import inspect_media
from .models import (
    AtifDocument,
    FailClosed,
    FindingSummary,
    LogicalArtifact,
    PriceProvenance,
    PrivateOriginal,
    PublicationError,
    PublicationOutcome,
    PublicationSnapshot,
    PublicBundle,
    PublicBundleComponent,
    Publishable,
    ReasonCode,
    RepairRequired,
    RunIdentity,
    RunLineage,
    RunMetadata,
    SanitizationResult,
    SourceDocument,
    StableRead,
    TaskUsageDaily,
    TaskUsageLifetime,
    TaskUsageProjection,
    TaskUsageSummary,
    UsageCosts,
    UsageCoverage,
    UsageGenerationMetadata,
    UsageInvocation,
    UsageRun,
    UsageSummary,
    UsageTokens,
    UsageTurn,
)
from .pipeline import build_publication_bundle
from .redaction import discover_secrets
from .scanner import CorpusEntry, run_trufflehog
from .usage import build_task_usage_projection
from . import outbox
from .outbox import GenerationIdentity, PublicationCounts


PUBLICATION_SCHEMA_VERSION: Final[str] = "2.0"
MAX_GENERATION_RUNS: Final[int] = 4_096
MAX_GENERATION_EVENTS: Final[int] = 4_096
MAX_GENERATION_ARTIFACTS: Final[int] = 16_384
MAX_GENERATION_OBJECTS: Final[int] = 16_384
MAX_GENERATION_GRAPH_NODES: Final[int] = 131_072
MAX_GENERATION_STRINGS: Final[int] = 65_536
MAX_GRAPH_CAPTURE_PASSES: Final[int] = 3

_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
_MISSING: Final = object()


def _publication_compose_kwargs(publication: object | None) -> dict[str, object]:
    """Return credential-aware inputs for the canonical publication composer."""

    if publication is None:
        return {"credential_sources": ()}
    return {
        "credential_sources": tuple(
            path
            for path in (
                getattr(publication, "d1_token_path", None),
                getattr(publication, "r2_access_key_id_path", None),
                getattr(publication, "r2_secret_access_key_path", None),
            )
            if path is not None
        ),
        "staging_root": getattr(publication, "staging_root", None),
    }


def _known_public_mapping(value: object) -> Mapping[str, Any] | None:
    """Serialize only named current publication values.

    This is deliberately a closed dispatch table.  In particular, an
    arbitrary object exposing a serializer-shaped attribute is not a
    publication input and must never get to execute that attribute.
    """

    if isinstance(value, RunIdentity):
        if type(value) is not RunIdentity:
            return None
        return RunIdentity.as_dict(value)
    if isinstance(value, RunLineage):
        if type(value) is not RunLineage:
            return None
        return RunLineage.as_dict(value)
    if isinstance(value, UsageSummary):
        if type(value) is not UsageSummary:
            return None
        return UsageSummary.as_dict(value)
    if isinstance(value, RunMetadata):
        if type(value) is not RunMetadata:
            return None
        if (
            type(value.identity) is not RunIdentity
            or type(value.lineage) is not RunLineage
            or (value.usage is not None and type(value.usage) is not UsageSummary)
        ):
            return None
        return RunMetadata.as_dict(value)
    if isinstance(value, SourceDocument):
        return SourceDocument.as_dict(value)
    if isinstance(value, LogicalArtifact):
        return LogicalArtifact.as_dict(value)
    if isinstance(value, PublicBundleComponent):
        return PublicBundleComponent.as_dict(value)
    if isinstance(value, PublicBundle):
        return PublicBundle.as_dict(value)
    if isinstance(value, PrivateOriginal):
        return PrivateOriginal.as_dict(value)
    if isinstance(value, FindingSummary):
        return FindingSummary.as_dict(value)
    if isinstance(value, PublicationSnapshot):
        return PublicationSnapshot.as_dict(value)
    if isinstance(value, Publishable):
        return Publishable.as_dict(value)
    if isinstance(value, RepairRequired):
        return RepairRequired.as_dict(value)
    if isinstance(value, FailClosed):
        return FailClosed.as_dict(value)
    if isinstance(value, AtifDocument):
        return AtifDocument.as_dict(value)
    if isinstance(value, SanitizationResult):
        return SanitizationResult.as_dict(value)
    if isinstance(value, UsageTokens):
        return UsageTokens.as_dict(value)
    if isinstance(value, UsageCosts):
        return UsageCosts.as_dict(value)
    if isinstance(value, UsageCoverage):
        return UsageCoverage.as_dict(value)
    if isinstance(value, PriceProvenance):
        return PriceProvenance.as_dict(value)
    if isinstance(value, UsageTurn):
        return UsageTurn.as_dict(value)
    if isinstance(value, UsageInvocation):
        return UsageInvocation.as_dict(value)
    if isinstance(value, UsageRun):
        return UsageRun.as_dict(value)
    if isinstance(value, TaskUsageSummary):
        return TaskUsageSummary.as_dict(value)
    if isinstance(value, TaskUsageDaily):
        return TaskUsageDaily.as_dict(value)
    if isinstance(value, TaskUsageLifetime):
        return TaskUsageLifetime.as_dict(value)
    if isinstance(value, UsageGenerationMetadata):
        return UsageGenerationMetadata.as_dict(value)
    if isinstance(value, TaskUsageProjection):
        return TaskUsageProjection.as_dict(value)
    if isinstance(value, GenerationObject):
        return GenerationObject.as_dict(value)
    if isinstance(value, GenerationOriginal):
        return GenerationOriginal.as_dict(value)
    if isinstance(value, PublicationGeneration):
        return PublicationGeneration.as_dict(value)
    if isinstance(value, PublicationCounts):
        return PublicationCounts.as_dict(value)
    return None


def _has_owned_content(value: object) -> bool:
    """Recognize the named byte-bearing values that must stay attached."""

    if isinstance(
        value,
        (
            StableRead,
            SourceDocument,
            PublicBundleComponent,
            PrivateOriginal,
            AtifDocument,
            GenerationObject,
            GenerationOriginal,
        ),
    ):
        return True
    if isinstance(value, SanitizationResult):
        return value.content is not None
    return False


def _preserve_owned_value(value: object) -> bool:
    return _has_owned_content(value) or isinstance(
        value,
        (LogicalArtifact, PublicationSnapshot, RunMetadata, Publishable, RepairRequired, FailClosed),
    )


def _freeze_graph(value: Any) -> Any:
    """Detach graph inputs before any builder or row composition runs."""

    if isinstance(value, AtifSource):
        try:
            return AtifSource(
                run=_freeze_graph(value.run),
                documents=_freeze_graph(value.documents),
                artifacts=tuple(_freeze_graph(item) for item in value.artifacts),
                # ATIF validates invocation telemetry as JSON-native lists;
                # keep the detached copy while restoring those container
                # types after the generic graph freeze.
                invocations=tuple(_thaw(_freeze_graph(item)) for item in value.invocations),
            )
        except (TypeError, ValueError, RecursionError):
            raise PublicationError(ReasonCode.invalid_metadata) from None
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_graph(item) for key, item in value.items()})
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, list):
        return tuple(_freeze_graph(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_graph(item) for item in value)
    if _preserve_owned_value(value):
        return value
    try:
        candidate = _known_public_mapping(value)
    except Exception:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if candidate is not None:
        return MappingProxyType({str(key): _freeze_graph(item) for key, item in candidate.items()})
    return value


def _graph_serial(value: Any, budget: list[int]) -> Any:
    """Create a bounded canonical representation for mutation authentication."""

    budget[0] += 1
    if budget[0] > MAX_GENERATION_GRAPH_NODES:
        raise PublicationError(ReasonCode.oversized)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (bytes, bytearray)):
        content = bytes(value)
        return {"__bytes__": hashlib.sha256(content).hexdigest(), "byteSize": len(content)}
    if isinstance(value, AtifSource):
        return {
            "__type__": "atif-source",
            "run": _graph_serial(value.run, budget),
            "documents": _graph_serial(value.documents, budget),
            "artifacts": _graph_serial(value.artifacts, budget),
            "invocations": _graph_serial(value.invocations, budget),
        }
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise PublicationError(ReasonCode.invalid_metadata)
            if key in result:
                raise PublicationError(ReasonCode.invalid_metadata)
            result[key] = _graph_serial(child, budget)
        return result
    if isinstance(value, (list, tuple)):
        return [_graph_serial(item, budget) for item in value]
    try:
        candidate = _known_public_mapping(value)
    except Exception:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if candidate is not None:
        return {"__type__": type(value).__name__, "value": _graph_serial(candidate, budget)}
    if isinstance(
        value,
        (
            StableRead,
            SourceDocument,
            PublicBundleComponent,
            PrivateOriginal,
            AtifDocument,
            GenerationObject,
            GenerationOriginal,
        ),
    ):
        content = value.content
        return {
            "__type__": type(value).__name__,
            "content": _graph_serial(content, budget),
            "byteSize": len(content),
        }
    raise PublicationError(ReasonCode.invalid_metadata)


def _graph_fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical(_graph_serial(value, [0]))).hexdigest()


def _capture_stable_graph(value: object) -> tuple[Any, str]:
    """Capture and authenticate a bounded number of detached graph views."""

    captures: list[Any] = []
    fingerprints: list[str] = []
    for _ in range(MAX_GRAPH_CAPTURE_PASSES):
        detached = _freeze_graph(value)
        captures.append(detached)
        fingerprints.append(_graph_fingerprint(detached))
    if len(set(fingerprints)) != 1:
        raise PublicationError(ReasonCode.changing)
    return captures[0], fingerprints[0]


def _failure(code: ReasonCode) -> FailClosed:
    """Return a bounded failure without retaining source diagnostics."""

    try:
        reason = ReasonCode(code)
    except (TypeError, ValueError):
        reason = ReasonCode.invalid_metadata
    return FailClosed((reason,))


def _unique_reasons(values: Sequence[ReasonCode | str]) -> tuple[ReasonCode, ...]:
    result: list[ReasonCode] = []
    for value in values:
        try:
            reason = ReasonCode(value)
        except (TypeError, ValueError):
            reason = ReasonCode.invalid_metadata
        if reason not in result:
            result.append(reason)
    return tuple(result)


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise PublicationError(ReasonCode.invalid_metadata) from None


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _mapping(value: object) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            return None
        return value
    try:
        candidate = _known_public_mapping(value)
    except Exception:
        return None
    return candidate if isinstance(candidate, Mapping) else None


def _id(value: object) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise PublicationError(ReasonCode.invalid_identifier)
    return value


def _timestamp(value: object) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise PublicationError(ReasonCode.invalid_metadata)
        return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise PublicationError(ReasonCode.invalid_metadata)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PublicationError(ReasonCode.invalid_metadata)
    return value


def _timestamp_value(value: object) -> datetime:
    return datetime.fromisoformat(_timestamp(value).replace("Z", "+00:00"))


def _text(value: object, *, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value):
        raise PublicationError(ReasonCode.invalid_metadata)
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PublicationError(ReasonCode.invalid_metadata)
    return value


def _state(value: object) -> str:
    if not isinstance(value, str):
        raise PublicationError(ReasonCode.invalid_metadata)
    normalized = value.casefold()
    if normalized in {"running", "queued", "pending", "started", "in_progress", "in-progress"}:
        return "running"
    if normalized in {"cancelled", "canceled"}:
        return "cancelled"
    if normalized in {"failed", "blocked", "interrupted", "error"}:
        return "failed"
    if normalized in {"completed", "succeeded", "success", "pushed", "no_changes", "no-changes"}:
        return "completed"
    raise PublicationError(ReasonCode.invalid_metadata)


def _raw_state(value: object) -> object:
    mapping = _mapping(value)
    if mapping is None:
        return _MISSING
    for key in ("state", "runState", "run_state", "status"):
        if key in mapping:
            return mapping[key]
    return _MISSING


def _source_from_entry(entry: object) -> object:
    if isinstance(entry, (Publishable, RepairRequired, FailClosed, PublicationSnapshot, AtifSource)):
        return entry
    mapping = _mapping(entry)
    if mapping is None:
        return entry
    for key in ("outcome", "bundle", "publication", "completedRun", "completed_run", "snapshot", "source", "input"):
        value = mapping.get(key, _MISSING)
        if value is not _MISSING and value is not None:
            return value
    return entry


def _run_mapping(value: object) -> Mapping[str, Any] | None:
    if isinstance(value, Publishable):
        return _run_mapping(value.snapshot.run)
    if isinstance(value, PublicationSnapshot):
        return _run_mapping(value.run)
    if isinstance(value, AtifSource):
        return _run_mapping(value.run)
    if isinstance(value, RunMetadata):
        return _known_public_mapping(value)
    mapping = _mapping(value)
    if mapping is None:
        return None
    for key in ("run", "runMetadata", "run_metadata", "metadata"):
        nested = mapping.get(key)
        if nested is not None and nested is not value:
            candidate = _run_mapping(nested)
            if candidate is not None:
                return candidate
    return mapping


def _preflight(entry: object) -> ReasonCode | None:
    """Reject unstable graph evidence before invoking the run builder."""

    mapping = _mapping(entry)
    if mapping is not None:
        # A graph descriptor is authoritative for lifecycle state even when
        # its nested source is an immutable AtifSource/PublicationSnapshot.
        wrapper_state = _raw_state(mapping)
        if wrapper_state is not _MISSING:
            try:
                if _state(wrapper_state) == "running":
                    return ReasonCode.running
            except PublicationError:
                return ReasonCode.invalid_metadata
        for key in ("mutating", "mutation", "changing", "changed", "unstable"):
            if mapping.get(key) is True:
                return ReasonCode.changing
        if mapping.get("stable") is False or mapping.get("isStable") is False:
            return ReasonCode.changing
        for before_key, after_key in (
            ("beforeIdentity", "afterIdentity"),
            ("before_identity", "after_identity"),
            ("beforeGeneration", "afterGeneration"),
            ("before_generation", "after_generation"),
            ("initialIdentity", "finalIdentity"),
        ):
            if before_key in mapping and after_key in mapping and mapping[before_key] != mapping[after_key]:
                return ReasonCode.changing
        nested_pipeline = _mapping(mapping.get("pipeline"))
        nested_run = _run_mapping(_source_from_entry(entry))
        if nested_run is not None:
            for field, aliases in (
                ("taskId", ("taskId", "task_id")),
                ("pipelineId", ("pipelineId", "pipeline_id")),
                ("runId", ("runId", "run_id")),
            ):
                declared = next((mapping[key] for key in aliases if key in mapping), _MISSING)
                observed = next((nested_run[key] for key in aliases if key in nested_run), _MISSING)
                if declared is not _MISSING and observed is not _MISSING and declared != observed:
                    return ReasonCode.invalid_metadata
        if nested_pipeline is not None and nested_run is not None:
            pipeline_id = nested_pipeline.get("pipelineId", nested_pipeline.get("pipeline_id", nested_pipeline.get("id")))
            nested_pipeline_task = nested_pipeline.get("taskId", nested_pipeline.get("task_id"))
            if pipeline_id is not None and nested_run.get("pipelineId", nested_run.get("pipeline_id")) != pipeline_id:
                return ReasonCode.invalid_metadata
            if nested_pipeline_task is not None and nested_run.get("taskId", nested_run.get("task_id")) != nested_pipeline_task:
                return ReasonCode.invalid_metadata
        for owner in ("task", "pipeline"):
            owner_mapping = _mapping(mapping.get(owner))
            if owner_mapping is None or nested_run is None:
                continue
            owner_task = owner_mapping.get("taskId", owner_mapping.get("task_id"))
            if owner_task is not None and nested_run.get("taskId", nested_run.get("task_id")) != owner_task:
                return ReasonCode.invalid_metadata
        if any(mapping.get(key) is False for key in ("complete", "completed", "materialized", "fullyMaterialized", "fully_materialized")):
            return ReasonCode.partial
        for key in ("unknownFiles", "unknown_files", "uncoveredFiles", "uncovered_files", "uncovered"):
            value = mapping.get(key)
            if value not in (None, False, (), [], {}, ""):
                return ReasonCode.partial
    run = _run_mapping(_source_from_entry(entry))
    if run is not None:
        raw = _raw_state(run)
        if raw is not _MISSING:
            try:
                if _state(raw) == "running":
                    return ReasonCode.running
            except PublicationError:
                return ReasonCode.invalid_metadata
    return None


def _builder_kwargs(
    *,
    credential_sources: object,
    known_secrets: Sequence[str] | str | None,
    staging_root: Path | None,
    scanner_runner: Any,
    scanner_timeout: float,
    max_repair_passes: int,
    ocr_runner: Any,
    ocr_timeout: float,
) -> dict[str, Any]:
    return {
        "credential_sources": credential_sources,
        "known_secrets": known_secrets,
        "staging_root": staging_root,
        "scanner_runner": scanner_runner,
        "scanner_timeout": scanner_timeout,
        "max_repair_passes": max_repair_passes,
        "ocr_runner": ocr_runner,
        "ocr_timeout": ocr_timeout,
    }


def _invoke_builder(
    entry: object,
    *,
    builder: PublicationBuilder,
    kwargs: Mapping[str, Any],
) -> PublicationOutcome:
    if isinstance(entry, (Publishable, RepairRequired, FailClosed)):
        return entry
    mapping = _mapping(entry)
    source = _source_from_entry(entry)
    if source is not entry and isinstance(source, (Publishable, RepairRequired, FailClosed)):
        return source
    selected_kwargs = dict(kwargs)
    if mapping is not None:
        extra = mapping.get("builder_kwargs")
        if isinstance(extra, Mapping):
            # Caller-provided stage options are still bounded by the explicit
            # generation API; transport and staging options are never copied.
            for key in selected_kwargs:
                if key != "staging_root" and key in extra:
                    selected_kwargs[key] = extra[key]
    selected_builder = builder if isinstance(builder, PublicationBuilder) else PublicationBuilder(builder)
    try:
        result = selected_builder(source, **selected_kwargs)
    except PublicationError as error:
        return _failure(error.code)
    except (MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    except Exception:
        return _failure(ReasonCode.invalid_metadata)
    if isinstance(result, (Publishable, RepairRequired, FailClosed)):
        return result
    return _failure(ReasonCode.invalid_metadata)


def _findings(value: object) -> tuple[FindingSummary, ...]:
    findings = getattr(value, "findings", ())
    return tuple(item for item in findings if isinstance(item, FindingSummary))


def _combine_outcomes(outcomes: Sequence[PublicationOutcome], preflight: Sequence[ReasonCode]) -> PublicationOutcome | None:
    failures: list[ReasonCode] = list(preflight)
    repairs: list[ReasonCode] = []
    findings: list[FindingSummary] = []
    saw_fail = bool(preflight)
    for outcome in outcomes:
        if isinstance(outcome, FailClosed):
            saw_fail = True
            failures.extend(outcome.reason_codes)
            findings.extend(_findings(outcome))
        elif isinstance(outcome, RepairRequired):
            repairs.extend(outcome.reason_codes)
            findings.extend(_findings(outcome))
    if saw_fail:
        reasons = _unique_reasons(failures)
        # FailClosed deliberately cannot contain a repair-only reason.
        reasons = tuple(reason for reason in reasons if reason not in {ReasonCode.source_finding, ReasonCode.patch_finding})
        if not reasons:
            reasons = (ReasonCode.invalid_metadata,)
        valid_findings = tuple(item for item in findings if item.code not in {ReasonCode.source_finding, ReasonCode.patch_finding})
        try:
            return FailClosed(reasons, valid_findings)
        except PublicationError:
            return _failure(ReasonCode.invalid_metadata)
    if repairs:
        reasons = _unique_reasons(repairs)
        valid_findings = tuple(item for item in findings if item.code in {ReasonCode.source_finding, ReasonCode.patch_finding})
        try:
            return RepairRequired(reasons, valid_findings)
        except PublicationError:
            return _failure(ReasonCode.invalid_metadata)
    return None


@dataclass(frozen=True, slots=True)
class GenerationObject:
    """One exact public object descriptor and its inspected bytes."""

    artifact_id: str
    task_id: str
    run_id: str
    logical_path: str
    public_key: str
    media_type: str
    content: bytes = field(repr=False)
    byte_size: int = field(init=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _id(self.artifact_id))
        object.__setattr__(self, "task_id", _id(self.task_id))
        object.__setattr__(self, "run_id", _id(self.run_id))
        if not isinstance(self.logical_path, str) or not self.logical_path or self.logical_path.startswith("/") or ".." in self.logical_path or "\\" in self.logical_path or "://" in self.logical_path:
            raise PublicationError(ReasonCode.invalid_path)
        object.__setattr__(self, "media_type", _text(self.media_type, maximum=128))
        if not isinstance(self.content, bytes):
            raise PublicationError(ReasonCode.invalid_metadata)
        object.__setattr__(self, "byte_size", len(self.content))
        object.__setattr__(self, "sha256", hashlib.sha256(self.content).hexdigest())
        expected_key = f"v1/tasks/{self.task_id}/objects/sha256/{self.sha256[:2]}/{self.sha256}"
        if self.public_key != expected_key:
            raise PublicationError(ReasonCode.invalid_metadata)

    @property
    def bytes(self) -> bytes:
        return self.content

    @property
    def body(self) -> bytes:
        return self.content

    @property
    def key(self) -> str:
        return self.public_key

    @property
    def object_key(self) -> str:
        return self.public_key

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifactId": self.artifact_id,
            "publicKey": self.public_key,
            "mediaType": self.media_type,
            "sha256": self.sha256,
            "byteSize": self.byte_size,
        }


@dataclass(frozen=True, slots=True)
class GenerationOriginal:
    """Private original bytes retained for a redacted run."""

    task_id: str
    run_id: str
    content: bytes = field(repr=False)
    byte_size: int = field(init=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _id(self.task_id))
        object.__setattr__(self, "run_id", _id(self.run_id))
        if not isinstance(self.content, bytes):
            raise PublicationError(ReasonCode.invalid_metadata)
        object.__setattr__(self, "byte_size", len(self.content))
        object.__setattr__(self, "sha256", hashlib.sha256(self.content).hexdigest())

    @property
    def bytes(self) -> bytes:
        return self.content

    def as_dict(self) -> dict[str, Any]:
        return {"taskId": self.task_id, "runId": self.run_id, "byteSize": self.byte_size, "sha256": self.sha256}


def _generation_boundary_from_payload(value: Mapping[str, Any]) -> str:
    """Recreate the canonical task-graph seed without exposing it publicly."""

    payload = _thaw(value)
    try:
        seed_metadata = {
            "taskId": payload["taskId"],
            "task": payload["task"],
            "pipelines": payload["pipelines"],
            "runs": payload["runs"],
            "events": payload["events"],
            "artifacts": payload["artifacts"],
        }
    except (KeyError, TypeError):
        raise PublicationError(ReasonCode.invalid_metadata) from None
    return hashlib.sha256(_canonical(seed_metadata)).hexdigest()


@dataclass(frozen=True, slots=True)
class PublicationGeneration:
    """Immutable generation envelope plus detached public/private bytes."""

    payload: Mapping[str, Any]
    objects: tuple[GenerationObject, ...] = ()
    private_originals: tuple[GenerationOriginal, ...] = ()
    status: str = field(init=False, default="publishable")
    _generation_boundary: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping):
            raise PublicationError(ReasonCode.invalid_metadata)
        objects = tuple(self.objects)
        originals = tuple(self.private_originals)
        if len(objects) > MAX_GENERATION_OBJECTS or any(not isinstance(item, GenerationObject) for item in objects):
            raise PublicationError(ReasonCode.invalid_metadata)
        if len(originals) > MAX_GENERATION_RUNS or any(not isinstance(item, GenerationOriginal) for item in originals):
            raise PublicationError(ReasonCode.invalid_metadata)
        boundary = _generation_boundary_from_payload(self.payload)
        try:
            task_value = self.payload["taskId"]
            if not isinstance(task_value, str):
                raise PublicationError(ReasonCode.invalid_metadata)
            identity = GenerationIdentity(task_value, boundary)
            generation = self.payload["generation"]
            if not isinstance(generation, Mapping):
                raise PublicationError(ReasonCode.invalid_metadata)
            if (
                self.payload.get("publicationId") != identity.publication_id
                or generation.get("publicationId") != identity.publication_id
                or generation.get("taskId") != identity.task_id
                or generation.get("idempotencyKey") != identity.idempotency_key
            ):
                raise PublicationError(ReasonCode.invalid_metadata)
        except (KeyError, TypeError, ValueError):
            raise PublicationError(ReasonCode.invalid_metadata) from None
        object.__setattr__(self, "_generation_boundary", boundary)
        object.__setattr__(self, "payload", _freeze(_thaw(self.payload)))
        object.__setattr__(self, "objects", objects)
        object.__setattr__(self, "private_originals", originals)

    @property
    def generation(self) -> Mapping[str, Any]:
        value = self.payload.get("generation")
        return value if isinstance(value, Mapping) else MappingProxyType({})

    @property
    def publication_id(self) -> str:
        return str(self.payload.get("publicationId", ""))

    @property
    def task_id(self) -> str:
        return str(self.payload.get("taskId", ""))

    @property
    def run_id(self) -> str:
        return str(self.generation.get("runId", ""))

    @property
    def metadata_digest(self) -> str:
        return str(self.generation.get("metadataDigest", ""))

    @property
    def idempotency_key(self) -> str:
        return str(self.generation.get("idempotencyKey", ""))

    @property
    def generation_boundary(self) -> str:
        """The canonical task-graph seed digest used by the outbox identity."""

        return self._generation_boundary

    @property
    def identity(self) -> GenerationIdentity:
        return GenerationIdentity(self.task_id, self.generation_boundary)

    @property
    def outbox_record(self) -> outbox.PublicationGeneration:
        """Return the exact durable outbox record represented by this envelope."""

        counts = self.generation.get("expectedCounts")
        if not isinstance(counts, Mapping):
            raise PublicationError(ReasonCode.invalid_metadata)
        try:
            count_values = {
                name: counts[name]
                for name in ("tasks", "pipelines", "runs", "events", "artifacts")
            }
        except KeyError:
            raise PublicationError(ReasonCode.invalid_metadata) from None
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in count_values.values()):
            raise PublicationError(ReasonCode.invalid_metadata)
        head_intent = self.payload.get("headIntent")
        if not isinstance(head_intent, Mapping):
            raise PublicationError(ReasonCode.invalid_metadata)
        return outbox.PublicationGeneration(
            publication_id=self.identity.publication_id,
            task_id=self.identity.task_id,
            run_id=self.run_id,
            generation_boundary=self.identity.generation_boundary,
            metadata_digest=self.metadata_digest,
            idempotency_key=self.identity.idempotency_key,
            rows=sum(count_values.values()),
            objects=len(self.objects) + len(self.private_originals),
            tasks=count_values["tasks"],
            pipelines=count_values["pipelines"],
            runs=count_values["runs"],
            events=count_values["events"],
            artifacts=count_values["artifacts"],
            created_at=_timestamp_value(self.generation.get("createdAt")),
            updated_at=_timestamp_value(head_intent.get("updatedAt")),
        )

    def to_outbox(self) -> outbox.PublicationGeneration:
        return self.outbox_record

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self.payload)


GenerationOutcome: TypeAlias = PublicationGeneration | RepairRequired | FailClosed


@dataclass(frozen=True, slots=True)
class PublicationBuilder:
    """One run-builder callback with the canonical stage contract."""

    callback: Any

    def __call__(
        self,
        source: object,
        *,
        credential_sources: object,
        known_secrets: Sequence[str] | str | None,
        scanner_runner: Any,
        scanner_timeout: float,
        max_repair_passes: int,
        ocr_runner: Any,
        ocr_timeout: float,
        staging_root: Path | None = None,
    ) -> PublicationOutcome:
        kwargs: dict[str, Any] = {
            "credential_sources": credential_sources,
            "known_secrets": known_secrets,
            "staging_root": staging_root,
            "scanner_runner": scanner_runner,
            "scanner_timeout": scanner_timeout,
            "max_repair_passes": max_repair_passes,
            "ocr_runner": ocr_runner,
            "ocr_timeout": ocr_timeout,
        }
        return self.callback(source, **kwargs)


@dataclass(frozen=True, slots=True)
class PublicationComposer:
    """One composer callback with the canonical composition contract."""

    callback: Any

    def __call__(
        self,
        source: object,
        *,
        task: object = None,
        completed_runs: object = None,
        task_id: str | None = None,
        run_builder: PublicationBuilder | None = None,
        builder: PublicationBuilder | None = None,
        credential_sources: object = None,
        known_secrets: Sequence[str] | str | None = None,
        staging_root: Path | None = None,
        scanner_runner: Any = None,
        scanner_timeout: float = 30.0,
        max_repair_passes: int = 2,
        ocr_runner: Any = None,
        ocr_timeout: float = 30.0,
        price_catalog: Any = None,
        generation_boundary: str | None = None,
        publication_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> GenerationOutcome:
        kwargs: dict[str, Any] = {
            "task": task,
            "completed_runs": completed_runs,
            "task_id": task_id,
            "run_builder": run_builder,
            "builder": builder,
            "credential_sources": credential_sources,
            "known_secrets": known_secrets,
            "scanner_runner": scanner_runner,
            "scanner_timeout": scanner_timeout,
            "max_repair_passes": max_repair_passes,
            "ocr_runner": ocr_runner,
            "ocr_timeout": ocr_timeout,
            "price_catalog": price_catalog,
            "generation_boundary": generation_boundary,
            "publication_id": publication_id,
            "idempotency_key": idempotency_key,
        }
        if staging_root is not None:
            kwargs["staging_root"] = staging_root
        return self.callback(source, **kwargs)

def _extract_items(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return [value]


_IDENTITY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "publicationId",
        "publication_id",
        "idempotencyKey",
        "idempotency_key",
        "generationBoundary",
        "generation_boundary",
    }
)


def _contains_identity_fields(value: object, *, budget: list[int]) -> bool:
    """Reject caller-provided identity material before composition."""

    budget[0] += 1
    if budget[0] > MAX_GENERATION_GRAPH_NODES:
        raise PublicationError(ReasonCode.oversized)
    if isinstance(value, Mapping):
        if any(key in _IDENTITY_FIELDS for key in value):
            return True
        return any(_contains_identity_fields(child, budget=budget) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_identity_fields(child, budget=budget) for child in value)
    if isinstance(value, AtifSource):
        return any(
            _contains_identity_fields(child, budget=budget)
            for child in (value.run, value.documents, value.artifacts)
        )
    try:
        candidate = _known_public_mapping(value)
    except Exception:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if candidate is not None:
        return _contains_identity_fields(candidate, budget=budget)
    return False


def _graph_parts(
    graph: object,
    *,
    task: object,
    pipelines: object,
    runs: object,
    events: object,
    completed_runs: object,
) -> tuple[object, list[object], list[object], list[object]]:
    top = _mapping(graph)
    if top is None:
        selected_task = task
        selected_runs = _extract_items(completed_runs if completed_runs is not None else (runs if runs is not None else graph))
        return selected_task, _extract_items(pipelines), selected_runs, _extract_items(events)

    selected_task = task if task is not None else top.get("task")
    if selected_task is None and any(key in top for key in ("taskId", "id", "title", "lifecycleState", "status")):
        selected_task = top
    selected_pipelines = _extract_items(pipelines if pipelines is not None else top.get("pipelines"))
    selected_events = _extract_items(events if events is not None else top.get("events", top.get("taskEvents")))
    selected_runs = _extract_items(
        completed_runs
        if completed_runs is not None
        else (runs if runs is not None else top.get("completedRuns", top.get("runSources", top.get("runs"))))
    )

    # A canonical archive view commonly nests run inputs under each pipeline.
    # Keep the pipeline metadata alongside each nested input without mutating
    # caller containers.
    nested: list[object] = []
    for pipeline in selected_pipelines:
        pipeline_mapping = _mapping(pipeline)
        if pipeline_mapping is None:
            continue
        nested_runs = pipeline_mapping.get("runs", pipeline_mapping.get("completedRuns"))
        if nested_runs is None:
            continue
        for run in _extract_items(nested_runs):
            nested.append({"source": run, "pipeline": pipeline})
    if nested and not selected_runs:
        selected_runs = nested
    elif nested:
        selected_runs.extend(nested)
    if not selected_runs and any(key in top for key in ("run", "snapshot", "source", "documents", "codex")):
        selected_runs = [graph]
    return selected_task, selected_pipelines, selected_runs, selected_events


def _task_row(value: object, *, task_id: str | None, run_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], str]:
    source = _mapping(value) or {}
    candidate_id = source.get("taskId", source.get("task_id", source.get("id", task_id)))
    if candidate_id is None and run_rows:
        candidate_id = run_rows[0].get("taskId")
    selected_id = _id(candidate_id)
    if task_id is not None and selected_id != task_id:
        raise PublicationError(ReasonCode.invalid_metadata)
    title = source.get("title", source.get("name", selected_id))
    title = _text(title, maximum=512)
    raw_lifecycle = source.get("lifecycleState", source.get("lifecycle_state", source.get("status", source.get("state", "completed"))))
    if not isinstance(raw_lifecycle, str):
        raise PublicationError(ReasonCode.invalid_metadata)
    lifecycle = raw_lifecycle.casefold()
    if lifecycle in {"running", "active", "queued", "pending", "in_progress", "in-progress"}:
        lifecycle = "active"
    elif lifecycle in {"succeeded", "completed", "pushed", "no_changes", "no-changes"}:
        lifecycle = "completed"
    elif lifecycle in {"failed", "blocked", "error", "interrupted"}:
        lifecycle = "failed"
    elif lifecycle in {"cancelled", "canceled"}:
        lifecycle = "cancelled"
    else:
        raise PublicationError(ReasonCode.invalid_metadata)
    started_values = [row.get("startedAt") for row in run_rows if row.get("startedAt") is not None]
    completed_values = [row.get("completedAt") for row in run_rows if row.get("completedAt") is not None]
    created_value = source.get("createdAt", source.get("created_at"))
    if created_value is None:
        created_value = min(started_values, key=_timestamp_value) if started_values else None
    if created_value is None:
        raise PublicationError(ReasonCode.invalid_metadata)
    created_at = _timestamp(created_value)
    completed_value = source.get("completedAt", source.get("completed_at"))
    if lifecycle == "active":
        completed_at = None
    else:
        if completed_value is None:
            completed_value = max(completed_values, key=_timestamp_value) if completed_values else None
        completed_at = _timestamp(completed_value) if completed_value is not None else None
        if completed_at is None:
            raise PublicationError(ReasonCode.invalid_metadata)
    return {
        "taskId": selected_id,
        "title": title,
        "lifecycleState": lifecycle,
        "createdAt": created_at,
        "completedAt": completed_at,
    }, selected_id


def _pipeline_row(value: object, *, task_id: str, run_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    source = _mapping(value) or {}
    pipeline_id = source.get("pipelineId", source.get("pipeline_id", source.get("id")))
    if pipeline_id is None and run_rows:
        pipeline_id = run_rows[0].get("pipelineId")
    pipeline_id = _id(pipeline_id)
    owner = source.get("taskId", source.get("task_id", task_id))
    if _id(owner) != task_id:
        raise PublicationError(ReasonCode.invalid_metadata)
    name = _text(source.get("name", source.get("pipelineName", pipeline_id)), maximum=256)
    created_value = source.get("createdAt", source.get("created_at", source.get("startedAt")))
    if created_value is None:
        values = [row.get("startedAt") for row in run_rows if row.get("startedAt") is not None]
        created_value = min(values, key=_timestamp_value) if values else None
    if created_value is None:
        raise PublicationError(ReasonCode.invalid_metadata)
    return {"pipelineId": pipeline_id, "taskId": task_id, "name": name, "createdAt": _timestamp(created_value)}


def _event_rows(value: Sequence[object], *, task_id: str, run_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not value:
        generated: list[dict[str, Any]] = []
        for row in run_rows:
            generated.extend(
                (
                    {
                        "taskId": task_id,
                        "sequence": 0,
                        "eventType": "run.started",
                        "occurredAt": row["startedAt"],
                        "summary": f"Run {row['runId']} started",
                    },
                    {
                        "taskId": task_id,
                        "sequence": 0,
                        "eventType": "run.completed",
                        "occurredAt": row["completedAt"],
                        "summary": f"Run {row['runId']} completed",
                    },
                )
            )
        generated.sort(key=lambda item: (_timestamp_value(item["occurredAt"]), item["eventType"], item["summary"]))
        for sequence, item in enumerate(generated, start=1):
            item["sequence"] = sequence
        return generated
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for event in value:
        source = _mapping(event)
        if source is None:
            raise PublicationError(ReasonCode.invalid_metadata)
        owner = source.get("taskId", source.get("task_id", task_id))
        if _id(owner) != task_id:
            raise PublicationError(ReasonCode.invalid_metadata)
        sequence = source.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1 or sequence in seen:
            raise PublicationError(ReasonCode.invalid_metadata)
        seen.add(sequence)
        event_type = source.get("eventType", source.get("event_type", source.get("kind", source.get("type"))))
        occurred = source.get("occurredAt", source.get("occurred_at", source.get("at", source.get("timestamp"))))
        summary = source.get("summary", source.get("message", event_type))
        rows.append(
            {
                "taskId": task_id,
                "sequence": sequence,
                "eventType": _text(event_type, maximum=128),
                "occurredAt": _timestamp(occurred),
                "summary": _text(summary, maximum=4096, allow_empty=True),
            }
        )
    rows.sort(key=lambda item: item["sequence"])
    if [item["sequence"] for item in rows] != list(range(1, len(rows) + 1)):
        raise PublicationError(ReasonCode.invalid_metadata)
    return rows


def _public_strings(value: object, result: list[str]) -> None:
    if isinstance(value, str):
        result.append(value)
        if len(result) > MAX_GENERATION_STRINGS:
            raise PublicationError(ReasonCode.oversized)
        return
    if isinstance(value, Mapping):
        for child in value.values():
            _public_strings(child, result)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _public_strings(child, result)


def _inspect_public_strings(
    payload: Mapping[str, Any],
    *,
    credential_sources: object,
    known_secrets: Sequence[str] | str | None,
    staging_root: Path | None,
    scanner_runner: Any,
    scanner_timeout: float,
) -> ReasonCode | None:
    """Apply the run builder's credential and scanner policy to D1 strings."""

    try:
        if isinstance(known_secrets, str):
            supplied = (known_secrets,)
        elif known_secrets is None:
            supplied = ()
        else:
            supplied = tuple(known_secrets)
        if any(not isinstance(value, str) for value in supplied):
            return ReasonCode.invalid_metadata
        discovered = discover_secrets(credential_sources) if credential_sources is not None else ()
        secrets = tuple(sorted(set((*discovered, *supplied)), key=lambda item: (-len(item.encode("utf-8")), item)))
    except (PublicationError, MemoryError, OSError, TypeError, ValueError, UnicodeError, RecursionError) as error:
        return error.code if isinstance(error, PublicationError) else ReasonCode.unsafe_content

    values: list[str] = []
    try:
        _public_strings(payload, values)
    except PublicationError as error:
        return error.code
    encoded_values = tuple(value.encode("utf-8") for value in values)
    if any(any(secret.encode("utf-8") in content for secret in secrets) for content in encoded_values):
        return ReasonCode.unsafe_content

    # ``inspect_media`` proves UTF-8/text identity and validates the same
    # credential inputs as Plan 026.  Text inspection intentionally does not
    # retain bytes or scanner records, so a separate bounded corpus scan below
    # supplies the scanner evidence for every public string.
    for content in encoded_values:
        inspection = inspect_media(
            content,
            "text/plain",
            known_secrets=secrets,
            staging_root=staging_root,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
        )
        if not inspection.approved:
            return inspection.reason or ReasonCode.unsafe_content

    entries = tuple(
        CorpusEntry(f"generation-string-{index:05d}.txt", content, "text")
        for index, content in enumerate(encoded_values)
    )
    report = run_trufflehog(
        entries,
        staging_root=staging_root,
        timeout=scanner_timeout,
        runner=scanner_runner,
    )
    if report.failure is not None or report.returncode != 0:
        return ReasonCode.scanner_failure
    if report.findings:
        return ReasonCode.unsafe_content
    return None


def _component_items(snapshot: PublicationSnapshot, *, task_id: str, run_id: str) -> list[tuple[Any, bytes]]:
    if not snapshot.public_bundle.inspected:
        raise PublicationError(ReasonCode.unsafe_content)
    values: list[tuple[Any, bytes]] = []
    for component in snapshot.public_bundle.components:
        if not component.inspected:
            raise PublicationError(ReasonCode.unsafe_content)
        values.append((component, component.content))
    if not values:
        raise PublicationError(ReasonCode.partial)
    return values


_USAGE_TOKEN_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("promptTokens", "input_tokens"),
    ("cachedTokens", "cached_input_tokens"),
    ("uncachedTokens", "uncached_input_tokens"),
    ("completionTokens", "output_tokens"),
    ("reasoningTokens", "reasoning_output_tokens"),
    ("totalTokens", "total_tokens"),
)
_USAGE_COST_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("uncachedInputCostMicroUsd", "uncached_input_micro_usd"),
    ("cachedInputCostMicroUsd", "cached_input_micro_usd"),
    ("outputCostMicroUsd", "output_micro_usd"),
    ("totalCostMicroUsd", "total_micro_usd"),
)


def _usage_trajectory(snapshot: PublicationSnapshot) -> Mapping[str, Any]:
    """Read the already inspected, canonical ATIF evidence for one run."""

    documents = [
        item
        for item in snapshot.documents
        if item.logical_path.rsplit("/", 1)[-1] == "trajectory.json"
    ]
    if len(documents) != 1:
        raise PublicationError(ReasonCode.invalid_metadata)
    try:
        value = json.loads(documents[0].content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if not isinstance(value, Mapping):
        raise PublicationError(ReasonCode.invalid_metadata)
    return value


def _usage_witnesses(
    evidence: Sequence[Mapping[str, Any]],
) -> tuple[dict[tuple[str, int], int], dict[tuple[str, int], str | None]]:
    counts: dict[tuple[str, int], int] = {}
    billing_modes: dict[tuple[str, int], str | None] = {}
    for document in evidence:
        extra = document.get("extra")
        coquic = extra.get("coquic") if isinstance(extra, Mapping) else None
        source = coquic.get("source") if isinstance(coquic, Mapping) else None
        invocations = source.get("invocations") if isinstance(source, Mapping) else None
        if not isinstance(invocations, Sequence) or isinstance(invocations, (str, bytes)):
            continue
        for invocation in invocations:
            if not isinstance(invocation, Mapping):
                continue
            run_id = invocation.get("runId")
            retry = invocation.get("retryOrdinal")
            if not isinstance(run_id, str) or isinstance(retry, bool) or not isinstance(retry, int) or retry < 0:
                continue
            key = (run_id, retry)
            billing_mode = invocation.get("billingMode")
            if billing_mode is None or billing_mode in {"unknown", "chatgpt", "api"}:
                billing_modes[key] = billing_mode
            issues = invocation.get("issues")
            total = 0
            if isinstance(issues, Sequence) and not isinstance(issues, (str, bytes)):
                for issue in issues:
                    if isinstance(issue, Mapping) and isinstance(issue.get("count"), int) and not isinstance(issue.get("count"), bool) and issue["count"] >= 0:
                        total += issue["count"]
            counts[key] = total
    return counts, billing_modes


def _usage_status(value: object) -> str:
    if value == "Complete":
        return "complete"
    if value == "Partial":
        return "partial"
    if value == "N.A.":
        return "unavailable"
    raise PublicationError(ReasonCode.invalid_metadata)


def _usage_tokens(value: object) -> dict[str, int | None]:
    try:
        return {public: getattr(value, private) for public, private in _USAGE_TOKEN_FIELDS}
    except (AttributeError, TypeError):
        raise PublicationError(ReasonCode.invalid_metadata) from None


def _usage_costs(value: object) -> dict[str, int | None]:
    try:
        return {public: getattr(value, private) for public, private in _USAGE_COST_FIELDS}
    except (AttributeError, TypeError):
        raise PublicationError(ReasonCode.invalid_metadata) from None


def _usage_price_digest(value: object | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, PriceProvenance):
        raise PublicationError(ReasonCode.invalid_metadata)
    try:
        return hashlib.sha256(_canonical(PriceProvenance.as_dict(value))).hexdigest()
    except (PublicationError, TypeError, ValueError, RecursionError):
        raise PublicationError(ReasonCode.invalid_metadata) from None


def _usage_price_row(value: object, usage_generation_id: str) -> dict[str, Any]:
    try:
        entry_digest = _usage_price_digest(value)
        model = value.model
        effective_from = value.effective_from
        effective_until = value.effective_until
        catalog_digest = value.catalog_digest
    except AttributeError:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if entry_digest is None:
        raise PublicationError(ReasonCode.invalid_metadata)
    return {
        "priceEntryDigest": entry_digest,
        "usageGenerationId": usage_generation_id,
        "catalogDigest": catalog_digest,
        "model": model,
        "effectiveAt": _timestamp(effective_from),
        "effectiveUntil": _timestamp(effective_until) if effective_until is not None else None,
    }


def _usage_shared_price_digest(values: Sequence[object]) -> str | None:
    digests = {_usage_price_digest(getattr(value, "price", None)) for value in values}
    digests.discard(None)
    return next(iter(digests)) if len(digests) == 1 else None


def _usage_summary_row(
    *,
    summary_id: str,
    usage_generation_id: str,
    publication_id: str,
    task_id: str,
    run_id: str | None,
    values: Sequence[object],
    summary: object,
) -> dict[str, Any]:
    try:
        tokens = summary.tokens
        costs = summary.cost
        coverage = summary.coverage
    except AttributeError:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    token_values = _usage_tokens(tokens)
    cost_values = _usage_costs(costs)
    covered_invocations = coverage.covered_invocations
    expected_invocations = coverage.expected_invocations
    if expected_invocations != len(values) or covered_invocations > expected_invocations:
        raise PublicationError(ReasonCode.invalid_metadata)
    return {
        "summaryId": summary_id,
        "usageGenerationId": usage_generation_id,
        "publicationId": publication_id,
        "taskId": task_id,
        "runId": run_id,
        "scope": "task" if run_id is None else "run",
        "coverage": _usage_status(coverage.status),
        "coveredInvocations": covered_invocations,
        "expectedInvocations": expected_invocations,
        "knownTokenSubtotal": token_values["totalTokens"],
        "knownCostSubtotalMicroUsd": cost_values["totalCostMicroUsd"],
        **token_values,
        **cost_values,
        "priceProvenanceDigest": _usage_shared_price_digest(values),
    }


def _usage_global_row(
    *,
    row: object,
    period_kind: str,
    period_key: str,
    usage_generation_id: str,
    matching_invocations: Sequence[object],
) -> dict[str, Any]:
    try:
        tokens = row.tokens
        costs = row.cost
        coverage = row.coverage
        model = row.model or "unknown"
    except AttributeError:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    token_values = _usage_tokens(tokens)
    cost_values = _usage_costs(costs)
    global_id = _usage_row_id("global", (usage_generation_id, period_kind, period_key, model, "task-owned"))
    return {
        "globalId": global_id,
        "usageGenerationId": usage_generation_id,
        "periodKind": period_kind,
        "periodKey": period_key,
        "model": model,
        "ownershipClass": "task-owned",
        "coverage": _usage_status(coverage.status),
        "coveredInvocations": coverage.covered_invocations,
        "expectedInvocations": coverage.expected_invocations,
        "knownTokenSubtotal": token_values["totalTokens"],
        "knownCostSubtotalMicroUsd": cost_values["totalCostMicroUsd"],
        **token_values,
        **cost_values,
        "priceProvenanceDigest": _usage_shared_price_digest(matching_invocations),
        "aggregateOnly": True,
    }


def _usage_row_id(prefix: str, identity: object) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(identity)).hexdigest()}"


def _usage_payload(
    projection: TaskUsageProjection,
    *,
    publication_id: str,
    task_id: str,
    run_rows: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    created_at: str,
) -> dict[str, Any]:
    """Flatten one typed projection into the closed D1 usage envelope."""

    if not isinstance(projection, TaskUsageProjection) or projection.task_id != task_id:
        raise PublicationError(ReasonCode.invalid_metadata)
    run_by_id = {row["runId"]: row for row in run_rows}
    projection_runs = {run.run_id: run for run in projection.runs}
    if set(run_by_id) != set(projection_runs):
        raise PublicationError(ReasonCode.invalid_metadata)
    usage_generation_id = projection.usage_generation_id
    issue_counts, billing_modes = _usage_witnesses(evidence)
    invocations = sorted(
        projection.invocations,
        key=lambda item: (item.run_id, item.retry_ordinal, item.invocation_id or ""),
    )
    invocation_ids: set[str] = set()
    invocation_rows: list[dict[str, Any]] = []
    for invocation in invocations:
        if invocation.task_id != task_id or invocation.run_id not in run_by_id:
            raise PublicationError(ReasonCode.invalid_metadata)
        if invocation.invocation_id is not None:
            if invocation.invocation_id in invocation_ids:
                raise PublicationError(ReasonCode.invalid_metadata)
            invocation_ids.add(invocation.invocation_id)
        token_values = _usage_tokens(invocation.tokens)
        cost_values = _usage_costs(invocation.cost)
        price_digest = _usage_price_digest(invocation.price)
        row = {
            "invocationId": invocation.invocation_id,
            "usageGenerationId": usage_generation_id,
            "publicationId": publication_id,
            "taskId": task_id,
            "pipelineId": invocation.pipeline_id,
            "runId": invocation.run_id,
            "ownershipClass": "task-owned",
            "retryOrdinal": invocation.retry_ordinal,
            "startedAt": _timestamp(invocation.started_at) if invocation.started_at is not None else None,
            "completedAt": _timestamp(invocation.completed_at) if invocation.completed_at is not None else None,
            "model": invocation.model,
            "billingMode": billing_modes.get((invocation.run_id, invocation.retry_ordinal)),
            "processOutcome": invocation.process_outcome,
            "coverage": _usage_status(invocation.coverage.status),
            "issueCount": issue_counts.get((invocation.run_id, invocation.retry_ordinal), 0),
            "coveredTurns": len(invocation.turns),
            "expectedTurns": len(invocation.turns),
            **token_values,
            **cost_values,
            "priceEntryDigest": price_digest,
        }
        invocation_rows.append(row)

    turns: list[dict[str, Any]] = []
    prices_by_digest: dict[str, dict[str, Any]] = {}
    for invocation in invocations:
        if invocation.price is not None:
            price_digest = _usage_price_digest(invocation.price)
            if price_digest is not None:
                prices_by_digest.setdefault(price_digest, _usage_price_row(invocation.price, usage_generation_id))
        if invocation.invocation_id is None:
            if invocation.turns:
                raise PublicationError(ReasonCode.invalid_metadata)
            continue
        for turn in sorted(invocation.turns, key=lambda item: item.turn_ordinal):
            if turn.invocation_id != invocation.invocation_id:
                raise PublicationError(ReasonCode.invalid_metadata)
            token_values = _usage_tokens(turn.tokens)
            cost_values = _usage_costs(turn.cost)
            price_digest = _usage_price_digest(turn.price)
            if turn.price is not None and price_digest is not None:
                prices_by_digest.setdefault(price_digest, _usage_price_row(turn.price, usage_generation_id))
            turns.append(
                {
                    "turnId": _usage_row_id(
                        "turn",
                        (usage_generation_id, turn.invocation_id, turn.retry_ordinal, turn.turn_ordinal),
                    ),
                    "usageGenerationId": usage_generation_id,
                    "invocationId": turn.invocation_id,
                    "publicationId": publication_id,
                    "taskId": task_id,
                    "runId": turn.run_id,
                    "ordinal": turn.turn_ordinal,
                    **token_values,
                    **cost_values,
                    "priceEntryDigest": price_digest,
                }
            )

    summaries: list[dict[str, Any]] = []
    summaries.append(
        _usage_summary_row(
            summary_id=_usage_row_id("summary", (usage_generation_id, "task")),
            usage_generation_id=usage_generation_id,
            publication_id=publication_id,
            task_id=task_id,
            run_id=None,
            values=invocations,
            summary=projection.summary,
        )
    )
    for run_id in sorted(projection_runs):
        run = projection_runs[run_id]
        run_invocations = tuple(run.invocations)
        summaries.append(
            _usage_summary_row(
                summary_id=_usage_row_id("summary", (usage_generation_id, "run", run_id)),
                usage_generation_id=usage_generation_id,
                publication_id=publication_id,
                task_id=task_id,
                run_id=run_id,
                values=run_invocations,
                summary=run,
            )
        )

    global_rows: list[dict[str, Any]] = []
    for row in projection.lifetime:
        model = row.model or "unknown"
        matching = tuple(item for item in invocations if (item.model or "unknown") == model)
        global_rows.append(
            _usage_global_row(
                row=row,
                period_kind="lifetime",
                period_key="lifetime",
                usage_generation_id=usage_generation_id,
                matching_invocations=matching,
            )
        )
    for row in projection.daily:
        model = row.model or "unknown"
        matching = tuple(
            item
            for item in invocations
            if (item.model or "unknown") == model
            and item.started_at is not None
            and item.started_at.astimezone(timezone.utc).date().isoformat() == row.date
        )
        global_rows.append(
            _usage_global_row(
                row=row,
                period_kind="daily",
                period_key=row.date,
                usage_generation_id=usage_generation_id,
                matching_invocations=matching,
            )
        )
    usage = {
        "schemaVersion": "1.0",
        "generation": {
            "usageGenerationId": usage_generation_id,
            "publicationId": publication_id,
            "taskId": task_id,
            "schemaVersion": projection.schema_version,
            "metadataDigest": "0" * 64,
            "state": "staged",
            "expectedCounts": {
                "summaries": len(summaries),
                "invocations": len(invocation_rows),
                "turns": len(turns),
                "prices": len(prices_by_digest),
                "globals": len(global_rows),
            },
            "createdAt": created_at,
        },
        "summaries": summaries,
        "invocations": invocation_rows,
        "turns": sorted(turns, key=lambda item: (item["invocationId"], item["ordinal"], item["turnId"])),
        "prices": [prices_by_digest[key] for key in sorted(prices_by_digest)],
        "globals": sorted(global_rows, key=lambda item: item["globalId"]),
    }
    usage["generation"]["metadataDigest"] = usage_metadata_digest(
        {"publicationId": publication_id, "taskId": task_id, "usage": usage}
    )
    return usage


def _build_generation(
    *,
    task_value: object,
    pipeline_values: Sequence[object],
    event_values: Sequence[object],
    run_entries: Sequence[object],
    explicit_task_id: str | None,
    builder: PublicationBuilder,
    builder_kwargs: Mapping[str, Any],
    mutation_watch: object,
    source_fingerprint: str,
    detached_view: object,
    detached_fingerprint: str,
    credential_sources: object,
    known_secrets: Sequence[str] | str | None,
    staging_root: Path | None,
    scanner_runner: Any,
    scanner_timeout: float,
    price_catalog: Any,
) -> GenerationOutcome:
    def source_changed() -> bool:
        try:
            return _graph_fingerprint(mutation_watch) != source_fingerprint
        except (PublicationError, MemoryError, OSError, TypeError, ValueError, RecursionError):
            return True

    def detached_changed() -> bool:
        try:
            return _graph_fingerprint(detached_view) != detached_fingerprint
        except (PublicationError, MemoryError, OSError, TypeError, ValueError, RecursionError):
            return True

    def changed() -> bool:
        return source_changed() or detached_changed()

    if changed():
        return _failure(ReasonCode.changing)
    if not run_entries or len(run_entries) > MAX_GENERATION_RUNS:
        return _failure(ReasonCode.partial)

    outcomes: list[PublicationOutcome] = []
    preflight: list[ReasonCode] = []
    for entry in run_entries:
        reason = _preflight(entry)
        if reason is not None:
            preflight.append(reason)
            continue
        outcomes.append(_invoke_builder(entry, builder=builder, kwargs=builder_kwargs))
    if changed():
        return _failure(ReasonCode.changing)
    combined = _combine_outcomes(outcomes, preflight)
    if combined is not None:
        return combined

    snapshots: list[PublicationSnapshot] = []
    for outcome in outcomes:
        if not isinstance(outcome, Publishable):
            return _failure(ReasonCode.invalid_metadata)
        snapshots.append(outcome.snapshot)
    if not snapshots:
        return _failure(ReasonCode.partial)
    snapshots.sort(key=lambda item: (item.run.identity.run_id, item.run.identity.pipeline_id))
    run_rows_for_task: list[dict[str, Any]] = []
    snapshot_by_run: dict[str, PublicationSnapshot] = {}
    for snapshot in snapshots:
        run = snapshot.run
        task_id = run.identity.task_id
        if explicit_task_id is not None and task_id != explicit_task_id:
            return _failure(ReasonCode.invalid_metadata)
        if run.identity.run_id in snapshot_by_run:
            return _failure(ReasonCode.changing)
        snapshot_by_run[run.identity.run_id] = snapshot
        run_rows_for_task.append(
            {
                "runId": run.identity.run_id,
                "taskId": task_id,
                "pipelineId": run.identity.pipeline_id,
                "role": _text(run.role, maximum=128),
                "runState": _state(run.state),
                "startedAt": _timestamp(run.started_at),
                "completedAt": _timestamp(run.completed_at),
                "durationMs": run.duration_ms,
            }
        )
    task_row, task_id = _task_row(task_value, task_id=explicit_task_id, run_rows=run_rows_for_task)
    if any(row["taskId"] != task_id for row in run_rows_for_task):
        return _failure(ReasonCode.invalid_metadata)

    # Keep only pipelines represented by an inspected completed run.  A
    # descriptor with no eligible run is not a publishable relationship.
    pipeline_by_id: dict[str, object] = {}
    for value in pipeline_values:
        source = _mapping(value)
        if source is None:
            return _failure(ReasonCode.invalid_metadata)
        pipeline_id = source.get("pipelineId", source.get("pipeline_id", source.get("id")))
        if pipeline_id is not None:
            try:
                pipeline_by_id[_id(pipeline_id)] = value
            except PublicationError:
                return _failure(ReasonCode.invalid_metadata)
    pipeline_rows: list[dict[str, Any]] = []
    for pipeline_id in sorted({row["pipelineId"] for row in run_rows_for_task}):
        source = pipeline_by_id.get(pipeline_id, {"pipelineId": pipeline_id, "taskId": task_id})
        related = [row for row in run_rows_for_task if row["pipelineId"] == pipeline_id]
        try:
            pipeline_rows.append(_pipeline_row(source, task_id=task_id, run_rows=related))
        except PublicationError as error:
            return _failure(error.code)

    try:
        event_rows = _event_rows(event_values, task_id=task_id, run_rows=run_rows_for_task)
    except PublicationError as error:
        return _failure(error.code)
    if not event_rows or len(event_rows) > MAX_GENERATION_EVENTS:
        return _failure(ReasonCode.partial)

    used_artifact_ids: set[str] = set()
    used_paths: set[str] = set()
    artifact_rows: list[dict[str, Any]] = []
    objects: list[GenerationObject] = []
    originals: list[GenerationOriginal] = []
    atif_ids: dict[str, str] = {}
    for snapshot in snapshots:
        run = snapshot.run
        run_id = run.identity.run_id
        components = _component_items(snapshot, task_id=task_id, run_id=run_id)
        trajectory_id: str | None = None
        for component, content in components:
            base_id = component.artifact.artifact_id
            artifact_id = base_id
            if artifact_id in used_artifact_ids:
                if component.artifact.logical_path.endswith("/trajectory.json"):
                    artifact_id = f"{base_id}-{run_id}"
                    suffix = 2
                    while artifact_id in used_artifact_ids:
                        artifact_id = f"{base_id}-{run_id}-{suffix}"
                        suffix += 1
                else:
                    # Renaming a source artifact would make the immutable ATIF
                    # descriptor disagree with its D1 row; fail closed instead.
                    return _failure(ReasonCode.invalid_metadata)
            used_artifact_ids.add(artifact_id)
            path = component.artifact.logical_path
            if path in used_paths:
                if path.endswith("/trajectory.json"):
                    path = f"runs/{run_id}/trajectory.json"
                else:
                    path = f"runs/{run_id}/{path}"
                if path in used_paths:
                    return _failure(ReasonCode.invalid_metadata)
            used_paths.add(path)
            public_key = f"v1/tasks/{task_id}/objects/sha256/{hashlib.sha256(content).hexdigest()[:2]}/{hashlib.sha256(content).hexdigest()}"
            try:
                object_value = GenerationObject(
                    artifact_id,
                    task_id,
                    run_id,
                    path,
                    public_key,
                    component.artifact.media_type,
                    content,
                )
            except PublicationError as error:
                return _failure(error.code)
            objects.append(object_value)
            artifact_rows.append(
                {
                    "artifactId": artifact_id,
                    "taskId": task_id,
                    "runId": run_id,
                    "logicalPath": path,
                    "publicKey": public_key,
                    "mediaType": component.artifact.media_type,
                    "byteSize": len(content),
                    "sha256": object_value.sha256,
                    "availability": "available",
                    "disclosure": {
                        "redactionApplied": component.redaction_applied,
                        "originalRetained": component.original_retained,
                    },
                }
            )
            if path.endswith("/trajectory.json"):
                trajectory_id = artifact_id
        if trajectory_id is None:
            return _failure(ReasonCode.partial)
        atif_ids[run_id] = trajectory_id
        private_original = snapshot.private_original
        if private_original is not None:
            try:
                originals.append(GenerationOriginal(task_id, run_id, private_original.content))
            except PublicationError as error:
                return _failure(error.code)

    if len(artifact_rows) == 0 or len(artifact_rows) > MAX_GENERATION_ARTIFACTS:
        return _failure(ReasonCode.partial)
    run_rows: list[dict[str, Any]] = []
    for row in run_rows_for_task:
        run_rows.append({**row, "atifDigest": next(item["sha256"] for item in artifact_rows if item["artifactId"] == atif_ids[row["runId"]]), "atifArtifactId": atif_ids[row["runId"]]})

    task_completed_values = [row["completedAt"] for row in run_rows]
    updated_value: object | None = (_mapping(task_value) or {}).get("updatedAt") if task_value is not None else None
    if updated_value is None:
        updated_at = max(task_completed_values, key=_timestamp_value)
    else:
        try:
            updated_at = _timestamp(updated_value)
        except PublicationError:
            return _failure(ReasonCode.invalid_metadata)
    latest_run = max(run_rows, key=lambda row: (_timestamp_value(row["completedAt"]), row["runId"]))

    try:
        usage_evidence = tuple(_usage_trajectory(snapshot) for snapshot in snapshots)
        usage_projection = build_task_usage_projection(
            usage_evidence,
            catalog=price_catalog,
            task_id=task_id,
        )
        if not isinstance(usage_projection, TaskUsageProjection):
            return _failure(ReasonCode.invalid_metadata)
    except (PublicationError, MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)

    seed_metadata = {
        "taskId": task_id,
        "task": task_row,
        "pipelines": sorted(pipeline_rows, key=lambda row: row["pipelineId"]),
        "runs": sorted(run_rows, key=lambda row: row["runId"]),
        "events": event_rows,
        "artifacts": sorted(artifact_rows, key=lambda row: (row["runId"], row["logicalPath"], row["artifactId"])),
    }
    seed = hashlib.sha256(_canonical(seed_metadata)).hexdigest()
    identity = GenerationIdentity(task_id, seed)
    publication_id = identity.publication_id
    idempotency_key = identity.idempotency_key
    try:
        usage_payload = _usage_payload(
            usage_projection,
            publication_id=publication_id,
            task_id=task_id,
            run_rows=run_rows,
            evidence=usage_evidence,
            created_at=task_row["createdAt"],
        )
    except (PublicationError, MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    payload: dict[str, Any] = {
        "schemaVersion": PUBLICATION_SCHEMA_VERSION,
        "publicationId": publication_id,
        "taskId": task_id,
        "generation": {
            "publicationId": publication_id,
            "taskId": task_id,
            "runId": latest_run["runId"],
            "metadataDigest": "0" * 64,
            "idempotencyKey": idempotency_key,
            "state": "staged",
            "expectedCounts": {
                "tasks": 1,
                "pipelines": len(pipeline_rows),
                "runs": len(run_rows),
                "events": len(event_rows),
                "artifacts": len(artifact_rows),
            },
            "createdAt": task_row["createdAt"],
        },
        "headIntent": {"publicationId": publication_id, "taskId": task_id, "state": "visible", "updatedAt": updated_at},
        "task": task_row,
        "pipelines": sorted(pipeline_rows, key=lambda row: row["pipelineId"]),
        "runs": sorted(run_rows, key=lambda row: row["runId"]),
        "events": event_rows,
        "artifacts": sorted(artifact_rows, key=lambda row: (row["runId"], row["logicalPath"], row["artifactId"])),
        "usage": usage_payload,
    }
    payload["generation"]["metadataDigest"] = publication_metadata_digest(payload)
    string_failure = _inspect_public_strings(
        payload,
        credential_sources=credential_sources,
        known_secrets=known_secrets,
        staging_root=staging_root,
        scanner_runner=scanner_runner,
        scanner_timeout=scanner_timeout,
    )
    if changed():
        return _failure(ReasonCode.changing)
    if string_failure is not None:
        return _failure(string_failure)
    try:
        validated = validate_publication_envelope(payload)
        # Validate detached rows against exact bytes too; this catches any
        # accidental divergence before handing the envelope to transport.
        if validated != payload:
            payload = validated
    except (EnvelopeError, PublicationError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    if changed():
        return _failure(ReasonCode.changing)
    try:
        return PublicationGeneration(payload, tuple(sorted(objects, key=lambda item: (item.run_id, item.logical_path, item.artifact_id))), tuple(sorted(originals, key=lambda item: (item.run_id, item.sha256))))
    except PublicationError as error:
        return _failure(error.code)


def compose_publication_generation(
    graph: object = None,
    pipelines: object = None,
    runs: object = None,
    events: object = None,
    *,
    task: object = None,
    completed_runs: object = None,
    task_id: str | None = None,
    run_builder: PublicationBuilder | None = None,
    builder: PublicationBuilder | None = None,
    credential_sources: object = None,
    known_secrets: Sequence[str] | str | None = None,
    staging_root: Path | None = None,
    scanner_runner: Any = None,
    scanner_timeout: float = 30.0,
    max_repair_passes: int = 2,
    ocr_runner: Any = None,
    ocr_timeout: float = 30.0,
    price_catalog: Any = None,
    generation_boundary: str | None = None,
    publication_id: str | None = None,
    idempotency_key: str | None = None,
) -> GenerationOutcome:
    """Compose one validated generation from a stable task graph.

    ``graph`` may be a mapping containing ``task``, ``pipelines``, ``runs``
    and ``events`` or a single completed-run source.  Explicit keyword values
    override graph fields.  All outcomes are bounded and never expose source
    paths, scanner records, credentials, or private bytes in the D1 payload.
    """

    if any(value is not None for value in (generation_boundary, publication_id, idempotency_key)):
        return _failure(ReasonCode.invalid_metadata)
    if task_id is not None:
        try:
            task_id = _id(task_id)
        except PublicationError as error:
            return _failure(error.code)
    try:
        if isinstance(known_secrets, str) or known_secrets is None:
            selected_secrets = known_secrets
        else:
            selected_secrets = tuple(known_secrets)
        mutation_watch = (graph, task, pipelines, runs, events, completed_runs)
        source_fingerprint_before = _graph_fingerprint(mutation_watch)
        detached_watch, detached_fingerprint = _capture_stable_graph(mutation_watch)
        source_fingerprint_after = _graph_fingerprint(mutation_watch)
        if (
            detached_fingerprint != source_fingerprint_before
            or detached_fingerprint != source_fingerprint_after
        ):
            return _failure(ReasonCode.changing)
        if _contains_identity_fields(detached_watch, budget=[0]):
            return _failure(ReasonCode.invalid_metadata)
        (
            detached_graph,
            detached_task,
            detached_pipelines,
            detached_runs,
            detached_events,
            detached_completed_runs,
        ) = detached_watch
        selected_task, pipeline_values, run_entries, event_values = _graph_parts(
            detached_graph,
            task=detached_task,
            pipelines=detached_pipelines,
            runs=detached_runs,
            events=detached_events,
            completed_runs=detached_completed_runs,
        )
        frozen_task = _freeze_graph(selected_task)
        frozen_pipelines = tuple(_freeze_graph(value) for value in pipeline_values)
        frozen_runs = tuple(_freeze_graph(value) for value in run_entries)
        frozen_events = tuple(_freeze_graph(value) for value in event_values)
        detached_view = (frozen_task, frozen_pipelines, frozen_runs, frozen_events)
        detached_fingerprint = _graph_fingerprint(detached_view)
    except PublicationError as error:
        return _failure(error.code)
    except (MemoryError, OSError, TypeError, ValueError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    selected_builder = run_builder or builder or build_publication_bundle
    if not isinstance(selected_builder, PublicationBuilder):
        selected_builder = PublicationBuilder(selected_builder)
    kwargs = _builder_kwargs(
        credential_sources=credential_sources,
        known_secrets=selected_secrets,
        staging_root=staging_root,
        scanner_runner=scanner_runner,
        scanner_timeout=scanner_timeout,
        max_repair_passes=max_repair_passes,
        ocr_runner=ocr_runner,
        ocr_timeout=ocr_timeout,
    )
    try:
        return _build_generation(
            task_value=frozen_task,
            pipeline_values=frozen_pipelines,
            event_values=frozen_events,
            run_entries=frozen_runs,
            explicit_task_id=task_id,
            builder=selected_builder,
            builder_kwargs=kwargs,
            mutation_watch=mutation_watch,
            source_fingerprint=source_fingerprint_after,
            detached_view=detached_view,
            detached_fingerprint=detached_fingerprint,
            credential_sources=credential_sources,
            known_secrets=selected_secrets,
            staging_root=staging_root,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
            price_catalog=price_catalog,
        )
    except PublicationError as error:
        return _failure(error.code)
    except (MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    except Exception:
        return _failure(ReasonCode.invalid_metadata)


__all__ = [
    "PUBLICATION_SCHEMA_VERSION",
    "MAX_GENERATION_RUNS",
    "MAX_GENERATION_EVENTS",
    "MAX_GENERATION_ARTIFACTS",
    "MAX_GENERATION_OBJECTS",
    "MAX_GRAPH_CAPTURE_PASSES",
    "GenerationObject",
    "GenerationOriginal",
    "GenerationIdentity",
    "PublicationGeneration",
    "GenerationOutcome",
    "compose_publication_generation",
]

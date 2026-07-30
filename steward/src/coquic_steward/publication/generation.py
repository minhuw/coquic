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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Final, TypeAlias

from .d1 import D1Error, _validate_payload
from .atif import AtifSource
from .media import inspect_media
from .models import (
    FailClosed,
    FindingSummary,
    LogicalArtifact,
    PublicationError,
    PublicationOutcome,
    PublicationSnapshot,
    Publishable,
    ReasonCode,
    RepairRequired,
    RunMetadata,
)
from .pipeline import build_publication_bundle
from .redaction import discover_secrets
from .scanner import CorpusEntry, run_trufflehog


PUBLICATION_SCHEMA_VERSION: Final[str] = "1.0"
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


def _freeze_graph(value: Any) -> Any:
    """Detach graph inputs before any builder or row composition runs."""

    if isinstance(value, AtifSource):
        try:
            return AtifSource(
                run=_freeze_graph(value.run),
                documents=_freeze_graph(value.documents),
                artifacts=tuple(_freeze_graph(item) for item in value.artifacts),
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
    if isinstance(getattr(value, "content", _MISSING), (bytes, bytearray)):
        return value
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict) and not isinstance(value, (LogicalArtifact, PublicationSnapshot, RunMetadata, Publishable, RepairRequired, FailClosed)):
        try:
            candidate = as_dict()
        except Exception:
            raise PublicationError(ReasonCode.invalid_metadata) from None
        if isinstance(candidate, Mapping):
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
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        try:
            candidate = as_dict()
        except Exception:
            raise PublicationError(ReasonCode.invalid_metadata) from None
        return {"__type__": type(value).__name__, "value": _graph_serial(candidate, budget)}
    content = getattr(value, "content", _MISSING)
    if isinstance(content, (bytes, bytearray)):
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
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        try:
            candidate = as_dict()
        except Exception:
            return None
        return candidate if isinstance(candidate, Mapping) else None
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            candidate = model_dump(mode="json", by_alias=True)
        except Exception:
            return None
        return candidate if isinstance(candidate, Mapping) else None
    return None


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
        return value.snapshot.run.as_dict()
    if isinstance(value, PublicationSnapshot):
        return value.run.as_dict()
    if isinstance(value, AtifSource):
        return _run_mapping(value.run)
    if isinstance(value, RunMetadata):
        return value.as_dict()
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
    scanner_runner: Any,
    scanner_timeout: float,
    max_repair_passes: int,
    ocr_runner: Any,
    ocr_timeout: float,
    run_scanner: bool,
) -> dict[str, Any]:
    return {
        "credential_sources": credential_sources,
        "known_secrets": known_secrets,
        "scanner_runner": scanner_runner,
        "scanner_timeout": scanner_timeout,
        "max_repair_passes": max_repair_passes,
        "ocr_runner": ocr_runner,
        "ocr_timeout": ocr_timeout,
        "run_scanner": run_scanner,
    }


def _invoke_builder(
    entry: object,
    *,
    builder: Callable[..., PublicationOutcome],
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
                if key in extra:
                    selected_kwargs[key] = extra[key]
    try:
        result = builder(source, **selected_kwargs)
    except TypeError:
        # Small test doubles and callers that already captured policy may
        # expose only the source positional argument.  Retrying without stage
        # options does not broaden the boundary or retain any diagnostics.
        try:
            result = builder(source)
        except PublicationError as error:
            return _failure(error.code)
        except (MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
            return _failure(ReasonCode.invalid_metadata)
        except Exception:
            return _failure(ReasonCode.invalid_metadata)
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


@dataclass(frozen=True, slots=True)
class PublicationGeneration:
    """Immutable generation envelope plus detached public/private bytes."""

    payload: Mapping[str, Any]
    objects: tuple[GenerationObject, ...] = ()
    private_originals: tuple[GenerationOriginal, ...] = ()
    status: str = field(init=False, default="publishable")

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping):
            raise PublicationError(ReasonCode.invalid_metadata)
        objects = tuple(self.objects)
        originals = tuple(self.private_originals)
        if len(objects) > MAX_GENERATION_OBJECTS or any(not isinstance(item, GenerationObject) for item in objects):
            raise PublicationError(ReasonCode.invalid_metadata)
        if len(originals) > MAX_GENERATION_RUNS or any(not isinstance(item, GenerationOriginal) for item in originals):
            raise PublicationError(ReasonCode.invalid_metadata)
        object.__setattr__(self, "payload", _freeze(_thaw(self.payload)))
        object.__setattr__(self, "objects", objects)
        object.__setattr__(self, "private_originals", originals)

    @property
    def envelope(self) -> Mapping[str, Any]:
        return self.payload

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
    def publication(self) -> Mapping[str, Any]:
        return self.payload

    @property
    def snapshot(self) -> Mapping[str, Any]:
        """Compatibility spelling for consumers that call the envelope a snapshot."""

        return self.payload

    @property
    def components(self) -> tuple[GenerationObject, ...]:
        return self.objects

    @property
    def object_descriptors(self) -> tuple[GenerationObject, ...]:
        return self.objects

    @property
    def originals(self) -> tuple[GenerationOriginal, ...]:
        return self.private_originals

    @property
    def private_original(self) -> GenerationOriginal | None:
        return self.private_originals[0] if len(self.private_originals) == 1 else None

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


GenerationOutcome: TypeAlias = PublicationGeneration | RepairRequired | FailClosed
Generation = PublicationGeneration
ComposedGeneration = PublicationGeneration
PublicationGenerationResult = PublicationGeneration
PublishableGeneration = PublicationGeneration
TaskPublicationGeneration = PublicationGeneration
GenerationObjectDescriptor = GenerationObject
PrivateOriginalDescriptor = GenerationOriginal


def _extract_items(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return [value]


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
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
        )
        if not inspection.approved:
            return inspection.reason or ReasonCode.unsafe_content

    entries = tuple(
        CorpusEntry(f"generation-string-{index:05d}.txt", content, "text")
        for index, content in enumerate(encoded_values)
    )
    report = run_trufflehog(entries, timeout=scanner_timeout, runner=scanner_runner)
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


def _build_generation(
    *,
    task_value: object,
    pipeline_values: Sequence[object],
    event_values: Sequence[object],
    run_entries: Sequence[object],
    explicit_task_id: str | None,
    builder: Callable[..., PublicationOutcome],
    builder_kwargs: Mapping[str, Any],
    mutation_watch: object,
    source_fingerprint: str,
    detached_view: object,
    detached_fingerprint: str,
    credential_sources: object,
    known_secrets: Sequence[str] | str | None,
    scanner_runner: Any,
    scanner_timeout: float,
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

    seed_metadata = {
        "taskId": task_id,
        "task": task_row,
        "pipelines": sorted(pipeline_rows, key=lambda row: row["pipelineId"]),
        "runs": sorted(run_rows, key=lambda row: row["runId"]),
        "events": event_rows,
        "artifacts": sorted(artifact_rows, key=lambda row: (row["runId"], row["logicalPath"], row["artifactId"])),
    }
    seed = hashlib.sha256(_canonical(seed_metadata)).hexdigest()
    publication_id = f"publication-{seed}"
    idempotency_key = f"generation-{seed}"
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
    }
    metadata = {key: payload[key] for key in ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts")}
    payload["generation"]["metadataDigest"] = hashlib.sha256(_canonical(metadata)).hexdigest()
    string_failure = _inspect_public_strings(
        payload,
        credential_sources=credential_sources,
        known_secrets=known_secrets,
        scanner_runner=scanner_runner,
        scanner_timeout=scanner_timeout,
    )
    if changed():
        return _failure(ReasonCode.changing)
    if string_failure is not None:
        return _failure(string_failure)
    try:
        validated = _validate_payload(payload)
        # Validate detached rows against exact bytes too; this catches any
        # accidental divergence before handing the envelope to transport.
        if validated != payload:
            payload = validated
    except (D1Error, PublicationError, TypeError, ValueError, KeyError, RecursionError):
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
    run_builder: Callable[..., PublicationOutcome] | None = None,
    builder: Callable[..., PublicationOutcome] | None = None,
    credential_sources: object = None,
    known_secrets: Sequence[str] | str | None = None,
    scanner_runner: Any = None,
    scanner_timeout: float = 30.0,
    max_repair_passes: int = 2,
    ocr_runner: Any = None,
    ocr_timeout: float = 30.0,
    run_scanner: bool = True,
) -> GenerationOutcome:
    """Compose one validated generation from a stable task graph.

    ``graph`` may be a mapping containing ``task``, ``pipelines``, ``runs``
    and ``events`` or a single completed-run source.  Explicit keyword values
    override graph fields.  All outcomes are bounded and never expose source
    paths, scanner records, credentials, or private bytes in the D1 payload.
    """

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
        source_fingerprint = _graph_fingerprint(mutation_watch)
        detached_watch, _ = _capture_stable_graph(mutation_watch)
        if _graph_fingerprint(mutation_watch) != source_fingerprint:
            return _failure(ReasonCode.changing)
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
    kwargs = _builder_kwargs(
        credential_sources=credential_sources,
        known_secrets=selected_secrets,
        scanner_runner=scanner_runner,
        scanner_timeout=scanner_timeout,
        max_repair_passes=max_repair_passes,
        ocr_runner=ocr_runner,
        ocr_timeout=ocr_timeout,
        run_scanner=run_scanner,
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
            source_fingerprint=source_fingerprint,
            detached_view=detached_view,
            detached_fingerprint=detached_fingerprint,
            credential_sources=credential_sources,
            known_secrets=selected_secrets,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
        )
    except PublicationError as error:
        return _failure(error.code)
    except (MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    except Exception:
        return _failure(ReasonCode.invalid_metadata)


build_publication_generation = compose_publication_generation
build_generation = compose_publication_generation
compose_generation = compose_publication_generation
assemble_publication_generation = compose_publication_generation
assemble_generation = compose_publication_generation
build_task_generation = compose_publication_generation
compose_task_generation = compose_publication_generation
build_task_publication = compose_publication_generation


__all__ = [
    "PUBLICATION_SCHEMA_VERSION",
    "MAX_GENERATION_RUNS",
    "MAX_GENERATION_EVENTS",
    "MAX_GENERATION_ARTIFACTS",
    "MAX_GENERATION_OBJECTS",
    "MAX_GRAPH_CAPTURE_PASSES",
    "GenerationObject",
    "GenerationObjectDescriptor",
    "GenerationOriginal",
    "PrivateOriginalDescriptor",
    "PublicationGeneration",
    "PublicationGenerationResult",
    "PublishableGeneration",
    "TaskPublicationGeneration",
    "GenerationOutcome",
    "Generation",
    "ComposedGeneration",
    "compose_publication_generation",
    "build_publication_generation",
    "build_generation",
    "compose_generation",
    "assemble_publication_generation",
    "assemble_generation",
    "build_task_generation",
    "compose_task_generation",
    "build_task_publication",
]

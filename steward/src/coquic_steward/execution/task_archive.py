"""Crash-consistent writer for the public Steward 2.0 task archive.

The archive is intentionally a small, dependency-free boundary.  SQLite is the
operational source of truth; this module only materializes expected bytes and
refuses to guess when a visible byte disagrees with that expectation.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..core.models import (
    EffectEvidence,
    EffectResult,
    effect_evidence_identity,
    TaskPipeline,
    TaskRecord,
    TaskRun,
    TaskStatus,
    derive_effect_result,
)
from ..agents.telemetry import (
    TELEMETRY_MAX_SIDECAR_BYTES,
    TELEMETRY_MAX_TURNS,
    load_sidecar,
)

SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_COMPONENT_RE = SAFE_ID_RE
FORMAT_VERSION = "1.0"
POLICY = "post-steward-2.0"
TERMINAL_TASK_STATUSES = {
    TaskStatus.succeeded.value,
    TaskStatus.pushed.value,
    TaskStatus.no_changes.value,
    TaskStatus.blocked.value,
    TaskStatus.failed.value,
    TaskStatus.cancelled.value,
}
HIDDEN_PREFIXES = (".", "~")
TEMPORARY_RE = re.compile(r"^\.[A-Za-z0-9._-]+\.tmp-[A-Za-z0-9]+$")
PRIVATE_KEYS = {
    "providerSessionId",
    "provider_session_id",
    "privateHomePath",
    "private_home_path",
    "providerRunId",
    "provider_run_id",
    "privatePath",
    "private_path",
    "executionId",
    "execution_id",
    "checkpointId",
    "checkpoint_id",
    "archiveGeneration",
    "archive_generation",
    "auth",
    "credentials",
}
TASK_KEYS = {
    "taskId",
    "epochId",
    "status",
    "promptPath",
    "eventsPath",
    "createdAt",
    "updatedAt",
    "currentPipelineId",
    "summary",
    "pipelines",
    "terminalStatusObservedAt",
    "manifestPath",
}
PIPELINE_KEYS = {
    "pipelineId",
    "taskId",
    "ordinal",
    "trigger",
    "parentPipelineId",
    "phase",
    "state",
    "baseIdentity",
    "inputIdentity",
    "outputIdentity",
    "patchIdentity",
    "startedAt",
    "updatedAt",
    "completedAt",
    "inputs",
    "patches",
    "validations",
    "reviews",
    "integration",
    "runs",
}
RUN_KEYS = {
    "runId",
    "taskId",
    "pipelineId",
    "role",
    "roleOrdinal",
    "sessionId",
    "resumeOfRunId",
    "parentRunId",
    "retryOfRunId",
    "state",
    "startedAt",
    "updatedAt",
    "completedAt",
    "model",
    "reasoning",
    "exit",
    "result",
    "usage",
    "cost",
    "artifacts",
    "invocations",
}

MAX_ARCHIVE_INVOCATIONS = 128
MAX_ARCHIVE_INVOCATION_TURNS = TELEMETRY_MAX_TURNS * MAX_ARCHIVE_INVOCATIONS
MAX_ARCHIVE_INVOCATION_BYTES = TELEMETRY_MAX_SIDECAR_BYTES
MAX_ARCHIVE_TELEMETRY_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_TOKEN_COUNT = 10**15
MAX_ARCHIVE_TOTAL_TOKEN_COUNT = 10**16
MAX_ARCHIVE_EFFECT_RECORDS = 512
MAX_ARCHIVE_EFFECT_BYTES = 512 * 1024
_EFFECTS_FILENAME = "effects.jsonl"
EFFECTS_FILENAME = _EFFECTS_FILENAME
_EFFECT_ID_RE = re.compile(r"^effect-[0-9a-f]{64}$")
_EFFECT_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_PROPOSAL_ID_RE = re.compile(r"^proposal-[0-9a-f]{64}$")
_INVOCATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TELEMETRY_FILE_RE = re.compile(
    r"^telemetry(?:\.retry-([1-9][0-9]*))?(?:\.unavailable-([1-9][0-9]*))?\.json$"
)


class ArchiveError(RuntimeError):
    """Base error for archive materialization failures."""


class ArchiveConflictError(ArchiveError):
    """A visible file differs from the expected generation."""


class ArchiveImmutableError(ArchiveError):
    """A completed archive or evidence file cannot be changed."""


class ArchiveValidationError(ArchiveError):
    """A path, document, or graph relation violates the archive contract."""


class ArchiveSealError(ArchiveError):
    """A task is not ready to be sealed or has corrupt terminal evidence."""


@dataclass(frozen=True, slots=True)
class VerifiedRerunArchive:
    """Immutable archive evidence accepted as a live-rerun source."""

    manifest_digest: str
    effects: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class ArchiveInvocation:
    """One bounded, archive-owned invocation and its optional telemetry."""

    invocation_id: str | None
    task_id: str
    pipeline_id: str
    run_id: str
    retry_ordinal: int
    path: str
    availability: str
    completeness: str
    started_at: str | None
    completed_at: str | None
    byte_size: int | None
    content_digest: str | None
    turn_count: int | None
    aggregate: dict[str, int] | None
    reason: str | None = None
    telemetry: dict[str, object] | None = field(default=None, repr=False, compare=False)

    def to_dict(self, *, include_telemetry: bool = False) -> dict[str, object]:
        """Return detached camel-case data suitable for archive/publication input."""

        value: dict[str, object] = {
            "invocationId": self.invocation_id,
            "taskId": self.task_id,
            "pipelineId": self.pipeline_id,
            "runId": self.run_id,
            "retryOrdinal": self.retry_ordinal,
            "path": self.path,
            "availability": self.availability,
            "completeness": self.completeness,
            "startedAt": self.started_at,
            "completedAt": self.completed_at,
            "byteSize": self.byte_size,
            "contentDigest": self.content_digest,
            "turnCount": self.turn_count,
            "aggregate": (
                dict(self.aggregate) if self.aggregate is not None else None
            ),
            "reason": self.reason,
        }
        if include_telemetry:
            value["telemetry"] = (
                json.loads(json.dumps(self.telemetry))
                if self.telemetry is not None
                else None
            )
        return value

    @property
    def descriptor(self) -> dict[str, object]:
        """Return the bounded descriptor retained in ``run.json``."""

        return self.to_dict()


def _validate_invocation_descriptor(value: Any, label: str = "invocation") -> None:
    keys = {
        "invocationId",
        "taskId",
        "pipelineId",
        "runId",
        "retryOrdinal",
        "path",
        "availability",
        "completeness",
        "startedAt",
        "completedAt",
        "byteSize",
        "contentDigest",
        "turnCount",
        "aggregate",
        "reason",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label=label)
    invocation_id = value["invocationId"]
    if invocation_id is not None and (
        not isinstance(invocation_id, str)
        or _INVOCATION_ID_RE.fullmatch(invocation_id) is None
    ):
        raise ArchiveValidationError(f"{label}.invocationId is invalid")
    for key in ("taskId", "pipelineId", "runId"):
        validate_opaque_id(value[key])
    _validate_nonnegative_integer(value["retryOrdinal"], f"{label}.retryOrdinal")
    if value["availability"] not in {"available", "partial"}:
        raise ArchiveValidationError(f"{label}.availability is invalid")
    if value["completeness"] not in {"complete", "partial", "unavailable"}:
        raise ArchiveValidationError(f"{label}.completeness is invalid")
    for key in ("startedAt", "completedAt"):
        if value[key] is not None:
            _validate_timestamp(value[key], f"{label}.{key}")
    for key in ("byteSize", "turnCount"):
        if value[key] is not None:
            _validate_nonnegative_integer(value[key], f"{label}.{key}")
    if value["byteSize"] is not None and value["byteSize"] > MAX_ARCHIVE_INVOCATION_BYTES:
        raise ArchiveValidationError(f"{label}.byteSize exceeds bound")
    digest = value["contentDigest"]
    if digest is not None and (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise ArchiveValidationError(f"{label}.contentDigest is invalid")
    if value["turnCount"] is not None and value["turnCount"] > TELEMETRY_MAX_TURNS:
        raise ArchiveValidationError(f"{label}.turnCount exceeds bound")
    validate_relative_path(value["path"])
    if _TELEMETRY_FILE_RE.fullmatch(PurePosixPath(value["path"]).name) is None:
        raise ArchiveValidationError(f"{label}.path has an unsafe telemetry filename")
    aggregate = value["aggregate"]
    if aggregate is not None:
        aggregate_keys = {
            "completed_turns",
            "input_tokens",
            "cached_input_tokens",
            "uncached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
            "total_tokens",
        }
        aggregate = _validate_shape(
            aggregate,
            required=aggregate_keys,
            allowed=aggregate_keys,
            label=f"{label}.aggregate",
        )
        for key in aggregate_keys:
            _validate_nonnegative_integer(aggregate[key], f"{label}.aggregate.{key}")
            if aggregate[key] > MAX_ARCHIVE_TOKEN_COUNT:
                raise ArchiveValidationError(
                    f"{label}.aggregate.{key} exceeds bound"
                )
        if aggregate["cached_input_tokens"] > aggregate["input_tokens"]:
            raise ArchiveValidationError(f"{label}.aggregate cached input exceeds input")
        if aggregate["uncached_input_tokens"] != (
            aggregate["input_tokens"] - aggregate["cached_input_tokens"]
        ):
            raise ArchiveValidationError(f"{label}.aggregate uncached input mismatch")
        if aggregate["reasoning_output_tokens"] > aggregate["output_tokens"]:
            raise ArchiveValidationError(f"{label}.aggregate reasoning exceeds output")
        if aggregate["total_tokens"] != (
            aggregate["input_tokens"] + aggregate["output_tokens"]
        ):
            raise ArchiveValidationError(f"{label}.aggregate total mismatch")
    _validate_optional_text(value["reason"], f"{label}.reason")
    if value["availability"] == "available":
        if value["invocationId"] is None or value["aggregate"] is None:
            raise ArchiveValidationError(f"{label} available evidence is incomplete")
        if value["byteSize"] is None or value["turnCount"] is None:
            raise ArchiveValidationError(f"{label} available bounds are missing")
        if value["completeness"] != "complete" or value["reason"] is not None:
            raise ArchiveValidationError(f"{label} available completeness is invalid")
    elif value["reason"] is None:
        raise ArchiveValidationError(f"{label} partial reason is required")
    if value["byteSize"] is not None and value["contentDigest"] is None:
        raise ArchiveValidationError(f"{label} sidecar content digest is missing")
    if value["byteSize"] is None and value["contentDigest"] is not None:
        raise ArchiveValidationError(f"{label} content digest has no sidecar")


def _is_unavailable_telemetry_marker(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == {"availability", "reason"}
        and value.get("availability") == "unavailable"
        and isinstance(value.get("reason"), str)
        and bool(value.get("reason"))
    )


def validate_opaque_id(value: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise ArchiveValidationError(f"invalid opaque archive id: {value!r}")
    return value


def validate_relative_path(value: str | PurePosixPath) -> str:
    text = value.as_posix() if isinstance(value, PurePosixPath) else str(value)
    if not text or "\x00" in text or "\\" in text:
        raise ArchiveValidationError(f"invalid archive path: {value!r}")
    if text.startswith("/") or text.startswith("./") or text.endswith("/"):
        raise ArchiveValidationError(f"invalid archive path: {value!r}")
    parts = text.split("/")
    if any(not part or part in {".", ".."} or part.startswith(HIDDEN_PREFIXES) for part in parts):
        raise ArchiveValidationError(f"invalid archive path: {value!r}")
    if any(not SAFE_COMPONENT_RE.fullmatch(part) for part in parts):
        raise ArchiveValidationError(f"invalid archive path: {value!r}")
    return "/".join(parts)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _not_applicable_effect_id(task_id: str, mode: str) -> str:
    """Return the stable identity for an aggregate with no actions."""

    seed = f"not-applicable\0{task_id}\0{mode}".encode("utf-8")
    return "effect-" + hashlib.sha256(seed).hexdigest()


def _json_bytes(value: Mapping[str, Any] | list[Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_filtered(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _private_filtered(item)
            for key, item in value.items()
            if str(key) not in PRIVATE_KEYS
        }
    if isinstance(value, list):
        return [_private_filtered(item) for item in value]
    return value


def _as_dict(
    value: Mapping[str, Any] | TaskRecord | TaskPipeline | TaskRun,
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if type(value) is TaskRecord:
        return dict(TaskRecord.model_dump(value, mode="json", by_alias=True))
    if type(value) is TaskPipeline:
        return dict(TaskPipeline.model_dump(value, mode="json", by_alias=True))
    if type(value) is TaskRun:
        return dict(TaskRun.model_dump(value, mode="json", by_alias=True))
    raise TypeError(f"expected mapping or pydantic model, got {type(value).__name__}")


def _ledger_run_reference(
    run: Mapping[str, Any] | TaskRun,
    *,
    task_id: str,
    pipeline_id: str,
) -> dict[str, Any]:
    value = _camelize(_as_dict(run))
    run_id = value.get("runId") or value.get("id")
    if not run_id:
        raise ArchiveValidationError("ledger run id is required")
    run_id = validate_opaque_id(str(run_id))
    if value.get("taskId") != task_id or value.get("pipelineId") != pipeline_id:
        raise ArchiveConflictError("ledger run does not belong to task pipeline")
    reference = {
        "runId": run_id,
        "role": value.get("role"),
        "roleOrdinal": value.get("roleOrdinal"),
        "state": value.get("state"),
        "path": f"pipelines/{pipeline_id}/runs/{run_id}/run.json",
    }
    _validate_run_reference(reference)
    return reference


def _validate_shape(
    value: Any,
    *,
    required: set[str],
    allowed: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ArchiveValidationError(f"{label} schema requires an object")
    keys = set(value)
    missing = required - keys
    extra = keys - allowed
    if missing:
        raise ArchiveValidationError(
            f"{label} schema is missing {', '.join(sorted(missing))}"
        )
    if extra:
        raise ArchiveValidationError(
            f"{label} schema has unknown fields: {', '.join(sorted(extra))}"
        )
    return value


def _validate_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ArchiveValidationError(f"{label} must be a UTC date-time")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ArchiveValidationError(f"{label} must be a UTC date-time") from exc
    if parsed.utcoffset() is None:
        raise ArchiveValidationError(f"{label} must be a UTC date-time")


def _validate_safe_id_or_none(value: Any, label: str) -> None:
    if value is not None:
        try:
            validate_opaque_id(value)
        except ArchiveValidationError as exc:
            raise ArchiveValidationError(f"{label} must be a safe id") from exc


def _validate_optional_text(value: Any, label: str) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ArchiveValidationError(f"{label} must be null or non-empty text")


def _validate_nonnegative_integer(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArchiveValidationError(f"{label} must be a non-negative integer")


def _validate_effect_record(value: Any, label: str = "effect") -> None:
    """Validate one private effect line without widening task.json."""

    keys = {
        "effectId",
        "taskId",
        "action",
        "actionId",
        "mode",
        "decision",
        "result",
        "at",
        "proposalId",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label=label)
    validate_opaque_id(value["taskId"])
    if not isinstance(value["effectId"], str) or _EFFECT_ID_RE.fullmatch(value["effectId"]) is None:
        raise ArchiveValidationError(f"{label}.effectId is invalid")
    if not isinstance(value["action"], str) or not value["action"]:
        raise ArchiveValidationError(f"{label}.action is invalid")
    if not isinstance(value["actionId"], str) or _EFFECT_ACTION_ID_RE.fullmatch(value["actionId"]) is None:
        raise ArchiveValidationError(f"{label}.actionId is invalid")
    if value["mode"] not in {"dry-run", "live"}:
        raise ArchiveValidationError(f"{label}.mode is invalid")
    if value["decision"] not in {"allow", "proposal-required", "not-applicable"}:
        raise ArchiveValidationError(f"{label}.decision is invalid")
    if value["result"] not in {"not-applicable", "not-applied", "applied"}:
        raise ArchiveValidationError(f"{label}.result is invalid")
    if value["result"] == "not-applicable":
        if value["action"] != "none" or value["actionId"] != "none" or value["decision"] != "not-applicable":
            raise ArchiveValidationError(f"{label}.not-applicable evidence is invalid")
        if value["effectId"] != _not_applicable_effect_id(
            value["taskId"], value["mode"]
        ):
            raise ArchiveValidationError(
                f"{label}.not-applicable identity is invalid"
            )
    else:
        try:
            expected_effect_id = effect_evidence_identity(
                value["action"], value["actionId"], value["mode"]
            )
        except (TypeError, ValueError) as exc:
            raise ArchiveValidationError(f"{label}.action identity is invalid") from exc
        if value["effectId"] != expected_effect_id:
            raise ArchiveValidationError(f"{label}.effectId does not match identity")
    if value["result"] == "applied" and (
        value["mode"] != "live" or value["decision"] != "allow"
    ):
        raise ArchiveValidationError(f"{label}.applied evidence is not live")
    if value["decision"] == "proposal-required" and (
        value["mode"] != "dry-run" or value["result"] != "not-applied"
    ):
        raise ArchiveValidationError(f"{label}.proposal evidence is invalid")
    _validate_timestamp(value["at"], f"{label}.at")
    proposal_id = value["proposalId"]
    if proposal_id is not None and (
        not isinstance(proposal_id, str) or _PROPOSAL_ID_RE.fullmatch(proposal_id) is None
    ):
        raise ArchiveValidationError(f"{label}.proposalId is invalid")
    if value["decision"] == "proposal-required" and proposal_id is None:
        raise ArchiveValidationError(f"{label}.proposalId is required")


def _effect_evidence_model(value: Mapping[str, Any]) -> EffectEvidence:
    normalized = dict(value)
    for source, target in (
        ("effectId", "effect_id"),
        ("taskId", "task_id"),
        ("actionId", "action_id"),
        ("proposalId", "proposal_id"),
    ):
        if source in normalized and target not in normalized:
            normalized[target] = normalized.pop(source)
    return EffectEvidence.model_validate(normalized)


def _validate_effects_document(
    raw: bytes,
    *,
    task_id: str,
) -> tuple[dict[str, Any], ...]:
    if len(raw) > MAX_ARCHIVE_EFFECT_BYTES:
        raise ArchiveValidationError("effects evidence exceeds bound")
    if not raw:
        return ()
    if not raw.endswith(b"\n"):
        raise ArchiveValidationError("effects evidence has an incomplete line")
    values: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for index, line in enumerate(raw.splitlines(), start=1):
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArchiveValidationError(f"effects evidence line {index} is invalid JSON") from exc
        _validate_effect_record(value, f"effect[{index}]")
        if value["taskId"] != task_id:
            raise ArchiveConflictError("effects evidence task identity mismatch")
        canonical = _json_bytes(value)
        if line + b"\n" != canonical:
            raise ArchiveValidationError("effects evidence is not canonical")
        effect_id = value["effectId"]
        previous = seen.get(effect_id)
        if previous is not None and previous != canonical:
            raise ArchiveConflictError("effects evidence identity is contradictory")
        if previous is not None:
            raise ArchiveValidationError("effects evidence identity is duplicated")
        seen[effect_id] = canonical
        values.append(dict(value))
        if len(values) > MAX_ARCHIVE_EFFECT_RECORDS:
            raise ArchiveValidationError("effects evidence record count exceeds bound")
    return tuple(values)


def _validate_artifact(value: Any, label: str) -> None:
    keys = {
        "path",
        "lifecycle",
        "availability",
        "mediaType",
        "byteSize",
        "sha256",
        "requiredAtTerminal",
        "reason",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label=label)
    validate_relative_path(value["path"])
    if value["lifecycle"] not in {"live", "terminal", "optional"}:
        raise ArchiveValidationError(f"{label} has invalid lifecycle")
    availability = value["availability"]
    if availability not in {
        "available",
        "partial",
        "missing",
        "unavailable",
        "notProduced",
    }:
        raise ArchiveValidationError(f"{label} has invalid availability")
    _validate_optional_text(value["mediaType"], f"{label}.mediaType")
    if value["byteSize"] is not None:
        _validate_nonnegative_integer(value["byteSize"], f"{label}.byteSize")
    digest = value["sha256"]
    if digest is not None and (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise ArchiveValidationError(f"{label}.sha256 is invalid")
    if not isinstance(value["requiredAtTerminal"], bool):
        raise ArchiveValidationError(f"{label}.requiredAtTerminal must be boolean")
    _validate_optional_text(value["reason"], f"{label}.reason")
    if availability == "available":
        if not isinstance(value["mediaType"], str) or not value["mediaType"]:
            raise ArchiveValidationError(f"{label} available mediaType is required")
        _validate_nonnegative_integer(value["byteSize"], f"{label}.byteSize")
        if value["reason"] is not None:
            raise ArchiveValidationError(f"{label} available reason must be null")
    elif availability == "partial":
        if not isinstance(value["reason"], str) or not value["reason"]:
            raise ArchiveValidationError(f"{label} partial reason is required")
    elif value["byteSize"] is not None or digest is not None:
        raise ArchiveValidationError(f"{label} unavailable size/hash must be null")
    elif not isinstance(value["reason"], str) or not value["reason"]:
        raise ArchiveValidationError(f"{label} unavailable reason is required")


def _validate_integration(value: Any) -> None:
    keys = {"state", "resultPath", "commit", "startedAt", "completedAt"}
    value = _validate_shape(
        value, required=keys, allowed=keys, label="integration"
    )
    if value["state"] not in {
        "pending",
        "succeeded",
        "failed",
        "conflict",
        "unavailable",
    }:
        raise ArchiveValidationError("integration schema has invalid state")
    if value["resultPath"] is not None:
        validate_relative_path(value["resultPath"])
    commit = value["commit"]
    if commit is not None and (
        not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    ):
        raise ArchiveValidationError("integration schema has invalid commit")
    _validate_timestamp(value["startedAt"], "integration.startedAt")
    if value["completedAt"] is not None:
        _validate_timestamp(value["completedAt"], "integration.completedAt")


def _validate_pipeline_reference(value: Any) -> None:
    keys = {"pipelineId", "ordinal", "path"}
    value = _validate_shape(
        value, required=keys, allowed=keys, label="pipeline reference"
    )
    validate_opaque_id(value["pipelineId"])
    _validate_nonnegative_integer(value["ordinal"], "pipeline reference ordinal")
    if value["ordinal"] < 1:
        raise ArchiveValidationError("pipeline reference ordinal must be positive")
    validate_relative_path(value["path"])


def _validate_run_reference(value: Any) -> None:
    keys = {"runId", "role", "roleOrdinal", "state", "path"}
    value = _validate_shape(
        value, required=keys, allowed=keys, label="run reference"
    )
    validate_opaque_id(value["runId"])
    if not isinstance(value["role"], str) or not (1 <= len(value["role"]) <= 128):
        raise ArchiveValidationError("run reference role is invalid")
    _validate_nonnegative_integer(value["roleOrdinal"], "run reference ordinal")
    if value["roleOrdinal"] < 1:
        raise ArchiveValidationError("run reference ordinal must be positive")
    if value["state"] not in {
        "running",
        "succeeded",
        "failed",
        "interrupted",
        "cancelled",
    }:
        raise ArchiveValidationError("run reference state is invalid")
    validate_relative_path(value["path"])


def _validate_task_document(value: Any) -> None:
    required = TASK_KEYS - {"terminalStatusObservedAt", "manifestPath"}
    value = _validate_shape(
        value, required=required, allowed=TASK_KEYS, label="task"
    )
    validate_opaque_id(value["taskId"])
    validate_opaque_id(value["epochId"])
    if value["status"] not in {
        "queued",
        "running",
        "reviewing",
        "integrating",
        *TERMINAL_TASK_STATUSES,
    }:
        raise ArchiveValidationError("task schema has invalid status")
    validate_relative_path(value["promptPath"])
    validate_relative_path(value["eventsPath"])
    _validate_timestamp(value["createdAt"], "task.createdAt")
    _validate_timestamp(value["updatedAt"], "task.updatedAt")
    _validate_safe_id_or_none(value["currentPipelineId"], "currentPipelineId")
    summary = _validate_shape(
        value["summary"],
        required={"title", "text"},
        allowed={"title", "text"},
        label="task summary",
    )
    for key in ("title", "text"):
        if not isinstance(summary[key], str) or not summary[key]:
            raise ArchiveValidationError(f"task summary {key} is required")
    pipelines = value["pipelines"]
    if not isinstance(pipelines, list) or not pipelines:
        raise ArchiveValidationError("task schema requires pipelines")
    for reference in pipelines:
        _validate_pipeline_reference(reference)
    if value.get("terminalStatusObservedAt") is not None:
        _validate_timestamp(
            value["terminalStatusObservedAt"], "task.terminalStatusObservedAt"
        )
    if value.get("manifestPath") is not None:
        validate_relative_path(value["manifestPath"])


def _validate_pipeline_document(value: Any) -> None:
    value = _validate_shape(
        value, required=PIPELINE_KEYS, allowed=PIPELINE_KEYS, label="pipeline"
    )
    validate_opaque_id(value["pipelineId"])
    validate_opaque_id(value["taskId"])
    _validate_nonnegative_integer(value["ordinal"], "pipeline.ordinal")
    if value["ordinal"] < 1:
        raise ArchiveValidationError("pipeline ordinal must be positive")
    if value["trigger"] not in {
        "initial",
        "validation-repair",
        "review-repair",
        "integration-rebase",
        "integration-conflict",
        "push-race",
    }:
        raise ArchiveValidationError("pipeline schema has invalid trigger")
    _validate_safe_id_or_none(value["parentPipelineId"], "parentPipelineId")
    if value["phase"] not in {
        "planning",
        "implementation",
        "validation",
        "review",
        "integration",
        "complete",
    }:
        raise ArchiveValidationError("pipeline schema has invalid phase")
    if value["state"] not in {
        "active",
        "succeeded",
        "failed",
        "blocked",
        "cancelled",
        "interrupted",
        "superseded",
    }:
        raise ArchiveValidationError("pipeline schema has invalid state")
    for key in ("baseIdentity", "inputIdentity", "outputIdentity", "patchIdentity"):
        _validate_optional_text(value[key], f"pipeline.{key}")
    _validate_timestamp(value["startedAt"], "pipeline.startedAt")
    _validate_timestamp(value["updatedAt"], "pipeline.updatedAt")
    if value["completedAt"] is not None:
        _validate_timestamp(value["completedAt"], "pipeline.completedAt")
    for key in ("inputs", "patches"):
        if not isinstance(value[key], list):
            raise ArchiveValidationError(f"pipeline {key} must be an array")
        for index, descriptor in enumerate(value[key]):
            _validate_artifact(descriptor, f"pipeline.{key}[{index}]")
    if not isinstance(value["validations"], list):
        raise ArchiveValidationError("pipeline validations must be an array")
    for reference in value["validations"]:
        keys = {"validationId", "ordinal", "path"}
        reference = _validate_shape(
            reference,
            required=keys,
            allowed=keys,
            label="validation reference",
        )
        validate_opaque_id(reference["validationId"])
        _validate_nonnegative_integer(reference["ordinal"], "validation ordinal")
        if reference["ordinal"] < 1:
            raise ArchiveValidationError("validation ordinal must be positive")
        validate_relative_path(reference["path"])
    if not isinstance(value["reviews"], list):
        raise ArchiveValidationError("pipeline reviews must be an array")
    for reference in value["reviews"]:
        keys = {"reviewId", "kind", "ordinal", "path"}
        reference = _validate_shape(
            reference, required=keys, allowed=keys, label="review reference"
        )
        validate_opaque_id(reference["reviewId"])
        if reference["kind"] not in {"raw", "effective"}:
            raise ArchiveValidationError("review reference kind is invalid")
        _validate_nonnegative_integer(reference["ordinal"], "review ordinal")
        if reference["ordinal"] < 1:
            raise ArchiveValidationError("review ordinal must be positive")
        validate_relative_path(reference["path"])
    _validate_integration(value["integration"])
    if not isinstance(value["runs"], list):
        raise ArchiveValidationError("pipeline runs must be an array")
    if not value["runs"] and value["state"] == "active":
        raise ArchiveValidationError("active pipeline schema requires runs")
    for reference in value["runs"]:
        _validate_run_reference(reference)


def _validate_usage(value: Any) -> None:
    keys = {
        "availability",
        "promptTokens",
        "completionTokens",
        "totalTokens",
        "sourcePath",
        "reason",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label="run usage")
    if value["availability"] not in {"available", "partial", "unavailable"}:
        raise ArchiveValidationError("run usage availability is invalid")
    for key in ("promptTokens", "completionTokens", "totalTokens"):
        if value[key] is not None:
            _validate_nonnegative_integer(value[key], f"run usage {key}")
    if value["sourcePath"] is not None:
        validate_relative_path(value["sourcePath"])
    _validate_optional_text(value["reason"], "run usage reason")
    if value["availability"] == "available":
        for key in ("promptTokens", "completionTokens", "totalTokens"):
            _validate_nonnegative_integer(value[key], f"run usage {key}")
        if value["sourcePath"] is None or value["reason"] is not None:
            raise ArchiveValidationError("available run usage is incomplete")
    elif value["availability"] == "partial":
        if all(value[key] is None for key in ("promptTokens", "completionTokens", "totalTokens")):
            raise ArchiveValidationError("partial run usage has no counters")
        if not isinstance(value["reason"], str) or not value["reason"]:
            raise ArchiveValidationError("partial run usage reason is required")
    elif any(
        value[key] is not None
        for key in ("promptTokens", "completionTokens", "totalTokens", "sourcePath")
    ) or not isinstance(value["reason"], str):
        raise ArchiveValidationError("unavailable run usage is invalid")


def _validate_cost(value: Any) -> None:
    keys = {
        "availability",
        "estimatedMicroUsd",
        "currency",
        "model",
        "pricingSource",
        "reason",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label="run cost")
    if value["availability"] not in {"available", "partial", "unavailable"}:
        raise ArchiveValidationError("run cost availability is invalid")
    if value["estimatedMicroUsd"] is not None:
        _validate_nonnegative_integer(
            value["estimatedMicroUsd"], "run cost estimatedMicroUsd"
        )
    for key in ("model", "pricingSource", "reason"):
        _validate_optional_text(value[key], f"run cost {key}")
    currency = value["currency"]
    if currency is not None and (
        not isinstance(currency, str) or re.fullmatch(r"[A-Z]{3}", currency) is None
    ):
        raise ArchiveValidationError("run cost currency is invalid")
    if value["availability"] == "available":
        _validate_nonnegative_integer(
            value["estimatedMicroUsd"], "run cost estimatedMicroUsd"
        )
        if (
            currency != "USD"
            or not value["model"]
            or not value["pricingSource"]
            or value["reason"] is not None
        ):
            raise ArchiveValidationError("available run cost is incomplete")
    elif value["availability"] == "unavailable":
        if any(
            value[key] is not None
            for key in ("estimatedMicroUsd", "currency", "pricingSource")
        ) or not isinstance(value["reason"], str):
            raise ArchiveValidationError("unavailable run cost is invalid")
    elif not isinstance(value["reason"], str) or not value["reason"]:
        raise ArchiveValidationError("partial run cost reason is required")


def _validate_run_document(value: Any) -> None:
    if isinstance(value, Mapping) and "invocations" not in value:
        value = dict(value)
        value["invocations"] = []
    value = _validate_shape(value, required=RUN_KEYS, allowed=RUN_KEYS, label="run")
    for key in ("runId", "taskId", "pipelineId", "sessionId"):
        validate_opaque_id(value[key])
    if not isinstance(value["role"], str) or not (1 <= len(value["role"]) <= 128):
        raise ArchiveValidationError("run schema has invalid role")
    _validate_nonnegative_integer(value["roleOrdinal"], "run.roleOrdinal")
    if value["roleOrdinal"] < 1:
        raise ArchiveValidationError("run role ordinal must be positive")
    for key in ("resumeOfRunId", "parentRunId", "retryOfRunId"):
        _validate_safe_id_or_none(value[key], f"run.{key}")
    if value["state"] not in {
        "running",
        "succeeded",
        "failed",
        "interrupted",
        "cancelled",
    }:
        raise ArchiveValidationError("run schema has invalid state")
    _validate_timestamp(value["startedAt"], "run.startedAt")
    _validate_timestamp(value["updatedAt"], "run.updatedAt")
    if value["state"] == "running":
        if value["completedAt"] is not None:
            raise ArchiveValidationError("running run completedAt must be null")
    else:
        _validate_timestamp(value["completedAt"], "run.completedAt")
    for key in ("model", "reasoning"):
        _validate_optional_text(value[key], f"run.{key}")
    if value["exit"] is not None:
        exit_keys = {"code", "signal", "reason"}
        exit_value = _validate_shape(
            value["exit"], required=exit_keys, allowed=exit_keys, label="run exit"
        )
        if exit_value["code"] is not None and (
            isinstance(exit_value["code"], bool)
            or not isinstance(exit_value["code"], int)
        ):
            raise ArchiveValidationError("run exit code is invalid")
        _validate_optional_text(exit_value["signal"], "run exit signal")
        _validate_optional_text(exit_value["reason"], "run exit reason")
    result_keys = {"status", "summary", "path"}
    result = _validate_shape(
        value["result"],
        required=result_keys,
        allowed=result_keys,
        label="run result",
    )
    if result["status"] not in {"available", "partial", "unavailable"}:
        raise ArchiveValidationError("run result status is invalid")
    if result["summary"] is not None and not isinstance(result["summary"], str):
        raise ArchiveValidationError("run result summary is invalid")
    if result["path"] is not None:
        validate_relative_path(result["path"])
    _validate_usage(value["usage"])
    _validate_cost(value["cost"])
    invocations = value["invocations"]
    if not isinstance(invocations, list) or len(invocations) > MAX_ARCHIVE_INVOCATIONS:
        raise ArchiveValidationError("run invocations exceed bound")
    previous_ordinal: int | None = None
    seen_ids: set[str] = set()
    for index, descriptor in enumerate(invocations):
        _validate_invocation_descriptor(descriptor, f"run invocation[{index}]")
        if descriptor["taskId"] != value["taskId"]:
            raise ArchiveValidationError("run invocation task identity mismatch")
        if descriptor["pipelineId"] != value["pipelineId"]:
            raise ArchiveValidationError("run invocation pipeline identity mismatch")
        if descriptor["runId"] != value["runId"]:
            raise ArchiveValidationError("run invocation identity mismatch")
        invocation_id = descriptor["invocationId"]
        if invocation_id is not None:
            if invocation_id in seen_ids:
                raise ArchiveValidationError("run invocation ids are not unique")
            seen_ids.add(invocation_id)
        ordinal = descriptor["retryOrdinal"]
        if previous_ordinal is not None and ordinal <= previous_ordinal:
            raise ArchiveValidationError("run invocation ordinals are not monotonic")
        previous_ordinal = ordinal
    artifact_keys = {
        "codex",
        "activities",
        "telemetry",
        "lastMessage",
        "result",
        "toolChangesManifest",
        "toolChangesSummary",
    }
    artifacts = _validate_shape(
        value["artifacts"],
        required=artifact_keys,
        allowed=artifact_keys,
        label="run artifacts",
    )
    for key, descriptor in artifacts.items():
        _validate_artifact(descriptor, f"run artifact {key}")


def _validate_validation_document(value: Any) -> None:
    keys = {
        "validationId",
        "taskId",
        "pipelineId",
        "ordinal",
        "command",
        "state",
        "startedAt",
        "completedAt",
        "result",
        "outputPath",
        "output",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label="validation")
    for key in ("validationId", "taskId", "pipelineId"):
        validate_opaque_id(value[key])
    _validate_nonnegative_integer(value["ordinal"], "validation ordinal")
    if value["ordinal"] < 1 or not isinstance(value["command"], str) or not value["command"]:
        raise ArchiveValidationError("validation schema has invalid ordinal/command")
    if value["state"] not in {"running", "completed", "unavailable"}:
        raise ArchiveValidationError("validation schema has invalid state")
    _validate_timestamp(value["startedAt"], "validation.startedAt")
    if value["completedAt"] is not None:
        _validate_timestamp(value["completedAt"], "validation.completedAt")
    if value["result"] not in {"pass", "fail", "skipped", "unavailable"}:
        raise ArchiveValidationError("validation schema has invalid result")
    validate_relative_path(value["outputPath"])
    _validate_artifact(value["output"], "validation output")


def _validate_review_document(value: Any) -> None:
    keys = {
        "reviewId",
        "taskId",
        "pipelineId",
        "ordinal",
        "kind",
        "role",
        "state",
        "verdict",
        "findings",
        "artifact",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label="review")
    for key in ("reviewId", "taskId", "pipelineId"):
        validate_opaque_id(value[key])
    _validate_nonnegative_integer(value["ordinal"], "review ordinal")
    if value["ordinal"] < 1 or value["kind"] not in {"raw", "effective"}:
        raise ArchiveValidationError("review schema has invalid ordinal/kind")
    if not isinstance(value["role"], str) or not value["role"]:
        raise ArchiveValidationError("review schema has invalid role")
    if value["state"] not in {"available", "partial", "unavailable"}:
        raise ArchiveValidationError("review schema has invalid state")
    if value["verdict"] not in {
        "approve",
        "request-changes",
        "unknown",
        "unavailable",
    }:
        raise ArchiveValidationError("review schema has invalid verdict")
    if not isinstance(value["findings"], list) or not all(
        isinstance(item, str) for item in value["findings"]
    ):
        raise ArchiveValidationError("review findings must be strings")
    _validate_artifact(value["artifact"], "review artifact")


def _validate_manifest_document(value: Any) -> None:
    keys = {
        "manifestVersion",
        "epochId",
        "taskId",
        "completionIdentity",
        "terminalStatus",
        "completedAt",
        "files",
    }
    value = _validate_shape(value, required=keys, allowed=keys, label="manifest")
    if value["manifestVersion"] != FORMAT_VERSION:
        raise ArchiveValidationError("manifest schema has invalid version")
    for key in ("epochId", "taskId", "completionIdentity"):
        validate_opaque_id(value[key])
    if value["terminalStatus"] not in TERMINAL_TASK_STATUSES:
        raise ArchiveValidationError("manifest schema has invalid terminal status")
    _validate_timestamp(value["completedAt"], "manifest.completedAt")
    if not isinstance(value["files"], list) or not value["files"]:
        raise ArchiveValidationError("manifest schema requires files")
    for descriptor in value["files"]:
        file_keys = {"path", "byteSize", "sha256"}
        descriptor = _validate_shape(
            descriptor,
            required=file_keys,
            allowed=file_keys,
            label="manifest file",
        )
        validate_relative_path(descriptor["path"])
        _validate_nonnegative_integer(descriptor["byteSize"], "manifest file size")
        if (
            not isinstance(descriptor["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", descriptor["sha256"]) is None
        ):
            raise ArchiveValidationError("manifest file hash is invalid")


class TaskArchive:
    """Materialize and verify one ``tasks/`` tree."""

    def __init__(self, root: Path | Any, *, epoch_id: str | None = None):
        configured = getattr(root, "tasks_dir", None)
        raw_root = Path(configured if configured is not None else root).expanduser()
        if raw_root.is_symlink():
            raise ArchiveValidationError("archive root must not be a symlink")
        self.root = raw_root.resolve()
        self.epoch_id = epoch_id

    # Paths are built exclusively here so no caller can accidentally publish
    # private state or escape the configured task root.
    def path(self, relative: str | PurePosixPath) -> Path:
        safe = validate_relative_path(relative)
        candidate = self.root / PurePosixPath(safe)
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ArchiveValidationError(f"path escapes archive root: {relative!r}") from exc
        return candidate

    def task_dir(self, task_id: str) -> Path:
        return self.root / validate_opaque_id(task_id)

    def task_path(self, task_id: str, relative: str = "") -> Path:
        validate_opaque_id(task_id)
        if not relative:
            return self.task_dir(task_id)
        return self.task_dir(task_id) / PurePosixPath(validate_relative_path(relative))

    def pipeline_dir(self, task_id: str, pipeline_id: str) -> Path:
        validate_opaque_id(task_id)
        validate_opaque_id(pipeline_id)
        return self.task_dir(task_id) / "pipelines" / pipeline_id

    def run_dir(self, task_id: str, pipeline_id: str, run_id: str) -> Path:
        validate_opaque_id(task_id)
        validate_opaque_id(pipeline_id)
        validate_opaque_id(run_id)
        return self.pipeline_dir(task_id, pipeline_id) / "runs" / run_id

    def collect_invocation_evidence(
        self,
        task_id: str,
        pipeline_id: str,
        run_id: str,
        *,
        expected_run: Mapping[str, Any] | TaskRun | None = None,
        strict: bool = True,
    ) -> tuple[ArchiveInvocation, ...]:
        """Collect only authenticated current/retry telemetry for one run.

        The collector examines direct, allow-listed sidecar names only.  It
        never recursively scans a task archive and never turns missing usage
        into zero-valued counters.
        """

        task_id = validate_opaque_id(task_id)
        pipeline_id = validate_opaque_id(pipeline_id)
        run_id = validate_opaque_id(run_id)
        self._authenticate_run_identity(
            expected_run, task_id=task_id, pipeline_id=pipeline_id, run_id=run_id
        )
        run_dir = self.run_dir(task_id, pipeline_id, run_id)
        try:
            self._assert_safe_archive_path(run_dir, target="directory")
        except ArchiveValidationError:
            if strict:
                raise
            run_dir = self.run_dir(task_id, pipeline_id, run_id)

        candidates: list[tuple[Path, int | None, bool]] = []
        current_unavailable_candidates = 0
        if run_dir.is_dir() and not run_dir.is_symlink():
            try:
                for path in sorted(run_dir.iterdir(), key=lambda item: item.name):
                    match = _TELEMETRY_FILE_RE.fullmatch(path.name)
                    if match is None:
                        if path.name.startswith("telemetry") and path.name.endswith(
                            ".json"
                        ):
                            self._invocation_collection_error(
                                "telemetry filename is unsafe", strict
                            )
                        continue
                    retry_text, unavailable_text = match.groups()
                    if (
                        (retry_text is not None and len(retry_text) > 9)
                        or (unavailable_text is not None and len(unavailable_text) > 9)
                    ):
                        self._invocation_collection_error(
                            "telemetry retry ordinal exceeds bound", strict
                        )
                        continue
                    archive_ordinal = (
                        int(retry_text) - 1 if retry_text is not None else None
                    )
                    if archive_ordinal is None and unavailable_text is not None:
                        current_unavailable_candidates += 1
                        if current_unavailable_candidates > 1:
                            self._invocation_collection_error(
                                "conflicting current unavailable telemetry markers",
                                strict,
                            )
                    candidates.append(
                        (path, archive_ordinal, retry_text is not None)
                    )
                    if len(candidates) > MAX_ARCHIVE_INVOCATIONS:
                        self._invocation_collection_error(
                            "telemetry invocation count exceeds bound", strict
                        )
                        break
            except OSError as exc:
                self._invocation_collection_error(
                    f"telemetry archive enumeration failed: {exc}", strict
                )

        selected: list[ArchiveInvocation] = []
        by_id: dict[str, tuple[str, ArchiveInvocation]] = {}
        unavailable_ordinals: dict[int, ArchiveInvocation] = {}
        current_unavailable: tuple[str, str, int, str] | None = None
        authenticated_ordinals: set[int] = set()
        total_bytes = 0
        current_seen = False
        for path, archive_ordinal, is_retry in candidates:
            if not is_retry:
                current_seen = True
            relative = path.relative_to(self.root).as_posix()
            try:
                info = path.lstat()
                if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ArchiveValidationError(
                        "telemetry sidecar is not a regular file"
                    )
                if info.st_size < 0 or info.st_size > MAX_ARCHIVE_INVOCATION_BYTES:
                    raise ArchiveValidationError("telemetry sidecar exceeds bound")
                total_bytes += info.st_size
                if total_bytes > MAX_ARCHIVE_TELEMETRY_BYTES:
                    raise ArchiveValidationError("telemetry archive exceeds bound")
                raw = path.read_bytes()
                content_digest = hashlib.sha256(raw).hexdigest()
                try:
                    marker = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ArchiveValidationError("telemetry sidecar is invalid JSON") from exc
                if _is_unavailable_telemetry_marker(marker):
                    reason = str(marker.get("reason") or "telemetry_unavailable")
                    if archive_ordinal is None:
                        current_unavailable = (
                            relative,
                            reason,
                            info.st_size,
                            content_digest,
                        )
                        continue
                    ordinal = archive_ordinal
                    authenticated_ordinals.add(ordinal)
                    evidence = self._missing_invocation(
                        task_id,
                        pipeline_id,
                        run_id,
                        ordinal=ordinal,
                        path=relative,
                        reason=reason,
                        byte_size=info.st_size,
                        content_digest=content_digest,
                    )
                    previous = unavailable_ordinals.get(ordinal)
                    if previous is not None and previous.path != evidence.path:
                        raise ArchiveValidationError(
                            "conflicting unavailable telemetry ordinal"
                        )
                    unavailable_ordinals[ordinal] = evidence
                    continue
                payload = load_sidecar(path)
                if payload.get("task_id") != task_id:
                    raise ArchiveValidationError("telemetry task identity mismatch")
                self._validate_sidecar_run_name(payload, expected_run)
                payload_ordinal = payload.get("retry_ordinal")
                if type(payload_ordinal) is not int or payload_ordinal < 0:
                    raise ArchiveValidationError("telemetry retry ordinal is invalid")
                if archive_ordinal is not None and payload_ordinal != archive_ordinal:
                    raise ArchiveValidationError(
                        "telemetry retry ordinal disagrees with archive filename"
                    )
                authenticated_ordinals.add(payload_ordinal)
                aggregate = payload.get("aggregate")
                if not isinstance(aggregate, Mapping):
                    raise ArchiveValidationError("telemetry aggregate is unavailable")
                aggregate_value = {
                    str(key): int(value)
                    for key, value in aggregate.items()
                    if isinstance(value, int) and not isinstance(value, bool)
                }
                if len(aggregate_value) != 7:
                    raise ArchiveValidationError("telemetry aggregate is invalid")
                for number in aggregate_value.values():
                    if number < 0 or number > MAX_ARCHIVE_TOKEN_COUNT:
                        raise ArchiveValidationError("telemetry aggregate exceeds bound")
                turns = payload.get("turns")
                if not isinstance(turns, list) or len(turns) > TELEMETRY_MAX_TURNS:
                    raise ArchiveValidationError("telemetry turns exceed bound")
                if not turns or payload.get("completeness") == "unavailable":
                    aggregate_value = None
                evidence = ArchiveInvocation(
                    invocation_id=str(payload["invocation_id"]),
                    task_id=task_id,
                    pipeline_id=pipeline_id,
                    run_id=run_id,
                    retry_ordinal=payload_ordinal,
                    path=relative,
                    availability=(
                        "available" if payload.get("completeness") == "complete" else "partial"
                    ),
                    completeness=str(payload.get("completeness")),
                    started_at=str(payload.get("started_at")),
                    completed_at=str(payload.get("completed_at")),
                    byte_size=info.st_size,
                    content_digest=content_digest,
                    turn_count=len(turns),
                    aggregate=aggregate_value,
                    reason=(
                        None
                        if payload.get("completeness") == "complete"
                        else "telemetry_incomplete"
                    ),
                    telemetry=payload,
                )
                previous = by_id.get(evidence.invocation_id or "")
                if previous is not None:
                    previous_digest, _ = previous
                    digest = hashlib.sha256(
                        json.dumps(
                            payload,
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    if digest != previous_digest:
                        raise ArchiveValidationError(
                            "conflicting telemetry invocation id reuse"
                        )
                    continue
                by_id[evidence.invocation_id or ""] = (
                    hashlib.sha256(
                        json.dumps(
                            payload,
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                    evidence,
                )
                selected.append(evidence)
            except (ArchiveError, OSError, ValueError, TypeError) as exc:
                if strict:
                    if isinstance(exc, ArchiveError):
                        raise
                    raise ArchiveValidationError(str(exc)) from exc
                ordinal = (
                    archive_ordinal
                    if archive_ordinal is not None
                    else self._next_invocation_ordinal(selected)
                )
                if archive_ordinal is not None:
                    authenticated_ordinals.add(archive_ordinal)
                unavailable_ordinals[ordinal] = self._missing_invocation(
                    task_id,
                    pipeline_id,
                    run_id,
                    ordinal=ordinal,
                    path=relative,
                    reason="telemetry_unavailable",
                    byte_size=None,
                )

        selected.extend(unavailable_ordinals.values())
        if current_unavailable is not None:
            relative, reason, byte_size, content_digest = current_unavailable
            selected.append(
                self._missing_invocation(
                    task_id,
                    pipeline_id,
                    run_id,
                    ordinal=self._next_invocation_ordinal(selected),
                    path=relative,
                    reason=reason,
                    byte_size=byte_size,
                    content_digest=content_digest,
                )
            )
        if not current_seen:
            selected.append(
                self._missing_invocation(
                    task_id,
                    pipeline_id,
                    run_id,
                    ordinal=self._next_invocation_ordinal(selected),
                    path=self.run_dir(task_id, pipeline_id, run_id)
                    .joinpath("telemetry.json")
                    .relative_to(self.root)
                    .as_posix(),
                    reason="telemetry_missing",
                    byte_size=None,
                )
            )
        if len(selected) > MAX_ARCHIVE_INVOCATIONS:
            self._invocation_collection_error(
                "telemetry invocation count exceeds bound", strict
            )
        selected.sort(
            key=lambda item: (
                item.retry_ordinal,
                item.started_at or "",
                item.invocation_id or "",
            )
        )
        previous_ordinal: int | None = None
        total_tokens = 0
        observed_ordinals: set[int] = set()
        for item in selected:
            if item.retry_ordinal in observed_ordinals:
                self._invocation_collection_error(
                    "telemetry retry ordinals are not unique", strict
                )
            observed_ordinals.add(item.retry_ordinal)
            if previous_ordinal is not None and item.retry_ordinal <= previous_ordinal:
                self._invocation_collection_error(
                    "telemetry retry ordinals are not monotonic", strict
                )
            previous_ordinal = item.retry_ordinal
            if item.aggregate is not None:
                total_tokens += item.aggregate.get("total_tokens", 0)
        if authenticated_ordinals and not authenticated_ordinals.issubset(observed_ordinals):
            self._invocation_collection_error(
                "telemetry retry ordinal evidence is missing", strict
            )
        if observed_ordinals:
            expected_ordinals = set(range(max(observed_ordinals) + 1))
            if observed_ordinals != expected_ordinals:
                self._invocation_collection_error(
                    "telemetry retry ordinals have gaps", strict
                )
        if total_tokens > MAX_ARCHIVE_TOTAL_TOKEN_COUNT:
            self._invocation_collection_error(
                "telemetry aggregate totals exceed bound", strict
            )
        if sum(item.turn_count or 0 for item in selected) > MAX_ARCHIVE_INVOCATION_TURNS:
            self._invocation_collection_error(
                "telemetry turn count exceeds bound", strict
            )
        return tuple(selected)

    def collect_run_publication_evidence(
        self,
        task_id: str,
        pipeline_id: str,
        run: Mapping[str, Any] | TaskRun,
    ) -> tuple[dict[str, bytes], tuple[ArchiveInvocation, ...]]:
        """Return stable source documents and authenticated retry evidence."""

        run_id = self._run_identity_value(run, "runId", "id", "run_id")
        if not isinstance(run_id, str):
            raise ArchiveValidationError("publication run id is required")
        invocations = self.collect_invocation_evidence(
            task_id,
            pipeline_id,
            run_id,
            expected_run=run,
        )
        documents: dict[str, bytes] = {}
        for name in ("codex.jsonl", "activities.jsonl", "telemetry.json", "run.json"):
            path = self.task_path(
                task_id, f"pipelines/{pipeline_id}/runs/{run_id}/{name}"
            )
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(self.root.resolve())
                info = path.lstat()
                if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    continue
                documents[name] = path.read_bytes()
            except (OSError, RuntimeError, ValueError):
                continue
        return documents, invocations

    @staticmethod
    def _run_identity_value(
        run: Mapping[str, Any] | TaskRun,
        *names: str,
    ) -> object:
        if isinstance(run, Mapping):
            for name in names:
                if name in run:
                    return run[name]
            return None
        for name in names:
            value = getattr(run, name, None)
            if value is not None:
                return value
        return None

    @classmethod
    def _authenticate_run_identity(
        cls,
        run: Mapping[str, Any] | TaskRun | None,
        *,
        task_id: str,
        pipeline_id: str,
        run_id: str,
    ) -> None:
        if run is None:
            return
        values = {
            "task": cls._run_identity_value(run, "taskId", "task_id"),
            "pipeline": cls._run_identity_value(run, "pipelineId", "pipeline_id"),
            "run": cls._run_identity_value(run, "runId", "id", "run_id"),
        }
        if values != {"task": task_id, "pipeline": pipeline_id, "run": run_id}:
            raise ArchiveValidationError("publication run identity mismatch")

    @staticmethod
    def _validate_sidecar_run_name(
        payload: Mapping[str, Any], expected_run: Mapping[str, Any] | TaskRun | None
    ) -> None:
        if expected_run is None:
            return
        role = TaskArchive._run_identity_value(expected_run, "role")
        run_name = payload.get("run_name")
        if not isinstance(role, str) or not role or not isinstance(run_name, str):
            return
        role_key = role.lower().replace("-", "_")
        run_key = run_name.lower().replace("-", "_")
        aliases = {
            "implementation": {"implementation", "worker", "code"},
            "implementation_plan": {"implementation_plan", "planner", "planning"},
            "planning": {"implementation_plan", "planner", "planning"},
            "planner": {"implementation_plan", "planner", "planning"},
            "validation": {"validation", "worker"},
            "review": {"review", "reviewer"},
            "reviewer": {"review", "reviewer"},
            "formality": {"formality", "reviewer", "worker"},
            "commit_message": {"commit_message", "commit-message", "commit", "worker"},
        }
        if run_key not in aliases.get(role_key, {role_key}):
            raise ArchiveValidationError("telemetry run identity mismatch")

    @staticmethod
    def _next_invocation_ordinal(values: Sequence[ArchiveInvocation]) -> int:
        return max((item.retry_ordinal for item in values), default=-1) + 1

    @staticmethod
    def _canonical_invocation_descriptors(
        values: Sequence[Mapping[str, Any] | ArchiveInvocation],
    ) -> tuple[str, ...]:
        descriptors: list[dict[str, Any]] = []
        for value in values:
            descriptor = value.descriptor if isinstance(value, ArchiveInvocation) else dict(value)
            descriptors.append(descriptor)
        descriptors.sort(
            key=lambda item: (
                int(item["retryOrdinal"]),
                item.get("startedAt") or "",
                item.get("invocationId") or "",
            )
        )
        return tuple(
            json.dumps(
                descriptor,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            for descriptor in descriptors
        )

    @staticmethod
    def _missing_invocation(
        task_id: str,
        pipeline_id: str,
        run_id: str,
        *,
        ordinal: int,
        path: str,
        reason: str,
        byte_size: int | None,
        content_digest: str | None = None,
    ) -> ArchiveInvocation:
        return ArchiveInvocation(
            invocation_id=None,
            task_id=task_id,
            pipeline_id=pipeline_id,
            run_id=run_id,
            retry_ordinal=ordinal,
            path=path,
            availability="partial",
            completeness="unavailable",
            started_at=None,
            completed_at=None,
            byte_size=byte_size,
            content_digest=content_digest,
            turn_count=None,
            aggregate=None,
            reason=reason,
        )

    @staticmethod
    def _invocation_collection_error(message: str, strict: bool) -> None:
        if strict:
            raise ArchiveValidationError(message)

    @property
    def epoch_path(self) -> Path:
        return self.root / "epoch.json"

    @property
    def archive_root(self) -> Path:
        return self.root

    @property
    def tasks_dir(self) -> Path:
        return self.root

    def ensure_epoch(self, epoch: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.epoch_path.is_symlink():
            raise ArchiveValidationError("epoch.json must not be a symlink")
        if self.epoch_path.exists():
            try:
                current = json.loads(self.epoch_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveValidationError("invalid epoch.json") from exc
            if not self._valid_epoch(current):
                raise ArchiveConflictError("epoch.json does not match the archive epoch")
            if self.epoch_id is not None and current["epochId"] != self.epoch_id:
                raise ArchiveConflictError("archive epoch id mismatch")
            self.epoch_id = current["epochId"]
            return current
        data = dict(epoch or {})
        data.setdefault("epochId", self.epoch_id or f"epoch-{secrets.token_hex(12)}")
        data.setdefault("formatVersion", FORMAT_VERSION)
        data.setdefault("policy", POLICY)
        data.setdefault("startedAt", _now())
        data.setdefault("endedAt", None)
        if not self._valid_epoch(data):
            raise ArchiveValidationError("invalid archive epoch")
        temporary = self.epoch_path.with_name(
            f".{self.epoch_path.name}.tmp-{secrets.token_hex(8)}"
        )
        try:
            with temporary.open("xb") as handle:
                handle.write(_json_bytes(data))
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, self.epoch_path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)
        _fsync_directory(self.root)
        if self.epoch_path.is_symlink():
            raise ArchiveValidationError("epoch.json must not be a symlink")
        try:
            result = json.loads(self.epoch_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveValidationError("invalid archive epoch") from exc
        if not self._valid_epoch(result):
            raise ArchiveConflictError("epoch.json does not match the archive epoch")
        self.epoch_id = result["epochId"]
        return result

    @staticmethod
    def _valid_epoch(value: Any) -> bool:
        required = {"epochId", "formatVersion", "policy", "startedAt"}
        allowed = required | {"endedAt"}
        if (
            not isinstance(value, Mapping)
            or not required.issubset(value)
            or not set(value).issubset(allowed)
        ):
            return False
        if (
            value.get("formatVersion") != FORMAT_VERSION
            or value.get("policy") != POLICY
            or not isinstance(value.get("epochId"), str)
            or SAFE_ID_RE.fullmatch(value["epochId"]) is None
            or value.get("endedAt") is not None
        ):
            return False
        try:
            _validate_timestamp(value.get("startedAt"), "epoch.startedAt")
        except ArchiveValidationError:
            return False
        return True

    def create_task(
        self,
        task_id: str,
        prompt: str | bytes,
        *,
        task: Mapping[str, Any] | TaskRecord | None = None,
        task_metadata: Mapping[str, Any] | None = None,
        pipeline_id: str | None = None,
        event: Mapping[str, Any] | None = None,
    ) -> Path:
        if task is not None:
            _as_dict(task)
        self.ensure_epoch()
        task_id = validate_opaque_id(task_id)
        directory = self.task_dir(task_id)
        self._assert_safe_archive_path(directory, target="directory")
        if directory.exists() and not directory.is_dir():
            raise ArchiveConflictError(f"task path is not a directory: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        self._assert_safe_archive_path(directory, target="directory")
        metadata = self._task_metadata(task_id, task, task_metadata, pipeline_id)
        self.write_json(task_id, "task.json", metadata)
        self.write_bytes(task_id, "prompt.md", prompt.encode("utf-8") if isinstance(prompt, str) else prompt)
        if not (directory / "events.jsonl").exists():
            self._atomic_bytes(directory / "events.jsonl", b"")
        if event is not None:
            self.append_event(task_id, event)
        return directory

    def create_task_from_record(
        self,
        record: TaskRecord,
        *,
        pipeline: TaskPipeline | None = None,
        pipeline_id: str | None = None,
    ) -> Path:
        if pipeline is not None:
            if pipeline.task_id != record.id:
                raise ArchiveConflictError("ledger pipeline does not belong to task")
            if pipeline_id is not None and pipeline_id != pipeline.id:
                raise ArchiveConflictError("ledger pipeline identities conflict")
            pipeline_id = pipeline.id
        if pipeline_id is None:
            raise ArchiveValidationError(
                "task materialization requires a ledger pipeline id"
            )
        return self.create_task(
            record.id,
            record.spec.prompt,
            task=record,
            pipeline_id=pipeline_id,
        )

    def update_task(self, task_id: str, metadata: Mapping[str, Any]) -> Path:
        value = _private_filtered(dict(metadata))
        if value.get("taskId") != task_id:
            raise ArchiveConflictError("task metadata identity does not match archive path")
        _validate_task_document(value)
        return self.write_json(task_id, "task.json", value)

    def materialize_effects(
        self,
        task_id: str,
        effects: Sequence[Mapping[str, Any] | EffectEvidence] | None = None,
        *,
        result: EffectResult | str | None = None,
        mode: str = "dry-run",
        recorded_at: str | None = None,
    ) -> Path:
        """Write one canonical, bounded private effect evidence sidecar."""

        task_id = validate_opaque_id(task_id)
        selected_result = (
            result.value
            if isinstance(result, EffectResult)
            else str(result or EffectResult.not_applicable.value)
        )
        selected_mode = getattr(mode, "value", str(mode))
        default_recorded_at = recorded_at
        if not default_recorded_at:
            try:
                metadata = json.loads(
                    self.task_path(task_id, "task.json").read_text(encoding="utf-8")
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                metadata = {}
            candidate_timestamp = (
                metadata.get("updatedAt")
                if isinstance(metadata, Mapping)
                else None
            )
            default_recorded_at = (
                candidate_timestamp
                if isinstance(candidate_timestamp, str) and candidate_timestamp
                else _now()
            )
        values: list[dict[str, Any]] = []
        for item in effects or ():
            if isinstance(item, EffectEvidence):
                value = item.as_dict()
            else:
                value = dict(item)
                if "at" not in value:
                    value["at"] = default_recorded_at
                if "taskId" not in value:
                    value["taskId"] = task_id
            if value.get("taskId") is None:
                value["taskId"] = task_id
            if value.get("taskId") != task_id:
                raise ArchiveConflictError("effects evidence task identity mismatch")
            values.append(value)
        if not values:
            if selected_result != EffectResult.not_applicable.value:
                raise ArchiveValidationError(
                    "empty effects evidence requires not-applicable result"
                )
            values.append(
                {
                    "effectId": _not_applicable_effect_id(task_id, selected_mode),
                    "taskId": task_id,
                    "action": "none",
                    "actionId": "none",
                    "mode": selected_mode,
                    "decision": "not-applicable",
                    "result": selected_result,
                    "at": default_recorded_at,
                    "proposalId": None,
                }
            )
        else:
            if selected_result == EffectResult.not_applicable.value:
                raise ArchiveValidationError(
                    "action evidence cannot have not-applicable aggregate"
                )
            normalized: list[dict[str, Any]] = []
            for value in values:
                try:
                    evidence = _effect_evidence_model(value)
                except (TypeError, ValueError) as exc:
                    raise ArchiveValidationError(
                        "effects evidence action is malformed"
                    ) from exc
                normalized.append(evidence.as_dict())
            values = normalized
            try:
                derived = derive_effect_result(values)
            except (TypeError, ValueError) as exc:
                raise ArchiveValidationError("effects evidence is contradictory") from exc
            if selected_result and derived.value != selected_result:
                raise ArchiveConflictError(
                    "effects evidence aggregate conflicts with Store result"
                )
            selected_result = derived.value
        values.sort(key=lambda item: (str(item["at"]), str(item["effectId"])))
        raw = b"".join(_json_bytes(value) for value in values)
        _validate_effects_document(raw, task_id=task_id)
        return self.write_bytes(task_id, _EFFECTS_FILENAME, raw)

    write_effects = materialize_effects

    def effects_path(self, task_id: str) -> Path:
        return self.task_path(task_id, _EFFECTS_FILENAME)

    def effect_records(self, task_id: str) -> tuple[dict[str, Any], ...]:
        """Read and validate the private effects sidecar when present."""

        path = self.effects_path(task_id)
        if not path.exists():
            return ()
        if path.is_symlink() or not path.is_file():
            raise ArchiveValidationError("effects evidence is not a regular file")
        return _validate_effects_document(path.read_bytes(), task_id=task_id)

    validate_effects = effect_records

    def verify_rerun_source(
        self,
        task_id: str,
        *,
        expected_status: TaskStatus | str,
        expected_mode: str = "dry-run",
        expected_result: EffectResult | str,
        expected_effects: Sequence[Mapping[str, Any] | EffectEvidence] = (),
    ) -> VerifiedRerunArchive:
        """Verify the retained terminal bytes and effect sidecar together.

        A sealed archive without an effects sidecar is not enough to authorize
        a live rerun.  The sidecar is compared with Store-owned event evidence
        so old proposals, commits, and payloads cannot become execution input.
        """

        self.verify_or_raise(task_id)
        expected_mode_value = getattr(expected_mode, "value", str(expected_mode))
        try:
            manifest = json.loads(
                self.task_path(task_id, "manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("terminal manifest is unreadable") from exc
        if not isinstance(manifest, Mapping) or manifest.get("terminalStatus") != str(expected_status):
            raise ArchiveConflictError("archive terminal status disagrees with Store")
        effects = self.effect_records(task_id)
        if not effects:
            raise ArchiveSealError("rerun source has no retained effect evidence")
        selected = (
            expected_result.value
            if isinstance(expected_result, EffectResult)
            else str(expected_result)
        )
        if selected == EffectResult.applied.value:
            raise ArchiveSealError("rerun source has an applied external effect")
        if any(item.get("mode") != expected_mode_value for item in effects):
            raise ArchiveConflictError("archive effect mode disagrees with Store")
        observed_results = {str(item.get("result")) for item in effects}
        if selected == EffectResult.not_applicable.value:
            if len(effects) != 1 or observed_results != {selected}:
                raise ArchiveConflictError("archive effect aggregate disagrees with Store")
        elif selected == EffectResult.not_applied.value:
            if observed_results != {selected}:
                raise ArchiveConflictError("archive effect aggregate disagrees with Store")
        else:
            raise ArchiveValidationError("rerun source effect result is invalid")

        expected_values: list[dict[str, Any]] = []
        for item in expected_effects:
            if isinstance(item, EffectEvidence):
                value = item.as_dict()
            else:
                value = dict(item)
                try:
                    value = _effect_evidence_model(value).as_dict()
                except (TypeError, ValueError) as exc:
                    raise ArchiveValidationError(
                        "expected effect evidence is malformed"
                    ) from exc
            expected_values.append(value)
        if selected == EffectResult.not_applicable.value:
            if expected_values:
                raise ArchiveConflictError("not-applicable Store evidence is not empty")
        else:
            actual = tuple(
                json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                for value in effects
            )
            expected = tuple(
                json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                for value in sorted(
                    expected_values,
                    key=lambda value: (str(value.get("at")), str(value.get("effectId"))),
                )
            )
            if actual != expected:
                raise ArchiveConflictError("archive effect evidence disagrees with Store")
        return VerifiedRerunArchive(
            manifest_digest=self.manifest_digest(task_id),
            effects=effects,
        )

    verify_live_rerun_source = verify_rerun_source

    def _task_metadata(
        self,
        task_id: str,
        task: Mapping[str, Any] | TaskRecord | None,
        supplied: Mapping[str, Any] | None,
        pipeline_id: str | None,
    ) -> dict[str, Any]:
        if isinstance(task, TaskRecord):
            value = {
                "taskId": task.id,
                "epochId": self.epoch_id,
                "status": str(task.status),
                "promptPath": "prompt.md",
                "eventsPath": "events.jsonl",
                "createdAt": task.created_at.isoformat().replace("+00:00", "Z"),
                "updatedAt": task.updated_at.isoformat().replace("+00:00", "Z"),
                "currentPipelineId": pipeline_id,
                "summary": {"title": task.spec.title, "text": task.summary or task.spec.prompt},
                "pipelines": [],
                "terminalStatusObservedAt": None,
                "manifestPath": None,
            }
        elif task is not None:
            value = dict(_as_dict(task))
        elif supplied is not None:
            value = dict(supplied)
        else:
            value = {}
        value.setdefault("taskId", task_id)
        value.setdefault("epochId", self.epoch_id)
        value.setdefault("status", TaskStatus.queued.value)
        value.setdefault("promptPath", "prompt.md")
        value.setdefault("eventsPath", "events.jsonl")
        value.setdefault("createdAt", _now())
        value.setdefault("updatedAt", value["createdAt"])
        selected_pipeline = pipeline_id
        if selected_pipeline is None:
            selected_pipeline = value.get("currentPipelineId")
        if selected_pipeline is not None:
            validate_opaque_id(str(selected_pipeline))
        if value.get("currentPipelineId") is None:
            value["currentPipelineId"] = selected_pipeline
        value.setdefault("summary", {"title": task_id, "text": "Task created."})
        if not value.get("pipelines"):
            if selected_pipeline is None:
                raise ArchiveValidationError(
                    "task materialization requires a ledger pipeline id"
                )
            value["pipelines"] = [
                {
                    "pipelineId": selected_pipeline,
                    "ordinal": 1,
                    "path": f"pipelines/{selected_pipeline}/pipeline.json",
                }
            ]
        value.setdefault("terminalStatusObservedAt", None)
        value.setdefault("manifestPath", None)
        if value["taskId"] != task_id or value["epochId"] != self.epoch_id:
            raise ArchiveConflictError("task metadata identity does not match archive path")
        if not isinstance(value.get("pipelines"), list):
            raise ArchiveValidationError("task pipelines must be an array")
        value = _private_filtered(value)
        _validate_task_document(value)
        return value

    def write_json(self, task_id: str, relative: str, value: Mapping[str, Any] | list[Any]) -> Path:
        path = self.task_path(task_id, relative)
        data = _json_bytes(_private_filtered(value))
        self._assert_safe_archive_path(path, target="file")
        if path.exists():
            if not path.is_file():
                raise ArchiveValidationError(
                    f"archive path is not a regular file: {path}"
                )
            if path.read_bytes() == data:
                return path
        self._assert_mutable(task_id, path)
        if path.exists() and path.name.endswith(".jsonl"):
            raise ArchiveConflictError("JSONL files are append-only")
        # JSON/Markdown metadata is live and may be atomically replaced. Raw
        # evidence and JSONL use write_bytes/reconcile and remain append-only.
        self._atomic_bytes(path, data)
        return path

    def write_bytes(self, task_id: str, relative: str, data: bytes) -> Path:
        path = self.task_path(task_id, relative)
        self._assert_mutable(task_id, path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists() and path.read_bytes() == data:
            return path
        if path.exists():
            raise ArchiveConflictError(f"visible archive file differs: {path}")
        self._atomic_bytes(path, data)
        return path

    def _atomic_bytes(self, path: Path, data: bytes) -> None:
        self._assert_safe_archive_path(path, target="file")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._assert_safe_archive_path(path, target="file")
        temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _atomic_create_bytes(self, path: Path, data: bytes) -> bool:
        """Publish complete bytes only when the visible path is still absent."""
        self._assert_safe_archive_path(path, target="file")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._assert_safe_archive_path(path, target="file")
        temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                return False
            _fsync_directory(path.parent)
            return True
        finally:
            temporary.unlink(missing_ok=True)

    def reconcile(self, task_id: str, relative: str, expected: bytes | Mapping[str, Any] | list[Any]) -> str:
        data = _json_bytes(expected) if isinstance(expected, (Mapping, list)) else expected
        path = self.task_path(task_id, relative)
        self._assert_safe_archive_path(path, target="file")
        if not path.exists():
            self.write_bytes(task_id, relative, data)
            return "materialized"
        if path.is_symlink() or not path.is_file():
            raise ArchiveConflictError(f"archive path is not a regular file: {path}")
        if path.read_bytes() != data:
            raise ArchiveConflictError(f"conflicting visible archive bytes: {path}")
        return "adopted"

    def reconcile_expected(self, task_id: str, expected: Mapping[str, bytes | Mapping[str, Any] | list[Any]]) -> dict[str, str]:
        return {relative: self.reconcile(task_id, relative, value) for relative, value in expected.items()}

    def append_jsonl(
        self,
        task_id: str,
        relative: str,
        record: Mapping[str, Any] | bytes,
        *,
        generated_at: bool = False,
    ) -> int:
        path = self.task_path(task_id, relative)
        self._assert_mutable(task_id, path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._assert_safe_archive_path(path, target="file")
        line = (_json_bytes(record) if isinstance(record, Mapping) else record)
        if not line.endswith(b"\n"):
            line += b"\n"
        stable_event_id = record.get("eventId") if isinstance(record, Mapping) else None
        flags = os.O_CREAT | os.O_APPEND | os.O_RDWR
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ArchiveConflictError(f"could not open JSONL path safely: {path}") from exc
        with os.fdopen(descriptor, "r+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ArchiveConflictError(f"JSONL path is not regular: {path}")
            handle.seek(0)
            existing = handle.read()
            if existing and not existing.endswith(b"\n"):
                raise ArchiveConflictError("cannot append after incomplete JSONL line")
            if stable_event_id is not None:
                matching_offsets: list[tuple[int, bytes]] = []
                offset = 0
                for existing_line in existing.splitlines(keepends=True):
                    offset += len(existing_line)
                    try:
                        existing_record = json.loads(existing_line)
                    except json.JSONDecodeError:
                        continue
                    if (
                        isinstance(existing_record, Mapping)
                        and existing_record.get("eventId") == stable_event_id
                    ):
                        matching_offsets.append((offset, existing_line))
                if len(matching_offsets) > 1:
                    raise ArchiveConflictError(
                        f"duplicate JSONL eventId already exists: {stable_event_id}"
                    )
                if matching_offsets:
                    offset, existing_line = matching_offsets[0]
                    equivalent = existing_line == line
                    if not equivalent and generated_at:
                        try:
                            existing_value = json.loads(existing_line)
                        except json.JSONDecodeError:
                            existing_value = None
                        if isinstance(existing_value, Mapping):
                            existing_without_at = dict(existing_value)
                            requested_without_at = dict(record)
                            existing_without_at.pop("at", None)
                            requested_without_at.pop("at", None)
                            equivalent = existing_without_at == requested_without_at
                    if not equivalent:
                        raise ArchiveConflictError(
                            f"conflicting JSONL eventId reuse: {stable_event_id}"
                        )
                    return offset
            handle.seek(0, os.SEEK_END)
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
            offset = handle.tell()
        _fsync_directory(path.parent)
        return offset

    def append_event(self, task_id: str, event: Mapping[str, Any]) -> int:
        value = dict(event)
        value.setdefault("eventId", f"event-{secrets.token_hex(10)}")
        generated_at = "at" not in value
        value.setdefault("at", _now())
        if not SAFE_ID_RE.fullmatch(str(value["eventId"])):
            raise ArchiveValidationError("eventId must be an opaque safe id")
        return self.append_jsonl(
            task_id, "events.jsonl", value, generated_at=generated_at
        )

    def materialize_pipeline(
        self,
        task_id: str,
        pipeline: Mapping[str, Any] | TaskPipeline,
        *,
        pipeline_id: str | None = None,
        runs: Sequence[Mapping[str, Any] | TaskRun] | None = None,
    ) -> Path:
        value = _as_dict(pipeline)
        identifier = pipeline_id or value.get("pipelineId") or value.get("id")
        if not identifier:
            raise ArchiveValidationError("pipeline id is required")
        identifier = validate_opaque_id(str(identifier))
        value = _camelize(value)
        value.pop("id", None)
        value.pop("executionId", None)
        value.pop("execution_id", None)
        value.pop("metadata", None)
        value["pipelineId"] = identifier
        value.setdefault("taskId", task_id)
        value.setdefault("ordinal", 1)
        value.setdefault("trigger", "initial")
        value.setdefault("parentPipelineId", None)
        value.setdefault("phase", "planning")
        value.setdefault("state", "active")
        value.setdefault("baseIdentity", None)
        value.setdefault("inputIdentity", None)
        value.setdefault("outputIdentity", None)
        value.setdefault("patchIdentity", None)
        value.setdefault("startedAt", _now())
        value.setdefault("updatedAt", value["startedAt"])
        if value.get("completedAt") is None and value.get("state") != "active":
            value["completedAt"] = value["updatedAt"]
        else:
            value.setdefault("completedAt", None)
        relative = f"pipelines/{identifier}/pipeline.json"
        existing_path = self.task_path(task_id, relative)
        self._assert_safe_archive_path(existing_path, target="file")
        if existing_path.exists():
            try:
                existing = json.loads(existing_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ArchiveValidationError("pipeline.json is not valid JSON") from exc
            _validate_pipeline_document(existing)
            if existing["taskId"] != task_id or existing["pipelineId"] != identifier:
                raise ArchiveConflictError("pipeline identity does not match directory")
            # Ledger pipelines omit archive-owned graph fields. Refresh only the
            # supplied fields; never reconstruct references from orphan files.
            for key in ("inputs", "patches", "validations", "reviews", "runs", "integration"):
                value.setdefault(key, existing[key])
        for key in ("inputs", "patches", "validations", "reviews", "runs"):
            value.setdefault(key, [])
        if runs is not None:
            value["runs"] = [
                _ledger_run_reference(
                    run,
                    task_id=task_id,
                    pipeline_id=identifier,
                )
                for run in runs
            ]
            value["runs"].sort(
                key=lambda item: (item["roleOrdinal"], item["runId"])
            )
        value.setdefault(
            "integration",
            {
                "state": "pending",
                "resultPath": None,
                "commit": None,
                "startedAt": value["startedAt"],
                "completedAt": None,
            },
        )
        if value["taskId"] != task_id:
            raise ArchiveConflictError("pipeline task id does not match directory")
        value = {key: item for key, item in value.items() if key in PIPELINE_KEYS}
        _validate_pipeline_document(value)
        path = self.write_json(task_id, relative, value)
        self._add_task_pipeline_reference(task_id, identifier, int(value["ordinal"]))
        return path

    def materialize_ledger(
        self,
        task: TaskRecord,
        pipeline: TaskPipeline,
        runs: Sequence[TaskRun],
    ) -> Path:
        if not runs:
            raise ArchiveValidationError(
                "canonical pipeline materialization requires ledger runs"
            )
        _as_dict(task)
        _as_dict(pipeline)
        for run in runs:
            _as_dict(run)
        if pipeline.task_id != task.id:
            raise ArchiveConflictError("ledger pipeline does not belong to task")
        task_path = self.create_task_from_record(task, pipeline=pipeline)
        for run in runs:
            if run.task_id != task.id or run.pipeline_id != pipeline.id:
                raise ArchiveConflictError("ledger run does not belong to task pipeline")
            self.materialize_run(task.id, pipeline.id, run)
        self.materialize_pipeline(task.id, pipeline, runs=runs)
        return task_path

    def materialize_run(
        self,
        task_id: str,
        pipeline_id: str,
        run: Mapping[str, Any] | TaskRun,
        *,
        run_id: str | None = None,
    ) -> Path:
        value = _camelize(_as_dict(run))
        identifier = run_id or value.get("runId") or value.get("id")
        if not identifier:
            raise ArchiveValidationError("run id is required")
        identifier = validate_opaque_id(str(identifier))
        value["runId"] = identifier
        value.pop("id", None)
        value.pop("executionId", None)
        value.pop("execution_id", None)
        value.pop("providerRunId", None)
        value.pop("provider_run_id", None)
        value.pop("image_version", None)
        value.pop("runtime_version", None)
        value.pop("checkpoint_id", None)
        value.pop("imageVersion", None)
        value.pop("runtimeVersion", None)
        value.pop("checkpointId", None)
        exit_value = value.get("exit")
        if exit_value is None and any(
            key in value for key in ("exit_code", "exit_signal", "exit_reason")
        ):
            value["exit"] = {
                "code": value.get("exit_code"),
                "signal": value.get("exit_signal"),
                "reason": value.get("exit_reason"),
            }
        if "result_summary" in value and "result" not in value:
            summary = value.get("result_summary")
            value["result"] = {
                "status": "available" if summary is not None else "unavailable",
                "summary": summary,
                "path": None,
            }
        value.setdefault("taskId", task_id)
        value.setdefault("pipelineId", pipeline_id)
        value.setdefault("role", "unknown")
        value.setdefault("roleOrdinal", 1)
        value.setdefault("sessionId", value.get("session_id") or "session-unknown")
        value.setdefault("resumeOfRunId", None)
        value.setdefault("parentRunId", None)
        value.setdefault("retryOfRunId", None)
        value.setdefault("state", "running")
        value.setdefault("startedAt", _now())
        value.setdefault("updatedAt", value["startedAt"])
        if value.get("completedAt") is None and value.get("state") != "running":
            value["completedAt"] = value["updatedAt"]
        else:
            value.setdefault("completedAt", None)
        value.setdefault("model", None)
        value.setdefault("reasoning", None)
        value.setdefault("exit", None)
        value.setdefault("result", {"status": "unavailable", "summary": None, "path": None})
        value.setdefault("usage", _unavailable_usage())
        value.setdefault("cost", _unavailable_cost())
        value.setdefault("artifacts", _empty_artifacts(task_id, pipeline_id, identifier))
        if value["taskId"] != task_id or value["pipelineId"] != pipeline_id:
            raise ArchiveConflictError("run identity does not match directory")
        if "invocations" not in value:
            try:
                value["invocations"] = [
                    item.descriptor
                    for item in self.collect_invocation_evidence(
                        task_id,
                        pipeline_id,
                        identifier,
                        expected_run=value,
                        strict=False,
                    )
                ]
            except (ArchiveError, OSError, ValueError, TypeError):
                value["invocations"] = [
                    self._missing_invocation(
                        task_id,
                        pipeline_id,
                        identifier,
                        ordinal=0,
                        path=f"pipelines/{pipeline_id}/runs/{identifier}/telemetry.json",
                        reason="telemetry_unavailable",
                        byte_size=None,
                    ).descriptor
                ]
        value = {key: item for key, item in value.items() if key in RUN_KEYS}
        _validate_run_document(value)
        path = self.write_json(task_id, f"pipelines/{validate_opaque_id(pipeline_id)}/runs/{identifier}/run.json", value)
        self._add_pipeline_run_reference(task_id, pipeline_id, identifier, int(value["roleOrdinal"]), str(value["role"]), str(value["state"]))
        return path

    def materialize_artifact(
        self,
        task_id: str,
        relative: str,
        value: bytes | str,
        *,
        append: bool = False,
    ) -> Path:
        if append:
            self.append_jsonl(task_id, relative, value.encode("utf-8") if isinstance(value, str) else value)
            return self.task_path(task_id, relative)
        return self.write_bytes(task_id, relative, value.encode("utf-8") if isinstance(value, str) else value)

    def materialize_validation(
        self,
        task_id: str,
        pipeline_id: str,
        validation: Mapping[str, Any],
        *,
        validation_id: str | None = None,
        output: bytes | str | None = None,
    ) -> Path:
        value = _camelize(validation)
        identifier = validate_opaque_id(str(validation_id or value.get("validationId") or value.get("id") or f"validation-{secrets.token_hex(8)}"))
        value.pop("id", None)
        value["validationId"] = identifier
        value.setdefault("taskId", task_id)
        value.setdefault("pipelineId", pipeline_id)
        value.setdefault("ordinal", 1)
        value.setdefault("command", "unavailable")
        value.setdefault("state", "unavailable")
        value.setdefault("startedAt", _now())
        value.setdefault("completedAt", None)
        value.setdefault("result", "unavailable")
        output_path = value.setdefault(
            "outputPath",
            f"pipelines/{pipeline_id}/validations/{identifier}/output.log",
        )
        value.setdefault("output", _artifact_descriptor(output_path, "text/plain", output is not None))
        if output is not None:
            output_bytes = output.encode("utf-8") if isinstance(output, str) else output
            self.write_bytes(
                task_id,
                output_path,
                output_bytes,
            )
            descriptor = dict(value["output"])
            descriptor.update(
                {
                    "availability": "available",
                    "byteSize": len(output_bytes),
                    "sha256": hashlib.sha256(output_bytes).hexdigest(),
                    "reason": None,
                }
            )
            value["output"] = descriptor
        _validate_validation_document(value)
        path = self.write_json(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/validations/{identifier}/validation.json",
            value,
        )
        self._add_pipeline_validation_reference(
            task_id, pipeline_id, identifier, int(value["ordinal"])
        )
        return path

    def materialize_review(
        self,
        task_id: str,
        pipeline_id: str,
        review: Mapping[str, Any],
        *,
        review_id: str | None = None,
        kind: str | None = None,
    ) -> Path:
        value = _camelize(review)
        identifier = validate_opaque_id(str(review_id or value.get("reviewId") or value.get("id") or f"review-{secrets.token_hex(8)}"))
        value.pop("id", None)
        value["reviewId"] = identifier
        value.setdefault("taskId", task_id)
        value.setdefault("pipelineId", pipeline_id)
        value.setdefault("ordinal", 1)
        value.setdefault("kind", kind or "raw")
        value.setdefault("role", "review")
        value.setdefault("state", "unavailable")
        value.setdefault("verdict", "unavailable")
        value.setdefault("findings", [])
        value.setdefault(
            "artifact",
            {
                "path": f"pipelines/{pipeline_id}/reviews/{identifier}.json",
                "lifecycle": "terminal",
                "availability": "available",
                "mediaType": "application/json",
                "byteSize": 0,
                "sha256": None,
                "requiredAtTerminal": True,
                "reason": None,
            },
        )
        artifact = value.get("artifact")
        if isinstance(artifact, dict) and artifact.get("path") == (
            f"pipelines/{pipeline_id}/reviews/{identifier}.json"
        ):
            for _ in range(4):
                size = len(_json_bytes(value))
                if artifact.get("byteSize") == size:
                    break
                artifact["byteSize"] = size
        _validate_review_document(value)
        path = self.write_json(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/reviews/{identifier}.json",
            value,
        )
        self._add_pipeline_review_reference(
            task_id,
            pipeline_id,
            identifier,
            int(value["ordinal"]),
            str(value["kind"]),
        )
        return path

    def materialize_integration(
        self,
        task_id: str,
        pipeline_id: str,
        integration: Mapping[str, Any],
    ) -> Path:
        value = _camelize(integration)
        value.setdefault("state", "pending")
        value.setdefault("resultPath", None)
        value.setdefault("commit", None)
        value.setdefault("startedAt", _now())
        value.setdefault("completedAt", None)
        _validate_integration(value)
        return self.write_json(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/integration.json",
            value,
        )

    def append_run_jsonl(
        self,
        task_id: str,
        pipeline_id: str,
        run_id: str,
        name: str,
        record: Mapping[str, Any] | bytes,
    ) -> int:
        if name not in {"codex.jsonl", "activities.jsonl", "tool-changes/manifest.jsonl"}:
            raise ArchiveValidationError(f"unsupported run JSONL artifact: {name}")
        return self.append_jsonl(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/runs/{validate_opaque_id(run_id)}/{name}",
            record,
        )

    def write_run_file(
        self,
        task_id: str,
        pipeline_id: str,
        run_id: str,
        name: str,
        value: bytes | str | Mapping[str, Any],
    ) -> Path:
        if name in {"telemetry.json", "result.json", "tool-changes/summary.json"} and isinstance(value, Mapping):
            payload: bytes | str = _json_bytes(_private_filtered(value))
        elif isinstance(value, Mapping):
            payload = _json_bytes(_private_filtered(value))
        else:
            payload = value.encode("utf-8") if isinstance(value, str) else value
        return self.write_bytes(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/runs/{validate_opaque_id(run_id)}/{validate_relative_path(name)}",
            payload,
        )

    def seal(
        self,
        task_id: str,
        terminal_status: str | TaskStatus,
        *,
        completion_identity: str | None = None,
        completed_at: str | None = None,
        external_actions_complete: bool = False,
        writer_final: bool = False,
        ready: bool | None = None,
        external_actions_declared: bool | None = None,
        no_active_writers: bool | None = None,
        completion_id: str | None = None,
    ) -> Path:
        if external_actions_declared is not None:
            external_actions_complete = external_actions_declared
        if no_active_writers is not None:
            writer_final = no_active_writers
        if completion_identity is None:
            completion_identity = completion_id
        if ready is not None:
            external_actions_complete = writer_final = bool(ready)
        status = str(terminal_status)
        if status not in TERMINAL_TASK_STATUSES:
            raise ArchiveSealError(f"task status is not terminal: {status}")
        if not external_actions_complete or not writer_final:
            raise ArchiveSealError("sealing requires external actions and writer finality")
        if completion_identity is None or completed_at is None:
            raise ArchiveSealError(
                "sealing requires stable completion identity and timestamp"
            )
        validate_opaque_id(completion_identity)
        _validate_timestamp(completed_at, "manifest.completedAt")
        task_dir = self.task_dir(task_id)
        try:
            self._assert_safe_archive_path(task_dir, target="directory")
        except ArchiveValidationError as exc:
            raise ArchiveSealError(str(exc)) from exc
        if not task_dir.is_dir():
            raise ArchiveSealError(f"task archive does not exist: {task_id}")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(task_dir, flags)
        except OSError as exc:
            raise ArchiveSealError(f"could not lock task archive: {task_id}") from exc
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return self._seal_locked(
                task_id,
                status,
                completion_identity,
                completed_at,
            )
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _seal_locked(
        self,
        task_id: str,
        status: str,
        completion_identity: str,
        completed_at: str,
    ) -> Path:
        task_dir = self.task_dir(task_id)
        manifest_path = task_dir / "manifest.json"
        if manifest_path.exists():
            self._verify_manifest_path(task_id, manifest_path)
            try:
                existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveSealError("invalid terminal manifest") from exc
            if existing_manifest.get("terminalStatus") != status:
                raise ArchiveConflictError("terminal status conflicts with manifest")
            if existing_manifest.get("completionIdentity") != completion_identity:
                raise ArchiveConflictError("completion identity conflicts with manifest")
            if existing_manifest.get("completedAt") != completed_at:
                raise ArchiveConflictError("completion timestamp conflicts with manifest")
            return manifest_path
        self._reconcile_hidden(task_dir)
        self._validate_tree_paths(task_dir)
        self._validate_task_graph(task_id, status)
        self._record_completion(
            task_id,
            status=status,
            completion_identity=completion_identity,
            completed_at=completed_at,
        )
        self._validate_task_graph(task_id, status)
        files: list[dict[str, Any]] = []
        for path in sorted(task_dir.rglob("*")):
            relative = path.relative_to(task_dir).as_posix()
            hidden_parts = [part for part in Path(relative).parts if part.startswith(".")]
            if hidden_parts:
                if path.is_file() and all(TEMPORARY_RE.fullmatch(part) for part in hidden_parts):
                    continue
                raise ArchiveSealError(f"unknown hidden archive path: {relative}")
            if relative == "manifest.json":
                continue
            if path.is_symlink():
                raise ArchiveSealError(f"symlinked archive path: {relative}")
            if path.is_dir():
                continue
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ArchiveSealError(f"non-regular visible archive path: {relative}")
            data = path.read_bytes()
            files.append({"path": validate_relative_path(relative), "byteSize": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        if not files:
            raise ArchiveSealError("cannot seal an empty task archive")
        manifest = {
            "manifestVersion": FORMAT_VERSION,
            "epochId": self.ensure_epoch()["epochId"],
            "taskId": validate_opaque_id(task_id),
            "completionIdentity": completion_identity,
            "terminalStatus": status,
            "completedAt": completed_at,
            "files": files,
        }
        manifest_bytes = _json_bytes(manifest)
        if not self._atomic_create_bytes(manifest_path, manifest_bytes):
            self._verify_manifest_path(task_id, manifest_path)
            if manifest_path.read_bytes() != manifest_bytes:
                raise ArchiveConflictError(
                    "another completion already sealed the task archive"
                )
        return manifest_path

    def _record_completion(
        self,
        task_id: str,
        *,
        status: str,
        completion_identity: str,
        completed_at: str,
    ) -> None:
        task_path = self.task_path(task_id, "task.json")
        try:
            task = json.loads(task_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("task.json is not valid JSON") from exc
        if not isinstance(task, dict):
            raise ArchiveSealError("task.json must contain an object")
        if task.get("status") != status:
            raise ArchiveSealError("task metadata status is not terminal status")
        manifest_reference = task.get("manifestPath")
        if manifest_reference not in {None, "manifest.json"}:
            raise ArchiveConflictError("task manifest path conflicts with completion")
        observed_at = task.get("terminalStatusObservedAt")
        if observed_at is not None and observed_at != completed_at:
            raise ArchiveConflictError("completion timestamp conflicts with task metadata")

        event = self._completion_event(
            task_id,
            status=status,
            completion_identity=completion_identity,
            completed_at=completed_at,
        )
        events_path = self.task_path(task_id, "events.jsonl")
        existing_completion: list[Mapping[str, Any]] = []
        try:
            lines = events_path.read_bytes().splitlines()
            for line in lines:
                value = json.loads(line)
                if isinstance(value, Mapping) and value.get("kind") == "archive.frozen":
                    existing_completion.append(value)
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveConflictError("task completion events are invalid") from exc
        if existing_completion:
            if len(existing_completion) != 1 or existing_completion[0] != event:
                raise ArchiveConflictError("completion identity conflicts with task events")
        else:
            self.append_event(task_id, event)

        task["manifestPath"] = "manifest.json"
        task["terminalStatusObservedAt"] = completed_at
        self.write_json(task_id, "task.json", task)

    def _completion_event(
        self,
        task_id: str,
        *,
        status: str,
        completion_identity: str,
        completed_at: str,
    ) -> dict[str, Any]:
        suffix = hashlib.sha256(completion_identity.encode("utf-8")).hexdigest()[:24]
        return {
            "eventId": f"event-archive-{suffix}",
            "kind": "archive.frozen",
            "at": completed_at,
            "epochId": self.ensure_epoch()["epochId"],
            "taskId": task_id,
            "completionIdentity": completion_identity,
            "terminalStatus": status,
            "completedAt": completed_at,
        }

    def verify(self, task_id: str) -> bool:
        manifest_path = self.task_dir(task_id) / "manifest.json"
        if not manifest_path.exists():
            return False
        try:
            self._verify_manifest_path(task_id, manifest_path)
        except ArchiveError:
            return False
        return True

    def verify_or_raise(self, task_id: str) -> bool:
        manifest_path = self.task_dir(task_id) / "manifest.json"
        self._verify_manifest_path(task_id, manifest_path)
        return True

    def manifest_digest(self, task_id: str) -> str:
        """Verify one sealed archive and return its immutable manifest digest."""

        task_id = validate_opaque_id(task_id)
        manifest_path = self.task_dir(task_id) / "manifest.json"
        self._verify_manifest_path(task_id, manifest_path)
        return hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    def delete_verified(
        self,
        task_id: str,
        *,
        allow_absent: bool = False,
        return_digest: bool = False,
        expected_digest: str | None = None,
    ) -> str:
        """Remove one exact, sealed task child after re-verifying its manifest.

        ``allow_absent`` is reserved for restart reconciliation after a durable
        deletion intent has already been verified.  A normal deletion refuses
        an absent archive so a missing path cannot be mistaken for a completed
        destructive action.  When supplied, ``expected_digest`` is checked
        after manifest verification and before any deletion side effect.
        """

        task_id = validate_opaque_id(task_id)
        root = self.root
        try:
            root_mode = root.lstat().st_mode
        except FileNotFoundError as exc:
            raise ArchiveValidationError("archive root is missing") from exc
        if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
            raise ArchiveValidationError("archive root must be a directory")

        task_dir = self.task_dir(task_id)
        if task_dir == root or task_dir.parent != root:
            raise ArchiveValidationError("task archive is not a direct root child")
        try:
            task_mode = task_dir.lstat().st_mode
        except FileNotFoundError as exc:
            if allow_absent:
                _fsync_directory(root)
                return "absent"
            raise ArchiveValidationError(
                "task archive is absent before a durable deletion intent"
            ) from exc
        if stat.S_ISLNK(task_mode):
            raise ArchiveValidationError("task archive must not be a symlink")
        if not stat.S_ISDIR(task_mode):
            raise ArchiveValidationError("task archive must be a directory")

        resolved_root = root.resolve(strict=True)
        resolved_task = task_dir.resolve(strict=True)
        if resolved_task == resolved_root or resolved_task.parent != resolved_root:
            raise ArchiveValidationError("task archive escapes the configured root")

        manifest_path = task_dir / "manifest.json"
        self._verify_manifest_path(task_id, manifest_path)
        manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if expected_digest is not None and manifest_digest != expected_digest:
            raise ArchiveConflictError(
                "terminal manifest digest does not match deletion intent"
            )
        try:
            shutil.rmtree(task_dir)
        except FileNotFoundError as exc:
            if allow_absent and not task_dir.exists():
                _fsync_directory(root)
                return "absent"
            raise ArchiveValidationError("task archive disappeared during deletion") from exc
        _fsync_directory(root)
        if task_dir.exists() or task_dir.is_symlink():
            raise ArchiveConflictError("task archive remains after deletion")
        return manifest_digest if return_digest else "deleted"

    def _add_task_pipeline_reference(self, task_id: str, pipeline_id: str, ordinal: int) -> None:
        path = self.task_path(task_id, "task.json")
        if not path.is_file():
            return
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveValidationError("task.json is not valid JSON") from exc
        references = metadata.setdefault("pipelines", [])
        if not isinstance(references, list):
            raise ArchiveValidationError("task pipelines must be an array")
        reference = {
            "pipelineId": pipeline_id,
            "ordinal": ordinal,
            "path": f"pipelines/{pipeline_id}/pipeline.json",
        }
        if not any(item.get("pipelineId") == pipeline_id for item in references if isinstance(item, Mapping)):
            references.append(reference)
            references.sort(key=lambda item: (int(item.get("ordinal", 0)), str(item.get("pipelineId", ""))))
        if metadata.get("currentPipelineId") is None:
            metadata["currentPipelineId"] = pipeline_id
        self.write_json(task_id, "task.json", metadata)

    def _add_pipeline_run_reference(
        self,
        task_id: str,
        pipeline_id: str,
        run_id: str,
        role_ordinal: int,
        role: str,
        state: str,
    ) -> None:
        path = self.task_path(task_id, f"pipelines/{pipeline_id}/pipeline.json")
        if not path.is_file():
            return
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveValidationError("pipeline.json is not valid JSON") from exc
        references = metadata.setdefault("runs", [])
        if not isinstance(references, list):
            raise ArchiveValidationError("pipeline runs must be an array")
        reference = {
            "runId": run_id,
            "role": role,
            "roleOrdinal": role_ordinal,
            "state": state,
            "path": f"pipelines/{pipeline_id}/runs/{run_id}/run.json",
        }
        for index, item in enumerate(references):
            if isinstance(item, Mapping) and item.get("runId") == run_id:
                references[index] = reference
                break
        else:
            references.append(reference)
        references.sort(key=lambda item: (int(item.get("roleOrdinal", 0)), str(item.get("runId", ""))))
        self.write_json(task_id, f"pipelines/{pipeline_id}/pipeline.json", metadata)

    def _add_pipeline_validation_reference(
        self,
        task_id: str,
        pipeline_id: str,
        validation_id: str,
        ordinal: int,
    ) -> None:
        path = self.task_path(task_id, f"pipelines/{pipeline_id}/pipeline.json")
        if not path.is_file():
            return
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveValidationError("pipeline.json is not valid JSON") from exc
        references = metadata.setdefault("validations", [])
        reference = {
            "validationId": validation_id,
            "ordinal": ordinal,
            "path": (
                f"pipelines/{pipeline_id}/validations/{validation_id}/validation.json"
            ),
        }
        for index, item in enumerate(references):
            if isinstance(item, Mapping) and item.get("validationId") == validation_id:
                references[index] = reference
                break
        else:
            references.append(reference)
        references.sort(
            key=lambda item: (
                int(item.get("ordinal", 0)),
                str(item.get("validationId", "")),
            )
        )
        self.write_json(task_id, f"pipelines/{pipeline_id}/pipeline.json", metadata)

    def _add_pipeline_review_reference(
        self,
        task_id: str,
        pipeline_id: str,
        review_id: str,
        ordinal: int,
        kind: str,
    ) -> None:
        path = self.task_path(task_id, f"pipelines/{pipeline_id}/pipeline.json")
        if not path.is_file():
            return
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveValidationError("pipeline.json is not valid JSON") from exc
        references = metadata.setdefault("reviews", [])
        reference = {
            "reviewId": review_id,
            "kind": kind,
            "ordinal": ordinal,
            "path": f"pipelines/{pipeline_id}/reviews/{review_id}.json",
        }
        for index, item in enumerate(references):
            if isinstance(item, Mapping) and item.get("reviewId") == review_id:
                references[index] = reference
                break
        else:
            references.append(reference)
        references.sort(
            key=lambda item: (
                int(item.get("ordinal", 0)),
                str(item.get("reviewId", "")),
            )
        )
        self.write_json(task_id, f"pipelines/{pipeline_id}/pipeline.json", metadata)

    def _verify_manifest_path(self, task_id: str, manifest_path: Path) -> None:
        task_id = validate_opaque_id(task_id)
        task_dir = self.task_dir(task_id)
        try:
            self._assert_safe_archive_path(task_dir, target="directory")
            self._assert_safe_archive_path(manifest_path, target="file")
            self._assert_safe_archive_path(self.epoch_path, target="file")
        except ArchiveValidationError as exc:
            raise ArchiveSealError(str(exc)) from exc
        if not manifest_path.exists() or not self.epoch_path.exists():
            raise ArchiveSealError("terminal manifest or archive epoch is missing")
        try:
            raw_manifest = manifest_path.read_bytes()
            manifest = json.loads(raw_manifest.decode("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("invalid terminal manifest") from exc
        try:
            _validate_manifest_document(manifest)
        except ArchiveValidationError as exc:
            raise ArchiveSealError(f"invalid terminal manifest schema: {exc}") from exc
        if manifest["taskId"] != task_id:
            raise ArchiveSealError("manifest task identity mismatch")
        if raw_manifest != _json_bytes(manifest):
            raise ArchiveSealError("terminal manifest bytes are not canonical")
        try:
            epoch = json.loads(self.epoch_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("archive epoch is invalid") from exc
        if not self._valid_epoch(epoch) or manifest["epochId"] != epoch["epochId"]:
            raise ArchiveSealError("manifest epoch identity mismatch")
        self._validate_tree_paths(task_dir)
        self._validate_task_graph(task_id, manifest["terminalStatus"])
        self._validate_completion_binding(task_id, manifest)
        expected: dict[str, Mapping[str, Any]] = {}
        for descriptor in manifest["files"]:
            relative = descriptor["path"]
            if relative in expected:
                raise ArchiveSealError("manifest contains duplicate file paths")
            expected[relative] = descriptor
        actual: dict[str, Path] = {}
        for path in task_dir.rglob("*"):
            relative = path.relative_to(task_dir).as_posix()
            hidden_parts = [part for part in Path(relative).parts if part.startswith(".")]
            if hidden_parts:
                if path.is_file() and all(TEMPORARY_RE.fullmatch(part) for part in hidden_parts):
                    continue
                raise ArchiveSealError(f"unknown hidden archive path: {relative}")
            if relative == "manifest.json":
                continue
            if path.is_dir():
                continue
            actual[relative] = path
        if set(expected) != set(actual):
            raise ArchiveSealError("terminal manifest coverage does not match visible files")
        ordered = [item.get("path") for item in manifest["files"]]
        if ordered != sorted(ordered):
            raise ArchiveSealError("manifest file list is not canonical")
        for relative, descriptor in expected.items():
            data = actual[relative].read_bytes()
            if descriptor.get("byteSize") != len(data) or descriptor.get("sha256") != hashlib.sha256(data).hexdigest():
                raise ArchiveSealError(f"terminal file hash mismatch: {relative}")

    def _validate_completion_binding(
        self,
        task_id: str,
        manifest: Mapping[str, Any],
    ) -> None:
        events_path = self.task_path(task_id, "events.jsonl")
        try:
            data = events_path.read_bytes()
            if data and not data.endswith(b"\n"):
                raise ArchiveSealError("task completion events have an incomplete line")
            completion_events = []
            for line in data.splitlines():
                value = json.loads(line)
                if isinstance(value, Mapping) and value.get("kind") == "archive.frozen":
                    completion_events.append(value)
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("task completion events are invalid") from exc
        expected = self._completion_event(
            task_id,
            status=str(manifest["terminalStatus"]),
            completion_identity=str(manifest["completionIdentity"]),
            completed_at=str(manifest["completedAt"]),
        )
        if completion_events != [expected]:
            raise ArchiveSealError(
                "terminal manifest completion does not match the task graph"
            )
        try:
            task = json.loads(
                self.task_path(task_id, "task.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("task.json is not valid JSON") from exc
        if (
            not isinstance(task, Mapping)
            or task.get("terminalStatusObservedAt") != manifest["completedAt"]
            or task.get("manifestPath") != "manifest.json"
        ):
            raise ArchiveSealError(
                "task metadata does not bind the terminal manifest"
            )

    def _validate_task_graph(self, task_id: str, status: str) -> None:
        task_dir = self.task_dir(task_id)

        def load_document(path: Path, label: str) -> Mapping[str, Any]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveSealError(f"{label} is not valid JSON") from exc
            if not isinstance(value, Mapping):
                raise ArchiveSealError(f"{label} must be an object")
            return value

        task_path = self.task_dir(task_id) / "task.json"
        if not task_path.is_file():
            raise ArchiveSealError("task.json is required before sealing")
        task = load_document(task_path, "task.json")
        try:
            _validate_task_document(task)
        except ArchiveValidationError as exc:
            raise ArchiveSealError(f"task schema is invalid: {exc}") from exc
        if task.get("taskId") != task_id or task.get("epochId") != self.ensure_epoch()["epochId"]:
            raise ArchiveSealError("task metadata identity mismatch")
        if task.get("status") != status:
            raise ArchiveSealError("task metadata status is not terminal status")
        if task.get("promptPath") != "prompt.md" or task.get("eventsPath") != "events.jsonl":
            raise ArchiveSealError("task metadata has invalid canonical paths")
        if not (self.task_dir(task_id) / "prompt.md").is_file() or not (self.task_dir(task_id) / "events.jsonl").is_file():
            raise ArchiveSealError("prompt.md and events.jsonl are required")
        effects_path = self.task_path(task_id, _EFFECTS_FILENAME)
        if effects_path.exists():
            try:
                _validate_effects_document(effects_path.read_bytes(), task_id=task_id)
            except ArchiveError as exc:
                raise ArchiveSealError(f"effects evidence is invalid: {exc}") from exc
        pipelines = task.get("pipelines")
        if not isinstance(pipelines, list) or not pipelines:
            raise ArchiveSealError("task metadata must reference at least one pipeline")
        pipeline_ids: set[str] = set()
        pipeline_ordinals: set[int] = set()
        parent_ids: dict[str, str | None] = {}
        for reference in pipelines:
            pipeline_id = reference["pipelineId"]
            relative = reference["path"]
            if pipeline_id in pipeline_ids or relative != f"pipelines/{pipeline_id}/pipeline.json":
                raise ArchiveSealError("pipeline references are not canonical")
            if reference["ordinal"] in pipeline_ordinals:
                raise ArchiveSealError("pipeline ordinals are not unique")
            pipeline_ids.add(pipeline_id)
            pipeline_ordinals.add(reference["ordinal"])
            pipeline_path = self.task_path(task_id, relative)
            if not pipeline_path.is_file():
                raise ArchiveSealError(f"missing pipeline metadata: {relative}")
            pipeline = load_document(pipeline_path, relative)
            try:
                _validate_pipeline_document(pipeline)
            except ArchiveValidationError as exc:
                raise ArchiveSealError(f"pipeline schema is invalid: {exc}") from exc
            if pipeline.get("pipelineId") != pipeline_id or pipeline.get("taskId") != task_id:
                raise ArchiveSealError("pipeline identity does not match task graph")
            if pipeline["ordinal"] != reference["ordinal"]:
                raise ArchiveSealError("pipeline ordinal disagrees with task graph")
            parent_ids[pipeline_id] = pipeline.get("parentPipelineId")
            if pipeline.get("state") in {"active", "interrupted"}:
                raise ArchiveSealError("cannot seal while a pipeline is active or interrupted")
            for descriptor in (*pipeline["inputs"], *pipeline["patches"]):
                self._validate_artifact_evidence(task_id, descriptor)
            validation_paths: set[str] = set()
            for validation_reference in pipeline["validations"]:
                validation_id = validation_reference["validationId"]
                validation_relative = validation_reference["path"]
                expected_validation = (
                    f"pipelines/{pipeline_id}/validations/{validation_id}/validation.json"
                )
                if validation_relative != expected_validation or validation_relative in validation_paths:
                    raise ArchiveSealError("validation references are not canonical")
                validation_paths.add(validation_relative)
                validation = load_document(
                    self.task_path(task_id, validation_relative), validation_relative
                )
                try:
                    _validate_validation_document(validation)
                except ArchiveValidationError as exc:
                    raise ArchiveSealError(f"validation schema is invalid: {exc}") from exc
                if (
                    validation["validationId"] != validation_id
                    or validation["taskId"] != task_id
                    or validation["pipelineId"] != pipeline_id
                    or validation["ordinal"] != validation_reference["ordinal"]
                ):
                    raise ArchiveSealError("validation identity disagrees with graph")
                self._validate_artifact_evidence(task_id, validation["output"])
            actual_validation_paths = {
                path.relative_to(task_dir).as_posix()
                for path in self.pipeline_dir(task_id, pipeline_id).glob(
                    "validations/*/validation.json"
                )
            }
            if actual_validation_paths != validation_paths:
                raise ArchiveSealError("validation graph coverage is not exact")
            review_paths: set[str] = set()
            for review_reference in pipeline["reviews"]:
                review_id = review_reference["reviewId"]
                review_relative = review_reference["path"]
                expected_review = f"pipelines/{pipeline_id}/reviews/{review_id}.json"
                if review_relative != expected_review or review_relative in review_paths:
                    raise ArchiveSealError("review references are not canonical")
                review_paths.add(review_relative)
                review = load_document(
                    self.task_path(task_id, review_relative), review_relative
                )
                try:
                    _validate_review_document(review)
                except ArchiveValidationError as exc:
                    raise ArchiveSealError(f"review schema is invalid: {exc}") from exc
                if (
                    review["reviewId"] != review_id
                    or review["taskId"] != task_id
                    or review["pipelineId"] != pipeline_id
                    or review["ordinal"] != review_reference["ordinal"]
                    or review["kind"] != review_reference["kind"]
                ):
                    raise ArchiveSealError("review identity disagrees with graph")
                self._validate_artifact_evidence(task_id, review["artifact"])
            actual_review_paths = {
                path.relative_to(task_dir).as_posix()
                for path in self.pipeline_dir(task_id, pipeline_id).glob("reviews/*.json")
            }
            if actual_review_paths != review_paths:
                raise ArchiveSealError("review graph coverage is not exact")
            run_paths: set[str] = set()
            run_documents: dict[str, Mapping[str, Any]] = {}
            runs = pipeline["runs"]
            for run_reference in runs:
                run_id = run_reference["runId"]
                run_relative = run_reference["path"]
                expected_run_path = f"pipelines/{pipeline_id}/runs/{run_id}/run.json"
                if run_relative != expected_run_path or run_relative in run_paths:
                    raise ArchiveSealError("run reference is not canonical")
                run_paths.add(run_relative)
                run_path = self.task_path(task_id, run_relative)
                if not run_path.is_file():
                    raise ArchiveSealError(f"missing run metadata: {run_relative}")
                run = load_document(run_path, run_relative)
                try:
                    _validate_run_document(run)
                except ArchiveValidationError as exc:
                    raise ArchiveSealError(f"run schema is invalid: {exc}") from exc
                if run.get("runId") != run_id or run.get("taskId") != task_id or run.get("pipelineId") != pipeline_id:
                    raise ArchiveSealError("run identity does not match task graph")
                if any(
                    run[key] != run_reference[key]
                    for key in ("role", "roleOrdinal", "state")
                ):
                    raise ArchiveSealError("run reference disagrees with run metadata")
                if run.get("state") == "running":
                    raise ArchiveSealError("cannot seal while a run is running")
                try:
                    collected_invocations = self.collect_invocation_evidence(
                        task_id,
                        pipeline_id,
                        run_id,
                        expected_run=run,
                    )
                except ArchiveError as exc:
                    raise ArchiveSealError(
                        f"run invocation evidence is invalid: {exc}"
                    ) from exc
                if self._canonical_invocation_descriptors(
                    run["invocations"]
                ) != self._canonical_invocation_descriptors(collected_invocations):
                    raise ArchiveSealError(
                        "run invocation descriptors disagree with sidecars"
                    )
                run_documents[run_id] = run
                artifacts = run["artifacts"]
                for descriptor in artifacts.values():
                    self._validate_artifact_evidence(task_id, descriptor)
            actual_run_paths = {
                path.relative_to(task_dir).as_posix()
                for path in self.pipeline_dir(task_id, pipeline_id).glob(
                    "runs/*/run.json"
                )
            }
            if actual_run_paths != run_paths:
                raise ArchiveSealError("run graph coverage is not exact")
            for run_id, run in run_documents.items():
                for relation in ("parentRunId", "retryOfRunId"):
                    related = run[relation]
                    if related is not None and related not in run_documents:
                        raise ArchiveSealError(
                            f"run {relation} leaves its owning pipeline: {run_id}"
                        )
                resumed = run["resumeOfRunId"]
                if resumed is not None:
                    predecessor = run_documents.get(resumed)
                    if predecessor is None:
                        raise ArchiveSealError("recovery predecessor is missing")
                    if (
                        predecessor["state"] != "interrupted"
                        or predecessor["role"] != run["role"]
                        or predecessor["sessionId"] != run["sessionId"]
                    ):
                        raise ArchiveSealError("recovery lineage is invalid")
            if pipeline.get("state") != "active" and not pipeline.get("completedAt"):
                raise ArchiveSealError("terminal pipeline is missing completedAt")
        actual_pipeline_paths = {
            path.relative_to(task_dir).as_posix()
            for path in (task_dir / "pipelines").glob("*/pipeline.json")
        }
        expected_pipeline_paths = {
            reference["path"] for reference in pipelines
        }
        if actual_pipeline_paths != expected_pipeline_paths:
            raise ArchiveSealError("pipeline graph coverage is not exact")
        for pipeline_id, parent_id in parent_ids.items():
            if parent_id is not None and parent_id not in pipeline_ids:
                raise ArchiveSealError(f"pipeline parent is missing: {pipeline_id}")
            seen: set[str] = set()
            current: str | None = pipeline_id
            while current is not None:
                if current in seen:
                    raise ArchiveSealError("pipeline parent graph contains a cycle")
                seen.add(current)
                current = parent_ids.get(current)
        current_pipeline = task.get("currentPipelineId")
        if current_pipeline is not None and current_pipeline not in pipeline_ids:
            raise ArchiveSealError("current pipeline is missing from task graph")
        for jsonl_path in self.task_dir(task_id).rglob("*.jsonl"):
            if jsonl_path.is_symlink() or not jsonl_path.is_file():
                raise ArchiveSealError(f"JSONL path is not regular: {jsonl_path.relative_to(self.task_dir(task_id))}")
            data = jsonl_path.read_bytes()
            if data and not data.endswith(b"\n"):
                raise ArchiveSealError(f"JSONL ends with an incomplete record: {jsonl_path.relative_to(self.task_dir(task_id))}")
            for line in data.splitlines():
                try:
                    json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ArchiveSealError(f"JSONL contains an invalid record: {jsonl_path.relative_to(self.task_dir(task_id))}") from exc

    def _validate_artifact_evidence(
        self, task_id: str, descriptor: Mapping[str, Any]
    ) -> None:
        relative = descriptor["path"]
        availability = descriptor["availability"]
        if descriptor["requiredAtTerminal"] and availability not in {
            "available",
            "partial",
        }:
            raise ArchiveSealError(f"required terminal artifact is unavailable: {relative}")
        if availability not in {"available", "partial"}:
            return
        path = self.task_path(task_id, relative)
        if not path.is_file():
            raise ArchiveSealError(f"available artifact is missing: {relative}")
        data = path.read_bytes()
        if descriptor["byteSize"] is not None and descriptor["byteSize"] != len(data):
            raise ArchiveSealError(f"artifact size disagrees: {relative}")
        if (
            descriptor["sha256"] is not None
            and descriptor["sha256"] != hashlib.sha256(data).hexdigest()
        ):
            raise ArchiveSealError(f"artifact hash disagrees: {relative}")

    @staticmethod
    def _validate_tree_paths(task_dir: Path) -> None:
        for path in task_dir.rglob("*"):
            relative = path.relative_to(task_dir).as_posix()
            if path.is_symlink():
                raise ArchiveSealError(f"symlinked archive path: {relative}")
            mode = path.lstat().st_mode
            if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
                raise ArchiveSealError(f"non-regular archive path: {relative}")
            hidden_parts = [part for part in Path(relative).parts if part.startswith(".")]
            if hidden_parts and not (
                stat.S_ISREG(mode)
                and all(TEMPORARY_RE.fullmatch(part) for part in hidden_parts)
            ):
                raise ArchiveSealError(f"unknown hidden archive path: {relative}")

    @staticmethod
    def _reconcile_hidden(task_dir: Path) -> None:
        # Hidden temporary files are incomplete generations and are not public.
        # They are intentionally ignored; a caller can retry the seal safely.
        for path in task_dir.rglob("*"):
            if not path.name.startswith("."):
                continue
            if (
                not path.is_symlink()
                and stat.S_ISREG(path.lstat().st_mode)
                and TEMPORARY_RE.fullmatch(path.name)
            ):
                continue
            raise ArchiveSealError(f"unknown hidden archive path: {path.relative_to(task_dir)}")

    def _assert_mutable(self, task_id: str, path: Path) -> None:
        manifest = self.task_dir(task_id) / "manifest.json"
        if manifest.exists():
            raise ArchiveImmutableError(f"task archive is terminally sealed: {task_id}")
        task_dir = self.task_dir(task_id)
        self._assert_safe_archive_path(task_dir, target="directory")
        self._assert_safe_archive_path(path, target="file")
        try:
            relative_parent = path.parent.relative_to(task_dir)
        except ValueError as exc:
            raise ArchiveValidationError("archive path escapes task directory") from exc
        current = task_dir
        for component in relative_parent.parts:
            current = current / component
            if current.is_symlink():
                raise ArchiveValidationError(f"archive parent must not be a symlink: {current}")
        # Completed evidence is immutable while the task is still live too.
        # Check the owning metadata even when a new artifact path is being
        # created under a completed pipeline/run directory.
        pipeline_json = next(
            (parent / "pipeline.json" for parent in path.parents if (parent / "pipeline.json").exists()),
            None,
        )
        if pipeline_json is not None:
            try:
                pipeline_state = json.loads(pipeline_json.read_text(encoding="utf-8")).get("state")
            except (OSError, json.JSONDecodeError):
                pipeline_state = None
            if pipeline_state in {"succeeded", "failed", "blocked", "cancelled", "superseded"}:
                raise ArchiveImmutableError(f"completed pipeline evidence is immutable: {path}")
        run_json = next(
            (parent / "run.json" for parent in path.parents if (parent / "run.json").exists()),
            None,
        )
        if run_json is not None:
            try:
                run_state = json.loads(run_json.read_text(encoding="utf-8")).get("state")
            except (OSError, json.JSONDecodeError):
                run_state = None
            if run_state in {"succeeded", "failed", "interrupted", "cancelled"}:
                raise ArchiveImmutableError(f"completed run evidence is immutable: {path}")

    def _assert_safe_archive_path(self, path: Path, *, target: str) -> None:
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise ArchiveValidationError("archive path escapes configured root") from exc
        current = self.root
        components = (Path("."), *relative.parts)
        for index, component in enumerate(components):
            if component != Path("."):
                current = current / component
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                break
            if stat.S_ISLNK(mode):
                raise ArchiveValidationError(f"archive path component is a symlink: {current}")
            is_target = index == len(components) - 1
            expected = target if is_target else "directory"
            if expected == "directory" and not stat.S_ISDIR(mode):
                raise ArchiveValidationError(
                    f"archive path component is not a directory: {current}"
                )
            if expected == "file" and not stat.S_ISREG(mode):
                raise ArchiveValidationError(
                    f"archive path is not a regular file: {current}"
                )


class TaskArchiveWriter(TaskArchive):
    """Explicit name for callers that distinguish the writer from verifier."""




def archive_for(config_or_root: Path | Any, *, epoch_id: str | None = None) -> TaskArchive:
    return TaskArchive(config_or_root, epoch_id=epoch_id)


def ensure_epoch(config_or_root: Path | Any, *, epoch_id: str | None = None) -> dict[str, Any]:
    return TaskArchive(config_or_root, epoch_id=epoch_id).ensure_epoch()


def verify_archive(config_or_root: Path | Any, task_id: str) -> bool:
    return TaskArchive(config_or_root).verify(task_id)


def collect_invocation_evidence(
    config_or_root: Path | Any,
    task_id: str,
    pipeline_id: str,
    run_id: str,
    *,
    expected_run: Mapping[str, Any] | TaskRun | None = None,
    strict: bool = True,
) -> tuple[ArchiveInvocation, ...]:
    """Collect one bounded run's invocation evidence from an archive root."""

    return TaskArchive(config_or_root).collect_invocation_evidence(
        task_id,
        pipeline_id,
        run_id,
        expected_run=expected_run,
        strict=strict,
    )


def _camelize(value: Mapping[str, Any]) -> dict[str, Any]:
    names = {
        "task_id": "taskId",
        "pipeline_id": "pipelineId",
        "parent_pipeline_id": "parentPipelineId",
        "base_identity": "baseIdentity",
        "input_identity": "inputIdentity",
        "output_identity": "outputIdentity",
        "patch_identity": "patchIdentity",
        "started_at": "startedAt",
        "updated_at": "updatedAt",
        "completed_at": "completedAt",
        "run_id": "runId",
        "role_ordinal": "roleOrdinal",
        "session_id": "sessionId",
        "resume_of_run_id": "resumeOfRunId",
        "parent_run_id": "parentRunId",
        "retry_of_run_id": "retryOfRunId",
    }
    return {names.get(str(key), str(key)): _private_filtered(item) for key, item in value.items()}


def _unavailable_usage() -> dict[str, Any]:
    return {"availability": "unavailable", "promptTokens": None, "completionTokens": None, "totalTokens": None, "sourcePath": None, "reason": "usage was not produced"}


def _unavailable_cost() -> dict[str, Any]:
    return {"availability": "unavailable", "estimatedMicroUsd": None, "currency": None, "model": None, "pricingSource": None, "reason": "cost was not produced"}


def _empty_artifacts(task_id: str, pipeline_id: str, run_id: str) -> dict[str, Any]:
    base = f"pipelines/{pipeline_id}/runs/{run_id}"
    descriptors = {
        "codex": (f"{base}/codex.jsonl", "application/x-ndjson"),
        "activities": (f"{base}/activities.jsonl", "application/x-ndjson"),
        "telemetry": (f"{base}/telemetry.json", "application/json"),
        "lastMessage": (f"{base}/last-message.md", "text/markdown"),
        "result": (f"{base}/result.json", "application/json"),
        "toolChangesManifest": (f"{base}/tool-changes/manifest.jsonl", "application/x-ndjson"),
        "toolChangesSummary": (f"{base}/tool-changes/summary.json", "application/json"),
    }
    return {
        key: {
            "path": path,
            "lifecycle": "live",
            "availability": "missing",
            "mediaType": media,
            "byteSize": None,
            "sha256": None,
            "requiredAtTerminal": False,
            "reason": "artifact not produced",
        }
        for key, (path, media) in descriptors.items()
    }


def _artifact_descriptor(path: str, media_type: str, available: bool) -> dict[str, Any]:
    return {
        "path": validate_relative_path(path),
        "lifecycle": "live",
        "availability": "available" if available else "missing",
        "mediaType": media_type,
        "byteSize": None,
        "sha256": None,
        "requiredAtTerminal": False,
        "reason": None if available else "artifact not produced",
    }


__all__ = [
    "ArchiveInvocation",
    "ArchiveConflictError",
    "ArchiveError",
    "ArchiveImmutableError",
    "ArchiveSealError",
    "ArchiveValidationError",
    "archive_for",
    "ensure_epoch",
    "verify_archive",
    "TaskArchive",
    "TaskArchiveWriter",
    "MAX_ARCHIVE_INVOCATIONS",
    "MAX_ARCHIVE_INVOCATION_TURNS",
    "MAX_ARCHIVE_INVOCATION_BYTES",
    "MAX_ARCHIVE_TELEMETRY_BYTES",
    "MAX_ARCHIVE_TOTAL_TOKEN_COUNT",
    "collect_invocation_evidence",
    "validate_opaque_id",
    "validate_relative_path",
]

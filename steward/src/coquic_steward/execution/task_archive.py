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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..core.models import TaskPipeline, TaskRecord, TaskRun, TaskStatus

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
}


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


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return dict(value.model_dump(mode="json", by_alias=True))
    if isinstance(value, Mapping):
        return dict(value)
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
    if not isinstance(value["runs"], list) or not value["runs"]:
        raise ArchiveValidationError("pipeline schema requires runs")
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

    task_root = task_dir
    task_archive_path = task_dir

    def task_path(self, task_id: str, relative: str = "") -> Path:
        validate_opaque_id(task_id)
        if not relative:
            return self.task_dir(task_id)
        return self.task_dir(task_id) / PurePosixPath(validate_relative_path(relative))

    def pipeline_dir(self, task_id: str, pipeline_id: str) -> Path:
        validate_opaque_id(task_id)
        validate_opaque_id(pipeline_id)
        return self.task_dir(task_id) / "pipelines" / pipeline_id

    pipeline_path = pipeline_dir

    def run_dir(self, task_id: str, pipeline_id: str, run_id: str) -> Path:
        validate_opaque_id(task_id)
        validate_opaque_id(pipeline_id)
        validate_opaque_id(run_id)
        return self.pipeline_dir(task_id, pipeline_id) / "runs" / run_id

    run_path = run_dir

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

    write_task = create_task

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

    materialize_task = update_task

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

    write_metadata = write_json
    atomic_write = write_json

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

    reconcile_generation = reconcile

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

    append_jsonl_record = append_jsonl

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

    append_task_event = append_event

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
        relative = f"pipelines/{identifier}/pipeline.json"
        path = self.write_json(task_id, relative, value)
        self._add_task_pipeline_reference(task_id, identifier, int(value["ordinal"]))
        return path

    write_pipeline = materialize_pipeline
    materialize_pipeline_descriptor = materialize_pipeline

    def materialize_ledger(
        self,
        task: TaskRecord,
        pipeline: TaskPipeline,
        runs: Sequence[TaskRun],
    ) -> Path:
        if pipeline.task_id != task.id:
            raise ArchiveConflictError("ledger pipeline does not belong to task")
        if not runs:
            raise ArchiveValidationError(
                "canonical pipeline materialization requires ledger runs"
            )
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
        value = {key: item for key, item in value.items() if key in RUN_KEYS}
        _validate_run_document(value)
        path = self.write_json(task_id, f"pipelines/{validate_opaque_id(pipeline_id)}/runs/{identifier}/run.json", value)
        self._add_pipeline_run_reference(task_id, pipeline_id, identifier, int(value["roleOrdinal"]), str(value["role"]), str(value["state"]))
        return path

    write_run = materialize_run
    materialize_run_descriptor = materialize_run

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

    write_artifact = materialize_artifact

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

    write_validation = materialize_validation

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

    write_review = materialize_review

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

    write_integration = materialize_integration

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

    append_codex_record = lambda self, task_id, pipeline_id, run_id, record: self.append_run_jsonl(task_id, pipeline_id, run_id, "codex.jsonl", record)
    append_activity = lambda self, task_id, pipeline_id, run_id, record: self.append_run_jsonl(task_id, pipeline_id, run_id, "activities.jsonl", record)
    append_tool_change = lambda self, task_id, pipeline_id, run_id, record: self.append_run_jsonl(task_id, pipeline_id, run_id, "tool-changes/manifest.jsonl", record)

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

    write_codex_artifact = write_run_file

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

    seal_task = seal
    freeze = seal
    seal_archive = seal

    def verify(self, task_id: str) -> bool:
        manifest_path = self.task_dir(task_id) / "manifest.json"
        if not manifest_path.exists():
            return False
        try:
            self._verify_manifest_path(task_id, manifest_path)
        except ArchiveError:
            return False
        return True

    verify_manifest = verify
    verify_task = verify

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

    # Keep the destructive operation discoverable under the archive vocabulary
    # used by callers while preserving one exact task-id input boundary.
    delete = delete_verified
    delete_task = delete_verified
    delete_archive = delete_verified

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


ArchiveWriter = TaskArchiveWriter


def archive_for(config_or_root: Path | Any, *, epoch_id: str | None = None) -> TaskArchive:
    return TaskArchive(config_or_root, epoch_id=epoch_id)


def ensure_epoch(config_or_root: Path | Any, *, epoch_id: str | None = None) -> dict[str, Any]:
    return TaskArchive(config_or_root, epoch_id=epoch_id).ensure_epoch()


def verify_archive(config_or_root: Path | Any, task_id: str) -> bool:
    return TaskArchive(config_or_root).verify(task_id)


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
    "ArchiveConflictError",
    "ArchiveError",
    "ArchiveImmutableError",
    "ArchiveSealError",
    "ArchiveValidationError",
    "ArchiveWriter",
    "archive_for",
    "ensure_epoch",
    "verify_archive",
    "TaskArchive",
    "TaskArchiveWriter",
    "validate_opaque_id",
    "validate_relative_path",
]

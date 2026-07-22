"""Crash-consistent writer for the public Steward 2.0 task archive.

The archive is intentionally a small, dependency-free boundary.  SQLite is the
operational source of truth; this module only materializes expected bytes and
refuses to guess when a visible byte disagrees with that expectation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
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
        return (
            isinstance(value, Mapping)
            and value.get("formatVersion") == FORMAT_VERSION
            and value.get("policy") == POLICY
            and isinstance(value.get("epochId"), str)
            and SAFE_ID_RE.fullmatch(value["epochId"]) is not None
            and isinstance(value.get("startedAt"), str)
            and value.get("endedAt") is None
        )

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
        if directory.exists() and not directory.is_dir():
            raise ArchiveConflictError(f"task path is not a directory: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        metadata = self._task_metadata(task_id, task, task_metadata, pipeline_id)
        self.write_json(task_id, "task.json", metadata)
        self.write_bytes(task_id, "prompt.md", prompt.encode("utf-8") if isinstance(prompt, str) else prompt)
        if not (directory / "events.jsonl").exists():
            self._atomic_bytes(directory / "events.jsonl", b"")
        if event is not None:
            self.append_event(task_id, event)
        return directory

    write_task = create_task

    def create_task_from_record(self, record: TaskRecord) -> Path:
        return self.create_task(record.id, record.spec.prompt, task=record)

    def update_task(self, task_id: str, metadata: Mapping[str, Any]) -> Path:
        value = _private_filtered(dict(metadata))
        if value.get("taskId") != task_id:
            raise ArchiveConflictError("task metadata identity does not match archive path")
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
        if selected_pipeline is None and not value.get("pipelines"):
            selected_pipeline = "pipeline-initial"
        if selected_pipeline is not None:
            validate_opaque_id(str(selected_pipeline))
        if value.get("currentPipelineId") is None:
            value["currentPipelineId"] = selected_pipeline
        value.setdefault("summary", {"title": task_id, "text": "Task created."})
        if not value.get("pipelines"):
            value["pipelines"] = (
                [{"pipelineId": selected_pipeline, "ordinal": 1, "path": f"pipelines/{selected_pipeline}/pipeline.json"}]
                if selected_pipeline is not None
                else []
            )
        value.setdefault("terminalStatusObservedAt", None)
        value.setdefault("manifestPath", None)
        if value["taskId"] != task_id or value["epochId"] != self.epoch_id:
            raise ArchiveConflictError("task metadata identity does not match archive path")
        if not isinstance(value.get("pipelines"), list):
            raise ArchiveValidationError("task pipelines must be an array")
        return _private_filtered(value)

    def write_json(self, task_id: str, relative: str, value: Mapping[str, Any] | list[Any]) -> Path:
        path = self.task_path(task_id, relative)
        self._assert_mutable(task_id, path)
        data = _json_bytes(_private_filtered(value))
        if path.exists() and path.is_file() and path.read_bytes() == data:
            return path
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
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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

    def reconcile(self, task_id: str, relative: str, expected: bytes | Mapping[str, Any] | list[Any]) -> str:
        data = _json_bytes(expected) if isinstance(expected, (Mapping, list)) else expected
        path = self.task_path(task_id, relative)
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

    def append_jsonl(self, task_id: str, relative: str, record: Mapping[str, Any] | bytes) -> int:
        path = self.task_path(task_id, relative)
        self._assert_mutable(task_id, path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        line = (_json_bytes(record) if isinstance(record, Mapping) else record)
        if not line.endswith(b"\n"):
            line += b"\n"
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ArchiveConflictError(f"JSONL path is not regular: {path}")
            with path.open("rb") as handle:
                existing = handle.read()
            if existing and not existing.endswith(b"\n"):
                raise ArchiveConflictError("cannot append after incomplete JSONL line")
        else:
            existing = b""
        with path.open("ab") as handle:
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
        value.setdefault("at", _now())
        if not SAFE_ID_RE.fullmatch(str(value["eventId"])):
            raise ArchiveValidationError("eventId must be an opaque safe id")
        return self.append_jsonl(task_id, "events.jsonl", value)

    append_task_event = append_event

    def materialize_pipeline(
        self,
        task_id: str,
        pipeline: Mapping[str, Any] | TaskPipeline,
        *,
        pipeline_id: str | None = None,
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
        if value["taskId"] != task_id:
            raise ArchiveConflictError("pipeline task id does not match directory")
        relative = f"pipelines/{identifier}/pipeline.json"
        path = self.write_json(task_id, relative, value)
        self._add_task_pipeline_reference(task_id, identifier, int(value["ordinal"]))
        return path

    write_pipeline = materialize_pipeline
    materialize_pipeline_descriptor = materialize_pipeline

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
        path = self.write_json(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/validations/{identifier}/validation.json",
            value,
        )
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
            self.write_json(
                task_id,
                f"pipelines/{validate_opaque_id(pipeline_id)}/validations/{identifier}/validation.json",
                value,
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
            _artifact_descriptor(
                f"pipelines/{pipeline_id}/reviews/{identifier}.json",
                "application/json",
                True,
            ),
        )
        return self.write_json(
            task_id,
            f"pipelines/{validate_opaque_id(pipeline_id)}/reviews/{identifier}.json",
            value,
        )

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
        task_dir = self.task_dir(task_id)
        if not task_dir.is_dir():
            raise ArchiveSealError(f"task archive does not exist: {task_id}")
        manifest_path = task_dir / "manifest.json"
        if manifest_path.exists():
            self._verify_manifest_path(task_id, manifest_path)
            try:
                existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveSealError("invalid terminal manifest") from exc
            if existing_manifest.get("terminalStatus") != status:
                raise ArchiveConflictError("terminal status conflicts with manifest")
            if completion_identity is not None and existing_manifest.get("completionIdentity") != completion_identity:
                raise ArchiveConflictError("completion identity conflicts with manifest")
            if completed_at is not None and existing_manifest.get("completedAt") != completed_at:
                raise ArchiveConflictError("completion timestamp conflicts with manifest")
            return manifest_path
        self._reconcile_hidden(task_dir)
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
            if path.is_symlink() or not path.is_file():
                if path.is_dir():
                    continue
                raise ArchiveSealError(f"non-regular visible archive path: {relative}")
            data = path.read_bytes()
            files.append({"path": validate_relative_path(relative), "byteSize": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        if not files:
            raise ArchiveSealError("cannot seal an empty task archive")
        manifest = {
            "manifestVersion": FORMAT_VERSION,
            "epochId": self.ensure_epoch()["epochId"],
            "taskId": validate_opaque_id(task_id),
            "completionIdentity": validate_opaque_id(completion_identity or f"completion-{secrets.token_hex(12)}"),
            "terminalStatus": status,
            "completedAt": completed_at or _now(),
            "files": files,
        }
        self._atomic_bytes(manifest_path, _json_bytes(manifest))
        return manifest_path

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

    def _verify_manifest_path(self, task_id: str, manifest_path: Path) -> None:
        try:
            raw_manifest = manifest_path.read_bytes()
            manifest = json.loads(raw_manifest.decode("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("invalid terminal manifest") from exc
        if not isinstance(manifest, Mapping) or manifest.get("taskId") != task_id:
            raise ArchiveSealError("manifest task identity mismatch")
        if manifest.get("manifestVersion") != FORMAT_VERSION or not isinstance(manifest.get("files"), list):
            raise ArchiveSealError("invalid terminal manifest schema")
        if raw_manifest != _json_bytes(manifest):
            raise ArchiveSealError("terminal manifest bytes are not canonical")
        expected = {item.get("path"): item for item in manifest["files"] if isinstance(item, Mapping)}
        task_dir = self.task_dir(task_id)
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
            if path.is_symlink() or not path.is_file():
                if path.is_dir():
                    continue
                raise ArchiveSealError(f"non-regular visible path: {relative}")
            actual[relative] = path
        if set(expected) != set(actual):
            raise ArchiveSealError("terminal manifest coverage does not match visible files")
        ordered = [item.get("path") for item in manifest["files"]]
        if ordered != sorted(ordered):
            raise ArchiveSealError("manifest file list is not canonical")
        for relative, descriptor in expected.items():
            if not isinstance(relative, str) or not validate_relative_path(relative):
                raise ArchiveSealError("manifest contains an unsafe path")
            data = actual[relative].read_bytes()
            if descriptor.get("byteSize") != len(data) or descriptor.get("sha256") != hashlib.sha256(data).hexdigest():
                raise ArchiveSealError(f"terminal file hash mismatch: {relative}")

    def _validate_task_graph(self, task_id: str, status: str) -> None:
        task_path = self.task_dir(task_id) / "task.json"
        if not task_path.is_file():
            raise ArchiveSealError("task.json is required before sealing")
        try:
            task = json.loads(task_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveSealError("task.json is not valid JSON") from exc
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
        parent_ids: dict[str, str | None] = {}
        for reference in pipelines:
            if not isinstance(reference, Mapping):
                raise ArchiveSealError("pipeline reference is not an object")
            try:
                pipeline_id = validate_opaque_id(str(reference["pipelineId"]))
                relative = validate_relative_path(str(reference["path"]))
            except (KeyError, ArchiveError) as exc:
                raise ArchiveSealError("invalid pipeline reference") from exc
            if not isinstance(reference.get("ordinal"), int) or reference["ordinal"] < 1:
                raise ArchiveSealError("pipeline reference ordinal is invalid")
            if pipeline_id in pipeline_ids or relative != f"pipelines/{pipeline_id}/pipeline.json":
                raise ArchiveSealError("pipeline references are not canonical")
            pipeline_ids.add(pipeline_id)
            pipeline_path = self.task_path(task_id, relative)
            if not pipeline_path.is_file():
                raise ArchiveSealError(f"missing pipeline metadata: {relative}")
            try:
                pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveSealError(f"invalid pipeline metadata: {relative}") from exc
            if pipeline.get("pipelineId") != pipeline_id or pipeline.get("taskId") != task_id:
                raise ArchiveSealError("pipeline identity does not match task graph")
            parent_ids[pipeline_id] = pipeline.get("parentPipelineId")
            if pipeline.get("state") not in {"active", "succeeded", "failed", "blocked", "cancelled", "interrupted", "superseded"}:
                raise ArchiveSealError("invalid pipeline state")
            if pipeline.get("state") in {"active", "interrupted"}:
                raise ArchiveSealError("cannot seal while a pipeline is active or interrupted")
            runs = pipeline.get("runs")
            if not isinstance(runs, list) or not runs:
                raise ArchiveSealError("pipeline must reference at least one run")
            for run_reference in runs:
                if not isinstance(run_reference, Mapping):
                    raise ArchiveSealError("run reference is not an object")
                try:
                    run_id = validate_opaque_id(str(run_reference["runId"]))
                    run_relative = validate_relative_path(str(run_reference["path"]))
                except (KeyError, ArchiveError) as exc:
                    raise ArchiveSealError("invalid run reference") from exc
                expected_run_path = f"pipelines/{pipeline_id}/runs/{run_id}/run.json"
                if run_relative != expected_run_path:
                    raise ArchiveSealError("run reference is not canonical")
                run_path = self.task_path(task_id, run_relative)
                if not run_path.is_file():
                    raise ArchiveSealError(f"missing run metadata: {run_relative}")
                try:
                    run = json.loads(run_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ArchiveSealError(f"invalid run metadata: {run_relative}") from exc
                if run.get("runId") != run_id or run.get("taskId") != task_id or run.get("pipelineId") != pipeline_id:
                    raise ArchiveSealError("run identity does not match task graph")
                if run.get("state") not in {"running", "succeeded", "failed", "interrupted", "cancelled"}:
                    raise ArchiveSealError("invalid run state")
                if run.get("state") == "running":
                    raise ArchiveSealError("cannot seal while a run is running")
                if not run.get("completedAt"):
                    raise ArchiveSealError("terminal run is missing completedAt")
                artifacts = run.get("artifacts")
                if not isinstance(artifacts, Mapping):
                    raise ArchiveSealError("run artifacts are missing")
                for descriptor in artifacts.values():
                    if not isinstance(descriptor, Mapping):
                        raise ArchiveSealError("invalid run artifact descriptor")
                    try:
                        artifact_relative = validate_relative_path(str(descriptor["path"]))
                    except (KeyError, ArchiveError) as exc:
                        raise ArchiveSealError("invalid run artifact path") from exc
                    artifact_path = self.task_path(task_id, artifact_relative)
                    if descriptor.get("requiredAtTerminal"):
                        if descriptor.get("availability") not in {"available", "partial"}:
                            raise ArchiveSealError("required terminal artifact is unavailable")
                        if not artifact_path.is_file():
                            raise ArchiveSealError(f"missing required run artifact: {artifact_relative}")
                        artifact_bytes = artifact_path.read_bytes()
                        if descriptor.get("byteSize") is not None and descriptor.get("byteSize") != len(artifact_bytes):
                            raise ArchiveSealError(f"run artifact size disagrees: {artifact_relative}")
                        if descriptor.get("sha256") is not None and descriptor.get("sha256") != hashlib.sha256(artifact_bytes).hexdigest():
                            raise ArchiveSealError(f"run artifact hash disagrees: {artifact_relative}")
            if pipeline.get("state") != "active" and not pipeline.get("completedAt"):
                raise ArchiveSealError("terminal pipeline is missing completedAt")
        for pipeline_id, parent_id in parent_ids.items():
            if parent_id is not None and parent_id not in pipeline_ids:
                raise ArchiveSealError(f"pipeline parent is missing: {pipeline_id}")
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

    @staticmethod
    def _reconcile_hidden(task_dir: Path) -> None:
        # Hidden temporary files are incomplete generations and are not public.
        # They are intentionally ignored; a caller can retry the seal safely.
        for path in task_dir.rglob("*"):
            if not path.name.startswith("."):
                continue
            if path.is_file() and TEMPORARY_RE.fullmatch(path.name):
                continue
            raise ArchiveSealError(f"unknown hidden archive path: {path.relative_to(task_dir)}")

    def _assert_mutable(self, task_id: str, path: Path) -> None:
        manifest = self.task_dir(task_id) / "manifest.json"
        if manifest.exists():
            raise ArchiveImmutableError(f"task archive is terminally sealed: {task_id}")
        if path.is_symlink():
            raise ArchiveValidationError(f"archive path must not be a symlink: {path}")
        task_dir = self.task_dir(task_id)
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

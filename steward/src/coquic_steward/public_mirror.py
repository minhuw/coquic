from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .agents.diagnostics import diagnostics_for_paths
from .agents.tool_changes import (
    TOOL_CHANGE_ERROR_CATEGORIES,
    TOOL_CHANGE_MAX_COMPLETED_RECORDS,
    TOOL_CHANGE_MAX_MANIFEST_BYTES,
    TOOL_CHANGE_SAFE_ID_RE,
    TOOL_CHANGE_SCHEMA_VERSION,
    TOOL_CHANGE_SUPPORTED_TOOLS,
    TOOL_CHANGE_TREE_RE,
    tool_change_run_directories,
)
from .core.config import (
    DEFAULT_PUBLIC_MIRROR_OUTPUT,
    PublicMirrorConfig,
    StewardConfig,
)
from .core.models import (
    DaemonRuntime,
    Event,
    PublicMirrorFailureCategory,
    PublicMirrorHealth,
    SignalFetchRun,
    SignalItem,
    SignalItemStatus,
    SchedulerState,
    TaskIteration,
    TaskRecord,
    TaskStatus,
    ValidationResult,
    utc_now,
)
from .core.subprocesses import CommandResult, run_command
from .signals import project_signals_from_items
from .storage import TaskStore, scheduler_state
from .public_schema import PUBLIC_STEWARD_SCHEMA_VERSION

PUBLIC_MIRROR_SCHEMA_VERSION = PUBLIC_STEWARD_SCHEMA_VERSION
PUBLIC_TASK_DETAIL_SCHEMA_VERSION = 2
DEFAULT_MIRROR_TASK_LIMIT = 80
DEFAULT_MIRROR_SIGNAL_LIMIT = 80
DEFAULT_MIRROR_FETCH_LIMIT = 40
DEFAULT_MIRROR_WAKEUP_LIMIT = 20
PUBLIC_TASK_DATA_PREFIX = "/steward/data/tasks"
REMOTE_MIRROR_ROOT = ".cache/coquic-steward/public-mirror"
REMOTE_MIRROR_HELPER = f"{REMOTE_MIRROR_ROOT}/publish-helper-v1"
REMOTE_MIRROR_LOCK = f"{REMOTE_MIRROR_ROOT}/publish.lock"
MIRROR_PATCH_BYTES = 128 * 1024
MIRROR_TRAJECTORY_PATCH_BYTES = MIRROR_PATCH_BYTES
MIRROR_TRAJECTORY_AGGREGATE_PATCH_BYTES = 512 * 1024
MIRROR_TRAJECTORY_RECORDS = 100
MIRROR_TRAJECTORY_SUMMARY_BYTES = 64 * 1024
MIRROR_TRAJECTORY_MAX_RUNS = 128
MIRROR_TRAJECTORY_MAX_DURATION_MS = 24 * 60 * 60 * 1000
MIRROR_TRAJECTORY_MAX_PATHS = 256
MIRROR_TRAJECTORY_MAX_PATH_BYTES = 4096
MIRROR_TRAJECTORY_MAX_PATCH_BYTES = 16 * 1024 * 1024
MIRROR_TRAJECTORY_MAX_HASH_BYTES = 64 * 1024 * 1024
MIRROR_TRANSCRIPT_BYTES = 64 * 1024
MIRROR_LOG_BYTES = 64 * 1024
MIRROR_LAST_MESSAGE_BYTES = 24 * 1024
_RawTranscriptArtifacts = dict[str, dict[str, object]]
WORKING_STATUSES = {
    TaskStatus.running,
    TaskStatus.reviewing,
    TaskStatus.integrating,
}
PRIVATE_DATA_KEY_PARTS = (
    "path",
    "prompt",
    "transcript",
    "worktree",
    "payload",
    "secret",
    "thread",
    "token",
    "key",
)
_DEFAULT_RUNTIME = DaemonRuntime()
PUBLIC_METADATA_KEYS = {
    "source_task_id",
    "main_commit",
    "selected_signal_item_ids",
    "evidence",
    "workflow_file",
    "workflow_name",
    "run_id",
    "dedupe_key",
}
_TRAJECTORY_STATUSES = frozenset({"captured", "empty", "failed", "incomplete"})
_TRAJECTORY_COMPLETED_STATUSES = frozenset({"captured", "empty", "failed"})
_TRAJECTORY_SAFE_PATH_RE = re.compile(r"^[^\x00\\]+(?:/[^\x00\\]+)*$")
_TRAJECTORY_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.|$)|.*(?:secret|token|credential|password|private|api[_-]?key).*)"
)
_TRAJECTORY_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|glpat-[A-Za-z0-9_-]{8,})\b"
)
_TRAJECTORY_WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:(?:\\+|/)|\\{2,})[^\s'\"`),;]+"
)
_TRAJECTORY_PRIVATE_MARKER_RE = re.compile(
    r"(?i)\bprivate[-_ ]+(?:prompt|context|session|turn|payload|response|input|secret|token|key)\b.*"
)
_TRAJECTORY_PRIVATE_ASSIGNMENT_PARTS = (
    "prompt",
    "secret",
    "token",
    "credential",
    "password",
    "authorization",
)
_PUBLIC_TOKEN_TERMINATORS = frozenset("'\"`),;")


def public_mirror_payload(
    config: StewardConfig,
    store: TaskStore,
    *,
    task_limit: int = DEFAULT_MIRROR_TASK_LIMIT,
    signal_limit: int = DEFAULT_MIRROR_SIGNAL_LIMIT,
    fetch_limit: int = DEFAULT_MIRROR_FETCH_LIMIT,
    runtime: DaemonRuntime | None = None,
    publication: PublicMirrorHealth | None = None,
) -> dict[str, object]:
    runtime = runtime or _DEFAULT_RUNTIME
    generated_at = utc_now()
    task_window = store.list_tasks(limit=task_limit + 1)
    signal_window = store.list_signal_items(limit=signal_limit + 1)
    fetch_window = store.list_signal_fetch_runs(limit=fetch_limit + 1)
    tasks_truncated = len(task_window) > task_limit
    signal_items_truncated = len(signal_window) > signal_limit
    fetches_truncated = len(fetch_window) > fetch_limit
    tasks = task_window[:task_limit]
    signal_items = signal_window[:signal_limit]
    fetch_runs = fetch_window[:fetch_limit]
    signals = project_signals_from_items(config, signal_items, fetches=fetch_runs)
    planner_runs, planner_runs_truncated = _public_planner_runs(config, store)
    scheduler = scheduler_state(config, store)
    pending_wakeups = store.pending_wakeups(limit=DEFAULT_MIRROR_WAKEUP_LIMIT + 1)
    recent_wakeups = store.recent_wakeups(limit=DEFAULT_MIRROR_WAKEUP_LIMIT + 1)
    return {
        "schema_version": PUBLIC_MIRROR_SCHEMA_VERSION,
        "compatibility_state": "compatible",
        "generated_at": _public_timestamp(generated_at),
        "repository": config.github_repository,
        "main_branch": config.main_branch,
        "state": _public_state(tasks),
        "counts": _counts(tasks, signal_items),
        "runtime": _public_runtime(runtime),
        "publication": _public_publication(config, generated_at, publication),
        "audit": [_public_text(config, finding) for finding in store.audit()],
        "configuration": _public_configuration(config),
        "tasks_truncated": tasks_truncated,
        "tasks": [
            {
                **_public_task(config, task),
                "detail_url": f"/steward/tasks/{task.id}",
                "detail_json": _public_task_detail_url(task.id),
            }
            for task in tasks
        ],
        "signals": {
            "schema_version": signals.schema_version,
            "repository": signals.repository,
            "enabled_signals": list(config.enabled_signals),
            "generated_at": _public_timestamp(signals.generated_at),
            "items_truncated": signal_items_truncated,
            "fetches_truncated": fetches_truncated,
            "summary": _public_signals_summary(signal_items, fetch_runs),
            "items": [_public_signal_item(config, item) for item in signal_items],
            "fetches": [_public_fetch_run(config, run) for run in fetch_runs],
        },
        "scheduler": _public_scheduler_state(
            scheduler,
            pending_wakeups=pending_wakeups,
            recent_wakeups=recent_wakeups,
        ),
        "planner_runs_truncated": planner_runs_truncated,
        "planner_runs": planner_runs,
        "integration": _integration_summary(config, tasks),
    }


def write_public_mirror(
    config: StewardConfig,
    store: TaskStore,
    output_path: Path | None = None,
    *,
    runtime: DaemonRuntime | None = None,
    publication: PublicMirrorHealth | None = None,
) -> Path:
    path = _mirror_output_path(config, output_path)
    payload = public_mirror_payload(
        config, store, runtime=runtime, publication=publication
    )
    tasks = store.list_tasks(limit=DEFAULT_MIRROR_TASK_LIMIT)
    mirror_dir = path.parent
    tasks_dir = mirror_dir / "data" / "tasks"
    raw_task_ids = (
        {_safe_public_segment(task.id, fallback="task") for task in tasks}
        if config.public_mirror.transcript_mode == "raw"
        else set()
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if _is_default_mirror_output(config, path):
        _remove_legacy_task_details(mirror_dir)
    _atomic_write_text(
        path,
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    )
    tasks_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_task_details(
        tasks_dir,
        detail_task_ids={task.id for task in tasks},
        raw_task_ids=raw_task_ids,
    )
    raw_transcript_artifacts: _RawTranscriptArtifacts = {}
    for task in tasks:
        raw_transcript_artifacts.update(
            _write_public_raw_transcripts(config, store, tasks_dir, task)
        )
    task_index = []
    for task in tasks:
        detail = public_task_detail_payload(
            config,
            store,
            task,
            raw_transcript_artifacts=raw_transcript_artifacts,
        )
        detail_path = tasks_dir / f"{task.id}.json"
        _atomic_write_text(
            detail_path,
            json.dumps(detail, sort_keys=True, separators=(",", ":")) + "\n",
        )
        task_index.append(
            {
                "id": task.id,
                "title": _public_text(config, task.spec.title),
                "status": str(task.status),
                "updated_at": _public_timestamp(task.updated_at),
                "detail_json": _public_task_detail_url(task.id),
            }
        )
    _atomic_write_text(
        tasks_dir / "index.json",
        json.dumps(
            {
                "schema_version": PUBLIC_TASK_DETAIL_SCHEMA_VERSION,
                "generated_at": str(payload["generated_at"]),
                "tasks": task_index,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    return path


def write_public_mirror_status(
    config: StewardConfig,
    store: TaskStore,
    output_path: Path | None = None,
    *,
    runtime: DaemonRuntime | None = None,
    publication: PublicMirrorHealth | None = None,
) -> Path:
    path = _mirror_output_path(config, output_path)
    payload = public_mirror_payload(
        config, store, runtime=runtime, publication=publication
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(
        path,
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    )
    return path


def publish_public_mirror(
    config: StewardConfig,
    store: TaskStore,
    *,
    publisher: PublicMirrorPublisher | None = None,
    force: bool = False,
    publish: bool | None = None,
    runtime: DaemonRuntime | None = None,
    publication: PublicMirrorHealth | None = None,
) -> tuple[Path, CommandResult | None]:
    path = write_public_mirror(
        config, store, runtime=runtime, publication=publication
    )
    refreshed_runtime = runtime or DaemonRuntime()
    refreshed_runtime.heartbeat_at = utc_now()
    write_public_mirror_status(
        config,
        store,
        output_path=path,
        runtime=refreshed_runtime,
        publication=publication,
    )
    should_publish = config.public_mirror.publish if publish is None else publish
    if not force and not should_publish:
        return path, None
    selected = publisher or PublicMirrorPublisher(config.public_mirror)
    return path, selected.publish(path, cwd=config.repo_root)


def public_task_detail_payload(
    config: StewardConfig,
    store: TaskStore,
    task: TaskRecord | str,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object]:
    record = store.get(task) if isinstance(task, str) else task
    source_task = _source_task_for_integration(store, record)
    events = store.events(record.id)
    source_events = (
        store.events(source_task.id)
        if source_task is not None and source_task.id != record.id
        else []
    )
    return {
        "schema_version": PUBLIC_TASK_DETAIL_SCHEMA_VERSION,
        "generated_at": _public_timestamp(utc_now()),
        "repository": config.github_repository,
        "main_branch": config.main_branch,
        "task": _public_task_detail_record(config, record),
        "source_task": (
            _public_task_detail_record(config, source_task)
            if source_task is not None
            else None
        ),
        "events": [_public_event(config, event) for event in events],
        "source_events": [
            _public_event(config, event)
            for event in source_events
            if event.kind.startswith("integration.") or event.kind == "main.pushed"
        ],
        "attempts": _public_attempts(
            config,
            store,
            record,
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "plan_runs": _public_plan_runs(
            config,
            store,
            record,
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "validations": [
            _public_validation(config, validation, index)
            for index, validation in enumerate(record.validations)
        ],
        "artifacts": _public_task_artifacts(
            config,
            record,
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "integration": _public_integration_detail(
            config,
            store,
            record,
            source_task,
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "remote": _task_remote(config, store, record.id),
    }


def public_mirror_digest(
    config: StewardConfig,
    store: TaskStore,
    *,
    runtime: DaemonRuntime | None = None,
    publication: PublicMirrorHealth | None = None,
) -> str:
    payload = public_mirror_payload(
        config, store, runtime=runtime, publication=publication
    )
    task_details = [
        public_task_detail_payload(config, store, task)
        for task in store.list_tasks(limit=DEFAULT_MIRROR_TASK_LIMIT)
    ]
    for detail in task_details:
        detail.pop("generated_at", None)
    payload.pop("generated_at", None)
    if isinstance(payload.get("signals"), dict):
        payload["signals"].pop("generated_at", None)
    scheduler = payload.get("scheduler")
    if isinstance(scheduler, dict):
        for provider in scheduler.get("providers", []):
            if isinstance(provider, dict):
                provider.pop("next_due_at", None)
                provider.pop("idle_next_due_at", None)
                provider.pop("due", None)
                provider.pop("idle_due", None)
    publication_payload = payload.get("publication")
    if isinstance(publication_payload, dict):
        for key in (
            "state",
            "snapshot_id",
            "generated_at",
            "last_attempt_at",
            "last_success_at",
            "last_failure_at",
            "last_failure_category",
            "retry_count",
            "last_accepted_digest",
        ):
            publication_payload.pop(key, None)
    encoded = json.dumps(
        {"status": payload, "task_details": task_details},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(encoded.encode("utf-8")).hexdigest()


class PublicMirrorPublisher:
    def __init__(self, mirror_config: PublicMirrorConfig):
        self.config = mirror_config

    def publish(self, local_path: Path, *, cwd: Path) -> CommandResult:
        remote_target = f"{self.config.remote_user}@{self.config.remote_host}"
        remote_path = self.config.remote_path
        target_key = sha256(remote_path.encode("utf-8")).hexdigest()
        stage_dir = f"{REMOTE_MIRROR_ROOT}/targets/{target_key}"
        local_dir = local_path.parent
        stage_result = self._prepare_remote_stage(
            remote_target,
            remote_path,
            target_key,
            cwd=cwd,
        )
        if not stage_result.ok:
            return stage_result
        rsync_result = run_command(
            [
                "rsync",
                "-az",
                "--checksum",
                "--delete-delay",
                "--partial",
                "--delay-updates",
                "--exclude=.~tmp~/",
                "--rsync-path",
                self._remote_rsync_path(remote_path, stage_dir),
                "-e",
                self._rsync_ssh_command(),
                f"{local_dir}/",
                f"{remote_target}:{stage_dir}/steward/",
            ],
            cwd=cwd,
            timeout=self._rsync_timeout_seconds(),
        )
        return rsync_result

    def _prepare_remote_stage(
        self,
        remote_target: str,
        remote_path: str,
        target_key: str,
        *,
        cwd: Path,
    ) -> CommandResult:
        return run_command(
            [
                "ssh",
                *self._ssh_options(),
                remote_target,
                "bash",
                "-s",
                "--",
                remote_path,
                target_key,
            ],
            cwd=cwd,
            input_text=(
                "set -euo pipefail\n"
                "remote_path=\"$1\"\n"
                "target_key=\"$2\"\n"
                "cache_root=\"$HOME/.cache/coquic-steward\"\n"
                f"mirror_root=\"$HOME/{REMOTE_MIRROR_ROOT}\"\n"
                "targets_dir=\"${mirror_root}/targets\"\n"
                "stage_dir=\"${targets_dir}/${target_key}\"\n"
                f"helper_path=\"$HOME/{REMOTE_MIRROR_HELPER}\"\n"
                f"lock_path=\"$HOME/{REMOTE_MIRROR_LOCK}\"\n"
                "umask 077\n"
                "case \"${target_key}\" in\n"
                "  *[!0-9a-f]*) echo 'invalid mirror target key' >&2; exit 1 ;;\n"
                "esac\n"
                "if [ -L \"${cache_root}\" ] || [ -L \"${mirror_root}\" ] || "
                "[ -L \"${targets_dir}\" ] || [ -L \"${stage_dir}\" ]; then\n"
                "  echo 'refusing symlinked Steward mirror stage' >&2\n"
                "  exit 1\n"
                "fi\n"
                "install -d -m 700 \"${cache_root}\" \"${mirror_root}\" "
                "\"${targets_dir}\" \"${stage_dir}\" "
                "\"${stage_dir}/steward\"\n"
                ": > \"${lock_path}\"\n"
                "chmod 600 \"${lock_path}\"\n"
                "exec 9>\"${lock_path}\"\n"
                "flock -x 9\n"
                "helper_tmp=\"${helper_path}.tmp.$$\"\n"
                "trap 'rm -f \"${helper_tmp}\"' EXIT\n"
                "cat > \"${helper_tmp}\" <<'STEWARD_PUBLISH_HELPER'\n"
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "remote_path=\"$1\"\n"
                "stage_relative=\"$2\"\n"
                "shift 2\n"
                "stage_dir=\"$HOME/${stage_relative}\"\n"
                "remote_dir=\"$(dirname \"${remote_path}\")\"\n"
                "rsync \"$@\"\n"
                "test -d \"${stage_dir}/steward\"\n"
                "sudo install -d -m 755 \"${remote_dir}\"\n"
                "sudo rsync -a --checksum --delete-delay --delay-updates "
                "--exclude='.~tmp~/' \"${stage_dir}/steward/\" "
                "\"${remote_dir}/\"\n"
                "sudo chmod -R a+rX \"${remote_dir}\"\n"
                "STEWARD_PUBLISH_HELPER\n"
                "chmod 700 \"${helper_tmp}\"\n"
                "mv -f \"${helper_tmp}\" \"${helper_path}\"\n"
                "trap - EXIT\n"
            ),
            timeout=self._rsync_timeout_seconds(),
        )

    def _remote_rsync_path(self, remote_path: str, stage_dir: str) -> str:
        return shlex.join(
            [
                "flock",
                "-x",
                REMOTE_MIRROR_LOCK,
                REMOTE_MIRROR_HELPER,
                remote_path,
                stage_dir,
            ]
        )

    def _ssh_options(self) -> list[str]:
        options = [
            "-p",
            str(self.config.remote_port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.config.connect_timeout_seconds}",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "StrictHostKeyChecking=yes",
        ]
        if self.config.ssh_key_path is not None:
            options.extend(["-i", str(self.config.ssh_key_path)])
        if self.config.known_hosts_path is not None:
            options.extend(["-o", f"UserKnownHostsFile={self.config.known_hosts_path}"])
        return options

    def _rsync_ssh_command(self) -> str:
        return shlex.join(["ssh", *self._ssh_options()])

    def _rsync_timeout_seconds(self) -> int:
        return max(300, self.config.connect_timeout_seconds * 30)


def _mirror_output_path(config: StewardConfig, output_path: Path | None) -> Path:
    selected = output_path or config.public_mirror.output_path
    if selected is None:
        selected = Path(DEFAULT_PUBLIC_MIRROR_OUTPUT)
    return selected if selected.is_absolute() else config.state_dir / selected


def _is_default_mirror_output(config: StewardConfig, path: Path) -> bool:
    default_path = config.state_dir / DEFAULT_PUBLIC_MIRROR_OUTPUT
    return path.resolve() == default_path.resolve()


def _public_runtime(runtime: DaemonRuntime) -> dict[str, object]:
    last_completed = runtime.last_completed_cycle
    return {
        "instance_id": runtime.instance_id,
        "started_at": _public_timestamp(runtime.started_at),
        "heartbeat_at": _public_timestamp(runtime.heartbeat_at),
        "state": runtime.state.value,
        "current_cycle_started_at": (
            _public_timestamp(runtime.current_cycle_started_at)
            if runtime.current_cycle_started_at is not None
            else None
        ),
        "current_cycle_reason": runtime.current_cycle_reason,
        "last_completed_cycle": (
            {
                "completed_at": _public_timestamp(last_completed.completed_at),
                "reason": last_completed.reason,
                "result": last_completed.result.model_dump(mode="json"),
            }
            if last_completed is not None
            else None
        ),
        "heartbeat_interval_seconds": runtime.heartbeat_interval_seconds,
    }


def _public_publication(
    config: StewardConfig,
    generated_at,
    health: PublicMirrorHealth | None,
) -> dict[str, object]:
    selected = health or PublicMirrorHealth(
        state=(
            "pending"
            if config.public_mirror.enabled and config.public_mirror.publish
            else "disabled"
        ),
        generated_at=generated_at,
    )
    return {
        "state": str(selected.state),
        "snapshot_id": selected.snapshot_id,
        "generated_at": _public_timestamp(generated_at),
        "last_attempt_at": (
            _public_timestamp(selected.last_attempt_at)
            if selected.last_attempt_at
            else None
        ),
        "last_success_at": (
            _public_timestamp(selected.last_success_at)
            if selected.last_success_at
            else None
        ),
        "last_failure_at": (
            _public_timestamp(selected.last_failure_at)
            if selected.last_failure_at
            else None
        ),
        "last_failure_category": (
            str(selected.last_failure_category)
            if selected.last_failure_category
            else None
        ),
        "retry_count": selected.retry_count,
        "last_accepted_digest": selected.last_accepted_digest,
    }


def classify_publish_failure(
    result: CommandResult | BaseException,
) -> PublicMirrorFailureCategory:
    if isinstance(result, BaseException):
        if isinstance(result, TimeoutError):
            return PublicMirrorFailureCategory.timeout
        return PublicMirrorFailureCategory.serialization
    text = f"{result.stdout} {result.stderr}".lower()
    if result.returncode == 124 or "timed out" in text or "timeout" in text:
        return PublicMirrorFailureCategory.timeout
    if "permission denied" in text or "operation not permitted" in text:
        return PublicMirrorFailureCategory.permissions
    command = Path(result.args[0]).name if result.args else ""
    if command == "ssh":
        return PublicMirrorFailureCategory.ssh_preparation
    if command == "rsync":
        return PublicMirrorFailureCategory.rsync_transfer
    return PublicMirrorFailureCategory.unknown


def _public_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _public_state(tasks: list[TaskRecord]) -> str:
    if any(TaskStatus(task.status) in WORKING_STATUSES for task in tasks):
        return "working"
    if any(TaskStatus(task.status) == TaskStatus.queued for task in tasks):
        return "queued"
    if any(
        TaskStatus(task.status) in {TaskStatus.blocked, TaskStatus.failed}
        for task in tasks
    ):
        return "attention"
    return "idle"


def _counts(tasks: list[TaskRecord], signal_items: list[SignalItem]) -> dict[str, int]:
    return {
        "tasks": len(tasks),
        "active": sum(TaskStatus(task.status) in WORKING_STATUSES for task in tasks),
        "queued": sum(TaskStatus(task.status) == TaskStatus.queued for task in tasks),
        "attention": sum(
            TaskStatus(task.status) in {TaskStatus.blocked, TaskStatus.failed}
            for task in tasks
        ),
        "completed": sum(TaskStatus(task.status).terminal for task in tasks),
        "signals": len(signal_items),
        "pending_signals": sum(
            SignalItemStatus(item.status) == SignalItemStatus.pending
            for item in signal_items
        ),
    }


def _public_task(config: StewardConfig, task: TaskRecord) -> dict[str, object]:
    return {
        "id": task.id,
        "title": _public_text(config, task.spec.title),
        "kind": str(task.spec.kind),
        "workflow": str(task.spec.workflow),
        "worker": str(task.spec.worker),
        "priority": str(task.spec.priority),
        "risk": str(task.spec.risk),
        "status": str(task.status),
        "summary": _public_text(config, task.summary),
        "source": task.spec.source,
        "created_at": _public_timestamp(task.created_at),
        "updated_at": _public_timestamp(task.updated_at),
        "validations": [
            {
                "passed": validation.passed,
                "exit_code": validation.exit_code,
                "summary": _public_text(config, validation.summary),
                "iteration": validation.iteration,
                "started_at": _public_timestamp(validation.started_at),
                "completed_at": _public_timestamp(validation.completed_at),
            }
            for validation in task.validations[-5:]
        ],
    }


def _public_task_detail_record(
    config: StewardConfig, task: TaskRecord
) -> dict[str, object]:
    return {
        **_public_task(config, task),
        "branch_name": _public_text(config, task.branch_name),
        "spec": {
            "id": task.id,
            "kind": str(task.spec.kind),
            "workflow": str(task.spec.workflow),
            "worker": str(task.spec.worker),
            "title": _public_text(config, task.spec.title),
            "prompt": (
                _public_text(config, task.spec.prompt)
                if config.public_mirror.transcript_mode == "raw"
                else ""
            ),
            "priority": str(task.spec.priority),
            "risk": str(task.spec.risk),
            "source": task.spec.source,
            "allow_main_write": task.spec.allow_main_write,
            "metadata": _public_metadata(config, task.spec.metadata),
        },
        "has_patch": _safe_file_exists(task.patch_path, config.state_dir),
        "has_transcript": _safe_file_exists(task.transcript_path, config.state_dir),
        "has_last_message": _safe_file_exists(task.last_message_path, config.state_dir),
    }


def _public_attempts(
    config: StewardConfig,
    store: TaskStore,
    task: TaskRecord,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> list[dict[str, object]]:
    iterations = store.iterations(task.id)
    if iterations:
        return [
            _public_iteration_attempt(
                config,
                task,
                item,
                raw_transcript_artifacts=raw_transcript_artifacts,
            )
            for item in iterations
        ]
    worker = _public_run_artifact(
        config,
        task.transcript_path,
        task.last_message_path,
        task_id=task.id,
        label="Worker",
        role="worker",
        name="worker",
        exit_code=None,
        completed=None,
        include_change_trajectory=True,
        raw_transcript_artifacts=raw_transcript_artifacts,
    )
    if worker is None and not task.validations:
        return []
    return [
        {
            "attempt": 0,
            "label": "Initial attempt",
            "worker": worker,
            "reviewer": None,
            "review": None,
            "patch": _public_patch(config, task.patch_path),
            "validations": [
                _public_validation(config, validation, index)
                for index, validation in enumerate(task.validations)
            ],
        }
    ]


def _public_plan_runs(
    config: StewardConfig,
    store: TaskStore,
    task: TaskRecord,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> list[dict[str, object]]:
    return [
        {
            "run": item.run,
            "name": f"implementation-plan-{item.run}",
            "model": _public_text(config, item.model),
            "reasoning_effort": _public_text(config, item.reasoning_effort),
            "exit_code": item.exit_code,
            "completed": item.completed,
            "started_at": _public_timestamp(item.started_at),
            "updated_at": _public_timestamp(item.updated_at),
            "plan": _public_json(config, item.plan_json),
            "planner": _public_run_artifact(
                config,
                item.transcript_path,
                item.last_message_path,
                task_id=task.id,
                label=f"Implementation plan {item.run}",
                role="planner",
                name=f"implementation-plan-{item.run}",
                exit_code=item.exit_code,
                completed=item.completed,
                model=item.model,
                reasoning_effort=item.reasoning_effort,
                include_change_trajectory=False,
                raw_transcript_artifacts=raw_transcript_artifacts,
            ),
        }
        for item in store.plan_runs(task.id)
    ]


def _public_iteration_attempt(
    config: StewardConfig,
    task: TaskRecord,
    item: TaskIteration,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object]:
    return {
        "attempt": item.iteration,
        "label": _public_text(config, item.label),
        "started_at": _public_timestamp(item.started_at),
        "updated_at": _public_timestamp(item.updated_at),
        "worker": _public_run_artifact(
            config,
            item.worker_transcript_path,
            item.worker_last_message_path,
            task_id=task.id,
            label=item.label,
            role="worker",
            name=item.worker_name or f"worker-{item.iteration}",
            exit_code=item.worker_exit_code,
            completed=item.worker_completed,
            model=item.worker_model,
            reasoning_effort=item.worker_reasoning_effort,
            include_change_trajectory=True,
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "reviewer": _public_run_artifact(
            config,
            item.reviewer_transcript_path,
            item.reviewer_last_message_path,
            task_id=task.id,
            label=f"Reviewer {item.iteration}",
            role="reviewer",
            name=item.reviewer_name or f"reviewer-{item.iteration}",
            exit_code=item.reviewer_exit_code,
            completed=item.reviewer_completed,
            model=item.reviewer_model,
            reasoning_effort=item.reviewer_reasoning_effort,
            include_change_trajectory=False,
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "review": _public_review(config, item.review_json),
        "patch": _public_patch(config, item.patch_path),
        "validations": [
            _public_validation(config, validation, index)
            for index, validation in enumerate(task.validations)
            if validation.iteration == item.iteration
        ],
    }


def _public_run_artifact(
    config: StewardConfig,
    transcript_path: Path | None,
    last_message_path: Path | None,
    *,
    task_id: str,
    label: str,
    role: str,
    name: str,
    exit_code: int | None,
    completed: bool | None,
    model: str | None = None,
    reasoning_effort: str | None = None,
    include_change_trajectory: bool = True,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object] | None:
    transcript = _public_text_artifact(
        config,
        transcript_path,
        root=config.state_dir,
        max_bytes=MIRROR_TRANSCRIPT_BYTES,
        line_aligned=True,
        transcript=True,
        task_id=task_id,
        run_name=name,
        raw_transcript_artifacts=raw_transcript_artifacts,
    )
    last_message = _public_text_artifact(
        config,
        last_message_path,
        root=config.state_dir,
        max_bytes=MIRROR_LAST_MESSAGE_BYTES,
        line_aligned=False,
    )
    include_change_trajectory = include_change_trajectory and role == "worker"
    change_trajectory = (
        _public_change_trajectory(config, transcript_path)
        if include_change_trajectory
        and (transcript_path is not None or last_message_path is not None)
        else None
    )
    if transcript is None and last_message is None and change_trajectory is None:
        return None
    diagnostics = diagnostics_for_paths(
        transcript_path=transcript_path,
        last_message_path=last_message_path,
        exit_code=exit_code,
        completed=completed,
    )
    diagnostic_payload = diagnostics.model_dump(mode="json")
    diagnostic_payload.pop("transcript_path", None)
    diagnostic_payload.pop("last_message_path", None)
    diagnostic_payload.pop("thread_id", None)
    diagnostic_payload["summary"] = _public_text(
        config, str(diagnostic_payload.get("summary") or "")
    )
    diagnostic_payload["last_error"] = _public_text(
        config, str(diagnostic_payload.get("last_error") or "")
    )
    diagnostic_payload["last_output"] = _public_text(
        config, str(diagnostic_payload.get("last_output") or "")
    )
    return {
        "name": name,
        "role": role,
        "label": _public_text(config, label),
        "exit_code": exit_code,
        "completed": completed,
        "model": _public_text(config, model),
        "reasoning_effort": _public_text(config, reasoning_effort),
        "diagnostics": diagnostic_payload,
        "transcript": transcript,
        "last_message": last_message,
        "change_trajectory": change_trajectory,
    }


class _TrajectoryReadError(ValueError):
    """Private trajectory evidence failed a trust boundary."""


def _trajectory_empty(
    availability: str,
    completeness: str = "unavailable",
) -> dict[str, object]:
    return {
        "availability": availability,
        "completeness": completeness,
        "discovered_count": 0,
        "published_count": 0,
        "omitted_count": 0,
        "truncated": False,
        "reconciliation": {
            "continuous": False,
            "replay_matches_final": False,
            "gap_count": 0,
            "overlap_count": 0,
            "incomplete_count": 0,
        },
        "changes": [],
    }


def _public_change_trajectory(
    config: StewardConfig, transcript_path: Path | None
) -> dict[str, object]:
    """Read and project bounded code-stage change evidence.

    Only the private summary, manifest metadata, and referenced canonical Git
    deltas are considered.  Inputs, responses, context, and state files are
    deliberately never opened.
    """

    if transcript_path is None:
        return _trajectory_empty("not_produced")
    if not _trajectory_path_beneath(transcript_path.parent, config.state_dir):
        return _trajectory_empty("unavailable")
    try:
        if os.path.lexists(transcript_path):
            transcript_info = transcript_path.lstat()
            if transcript_path.is_symlink() or not transcript_path.is_file() or transcript_info.st_nlink != 1:
                return _trajectory_empty("unavailable")
    except OSError:
        return _trajectory_empty("unavailable")
    try:
        candidates = _trajectory_candidates(transcript_path)
        if not candidates:
            return _trajectory_empty("not_produced")
        if len(candidates) > MIRROR_TRAJECTORY_MAX_RUNS:
            raise _TrajectoryReadError("too many runs")
        runs = [_read_trajectory_run(path) for path in candidates]
        return _project_trajectory(config, runs)
    except _TrajectoryReadError:
        return _trajectory_empty("unavailable")
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        UnicodeError,
        KeyError,
        IndexError,
        AttributeError,
        OverflowError,
    ):
        return _trajectory_empty("unavailable")
    except Exception:
        return _trajectory_empty("unavailable")


def _trajectory_path_beneath(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _trajectory_candidates(transcript_path: Path) -> list[Path]:
    parent = transcript_path.parent
    try:
        if not parent.exists():
            return []
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
            raise _TrajectoryReadError("unsafe run parent")
        names = list(parent.iterdir()) if parent.exists() else []
    except OSError as exc:
        raise _TrajectoryReadError("run parent unavailable") from exc
    for path in names:
        if path.name.startswith("tool-changes.retry-") and not re.fullmatch(
            r"tool-changes\.retry-[1-9][0-9]*", path.name
        ):
            raise _TrajectoryReadError("malformed retry directory")
    # The dependency helper only derives the exact final/retry names; this
    # wrapper adds the fail-closed checks for malformed and symlinked entries.
    candidates = list(tool_change_run_directories(transcript_path))
    unique: dict[str, Path] = {}
    for path in candidates:
        unique[str(path)] = path
    return [unique[key] for key in sorted(unique, key=_trajectory_run_sort_key)]


def _trajectory_run_sort_key(path: str) -> tuple[int, str]:
    name = Path(path).name
    if name == "tool-changes":
        return (1, name)
    match = re.fullmatch(r"tool-changes\.retry-([1-9][0-9]*)", name)
    if match is not None:
        return (0, f"{int(match.group(1)):020d}")
    return (2, name)


def _read_trajectory_run(run_dir: Path) -> dict[str, object]:
    _trajectory_directory(run_dir)
    summary_path = run_dir / "summary.json"
    manifest_path = run_dir / "manifest.jsonl"
    summary = _trajectory_json_file(summary_path, MIRROR_TRAJECTORY_SUMMARY_BYTES)
    manifest_data = _trajectory_manifest_bytes(manifest_path)
    summary_state = _validate_trajectory_summary(summary)
    records = _validate_trajectory_manifest(manifest_data, summary)
    _validate_trajectory_run_trees(summary_state, summary, records)
    hash_budget = 0
    for record in records:
        patch = record.get("patch")
        if isinstance(patch, dict):
            hash_budget += int(patch["bytes"])
            if hash_budget > MIRROR_TRAJECTORY_MAX_HASH_BYTES:
                raise _TrajectoryReadError("patch hash budget")
            _trajectory_validate_patch_file(run_dir, patch)
    return {
        "run_dir": run_dir,
        "summary": summary,
        "state": summary_state,
        "records": records,
    }


def _trajectory_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise _TrajectoryReadError("missing run directory") from exc
    if path.is_symlink() or not path.is_dir() or not _trajectory_no_symlink_parents(path):
        raise _TrajectoryReadError("unsafe run directory")
    if info.st_size < 0:
        raise _TrajectoryReadError("invalid run directory")


def _trajectory_no_symlink_parents(path: Path) -> bool:
    current = path
    try:
        while True:
            if current.is_symlink():
                return False
            if current == current.parent:
                return True
            current = current.parent
    except OSError:
        return False


def _trajectory_regular_file(path: Path, max_bytes: int) -> int:
    try:
        info = path.lstat()
    except OSError as exc:
        raise _TrajectoryReadError("missing evidence file") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or int(info.st_nlink) != 1
        or not _trajectory_no_symlink_parents(path.parent)
    ):
        raise _TrajectoryReadError("unsafe evidence file")
    size = int(info.st_size)
    if size < 0 or size > max_bytes:
        raise _TrajectoryReadError("evidence file exceeds bound")
    return size


def _trajectory_json_file(path: Path, max_bytes: int) -> dict[str, object]:
    _trajectory_regular_file(path, max_bytes)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _TrajectoryReadError("malformed summary") from exc
    if not isinstance(value, dict):
        raise _TrajectoryReadError("summary must be an object")
    return value


def _trajectory_manifest_bytes(path: Path) -> list[bytes]:
    size = _trajectory_regular_file(path, TOOL_CHANGE_MAX_MANIFEST_BYTES)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _TrajectoryReadError("manifest unavailable") from exc
    if len(data) != size:
        raise _TrajectoryReadError("manifest changed during read")
    lines = data.splitlines()
    if len(lines) > TOOL_CHANGE_MAX_COMPLETED_RECORDS:
        raise _TrajectoryReadError("manifest record bound")
    return lines


def _trajectory_nonnegative(value: object, *, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise _TrajectoryReadError("invalid count")
    return value


def _trajectory_tree(value: object, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or TOOL_CHANGE_TREE_RE.fullmatch(value) is None:
        raise _TrajectoryReadError("invalid tree id")
    return value


def _trajectory_timestamp(value: object, *, allow_none: bool = False) -> datetime | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or len(value) > 80:
        raise _TrajectoryReadError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _TrajectoryReadError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise _TrajectoryReadError("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _validate_trajectory_summary(summary: dict[str, object]) -> str:
    if summary.get("schema_version") != TOOL_CHANGE_SCHEMA_VERSION:
        raise _TrajectoryReadError("unsupported summary schema")
    state = summary.get("state")
    completeness = summary.get("completeness")
    if state not in {"complete", "partial", "unavailable"} or completeness != state:
        raise _TrajectoryReadError("invalid summary state")
    counts = {
        key: _trajectory_nonnegative(
            summary.get(key), maximum=TOOL_CHANGE_MAX_COMPLETED_RECORDS
        )
        for key in (
            "discovered",
            "captured",
            "empty",
            "failed",
            "incomplete",
            "gaps",
            "overlaps",
            "omitted",
        )
    }
    if counts["captured"] + counts["empty"] + counts["failed"] + counts["incomplete"] > counts["discovered"]:
        raise _TrajectoryReadError("summary counts exceed discovered")
    reasons = summary.get("reasons")
    reason_categories = summary.get("reason_categories")
    if not isinstance(reasons, list) or not isinstance(reason_categories, list):
        raise _TrajectoryReadError("invalid summary reasons")
    if any(
        not isinstance(item, str) or item not in TOOL_CHANGE_ERROR_CATEGORIES
        for item in reasons + reason_categories
    ):
        raise _TrajectoryReadError("unsupported summary reason")
    if reasons != reason_categories:
        raise _TrajectoryReadError("summary reason mismatch")
    run_start = _trajectory_tree(summary.get("run_start_tree"), allow_none=True)
    final_tree = _trajectory_tree(summary.get("final_tree"), allow_none=True)
    replayed_tree = _trajectory_tree(summary.get("replayed_tree"), allow_none=True)
    for alias, value in (
        ("run_start_tree_id", run_start),
        ("final_tree_id", final_tree),
        ("replayed_tree_id", replayed_tree),
    ):
        if alias not in summary or summary.get(alias) != value:
            raise _TrajectoryReadError("summary tree alias mismatch")
    if state == "unavailable":
        if any(counts.values()) or any(value is not None for value in (run_start, final_tree, replayed_tree)):
            raise _TrajectoryReadError("unavailable summary contains evidence")
    elif state == "complete":
        if reasons or counts["failed"] or counts["incomplete"] or counts["gaps"] or counts["overlaps"] or counts["omitted"]:
            raise _TrajectoryReadError("complete summary has degradation")
        if run_start is None or final_tree is None or replayed_tree != final_tree:
            raise _TrajectoryReadError("complete summary lacks reconciliation")
        if counts["captured"] + counts["empty"] + counts["failed"] != counts["discovered"]:
            raise _TrajectoryReadError("complete summary count mismatch")
    return state


def _trajectory_safe_path(value: object) -> str:
    if not isinstance(value, str) or len(value) > MIRROR_TRAJECTORY_MAX_PATH_BYTES:
        raise _TrajectoryReadError("unsafe path")
    if (
        not value
        or value.startswith("/")
        or value.startswith("./")
        or value == "."
        or "/../" in f"/{value}/"
        or value.endswith("/..")
        or not _TRAJECTORY_SAFE_PATH_RE.fullmatch(value)
        or any(ord(character) < 0x20 for character in value)
    ):
        raise _TrajectoryReadError("unsafe path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _TrajectoryReadError("unsafe path")
    return value


def _trajectory_patch_metadata(patch: object) -> dict[str, object] | None:
    if patch is None:
        return None
    if not isinstance(patch, dict):
        raise _TrajectoryReadError("invalid patch metadata")
    path = _trajectory_safe_path(patch.get("path"))
    if not path.startswith("patches/") or path.count("/") != 1:
        raise _TrajectoryReadError("patch outside patch directory")
    size = _trajectory_nonnegative(
        patch.get("bytes"), maximum=MIRROR_TRAJECTORY_MAX_PATCH_BYTES
    )
    if size <= 0:
        raise _TrajectoryReadError("empty patch metadata")
    digest = patch.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _TrajectoryReadError("invalid patch digest")
    return {"path": path, "bytes": size, "sha256": digest}


def _validate_trajectory_run_trees(
    state: str,
    summary: dict[str, object],
    records: list[dict[str, object]],
) -> None:
    if state != "complete":
        return
    current_tree = summary["run_start_tree"]
    for record in records:
        if record["status"] not in _TRAJECTORY_COMPLETED_STATUSES:
            raise _TrajectoryReadError("complete run contains incomplete record")
        if record["gap_before"] or record["overlap"]:
            raise _TrajectoryReadError("complete run contains discontinuity")
        if record["base_tree"] != current_tree:
            raise _TrajectoryReadError("record tree discontinuity")
        current_tree = record["result_tree"]
    if current_tree != summary["final_tree"]:
        raise _TrajectoryReadError("summary final tree mismatch")


def _validate_trajectory_manifest(
    lines: list[bytes], summary: dict[str, object]
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_starts: set[int] = set()
    seen_completions: set[int] = set()
    last_completion = 0
    counts = {status: 0 for status in _TRAJECTORY_STATUSES}
    for raw_line in lines:
        if not raw_line:
            raise _TrajectoryReadError("blank manifest record")
        try:
            value = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _TrajectoryReadError("malformed manifest record") from exc
        if not isinstance(value, dict):
            raise _TrajectoryReadError("manifest record must be an object")
        status = value.get("status")
        if status not in _TRAJECTORY_STATUSES:
            raise _TrajectoryReadError("unsupported record status")
        tool_name = value.get("tool_name")
        if tool_name not in TOOL_CHANGE_SUPPORTED_TOOLS:
            raise _TrajectoryReadError("unsupported tool")
        tool_id = value.get("tool_use_id")
        if not isinstance(tool_id, str) or TOOL_CHANGE_SAFE_ID_RE.fullmatch(tool_id) is None:
            raise _TrajectoryReadError("unsafe tool id")
        if tool_id in seen_ids:
            raise _TrajectoryReadError("duplicate tool id")
        seen_ids.add(tool_id)
        start = value.get("start_sequence")
        if type(start) is not int or start <= 0 or start > TOOL_CHANGE_MAX_COMPLETED_RECORDS or start in seen_starts:
            raise _TrajectoryReadError("invalid start sequence")
        seen_starts.add(start)
        if value.get("start_order") not in (None, start):
            raise _TrajectoryReadError("start order mismatch")
        if status in _TRAJECTORY_COMPLETED_STATUSES and value.get("start_order") != start:
            raise _TrajectoryReadError("completed record lacks start order")
        start_monotonic = value.get("start_monotonic_ns")
        if type(start_monotonic) is not int or start_monotonic < 0 or start_monotonic > 10**20:
            raise _TrajectoryReadError("invalid monotonic timestamp")
        _trajectory_timestamp(value.get("started_at"))
        _trajectory_tree(value.get("base_tree"))
        if value.get("base_tree_id") not in (None, value.get("base_tree")):
            raise _TrajectoryReadError("base tree alias mismatch")
        if status in _TRAJECTORY_COMPLETED_STATUSES and value.get("base_tree_id") != value.get("base_tree"):
            raise _TrajectoryReadError("completed record lacks base tree alias")
        paths = value.get("paths")
        if not isinstance(paths, list) or len(paths) > MIRROR_TRAJECTORY_MAX_PATHS:
            raise _TrajectoryReadError("invalid changed paths")
        validated_paths = [_trajectory_safe_path(item) for item in paths]
        if validated_paths != sorted(set(validated_paths)):
            raise _TrajectoryReadError("changed paths not canonical")
        if type(value.get("gap_before")) is not bool or type(value.get("overlap")) is not bool:
            raise _TrajectoryReadError("invalid continuity metadata")
        if not isinstance(value.get("input"), dict):
            raise _TrajectoryReadError("invalid private input metadata")
        if status in _TRAJECTORY_COMPLETED_STATUSES and value.get("input_artifact") != value.get("input"):
            raise _TrajectoryReadError("input metadata alias mismatch")
        if status == "incomplete" and "input_artifact" in value and value.get("input_artifact") != value.get("input"):
            raise _TrajectoryReadError("input metadata alias mismatch")
        if status in _TRAJECTORY_COMPLETED_STATUSES and (
            "response" not in value or "response_artifact" not in value
        ):
            raise _TrajectoryReadError("missing response metadata")
        if value.get("response") is not None and not isinstance(value.get("response"), dict):
            raise _TrajectoryReadError("invalid private response metadata")
        if value.get("response_artifact") != value.get("response"):
            raise _TrajectoryReadError("response metadata alias mismatch")
        completion = value.get("completion_sequence")
        if status in _TRAJECTORY_COMPLETED_STATUSES:
            if type(completion) is not int or completion <= 0 or completion > TOOL_CHANGE_MAX_COMPLETED_RECORDS:
                raise _TrajectoryReadError("invalid completion sequence")
            if completion in seen_completions or completion <= last_completion:
                raise _TrajectoryReadError("non-monotonic completion sequence")
            seen_completions.add(completion)
            last_completion = completion
            if value.get("completion_order") != completion:
                raise _TrajectoryReadError("completion order mismatch")
            _trajectory_timestamp(value.get("completed_at"))
            _trajectory_nonnegative(value.get("duration_ms"), maximum=MIRROR_TRAJECTORY_MAX_DURATION_MS)
            _trajectory_tree(value.get("result_tree"))
            if value.get("result_tree_id") != value.get("result_tree"):
                raise _TrajectoryReadError("result tree alias mismatch")
        else:
            if completion is not None or value.get("completion_order") is not None:
                raise _TrajectoryReadError("incomplete completion sequence")
            if value.get("completed_at") is not None or value.get("duration_ms") is not None:
                raise _TrajectoryReadError("incomplete completion metadata")
            if value.get("result_tree") is not None or value.get("result_tree_id") is not None:
                raise _TrajectoryReadError("incomplete result tree")
        patch = _trajectory_patch_metadata(value.get("patch"))
        if status == "captured" and patch is None:
            raise _TrajectoryReadError("captured record lacks patch")
        if status == "empty" and patch is not None:
            raise _TrajectoryReadError("empty record has patch")
        if status in _TRAJECTORY_COMPLETED_STATUSES:
            changed = value.get("base_tree") != value.get("result_tree")
            if (patch is not None) != changed or bool(validated_paths) != changed:
                raise _TrajectoryReadError("record change evidence mismatch")
        if not {"patch_path", "patch_size_bytes", "patch_sha256"}.issubset(value):
            raise _TrajectoryReadError("missing patch aliases")
        if value.get("patch_path") != (patch.get("path") if patch else None):
            raise _TrajectoryReadError("patch path alias mismatch")
        if value.get("patch_size_bytes") != (patch.get("bytes") if patch else 0):
            raise _TrajectoryReadError("patch size alias mismatch")
        if value.get("patch_sha256") != (patch.get("sha256") if patch else None):
            raise _TrajectoryReadError("patch digest alias mismatch")
        error_category = value.get("error_category")
        if error_category is not None and error_category not in TOOL_CHANGE_ERROR_CATEGORIES:
            raise _TrajectoryReadError("unsupported error category")
        if status == "incomplete" and error_category != "missing_post":
            raise _TrajectoryReadError("incomplete error mismatch")
        if status == "failed" and error_category != "tool_failed":
            raise _TrajectoryReadError("failed error mismatch")
        counts[status] += 1
        value["paths"] = validated_paths
        value["patch"] = patch
        value["_completed_at"] = (
            _trajectory_timestamp(value.get("completed_at"))
            if status in _TRAJECTORY_COMPLETED_STATUSES
            else None
        )
        records.append(value)
    for status in _TRAJECTORY_STATUSES:
        if summary.get(status) != counts[status]:
            raise _TrajectoryReadError("manifest count mismatch")
    return records


def _trajectory_validate_patch_file(run_dir: Path, patch: dict[str, object]) -> None:
    relative = str(patch["path"])
    candidate = run_dir.joinpath(*relative.split("/"))
    declared_size = int(patch["bytes"])
    size = _trajectory_regular_file(candidate, MIRROR_TRAJECTORY_MAX_PATCH_BYTES)
    if size != declared_size:
        raise _TrajectoryReadError("patch size mismatch")
    digest = sha256()
    read = 0
    try:
        with candidate.open("rb") as handle:
            while read < declared_size:
                chunk = handle.read(min(1024 * 1024, declared_size - read))
                if not chunk:
                    break
                read += len(chunk)
                digest.update(chunk)
            if handle.read(1):
                raise _TrajectoryReadError("patch grew during read")
    except _TrajectoryReadError:
        raise
    except OSError as exc:
        raise _TrajectoryReadError("patch unavailable") from exc
    if read != declared_size or digest.hexdigest() != patch["sha256"]:
        raise _TrajectoryReadError("patch digest mismatch")


def _trajectory_read_patch(run_dir: Path, patch: dict[str, object]) -> bytes:
    candidate = run_dir.joinpath(*str(patch["path"]).split("/"))
    limit = MIRROR_TRAJECTORY_PATCH_BYTES + 1
    try:
        with candidate.open("rb") as handle:
            data = handle.read(limit)
    except OSError as exc:
        raise _TrajectoryReadError("patch unavailable") from exc
    if not data:
        raise _TrajectoryReadError("patch unexpectedly empty")
    return data


def _trajectory_public_path(config: StewardConfig, value: str) -> str:
    if _TRAJECTORY_SENSITIVE_PATH_RE.search(value):
        return "[redacted-path]"
    return _public_text(config, value)


def _trajectory_redacted_patch(config: StewardConfig, data: bytes) -> str:
    # Canonical patches are generated by Git; only their text is projected.
    # Tool inputs and responses are in separate private files and never enter
    # this function.
    text = data.decode("utf-8", errors="replace")
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split(" ")
            if len(parts) >= 4:
                parts[2] = _trajectory_public_patch_path(config, parts[2])
                parts[3] = _trajectory_public_patch_path(config, parts[3])
                line = " ".join(parts)
        elif line.startswith(("--- ", "+++ ")):
            prefix, _, path = line.partition(" ")
            line = f"{prefix} {_trajectory_public_patch_path(config, path)}"
        lines.append(_trajectory_public_patch_line(config, line))
    return "\n".join(lines) + ("\n" if lines else "")


def _trajectory_public_patch_line(config: StewardConfig, value: str) -> str:
    projected = _public_json(config, value)
    if not isinstance(projected, str):
        raise _TrajectoryReadError("invalid public patch line")
    projected = _trajectory_redact_absolute_paths(projected)
    projected = _TRAJECTORY_WINDOWS_PATH_RE.sub("[local-path]", projected)
    projected = _trajectory_redact_urls(projected)
    projected = _TRAJECTORY_CREDENTIAL_RE.sub("[redacted-secret]", projected)
    projected = _TRAJECTORY_PRIVATE_MARKER_RE.sub("[redacted-private]", projected)
    return _trajectory_redact_private_assignment(projected)


def _trajectory_redact_absolute_paths(value: str) -> str:
    output: list[str] = []
    copied = 0
    index = 0
    while index < len(value):
        if value[index] != "/" or (
            index > 0 and (value[index - 1].isalnum() or value[index - 1] == ":")
        ):
            index += 1
            continue
        end = index + 1
        while end < len(value) and (
            value[end].isascii()
            and (value[end].isalnum() or value[end] in {".", "_", "-", "/"})
        ):
            end += 1
        path = value[index + 1 : end].rstrip("/")
        parts = path.split("/")
        if len(parts) >= 2 and all(parts):
            output.extend((value[copied:index], "[local-path]"))
            copied = index + 1 + len(path)
        index = end
    output.append(value[copied:])
    return "".join(output)


def _trajectory_redact_urls(value: str) -> str:
    output: list[str] = []
    copied = 0
    search_from = 0
    while True:
        marker = value.find("://", search_from)
        if marker < 0:
            break
        run_start = marker
        while run_start > copied and _trajectory_scheme_character(value[run_start - 1]):
            run_start -= 1
        scheme_start = run_start
        while scheme_start < marker and not (
            value[scheme_start].isascii() and value[scheme_start].isalpha()
        ):
            scheme_start += 1
        end = marker + 3
        while end < len(value) and not _public_token_terminator(value[end]):
            end += 1
        if scheme_start == marker:
            search_from = marker + 3
            continue
        output.extend((value[copied:scheme_start], "[redacted-url]"))
        copied = end
        search_from = end
    output.append(value[copied:])
    return "".join(output)


def _trajectory_scheme_character(value: str) -> bool:
    return value.isascii() and (value.isalnum() or value in {"+", ".", "-"})


def _public_token_terminator(value: str) -> bool:
    return value.isspace() or value in _PUBLIC_TOKEN_TERMINATORS


def _trajectory_redact_private_assignment(value: str) -> str:
    for separator, character in enumerate(value):
        if character not in {":", "="}:
            continue
        key_end = separator
        while key_end > 0 and value[key_end - 1].isspace():
            key_end -= 1
        if key_end > 0 and value[key_end - 1] in {"\"", "'"}:
            key_end -= 1
        key_start = key_end
        while key_start > 0 and (
            value[key_start - 1].isalnum() or value[key_start - 1] in {"_", "-"}
        ):
            key_start -= 1
        key = value[key_start:key_end].lower()
        normalized_key = key.replace("_", "").replace("-", "")
        if not (
            any(part in key for part in _TRAJECTORY_PRIVATE_ASSIGNMENT_PARTS)
            or "apikey" in normalized_key
        ):
            continue
        value_start = separator + 1
        while value_start < len(value) and value[value_start].isspace():
            value_start += 1
        return f"{value[:value_start]}[redacted-private]"
    return value


def _trajectory_public_patch_path(config: StewardConfig, value: str) -> str:
    # Preserve Git's a/ and b/ markers while avoiding private absolute paths
    # and credential-looking filenames in the public delta.
    marker = ""
    path = value
    if value[:2] in {"a/", "b/"}:
        marker, path = value[:2], value[2:]
    if path.startswith("/") or _TRAJECTORY_SENSITIVE_PATH_RE.search(path):
        return marker + "[redacted-path]"
    return marker + _public_text(config, path)


def _trajectory_bound_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    bounded = encoded[:max_bytes]
    # Avoid publishing a partial UTF-8 code point and keep a canonical line
    # boundary where possible.
    bounded = bounded.decode("utf-8", errors="ignore").encode("utf-8")
    newline = bounded.rfind(b"\n")
    if newline >= 0:
        bounded = bounded[: newline + 1]
    return bounded.decode("utf-8", errors="ignore"), True


def _trajectory_patch_artifact(
    config: StewardConfig,
    run_dir: Path,
    record: dict[str, object],
    remaining_budget: int,
) -> tuple[dict[str, object], int, bool]:
    patch = record.get("patch")
    status = str(record.get("status"))
    if patch is None:
        availability = "not_produced" if status == "empty" else "unavailable"
        return (
            {
                "availability": availability,
                "mode": "redacted",
                "text": "",
                "size_bytes": 0,
                "original_size_bytes": None,
                "truncated": False,
            },
            0,
            False,
        )
    if remaining_budget <= 0:
        return (
            {
                "availability": "unavailable",
                "mode": "redacted",
                "text": "",
                "size_bytes": 0,
                "original_size_bytes": patch["bytes"],
                "truncated": True,
            },
            0,
            True,
        )
    data = _trajectory_read_patch(run_dir, patch)
    text = _trajectory_redacted_patch(config, data)
    bounded, per_patch_truncated = _trajectory_bound_text(
        text, MIRROR_TRAJECTORY_PATCH_BYTES
    )
    encoded = bounded.encode("utf-8")
    aggregate_truncated = False
    if len(encoded) > remaining_budget:
        bounded, aggregate_truncated = _trajectory_bound_text(
            bounded, remaining_budget
        )
        encoded = bounded.encode("utf-8")
    truncated = per_patch_truncated or aggregate_truncated or len(data) > MIRROR_TRAJECTORY_PATCH_BYTES
    artifact = {
        "availability": "available",
        "mode": "redacted",
        "text": bounded,
        "size_bytes": len(encoded),
        "original_size_bytes": patch["bytes"],
        "truncated": truncated,
    }
    return artifact, len(encoded), truncated


def _public_trajectory_change(
    config: StewardConfig,
    run: dict[str, object],
    record: dict[str, object],
    remaining_budget: int,
) -> tuple[dict[str, object], int, bool]:
    patch_artifact, used, omitted = _trajectory_patch_artifact(
        config, run["run_dir"], record, remaining_budget
    )
    status = str(record["status"])
    error_category = record.get("error_category")
    return (
        {
            "sequence": 0,
            "tool_call_id": record["tool_use_id"],
            "tool_name": record["tool_name"],
            "status": status,
            "paths": [
                _trajectory_public_path(config, path) for path in record["paths"]
            ],
            "base_tree": record["base_tree"],
            "result_tree": record.get("result_tree"),
            "patch": patch_artifact,
            "error_category": error_category or "",
        },
        used,
        omitted,
    )


def _project_trajectory(
    config: StewardConfig, runs: list[dict[str, object]]
) -> dict[str, object]:
    states = [str(run["state"]) for run in runs]
    if any(state == "unavailable" for state in states):
        return _trajectory_empty("unavailable")
    records: list[tuple[datetime, int, int, dict[str, object], dict[str, object]]] = []
    discovered = 0
    omitted_count = 0
    gap_count = 0
    overlap_count = 0
    incomplete_count = 0
    replay_matches = True
    continuous = True
    summary_truncated = False
    previous_final_tree: object = None
    for run_index, run in enumerate(runs):
        summary = run["summary"]
        run_start_tree = summary.get("run_start_tree")
        if (
            previous_final_tree is not None
            and run_start_tree is not None
            and run_start_tree != previous_final_tree
        ):
            raise _TrajectoryReadError("retry tree discontinuity")
        previous_final_tree = summary.get("final_tree")
        discovered += int(summary["discovered"])
        omitted_count += int(summary["omitted"])
        gap_count += int(summary["gaps"])
        overlap_count += int(summary["overlaps"])
        incomplete_count += int(summary["incomplete"])
        final_tree = summary.get("final_tree")
        replayed_tree = summary.get("replayed_tree")
        if final_tree is None or replayed_tree is None or final_tree != replayed_tree:
            replay_matches = False
        if summary["gaps"] or summary["overlaps"] or summary["incomplete"] or summary["omitted"]:
            continuous = False
        if summary["omitted"]:
            summary_truncated = True
        for record in run["records"]:
            if record["status"] not in _TRAJECTORY_COMPLETED_STATUSES:
                continue
            completed_at = record.get("_completed_at")
            if not isinstance(completed_at, datetime):
                raise _TrajectoryReadError("completed record lacks timestamp")
            records.append(
                (
                    completed_at,
                    int(record["completion_sequence"]),
                    run_index,
                    run,
                    record,
                )
            )
    records.sort(key=lambda item: (item[0], item[2], item[1]))
    record_truncated = len(records) > MIRROR_TRAJECTORY_RECORDS
    selected = records[-MIRROR_TRAJECTORY_RECORDS:]
    if record_truncated:
        omitted_count += len(records) - len(selected)
        continuous = False
    aggregate_budget = MIRROR_TRAJECTORY_AGGREGATE_PATCH_BYTES
    changes: list[dict[str, object]] = []
    omitted_patches = 0
    any_patch_truncated = False
    for sequence, (_completed_at, _completion, _run_index, run, record) in enumerate(
        selected, start=1
    ):
        change, used, patch_omitted = _public_trajectory_change(
            config, run, record, aggregate_budget
        )
        change["sequence"] = sequence
        aggregate_budget -= used
        omitted_patches += int(patch_omitted)
        patch = change.get("patch")
        if isinstance(patch, dict) and patch.get("truncated"):
            any_patch_truncated = True
        changes.append(change)
    if omitted_patches:
        omitted_count += omitted_patches
        continuous = False
    truncated = (
        summary_truncated
        or record_truncated
        or omitted_patches > 0
        or any_patch_truncated
    )
    completeness = "partial" if any(state == "partial" for state in states) else "complete"
    if truncated:
        completeness = "partial"
    return {
        "availability": "available",
        "completeness": completeness,
        "discovered_count": discovered,
        "published_count": len(changes),
        "omitted_count": omitted_count,
        "truncated": truncated,
        "reconciliation": {
            "continuous": continuous,
            "replay_matches_final": replay_matches,
            "gap_count": gap_count,
            "overlap_count": overlap_count,
            "incomplete_count": incomplete_count,
        },
        "changes": changes,
    }


def _public_validation(
    config: StewardConfig, validation: ValidationResult, index: int
) -> dict[str, object]:
    log = _public_text_artifact(
        config,
        validation.output_path,
        root=config.state_dir,
        max_bytes=MIRROR_LOG_BYTES,
        line_aligned=True,
    )
    return {
        "index": index,
        "command": [_public_command_part(config, part) for part in validation.command],
        "passed": validation.passed,
        "exit_code": validation.exit_code,
        "summary": _public_text(config, validation.summary),
        "iteration": validation.iteration,
        "started_at": _public_timestamp(validation.started_at),
        "completed_at": _public_timestamp(validation.completed_at),
        "log": log,
    }


def _public_task_artifacts(
    config: StewardConfig,
    task: TaskRecord,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object]:
    return {
        "patch": _public_patch(config, task.patch_path),
        "transcript": _public_text_artifact(
            config,
            task.transcript_path,
            root=config.state_dir,
            max_bytes=MIRROR_TRANSCRIPT_BYTES,
            line_aligned=True,
            transcript=True,
            task_id=task.id,
            run_name="task",
            raw_transcript_artifacts=raw_transcript_artifacts,
        ),
        "last_message": _public_text_artifact(
            config,
            task.last_message_path,
            root=config.state_dir,
            max_bytes=MIRROR_LAST_MESSAGE_BYTES,
            line_aligned=False,
        ),
    }


def _public_patch(config: StewardConfig, path: Path | None) -> dict[str, object] | None:
    return _public_text_artifact(
        config,
        path,
        root=config.state_dir,
        max_bytes=MIRROR_PATCH_BYTES,
        line_aligned=True,
    )


def _public_text_artifact(
    config: StewardConfig,
    path: Path | None,
    *,
    root: Path,
    max_bytes: int,
    line_aligned: bool,
    transcript: bool = False,
    task_id: str | None = None,
    run_name: str | None = None,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object] | None:
    if path is None or not _allowed_public_file(path, root):
        return None
    if transcript and config.public_mirror.transcript_mode == "none":
        return None
    if transcript and config.public_mirror.transcript_mode == "raw":
        if task_id is None or run_name is None:
            return None
        if raw_transcript_artifacts is not None:
            return raw_transcript_artifacts.get(
                _public_raw_transcript_url(task_id, run_name)
            )
        return _public_raw_transcript_artifact(
            config, path, task_id=task_id, run_name=run_name
        )
    try:
        size = path.stat().st_size
        text = _tail_text(path, max_bytes=max_bytes, line_aligned=line_aligned)
    except OSError:
        return None
    if transcript:
        text = _public_transcript_text(text)
    text = _public_text(config, text)
    return {
        "text": text,
        "size": size,
        "size_bytes": len(text.encode("utf-8")),
        "original_size_bytes": size,
        "truncated": size > max_bytes,
        "tail_bytes": min(size, max_bytes),
        "availability": "available",
        "mode": "redacted",
    }


def _public_raw_transcript_artifact(
    config: StewardConfig, path: Path, *, task_id: str, run_name: str
) -> dict[str, object] | None:
    try:
        size = path.stat().st_size
        digest = _file_sha256(path)
    except OSError:
        return None
    return {
        "text": "",
        "size": size,
        "size_bytes": size,
        "original_size_bytes": size,
        "truncated": False,
        "tail_bytes": 0,
        "availability": "available",
        "mode": "raw",
        "url": _public_raw_transcript_url(task_id, run_name),
        "sha256": digest,
    }


def _write_public_raw_transcripts(
    config: StewardConfig, store: TaskStore, tasks_dir: Path, task: TaskRecord
) -> _RawTranscriptArtifacts:
    snapshots: _RawTranscriptArtifacts = {}
    if config.public_mirror.transcript_mode != "raw":
        return snapshots
    task_dir = tasks_dir / _safe_public_segment(task.id, fallback="task")
    expected_runs: set[str] = set()

    def copy_transcript(source: Path | None, run_name: str) -> None:
        copied = _copy_public_raw_transcript(
            config,
            source,
            task_dir=task_dir,
            run_name=run_name,
        )
        if copied is None:
            return
        run_segment, destination = copied
        expected_runs.add(run_segment)
        artifact = _public_raw_transcript_artifact(
            config,
            destination,
            task_id=task.id,
            run_name=run_segment,
        )
        if artifact is not None:
            snapshots[_public_raw_transcript_url(task.id, run_segment)] = artifact

    copy_transcript(task.transcript_path, "task")
    for item in store.plan_runs(task.id):
        copy_transcript(item.transcript_path, f"implementation-plan-{item.run}")
    iterations = store.iterations(task.id)
    if iterations:
        for item in iterations:
            copy_transcript(
                item.worker_transcript_path,
                item.worker_name or f"worker-{item.iteration}",
            )
            copy_transcript(
                item.reviewer_transcript_path,
                item.reviewer_name or f"reviewer-{item.iteration}",
            )
    else:
        copy_transcript(task.transcript_path, "worker")
    copy_transcript(
        config.transcripts_dir / task.id / "commit-message" / "codex.jsonl",
        "commit-message",
    )
    runs_dir = task_dir / "runs"
    if runs_dir.is_dir():
        for path in runs_dir.iterdir():
            if path.name in expected_runs:
                continue
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path)
    if not expected_runs and task_dir.is_dir():
        shutil.rmtree(task_dir)
    return snapshots


def _copy_public_raw_transcript(
    config: StewardConfig,
    source: Path | None,
    *,
    task_dir: Path,
    run_name: str,
) -> tuple[str, Path] | None:
    if source is None or not _allowed_public_file(source, config.state_dir):
        return None
    run_segment = _safe_public_segment(run_name)
    destination = task_dir / "runs" / run_segment / "codex.jsonl"
    try:
        if source.resolve() == destination.resolve():
            return run_segment, destination
    except OSError:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        unchanged = destination.is_file() and (
            _file_sha256(source) == _file_sha256(destination)
        )
    except OSError:
        unchanged = False
    if not unchanged:
        shutil.copyfile(source, destination)
        _restrictive_file_permissions(destination)
    return run_segment, destination


def _public_raw_transcript_url(task_id: str, run_name: str) -> str:
    return (
        f"{PUBLIC_TASK_DATA_PREFIX}/{_safe_public_segment(task_id, fallback='task')}/runs/"
        f"{_safe_public_segment(run_name)}/codex.jsonl"
    )


def _public_task_detail_url(task_id: str) -> str:
    return f"{PUBLIC_TASK_DATA_PREFIX}/{_safe_public_segment(task_id, fallback='task')}.json"


def _safe_public_segment(value: object, *, fallback: str = "run") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip(".-")
    return cleaned or fallback


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _public_transcript_text(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            lines.append(line)
            continue
        if event.get("type") in {"thread.started", "turn.started", "turn.completed"}:
            continue
        rendered = _render_transcript_event(event)
        if rendered:
            lines.append(rendered)
    return "\n".join(lines)


def _render_transcript_event(event: dict[str, Any]) -> str:
    item = event.get("item")
    if isinstance(item, dict):
        return _render_transcript_item(item)
    event_type = str(event.get("type") or "")
    if event_type == "stderr":
        return _labeled_text("stderr", event.get("text") or event.get("message"))
    return _labeled_text(event_type or "event", event.get("text") or event.get("message"))


def _render_transcript_item(item: dict[str, Any]) -> str:
    item_type = str(item.get("type") or "item")
    renderer = _TRANSCRIPT_ITEM_RENDERERS.get(item_type)
    if renderer is not None:
        return renderer(item)
    if item_type in _TRANSCRIPT_TOOL_CALL_TYPES:
        return _render_transcript_tool_call(item, item_type)
    return _render_default_transcript_item(item, item_type)


def _render_agent_message_item(item: dict[str, Any]) -> str:
    return str(item.get("text") or "")


def _render_reasoning_item(item: dict[str, Any]) -> str:
    return _labeled_text("reasoning", item.get("text") or item.get("message"))


def _render_command_execution_item(item: dict[str, Any]) -> str:
    command = str(item.get("command") or "").strip()
    output = str(item.get("aggregated_output") or "").strip()
    status = str(item.get("status") or "unknown")
    exit_code = item.get("exit_code")
    header = f"command {status}"
    if exit_code is not None:
        header += f" exit={exit_code}"
    if command:
        header += f": {command}"
    return "\n".join(part for part in (header, output) if part)


def _render_file_change_item(item: dict[str, Any]) -> str:
    changes = item.get("changes")
    if not isinstance(changes, list):
        return _render_default_transcript_item(item, "file_change")
    rendered = [
        _render_file_change(change) for change in changes if isinstance(change, dict)
    ]
    if not rendered:
        return _render_default_transcript_item(item, "file_change")
    return "file changes\n" + "\n".join(rendered)


def _render_file_change(change: dict[str, Any]) -> str:
    return f"{change.get('kind', 'change')}: {change.get('path', '')}"


def _render_todo_list_item(item: dict[str, Any]) -> str:
    todos = item.get("items")
    if not isinstance(todos, list):
        return _render_default_transcript_item(item, "todo_list")
    rendered = [_render_todo(todo) for todo in todos if isinstance(todo, dict)]
    if not rendered:
        return _render_default_transcript_item(item, "todo_list")
    return "todo list\n" + "\n".join(rendered)


def _render_todo(todo: dict[str, Any]) -> str:
    mark = "x" if todo.get("completed") else " "
    return f"[{mark}] {todo.get('text', '')}"


def _render_transcript_tool_call(item: dict[str, Any], item_type: str) -> str:
    return _labeled_text(
        str(item.get("name") or item.get("tool_name") or item_type),
        item.get("status") or item.get("text") or item.get("message"),
    )


def _render_error_item(item: dict[str, Any]) -> str:
    return _labeled_text("error", item.get("message"))


def _render_default_transcript_item(item: dict[str, Any], item_type: str) -> str:
    return _labeled_text(item_type, item.get("text") or item.get("message"))


_TRANSCRIPT_TOOL_CALL_TYPES = {"tool_call", "function_call", "mcp_tool_call"}
_TRANSCRIPT_ITEM_RENDERERS = {
    "agent_message": _render_agent_message_item,
    "reasoning": _render_reasoning_item,
    "command_execution": _render_command_execution_item,
    "file_change": _render_file_change_item,
    "todo_list": _render_todo_list_item,
    "error": _render_error_item,
}


def _labeled_text(label: str, value: object) -> str:
    text = str(value or "").strip()
    return f"{label}: {text}" if text else label


def _public_review(config: StewardConfig, review: dict[str, Any] | None) -> dict[str, object] | None:
    if not isinstance(review, dict):
        return None
    return _public_json(config, review)


def _public_event(config: StewardConfig, event: Event) -> dict[str, object]:
    return {
        "task_id": event.task_id,
        "kind": event.kind,
        "message": _public_text(config, event.message),
        "created_at": _public_timestamp(event.created_at),
        "data": _public_event_data(config, event.data),
    }


def _public_event_data(config: StewardConfig, data: dict[str, Any]) -> dict[str, object]:
    cleaned = _public_json(config, data)
    return cleaned if isinstance(cleaned, dict) else {}


def _public_metadata(config: StewardConfig, metadata: dict[str, Any]) -> dict[str, object]:
    return {
        key: _public_json(config, value)
        for key, value in metadata.items()
        if key in PUBLIC_METADATA_KEYS and not _private_key(key)
    }


def _public_json(config: StewardConfig, value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            key_text = str(key)
            if _private_key(key_text):
                continue
            if _looks_like_link(key_text) and isinstance(item, str):
                safe_link = _safe_public_link(config, item)
                if safe_link is None:
                    continue
                cleaned[key_text] = safe_link
                continue
            cleaned[key_text] = _public_json(config, item)
        return cleaned
    if isinstance(value, list):
        return [_public_json(config, item) for item in value[:40]]
    if isinstance(value, tuple):
        return [_public_json(config, item) for item in value[:40]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _public_text(config, value) if isinstance(value, str) else value
    return _public_text(config, str(value))


def _private_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in PRIVATE_DATA_KEY_PARTS)


def _public_command_part(config: StewardConfig, value: object) -> str:
    return _public_text(config, str(value))


def _public_signal_item(
    config: StewardConfig, item: SignalItem
) -> dict[str, object]:
    return {
        "id": item.id,
        "provider": item.provider,
        "kind": item.kind,
        "title": _public_text(config, item.title),
        "summary": _public_text(config, item.summary),
        "severity": item.severity,
        "status": item.status,
        "created_at": _public_timestamp(item.created_at),
        "updated_at": _public_timestamp(item.updated_at),
        "planned_at": _public_timestamp(item.planned_at) if item.planned_at else None,
        "planned_task_id": item.planned_task_id,
        "links": [
            {**link, "url": safe_url}
            for link in item.links
            if isinstance(link.get("url"), str)
            and (safe_url := _safe_public_link(config, str(link["url"])))
        ],
    }


def _public_fetch_run(config: StewardConfig, run: SignalFetchRun) -> dict[str, object]:
    return {
        "id": run.id,
        "provider": run.provider,
        "status": run.status,
        "started_at": _public_timestamp(run.started_at),
        "completed_at": _public_timestamp(run.completed_at),
        "item_count": run.item_count,
        "new_item_count": run.new_item_count,
        "has_more": run.has_more,
        "summary": _public_fetch_summary(config, run),
        "error": _public_error(run.error),
    }


def _public_error(error: str | None) -> str | None:
    if not error:
        return None
    if "timed out" in error.lower():
        return "request timed out"
    return "provider error"


def _public_fetch_summary(config: StewardConfig, run: SignalFetchRun) -> str:
    if run.error:
        return _public_error(run.error) or "provider error"
    return _public_text(config, run.summary)


def _public_signals_summary(
    items: list[SignalItem], fetch_runs: list[SignalFetchRun]
) -> str:
    errors = sum(run.status == "error" for run in fetch_runs)
    return f"{len(items)} signal item(s), {errors} provider error(s)"


def _public_scheduler_state(
    state: SchedulerState,
    *,
    pending_wakeups: list[Any] | None = None,
    recent_wakeups: list[Any] | None = None,
) -> dict[str, object]:
    pending = state.pending_wakeups if pending_wakeups is None else pending_wakeups
    recent = state.recent_wakeups if recent_wakeups is None else recent_wakeups
    return {
        "source_active": state.source_active,
        "source_capacity": state.source_capacity,
        "source_queued": state.source_queued,
        "integration_active": state.integration_active,
        "integration_queued": state.integration_queued,
        "pending_wakeups_truncated": len(pending) > DEFAULT_MIRROR_WAKEUP_LIMIT,
        "recent_wakeups_truncated": len(recent) > DEFAULT_MIRROR_WAKEUP_LIMIT,
        "pending_wakeups": [
            _public_wakeup(wakeup) for wakeup in pending[:DEFAULT_MIRROR_WAKEUP_LIMIT]
        ],
        "recent_wakeups": [
            _public_wakeup(wakeup) for wakeup in recent[:DEFAULT_MIRROR_WAKEUP_LIMIT]
        ],
        "providers": [
            _public_provider(provider)
            for provider in state.providers
        ],
    }


def _public_provider(provider: Any) -> dict[str, object]:
    return {
        "provider": provider.provider,
        "poll_interval_minutes": provider.poll_interval_minutes,
        "error_retry_minutes": provider.error_retry_minutes,
        "idle_poll_interval_minutes": provider.idle_poll_interval_minutes,
        "suppression_hours": provider.suppression_hours,
        "max_items": provider.max_items,
        "last_fetch_at": (
            _public_timestamp(provider.last_fetch_at)
            if provider.last_fetch_at is not None
            else None
        ),
        "last_status": (
            str(provider.last_status) if provider.last_status is not None else None
        ),
        "last_error": _public_error(provider.last_error),
        "next_due_at": _public_timestamp(provider.next_due_at),
        "idle_next_due_at": (
            _public_timestamp(provider.idle_next_due_at)
            if provider.idle_next_due_at is not None
            else None
        ),
        "due": provider.due,
        "idle_due": provider.idle_due,
    }


def _public_wakeup(wakeup: Any) -> dict[str, object]:
    return {
        "id": wakeup.id,
        "reason": wakeup.reason,
        "status": str(wakeup.status),
        "created_at": _public_timestamp(wakeup.created_at),
        "consumed_at": (
            _public_timestamp(wakeup.consumed_at) if wakeup.consumed_at else None
        ),
        "data": _public_json_for_scheduler(wakeup.data),
    }


def _public_json_for_scheduler(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _public_json_for_scheduler(item)
            for key, item in value.items()
            if not _private_key(str(key))
        }
    if isinstance(value, list):
        return [_public_json_for_scheduler(item) for item in value[:20]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _public_configuration(config: StewardConfig) -> dict[str, object]:
    return {
        "repository": config.github_repository,
        "main_branch": config.main_branch,
        "integration_mode": config.integration_mode,
        "local_only": config.local_only,
        "enabled_signals": list(config.enabled_signals),
        "scheduler_wait_interval_sec": config.scheduler_wait_interval_sec,
        "limits": {
            "max_active_tasks": config.limits.max_active_tasks,
            "max_main_pushes_per_day": config.limits.max_main_pushes_per_day,
            "plan_timeout_minutes": config.limits.plan_timeout_minutes,
            "worker_timeout_minutes": config.limits.worker_timeout_minutes,
            "review_timeout_minutes": config.limits.review_timeout_minutes,
            "validation_timeout_minutes": config.limits.validation_timeout_minutes,
            "stale_task_minutes": config.limits.stale_task_minutes,
        },
        "signal_providers": {
            name: {
                "poll_interval_minutes": provider.poll_interval_minutes,
                "error_retry_minutes": provider.error_retry_minutes,
                "idle_poll_interval_minutes": provider.idle_poll_interval_minutes,
                "suppression_hours": provider.suppression_hours,
                "max_items": provider.max_items,
            }
            for name, provider in sorted(config.signal_providers.items())
        },
    }


def _public_planner_runs(
    config: StewardConfig, store: TaskStore
) -> tuple[list[dict[str, object]], bool]:
    run_ids = {
        path.name
        for root in (config.prompts_dir, config.transcripts_dir)
        for path in root.glob("planner-task-*")
        if path.is_dir() and re.fullmatch(r"planner-task-\d{14}-[a-f0-9]{8}", path.name)
    }
    finished_by_id: dict[str, Any] = {}
    for event in store.events("daemon", limit=400):
        if event.kind != "planner.finished":
            continue
        run_id = event.data.get("run_id")
        if isinstance(run_id, str) and re.fullmatch(
            r"planner-task-\d{14}-[a-f0-9]{8}", run_id
        ):
            finished_by_id[run_id] = event
            run_ids.add(run_id)

    records: list[dict[str, object]] = []
    for run_id in run_ids:
        prompt_path = config.prompts_dir / run_id / "planner.md"
        transcript_path = config.transcripts_dir / run_id / "planner" / "codex.jsonl"
        last_message_path = config.transcripts_dir / run_id / "planner" / "last-message.md"
        event = finished_by_id.get(run_id)
        data = event.data if event is not None else {}
        completed = data.get("completed") if isinstance(data.get("completed"), bool) else None
        exit_code = data.get("exit_code") if isinstance(data.get("exit_code"), int) else None
        status = _planner_public_status(completed, exit_code)
        diagnostics = _planner_public_diagnostics(
            config,
            transcript_path,
            last_message_path,
            completed=completed,
            exit_code=exit_code,
        )
        started_at = _path_timestamp(prompt_path, transcript_path)
        completed_at = _path_timestamp(transcript_path, last_message_path) if completed is not None else None
        records.append(
            {
                "id": run_id,
                "status": status,
                "started_at": started_at,
                "completed_at": completed_at,
                "accepted_count": _nonnegative_int(data.get("accepted_count")),
                "proposed_count": _nonnegative_int(data.get("proposed_count")),
                "consumed_signal_ids": [
                    item
                    for item in data.get("consumed_item_ids", [])[:40]
                    if isinstance(item, str)
                ],
                "diagnostics": diagnostics,
                "artifacts": {
                    "transcript": _public_text_artifact(
                        config,
                        transcript_path,
                        root=config.state_dir,
                        max_bytes=MIRROR_TRANSCRIPT_BYTES,
                        line_aligned=True,
                        transcript=True,
                    ),
                    "last_message": _public_text_artifact(
                        config,
                        last_message_path,
                        root=config.state_dir,
                        max_bytes=MIRROR_LAST_MESSAGE_BYTES,
                        line_aligned=False,
                    ),
                },
            }
        )
    records.sort(key=lambda item: str(item["started_at"]), reverse=True)
    return records[:40], len(records) > 40


def _planner_public_status(completed: bool | None, exit_code: int | None) -> str:
    if completed is None:
        return "running"
    if completed and exit_code == 0:
        return "succeeded"
    return "failed"


def _planner_public_diagnostics(
    config: StewardConfig,
    transcript_path: Path,
    last_message_path: Path,
    *,
    completed: bool | None,
    exit_code: int | None,
) -> dict[str, object]:
    if completed is True and exit_code == 0:
        category = "none"
    elif exit_code == 124:
        category = "timeout"
    elif completed is False:
        category = "execution_error"
    else:
        category = "invalid_output"
    diagnostics = diagnostics_for_paths(
        transcript_path=transcript_path,
        last_message_path=last_message_path,
        exit_code=exit_code,
        completed=completed,
    ).model_dump(mode="json")
    return {
        "summary": _public_text(config, str(diagnostics.get("summary") or "")),
        "exit_code": exit_code,
        "error_category": category,
        "last_message_present": last_message_path.is_file(),
    }


def _path_timestamp(*paths: Path) -> str:
    existing = [path for path in paths if path.is_file()]
    timestamp = max((path.stat().st_mtime for path in existing), default=0)
    if timestamp <= 0:
        return _public_timestamp(utc_now())
    return _public_timestamp(datetime.fromtimestamp(timestamp, timezone.utc))


def _nonnegative_int(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _integration_summary(
    config: StewardConfig, tasks: list[TaskRecord]
) -> dict[str, object]:
    integration_tasks = [
        task
        for task in tasks
        if task.spec.kind == "integration" or task.spec.worker == "integration-manager"
    ]
    commits = []
    for task in integration_tasks:
        commit = _str_or_none(task.spec.metadata.get("main_commit"))
        if not commit:
            continue
        commits.append(
            {
                "task_id": task.id,
                "title": _public_text(config, task.spec.title),
                "status": str(task.status),
                "summary": _public_text(config, task.summary),
                "commit": commit,
                "commit_url": f"https://github.com/{config.github_repository}/commit/{commit}",
                "updated_at": _public_timestamp(task.updated_at),
            }
        )
    return {
        "active": [
            _public_task(config, task)
            for task in integration_tasks
            if TaskStatus(task.status) in WORKING_STATUSES
        ],
        "queue": [
            _public_task(config, task)
            for task in integration_tasks
            if TaskStatus(task.status) == TaskStatus.queued
        ],
        "commits": commits[:20],
    }


def _public_integration_detail(
    config: StewardConfig,
    store: TaskStore,
    task: TaskRecord,
    source_task: TaskRecord | None,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object]:
    integration_tasks = [
        candidate
        for candidate in store.list_tasks(limit=400)
        if _is_integration_task(candidate)
        and (
            candidate.id == task.id
            or candidate.spec.metadata.get("source_task_id") == task.id
            or (
                source_task is not None
                and candidate.spec.metadata.get("source_task_id") == source_task.id
            )
        )
    ]
    return {
        "is_integration_task": _is_integration_task(task),
        "source_task_id": _str_or_none(task.spec.metadata.get("source_task_id")),
        "runs": [
            {
                "task": _public_task(config, run),
                "remote": _task_remote(config, store, run.id),
                "commit_message": _public_commit_message_artifact(
                    config,
                    run.id,
                    raw_transcript_artifacts=raw_transcript_artifacts,
                ),
                "push_log": _public_push_log(config, run.id),
            }
            for run in integration_tasks[:8]
        ],
    }


def _public_commit_message_artifact(
    config: StewardConfig,
    integration_task_id: str,
    *,
    raw_transcript_artifacts: _RawTranscriptArtifacts | None = None,
) -> dict[str, object] | None:
    run_dir = config.transcripts_dir / integration_task_id / "commit-message"
    transcript = _public_text_artifact(
        config,
        run_dir / "codex.jsonl",
        root=config.state_dir,
        max_bytes=MIRROR_TRANSCRIPT_BYTES,
        line_aligned=True,
        transcript=True,
        task_id=integration_task_id,
        run_name="commit-message",
        raw_transcript_artifacts=raw_transcript_artifacts,
    )
    last_message = _public_text_artifact(
        config,
        run_dir / "last-message.md",
        root=config.state_dir,
        max_bytes=MIRROR_LAST_MESSAGE_BYTES,
        line_aligned=False,
    )
    if transcript is None and last_message is None:
        return None
    return {"transcript": transcript, "last_message": last_message}


def _public_push_log(
    config: StewardConfig, integration_task_id: str
) -> dict[str, object] | None:
    return _public_text_artifact(
        config,
        config.logs_dir / integration_task_id / "git-push.txt",
        root=config.logs_dir,
        max_bytes=MIRROR_LOG_BYTES,
        line_aligned=True,
    )


def _source_task_for_integration(
    store: TaskStore, task: TaskRecord
) -> TaskRecord | None:
    source_task_id = task.spec.metadata.get("source_task_id")
    if not isinstance(source_task_id, str) or not source_task_id:
        return None
    try:
        return store.get(source_task_id)
    except KeyError:
        return None


def _task_remote(
    config: StewardConfig, store: TaskStore, task_id: str
) -> dict[str, str | None]:
    pushed = next(
        (
            event
            for event in reversed(store.events(task_id))
            if event.kind == "main.pushed"
        ),
        None,
    )
    if pushed is None:
        return {"commit": None, "commit_url": None}
    sha = pushed.message.strip()
    if not _safe_sha(sha):
        return {"commit": None, "commit_url": None}
    return {
        "commit": sha,
        "commit_url": f"https://github.com/{config.github_repository}/commit/{sha}",
    }


def _safe_sha(value: str) -> bool:
    return 7 <= len(value) <= 64 and all(
        character in "0123456789abcdefABCDEF" for character in value
    )


def _is_integration_task(task: TaskRecord) -> bool:
    return task.spec.kind == "integration" or task.spec.worker == "integration-manager"


def _remove_stale_task_details(
    tasks_dir: Path, *, detail_task_ids: set[str], raw_task_ids: set[str]
) -> None:
    for path in tasks_dir.glob("task-*.json"):
        task_id = path.stem
        if task_id not in detail_task_ids:
            path.unlink(missing_ok=True)
    for path in tasks_dir.glob("task-*"):
        if path.is_dir() and path.name not in raw_task_ids:
            shutil.rmtree(path)


def _remove_legacy_task_details(mirror_dir: Path) -> None:
    legacy_tasks_dir = mirror_dir / "tasks"
    if legacy_tasks_dir.is_symlink() or legacy_tasks_dir.is_file():
        legacy_tasks_dir.unlink(missing_ok=True)
    elif legacy_tasks_dir.is_dir():
        shutil.rmtree(legacy_tasks_dir)


def _safe_file_exists(path: Path | None, root: Path) -> bool:
    return bool(path and _allowed_public_file(path, root))


def _allowed_public_file(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        resolved_root = root.resolve()
    except OSError:
        return False
    return (
        resolved.exists()
        and resolved.is_file()
        and (resolved == resolved_root or resolved_root in resolved.parents)
    )


def _tail_text(path: Path, *, max_bytes: int, line_aligned: bool = False) -> str:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        start = max(0, size - max_bytes)
        handle.seek(start)
        data = handle.read(max_bytes)
    if line_aligned and start > 0:
        newline = data.find(b"\n")
        if newline >= 0:
            data = data[newline + 1 :]
    return data.decode("utf-8", errors="replace")


def _str_or_none(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _public_text(config: StewardConfig, value: str | None) -> str:
    if not value:
        return ""
    text = str(value)
    replacements = {
        str(config.repo_root): "[repo]",
        str(config.coquic_home): "[coquic-home]",
        str(config.steward_home): "[steward-home]",
        str(config.state_dir): "[steward-state]",
    }
    for original, replacement in sorted(
        replacements.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if original:
            text = text.replace(original, replacement)
    generated_state_replacements = {
        ".remote-ci/": "[remote-ci]/",
        " .remote-ci": " [remote-ci]",
        "coverage/": "[coverage]/",
        " .rag": " [rag-state]",
        ".rag/": "[rag-state]/",
    }
    for original, replacement in generated_state_replacements.items():
        text = text.replace(original, replacement)
    text = re.sub(r"/(?:home|media|tmp|var|opt)/[^\s'\"`),;]+", "[local-path]", text)
    text = _redact_private_location_tokens(text)
    text = re.sub(
        r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        "[redacted-secret]",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[^\s,;]+", "Bearer [redacted-secret]", text)
    text = re.sub(
        r"(?i)(?:api[_-]?key|access[_-]?token|secret|password|authorization)"
        r"\s*[:=](?:\s*[^\s,;]+)?",
        "[redacted-secret]",
        text,
    )
    text = re.sub(r"(?i)\bthread[_-][A-Za-z0-9._-]+", "[redacted-thread]", text)
    return text


def _redact_private_location_tokens(value: str) -> str:
    output: list[str] = []
    copied = 0
    index = 0
    while index < len(value):
        if _public_token_terminator(value[index]):
            index += 1
            continue
        start = index
        while index < len(value) and not _public_token_terminator(value[index]):
            index += 1
        lowered = value[start:index].lower()
        if "file://" in lowered or any(
            marker in lowered
            for marker in ("/worktrees/", "/transcripts/", "/patches/")
        ):
            output.extend((value[copied:start], "[local-path]"))
            copied = index
    output.append(value[copied:])
    return "".join(output)


def _looks_like_link(key: str) -> bool:
    lowered = key.lower()
    return lowered in {"url", "href", "link", "detail_url", "detail_json", "commit_url"} or lowered.endswith("_url")


def _safe_public_link(config: StewardConfig, value: str) -> str | None:
    if value.startswith("/steward/"):
        return value if ".." not in value.split("?")[0].split("#")[0] else None
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    expected_prefix = f"/{config.github_repository}/"
    if not parsed.path.startswith(expected_prefix):
        return None
    return value


def _restrictive_file_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        return


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _restrictive_file_permissions(temporary_path)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

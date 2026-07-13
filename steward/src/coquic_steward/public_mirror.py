from __future__ import annotations

import json
import re
import shlex
import shutil
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .agents.diagnostics import diagnostics_for_paths
from .core.config import (
    DEFAULT_PUBLIC_MIRROR_OUTPUT,
    PublicMirrorConfig,
    StewardConfig,
)
from .core.models import (
    DaemonRuntime,
    Event,
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

PUBLIC_MIRROR_SCHEMA_VERSION = 3
PUBLIC_TASK_DETAIL_SCHEMA_VERSION = 2
DEFAULT_MIRROR_TASK_LIMIT = 80
DEFAULT_MIRROR_SIGNAL_LIMIT = 80
DEFAULT_MIRROR_FETCH_LIMIT = 40
PUBLIC_TASK_DATA_PREFIX = "/steward/data/tasks"
REMOTE_MIRROR_ROOT = ".cache/coquic-steward/public-mirror"
REMOTE_MIRROR_HELPER = f"{REMOTE_MIRROR_ROOT}/publish-helper-v1"
REMOTE_MIRROR_LOCK = f"{REMOTE_MIRROR_ROOT}/publish.lock"
MIRROR_PATCH_BYTES = 128 * 1024
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


def public_mirror_payload(
    config: StewardConfig,
    store: TaskStore,
    *,
    task_limit: int = DEFAULT_MIRROR_TASK_LIMIT,
    signal_limit: int = DEFAULT_MIRROR_SIGNAL_LIMIT,
    fetch_limit: int = DEFAULT_MIRROR_FETCH_LIMIT,
    runtime: DaemonRuntime | None = None,
) -> dict[str, object]:
    runtime = runtime or _DEFAULT_RUNTIME
    tasks = store.list_tasks(limit=task_limit)
    signal_items = store.list_signal_items(limit=signal_limit)
    fetch_runs = store.list_signal_fetch_runs(limit=fetch_limit)
    signals = project_signals_from_items(config, signal_items, fetches=fetch_runs)
    return {
        "schema_version": PUBLIC_MIRROR_SCHEMA_VERSION,
        "compatibility_state": "compatible",
        "generated_at": utc_now().isoformat(),
        "repository": config.github_repository,
        "main_branch": config.main_branch,
        "state": _public_state(tasks),
        "counts": _counts(tasks, signal_items),
        "runtime": _public_runtime(runtime),
        "audit": [_public_text(config, finding) for finding in store.audit()],
        "configuration": _public_configuration(config),
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
            "generated_at": signals.generated_at.isoformat(),
            "summary": _public_signals_summary(signal_items, fetch_runs),
            "items": [_public_signal_item(config, item) for item in signal_items],
            "fetches": [_public_fetch_run(config, run) for run in fetch_runs],
        },
        "scheduler": _public_scheduler_state(scheduler_state(config, store)),
        "integration": _integration_summary(config, tasks),
    }


def write_public_mirror(
    config: StewardConfig,
    store: TaskStore,
    output_path: Path | None = None,
    *,
    runtime: DaemonRuntime | None = None,
) -> Path:
    path = _mirror_output_path(config, output_path)
    payload = public_mirror_payload(config, store, runtime=runtime)
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
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
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
        detail_path.write_text(
            json.dumps(detail, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        task_index.append(
            {
                "id": task.id,
                "title": _public_text(config, task.spec.title),
                "status": str(task.status),
                "updated_at": task.updated_at.isoformat(),
                "detail_json": _public_task_detail_url(task.id),
            }
        )
    (tasks_dir / "index.json").write_text(
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
        encoding="utf-8",
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
) -> tuple[Path, CommandResult | None]:
    path = write_public_mirror(config, store, runtime=runtime)
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
        "generated_at": utc_now().isoformat(),
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
) -> str:
    payload = public_mirror_payload(config, store, runtime=runtime)
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
        "created_at": task.created_at.isoformat(),
        "updated_at": task.updated_at.isoformat(),
        "validations": [
            {
                "passed": validation.passed,
                "exit_code": validation.exit_code,
                "summary": _public_text(config, validation.summary),
                "iteration": validation.iteration,
                "started_at": validation.started_at.isoformat(),
                "completed_at": validation.completed_at.isoformat(),
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
            "started_at": item.started_at.isoformat(),
            "updated_at": item.updated_at.isoformat(),
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
        "started_at": item.started_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
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
    if transcript is None and last_message is None:
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
        "started_at": validation.started_at.isoformat(),
        "completed_at": validation.completed_at.isoformat(),
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
        "truncated": size > max_bytes,
        "tail_bytes": min(size, max_bytes),
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
        "truncated": False,
        "tail_bytes": 0,
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
        "created_at": event.created_at.isoformat(),
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
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
        "planned_at": item.planned_at.isoformat() if item.planned_at else None,
        "planned_task_id": item.planned_task_id,
        "links": [
            link
            for link in item.links
            if isinstance(link.get("url"), str)
            and str(link.get("url")).startswith("https://github.com/")
        ],
    }


def _public_fetch_run(config: StewardConfig, run: SignalFetchRun) -> dict[str, object]:
    return {
        "id": run.id,
        "provider": run.provider,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "completed_at": run.completed_at.isoformat(),
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


def _public_scheduler_state(state: SchedulerState) -> dict[str, object]:
    return {
        "source_active": state.source_active,
        "source_capacity": state.source_capacity,
        "source_queued": state.source_queued,
        "integration_active": state.integration_active,
        "integration_queued": state.integration_queued,
        "pending_wakeups": [
            _public_wakeup(wakeup) for wakeup in state.pending_wakeups
        ],
        "recent_wakeups": [
            _public_wakeup(wakeup) for wakeup in state.recent_wakeups
        ],
        "providers": [
            {
                **provider.model_dump(mode="json"),
                "last_error": _public_error(provider.last_error),
            }
            for provider in state.providers
        ],
    }


def _public_wakeup(wakeup: Any) -> dict[str, object]:
    return {
        "id": wakeup.id,
        "reason": wakeup.reason,
        "status": str(wakeup.status),
        "created_at": wakeup.created_at.isoformat(),
        "consumed_at": wakeup.consumed_at.isoformat() if wakeup.consumed_at else None,
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
                "updated_at": task.updated_at.isoformat(),
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
    return text

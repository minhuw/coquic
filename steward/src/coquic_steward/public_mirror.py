from __future__ import annotations

import json
import re
import shutil
import tarfile
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .agents.diagnostics import diagnostics_for_paths
from .core.config import PublicMirrorConfig, StewardConfig
from .core.models import (
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
from .storage import TaskStore

PUBLIC_MIRROR_SCHEMA_VERSION = 1
PUBLIC_TASK_DETAIL_SCHEMA_VERSION = 1
DEFAULT_MIRROR_TASK_LIMIT = 80
DEFAULT_MIRROR_SIGNAL_LIMIT = 80
DEFAULT_MIRROR_FETCH_LIMIT = 40
PUBLIC_TASK_DATA_PREFIX = "/steward/data/tasks"
MIRROR_PATCH_BYTES = 128 * 1024
MIRROR_TRANSCRIPT_BYTES = 64 * 1024
MIRROR_LOG_BYTES = 64 * 1024
MIRROR_LAST_MESSAGE_BYTES = 24 * 1024
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
) -> dict[str, object]:
    from .orchestration.daemon import scheduler_state

    tasks = store.list_tasks(limit=task_limit)
    signal_items = store.list_signal_items(limit=signal_limit)
    fetch_runs = store.list_signal_fetch_runs(limit=fetch_limit)
    signals = project_signals_from_items(config, signal_items, fetches=fetch_runs)
    return {
        "schema_version": PUBLIC_MIRROR_SCHEMA_VERSION,
        "generated_at": utc_now().isoformat(),
        "repository": config.github_repository,
        "main_branch": config.main_branch,
        "state": _public_state(tasks),
        "counts": _counts(tasks, signal_items),
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
) -> Path:
    path = _mirror_output_path(config, output_path)
    payload = public_mirror_payload(config, store)
    tasks = store.list_tasks(limit=DEFAULT_MIRROR_TASK_LIMIT)
    mirror_dir = path.parent
    tasks_dir = mirror_dir / "data" / "tasks"
    raw_task_ids = (
        {_safe_public_segment(task.id, fallback="task") for task in tasks}
        if config.public_mirror.transcript_mode == "raw"
        else set()
    )
    path.parent.mkdir(parents=True, exist_ok=True)
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
    task_index = []
    for task in tasks:
        _write_public_raw_transcripts(config, store, tasks_dir, task)
        detail = public_task_detail_payload(config, store, task)
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
) -> tuple[Path, CommandResult | None]:
    path = write_public_mirror(config, store)
    should_publish = config.public_mirror.publish if publish is None else publish
    if not force and not should_publish:
        return path, None
    selected = publisher or PublicMirrorPublisher(config.public_mirror)
    return path, selected.publish(path, cwd=config.repo_root)


def public_task_detail_payload(
    config: StewardConfig,
    store: TaskStore,
    task: TaskRecord | str,
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
        "attempts": _public_attempts(config, store, record),
        "validations": [
            _public_validation(config, validation, index)
            for index, validation in enumerate(record.validations)
        ],
        "artifacts": _public_task_artifacts(config, record),
        "integration": _public_integration_detail(config, store, record, source_task),
        "remote": _task_remote(config, store, record.id),
    }


def public_mirror_digest(config: StewardConfig, store: TaskStore) -> str:
    payload = public_mirror_payload(config, store)
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
        local_dir = local_path.parent
        with TemporaryDirectory(prefix="steward-mirror-") as temp_dir:
            archive_path = Path(temp_dir) / "steward-public.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(local_dir, arcname="steward")
            tmp_remote = (
                "/tmp/coquic-steward-mirror-"
                + sha256(str(local_path).encode("utf-8")).hexdigest()[:12]
                + ".tar.gz"
            )
            scp_result = run_command(
                [
                    "scp",
                    *self._scp_options(),
                    str(archive_path),
                    f"{remote_target}:{tmp_remote}",
                ],
                cwd=cwd,
                timeout=max(10, self.config.connect_timeout_seconds + 10),
            )
            if not scp_result.ok:
                return scp_result
        install_result = run_command(
            [
                "ssh",
                *self._ssh_options(),
                remote_target,
                "bash",
                "-s",
                "--",
                remote_path,
                tmp_remote,
            ],
            cwd=cwd,
            input_text=(
                "set -euo pipefail\n"
                "remote_path=\"$1\"\n"
                "tmp_remote=\"$2\"\n"
                "remote_dir=\"$(dirname \"${remote_path}\")\"\n"
                "tmp_dir=\"$(mktemp -d /tmp/coquic-steward-public.XXXXXX)\"\n"
                "trap 'rm -rf \"${tmp_dir}\" \"${tmp_remote}\"' EXIT\n"
                "tar -xzf \"${tmp_remote}\" -C \"${tmp_dir}\"\n"
                "sudo install -d -m 755 \"${remote_dir}\"\n"
                "sudo find \"${remote_dir}\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +\n"
                "sudo cp -a \"${tmp_dir}/steward/.\" \"${remote_dir}/\"\n"
                "sudo chmod -R a+rX \"${remote_dir}\"\n"
                "rm -f \"${tmp_remote}\"\n"
            ),
            timeout=max(10, self.config.connect_timeout_seconds + 10),
        )
        return install_result

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

    def _scp_options(self) -> list[str]:
        options = self._ssh_options()
        scp_options = options.copy()
        port_index = scp_options.index("-p")
        scp_options[port_index] = "-P"
        return scp_options


def _mirror_output_path(config: StewardConfig, output_path: Path | None) -> Path:
    selected = output_path or config.public_mirror.output_path
    if selected is None:
        selected = Path("public/steward/status.json")
    return selected if selected.is_absolute() else config.state_dir / selected


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
    config: StewardConfig, store: TaskStore, task: TaskRecord
) -> list[dict[str, object]]:
    iterations = store.iterations(task.id)
    if iterations:
        return [_public_iteration_attempt(config, task, item) for item in iterations]
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


def _public_iteration_attempt(
    config: StewardConfig, task: TaskRecord, item: TaskIteration
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
    config: StewardConfig, task: TaskRecord
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
) -> dict[str, object] | None:
    if path is None or not _allowed_public_file(path, root):
        return None
    if transcript and config.public_mirror.transcript_mode == "none":
        return None
    if transcript and config.public_mirror.transcript_mode == "raw":
        if task_id is None or run_name is None:
            return None
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
) -> None:
    if config.public_mirror.transcript_mode != "raw":
        return
    task_dir = tasks_dir / _safe_public_segment(task.id, fallback="task")
    if task_dir.exists():
        shutil.rmtree(task_dir)
    _copy_public_raw_transcript(
        config,
        task.transcript_path,
        task_dir=task_dir,
        run_name="task",
    )
    iterations = store.iterations(task.id)
    if iterations:
        for item in iterations:
            _copy_public_raw_transcript(
                config,
                item.worker_transcript_path,
                task_dir=task_dir,
                run_name=item.worker_name or f"worker-{item.iteration}",
            )
            _copy_public_raw_transcript(
                config,
                item.reviewer_transcript_path,
                task_dir=task_dir,
                run_name=item.reviewer_name or f"reviewer-{item.iteration}",
            )
    else:
        _copy_public_raw_transcript(
            config,
            task.transcript_path,
            task_dir=task_dir,
            run_name="worker",
        )
    _copy_public_raw_transcript(
        config,
        config.transcripts_dir / task.id / "commit-message" / "codex.jsonl",
        task_dir=task_dir,
        run_name="commit-message",
    )


def _copy_public_raw_transcript(
    config: StewardConfig,
    source: Path | None,
    *,
    task_dir: Path,
    run_name: str,
) -> None:
    if source is None or not _allowed_public_file(source, config.state_dir):
        return
    destination = task_dir / "runs" / _safe_public_segment(run_name) / "codex.jsonl"
    try:
        if source.resolve() == destination.resolve():
            return
    except OSError:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


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
        item_type = str(item.get("type") or "item")
        if item_type == "agent_message":
            return str(item.get("text") or "")
        if item_type == "reasoning":
            return _labeled_text("reasoning", item.get("text") or item.get("message"))
        if item_type == "command_execution":
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
        if item_type == "file_change":
            changes = item.get("changes")
            if isinstance(changes, list):
                rendered = []
                for change in changes:
                    if isinstance(change, dict):
                        rendered.append(
                            f"{change.get('kind', 'change')}: {change.get('path', '')}"
                        )
                if rendered:
                    return "file changes\n" + "\n".join(rendered)
        if item_type == "todo_list":
            todos = item.get("items")
            if isinstance(todos, list):
                rendered = []
                for todo in todos:
                    if isinstance(todo, dict):
                        mark = "x" if todo.get("completed") else " "
                        rendered.append(f"[{mark}] {todo.get('text', '')}")
                if rendered:
                    return "todo list\n" + "\n".join(rendered)
        if item_type in {"tool_call", "function_call", "mcp_tool_call"}:
            return _labeled_text(
                str(item.get("name") or item.get("tool_name") or item_type),
                item.get("status") or item.get("text") or item.get("message"),
            )
        if item_type == "error":
            return _labeled_text("error", item.get("message"))
        return _labeled_text(item_type, item.get("text") or item.get("message"))
    event_type = str(event.get("type") or "")
    if event_type == "stderr":
        return _labeled_text("stderr", event.get("text") or event.get("message"))
    return _labeled_text(event_type or "event", event.get("text") or event.get("message"))


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
                "commit_message": _public_commit_message_artifact(config, run.id),
                "push_log": _public_push_log(config, run.id),
            }
            for run in integration_tasks[:8]
        ],
    }


def _public_commit_message_artifact(
    config: StewardConfig, integration_task_id: str
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

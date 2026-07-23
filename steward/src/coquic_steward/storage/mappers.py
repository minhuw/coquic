from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.models import (
    CodexSession,
    Event,
    TaskExecution,
    TaskPipeline,
    TaskRun,
    WorktreeCheckpoint,
    SchedulerWakeup,
    SignalFetchRun,
    SignalItem,
    TaskIteration,
    TaskPlanRun,
    TaskRecord,
    TaskSpec,
    ValidationResult,
)
from ..task_archive_sync_config import (
    TASK_ARCHIVE_SYNC_HEALTH_ID,
    TaskArchiveSyncHealth,
)
from .schema import (
    CodexSessionRow,
    EventRow,
    SchedulerWakeupRow,
    SignalFetchRunRow,
    SignalItemRow,
    TaskIterationRow,
    TaskExecutionRow,
    TaskPlanRunRow,
    TaskPipelineRow,
    TaskRow,
    TaskRunRow,
    TaskWorktreeCheckpointRow,
    TaskArchiveSyncHealthRow,
    ValidationRow,
)


class PathCodec:
    _RELATIVE_ROOTS = frozenset(
        {
            "implementation-plans",
            "logs",
            "patches",
            "prompts",
            "schemas",
            "transcripts",
            "worktrees",
        }
    )
    _LEGACY_ROOTS = frozenset(
        {
            "implementation-plans",
            "logs",
            "patches",
            "prompts",
            "schemas",
            "transcripts",
        }
    )
    _PATH_KEYS = frozenset({"cwd", "log", "logs", "path", "paths"})

    def __init__(self, base_dir: Path, legacy_dir: Path | None = None):
        self.base_dir = base_dir.resolve()
        self.legacy_dir = legacy_dir.resolve() if legacy_dir is not None else None

    def dump(self, value: Path | None) -> str | None:
        if value is None:
            return None
        path = value.expanduser()
        if not path.is_absolute():
            return path.as_posix()
        if self.legacy_dir is not None:
            try:
                relative = path.resolve().relative_to(self.legacy_dir)
            except ValueError:
                pass
            else:
                return relative.as_posix()
        try:
            return path.resolve().relative_to(self.base_dir).as_posix()
        except ValueError:
            return str(path)

    def load(self, value: str | None) -> Path | None:
        if not value:
            return None
        path = Path(value)
        if path.is_absolute():
            return path
        if self.legacy_dir is not None and self._looks_like_legacy_path(path):
            return self.legacy_dir / path
        return self.base_dir / path

    def is_portable(self, value: str | None) -> bool:
        if not value:
            return True
        return not Path(value).is_absolute()

    def dump_text_path(self, value: str) -> str:
        return self._dump_string(value)

    def load_text_path(self, value: str) -> str:
        return self._load_string(value)

    def dump_json(self, value: Any, *, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {
                item_key: self.dump_json(item, key=item_key)
                for item_key, item in value.items()
            }
        if isinstance(value, list):
            return [self.dump_json(item, key=key) for item in value]
        if isinstance(value, str) and self._is_path_key(key):
            return self._dump_string(value)
        return value

    def load_json(self, value: Any, *, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {
                item_key: self.load_json(item, key=item_key)
                for item_key, item in value.items()
            }
        if isinstance(value, list):
            return [self.load_json(item, key=key) for item in value]
        if isinstance(value, str) and self._is_path_key(key):
            return self._load_string(value)
        return value

    def _dump_string(self, value: str) -> str:
        path = Path(value).expanduser()
        if not path.is_absolute():
            return value
        dumped = self.dump(path)
        return dumped if dumped is not None else value

    def _load_string(self, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or not self._looks_like_state_path(path):
            return value
        if self.legacy_dir is not None and self._looks_like_legacy_path(path):
            return str(self.legacy_dir / path)
        return str(self.base_dir / path)

    def _looks_like_state_path(self, path: Path) -> bool:
        parts = path.parts
        return bool(parts) and parts[0] in self._RELATIVE_ROOTS

    def _looks_like_legacy_path(self, path: Path) -> bool:
        parts = path.parts
        return bool(parts) and parts[0] in self._LEGACY_ROOTS

    def _is_path_key(self, key: str | None) -> bool:
        if key is None:
            return False
        return key in self._PATH_KEYS or key.endswith("_path") or key.endswith("_paths")


def task_to_row(
    record: TaskRecord, *, dedupe_key: str | None = None, path_codec: PathCodec
) -> TaskRow:
    return TaskRow(
        id=record.id,
        kind=str(record.spec.kind),
        workflow=str(record.spec.workflow),
        worker=str(record.spec.worker),
        title=record.spec.title,
        prompt=record.spec.prompt,
        priority=str(record.spec.priority),
        risk=str(record.spec.risk),
        source=record.spec.source,
        allow_main_write=record.spec.allow_main_write,
        metadata_json=_dump_json(record.spec.metadata, path_codec=path_codec),
        dedupe_key=dedupe_key or _dedupe_key(record),
        status=str(record.status),
        summary=record.summary,
        created_at=_dump_datetime(record.created_at),
        updated_at=_dump_datetime(record.updated_at),
        worktree_path=path_codec.dump(record.worktree_path),
        branch_name=record.branch_name,
        transcript_path=path_codec.dump(record.transcript_path),
        last_message_path=path_codec.dump(record.last_message_path),
        patch_path=path_codec.dump(record.patch_path),
        validations=[
            validation_to_row(record.id, index, item, path_codec=path_codec)
            for index, item in enumerate(record.validations)
        ],
    )


def update_task_row(row: TaskRow, record: TaskRecord, *, path_codec: PathCodec) -> None:
    row.kind = str(record.spec.kind)
    row.workflow = str(record.spec.workflow)
    row.worker = str(record.spec.worker)
    row.title = record.spec.title
    row.prompt = record.spec.prompt
    row.priority = str(record.spec.priority)
    row.risk = str(record.spec.risk)
    row.source = record.spec.source
    row.allow_main_write = record.spec.allow_main_write
    row.metadata_json = _dump_json(record.spec.metadata, path_codec=path_codec)
    row.dedupe_key = _dedupe_key(record)
    row.created_at = _dump_datetime(record.created_at)
    row.updated_at = _dump_datetime(record.updated_at)
    row.worktree_path = path_codec.dump(record.worktree_path)
    row.branch_name = record.branch_name
    row.transcript_path = path_codec.dump(record.transcript_path)
    row.last_message_path = path_codec.dump(record.last_message_path)
    row.patch_path = path_codec.dump(record.patch_path)
    row.validations = [
        validation_to_row(record.id, index, item, path_codec=path_codec)
        for index, item in enumerate(record.validations)
    ]


def row_to_task(row: TaskRow, *, path_codec: PathCodec) -> TaskRecord:
    metadata = _loads_dict(row.metadata_json, path_codec=path_codec)
    spec = TaskSpec(
        id=row.id,
        kind=row.kind,
        workflow=row.workflow,
        worker=row.worker,
        title=row.title,
        prompt=row.prompt,
        priority=row.priority,
        risk=row.risk,
        source=row.source,
        allow_main_write=row.allow_main_write,
        metadata=metadata,
    )
    return TaskRecord(
        spec=spec,
        status=row.status,
        summary=row.summary,
        created_at=_load_datetime(row.created_at),
        updated_at=_load_datetime(row.updated_at),
        worktree_path=path_codec.load(row.worktree_path),
        branch_name=row.branch_name,
        transcript_path=path_codec.load(row.transcript_path),
        last_message_path=path_codec.load(row.last_message_path),
        patch_path=path_codec.load(row.patch_path),
        validations=[
            row_to_validation(item, path_codec=path_codec) for item in row.validations
        ],
    )


def validation_to_row(
    task_id: str,
    position: int,
    result: ValidationResult,
    *,
    iteration: int | None = None,
    path_codec: PathCodec,
) -> ValidationRow:
    return ValidationRow(
        task_id=task_id,
        iteration=iteration if iteration is not None else result.iteration,
        position=position,
        command_json=json.dumps(result.command),
        cwd=path_codec.dump(result.cwd) or str(result.cwd),
        passed=result.passed,
        exit_code=result.exit_code,
        output_path=path_codec.dump(result.output_path) or "",
        summary=result.summary,
        started_at=_dump_datetime(result.started_at),
        completed_at=_dump_datetime(result.completed_at),
    )


def iteration_to_row(iteration: TaskIteration, *, path_codec: PathCodec) -> TaskIterationRow:
    return TaskIterationRow(
        task_id=iteration.task_id,
        iteration=iteration.iteration,
        label=iteration.label,
        worker_name=iteration.worker_name,
        worker_prompt_path=path_codec.dump(iteration.worker_prompt_path),
        worker_transcript_path=path_codec.dump(iteration.worker_transcript_path),
        worker_last_message_path=path_codec.dump(iteration.worker_last_message_path),
        worker_exit_code=iteration.worker_exit_code,
        worker_completed=iteration.worker_completed,
        worker_model=iteration.worker_model,
        worker_reasoning_effort=iteration.worker_reasoning_effort,
        reviewer_name=iteration.reviewer_name,
        reviewer_prompt_path=path_codec.dump(iteration.reviewer_prompt_path),
        reviewer_transcript_path=path_codec.dump(iteration.reviewer_transcript_path),
        reviewer_last_message_path=path_codec.dump(iteration.reviewer_last_message_path),
        reviewer_exit_code=iteration.reviewer_exit_code,
        reviewer_completed=iteration.reviewer_completed,
        reviewer_model=iteration.reviewer_model,
        reviewer_reasoning_effort=iteration.reviewer_reasoning_effort,
        reviewer_run=iteration.reviewer_run,
        review_json=_dump_json(iteration.review_json),
        patch_path=path_codec.dump(iteration.patch_path),
        started_at=_dump_datetime(iteration.started_at),
        updated_at=_dump_datetime(iteration.updated_at),
    )


def update_iteration_row(
    row: TaskIterationRow, iteration: TaskIteration, *, path_codec: PathCodec
) -> None:
    row.label = iteration.label
    row.worker_name = iteration.worker_name
    row.worker_prompt_path = path_codec.dump(iteration.worker_prompt_path)
    row.worker_transcript_path = path_codec.dump(iteration.worker_transcript_path)
    row.worker_last_message_path = path_codec.dump(iteration.worker_last_message_path)
    row.worker_exit_code = iteration.worker_exit_code
    row.worker_completed = iteration.worker_completed
    row.worker_model = iteration.worker_model
    row.worker_reasoning_effort = iteration.worker_reasoning_effort
    row.reviewer_name = iteration.reviewer_name
    row.reviewer_prompt_path = path_codec.dump(iteration.reviewer_prompt_path)
    row.reviewer_transcript_path = path_codec.dump(iteration.reviewer_transcript_path)
    row.reviewer_last_message_path = path_codec.dump(iteration.reviewer_last_message_path)
    row.reviewer_exit_code = iteration.reviewer_exit_code
    row.reviewer_completed = iteration.reviewer_completed
    row.reviewer_model = iteration.reviewer_model
    row.reviewer_reasoning_effort = iteration.reviewer_reasoning_effort
    row.reviewer_run = iteration.reviewer_run
    row.review_json = _dump_json(iteration.review_json)
    row.patch_path = path_codec.dump(iteration.patch_path)
    row.started_at = _dump_datetime(iteration.started_at)
    row.updated_at = _dump_datetime(iteration.updated_at)


def row_to_iteration(row: TaskIterationRow, *, path_codec: PathCodec) -> TaskIteration:
    return TaskIteration(
        task_id=row.task_id,
        iteration=row.iteration,
        label=row.label,
        worker_name=row.worker_name,
        worker_prompt_path=path_codec.load(row.worker_prompt_path),
        worker_transcript_path=path_codec.load(row.worker_transcript_path),
        worker_last_message_path=path_codec.load(row.worker_last_message_path),
        worker_exit_code=row.worker_exit_code,
        worker_completed=row.worker_completed,
        worker_model=row.worker_model,
        worker_reasoning_effort=row.worker_reasoning_effort,
        reviewer_name=row.reviewer_name,
        reviewer_prompt_path=path_codec.load(row.reviewer_prompt_path),
        reviewer_transcript_path=path_codec.load(row.reviewer_transcript_path),
        reviewer_last_message_path=path_codec.load(row.reviewer_last_message_path),
        reviewer_exit_code=row.reviewer_exit_code,
        reviewer_completed=row.reviewer_completed,
        reviewer_model=row.reviewer_model,
        reviewer_reasoning_effort=row.reviewer_reasoning_effort,
        reviewer_run=row.reviewer_run,
        review_json=_loads_optional_dict(row.review_json),
        patch_path=path_codec.load(row.patch_path),
        started_at=_load_datetime(row.started_at),
        updated_at=_load_datetime(row.updated_at),
    )


def plan_run_to_row(item: TaskPlanRun, *, path_codec: PathCodec) -> TaskPlanRunRow:
    return TaskPlanRunRow(
        task_id=item.task_id,
        run=item.run,
        prompt_path=path_codec.dump(item.prompt_path),
        transcript_path=path_codec.dump(item.transcript_path),
        last_message_path=path_codec.dump(item.last_message_path),
        plan_path=path_codec.dump(item.plan_path),
        exit_code=item.exit_code,
        completed=item.completed,
        model=item.model,
        reasoning_effort=item.reasoning_effort,
        plan_json=_dump_json(item.plan_json),
        started_at=_dump_datetime(item.started_at),
        updated_at=_dump_datetime(item.updated_at),
    )


def update_plan_run_row(
    row: TaskPlanRunRow, item: TaskPlanRun, *, path_codec: PathCodec
) -> None:
    row.prompt_path = path_codec.dump(item.prompt_path)
    row.transcript_path = path_codec.dump(item.transcript_path)
    row.last_message_path = path_codec.dump(item.last_message_path)
    row.plan_path = path_codec.dump(item.plan_path)
    row.exit_code = item.exit_code
    row.completed = item.completed
    row.model = item.model
    row.reasoning_effort = item.reasoning_effort
    row.plan_json = _dump_json(item.plan_json)
    row.started_at = _dump_datetime(item.started_at)
    row.updated_at = _dump_datetime(item.updated_at)


def row_to_plan_run(row: TaskPlanRunRow, *, path_codec: PathCodec) -> TaskPlanRun:
    return TaskPlanRun(
        task_id=row.task_id,
        run=row.run,
        prompt_path=path_codec.load(row.prompt_path),
        transcript_path=path_codec.load(row.transcript_path),
        last_message_path=path_codec.load(row.last_message_path),
        plan_path=path_codec.load(row.plan_path),
        exit_code=row.exit_code,
        completed=row.completed,
        model=row.model,
        reasoning_effort=row.reasoning_effort,
        plan_json=_loads_optional_dict(row.plan_json),
        started_at=_load_datetime(row.started_at),
        updated_at=_load_datetime(row.updated_at),
    )


def row_to_validation(row: ValidationRow, *, path_codec: PathCodec) -> ValidationResult:
    return ValidationResult(
        command=json.loads(row.command_json),
        cwd=path_codec.load(row.cwd) or Path(row.cwd),
        passed=row.passed,
        exit_code=row.exit_code,
        output_path=path_codec.load(row.output_path) or Path(row.output_path),
        summary=row.summary,
        iteration=row.iteration,
        started_at=_load_datetime(row.started_at),
        completed_at=_load_datetime(row.completed_at),
    )


def event_to_row(event: Event, *, path_codec: PathCodec) -> EventRow:
    return EventRow(
        task_id=event.task_id,
        kind=event.kind,
        message=path_codec.dump_text_path(event.message),
        created_at=_dump_datetime(event.created_at),
        data_json=_dump_json(event.data, path_codec=path_codec),
    )


def row_to_event(row: EventRow, *, path_codec: PathCodec) -> Event:
    return Event(
        task_id=row.task_id,
        kind=row.kind,
        message=path_codec.load_text_path(row.message),
        created_at=_load_datetime(row.created_at),
        data=_loads_dict(row.data_json, path_codec=path_codec),
    )


def signal_item_to_row(item: SignalItem, *, path_codec: PathCodec) -> SignalItemRow:
    return SignalItemRow(
        id=item.id,
        provider=item.provider,
        kind=item.kind,
        fingerprint=item.fingerprint,
        title=item.title,
        summary=item.summary,
        severity=item.severity,
        location_json=_dump_json(item.location, path_codec=path_codec),
        links_json=_dump_list(item.links, path_codec=path_codec),
        payload_json=_dump_json(item.payload, path_codec=path_codec) or "{}",
        status=str(item.status),
        created_at=_dump_datetime(item.created_at),
        updated_at=_dump_datetime(item.updated_at),
        planned_at=_dump_datetime(item.planned_at) if item.planned_at else None,
        planner_run_id=item.planner_run_id,
        planned_task_id=item.planned_task_id,
        source_fetch_id=item.source_fetch_id,
    )


def row_to_signal_item(row: SignalItemRow, *, path_codec: PathCodec) -> SignalItem:
    return SignalItem(
        id=row.id,
        provider=row.provider,
        kind=row.kind,
        fingerprint=row.fingerprint,
        title=row.title,
        summary=row.summary,
        severity=row.severity,
        location=_loads_optional_dict(row.location_json, path_codec=path_codec),
        links=_loads_list(row.links_json, path_codec=path_codec),
        payload=_loads_dict(row.payload_json, path_codec=path_codec),
        status=row.status,
        created_at=_load_datetime(row.created_at),
        updated_at=_load_datetime(row.updated_at),
        planned_at=_load_datetime(row.planned_at) if row.planned_at else None,
        planner_run_id=row.planner_run_id,
        planned_task_id=row.planned_task_id,
        source_fetch_id=row.source_fetch_id,
    )


def signal_fetch_run_to_row(run: SignalFetchRun) -> SignalFetchRunRow:
    return SignalFetchRunRow(
        id=run.id,
        provider=run.provider,
        status=str(run.status),
        started_at=_dump_datetime(run.started_at),
        completed_at=_dump_datetime(run.completed_at),
        item_count=run.item_count,
        new_item_count=run.new_item_count,
        has_more=run.has_more,
        error=run.error,
        summary=run.summary,
    )


def row_to_signal_fetch_run(row: SignalFetchRunRow) -> SignalFetchRun:
    return SignalFetchRun(
        id=row.id,
        provider=row.provider,
        status=row.status,
        started_at=_load_datetime(row.started_at),
        completed_at=_load_datetime(row.completed_at),
        item_count=row.item_count,
        new_item_count=row.new_item_count,
        has_more=row.has_more,
        error=row.error,
        summary=row.summary,
    )


def execution_to_row(item: TaskExecution, *, path_codec: PathCodec) -> TaskExecutionRow:
    return TaskExecutionRow(
        id=item.id,
        task_id=item.task_id,
        state=str(item.state),
        current_phase=str(item.current_phase),
        owning_pipeline_id=item.owning_pipeline_id,
        active_session_id=item.active_session_id,
        active_run_id=item.active_run_id,
        base_commit=item.base_commit,
        expected_tree=item.expected_tree,
        worktree_path=path_codec.dump(item.worktree_path),
        image_version=item.image_version,
        runtime_version=item.runtime_version,
        idempotency_key=item.idempotency_key,
        archive_generation=item.archive_generation,
        created_at=_dump_datetime(item.created_at),
        updated_at=_dump_datetime(item.updated_at),
    )


def row_to_execution(row: TaskExecutionRow, *, path_codec: PathCodec) -> TaskExecution:
    return TaskExecution(
        id=row.id,
        task_id=row.task_id,
        state=row.state,
        current_phase=row.current_phase,
        owning_pipeline_id=row.owning_pipeline_id,
        active_session_id=row.active_session_id,
        active_run_id=row.active_run_id,
        base_commit=row.base_commit,
        expected_tree=row.expected_tree,
        worktree_path=path_codec.load(row.worktree_path),
        image_version=row.image_version,
        runtime_version=row.runtime_version,
        idempotency_key=row.idempotency_key,
        archive_generation=row.archive_generation,
        created_at=_load_datetime(row.created_at),
        updated_at=_load_datetime(row.updated_at),
    )


def pipeline_to_row(item: TaskPipeline) -> TaskPipelineRow:
    return TaskPipelineRow(
        id=item.id,
        task_id=item.task_id,
        execution_id=item.execution_id,
        ordinal=item.ordinal,
        trigger=str(item.trigger),
        parent_pipeline_id=item.parent_pipeline_id,
        phase=str(item.phase),
        state=str(item.state),
        base_identity=item.base_identity,
        input_identity=item.input_identity,
        output_identity=item.output_identity,
        patch_identity=item.patch_identity,
        metadata_json=_dump_json(item.metadata),
        started_at=_dump_datetime(item.started_at),
        updated_at=_dump_datetime(item.updated_at),
        completed_at=_dump_datetime(item.completed_at) if item.completed_at else None,
        archive_generation=item.archive_generation,
    )


def row_to_pipeline(row: TaskPipelineRow) -> TaskPipeline:
    return TaskPipeline(
        id=row.id,
        task_id=row.task_id,
        execution_id=row.execution_id,
        ordinal=row.ordinal,
        trigger=row.trigger,
        parent_pipeline_id=row.parent_pipeline_id,
        phase=row.phase,
        state=row.state,
        base_identity=row.base_identity,
        input_identity=row.input_identity,
        output_identity=row.output_identity,
        patch_identity=row.patch_identity,
        metadata=_loads_dict(row.metadata_json),
        started_at=_load_datetime(row.started_at),
        updated_at=_load_datetime(row.updated_at),
        completed_at=_load_datetime(row.completed_at) if row.completed_at else None,
        archive_generation=row.archive_generation,
    )


def session_to_row(item: CodexSession, *, path_codec: PathCodec) -> CodexSessionRow:
    return CodexSessionRow(
        id=item.id,
        task_id=item.task_id,
        pipeline_id=item.pipeline_id,
        state=str(item.state),
        provider_session_id=item.provider_session_id,
        private_home_path=path_codec.dump(item.private_home_path),
        private_home_relative_path=item.private_home_relative_path,
        home_uid=item.home_uid,
        image_digest=item.image_digest,
        codex_identity=item.codex_identity,
        cwd=path_codec.dump(item.cwd),
        checkpoint_id=item.checkpoint_id,
        provider_store_identity=item.provider_store_identity,
        owner_role=item.owner_role,
        idempotency_key=item.idempotency_key,
        archive_generation=item.archive_generation,
        started_at=_dump_datetime(item.started_at),
        updated_at=_dump_datetime(item.updated_at),
        closed_at=_dump_datetime(item.closed_at) if item.closed_at else None,
    )


def row_to_session(row: CodexSessionRow, *, path_codec: PathCodec) -> CodexSession:
    return CodexSession(
        id=row.id,
        task_id=row.task_id,
        pipeline_id=row.pipeline_id,
        state=row.state,
        provider_session_id=row.provider_session_id,
        private_home_path=path_codec.load(row.private_home_path),
        private_home_relative_path=row.private_home_relative_path,
        home_uid=row.home_uid,
        image_digest=row.image_digest,
        codex_identity=row.codex_identity,
        cwd=path_codec.load(row.cwd),
        checkpoint_id=row.checkpoint_id,
        provider_store_identity=row.provider_store_identity,
        owner_role=row.owner_role,
        idempotency_key=row.idempotency_key,
        archive_generation=row.archive_generation,
        started_at=_load_datetime(row.started_at),
        updated_at=_load_datetime(row.updated_at),
        closed_at=_load_datetime(row.closed_at) if row.closed_at else None,
    )


def run_to_row(item: TaskRun) -> TaskRunRow:
    return TaskRunRow(
        id=item.id,
        task_id=item.task_id,
        pipeline_id=item.pipeline_id,
        session_id=item.session_id,
        role=item.role,
        role_ordinal=item.role_ordinal,
        state=str(item.state),
        resume_of_run_id=item.resume_of_run_id,
        parent_run_id=item.parent_run_id,
        retry_of_run_id=item.retry_of_run_id,
        model=item.model,
        reasoning=item.reasoning,
        image_version=item.image_version,
        runtime_version=item.runtime_version,
        checkpoint_id=item.checkpoint_id,
        provider_run_id=item.provider_run_id,
        provider_store_identity=item.provider_store_identity,
        wrapper_pid=item.wrapper_pid,
        exec_identity=item.exec_identity,
        exit_code=item.exit_code,
        exit_signal=item.exit_signal,
        exit_reason=item.exit_reason,
        result_summary=item.result_summary,
        idempotency_key=item.idempotency_key,
        started_at=_dump_datetime(item.started_at),
        updated_at=_dump_datetime(item.updated_at),
        completed_at=_dump_datetime(item.completed_at) if item.completed_at else None,
        archive_generation=item.archive_generation,
    )


def row_to_run(row: TaskRunRow) -> TaskRun:
    return TaskRun(
        id=row.id,
        task_id=row.task_id,
        pipeline_id=row.pipeline_id,
        session_id=row.session_id,
        role=row.role,
        role_ordinal=row.role_ordinal,
        state=row.state,
        resume_of_run_id=row.resume_of_run_id,
        parent_run_id=row.parent_run_id,
        retry_of_run_id=row.retry_of_run_id,
        model=row.model,
        reasoning=row.reasoning,
        image_version=row.image_version,
        runtime_version=row.runtime_version,
        checkpoint_id=row.checkpoint_id,
        provider_run_id=row.provider_run_id,
        provider_store_identity=row.provider_store_identity,
        wrapper_pid=row.wrapper_pid,
        exec_identity=row.exec_identity,
        exit_code=row.exit_code,
        exit_signal=row.exit_signal,
        exit_reason=row.exit_reason,
        result_summary=row.result_summary,
        idempotency_key=row.idempotency_key,
        started_at=_load_datetime(row.started_at),
        updated_at=_load_datetime(row.updated_at),
        completed_at=_load_datetime(row.completed_at) if row.completed_at else None,
        archive_generation=row.archive_generation,
    )


def checkpoint_to_row(item: WorktreeCheckpoint, *, path_codec: PathCodec) -> TaskWorktreeCheckpointRow:
    return TaskWorktreeCheckpointRow(
        id=item.id,
        task_id=item.task_id,
        execution_id=item.execution_id,
        base_commit=item.base_commit,
        expected_tree=item.expected_tree,
        phase=str(item.phase),
        owning_pipeline_id=item.owning_pipeline_id,
        active_session_id=item.active_session_id,
        active_run_id=item.active_run_id,
        worktree_path=path_codec.dump(item.worktree_path),
        image_version=item.image_version,
        runtime_version=item.runtime_version,
        created_at=_dump_datetime(item.created_at),
        updated_at=_dump_datetime(item.updated_at),
    )


def row_to_checkpoint(row: TaskWorktreeCheckpointRow, *, path_codec: PathCodec) -> WorktreeCheckpoint:
    return WorktreeCheckpoint(
        id=row.id,
        task_id=row.task_id,
        execution_id=row.execution_id,
        base_commit=row.base_commit,
        expected_tree=row.expected_tree,
        phase=row.phase,
        owning_pipeline_id=row.owning_pipeline_id,
        active_session_id=row.active_session_id,
        active_run_id=row.active_run_id,
        worktree_path=path_codec.load(row.worktree_path),
        image_version=row.image_version,
        runtime_version=row.runtime_version,
        created_at=_load_datetime(row.created_at),
        updated_at=_load_datetime(row.updated_at),
    )


def scheduler_wakeup_to_row(
    wakeup: SchedulerWakeup, *, path_codec: PathCodec
) -> SchedulerWakeupRow:
    return SchedulerWakeupRow(
        id=wakeup.id,
        reason=wakeup.reason,
        status=str(wakeup.status),
        created_at=_dump_datetime(wakeup.created_at),
        consumed_at=_dump_datetime(wakeup.consumed_at)
        if wakeup.consumed_at
        else None,
        data_json=_dump_json(wakeup.data, path_codec=path_codec) or "{}",
    )


def row_to_scheduler_wakeup(
    row: SchedulerWakeupRow, *, path_codec: PathCodec
) -> SchedulerWakeup:
    return SchedulerWakeup(
        id=row.id,
        reason=row.reason,
        status=row.status,
        created_at=_load_datetime(row.created_at),
        consumed_at=_load_datetime(row.consumed_at) if row.consumed_at else None,
        data=_loads_dict(row.data_json, path_codec=path_codec),
    )


def task_archive_sync_health_to_row(
    health: TaskArchiveSyncHealth,
    *,
    row: TaskArchiveSyncHealthRow | None = None,
) -> TaskArchiveSyncHealthRow:
    values = {
        "id": TASK_ARCHIVE_SYNC_HEALTH_ID,
        "enabled": health.enabled,
        "active_cycle_id": health.active_cycle_id,
        "last_started_at": _dump_datetime(health.last_started_at)
        if health.last_started_at
        else None,
        "last_finished_at": _dump_datetime(health.last_finished_at)
        if health.last_finished_at
        else None,
        "last_success_at": _dump_datetime(health.last_success_at)
        if health.last_success_at
        else None,
        "last_duration_seconds": health.last_duration_seconds,
        "last_exit_code": health.last_exit_code,
        "last_category": health.last_category,
        "last_detail": health.last_detail,
        "consecutive_failure_count": health.consecutive_failure_count,
    }
    if row is None:
        return TaskArchiveSyncHealthRow(**values)
    for name, value in values.items():
        if name != "id":
            setattr(row, name, value)
    return row


def row_to_task_archive_sync_health(
    row: TaskArchiveSyncHealthRow,
) -> TaskArchiveSyncHealth:
    return TaskArchiveSyncHealth(
        enabled=bool(row.enabled),
        active_cycle_id=row.active_cycle_id,
        last_started_at=_load_datetime(row.last_started_at)
        if row.last_started_at
        else None,
        last_finished_at=_load_datetime(row.last_finished_at)
        if row.last_finished_at
        else None,
        last_success_at=_load_datetime(row.last_success_at)
        if row.last_success_at
        else None,
        last_duration_seconds=row.last_duration_seconds,
        last_exit_code=row.last_exit_code,
        last_category=row.last_category,
        last_detail=row.last_detail,
        consecutive_failure_count=int(row.consecutive_failure_count),
    )


# Short aliases keep storage callers independent of the SQL row name.
archive_sync_health_to_row = task_archive_sync_health_to_row
row_to_archive_sync_health = row_to_task_archive_sync_health


def _dedupe_key(record: TaskRecord) -> str | None:
    value = record.spec.metadata.get("dedupe_key")
    return str(value) if value is not None else None


def _dump_datetime(value: datetime) -> str:
    return value.isoformat()


def _load_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _loads_dict(value: str, *, path_codec: PathCodec | None = None) -> dict[str, Any]:
    loaded = json.loads(value or "{}")
    if path_codec is not None:
        loaded = path_codec.load_json(loaded)
    return loaded if isinstance(loaded, dict) else {}


def _loads_optional_dict(
    value: str | None, *, path_codec: PathCodec | None = None
) -> dict[str, Any] | None:
    if not value:
        return None
    loaded = json.loads(value)
    if path_codec is not None:
        loaded = path_codec.load_json(loaded)
    return loaded if isinstance(loaded, dict) else None


def _loads_list(value: str | None, *, path_codec: PathCodec | None = None) -> list[Any]:
    if not value:
        return []
    loaded = json.loads(value)
    if path_codec is not None:
        loaded = path_codec.load_json(loaded)
    return loaded if isinstance(loaded, list) else []


def _dump_json(
    value: dict[str, Any] | None, *, path_codec: PathCodec | None = None
) -> str | None:
    if value is None:
        return None
    if path_codec is not None:
        value = path_codec.dump_json(value)
    return json.dumps(value, sort_keys=True) if value is not None else None


def _dump_list(
    value: list[dict[str, str]], *, path_codec: PathCodec | None = None
) -> str:
    dumped: Any = value
    if path_codec is not None:
        dumped = path_codec.dump_json(dumped)
    return json.dumps(dumped, sort_keys=True)

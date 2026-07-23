from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import Connection, Select, create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..core.lifecycle import (
    TaskPhase,
    TaskTransition,
    integration_started,
    implementation_plan_started,
    recovery_failed,
    require_transition_allowed,
    review_started,
    terminal_status,
    validation_started,
    worker_started,
)
from ..core.models import (
    ACTIVE_STATUSES,
    CodexRunState,
    CodexSession,
    Event,
    ExecutionState,
    SchedulerWakeup,
    SchedulerWakeupStatus,
    SignalFetchRun,
    SignalItem,
    SignalItemStatus,
    TaskIteration,
    TaskExecution,
    TaskPipeline,
    PipelineState,
    PipelinePhase,
    TaskPlanRun,
    TaskRecord,
    TaskRun,
    TaskSpec,
    TaskStatus,
    ValidationResult,
    WorktreeCheckpoint,
    new_execution_id,
    new_pipeline_id,
    new_run_id,
    new_session_id,
    WorkerKind,
    WorkerResult,
    new_signal_item_id,
    utc_now,
)
from ..task_archive_sync_config import (
    TASK_ARCHIVE_SYNC_HEALTH_ID,
    TaskArchiveSyncHealth,
    bounded_safe_detail,
    validate_cycle_id,
)
from .mappers import (
    PathCodec,
    event_to_row,
    checkpoint_to_row,
    execution_to_row,
    iteration_to_row,
    plan_run_to_row,
    row_to_event,
    row_to_checkpoint,
    row_to_execution,
    row_to_pipeline,
    row_to_run,
    row_to_session,
    row_to_scheduler_wakeup,
    row_to_signal_fetch_run,
    row_to_signal_item,
    row_to_iteration,
    row_to_plan_run,
    row_to_task,
    scheduler_wakeup_to_row,
    pipeline_to_row,
    run_to_row,
    session_to_row,
    signal_fetch_run_to_row,
    signal_item_to_row,
    task_to_row,
    update_iteration_row,
    update_plan_run_row,
    update_task_row,
    validation_to_row,
    row_to_task_archive_sync_health,
)
from .schema import (
    Base,
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

PRIORITY_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
WORKER_REVISION_STARTED_EVENTS = {
    "worker.revision_requested",
    "worker.validation_revision_requested",
}
WORKER_REVISION_FINISHED_EVENTS = {
    "worker.revision_finished",
    "worker.validation_revision_finished",
}
REVIEW_FINISHED_EVENTS = {
    "review.failed",
    "review.finished",
    "review.invalid_output",
}


class SQLiteTaskStore:
    """SQLite-backed store hidden behind Steward's TaskStore API."""

    def __init__(self, path: Path, on_change: Callable[[], None] | None = None):
        self.path = path
        self.on_change = on_change
        self.path_codec = PathCodec(path.parent, legacy_dir=path.parent / "steward")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}", future=True)
        event.listen(self.engine, "connect", _configure_sqlite)
        Base.metadata.create_all(self.engine)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self._migrate_schema()
        self._ensure_task_archive_sync_health()
        self._migrate_portable_paths()
        self._migrate_legacy_json()

    def add_task(
        self, spec: TaskSpec, *, dedupe_key: str | None = None
    ) -> tuple[TaskRecord, bool]:
        self._ensure_archive_epoch()
        metadata = dict(spec.metadata)
        if dedupe_key is not None:
            existing = self._find_active_dedupe(dedupe_key)
            if existing is not None:
                return existing, False
            metadata["dedupe_key"] = dedupe_key
            spec = spec.model_copy(update={"metadata": metadata}, deep=True)
        record = TaskRecord(spec=spec)
        row = task_to_row(record, dedupe_key=dedupe_key, path_codec=self.path_codec)
        event_row = event_to_row(
            Event(task_id=record.id, kind="task.created", message=record.spec.title),
            path_codec=self.path_codec,
        )
        now = utc_now()
        execution = TaskExecution(
            id=new_execution_id(),
            task_id=record.id,
            created_at=now,
            updated_at=now,
        )
        pipeline = TaskPipeline(
            id=new_pipeline_id(),
            task_id=record.id,
            execution_id=execution.id,
            ordinal=1,
            trigger="initial",
            started_at=now,
            updated_at=now,
        )
        execution_row = execution_to_row(execution, path_codec=self.path_codec)
        pipeline_row = pipeline_to_row(pipeline)
        try:
            with Session(self.engine) as session, session.begin():
                session.add(row)
                session.add(event_row)
                session.flush()
                session.add(execution_row)
                session.flush()
                session.add(pipeline_row)
                session.flush()
                execution_row.owning_pipeline_id = pipeline.id
        except IntegrityError:
            if dedupe_key is None:
                raise
            existing = self._find_active_dedupe(dedupe_key)
            if existing is None:
                raise
            return existing, False
        self.request_wakeup(
            "task.created",
            {"task_id": record.id, "kind": str(record.spec.kind)},
        )
        return record, True

    def _ensure_archive_epoch(self) -> None:
        # The first post-2.0 allocation starts the immutable archive epoch.
        # Legacy rows are never enumerated or copied by this hook.
        from ..execution.task_archive import TaskArchive

        TaskArchive(self.path.parent / "tasks").ensure_epoch()

    @property
    def archive_epoch_path(self) -> Path:
        return self.path.parent / "tasks" / "epoch.json"

    # ------------------------------------------------------------------
    # Steward 2.0 normalized execution ledger

    def ensure_execution(
        self,
        task_id: str,
        *,
        execution_id: str | None = None,
        idempotency_key: str | None = None,
        initialize_pipeline: bool = True,
        **fields: object,
    ) -> TaskExecution:
        """Create (or return) the single execution owner for a task."""
        with Session(self.engine) as session, session.begin():
            existing = session.scalar(
                select(TaskExecutionRow).where(TaskExecutionRow.task_id == task_id)
            )
            if existing is not None:
                item = row_to_execution(existing, path_codec=self.path_codec)
                if initialize_pipeline:
                    pipeline_exists = session.scalar(
                        select(TaskPipelineRow.id).where(
                            TaskPipelineRow.execution_id == existing.id
                        )
                    )
                    if pipeline_exists is None:
                        # The surrounding transaction is read-only for this
                        # path; create the initial pipeline after it closes.
                        pass
                    else:
                        return item
                else:
                    return item
            else:
                item = None
            if item is None:
                now = utc_now()
                item = TaskExecution(
                    id=execution_id or new_execution_id(),
                    task_id=task_id,
                    idempotency_key=idempotency_key,
                    **_execution_fields(fields),
                    created_at=now,
                    updated_at=now,
                )
                session.add(execution_to_row(item, path_codec=self.path_codec))
                session.flush()
        if initialize_pipeline:
            self._insert_pipeline(
                task_id,
                item.id,
                pipeline_id=None,
                trigger="initial",
                parent_pipeline_id=None,
                ordinal=1,
            )
            item = self.get_execution(task_id)
        return item

    create_execution = ensure_execution
    create_task_execution = ensure_execution
    allocate_execution = ensure_execution

    def get_execution(self, task_id_or_execution_id: str) -> TaskExecution:
        with Session(self.engine) as session:
            row = session.get(TaskExecutionRow, task_id_or_execution_id)
            if row is None:
                row = session.scalar(
                    select(TaskExecutionRow).where(
                        TaskExecutionRow.task_id == task_id_or_execution_id
                    )
                )
            if row is None:
                raise KeyError(task_id_or_execution_id)
            return row_to_execution(row, path_codec=self.path_codec)

    def transition_execution(
        self,
        execution_id: str,
        state: str,
        *,
        expected_state: str | None = None,
        phase: str | None = None,
        pipeline_id: str | None = None,
        session_id: str | None = None,
        run_id: str | None = None,
    ) -> TaskExecution:
        if state not in {item.value for item in ExecutionState}:
            raise ValueError(f"invalid execution state {state!r}")
        if phase is not None and phase not in {item.value for item in PipelinePhase}:
            raise ValueError(f"invalid execution phase {phase!r}")
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskExecutionRow, execution_id)
            if row is None:
                raise KeyError(execution_id)
            if expected_state is not None and row.state != expected_state:
                raise ValueError(
                    f"execution compare-and-set failed: expected {expected_state}, found {row.state}"
                )
            if row.state == ExecutionState.complete.value and state != row.state:
                raise ValueError("completed execution is immutable")
            if row.state == state and row.state == ExecutionState.complete.value:
                return row_to_execution(row, path_codec=self.path_codec)
            self._validate_execution_ownership(
                session,
                row,
                pipeline_id=pipeline_id,
                session_id=session_id,
                run_id=run_id,
            )
            row.state = state
            row.updated_at = now
            if phase is not None:
                row.current_phase = phase
            if pipeline_id is not None:
                row.owning_pipeline_id = pipeline_id
            if session_id is not None:
                row.active_session_id = session_id
            if run_id is not None:
                row.active_run_id = run_id
        return self.get_execution(execution_id)

    @staticmethod
    def _validate_execution_ownership(
        session: Session,
        execution: TaskExecutionRow,
        *,
        pipeline_id: str | None,
        session_id: str | None,
        run_id: str | None,
    ) -> None:
        selected_pipeline_id = pipeline_id or execution.owning_pipeline_id
        if pipeline_id is not None:
            pipeline = session.get(TaskPipelineRow, pipeline_id)
            if (
                pipeline is None
                or pipeline.task_id != execution.task_id
                or pipeline.execution_id != execution.id
            ):
                raise ValueError("execution pipeline does not belong to task")
        selected_session_id = session_id or execution.active_session_id
        if session_id is not None:
            session_row = session.get(CodexSessionRow, session_id)
            if (
                session_row is None
                or session_row.task_id != execution.task_id
                or session_row.pipeline_id != selected_pipeline_id
            ):
                raise ValueError("execution session does not belong to task pipeline")
        if run_id is not None:
            run = session.get(TaskRunRow, run_id)
            if (
                run is None
                or run.task_id != execution.task_id
                or run.pipeline_id != selected_pipeline_id
                or run.session_id != selected_session_id
            ):
                raise ValueError("execution run does not belong to task session")

    update_execution_state = transition_execution

    def list_executions(self, task_id: str) -> list[TaskExecution]:
        try:
            return [self.get_execution(task_id)]
        except KeyError:
            return []

    execution_history = list_executions

    def create_pipeline(
        self,
        task_id: str,
        *,
        execution_id: str | None = None,
        pipeline_id: str | None = None,
        trigger: str = "initial",
        parent_pipeline_id: str | None = None,
        ordinal: int | None = None,
        **fields: object,
    ) -> TaskPipeline:
        execution = self.ensure_execution(
            task_id, execution_id=execution_id, initialize_pipeline=False
        )
        if parent_pipeline_id is not None:
            parent = self.get_pipeline(parent_pipeline_id)
            if parent.task_id != task_id or parent.execution_id != execution.id:
                raise ValueError("parent pipeline must belong to the same task execution")
        return self._insert_pipeline(
            task_id,
            execution.id,
            pipeline_id=pipeline_id,
            trigger=trigger,
            parent_pipeline_id=parent_pipeline_id,
            ordinal=ordinal,
            **fields,
        )

    def _insert_pipeline(
        self,
        task_id: str,
        execution_id: str,
        *,
        pipeline_id: str | None,
        trigger: str,
        parent_pipeline_id: str | None,
        ordinal: int | None,
        **fields: object,
    ) -> TaskPipeline:
        for attempt in range(8):
            try:
                with self.engine.connect() as connection:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                    if ordinal is None:
                        value = connection.execute(
                            select(func.coalesce(func.max(TaskPipelineRow.ordinal), 0) + 1).where(
                                TaskPipelineRow.task_id == task_id
                            )
                        ).scalar_one()
                        selected_ordinal = int(value)
                    else:
                        selected_ordinal = int(ordinal)
                    now = utc_now()
                    item = TaskPipeline(
                        id=pipeline_id or new_pipeline_id(),
                        task_id=task_id,
                        execution_id=execution_id,
                        ordinal=selected_ordinal,
                        trigger=trigger,
                        parent_pipeline_id=parent_pipeline_id,
                        **_pipeline_fields(fields),
                        started_at=now,
                        updated_at=now,
                    )
                    connection.execute(TaskPipelineRow.__table__.insert().values(**_row_values(pipeline_to_row(item))))
                    connection.exec_driver_sql("COMMIT")
                    self._set_pipeline_owner(item)
                    return item
            except IntegrityError:
                if attempt == 7:
                    raise
                time.sleep(0.005 * (attempt + 1))
        raise RuntimeError("pipeline allocation failed")

    def _set_pipeline_owner(self, item: TaskPipeline) -> None:
        now = item.updated_at.isoformat()
        with Session(self.engine) as session, session.begin():
            execution = session.get(TaskExecutionRow, item.execution_id)
            if execution is not None:
                execution.owning_pipeline_id = item.id
                execution.updated_at = now

    def list_pipelines(self, task_id: str) -> list[TaskPipeline]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(TaskPipelineRow)
                .where(TaskPipelineRow.task_id == task_id)
                .order_by(TaskPipelineRow.ordinal, TaskPipelineRow.id)
            ).all()
            return [row_to_pipeline(row) for row in rows]

    pipeline_history = list_pipelines

    def get_pipeline(self, pipeline_id: str) -> TaskPipeline:
        with Session(self.engine) as session:
            row = session.get(TaskPipelineRow, pipeline_id)
            if row is None:
                raise KeyError(pipeline_id)
            return row_to_pipeline(row)

    def transition_pipeline(
        self,
        pipeline_id: str,
        state: str,
        *,
        expected_state: str | None = None,
        phase: str | None = None,
        summary: str | None = None,
    ) -> TaskPipeline:
        if state not in {item.value for item in PipelineState}:
            raise ValueError(f"invalid pipeline state {state!r}")
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskPipelineRow, pipeline_id)
            if row is None:
                raise KeyError(pipeline_id)
            if expected_state is not None and row.state != expected_state:
                raise ValueError(f"pipeline compare-and-set failed: expected {expected_state}, found {row.state}")
            if row.state != "active" and state != row.state:
                raise ValueError("completed pipeline is immutable")
            if row.state == state and row.state != "active":
                return row_to_pipeline(row)
            row.state = state
            if phase is not None:
                row.phase = phase
            row.updated_at = now
            if state != "active":
                row.completed_at = now
            execution = session.get(TaskExecutionRow, row.execution_id)
            if execution is not None:
                execution.owning_pipeline_id = row.id
                if phase is not None:
                    execution.current_phase = phase
                execution.updated_at = now
        return self.get_pipeline(pipeline_id)

    update_pipeline_state = transition_pipeline
    create_task_pipeline = create_pipeline
    allocate_pipeline = create_pipeline

    def create_session(
        self,
        task_id: str,
        pipeline_id: str,
        *,
        session_id: str | None = None,
        provider_session_id: str | None = None,
        private_home_path: Path | None = None,
        idempotency_key: str | None = None,
        archive_generation: int = 0,
    ) -> CodexSession:
        pipeline = self.get_pipeline(pipeline_id)
        if pipeline.task_id != task_id:
            raise ValueError("session pipeline does not belong to task")

        def existing_idempotent_session() -> CodexSession | None:
            if not idempotency_key:
                return None
            with Session(self.engine) as query_session:
                existing = query_session.scalar(
                    select(CodexSessionRow).where(
                        CodexSessionRow.task_id == task_id,
                        CodexSessionRow.idempotency_key == idempotency_key,
                    )
                )
                if existing is None:
                    return None
                if existing.pipeline_id != pipeline_id:
                    raise ValueError(
                        "session idempotency key belongs to another pipeline"
                    )
                return row_to_session(existing, path_codec=self.path_codec)

        if idempotency_key:
            existing = existing_idempotent_session()
            if existing is not None:
                return existing
        now = utc_now()
        item = CodexSession(
            id=session_id or new_session_id(),
            task_id=task_id,
            pipeline_id=pipeline_id,
            provider_session_id=provider_session_id,
            private_home_path=private_home_path,
            idempotency_key=idempotency_key,
            archive_generation=archive_generation,
            started_at=now,
            updated_at=now,
        )
        try:
            with Session(self.engine) as session, session.begin():
                session.add(session_to_row(item, path_codec=self.path_codec))
                session.flush()
        except IntegrityError:
            existing = existing_idempotent_session()
            if existing is not None:
                return existing
            raise
        return item

    def get_session(self, session_id: str) -> CodexSession:
        with Session(self.engine) as session:
            row = session.get(CodexSessionRow, session_id)
            if row is None:
                raise KeyError(session_id)
            return row_to_session(row, path_codec=self.path_codec)

    def list_sessions(self, task_id: str, *, pipeline_id: str | None = None) -> list[CodexSession]:
        with Session(self.engine) as session:
            statement = select(CodexSessionRow).where(CodexSessionRow.task_id == task_id)
            if pipeline_id is not None:
                statement = statement.where(CodexSessionRow.pipeline_id == pipeline_id)
            rows = session.scalars(statement.order_by(CodexSessionRow.started_at, CodexSessionRow.id)).all()
            return [row_to_session(row, path_codec=self.path_codec) for row in rows]

    session_history = list_sessions

    def close_session(
        self, session_id: str, *, state: str = "closed", expected_state: str | None = None
    ) -> CodexSession:
        if state not in {"closed", "interrupted"}:
            raise ValueError(f"invalid session state {state!r}")
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.get(CodexSessionRow, session_id)
            if row is None:
                raise KeyError(session_id)
            if expected_state is not None and row.state != expected_state:
                raise ValueError(f"session compare-and-set failed: expected {expected_state}, found {row.state}")
            if row.state == "closed" and state != "closed":
                raise ValueError("closed session is immutable")
            row.state = state
            row.updated_at = now
            row.closed_at = now
        return self.get_session(session_id)

    end_session = close_session
    create_codex_session = create_session
    allocate_session = create_session

    def create_run(
        self,
        task_id: str,
        pipeline_id: str,
        session_id: str,
        *,
        role: str,
        run_id: str | None = None,
        role_ordinal: int | None = None,
        resume_of_run_id: str | None = None,
        parent_run_id: str | None = None,
        retry_of_run_id: str | None = None,
        idempotency_key: str | None = None,
        **fields: object,
    ) -> TaskRun:
        pipeline = self.get_pipeline(pipeline_id)
        if pipeline.task_id != task_id:
            raise ValueError("run pipeline does not belong to task")
        session = self.get_session(session_id)
        if session.task_id != task_id or session.pipeline_id != pipeline_id:
            raise ValueError("run session does not belong to task pipeline")
        for relation, related_run_id in (
            ("parent", parent_run_id),
            ("retry", retry_of_run_id),
        ):
            if related_run_id is None:
                continue
            related = self.get_run(related_run_id)
            if related.task_id != task_id or related.pipeline_id != pipeline_id:
                raise ValueError(
                    f"{relation} run must belong to the same task and pipeline"
                )
        if resume_of_run_id is not None:
            predecessor = self.get_run(resume_of_run_id)
            if predecessor.task_id != task_id or predecessor.pipeline_id != pipeline_id:
                raise ValueError("recovery run must remain in the same task and pipeline")
            if predecessor.state != CodexRunState.interrupted.value:
                raise ValueError("only an interrupted run can be resumed")
            if predecessor.role not in {"planning", "implementation", "review"}:
                raise ValueError("only planning, implementation, or review runs can resume")
            if role != predecessor.role:
                raise ValueError("recovery run role does not match predecessor")
            if predecessor.session_id != session_id:
                raise ValueError("a recovery run must reuse the interrupted session")
            expected_image = fields.get("image_version")
            expected_runtime = fields.get("runtime_version")
            if predecessor.image_version != expected_image:
                raise ValueError("recovery run image version does not match predecessor")
            if predecessor.runtime_version != expected_runtime:
                raise ValueError("recovery run runtime version does not match predecessor")
            expected_checkpoint = fields.get("checkpoint_id")
            if predecessor.checkpoint_id != expected_checkpoint:
                raise ValueError("recovery run worktree checkpoint does not match predecessor")
        if idempotency_key:
            with Session(self.engine) as session:
                existing = session.scalar(
                    select(TaskRunRow).where(
                        TaskRunRow.task_id == task_id,
                        TaskRunRow.idempotency_key == idempotency_key,
                    )
                )
                if existing is not None:
                    item = row_to_run(existing)
                    if (
                        item.pipeline_id != pipeline_id
                        or item.session_id != session_id
                        or item.role != role
                        or item.resume_of_run_id != resume_of_run_id
                        or item.parent_run_id != parent_run_id
                        or item.retry_of_run_id != retry_of_run_id
                    ):
                        raise ValueError("run idempotency key conflicts with request")
                    return item
        for attempt in range(8):
            try:
                with self.engine.connect() as connection:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                    if resume_of_run_id is not None:
                        existing_recovery = connection.execute(
                            select(TaskRunRow.id).where(
                                TaskRunRow.resume_of_run_id == resume_of_run_id
                            )
                        ).scalar_one_or_none()
                        if existing_recovery is not None:
                            connection.exec_driver_sql("ROLLBACK")
                            raise ValueError(
                                "interrupted run already has a recovery"
                            )
                    selected = role_ordinal
                    if selected is None:
                        selected = connection.execute(
                            select(func.coalesce(func.max(TaskRunRow.role_ordinal), 0) + 1).where(
                                TaskRunRow.pipeline_id == pipeline_id,
                                TaskRunRow.role == role,
                            )
                        ).scalar_one()
                    now = utc_now()
                    item = TaskRun(
                        id=run_id or new_run_id(),
                        task_id=task_id,
                        pipeline_id=pipeline_id,
                        session_id=session_id,
                        role=role,
                        role_ordinal=int(selected),
                        resume_of_run_id=resume_of_run_id,
                        parent_run_id=parent_run_id,
                        retry_of_run_id=retry_of_run_id,
                        idempotency_key=idempotency_key,
                        **_run_fields(fields),
                        started_at=now,
                        updated_at=now,
                    )
                    connection.execute(TaskRunRow.__table__.insert().values(**_row_values(run_to_row(item))))
                    connection.exec_driver_sql("COMMIT")
                    self._activate_run_ownership(item)
                    return item
            except IntegrityError as exc:
                if idempotency_key:
                    with Session(self.engine) as session:
                        existing = session.scalar(
                            select(TaskRunRow).where(
                                TaskRunRow.task_id == task_id,
                                TaskRunRow.idempotency_key == idempotency_key,
                            )
                        )
                        if existing is not None:
                            return row_to_run(existing)
                if resume_of_run_id is not None:
                    with Session(self.engine) as session:
                        existing_recovery = session.scalar(
                            select(TaskRunRow.id).where(
                                TaskRunRow.resume_of_run_id == resume_of_run_id
                            )
                        )
                    if existing_recovery is not None:
                        raise ValueError(
                            "interrupted run already has a recovery"
                        ) from exc
                if attempt == 7:
                    raise
                time.sleep(0.005 * (attempt + 1))
        raise RuntimeError("run allocation failed")

    def _activate_run_ownership(self, item: TaskRun) -> None:
        now = item.updated_at.isoformat()
        with Session(self.engine) as session, session.begin():
            session_row = session.get(CodexSessionRow, item.session_id)
            if session_row is not None:
                session_row.state = "active"
                session_row.updated_at = now
            execution = session.scalar(
                select(TaskExecutionRow).where(TaskExecutionRow.task_id == item.task_id)
            )
            if execution is not None:
                execution.owning_pipeline_id = item.pipeline_id
                execution.active_session_id = item.session_id
                execution.active_run_id = item.id
                execution.updated_at = now

    def get_run(self, run_id: str) -> TaskRun:
        with Session(self.engine) as session:
            row = session.get(TaskRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            return row_to_run(row)

    def list_runs(self, task_id: str, *, pipeline_id: str | None = None) -> list[TaskRun]:
        with Session(self.engine) as session:
            statement = select(TaskRunRow).where(TaskRunRow.task_id == task_id)
            if pipeline_id is not None:
                statement = statement.where(TaskRunRow.pipeline_id == pipeline_id)
            rows = session.scalars(statement.order_by(TaskRunRow.started_at, TaskRunRow.id)).all()
            return [row_to_run(row) for row in rows]

    run_history = list_runs

    def transition_run(
        self,
        run_id: str,
        state: str,
        *,
        expected_state: str | None = None,
        exit_code: int | None = None,
        exit_signal: str | None = None,
        exit_reason: str | None = None,
        result_summary: str | None = None,
    ) -> TaskRun:
        valid_states = {item.value for item in CodexRunState}
        if state not in valid_states:
            raise ValueError(f"invalid run state {state!r}")
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            if expected_state is not None and row.state != expected_state:
                raise ValueError(f"run compare-and-set failed: expected {expected_state}, found {row.state}")
            if row.state != CodexRunState.running.value and state != row.state:
                raise ValueError("terminal run is immutable")
            if row.state == state and row.state != CodexRunState.running.value:
                return row_to_run(row)
            row.state = state
            row.updated_at = now
            if exit_code is not None:
                row.exit_code = exit_code
            row.exit_signal = exit_signal
            row.exit_reason = exit_reason
            row.result_summary = result_summary
            row.completed_at = None if state == CodexRunState.running.value else now
            if state == CodexRunState.interrupted.value:
                session_row = session.get(CodexSessionRow, row.session_id)
                if session_row is not None:
                    session_row.state = "interrupted"
                    session_row.updated_at = now
            if state != CodexRunState.running.value:
                execution = session.scalar(
                    select(TaskExecutionRow).where(TaskExecutionRow.task_id == row.task_id)
                )
                if execution is not None and execution.active_run_id == row.id:
                    execution.active_run_id = None
                    execution.updated_at = now
        return self.get_run(run_id)

    update_run_state = transition_run
    create_task_run = create_run
    allocate_run = create_run

    def mark_run_interrupted(self, run_id: str, *, reason: str | None = None) -> TaskRun:
        return self.transition_run(
            run_id,
            CodexRunState.interrupted.value,
            expected_state=CodexRunState.running.value,
            exit_reason=reason,
        )

    interrupt_run = mark_run_interrupted
    record_run_interruption = mark_run_interrupted

    def link_recovery_run(self, predecessor_run_id: str, **kwargs: object) -> TaskRun:
        predecessor = self.get_run(predecessor_run_id)
        return self.create_run(
            predecessor.task_id,
            predecessor.pipeline_id,
            predecessor.session_id,
            role=predecessor.role,
            resume_of_run_id=predecessor_run_id,
            **kwargs,
        )

    def upsert_checkpoint(self, checkpoint: WorktreeCheckpoint) -> WorktreeCheckpoint:
        with Session(self.engine) as session, session.begin():
            execution = session.get(TaskExecutionRow, checkpoint.execution_id)
            if execution is None or execution.task_id != checkpoint.task_id:
                raise ValueError("checkpoint execution does not belong to task")
            pipeline = session.get(TaskPipelineRow, checkpoint.owning_pipeline_id)
            if (
                pipeline is None
                or pipeline.task_id != checkpoint.task_id
                or pipeline.execution_id != checkpoint.execution_id
            ):
                raise ValueError("checkpoint pipeline does not belong to execution")
            if checkpoint.active_session_id is not None:
                active_session = session.get(
                    CodexSessionRow, checkpoint.active_session_id
                )
                if (
                    active_session is None
                    or active_session.task_id != checkpoint.task_id
                    or active_session.pipeline_id != checkpoint.owning_pipeline_id
                ):
                    raise ValueError(
                        "checkpoint session does not belong to task pipeline"
                    )
            if checkpoint.active_run_id is not None:
                active_run = session.get(TaskRunRow, checkpoint.active_run_id)
                if (
                    active_run is None
                    or active_run.task_id != checkpoint.task_id
                    or active_run.pipeline_id != checkpoint.owning_pipeline_id
                    or active_run.session_id != checkpoint.active_session_id
                ):
                    raise ValueError("checkpoint run does not belong to task session")
            row = session.get(TaskWorktreeCheckpointRow, checkpoint.id)
            if row is None:
                existing = session.scalar(
                    select(TaskWorktreeCheckpointRow).where(
                        TaskWorktreeCheckpointRow.execution_id == checkpoint.execution_id
                    )
                )
                if existing is not None:
                    row = existing
                    checkpoint = checkpoint.model_copy(update={"id": existing.id})
                else:
                    row = checkpoint_to_row(checkpoint, path_codec=self.path_codec)
                    session.add(row)
            if row is not None and row.id == checkpoint.id:
                values = _row_values(checkpoint_to_row(checkpoint, path_codec=self.path_codec))
                for key, value in values.items():
                    if key != "id":
                        setattr(row, key, value)
            session.flush()
        return checkpoint

    save_checkpoint = upsert_checkpoint

    def get_checkpoint(self, execution_id: str) -> WorktreeCheckpoint:
        with Session(self.engine) as session:
            row = session.scalar(
                select(TaskWorktreeCheckpointRow).where(
                    TaskWorktreeCheckpointRow.execution_id == execution_id
                )
            )
            if row is None:
                raise KeyError(execution_id)
            return row_to_checkpoint(row, path_codec=self.path_codec)

    def checkpoint_matches(self, execution_id: str, **expected: object) -> bool:
        try:
            checkpoint = self.get_checkpoint(execution_id)
        except KeyError:
            return False
        return all(getattr(checkpoint, key, None) == value for key, value in expected.items())

    def get(self, task_id: str) -> TaskRecord:
        with Session(self.engine) as session:
            row = session.scalar(_task_query().where(TaskRow.id == task_id))
            if row is None:
                raise KeyError(task_id)
            return row_to_task(row, path_codec=self.path_codec)

    def save(self, record: TaskRecord) -> None:
        record.updated_at = utc_now()
        with Session(self.engine) as session, session.begin():
            row = session.scalar(_task_query().where(TaskRow.id == record.id))
            if row is None:
                raise KeyError(record.id)
            row.validations.clear()
            session.flush()
            update_task_row(row, record, path_codec=self.path_codec)
        self._notify_change()

    def update_status(
        self, task_id: str, status: TaskStatus, summary: str = ""
    ) -> TaskRecord:
        return self.transition_task(
            task_id,
            _transition_for_status(TaskStatus(status), summary),
        )

    def transition_task(
        self, task_id: str, transition: TaskTransition
    ) -> TaskRecord:
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.scalar(_task_query().where(TaskRow.id == task_id))
            if row is None:
                raise KeyError(task_id)
            current = TaskStatus(row.status)
            require_transition_allowed(current, transition)
            row.status = transition.status.value
            row.summary = transition.summary
            row.updated_at = now
            session.add(
                event_to_row(
                    Event(
                        task_id=task_id,
                        kind="task.status",
                        message=transition.status.value,
                        data={
                            "summary": transition.summary,
                            "phase": transition.phase.value,
                        },
                    ),
                    path_codec=self.path_codec,
                )
            )
        self.request_wakeup(
            "task.status",
            {
                "task_id": task_id,
                "status": transition.status.value,
                "phase": transition.phase.value,
            },
        )
        return self.get(task_id)

    def start_worker(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, worker_started(summary))

    def start_implementation_plan(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, implementation_plan_started(summary))

    def start_validation(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, validation_started(summary))

    def start_review(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, review_started(summary))

    def start_integration(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, integration_started(summary))

    def finish_task(
        self, task_id: str, status: TaskStatus, summary: str = ""
    ) -> TaskRecord:
        return self.transition_task(task_id, terminal_status(TaskStatus(status), summary))

    def touch_active_task(self, task_id: str) -> bool:
        active_statuses = {status.value for status in ACTIVE_STATUSES}
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskRow, task_id)
            if row is None or row.status not in active_statuses:
                return False
            row.updated_at = utc_now().isoformat()
        self._notify_change()
        return True

    def add_event(
        self,
        task_id: str,
        kind: str,
        message: str,
        data: dict[str, object] | None = None,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            session.add(
                event_to_row(
                    Event(task_id=task_id, kind=kind, message=message, data=data or {}),
                    path_codec=self.path_codec,
                )
            )
        self._notify_change()

    def add_signal_fetch_run(self, run: SignalFetchRun) -> None:
        with Session(self.engine) as session, session.begin():
            session.add(signal_fetch_run_to_row(run))
        self._notify_change()

    def list_signal_fetch_runs(
        self, *, limit: int | None = None
    ) -> list[SignalFetchRun]:
        statement = select(SignalFetchRunRow).order_by(
            SignalFetchRunRow.started_at.desc()
        )
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_signal_fetch_run(row)
                for row in session.scalars(statement).all()
            ]

    def latest_signal_fetch_run(self, provider: str) -> SignalFetchRun | None:
        with Session(self.engine) as session:
            row = session.scalar(
                select(SignalFetchRunRow)
                .where(SignalFetchRunRow.provider == provider)
                .order_by(SignalFetchRunRow.completed_at.desc())
                .limit(1)
            )
            return row_to_signal_fetch_run(row) if row is not None else None

    def add_signal_item(
        self, item: SignalItem, *, suppression_hours: int = 24
    ) -> tuple[SignalItem, bool]:
        now = utc_now()
        item = item.model_copy(
            update={"created_at": item.created_at, "updated_at": now}
        )
        saved_item: SignalItem | None = None
        was_created = False
        with Session(self.engine) as session, session.begin():
            existing = _matching_signal_row(session, item)
            if existing is not None:
                if _signal_row_suppressed(
                    session,
                    existing,
                    suppression_hours=suppression_hours,
                ):
                    existing.updated_at = now.isoformat()
                    if item.source_fetch_id:
                        existing.source_fetch_id = item.source_fetch_id
                    saved_item = row_to_signal_item(existing, path_codec=self.path_codec)
                else:
                    item = item.model_copy(update={"id": new_signal_item_id()})
            if saved_item is None:
                session.add(signal_item_to_row(item, path_codec=self.path_codec))
                was_created = True
        if was_created:
            self.request_wakeup(
                "signal.pending",
                {"signal_item_id": item.id, "provider": item.provider},
            )
            return item, True
        self._notify_change()
        assert saved_item is not None
        return saved_item, False

    def add_signal_items(
        self, items: list[SignalItem], *, suppression_hours: int = 24
    ) -> tuple[list[SignalItem], int]:
        saved: list[SignalItem] = []
        created = 0
        for item in items:
            saved_item, was_created = self.add_signal_item(
                item, suppression_hours=suppression_hours
            )
            saved.append(saved_item)
            if was_created:
                created += 1
        return saved, created

    def list_signal_items(
        self,
        *,
        include_errors: bool = False,
        status: SignalItemStatus | str | None = None,
        limit: int | None = None,
    ) -> list[SignalItem]:
        statement = select(SignalItemRow).order_by(SignalItemRow.created_at.desc())
        if not include_errors:
            statement = statement.where(SignalItemRow.kind != "signal-error")
        if status is not None:
            statement = statement.where(SignalItemRow.status == str(status))
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_signal_item(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def pending_signal_items(
        self, *, include_errors: bool = False, limit: int | None = None
    ) -> list[SignalItem]:
        statement = (
            select(SignalItemRow)
            .where(SignalItemRow.status == SignalItemStatus.pending.value)
            .order_by(SignalItemRow.created_at)
        )
        if not include_errors:
            statement = statement.where(SignalItemRow.kind != "signal-error")
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_signal_item(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def request_wakeup(
        self, reason: str, data: dict[str, object] | None = None
    ) -> SchedulerWakeup:
        wakeup = SchedulerWakeup(reason=reason, data=data or {})
        with Session(self.engine) as session, session.begin():
            session.add(scheduler_wakeup_to_row(wakeup, path_codec=self.path_codec))
        self._notify_change()
        return wakeup

    # ------------------------------------------------------------------
    # Standalone raw task-archive synchronizer health

    def _ensure_task_archive_sync_health(self) -> None:
        """Create the one health row without touching task or mirror state."""

        with Session(self.engine) as session, session.begin():
            row = session.get(TaskArchiveSyncHealthRow, TASK_ARCHIVE_SYNC_HEALTH_ID)
            if row is None:
                session.add(
                    TaskArchiveSyncHealthRow(
                        id=TASK_ARCHIVE_SYNC_HEALTH_ID,
                        enabled=False,
                        consecutive_failure_count=0,
                    )
                )

    def get_task_archive_sync_health(self) -> TaskArchiveSyncHealth:
        with Session(self.engine) as session:
            row = session.get(TaskArchiveSyncHealthRow, TASK_ARCHIVE_SYNC_HEALTH_ID)
            if row is None:
                # This is defensive for databases created by an interrupted
                # migration; normal construction always creates the row.
                session.add(
                    TaskArchiveSyncHealthRow(
                        id=TASK_ARCHIVE_SYNC_HEALTH_ID,
                        enabled=False,
                        consecutive_failure_count=0,
                    )
                )
                session.commit()
                row = session.get(TaskArchiveSyncHealthRow, TASK_ARCHIVE_SYNC_HEALTH_ID)
            assert row is not None
            return row_to_task_archive_sync_health(row)

    task_archive_sync_health = get_task_archive_sync_health
    archive_sync_health = get_task_archive_sync_health

    def set_task_archive_sync_enabled(self, enabled: bool) -> TaskArchiveSyncHealth:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                """
                UPDATE task_archive_sync_health
                   SET enabled = :enabled
                 WHERE id = :id
                """,
                {"enabled": int(enabled), "id": TASK_ARCHIVE_SYNC_HEALTH_ID},
            )
        self._notify_change()
        return self.get_task_archive_sync_health()

    enable_task_archive_sync = set_task_archive_sync_enabled

    def claim_task_archive_sync_cycle(
        self,
        cycle_id: str,
        *,
        started_at: datetime | None = None,
        require_enabled: bool = False,
    ) -> bool:
        """Atomically claim the idle health row for one transfer cycle."""

        validate_cycle_id(cycle_id)
        if not isinstance(require_enabled, bool):
            raise ValueError("require_enabled must be a boolean")
        timestamp = (started_at or utc_now()).isoformat()
        predicate = "AND enabled = 1" if require_enabled else ""
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(
                f"""
                UPDATE task_archive_sync_health
                   SET active_cycle_id = :cycle_id,
                       last_started_at = :started_at,
                       last_finished_at = NULL,
                       last_exit_code = NULL,
                       last_category = NULL,
                       last_detail = NULL,
                       last_duration_seconds = NULL
                 WHERE id = :id
                   AND active_cycle_id IS NULL
                   {predicate}
                """,
                {
                    "id": TASK_ARCHIVE_SYNC_HEALTH_ID,
                    "cycle_id": cycle_id,
                    "started_at": timestamp,
                },
            )
            claimed = result.rowcount == 1
        if claimed:
            self._notify_change()
        return claimed

    claim_archive_sync_cycle = claim_task_archive_sync_cycle
    claim_task_archive_cycle = claim_task_archive_sync_cycle

    @staticmethod
    def _bounded_duration(duration_seconds: float | None) -> float | None:
        if duration_seconds is None:
            return None
        if isinstance(duration_seconds, bool):
            return None
        try:
            value = float(duration_seconds)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(value):
            return None
        if value < 0:
            return 0.0
        return min(value, 86400.0)

    @staticmethod
    def _bounded_exit_code(exit_code: int | None) -> int | None:
        if exit_code is None:
            return None
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError("exit_code must be an integer or None")
        return max(-255, min(255, exit_code))

    def finish_task_archive_sync_success(
        self,
        cycle_id: str,
        *,
        finished_at: datetime | None = None,
        duration_seconds: float | None = None,
        exit_code: int = 0,
        safe_detail: str | None = None,
        detail: str | None = None,
    ) -> bool:
        """Record rsync exit 0 and release the active-cycle claim."""

        validate_cycle_id(cycle_id)
        bounded_exit_code = self._bounded_exit_code(exit_code)
        if bounded_exit_code != 0:
            raise ValueError("success requires exit_code 0")
        timestamp = (finished_at or utc_now()).isoformat()
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(
                """
                UPDATE task_archive_sync_health
                   SET active_cycle_id = NULL,
                       last_finished_at = :finished_at,
                       last_success_at = :finished_at,
                       last_duration_seconds = :duration,
                       last_exit_code = :exit_code,
                       last_category = 'success',
                       last_detail = :detail,
                       consecutive_failure_count = 0
                 WHERE id = :id AND active_cycle_id = :cycle_id
                """,
                {
                    "id": TASK_ARCHIVE_SYNC_HEALTH_ID,
                    "cycle_id": cycle_id,
                    "finished_at": timestamp,
                    "duration": self._bounded_duration(duration_seconds),
                    "exit_code": bounded_exit_code,
                    "detail": bounded_safe_detail(
                        safe_detail if safe_detail is not None else detail
                    ),
                },
            )
            finished = result.rowcount == 1
        if finished:
            self._notify_change()
        return finished

    finish_archive_sync_success = finish_task_archive_sync_success

    def finish_task_archive_sync_failure(
        self,
        cycle_id: str,
        *,
        category: str,
        exit_code: int | None = None,
        safe_detail: str | None = None,
        detail: str | None = None,
        finished_at: datetime | None = None,
        duration_seconds: float | None = None,
    ) -> bool:
        """Record a bounded failure/incomplete outcome and release the claim."""

        validate_cycle_id(cycle_id)
        if not isinstance(category, str) or not category or len(category) > 64:
            raise ValueError("category must be a short non-empty string")
        if any(not character.isalnum() and character not in "_-" for character in category):
            raise ValueError("category contains unsupported characters")
        bounded_exit_code = self._bounded_exit_code(exit_code)
        timestamp = (finished_at or utc_now()).isoformat()
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(
                """
                UPDATE task_archive_sync_health
                   SET active_cycle_id = NULL,
                       last_finished_at = :finished_at,
                       last_duration_seconds = :duration,
                       last_exit_code = :exit_code,
                       last_category = :category,
                       last_detail = :detail,
                       consecutive_failure_count = MIN(consecutive_failure_count + 1, 1000000)
                 WHERE id = :id AND active_cycle_id = :cycle_id
                """,
                {
                    "id": TASK_ARCHIVE_SYNC_HEALTH_ID,
                    "cycle_id": cycle_id,
                    "finished_at": timestamp,
                    "duration": self._bounded_duration(duration_seconds),
                    "exit_code": bounded_exit_code,
                    "category": category,
                    "detail": bounded_safe_detail(
                        safe_detail if safe_detail is not None else detail
                    ),
                },
            )
            finished = result.rowcount == 1
        if finished:
            self._notify_change()
        return finished

    finish_archive_sync_failure = finish_task_archive_sync_failure

    def finish_task_archive_sync_incomplete(
        self,
        cycle_id: str,
        *,
        exit_code: int | None = 24,
        safe_detail: str | None = None,
        detail: str | None = None,
        finished_at: datetime | None = None,
        duration_seconds: float | None = None,
    ) -> bool:
        return self.finish_task_archive_sync_failure(
            cycle_id,
            category="incomplete",
            exit_code=exit_code,
            safe_detail=safe_detail,
            detail=detail,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
        )

    finish_archive_sync_incomplete = finish_task_archive_sync_incomplete

    def reconcile_interrupted_task_archive_sync(
        self,
        *,
        finished_at: datetime | None = None,
        safe_detail: str = "cycle interrupted before completion",
        detail: str | None = None,
    ) -> bool:
        """Close an active cycle left by a process restart."""

        timestamp = (finished_at or utc_now()).isoformat()
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(
                """
                UPDATE task_archive_sync_health
                   SET active_cycle_id = NULL,
                       last_finished_at = :finished_at,
                       last_duration_seconds = NULL,
                       last_exit_code = NULL,
                       last_category = 'interrupted',
                       last_detail = :detail,
                       consecutive_failure_count = MIN(consecutive_failure_count + 1, 1000000)
                 WHERE id = :id AND active_cycle_id IS NOT NULL
                """,
                {
                    "id": TASK_ARCHIVE_SYNC_HEALTH_ID,
                    "finished_at": timestamp,
                    "detail": bounded_safe_detail(
                        safe_detail if detail is None else detail
                    )
                    or "cycle interrupted before completion",
                },
            )
            reconciled = result.rowcount == 1
        if reconciled:
            self._notify_change()
        return reconciled

    reconcile_task_archive_sync = reconcile_interrupted_task_archive_sync
    reconcile_archive_sync_interruption = reconcile_interrupted_task_archive_sync
    reconcile_interrupted_active_cycle = reconcile_interrupted_task_archive_sync

    def pending_wakeups(self, *, limit: int | None = None) -> list[SchedulerWakeup]:
        statement = (
            select(SchedulerWakeupRow)
            .where(SchedulerWakeupRow.status == SchedulerWakeupStatus.pending.value)
            .order_by(SchedulerWakeupRow.created_at)
        )
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_scheduler_wakeup(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def recent_wakeups(self, *, limit: int = 20) -> list[SchedulerWakeup]:
        statement = (
            select(SchedulerWakeupRow)
            .order_by(SchedulerWakeupRow.created_at.desc())
            .limit(limit)
        )
        with Session(self.engine) as session:
            return [
                row_to_scheduler_wakeup(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def consume_wakeups(self, wakeup_ids: list[str]) -> int:
        if not wakeup_ids:
            return 0
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                select(SchedulerWakeupRow).where(
                    SchedulerWakeupRow.id.in_(wakeup_ids),
                    SchedulerWakeupRow.status == SchedulerWakeupStatus.pending.value,
                )
            ).all()
            for row in rows:
                row.status = SchedulerWakeupStatus.consumed.value
                row.consumed_at = now
            consumed = len(rows)
        if consumed:
            self._notify_change()
        return consumed

    def prune_consumed_wakeups(self, *, older_than_days: int = 7) -> int:
        cutoff = (utc_now() - timedelta(days=older_than_days)).isoformat()
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                select(SchedulerWakeupRow).where(
                    SchedulerWakeupRow.status == SchedulerWakeupStatus.consumed.value,
                    SchedulerWakeupRow.consumed_at < cutoff,
                )
            ).all()
            for row in rows:
                session.delete(row)
            deleted = len(rows)
        if deleted:
            self._notify_change()
        return deleted

    def mark_signal_items_planned(
        self,
        ids: list[str],
        *,
        planner_run_id: str | None,
        task_id: str | None,
    ) -> int:
        if not ids:
            return 0
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                select(SignalItemRow).where(
                    SignalItemRow.id.in_(ids),
                    SignalItemRow.status == SignalItemStatus.pending.value,
                )
            ).all()
            for row in rows:
                row.status = SignalItemStatus.planned.value
                row.planned_at = now
                row.updated_at = now
                row.planner_run_id = planner_run_id
                row.planned_task_id = task_id
            planned = len(rows)
        if planned:
            self._notify_change()
        return planned

    def requeue_failed_signal_items(
        self, *, retry_after_hours: int = 24, provider: str | None = None
    ) -> int:
        now = utc_now()
        cutoff = now - timedelta(hours=retry_after_hours)
        now_text = now.isoformat()
        statement = (
            select(SignalItemRow, TaskRow)
            .join(TaskRow, SignalItemRow.planned_task_id == TaskRow.id)
            .where(
                SignalItemRow.status == SignalItemStatus.planned.value,
                TaskRow.status == TaskStatus.failed.value,
            )
            .order_by(SignalItemRow.created_at.desc())
        )
        if provider is not None:
            statement = statement.where(SignalItemRow.provider == provider)
        with Session(self.engine) as session, session.begin():
            rows = session.execute(statement).all()
            requeued = 0
            for signal_row, task_row in rows:
                planned_at = signal_row.planned_at or signal_row.updated_at
                retry_from = max(
                    datetime.fromisoformat(planned_at),
                    datetime.fromisoformat(task_row.updated_at),
                )
                if retry_from > cutoff:
                    continue
                duplicate_rows = session.execute(
                    select(SignalItemRow, TaskRow)
                    .outerjoin(TaskRow, SignalItemRow.planned_task_id == TaskRow.id)
                    .where(
                        SignalItemRow.id != signal_row.id,
                        SignalItemRow.provider == signal_row.provider,
                        SignalItemRow.fingerprint == signal_row.fingerprint,
                        SignalItemRow.status.in_(
                            [
                                SignalItemStatus.pending.value,
                                SignalItemStatus.planned.value,
                            ]
                        ),
                    )
                ).all()
                if any(
                    _signal_duplicate_blocks_requeue(
                        duplicate_signal_row,
                        duplicate_task_row,
                        cutoff=cutoff,
                    )
                    for duplicate_signal_row, duplicate_task_row in duplicate_rows
                ):
                    continue
                signal_row.status = SignalItemStatus.pending.value
                signal_row.updated_at = now_text
                signal_row.planned_at = None
                signal_row.planner_run_id = None
                signal_row.planned_task_id = None
                requeued += 1
        if requeued:
            self.request_wakeup(
                "signal.pending",
                {"provider": provider, "requeued_failed": requeued},
            )
        return requeued

    def supersede_signal_items(
        self, ids: list[str], *, planner_run_id: str | None
    ) -> int:
        if not ids:
            return 0
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                select(SignalItemRow).where(
                    SignalItemRow.id.in_(ids),
                    SignalItemRow.status == SignalItemStatus.pending.value,
                )
            ).all()
            for row in rows:
                row.status = SignalItemStatus.superseded.value
                row.updated_at = now
                row.planner_run_id = planner_run_id
            superseded = len(rows)
        if superseded:
            self._notify_change()
        return superseded

    def begin_iteration(
        self,
        task_id: str,
        iteration: int,
        label: str,
        *,
        worker_name: str,
        worker_prompt_path: Path | None,
        worker_transcript_path: Path,
        worker_last_message_path: Path,
        running_summary: str | None = None,
    ) -> TaskIteration:
        now = utc_now()
        item = TaskIteration(
            task_id=task_id,
            iteration=iteration,
            label=label,
            worker_name=worker_name,
            worker_prompt_path=worker_prompt_path,
            worker_transcript_path=worker_transcript_path,
            worker_last_message_path=worker_last_message_path,
            started_at=now,
            updated_at=now,
        )
        self._upsert_iteration(
            item,
            running_summary=running_summary if iteration > 0 else None,
        )
        return item

    def finish_iteration_worker(
        self, task_id: str, iteration: int, result: WorkerResult
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.worker_prompt_path = result.prompt_path
        item.worker_transcript_path = result.transcript_path
        item.worker_last_message_path = result.last_message_path
        item.worker_exit_code = result.exit_code
        item.worker_completed = result.completed
        item.worker_model = result.model
        item.worker_reasoning_effort = result.reasoning_effort
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def record_iteration_validations(
        self,
        task_id: str,
        iteration: int,
        validations: list[ValidationResult],
    ) -> None:
        with Session(self.engine) as session, session.begin():
            now = utc_now().isoformat()
            existing_count = (
                session.scalar(
                    select(func.count())
                    .select_from(ValidationRow)
                    .where(ValidationRow.task_id == task_id)
                )
                or 0
            )
            rows = [
                validation_to_row(
                    task_id,
                    existing_count + index,
                    validation,
                    iteration=iteration,
                    path_codec=self.path_codec,
                )
                for index, validation in enumerate(validations)
            ]
            session.add_all(rows)
            row = session.scalar(
                select(TaskIterationRow).where(
                    TaskIterationRow.task_id == task_id,
                    TaskIterationRow.iteration == iteration,
                )
            )
            if row is not None:
                row.updated_at = now
            task = session.get(TaskRow, task_id)
            if task is not None:
                task.updated_at = now
        self._notify_change()

    def record_iteration_patch(
        self, task_id: str, iteration: int, patch_path: Path
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.patch_path = patch_path
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def start_iteration_review(
        self,
        task_id: str,
        iteration: int,
        *,
        reviewer_name: str,
        reviewer_prompt_path: Path,
        reviewer_transcript_path: Path,
        reviewer_last_message_path: Path,
        review_run: int,
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.reviewer_name = reviewer_name
        item.reviewer_prompt_path = reviewer_prompt_path
        item.reviewer_transcript_path = reviewer_transcript_path
        item.reviewer_last_message_path = reviewer_last_message_path
        item.reviewer_exit_code = None
        item.reviewer_completed = False
        item.reviewer_run = review_run
        item.review_json = None
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def record_iteration_review(
        self,
        task_id: str,
        iteration: int,
        result: WorkerResult,
        *,
        reviewer_name: str,
        review_run: int,
        review: dict[str, object] | None,
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.reviewer_name = reviewer_name
        item.reviewer_prompt_path = result.prompt_path
        item.reviewer_transcript_path = result.transcript_path
        item.reviewer_last_message_path = result.last_message_path
        item.reviewer_exit_code = result.exit_code
        item.reviewer_completed = result.completed
        item.reviewer_model = result.model
        item.reviewer_reasoning_effort = result.reasoning_effort
        item.reviewer_run = review_run
        item.review_json = review
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def get_iteration(self, task_id: str, iteration: int) -> TaskIteration:
        with Session(self.engine) as session:
            row = session.scalar(
                select(TaskIterationRow).where(
                    TaskIterationRow.task_id == task_id,
                    TaskIterationRow.iteration == iteration,
                )
            )
            if row is None:
                raise KeyError(f"{task_id}:{iteration}")
            return row_to_iteration(row, path_codec=self.path_codec)

    def iterations(self, task_id: str) -> list[TaskIteration]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(TaskIterationRow)
                .where(TaskIterationRow.task_id == task_id)
                .order_by(TaskIterationRow.iteration)
            ).all()
            return [row_to_iteration(row, path_codec=self.path_codec) for row in rows]

    def begin_plan_run(
        self,
        task_id: str,
        run: int,
        *,
        prompt_path: Path,
        transcript_path: Path,
        last_message_path: Path,
        model: str | None,
        reasoning_effort: str | None,
    ) -> TaskPlanRun:
        now = utc_now()
        item = TaskPlanRun(
            task_id=task_id,
            run=run,
            prompt_path=prompt_path,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            completed=False,
            model=model,
            reasoning_effort=reasoning_effort,
            started_at=now,
            updated_at=now,
        )
        self._upsert_plan_run(item)
        return item

    def finish_plan_run(
        self,
        task_id: str,
        run: int,
        result: WorkerResult,
        *,
        plan: dict[str, object] | None,
        plan_path: Path | None,
    ) -> TaskPlanRun:
        item = self.get_plan_run(task_id, run)
        item.prompt_path = result.prompt_path
        item.transcript_path = result.transcript_path
        item.last_message_path = result.last_message_path
        item.plan_path = plan_path
        item.exit_code = result.exit_code
        item.completed = result.completed
        item.model = result.model
        item.reasoning_effort = result.reasoning_effort
        item.plan_json = plan
        item.updated_at = utc_now()
        self._upsert_plan_run(item)
        return item

    def get_plan_run(self, task_id: str, run: int) -> TaskPlanRun:
        with Session(self.engine) as session:
            row = session.scalar(
                select(TaskPlanRunRow).where(
                    TaskPlanRunRow.task_id == task_id,
                    TaskPlanRunRow.run == run,
                )
            )
            if row is None:
                raise KeyError(f"{task_id}:plan:{run}")
            return row_to_plan_run(row, path_codec=self.path_codec)

    def plan_runs(self, task_id: str) -> list[TaskPlanRun]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(TaskPlanRunRow)
                .where(TaskPlanRunRow.task_id == task_id)
                .order_by(TaskPlanRunRow.run)
            ).all()
            return [row_to_plan_run(row, path_codec=self.path_codec) for row in rows]

    def list_tasks(self, *, limit: int | None = None) -> list[TaskRecord]:
        statement = _task_query().order_by(TaskRow.created_at.desc())
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_task(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def queued_tasks(self, *, limit: int | None = None) -> list[TaskRecord]:
        tasks = self._tasks_by_status(TaskStatus.queued)
        tasks.sort(
            key=lambda task: (
                0 if task.spec.worker == "integration-manager" else 1,
                PRIORITY_ORDER.get(str(task.spec.priority), 99),
                task.created_at,
            )
        )
        return tasks if limit is None else tasks[:limit]

    def active_count(self) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(TaskRow)
                    .where(TaskRow.status.in_(ACTIVE_STATUSES))
                )
                or 0
            )

    def source_active_count(self) -> int:
        with Session(self.engine) as session:
            return _count_tasks(
                session,
                statuses=[
                    TaskStatus.running.value,
                    TaskStatus.reviewing.value,
                    TaskStatus.integrating.value,
                ],
                integration=False,
            )

    def source_queued_count(self) -> int:
        with Session(self.engine) as session:
            return _count_tasks(
                session,
                statuses=[TaskStatus.queued.value],
                integration=False,
            )

    def integration_active_count(self) -> int:
        with Session(self.engine) as session:
            return _count_tasks(
                session,
                statuses=[
                    TaskStatus.running.value,
                    TaskStatus.reviewing.value,
                    TaskStatus.integrating.value,
                ],
                integration=True,
            )

    def integration_queued_count(self) -> int:
        with Session(self.engine) as session:
            return _count_tasks(
                session,
                statuses=[TaskStatus.queued.value],
                integration=True,
            )

    def events(self, task_id: str, *, limit: int | None = None) -> list[Event]:
        statement = (
            select(EventRow)
            .where(EventRow.task_id == task_id)
            .order_by(EventRow.created_at)
        )
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_event(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def count_events(self, kind: str) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(EventRow)
                    .where(EventRow.kind == kind)
                )
                or 0
            )

    def count_events_since(self, kind: str, since: datetime) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(EventRow)
                    .where(EventRow.kind == kind)
                    .where(EventRow.created_at >= since.isoformat())
                )
                or 0
            )

    def recover_stale_active_tasks(
        self,
        *,
        stale_after_minutes: int,
        status_stale_after_minutes: dict[str, int] | None = None,
    ) -> list[str]:
        recovered: list[str] = []
        active_statuses = [
            status.value for status in ACTIVE_STATUSES if status != TaskStatus.queued
        ]
        status_stale_after_minutes = status_stale_after_minutes or {}
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                _task_query().where(TaskRow.status.in_(active_statuses))
            ).all()
            for row in rows:
                if row.status == TaskStatus.integrating.value and (
                    _has_active_integration_for_source(session, row.id)
                ):
                    continue
                events = session.scalars(
                    select(EventRow)
                    .where(EventRow.task_id == row.id)
                    .order_by(EventRow.id)
                ).all()
                effective_status = _effective_stale_status(row, events)
                stale_after = status_stale_after_minutes.get(
                    effective_status, stale_after_minutes
                )
                cutoff = utc_now() - timedelta(minutes=stale_after)
                if _effective_stale_since(row, events) >= cutoff:
                    continue
                previous_status = row.status
                summary = f"stale active task recovered after {stale_after} minutes"
                transition = recovery_failed(summary)
                require_transition_allowed(TaskStatus(row.status), transition)
                row.status = transition.status.value
                row.summary = transition.summary
                row.updated_at = utc_now().isoformat()
                session.add(
                    event_to_row(
                        Event(
                            task_id=row.id,
                            kind="task.recovered_stale",
                            message=transition.summary,
                            data={
                                "previous_status": previous_status,
                                "effective_status": effective_status,
                                "phase": transition.phase.value,
                                "stale_after_minutes": stale_after,
                            },
                        ),
                        path_codec=self.path_codec,
                    )
                )
                recovered.append(row.id)
        if recovered:
            self._notify_change()
        return recovered

    def audit(self) -> list[str]:
        findings: list[str] = []
        seen: set[str] = set()
        for task in self.list_tasks():
            if task.id in seen:
                findings.append(f"duplicate task id: {task.id}")
            seen.add(task.id)
            if (
                TaskStatus(task.status) == TaskStatus.succeeded
                and task.patch_path is None
            ):
                findings.append(f"{task.id}: succeeded without a saved patch")
            if TaskStatus(task.status) == TaskStatus.pushed and task.patch_path is None:
                findings.append(f"{task.id}: pushed without a saved patch")
        return findings

    def _tasks_by_status(self, status: TaskStatus) -> list[TaskRecord]:
        with Session(self.engine) as session:
            rows = session.scalars(
                _task_query().where(TaskRow.status == status.value)
            ).all()
            return [row_to_task(row, path_codec=self.path_codec) for row in rows]

    def _find_active_dedupe(self, dedupe_key: str) -> TaskRecord | None:
        with Session(self.engine) as session:
            row = session.scalar(
                _task_query()
                .where(
                    TaskRow.dedupe_key == dedupe_key,
                    TaskRow.status.in_(ACTIVE_STATUSES),
                )
                .limit(1)
            )
            return row_to_task(row, path_codec=self.path_codec) if row is not None else None

    def _migrate_legacy_json(self) -> None:
        legacy = self.path.with_suffix(".json")
        if not legacy.exists() or self.list_tasks():
            return
        raw = json.loads(legacy.read_text(encoding="utf-8"))
        tasks = [TaskRecord.model_validate(item) for item in raw.get("tasks", [])]
        events = [Event.model_validate(item) for item in raw.get("events", [])]
        with Session(self.engine) as session, session.begin():
            session.add_all(
                task_to_row(task, path_codec=self.path_codec) for task in tasks
            )
            session.add_all(
                event_to_row(item, path_codec=self.path_codec) for item in events
            )

    def _upsert_iteration(
        self, item: TaskIteration, *, running_summary: str | None = None
    ) -> None:
        with Session(self.engine) as session, session.begin():
            row = session.scalar(
                select(TaskIterationRow).where(
                    TaskIterationRow.task_id == item.task_id,
                    TaskIterationRow.iteration == item.iteration,
                )
            )
            if row is None:
                session.add(iteration_to_row(item, path_codec=self.path_codec))
            else:
                update_iteration_row(row, item, path_codec=self.path_codec)
            task = session.get(TaskRow, item.task_id)
            if task is not None:
                if (
                    running_summary is not None
                    and task.status == TaskStatus.reviewing.value
                ):
                    transition = worker_started(running_summary)
                    require_transition_allowed(TaskStatus(task.status), transition)
                    task.status = transition.status.value
                    task.summary = transition.summary
                    session.add(
                        event_to_row(
                            Event(
                                task_id=item.task_id,
                                kind="task.status",
                                message=transition.status.value,
                                data={
                                    "summary": transition.summary,
                                    "phase": transition.phase.value,
                                    "source": "begin_iteration",
                                },
                            ),
                            path_codec=self.path_codec,
                        )
                    )
                task.updated_at = item.updated_at.isoformat()
        self._notify_change()

    def _upsert_plan_run(self, item: TaskPlanRun) -> None:
        with Session(self.engine) as session, session.begin():
            row = session.scalar(
                select(TaskPlanRunRow).where(
                    TaskPlanRunRow.task_id == item.task_id,
                    TaskPlanRunRow.run == item.run,
                )
            )
            if row is None:
                session.add(plan_run_to_row(item, path_codec=self.path_codec))
            else:
                update_plan_run_row(row, item, path_codec=self.path_codec)
            task = session.get(TaskRow, item.task_id)
            if task is not None:
                task.updated_at = item.updated_at.isoformat()
        self._notify_change()

    def _notify_change(self) -> None:
        if self.on_change is not None:
            self.on_change()

    def _migrate_schema(self) -> None:
        with self.engine.begin() as connection:
            task_columns = {
                row[1] for row in connection.exec_driver_sql("PRAGMA table_info(tasks)")
            }
            if "workflow" not in task_columns:
                connection.exec_driver_sql(
                    "ALTER TABLE tasks ADD COLUMN workflow TEXT NOT NULL DEFAULT 'fix'"
                )
                connection.exec_driver_sql(
                    "UPDATE tasks SET workflow = 'feature' WHERE kind = 'feature'"
                )
            item_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(signal_items)")
            }
            if item_columns and (
                "evidence_id" in item_columns
                or "location_json" not in item_columns
                or "links_json" not in item_columns
            ):
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_items")
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_messages")
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_fetch_runs")
                Base.metadata.create_all(connection)
            fetch_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(signal_fetch_runs)")
            }
            if fetch_columns and (
                "message_count" in fetch_columns
                or "item_count" not in fetch_columns
                or "has_more" not in fetch_columns
            ):
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_fetch_runs")
                Base.metadata.create_all(connection)
            connection.exec_driver_sql("DROP TABLE IF EXISTS signal_messages")
            validation_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(validations)")
            }
            if "iteration" not in validation_columns:
                connection.exec_driver_sql(
                    "ALTER TABLE validations ADD COLUMN iteration INTEGER"
                )
            iteration_columns = {
                row[1]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(task_iterations)"
                )
            }
            for column in (
                "worker_model",
                "worker_reasoning_effort",
                "reviewer_model",
                "reviewer_reasoning_effort",
            ):
                if column not in iteration_columns:
                    connection.exec_driver_sql(
                        f"ALTER TABLE task_iterations ADD COLUMN {column} TEXT"
                    )
            plan_columns = {
                row[1]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(task_plan_runs)"
                )
            }
            if not plan_columns:
                TaskPlanRunRow.__table__.create(connection, checkfirst=True)
            wakeup_columns = {
                row[1]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(scheduler_wakeups)"
                )
            }
            if not wakeup_columns:
                Base.metadata.create_all(connection)
            # This table is additive and independent of task, pipeline, run,
            # and sanitized public-mirror health state.
            TaskArchiveSyncHealthRow.__table__.create(connection, checkfirst=True)
            _install_ledger_ownership_triggers(connection)

    def _migrate_portable_paths(self) -> None:
        task_columns = (
            "worktree_path",
            "transcript_path",
            "last_message_path",
            "patch_path",
        )
        iteration_columns = (
            "worker_prompt_path",
            "worker_transcript_path",
            "worker_last_message_path",
            "reviewer_prompt_path",
            "reviewer_transcript_path",
            "reviewer_last_message_path",
            "patch_path",
        )
        plan_columns = (
            "prompt_path",
            "transcript_path",
            "last_message_path",
            "plan_path",
        )
        with Session(self.engine) as session, session.begin():
            for row in session.scalars(select(TaskRow)).all():
                for column in task_columns:
                    setattr(row, column, self._portable_path(getattr(row, column)))
                row.metadata_json = self._portable_json(row.metadata_json)
            for row in session.scalars(select(TaskIterationRow)).all():
                for column in iteration_columns:
                    setattr(row, column, self._portable_path(getattr(row, column)))
            for row in session.scalars(select(TaskPlanRunRow)).all():
                for column in plan_columns:
                    setattr(row, column, self._portable_path(getattr(row, column)))
            for row in session.scalars(select(ValidationRow)).all():
                row.output_path = self._portable_path(row.output_path) or row.output_path
                row.cwd = self._portable_path(row.cwd) or row.cwd
            for row in session.scalars(select(EventRow)).all():
                row.message = self._portable_path(row.message) or row.message
                row.data_json = self._portable_json(row.data_json)
            for row in session.scalars(select(SignalItemRow)).all():
                row.payload_json = self._portable_json(row.payload_json)
                if row.location_json:
                    row.location_json = self._portable_json(row.location_json)
            for row in session.scalars(select(SchedulerWakeupRow)).all():
                row.data_json = self._portable_json(row.data_json)

    def _portable_path(self, value: str | None) -> str | None:
        if self.path_codec.is_portable(value):
            return value
        return self.path_codec.dump(Path(value))

    def _portable_json(self, value: str) -> str:
        try:
            loaded = json.loads(value or "{}")
        except json.JSONDecodeError:
            return value
        if not isinstance(loaded, dict):
            return value
        return json.dumps(self.path_codec.dump_json(loaded), sort_keys=True)


def _install_ledger_ownership_triggers(connection: Connection) -> None:
    execution_checks = """
        SELECT RAISE(ABORT, 'execution pipeline ownership mismatch')
        WHERE NEW.owning_pipeline_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM task_pipelines AS pipeline
            WHERE pipeline.id = NEW.owning_pipeline_id
              AND pipeline.task_id = NEW.task_id
              AND pipeline.execution_id = NEW.id
        );
        SELECT RAISE(ABORT, 'execution session ownership mismatch')
        WHERE NEW.active_session_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM codex_sessions AS codex_session
            WHERE codex_session.id = NEW.active_session_id
              AND codex_session.task_id = NEW.task_id
              AND codex_session.pipeline_id = NEW.owning_pipeline_id
        );
        SELECT RAISE(ABORT, 'execution run ownership mismatch')
        WHERE NEW.active_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM task_runs AS run
            WHERE run.id = NEW.active_run_id
              AND run.task_id = NEW.task_id
              AND run.pipeline_id = NEW.owning_pipeline_id
              AND run.session_id = NEW.active_session_id
        );
    """
    checkpoint_checks = """
        SELECT RAISE(ABORT, 'checkpoint execution ownership mismatch')
        WHERE NOT EXISTS (
            SELECT 1 FROM task_executions AS execution
            WHERE execution.id = NEW.execution_id
              AND execution.task_id = NEW.task_id
        );
        SELECT RAISE(ABORT, 'checkpoint pipeline ownership mismatch')
        WHERE NOT EXISTS (
            SELECT 1 FROM task_pipelines AS pipeline
            WHERE pipeline.id = NEW.owning_pipeline_id
              AND pipeline.task_id = NEW.task_id
              AND pipeline.execution_id = NEW.execution_id
        );
        SELECT RAISE(ABORT, 'checkpoint session ownership mismatch')
        WHERE NEW.active_session_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM codex_sessions AS codex_session
            WHERE codex_session.id = NEW.active_session_id
              AND codex_session.task_id = NEW.task_id
              AND codex_session.pipeline_id = NEW.owning_pipeline_id
        );
        SELECT RAISE(ABORT, 'checkpoint run ownership mismatch')
        WHERE NEW.active_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM task_runs AS run
            WHERE run.id = NEW.active_run_id
              AND run.task_id = NEW.task_id
              AND run.pipeline_id = NEW.owning_pipeline_id
              AND run.session_id = NEW.active_session_id
        );
    """
    pipeline_reverse_checks = """
        SELECT RAISE(ABORT, 'execution pipeline ownership mismatch')
        WHERE EXISTS (
            SELECT 1 FROM task_executions AS execution
            WHERE execution.owning_pipeline_id = OLD.id
              AND (
                  execution.owning_pipeline_id != NEW.id
                  OR execution.task_id != NEW.task_id
                  OR execution.id != NEW.execution_id
              )
        );
        SELECT RAISE(ABORT, 'checkpoint pipeline ownership mismatch')
        WHERE EXISTS (
            SELECT 1 FROM task_worktree_checkpoints AS checkpoint
            WHERE checkpoint.owning_pipeline_id = OLD.id
              AND (
                  checkpoint.owning_pipeline_id != NEW.id
                  OR checkpoint.task_id != NEW.task_id
                  OR checkpoint.execution_id != NEW.execution_id
              )
        );
    """
    for action in ("INSERT", "UPDATE"):
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER IF NOT EXISTS validate_task_execution_ownership_{action.lower()}
            BEFORE {action} ON task_executions
            BEGIN
                {execution_checks}
            END
            """
        )
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER IF NOT EXISTS validate_worktree_checkpoint_ownership_{action.lower()}
            BEFORE {action} ON task_worktree_checkpoints
            BEGIN
                {checkpoint_checks}
            END
            """
        )
    connection.exec_driver_sql(
        f"""
        CREATE TRIGGER IF NOT EXISTS validate_task_pipeline_reverse_ownership_update
        BEFORE UPDATE OF id, task_id, execution_id ON task_pipelines
        BEGIN
            {pipeline_reverse_checks}
        END
        """
    )


def _row_values(row: object) -> dict[str, object]:
    table = getattr(row, "__table__")
    return {column.name: getattr(row, column.name) for column in table.columns}


def _execution_fields(fields: dict[str, object]) -> dict[str, object]:
    accepted = {
        key: fields[key]
        for key in (
            "state",
            "current_phase",
            "owning_pipeline_id",
            "active_session_id",
            "active_run_id",
            "base_commit",
            "expected_tree",
            "worktree_path",
            "image_version",
            "runtime_version",
            "archive_generation",
        )
        if key in fields
    }
    aliases = {
        "phase": "current_phase",
        "owning_pipeline": "owning_pipeline_id",
        "pipeline_id": "owning_pipeline_id",
        "session_id": "active_session_id",
        "run_id": "active_run_id",
        "base": "base_commit",
        "tree": "expected_tree",
    }
    for source, target in aliases.items():
        if source in fields and target not in accepted:
            accepted[target] = fields[source]
    return accepted


def _pipeline_fields(fields: dict[str, object]) -> dict[str, object]:
    accepted = {
        key: fields[key]
        for key in (
            "phase",
            "state",
            "base_identity",
            "input_identity",
            "output_identity",
            "patch_identity",
            "metadata",
            "completed_at",
            "archive_generation",
        )
        if key in fields
    }
    aliases = {
        "base": "base_identity",
        "input": "input_identity",
        "output": "output_identity",
        "patch": "patch_identity",
    }
    for source, target in aliases.items():
        if source in fields and target not in accepted:
            accepted[target] = fields[source]
    return accepted


def _run_fields(fields: dict[str, object]) -> dict[str, object]:
    accepted = {
        key: fields[key]
        for key in (
            "state",
            "model",
            "reasoning",
            "image_version",
            "runtime_version",
            "checkpoint_id",
            "provider_run_id",
            "exit_code",
            "exit_signal",
            "exit_reason",
            "result_summary",
            "completed_at",
            "archive_generation",
        )
        if key in fields
    }
    aliases = {
        "provider_id": "provider_run_id",
        "provider_run": "provider_run_id",
        "reasoning_effort": "reasoning",
        "summary": "result_summary",
    }
    for source, target in aliases.items():
        if source in fields and target not in accepted:
            accepted[target] = fields[source]
    return accepted


def _task_query() -> Select[tuple[TaskRow]]:
    return select(TaskRow).options(selectinload(TaskRow.validations))


def _count_tasks(
    session: Session, *, statuses: list[str], integration: bool
) -> int:
    statement = select(func.count()).select_from(TaskRow).where(TaskRow.status.in_(statuses))
    if integration:
        statement = statement.where(TaskRow.worker == WorkerKind.integration_manager.value)
    else:
        statement = statement.where(TaskRow.worker != WorkerKind.integration_manager.value)
    return session.scalar(statement) or 0


def _signal_row_suppressed(
    session: Session, row: SignalItemRow, *, suppression_hours: int
) -> bool:
    if row.status == SignalItemStatus.pending.value:
        return True
    if row.status != SignalItemStatus.planned.value:
        return False
    if row.planned_task_id:
        task = session.get(TaskRow, row.planned_task_id)
        if task is not None:
            if task.status in {status.value for status in ACTIVE_STATUSES}:
                return True
            if task.status in {
                TaskStatus.no_changes.value,
                TaskStatus.pushed.value,
                TaskStatus.succeeded.value,
            }:
                return True
    cutoff = utc_now() - timedelta(hours=suppression_hours)
    planned_at = row.planned_at or row.updated_at
    return datetime.fromisoformat(planned_at) >= cutoff


def _matching_signal_row(session: Session, item: SignalItem) -> SignalItemRow | None:
    exact = session.scalar(
        select(SignalItemRow)
        .where(
            SignalItemRow.provider == item.provider,
            SignalItemRow.fingerprint == item.fingerprint,
        )
        .order_by(SignalItemRow.updated_at.desc())
        .limit(1)
    )
    if exact is not None:
        return exact
    if not item.provider.startswith("github-actions:"):
        return None
    run_id = str(item.payload.get("run_id") or "")
    if not run_id:
        return None
    run_attempt = _workflow_run_attempt(item.payload)
    rows = session.scalars(
        select(SignalItemRow)
        .where(SignalItemRow.provider == item.provider)
        .order_by(SignalItemRow.updated_at.desc())
    ).all()
    for row in rows:
        try:
            payload = json.loads(row.payload_json or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("run_id") or "") != run_id:
            continue
        if _workflow_run_attempt(payload) == run_attempt:
            return row
    return None


def _workflow_run_attempt(payload: dict[str, object]) -> int:
    value = payload.get("run_attempt")
    return value if isinstance(value, int) and value > 0 else 1


def _signal_duplicate_blocks_requeue(
    row: SignalItemRow, task: TaskRow | None, *, cutoff: datetime
) -> bool:
    if row.status == SignalItemStatus.pending.value:
        return True
    if row.status != SignalItemStatus.planned.value:
        return False
    if task is not None and task.status in {
        status.value for status in ACTIVE_STATUSES
    }:
        return True
    retry_from = datetime.fromisoformat(row.planned_at or row.updated_at)
    if task is not None:
        retry_from = max(retry_from, datetime.fromisoformat(task.updated_at))
    return retry_from > cutoff


def _has_active_integration_for_source(session: Session, source_task_id: str) -> bool:
    active_statuses = {status.value for status in ACTIVE_STATUSES}
    rows = session.scalars(
        select(TaskRow).where(
            TaskRow.worker == WorkerKind.integration_manager.value,
            TaskRow.status.in_(active_statuses),
        )
    ).all()
    for row in rows:
        try:
            metadata = json.loads(row.metadata_json or "{}")
        except json.JSONDecodeError:
            continue
        if metadata.get("source_task_id") == source_task_id:
            return True
    return False


def _transition_for_status(status: TaskStatus, summary: str) -> TaskTransition:
    if status == TaskStatus.running:
        return worker_started(summary)
    if status == TaskStatus.reviewing:
        return review_started(summary)
    if status == TaskStatus.integrating:
        return integration_started(summary)
    if status.terminal:
        return terminal_status(status, summary)
    return TaskTransition(status, summary, TaskPhase.dispatch)


def _effective_stale_status(row: TaskRow, events: list[EventRow]) -> str:
    latest_worker_start = _latest_event_id(events, WORKER_REVISION_STARTED_EVENTS)
    latest_worker_finish = _latest_event_id(events, WORKER_REVISION_FINISHED_EVENTS)
    if latest_worker_start is not None and (
        latest_worker_finish is None or latest_worker_start > latest_worker_finish
    ):
        return TaskStatus.running.value

    latest_review_start = _latest_review_start_id(events)
    latest_review_finish = _latest_event_id(
        events, REVIEW_FINISHED_EVENTS | WORKER_REVISION_STARTED_EVENTS
    )
    if latest_review_start is not None and (
        latest_review_finish is None or latest_review_start > latest_review_finish
    ):
        return TaskStatus.reviewing.value

    latest_phase = _latest_status_phase(events)
    if latest_phase in {
        TaskPhase.implementation_plan.value,
        TaskPhase.validation.value,
    }:
        return latest_phase

    return row.status


def _effective_stale_since(row: TaskRow, events: list[EventRow]) -> datetime:
    if _latest_status_phase(events) == TaskPhase.validation.value:
        event = _latest_validation_progress_event(events)
        if event is not None:
            return datetime.fromisoformat(event.created_at)
    return datetime.fromisoformat(row.updated_at)


def _latest_event_id(events: list[EventRow], kinds: set[str]) -> int | None:
    matching = [event.id for event in events if event.kind in kinds]
    return max(matching) if matching else None


def _latest_status_event(events: list[EventRow]) -> EventRow | None:
    matching = [event for event in events if event.kind == "task.status"]
    if not matching:
        return None
    return max(matching, key=lambda event: event.id)


def _latest_status_phase(events: list[EventRow]) -> str | None:
    event = _latest_status_event(events)
    if event is None:
        return None
    try:
        data = json.loads(event.data_json)
    except json.JSONDecodeError:
        return None
    phase = data.get("phase")
    return phase if isinstance(phase, str) else None


def _latest_validation_progress_event(events: list[EventRow]) -> EventRow | None:
    matching = [
        event
        for event in events
        if event.kind in {"validation.command_started", "validation.command_finished"}
        or (
            event.kind == "task.status"
            and event.message == TaskStatus.running.value
            and _event_phase(event) == TaskPhase.validation.value
        )
    ]
    if not matching:
        return None
    return max(matching, key=lambda event: event.id)


def _event_phase(event: EventRow) -> str | None:
    try:
        data = json.loads(event.data_json)
    except json.JSONDecodeError:
        return None
    phase = data.get("phase")
    return phase if isinstance(phase, str) else None


def _latest_review_start_id(events: list[EventRow]) -> int | None:
    matching = [
        event.id
        for event in events
        if event.kind == "task.status" and event.message == TaskStatus.reviewing.value
    ]
    return max(matching) if matching else None


def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


ACTIVE_STATUS_VALUES = ("queued", "running", "reviewing", "integrating")


class Base(DeclarativeBase):
    pass


class TaskRow(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    workflow: Mapped[str] = mapped_column(String, nullable=False, default="fix")
    worker: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String, nullable=False)
    risk: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    allow_main_write: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    dedupe_key: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    worktree_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    branch_name: Mapped[str | None] = mapped_column(String, nullable=True)
    transcript_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_message_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    validations: Mapped[list[ValidationRow]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        order_by="ValidationRow.position",
    )
    iterations: Mapped[list[TaskIterationRow]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        order_by="TaskIterationRow.iteration",
    )
    plan_runs: Mapped[list[TaskPlanRunRow]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        order_by="TaskPlanRunRow.run",
    )


class TaskPlanRunRow(Base):
    __tablename__ = "task_plan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run: Mapped[int] = mapped_column(Integer, nullable=False)
    prompt_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    transcript_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_message_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    plan_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    reasoning_effort: Mapped[str | None] = mapped_column(String, nullable=True)
    plan_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    task: Mapped[TaskRow] = relationship(back_populates="plan_runs")


class TaskIterationRow(Base):
    __tablename__ = "task_iterations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False)
    worker_name: Mapped[str | None] = mapped_column(String, nullable=True)
    worker_prompt_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_transcript_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_last_message_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    worker_completed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    worker_model: Mapped[str | None] = mapped_column(String, nullable=True)
    worker_reasoning_effort: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewer_name: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewer_prompt_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_transcript_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_last_message_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reviewer_completed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reviewer_model: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewer_reasoning_effort: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewer_run: Mapped[int | None] = mapped_column(Integer, nullable=True)
    review_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    task: Mapped[TaskRow] = relationship(back_populates="iterations")


class ValidationRow(Base):
    __tablename__ = "validations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    iteration: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    command_json: Mapped[str] = mapped_column(Text, nullable=False)
    cwd: Mapped[str] = mapped_column(Text, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    exit_code: Mapped[int] = mapped_column(Integer, nullable=False)
    output_path: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str] = mapped_column(String, nullable=False)

    task: Mapped[TaskRow] = relationship(back_populates="validations")


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String, nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class SignalItemRow(Base):
    __tablename__ = "signal_items"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String, nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    location_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    links_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    planned_at: Mapped[str | None] = mapped_column(String, nullable=True)
    planner_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    planned_task_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source_fetch_id: Mapped[str | None] = mapped_column(String, nullable=True)


class SignalFetchRunRow(Base):
    __tablename__ = "signal_fetch_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    started_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    completed_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_more: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")


class SchedulerWakeupRow(Base):
    __tablename__ = "scheduler_wakeups"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    reason: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    consumed_at: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class TaskArchiveSyncHealthRow(Base):
    """Single operational row for the standalone raw archive synchronizer."""

    __tablename__ = "task_archive_sync_health"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active_cycle_id: Mapped[str | None] = mapped_column(String, nullable=True)
    last_started_at: Mapped[str | None] = mapped_column(String, nullable=True)
    last_finished_at: Mapped[str | None] = mapped_column(String, nullable=True)
    last_success_at: Mapped[str | None] = mapped_column(String, nullable=True)
    last_duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
    last_exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_category: Mapped[str | None] = mapped_column(String, nullable=True)
    last_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failure_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )


class TaskExecutionRow(Base):
    """Normalized private execution ownership and phase cursor."""

    __tablename__ = "task_executions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    state: Mapped[str] = mapped_column(String, nullable=False, default="active")
    current_phase: Mapped[str] = mapped_column(String, nullable=False, default="planning")
    owning_pipeline_id: Mapped[str | None] = mapped_column(String, nullable=True)
    active_session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    active_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String, nullable=True)
    expected_tree: Mapped[str | None] = mapped_column(String, nullable=True)
    worktree_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_version: Mapped[str | None] = mapped_column(String, nullable=True)
    runtime_version: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    archive_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("task_id", name="uq_task_executions_task"),
        UniqueConstraint("id", "task_id", name="uq_task_executions_id_task"),
        UniqueConstraint(
            "task_id",
            "idempotency_key",
            name="uq_task_executions_task_idempotency",
        ),
        CheckConstraint(
            "state IN ('active', 'interrupted', 'complete')",
            name="ck_task_executions_state",
        ),
    )


class TaskPipelineRow(Base):
    __tablename__ = "task_pipelines"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    trigger: Mapped[str] = mapped_column(String, nullable=False)
    parent_pipeline_id: Mapped[str | None] = mapped_column(String, nullable=True)
    phase: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="active")
    base_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    input_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    output_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    patch_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    archive_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("task_id", "ordinal", name="uq_task_pipelines_task_ordinal"),
        UniqueConstraint("id", "task_id", name="uq_task_pipelines_id_task"),
        UniqueConstraint(
            "id",
            "task_id",
            "execution_id",
            name="uq_task_pipelines_id_task_execution",
        ),
        ForeignKeyConstraint(
            ("execution_id", "task_id"),
            ("task_executions.id", "task_executions.task_id"),
            ondelete="CASCADE",
            name="fk_task_pipelines_execution_task",
        ),
        ForeignKeyConstraint(
            ("parent_pipeline_id", "task_id", "execution_id"),
            (
                "task_pipelines.id",
                "task_pipelines.task_id",
                "task_pipelines.execution_id",
            ),
            ondelete="RESTRICT",
            name="fk_task_pipelines_parent_task_execution",
        ),
        CheckConstraint("ordinal > 0", name="ck_task_pipelines_ordinal"),
        CheckConstraint(
            "trigger IN ('initial', 'validation-repair', 'review-repair', 'integration-rebase', 'integration-conflict', 'push-race')",
            name="ck_task_pipelines_trigger",
        ),
        CheckConstraint(
            "phase IN ('planning', 'implementation', 'validation', 'review', 'integration', 'complete')",
            name="ck_task_pipelines_phase",
        ),
        CheckConstraint(
            "state IN ('active', 'succeeded', 'failed', 'blocked', 'cancelled', 'interrupted', 'superseded')",
            name="ck_task_pipelines_state",
        ),
    )


class CodexSessionRow(Base):
    __tablename__ = "codex_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pipeline_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="active")
    provider_session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    private_home_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    archive_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    closed_at: Mapped[str | None] = mapped_column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "id", "task_id", "pipeline_id", name="uq_codex_sessions_id_task_pipeline"
        ),
        UniqueConstraint(
            "task_id",
            "idempotency_key",
            name="uq_codex_sessions_task_idempotency",
        ),
        ForeignKeyConstraint(
            ("pipeline_id", "task_id"),
            ("task_pipelines.id", "task_pipelines.task_id"),
            ondelete="CASCADE",
            name="fk_codex_sessions_pipeline_task",
        ),
        CheckConstraint(
            "state IN ('active', 'closed', 'interrupted')",
            name="ck_codex_sessions_state",
        ),
    )


class TaskRunRow(Base):
    __tablename__ = "task_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pipeline_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    role: Mapped[str] = mapped_column(String, nullable=False)
    role_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False, default="running")
    resume_of_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    retry_of_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(String, nullable=True)
    image_version: Mapped[str | None] = mapped_column(String, nullable=True)
    runtime_version: Mapped[str | None] = mapped_column(String, nullable=True)
    checkpoint_id: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_run_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exit_signal: Mapped[str | None] = mapped_column(String, nullable=True)
    exit_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    archive_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("pipeline_id", "role", "role_ordinal", name="uq_task_runs_role_ordinal"),
        UniqueConstraint("id", "task_id", "pipeline_id", name="uq_task_runs_id_task_pipeline"),
        UniqueConstraint("resume_of_run_id", name="uq_task_runs_single_recovery"),
        UniqueConstraint(
            "task_id", "idempotency_key", name="uq_task_runs_task_idempotency"
        ),
        ForeignKeyConstraint(
            ("pipeline_id", "task_id"),
            ("task_pipelines.id", "task_pipelines.task_id"),
            ondelete="CASCADE",
            name="fk_task_runs_pipeline_task",
        ),
        ForeignKeyConstraint(
            ("session_id", "task_id", "pipeline_id"),
            (
                "codex_sessions.id",
                "codex_sessions.task_id",
                "codex_sessions.pipeline_id",
            ),
            ondelete="RESTRICT",
            name="fk_task_runs_session_task_pipeline",
        ),
        ForeignKeyConstraint(
            ("resume_of_run_id", "task_id", "pipeline_id"),
            ("task_runs.id", "task_runs.task_id", "task_runs.pipeline_id"),
            ondelete="RESTRICT",
            name="fk_task_runs_resume_task_pipeline",
        ),
        ForeignKeyConstraint(
            ("parent_run_id", "task_id", "pipeline_id"),
            ("task_runs.id", "task_runs.task_id", "task_runs.pipeline_id"),
            ondelete="RESTRICT",
            name="fk_task_runs_parent_task_pipeline",
        ),
        ForeignKeyConstraint(
            ("retry_of_run_id", "task_id", "pipeline_id"),
            ("task_runs.id", "task_runs.task_id", "task_runs.pipeline_id"),
            ondelete="RESTRICT",
            name="fk_task_runs_retry_task_pipeline",
        ),
        CheckConstraint("role_ordinal > 0", name="ck_task_runs_role_ordinal"),
        CheckConstraint(
            "state IN ('running', 'succeeded', 'failed', 'interrupted', 'cancelled')",
            name="ck_task_runs_state",
        ),
        CheckConstraint(
            "(state = 'running' AND completed_at IS NULL) OR (state != 'running' AND completed_at IS NOT NULL)",
            name="ck_task_runs_completed",
        ),
    )


class TaskWorktreeCheckpointRow(Base):
    __tablename__ = "task_worktree_checkpoints"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("task_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    base_commit: Mapped[str] = mapped_column(String, nullable=False)
    expected_tree: Mapped[str] = mapped_column(String, nullable=False)
    phase: Mapped[str] = mapped_column(String, nullable=False)
    owning_pipeline_id: Mapped[str] = mapped_column(String, nullable=False)
    active_session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    active_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    worktree_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_version: Mapped[str | None] = mapped_column(String, nullable=True)
    runtime_version: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("execution_id", name="uq_task_worktree_checkpoints_execution"),
        CheckConstraint(
            "phase IN ('planning', 'implementation', 'validation', 'review', 'integration', 'complete')",
            name="ck_task_worktree_checkpoints_phase",
        ),
    )


Index(
    "ix_tasks_active_dedupe_key",
    TaskRow.dedupe_key,
    unique=True,
    sqlite_where=TaskRow.status.in_(ACTIVE_STATUS_VALUES),
)

Index(
    "ix_validations_task_position",
    ValidationRow.task_id,
    ValidationRow.position,
    unique=True,
)

Index(
    "ix_task_iterations_task_iteration",
    TaskIterationRow.task_id,
    TaskIterationRow.iteration,
    unique=True,
)

Index(
    "ix_task_plan_runs_task_run",
    TaskPlanRunRow.task_id,
    TaskPlanRunRow.run,
    unique=True,
)

Index(
    "ix_signal_items_provider_fingerprint_status",
    SignalItemRow.provider,
    SignalItemRow.fingerprint,
    unique=True,
    sqlite_where=SignalItemRow.status == "pending",
)

Index("ix_task_pipelines_task_ordinal", TaskPipelineRow.task_id, TaskPipelineRow.ordinal)
Index("ix_task_runs_task_started", TaskRunRow.task_id, TaskRunRow.started_at)

# Readable aliases for callers that inspect the normalized SQL schema directly.
TaskExecution = TaskExecutionRow
TaskPipeline = TaskPipelineRow
CodexSession = CodexSessionRow
TaskRun = TaskRunRow
WorktreeCheckpoint = TaskWorktreeCheckpointRow
TaskArchiveSyncHealth = TaskArchiveSyncHealthRow

from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


ACTIVE_STATUS_VALUES = ("queued", "running", "reviewing", "integrating")


class Base(DeclarativeBase):
    pass


class TaskRow(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)
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
    reviewer_name: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewer_prompt_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_transcript_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_last_message_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reviewer_completed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
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
    "ix_signal_items_provider_fingerprint_status",
    SignalItemRow.provider,
    SignalItemRow.fingerprint,
    unique=True,
    sqlite_where=SignalItemRow.status == "pending",
)

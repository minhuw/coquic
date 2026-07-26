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


# The scheduler control-loop ledger is additive to the task ledger.  These
# normalized rows intentionally keep provider/session internals in private
# JSON columns owned by Steward; the archive writer selects only normalized
# control-loop payloads for publication.
class ControlLoopMetaRow(Base):
    __tablename__ = "control_loop_meta"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class ControlLoopFetchRow(Base):
    __tablename__ = "control_loop_fetches"

    fetch_id: Mapped[str] = mapped_column(String, primary_key=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str] = mapped_column(String, nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_more: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    normalized_json: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("status IN ('ok','error')", name="ck_control_loop_fetch_status"),
        CheckConstraint("item_count >= 0", name="ck_control_loop_fetch_item_count"),
        CheckConstraint("new_item_count >= 0", name="ck_control_loop_fetch_new_item_count"),
    )


class ControlLoopSignalRow(Base):
    __tablename__ = "control_loop_signals"

    signal_id: Mapped[str] = mapped_column(String, primary_key=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    normalized_json: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint("epoch_id", "provider", "fingerprint", name="uq_control_loop_signal_dedupe"),
        CheckConstraint("status IN ('pending','planned','superseded','errored')", name="ck_control_loop_signal_status"),
    )


class ControlLoopObservationRow(Base):
    __tablename__ = "control_loop_observations"

    observation_id: Mapped[str] = mapped_column(String, primary_key=True)
    fetch_id: Mapped[str] = mapped_column(ForeignKey("control_loop_fetches.fetch_id"), nullable=False, index=True)
    signal_id: Mapped[str] = mapped_column(ForeignKey("control_loop_signals.signal_id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    dedupe_result: Mapped[str] = mapped_column(String, nullable=False)
    observed_at: Mapped[str] = mapped_column(String, nullable=False)
    normalized_json: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("dedupe_result IN ('new','existing')", name="ck_control_loop_observation_dedupe"),
    )


class ControlLoopWakeupRow(Base):
    __tablename__ = "control_loop_wakeups"

    wakeup_id: Mapped[str] = mapped_column(String, primary_key=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    consumed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    input_signal_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    __table_args__ = (
        CheckConstraint("status IN ('pending','consumed')", name="ck_control_loop_wakeup_status"),
    )


class ControlLoopCycleRow(Base):
    __tablename__ = "control_loop_cycles"

    cycle_id: Mapped[str] = mapped_column(String, primary_key=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    runtime_state: Mapped[str] = mapped_column(String, nullable=False)
    input_signal_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")


class ControlLoopPlannerRunRow(Base):
    __tablename__ = "control_loop_planner_runs"

    planner_run_id: Mapped[str] = mapped_column(String, primary_key=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    state: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    input_signal_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    active_task_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    prompt_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    diagnostics_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    retry_eligible_at: Mapped[str | None] = mapped_column(String, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        CheckConstraint("state IN ('claimed','running','succeeded','failed','interrupted','cancelled')", name="ck_control_loop_planner_state"),
        CheckConstraint("attempt >= 1", name="ck_control_loop_planner_attempt"),
    )


class ControlLoopProposalRow(Base):
    __tablename__ = "control_loop_proposals"

    proposal_id: Mapped[str] = mapped_column(String, primary_key=True)
    planner_run_id: Mapped[str] = mapped_column(ForeignKey("control_loop_planner_runs.planner_run_id"), nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String, nullable=False)
    reason_code: Mapped[str] = mapped_column(String, nullable=False)
    signal_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    dedupe_key: Mapped[str | None] = mapped_column(String, nullable=True)
    task_id: Mapped[str | None] = mapped_column(String, nullable=True)
    proposal_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint("planner_run_id", "ordinal", name="uq_control_loop_proposal_ordinal"),
        CheckConstraint("ordinal >= 1", name="ck_control_loop_proposal_ordinal"),
        CheckConstraint("outcome IN ('accepted','invalid','policy_rejected','duplicate','capacity_skipped')", name="ck_control_loop_proposal_outcome"),
    )


class ControlLoopPlannerSignalRow(Base):
    __tablename__ = "control_loop_planner_signals"

    planner_run_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_planner_runs.planner_run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    signal_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_signals.signal_id"), primary_key=True
    )

    __table_args__ = (
        UniqueConstraint("planner_run_id", "ordinal", name="uq_control_loop_planner_signal_ordinal"),
        CheckConstraint("ordinal >= 1", name="ck_control_loop_planner_signal_ordinal"),
    )


class ControlLoopPlannerTaskRow(Base):
    __tablename__ = "control_loop_planner_tasks"

    planner_run_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_planner_runs.planner_run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)

    __table_args__ = (
        UniqueConstraint("planner_run_id", "ordinal", name="uq_control_loop_planner_task_ordinal"),
        CheckConstraint("ordinal >= 1", name="ck_control_loop_planner_task_ordinal"),
    )


class ControlLoopProposalSignalRow(Base):
    __tablename__ = "control_loop_proposal_signals"

    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_proposals.proposal_id", ondelete="CASCADE"),
        primary_key=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    signal_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_signals.signal_id"), primary_key=True
    )

    __table_args__ = (
        UniqueConstraint("proposal_id", "ordinal", name="uq_control_loop_proposal_signal_ordinal"),
        CheckConstraint("ordinal >= 1", name="ck_control_loop_proposal_signal_ordinal"),
    )


class ControlLoopProposalTaskRow(Base):
    __tablename__ = "control_loop_proposal_tasks"

    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_proposals.proposal_id", ondelete="CASCADE"),
        primary_key=True,
    )
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), nullable=False)


class ControlLoopPlannerArtifactRow(Base):
    __tablename__ = "control_loop_planner_artifacts"

    planner_run_id: Mapped[str] = mapped_column(
        ForeignKey("control_loop_planner_runs.planner_run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(String, primary_key=True)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ControlLoopEdgeRow(Base):
    __tablename__ = "control_loop_edges"

    edge_id: Mapped[str] = mapped_column(String, primary_key=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    edge_type: Mapped[str] = mapped_column(String, nullable=False)
    source_id: Mapped[str] = mapped_column(String, nullable=False)
    target_id: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("edge_type", "source_id", "target_id", name="uq_control_loop_edge"),
    )


class ControlLoopEventRow(Base):
    __tablename__ = "control_loop_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    occurred_at: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class ControlLoopOutboxRow(Base):
    __tablename__ = "control_loop_outbox"

    sequence: Mapped[int] = mapped_column(ForeignKey("control_loop_events.sequence"), primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    materialized_at: Mapped[str | None] = mapped_column(String, nullable=True)


class ControlLoopRetryRow(Base):
    __tablename__ = "control_loop_retry"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    eligible_at: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        CheckConstraint("attempt >= 0", name="ck_control_loop_retry_attempt"),
        CheckConstraint(
            "(attempt = 0 AND eligible_at IS NULL) OR (attempt > 0 AND eligible_at IS NOT NULL)",
            name="ck_control_loop_retry_eligibility",
        ),
    )


class DatasetSyncHealthRow(Base):
    """Single operational row for the standalone raw dataset synchronizer."""

    __tablename__ = "dataset_sync_health"

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


class DaemonStateRow(Base):
    """One compare-and-set row for daemon ownership and lifecycle state."""

    __tablename__ = "daemon_state"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    instance_id: Mapped[str | None] = mapped_column(String, nullable=True)
    lifecycle: Mapped[str] = mapped_column(String, nullable=False, default="starting")
    state_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class StewardImageReleaseRow(Base):
    """Private verified image pair retained for recovery and rollback."""

    __tablename__ = "steward_image_releases"

    release_id: Mapped[str] = mapped_column(String, primary_key=True)
    daemon_image_id: Mapped[str] = mapped_column(String, nullable=False)
    task_image_id: Mapped[str] = mapped_column(String, nullable=False)
    validation_image_id: Mapped[str | None] = mapped_column(String, nullable=True)
    labels_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    verified_at: Mapped[str] = mapped_column(String, nullable=False)
    selected_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    selected_previous: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class StewardContainerReferenceRow(Base):
    """Exact label/ledger reference used by cleanup and image retention."""

    __tablename__ = "steward_container_references"

    container_id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    image_id: Mapped[str] = mapped_column(String, nullable=False)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False)
    cleanup_status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class StewardValidationCleanupRow(Base):
    """Private pre-create cleanup intent for one disposable validation run."""

    __tablename__ = "steward_validation_cleanups"

    run_id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    pipeline_id: Mapped[str] = mapped_column(String, nullable=False)
    owner_instance_id: Mapped[str] = mapped_column(String, nullable=False)
    container_name: Mapped[str] = mapped_column(String, nullable=False)
    image_id: Mapped[str] = mapped_column(String, nullable=False)
    epoch_id: Mapped[str] = mapped_column(String, nullable=False)
    release_id: Mapped[str | None] = mapped_column(String, nullable=True)
    deployment_id: Mapped[str] = mapped_column(String, nullable=False)
    worktree_path: Mapped[str] = mapped_column(Text, nullable=False)
    root_path: Mapped[str] = mapped_column(Text, nullable=False)
    cleanup_ready: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cleanup_status: Mapped[str] = mapped_column(
        String, nullable=False, default="cleanup_pending"
    )
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class StewardResourcePressureRow(Base):
    """Durable, bounded resource-pressure facts (never raw Docker output)."""

    __tablename__ = "steward_resource_pressure"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    state: Mapped[str] = mapped_column(String, nullable=False, default="normal")
    home_free_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owned_docker_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cleanup_pending_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


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
    private_home_relative_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    home_uid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String, nullable=True)
    codex_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    cwd: Mapped[str | None] = mapped_column(Text, nullable=True)
    checkpoint_id: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_store_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    owner_role: Mapped[str | None] = mapped_column(String, nullable=True)
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
        CheckConstraint(
            "home_uid IS NULL OR (home_uid >= 10000 AND home_uid <= 60000)",
            name="ck_codex_sessions_home_uid",
        ),
        UniqueConstraint("home_uid", name="uq_codex_sessions_home_uid"),
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
    provider_store_identity: Mapped[str | None] = mapped_column(String, nullable=True)
    wrapper_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exec_identity: Mapped[str | None] = mapped_column(String, nullable=True)
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
DatasetSyncHealth = DatasetSyncHealthRow
DaemonState = DaemonStateRow
StewardImageRelease = StewardImageReleaseRow
StewardContainerReference = StewardContainerReferenceRow
StewardValidationCleanup = StewardValidationCleanupRow
StewardResourcePressure = StewardResourcePressureRow

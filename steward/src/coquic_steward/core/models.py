from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

_ID_TIMESTAMP_TRANSLATION = str.maketrans("", "", "-:T")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id_timestamp() -> str:
    timestamp = utc_now().astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return timestamp.isoformat(timespec="seconds").translate(_ID_TIMESTAMP_TRANSLATION)


def new_task_id() -> str:
    return f"task-{_new_id_timestamp()}-{uuid4().hex[:8]}"


def new_signal_fetch_id() -> str:
    return f"signal-fetch-{_new_id_timestamp()}-{uuid4().hex[:8]}"


def new_scheduler_wakeup_id() -> str:
    return f"wakeup-{_new_id_timestamp()}-{uuid4().hex[:8]}"


def new_signal_item_id() -> str:
    return f"wi-signal-item-{uuid4().hex[:12]}"


def new_daemon_instance_id() -> str:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return f"steward-{timestamp}-{uuid4().hex[:8]}"


class TaskKind(StrEnum):
    code_quality = "code-quality"
    feature = "feature"
    interop = "interop"
    ci = "ci"
    rfc_audit = "rfc-audit"
    health = "health"
    integration = "integration"
    custom = "custom"


class TaskWorkflow(StrEnum):
    fix = "fix"
    feature = "feature"


def default_workflow_for_kind(kind: TaskKind | str) -> TaskWorkflow:
    return (
        TaskWorkflow.feature
        if TaskKind(kind) == TaskKind.feature
        else TaskWorkflow.fix
    )


class TaskStatus(StrEnum):
    queued = "queued"
    running = "running"
    reviewing = "reviewing"
    integrating = "integrating"
    succeeded = "succeeded"
    pushed = "pushed"
    no_changes = "no_changes"
    blocked = "blocked"
    failed = "failed"
    cancelled = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in TERMINAL_STATUSES


class WorkerKind(StrEnum):
    planner = "planner"
    integration_manager = "integration-manager"
    interop_doctor = "interop-doctor"
    code_quality_janitor = "code-quality-janitor"
    ci_doctor = "ci-doctor"
    rfc_auditor = "rfc-auditor"
    feature_implementer = "feature-implementer"
    issue_implementer = "issue-implementer"
    work_item_creator = "work-item-creator"
    reviewer = "reviewer"
    custom = "custom"


class Priority(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    urgent = "urgent"


class Risk(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


class IntegrationMode(StrEnum):
    local_only = "local-only"
    push_main = "push-main"


class CodexStage(StrEnum):
    signal_planner = "signal_planner"
    implementation_plan = "implementation_plan"
    code = "code"
    review = "review"
    commit_message = "commit_message"


class ExecutionState(StrEnum):
    active = "active"
    interrupted = "interrupted"
    complete = "complete"


class PipelineTrigger(StrEnum):
    initial = "initial"
    validation_repair = "validation-repair"
    review_repair = "review-repair"
    integration_rebase = "integration-rebase"
    integration_conflict = "integration-conflict"
    push_race = "push-race"


class PipelinePhase(StrEnum):
    """Coarse phase values accepted by the Plan 002 ledger schema.

    The durable executor also records a finer cursor in its pipeline events.
    Keeping these values stable preserves compatibility with existing ledger
    rows and archive validators.
    """

    planning = "planning"
    implementation = "implementation"
    validation = "validation"
    review = "review"
    provisioned = "provisioned"
    formality = "formality"
    repair = "repair"
    integration = "integration"
    commit_message = "commit_message"
    commit = "commit"
    push = "push"
    ready_to_seal = "ready_to_seal"
    complete = "complete"


class PipelineCursorPhase(StrEnum):
    """Idempotent action cursor used by the durable task pipeline."""

    provisioned = "provisioned"
    planning = "planning"
    implementation = "implementation"
    validation = "validation"
    review = "review"
    formality = "formality"
    repair = "repair"
    integration = "integration"
    commit_message = "commit_message"
    commit = "commit"
    push = "push"
    ready_to_seal = "ready_to_seal"


class FormalityDisposition(StrEnum):
    """Disposition assigned to exactly one raw review finding."""

    required = "required"
    revert = "revert"
    follow_up = "followUp"
    followUp = "followUp"
    reject = "reject"
    escalate = "escalate"


class PipelineState(StrEnum):
    active = "active"
    succeeded = "succeeded"
    failed = "failed"
    blocked = "blocked"
    cancelled = "cancelled"
    interrupted = "interrupted"
    superseded = "superseded"


class CodexRunState(StrEnum):
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    interrupted = "interrupted"
    cancelled = "cancelled"


class SessionState(StrEnum):
    active = "active"
    closed = "closed"
    interrupted = "interrupted"


def _new_opaque_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:20]}"


def new_execution_id() -> str:
    return _new_opaque_id("execution")


def new_pipeline_id() -> str:
    return _new_opaque_id("pipeline")


def new_session_id() -> str:
    return _new_opaque_id("session")


def new_run_id() -> str:
    return _new_opaque_id("run")


def new_checkpoint_id() -> str:
    return _new_opaque_id("checkpoint")


new_task_execution_id = new_execution_id
new_task_pipeline_id = new_pipeline_id
new_codex_session_id = new_session_id
new_task_run_id = new_run_id
new_archive_session_id = new_session_id


class SignalItemStatus(StrEnum):
    pending = "pending"
    planned = "planned"
    superseded = "superseded"
    errored = "errored"


class SignalFetchStatus(StrEnum):
    ok = "ok"
    error = "error"


class SchedulerWakeupStatus(StrEnum):
    pending = "pending"
    consumed = "consumed"


class DaemonRuntimeState(StrEnum):
    starting = "starting"
    idle = "idle"
    active = "active"
    stopping = "stopping"


class DaemonLifecycleState(StrEnum):
    starting = "starting"
    reconciling = "reconciling"
    running = "running"
    stopping = "stopping"
    stopped = "stopped"


class PublicMirrorPublishState(StrEnum):
    disabled = "disabled"
    pending = "pending"
    published = "published"
    failed = "failed"


class PublicMirrorFailureCategory(StrEnum):
    ssh_preparation = "ssh_preparation"
    rsync_transfer = "rsync_transfer"
    timeout = "timeout"
    serialization = "serialization"
    permissions = "permissions"
    unknown = "unknown"


TERMINAL_STATUSES = {
    TaskStatus.succeeded,
    TaskStatus.pushed,
    TaskStatus.no_changes,
    TaskStatus.blocked,
    TaskStatus.failed,
    TaskStatus.cancelled,
}

ACTIVE_STATUSES = {
    TaskStatus.queued,
    TaskStatus.running,
    TaskStatus.reviewing,
    TaskStatus.integrating,
}


class ValidationResult(BaseModel):
    command: list[str]
    cwd: Path
    passed: bool
    exit_code: int
    output_path: Path
    summary: str = ""
    iteration: int | None = None
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)


class TaskIteration(BaseModel):
    task_id: str
    iteration: int
    label: str
    worker_name: str | None = None
    worker_prompt_path: Path | None = None
    worker_transcript_path: Path | None = None
    worker_last_message_path: Path | None = None
    worker_exit_code: int | None = None
    worker_completed: bool | None = None
    worker_model: str | None = None
    worker_reasoning_effort: str | None = None
    reviewer_name: str | None = None
    reviewer_prompt_path: Path | None = None
    reviewer_transcript_path: Path | None = None
    reviewer_last_message_path: Path | None = None
    reviewer_exit_code: int | None = None
    reviewer_completed: bool | None = None
    reviewer_model: str | None = None
    reviewer_reasoning_effort: str | None = None
    reviewer_run: int | None = None
    review_json: dict[str, Any] | None = None
    patch_path: Path | None = None
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class TaskPlanRun(BaseModel):
    task_id: str
    run: int
    prompt_path: Path | None = None
    transcript_path: Path | None = None
    last_message_path: Path | None = None
    plan_path: Path | None = None
    exit_code: int | None = None
    completed: bool | None = None
    model: str | None = None
    reasoning_effort: str | None = None
    plan_json: dict[str, Any] | None = None
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class TaskSpec(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=new_task_id)
    kind: TaskKind
    workflow: TaskWorkflow
    worker: WorkerKind
    title: str
    prompt: str
    priority: Priority = Priority.medium
    risk: Risk = Risk.medium
    source: str = "manual"
    allow_main_write: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _default_workflow(cls, value: Any) -> Any:
        if isinstance(value, dict) and value.get("workflow") is None and "kind" in value:
            return {**value, "workflow": default_workflow_for_kind(value["kind"])}
        return value


class TaskRecord(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    spec: TaskSpec
    status: TaskStatus = TaskStatus.queued
    summary: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    worktree_path: Path | None = None
    branch_name: str | None = None
    transcript_path: Path | None = None
    last_message_path: Path | None = None
    patch_path: Path | None = None
    validations: list[ValidationResult] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return self.spec.id


class WorktreeCheckpoint(BaseModel):
    """Private proof used before a recovery may adopt a disposable worktree."""

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: str = Field(default_factory=new_checkpoint_id)
    task_id: str
    execution_id: str
    base_commit: str
    expected_tree: str
    phase: PipelinePhase | str
    owning_pipeline_id: str
    active_session_id: str | None = None
    active_run_id: str | None = None
    worktree_path: Path | None = None
    image_version: str | None = None
    runtime_version: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="before")
    @classmethod
    def _aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "checkpoint_id" in value and "id" not in value:
                value["id"] = value["checkpoint_id"]
        return value

    @property
    def checkpoint_id(self) -> str:
        return self.id


class TaskExecution(BaseModel):
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: str = Field(default_factory=new_execution_id)
    task_id: str
    state: ExecutionState | str = ExecutionState.active
    current_phase: PipelinePhase | str = PipelinePhase.planning
    owning_pipeline_id: str | None = None
    active_session_id: str | None = None
    active_run_id: str | None = None
    base_commit: str | None = None
    expected_tree: str | None = None
    worktree_path: Path | None = None
    image_version: str | None = None
    runtime_version: str | None = None
    idempotency_key: str | None = None
    archive_generation: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="before")
    @classmethod
    def _aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "execution_id" in value and "id" not in value:
                value["id"] = value["execution_id"]
            if "phase" in value and "current_phase" not in value:
                value["current_phase"] = value["phase"]
        return value

    @property
    def execution_id(self) -> str:
        return self.id

    @property
    def phase(self) -> PipelinePhase | str:
        return self.current_phase


class TaskPipeline(BaseModel):
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: str = Field(default_factory=new_pipeline_id)
    task_id: str
    execution_id: str
    ordinal: int = Field(ge=1)
    trigger: PipelineTrigger | str = PipelineTrigger.initial
    parent_pipeline_id: str | None = None
    phase: PipelinePhase | str = PipelinePhase.planning
    state: PipelineState | str = PipelineState.active
    base_identity: str | None = None
    input_identity: str | None = None
    output_identity: str | None = None
    patch_identity: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    archive_generation: int = Field(default=0, ge=0)

    @model_validator(mode="before")
    @classmethod
    def _aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "pipeline_id" in value and "id" not in value:
                value["id"] = value["pipeline_id"]
        return value

    @property
    def pipeline_id(self) -> str:
        return self.id


class CodexSession(BaseModel):
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: str = Field(default_factory=new_session_id)
    task_id: str
    pipeline_id: str
    state: SessionState | str = SessionState.active
    provider_session_id: str | None = None
    private_home_path: Path | None = None
    private_home_relative_path: str | None = None
    home_uid: int | None = Field(default=None, ge=10000, le=60000)
    image_digest: str | None = None
    codex_identity: str | None = None
    cwd: Path | None = None
    checkpoint_id: str | None = None
    provider_store_identity: str | None = None
    owner_role: str | None = None
    idempotency_key: str | None = None
    archive_generation: int = Field(default=0, ge=0)
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    closed_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def _aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "session_id" in value and "id" not in value:
                value["id"] = value["session_id"]
        return value

    @property
    def session_id(self) -> str:
        return self.id

    @property
    def archive_session_id(self) -> str:
        return self.id


class TaskRun(BaseModel):
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: str = Field(default_factory=new_run_id)
    task_id: str
    pipeline_id: str
    session_id: str
    role: str
    role_ordinal: int = Field(ge=1)
    state: CodexRunState | str = CodexRunState.running
    resume_of_run_id: str | None = None
    parent_run_id: str | None = None
    retry_of_run_id: str | None = None
    model: str | None = None
    reasoning: str | None = None
    image_version: str | None = None
    runtime_version: str | None = None
    checkpoint_id: str | None = None
    provider_run_id: str | None = None
    provider_store_identity: str | None = None
    wrapper_pid: int | None = Field(default=None, ge=1)
    exec_identity: str | None = None
    exit_code: int | None = None
    exit_signal: str | None = None
    exit_reason: str | None = None
    result_summary: str | None = None
    idempotency_key: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    archive_generation: int = Field(default=0, ge=0)

    @model_validator(mode="before")
    @classmethod
    def _aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "run_id" in value and "id" not in value:
                value["id"] = value["run_id"]
        return value

    @property
    def run_id(self) -> str:
        return self.id

    @property
    def archive_session_id(self) -> str:
        return self.session_id


class Event(BaseModel):
    task_id: str
    kind: str
    message: str
    created_at: datetime = Field(default_factory=utc_now)
    data: dict[str, Any] = Field(default_factory=dict)


class SignalItem(BaseModel):
    id: str = Field(default_factory=new_signal_item_id)
    provider: str
    kind: str
    fingerprint: str
    title: str
    summary: str = ""
    severity: str | None = None
    location: dict[str, Any] | None = None
    links: list[dict[str, str]] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    status: SignalItemStatus = SignalItemStatus.pending
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    planned_at: datetime | None = None
    planner_run_id: str | None = None
    planned_task_id: str | None = None
    source_fetch_id: str | None = None


class SignalFetchRun(BaseModel):
    id: str = Field(default_factory=new_signal_fetch_id)
    provider: str
    status: SignalFetchStatus
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)
    item_count: int = 0
    new_item_count: int = 0
    has_more: bool = False
    error: str | None = None
    summary: str = ""


class SchedulerWakeup(BaseModel):
    id: str = Field(default_factory=new_scheduler_wakeup_id)
    reason: str
    status: SchedulerWakeupStatus = SchedulerWakeupStatus.pending
    created_at: datetime = Field(default_factory=utc_now)
    consumed_at: datetime | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class SchedulerProviderState(BaseModel):
    provider: str
    poll_interval_minutes: int
    error_retry_minutes: int
    idle_poll_interval_minutes: int
    suppression_hours: int
    max_items: int
    last_fetch_at: datetime | None = None
    last_status: SignalFetchStatus | None = None
    last_error: str | None = None
    next_due_at: datetime
    idle_next_due_at: datetime | None = None
    due: bool = False
    idle_due: bool = False


class SchedulerState(BaseModel):
    source_active: int = 0
    source_capacity: int = 0
    source_queued: int = 0
    integration_active: int = 0
    integration_queued: int = 0
    pending_wakeups: list[SchedulerWakeup] = Field(default_factory=list)
    recent_wakeups: list[SchedulerWakeup] = Field(default_factory=list)
    providers: list[SchedulerProviderState] = Field(default_factory=list)


class DaemonCycleResult(BaseModel):
    recovered: int = Field(default=0, ge=0)
    signal_fetches: int = Field(default=0, ge=0)
    signal_items: int = Field(default=0, ge=0)
    new_signal_items: int = Field(default=0, ge=0)
    planned: int = Field(default=0, ge=0)
    enqueued: int = Field(default=0, ge=0)
    dispatched: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)


class DaemonCycleSummary(BaseModel):
    completed_at: datetime
    reason: str = Field(max_length=64)
    result: DaemonCycleResult


class DaemonRuntime(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    instance_id: str = Field(default_factory=new_daemon_instance_id)
    started_at: datetime = Field(default_factory=utc_now)
    heartbeat_at: datetime = Field(default_factory=utc_now)
    state: DaemonRuntimeState = DaemonRuntimeState.starting
    current_cycle_started_at: datetime | None = None
    current_cycle_reason: str | None = Field(default=None, max_length=64)
    last_completed_cycle: DaemonCycleSummary | None = None
    heartbeat_interval_seconds: int = Field(default=30, ge=5, le=60)
    lifecycle: DaemonLifecycleState = DaemonLifecycleState.starting
    reconciliation_complete: bool = False
    stopping_requested_at: datetime | None = None
    forced_stop: bool = False


class ReconciliationRecord(BaseModel):
    task_id: str
    disposition: str
    detail: str = Field(default="", max_length=256)
    run_id: str | None = None
    container_id: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ShutdownStatus(BaseModel):
    state: DaemonLifecycleState = DaemonLifecycleState.stopped
    forced: bool = False
    interrupted_runs: int = 0
    stopped_containers: int = 0
    final_sync_attempted: bool = False


class PublicMirrorHealth(BaseModel):
    model_config = ConfigDict(validate_assignment=True, use_enum_values=True)

    state: PublicMirrorPublishState = PublicMirrorPublishState.disabled
    snapshot_id: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_failure_category: PublicMirrorFailureCategory | None = None
    retry_count: int = Field(default=0, ge=0, le=10)
    last_accepted_digest: str | None = None


class ProjectSignals(BaseModel):
    schema_version: int = 2
    repository: str
    enabled_signals: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    summary: str = ""
    items: list[SignalItem] = Field(default_factory=list)
    fetches: list[SignalFetchRun] = Field(default_factory=list)


class WorkerResult(BaseModel):
    completed: bool
    command: list[str]
    cwd: Path
    exit_code: int
    prompt_path: Path | None = None
    transcript_path: Path
    last_message_path: Path
    final_message: str = ""
    thread_id: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    pipeline_id: str | None = None
    stage: CodexStage = CodexStage.code
    model: str | None = None
    reasoning_effort: str | None = None
    diagnostics: dict[str, Any] = Field(default_factory=dict)

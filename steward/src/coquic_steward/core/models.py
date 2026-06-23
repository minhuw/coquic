from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

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


class TaskKind(StrEnum):
    code_quality = "code-quality"
    interop = "interop"
    ci = "ci"
    rfc_audit = "rfc-audit"
    health = "health"
    integration = "integration"
    custom = "custom"


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
    reviewer_name: str | None = None
    reviewer_prompt_path: Path | None = None
    reviewer_transcript_path: Path | None = None
    reviewer_last_message_path: Path | None = None
    reviewer_exit_code: int | None = None
    reviewer_completed: bool | None = None
    reviewer_run: int | None = None
    review_json: dict[str, Any] | None = None
    patch_path: Path | None = None
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class TaskSpec(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=new_task_id)
    kind: TaskKind
    worker: WorkerKind
    title: str
    prompt: str
    priority: Priority = Priority.medium
    risk: Risk = Risk.medium
    source: str = "manual"
    allow_main_write: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    suppression_hours: int
    max_items: int
    last_fetch_at: datetime | None = None
    last_status: SignalFetchStatus | None = None
    last_error: str | None = None
    next_due_at: datetime
    due: bool = False


class SchedulerState(BaseModel):
    source_active: int = 0
    source_capacity: int = 0
    source_queued: int = 0
    integration_active: int = 0
    integration_queued: int = 0
    pending_wakeups: list[SchedulerWakeup] = Field(default_factory=list)
    recent_wakeups: list[SchedulerWakeup] = Field(default_factory=list)
    providers: list[SchedulerProviderState] = Field(default_factory=list)


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
    diagnostics: dict[str, Any] = Field(default_factory=dict)

"""Typed records for Steward's raw scheduler control-loop archive.

The control-loop archive deliberately has its own vocabulary.  These models
are used at the private SQLite and public-by-placement boundaries; provider
objects, credentials, and private session paths are never accepted as fields.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CONTROL_LOOP_FORMAT_VERSION = "1.0"
CONTROL_LOOP_POLICY = "post-steward-2.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | str | None = None) -> str:
    selected = value or utc_now()
    if isinstance(selected, str):
        selected = datetime.fromisoformat(selected.replace("Z", "+00:00"))
    if selected.tzinfo is None:
        selected = selected.replace(tzinfo=timezone.utc)
    return selected.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:20]}"


def validate_id(value: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"invalid control-loop id: {value!r}")
    return value


def validate_relative_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
        or any(part in {"", ".", ".."} or part.startswith(".") for part in value.split("/"))
        or SAFE_RELATIVE_PATH.fullmatch(value) is None
    ):
        raise ValueError(f"unsafe control-loop relative path: {value!r}")
    return value


class ControlLoopModel(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        extra="forbid",
    )


class Epoch(ControlLoopModel):
    epoch_id: str = Field(alias="epochId")
    format_version: str = Field(default=CONTROL_LOOP_FORMAT_VERSION, alias="formatVersion")
    task_format_version: str = Field(alias="taskFormatVersion")
    policy: str = CONTROL_LOOP_POLICY
    started_at: datetime = Field(alias="startedAt")

    _id: ClassVar[Any] = field_validator("epoch_id")(validate_id)

    @field_validator("started_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("epoch timestamp must include timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _contract(self) -> "Epoch":
        if self.format_version != CONTROL_LOOP_FORMAT_VERSION:
            raise ValueError("unsupported control-loop archive format")
        if self.policy != CONTROL_LOOP_POLICY:
            raise ValueError("control-loop epoch policy must be post-steward-2.0")
        return self


class EventKind(StrEnum):
    fetch_started = "signal_fetch.started"
    fetch_finished = "signal_fetch.finished"
    observation = "signal.observation"
    signal_created = "signal.created"
    signal_transition = "signal.transition"
    wakeup = "scheduler.wakeup"
    cycle = "daemon.cycle"
    planner_started = "planner.started"
    planner_finished = "planner.finished"
    proposal = "planner.proposal"
    edge = "graph.edge"
    runtime = "daemon.runtime"


class Event(ControlLoopModel):
    event_id: str = Field(default_factory=lambda: new_id("event"), alias="eventId")
    epoch_id: str = Field(alias="epochId")
    sequence: int = Field(ge=0)
    occurred_at: datetime = Field(default_factory=utc_now, alias="occurredAt")
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)

    _ids: ClassVar[Any] = field_validator("event_id", "epoch_id")(validate_id)

    @field_validator("occurred_at")
    @classmethod
    def _event_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("event timestamp must include timezone")
        return value.astimezone(timezone.utc)


class SignalFetch(ControlLoopModel):
    fetch_id: str = Field(alias="fetchId")
    provider: str
    status: str
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    item_count: int = Field(default=0, ge=0, alias="itemCount")
    new_item_count: int = Field(default=0, ge=0, alias="newItemCount")
    has_more: bool = Field(default=False, alias="hasMore")
    error: str | None = None
    summary: str = ""

    _id: ClassVar[Any] = field_validator("fetch_id")(validate_id)


class Observation(ControlLoopModel):
    observation_id: str = Field(alias="observationId")
    fetch_id: str = Field(alias="fetchId")
    provider: str
    kind: str
    fingerprint: str
    title: str
    summary: str = ""
    severity: str | None = None
    location: dict[str, Any] | None = None
    links: list[dict[str, str]] = Field(default_factory=list)
    normalized: dict[str, Any] = Field(default_factory=dict)
    canonical_signal_id: str | None = Field(default=None, alias="canonicalSignalId")
    dedupe_result: str = Field(default="new", alias="dedupeResult")
    observed_at: datetime = Field(default_factory=utc_now, alias="observedAt")

    _ids: ClassVar[Any] = field_validator(
        "observation_id", "fetch_id", "canonical_signal_id"
    )(lambda value: None if value is None else validate_id(value))


class CanonicalSignal(ControlLoopModel):
    signal_id: str = Field(alias="signalId")
    provider: str
    fingerprint: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=utc_now, alias="createdAt")
    updated_at: datetime = Field(default_factory=utc_now, alias="updatedAt")
    transition: str | None = None

    _id: ClassVar[Any] = field_validator("signal_id")(validate_id)


class Wakeup(ControlLoopModel):
    wakeup_id: str = Field(alias="wakeupId")
    reason: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=utc_now, alias="createdAt")
    consumed_at: datetime | None = Field(default=None, alias="consumedAt")
    input_signal_ids: list[str] = Field(default_factory=list, alias="inputSignalIds")

    _id: ClassVar[Any] = field_validator("wakeup_id")(validate_id)


class Cycle(ControlLoopModel):
    cycle_id: str = Field(alias="cycleId")
    reason: str
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime | None = Field(default=None, alias="completedAt")
    runtime_state: str = Field(default="idle", alias="runtimeState")
    input_signal_ids: list[str] = Field(default_factory=list, alias="inputSignalIds")

    _id: ClassVar[Any] = field_validator("cycle_id")(validate_id)


class PlannerRun(ControlLoopModel):
    planner_run_id: str = Field(alias="plannerRunId")
    epoch_id: str = Field(alias="epochId")
    state: str = "claimed"
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime | None = Field(default=None, alias="completedAt")
    input_signal_ids: list[str] = Field(default_factory=list, alias="inputSignalIds")
    active_task_ids: list[str] = Field(default_factory=list, alias="activeTaskIds")
    prompt: dict[str, Any] | None = None
    artifacts: dict[str, "Artifact"] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    diagnostics: dict[str, Any] = Field(default_factory=dict)

    _ids: ClassVar[Any] = field_validator("planner_run_id", "epoch_id")(validate_id)

    @model_validator(mode="after")
    def _terminal(self) -> "PlannerRun":
        if self.state in {"succeeded", "failed", "interrupted", "cancelled"} and self.completed_at is None:
            raise ValueError("terminal planner run requires completedAt")
        return self


class ProposalDisposition(ControlLoopModel):
    proposal_id: str = Field(alias="proposalId")
    planner_run_id: str = Field(alias="plannerRunId")
    ordinal: int = Field(ge=1)
    outcome: str
    reason_code: str = Field(alias="reasonCode")
    signal_ids: list[str] = Field(default_factory=list, alias="signalIds")
    dedupe_key: str | None = Field(default=None, alias="dedupeKey")
    task_id: str | None = Field(default=None, alias="taskId")
    proposal: dict[str, Any] = Field(default_factory=dict)

    _ids: ClassVar[Any] = field_validator(
        "proposal_id", "planner_run_id", "task_id"
    )(lambda value: None if value is None else validate_id(value))

    @field_validator("dedupe_key")
    @classmethod
    def _bounded_dedupe_key(cls, value: str | None) -> str | None:
        # Dedupe keys are planner-owned strings, not opaque control-loop IDs.
        # They may contain spaces or provider punctuation but must remain
        # bounded before they enter SQLite or the raw archive.
        if value is not None and (len(value) > 160 or "\x00" in value):
            raise ValueError("dedupeKey must be at most 160 characters")
        return value

    @field_validator("reason_code")
    @classmethod
    def _bounded_reason_code(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
            raise ValueError("reasonCode must be a bounded snake-case code")
        return value

    @field_validator("signal_ids")
    @classmethod
    def _unique_signal_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("signalIds must be unique")
        return value

    @model_validator(mode="after")
    def _outcome(self) -> "ProposalDisposition":
        allowed = {"accepted", "invalid", "policy_rejected", "duplicate", "capacity_skipped"}
        if self.outcome not in allowed:
            raise ValueError(f"unsupported proposal outcome: {self.outcome}")
        if self.outcome == "accepted" and self.task_id is None:
            raise ValueError("accepted proposal requires taskId")
        if self.outcome == "duplicate" and self.task_id is None:
            raise ValueError("duplicate proposal requires covering taskId")
        return self


class GraphEdge(ControlLoopModel):
    edge_id: str = Field(alias="edgeId")
    edge_type: str = Field(alias="edgeType")
    source_id: str = Field(alias="sourceId")
    target_id: str = Field(alias="targetId")
    created_at: datetime = Field(default_factory=utc_now, alias="createdAt")

    _ids: ClassVar[Any] = field_validator("edge_id", "source_id", "target_id")(validate_id)


class Artifact(ControlLoopModel):
    path: str
    availability: str = "available"
    byte_size: int = Field(ge=0, alias="byteSize")
    sha256: str
    mode: str = "raw"

    _path: ClassVar[Any] = field_validator("path")(validate_relative_path)

    @field_validator("sha256")
    @classmethod
    def _hash(cls, value: str) -> str:
        if SHA256.fullmatch(value) is None:
            raise ValueError("artifact sha256 must be lowercase hexadecimal")
        return value


class Manifest(ControlLoopModel):
    manifest_version: str = Field(default="1.0", alias="manifestVersion")
    epoch_id: str = Field(alias="epochId")
    planner_run_id: str = Field(alias="plannerRunId")
    terminal_state: str = Field(alias="terminalState")
    completed_at: datetime = Field(alias="completedAt")
    files: list[Artifact] = Field(min_length=1)

    _ids: ClassVar[Any] = field_validator("epoch_id", "planner_run_id")(validate_id)

    @model_validator(mode="after")
    def _unique_files(self) -> "Manifest":
        paths = [item.path for item in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("manifest files must have unique paths")
        return self


class CurrentState(ControlLoopModel):
    epoch_id: str = Field(alias="epochId")
    generated_at: datetime = Field(default_factory=utc_now, alias="generatedAt")
    provider_state: dict[str, Any] = Field(default_factory=dict, alias="providerState")
    scheduler_state: dict[str, Any] = Field(default_factory=dict, alias="schedulerState")
    runtime_state: dict[str, Any] = Field(default_factory=dict, alias="runtimeState")
    counts: dict[str, int] = Field(default_factory=dict)
    pending_signal_ids: list[str] = Field(default_factory=list, alias="pendingSignalIds")
    active_planner_run_id: str | None = Field(default=None, alias="activePlannerRunId")
    retry: dict[str, Any] = Field(default_factory=dict)
    archive: dict[str, Any] = Field(default_factory=dict)

    _ids: ClassVar[Any] = field_validator("epoch_id", "active_planner_run_id")(
        lambda value: None if value is None else validate_id(value)
    )


def artifact_from_bytes(path: str, content: bytes, *, mode: str = "raw") -> Artifact:
    return Artifact(path=path, byteSize=len(content), sha256=sha256(content).hexdigest(), mode=mode)


__all__ = [
    "Artifact",
    "CanonicalSignal",
    "CONTROL_LOOP_FORMAT_VERSION",
    "CONTROL_LOOP_POLICY",
    "ControlLoopModel",
    "CurrentState",
    "Cycle",
    "Epoch",
    "Event",
    "EventKind",
    "GraphEdge",
    "Manifest",
    "Observation",
    "PlannerRun",
    "ProposalDisposition",
    "SAFE_ID",
    "SignalFetch",
    "Wakeup",
    "artifact_from_bytes",
    "new_id",
    "timestamp",
    "utc_now",
    "validate_id",
    "validate_relative_path",
]

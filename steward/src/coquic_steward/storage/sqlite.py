from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

from sqlalchemy import (
    Connection,
    Select,
    and_,
    case,
    create_engine,
    delete as sql_delete,
    event,
    func,
    or_,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased, selectinload

from ..core.lifecycle import (
    TaskPhase,
    TaskTransition,
    integration_started,
    implementation_plan_started,
    require_transition_allowed,
    review_started,
    terminal_status,
    validation_started,
    worker_started,
)
from ..core.models import (
    ACTIVE_STATUSES,
    CleanupStatus,
    DispatchSnapshot,
    SchedulerStoreSnapshot,
    CodexRunState,
    EffectActionKind,
    EffectDecisionKind,
    EffectEvidence,
    EffectProposal,
    EffectResult,
    EFFECT_RESULT_EVENT_KIND,
    DRY_RUN_OF_TASK_ID_METADATA_ALIAS,
    DRY_RUN_OF_TASK_ID_METADATA_KEY,
    LiveRerunAllocation,
    EFFECT_RESULT_METADATA_KEY,
    LEGACY_EFFECT_RESULT_METADATA_KEY,
    derive_effect_result,
    CodexSession,
    Event,
    ExecutionState,
    ExecutionMode,
    EXECUTION_MODE_METADATA_KEY,
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
    PipelineCursorPhase,
    TaskPlanRun,
    TaskRecord,
    TaskRun,
    TaskSpec,
    TaskStatus,
    coerce_effect_result,
    coerce_execution_mode,
    execution_mode_for_dry_run,
    resolve_execution_mode,
    ValidationResult,
    WorktreeCheckpoint,
    new_execution_id,
    new_pipeline_id,
    new_run_id,
    new_task_id,
    new_session_id,
    WorkerKind,
    WorkerResult,
    new_signal_item_id,
    utc_now,
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
    effect_result_from_metadata,
    execution_mode_from_metadata,
    preserve_effect_result,
    preserve_execution_mode,
    scheduler_wakeup_to_row,
    pipeline_to_row,
    run_to_row,
    session_to_row,
    signal_fetch_run_to_row,
    signal_item_to_row,
    SignalWorkflowIdentity,
    signal_workflow_identity,
    task_to_row,
    update_iteration_row,
    update_plan_run_row,
    update_task_row,
    validation_to_row,
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
    DaemonStateRow,
    ValidationRow,
    StewardImageReleaseRow,
)
from ..control_loop import (
    ControlLoopLedger,
    ProposalDisposition as ControlProposalDisposition,
    Wakeup as ControlWakeup,
)
from ..publication.outbox import (
    CleanupIntent,
    CleanupState,
    GenerationIdentity,
    MAX_LEASE_SECONDS,
    MAX_RETRY_DELAY_SECONDS,
    PublicationRetryPolicy,
    OutboxValidationError,
    PublicationCounts,
    PublicationGeneration,
    PublicationHealth,
    PublicationHideFence,
    PublicationHideState,
    PublicationOperationResult,
    PublicationOperationStatus,
    PublicationReceipt,
    PublicationState,
    ReceiptClass,
    _PERSISTED_REASON_VALUES,
    allowed_transition,
    transition_state,
)

PRIORITY_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3}

# These values are execution artifacts or effect authority, not canonical task
# specification.  A live rerun receives a new identity and starts with a
# clean local execution envelope.
_LIVE_RERUN_METADATA_DROP_KEYS = frozenset(
    {
        "dedupe_key",
        "execution_mode",
        "effect_result",
        "external_effect_result",
        "effect_proposal",
        "effect_proposals",
        "proposal",
        "proposals",
        "source_context",
        "selected_signal_items",
        "selected_signal_item_ids",
        "dryRunOfTaskId",
        "source_task_id",
        "provider_payload",
        "provider_result",
        "provider_response",
        "provider_data",
        "signal_payload",
        "selected_signal_payload",
        "source_payload",
        "payload",
        "worker_context",
        "old_proposal",
        "terminal_status",
        "terminal_state",
        "result",
        "validation_results",
        "validations",
        "patches",
        "runs",
        "pipelines",
        "sessions",
        "wakeup",
        "worktree",
        "worktree_path",
        "branch",
        "branch_name",
        "commit",
        "commit_sha",
        "commit_path",
        "patch",
        "patch_path",
        "transcript",
        "transcript_path",
        "last_message",
        "last_message_path",
        "archive",
        "archive_path",
        "execution",
        "execution_id",
        "terminal_effect",
        "effect_evidence",
        "effects",
    }
)

_PUBLICATION_ID_RE = re.compile(r"^pub-[0-9a-f]{64}$")
_PRIVATE_RECEIPT_KEY_RE = re.compile(
    r"^v1/originals/(?P<task>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/"
    r"(?P<run>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/sha256/(?P<digest>[0-9a-f]{64})\.jsonl$"
)
_PERSISTED_REASON_SET = frozenset(_PERSISTED_REASON_VALUES)
_PUBLICATION_HIDE_REASONS = frozenset(
    _PERSISTED_REASON_SET
    - {
        "network",
        "quota",
        "timeout",
        "lease_expired",
        "retry_exhausted",
        "cleanup_failed",
        "operator_blocked",
    }
)
_PUBLICATION_HIDE_REASON_SQL = ",".join(
    f"'{reason}'" for reason in sorted(_PUBLICATION_HIDE_REASONS)
)
_PUBLICATION_HIDE_RETRY_SQL = (
    "state='retry_wait' AND reason IN (" + _PUBLICATION_HIDE_REASON_SQL + ")"
)
_PUBLICATION_GENERATION_COLUMNS = (
    "publication_id,task_id,run_id,generation_boundary,metadata_digest,idempotency_key,"
    "state,attempt,lease_owner,lease_expires_at,retry_at,reason,"
    "expected_row_count,expected_object_count,expected_task_count,expected_pipeline_count,"
    "expected_run_count,expected_event_count,expected_artifact_count,created_at,updated_at,exposed_at"
)
_PUBLICATION_RECEIPT_COLUMNS = (
    "receipt_id,publication_id,task_id,receipt_class,sha256,byte_size,content_key,"
    "logical_path,verified_at"
)
_PUBLICATION_CLEANUP_COLUMNS = (
    "intent_id,publication_id,task_id,manifest_digest,exact_path,state,requested_at,"
    "verified_at,completed_at,reason"
)
_PUBLICATION_HIDE_FENCE_COLUMNS = (
    "task_id,reason,state,generation_boundary,requested_at,confirmed_at"
)

# Exact factories create only this current SQLite shape.  The constructor remains
# the compatibility path until the ordered caller migration removes it.
SQLITE_USER_VERSION = 2
CURRENT_SCHEMA_CATALOG_DIGEST = "8960dbc8bca84606c640e452f1928093e56e11afbfd46265ca64358d79f32165"
SCHEMA_CATALOG_DIGEST = CURRENT_SCHEMA_CATALOG_DIGEST
_CONTROL_LOOP_META_SEED_KEYS = frozenset({"epoch_id", "next_sequence", "planning_blocked"})
_STORE_RECEIPT_FORMAT_VERSION = 1
_STORE_RECEIPT_PREFIX = ".store-receipt-"
_STORE_RECEIPT_SUFFIX = ".json"
_STORE_RECEIPT_STATES = frozenset({"creating", "committed"})


class _ExecutionAdmissionGuard:
    """Coordinate task admission across Store instances and processes."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._local = threading.local()

    @contextmanager
    def locked(self) -> Iterator[None]:
        self._lock.acquire()
        depth = int(getattr(self._local, "depth", 0))
        try:
            if depth == 0:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                handle = self.path.open("a+", encoding="ascii")
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                except BaseException:
                    handle.close()
                    raise
                self._local.handle = handle
            self._local.depth = depth + 1
            yield
        finally:
            next_depth = int(getattr(self._local, "depth", 1)) - 1
            if next_depth <= 0:
                self._local.depth = 0
                handle = getattr(self._local, "handle", None)
                try:
                    if handle is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                finally:
                    if handle is not None:
                        handle.close()
                    try:
                        del self._local.handle
                    except AttributeError:
                        pass
            else:
                self._local.depth = next_depth
            self._lock.release()


_execution_admission_guards: dict[tuple[Path, str], _ExecutionAdmissionGuard] = {}
_execution_admission_guards_lock = threading.Lock()


def _execution_admission_guard(
    database: Path, task_id: str
) -> _ExecutionAdmissionGuard:
    key = database.expanduser().resolve()
    guard_key = (key, task_id)
    with _execution_admission_guards_lock:
        guard = _execution_admission_guards.get(guard_key)
        if guard is None:
            if task_id:
                digest = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
                name = f"{key.name}-{digest}.lock"
            else:
                name = f"{key.name}.lock"
            guard = _ExecutionAdmissionGuard(
                key.parent / ".steward-admission" / name
            )
            _execution_admission_guards[guard_key] = guard
        return guard


@dataclass(frozen=True, slots=True)
class _StoreCreationReceipt:
    epoch_id: str
    database_name: str
    state: str


@dataclass(frozen=True, slots=True)
class _StoreSidecarSnapshot:
    data: bytes
    mode: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class _StoreDatabaseSnapshot:
    digest: bytes
    mode: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class StoreRecoveryResult:
    """The durable changes made while recovering one exact Store."""

    expired_leases: int = 0
    health_changed: bool = False
    changed: bool = False

    def __post_init__(self) -> None:
        if self.expired_leases < 0:
            raise ValueError("expired lease count cannot be negative")
        expected = self.expired_leases > 0 or self.health_changed
        if self.changed != expected:
            raise ValueError("Store recovery changed flag does not match its fields")


class SQLiteStoreLifecycleError(RuntimeError):
    """The exact Store lifecycle precondition or validation failed."""


class TaskLedgerOwnershipError(ValueError):
    """A task execution cannot be used without its persisted pipeline owner."""


_EFFECT_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


def _fallback_effect_action_id(
    prefix: str,
    task_id: str,
    event_kind: str,
    *semantic_parts: object,
) -> str:
    """Derive a bounded legacy identity without retaining event text."""

    seed = "\0".join(
        [prefix, task_id, event_kind, *(str(part) for part in semantic_parts)]
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(seed).hexdigest()}"


def _event_effect_action_id(
    data: Mapping[str, object],
    *,
    task_id: str,
    event_kind: str,
    prefix: str,
    semantic_parts: tuple[object, ...],
) -> str:
    """Keep persisted identities or replace unsafe legacy fallbacks."""

    candidate = data.get("action_id")
    if candidate is None:
        candidate = data.get("actionId")
    if candidate is None or candidate == "":
        return _fallback_effect_action_id(
            prefix, task_id, event_kind, *semantic_parts
        )
    if isinstance(candidate, str) and _EFFECT_ACTION_ID_RE.fullmatch(candidate):
        return candidate
    raise ValueError("effect action identity is invalid")


class TaskPage(NamedTuple):
    """One detached keyset page of tasks and its continuation cursor."""

    items: list[TaskRecord]
    next_cursor: tuple[str, str] | None

    @property
    def tasks(self) -> list[TaskRecord]:
        return self.items

    @property
    def cursor(self) -> tuple[str, str] | None:
        return self.next_cursor


class SQLiteTaskStore:
    """SQLite-backed store hidden behind Steward's TaskStore API."""

    _control_loop: ControlLoopLedger

    def __init__(self, path: Path, on_change: Callable[[], None] | None = None):
        raise TypeError(
            "TaskStore cannot be constructed directly; use TaskStore.create() "
            "or TaskStore.open()"
        )

    @classmethod
    def create(
        cls,
        path: Path | str,
        *,
        on_change: Callable[[], None] | None = None,
        dry_run: bool | None = None,
    ) -> "SQLiteTaskStore":
        """Create and durably publish one exact current Store database.

        The task epoch is published before the database and is the only
        creation identity.  A failed attempt leaves only the narrowly
        recognized hidden prefix, which a later attempt rebuilds from scratch.
        """

        database = Path(path).expanduser()
        epoch_id, _remnants = cls._prepare_creation_state(database)
        # Recognized remnants are evidence of an interrupted attempt, not a
        # database to adopt.  Leave them untouched so a concurrent creator
        # cannot delete another live attempt; this attempt always gets a new
        # temporary name and builds it from scratch.
        temporary = cls._new_database_temporary(database, epoch_id)
        keep_temporary = False
        publication_conflict = False
        try:
            _reserve_store_receipt(database, epoch_id)
            cls._build_current_database(temporary, epoch_id)
            cls._durabilize_database(temporary)
            cls._validate_current_database(temporary, epoch_id)
            try:
                # Publish the sidecars first.  The database hard link is the
                # final visible name, so an interruption before it leaves only
                # a recognized retryable prefix and never an openable-looking
                # database without its WAL state.
                _publish_database_sidecars(temporary, database)
                try:
                    os.link(temporary, database)
                except FileExistsError:
                    publication_conflict = True
                    # The target was absent at entry but another creator won
                    # the no-replace publication race.  Only an exact current
                    # winner can be adopted; an arbitrary file is never
                    # inspected as a usable Store.
                    _validate_optional_sqlite_sidecars(database)
                    winner_epoch = _read_task_epoch(database.parent / "tasks")
                    if winner_epoch["epochId"] != epoch_id:
                        raise SQLiteStoreLifecycleError(
                            "concurrent Store winner has a mismatched task epoch"
                        )
                    cls._validate_current_database(database, epoch_id)
                    # The adopter must establish durability independently of
                    # the creator that won the link race.
                    _fsync_directory(database.parent)
                    _commit_store_receipt(database, epoch_id)
                    store = cls._open_validated(
                        database, epoch_id, on_change, dry_run=dry_run
                    )
                    if dry_run is not None:
                        store.resolve_execution_modes(dry_run)
                    return store
                _fsync_directory(database.parent)
            except BaseException:
                if not publication_conflict:
                    # Preserve a partially published prefix for inspection, but
                    # never remove a visible database or sidecar.  A later
                    # creator refuses that state unchanged; only this attempt's
                    # hidden temporary is removed below when appropriate.
                    keep_temporary = _temporary_publication_is_partial(
                        temporary, database
                    )
                raise
            _commit_store_receipt(database, epoch_id)
            return cls.open(database, on_change=on_change, dry_run=dry_run)
        finally:
            if not keep_temporary:
                _remove_factory_temporary(temporary)

    @classmethod
    def open(
        cls,
        path: Path | str,
        *,
        on_change: Callable[[], None] | None = None,
        dry_run: bool | None = None,
    ) -> "SQLiteTaskStore":
        """Open an exact current Store, optionally resolving task admission."""

        database = Path(path).expanduser()
        epoch = _read_task_epoch(database.parent / "tasks")
        epoch_id = epoch["epochId"]
        database_snapshot = _snapshot_store_database(database)
        sidecar_snapshot = _snapshot_store_sidecars(database)
        cls._validate_current_database(database, epoch_id)
        store = cls._open_validated(
            database,
            epoch_id,
            on_change,
            dry_run=dry_run,
            database_snapshot=database_snapshot,
            sidecar_snapshot=sidecar_snapshot,
        )
        if dry_run is not None:
            store.resolve_execution_modes(dry_run)
        return store

    @classmethod
    def _open_validated(
        cls,
        database: Path,
        epoch_id: str,
        on_change: Callable[[], None] | None,
        *,
        dry_run: bool | None = None,
        database_snapshot: _StoreDatabaseSnapshot | None = None,
        sidecar_snapshot: Mapping[str, _StoreSidecarSnapshot] | None = None,
    ) -> "SQLiteTaskStore":
        store = cls._blank_store(
            database, on_change=on_change, wal=False, dry_run=dry_run
        )
        store._control_loop = _bind_existing_control_loop(database, epoch_id)
        store._database_snapshot = (
            database_snapshot
            if database_snapshot is not None
            else _snapshot_store_database(database)
        )
        store._sidecar_snapshot = dict(
            sidecar_snapshot
            if sidecar_snapshot is not None
            else _snapshot_store_sidecars(database)
        )
        store._database_snapshot_digest = store._database_snapshot.digest
        return store

    def _finalize_exact_store(self) -> None:
        """Close an initialized Store without replaying stale WAL state."""

        # The WAL snapshot is used only as an equality guard.  It is never
        # written back, so a latch resolution or concurrent WAL commit remains
        # authoritative; a clean SHM image is preserved only after that proof.
        snapshots = self._sidecar_snapshot
        self.engine.dispose()
        database_changed = (
            self._database_snapshot_digest is not None
            and hashlib.sha256(self.path.read_bytes()).digest()
            != self._database_snapshot_digest
        )
        sidecars = _database_publication_paths(self.path)[1:]
        if database_changed or not all(os.path.lexists(sidecar) for sidecar in sidecars):
            self._durabilize_database(self.path)
        epoch_id = _read_task_epoch(self.path.parent / "tasks")["epochId"]
        self._validate_current_database(self.path, epoch_id)
        _ensure_store_sidecars(self.path)
        _preserve_store_database_metadata(self.path, self._database_snapshot)
        _preserve_store_sidecar_metadata(
            self.path,
            snapshots,
            database_snapshot=self._database_snapshot,
        )

    def resolve_execution_modes(
        self, dry_run: bool | ExecutionMode | str
    ) -> int:
        """Adopt and monotonically tighten every task admission latch.

        The latch lives in task metadata so this operation deliberately avoids
        schema/catalog changes.  A live startup may not unlock an existing
        dry-run task; a dry-run startup may tighten a live task.
        """

        if isinstance(dry_run, bool):
            startup = execution_mode_for_dry_run(dry_run)
            selected_dry_run = dry_run
        else:
            startup = coerce_execution_mode(dry_run)
            if startup is None:
                raise TypeError("startup execution mode is required")
            selected_dry_run = startup is ExecutionMode.dry_run
        with Session(self.engine) as session:
            task_ids = sorted(session.scalars(select(TaskRow.id)).all())
        with ExitStack() as admission_locks:
            for task_id in task_ids:
                admission_locks.enter_context(
                    _execution_admission_guard(self.path, task_id).locked()
                )
            self._startup_dry_run = selected_dry_run
            changed = 0
            with Session(self.engine) as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    rows = session.scalars(select(TaskRow)).all()
                    for row in rows:
                        metadata = _metadata_dict(row.metadata_json, self.path_codec)
                        current = execution_mode_from_metadata(metadata)
                        resolved = resolve_execution_mode(current, startup)
                        if current is resolved and metadata.get(EXECUTION_MODE_METADATA_KEY) == resolved.value:
                            continue
                        row.metadata_json = _dump_metadata(
                            preserve_execution_mode(metadata, resolved=resolved),
                            self.path_codec,
                        )
                        changed += 1
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
        if changed:
            self._notify_change()
        return changed

    # Explicit aliases make the authority discoverable without exposing a
    # second persistence path.
    set_startup_execution_mode = resolve_execution_modes
    resolve_task_execution_modes = resolve_execution_modes

    def task_execution_mode(self, task_id: str) -> ExecutionMode | None:
        """Return the persisted task latch without inferring a caller mode."""

        # Read the persisted JSON directly so a detached TaskRecord never
        # becomes execution authority.
        with Session(self.engine) as session:
            row = session.get(TaskRow, task_id)
            if row is None:
                raise KeyError(task_id)
            metadata = _metadata_dict(row.metadata_json, self.path_codec)
        return execution_mode_from_metadata(metadata)

    get_task_execution_mode = task_execution_mode

    @staticmethod
    def _effect_evidence_from_events(
        task_id: str,
        events: Iterable[Event],
        mode: ExecutionMode,
    ) -> tuple[EffectEvidence, ...]:
        """Validate and normalize the action facts already in the event ledger."""

        values: list[EffectEvidence] = []
        for event_record in events:
            data = event_record.data if isinstance(event_record.data, Mapping) else {}
            try:
                if event_record.kind == "effect.proposed":
                    proposal_data = dict(data)
                    for source, target in (
                        ("proposalId", "proposal_id"),
                        ("actionId", "action_id"),
                    ):
                        if source in proposal_data and target not in proposal_data:
                            proposal_data[target] = proposal_data.pop(source)
                    proposal = EffectProposal.model_validate(proposal_data)
                    if mode is not ExecutionMode.dry_run:
                        raise ValueError("live task contains a blocked effect proposal")
                    values.append(
                        EffectEvidence(
                            task_id=task_id,
                            action=proposal.action,
                            action_id=proposal.action_id,
                            mode=mode,
                            decision=EffectDecisionKind.proposal_required,
                            result=EffectResult.not_applied,
                            at=event_record.created_at,
                            proposal_id=proposal.identity,
                        )
                    )
                    continue
                if event_record.kind in {"effect.authorized", "effect.recorded"}:
                    action = EffectActionKind(data.get("action"))
                    action_id = data.get("actionId", data.get("action_id"))
                    if not isinstance(action_id, str) or not action_id:
                        raise ValueError("effect action identity is missing")
                    evidence_mode = coerce_execution_mode(data.get("mode")) or mode
                    decision = EffectDecisionKind(
                        data.get("decision", EffectDecisionKind.allow.value)
                    )
                    evidence_result = coerce_effect_result(
                        data.get("result", EffectResult.not_applied.value)
                    )
                    if evidence_result is None:
                        raise ValueError("effect result is missing")
                    values.append(
                        EffectEvidence(
                            effect_id=data.get("effectId", data.get("effect_id")),
                            task_id=task_id,
                            action=action,
                            action_id=action_id,
                            mode=evidence_mode,
                            decision=decision,
                            result=evidence_result,
                            at=event_record.created_at,
                            proposal_id=data.get("proposalId", data.get("proposal_id")),
                        )
                    )
                    continue
                if event_record.kind == "effect.applied":
                    action = EffectActionKind(data.get("action"))
                    action_id = data.get("actionId", data.get("action_id"))
                    if not isinstance(action_id, str) or not action_id:
                        raise ValueError("applied effect action identity is missing")
                    evidence_mode = coerce_execution_mode(data.get("mode"))
                    if evidence_mode is None:
                        raise ValueError("applied effect mode is missing")
                    if evidence_mode is not ExecutionMode.live:
                        raise ValueError("dry-run task contains an applied effect")
                    values.append(
                        EffectEvidence(
                            task_id=task_id,
                            action=action,
                            action_id=action_id,
                            mode=evidence_mode,
                            decision=EffectDecisionKind.allow,
                            result=EffectResult.applied,
                            at=event_record.created_at,
                            proposal_id=data.get("proposalId", data.get("proposal_id")),
                        )
                    )
                    continue

                action: EffectActionKind | None = None
                action_id: str | None = None
                result = EffectResult.applied
                evidence_mode = ExecutionMode.live
                pipeline_id = data.get("pipeline_id", data.get("pipelineId"))
                commit = data.get("commit")
                attempt = data.get("attempt")
                if event_record.kind in {
                    "pipeline.push",
                    "main.pushed",
                    "pipeline.push.ambiguous_resolved",
                }:
                    action = EffectActionKind.git_push
                    action_id = _event_effect_action_id(
                        data,
                        task_id=task_id,
                        event_kind=event_record.kind,
                        prefix="git-push-legacy",
                        semantic_parts=(pipeline_id, commit, attempt),
                    )
                elif event_record.kind in {"github.issue_closed", "github.issue_commented"}:
                    action = (
                        EffectActionKind.github_issue_close
                        if event_record.kind == "github.issue_closed"
                        else EffectActionKind.github_issue_comment
                    )
                    issue_number = data.get("issue_number", data.get("issueNumber"))
                    action_id = _event_effect_action_id(
                        data,
                        task_id=task_id,
                        event_kind=event_record.kind,
                        prefix=(
                            "github-issue-close-legacy"
                            if action is EffectActionKind.github_issue_close
                            else "github-issue-comment-legacy"
                        ),
                        semantic_parts=(issue_number, data.get("integration_task_id")),
                    )
                elif event_record.kind in {"publication.exposed", "publication.applied"}:
                    action = EffectActionKind.publication_transport
                    publication_id = data.get(
                        "publication_id", data.get("publicationId")
                    )
                    action_id = _event_effect_action_id(
                        data,
                        task_id=task_id,
                        event_kind=event_record.kind,
                        prefix="publication-expose-legacy",
                        semantic_parts=(publication_id,),
                    )
                elif event_record.kind in {"pipeline.push.failure", "pipeline.push.blocked"}:
                    action = EffectActionKind.git_push
                    action_id = _event_effect_action_id(
                        data,
                        task_id=task_id,
                        event_kind=event_record.kind,
                        prefix="git-push-legacy",
                        semantic_parts=(
                            pipeline_id,
                            commit,
                            attempt,
                            data.get("day"),
                        ),
                    )
                    result = EffectResult.not_applied
                elif event_record.kind == "github.issue_update_failed":
                    step = str(data.get("step", "comment"))
                    if step in {"proposal", "bookkeeping"}:
                        # These are local diagnostics, not failed external
                        # actions.  A later retry may still persist the real
                        # proposal or post-push issue evidence.
                        continue
                    if step not in {"comment", "close"}:
                        raise ValueError("unknown GitHub issue update step")
                    action = (
                        EffectActionKind.github_issue_close
                        if step == "close"
                        else EffectActionKind.github_issue_comment
                    )
                    issue_number = data.get("issue_number", data.get("issueNumber"))
                    action_id = _event_effect_action_id(
                        data,
                        task_id=task_id,
                        event_kind=event_record.kind,
                        prefix=(
                            "github-issue-close-legacy"
                            if action is EffectActionKind.github_issue_close
                            else "github-issue-comment-legacy"
                        ),
                        semantic_parts=(issue_number, data.get("integration_task_id"), step),
                    )
                    result = EffectResult.not_applied
                if action is None or action_id is None:
                    continue
                values.append(
                    EffectEvidence(
                        task_id=task_id,
                        action=action,
                        action_id=action_id,
                        mode=evidence_mode,
                        decision=EffectDecisionKind.allow,
                        result=result,
                        at=event_record.created_at,
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"malformed external effect evidence in {event_record.kind}"
                ) from exc
        unique: dict[str, EffectEvidence] = {}
        for value in values:
            assert value.effect_id is not None
            previous = unique.get(value.effect_id)
            if previous is not None:
                if previous.result is not value.result or previous.proposal_id != value.proposal_id:
                    raise ValueError("contradictory external effect evidence")
                continue
            unique[value.effect_id] = value
        return tuple(unique.values())

    @staticmethod
    def _validate_effect_result_events(
        events: Iterable[Event],
        *,
        result: EffectResult,
        evidence: Iterable[EffectEvidence],
    ) -> None:
        evidence_ids = {
            item.effect_id for item in evidence if item.effect_id is not None
        }
        for event_record in events:
            if event_record.kind != EFFECT_RESULT_EVENT_KIND:
                continue
            data = event_record.data if isinstance(event_record.data, Mapping) else {}
            try:
                observed = coerce_effect_result(data.get("result"))
                if observed is not result:
                    raise ValueError("effect result event disagrees with aggregate")
                raw_evidence = data.get("evidence")
                if not isinstance(raw_evidence, list):
                    raise ValueError("effect result event evidence is not an array")
                observed_ids = {
                    EffectEvidence.model_validate(item).effect_id
                    for item in raw_evidence
                }
                if observed_ids != evidence_ids:
                    raise ValueError("effect result event evidence is incomplete")
            except (TypeError, ValueError) as exc:
                raise ValueError("malformed external effect result event") from exc

    def effect_evidence(self, task_id: str) -> tuple[EffectEvidence, ...]:
        """Return validated action evidence without changing the Store."""

        mode = self.task_execution_mode(task_id)
        if mode is None:
            raise ValueError("task execution mode is required for effect evidence")
        return self._effect_evidence_from_events(task_id, self.events(task_id), mode)

    list_effect_evidence = effect_evidence

    def derive_effect_result(self, task_id: str) -> EffectResult:
        """Derive the aggregate from validated action evidence."""

        return derive_effect_result(self.effect_evidence(task_id))

    def effect_result(self, task_id: str) -> EffectResult | None:
        """Read the Store-owned aggregate; missing means not finalized."""

        with Session(self.engine) as session:
            row = session.get(TaskRow, task_id)
            if row is None:
                raise KeyError(task_id)
            metadata = _metadata_dict(row.metadata_json, self.path_codec)
        result = effect_result_from_metadata(metadata)
        if result is None:
            return None
        evidence = self.effect_evidence(task_id)
        self._validate_effect_result_events(
            self.events(task_id), result=result, evidence=evidence
        )
        if derive_effect_result(evidence) is not result:
            raise ValueError("stored external effect result contradicts evidence")
        return result

    get_effect_result = effect_result
    get_external_effect_result = effect_result
    external_effect_result = effect_result
    aggregate_effect_result = effect_result

    def finalize_effect_result(
        self,
        task_id: str,
        result: EffectResult | str | None = None,
    ) -> EffectResult:
        """Finalize one aggregate exactly once and make retries idempotent."""

        guard = _execution_admission_guard(self.path, task_id)
        with guard.locked():
            with Session(self.engine) as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    row = session.get(TaskRow, task_id)
                    if row is None:
                        raise KeyError(task_id)
                    metadata = _metadata_dict(row.metadata_json, self.path_codec)
                    mode = execution_mode_from_metadata(metadata)
                    if mode is None:
                        raise ValueError("task execution mode is required")
                    event_values = [
                        row_to_event(item, path_codec=self.path_codec)
                        for item in session.scalars(
                            select(EventRow)
                            .where(EventRow.task_id == task_id)
                            .order_by(EventRow.created_at, EventRow.id)
                        ).all()
                    ]
                    evidence = self._effect_evidence_from_events(
                        task_id, event_values, mode
                    )
                    derived = derive_effect_result(evidence)
                    requested = coerce_effect_result(result)
                    if requested is not None and requested is not derived:
                        raise ValueError(
                            "requested external effect result contradicts evidence"
                        )
                    existing = effect_result_from_metadata(metadata)
                    self._validate_effect_result_events(
                        event_values,
                        result=existing or derived,
                        evidence=evidence,
                    )
                    if existing is not None:
                        if existing is not derived:
                            raise ValueError(
                                "stored external effect result contradicts evidence"
                            )
                        session.commit()
                        return existing
                    metadata = preserve_effect_result(metadata, resolved=derived)
                    row.metadata_json = _dump_metadata(metadata, self.path_codec)
                    event = Event(
                        task_id=task_id,
                        kind=EFFECT_RESULT_EVENT_KIND,
                        message=derived.value,
                        data={
                            "result": derived.value,
                            "evidence": [item.as_dict() for item in evidence],
                        },
                    )
                    session.add(event_to_row(event, path_codec=self.path_codec))
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
        self._notify_change()
        return derived

    finalize_external_effect_result = finalize_effect_result
    finalize_task_effect_result = finalize_effect_result
    set_effect_result = finalize_effect_result
    seal_effect_result = finalize_effect_result

    @contextmanager
    def phase_admission(self, task_id: str) -> Iterator[bool]:
        """Hold the Store authority across local phase work and effect checks.

        Dry-run is not an execution pause.  The lock keeps a phase and its
        immediately-following effect decision atomic; semantic effect methods
        below are the only places that decide whether a mutation may escape.
        """

        guard = _execution_admission_guard(self.path, task_id)
        with guard.locked():
            # Validate the row even though both live and dry-run tasks execute
            # local analysis, validation, worktree changes, and commits.
            self.task_execution_mode(task_id)
            yield True

    def effect_decision(
        self,
        task_id: str,
        *,
        action: str,
        action_id: str,
        target: str,
        payload: Mapping[str, object] | None = None,
        reason: str = "dry-run",
    ) -> object:
        """Resolve one effect from the persisted task latch immediately before it.

        The per-task file lock and SQLite transaction make the persisted latch
        authoritative even when a second Store instance tightens it between
        phase snapshots.  Dry-run decisions are returned as bounded proposals;
        callers must not invoke the external operation in that case.
        """

        from ..core.models import decide_effect

        guard = _execution_admission_guard(self.path, task_id)
        with guard.locked():
            with Session(self.engine) as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    row = session.get(TaskRow, task_id)
                    if row is None:
                        raise KeyError(task_id)
                    metadata = _metadata_dict(row.metadata_json, self.path_codec)
                    mode = execution_mode_from_metadata(metadata)
                    startup_mode = execution_mode_for_dry_run(self._startup_dry_run)
                    resolved = resolve_execution_mode(mode, startup_mode)
                    if resolved is not mode:
                        metadata = preserve_execution_mode(metadata, resolved=resolved)
                        row.metadata_json = _dump_metadata(metadata, self.path_codec)
                        mode = resolved
                    decision = decide_effect(
                        mode,
                        action=action,
                        action_id=action_id,
                        target=target,
                        payload=payload,
                        reason=reason,
                    )
                    if decision.proposal is not None:
                        proposal = decision.proposal
                        duplicate = False
                        for data_json in session.scalars(
                            select(EventRow.data_json).where(
                                EventRow.task_id == task_id,
                                EventRow.kind == "effect.proposed",
                            )
                        ).all():
                            try:
                                existing = json.loads(data_json or "{}")
                            except (TypeError, json.JSONDecodeError):
                                existing = {}
                            if isinstance(existing, dict) and existing.get("proposalId") == proposal.identity:
                                duplicate = True
                                break
                        if not duplicate:
                            event = Event(
                                task_id=task_id,
                                kind="effect.proposed",
                                message=proposal.action.value,
                                data=proposal.as_dict(),
                            )
                            session.add(event_to_row(event, path_codec=self.path_codec))
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
        if decision.proposal is not None:
            self._notify_change()
        return decision

    def record_effect_applied(
        self,
        task_id: str,
        *,
        action: str,
        action_id: str,
        proposal_id: str | None = None,
    ) -> EffectEvidence:
        """Record confirmation that one live external action completed."""

        guard = _execution_admission_guard(self.path, task_id)
        with guard.locked():
            with Session(self.engine) as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    row = session.get(TaskRow, task_id)
                    if row is None:
                        raise KeyError(task_id)
                    metadata = _metadata_dict(row.metadata_json, self.path_codec)
                    mode = execution_mode_from_metadata(metadata)
                    if mode is not ExecutionMode.live:
                        raise ValueError("only live tasks may record applied effects")
                    evidence = EffectEvidence(
                        task_id=task_id,
                        action=action,
                        action_id=action_id,
                        mode=mode,
                        decision=EffectDecisionKind.allow,
                        result=EffectResult.applied,
                        proposal_id=proposal_id,
                    )
                    assert evidence.effect_id is not None
                    for data_json in session.scalars(
                        select(EventRow.data_json).where(
                            EventRow.task_id == task_id,
                            EventRow.kind == "effect.recorded",
                        )
                    ).all():
                        try:
                            recorded = json.loads(data_json or "{}")
                        except (TypeError, json.JSONDecodeError) as exc:
                            raise ValueError("malformed recorded effect evidence") from exc
                        if isinstance(recorded, dict) and recorded.get("effectId") == evidence.effect_id:
                            raise ValueError("contradictory applied effect evidence")
                    matching: list[dict[str, object]] = []
                    for data_json in session.scalars(
                        select(EventRow.data_json).where(
                            EventRow.task_id == task_id,
                            EventRow.kind == "effect.applied",
                        )
                    ).all():
                        try:
                            existing = json.loads(data_json or "{}")
                        except (TypeError, json.JSONDecodeError):
                            raise ValueError("malformed applied effect evidence")
                        if isinstance(existing, dict) and existing.get("effectId") == evidence.effect_id:
                            matching.append(existing)
                    if matching:
                        existing_evidence = EffectEvidence.model_validate(matching[0])
                        if (
                            existing_evidence.effect_id != evidence.effect_id
                            or existing_evidence.result is not EffectResult.applied
                        ):
                            raise ValueError("contradictory applied effect evidence")
                        session.commit()
                        return existing_evidence
                    if effect_result_from_metadata(metadata) is not None:
                        raise ValueError("external effect result is already finalized")
                    event = Event(
                        task_id=task_id,
                        kind="effect.applied",
                        message=evidence.action.value,
                        data=evidence.as_dict(),
                    )
                    session.add(event_to_row(event, path_codec=self.path_codec))
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
        self._notify_change()
        return evidence

    confirm_effect = record_effect_applied
    record_applied_effect = record_effect_applied

    def record_effect(
        self,
        task_id: str,
        *,
        action: str,
        action_id: str,
        mode: ExecutionMode | str | None = None,
        decision: EffectDecisionKind | str = EffectDecisionKind.allow,
        result: EffectResult | str = EffectResult.not_applied,
        proposal_id: str | None = None,
    ) -> EffectEvidence:
        """Record a typed effect observation for integrations and tests."""

        selected_mode = coerce_execution_mode(mode) if mode is not None else self.task_execution_mode(task_id)
        if selected_mode is None:
            raise ValueError("effect mode is required")
        selected_decision = EffectDecisionKind(decision)
        selected_result = coerce_effect_result(result)
        if selected_result is None:
            raise ValueError("effect result is required")
        evidence = EffectEvidence(
            task_id=task_id,
            action=action,
            action_id=action_id,
            mode=selected_mode,
            decision=selected_decision,
            result=selected_result,
            proposal_id=proposal_id,
        )
        if selected_result is EffectResult.applied:
            return self.record_effect_applied(
                task_id,
                action=action,
                action_id=action_id,
                proposal_id=proposal_id,
            )
        with Session(self.engine) as session, session.begin():
            existing_values = session.scalars(
                select(EventRow.data_json).where(
                    EventRow.task_id == task_id,
                    EventRow.kind == "effect.recorded",
                )
            ).all()
            existing = None
            for data_json in existing_values:
                try:
                    value = json.loads(data_json or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError("malformed recorded effect evidence") from exc
                if isinstance(value, dict) and value.get("effectId") == evidence.effect_id:
                    existing = EffectEvidence.model_validate(value)
                    break
            if existing is not None:
                if (
                    existing.result is not evidence.result
                    or existing.proposal_id != evidence.proposal_id
                ):
                    raise ValueError("contradictory recorded effect evidence")
            else:
                row = session.get(TaskRow, task_id)
                if row is None:
                    raise KeyError(task_id)
                metadata = _metadata_dict(row.metadata_json, self.path_codec)
                if effect_result_from_metadata(metadata) is not None:
                    raise ValueError("external effect result is already finalized")
                session.add(
                    event_to_row(
                        Event(
                            task_id=task_id,
                            kind="effect.recorded",
                            message=evidence.action.value,
                            data=evidence.as_dict(),
                        ),
                        path_codec=self.path_codec,
                    )
                )
        self._notify_change()
        return evidence

    record_effect_evidence = record_effect

    @contextmanager
    def effect_admission(
        self,
        task_id: str,
        *,
        action: str,
        action_id: str,
        target: str,
        payload: Mapping[str, object] | None = None,
        reason: str = "dry-run",
    ) -> Iterator[object]:
        """Hold the task latch lock across the decision and the effect call."""

        guard = _execution_admission_guard(self.path, task_id)
        with guard.locked():
            yield self.effect_decision(
                task_id,
                action=action,
                action_id=action_id,
                target=target,
                payload=payload,
                reason=reason,
            )

    # Descriptive aliases keep the Store-owned seam discoverable to callers.
    check_effect = effect_decision
    authorize_effect = effect_decision
    resolve_effect = effect_decision
    effect_scope = effect_admission

    def resolve_task_execution_mode(
        self, task_id: str, startup: bool | ExecutionMode | str
    ) -> ExecutionMode:
        """Resolve one task latch atomically at the configured startup mode."""

        if isinstance(startup, bool):
            startup_mode = execution_mode_for_dry_run(startup)
        else:
            startup_mode = coerce_execution_mode(startup)
            if startup_mode is None:
                raise TypeError("startup execution mode is required")
        guard = _execution_admission_guard(self.path, task_id)
        with guard.locked():
            with Session(self.engine) as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    row = session.scalar(_task_query().where(TaskRow.id == task_id))
                    if row is None:
                        raise KeyError(task_id)
                    metadata = _metadata_dict(row.metadata_json, self.path_codec)
                    resolved = resolve_execution_mode(
                        execution_mode_from_metadata(metadata), startup_mode
                    )
                    row.metadata_json = _dump_metadata(
                        preserve_execution_mode(metadata, resolved=resolved),
                        self.path_codec,
                    )
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
            self._startup_dry_run = startup_mode is ExecutionMode.dry_run
        self._notify_change()
        return resolved

    def recover(self) -> StoreRecoveryResult:
        """Recover same-version publication leases and derived health once."""

        if self._startup_dry_run:
            # Evaluation must not rewrite pre-existing live publication rows.
            return StoreRecoveryResult()
        timestamp = _publication_now(None)
        connection = self.engine.connect()
        expired_leases = 0
        health_changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            expired_leases = int(
                connection.exec_driver_sql(
                    """
                    SELECT COUNT(*)
                    FROM publication_generations AS generation
                    WHERE generation.state IN ('claimed','building','uploading','d1_staged')
                      AND generation.lease_expires_at <= :now
                      AND NOT EXISTS (
                          SELECT 1
                          FROM publication_hide_fences AS fence
                          WHERE fence.task_id=generation.task_id
                            AND fence.state IN ('pending','confirmed')
                      )
                    """,
                    {"now": _publication_timestamp(timestamp)},
                ).scalar_one()
            )
            if expired_leases:
                self._expire_publication_leases_in_connection(connection, timestamp)
            health_changed = expired_leases > 0 or _publication_health_needs_refresh(
                connection
            )
            if health_changed:
                self._refresh_publication_health(
                    connection,
                    updated_at=timestamp,
                    reason="lease_expired" if expired_leases else None,
                    preserve_category=expired_leases == 0,
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        result = StoreRecoveryResult(
            expired_leases=expired_leases,
            health_changed=health_changed,
            changed=expired_leases > 0 or health_changed,
        )
        if result.changed:
            self._notify_change()
        return result

    @classmethod
    def _blank_store(
        cls,
        database: Path,
        *,
        on_change: Callable[[], None] | None,
        wal: bool,
        dry_run: bool | None = None,
    ) -> "SQLiteTaskStore":
        store = cls.__new__(cls)
        store._startup_dry_run = bool(dry_run) if dry_run is not None else False
        store.path = database
        store.on_change = on_change
        store.path_codec = PathCodec(database.parent)
        store._database_snapshot = None
        store._database_snapshot_digest = None
        store.engine = create_engine(f"sqlite:///{database}", future=True)
        event.listen(
            store.engine,
            "connect",
            _configure_sqlite if wal else _configure_sqlite_read_only,
        )
        return store

    @classmethod
    def _prepare_creation_state(
        cls, database: Path
    ) -> tuple[str, list[Path]]:
        _ensure_database_parent(database.parent)

        tasks_root = database.parent / "tasks"
        control_loop_root = database.parent / "control-loop"
        if os.path.lexists(control_loop_root):
            _require_directory(control_loop_root, "control-loop root")
            if _directory_entries(control_loop_root, "control-loop root"):
                raise SQLiteStoreLifecycleError(
                    "control-loop root contains existing state"
                )

        epoch_path = tasks_root / "epoch.json"
        epoch: dict[str, object] | None = None
        epoch_temporaries: list[Path] = []
        if os.path.lexists(tasks_root):
            _require_directory(tasks_root, "task archive root")
            entries = _directory_entries(tasks_root, "task archive root")
            if os.path.lexists(epoch_path):
                epoch = _read_epoch_document(epoch_path)
                for entry in entries:
                    if entry == epoch_path:
                        continue
                    if entry.name.startswith(f".{epoch_path.name}.tmp-"):
                        _require_regular_file(entry, "epoch temporary")
                        epoch_temporaries.append(entry)
                    elif entry.name.startswith(_STORE_RECEIPT_PREFIX):
                        _read_store_receipt_file(entry, str(epoch["epochId"]))
                    else:
                        raise SQLiteStoreLifecycleError(
                            "task archive root contains extra visible state"
                        )
            elif entries:
                raise SQLiteStoreLifecycleError(
                    "task archive root lacks a valid epoch"
                )

        expected_epoch_id = None if epoch is None else str(epoch["epochId"])
        store_receipt = (
            None
            if expected_epoch_id is None
            else _read_store_receipt(database, expected_epoch_id)
        )
        if epoch is None:
            # Refuse all visible target state before publishing a new epoch.
            # A hidden database temporary without an epoch is a reverse orphan,
            # not a creation prefix that may be inferred or adopted.
            _refuse_existing_database_state(database)
            database_temporaries = _scan_database_temporaries(
                database, expected_epoch_id
            )
            if database_temporaries:
                raise SQLiteStoreLifecycleError(
                    "database temporary exists without a task epoch"
                )
            from ..execution.task_archive import TaskArchive

            try:
                epoch = TaskArchive(tasks_root).ensure_epoch()
            except Exception as exc:
                raise SQLiteStoreLifecycleError(
                    "unable to publish the task epoch"
                ) from exc
            expected_epoch_id = str(epoch["epochId"])
            # Recheck the related prefix after epoch publication.  A
            # mismatched remnant must not be hidden by the newly chosen ID.
            database_temporaries = _scan_database_temporaries(
                database, expected_epoch_id
            )
        else:
            database_temporaries = _scan_database_temporaries(
                database, expected_epoch_id
            )
            sibling_store_exists = _validated_sibling_store_exists(
                database, expected_epoch_id
            )
            target_present = any(
                os.path.lexists(path)
                for path in _database_publication_paths(database)
            )
            if not target_present and not database_temporaries:
                if store_receipt is not None:
                    raise SQLiteStoreLifecycleError(
                        "Store creation receipt exists without its database"
                    )
                if not sibling_store_exists:
                    raise SQLiteStoreLifecycleError(
                        "task archive exists without a Store database"
                    )

        assert expected_epoch_id is not None
        # Visible database and sidecar paths are never a retry prefix.  Refuse
        # them unchanged instead of unlinking paths that may belong to a live
        # creator.
        _refuse_existing_database_state(database)
        return expected_epoch_id, [*epoch_temporaries, *database_temporaries]

    @classmethod
    def _new_database_temporary(cls, database: Path, epoch_id: str) -> Path:
        for _ in range(32):
            candidate = database.parent / (
                f".{database.name}.create-{epoch_id}-{secrets.token_hex(8)}.tmp"
            )
            if not os.path.lexists(candidate):
                return candidate
        raise SQLiteStoreLifecycleError("unable to allocate a database temporary")

    @classmethod
    def _build_current_database(cls, database: Path, epoch_id: str) -> None:
        store = cls._blank_store(database, on_change=None, wal=True)
        try:
            Base.metadata.create_all(store.engine)
            store._control_loop = ControlLoopLedger(database, epoch_id=epoch_id)
            with store.engine.begin() as connection:
                connection.exec_driver_sql(
                    f"PRAGMA user_version = {SQLITE_USER_VERSION}"
                )
                _install_ledger_ownership_triggers(connection)
            store._ensure_publication_health()
            try:
                os.chmod(database, 0o600)
            except OSError:
                pass
        finally:
            store.engine.dispose()

    @classmethod
    def _durabilize_database(cls, database: Path) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(database, timeout=30)
            _disable_sqlite_close_checkpoint(connection)
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        except sqlite3.Error as exc:
            raise SQLiteStoreLifecycleError(
                "unable to checkpoint the Store database"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        for suffix in ("-wal", "-shm"):
            sidecar = database.with_name(database.name + suffix)
            if os.path.lexists(sidecar):
                _require_regular_file(sidecar, "database temporary sidecar")
            else:
                try:
                    with sidecar.open("xb"):
                        pass
                except OSError as exc:
                    raise SQLiteStoreLifecycleError(
                        "unable to initialize WAL sidecar"
                    ) from exc
            try:
                with sidecar.open("rb") as handle:
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise SQLiteStoreLifecycleError(
                    "unable to sync WAL sidecar"
                ) from exc
        try:
            with database.open("rb") as handle:
                os.fsync(handle.fileno())
            _fsync_directory(database.parent)
        except OSError as exc:
            raise SQLiteStoreLifecycleError(
                "unable to durably sync the Store database"
            ) from exc

    @classmethod
    def _validate_current_database(
        cls, database: Path, epoch_id: str
    ) -> None:
        _require_regular_file(database, "Store database")
        _require_wal_sidecars(database)
        try:
            uri = database.resolve().as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=30)
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteStoreLifecycleError("unable to open the Store database") from exc
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            if journal_mode != "wal":
                raise SQLiteStoreLifecycleError(
                    "Store database is not using WAL journaling"
                )
            user_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if user_version != SQLITE_USER_VERSION:
                raise SQLiteStoreLifecycleError("Store database version mismatch")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise SQLiteStoreLifecycleError("Store database integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise SQLiteStoreLifecycleError(
                    "Store database foreign-key check failed"
                )
            if _catalog_digest(connection) != CURRENT_SCHEMA_CATALOG_DIGEST:
                raise SQLiteStoreLifecycleError("Store database catalog mismatch")
            _validate_store_seeds(connection, epoch_id)
        except sqlite3.Error as exc:
            raise SQLiteStoreLifecycleError("invalid Store database") from exc
        finally:
            connection.close()

    def _is_verified_live_rerun_owner(
        self, session: Session, owner: TaskRow, source_task_id: str
    ) -> bool:
        """Prove that a signal owner is an allocated live rerun descendant."""

        if owner.id == source_task_id:
            return True
        if owner.source != "rerun-live":
            return False
        owner_metadata = _metadata_dict(owner.metadata_json, self.path_codec)
        try:
            owner_mode = execution_mode_from_metadata(owner_metadata)
        except (TypeError, ValueError):
            return False
        if owner_mode is not ExecutionMode.live:
            return False
        lineage = owner_metadata.get(DRY_RUN_OF_TASK_ID_METADATA_KEY)
        if lineage is None:
            lineage = owner_metadata.get(DRY_RUN_OF_TASK_ID_METADATA_ALIAS)
        if lineage != source_task_id:
            return False
        if not owner.dedupe_key or owner_metadata.get("dedupe_key") != owner.dedupe_key:
            return False
        return (
            session.execute(
                text(
                    "SELECT 1 FROM control_loop_edges "
                    "WHERE epoch_id=:epoch_id AND edge_type=:edge_type "
                    "AND source_id=:source_id AND target_id=:target_id"
                ),
                {
                    "epoch_id": self.control_loop.epoch_id,
                    "edge_type": "task_rerun",
                    "source_id": source_task_id,
                    "target_id": owner.id,
                },
            ).first()
            is not None
        )

    def active_live_descendants(self, source_task_id: str) -> list[TaskRecord]:
        """Return all active live descendants recorded for one source."""

        values: list[TaskRecord] = []
        with Session(self.engine) as session:
            rows = session.scalars(
                _task_query().where(
                    TaskRow.status.in_([status.value for status in ACTIVE_STATUSES])
                )
            ).all()
            for row in rows:
                record = row_to_task(row, path_codec=self.path_codec)
                if record.id != source_task_id and self._is_verified_live_rerun_owner(
                    session, row, source_task_id
                ):
                    values.append(record)
        values.sort(key=lambda value: (value.created_at, value.id))
        return values

    def active_live_rerun(self, source_task_id: str) -> TaskRecord | None:
        """Return the active live descendant for one dry-run source, if any."""

        values = self.active_live_descendants(source_task_id)
        return values[0] if values else None

    get_active_live_descendant = active_live_rerun
    find_active_live_descendant = active_live_rerun
    active_live_descendant = active_live_rerun
    list_active_live_descendants = active_live_descendants

    def signal_items_by_id(self, ids: Iterable[str]) -> list[SignalItem]:
        """Load exactly the Store-owned signal identities named by a task."""

        selected = list(dict.fromkeys(value for value in ids if isinstance(value, str)))
        if not selected:
            return []
        with Session(self.engine) as session:
            rows = session.scalars(
                select(SignalItemRow).where(SignalItemRow.id.in_(selected))
            ).all()
            by_id = {
                row.id: row_to_signal_item(row, path_codec=self.path_codec)
                for row in rows
            }
        if set(by_id) != set(selected):
            missing = sorted(set(selected) - set(by_id))
            raise KeyError(f"missing signal item(s): {', '.join(missing)}")
        return [by_id[value] for value in selected]

    get_signal_items = signal_items_by_id

    def selected_signal_items_for_task(self, task_id: str) -> list[SignalItem]:
        """Recover a task's selected signals from metadata and relations.

        The two Store-owned representations must agree.  A task with neither
        representation is genuinely manual; a partial or broken link fails
        closed instead of silently rerunning an unrelated source.
        """

        with Session(self.engine) as session:
            task_row = session.get(TaskRow, task_id)
            if task_row is None:
                raise KeyError(task_id)
            metadata = _metadata_dict(task_row.metadata_json, self.path_codec)
            metadata_present = "selected_signal_item_ids" in metadata
            raw_ids = metadata.get("selected_signal_item_ids")
            if raw_ids is None and not metadata_present:
                metadata_ids: list[str] = []
            elif isinstance(raw_ids, list):
                metadata_ids = list(dict.fromkeys(
                    value for value in raw_ids if isinstance(value, str) and value
                ))
                if len(metadata_ids) != len(raw_ids):
                    raise ValueError("task selected signal metadata is malformed")
            else:
                raise ValueError("task selected signal metadata is malformed")
            relation_rows = session.scalars(
                select(SignalItemRow)
                .where(SignalItemRow.planned_task_id == task_id)
                .order_by(SignalItemRow.created_at, SignalItemRow.id)
            ).all()
            relation_ids = {row.id for row in relation_rows}
            if not metadata_present:
                selected_ids = [row.id for row in relation_rows]
                if not selected_ids:
                    return []
                return [
                    row_to_signal_item(row, path_codec=self.path_codec)
                    for row in relation_rows
                ]

            # A previous live descendant may now own the one mutable coverage
            # pointer.  That is a valid lineage transition; an absent row or
            # an unrelated owner is still a broken source link.
            if not relation_ids.issubset(set(metadata_ids)):
                raise ValueError("task selected signal metadata and relation disagree")
            rows = session.scalars(
                select(SignalItemRow).where(SignalItemRow.id.in_(metadata_ids))
            ).all()
            by_id = {row.id: row for row in rows}
            if set(by_id) != set(metadata_ids):
                missing = sorted(set(metadata_ids) - set(by_id))
                raise ValueError(
                    "task selected signal link is missing: " + ", ".join(missing)
                )
            for row in rows:
                if row.planned_task_id == task_id:
                    continue
                if not row.planned_task_id:
                    raise ValueError("task selected signal link is missing")
                owner = session.get(TaskRow, row.planned_task_id)
                if owner is None:
                    raise ValueError("task selected signal link owner is missing")
                if not self._is_verified_live_rerun_owner(session, owner, task_id):
                    raise ValueError("task selected signal link owner is unrelated")
            return [
                row_to_signal_item(by_id[item_id], path_codec=self.path_codec)
                for item_id in metadata_ids
            ]

    get_selected_signal_items = selected_signal_items_for_task
    task_signal_items = selected_signal_items_for_task

    def allocate_live_rerun(
        self,
        source_task_id: str,
        *,
        selected_signal_ids: Iterable[str] = (),
        selected_signal_items: Iterable[SignalItem] = (),
        stale_signal_ids: Iterable[str] = (),
        stale_reasons: Mapping[str, str] | None = None,
        dedupe_key: str | None = None,
    ) -> LiveRerunAllocation:
        """Allocate one fresh live task and transfer current signal coverage.

        Validation of archive bytes and provider state belongs to the caller;
        this method is the final Store transaction and therefore rechecks task,
        signal ownership, duplicate lineage, and all durable writes together.
        """

        if not isinstance(source_task_id, str) or not source_task_id:
            raise ValueError("source task id is required")
        selected = list(dict.fromkeys(
            value for value in selected_signal_ids if isinstance(value, str)
        ))
        current_items = {
            item.id: item
            for item in selected_signal_items
            if isinstance(item, SignalItem) and item.id in selected
        }
        stale = list(dict.fromkeys(
            value for value in stale_signal_ids if isinstance(value, str)
        ))
        reasons = {
            key: value[:256]
            for key, value in dict(stale_reasons or {}).items()
            if isinstance(key, str) and key in stale and isinstance(value, str)
        }
        lineage_dedupe = dedupe_key or _live_rerun_dedupe_key(source_task_id)
        if not lineage_dedupe:
            raise ValueError("live rerun dedupe key is required")
        wakeup: SchedulerWakeup | None = None
        created = False
        saved: TaskRecord | None = None
        with Session(self.engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                source_row = session.scalar(
                    _task_query().where(TaskRow.id == source_task_id)
                )
                if source_row is None:
                    raise KeyError(source_task_id)
                source_metadata = _metadata_dict(
                    source_row.metadata_json, self.path_codec
                )
                source_mode = execution_mode_from_metadata(source_metadata)
                if source_mode is not ExecutionMode.dry_run:
                    raise ValueError("live rerun source is not dry-run")
                if source_row.status not in {
                    TaskStatus.succeeded.value,
                    TaskStatus.no_changes.value,
                }:
                    raise ValueError("live rerun source is not a successful terminal task")

                active_rows = session.scalars(
                    _task_query().where(
                        TaskRow.status.in_([status.value for status in ACTIVE_STATUSES])
                    )
                ).all()
                existing_row = None
                for candidate in active_rows:
                    if self._is_verified_live_rerun_owner(
                        session, candidate, source_task_id
                    ):
                        existing_row = candidate
                        break
                    if candidate.dedupe_key == lineage_dedupe:
                        raise ValueError("live rerun dedupe key conflicts with another task")
                if existing_row is not None:
                    saved = row_to_task(existing_row, path_codec=self.path_codec)
                else:
                    signal_rows: list[SignalItemRow] = []
                    if selected:
                        signal_rows = session.scalars(
                            select(SignalItemRow).where(
                                SignalItemRow.id.in_(selected)
                            )
                        ).all()
                        if {row.id for row in signal_rows} != set(selected):
                            raise ValueError("live rerun signal identity is missing")
                        if set(current_items) != set(selected):
                            raise ValueError("live rerun signal context is missing")
                        for row in signal_rows:
                            current = current_items[row.id]
                            if current.provider != row.provider or current.kind != row.kind:
                                raise ValueError("live rerun signal context identity disagrees")
                            if row.planned_task_id == source_task_id:
                                continue
                            if not row.planned_task_id:
                                raise ValueError("live rerun signal is not covered by source task")
                            owner = session.get(TaskRow, row.planned_task_id)
                            if owner is None:
                                raise ValueError("live rerun signal owner is missing")
                            if not self._is_verified_live_rerun_owner(
                                session, owner, source_task_id
                            ):
                                raise ValueError("live rerun signal owner is unrelated")
                    if set(selected) & set(stale):
                        raise ValueError("live rerun signal cannot be both actionable and stale")

                    metadata = {
                        key: value
                        for key, value in source_metadata.items()
                        if key not in _LIVE_RERUN_METADATA_DROP_KEYS
                    }
                    metadata[DRY_RUN_OF_TASK_ID_METADATA_KEY] = source_task_id
                    metadata["dedupe_key"] = lineage_dedupe
                    metadata["selected_signal_item_ids"] = list(selected)
                    if signal_rows:
                        # Signal rows retain historical provider payloads.  Only
                        # items freshly returned by strict provider revalidation
                        # may become live worker context.
                        metadata["source_context"] = {
                            "selected_signal_item_ids": list(selected),
                        }
                        metadata["source_context"]["selected_signal_items"] = [
                            current_items[item_id].model_dump(mode="json")
                            for item_id in selected
                        ]
                        metadata["evidence"] = list(selected)
                    else:
                        metadata.pop("selected_signal_item_ids", None)
                        metadata.pop("evidence", None)
                    metadata[EXECUTION_MODE_METADATA_KEY] = ExecutionMode.live.value
                    task_id = new_task_id()
                    spec = TaskSpec(
                        id=task_id,
                        kind=source_row.kind,
                        workflow=source_row.workflow,
                        worker=source_row.worker,
                        title=source_row.title,
                        prompt=source_row.prompt,
                        priority=source_row.priority,
                        risk=source_row.risk,
                        source="rerun-live",
                        allow_main_write=source_row.allow_main_write,
                        metadata=metadata,
                    )
                    now = utc_now()
                    record = TaskRecord(
                        spec=spec,
                        status=TaskStatus.queued,
                        created_at=now,
                        updated_at=now,
                    )
                    execution = TaskExecution(
                        id=new_execution_id(),
                        task_id=task_id,
                        created_at=now,
                        updated_at=now,
                    )
                    pipeline = TaskPipeline(
                        id=new_pipeline_id(),
                        task_id=task_id,
                        execution_id=execution.id,
                        ordinal=1,
                        trigger="initial",
                        started_at=now,
                        updated_at=now,
                    )
                    session.add(
                        task_to_row(
                            record,
                            dedupe_key=lineage_dedupe,
                            path_codec=self.path_codec,
                        )
                    )
                    session.add(
                        event_to_row(
                            Event(
                                task_id=task_id,
                                kind="task.created",
                                message=record.spec.title,
                                data={
                                    "source": "rerun-live",
                                    "dry_run_of_task_id": source_task_id,
                                },
                            ),
                            path_codec=self.path_codec,
                        )
                    )
                    session.add(
                        event_to_row(
                            Event(
                                task_id=task_id,
                                kind="task.live_rerun",
                                message="live task allocated from verified dry-run source",
                                data={
                                    "source_task_id": source_task_id,
                                    "selected_signal_ids": list(selected),
                                    "stale_signal_ids": list(stale),
                                    "stale_reasons": reasons,
                                },
                            ),
                            path_codec=self.path_codec,
                        )
                    )
                    session.flush()
                    execution_row = execution_to_row(
                        execution, path_codec=self.path_codec
                    )
                    pipeline_row = pipeline_to_row(pipeline)
                    session.add(execution_row)
                    session.flush()
                    session.add(pipeline_row)
                    session.flush()
                    execution_row.owning_pipeline_id = pipeline.id
                    now_text = now.isoformat()
                    for row in signal_rows:
                        row.planned_task_id = task_id
                        row.updated_at = now_text
                    raw_connection = session.connection().connection.driver_connection
                    raw_connection.row_factory = sqlite3.Row
                    canonical_signal_ids: list[str] = []
                    for row in signal_rows:
                        canonical = raw_connection.execute(
                            "SELECT signal_id FROM control_loop_signals "
                            "WHERE epoch_id=? AND provider=? AND fingerprint=?",
                            (self.control_loop.epoch_id, row.provider, row.fingerprint),
                        ).fetchone()
                        if canonical is None:
                            raise ValueError("live rerun control-loop signal identity is missing")
                        canonical_id = str(canonical[0])
                        canonical_signal_ids.append(canonical_id)
                        self.control_loop._edge(
                            raw_connection, "signal_task", canonical_id, task_id
                        )
                    self.control_loop._edge(
                        raw_connection, "task_rerun", source_task_id, task_id
                    )
                    wakeup = SchedulerWakeup(
                        reason="task.live_rerun",
                        data={
                            "source_task_id": source_task_id,
                            "task_id": task_id,
                            "signal_ids": canonical_signal_ids,
                            "retained_signal_count": len(selected),
                            "stale_signal_count": len(stale),
                        },
                    )
                    self._record_wakeup_in_session(session, wakeup)
                    session.commit()
                    saved = record
                    created = True
            except Exception:
                session.rollback()
                raise
        if created:
            self._notify_change()
        assert saved is not None
        return LiveRerunAllocation(task=saved, created=created, wakeup=wakeup)

    create_live_rerun = allocate_live_rerun
    rerun_live_task = allocate_live_rerun
    allocate_live_task_rerun = allocate_live_rerun
    create_live_rerun_task = allocate_live_rerun
    enqueue_live_rerun = allocate_live_rerun

    def add_task(
        self, spec: TaskSpec, *, dedupe_key: str | None = None
    ) -> tuple[TaskRecord, bool]:
        self._ensure_archive_epoch()
        metadata = dict(spec.metadata)
        # The aggregate is Store-owned and cannot be pre-seeded by a caller.
        metadata.pop(EFFECT_RESULT_METADATA_KEY, None)
        metadata.pop(LEGACY_EFFECT_RESULT_METADATA_KEY, None)
        if dedupe_key is not None:
            existing = self.find_active_dedupe(dedupe_key)
            if existing is not None:
                return existing, False
            metadata["dedupe_key"] = dedupe_key
        metadata[EXECUTION_MODE_METADATA_KEY] = execution_mode_for_dry_run(
            self._startup_dry_run
        ).value
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
            existing = self.find_active_dedupe(dedupe_key)
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
    # Daemon lifecycle ownership

    def get_daemon_state(self) -> dict[str, object] | None:
        with Session(self.engine) as session:
            row = session.get(DaemonStateRow, "daemon")
            if row is None:
                return None
            try:
                value = json.loads(row.state_json)
            except (TypeError, json.JSONDecodeError):
                value = {}
            return {
                "instance_id": row.instance_id,
                "lifecycle": row.lifecycle,
                "updated_at": row.updated_at,
                **(value if isinstance(value, dict) else {}),
            }

    def claim_daemon_instance(
        self, instance_id: str, *, lifecycle: str = "starting", state: dict[str, object] | None = None
    ) -> dict[str, object]:
        if not instance_id or len(instance_id) > 128:
            raise ValueError("daemon instance identity is invalid")
        now = utc_now().isoformat()
        payload = dict(state or {})
        payload.pop("provider_session_id", None)
        payload.pop("private_home_path", None)
        with Session(self.engine) as session, session.begin():
            row = session.get(DaemonStateRow, "daemon")
            if row is None:
                row = DaemonStateRow(
                    id="daemon", instance_id=instance_id, lifecycle=lifecycle,
                    state_json=json.dumps(payload, sort_keys=True), updated_at=now,
                )
                session.add(row)
            else:
                row.instance_id = instance_id
                row.lifecycle = lifecycle
                row.state_json = json.dumps(payload, sort_keys=True)
                row.updated_at = now
        self._notify_change()
        return self.get_daemon_state() or {"instance_id": instance_id, "lifecycle": lifecycle}

    def set_daemon_lifecycle(
        self, lifecycle: str, *, instance_id: str | None = None, state: dict[str, object] | None = None
    ) -> dict[str, object]:
        current = self.get_daemon_state() or {}
        selected_instance = instance_id or str(current.get("instance_id") or "")
        if not selected_instance:
            selected_instance = "unknown"
        payload = dict(current)
        payload.update(state or {})
        payload.pop("instance_id", None)
        payload.pop("lifecycle", None)
        payload.pop("updated_at", None)
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.get(DaemonStateRow, "daemon")
            if row is None:
                row = DaemonStateRow(id="daemon")
                session.add(row)
            row.instance_id = selected_instance
            row.lifecycle = lifecycle
            row.state_json = json.dumps(payload, sort_keys=True)
            row.updated_at = now
        self._notify_change()
        return self.get_daemon_state() or {}

    # ------------------------------------------------------------------
    # Steward 2.0 normalized execution ledger

    @staticmethod
    def _require_execution_owner(
        session: Session,
        task_id: str,
        *,
        execution_id: str | None = None,
        pipeline_id: str | None = None,
    ) -> tuple[TaskExecutionRow, TaskPipelineRow]:
        execution = (
            session.get(TaskExecutionRow, execution_id)
            if execution_id is not None
            else session.scalar(
                select(TaskExecutionRow).where(TaskExecutionRow.task_id == task_id)
            )
        )
        if execution is None or execution.task_id != task_id:
            raise TaskLedgerOwnershipError("task execution does not belong to task")
        owner_id = execution.owning_pipeline_id
        if owner_id is None:
            raise TaskLedgerOwnershipError("task execution has no owning pipeline")
        owner = session.get(TaskPipelineRow, owner_id)
        if (
            owner is None
            or owner.task_id != task_id
            or owner.execution_id != execution.id
        ):
            raise TaskLedgerOwnershipError("task execution owner is invalid")
        selected_id = pipeline_id or owner_id
        selected = session.get(TaskPipelineRow, selected_id)
        if (
            selected is None
            or selected.task_id != task_id
            or selected.execution_id != execution.id
        ):
            raise TaskLedgerOwnershipError(
                "pipeline does not belong to task execution"
            )
        if pipeline_id is not None and pipeline_id != owner_id:
            raise TaskLedgerOwnershipError(
                "pipeline is not the current execution owner"
            )
        return execution, selected

    @staticmethod
    def _require_execution_owner_connection(
        connection: Connection,
        task_id: str,
        *,
        execution_id: str | None = None,
        pipeline_id: str | None = None,
    ) -> tuple[Mapping[str, object], Mapping[str, object]]:
        execution_statement = select(
            TaskExecutionRow.id,
            TaskExecutionRow.task_id,
            TaskExecutionRow.owning_pipeline_id,
        )
        if execution_id is not None:
            execution_statement = execution_statement.where(
                TaskExecutionRow.id == execution_id
            )
        else:
            execution_statement = execution_statement.where(
                TaskExecutionRow.task_id == task_id
            )
        execution = connection.execute(execution_statement).mappings().first()
        if execution is None or execution["task_id"] != task_id:
            raise TaskLedgerOwnershipError("task execution does not belong to task")
        owner_id = execution["owning_pipeline_id"]
        owner = (
            connection.execute(
                select(
                    TaskPipelineRow.id,
                    TaskPipelineRow.task_id,
                    TaskPipelineRow.execution_id,
                ).where(
                    TaskPipelineRow.id == owner_id,
                    TaskPipelineRow.task_id == task_id,
                    TaskPipelineRow.execution_id == execution["id"],
                )
            )
            .mappings()
            .first()
            if owner_id is not None
            else None
        )
        if owner is None:
            raise TaskLedgerOwnershipError("task execution has no owning pipeline")
        selected_id = pipeline_id if pipeline_id is not None else owner_id
        selected = connection.execute(
            select(
                TaskPipelineRow.id,
                TaskPipelineRow.task_id,
                TaskPipelineRow.execution_id,
            ).where(
                TaskPipelineRow.id == selected_id,
                TaskPipelineRow.task_id == task_id,
                TaskPipelineRow.execution_id == execution["id"],
            )
        ).mappings().first()
        if selected is None:
            raise TaskLedgerOwnershipError(
                "pipeline does not belong to task execution"
            )
        if pipeline_id is not None and pipeline_id != owner_id:
            raise TaskLedgerOwnershipError(
                "pipeline is not the current execution owner"
            )
        return execution, selected

    @staticmethod
    def _merge_provider_session_id(
        session_row: CodexSessionRow,
        provider_session_id: str,
        now: str,
    ) -> None:
        if (
            session_row.provider_session_id is not None
            and session_row.provider_session_id != provider_session_id
        ):
            raise ValueError("provider session identity conflicts with persisted value")
        if session_row.provider_session_id is None:
            session_row.provider_session_id = provider_session_id
            session_row.updated_at = now

    @classmethod
    def _activate_run_ownership_connection(
        cls, connection: Connection, item: TaskRun
    ) -> None:
        now = item.updated_at.isoformat()
        execution, _ = cls._require_execution_owner_connection(
            connection,
            item.task_id,
            pipeline_id=item.pipeline_id,
        )
        session_row = connection.execute(
            select(
                CodexSessionRow.id,
                CodexSessionRow.task_id,
                CodexSessionRow.pipeline_id,
            ).where(CodexSessionRow.id == item.session_id)
        ).mappings().first()
        if (
            session_row is None
            or session_row["task_id"] != item.task_id
            or session_row["pipeline_id"] != item.pipeline_id
        ):
            raise TaskLedgerOwnershipError("run session ownership is invalid")
        connection.execute(
            CodexSessionRow.__table__
            .update()
            .where(CodexSessionRow.id == item.session_id)
            .values(state="active", updated_at=now)
        )
        connection.execute(
            TaskExecutionRow.__table__
            .update()
            .where(TaskExecutionRow.id == execution["id"])
            .values(
                owning_pipeline_id=item.pipeline_id,
                active_session_id=item.session_id,
                active_run_id=item.id,
                updated_at=now,
            )
        )

    def validate_execution_ownership(
        self, task_id: str, *, pipeline_id: str | None = None
    ) -> None:
        """Validate execution and selected pipeline ownership without mutation."""

        with Session(self.engine) as session:
            self._require_execution_owner(
                session,
                task_id,
                pipeline_id=pipeline_id,
            )

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

    @classmethod
    def _validate_execution_ownership(
        cls,
        session: Session,
        execution: TaskExecutionRow,
        *,
        pipeline_id: str | None,
        session_id: str | None,
        run_id: str | None,
    ) -> None:
        _, selected_pipeline = cls._require_execution_owner(
            session,
            execution.task_id,
            execution_id=execution.id,
            pipeline_id=pipeline_id,
        )
        selected_session_id = session_id or execution.active_session_id
        if session_id is not None:
            session_row = session.get(CodexSessionRow, session_id)
            if (
                session_row is None
                or session_row.task_id != execution.task_id
                or session_row.pipeline_id != selected_pipeline.id
            ):
                raise ValueError("execution session does not belong to task pipeline")
        if run_id is not None:
            run = session.get(TaskRunRow, run_id)
            if (
                run is None
                or run.task_id != execution.task_id
                or run.pipeline_id != selected_pipeline.id
                or run.session_id != selected_session_id
            ):
                raise ValueError("execution run does not belong to task session")

    def list_executions(self, task_id: str) -> list[TaskExecution]:
        try:
            return [self.get_execution(task_id)]
        except KeyError:
            return []

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
        normalized_fields = _pipeline_fields(fields)
        with Session(self.engine) as session:
            execution, _ = self._require_execution_owner(
                session,
                task_id,
                execution_id=execution_id,
                pipeline_id=parent_pipeline_id,
            )
            if parent_pipeline_id is not None:
                parent = session.get(TaskPipelineRow, parent_pipeline_id)
                if (
                    parent is None
                    or parent.task_id != task_id
                    or parent.execution_id != execution.id
                ):
                    raise ValueError(
                        "parent pipeline must belong to the same task execution"
                    )
        return self._insert_pipeline(
            task_id,
            execution.id,
            pipeline_id=pipeline_id,
            trigger=trigger,
            parent_pipeline_id=parent_pipeline_id,
            ordinal=ordinal,
            **normalized_fields,
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
                    self._require_execution_owner_connection(
                        connection,
                        task_id,
                        execution_id=execution_id,
                        pipeline_id=parent_pipeline_id,
                    )
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
                    connection.execute(
                        TaskPipelineRow.__table__.insert().values(
                            **_row_values(pipeline_to_row(item))
                        )
                    )
                    connection.execute(
                        TaskExecutionRow.__table__.update()
                        .where(TaskExecutionRow.id == execution_id)
                        .values(
                            owning_pipeline_id=item.id,
                            updated_at=item.updated_at.isoformat(),
                        )
                    )
                    connection.exec_driver_sql("COMMIT")
                    return item
            except IntegrityError:
                if attempt == 7:
                    raise
                time.sleep(0.005 * (attempt + 1))
        raise RuntimeError("pipeline allocation failed")

    def list_pipelines(self, task_id: str) -> list[TaskPipeline]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(TaskPipelineRow)
                .where(TaskPipelineRow.task_id == task_id)
                .order_by(TaskPipelineRow.ordinal, TaskPipelineRow.id)
            ).all()
            return [row_to_pipeline(row) for row in rows]

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
            execution, _ = self._require_execution_owner(
                session,
                row.task_id,
                execution_id=row.execution_id,
                pipeline_id=row.id,
            )
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
            execution.owning_pipeline_id = row.id
            if phase is not None:
                execution.current_phase = phase
            execution.updated_at = now
        return self.get_pipeline(pipeline_id)

    def update_pipeline_identity(
        self,
        pipeline_id: str,
        *,
        base_identity: str | None = None,
        input_identity: str | None = None,
        output_identity: str | None = None,
        patch_identity: str | None = None,
        phase: PipelinePhase | str | None = None,
        expected_tree: str | None = None,
        worktree_path: Path | None = None,
    ) -> TaskPipeline:
        """Persist pipeline identities and their execution mirrors atomically."""

        with Session(self.engine) as session, session.begin():
            row = session.get(TaskPipelineRow, pipeline_id)
            if row is None:
                raise KeyError(pipeline_id)
            execution, _ = self._require_execution_owner(
                session,
                row.task_id,
                execution_id=row.execution_id,
                pipeline_id=row.id,
            )
            if not any(
                value is not None
                for value in (
                    base_identity,
                    input_identity,
                    output_identity,
                    patch_identity,
                    phase,
                    expected_tree,
                    worktree_path,
                )
            ):
                return row_to_pipeline(row)

            now = utc_now().isoformat()
            if base_identity is not None:
                row.base_identity = base_identity
                execution.base_commit = base_identity
            if input_identity is not None:
                row.input_identity = input_identity
            if output_identity is not None:
                row.output_identity = output_identity
            if patch_identity is not None:
                row.patch_identity = patch_identity
            if phase is not None:
                row.phase = str(phase)
            if expected_tree is not None:
                execution.expected_tree = expected_tree
            if worktree_path is not None:
                execution.worktree_path = self.path_codec.dump(worktree_path)
            row.updated_at = now
            execution.updated_at = now
        return self.get_pipeline(pipeline_id)

    def create_session(
        self,
        task_id: str,
        pipeline_id: str,
        *,
        session_id: str | None = None,
        provider_session_id: str | None = None,
        private_home_path: Path | None = None,
        private_home_relative_path: str | None = None,
        home_uid: int | None = None,
        image_digest: str | None = None,
        codex_identity: str | None = None,
        cwd: Path | None = None,
        checkpoint_id: str | None = None,
        provider_store_identity: str | None = None,
        owner_role: str | None = None,
        idempotency_key: str | None = None,
        archive_generation: int = 0,
    ) -> CodexSession:
        pipeline = self.get_pipeline(pipeline_id)
        if pipeline.task_id != task_id:
            raise ValueError("session pipeline does not belong to task")
        with Session(self.engine) as session:
            self._require_execution_owner(
                session,
                task_id,
                pipeline_id=pipeline_id,
            )

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
        for attempt in range(8):
            try:
                with self.engine.connect() as connection:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                    selected_uid = home_uid
                    if selected_uid is None:
                        selected_uid = connection.execute(
                            select(func.coalesce(func.max(CodexSessionRow.home_uid), 9999) + 1)
                        ).scalar_one()
                    if not isinstance(selected_uid, int) or not 10000 <= selected_uid <= 60000:
                        connection.exec_driver_sql("ROLLBACK")
                        raise ValueError("session home UID allocation exhausted")
                    item = CodexSession(
                        id=session_id or new_session_id(),
                        task_id=task_id,
                        pipeline_id=pipeline_id,
                        provider_session_id=provider_session_id,
                        private_home_path=private_home_path,
                        private_home_relative_path=private_home_relative_path,
                        home_uid=selected_uid,
                        image_digest=image_digest,
                        codex_identity=codex_identity,
                        cwd=cwd,
                        checkpoint_id=checkpoint_id,
                        provider_store_identity=provider_store_identity,
                        owner_role=owner_role,
                        idempotency_key=idempotency_key,
                        archive_generation=archive_generation,
                        started_at=now,
                        updated_at=now,
                    )
                    connection.execute(
                        CodexSessionRow.__table__.insert().values(
                            **_row_values(session_to_row(item, path_codec=self.path_codec))
                        )
                    )
                    connection.exec_driver_sql("COMMIT")
                    return item
            except IntegrityError:
                existing = existing_idempotent_session()
                if existing is not None:
                    return existing
                if home_uid is not None or attempt == 7:
                    raise
                time.sleep(0.005 * (attempt + 1))
        raise RuntimeError("session allocation failed")

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

    def create_session_with_run(
        self,
        task_id: str,
        pipeline_id: str,
        *,
        session_id: str,
        private_home_path: Path,
        private_home_relative_path: str,
        image_digest: str,
        codex_identity: str,
        cwd: Path,
        checkpoint_id: str | None,
        provider_store_identity: str,
        owner_role: str,
        session_idempotency_key: str | None,
        role: str,
        model: str | None,
        reasoning: str | None,
        image_version: str,
        runtime_version: str,
        run_checkpoint_id: str | None,
        run_provider_store_identity: str,
        run_id: str | None = None,
        retry_of_run_id: str | None = None,
    ) -> tuple[CodexSession, TaskRun]:
        """Allocate a session UID and its mandatory first run atomically."""

        pipeline = self.get_pipeline(pipeline_id)
        if pipeline.task_id != task_id:
            raise ValueError("session pipeline does not belong to task")
        with Session(self.engine) as session:
            self._require_execution_owner(
                session,
                task_id,
                pipeline_id=pipeline_id,
            )
        if retry_of_run_id is not None:
            predecessor = self.get_run(retry_of_run_id)
            if (
                predecessor.task_id != task_id
                or predecessor.pipeline_id != pipeline_id
            ):
                raise ValueError(
                    "retry run must belong to the same task and pipeline"
                )

        def existing_allocation() -> tuple[CodexSession, TaskRun] | None:
            if session_idempotency_key is None:
                return None
            with Session(self.engine) as query_session:
                session_row = query_session.scalar(
                    select(CodexSessionRow).where(
                        CodexSessionRow.task_id == task_id,
                        CodexSessionRow.idempotency_key == session_idempotency_key,
                    )
                )
                if session_row is None:
                    return None
                if session_row.pipeline_id != pipeline_id:
                    raise ValueError(
                        "session idempotency key belongs to another pipeline"
                    )
                run_row = query_session.scalar(
                    select(TaskRunRow)
                    .where(TaskRunRow.session_id == session_row.id)
                    .order_by(TaskRunRow.role_ordinal, TaskRunRow.id)
                )
                if run_row is None:
                    raise RuntimeError("session allocation is missing its first run")
                if run_row.role != role:
                    raise ValueError("session idempotency key conflicts with role")
                if run_row.retry_of_run_id != retry_of_run_id:
                    raise ValueError(
                        "session idempotency key conflicts with retry lineage"
                    )
                return (
                    row_to_session(session_row, path_codec=self.path_codec),
                    row_to_run(run_row),
                )

        existing = existing_allocation()
        if existing is not None:
            return existing
        now = utc_now()
        for attempt in range(8):
            try:
                with self.engine.connect() as connection:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                    self._require_execution_owner_connection(
                        connection,
                        task_id,
                        pipeline_id=pipeline_id,
                    )
                    selected_uid = connection.execute(
                        select(func.coalesce(func.max(CodexSessionRow.home_uid), 9999) + 1)
                    ).scalar_one()
                    if not isinstance(selected_uid, int) or not 10000 <= selected_uid <= 60000:
                        connection.exec_driver_sql("ROLLBACK")
                        raise ValueError("session home UID allocation exhausted")
                    ordinal = connection.execute(
                        select(func.coalesce(func.max(TaskRunRow.role_ordinal), 0) + 1).where(
                            TaskRunRow.pipeline_id == pipeline_id,
                            TaskRunRow.role == role,
                        )
                    ).scalar_one()
                    session_item = CodexSession(
                        id=session_id,
                        task_id=task_id,
                        pipeline_id=pipeline_id,
                        private_home_path=private_home_path,
                        private_home_relative_path=private_home_relative_path,
                        home_uid=selected_uid,
                        image_digest=image_digest,
                        codex_identity=codex_identity,
                        cwd=cwd,
                        checkpoint_id=checkpoint_id,
                        provider_store_identity=provider_store_identity,
                        owner_role=owner_role,
                        idempotency_key=session_idempotency_key,
                        started_at=now,
                        updated_at=now,
                    )
                    run_item = TaskRun(
                        id=run_id or new_run_id(),
                        task_id=task_id,
                        pipeline_id=pipeline_id,
                        session_id=session_id,
                        role=role,
                        role_ordinal=int(ordinal),
                        retry_of_run_id=retry_of_run_id,
                        model=model,
                        reasoning=reasoning,
                        image_version=image_version,
                        runtime_version=runtime_version,
                        checkpoint_id=run_checkpoint_id,
                        provider_store_identity=run_provider_store_identity,
                        started_at=now,
                        updated_at=now,
                    )
                    connection.execute(
                        CodexSessionRow.__table__.insert().values(
                            **_row_values(
                                session_to_row(session_item, path_codec=self.path_codec)
                            )
                        )
                    )
                    connection.execute(
                        TaskRunRow.__table__.insert().values(
                            **_row_values(run_to_row(run_item))
                        )
                    )
                    self._activate_run_ownership_connection(connection, run_item)
                    connection.exec_driver_sql("COMMIT")
                    return session_item, run_item
            except IntegrityError:
                existing = existing_allocation()
                if existing is not None:
                    return existing
                if attempt == 7:
                    raise
                time.sleep(0.005 * (attempt + 1))
        raise RuntimeError("session and first-run allocation failed")

    def update_session(self, session_id: str, **fields: object) -> CodexSession:
        allowed = {
            "provider_session_id",
            "private_home_path",
            "private_home_relative_path",
            "home_uid",
            "image_digest",
            "codex_identity",
            "cwd",
            "checkpoint_id",
            "provider_store_identity",
            "owner_role",
            "state",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported session fields: {sorted(unknown)}")
        with Session(self.engine) as session, session.begin():
            row = session.get(CodexSessionRow, session_id)
            if row is None:
                raise KeyError(session_id)
            for key, value in fields.items():
                if key in {"private_home_path", "cwd"}:
                    value = (
                        self.path_codec.dump(Path(value))
                        if value is not None
                        else None
                    )
                setattr(row, key, value)
            row.updated_at = utc_now().isoformat()
        return self.get_session(session_id)

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
        normalized_fields = _run_fields(fields)
        pipeline = self.get_pipeline(pipeline_id)
        if pipeline.task_id != task_id:
            raise ValueError("run pipeline does not belong to task")
        session = self.get_session(session_id)
        if session.task_id != task_id or session.pipeline_id != pipeline_id:
            raise ValueError("run session does not belong to task pipeline")
        with Session(self.engine) as ownership_session:
            self._require_execution_owner(
                ownership_session,
                task_id,
                pipeline_id=pipeline_id,
            )
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
            if predecessor.role not in {
                "planner",
                "planning",
                "implementation",
                "reviewer",
                "review",
            }:
                raise ValueError("only planning, implementation, or review runs can resume")
            if role != predecessor.role:
                raise ValueError("recovery run role does not match predecessor")
            if predecessor.session_id != session_id:
                raise ValueError("a recovery run must reuse the interrupted session")
            expected_image = normalized_fields.get("image_version")
            expected_runtime = normalized_fields.get("runtime_version")
            if predecessor.image_version != expected_image:
                raise ValueError("recovery run image version does not match predecessor")
            if predecessor.runtime_version != expected_runtime:
                raise ValueError("recovery run runtime version does not match predecessor")
            expected_checkpoint = normalized_fields.get("checkpoint_id")
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
                    self._require_execution_owner_connection(
                        connection,
                        task_id,
                        pipeline_id=pipeline_id,
                    )
                    session_row = connection.execute(
                        select(
                            CodexSessionRow.task_id,
                            CodexSessionRow.pipeline_id,
                        ).where(CodexSessionRow.id == session_id)
                    ).mappings().first()
                    if (
                        session_row is None
                        or session_row["task_id"] != task_id
                        or session_row["pipeline_id"] != pipeline_id
                    ):
                        raise TaskLedgerOwnershipError(
                            "run session ownership is invalid"
                        )
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
                        **normalized_fields,
                        started_at=now,
                        updated_at=now,
                    )
                    connection.execute(TaskRunRow.__table__.insert().values(**_row_values(run_to_row(item))))
                    self._activate_run_ownership_connection(connection, item)
                    connection.exec_driver_sql("COMMIT")
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

    def running_runs(
        self, *, task_id: str | None = None, limit: int | None = None
    ) -> list[TaskRun]:
        """Return every currently running run in stable start/id order."""

        statement = select(TaskRunRow).where(
            TaskRunRow.state == CodexRunState.running.value
        )
        if task_id is not None:
            statement = statement.where(TaskRunRow.task_id == task_id)
        statement = statement.order_by(TaskRunRow.started_at, TaskRunRow.id)
        if limit is not None:
            if limit < 0:
                raise ValueError("running run limit must not be negative")
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            rows = session.scalars(statement).all()
            return [row_to_run(row) for row in rows]

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
        provider_session_id: str | None = None,
        checkpoint_id: str | None = None,
    ) -> TaskRun:
        valid_states = {item.value for item in CodexRunState}
        if state not in valid_states:
            raise ValueError(f"invalid run state {state!r}")
        now = utc_now().isoformat()
        cas_error: ValueError | None = None
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            if expected_state is not None and row.state != expected_state:
                if (
                    row.state == CodexRunState.running.value
                    or provider_session_id is None
                ):
                    raise ValueError(
                        f"run compare-and-set failed: expected {expected_state}, found {row.state}"
                    )
                execution, _ = self._require_execution_owner(
                    session,
                    row.task_id,
                    pipeline_id=row.pipeline_id,
                )
                session_row = session.get(CodexSessionRow, row.session_id)
                if (
                    session_row is None
                    or session_row.task_id != row.task_id
                    or session_row.pipeline_id != row.pipeline_id
                ):
                    raise TaskLedgerOwnershipError("run session ownership is invalid")
                self._merge_provider_session_id(session_row, provider_session_id, now)
                cas_error = ValueError(
                    f"run compare-and-set failed: expected {expected_state}, found {row.state}"
                )
            else:
                if row.state != CodexRunState.running.value and state != row.state:
                    raise ValueError("terminal run is immutable")
                execution, _ = self._require_execution_owner(
                    session,
                    row.task_id,
                    pipeline_id=row.pipeline_id,
                )
                session_row = session.get(CodexSessionRow, row.session_id)
                if (
                    session_row is None
                    or session_row.task_id != row.task_id
                    or session_row.pipeline_id != row.pipeline_id
                ):
                    raise TaskLedgerOwnershipError("run session ownership is invalid")
                if row.state == state and row.state != CodexRunState.running.value:
                    if provider_session_id is not None:
                        self._merge_provider_session_id(
                            session_row, provider_session_id, now
                        )
                    if checkpoint_id is not None:
                        session_row.checkpoint_id = checkpoint_id
                        session_row.updated_at = now
                        row.checkpoint_id = checkpoint_id
                    if (
                        execution.active_run_id == row.id
                        or (
                            execution.active_run_id is None
                            and execution.active_session_id == row.session_id
                        )
                    ):
                        execution.active_run_id = None
                        execution.active_session_id = None
                        execution.updated_at = now
                else:
                    if provider_session_id is not None:
                        self._merge_provider_session_id(
                            session_row, provider_session_id, now
                        )
                    if checkpoint_id is not None:
                        session_row.checkpoint_id = checkpoint_id
                        session_row.updated_at = now
                        row.checkpoint_id = checkpoint_id
                    row.state = state
                    row.updated_at = now
                    if exit_code is not None:
                        row.exit_code = exit_code
                    row.exit_signal = exit_signal
                    row.exit_reason = exit_reason
                    row.result_summary = result_summary
                    row.completed_at = None if state == CodexRunState.running.value else now
                    if state == CodexRunState.interrupted.value:
                        session_row.state = "interrupted"
                        session_row.updated_at = now
                    if state != CodexRunState.running.value and (
                        execution.active_run_id == row.id
                        or (
                            execution.active_run_id is None
                            and execution.active_session_id == row.session_id
                        )
                    ):
                        execution.active_run_id = None
                        execution.active_session_id = None
                        execution.updated_at = now
        if cas_error is not None:
            raise cas_error
        return self.get_run(run_id)

    def mark_run_interrupted(self, run_id: str, *, reason: str | None = None) -> TaskRun:
        return self.transition_run(
            run_id,
            CodexRunState.interrupted.value,
            expected_state=CodexRunState.running.value,
            exit_reason=reason,
        )

    def restart_run(self, run_id: str, *, reason: str = "resume retry") -> TaskRun:
        """Re-arm one persisted recovery run for a bounded provider retry."""

        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            if row.resume_of_run_id is None:
                raise ValueError("only a session recovery run can be restarted")
            execution, _ = self._require_execution_owner(
                session,
                row.task_id,
                pipeline_id=row.pipeline_id,
            )
            session_row = session.get(CodexSessionRow, row.session_id)
            if (
                session_row is None
                or session_row.task_id != row.task_id
                or session_row.pipeline_id != row.pipeline_id
            ):
                raise TaskLedgerOwnershipError("run session ownership is invalid")
            row.state = CodexRunState.running.value
            row.exit_code = None
            row.exit_signal = None
            row.exit_reason = reason
            row.result_summary = None
            row.completed_at = None
            row.updated_at = now
            session_row.state = "active"
            session_row.closed_at = None
            session_row.updated_at = now
            execution.owning_pipeline_id = row.pipeline_id
            execution.active_session_id = row.session_id
            execution.active_run_id = row.id
            execution.updated_at = now
        return self.get_run(run_id)

    def update_run(self, run_id: str, **fields: object) -> TaskRun:
        allowed = {
            "provider_run_id",
            "provider_store_identity",
            "wrapper_pid",
            "exec_identity",
            "exit_code",
            "exit_signal",
            "exit_reason",
            "result_summary",
            "checkpoint_id",
            "parent_run_id",
            "retry_of_run_id",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported run fields: {sorted(unknown)}")
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            for key, value in fields.items():
                if key in {"parent_run_id", "retry_of_run_id"} and value is not None:
                    related = session.get(TaskRunRow, str(value))
                    if related is None or related.task_id != row.task_id or related.pipeline_id != row.pipeline_id:
                        raise ValueError(f"{key} must reference the same task pipeline")
                setattr(row, key, value)
            row.updated_at = utc_now().isoformat()
        return self.get_run(run_id)

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
            _, _ = self._require_execution_owner(
                session,
                checkpoint.task_id,
                execution_id=checkpoint.execution_id,
                pipeline_id=checkpoint.owning_pipeline_id,
            )
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
            self._require_execution_owner(session, record.id)
            row.validations.clear()
            session.flush()
            update_task_row(
                row,
                record,
                path_codec=self.path_codec,
                execution_mode=execution_mode_for_dry_run(self._startup_dry_run),
            )
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
            self._require_execution_owner(session, task_id)
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
            self._require_execution_owner(session, task_id)
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

    def claim_pipeline_action(
        self,
        task_id: str,
        pipeline_id: str,
        phase: PipelineCursorPhase | str,
        action_id: str,
        data: dict[str, object],
    ) -> bool:
        """Atomically record one pipeline phase action claim.

        A phase may have only one active action, while an action that already
        finished cannot be claimed again.  Interrupted actions remain
        claimable so deterministic recovery can retry them.
        """

        normalized_phase = PipelineCursorPhase(phase).value
        event = Event(
            task_id=task_id,
            kind="pipeline.phase.started",
            message=normalized_phase,
            data=data,
        )
        row = event_to_row(event, path_codec=self.path_codec)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                records = connection.execute(
                    select(EventRow.kind, EventRow.data_json).where(
                        EventRow.task_id == task_id,
                        EventRow.kind.in_(
                            (
                                "pipeline.phase.started",
                                "pipeline.phase.finished",
                                "pipeline.phase.interrupted",
                            )
                        ),
                    )
                ).all()
                states: dict[str, str] = {}
                for kind, data_json in records:
                    try:
                        payload = json.loads(data_json)
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if payload.get("pipeline_id") != pipeline_id:
                        continue
                    if (
                        kind == "pipeline.phase.started"
                        and payload.get("phase") == normalized_phase
                    ):
                        claimed = payload.get("action_id")
                        if claimed:
                            states[str(claimed)] = "active"
                    elif kind == "pipeline.phase.finished":
                        completed = payload.get("output", {}).get("action_id")
                        if completed:
                            states[str(completed)] = "finished"
                    elif kind == "pipeline.phase.interrupted":
                        interrupted = payload.get("action_id")
                        if interrupted:
                            states[str(interrupted)] = "interrupted"
                if any(state == "active" for state in states.values()) or states.get(
                    action_id
                ) == "finished":
                    connection.rollback()
                    return False
                connection.execute(
                    EventRow.__table__.insert().values(
                        task_id=row.task_id,
                        kind=row.kind,
                        message=row.message,
                        created_at=row.created_at,
                        data_json=row.data_json,
                    )
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self._notify_change()
        return True

    def add_signal_fetch_run(
        self, run: SignalFetchRun, *, _session: Session | None = None
    ) -> None:
        if _session is not None:
            _session.add(signal_fetch_run_to_row(run))
            return
        with Session(self.engine) as session, session.begin():
            session.add(signal_fetch_run_to_row(run))
        self._notify_change()

    @property
    def control_loop(self) -> ControlLoopLedger:
        return self._control_loop

    @property
    def control_loop_ledger(self) -> ControlLoopLedger:
        return self._control_loop

    def _record_wakeup_in_session(
        self, session: Session, wakeup: SchedulerWakeup
    ) -> None:
        session.add(scheduler_wakeup_to_row(wakeup, path_codec=self.path_codec))
        session.flush()
        raw_connection = session.connection().connection.driver_connection
        raw_connection.row_factory = sqlite3.Row
        data = wakeup.data
        input_signal_values = data.get(
            "signal_ids", data.get("input_signal_ids", [])
        )
        input_signal_ids = [
            value for value in input_signal_values if isinstance(value, str)
        ]
        self.control_loop.record_wakeup(
            ControlWakeup(
                wakeupId=wakeup.id,
                reason=wakeup.reason,
                status="pending",
                createdAt=wakeup.created_at,
                inputSignalIds=input_signal_ids,
            ),
            connection=raw_connection,
        )

    def ingest_signal_collection(
        self,
        fetch: SignalFetchRun,
        items: list[SignalItem],
        *,
        wakeup: object | None = None,
        suppression_hours: int = 24,
    ):
        """Persist one normalized provider collection atomically.

        Every observation goes through the control-loop graph ledger.
        """

        with Session(self.engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                existing_fetch = session.get(SignalFetchRunRow, fetch.id)
                if existing_fetch is None:
                    saved_items, created_items, new_wakeups = (
                        self._add_signal_items_in_session(
                            session,
                            items,
                            suppression_hours=suppression_hours,
                        )
                    )
                    fetch_run = fetch.model_copy(
                        update={
                            "item_count": len(saved_items),
                            "new_item_count": created_items,
                        }
                    )
                else:
                    fetch_run = row_to_signal_fetch_run(existing_fetch)
                    saved_items = []
                    new_wakeups = []
                    for item in items:
                        workflow_identity = signal_workflow_identity(item)
                        row = _matching_signal_row(
                            session, item, workflow_identity=workflow_identity
                        )
                        if row is None:
                            raise ValueError(
                                f"replayed fetch {fetch.id} is missing scheduler signal {item.id}"
                            )
                        saved_items.append(
                            row_to_signal_item(row, path_codec=self.path_codec)
                        )
                    created_items = 0

                raw_connection = session.connection().connection.driver_connection
                raw_connection.row_factory = sqlite3.Row
                result = self.control_loop.ingest_fetch(
                    fetch_run,
                    items,
                    wakeup=wakeup,
                    connection=raw_connection,
                )
                for new_wakeup in new_wakeups:
                    self._record_wakeup_in_session(session, new_wakeup)
                if existing_fetch is None:
                    self.add_signal_fetch_run(fetch_run, _session=session)
                session.commit()
            except Exception:
                session.rollback()
                raise
        self._notify_change()
        return saved_items, result[1], created_items

    def _add_signal_items_in_session(
        self,
        session: Session,
        items: list[SignalItem],
        *,
        suppression_hours: int,
    ) -> tuple[list[SignalItem], int, list[SchedulerWakeup]]:
        saved: list[SignalItem] = []
        new_wakeups: list[SchedulerWakeup] = []
        created = 0
        for source in items:
            now = utc_now()
            item = source.model_copy(
                update={"created_at": source.created_at, "updated_at": now}
            )
            saved_item: SignalItem | None = None
            workflow_identity = signal_workflow_identity(item)
            existing = _matching_signal_row(
                session, item, workflow_identity=workflow_identity
            )
            if existing is not None:
                if _signal_row_suppressed(
                    session,
                    existing,
                    suppression_hours=suppression_hours,
                ):
                    existing.updated_at = now.isoformat()
                    if item.source_fetch_id:
                        existing.source_fetch_id = item.source_fetch_id
                    saved_item = row_to_signal_item(
                        existing, path_codec=self.path_codec
                    )
                else:
                    item = item.model_copy(update={"id": new_signal_item_id()})
            if saved_item is None:
                session.add(
                    signal_item_to_row(
                        item,
                        path_codec=self.path_codec,
                        workflow_identity=workflow_identity,
                    )
                )
                new_wakeups.append(
                    SchedulerWakeup(
                        reason="signal.pending",
                        data={
                            "signal_item_id": item.id,
                            "provider": item.provider,
                        },
                    )
                )
                saved_item = item
                created += 1
            saved.append(saved_item)
        return saved, created, new_wakeups

    def commit_planner_decision(
        self,
        planner_run_id: str,
        *,
        planned: list[tuple[TaskSpec, str]],
        planner_dispositions: list[object],
        consumed_item_ids: list[str],
        selected_item_ids_by_dedupe: dict[str, list[str]],
        canonical_signal_by_item: dict[str, str],
        state: str,
        result: dict[str, object],
        diagnostics: dict[str, object],
        retry_after: timedelta | None,
        artifact_sources: dict[str, tuple[str, bool]],
        schedule_retry_key: str | None = None,
    ) -> dict[str, object]:
        """Commit tasks, signal mutations, graph edges, and outbox intent once."""

        created_records: list[TaskRecord] = []
        selected_records: list[tuple[TaskRecord, bool]] = []
        with Session(self.engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                task_ids_by_dedupe: dict[str, str] = {}
                for spec, dedupe_key in planned:
                    selected_ids = list(
                        dict.fromkeys(
                            item_id
                            for item_id in selected_item_ids_by_dedupe.get(dedupe_key, [])
                            if isinstance(item_id, str)
                        )
                    )
                    existing_row = session.scalar(
                        select(TaskRow).where(
                            TaskRow.dedupe_key == dedupe_key,
                            TaskRow.status.in_([value.value for value in ACTIVE_STATUSES]),
                        )
                    )
                    if existing_row is not None:
                        existing_metadata = _metadata_dict(
                            existing_row.metadata_json, self.path_codec
                        )
                        if selected_ids:
                            existing_metadata["selected_signal_item_ids"] = list(
                                dict.fromkeys(
                                    [
                                        *(
                                            existing_metadata.get(
                                                "selected_signal_item_ids", []
                                            )
                                            if isinstance(
                                                existing_metadata.get(
                                                    "selected_signal_item_ids"
                                                ),
                                                list,
                                            )
                                            else []
                                        ),
                                        *selected_ids,
                                    ]
                                )
                            )
                        existing_mode = resolve_execution_mode(
                            execution_mode_from_metadata(existing_metadata),
                            execution_mode_for_dry_run(self._startup_dry_run),
                        )
                        existing_row.metadata_json = _dump_metadata(
                            preserve_execution_mode(
                                existing_metadata, resolved=existing_mode
                            ),
                            self.path_codec,
                        )
                        existing = row_to_task(existing_row, path_codec=self.path_codec)
                        selected_records.append((existing, False))
                        task_ids_by_dedupe[dedupe_key] = existing.id
                        continue
                    metadata = dict(spec.metadata)
                    metadata["dedupe_key"] = dedupe_key
                    if selected_ids:
                        metadata["selected_signal_item_ids"] = selected_ids
                    metadata[EXECUTION_MODE_METADATA_KEY] = execution_mode_for_dry_run(
                        self._startup_dry_run
                    ).value
                    stored_spec = spec.model_copy(update={"metadata": metadata}, deep=True)
                    record = TaskRecord(spec=stored_spec)
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
                    session.add(task_to_row(record, dedupe_key=dedupe_key, path_codec=self.path_codec))
                    session.add(
                        event_to_row(
                            Event(
                                task_id=record.id,
                                kind="task.created",
                                message=record.spec.title,
                            ),
                            path_codec=self.path_codec,
                        )
                    )
                    session.flush()
                    session.add(execution_row)
                    session.flush()
                    session.add(pipeline_to_row(pipeline))
                    session.flush()
                    execution_row.owning_pipeline_id = pipeline.id
                    created_records.append(record)
                    selected_records.append((record, True))
                    task_ids_by_dedupe[dedupe_key] = record.id

                planned_item_ids: set[str] = set()
                for record, _created in selected_records:
                    dedupe_key = str(record.spec.metadata.get("dedupe_key") or "")
                    selected_ids = selected_item_ids_by_dedupe.get(dedupe_key, [])
                    rows = session.scalars(
                        select(SignalItemRow).where(
                            SignalItemRow.id.in_(selected_ids),
                            SignalItemRow.status == SignalItemStatus.pending.value,
                        )
                    ).all()
                    now_text = utc_now().isoformat()
                    for row in rows:
                        row.status = SignalItemStatus.planned.value
                        row.planned_at = now_text
                        row.updated_at = now_text
                        row.planner_run_id = planner_run_id
                        row.planned_task_id = record.id
                        planned_item_ids.add(row.id)

                superseded_rows = session.scalars(
                    select(SignalItemRow).where(
                        SignalItemRow.id.in_(
                            [
                                item_id
                                for item_id in consumed_item_ids
                                if item_id not in planned_item_ids
                            ]
                        ),
                        SignalItemRow.status == SignalItemStatus.pending.value,
                    )
                ).all()
                now_text = utc_now().isoformat()
                for row in superseded_rows:
                    row.status = SignalItemStatus.superseded.value
                    row.updated_at = now_text
                    row.planner_run_id = planner_run_id

                dispositions: list[ControlProposalDisposition] = []
                for disposition in planner_dispositions:
                    dedupe_key = getattr(disposition, "dedupe_key", None)
                    if not dedupe_key or dedupe_key in task_ids_by_dedupe:
                        continue
                    existing_row = session.scalar(
                        select(TaskRow).where(
                            TaskRow.dedupe_key == dedupe_key,
                            TaskRow.status.in_([value.value for value in ACTIVE_STATUSES]),
                        )
                    )
                    if existing_row is not None:
                        task_ids_by_dedupe[dedupe_key] = existing_row.id
                for ordinal, disposition in enumerate(planner_dispositions, 1):
                    dedupe_key = getattr(disposition, "dedupe_key", None)
                    task_id = task_ids_by_dedupe.get(dedupe_key) if dedupe_key else None
                    outcome = str(getattr(disposition, "outcome", "invalid"))
                    reason_code = str(
                        getattr(disposition, "reason_code", "invalid_output")
                    )
                    if outcome in {"accepted", "duplicate"} and task_id is None:
                        outcome = "invalid"
                        reason_code = "missing_covering_task"
                    signal_ids = list(
                        dict.fromkeys(
                            canonical_signal_by_item[item_id]
                            for item_id in getattr(disposition, "signal_ids", [])
                            if item_id in canonical_signal_by_item
                        )
                    )
                    dispositions.append(
                        ControlProposalDisposition(
                            proposalId=f"{planner_run_id}-proposal-{ordinal}",
                            plannerRunId=planner_run_id,
                            ordinal=ordinal,
                            outcome=outcome,
                            reasonCode=reason_code,
                            signalIds=signal_ids,
                            dedupeKey=dedupe_key,
                            taskId=task_id,
                            proposal=getattr(disposition, "proposal", {}) or {},
                        )
                    )

                session.flush()
                raw_connection = session.connection().connection.driver_connection
                raw_connection.row_factory = sqlite3.Row
                completed = self.control_loop.complete_planner_run(
                    planner_run_id,
                    dispositions,
                    state=state,
                    result=result,
                    diagnostics=diagnostics,
                    retry_after=retry_after,
                    consume_signal_ids=(
                        list(
                            dict.fromkeys(
                                canonical_signal_by_item[item_id]
                                for item_id in consumed_item_ids
                                if item_id in canonical_signal_by_item
                            )
                        )
                        if state == "succeeded"
                        else ()
                    ),
                    artifact_sources=artifact_sources,
                    reset_retry_key="planner" if state == "succeeded" else None,
                    schedule_retry_key=schedule_retry_key,
                    connection=raw_connection,
                )
                session.commit()
            except Exception:
                session.rollback()
                raise

        for record in created_records:
            self.request_wakeup(
                "task.created",
                {"task_id": record.id, "kind": str(record.spec.kind)},
            )
        self._notify_change()
        return {
            "completed": completed,
            "records": selected_records,
            "planned_item_count": len(planned_item_ids),
            "superseded_item_count": len(superseded_rows),
            "dispositions": dispositions,
        }

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
            self._record_wakeup_in_session(session, wakeup)
        self._notify_change()
        return wakeup

    # ------------------------------------------------------------------
    # Durable publication outbox

    def begin_publication_hide(
        self,
        task_id: str,
        reason: str = "operator_blocked",
        *,
        now: datetime | None = None,
        generation_boundary: str | None = None,
    ) -> PublicationOperationResult:
        """Fence one task and retire every local pre-exposure generation.

        This is the local half of a hide operation.  It deliberately performs
        no provider call; callers may only cross that boundary after this
        transaction commits.
        """

        task = _publication_identifier(task_id)
        safe_reason = _publication_reason(reason)
        assert safe_reason is not None
        timestamp = _publication_now(now)
        boundary = None
        if generation_boundary is not None:
            boundary = GenerationIdentity(task, generation_boundary).stable_boundary
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            existing_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                "WHERE task_id=:task_id",
                {"task_id": task},
            ).mappings().first()
            if existing_row is not None:
                existing = _publication_hide_from_row(existing_row)
                if existing.state is PublicationHideState.released:
                    # A repaired generation has reopened the task.  A new hide
                    # starts a fresh durable request in the same task row.
                    pass
                elif existing.reason != safe_reason or (
                    boundary is not None
                    and existing.generation_boundary != boundary
                ):
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.conflict,
                        reason="integrity",
                        fence=existing,
                    )
                else:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.existing,
                        reason=existing.reason,
                        fence=existing,
                    )

            generation_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE task_id=:task_id "
                "ORDER BY updated_at DESC,created_at DESC,publication_id DESC LIMIT 1",
                {"task_id": task},
            ).mappings().first()
            latest_boundary = (
                None
                if generation_row is None
                else str(generation_row["generation_boundary"])
            )
            if boundary is None:
                boundary = latest_boundary
            elif latest_boundary is not None and boundary != latest_boundary:
                # A caller may name the exact boundary only when it is still
                # the current local pre-exposure head.
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    reason="integrity",
                )
            generation_rows = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE task_id=:task_id AND state NOT IN ('exposed','terminal_cleaned') "
                "ORDER BY created_at,publication_id",
                {"task_id": task},
            ).mappings().all()
            for row in generation_rows:
                if timestamp < _publication_datetime(row["updated_at"]):
                    raise OutboxValidationError("invalid_metadata")

            fence = PublicationHideFence(
                task_id=task,
                reason=safe_reason,
                state=PublicationHideState.pending,
                generation_boundary=boundary,
                requested_at=timestamp,
            )
            if existing_row is None:
                connection.exec_driver_sql(
                    "INSERT INTO publication_hide_fences "
                    "(task_id,reason,state,generation_boundary,requested_at,confirmed_at) "
                    "VALUES (:task_id,:reason,'pending',:generation_boundary,:requested_at,NULL)",
                    {
                        "task_id": fence.task_id,
                        "reason": fence.reason,
                        "generation_boundary": fence.generation_boundary,
                        "requested_at": _publication_timestamp(fence.requested_at),
                    },
                )
            else:
                connection.exec_driver_sql(
                    "UPDATE publication_hide_fences SET reason=:reason,state='pending',"
                    "generation_boundary=:generation_boundary,requested_at=:requested_at,"
                    "confirmed_at=NULL WHERE task_id=:task_id AND state='released'",
                    {
                        "task_id": fence.task_id,
                        "reason": fence.reason,
                        "generation_boundary": fence.generation_boundary,
                        "requested_at": _publication_timestamp(fence.requested_at),
                    },
                )
            retired = connection.exec_driver_sql(
                "UPDATE publication_generations SET state='blocked',lease_owner=NULL,"
                "lease_expires_at=NULL,retry_at=NULL,reason=:reason,updated_at=:updated_at "
                "WHERE task_id=:task_id AND state NOT IN ('exposed','terminal_cleaned')",
                {
                    "task_id": task,
                    "reason": safe_reason,
                    "updated_at": _publication_timestamp(timestamp),
                },
            )
            refreshed_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                "WHERE task_id=:task_id",
                {"task_id": task},
            ).mappings().first()
            assert refreshed_row is not None
            saved = _publication_hide_from_row(refreshed_row)
            self._refresh_publication_health(
                connection, updated_at=timestamp, reason=safe_reason
            )
            connection.commit()
            changed = existing_row is None or retired.rowcount > 0
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.enqueued,
            reason=saved.reason,
            fence=saved,
        )

    def confirm_publication_hide(
        self,
        task_id: str,
        *,
        reason: str | None = None,
        confirmed_at: datetime | None = None,
        now: datetime | None = None,
    ) -> PublicationOperationResult:
        """Confirm a previously committed local hide fence."""

        task = _publication_identifier(task_id)
        safe_reason = None if reason is None else _publication_reason(reason)
        timestamp = _publication_now(confirmed_at if confirmed_at is not None else now)
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                "WHERE task_id=:task_id",
                {"task_id": task},
            ).mappings().first()
            if row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            current = _publication_hide_from_row(row)
            if safe_reason is not None and safe_reason != current.reason:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.conflict,
                    reason="integrity",
                    fence=current,
                )
            if timestamp < current.requested_at:
                raise OutboxValidationError("invalid_metadata")
            if current.state is PublicationHideState.released:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    reason=current.reason,
                    fence=current,
                )
            if current.state is PublicationHideState.confirmed:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    reason=current.reason,
                    fence=current,
                )
            update = connection.exec_driver_sql(
                "UPDATE publication_hide_fences SET state='confirmed',confirmed_at=:confirmed_at "
                "WHERE task_id=:task_id AND state='pending' AND confirmed_at IS NULL",
                {
                    "task_id": task,
                    "confirmed_at": _publication_timestamp(timestamp),
                },
            )
            if update.rowcount != 1:
                row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                    "WHERE task_id=:task_id",
                    {"task_id": task},
                ).mappings().first()
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    reason="integrity",
                    fence=None if row is None else _publication_hide_from_row(row),
                )
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                "WHERE task_id=:task_id",
                {"task_id": task},
            ).mappings().first()
            assert row is not None
            saved = _publication_hide_from_row(row)
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.verified,
            reason=saved.reason,
            fence=saved,
        )

    def get_publication_hide(self, task_id: str) -> PublicationHideFence | None:
        task = _publication_identifier(task_id)
        with self.engine.begin() as connection:
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                "WHERE task_id=:task_id",
                {"task_id": task},
            ).mappings().first()
        return None if row is None else _publication_hide_from_row(row)

    def list_publication_hides(
        self,
        *,
        task_id: str | None = None,
        states: set[PublicationHideState | str] | None = None,
        pending_only: bool = False,
    ) -> list[PublicationHideFence]:
        parameters: dict[str, object] = {}
        clauses: list[str] = []
        if task_id is not None:
            clauses.append("task_id=:task_id")
            parameters["task_id"] = _publication_identifier(task_id)
        if pending_only:
            clauses.append("state='pending'")
        elif states:
            normalized = [PublicationHideState(item).value for item in states]
            placeholders = ",".join(f":hide_state_{index}" for index in range(len(normalized)))
            clauses.append(f"state IN ({placeholders})")
            parameters.update(
                {f"hide_state_{index}": value for index, value in enumerate(normalized)}
            )
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences"
                f"{where} ORDER BY requested_at,task_id",
                parameters,
            ).mappings().all()
        return [_publication_hide_from_row(row) for row in rows]

    def list_pending_publication_hides(
        self, *, task_id: str | None = None
    ) -> list[PublicationHideFence]:
        return self.list_publication_hides(task_id=task_id, pending_only=True)

    def enqueue_publication(
        self,
        generation: PublicationGeneration | None = None,
        *,
        task_id: str | None = None,
        run_id: str | None = None,
        generation_boundary: str | None = None,
        metadata_digest: str | None = None,
        publication_id: str | None = None,
        idempotency_key: str | None = None,
        counts: PublicationCounts | Mapping[str, object] | None = None,
        rows: int = 0,
        objects: int = 0,
        tasks: int = 1,
        pipelines: int = 0,
        runs: int = 0,
        events: int = 0,
        artifacts: int = 0,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> PublicationOperationResult:
        """Insert one queued generation, coalescing an exact replay.

        The identity and all immutable expected counts are checked before the
        transaction.  A duplicate notification therefore has no write and no
        scheduler wakeup, while a conflicting replay fails with a bounded
        validation category.
        """

        value = _coerce_publication_generation(
            generation,
            task_id=task_id,
            run_id=run_id,
            generation_boundary=generation_boundary,
            metadata_digest=metadata_digest,
            publication_id=publication_id,
            idempotency_key=idempotency_key,
            counts=counts,
            rows=rows,
            objects=objects,
            tasks=tasks,
            pipelines=pipelines,
            runs=runs,
            events=events,
            artifacts=artifacts,
            created_at=created_at,
            updated_at=updated_at,
        )
        if (
            value.state is not PublicationState.queued
            or value.attempt != 0
            or value.reason is not None
        ):
            raise OutboxValidationError("invalid_metadata")

        connection = self.engine.connect()
        inserted = False
        saved = value
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            task_row = connection.exec_driver_sql(
                "SELECT metadata_json FROM tasks WHERE id=:task_id",
                {"task_id": value.task_id},
            ).mappings().first()
            if task_row is not None:
                try:
                    metadata = json.loads(task_row["metadata_json"] or "{}")
                    mode = (
                        execution_mode_from_metadata(metadata)
                        if isinstance(metadata, dict)
                        else None
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    mode = None
                if mode is not ExecutionMode.live:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.precondition,
                    )
            fence = _publication_hide_fence_from_connection(connection, value.task_id)
            if fence is not None:
                # A confirmed remote hide remains a local fence until the
                # explicit repair transition installs a distinct generation.
                # Ordinary enqueue must never reopen the task implicitly.
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    reason=fence.reason,
                    fence=fence,
                )
            existing_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id OR (task_id=:task_id AND run_id=:run_id) "
                "ORDER BY CASE WHEN publication_id=:publication_id THEN 0 ELSE 1 END LIMIT 1",
                {
                    "publication_id": value.publication_id,
                    "task_id": value.task_id,
                    "run_id": value.run_id,
                },
            ).mappings().first()
            if existing_row is not None:
                existing = _publication_generation_from_row(existing_row)
                if not _same_generation_input(existing, value):
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.conflict,
                        generation=existing,
                        reason="integrity",
                    )
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    generation=existing,
                )
            connection.exec_driver_sql(
                """
                INSERT INTO publication_generations
                  (publication_id,task_id,run_id,generation_boundary,metadata_digest,
                   idempotency_key,state,attempt,lease_owner,lease_expires_at,retry_at,
                   reason,expected_row_count,expected_object_count,expected_task_count,
                   expected_pipeline_count,expected_run_count,expected_event_count,
                   expected_artifact_count,created_at,updated_at,exposed_at)
                VALUES
                  (:publication_id,:task_id,:run_id,:generation_boundary,:metadata_digest,
                   :idempotency_key,'queued',0,NULL,NULL,NULL,NULL,
                   :expected_row_count,:expected_object_count,:expected_task_count,
                   :expected_pipeline_count,:expected_run_count,:expected_event_count,
                   :expected_artifact_count,:created_at,:updated_at,NULL)
                """,
                _generation_parameters(value),
            )
            saved_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": value.publication_id},
            ).mappings().first()
            assert saved_row is not None
            saved = _publication_generation_from_row(saved_row)
            self._refresh_publication_health(connection, updated_at=value.updated_at)
            connection.commit()
            inserted = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if inserted:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.enqueued,
            generation=saved,
            fence=fence,
        )

    def replace_blocked_publication(
        self,
        old_publication_id: str,
        generation: PublicationGeneration,
    ) -> PublicationOperationResult:
        """Atomically install one repaired generation.

        Blocked rows are replaced in place, while exposed and terminal-cleaned
        rows remain as immutable evidence under a confirmed hide fence.  A
        repaired generation and fence release commit together; receipts and
        cleanup intents therefore cannot be erased as part of the repair.
        """

        try:
            old_id = _publication_identifier(old_publication_id, prefix="pub-")
        except OutboxValidationError as error:
            return PublicationOperationResult(
                PublicationOperationStatus.precondition,
                reason=error.code.value,
            )
        if not isinstance(generation, PublicationGeneration):
            return PublicationOperationResult(
                PublicationOperationStatus.precondition,
                reason="invalid_metadata",
            )
        if (
            generation.state is not PublicationState.queued
            or generation.attempt != 0
            or generation.reason is not None
            or generation.lease_owner is not None
            or generation.lease_expires_at is not None
            or generation.retry_at is not None
            or generation.exposed_at is not None
        ):
            return PublicationOperationResult(
                PublicationOperationStatus.precondition,
                reason="invalid_metadata",
            )

        connection = self.engine.connect()
        changed = False
        saved = generation
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            old_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": old_id},
            ).mappings().first()
            candidate_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": generation.publication_id},
            ).mappings().first()
            fence = None
            if old_row is not None:
                fence = _publication_hide_fence_from_connection(
                    connection, str(old_row["task_id"])
                )
                if fence is not None and fence.state is not PublicationHideState.confirmed:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.precondition,
                        generation=_publication_generation_from_row(old_row),
                        reason=fence.reason,
                        fence=fence,
                    )

            # Once the old row has been replaced, an exact replay is the new
            # row.  Do not emit another wakeup or touch its health timestamp.
            if old_row is None:
                if candidate_row is not None:
                    existing = _publication_generation_from_row(candidate_row)
                    if _same_generation_input(existing, generation):
                        connection.commit()
                        return PublicationOperationResult(
                            PublicationOperationStatus.existing,
                            generation=existing,
                        )
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.conflict,
                        generation=existing,
                        reason="integrity",
                    )
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.missing,
                    reason="missing",
                )

            old = _publication_generation_from_row(old_row)
            preserve_evidence = old.state in {
                PublicationState.exposed,
                PublicationState.terminal_cleaned,
            }
            if preserve_evidence and (
                fence is None or fence.state is not PublicationHideState.confirmed
            ):
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=old,
                    reason="integrity",
                    fence=fence,
                )
            if old.task_id != generation.task_id or (
                not preserve_evidence and old.run_id != generation.run_id
            ):
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.conflict,
                    generation=old,
                    reason="integrity",
                )
            if preserve_evidence and old.run_id == generation.run_id:
                # Keep the historical row and the task/run uniqueness boundary;
                # a repaired exposed generation must use a new run identity.
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.conflict,
                    generation=old,
                    reason="integrity",
                    fence=fence,
                )
            if old.publication_id == generation.publication_id:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.conflict,
                    generation=old,
                    reason="integrity",
                )
            if old.state not in {
                PublicationState.blocked,
                PublicationState.exposed,
                PublicationState.terminal_cleaned,
            } or old.lease_owner is not None or old.lease_expires_at is not None:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=old,
                    reason="integrity",
                )
            if fence is not None:
                if (
                    fence.generation_boundary is not None
                    and old.generation_boundary != fence.generation_boundary
                ) or old.generation_boundary == generation.generation_boundary:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.precondition,
                        generation=old,
                        reason="integrity",
                        fence=fence,
                    )

            if not preserve_evidence:
                receipt_count = connection.exec_driver_sql(
                    "SELECT COUNT(*) FROM publication_receipts "
                    "WHERE publication_id=:publication_id",
                    {"publication_id": old.publication_id},
                ).scalar_one()
                cleanup_count = connection.exec_driver_sql(
                    "SELECT COUNT(*) FROM publication_cleanup_intents "
                    "WHERE publication_id=:publication_id",
                    {"publication_id": old.publication_id},
                ).scalar_one()
                if receipt_count or cleanup_count:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.precondition,
                        generation=old,
                        reason="integrity",
                    )
            if candidate_row is not None:
                existing = _publication_generation_from_row(candidate_row)
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.conflict,
                    generation=existing,
                    reason="integrity",
                )

            if not preserve_evidence:
                connection.exec_driver_sql(
                    "DELETE FROM publication_generations WHERE publication_id=:publication_id",
                    {"publication_id": old.publication_id},
                )
            connection.exec_driver_sql(
                """
                INSERT INTO publication_generations
                  (publication_id,task_id,run_id,generation_boundary,metadata_digest,
                   idempotency_key,state,attempt,lease_owner,lease_expires_at,retry_at,
                   reason,expected_row_count,expected_object_count,expected_task_count,
                   expected_pipeline_count,expected_run_count,expected_event_count,
                   expected_artifact_count,created_at,updated_at,exposed_at)
                VALUES
                  (:publication_id,:task_id,:run_id,:generation_boundary,:metadata_digest,
                   :idempotency_key,'queued',0,NULL,NULL,NULL,NULL,
                   :expected_row_count,:expected_object_count,:expected_task_count,
                   :expected_pipeline_count,:expected_run_count,:expected_event_count,
                   :expected_artifact_count,:created_at,:updated_at,NULL)
                """,
                _generation_parameters(generation),
            )
            saved_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": generation.publication_id},
            ).mappings().first()
            assert saved_row is not None
            saved = _publication_generation_from_row(saved_row)
            if fence is not None:
                connection.exec_driver_sql(
                    "UPDATE publication_hide_fences SET state='released' "
                    "WHERE task_id=:task_id AND state='confirmed'",
                    {"task_id": old.task_id},
                )
                released_row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
                    "WHERE task_id=:task_id",
                    {"task_id": old.task_id},
                ).mappings().first()
                fence = None if released_row is None else _publication_hide_from_row(released_row)
            self._refresh_publication_health(connection, updated_at=saved.updated_at)
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.enqueued,
            generation=saved,
            fence=fence,
        )

    def get_publication_generation(
        self, publication_id: str
    ) -> PublicationGeneration | None:
        with self.engine.begin() as connection:
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": publication_id},
            ).mappings().first()
        return None if row is None else _publication_generation_from_row(row)

    def list_publication_generations(
        self,
        *,
        task_id: str | None = None,
        states: set[PublicationState | str] | None = None,
        limit: int | None = None,
    ) -> list[PublicationGeneration]:
        parameters: dict[str, object] = {}
        clauses: list[str] = []
        if task_id is not None:
            clauses.append("task_id=:task_id")
            parameters["task_id"] = task_id
        if states:
            normalized = [PublicationState(item).value for item in states]
            placeholders = ",".join(f":state_{index}" for index in range(len(normalized)))
            clauses.append(f"state IN ({placeholders})")
            parameters.update(
                {f"state_{index}": value for index, value in enumerate(normalized)}
            )
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        limit_clause = " LIMIT :limit" if limit is not None else ""
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise ValueError("limit must be non-negative")
            parameters["limit"] = limit
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations"
                f"{where} ORDER BY created_at,publication_id{limit_clause}",
                parameters,
            ).mappings().all()
        return [_publication_generation_from_row(row) for row in rows]

    def claim_publication(
        self,
        worker_id: str,
        *,
        retry_policy: PublicationRetryPolicy,
        publication_id: str | None = None,
        now: datetime | None = None,
        lease_seconds: int = MAX_LEASE_SECONDS,
    ) -> PublicationOperationResult:
        """Atomically claim the oldest eligible generation.

        Queued generations enter ``claimed``.  A due retry resumes directly in
        ``building`` so the persisted receipt boundary remains the first work
        still requiring an external side effect.
        """

        worker = _publication_identifier(worker_id)
        if not isinstance(retry_policy, PublicationRetryPolicy):
            raise OutboxValidationError("invalid_metadata")
        timestamp = _publication_now(now)
        lease_seconds = _bounded_publication_seconds(
            lease_seconds, MAX_LEASE_SECONDS, minimum=1
        )
        now_text = _publication_timestamp(timestamp)
        lease_text = _publication_timestamp(timestamp + timedelta(seconds=lease_seconds))
        connection = self.engine.connect()
        changed = False
        result: PublicationOperationResult
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            expired = self._expire_publication_leases_in_connection(connection, timestamp)
            changed = expired
            parameters: dict[str, object] = {"now": now_text}
            selector = (
                "(state='queued' OR (state='retry_wait' AND retry_at<=:now)) "
                "AND NOT EXISTS ("
                "SELECT 1 FROM publication_generations active "
                "WHERE active.task_id=publication_generations.task_id "
                "AND active.lease_expires_at IS NOT NULL) "
                "AND NOT EXISTS ("
                "SELECT 1 FROM publication_hide_fences AS fence "
                "WHERE fence.task_id=publication_generations.task_id "
                "AND fence.state IN ('pending','confirmed')) "
                "AND (attempt < :max_attempts OR ("
                + _PUBLICATION_HIDE_RETRY_SQL
                + "))"
            )
            parameters["max_attempts"] = retry_policy.max_attempts
            if publication_id is not None:
                selector += " AND publication_id=:publication_id"
                parameters["publication_id"] = publication_id
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                f"WHERE {selector} ORDER BY CASE WHEN state='queued' THEN 0 ELSE 1 END,"
                "COALESCE(retry_at,created_at),created_at,publication_id LIMIT 1",
                parameters,
            ).mappings().first()
            if row is None:
                # A row which has reached the attempt ceiling is made
                # fail-closed rather than left permanently claimable-looking.
                exhausted_parameters: dict[str, object] = {}
                exhausted_selector = (
                    "state IN ('queued','retry_wait') AND attempt >= :max_attempts "
                    "AND NOT ("
                    + _PUBLICATION_HIDE_RETRY_SQL
                    + ")"
                )
                exhausted_parameters["max_attempts"] = retry_policy.max_attempts
                if publication_id is not None:
                    exhausted_selector += " AND publication_id=:publication_id"
                    exhausted_parameters["publication_id"] = publication_id
                exhausted = connection.exec_driver_sql(
                    f"SELECT publication_id FROM publication_generations WHERE {exhausted_selector} "
                    "ORDER BY created_at,publication_id LIMIT 1",
                    exhausted_parameters,
                ).fetchone()
                if exhausted is not None:
                    connection.exec_driver_sql(
                        "UPDATE publication_generations SET state='blocked',reason='retry_exhausted',"
                        "retry_at=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=:updated_at "
                        "WHERE publication_id=:publication_id AND state IN ('queued','retry_wait') "
                        "AND attempt>=:max_attempts",
                        {
                            "updated_at": now_text,
                            "publication_id": exhausted[0],
                            "max_attempts": retry_policy.max_attempts,
                        },
                    )
                    self._refresh_publication_health(
                        connection, updated_at=timestamp, reason="retry_exhausted"
                    )
                    changed = True
                    connection.commit()
                    result = PublicationOperationResult(
                        PublicationOperationStatus.retry_exhausted,
                        reason="retry_exhausted",
                    )
                else:
                    if expired:
                        self._refresh_publication_health(
                            connection,
                            updated_at=timestamp,
                            reason="lease_expired",
                        )
                    connection.commit()
                    status = (
                        PublicationOperationStatus.missing
                        if publication_id is not None
                        and self._publication_exists(connection, publication_id) is False
                        else PublicationOperationStatus.empty
                    )
                    result = PublicationOperationResult(status)
            else:
                current = _publication_generation_from_row(row)
                if timestamp < current.updated_at:
                    raise OutboxValidationError("invalid_metadata")
                target = (
                    PublicationState.claimed
                    if current.state is PublicationState.queued
                    else PublicationState.building
                )
                connection.exec_driver_sql(
                    "UPDATE publication_generations SET state=:state,"
                    "attempt=CASE WHEN attempt < :max_attempts THEN attempt+1 ELSE attempt END,"
                    "lease_owner=:lease_owner,lease_expires_at=:lease_expires_at,retry_at=NULL,"
                    "reason=CASE WHEN state='retry_wait' AND reason IN ("
                    + _PUBLICATION_HIDE_REASON_SQL
                    + ") THEN reason ELSE NULL END,updated_at=:updated_at "
                    "WHERE publication_id=:publication_id "
                    "AND state=:expected_state AND (attempt < :max_attempts OR ("
                    + _PUBLICATION_HIDE_RETRY_SQL
                    + "))",
                    {
                        "state": target.value,
                        "lease_owner": worker,
                        "lease_expires_at": lease_text,
                        "updated_at": now_text,
                        "publication_id": current.publication_id,
                        "expected_state": current.state.value,
                        "max_attempts": retry_policy.max_attempts,
                    },
                )
                updated_row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                    "WHERE publication_id=:publication_id",
                    {"publication_id": current.publication_id},
                ).mappings().first()
                assert updated_row is not None
                updated = _publication_generation_from_row(updated_row)
                self._refresh_publication_health(connection, updated_at=timestamp)
                connection.commit()
                changed = True
                result = PublicationOperationResult(
                    PublicationOperationStatus.claimed,
                    generation=updated,
                )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return result

    def expire_publication_leases(
        self, *, now: datetime | None = None
    ) -> list[PublicationGeneration]:
        """Move abandoned leases to an immediately eligible retry boundary."""

        timestamp = _publication_now(now)
        connection = self.engine.connect()
        changed = False
        expired_ids: list[str] = []
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            expired_ids = [
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT publication_id FROM publication_generations "
                    "WHERE state IN ('claimed','building','uploading','d1_staged') AND lease_expires_at<=:now",
                    {"now": _publication_timestamp(timestamp)},
                ).fetchall()
            ]
            changed = self._expire_publication_leases_in_connection(connection, timestamp)
            if changed:
                self._refresh_publication_health(
                    connection, updated_at=timestamp, reason="lease_expired"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return [
            generation
            for publication_id in expired_ids
            if (generation := self.get_publication_generation(publication_id)) is not None
        ]

    def renew_publication_lease(
        self,
        worker_id: str | None = None,
        *,
        lease_owner: str | None = None,
        publication_id: str,
        now: datetime | None = None,
        lease_seconds: int = MAX_LEASE_SECONDS,
    ) -> PublicationOperationResult:
        """Extend one live lease using owner/state compare-and-set."""

        owner = _publication_identifier(lease_owner or worker_id)
        timestamp = _publication_now(now)
        lease_seconds = _bounded_publication_seconds(
            lease_seconds, MAX_LEASE_SECONDS, minimum=1
        )
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": publication_id},
            ).mappings().first()
            if row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            current = _publication_generation_from_row(row)
            fence = _publication_hide_fence_from_connection(connection, current.task_id)
            if fence is not None:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=current,
                    reason=fence.reason,
                    fence=fence,
                )
            if current.state not in {
                PublicationState.claimed,
                PublicationState.building,
                PublicationState.uploading,
                PublicationState.d1_staged,
            }:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired",
                )
            if current.lease_owner != owner or current.lease_expires_at is None:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired",
                )
            if current.lease_expires_at <= timestamp:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired",
                )
            if timestamp < current.updated_at:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=current,
                    reason="invalid_metadata",
                )
            now_text = _publication_timestamp(timestamp)
            renewed_until = max(
                current.lease_expires_at,
                timestamp + timedelta(seconds=lease_seconds),
            )
            update = connection.exec_driver_sql(
                "UPDATE publication_generations SET lease_expires_at=:lease_expires_at,"
                "updated_at=:updated_at WHERE publication_id=:publication_id "
                "AND state=:state AND lease_owner=:lease_owner AND lease_expires_at>:now",
                {
                    "lease_expires_at": _publication_timestamp(renewed_until),
                    "updated_at": now_text,
                    "publication_id": publication_id,
                    "state": current.state.value,
                    "lease_owner": owner,
                    "now": now_text,
                },
            )
            if update.rowcount != 1:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired",
                )
            updated_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": publication_id},
            ).mappings().first()
            assert updated_row is not None
            updated = _publication_generation_from_row(updated_row)
            self._refresh_publication_health(connection, updated_at=timestamp)
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.renewed,
            generation=updated,
        )

    def advance_publication(
        self,
        publication_id: str,
        expected_state: PublicationState | str,
        target_state: PublicationState | str,
        *,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        now: datetime | None = None,
        lease_expires_at: datetime | None = None,
        retry_at: datetime | None = None,
        reason: str | None = None,
    ) -> PublicationOperationResult:
        """Compare-and-set one legal generation edge."""

        owner = lease_owner or worker_id
        if owner is not None:
            owner = _publication_identifier(owner)
        timestamp = _publication_now(now)
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": publication_id},
            ).mappings().first()
            if row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            current = _publication_generation_from_row(row)
            fence = _publication_hide_fence_from_connection(connection, current.task_id)
            if fence is not None:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=current,
                    reason=fence.reason,
                    fence=fence,
                )
            try:
                expected = PublicationState(expected_state)
                target = transition_state(expected, target_state)
            except (TypeError, ValueError, OutboxValidationError):
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.illegal_transition,
                    generation=current,
                    reason="invalid_metadata",
                )
            if (
                expected is PublicationState.queued
                and target in {PublicationState.claimed, PublicationState.building}
            ) or (
                expected is PublicationState.retry_wait
                and target is PublicationState.building
            ):
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.illegal_transition,
                    generation=current,
                    reason="invalid_metadata",
                )
            if current.state is not expected:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired" if current.lease_owner else None,
                )
            if (
                current.lease_expires_at is not None
                and current.lease_expires_at <= timestamp
            ):
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired",
                )
            if current.lease_owner is not None and current.lease_owner != owner:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired",
                )
            update_values = _publication_transition_values(
                current,
                target,
                timestamp=timestamp,
                lease_owner=owner,
                lease_expires_at=lease_expires_at,
                retry_at=retry_at,
                reason=reason,
            )
            if current.lease_owner is not None:
                update_values["expected_lease_owner"] = current.lease_owner
                owner_clause = " AND lease_owner=:expected_lease_owner"
            else:
                owner_clause = " AND lease_owner IS NULL"
            update = connection.exec_driver_sql(
                "UPDATE publication_generations SET state=:state,lease_owner=:lease_owner,"
                "lease_expires_at=:lease_expires_at,retry_at=:retry_at,reason=:reason,"
                "updated_at=:updated_at,exposed_at=:exposed_at WHERE publication_id=:publication_id "
                "AND state=:expected_state" + owner_clause,
                {
                    **update_values,
                    "publication_id": publication_id,
                    "expected_state": expected.value,
                },
            )
            if update.rowcount != 1:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=current,
                    reason="lease_expired" if current.lease_owner else None,
                )
            updated_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": publication_id},
            ).mappings().first()
            assert updated_row is not None
            updated = _publication_generation_from_row(updated_row)
            self._refresh_publication_health(
                connection, updated_at=timestamp, reason=updated.reason
            )
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.advanced,
            generation=updated,
        )

    def record_publication_receipt(
        self,
        publication_id: str,
        receipt: PublicationReceipt,
        *,
        receipt_id: str | None = None,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        owner: str | None = None,
        now: datetime | None = None,
    ) -> PublicationOperationResult:
        """Persist one verified object receipt under an active owner lease.

        Receipt replay is still idempotent, but the replay is authorized by the
        current generation lease before an existing row is returned.  This
        keeps an expired or replaced worker from manufacturing a successful
        local boundary after its remote request completed.
        """

        if not isinstance(receipt, PublicationReceipt):
            raise OutboxValidationError("invalid_metadata")
        owner_value = (
            lease_owner
            if lease_owner is not None
            else worker_id
            if worker_id is not None
            else owner
        )
        owner = None if owner_value is None else _publication_identifier(owner_value)
        timestamp = _publication_now(now)
        identifier = receipt_id or _publication_receipt_id(publication_id, receipt)
        _publication_identifier(identifier, prefix="receipt-")
        connection = self.engine.connect()
        inserted = False
        saved = receipt
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            generation_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id",
                {"publication_id": publication_id},
            ).mappings().first()
            if generation_row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            generation = _publication_generation_from_row(generation_row)
            private_run_id: str | None = None
            if receipt.receipt_class is ReceiptClass.public:
                expected_prefix = f"v1/tasks/{generation.task_id}/"
                if not receipt.content_key.startswith(expected_prefix):
                    raise OutboxValidationError("invalid_path")
            else:
                private_match = _PRIVATE_RECEIPT_KEY_RE.fullmatch(receipt.content_key)
                if private_match is None or private_match.group("task") != generation.task_id:
                    raise OutboxValidationError("invalid_path")
                private_run_id = private_match.group("run")

            # Verify the active state and lease before looking at an existing
            # receipt.  Matching bytes do not authorize a stale worker to
            # replay a receipt after its lease has expired or been replaced.
            if generation.state not in {
                PublicationState.building,
                PublicationState.uploading,
            }:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=generation,
                    reason="integrity",
                )
            if (
                owner is None
                or generation.lease_owner != owner
                or generation.lease_expires_at is None
                or generation.lease_expires_at <= timestamp
            ):
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    generation=generation,
                    reason="lease_expired",
                )
            if timestamp < generation.updated_at:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=generation,
                    reason="invalid_metadata",
                )
            existing_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_RECEIPT_COLUMNS} FROM publication_receipts "
                "WHERE receipt_id=:receipt_id",
                {"receipt_id": identifier},
            ).mappings().first()
            if existing_row is None:
                existing_row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_RECEIPT_COLUMNS} FROM publication_receipts "
                    "WHERE publication_id=:publication_id AND receipt_class=:receipt_class "
                    "AND sha256=:sha256 AND content_key=:content_key",
                    {
                        "publication_id": publication_id,
                        "receipt_class": receipt.receipt_class.value,
                        "sha256": receipt.sha256,
                        "content_key": receipt.content_key,
                    },
                ).mappings().first()
            if existing_row is not None:
                existing = _publication_receipt_from_row(existing_row)
                if (
                    str(existing_row["publication_id"]) != publication_id
                    or str(existing_row["task_id"]) != generation.task_id
                    or not _same_receipt(existing, receipt)
                ):
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.conflict,
                        receipt=existing,
                        reason="integrity",
                    )
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    receipt=existing,
                )
            if receipt.verified_at < generation.updated_at:
                raise OutboxValidationError("invalid_metadata")
            if private_run_id is not None:
                trajectory = connection.exec_driver_sql(
                    "SELECT verified_at FROM publication_receipts "
                    "WHERE publication_id=:publication_id AND task_id=:task_id "
                    "AND receipt_class='public' AND logical_path=:logical_path "
                    "ORDER BY verified_at,receipt_id LIMIT 1",
                    {
                        "publication_id": publication_id,
                        "task_id": generation.task_id,
                        "logical_path": f"runs/{private_run_id}/trajectory.json",
                    },
                ).scalar()
                if trajectory is None:
                    if private_run_id != generation.run_id:
                        raise OutboxValidationError("invalid_path")
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.precondition,
                        generation=generation,
                        reason="integrity",
                    )
                if _publication_datetime(trajectory) > receipt.verified_at:
                    raise OutboxValidationError("invalid_metadata")
            connection.exec_driver_sql(
                """
                INSERT INTO publication_receipts
                  (receipt_id,publication_id,task_id,receipt_class,sha256,byte_size,
                   content_key,logical_path,verified_at)
                VALUES
                  (:receipt_id,:publication_id,:task_id,:receipt_class,:sha256,:byte_size,
                   :content_key,:logical_path,:verified_at)
                """,
                {
                    "receipt_id": identifier,
                    "publication_id": publication_id,
                    "task_id": generation.task_id,
                    "receipt_class": receipt.receipt_class.value,
                    "sha256": receipt.sha256,
                    "byte_size": receipt.byte_size,
                    "content_key": receipt.content_key,
                    "logical_path": receipt.logical_path,
                    "verified_at": _publication_timestamp(receipt.verified_at),
                },
            )
            saved_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_RECEIPT_COLUMNS} FROM publication_receipts "
                "WHERE receipt_id=:receipt_id",
                {"receipt_id": identifier},
            ).mappings().first()
            assert saved_row is not None
            saved = _publication_receipt_from_row(saved_row)
            self._refresh_publication_health(connection, updated_at=receipt.verified_at)
            connection.commit()
            inserted = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if inserted:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.recorded,
            receipt=saved,
        )

    def list_publication_receipts(
        self,
        publication_id: str,
        *,
        receipt_class: ReceiptClass | str | None = None,
    ) -> list[PublicationReceipt]:
        parameters: dict[str, object] = {"publication_id": publication_id}
        clause = ""
        if receipt_class is not None:
            try:
                normalized_class = ReceiptClass(receipt_class)
            except (TypeError, ValueError):
                raise OutboxValidationError("invalid_metadata") from None
            clause = " AND receipt_class=:receipt_class"
            parameters["receipt_class"] = normalized_class.value
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_RECEIPT_COLUMNS} FROM publication_receipts "
                "WHERE publication_id=:publication_id" + clause + " ORDER BY verified_at,receipt_id",
                parameters,
            ).mappings().all()
        return [_publication_receipt_from_row(row) for row in rows]

    def schedule_publication_retry(
        self,
        publication_id: str,
        *,
        expected_state: PublicationState | str | None = None,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        retry_policy: PublicationRetryPolicy,
        retry_at: datetime | None = None,
        backoff_seconds: int | None = None,
        reason: str = "network",
        now: datetime | None = None,
    ) -> PublicationOperationResult:
        """Schedule a bounded retry from the current claimed boundary."""

        safe_reason = _publication_reason(reason)
        assert safe_reason is not None
        if not isinstance(retry_policy, PublicationRetryPolicy):
            raise OutboxValidationError("invalid_metadata")
        timestamp = _publication_now(now)
        current = self.get_publication_generation(publication_id)
        if current is None:
            return PublicationOperationResult(PublicationOperationStatus.missing)
        try:
            expected = (
                current.state
                if expected_state is None
                else PublicationState(expected_state)
            )
        except (TypeError, ValueError):
            raise OutboxValidationError("invalid_metadata") from None
        hide_pending = safe_reason in _PUBLICATION_HIDE_REASONS
        if retry_at is None:
            delay = 1 if backoff_seconds is None else _bounded_publication_seconds(
                backoff_seconds, MAX_RETRY_DELAY_SECONDS
            )
            retry_at = timestamp + timedelta(seconds=delay)
        else:
            retry_at = _publication_datetime(retry_at)
            if retry_at < timestamp or retry_at > timestamp + timedelta(seconds=MAX_RETRY_DELAY_SECONDS):
                raise OutboxValidationError("invalid_metadata")
        if current.attempt >= retry_policy.max_attempts:
            if hide_pending:
                retained = self.advance_publication(
                    publication_id,
                    expected,
                    PublicationState.retry_wait,
                    lease_owner=lease_owner or worker_id,
                    now=timestamp,
                    retry_at=retry_at,
                    reason=safe_reason,
                )
                return (
                    retained.with_status(PublicationOperationStatus.retry_wait)
                    if retained.status is PublicationOperationStatus.advanced
                    else retained
                )
            if not allowed_transition(current.state, PublicationState.blocked):
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=current,
                    reason="retry_exhausted",
                )
            blocked = self.block_publication(
                publication_id,
                expected_state=expected,
                lease_owner=lease_owner or worker_id,
                reason="retry_exhausted",
                now=timestamp,
            )
            return (
                blocked.with_status(PublicationOperationStatus.retry_exhausted)
                if blocked.status is PublicationOperationStatus.blocked
                else blocked
            )
        result = self.advance_publication(
            publication_id,
            expected,
            PublicationState.retry_wait,
            lease_owner=lease_owner or worker_id,
            now=timestamp,
            retry_at=retry_at,
            reason=safe_reason,
        )
        return (
            result.with_status(PublicationOperationStatus.retry_wait)
            if result.status is PublicationOperationStatus.advanced
            else result
        )

    def block_publication(
        self,
        publication_id: str,
        *,
        expected_state: PublicationState | str | None = None,
        lease_owner: str | None = None,
        worker_id: str | None = None,
        reason: str = "operator_blocked",
        now: datetime | None = None,
    ) -> PublicationOperationResult:
        """Fail closed with one safe reason and release any lease."""

        safe_reason = _publication_reason(reason)
        assert safe_reason is not None
        current = self.get_publication_generation(publication_id)
        if current is None:
            return PublicationOperationResult(PublicationOperationStatus.missing)
        if current.state is PublicationState.blocked:
            return PublicationOperationResult(
                PublicationOperationStatus.existing,
                generation=current,
                reason=current.reason,
            )
        try:
            expected = (
                current.state
                if expected_state is None
                else PublicationState(expected_state)
            )
        except (TypeError, ValueError):
            raise OutboxValidationError("invalid_metadata") from None
        # A successful task-head hide must also retire an unpublished queued
        # generation.  Keep the normal state graph unchanged: this explicit
        # compare-and-set is available only when the caller supplies the
        # queued expectation and one of the bounded hide reasons.
        if (
            expected_state is not None
            and current.state is PublicationState.queued
            and expected is PublicationState.queued
        ):
            if safe_reason not in _PUBLICATION_HIDE_REASONS and safe_reason != "operator_blocked":
                return PublicationOperationResult(
                    PublicationOperationStatus.illegal_transition,
                    generation=current,
                    reason="invalid_metadata",
                )
            timestamp = _publication_now(now)
            if timestamp < current.updated_at:
                raise OutboxValidationError("invalid_metadata")
            if lease_owner is not None or worker_id is not None:
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=current,
                    reason="integrity",
                )
            connection = self.engine.connect()
            changed = False
            updated = current
            try:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                    "WHERE publication_id=:publication_id",
                    {"publication_id": publication_id},
                ).mappings().first()
                if row is None:
                    connection.commit()
                    return PublicationOperationResult(PublicationOperationStatus.missing)
                latest = _publication_generation_from_row(row)
                if latest.state is PublicationState.blocked:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.existing,
                        generation=latest,
                        reason=latest.reason,
                    )
                if latest.state is not PublicationState.queued:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.lost_claim,
                        generation=latest,
                        reason="lease_expired" if latest.lease_owner else None,
                    )
                if latest.lease_owner is not None or latest.lease_expires_at is not None:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.precondition,
                        generation=latest,
                        reason="integrity",
                    )
                if timestamp < latest.updated_at:
                    raise OutboxValidationError("invalid_metadata")
                update = connection.exec_driver_sql(
                    "UPDATE publication_generations SET state='blocked',reason=:reason,"
                    "retry_at=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=:updated_at "
                    "WHERE publication_id=:publication_id AND state='queued' "
                    "AND lease_owner IS NULL AND lease_expires_at IS NULL",
                    {
                        "reason": safe_reason,
                        "updated_at": _publication_timestamp(timestamp),
                        "publication_id": publication_id,
                    },
                )
                if update.rowcount != 1:
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.lost_claim,
                        generation=latest,
                        reason="lease_expired",
                    )
                updated_row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                    "WHERE publication_id=:publication_id",
                    {"publication_id": publication_id},
                ).mappings().first()
                assert updated_row is not None
                updated = _publication_generation_from_row(updated_row)
                self._refresh_publication_health(
                    connection, updated_at=timestamp, reason=updated.reason
                )
                connection.commit()
                changed = True
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            if changed:
                self._notify_change()
            return PublicationOperationResult(
                PublicationOperationStatus.blocked,
                generation=updated,
                reason=updated.reason,
            )
        result = self.advance_publication(
            publication_id,
            expected,
            PublicationState.blocked,
            lease_owner=lease_owner or worker_id,
            now=now,
            reason=safe_reason,
        )
        return (
            result.with_status(PublicationOperationStatus.blocked)
            if result.status is PublicationOperationStatus.advanced
            else result
        )

    def create_cleanup_intent(
        self, intent: CleanupIntent
    ) -> PublicationOperationResult:
        """Persist exact deletion authority only after remote exposure."""

        if not isinstance(intent, CleanupIntent):
            raise OutboxValidationError("invalid_metadata")
        connection = self.engine.connect()
        inserted = False
        saved = intent
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            generation_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_GENERATION_COLUMNS} FROM publication_generations "
                "WHERE publication_id=:publication_id AND task_id=:task_id",
                {"publication_id": intent.publication_id, "task_id": intent.task_id},
            ).mappings().first()
            if generation_row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            generation = _publication_generation_from_row(generation_row)
            existing_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent.intent_id},
            ).mappings().first()
            if existing_row is None:
                existing_row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                    "WHERE publication_id=:publication_id AND task_id=:task_id",
                    {
                        "publication_id": intent.publication_id,
                        "task_id": intent.task_id,
                    },
                ).mappings().first()
            if existing_row is not None:
                existing = _publication_cleanup_from_row(existing_row)
                if not _same_cleanup_input(existing, intent):
                    connection.commit()
                    return PublicationOperationResult(
                        PublicationOperationStatus.conflict,
                        cleanup=existing,
                        reason="integrity",
                    )
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    cleanup=existing,
                )
            if (
                intent.state is not CleanupState.pending
                or intent.verified_at is not None
                or intent.completed_at is not None
                or intent.reason is not None
            ):
                raise OutboxValidationError("invalid_metadata")
            if generation.state is not PublicationState.exposed:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    generation=generation,
                    reason="integrity"
                    if generation.state is PublicationState.terminal_cleaned
                    else "running",
                )
            if intent.requested_at < generation.updated_at:
                raise OutboxValidationError("invalid_metadata")
            connection.exec_driver_sql(
                """
                INSERT INTO publication_cleanup_intents
                  (intent_id,publication_id,task_id,manifest_digest,exact_path,state,
                   requested_at,verified_at,completed_at,reason)
                VALUES
                  (:intent_id,:publication_id,:task_id,:manifest_digest,:exact_path,
                   'pending',:requested_at,NULL,NULL,NULL)
                """,
                {
                    "intent_id": intent.intent_id,
                    "publication_id": intent.publication_id,
                    "task_id": intent.task_id,
                    "manifest_digest": intent.manifest_digest,
                    "exact_path": intent.exact_path,
                    "requested_at": _publication_timestamp(intent.requested_at),
                },
            )
            saved_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent.intent_id},
            ).mappings().first()
            assert saved_row is not None
            saved = _publication_cleanup_from_row(saved_row)
            self._refresh_publication_health(connection, updated_at=intent.requested_at)
            connection.commit()
            inserted = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if inserted:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.enqueued,
            cleanup=saved,
        )

    def get_cleanup_intent(self, intent_id: str) -> CleanupIntent | None:
        with self.engine.begin() as connection:
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
        return None if row is None else _publication_cleanup_from_row(row)

    def list_cleanup_intents(
        self,
        *,
        task_id: str | None = None,
        states: set[CleanupState | str] | None = None,
    ) -> list[CleanupIntent]:
        parameters: dict[str, object] = {}
        clauses: list[str] = []
        if task_id is not None:
            clauses.append("task_id=:task_id")
            parameters["task_id"] = task_id
        if states:
            normalized = [CleanupState(item).value for item in states]
            placeholders = ",".join(f":cleanup_state_{index}" for index in range(len(normalized)))
            clauses.append(f"state IN ({placeholders})")
            parameters.update(
                {f"cleanup_state_{index}": value for index, value in enumerate(normalized)}
            )
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents"
                f"{where} ORDER BY requested_at,intent_id",
                parameters,
            ).mappings().all()
        return [_publication_cleanup_from_row(row) for row in rows]

    def verify_cleanup_intent(
        self,
        intent_id: str,
        *,
        manifest_digest: str,
        verified_at: datetime | None = None,
    ) -> PublicationOperationResult:
        """Record manifest verification before a deletion side effect."""

        timestamp = _publication_now(verified_at)
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
            if row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            current = _publication_cleanup_from_row(row)
            if current.manifest_digest != manifest_digest:
                raise OutboxValidationError("digest_mismatch")
            if timestamp < current.requested_at:
                raise OutboxValidationError("invalid_metadata")
            if current.state is CleanupState.completed:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    cleanup=current,
                )
            if current.state is CleanupState.blocked:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    cleanup=current,
                    reason=current.reason,
                )
            if current.verified_at is not None:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    cleanup=current,
                )
            update = connection.exec_driver_sql(
                "UPDATE publication_cleanup_intents SET verified_at=:verified_at "
                "WHERE intent_id=:intent_id AND state='pending' AND verified_at IS NULL",
                {"verified_at": _publication_timestamp(timestamp), "intent_id": intent_id},
            )
            if update.rowcount != 1:
                row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                    "WHERE intent_id=:intent_id",
                    {"intent_id": intent_id},
                ).mappings().first()
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    cleanup=None if row is None else _publication_cleanup_from_row(row),
                    reason="integrity",
                )
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
            assert row is not None
            updated = _publication_cleanup_from_row(row)
            self._refresh_publication_health(connection, updated_at=timestamp)
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.verified,
            cleanup=updated,
        )

    def complete_cleanup_intent(
        self,
        intent_id: str,
        *,
        manifest_digest: str | None = None,
        completed_at: datetime | None = None,
    ) -> PublicationOperationResult:
        """Finish one verified exact-path deletion and seal its generation."""

        timestamp = _publication_now(completed_at)
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
            if row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            current = _publication_cleanup_from_row(row)
            if manifest_digest is not None and current.manifest_digest != manifest_digest:
                raise OutboxValidationError("digest_mismatch")
            if timestamp < (current.verified_at or current.requested_at):
                raise OutboxValidationError("invalid_metadata")
            if current.state is CleanupState.completed:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    cleanup=current,
                )
            if current.state is not CleanupState.pending or current.verified_at is None:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    cleanup=current,
                    reason="integrity",
                )
            completion_text = _publication_timestamp(timestamp)
            update = connection.exec_driver_sql(
                "UPDATE publication_cleanup_intents SET state='completed',completed_at=:completed_at "
                "WHERE intent_id=:intent_id AND state='pending' AND verified_at IS NOT NULL",
                {"completed_at": completion_text, "intent_id": intent_id},
            )
            if update.rowcount != 1:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    cleanup=current,
                    reason="integrity",
                )
            generation_update = connection.exec_driver_sql(
                "UPDATE publication_generations SET state='terminal_cleaned',updated_at=:updated_at "
                "WHERE publication_id=:publication_id AND task_id=:task_id AND state='exposed'",
                {
                    "updated_at": completion_text,
                    "publication_id": current.publication_id,
                    "task_id": current.task_id,
                },
            )
            if generation_update.rowcount != 1:
                connection.rollback()
                return PublicationOperationResult(
                    PublicationOperationStatus.precondition,
                    cleanup=current,
                    reason="integrity",
                )
            updated_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
            assert updated_row is not None
            updated = _publication_cleanup_from_row(updated_row)
            self._refresh_publication_health(connection, updated_at=timestamp)
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.completed,
            cleanup=updated,
        )

    def block_cleanup_intent(
        self,
        intent_id: str,
        *,
        reason: str = "cleanup_failed",
        now: datetime | None = None,
    ) -> PublicationOperationResult:
        reason = _publication_reason(reason)
        assert reason is not None
        timestamp = _publication_now(now)
        connection = self.engine.connect()
        changed = False
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            current_row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
            if current_row is None:
                connection.commit()
                return PublicationOperationResult(PublicationOperationStatus.missing)
            current = _publication_cleanup_from_row(current_row)
            if timestamp < current.requested_at:
                raise OutboxValidationError("invalid_metadata")
            if current.state is CleanupState.completed:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing,
                    cleanup=current,
                )
            if current.state is CleanupState.blocked:
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.existing
                    if current.reason == reason
                    else PublicationOperationStatus.conflict,
                    cleanup=current,
                    reason=current.reason,
                )
            update = connection.exec_driver_sql(
                "UPDATE publication_cleanup_intents SET state='blocked',reason=:reason "
                "WHERE intent_id=:intent_id AND state='pending'",
                {"reason": reason, "intent_id": intent_id},
            )
            if update.rowcount != 1:
                row = connection.exec_driver_sql(
                    f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                    "WHERE intent_id=:intent_id",
                    {"intent_id": intent_id},
                ).mappings().first()
                connection.commit()
                return PublicationOperationResult(
                    PublicationOperationStatus.lost_claim,
                    cleanup=None if row is None else _publication_cleanup_from_row(row),
                    reason="cleanup_failed",
                )
            row = connection.exec_driver_sql(
                f"SELECT {_PUBLICATION_CLEANUP_COLUMNS} FROM publication_cleanup_intents "
                "WHERE intent_id=:intent_id",
                {"intent_id": intent_id},
            ).mappings().first()
            assert row is not None
            updated = _publication_cleanup_from_row(row)
            self._refresh_publication_health(
                connection, updated_at=timestamp, reason=updated.reason
            )
            connection.commit()
            changed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if changed:
            self._notify_change()
        return PublicationOperationResult(
            PublicationOperationStatus.blocked,
            cleanup=updated,
            reason=updated.reason,
        )

    def _expire_publication_leases_in_connection(
        self, connection: Connection, timestamp: datetime
    ) -> bool:
        return _expire_publication_leases_in_connection(self, connection, timestamp)

    def _refresh_publication_health(
        self,
        connection: Connection,
        *,
        updated_at: datetime,
        reason: str | None = None,
        preserve_category: bool = False,
    ) -> None:
        _refresh_publication_health(
            self,
            connection,
            updated_at=updated_at,
            reason=reason,
            preserve_category=preserve_category,
        )

    def _publication_exists(self, connection: Connection, publication_id: str) -> bool:
        return _publication_exists(connection, publication_id)

    def _ensure_publication_health(
        self, *, required: bool | None = None
    ) -> None:
        """Create the singleton health row and reconcile expired leases."""

        timestamp = _publication_now(None)
        if required is None:
            now_text = _publication_timestamp(timestamp)
            uri = self.path.resolve().as_uri() + "?mode=ro"
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(uri, uri=True)
                expired = connection.execute(
                    """
                    SELECT 1
                    FROM publication_generations AS generation
                    WHERE generation.state IN ('claimed','building','uploading','d1_staged')
                      AND generation.lease_expires_at <= ?
                      AND NOT EXISTS (
                          SELECT 1
                          FROM publication_hide_fences AS fence
                          WHERE fence.task_id=generation.task_id
                            AND fence.state IN ('pending','confirmed')
                      )
                    LIMIT 1
                    """,
                    (now_text,),
                ).fetchone()
                health_exists = connection.execute(
                    "SELECT 1 FROM publication_health WHERE id=1"
                ).fetchone()
            finally:
                if connection is not None:
                    connection.close()
            required = expired is not None or health_exists is None
        if not required:
            return

        with self.engine.begin() as connection:
            expired = self._expire_publication_leases_in_connection(
                connection, timestamp
            )
            self._refresh_publication_health(
                connection,
                updated_at=timestamp,
                reason="lease_expired" if expired else None,
                preserve_category=not expired,
            )

    def get_publication_health(
        self, *, now: datetime | None = None
    ) -> PublicationHealth:
        """Return bounded queue, block, and cleanup pressure facts."""

        with self.engine.begin() as connection:
            row = connection.exec_driver_sql(
                """
                SELECT
                  (SELECT COUNT(*) FROM publication_generations
                    WHERE state IN ('queued','retry_wait')) AS queued_count,
                  (SELECT COUNT(*) FROM publication_generations WHERE state='blocked') AS blocked_count,
                  (SELECT COUNT(*) FROM publication_cleanup_intents
                    WHERE state IN ('pending','blocked')) AS cleanup_count,
                  (SELECT COALESCE(SUM(receipt.byte_size),0)
                     FROM publication_cleanup_intents AS intent
                     LEFT JOIN publication_receipts AS receipt
                       ON receipt.publication_id=intent.publication_id
                    WHERE intent.state IN ('pending','blocked')) AS cleanup_bytes,
                  (SELECT MIN(created_at) FROM publication_generations
                    WHERE state IN ('queued','retry_wait')) AS oldest_queued_at,
                  (SELECT reason FROM publication_health WHERE id=1) AS reason,
                  (SELECT updated_at FROM publication_health WHERE id=1) AS updated_at
                """
            ).mappings().first()
        assert row is not None
        observed_at = _publication_now(now)
        timestamp = max(
            _publication_datetime(row["updated_at"])
            if row["updated_at"]
            else observed_at,
            observed_at,
        )
        oldest = (
            None
            if row["oldest_queued_at"] is None
            else _publication_datetime(row["oldest_queued_at"])
        )
        if oldest is not None:
            timestamp = max(timestamp, oldest)
        return PublicationHealth(
            queued_count=_bounded_health_count(row["queued_count"]),
            blocked_count=_bounded_health_count(row["blocked_count"]),
            cleanup_pending_count=_bounded_health_count(row["cleanup_count"]),
            cleanup_pending_bytes=_bounded_health_count(row["cleanup_bytes"]),
            updated_at=timestamp,
            reason=row["reason"],
            oldest_queued_at=oldest,
            last_category=row["reason"],
        )

    # ------------------------------------------------------------------
    # Private Compose release/container/resource facts

    def record_image_release(
        self,
        release_id: str,
        *,
        daemon_image_id: str,
        task_image_id: str,
        validation_image_id: str | None = None,
        labels: dict[str, object] | None = None,
        verified_at: datetime | None = None,
        current: bool = False,
        previous: bool = False,
    ) -> None:
        """Persist an immutable verified pair without secret or path data."""

        if not release_id or not daemon_image_id.startswith("sha256:") or not task_image_id.startswith("sha256:"):
            raise ValueError("release and image identities must be immutable")
        if validation_image_id is not None and not validation_image_id.startswith("sha256:"):
            raise ValueError("validation image identity must be immutable")
        timestamp = (verified_at or utc_now()).isoformat()
        payload = json.dumps(labels or {}, sort_keys=True, separators=(",", ":"))
        with self.engine.begin() as connection:
            if current:
                connection.exec_driver_sql(
                    "UPDATE steward_image_releases SET selected_current=0"
                )
            if previous:
                connection.exec_driver_sql(
                    "UPDATE steward_image_releases SET selected_previous=0"
                )
            connection.exec_driver_sql(
                """
                INSERT INTO steward_image_releases
                  (release_id,daemon_image_id,task_image_id,validation_image_id,labels_json,verified_at,selected_current,selected_previous)
                VALUES (:release_id,:daemon_image_id,:task_image_id,:validation_image_id,:labels_json,:verified_at,:current,:previous)
                ON CONFLICT(release_id) DO UPDATE SET
                  daemon_image_id=excluded.daemon_image_id,
                  task_image_id=excluded.task_image_id,
                  validation_image_id=excluded.validation_image_id,
                  labels_json=excluded.labels_json,
                  verified_at=excluded.verified_at,
                  selected_current=excluded.selected_current,
                  selected_previous=excluded.selected_previous
                """,
                {
                    "release_id": release_id,
                    "daemon_image_id": daemon_image_id,
                    "task_image_id": task_image_id,
                    "validation_image_id": validation_image_id,
                    "labels_json": payload,
                    "verified_at": timestamp,
                    "current": int(current),
                    "previous": int(previous),
                },
            )
        self._notify_change()

    def list_image_releases(self) -> list[dict[str, object]]:
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                "SELECT release_id,daemon_image_id,task_image_id,validation_image_id,labels_json,verified_at,selected_current,selected_previous FROM steward_image_releases ORDER BY verified_at"
            ).fetchall()
        return [
            {
                "release_id": row[0],
                "daemon_image_id": row[1],
                "task_image_id": row[2],
                "validation_image_id": row[3],
                "labels": json.loads(row[4] or "{}"),
                "verified_at": row[5],
                "current": bool(row[6]),
                "previous": bool(row[7]),
            }
            for row in rows
        ]

    def replace_container_references(
        self, references: list[dict[str, object]], *, updated_at: datetime | None = None
    ) -> None:
        """Replace the exact container view after one complete labeled scan."""

        timestamp = (updated_at or utc_now()).isoformat()
        normalized: list[dict[str, object]] = []
        for reference in references:
            container_id = str(reference.get("container_id", ""))
            image_id = str(reference.get("image_id", ""))
            epoch_id = str(reference.get("epoch_id", ""))
            if (
                not container_id
                or "\n" in container_id
                or not image_id.startswith("sha256:")
                or not epoch_id
                or "\n" in epoch_id
            ):
                raise ValueError("container reference identity is invalid")
            size = reference.get("size_bytes")
            if size is not None and (isinstance(size, bool) or int(size) < 0):
                raise ValueError("container reference size is invalid")
            normalized.append(
                {
                    "container_id": container_id,
                    "task_id": reference.get("task_id"),
                    "image_id": image_id,
                    "epoch_id": epoch_id,
                    "state": str(reference.get("state", "unknown"))[:64],
                    "cleanup_status": str(reference.get("cleanup_status", "active"))[
                        :64
                    ],
                    "size_bytes": int(size) if size is not None else None,
                    "updated_at": timestamp,
                }
            )
        with self.engine.begin() as connection:
            observed = {item["container_id"] for item in normalized}
            if observed:
                placeholders = ",".join("?" for _ in observed)
                connection.exec_driver_sql(
                    f"DELETE FROM steward_container_references WHERE container_id NOT IN ({placeholders})",  # nosec B608 - placeholders only
                    tuple(sorted(observed)),
                )
            else:
                connection.exec_driver_sql("DELETE FROM steward_container_references")
            for item in normalized:
                connection.exec_driver_sql(
                    """
                    INSERT INTO steward_container_references
                      (container_id,task_id,image_id,epoch_id,state,cleanup_status,size_bytes,updated_at)
                    VALUES (:container_id,:task_id,:image_id,:epoch_id,:state,:cleanup_status,:size_bytes,:updated_at)
                    ON CONFLICT(container_id) DO UPDATE SET
                      task_id=excluded.task_id,image_id=excluded.image_id,
                      epoch_id=excluded.epoch_id,state=excluded.state,
                      cleanup_status=excluded.cleanup_status,
                      size_bytes=excluded.size_bytes,updated_at=excluded.updated_at
                    """,
                    item,
                )
        self._notify_change()

    def list_container_references(self) -> list[dict[str, object]]:
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                "SELECT container_id,task_id,image_id,epoch_id,state,cleanup_status,size_bytes,updated_at FROM steward_container_references ORDER BY container_id"
            ).fetchall()
        return [
            {
                "container_id": row[0],
                "task_id": row[1],
                "image_id": row[2],
                "epoch_id": row[3],
                "state": row[4],
                "cleanup_status": row[5],
                "size_bytes": row[6],
                "updated_at": row[7],
            }
            for row in rows
        ]

    def record_validation_cleanup_pending(
        self,
        *,
        run_id: str,
        task_id: str,
        pipeline_id: str,
        owner_instance_id: str,
        container_name: str,
        image_id: str,
        epoch_id: str,
        release_id: str | None,
        deployment_id: str,
        worktree_path: Path,
        git_common_dir_path: Path,
        root_path: Path,
    ) -> None:
        """Persist cleanup authority before creating validation state."""

        tokens = (
            run_id,
            task_id,
            pipeline_id,
            owner_instance_id,
            container_name,
            epoch_id,
            deployment_id,
        )
        if any(not value or len(value) > 256 or "\n" in value for value in tokens):
            raise ValueError("validation cleanup identity is invalid")
        if release_id is not None and (
            not release_id or len(release_id) > 128 or "\n" in release_id
        ):
            raise ValueError("validation cleanup release identity is invalid")
        if (
            len(image_id) != 71
            or not image_id.startswith("sha256:")
            or any(value not in "0123456789abcdef" for value in image_id[7:])
        ):
            raise ValueError("validation cleanup image identity is invalid")
        paths = (Path(worktree_path), Path(git_common_dir_path), Path(root_path))
        if any(not path.is_absolute() or path.is_symlink() for path in paths):
            raise ValueError("validation cleanup paths must be absolute non-symlinks")
        timestamp = utc_now().isoformat()
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            existing = connection.exec_driver_sql(
                "SELECT cleanup_status FROM steward_validation_cleanups WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if existing is not None and existing[0] != "cleanup_complete":
                connection.exec_driver_sql("ROLLBACK")
                raise ValueError("validation cleanup is already pending")
            connection.exec_driver_sql(
                """
                INSERT INTO steward_validation_cleanups
                  (run_id,task_id,pipeline_id,owner_instance_id,container_name,
                   image_id,epoch_id,release_id,deployment_id,worktree_path,
                   git_common_dir_path,root_path,cleanup_ready,cleanup_status,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,'cleanup_pending',?)
                ON CONFLICT(run_id) DO UPDATE SET
                  task_id=excluded.task_id,pipeline_id=excluded.pipeline_id,
                  owner_instance_id=excluded.owner_instance_id,
                  container_name=excluded.container_name,image_id=excluded.image_id,
                  epoch_id=excluded.epoch_id,release_id=excluded.release_id,
                  deployment_id=excluded.deployment_id,
                  worktree_path=excluded.worktree_path,
                  git_common_dir_path=excluded.git_common_dir_path,
                  root_path=excluded.root_path,
                  cleanup_ready=0,cleanup_status='cleanup_pending',
                  updated_at=excluded.updated_at
                """,
                (
                    run_id,
                    task_id,
                    pipeline_id,
                    owner_instance_id,
                    container_name,
                    image_id,
                    epoch_id,
                    release_id,
                    deployment_id,
                    str(paths[0]),
                    str(paths[1]),
                    str(paths[2]),
                    timestamp,
                ),
            )
            connection.exec_driver_sql("COMMIT")
        self._notify_change()

    def mark_validation_cleanup_ready(self, run_id: str) -> None:
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(
                """
                UPDATE steward_validation_cleanups
                SET cleanup_ready=1,updated_at=?
                WHERE run_id=? AND cleanup_status='cleanup_pending'
                """,
                (utc_now().isoformat(), run_id),
            )
            if result.rowcount != 1:
                raise ValueError("validation cleanup record is unavailable")
        self._notify_change()

    def complete_validation_cleanup(self, run_id: str) -> None:
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(
                """
                UPDATE steward_validation_cleanups
                SET cleanup_ready=1,cleanup_status='cleanup_complete',updated_at=?
                WHERE run_id=? AND cleanup_status='cleanup_pending'
                """,
                (utc_now().isoformat(), run_id),
            )
            if result.rowcount != 1:
                raise ValueError("validation cleanup record is unavailable")
        self._notify_change()

    def list_validation_cleanup_pending(self) -> list[dict[str, object]]:
        with self.engine.begin() as connection:
            rows = connection.exec_driver_sql(
                """
                SELECT run_id,task_id,pipeline_id,owner_instance_id,container_name,
                       image_id,epoch_id,release_id,deployment_id,worktree_path,
                       git_common_dir_path,root_path,cleanup_ready,updated_at
                FROM steward_validation_cleanups
                WHERE cleanup_status='cleanup_pending'
                ORDER BY updated_at,run_id
                """
            ).fetchall()
        names = (
            "run_id",
            "task_id",
            "pipeline_id",
            "owner_instance_id",
            "container_name",
            "image_id",
            "epoch_id",
            "release_id",
            "deployment_id",
            "worktree_path",
            "git_common_dir_path",
            "root_path",
            "cleanup_ready",
            "updated_at",
        )
        records = [dict(zip(names, row, strict=True)) for row in rows]
        for record in records:
            record["cleanup_ready"] = bool(record["cleanup_ready"])
        return records

    def referenced_image_ids(self) -> frozenset[str]:
        """Return exact images protected by deployment, ledger, or containers."""

        with self.engine.begin() as connection:
            releases = connection.exec_driver_sql(
                "SELECT daemon_image_id,task_image_id,validation_image_id FROM steward_image_releases WHERE selected_current=1 OR selected_previous=1"
            ).fetchall()
            containers = connection.exec_driver_sql(
                "SELECT DISTINCT image_id FROM steward_container_references"
            ).fetchall()
            validation_cleanups = connection.exec_driver_sql(
                "SELECT DISTINCT image_id FROM steward_validation_cleanups WHERE cleanup_status='cleanup_pending'"
            ).fetchall()
            sessions = connection.exec_driver_sql(
                """
                SELECT DISTINCT session.image_digest
                FROM codex_sessions AS session
                JOIN tasks AS task ON task.id=session.task_id
                WHERE session.image_digest IS NOT NULL AND (
                  task.status IN ('queued','running','reviewing','integrating')
                  OR session.state IN ('active','interrupted')
                  OR (
                    EXISTS (SELECT 1 FROM events AS pending WHERE pending.task_id=task.id AND pending.kind='cleanup_pending')
                    AND NOT EXISTS (SELECT 1 FROM events AS complete WHERE complete.task_id=task.id AND complete.kind='cleanup_complete')
                  )
                )
                """
            ).fetchall()
        values = {str(row[0]) for row in containers if row[0]}
        values.update(str(row[0]) for row in validation_cleanups if row[0])
        values.update(str(row[0]) for row in sessions if row[0])
        for daemon_image_id, task_image_id, validation_image_id in releases:
            values.update((str(daemon_image_id), str(task_image_id)))
            if validation_image_id:
                values.add(str(validation_image_id))
        return frozenset(values)

    def record_resource_pressure(
        self,
        *,
        state: str,
        home_free_bytes: int | None,
        owned_docker_bytes: int | None,
        cleanup_pending_count: int = 0,
        reason: str | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        if state not in {"normal", "resource_pressure"}:
            raise ValueError("invalid resource pressure state")
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                """
                INSERT INTO steward_resource_pressure
                  (id,state,home_free_bytes,owned_docker_bytes,cleanup_pending_count,reason,updated_at)
                VALUES (1,:state,:home_free_bytes,:owned_docker_bytes,:cleanup_pending_count,:reason,:updated_at)
                ON CONFLICT(id) DO UPDATE SET
                  state=excluded.state,home_free_bytes=excluded.home_free_bytes,
                  owned_docker_bytes=excluded.owned_docker_bytes,
                  cleanup_pending_count=excluded.cleanup_pending_count,
                  reason=excluded.reason,updated_at=excluded.updated_at
                """,
                {
                    "state": state,
                    "home_free_bytes": home_free_bytes,
                    "owned_docker_bytes": owned_docker_bytes,
                    "cleanup_pending_count": cleanup_pending_count,
                    "reason": reason,
                    "updated_at": (updated_at or utc_now()).isoformat(),
                },
            )
        self._notify_change()

    def get_resource_pressure(self) -> dict[str, object]:
        with self.engine.begin() as connection:
            row = connection.exec_driver_sql(
                "SELECT state,home_free_bytes,owned_docker_bytes,cleanup_pending_count,reason,updated_at FROM steward_resource_pressure WHERE id=1"
            ).fetchone()
        if row is None:
            return {"state": "normal", "home_free_bytes": None, "owned_docker_bytes": None, "cleanup_pending_count": 0, "reason": None, "updated_at": None}
        return {"state": row[0], "home_free_bytes": row[1], "owned_docker_bytes": row[2], "cleanup_pending_count": row[3], "reason": row[4], "updated_at": row[5]}

    def scheduler_snapshot(
        self, providers: Iterable[str] = ()
    ) -> SchedulerStoreSnapshot:
        """Read bounded scheduler inputs in one SQLite transaction."""

        provider_names = tuple(dict.fromkeys(providers))
        active_statuses = [
            TaskStatus.running.value,
            TaskStatus.reviewing.value,
            TaskStatus.integrating.value,
        ]
        latest_fetches: dict[str, SignalFetchRun | None] = {
            provider: None for provider in provider_names
        }
        with Session(self.engine) as session, session.begin():
            source_active = _count_tasks(
                session,
                statuses=active_statuses,
                integration=False,
            )
            source_queued = _count_tasks(
                session,
                statuses=[TaskStatus.queued.value],
                integration=False,
            )
            integration_active = _count_tasks(
                session,
                statuses=active_statuses,
                integration=True,
            )
            integration_queued = _count_tasks(
                session,
                statuses=[TaskStatus.queued.value],
                integration=True,
            )
            pending_wakeup_rows = session.scalars(
                select(SchedulerWakeupRow)
                .where(SchedulerWakeupRow.status == SchedulerWakeupStatus.pending.value)
                .order_by(SchedulerWakeupRow.created_at)
                .limit(20)
            ).all()
            recent_wakeup_rows = session.scalars(
                select(SchedulerWakeupRow)
                .order_by(SchedulerWakeupRow.created_at.desc())
                .limit(20)
            ).all()
            pending_signal = (
                session.scalar(
                    select(SignalItemRow.id)
                    .where(
                        SignalItemRow.status == SignalItemStatus.pending.value,
                        SignalItemRow.kind != "signal-error",
                    )
                    .limit(1)
                )
                is not None
            )
            if provider_names:
                ranked_fetches = (
                    select(
                        SignalFetchRunRow,
                        func.row_number()
                        .over(
                            partition_by=SignalFetchRunRow.provider,
                            order_by=SignalFetchRunRow.completed_at.desc(),
                        )
                        .label("provider_rank"),
                    )
                    .where(SignalFetchRunRow.provider.in_(provider_names))
                    .subquery()
                )
                latest_fetch_row = aliased(SignalFetchRunRow, ranked_fetches)
                latest_rows = session.scalars(
                    select(latest_fetch_row).where(
                        ranked_fetches.c.provider_rank == 1
                    )
                ).all()
                latest_fetches.update(
                    {
                        row.provider: row_to_signal_fetch_run(row)
                        for row in latest_rows
                    }
                )
            pending_wakeups = tuple(
                row_to_scheduler_wakeup(row, path_codec=self.path_codec)
                for row in pending_wakeup_rows
            )
            recent_wakeups = tuple(
                row_to_scheduler_wakeup(row, path_codec=self.path_codec)
                for row in recent_wakeup_rows
            )

        return SchedulerStoreSnapshot(
            source_active=source_active,
            source_queued=source_queued,
            integration_active=integration_active,
            integration_queued=integration_queued,
            pending_wakeups=pending_wakeups,
            recent_wakeups=recent_wakeups,
            pending_signal=pending_signal,
            latest_fetches=latest_fetches,
        )

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
            try:
                self.prune_consumed_wakeups(_notify=False)
            finally:
                self._notify_change()
        return consumed

    def prune_consumed_wakeups(
        self, *, older_than_days: int = 7, _notify: bool = True
    ) -> int:
        cutoff = (utc_now() - timedelta(days=older_than_days)).isoformat()
        with Session(self.engine) as session, session.begin():
            result = session.execute(
                sql_delete(SchedulerWakeupRow).where(
                    SchedulerWakeupRow.status == SchedulerWakeupStatus.consumed.value,
                    SchedulerWakeupRow.consumed_at < cutoff,
                )
            )
            deleted = int(result.rowcount or 0)
        if deleted and _notify:
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
            session.flush()
            raw_connection = session.connection().connection.driver_connection
            raw_connection.row_factory = sqlite3.Row
            self.control_loop.transition_signal_identities(
                [(row.provider, row.fingerprint) for row in rows],
                "planned",
                planner_run_id=planner_run_id,
                reason="legacy_signal_planned",
                connection=raw_connection,
            )
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
            session.flush()
            if requeued:
                raw_connection = session.connection().connection.driver_connection
                raw_connection.row_factory = sqlite3.Row
                self.control_loop.transition_signal_identities(
                    [
                        (signal_row.provider, signal_row.fingerprint)
                        for signal_row, _task_row in rows
                        if signal_row.status == SignalItemStatus.pending.value
                    ],
                    "pending",
                    reason="failed_task_requeued",
                    connection=raw_connection,
                )
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
            session.flush()
            raw_connection = session.connection().connection.driver_connection
            raw_connection.row_factory = sqlite3.Row
            self.control_loop.transition_signal_identities(
                [(row.provider, row.fingerprint) for row in rows],
                "superseded",
                planner_run_id=planner_run_id,
                reason="signal_superseded",
                connection=raw_connection,
            )
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

    def list_tasks_page(
        self,
        *,
        limit: int = 100,
        statuses: Iterable[TaskStatus | str] | TaskStatus | str | None = None,
        status: TaskStatus | str | None = None,
        after: tuple[str, str] | None = None,
        cursor: tuple[str, str] | None = None,
        page_size: int | None = None,
    ) -> TaskPage:
        """Return one detached, stable keyset page of tasks.

        Pages use newest-first ``(created_at, id)`` ordering.  The immutable
        task id breaks timestamp ties, and the returned cursor is the last
        materialized row rather than an offset.  A page owns its database
        transaction; callers can safely perform external work before asking
        for the next page.
        """

        if page_size is not None:
            if limit != 100 and limit != page_size:
                raise ValueError("limit and page_size disagree")
            limit = page_size
        if limit <= 0:
            raise ValueError("task page limit must be positive")
        if status is not None:
            if statuses is not None:
                raise ValueError("status and statuses are mutually exclusive")
            statuses = status
        if after is not None and cursor is not None and after != cursor:
            raise ValueError("after and cursor disagree")
        selected_cursor = cursor if cursor is not None else after
        if selected_cursor is not None:
            if (
                not isinstance(selected_cursor, tuple)
                or len(selected_cursor) != 2
                or any(not isinstance(value, str) for value in selected_cursor)
            ):
                raise ValueError("task cursor must be a (created_at, task_id) tuple")

        normalized_statuses = _normalize_task_statuses(statuses)
        statement = _task_query()
        if normalized_statuses is not None:
            statement = statement.where(TaskRow.status.in_(normalized_statuses))
        if normalized_statuses == ():
            return TaskPage([], None)
        if selected_cursor is not None:
            created_at, task_id = selected_cursor
            statement = statement.where(
                or_(
                    TaskRow.created_at < created_at,
                    and_(
                        TaskRow.created_at == created_at,
                        TaskRow.id < task_id,
                    ),
                )
            )
        statement = statement.order_by(TaskRow.created_at.desc(), TaskRow.id.desc())
        with Session(self.engine) as session:
            rows = session.scalars(statement.limit(limit + 1)).all()
            has_more = len(rows) > limit
            rows = rows[:limit]
            tasks = [
                row_to_task(row, path_codec=self.path_codec)
                for row in rows
            ]
        next_cursor = (
            (rows[-1].created_at, rows[-1].id) if has_more and rows else None
        )
        return TaskPage(tasks, next_cursor)

    # A short name is useful to callers that already use ``list_*`` for
    # unpaged compatibility methods.

    def iter_tasks(
        self,
        *,
        page_size: int = 100,
        statuses: Iterable[TaskStatus | str] | TaskStatus | str | None = None,
        status: TaskStatus | str | None = None,
    ) -> Iterator[TaskRecord]:
        """Iterate detached task pages without holding a transaction open."""

        if status is not None:
            if statuses is not None:
                raise ValueError("status and statuses are mutually exclusive")
            statuses = status
        statuses = _normalize_task_statuses(statuses)
        cursor: tuple[str, str] | None = None
        while True:
            page = self.list_tasks_page(
                limit=page_size,
                statuses=statuses,
                cursor=cursor,
            )
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def dispatch_snapshot(
        self,
        *,
        source_limit: int,
        integration_limit: int,
        resumable_limit: int,
    ) -> DispatchSnapshot:
        """Read one bounded dispatch snapshot in one SQLite transaction.

        Queued lanes are selected independently so a saturated integration lane
        cannot consume the source candidate bound.
        """

        source_limit = _validate_dispatch_limit(source_limit, "source")
        integration_limit = _validate_dispatch_limit(integration_limit, "integration")
        resumable_limit = _validate_dispatch_limit(resumable_limit, "resumable")
        active_statuses = [
            TaskStatus.running.value,
            TaskStatus.reviewing.value,
            TaskStatus.integrating.value,
        ]
        integration_worker = WorkerKind.integration_manager.value

        with Session(self.engine) as session, session.begin():
            source_active = _count_tasks(
                session,
                statuses=active_statuses,
                integration=False,
            )
            integration_active = _count_tasks(
                session,
                statuses=active_statuses,
                integration=True,
            )
            integration_rows = session.scalars(
                _task_query()
                .where(
                    TaskRow.status == TaskStatus.queued.value,
                    TaskRow.worker == integration_worker,
                )
                .order_by(*_queued_dispatch_order())
                .limit(integration_limit)
            ).all()
            source_rows = session.scalars(
                _task_query()
                .where(
                    TaskRow.status == TaskStatus.queued.value,
                    TaskRow.worker != integration_worker,
                )
                .order_by(*_queued_dispatch_order())
                .limit(source_limit)
            ).all()
            resumable_rows = session.scalars(
                _task_query()
                .where(TaskRow.status.in_(active_statuses))
                .order_by(TaskRow.created_at.desc(), TaskRow.id.desc())
                .limit(resumable_limit)
            ).all()
            queued = [
                row_to_task(row, path_codec=self.path_codec)
                for row in [*integration_rows, *source_rows]
            ]
            resumable = [
                row_to_task(row, path_codec=self.path_codec)
                for row in resumable_rows
            ]

        return DispatchSnapshot(
            queued_tasks=tuple(queued),
            resumable_tasks=tuple(resumable),
            source_active_count=source_active,
            integration_active_count=integration_active,
        )

    def queued_tasks(self, *, limit: int | None = None) -> list[TaskRecord]:
        tasks = self._tasks_by_status(TaskStatus.queued)
        tasks.sort(
            key=lambda task: (
                0 if task.spec.worker == "integration-manager" else 1,
                PRIORITY_ORDER.get(str(task.spec.priority), 99),
                task.created_at,
                task.id,
            )
        )
        return tasks if limit is None else tasks[:limit]

    def active_count(self) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(TaskRow)
                    .where(
                        TaskRow.status.in_(ACTIVE_STATUSES),
                    )
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

    def events(self, task_id: str, *, limit: int | None = None) -> list[Event]:
        statement = (
            select(EventRow)
            .where(EventRow.task_id == task_id)
            .order_by(EventRow.created_at, EventRow.id)
        )
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_event(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def cleanup_obligation_state(self, task_id: str) -> CleanupStatus | None:
        """Return the latest ordered terminal cleanup obligation state."""

        with Session(self.engine) as session:
            kind = session.scalar(
                select(EventRow.kind)
                .where(
                    EventRow.task_id == task_id,
                    EventRow.kind.in_(
                        (
                            CleanupStatus.pending.value,
                            CleanupStatus.complete.value,
                        )
                    ),
                )
                .order_by(EventRow.id.desc())
                .limit(1)
            )
        return CleanupStatus(kind) if kind is not None else None

    def event_exists(self, task_id: str, kind: str) -> bool:
        """Return whether one event kind exists for a task."""

        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(EventRow.id)
                    .where(EventRow.task_id == task_id, EventRow.kind == kind)
                    .limit(1)
                )
                is not None
            )

    def count_task_events(self, task_id: str, kind: str | None = None) -> int:
        statement = select(func.count()).select_from(EventRow).where(
            EventRow.task_id == task_id
        )
        if kind is not None:
            statement = statement.where(EventRow.kind == kind)
        with Session(self.engine) as session:
            return session.scalar(statement) or 0

    def cleanup_pending_tasks(
        self,
        *,
        limit: int | None = None,
        statuses: Iterable[TaskStatus | str] | TaskStatus | str | None = None,
        status: TaskStatus | str | None = None,
    ) -> list[TaskRecord]:
        """Return tasks whose latest cleanup obligation is still pending.

        A completion only clears a pending event when it was recorded later
        than that pending event.  Duplicate pending events therefore describe
        one task obligation, while a later pending event re-opens an earlier
        completed obligation.
        """

        if status is not None:
            if statuses is not None:
                raise ValueError("status and statuses are mutually exclusive")
            statuses = status
        normalized_statuses = _normalize_task_statuses(statuses)
        if normalized_statuses == ():
            return []
        statement = _task_query().where(_cleanup_pending_predicate())
        if normalized_statuses is not None:
            statement = statement.where(TaskRow.status.in_(normalized_statuses))
        statement = statement.order_by(TaskRow.created_at, TaskRow.id)
        if limit is not None:
            if limit < 0:
                raise ValueError("cleanup task limit must not be negative")
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            rows = session.scalars(statement).all()
            return [
                row_to_task(row, path_codec=self.path_codec)
                for row in rows
            ]

    def cleanup_pending_task_ids(self, *, limit: int | None = None) -> list[str]:
        statement = (
            select(TaskRow.id)
            .where(_cleanup_pending_predicate())
            .order_by(TaskRow.created_at, TaskRow.id)
        )
        if limit is not None:
            if limit < 0:
                raise ValueError("cleanup task limit must not be negative")
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return list(session.scalars(statement).all())

    def cleanup_pending_count(self) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(TaskRow)
                    .where(_cleanup_pending_predicate())
                )
                or 0
            )

    def has_cleanup_pending(self, task_id: str) -> bool:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(TaskRow.id)
                    .where(TaskRow.id == task_id, _cleanup_pending_predicate())
                    .limit(1)
                )
                is not None
            )

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

    def audit(self) -> list[str]:
        findings: list[str] = []
        seen: set[str] = set()
        for task in self.list_tasks():
            if task.id in seen:
                findings.append(f"duplicate task id: {task.id}")
            seen.add(task.id)
            try:
                task_mode = self.task_execution_mode(task.id)
                task_effect = self.effect_result(task.id)
            except (KeyError, TypeError, ValueError):
                task_mode = None
                task_effect = None
            if (
                TaskStatus(task.status).terminal
                and task_mode is ExecutionMode.dry_run
                and task_effect is None
            ):
                findings.append(f"{task.id}: terminal dry-run task has no effect result")
            proposal_only = (
                task_mode is ExecutionMode.dry_run
                and task_effect in {EffectResult.not_applied, EffectResult.not_applicable}
            )
            if (
                TaskStatus(task.status) == TaskStatus.succeeded
                and task.patch_path is None
                and not proposal_only
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

    def find_active_dedupe(self, dedupe_key: str) -> TaskRecord | None:
        """Return the active task for one indexed dedupe key, if present."""

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


def _validated_fields(
    fields: dict[str, object], allowed: tuple[str, ...], label: str
) -> dict[str, object]:
    unknown = set(fields) - set(allowed)
    if unknown:
        raise ValueError(f"unsupported {label} fields: {sorted(unknown)}")
    return {key: fields[key] for key in allowed if key in fields}


def _pipeline_fields(fields: dict[str, object]) -> dict[str, object]:
    return _validated_fields(
        fields,
        (
            "phase",
            "state",
            "base_identity",
            "input_identity",
            "output_identity",
            "patch_identity",
            "metadata",
            "completed_at",
            "archive_generation",
        ),
        "pipeline",
    )


def _run_fields(fields: dict[str, object]) -> dict[str, object]:
    return _validated_fields(
        fields,
        (
            "state",
            "model",
            "reasoning",
            "image_version",
            "runtime_version",
            "checkpoint_id",
            "provider_run_id",
            "provider_store_identity",
            "wrapper_pid",
            "exec_identity",
            "exit_code",
            "exit_signal",
            "exit_reason",
            "result_summary",
            "completed_at",
            "archive_generation",
        ),
        "run",
    )


def _live_rerun_dedupe_key(source_task_id: str) -> str:
    if not isinstance(source_task_id, str) or not source_task_id:
        raise ValueError("source task id is required")
    return f"live-rerun:{source_task_id}"


def _metadata_dict(value: str | None, path_codec: PathCodec) -> dict[str, object]:
    try:
        loaded = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("task metadata is not valid JSON") from exc
    if not isinstance(loaded, dict):
        return {}
    decoded = path_codec.load_json(loaded)
    return decoded if isinstance(decoded, dict) else {}


def _dump_metadata(metadata: dict[str, object], path_codec: PathCodec) -> str:
    dumped = path_codec.dump_json(metadata)
    return json.dumps(dumped, sort_keys=True)


def _task_query() -> Select[tuple[TaskRow]]:
    return select(TaskRow).options(selectinload(TaskRow.validations))


def _live_task_latch():
    """Match only the Store-owned top-level live execution latch."""

    return and_(
        func.json_valid(TaskRow.metadata_json) == 1,
        func.json_extract(TaskRow.metadata_json, "$.execution_mode")
        == ExecutionMode.live.value,
    )


def _task_row_is_dry_run(task: TaskRow | None) -> bool:
    """Treat a reserved dry-run latch as ongoing signal coverage."""

    if task is None:
        return False
    try:
        metadata = json.loads(task.metadata_json or "{}")
        if not isinstance(metadata, dict):
            return True
        return execution_mode_from_metadata(metadata) is ExecutionMode.dry_run
    except (TypeError, ValueError, json.JSONDecodeError):
        return True


def _queued_dispatch_order():
    return (
        case(
            (TaskRow.worker == WorkerKind.integration_manager.value, 0),
            else_=1,
        ),
        case(
            (TaskRow.priority == "urgent", 0),
            (TaskRow.priority == "high", 1),
            (TaskRow.priority == "medium", 2),
            (TaskRow.priority == "low", 3),
            else_=99,
        ),
        TaskRow.created_at,
        TaskRow.id,
    )


def _validate_dispatch_limit(value: int, lane: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{lane} dispatch limit must be a non-negative integer")
    return value


def _normalize_task_statuses(
    statuses: Iterable[TaskStatus | str] | TaskStatus | str | None,
) -> tuple[str, ...] | None:
    if statuses is None:
        return None
    if isinstance(statuses, (TaskStatus, str)):
        statuses = (statuses,)
    normalized: list[str] = []
    for status in statuses:
        value = status.value if isinstance(status, TaskStatus) else str(status)
        normalized_value = TaskStatus(value).value
        if normalized_value not in normalized:
            normalized.append(normalized_value)
    return tuple(normalized)


def _cleanup_pending_predicate():
    """Correlate each task with its latest unresolved cleanup event."""

    pending = aliased(EventRow)
    complete = aliased(EventRow)
    later_completion = (
        select(1)
        .select_from(complete)
        .where(
            complete.task_id == pending.task_id,
            complete.kind == "cleanup_complete",
            complete.id > pending.id,
        )
        .correlate(pending)
        .exists()
    )
    return (
        select(1)
        .select_from(pending)
        .where(
            pending.task_id == TaskRow.id,
            pending.kind == "cleanup_pending",
            ~later_completion,
        )
        .correlate(TaskRow)
        .exists()
    )


def _count_tasks(
    session: Session,
    *,
    statuses: list[str],
    integration: bool,
    live_only: bool = False,
) -> int:
    statement = select(func.count()).select_from(TaskRow).where(TaskRow.status.in_(statuses))
    if integration:
        statement = statement.where(TaskRow.worker == WorkerKind.integration_manager.value)
    else:
        statement = statement.where(TaskRow.worker != WorkerKind.integration_manager.value)
    if live_only:
        statement = statement.where(_live_task_latch())
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


def _matching_signal_row(
    session: Session,
    item: SignalItem,
    *,
    workflow_identity: SignalWorkflowIdentity | None,
) -> SignalItemRow | None:
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
    if workflow_identity is None:
        return None
    return session.scalar(
        select(SignalItemRow)
        .where(
            SignalItemRow.provider == item.provider,
            SignalItemRow.workflow_run_id == workflow_identity.run_id,
            SignalItemRow.workflow_run_attempt == workflow_identity.run_attempt,
        )
        .order_by(SignalItemRow.updated_at.desc())
        .limit(1)
    )


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


# Publication values are serialized at the store boundary instead of relying
# on SQLAlchemy's datetime adapters.  The schema intentionally accepts only
# UTC millisecond timestamps, so every read/write uses these bounded helpers.
def _publication_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(
                value[:-1] + "+00:00" if value.endswith("Z") else value
            )
        except ValueError:
            raise OutboxValidationError("invalid_metadata") from None
    else:
        raise OutboxValidationError("invalid_metadata")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OutboxValidationError("invalid_metadata")
    return parsed.astimezone(timezone.utc)


def _publication_timestamp(value: object) -> str:
    return (
        _publication_datetime(value)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _publication_now(value: datetime | None) -> datetime:
    return _publication_datetime(value or datetime.now(timezone.utc))


def _publication_identifier(value: object, *, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise OutboxValidationError("invalid_identifier")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is None:
        raise OutboxValidationError("invalid_identifier")
    if prefix is not None and not value.startswith(prefix):
        raise OutboxValidationError("invalid_identifier")
    return value


def _publication_reason(value: object | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise OutboxValidationError("invalid_metadata")
    reason = value
    if reason not in _PERSISTED_REASON_SET:
        raise OutboxValidationError("invalid_metadata")
    return reason


def _bounded_publication_seconds(
    value: object, maximum: int, *, minimum: int = 0
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OutboxValidationError("invalid_metadata")
    if value < minimum or value > maximum:
        raise OutboxValidationError("invalid_metadata")
    return value


def _bounded_health_count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        count = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(count, 2**31 - 1))


def _publication_generation_from_row(row: Mapping[str, object]) -> PublicationGeneration:
    return PublicationGeneration(
        publication_id=str(row["publication_id"]),
        task_id=str(row["task_id"]),
        run_id=str(row["run_id"]),
        generation_boundary=str(row["generation_boundary"]),
        metadata_digest=str(row["metadata_digest"]),
        idempotency_key=str(row["idempotency_key"]),
        state=str(row["state"]),
        attempt=int(row["attempt"]),
        lease_owner=None if row["lease_owner"] is None else str(row["lease_owner"]),
        lease_expires_at=row["lease_expires_at"],
        retry_at=row["retry_at"],
        reason=None if row["reason"] is None else str(row["reason"]),
        rows=int(row["expected_row_count"]),
        objects=int(row["expected_object_count"]),
        tasks=int(row["expected_task_count"]),
        pipelines=int(row["expected_pipeline_count"]),
        runs=int(row["expected_run_count"]),
        events=int(row["expected_event_count"]),
        artifacts=int(row["expected_artifact_count"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        exposed_at=row["exposed_at"],
    )


def _publication_receipt_from_row(row: Mapping[str, object]) -> PublicationReceipt:
    return PublicationReceipt(
        receipt_class=str(row["receipt_class"]),
        sha256=str(row["sha256"]),
        byte_size=int(row["byte_size"]),
        content_key=str(row["content_key"]),
        logical_path=None if row["logical_path"] is None else str(row["logical_path"]),
        verified_at=row["verified_at"],
    )


def _publication_cleanup_from_row(row: Mapping[str, object]) -> CleanupIntent:
    value = CleanupIntent(
        task_id=str(row["task_id"]),
        publication_id=str(row["publication_id"]),
        manifest_digest=str(row["manifest_digest"]),
        exact_path=str(row["exact_path"]),
        state=str(row["state"]),
        requested_at=row["requested_at"],
        verified_at=row["verified_at"],
        completed_at=row["completed_at"],
        reason=None if row["reason"] is None else str(row["reason"]),
    )
    if str(row["intent_id"]) != value.intent_id:
        raise OutboxValidationError("integrity")
    return value


def _publication_hide_from_row(row: Mapping[str, object]) -> PublicationHideFence:
    return PublicationHideFence(
        task_id=str(row["task_id"]),
        reason=str(row["reason"]),
        state=str(row["state"]),
        generation_boundary=(
            None
            if row["generation_boundary"] is None
            else str(row["generation_boundary"])
        ),
        requested_at=row["requested_at"],
        confirmed_at=row["confirmed_at"],
    )


def _publication_counts_values(
    counts: PublicationCounts | Mapping[str, object] | None,
    *,
    rows: int,
    objects: int,
    tasks: int,
    pipelines: int,
    runs: int,
    events: int,
    artifacts: int,
) -> dict[str, int]:
    values: dict[str, object] = {
        "rows": rows,
        "objects": objects,
        "tasks": tasks,
        "pipelines": pipelines,
        "runs": runs,
        "events": events,
        "artifacts": artifacts,
    }
    if counts is not None:
        if isinstance(counts, PublicationCounts):
            source: Mapping[str, object] = {
                "rows": counts.rows,
                "objects": counts.objects,
                "tasks": counts.tasks,
                "pipelines": counts.pipelines,
                "runs": counts.runs,
                "events": counts.events,
                "artifacts": counts.artifacts,
            }
        elif isinstance(counts, Mapping):
            source = counts
        else:
            raise OutboxValidationError("invalid_metadata")
        for name in values:
            if name in source:
                values[name] = source[name]
    for name, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise OutboxValidationError("invalid_metadata")
    return values  # type: ignore[return-value]


def _coerce_publication_generation(
    generation: PublicationGeneration | None,
    *,
    task_id: str | None,
    run_id: str | None,
    generation_boundary: str | None,
    metadata_digest: str | None,
    publication_id: str | None,
    idempotency_key: str | None,
    counts: PublicationCounts | Mapping[str, object] | None,
    rows: int,
    objects: int,
    tasks: int,
    pipelines: int,
    runs: int,
    events: int,
    artifacts: int,
    created_at: datetime | None,
    updated_at: datetime | None,
) -> PublicationGeneration:
    if generation is not None:
        if not isinstance(generation, PublicationGeneration):
            raise OutboxValidationError("invalid_metadata")
        return generation
    if task_id is None or run_id is None or generation_boundary is None or metadata_digest is None:
        raise OutboxValidationError("invalid_metadata")
    identity = GenerationIdentity(task_id, generation_boundary)
    count_values = _publication_counts_values(
        counts,
        rows=rows,
        objects=objects,
        tasks=tasks,
        pipelines=pipelines,
        runs=runs,
        events=events,
        artifacts=artifacts,
    )
    created = _publication_now(created_at)
    return PublicationGeneration(
        publication_id=publication_id or identity.publication_id,
        task_id=identity.task_id,
        run_id=run_id,
        generation_boundary=identity.stable_boundary,
        metadata_digest=metadata_digest,
        idempotency_key=idempotency_key or identity.idempotency_key,
        rows=count_values["rows"],
        objects=count_values["objects"],
        tasks=count_values["tasks"],
        pipelines=count_values["pipelines"],
        runs=count_values["runs"],
        events=count_values["events"],
        artifacts=count_values["artifacts"],
        created_at=created,
        updated_at=created if updated_at is None else updated_at,
    )


def _generation_parameters(value: PublicationGeneration) -> dict[str, object]:
    return {
        "publication_id": value.publication_id,
        "task_id": value.task_id,
        "run_id": value.run_id,
        "generation_boundary": value.generation_boundary,
        "metadata_digest": value.metadata_digest,
        "idempotency_key": value.idempotency_key,
        "expected_row_count": value.rows,
        "expected_object_count": value.objects,
        "expected_task_count": value.tasks,
        "expected_pipeline_count": value.pipelines,
        "expected_run_count": value.runs,
        "expected_event_count": value.events,
        "expected_artifact_count": value.artifacts,
        "created_at": _publication_timestamp(value.created_at),
        "updated_at": _publication_timestamp(value.updated_at),
    }


def _same_generation_input(
    existing: PublicationGeneration, candidate: PublicationGeneration
) -> bool:
    return (
        existing.publication_id == candidate.publication_id
        and existing.task_id == candidate.task_id
        and existing.run_id == candidate.run_id
        and existing.generation_boundary == candidate.generation_boundary
        and existing.metadata_digest == candidate.metadata_digest
        and existing.idempotency_key == candidate.idempotency_key
        and existing.counts() == candidate.counts()
    )


def _publication_transition_values(
    current: PublicationGeneration,
    target: PublicationState,
    *,
    timestamp: datetime,
    lease_owner: str | None,
    lease_expires_at: datetime | None,
    retry_at: datetime | None,
    reason: str | None,
) -> dict[str, object]:
    updated = _publication_now(timestamp)
    if updated < current.updated_at:
        raise OutboxValidationError("invalid_metadata")
    owner = lease_owner
    expires = lease_expires_at
    retry = retry_at
    safe_reason = _publication_reason(reason)
    if target in {
        PublicationState.claimed,
        PublicationState.building,
        PublicationState.uploading,
        PublicationState.d1_staged,
    }:
        owner = owner or current.lease_owner
        if owner is None:
            raise OutboxValidationError("invalid_metadata")
        owner = _publication_identifier(owner)
        expires = (
            current.lease_expires_at
            if expires is None
            else _publication_datetime(expires)
        )
        if expires is None:
            expires = updated + timedelta(seconds=MAX_LEASE_SECONDS)
        if expires < updated or expires > updated + timedelta(seconds=MAX_LEASE_SECONDS):
            raise OutboxValidationError("invalid_metadata")
        retry = None
        safe_reason = None
    elif target is PublicationState.retry_wait:
        owner = None
        expires = None
        retry = updated + timedelta(seconds=1) if retry is None else _publication_datetime(retry)
        if retry < updated or retry > updated + timedelta(seconds=MAX_RETRY_DELAY_SECONDS):
            raise OutboxValidationError("invalid_metadata")
        safe_reason = safe_reason or "network"
    elif target is PublicationState.blocked:
        owner = None
        expires = None
        retry = None
        if safe_reason is None:
            raise OutboxValidationError("invalid_metadata")
    else:
        owner = None
        expires = None
        retry = None
        safe_reason = None
    exposed_at = current.exposed_at
    if target is PublicationState.exposed:
        exposed_at = updated
    return {
        "state": target.value,
        "lease_owner": owner,
        "lease_expires_at": None if expires is None else _publication_timestamp(expires),
        "retry_at": None if retry is None else _publication_timestamp(retry),
        "reason": safe_reason,
        "updated_at": _publication_timestamp(updated),
        "exposed_at": None if exposed_at is None else _publication_timestamp(exposed_at),
    }


def _publication_receipt_id(publication_id: str, receipt: PublicationReceipt) -> str:
    seed = (
        f"receipt-v1\0{publication_id}\0{receipt.receipt_class.value}\0"
        f"{receipt.sha256}\0{receipt.content_key}"
    ).encode()
    return f"receipt-{hashlib.sha256(seed).hexdigest()}"


def _same_receipt(existing: PublicationReceipt, candidate: PublicationReceipt) -> bool:
    return (
        existing.receipt_class is candidate.receipt_class
        and existing.sha256 == candidate.sha256
        and existing.byte_size == candidate.byte_size
        and existing.content_key == candidate.content_key
        and existing.logical_path == candidate.logical_path
    )


def _same_cleanup_input(existing: CleanupIntent, candidate: CleanupIntent) -> bool:
    return (
        existing.intent_id == candidate.intent_id
        and existing.task_id == candidate.task_id
        and existing.publication_id == candidate.publication_id
        and existing.manifest_digest == candidate.manifest_digest
        and existing.exact_path == candidate.exact_path
    )


def _publication_hide_fence_from_connection(
    connection: Connection, task_id: str, *, active_only: bool = True
) -> PublicationHideFence | None:
    state_clause = " AND state IN ('pending','confirmed')" if active_only else ""
    row = connection.exec_driver_sql(
        f"SELECT {_PUBLICATION_HIDE_FENCE_COLUMNS} FROM publication_hide_fences "
        "WHERE task_id=:task_id" + state_clause,
        {"task_id": task_id},
    ).mappings().first()
    return None if row is None else _publication_hide_from_row(row)


def _publication_exists(connection: Connection, publication_id: str) -> bool:
    row = connection.exec_driver_sql(
        "SELECT 1 FROM publication_generations WHERE publication_id=:publication_id",
        {"publication_id": publication_id},
    ).first()
    return row is not None


def _publication_health_needs_refresh(connection: Connection) -> bool:
    counts = connection.exec_driver_sql(
        """
        SELECT
          (SELECT COUNT(*) FROM publication_generations
            WHERE state IN ('queued','retry_wait')) AS queued_count,
          (SELECT COUNT(*) FROM publication_generations WHERE state='blocked') AS blocked_count,
          (SELECT COUNT(*) FROM publication_cleanup_intents
            WHERE state IN ('pending','blocked')) AS cleanup_count,
          (SELECT COALESCE(SUM(receipt.byte_size),0)
             FROM publication_cleanup_intents AS intent
             LEFT JOIN publication_receipts AS receipt
               ON receipt.publication_id=intent.publication_id
            WHERE intent.state IN ('pending','blocked')) AS cleanup_bytes
        """
    ).mappings().first()
    assert counts is not None
    current = connection.exec_driver_sql(
        """
        SELECT queued_count,blocked_count,cleanup_pending_count,
               cleanup_pending_bytes
        FROM publication_health
        WHERE id=1
        """
    ).mappings().first()
    if current is None:
        return True
    expected = {
        "queued_count": _bounded_health_count(counts["queued_count"]),
        "blocked_count": _bounded_health_count(counts["blocked_count"]),
        "cleanup_pending_count": _bounded_health_count(counts["cleanup_count"]),
        "cleanup_pending_bytes": _bounded_health_count(counts["cleanup_bytes"]),
    }
    return any(current[key] != value for key, value in expected.items())


def _expire_publication_leases_in_connection(
    store: SQLiteTaskStore, connection: Connection, timestamp: datetime
) -> bool:
    now_text = _publication_timestamp(timestamp)
    result = connection.exec_driver_sql(
        "UPDATE publication_generations "
        "SET state='retry_wait',lease_owner=NULL,lease_expires_at=NULL,retry_at=:retry_at,"
        "reason=CASE WHEN reason IN (" + _PUBLICATION_HIDE_REASON_SQL + ") "
        "THEN reason ELSE 'lease_expired' END,updated_at=:updated_at "
        "WHERE state IN ('claimed','building','uploading','d1_staged') AND lease_expires_at<=:now "
        "AND NOT EXISTS (SELECT 1 FROM publication_hide_fences AS fence "
        "WHERE fence.task_id=publication_generations.task_id "
        "AND fence.state IN ('pending','confirmed'))",
        {"retry_at": now_text, "updated_at": now_text, "now": now_text},
    )
    return result.rowcount > 0


def _refresh_publication_health(
    store: SQLiteTaskStore,
    connection: Connection,
    *,
    updated_at: datetime,
    reason: str | None = None,
    preserve_category: bool = False,
) -> None:
    safe_reason = _publication_reason(reason)
    counts = connection.exec_driver_sql(
        """
        SELECT
          (SELECT COUNT(*) FROM publication_generations WHERE state IN ('queued','retry_wait')) AS queued_count,
          (SELECT COUNT(*) FROM publication_generations WHERE state='blocked') AS blocked_count,
          (SELECT COUNT(*) FROM publication_cleanup_intents
            WHERE state IN ('pending','blocked')) AS cleanup_count,
          (SELECT COALESCE(SUM(receipt.byte_size),0)
             FROM publication_cleanup_intents AS intent
             LEFT JOIN publication_receipts AS receipt
               ON receipt.publication_id=intent.publication_id
            WHERE intent.state IN ('pending','blocked')) AS cleanup_bytes
        """
    ).mappings().first()
    assert counts is not None
    existing = connection.exec_driver_sql(
        "SELECT reason,updated_at FROM publication_health WHERE id=1"
    ).mappings().first()
    timestamp = _publication_now(updated_at)
    if existing is not None and existing["updated_at"]:
        timestamp = max(timestamp, _publication_datetime(existing["updated_at"]))
    if preserve_category and safe_reason is None and existing is not None:
        safe_reason = _publication_reason(existing["reason"])
    parameters = {
        "queued_count": _bounded_health_count(counts["queued_count"]),
        "blocked_count": _bounded_health_count(counts["blocked_count"]),
        "cleanup_pending_count": _bounded_health_count(counts["cleanup_count"]),
        "cleanup_pending_bytes": _bounded_health_count(counts["cleanup_bytes"]),
        "reason": safe_reason,
        "updated_at": _publication_timestamp(timestamp),
    }
    connection.exec_driver_sql(
        """
        INSERT INTO publication_health
          (id,queued_count,blocked_count,cleanup_pending_count,cleanup_pending_bytes,reason,updated_at)
        VALUES (1,:queued_count,:blocked_count,:cleanup_pending_count,:cleanup_pending_bytes,:reason,:updated_at)
        ON CONFLICT(id) DO UPDATE SET
          queued_count=excluded.queued_count,
          blocked_count=excluded.blocked_count,
          cleanup_pending_count=excluded.cleanup_pending_count,
          cleanup_pending_bytes=excluded.cleanup_pending_bytes,
          reason=excluded.reason,
          updated_at=excluded.updated_at
        """,
        parameters,
    )


def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    _disable_sqlite_close_checkpoint(dbapi_connection)
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _configure_sqlite_read_only(dbapi_connection, _connection_record) -> None:
    """Configure an already validated WAL database without changing its mode."""

    _disable_sqlite_close_checkpoint(dbapi_connection)
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _disable_sqlite_close_checkpoint(connection: sqlite3.Connection) -> None:
    try:
        option = sqlite3.SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
        connection.setconfig(option, 1)
    except AttributeError:
        # Python versions before sqlite3.Connection.setconfig do not expose
        # the close-checkpoint switch; explicit Store finalization remains the
        # fallback on those runtimes.
        return


def _require_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SQLiteStoreLifecycleError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SQLiteStoreLifecycleError(f"{label} must be a real directory")


def _require_regular_file(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SQLiteStoreLifecycleError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SQLiteStoreLifecycleError(f"{label} must be a regular file")


def _directory_entries(path: Path, label: str) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError as exc:
        raise SQLiteStoreLifecycleError(f"unable to inspect {label}") from exc


def _ensure_database_parent(parent: Path) -> None:
    if os.path.lexists(parent):
        _require_directory(parent, "database parent")
        return
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SQLiteStoreLifecycleError("unable to create database parent") from exc
    _require_directory(parent, "database parent")


def _validate_database_namespace(database: Path) -> None:
    parent = database.parent
    if not os.path.lexists(parent):
        return
    _require_directory(parent, "database parent")
    target_names = {
        path.name for path in _database_publication_paths(database)
    }
    temporary_marker = f".{database.name}.create-"
    target_prefixes = (
        database.name + "-",
        database.name + ".",
        "." + database.name,
    )
    for candidate in _directory_entries(parent, "database parent"):
        if candidate.name in target_names or candidate.name.startswith(
            temporary_marker
        ):
            continue
        if candidate.name.startswith(target_prefixes):
            raise SQLiteStoreLifecycleError(
                "create() refuses a pre-existing database state"
            )


def _refuse_existing_database_state(database: Path) -> None:
    _validate_database_namespace(database)
    for candidate in _database_publication_paths(database):
        if os.path.lexists(candidate):
            raise SQLiteStoreLifecycleError(
                "create() refuses a pre-existing database state"
            )


def _database_publication_paths(database: Path) -> tuple[Path, Path, Path]:
    return (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
    )


def _snapshot_store_database(database: Path) -> _StoreDatabaseSnapshot:
    _require_regular_file(database, "Store database")
    metadata = os.stat(database)
    return _StoreDatabaseSnapshot(
        digest=hashlib.sha256(database.read_bytes()).digest(),
        mode=stat.S_IMODE(metadata.st_mode),
        mtime_ns=metadata.st_mtime_ns,
    )


def _snapshot_store_sidecars(
    database: Path,
) -> dict[str, _StoreSidecarSnapshot]:
    snapshots: dict[str, _StoreSidecarSnapshot] = {}
    for suffix in ("-wal", "-shm"):
        sidecar = database.with_name(database.name + suffix)
        if not os.path.lexists(sidecar):
            raise SQLiteStoreLifecycleError("Store WAL sidecar is missing")
        _require_regular_file(sidecar, "Store WAL sidecar")
        metadata = os.stat(sidecar)
        snapshots[suffix] = _StoreSidecarSnapshot(
            data=sidecar.read_bytes(),
            mode=stat.S_IMODE(metadata.st_mode),
            mtime_ns=metadata.st_mtime_ns,
        )
    return snapshots


def _preserve_store_database_metadata(
    database: Path,
    snapshot: _StoreDatabaseSnapshot | None,
) -> None:
    if snapshot is None:
        return
    _require_regular_file(database, "Store database")
    if hashlib.sha256(database.read_bytes()).digest() != snapshot.digest:
        return
    try:
        os.chmod(database, snapshot.mode)
        os.utime(database, ns=(snapshot.mtime_ns, snapshot.mtime_ns))
    except OSError as exc:
        raise SQLiteStoreLifecycleError(
            "unable to preserve Store database metadata"
        ) from exc
    _fsync_directory(database.parent)


def _ensure_store_sidecars(database: Path) -> None:
    """Materialize empty sidecars after SQLite has finished validating state."""

    for suffix in ("-wal", "-shm"):
        sidecar = database.with_name(database.name + suffix)
        if os.path.lexists(sidecar):
            _require_regular_file(sidecar, "Store WAL sidecar")
            continue
        try:
            with sidecar.open("xb"):
                pass
        except OSError as exc:
            raise SQLiteStoreLifecycleError(
                "unable to preserve Store WAL sidecar"
            ) from exc
        _require_regular_file(sidecar, "Store WAL sidecar")
    _fsync_directory(database.parent)


def _preserve_clean_store_shm(
    sidecar: Path,
    snapshot: _StoreSidecarSnapshot,
) -> None:
    temporary = sidecar.with_name(
        f".{sidecar.name}.preserve-{secrets.token_hex(8)}"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(snapshot.data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, snapshot.mode)
        os.replace(temporary, sidecar)
    except OSError as exc:
        raise SQLiteStoreLifecycleError(
            "unable to preserve clean Store WAL state"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _preserve_store_sidecar_metadata(
    database: Path,
    snapshots: Mapping[str, _StoreSidecarSnapshot],
    *,
    database_snapshot: _StoreDatabaseSnapshot | None,
) -> None:
    """Preserve clean metadata without replaying a stale WAL."""

    if database_snapshot is not None:
        _require_regular_file(database, "Store database")
        if hashlib.sha256(database.read_bytes()).digest() != database_snapshot.digest:
            return
    wal_snapshot = snapshots.get("-wal")
    if wal_snapshot is not None:
        wal = database.with_name(database.name + "-wal")
        _require_regular_file(wal, "Store WAL sidecar")
        if wal.read_bytes() != wal_snapshot.data:
            return
    clean_wal = wal_snapshot is not None and not wal_snapshot.data
    preserved = False
    for suffix in ("-wal", "-shm"):
        snapshot = snapshots.get(suffix)
        if snapshot is None:
            continue
        sidecar = database.with_name(database.name + suffix)
        _require_regular_file(sidecar, "Store WAL sidecar")
        current = sidecar.read_bytes()
        # A changed WAL is authoritative, even if the main database bytes did
        # not change because the write is still resident in the WAL.  A clean
        # empty WAL proves that an SHM refresh contains only transient reader
        # state, so that exact clean SHM image may be retained.
        if suffix == "-wal" and current != snapshot.data:
            return
        if suffix == "-shm" and clean_wal and current != snapshot.data:
            _preserve_clean_store_shm(sidecar, snapshot)
        try:
            os.chmod(sidecar, snapshot.mode)
            os.utime(sidecar, ns=(snapshot.mtime_ns, snapshot.mtime_ns))
        except OSError as exc:
            raise SQLiteStoreLifecycleError(
                "unable to preserve Store WAL sidecar metadata"
            ) from exc
        preserved = True
    if preserved:
        _fsync_directory(database.parent)


def _valid_store_database_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 255
        and value not in {".", ".."}
        and "\x00" not in value
        and "/" not in value
        and "\\" not in value
        and Path(value).name == value
    )


def _store_receipt_path(database: Path) -> Path:
    digest = hashlib.sha256(database.name.encode("utf-8")).hexdigest()
    return database.parent / "tasks" / (
        f"{_STORE_RECEIPT_PREFIX}{digest}{_STORE_RECEIPT_SUFFIX}"
    )


def _store_receipt_value(
    *, epoch_id: str, database_name: str, state: str
) -> bytes:
    return json.dumps(
        {
            "database": database_name,
            "epochId": epoch_id,
            "formatVersion": _STORE_RECEIPT_FORMAT_VERSION,
            "state": state,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_store_receipt_file(
    path: Path, epoch_id: str
) -> _StoreCreationReceipt:
    _require_regular_file(path, "Store creation receipt")
    name = path.name
    if not (
        name.startswith(_STORE_RECEIPT_PREFIX)
        and name.endswith(_STORE_RECEIPT_SUFFIX)
    ):
        raise SQLiteStoreLifecycleError("Store creation receipt name is invalid")
    digest = name[len(_STORE_RECEIPT_PREFIX) : -len(_STORE_RECEIPT_SUFFIX)]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SQLiteStoreLifecycleError("Store creation receipt is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "database",
        "epochId",
        "formatVersion",
        "state",
    }:
        raise SQLiteStoreLifecycleError("Store creation receipt is invalid")
    database_name = value["database"]
    if (
        not _valid_store_database_name(database_name)
        or hashlib.sha256(database_name.encode("utf-8")).hexdigest() != digest
        or value["epochId"] != epoch_id
        or value["formatVersion"] != _STORE_RECEIPT_FORMAT_VERSION
        or value["state"] not in _STORE_RECEIPT_STATES
    ):
        raise SQLiteStoreLifecycleError("Store creation receipt is invalid")
    return _StoreCreationReceipt(
        epoch_id=epoch_id,
        database_name=database_name,
        state=value["state"],
    )


def _read_store_receipt(
    database: Path, epoch_id: str
) -> _StoreCreationReceipt | None:
    path = _store_receipt_path(database)
    if not os.path.lexists(path):
        return None
    receipt = _read_store_receipt_file(path, epoch_id)
    if receipt.database_name != database.name:
        raise SQLiteStoreLifecycleError("Store creation receipt targets another database")
    return receipt


def _reserve_store_receipt(database: Path, epoch_id: str) -> None:
    tasks_root = database.parent / "tasks"
    _require_directory(tasks_root, "task archive root")
    path = _store_receipt_path(database)
    if os.path.lexists(path):
        receipt = _read_store_receipt(database, epoch_id)
        assert receipt is not None
        if receipt.state != "creating":
            raise SQLiteStoreLifecycleError(
                "Store creation receipt already commits another database state"
            )
        return
    try:
        with path.open("xb") as handle:
            handle.write(
                _store_receipt_value(
                    epoch_id=epoch_id,
                    database_name=database.name,
                    state="creating",
                )
            )
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(tasks_root)
    except OSError as exc:
        raise SQLiteStoreLifecycleError(
            "unable to reserve Store creation receipt"
        ) from exc


def _commit_store_receipt(database: Path, epoch_id: str) -> None:
    path = _store_receipt_path(database)
    receipt = _read_store_receipt(database, epoch_id)
    if receipt is None:
        raise SQLiteStoreLifecycleError("Store creation receipt is missing")
    if receipt.state == "committed":
        return
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    try:
        with temporary.open("xb") as handle:
            handle.write(
                _store_receipt_value(
                    epoch_id=epoch_id,
                    database_name=database.name,
                    state="committed",
                )
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise SQLiteStoreLifecycleError(
            "unable to commit Store creation receipt"
        ) from exc


def _validated_sibling_store_exists(database: Path, epoch_id: str) -> bool:
    """Recognize only a complete current sibling with a committed receipt."""

    target_names = {path.name for path in _database_publication_paths(database)}
    for candidate in _directory_entries(database.parent, "database parent"):
        if candidate.name in target_names or candidate.suffix != database.suffix:
            continue
        try:
            SQLiteTaskStore._validate_current_database(candidate, epoch_id)
            receipt = _read_store_receipt(candidate, epoch_id)
        except SQLiteStoreLifecycleError:
            continue
        if receipt is not None and receipt.state == "committed":
            return True
    return False


def _same_regular_file(left: Path, right: Path) -> bool:
    try:
        _require_regular_file(left, "database publication entry")
        _require_regular_file(right, "database publication temporary")
        return os.path.samefile(left, right)
    except (OSError, SQLiteStoreLifecycleError):
        return False


def _publication_matches_temporary(
    temporary: Path, database: Path
) -> bool:
    present = False
    for target, suffix in zip(
        _database_publication_paths(database), ("", "-wal", "-shm")
    ):
        if not os.path.lexists(target):
            continue
        present = True
        source = temporary if not suffix else temporary.with_name(
            temporary.name + suffix
        )
        if not _same_regular_file(target, source):
            return False
    return present


def _temporary_publication_is_partial(
    temporary: Path, database: Path
) -> bool:
    paths = _database_publication_paths(database)
    present = [os.path.lexists(path) for path in paths]
    if not any(present) or all(present):
        return False
    return _publication_matches_temporary(temporary, database)


def _read_epoch_document(path: Path) -> dict[str, object]:
    _require_regular_file(path, "epoch document")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SQLiteStoreLifecycleError("invalid task epoch document") from exc
    from ..execution.task_archive import TaskArchive

    if not TaskArchive._valid_epoch(value):
        raise SQLiteStoreLifecycleError("invalid task epoch document")
    return dict(value)


def _read_task_epoch(tasks_root: Path) -> dict[str, object]:
    _require_directory(tasks_root, "task archive root")
    return _read_epoch_document(tasks_root / "epoch.json")


def _scan_database_temporaries(
    database: Path, epoch_id: str | None
) -> list[Path]:
    parent = database.parent
    marker = f".{database.name}.create-"
    if not os.path.lexists(parent):
        return []
    _require_directory(parent, "database parent")
    remnants: list[Path] = []
    entries = _directory_entries(parent, "database parent")
    base_names: set[str] = set()
    sidecar_bases: set[str] = set()
    for entry in entries:
        if not entry.name.startswith(marker):
            continue
        suffix = entry.name[len(marker) :]
        if epoch_id is None:
            raise SQLiteStoreLifecycleError(
                "database temporary exists without a task epoch"
            )
        expected = f"{epoch_id}-"
        is_base = suffix.endswith(".tmp")
        sidecar_suffix = next(
            (
                candidate
                for candidate in ("-wal", "-shm")
                if suffix.endswith(".tmp" + candidate)
            ),
            None,
        )
        if not is_base and sidecar_suffix is None:
            raise SQLiteStoreLifecycleError(
                "database temporary has a mismatched task epoch"
            )
        identity = (
            suffix[: -len(".tmp")]
            if is_base
            else suffix[: -len(".tmp" + sidecar_suffix)]
        )
        if not identity.startswith(expected) or len(identity) <= len(expected):
            raise SQLiteStoreLifecycleError("database temporary identity is empty")
        _require_regular_file(entry, "database temporary")
        remnants.append(entry)
        if is_base:
            base_names.add(entry.name)
        else:
            sidecar_bases.add(entry.name[: -len(sidecar_suffix)])
    if not sidecar_bases.issubset(base_names):
        raise SQLiteStoreLifecycleError("database temporary sidecar is orphaned")
    return remnants


def _unlink_regular_remnant(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SQLiteStoreLifecycleError("unable to remove Store temporary") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SQLiteStoreLifecycleError("Store temporary is not a regular file")
    try:
        path.unlink()
    except OSError as exc:
        raise SQLiteStoreLifecycleError("unable to remove Store temporary") from exc


def _remove_factory_temporary(path: Path) -> None:
    # Only remove the exact temporary family allocated by this attempt.  A
    # mismatched or special visible entry is never repaired here.
    _unlink_regular_remnant(path)
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if os.path.lexists(sidecar):
            _unlink_regular_remnant(sidecar)


def _validate_optional_sqlite_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = database.with_name(database.name + suffix)
        if os.path.lexists(sidecar):
            _require_regular_file(sidecar, "database sidecar")


def _require_wal_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = database.with_name(database.name + suffix)
        if not os.path.lexists(sidecar):
            raise SQLiteStoreLifecycleError("Store WAL sidecar is missing")
        _require_regular_file(sidecar, "Store WAL sidecar")


def _publish_database_sidecars(temporary: Path, database: Path) -> None:
    for suffix in ("-wal", "-shm"):
        source = temporary.with_name(temporary.name + suffix)
        target = database.with_name(database.name + suffix)
        _require_regular_file(source, "database temporary sidecar")
        try:
            os.link(source, target)
        except FileExistsError:
            _require_regular_file(target, "database sidecar")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SQLiteStoreLifecycleError("directory fsync is unavailable") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise SQLiteStoreLifecycleError("directory fsync failed") from exc
    finally:
        os.close(descriptor)


def _catalog_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    payload = [
        [str(kind), str(name), str(table), sql]
        for kind, name, table, sql in rows
    ]
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode(
            "utf-8"
        )
    ).hexdigest()


def _validate_store_seeds(connection: sqlite3.Connection, epoch_id: str) -> None:
    rows = dict(connection.execute("SELECT key, value FROM control_loop_meta"))
    if not _CONTROL_LOOP_META_SEED_KEYS.issubset(rows):
        raise SQLiteStoreLifecycleError("Store metadata seeds are incomplete")
    if rows["epoch_id"] != epoch_id:
        raise SQLiteStoreLifecycleError("Store and task epochs do not match")
    try:
        next_sequence = int(rows["next_sequence"])
        if next_sequence < 0:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise SQLiteStoreLifecycleError("Store sequence seed is invalid") from exc

    event_count, minimum_sequence, maximum_sequence = connection.execute(
        "SELECT COUNT(*), MIN(sequence), MAX(sequence) FROM control_loop_events"
    ).fetchone()
    expected_sequence = 0 if event_count == 0 else int(maximum_sequence) + 1
    if (
        next_sequence != expected_sequence
        or (event_count and minimum_sequence != 0)
        or (event_count and event_count != expected_sequence)
    ):
        raise SQLiteStoreLifecycleError("Store sequence seed is inconsistent")
    if connection.execute(
        "SELECT 1 FROM control_loop_events WHERE epoch_id<>? LIMIT 1",
        (epoch_id,),
    ).fetchone() is not None:
        raise SQLiteStoreLifecycleError("Store event epoch is inconsistent")
    outbox_count = connection.execute(
        "SELECT COUNT(*) FROM control_loop_outbox"
    ).fetchone()[0]
    if outbox_count != event_count:
        raise SQLiteStoreLifecycleError("Store event outbox is inconsistent")
    if connection.execute(
        """
        SELECT 1
        FROM control_loop_events AS event
        LEFT JOIN control_loop_outbox AS outbox
          ON outbox.sequence=event.sequence
        WHERE outbox.sequence IS NULL OR outbox.event_id<>event.event_id
        LIMIT 1
        """
    ).fetchone() is not None:
        raise SQLiteStoreLifecycleError("Store event outbox is inconsistent")
    if connection.execute(
        """
        SELECT 1
        FROM control_loop_outbox AS outbox
        LEFT JOIN control_loop_events AS event
          ON event.sequence=outbox.sequence
        WHERE event.sequence IS NULL
        LIMIT 1
        """
    ).fetchone() is not None:
        raise SQLiteStoreLifecycleError("Store event outbox is inconsistent")
    if rows["planning_blocked"] not in {"0", "1"}:
        raise SQLiteStoreLifecycleError("Store planning seed is invalid")

    health = connection.execute(
        """
        SELECT id, queued_count, blocked_count, cleanup_pending_count,
               cleanup_pending_bytes
        FROM publication_health
        """
    ).fetchall()
    if len(health) != 1 or health[0][0] != 1:
        raise SQLiteStoreLifecycleError("Store publication seed is invalid")
    if any(value < 0 for value in health[0][1:]):
        raise SQLiteStoreLifecycleError("Store publication seed is invalid")


def _bind_existing_control_loop(
    database: Path, epoch_id: str
) -> ControlLoopLedger:
    # Constructing ControlLoopLedger normally creates/probes tables and seeds
    # metadata. Exact validation has already established those bytes, so bind
    # the validated object without invoking its write-capable initializer.
    ledger = ControlLoopLedger.__new__(ControlLoopLedger)
    ledger.path = database
    ledger._epoch_id = epoch_id
    return ledger

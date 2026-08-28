from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from ..core.config import StewardConfig
from ..core.github_auth import git_environment
from ..core.lifecycle import (
    DaemonLifecycleState,
    DockerResourceManager,
    ResourcePressureController,
    ReconciliationDisposition,
    ReconciliationOutcome,
    ShutdownResult,
)
from ..core.models import (
    ACTIVE_STATUSES,
    CleanupStatus,
    DaemonCycleResult,
    DaemonCycleSummary,
    DaemonRuntime,
    DaemonRuntimeState,
    EffectResult,
    ExecutionMode,
    EXECUTION_MODE_METADATA_KEY,
    OwnedDockerUsage,
    PipelineCursorPhase,
    ResourcePressure,
    ResourcePressureState,
    SignalFetchStatus,
    SignalItem,
    TaskRecord,
    TaskStatus,
    utc_now,
    WorkerKind,
    coerce_execution_mode,
)
from ..execution.executor import StewardExecutor
from ..execution.publication_graph import task_publication_lifecycle
from ..storage.sqlite import (
    DaemonPublicationAuthority,
    DaemonPublicationRevocationResult,
    TaskLedgerOwnershipError,
)
from ..execution.container import bind_deployment_identity
from ..execution.session import (
    FreshPlannerSession,
    InvocationStatus,
    ResumeCategory,
    SessionResult,
    SessionSupervisor,
    _write_publication_snapshot,
    enqueue_materialized_publication,
    load_publication_snapshot,
    session_supervisor_for_config,
    planner_session_for_config,
)
from ..execution.task_archive import TaskArchive, TaskArchiveWriter
from ..publication.atif import AtifSource
from ..publication.models import RunIdentity, RunLineage, RunMetadata, UsageSummary
from ..publication.generation import (
    PublicationGeneration as ComposedPublicationGeneration,
    _publication_compose_kwargs,
    compose_publication_generation,
)
from ..publication.outbox import (
    CleanupIntent,
    CleanupState,
    PublicationGeneration,
    PublicationHealth,
    PublicationHideFence,
    PublicationOperationResult,
    PublicationOperationStatus,
    PublicationReceipt,
    PublicationRetryPolicy,
    PublicationState,
    ReceiptClass,
)
from ..publication.d1 import (
    D1Error,
    D1PublicationClient,
    OverheadReceipt,
    UsageBackfillReceipt,
    _overhead_digest,
)
from ..publication.publisher import (
    CloudPublisher,
    PublicationHideResult,
    PublicationHideStatus,
    PublicationResult,
    PublicationStatus,
)
from ..publication.r2 import R2Client, private_original_key
from ..core.subprocesses import (
    ProcessGroupCancellationOwner,
    run_command,
    use_subprocess_owner,
)
from ..agents.telemetry import PriceCatalog
from ..control_loop import (
    ArchiveConflictError,
    ArchiveError,
    ControlLoopArchive,
    ControlLoopLedger,
    CurrentState,
    Cycle as ControlLoopCycle,
    PlannerRun as ControlPlannerRun,
    new_id as new_control_loop_id,
    timestamp as control_timestamp,
)
from ..control_loop.models import StewardOverheadUsage
from ..control_loop.usage import StewardOverheadReducer
from ..planning import PlannerRun as PlanningPlannerRun, run_planner
from ..planning.planner import render_planner_prompt
from ..planning.verifier import selected_signal_item_ids, summarize_active_tasks
from ..storage import (
    SQLiteTaskStore,
    TaskStore,
    due_provider_names,
    idle_fetch_provider_names,
    planner_task_context,
    scheduler_state,
)
from ..signals import (
    collect_signal_items,
    project_signals_from_items,
    revalidate_signal_items,
)
from ..signals.collector import revalidate_signal_items_with_context
from .contracts import (
    DaemonCancellation,
    DaemonCancellationResult,
    PublicationTransportSetupError,
)
from .transport import (
    BotocoreR2TransportAdapter,
    HttpxD1TransportAdapter,
    _CallbackDaemonCancellation,
    _PublicationTransportCancellation,
    _PublicationTransportCancelled,
    _close_d1_provider_client,
    _close_r2_provider_client,
)
from .preflight import PreflightReport, preflight_remote_push, run_preflight

_NONINTERACTIVE_GIT_ENV = {
    "GCM_INTERACTIVE": "never",
    "GIT_TERMINAL_PROMPT": "0",
}
DAEMON_EVENT_TASK_ID = "daemon"
DAEMON_HEARTBEAT_INTERVAL_SECONDS = 30
SESSION_RESUME_MAX_ATTEMPTS = 2
PUBLICATION_RETRY_INTERVAL_SECONDS = 5.0
PUBLICATION_JOIN_TIMEOUT_SECONDS = 1.0
GLOBAL_ACTIVE_TASK_ADMISSION_CAP = 16
_BUILTIN_DOCKER_RECONCILE = DockerResourceManager.reconcile


def _task_execution_mode(task: TaskRecord) -> ExecutionMode | None:
    metadata = getattr(getattr(task, "spec", None), "metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    try:
        return coerce_execution_mode(metadata.get(EXECUTION_MODE_METADATA_KEY))
    except ValueError:
        # Unknown caller metadata is never treated as permission to execute.
        return ExecutionMode.dry_run


def _task_is_dry_run(task: TaskRecord) -> bool:
    return _task_execution_mode(task) is ExecutionMode.dry_run


def _live_rerun_allocation_counts(
    store: SQLiteTaskStore, task: TaskRecord
) -> tuple[int, int]:
    """Read retained and stale counts from the durable allocation event."""

    try:
        events = store.events(task.id)
    except (AttributeError, KeyError, TypeError, ValueError):
        return 0, 0
    for event in reversed(events):
        if event.kind != "task.live_rerun":
            continue
        if not isinstance(event.data, Mapping):
            return 0, 0
        selected = event.data.get("selected_signal_ids", [])
        stale = event.data.get("stale_signal_ids", [])
        return (
            len(selected) if isinstance(selected, list) else 0,
            len(stale) if isinstance(stale, list) else 0,
        )
    return 0, 0


def create_live_rerun(
    config: StewardConfig,
    store: SQLiteTaskStore,
    source_task_id: str,
) -> LiveRerunOutcome:
    """Validate current inputs, then enqueue one explicit live rerun.

    This helper intentionally stops at Store allocation.  It never constructs
    a daemon or calls the task driver; the normal scheduler will reread the
    repository and provider state when it later dispatches the new task.
    """

    if config.dry_run:
        raise LiveRerunRejected("dry_run_configured")
    try:
        source = store.get(source_task_id)
    except KeyError as exc:
        raise LiveRerunRejected("source_task_missing") from exc
    try:
        source_status = TaskStatus(source.status)
    except (TypeError, ValueError) as exc:
        raise LiveRerunRejected("source_status_invalid") from exc
    try:
        mode = store.task_execution_mode(source.id)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveRerunRejected("source_execution_mode_unavailable") from exc
    if mode is not ExecutionMode.dry_run:
        raise LiveRerunRejected("source_is_not_dry_run")
    if source_status not in {TaskStatus.succeeded, TaskStatus.no_changes}:
        raise LiveRerunRejected("source_not_successful_terminal")
    try:
        result = store.effect_result(source.id)
        evidence = store.effect_evidence(source.id)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveRerunRejected("source_effect_evidence_invalid") from exc
    if result not in {EffectResult.not_applied, EffectResult.not_applicable}:
        raise LiveRerunRejected("source_effect_was_applied")

    archive = TaskArchive(
        getattr(config, "tasks_dir", Path(store.path).parent / "tasks")
    )
    try:
        archive.verify_rerun_source(
            source.id,
            expected_status=source.status,
            expected_mode=ExecutionMode.dry_run.value,
            expected_result=result,
            expected_effects=evidence,
        )
    except Exception as exc:
        # Archive exceptions intentionally collapse to one bounded refusal;
        # their class remains available to diagnostics and tests without
        # exposing filesystem paths or old artifact content in CLI output.
        raise LiveRerunRejected("source_archive_unverified") from exc

    try:
        existing = store.active_live_rerun(source.id)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveRerunRejected("active_rerun_lookup_failed") from exc
    if existing is not None:
        retained_count, stale_count = _live_rerun_allocation_counts(store, existing)
        return LiveRerunOutcome(
            source_task_id=source.id,
            task=existing,
            created=False,
            retained_signal_count=retained_count,
            stale_signal_count=stale_count,
        )

    try:
        linked = store.selected_signal_items_for_task(source.id)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveRerunRejected("source_signal_links_invalid") from exc

    actionable: list[SignalItem] = []
    stale_reasons: dict[str, str] = {}
    refreshed_signal_items: dict[str, SignalItem] = {}
    if not linked and str(source.spec.source) != "manual":
        raise LiveRerunRejected("source_signal_links_missing")
    if linked:
        revalidation = revalidate_signal_items_with_context(
            config, linked, strict=True
        )
        actionable = revalidation.actionable
        stale_reasons = revalidation.stale_reasons
        refreshed_signal_items = revalidation.refreshed
        if any(reason == "provider_unavailable" for reason in stale_reasons.values()):
            raise LiveRerunRejected("signal_provider_unavailable")
        if not actionable:
            raise LiveRerunRejected(
                "all_source_signals_stale",
                retained_signal_count=0,
                stale_signal_count=len(stale_reasons),
                stale_reasons=stale_reasons,
            )

    selected_ids = [item.id for item in actionable]
    stale_ids = list(stale_reasons)
    if set(refreshed_signal_items) != set(selected_ids):
        raise LiveRerunRejected("signal_provider_unavailable")
    current_items = [refreshed_signal_items[item_id] for item_id in selected_ids]
    try:
        allocation = store.allocate_live_rerun(
            source.id,
            selected_signal_ids=selected_ids,
            selected_signal_items=current_items,
            stale_signal_ids=stale_ids,
            stale_reasons=stale_reasons,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveRerunRejected("rerun_allocation_conflict") from exc
    if allocation.created:
        retained_count = len(selected_ids)
        stale_count = len(stale_ids)
    else:
        retained_count, stale_count = _live_rerun_allocation_counts(
            store, allocation.task
        )
    return LiveRerunOutcome(
        source_task_id=source.id,
        task=allocation.task,
        created=allocation.created,
        retained_signal_count=retained_count,
        stale_signal_count=stale_count,
    )


rerun_live_task = create_live_rerun


def _inspection_confirms_stopped(inspection: object) -> bool:
    """Require a positive stop result when the boundary exposes confidence."""

    live = getattr(inspection, "live", None)
    if live is not False:
        return False
    confirmed = getattr(inspection, "confirmed_stopped", None)
    return True if confirmed is None else bool(confirmed)


_RESUMABLE_TASK_STATUSES = tuple(
    status for status in ACTIVE_STATUSES if status != TaskStatus.queued
)


@dataclass
class TickResult:
    signal_fetches: int = 0
    signal_items: int = 0
    new_signal_items: int = 0
    planned: int = 0
    enqueued: int = 0
    dispatched: int = 0
    skipped: int = 0


class LiveRerunRejected(ValueError):
    """A dry-run source failed the explicit live-rerun eligibility gate."""

    def __init__(
        self,
        reason: str,
        *,
        retained_signal_count: int = 0,
        stale_signal_count: int = 0,
        stale_reasons: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retained_signal_count = retained_signal_count
        self.stale_signal_count = stale_signal_count
        self.stale_reasons = dict(stale_reasons or {})


@dataclass(frozen=True)
class LiveRerunOutcome:
    source_task_id: str
    task: TaskRecord | None
    created: bool
    retained_signal_count: int
    stale_signal_count: int


@dataclass(frozen=True)
class SchedulerTrigger:
    reason: str
    providers: list[str]


class StewardDaemon:
    def __init__(
        self,
        config: StewardConfig,
        store: SQLiteTaskStore,
        *,
        logger: Callable[[str], None] | None = None,
        session_supervisor: SessionSupervisor | None = None,
        planner_session: FreshPlannerSession | None = None,
    ):
        if not isinstance(store, SQLiteTaskStore):
            raise TypeError("StewardDaemon requires a SQLiteTaskStore")
        if session_supervisor is not None and not isinstance(
            session_supervisor, SessionSupervisor
        ):
            raise TypeError("session_supervisor must be a SessionSupervisor")
        if planner_session is not None and not isinstance(
            planner_session, FreshPlannerSession
        ):
            raise TypeError("planner_session must be a FreshPlannerSession")
        self.config = config
        self.store = store
        self.logger = logger
        self._lifecycle_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._force_shutdown_event = threading.Event()
        self._startup_complete = False
        self._reconciliation: list[ReconciliationOutcome] = []
        self._adopted_runs: dict[str, str] = {}
        self._active_futures: dict[str, concurrent.futures.Future[object]] = {}
        self._worker_pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._worker_pool_lock = threading.RLock()
        self._integration_lock = threading.Lock()
        self._preflight_report: PreflightReport | None = None
        self._publication_thread: threading.Thread | None = None
        self._publication_stop = threading.Event()
        self._publication_wakeup = threading.Event()
        self._publication_lock = threading.RLock()
        self._publication_previous_callback: object | None = None
        self._publication_callback: Callable[[], None] | None = None
        self._publication_cancel: DaemonCancellation | None = None
        self._publication_authority: DaemonPublicationAuthority | None = None
        self._publication_overhead_position = 0
        self._publication_overhead_digest: str | None = None
        self._publication_backfill_cursor: str | None = None
        self._publication_backfill_catalog_digest: str | None = None
        self._publication_backfill_blocked = False
        self._subprocess_owner = ProcessGroupCancellationOwner("steward-daemon")
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._control_loop_ledger: ControlLoopLedger = store.control_loop_ledger
        self._control_loop_archive = ControlLoopArchive(config, task_root=config)
        usage_catalog = None
        try:
            usage_catalog = PriceCatalog.from_path(
                config.repo_root / "steward" / "model-prices.json"
            )
        except (FileNotFoundError, OSError, ValueError):
            # Cost remains N.A. when the repository has no committed catalog;
            # token evidence and coverage are still reduced.
            usage_catalog = None
        self._control_loop_usage = StewardOverheadReducer(
            self._control_loop_archive,
            self._control_loop_ledger,
            catalog=usage_catalog,
        )
        self._control_loop_stop = threading.Event()
        self._control_loop_wakeup = threading.Event()
        self._control_loop_thread: threading.Thread | None = None
        self._control_loop_lock = threading.RLock()
        self._active_planner_run_id: str | None = None
        self._planner_publication_queue: dict[str, ControlPlannerRun] = {}
        self._docker_resources: DockerResourceManager | None = None
        self._resource_reconciliation_failed = False
        usage_provider = None
        if config.deployment.enabled:
            self._docker_resources = DockerResourceManager(
                config.container.docker_bin,
                deployment_id=config.deployment.compose_project,
            )

            def usage_provider() -> object:
                if self._resource_reconciliation_failed:
                    raise RuntimeError("owned Docker reconciliation is ambiguous")
                assert self._docker_resources is not None
                return self._docker_resources.owned_usage()

        self._resource_pressure = ResourcePressureController(
            config,
            usage_provider=usage_provider,
            initial_state=ResourcePressureState.normal,
        )
        self._resource_pressure_restored = False
        self.session_supervisor = session_supervisor
        if self.session_supervisor is None:
            self.session_supervisor = session_supervisor_for_config(config, store)
        self.planner_session = planner_session
        self.executor = StewardExecutor(
            config,
            store,
            session_supervisor=self.session_supervisor,
        )
        self._install_live_rerun_effect_guard()
        self.runtime = DaemonRuntime(
            heartbeat_interval_seconds=DAEMON_HEARTBEAT_INTERVAL_SECONDS
        )
        self._runtime_lock = threading.Lock()

    @property
    def lifecycle_state(self) -> DaemonLifecycleState:
        with self._runtime_lock:
            return DaemonLifecycleState(self.runtime.lifecycle)

    @property
    def preflight_report(self) -> PreflightReport | None:
        return self._preflight_report

    @property
    def reconciliation_outcomes(self) -> tuple[ReconciliationOutcome, ...]:
        return tuple(self._reconciliation)

    @property
    def stopping(self) -> bool:
        return self._shutdown_event.is_set()

    @property
    def resource_pressure(self) -> dict[str, Any]:
        return self._refresh_resource_pressure()

    def admission_allowed(self) -> bool:
        """Return whether a new planner/task claim may be admitted."""

        return bool(self._refresh_resource_pressure().get("admissionAllowed"))

    def _restore_resource_pressure(self) -> None:
        if getattr(self, "_resource_pressure_restored", True):
            return
        initial_state = ResourcePressureState.normal
        try:
            persisted_pressure = self.store.get_resource_pressure()
            if persisted_pressure is not None:
                initial_state = ResourcePressureState(
                    str(persisted_pressure.get("state"))
                )
        except (AttributeError, OSError, TypeError, ValueError):
            initial_state = ResourcePressureState.pressure
        self._resource_pressure.state = initial_state
        self._resource_pressure.last = ResourcePressure(
            state=initial_state,
            admission_allowed=initial_state is ResourcePressureState.normal,
        )
        self._resource_pressure_restored = True

    def _prepare_planner_session(self) -> None:
        if self.planner_session is not None:
            return
        if self.config.task_image_digest and not self.config.local_codex_test_harness:
            self.planner_session = planner_session_for_config(self.config)
            runtime = self.planner_session.invoker.runtime
            bind_deployment_identity(runtime, self.config)
        elif self.config.local_codex_test_harness:
            self.planner_session = FreshPlannerSession(self.config)

    def _refresh_resource_pressure(self) -> dict[str, Any]:
        self._restore_resource_pressure()
        reconciled_usage = self._reconcile_docker_resources()
        if reconciled_usage is None:
            report = self._resource_pressure.measure()
        else:
            report = self._resource_pressure.measure(reconciled_usage)
        report_dict = report.as_dict()
        try:
            report_dict["cleanupPending"] = int(self.store.cleanup_pending_count())
        except Exception:
            report_dict["cleanupPending"] = None
        try:
            health = self.store.get_publication_health()
            if isinstance(health, PublicationHealth):
                health_dict = PublicationHealth.as_dict(health)
            elif isinstance(health, Mapping):
                health_dict = dict(health)
            elif type(health) is SimpleNamespace and "as_dict" in health.__dict__:
                # Keep the bounded test/provider adapter explicit; do not
                # discover serializers on arbitrary health values.
                health_dict = health.as_dict()
            else:
                health_dict = {}
            bounded_health: dict[str, object] = {}
            for key, value in health_dict.items():
                if isinstance(value, bool):
                    bounded_health[key] = value
                elif isinstance(value, int):
                    bounded_health[key] = max(0, min(value, 2**31 - 1))
                else:
                    bounded_health[key] = value
            report_dict["publication"] = bounded_health
            report_dict["publicationHealth"] = bounded_health
            aliases = {
                "queuedCount": "publicationQueuedCount",
                "blockedCount": "publicationBlockedCount",
                "cleanupPendingCount": "publicationCleanupPendingCount",
                "cleanupPendingBytes": "publicationCleanupPendingBytes",
                "oldestQueuedAt": "publicationOldestQueuedAt",
                "oldestQueuedAgeSeconds": "publicationOldestQueuedAgeSeconds",
                "lastCategory": "publicationLastCategory",
            }
            for key, alias in aliases.items():
                if key in bounded_health:
                    report_dict[alias] = bounded_health[key]
            if "queuedCount" in bounded_health:
                report_dict["publicationQueueCount"] = bounded_health["queuedCount"]
            if "cleanupPendingCount" in bounded_health:
                report_dict["publicationCleanupCount"] = bounded_health[
                    "cleanupPendingCount"
                ]
            if "cleanupPendingBytes" in bounded_health:
                report_dict["publicationRetainedBytes"] = bounded_health[
                    "cleanupPendingBytes"
                ]
        except Exception:
            report_dict["publication"] = None
        try:
            cleanup_count = int(report_dict.get("cleanupPending") or 0)
            publication_cleanup = report_dict.get("publicationCleanupPendingCount")
            if isinstance(publication_cleanup, int):
                cleanup_count = max(cleanup_count, publication_cleanup)
            self.store.record_resource_pressure(
                state=report_dict["state"],
                home_free_bytes=report_dict.get("homeFreeBytes"),
                owned_docker_bytes=report_dict.get("ownedBytes"),
                cleanup_pending_count=cleanup_count,
                reason=report_dict.get("reason"),
            )
        except Exception as exc:
            self._log(f"resource pressure health write failed error={exc.__class__.__name__}")
        return report_dict

    def _reconcile_docker_resources(self) -> OwnedDockerUsage | None:
        if self._docker_resources is None:
            return None
        if self.config.dry_run:
            # A custom lifecycle adapter owns its own read-only policy; retain
            # that adapter contract while the built-in manager stays guarded.
            if (
                type(self._docker_resources).reconcile
                is not _BUILTIN_DOCKER_RECONCILE
            ):
                result = self._docker_resources.reconcile(
                    self.store, self.config.deployment
                )
                usage = result.get("usage") if isinstance(result, Mapping) else None
                return usage if isinstance(usage, OwnedDockerUsage) else None
            # Keep the lifecycle manager's release journal and exact Docker
            # accounting, but do not call its destructive reconcile path.
            try:
                self._docker_resources.deployment_id = (
                    self.config.deployment.compose_project
                )
                release_images, _in_flight = (
                    self._docker_resources._record_deployment_releases(
                        self.store, self.config.deployment
                    )
                )
                known_images = frozenset(
                    image_id
                    for image_ids in release_images.values()
                    for image_id in image_ids
                )
                self._docker_resources._known_image_ids = known_images
                usage, references, _images, _active, complete = (
                    self._docker_resources._snapshot(known_images)
                )
                if not complete or usage.ambiguous:
                    self._resource_reconciliation_failed = True
                    return OwnedDockerUsage(ambiguous=True)
                self.store.replace_container_references(references)
                self._resource_reconciliation_failed = False
                return usage
            except Exception as exc:
                self._resource_reconciliation_failed = True
                self._log(
                    "owned Docker observation failed "
                    f"error={exc.__class__.__name__}"
                )
                return OwnedDockerUsage(ambiguous=True)
        try:
            result = self._docker_resources.reconcile(self.store, self.config.deployment)
            self._resource_reconciliation_failed = False
            usage = result.get("usage") if isinstance(result, Mapping) else None
            if isinstance(usage, OwnedDockerUsage):
                return usage
            self._resource_reconciliation_failed = True
            self._log("owned Docker reconciliation returned no usage")
        except Exception as exc:
            self._resource_reconciliation_failed = True
            self._log(f"owned Docker reconciliation failed error={exc.__class__.__name__}")
        return OwnedDockerUsage(ambiguous=True)

    def _retry_cleanup_pending_tasks(self) -> None:
        """Retry each durable terminal cleanup transaction once per cycle."""

        self.executor.retry_validation_cleanup_pending()
        cleanup_tasks = list(self.store.cleanup_pending_tasks())
        for task in cleanup_tasks:
            if not TaskStatus(task.status).terminal:
                continue
            self.finalize_terminal_task(task.id)

    def _cleanup_startup_claim(self, *, claim_attempted: bool) -> bool:
        """Persist a stopped lifecycle for a claim startup could have touched."""

        state = self.store.get_daemon_state()
        if not state:
            return False
        lifecycle = str(state.get("lifecycle") or "")
        instance_id = state.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            return False
        if lifecycle not in {
            DaemonLifecycleState.starting.value,
            DaemonLifecycleState.reconciling.value,
            DaemonLifecycleState.running.value,
        }:
            return False
        if claim_attempted and instance_id != self.runtime.instance_id:
            return False
        try:
            self.store.set_daemon_lifecycle(
                DaemonLifecycleState.stopped.value,
                instance_id=instance_id,
                state={"startup_failed": True},
            )
        except Exception:
            # The lifecycle transaction commits before change notifications; a
            # callback failure must not hide the durable cleanup attempt.
            pass
        return True

    def _install_live_rerun_effect_guard(self) -> None:
        """Revalidate rerun signals immediately before provider-backed effects."""

        original = self.executor._update_feature_issues_after_push

        def guarded(
            task: TaskRecord,
            source: TaskRecord,
            sha: str,
            transcript: Any,
        ) -> None:
            if self._is_live_rerun_task(source):
                if not self._refresh_live_rerun_context(source):
                    raise RuntimeError("live rerun signal revalidation failed")
                try:
                    source = self.store.get(source.id)
                except KeyError as exc:
                    raise RuntimeError("live rerun source disappeared") from exc
            original(task, source, sha, transcript)

        self.executor._update_feature_issues_after_push = guarded

    @staticmethod
    def _is_live_rerun_task(task: TaskRecord) -> bool:
        return (
            str(task.spec.source) == "rerun-live"
            and task.dry_run_of_task_id is not None
        )

    def _rerun_task_for_admission(self, task: TaskRecord) -> TaskRecord | None:
        if self._is_live_rerun_task(task):
            return task
        if not _is_integration_manager_task(task):
            return None
        source_task_id = task.spec.metadata.get("source_task_id")
        if not isinstance(source_task_id, str) or not source_task_id:
            return None
        try:
            source = self.store.get(source_task_id)
        except KeyError:
            return None
        return source if self._is_live_rerun_task(source) else None

    def _refresh_live_rerun_context(self, task: TaskRecord) -> bool:
        """Reject stale reruns and persist only an all-current context."""

        if not self._is_live_rerun_task(task):
            return True
        try:
            if self.store.task_execution_mode(task.id) is not ExecutionMode.live:
                return False
            linked = self.store.selected_signal_items_for_task(task.id)
        except (AttributeError, KeyError, TypeError, ValueError):
            return False
        if not linked:
            return True
        try:
            revalidation = revalidate_signal_items_with_context(
                self.config, linked, strict=True
            )
        except Exception:
            return False
        selected_ids = [item.id for item in linked]
        actionable_ids = [item.id for item in revalidation.actionable]
        if (
            revalidation.stale_reasons
            or actionable_ids != selected_ids
            or set(revalidation.refreshed) != set(selected_ids)
        ):
            return False
        current_items = [revalidation.refreshed[item_id] for item_id in selected_ids]
        context = {
            "selected_signal_item_ids": selected_ids,
            "selected_signal_items": [
                item.model_dump(mode="json") for item in current_items
            ],
        }
        if task.spec.metadata.get("source_context") == context:
            return True
        try:
            self.store.refresh_live_rerun_context(
                task.id, selected_signal_items=current_items
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return False
        task.spec.metadata["source_context"] = context
        return True

    def _task_admission_allowed(self, task: TaskRecord) -> bool:
        """Allow local work only after live reruns prove current inputs."""

        try:
            mode = self.store.task_execution_mode(task.id)
        except (AttributeError, KeyError, ValueError):
            return False
        if mode not in {ExecutionMode.live, ExecutionMode.dry_run}:
            return False
        rerun = self._rerun_task_for_admission(task)
        return rerun is None or self._refresh_live_rerun_context(rerun)

    def startup_reconcile(self) -> tuple[ReconciliationOutcome, ...]:
        """Validate and recover durable ownership before dispatch is allowed."""

        with self._lifecycle_lock:
            if self._startup_complete:
                return tuple(self._reconciliation)
            claim_attempted = False
            with self._runtime_lock:
                self.runtime.lifecycle = DaemonLifecycleState.reconciling
                self.runtime.state = DaemonRuntimeState.active
            try:
                with use_subprocess_owner(self._subprocess_owner):
                    remote_push_ready = preflight_remote_push(self.config)
                    report = run_preflight(
                        self.config, self.store, check_remote_push=False
                    )
                if remote_push_ready:
                    report = PreflightReport(
                        checks=(*report.checks, "remote-push"),
                        warnings=report.warnings,
                    )
                    self._log(
                        "remote push preflight ok "
                        f"remote={self.config.git_remote} branch={self.config.main_branch}"
                    )
                self._preflight_report = report
                self.store.recover()
                self._prepare_planner_session()
                self._restore_resource_pressure()

                outcomes: list[ReconciliationOutcome] = []
                self.executor.retry_validation_cleanup_pending()
                self._reconcile_docker_resources()
                self._startup_reconcile_control_loop()
                tasks = sorted(list(self.store.iter_tasks()), key=lambda item: item.id)
                for task in tasks:
                    outcome = self._reconcile_task(task)
                    outcomes.append(outcome)
                    if "ownership" not in outcome.detail.lower():
                        try:
                            self.store.add_event(
                                task.id,
                                "daemon.reconciled",
                                outcome.disposition.value,
                                outcome.as_dict(),
                            )
                        except Exception:
                            # Reconciliation evidence must not hide the identity result.
                            pass
                    if (
                        outcome.disposition is ReconciliationDisposition.blocked
                        and _is_identity_conflict(outcome.detail)
                        and "ownership" not in outcome.detail.lower()
                        and not TaskStatus(task.status).terminal
                    ):
                        try:
                            self.store.finish_task(
                                task.id,
                                TaskStatus.blocked,
                                outcome.detail,
                            )
                        except Exception:
                            # The durable reconciliation event remains evidence even
                            # when an older task row cannot accept a terminal block.
                            pass
                    if self._shutdown_event.is_set():
                        break
                self._reconciliation = outcomes
                if self._shutdown_event.is_set():
                    return tuple(outcomes)
                claim_attempted = True
                self.store.claim_daemon_instance(
                    self.runtime.instance_id,
                    lifecycle=DaemonLifecycleState.starting.value,
                )
                with self._runtime_lock:
                    self.runtime.lifecycle = DaemonLifecycleState.running
                    self.runtime.state = DaemonRuntimeState.idle
                    self.runtime.reconciliation_complete = True
                    self.runtime.heartbeat_at = utc_now()
                self.store.set_daemon_lifecycle(
                    DaemonLifecycleState.running.value,
                    instance_id=self.runtime.instance_id,
                    state={"reconciliation_complete": True},
                )
                self._publication_authority = (
                    self.store.get_daemon_publication_authority(
                        instance_id=self.runtime.instance_id
                    )
                )
                if self._publication_authority is None:
                    self._log("daemon publication authority unavailable")
                try:
                    self._control_loop_ledger.record_runtime(
                        "running", {"instanceId": self.runtime.instance_id}
                    )
                    self._control_loop_wakeup.set()
                except Exception as exc:
                    self._log(
                        "control-loop runtime start lag "
                        f"error={exc.__class__.__name__}"
                    )
                self._enqueue_materialized_publications()
                self._start_publication_worker()
                self._startup_complete = True
                return tuple(outcomes)
            except BaseException:
                self._startup_complete = False
                try:
                    claim_cleaned = self._cleanup_startup_claim(
                        claim_attempted=claim_attempted
                    )
                except Exception:
                    claim_cleaned = False
                with self._runtime_lock:
                    if claim_cleaned:
                        self.runtime.lifecycle = DaemonLifecycleState.stopped
                        self.runtime.state = DaemonRuntimeState.stopping
                    else:
                        self.runtime.lifecycle = DaemonLifecycleState.starting
                        self.runtime.state = DaemonRuntimeState.starting
                    self.runtime.reconciliation_complete = False
                raise

    def _startup_reconcile_control_loop(self) -> None:
        """Establish the shared epoch and repair archive lag before dispatch."""

        try:
            task_epoch = self.config.ensure_epoch()
            archive_epoch = self._control_loop_archive.ensure_task_epoch(task_epoch)
            if archive_epoch.epoch_id != self._control_loop_ledger.epoch_id:
                raise ArchiveConflictError("control-loop and ledger epochs differ")
            self._reconcile_interrupted_planner_runs()
            # Startup is the explicit fail-closed audit boundary.  It reads
            # every retained event and planner artifact once, after which the
            # archive can reuse identity-checked facts for recurring drains.
            result = self._drain_control_loop_once(full_audit=True, publish=False)
            if (
                result.get("error")
                or result.get("auditIncomplete")
                or result.get("eventAuditIncomplete")
                or result.get("plannerAuditIncomplete")
            ):
                self._control_loop_ledger.set_planning_blocked(
                    True, reason="control-loop startup audit incomplete"
                )
                self._log(
                    "control-loop reconciliation blocked "
                    f"error={result.get('error', 'incomplete')}"
                )
                return
            visible_ids = set(result.get("visibleRunIds", ()))
            invalid_ids = set(result.get("invalidRuns", ()))
            for run in self._control_loop_ledger.list_planner_runs():
                if run.completed_at is not None and (
                    run.planner_run_id not in visible_ids
                    or run.planner_run_id in invalid_ids
                ):
                    self._planner_publication_queue[run.planner_run_id] = run
            with self._control_loop_lock:
                self._publish_control_loop_runs(self._control_loop_ledger)
        except Exception as exc:
            self._control_loop_ledger.set_planning_blocked(
                True, reason=f"control-loop startup reconciliation: {exc.__class__.__name__}"
            )
            self._log(f"control-loop reconciliation blocked error={exc.__class__.__name__}")

    def _reconcile_interrupted_planner_runs(self) -> None:
        ledger = self._control_loop_ledger
        for run in ledger.list_planner_runs(include_terminal=False):
            if run.planner_run_id == self._active_planner_run_id:
                continue
            sources = self._interrupted_planner_artifact_sources(run)
            completed = ledger.complete_planner_run(
                run.planner_run_id,
                [],
                state="interrupted",
                result={},
                diagnostics={"reason_code": "daemon_restart_interrupted_planner"},
                artifact_sources=sources,
                schedule_retry_key="planner",
            )
            self._planner_publication_queue[run.planner_run_id] = completed
            self._control_loop_wakeup.set()

    def _interrupted_planner_artifact_sources(
        self, run: ControlPlannerRun
    ) -> dict[str, tuple[str, bool]]:
        safe_run = re.sub(
            r"[^A-Za-z0-9_.-]", "-", run.planner_run_id
        ).strip("-") or "planner"
        run_root = self.config.private_sessions_dir / "planner" / safe_run
        candidates = (
            sorted(path for path in run_root.iterdir() if path.is_dir())
            if run_root.is_dir()
            else []
        )
        if len(candidates) > 1:
            raise ArchiveConflictError(
                "interrupted planner run has ambiguous private session evidence"
            )
        source_root = candidates[0] if candidates else None
        fallback = (
            self.config.private_sessions_dir
            / "planner-evidence"
            / run.planner_run_id
        )
        fallback.mkdir(parents=True, exist_ok=True, mode=0o700)
        values: dict[str, bytes] = {
            "prompt.md": (
                json.dumps(run.prompt or {}, ensure_ascii=True, sort_keys=True).encode(
                    "utf-8"
                )
                + b"\n"
            ),
            "codex.jsonl": b"",
            "last-message.md": b"",
        }
        sources: dict[str, tuple[str, bool]] = {}
        for name, fallback_bytes in values.items():
            source = source_root / name if source_root is not None else fallback / name
            if not source.is_file():
                source = fallback / name
                source.write_bytes(fallback_bytes)
            sources[name] = (str(source), True)
        return sources

    def _build_control_loop_current(self) -> CurrentState | None:
        ledger = self._control_loop_ledger
        try:
            poll_result = scheduler_state(self.config, self.store)
            state = poll_result.state
            pending = self.store.pending_signal_items(limit=200)
            pending_ids = [
                signal_id
                for item in pending
                if (signal_id := ledger.canonical_signal_id(item.provider, item.fingerprint))
                is not None
            ]
            counts = {
                "fetches": len(self.store.list_signal_fetch_runs(limit=10_000)),
                "observations": 0,
                "signals": 0,
                "plannerRuns": 0,
                "pendingSignals": len(pending_ids),
                "activeTasks": self.store.active_count(),
            }
            with ledger._connect() as db:  # bounded local projection query
                for key, query in (
                    ("observations", "SELECT COUNT(*) FROM control_loop_observations"),
                    ("signals", "SELECT COUNT(*) FROM control_loop_signals"),
                    ("plannerRuns", "SELECT COUNT(*) FROM control_loop_planner_runs"),
                ):
                    counts[key] = int(db.execute(query).fetchone()[0])
            return CurrentState(
                epochId=ledger.epoch_id,
                providerState={
                    item.provider: item.model_dump(mode="json")
                    for item in state.providers
                },
                schedulerState={
                    **state.model_dump(mode="json"),
                    "planningBlocked": ledger.planning_blocked,
                },
                runtimeState=self._runtime_snapshot().model_dump(mode="json"),
                counts=counts,
                pendingSignalIds=pending_ids,
                activePlannerRunId=self._active_planner_run_id,
                archive={
                    "formatVersion": ControlLoopArchive.format_version,
                    "health": "blocked" if ledger.planning_blocked else "ok",
                    "lagSequences": len(ledger.outbox(limit=10_000)),
                },
            )
        except Exception:
            return None

    def _publish_control_loop_runs(self, ledger: ControlLoopLedger) -> bool:
        """Publish queued terminal planner runs and report remaining lag."""

        pending = False
        for run_id, run in list(self._planner_publication_queue.items()):
            try:
                artifacts = self._planner_artifacts(run)
                target = self._control_loop_archive.publish_planner_run(run, artifacts)
                if self._control_loop_archive.verify_planner_run(run_id):
                    self._planner_publication_queue.pop(run_id, None)
                    self._log(f"planner archive sealed run={run_id} path={target}")
                else:
                    pending = True
            except ArchiveConflictError as exc:
                pending = True
                ledger.set_planning_blocked(True, reason="visible planner-run conflict")
                self._log(f"planner archive blocked run={run_id} error={exc.__class__.__name__}")
            except (OSError, ArchiveError) as exc:
                pending = True
                self._log(f"planner archive lag run={run_id} error={exc.__class__.__name__}")
        return pending

    def overhead_usage_rows(self) -> tuple[object, ...]:
        """Return local aggregate rows without reading planner artifacts."""

        return tuple(self._control_loop_ledger.list_overhead_usage())

    def _reconcile_control_loop_usage(self) -> dict[str, Any]:
        reducer = self._control_loop_usage
        # The committed repository catalog is the sole pricing authority.
        # Refresh it at the bounded control-loop boundary so a catalog
        # replacement is observed without restarting the daemon.  A malformed
        # or unavailable candidate never displaces the last validated catalog.
        self._publication_catalog()
        result = reducer.reconcile()
        if result.get("processed") or result.get("pending"):
            publication_wakeup = getattr(self, "_publication_wakeup", None)
            if publication_wakeup is not None:
                publication_wakeup.set()
        return result

    def _drain_control_loop_once(
        self,
        *,
        full_audit: bool = False,
        publish: bool = True,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        ledger = self._control_loop_ledger
        if deadline is None:
            acquired = self._control_loop_lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "materialized": 0,
                    "conflicts": 0,
                    "deadline_exhausted": True,
                }
            acquired = self._control_loop_lock.acquire(timeout=remaining)
        if not acquired:
            return {
                "materialized": 0,
                "conflicts": 0,
                "deadline_exhausted": True,
            }
        try:
            try:
                result = self._control_loop_archive.reconcile(
                    ledger,
                    current=self._build_control_loop_current(),
                    full_audit=full_audit,
                )
            except Exception as exc:
                # A temporary writer failure must not stop task dispatch.  The
                # durable outbox remains pending for the next retry.
                self._log(f"control-loop archive lag error={exc.__class__.__name__}")
                return {
                    "materialized": 0,
                    "conflicts": 0,
                    "error": exc.__class__.__name__,
                    "auditIncomplete": full_audit,
                }
            if publish:
                if self._publish_control_loop_runs(ledger):
                    result["pending"] = True
            usage_allowed = not any(
                result.get(key)
                for key in ("auditIncomplete", "eventAuditIncomplete", "plannerAuditIncomplete")
            )
            if usage_allowed:
                try:
                    usage = self._reconcile_control_loop_usage()
                    # Keep the daemon result bounded; aggregate rows remain in
                    # the private ledger and are never emitted here.
                    result["usage"] = {
                        "processed": int(usage.get("processed", 0)),
                        "skipped": int(usage.get("skipped", 0)),
                        "errors": list(usage.get("errors", ()))[:32],
                        "pending": bool(usage.get("pending")),
                        "watermark": usage.get("watermark"),
                        "rowCount": len(usage.get("rows", ())),
                    }
                    if usage.get("pending"):
                        result["pending"] = True
                    if usage.get("processed") or usage.get("pending"):
                        self._publication_wakeup.set()
                except Exception as exc:
                    result["usage"] = {
                        "processed": 0,
                        "skipped": 0,
                        "errors": [exc.__class__.__name__],
                        "pending": False,
                        "watermark": ledger.overhead_usage_watermark(),
                        "rowCount": len(ledger.list_overhead_usage()),
                    }
            return result
        finally:
            self._control_loop_lock.release()

    def _start_control_loop_writer(self) -> None:
        with self._control_loop_lock:
            if self._control_loop_thread is not None and self._control_loop_thread.is_alive():
                return
            self._control_loop_stop.clear()
            self._control_loop_thread = threading.Thread(
                target=self._control_loop_writer_loop,
                name="steward-control-loop-archive",
                daemon=True,
            )
            self._control_loop_thread.start()

    def _control_loop_writer_loop(self) -> None:
        while not self._control_loop_stop.is_set():
            # Clear before the drain.  A wakeup raised during the drain stays
            # set and is observed by the following wait, avoiding a lost race.
            self._control_loop_wakeup.clear()
            result = self._drain_control_loop_once()
            if self._control_loop_stop.is_set():
                break
            pending = bool(
                result
                and (
                    result.get("pending")
                    or result.get("error")
                    or result.get("conflicts")
                    or self._planner_publication_queue
                )
            )
            timeout = self._control_loop_retry_interval() if pending else None
            self._control_loop_wakeup.wait(timeout)

    def _control_loop_retry_interval(self) -> float:
        configured = getattr(self.config, "scheduler_wait_interval_sec", 1.0)
        try:
            value = float(configured)
        except (TypeError, ValueError):
            value = 1.0
        return max(0.05, min(value, 5.0))

    def _stop_control_loop_writer(self, *, deadline: float | None = None) -> bool:
        self._control_loop_stop.set()
        self._control_loop_wakeup.set()
        thread = self._control_loop_thread
        if thread is None:
            return True
        if thread is not threading.current_thread():
            timeout = 2.0
            if deadline is not None:
                timeout = max(0.0, deadline - time.monotonic())
            thread.join(timeout=timeout)
        stopped = not thread.is_alive()
        if stopped and self._control_loop_thread is thread:
            self._control_loop_thread = None
        return stopped

    def _install_publication_change_callback(self) -> None:
        """Wake the publication worker after every committed local mutation."""

        if self.config.dry_run:
            return
        if not getattr(self.config.publication, "enabled", False):
            return
        with self._publication_lock:
            if self._publication_callback is not None:
                return
            previous = self.store.on_change

            def on_change() -> None:
                try:
                    if previous is not None:
                        previous()
                finally:
                    self._publication_wakeup.set()

            self.store.on_change = on_change
            self._publication_previous_callback = previous
            self._publication_callback = on_change

    def _uninstall_publication_change_callback(self) -> bool:
        """Release this daemon's store callback without overwriting a replacement."""

        # A few narrow worker tests construct the daemon without ``__init__``;
        # retain the same locking contract for those lightweight doubles.
        lock = getattr(self, "_publication_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._publication_lock = lock
        with lock:
            callback = getattr(self, "_publication_callback", None)
            if callback is None:
                self._publication_previous_callback = None
                return True

            current = self.store.on_change
            if current is callback:
                self.store.on_change = self._publication_previous_callback

            # Whether the callback was restored or superseded externally, the
            # daemon must drop its retained callback and previous-callback refs.
            self._publication_callback = None
            self._publication_previous_callback = None
            return True

    def _build_publication_publisher(self) -> CloudPublisher | None:
        """Construct transport clients only for a live publication worker."""

        if self.config.dry_run:
            return None
        publication = self.config.publication
        r2: object | None = None
        d1: object | None = None
        try:
            r2 = R2Client(
                config=publication,
                timeout_seconds=float(publication.network_timeout_seconds),
            )
            d1 = D1PublicationClient(
                config=publication,
                timeout_seconds=float(publication.network_timeout_seconds),
            )
        except Exception:
            if r2 is not None:
                _close_r2_provider_client(r2)
            if d1 is not None:
                _close_d1_provider_client(d1)
            raise
        lease_seconds = max(1, int(publication.lease_duration_seconds))
        retry_backoff_seconds = max(1, int(publication.retry_backoff_seconds))
        retry_policy = PublicationRetryPolicy(publication.max_retries)
        return CloudPublisher(
            self.store,
            r2,
            d1,
            worker_id=f"publication-{self.runtime.instance_id}",
            lease_seconds=lease_seconds,
            retry_backoff_seconds=retry_backoff_seconds,
            retry_policy=retry_policy,
        )

    def _publication_retry_interval(self) -> float:
        configured = getattr(self.config.publication, "retry_backoff_seconds", None)
        try:
            value = float(configured)
        except (TypeError, ValueError):
            value = PUBLICATION_RETRY_INTERVAL_SECONDS
        return max(0.05, min(PUBLICATION_RETRY_INTERVAL_SECONDS, value))

    def _repair_staged_generation(
        self,
        publisher: CloudPublisher,
        generation: PublicationGeneration,
        source: object | None,
        compose_kwargs: Mapping[str, object],
    ) -> bool:
        """Replace a credential-free staging row before any provider request."""

        if source is None:
            return False
        publication_id = generation.publication_id
        task_id = generation.task_id
        try:
            candidate = publisher.compose(
                source,
                task_id=task_id,
                **compose_kwargs,
            )
        except Exception as exc:
            self._log(
                "publication generation identity check failed "
                f"generation={publication_id} error={exc.__class__.__name__}"
            )
            return False
        # A blocked row is eligible for replacement only when the daemon's
        # credential-aware composition proves a different canonical
        # generation.  This check is transport-free and avoids replaying
        # an unchanged row's hide reconciliation against the provider.
        if type(candidate) is not ComposedPublicationGeneration:
            return False
        if candidate.task_id != task_id or candidate.publication_id == publication_id:
            return False
        try:
            result = publisher._enqueue_precomposed_repair(publication_id, candidate)
        except Exception as exc:
            self._log(
                "publication generation reconciliation failed "
                f"generation={publication_id} error={exc.__class__.__name__}"
            )
            return False
        if not isinstance(result, PublicationResult):
            return False
        if result.status is PublicationStatus.queued:
            self._log(
                "publication generation reconciled "
                f"generation={publication_id}"
            )
            return True
        return False

    def _publication_source(self, generation: PublicationGeneration) -> object | None:
        task_id = generation.task_id
        run_id = generation.run_id
        try:
            snapshot = load_publication_snapshot(self.config, task_id, run_id)
            if snapshot is not None:
                return snapshot
            task = self.store.get(task_id)
            return self.executor._integration_publication_graph(task)
        except Exception as exc:
            self._log(f"publication source unavailable error={exc.__class__.__name__}")
            return None

    @staticmethod
    def _publication_usage_mapping(value: object) -> Mapping[str, object] | None:
        if isinstance(value, Mapping):
            return value
        if type(value) is StewardOverheadUsage:
            return StewardOverheadUsage.public_dict(value)
        return None

    def _publication_overhead_rows(self) -> tuple[object, ...]:
        try:
            return tuple(self._control_loop_ledger.list_overhead_usage())
        except Exception as exc:
            self._log(f"publication overhead listing failed error={exc.__class__.__name__}")
            return ()

    def _publication_catalog(self) -> object | None:
        reducer = getattr(self, "_control_loop_usage", None)
        current = getattr(reducer, "catalog", None)
        config = getattr(self, "config", None)
        repo_root = getattr(config, "repo_root", None)
        if reducer is None or repo_root is None:
            return current
        try:
            candidate = PriceCatalog.from_path(Path(repo_root) / "steward" / "model-prices.json")
        except (FileNotFoundError, OSError, ValueError):
            return current
        current_digest = getattr(current, "digest", None)
        if current_digest is None:
            current_digest = getattr(current, "catalog_digest", None)
        if candidate.digest != current_digest:
            reducer.catalog = candidate
            current = candidate
            publication_wakeup = getattr(self, "_publication_wakeup", None)
            if publication_wakeup is not None:
                publication_wakeup.set()
        return current

    def _reconcile_publication_usage(self, publisher: CloudPublisher) -> bool:
        """Process one bounded overhead or cached-D1 backfill obligation."""

        authority = getattr(self, "_publication_authority", None)
        if authority is None:
            self._log("publication aggregate authority unavailable")
            return False
        rows = self._publication_overhead_rows()
        if rows:
            serialized = [self._publication_usage_mapping(row) for row in rows]
            if all(item is not None for item in serialized):
                try:
                    aggregate_digest = _overhead_digest(
                        tuple(item for item in serialized if item is not None)
                    )
                except D1Error:
                    # Keep malformed test doubles and legacy ledgers bounded;
                    # the D1 boundary still rejects this shape fail-closed.
                    aggregate_digest = hashlib.sha256(
                        json.dumps(
                            serialized,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                if aggregate_digest != getattr(self, "_publication_overhead_digest", None):
                    position = getattr(self, "_publication_overhead_position", 0)
                    if not isinstance(position, int) or position < 0 or position >= len(rows):
                        position = 0
                    row_mapping = serialized[position]
                    try:
                        row_digest = _overhead_digest((row_mapping,))
                    except D1Error:
                        row_digest = hashlib.sha256(
                            json.dumps(
                                row_mapping,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                    try:
                        receipt = publisher.reconcile_overhead(
                            row_mapping,
                            digest=row_digest,
                            authority=authority,
                        )
                    except Exception as exc:
                        self._log(
                            "publication overhead reconciliation failed "
                            f"error={exc.__class__.__name__}"
                        )
                        return False
                    if not isinstance(receipt, OverheadReceipt):
                        self._log("publication overhead reconciliation returned an invalid receipt")
                        return True
                    position += 1
                    if position >= len(rows):
                        position = 0
                        self._publication_overhead_digest = aggregate_digest
                    self._publication_overhead_position = position
                    return True

        catalog = self._publication_catalog()
        if catalog is None:
            return False
        catalog_digest = catalog.digest
        if not isinstance(catalog_digest, str) or not catalog_digest:
            return False
        previous_catalog_digest = getattr(
            self, "_publication_backfill_catalog_digest", None
        )
        previous_cursor = getattr(self, "_publication_backfill_cursor", None)
        previous_blocked = getattr(self, "_publication_backfill_blocked", False)
        if catalog_digest != previous_catalog_digest:
            self._publication_backfill_catalog_digest = catalog_digest
            self._publication_backfill_cursor = None
            self._publication_backfill_blocked = False
        if getattr(self, "_publication_backfill_blocked", False):
            return False
        try:
            receipt = publisher.backfill_usage(
                catalog,
                cursor=getattr(self, "_publication_backfill_cursor", None),
                limit=64,
                authority=authority,
            )
        except Exception as exc:
            self._publication_backfill_catalog_digest = previous_catalog_digest
            self._publication_backfill_cursor = previous_cursor
            self._publication_backfill_blocked = previous_blocked
            self._log(f"publication usage backfill failed error={exc.__class__.__name__}")
            return False
        if not isinstance(receipt, UsageBackfillReceipt):
            self._publication_backfill_catalog_digest = previous_catalog_digest
            self._publication_backfill_cursor = previous_cursor
            self._publication_backfill_blocked = previous_blocked
            self._log("publication usage backfill returned an invalid receipt")
            return False
        if receipt.blocked_reason:
            self._publication_backfill_blocked = True
            self._log(
                f"publication usage backfill blocked reason={receipt.blocked_reason}"
            )
            return False
        self._publication_backfill_cursor = receipt.next_cursor
        return bool(
            receipt.changed
            or receipt.processed_turns
            or self._publication_backfill_cursor is not None
        )

    def _drain_pending_publication_hides(
        self, publisher: CloudPublisher
    ) -> tuple[bool, bool]:
        """Reconcile local hide fences before claiming any exposure work.

        The first value reports progress; the second reports that a pending
        listing was available.  A listing or provider failure is fail-closed:
        queued generations remain untouched until the next bounded worker
        cycle can retry the hide.
        """

        try:
            pending = list(self.store.list_pending_publication_hides())
        except Exception as exc:
            self._log(
                "publication hide reconciliation listing failed "
                f"error={exc.__class__.__name__}"
            )
            return False, True
        if not pending:
            return False, False
        progressed = False
        for fence in pending:
            if not isinstance(fence, PublicationHideFence):
                self._log("publication hide reconciliation rejected malformed fence")
                return False, True
            task_id = fence.task_id
            reason = fence.reason
            try:
                result = publisher.hide_task(task_id, reason)
            except Exception as exc:
                self._log(
                    "publication hide reconciliation failed "
                    f"task={task_id} error={exc.__class__.__name__}"
                )
                return False, True
            if not isinstance(result, PublicationHideResult):
                self._log("publication hide reconciliation returned an invalid result")
                return False, True
            if result.status in {
                PublicationHideStatus.hidden,
                PublicationHideStatus.unchanged,
            }:
                progressed = True
                continue
            self._log(
                "publication hide reconciliation pending "
                f"task={task_id} status={result.status.value}"
            )
            return False, True
        return progressed, True

    def _publish_next_generation(self, publisher: CloudPublisher) -> bool:
        if self.config.dry_run:
            self._log("dry-run publication worker paused")
            return False
        hide_progress, hides_seen = self._drain_pending_publication_hides(publisher)
        if hides_seen:
            # Do not claim or expose a queued generation while any pending hide
            # remains unresolved.  Successful hides immediately re-run the
            # cycle so another pending fence is drained before exposure work.
            return hide_progress
        if self._reconcile_publication_usage(publisher):
            return True
        try:
            # Recovery is part of every worker cycle, not only startup.
            # The store performs the lease compare-and-set and preserves
            # all receipts while moving expired work to retry_wait.
            self.store.expire_publication_leases()
        except Exception as exc:
            self._log(
                "publication lease reconciliation failed "
                f"error={exc.__class__.__name__}"
            )
        try:
            generations = self.store.list_publication_generations(
                states={PublicationState.queued, PublicationState.retry_wait},
                limit=1,
            )
        except Exception as exc:
            self._log(
                "publication generation listing failed "
                f"error={exc.__class__.__name__}"
            )
            return False
        if not generations:
            # A daemon can crash after the publisher fail-closes the old
            # credential-free staging identity but before retry_publication
            # replaces it.  Reconcile that bounded local state on restart.
            try:
                generations = [
                    generation
                    for generation in self.store.list_publication_generations(
                        states={PublicationState.blocked},
                        limit=None,
                    )
                    if generation.reason == "integrity"
                ]
            except Exception as exc:
                self._log(
                    "publication blocked-generation listing failed "
                    f"error={exc.__class__.__name__}"
                )
                return False
        if not generations:
            return False
        compose_kwargs = _publication_compose_kwargs(
            getattr(getattr(self, "config", None), "publication", None)
        )
        generation: PublicationGeneration = generations[0]
        if generation.state is PublicationState.blocked:
            for generation in generations:
                source = self._publication_source(generation)
                if self._repair_staged_generation(
                    publisher,
                    generation,
                    source,
                    compose_kwargs,
                ):
                    return True
            return False
        source = self._publication_source(generation)
        publication_id = generation.publication_id
        try:
            result = publisher.publish(
                publication_id,
                source=source,
                compose_kwargs=compose_kwargs,
            )
            if not isinstance(result, PublicationResult):
                self._log("publication worker returned an invalid result")
                return True
            self._log(
                "publication worker processed "
                f"generation={publication_id} status={result.status.value}"
            )
            if (
                result.status is PublicationStatus.blocked
                and result.reason == "integrity"
                and result.phase == "authenticate"
            ):
                return self._repair_staged_generation(
                    publisher,
                    generation,
                    source,
                    compose_kwargs,
                )
        except Exception as exc:
            # CloudPublisher reduces expected provider failures to durable retry
            # states.  This guard keeps an unexpected local failure from taking
            # down the sole restartable worker.
            self._log(
                "publication worker cycle failed "
                f"generation={publication_id} error={exc.__class__.__name__}"
            )
            return True
        # A successful exposure may immediately drain another queued row.  All
        # other outcomes wait for the store callback or the bounded retry timer
        # so a durable retry boundary cannot turn into a busy loop.
        return result.status is PublicationStatus.exposed

    def _publication_worker_loop(self) -> None:
        publisher: CloudPublisher | None = None
        transport_cancellation: _PublicationTransportCancellation | None = None
        clients_closed = threading.Event()

        def close_clients() -> None:
            if clients_closed.is_set():
                return
            clients_closed.set()
            if transport_cancellation is not None:
                transport_cancellation.close()

        try:
            while not self._publication_stop.is_set():
                if publisher is None:
                    try:
                        publisher = self._build_publication_publisher()
                        if publisher is None:
                            break
                        transport_cancellation = _PublicationTransportCancellation(
                            publisher.r2,
                            publisher.d1,
                        )
                        self._publication_cancel = transport_cancellation
                        if self._publication_stop.is_set():
                            break
                    except Exception as exc:
                        publisher = None
                        transport_cancellation = None
                        self._publication_cancel = None
                        self._log(
                            "publication worker setup failed "
                            f"error={exc.__class__.__name__}"
                        )
                        self._publication_wakeup.wait(self._publication_retry_interval())
                        self._publication_wakeup.clear()
                        continue
                if self._publish_next_generation(publisher):
                    continue
                self._publication_wakeup.wait(self._publication_retry_interval())
                self._publication_wakeup.clear()
        finally:
            close_clients()
            self._publication_cancel = None
            self._uninstall_publication_change_callback()

    def _start_publication_worker(self) -> None:
        """Start the one daemon-owned publication worker when enabled."""

        if self.config.dry_run:
            return
        if not getattr(self.config.publication, "enabled", False):
            return
        self._install_publication_change_callback()
        with self._publication_lock:
            if self._publication_thread is not None and self._publication_thread.is_alive():
                return
            try:
                self.store.expire_publication_leases()
            except Exception as exc:
                self._log(
                    "publication lease reconciliation failed "
                    f"error={exc.__class__.__name__}"
                )
            self._publication_stop.clear()
            self._publication_wakeup.clear()
            self._publication_thread = threading.Thread(
                target=self._publication_worker_loop,
                name="steward-publication-worker",
                daemon=True,
            )
            self._publication_thread.start()

    def _request_publication_worker_stop(
        self, *, deadline: float | None = None
    ) -> DaemonCancellationResult:
        """Initiate bounded provider cancellation without worker teardown."""

        self._publication_stop.set()
        self._publication_wakeup.set()
        cancel = self._publication_cancel
        if cancel is None:
            return DaemonCancellationResult(quiescent=True)
        # Cancellation closes transport streams and sockets, while the worker
        # retains ownership of final client cleanup in its finally block.
        try:
            result = cancel.cancel(deadline=deadline)
        except Exception as exc:
            self._log(
                "publication transport cancellation failed "
                f"error={exc.__class__.__name__}"
            )
            return DaemonCancellationResult(quiescent=False)
        if isinstance(result, DaemonCancellationResult):
            return result
        # A collaborator that does not return the typed outcome cannot prove
        # quiescence and must not unlock durable authority revocation.
        return DaemonCancellationResult(quiescent=False)

    def _join_publication_worker(self, *, deadline: float | None = None) -> bool:
        """Join a cancelled publication worker within the shutdown deadline."""

        thread = self._publication_thread
        if thread is None:
            self._publication_cancel = None
            return self._uninstall_publication_change_callback()
        if thread is threading.current_thread():
            return False
        if not thread.is_alive():
            if self._publication_thread is thread:
                self._publication_thread = None
                self._publication_cancel = None
            return self._uninstall_publication_change_callback()
        timeout = PUBLICATION_JOIN_TIMEOUT_SECONDS
        if deadline is not None:
            timeout = max(0.0, deadline - time.monotonic())
        thread.join(timeout=timeout)
        if thread.is_alive():
            return False
        if self._publication_thread is thread:
            self._publication_thread = None
            self._publication_cancel = None
        return self._uninstall_publication_change_callback()

    def _stop_publication_worker(self, *, deadline: float | None = None) -> bool:
        """Request bounded worker teardown and acknowledge released ownership."""

        self._request_publication_worker_stop(deadline=deadline)
        return self._join_publication_worker(deadline=deadline)

    start_publication_worker = _start_publication_worker
    stop_publication_worker = _stop_publication_worker

    def _enqueue_materialized_publications(self) -> None:
        """Compose completion evidence without crossing the publication boundary."""

        if not getattr(self.config.publication, "enabled", False) or self.config.dry_run:
            return
        tasks = sorted(list(self.store.iter_tasks()), key=lambda item: item.id)
        materialized: list[tuple[TaskRecord, object]] = []
        for task in tasks:
            try:
                runs = self.store.list_runs(task.id)
            except (AttributeError, KeyError):
                continue
            materialized.extend((task, run) for run in runs)
        for task, run in materialized:
            enqueue_materialized_publication(self.config, self.store, task, run)

    reconcile_startup = startup_reconcile
    reconcile = startup_reconcile

    def _reconcile_task(self, task: TaskRecord) -> ReconciliationOutcome:
        """Reconcile archive, ledger, process, Git, and cleanup identities."""

        try:
            execution = self.store.get_execution(task.id)
            owner_id = execution.owning_pipeline_id
            if owner_id is None:
                raise TaskLedgerOwnershipError(
                    "task execution has no owning pipeline"
                )
            owner = self.store.get_pipeline(owner_id)
            if owner.task_id != task.id or owner.execution_id != execution.id:
                raise TaskLedgerOwnershipError("task execution owner is invalid")
            runs = self.store.list_runs(task.id)
        except (KeyError, TaskLedgerOwnershipError) as exc:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "task execution ownership is invalid",
                evidence={"error": exc.__class__.__name__},
            )

        cleanup_state = self.store.cleanup_obligation_state(task.id)
        terminal = TaskStatus(task.status).terminal
        if terminal and cleanup_state is CleanupStatus.complete:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.unchanged,
                "terminal cleanup already complete",
            )
        if terminal and cleanup_state in {
            CleanupStatus.pending,
            CleanupStatus.retryable,
        }:
            if self.finalize_terminal_task(task.id):
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.cleaned,
                    "pending terminal cleanup converged",
                )
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "terminal cleanup remains pending",
            )
        conflict, evidence = self._reconcile_identity_matrix(task, execution, runs)
        if conflict is not None:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                conflict,
                evidence=evidence,
            )

        if terminal:
            if self.finalize_terminal_task(task.id):
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.cleaned,
                    "terminal archive verified and cleanup converged",
                )
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "terminal sealing or cleanup remains pending",
            )

        if self.session_supervisor is not None and task.worktree_path is not None:
            try:
                self.session_supervisor.reconcile_container(
                    task.id, ensure_running=True
                )
            except Exception as exc:
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "task container identity could not be reconciled",
                    evidence={"error": exc.__class__.__name__},
                )

        running = [run for run in runs if str(run.state) == "running"]
        if len(running) > 1:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "multiple running ledger entries claim one task",
                evidence={"running_count": len(running)},
            )
        if running:
            run = running[0]
            completed = self._complete_atomic_run_result(task, run)
            if completed is not None:
                return completed
            if self.session_supervisor is None:
                try:
                    self.store.mark_run_interrupted(run.id, reason="daemon restart")
                except ValueError:
                    pass
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.interrupted,
                    "run interrupted without a session boundary",
                    run_id=run.id,
                )
            try:
                inspection = self.session_supervisor.inspect(run.id)
            except Exception as exc:
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "run ownership could not be verified",
                    run_id=run.id,
                    evidence={"error": exc.__class__.__name__},
                )
            if inspection.live:
                self._adopted_runs[task.id] = run.id
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.adopted,
                    "matching live wrapper adopted",
                    run_id=run.id,
                    container_id=getattr(getattr(inspection, "container", None), "container_id", None),
                )
            if not _inspection_confirms_stopped(inspection):
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "run liveness could not be confirmed stopped",
                    run_id=run.id,
                    evidence={"error": "liveness_unknown"},
                )
            try:
                self.store.mark_run_interrupted(
                    run.id,
                    reason="wrapper disappeared during daemon restart",
                )
            except ValueError:
                pass
            runs = self.store.list_runs(task.id)

        root = self._interrupted_recovery_root(runs)
        if root is not None and self.session_supervisor is not None:
            return self._resume_or_recover(task, root, runs)
        if root is not None:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.interrupted,
                "partial run evidence preserved for a configured session boundary",
                run_id=root.id,
            )
        deterministic = self._reconcile_deterministic_phase(task, execution)
        if deterministic is not None:
            return deterministic
        return ReconciliationOutcome(
            task.id,
            ReconciliationDisposition.unchanged,
            "ledger identities reconciled",
            evidence=evidence,
        )

    def _reconcile_identity_matrix(
        self,
        task: TaskRecord,
        execution: object,
        runs: list[object],
    ) -> tuple[str | None, dict[str, object]]:
        evidence: dict[str, object] = {
            "archive": "absent",
            "ledger": "matched",
            "worktree": "absent",
            "commit": "not-applicable",
            "remote": "not-applicable",
        }
        try:
            pipelines = self.store.list_pipelines(task.id)
            by_pipeline = {pipeline.id: pipeline for pipeline in pipelines}
            owner = getattr(execution, "owning_pipeline_id", None)
            if owner is None:
                return "execution ownership is missing", evidence
            owner_pipeline = by_pipeline.get(owner)
            if (
                owner_pipeline is None
                or owner_pipeline.execution_id != execution.id
            ):
                return "execution points at an unknown pipeline", evidence
            for run in runs:
                pipeline = by_pipeline.get(run.pipeline_id)
                if pipeline is None or pipeline.task_id != task.id:
                    return "run pipeline identity conflicts with its task", evidence
                session = self.store.get_session(run.session_id)
                if (
                    session.task_id != task.id
                    or session.pipeline_id != run.pipeline_id
                ):
                    return "run session identity conflicts with its pipeline", evidence

            archive = TaskArchiveWriter(self.config)
            task_dir = archive.task_dir(task.id)
            task_json = task_dir / "task.json"
            if task_dir.exists():
                if not task_json.is_file():
                    return "task archive exists without task metadata", evidence
                metadata = json.loads(task_json.read_text(encoding="utf-8"))
                if metadata.get("taskId") != task.id:
                    return "task archive identity conflicts with the ledger", evidence
                for pipeline in pipelines:
                    path = task_dir / "pipelines" / pipeline.id / "pipeline.json"
                    if path.exists():
                        value = json.loads(path.read_text(encoding="utf-8"))
                        if (
                            value.get("taskId") != task.id
                            or value.get("pipelineId") != pipeline.id
                        ):
                            return "pipeline archive identity conflicts with the ledger", evidence
                    else:
                        pipeline_runs = [
                            run for run in runs if run.pipeline_id == pipeline.id
                        ]
                        if pipeline_runs:
                            archive.materialize_pipeline(
                                task.id,
                                pipeline,
                                runs=pipeline_runs,
                            )
                for run in runs:
                    path = (
                        task_dir
                        / "pipelines"
                        / run.pipeline_id
                        / "runs"
                        / run.id
                        / "run.json"
                    )
                    if path.exists():
                        value = json.loads(path.read_text(encoding="utf-8"))
                        if (
                            value.get("taskId") != task.id
                            or value.get("pipelineId") != run.pipeline_id
                            or value.get("runId") != run.id
                        ):
                            return "run archive identity conflicts with the ledger", evidence
                    else:
                        archive.materialize_run(task.id, run.pipeline_id, run)
                evidence["archive"] = "matched"
            elif runs:
                archive.create_task_from_record(
                    task,
                    pipeline=owner_pipeline,
                )
                for pipeline in pipelines:
                    pipeline_runs = [
                        run for run in runs if run.pipeline_id == pipeline.id
                    ]
                    if not pipeline_runs:
                        continue
                    for run in pipeline_runs:
                        archive.materialize_run(task.id, pipeline.id, run)
                    archive.materialize_pipeline(
                        task.id,
                        pipeline,
                        runs=pipeline_runs,
                    )
                evidence["archive"] = "materialized"

            task_worktree = task.worktree_path
            execution_worktree = getattr(execution, "worktree_path", None)
            if task_worktree is not None and execution_worktree is not None:
                if Path(task_worktree).resolve() != Path(execution_worktree).resolve():
                    return "worktree path conflicts with execution ownership", evidence
            worktree = Path(task_worktree or execution_worktree) if (
                task_worktree is not None or execution_worktree is not None
            ) else None
            if worktree is not None:
                if not worktree.is_dir():
                    return "owned worktree is missing", evidence
                inside = run_command(
                    ["git", "rev-parse", "--is-inside-work-tree"],
                    cwd=worktree,
                    cancellation_owner=self._subprocess_owner,
                )
                if not inside.ok or inside.stdout.strip() != "true":
                    return "owned worktree is not a Git worktree", evidence
                base = getattr(execution, "base_commit", None)
                if base:
                    exists = run_command(
                        ["git", "cat-file", "-e", f"{base}^{{commit}}"],
                        cwd=worktree,
                        cancellation_owner=self._subprocess_owner,
                    )
                    if not exists.ok:
                        return "base commit identity is unavailable", evidence
                evidence["worktree"] = "matched"
                conflict = self._reconcile_commit_and_remote(task, worktree)
                if conflict is not None:
                    return conflict, evidence
                evidence["commit"] = "matched"
                if not self.config.dry_run:
                    evidence["remote"] = "matched"
            manifest = task_dir / "manifest.json"
            if manifest.exists() and not archive.verify(task.id):
                return "terminal manifest verification failed", evidence
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            evidence["error"] = exc.__class__.__name__
            return "persisted task identity could not be verified", evidence
        return None, evidence

    def _reconcile_deterministic_phase(
        self,
        task: TaskRecord,
        execution: object,
    ) -> ReconciliationOutcome | None:
        pipeline_id = getattr(execution, "owning_pipeline_id", None)
        if pipeline_id is None:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "execution ownership is missing",
            )
        active = self._unfinished_phase_event(task.id, pipeline_id)
        if active is None:
            return None
        phase = str(active.data.get("phase") or "")
        action = str(active.data.get("action_id") or "")
        pipeline = self.store.get_pipeline(pipeline_id)
        if phase in {"provisioned", "validation", "integration"}:
            self._release_phase_action(task.id, pipeline_id, phase, action)
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.interrupted,
                f"deterministic {phase} phase released for exact rerun",
                evidence={"phase": phase},
            )
        if phase == "commit":
            return self._reconcile_interrupted_commit(
                task,
                execution,
                pipeline,
                active,
            )
        if phase == "push":
            return self._reconcile_interrupted_push(task, pipeline, action)
        return ReconciliationOutcome(
            task.id,
            ReconciliationDisposition.blocked,
            "active phase cannot be reconciled without its run identity",
            evidence={"phase": phase},
        )

    def _reconcile_interrupted_commit(
        self,
        task: TaskRecord,
        execution: object,
        pipeline: object,
        active: object,
    ) -> ReconciliationOutcome:
        phase = "commit"
        action = str(active.data.get("action_id") or "")
        expected_tree = active.data.get("input", {}).get("payload", {}).get(
            "expected_tree"
        )
        worktree = Path(task.worktree_path) if task.worktree_path else None
        if worktree is None or not worktree.is_dir() or not expected_tree:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "commit phase has no exact worktree tree identity",
                evidence={"phase": phase},
            )
        tree = run_command(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=worktree,
            cancellation_owner=self._subprocess_owner,
        )
        status = run_command(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=worktree,
            cancellation_owner=self._subprocess_owner,
        )
        if not tree.ok or not status.ok:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "commit worktree state could not be inspected",
                evidence={"phase": phase},
            )
        if status.stdout:
            self._release_phase_action(task.id, pipeline.id, phase, action)
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.interrupted,
                "uncommitted accepted tree released for commit retry",
                evidence={"phase": phase},
            )
        if tree.stdout.strip() != str(expected_tree):
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "committed tree conflicts with the accepted tree",
                evidence={"phase": phase},
            )
        head = run_command(
            ["git", "rev-parse", "HEAD"],
            cwd=worktree,
            cancellation_owner=self._subprocess_owner,
        )
        if not head.ok:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "commit identity could not be inspected",
                evidence={"phase": phase},
            )
        commit = head.stdout.strip()
        base = pipeline.base_identity or getattr(execution, "base_commit", None)
        if commit == base:
            self.store.finish_task(
                task.id,
                TaskStatus.no_changes,
                "accepted tree was already committed",
            )
            next_phase = PipelineCursorPhase.ready_to_seal
        else:
            if not any(
                event.kind == "pipeline.commit"
                and event.data.get("commit") == commit
                for event in self.store.events(task.id)
            ):
                self.store.add_event(
                    task.id,
                    "pipeline.commit",
                    commit,
                    {
                        "pipeline_id": pipeline.id,
                        "action_id": action,
                        "commit": commit,
                        "tree": expected_tree,
                        "reconciled": True,
                    },
                )
            next_phase = PipelineCursorPhase.push
        self.executor._phase_finish(
            task,
            pipeline,
            PipelineCursorPhase.commit,
            next_phase,
            evidence={"commit": commit, "reconciled": True},
        )
        return ReconciliationOutcome(
            task.id,
            ReconciliationDisposition.ingested,
            "completed commit adopted from exact Git identity",
            evidence={"phase": phase, "commit": commit},
        )

    def _reconcile_interrupted_push(
        self,
        task: TaskRecord,
        pipeline: object,
        action: str,
    ) -> ReconciliationOutcome:
        commit = next(
            (
                event.data.get("commit")
                for event in reversed(self.store.events(task.id))
                if event.kind == "pipeline.commit"
                and isinstance(event.data.get("commit"), str)
            ),
            None,
        )
        if commit:
            try:
                mode = self.store.task_execution_mode(task.id)
            except (AttributeError, KeyError, ValueError):
                mode = None
            if mode is None:
                self._release_phase_action(
                    task.id, pipeline.id, "push", action
                )
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "task execution mode unavailable during push recovery",
                    evidence={"phase": "push"},
                )
            if mode is ExecutionMode.dry_run:
                with self.executor._push_effect_admission(
                    task, pipeline, commit
                ) as decision:
                    proposal_evidence = self.executor._record_push_proposal(
                        task, pipeline, commit, decision
                    )
                self._release_phase_action(
                    task.id, pipeline.id, "push", action
                )
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.interrupted,
                    "dry-run push proposal persisted for idempotent retry",
                    evidence={"phase": "push", **proposal_evidence},
                )
        worktree = Path(task.worktree_path) if task.worktree_path else None
        if commit and worktree is not None and worktree.is_dir():
            remote = f"{self.config.git_remote}/{self.config.main_branch}"
            fetched = run_command(
                ["git", "fetch", "--quiet", self.config.git_remote, self.config.main_branch],
                cwd=worktree,
                env={**git_environment(self.config), **_NONINTERACTIVE_GIT_ENV},
                cancellation_owner=self._subprocess_owner,
            )
            if not fetched.ok:
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "interrupted push remote ancestry could not be fetched",
                    evidence={"phase": "push", "category": "fetch-failed"},
                )
            ancestry = run_command(
                ["git", "merge-base", "--is-ancestor", commit, remote],
                cwd=worktree,
                cancellation_owner=self._subprocess_owner,
            )
            if ancestry.ok:
                self.store.add_event(
                    task.id,
                    "pipeline.push.ambiguous_resolved",
                    commit,
                    {
                        "pipeline_id": pipeline.id,
                        "commit": commit,
                        "reconciled": True,
                    },
                )
                self.store.finish_task(
                    task.id,
                    TaskStatus.pushed,
                    f"pushed {commit}",
                )
                self.executor._phase_finish(
                    task,
                    pipeline,
                    PipelineCursorPhase.push,
                    PipelineCursorPhase.ready_to_seal,
                    evidence={"commit": commit, "reconciled": True},
                )
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.ingested,
                    "completed push adopted from fetched remote ancestry",
                    evidence={"phase": "push", "commit": commit},
                )
        self._release_phase_action(task.id, pipeline.id, "push", action)
        return ReconciliationOutcome(
            task.id,
            ReconciliationDisposition.interrupted,
            "unconfirmed push released for idempotent retry",
            evidence={"phase": "push"},
        )

    def _unfinished_phase_event(self, task_id: str, pipeline_id: str):
        states: dict[str, tuple[str, object]] = {}
        for event in self.store.events(task_id):
            if event.data.get("pipeline_id") != pipeline_id:
                continue
            if event.kind == "pipeline.phase.started":
                action = event.data.get("action_id")
                if action:
                    states[str(action)] = ("active", event)
            elif event.kind == "pipeline.phase.finished":
                action = event.data.get("output", {}).get("action_id")
                if action:
                    states[str(action)] = ("finished", event)
            elif event.kind == "pipeline.phase.interrupted":
                action = event.data.get("action_id")
                if action:
                    states[str(action)] = ("interrupted", event)
        return next(
            (
                event
                for state, event in reversed(list(states.values()))
                if state == "active"
            ),
            None,
        )

    def _release_phase_action(
        self,
        task_id: str,
        pipeline_id: str,
        phase: str,
        action_id: str,
    ) -> None:
        self.store.add_event(
            task_id,
            "pipeline.phase.interrupted",
            f"{phase} interrupted by daemon restart",
            {
                "pipeline_id": pipeline_id,
                "phase": phase,
                "action_id": action_id,
                "reason": "daemon-restart",
            },
        )

    def _reconcile_commit_and_remote(
        self,
        task: TaskRecord,
        worktree: Path,
    ) -> str | None:
        events = self.store.events(task.id)
        commit = next(
            (
                str(event.data["commit"])
                for event in reversed(events)
                if event.kind == "pipeline.commit"
                and isinstance(event.data.get("commit"), str)
            ),
            None,
        )
        if commit is None:
            return None
        exists = run_command(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=worktree,
            cancellation_owner=self._subprocess_owner,
        )
        if not exists.ok:
            return "persisted commit identity is unavailable"
        expected_tree = next(
            (
                str(event.data["tree"])
                for event in reversed(events)
                if event.kind == "pipeline.commit"
                and event.data.get("commit") == commit
                and isinstance(event.data.get("tree"), str)
            ),
            None,
        )
        if expected_tree is not None:
            tree = run_command(
                ["git", "rev-parse", f"{commit}^{{tree}}"],
                cwd=worktree,
                cancellation_owner=self._subprocess_owner,
            )
            if not tree.ok or tree.stdout.strip() != expected_tree:
                return "persisted commit tree conflicts with accepted output"
        pushed = any(
            event.kind in {"pipeline.push", "pipeline.push.ambiguous_resolved"}
            and event.data.get("commit") == commit
            for event in events
        )
        try:
            mode = self.store.task_execution_mode(task.id)
        except (AttributeError, KeyError, ValueError):
            mode = None
        if pushed and mode is None:
            return "task execution mode unavailable for push reconciliation"
        if pushed and mode is ExecutionMode.live:
            remote = f"{self.config.git_remote}/{self.config.main_branch}"
            fetched = run_command(
                ["git", "fetch", "--quiet", self.config.git_remote, self.config.main_branch],
                cwd=worktree,
                env={**git_environment(self.config), **_NONINTERACTIVE_GIT_ENV},
                cancellation_owner=self._subprocess_owner,
            )
            if not fetched.ok:
                return "persisted push remote ancestry could not be fetched"
            ancestry = run_command(
                ["git", "merge-base", "--is-ancestor", commit, remote],
                cwd=worktree,
                cancellation_owner=self._subprocess_owner,
            )
            if not ancestry.ok:
                return "persisted push is not reachable from fetched remote ancestry"
        return None

    def _complete_atomic_run_result(
        self,
        task: TaskRecord,
        run: object,
    ) -> ReconciliationOutcome | None:
        run_dir = (
            TaskArchiveWriter(self.config).task_dir(task.id)
            / "pipelines"
            / run.pipeline_id
            / "runs"
            / run.id
        )
        result_path = run_dir / "result.json"
        last_message = run_dir / "last-message.md"
        if not result_path.is_file() or not last_message.is_file():
            return None
        try:
            result_metadata = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if result_metadata.get("status") != "available":
            return None
        try:
            saved = self.store.transition_run(
                run.id,
                "succeeded",
                expected_state="running",
                exit_code=run.exit_code or 0,
                result_summary=str(result_metadata.get("summary") or "completed"),
            )
        except ValueError:
            saved = self.store.get_run(run.id)
            if str(saved.state) != "succeeded":
                return None
        result = self._session_result_from_run(saved)
        try:
            reconciled = self.executor.reconcile_session_result(run.id, result)
        except Exception as exc:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "complete run result conflicts with its durable phase",
                run_id=run.id,
                evidence={"error": exc.__class__.__name__},
            )
        if reconciled is None:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "complete run result did not advance its durable phase",
                run_id=run.id,
            )
        self._add_recovery_event_once(
            task.id,
            "session.result.ingested",
            "complete atomic run result ingested",
            run.id,
            {"run_id": run.id},
        )
        return ReconciliationOutcome(
            task.id,
            ReconciliationDisposition.ingested,
            "complete atomic run result ingested once",
            run_id=run.id,
        )

    @staticmethod
    def _interrupted_recovery_root(runs: list[object]) -> object | None:
        """Select the newest unresolved interruption lineage.

        A successfully recovered root must not be selected again after a
        restart.  The latest interrupted descendant is the continuation point
        when a recovery or retry itself was interrupted.
        """

        by_parent: dict[str, list[object]] = {}
        for run in runs:
            for parent_id in (
                getattr(run, "resume_of_run_id", None),
                getattr(run, "retry_of_run_id", None),
                getattr(run, "parent_run_id", None),
            ):
                if parent_id:
                    by_parent.setdefault(str(parent_id), []).append(run)

        def descendants(root: object) -> list[object]:
            found: list[object] = []
            pending = [root]
            seen = {str(getattr(root, "id", ""))}
            while pending:
                current = pending.pop()
                for child in by_parent.get(str(getattr(current, "id", "")), []):
                    child_id = str(getattr(child, "id", ""))
                    if child_id in seen:
                        continue
                    seen.add(child_id)
                    found.append(child)
                    pending.append(child)
            return found

        def sort_key(run: object) -> str:
            return str(
                getattr(run, "updated_at", None)
                or getattr(run, "started_at", None)
                or getattr(run, "id", "")
            )

        candidates: list[object] = []
        for run in runs:
            if str(getattr(run, "state", "")) != "interrupted":
                continue
            if any(
                getattr(run, field, None) is not None
                for field in (
                    "resume_of_run_id",
                    "retry_of_run_id",
                    "parent_run_id",
                )
            ):
                continue
            lineage = [run, *descendants(run)]
            latest = max(lineage, key=sort_key)
            if str(getattr(latest, "state", "")) == "succeeded":
                continue
            candidates.append(run)
        return max(candidates, key=sort_key) if candidates else None

    def _resume_or_recover(
        self,
        task: TaskRecord,
        predecessor: object,
        runs: list[object],
    ) -> ReconciliationOutcome:
        recovery_ids = {predecessor.id}
        successors: list[object] = []
        for run in runs:
            if (
                run.resume_of_run_id in recovery_ids
                or run.retry_of_run_id in recovery_ids
            ):
                successors.append(run)
                recovery_ids.add(run.id)
        for successor in successors:
            if str(successor.state) == "succeeded":
                return self._ingest_recovered_result(task, predecessor, successor)
            if (
                str(successor.state) == "interrupted"
                and successor.retry_of_run_id is not None
            ):
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "fresh recovery was interrupted; evidence is preserved",
                    run_id=successor.id,
                )
            if str(successor.state) == "running":
                try:
                    inspection = self.session_supervisor.inspect(successor.id)
                except Exception as exc:
                    return ReconciliationOutcome(
                        task.id,
                        ReconciliationDisposition.blocked,
                        "recovery run ownership could not be verified",
                        run_id=successor.id,
                        evidence={"error": exc.__class__.__name__},
                    )
                if inspection.live:
                    self._adopted_runs[task.id] = successor.id
                    return ReconciliationOutcome(
                        task.id,
                        ReconciliationDisposition.adopted,
                        "matching live recovery wrapper adopted",
                        run_id=successor.id,
                    )
                if not _inspection_confirms_stopped(inspection):
                    return ReconciliationOutcome(
                        task.id,
                        ReconciliationDisposition.blocked,
                        "recovery run liveness could not be confirmed stopped",
                        run_id=successor.id,
                        evidence={"error": "liveness_unknown"},
                    )
                try:
                    self.store.mark_run_interrupted(
                        successor.id,
                        reason="recovery wrapper disappeared during daemon restart",
                    )
                except ValueError:
                    pass
                if successor.retry_of_run_id is not None:
                    return ReconciliationOutcome(
                        task.id,
                        ReconciliationDisposition.blocked,
                        "fresh recovery was interrupted; evidence is preserved",
                        run_id=successor.id,
                    )

        try:
            session = self.store.get_session(predecessor.session_id)
        except KeyError:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "interrupted run has no private session ledger",
                run_id=predecessor.id,
            )
        if (
            predecessor.checkpoint_id is not None
            and session.checkpoint_id is not None
            and predecessor.checkpoint_id != session.checkpoint_id
        ):
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "run and session checkpoint identities conflict",
                run_id=predecessor.id,
            )
        unfinished = self._unfinished_phase_action(
            task.id,
            predecessor.pipeline_id,
        )
        if (
            session.idempotency_key is not None
            and unfinished is not None
            and session.idempotency_key != unfinished
        ):
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "session action does not own the interrupted phase",
                run_id=predecessor.id,
            )

        resumable = predecessor.role in {
            "planner",
            "planning",
            "implementation",
            "reviewer",
            "review",
        }
        prompt = self.session_supervisor.build_recovery_packet(
            predecessor.id
        ).prompt()
        resume_result = None
        if resumable and predecessor.checkpoint_id is not None:
            self._add_recovery_event_once(
                task.id,
                "session.recovery.decision",
                "exact session resume selected",
                predecessor.id,
                {"predecessor_run_id": predecessor.id, "decision": "resume"},
            )
            try:
                resume_result = self._await_recovery_operation(
                    task,
                    predecessor,
                    lambda: self.session_supervisor.resume_with_retries(
                        predecessor.id,
                        prompt=prompt,
                        max_attempts=SESSION_RESUME_MAX_ATTEMPTS,
                        cwd=session.cwd,
                        checkpoint_id=predecessor.checkpoint_id,
                    ),
                )
            except Exception as exc:
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "exact session resume could not be launched safely",
                    run_id=predecessor.id,
                    evidence={"error": exc.__class__.__name__},
                )
            if isinstance(resume_result, ReconciliationOutcome):
                return resume_result
            if resume_result.category is ResumeCategory.success:
                assert resume_result.result is not None
                return self._ingest_recovered_result(
                    task,
                    predecessor,
                    self.store.get_run(resume_result.result.run_id),
                    result=resume_result.result,
                )
            if resume_result.category in {
                ResumeCategory.identity_mismatch,
                ResumeCategory.checkpoint_drift,
                ResumeCategory.incompatible_cli,
            }:
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "resume identity validation failed",
                    run_id=predecessor.id,
                    evidence={"category": resume_result.category.value},
                )

        category = (
            resume_result.category.value
            if resume_result is not None
            else "ineligible-or-missing-checkpoint"
        )
        self._add_recovery_event_once(
            task.id,
            "session.recovery.decision",
            "fresh evidence recovery selected",
            predecessor.id,
            {
                "predecessor_run_id": predecessor.id,
                "decision": "fresh-recovery",
                "resume_category": category,
            },
        )
        try:
            recovered = self._await_recovery_operation(
                task,
                predecessor,
                lambda: self.session_supervisor.recover(
                    predecessor.id,
                    cwd=session.cwd,
                ),
            )
        except Exception as exc:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "fresh evidence recovery could not be launched safely",
                run_id=predecessor.id,
                evidence={"error": exc.__class__.__name__, "category": category},
            )
        if isinstance(recovered, ReconciliationOutcome):
            return recovered
        if recovered.category is not ResumeCategory.success or recovered.result is None:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "fresh recovery did not produce a complete result",
                run_id=predecessor.id,
                evidence={"category": recovered.category.value},
            )
        return self._ingest_recovered_result(
            task,
            predecessor,
            self.store.get_run(recovered.result.run_id),
            result=recovered.result,
        )

    def _await_recovery_operation(
        self,
        task: TaskRecord,
        predecessor: object,
        operation: Callable[[], object],
    ) -> object | ReconciliationOutcome:
        """Wait only until recovery completes or exposes durable live ownership."""

        completed = threading.Event()
        state: dict[str, object] = {}

        def invoke() -> None:
            try:
                state["result"] = operation()
            except BaseException as exc:
                state["error"] = exc
            finally:
                completed.set()

        threading.Thread(
            target=invoke,
            name=f"steward-recovery-{task.id}",
            daemon=True,
        ).start()
        while not completed.wait(0.05):
            successor = self._running_recovery_successor(task.id, predecessor.id)
            if self._shutdown_event.is_set():
                run_id = successor.id if successor is not None else predecessor.id
                try:
                    self.session_supervisor.interrupt(
                        run_id,
                        force=self._force_shutdown_event.is_set(),
                        grace_seconds=0.0,
                    )
                except Exception:
                    pass
                completed.wait(timeout=0.25)
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.interrupted,
                    "session recovery interrupted for daemon shutdown",
                    run_id=run_id,
                )
            if successor is not None:
                self._adopted_runs[task.id] = successor.id
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.adopted,
                    "matching live recovery wrapper adopted",
                    run_id=successor.id,
                )
            self._touch_heartbeat()
        error = state.get("error")
        if isinstance(error, BaseException):
            raise error
        return state["result"]

    def _running_recovery_successor(
        self, task_id: str, predecessor_run_id: str
    ) -> object | None:
        lineage = {predecessor_run_id}
        selected = None
        pending = list(self.store.list_runs(task_id))
        changed = True
        while changed:
            changed = False
            for run in pending:
                if run.id in lineage:
                    continue
                if (
                    run.resume_of_run_id in lineage
                    or run.retry_of_run_id in lineage
                    or run.parent_run_id in lineage
                ):
                    lineage.add(run.id)
                    changed = True
                    if str(run.state) == "running":
                        selected = run
        if selected is None:
            return None
        try:
            inspection = self.session_supervisor.inspect(selected.id)
        except Exception:
            return None
        return selected if inspection.live else None

    def _ingest_recovered_result(
        self,
        task: TaskRecord,
        predecessor: object,
        recovered_run: object,
        *,
        result: SessionResult | None = None,
    ) -> ReconciliationOutcome:
        selected = result or self._session_result_from_run(recovered_run)
        try:
            reconciled = self.executor.reconcile_session_result(
                predecessor.id, selected
            )
        except Exception as exc:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "recovered result conflicts with its durable phase",
                run_id=recovered_run.id,
                evidence={"error": exc.__class__.__name__},
            )
        if reconciled is None:
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.blocked,
                "recovered result did not advance its durable phase",
                run_id=recovered_run.id,
            )
        self._add_recovery_event_once(
            task.id,
            "session.recovery.completed",
            "recovered run ingested",
            predecessor.id,
            {
                "predecessor_run_id": predecessor.id,
                "recovered_run_id": recovered_run.id,
                "mode": "resume"
                if recovered_run.resume_of_run_id is not None
                else "fresh-recovery",
            },
        )
        return ReconciliationOutcome(
            task.id,
            ReconciliationDisposition.resumed,
            "interrupted run recovered and ingested",
            run_id=recovered_run.id,
        )

    def _session_result_from_run(self, run: object) -> SessionResult:
        run_dir = (
            TaskArchiveWriter(self.config).task_dir(run.task_id)
            / "pipelines"
            / run.pipeline_id
            / "runs"
            / run.id
        )
        return SessionResult(
            run.task_id,
            run.pipeline_id,
            run.session_id,
            run.id,
            InvocationStatus.succeeded,
            run.exit_code or 0,
            None,
            run_dir / "codex.jsonl",
            run_dir / "last-message.md",
        )

    def _unfinished_phase_action(
        self,
        task_id: str,
        pipeline_id: str,
    ) -> str | None:
        event = self._unfinished_phase_event(task_id, pipeline_id)
        if event is None:
            return None
        action = event.data.get("action_id")
        return str(action) if action else None

    def _add_recovery_event_once(
        self,
        task_id: str,
        kind: str,
        message: str,
        identity: str,
        data: dict[str, object],
    ) -> None:
        if any(
            event.kind == kind
            and (
                event.data.get("predecessor_run_id") == identity
                or event.data.get("run_id") == identity
            )
            and all(event.data.get(key) == value for key, value in data.items())
            for event in self.store.events(task_id)
        ):
            return
        self.store.add_event(task_id, kind, message, data)

    def _terminal_publication_block(
        self,
        task_id: str,
        reason: str,
        *,
        publication_id: str | None = None,
    ) -> bool:
        """Retain one bounded publication-gate failure as local evidence."""

        evidence: dict[str, object] = {
            "publication_gate": True,
            "reason": reason[:64],
        }
        if publication_id is not None:
            evidence["publication_id"] = publication_id
        for event in self.store.events(task_id):
            data = getattr(event, "data", None)
            if not isinstance(data, Mapping):
                continue
            if (
                event.kind == "cleanup_blocked"
                and data.get("publication_gate") is True
                and all(data.get(key) == value for key, value in evidence.items())
            ):
                return False
        self.store.add_event(
            task_id,
            "cleanup_blocked",
            "terminal cleanup requires verified publication",
            evidence,
        )
        return False

    def _terminal_publication_run(self, task_id: str) -> object | None:
        try:
            runs = self.store.list_runs(task_id)
        except (AttributeError, KeyError):
            return None
        completed: list[object] = []
        for run in runs:
            if getattr(run, "completed_at", None) is None:
                continue
            if str(getattr(run, "state", "")) == "running":
                continue
            if not isinstance(getattr(run, "id", None), str):
                continue
            completed.append(run)
        if not completed:
            return None

        def order(run: object) -> tuple[str, str]:
            completed_at = getattr(run, "completed_at", None)
            if isinstance(completed_at, datetime):
                try:
                    timestamp = completed_at.astimezone(timezone.utc).isoformat()
                except (OverflowError, ValueError):
                    timestamp = ""
            else:
                timestamp = str(completed_at)
            return timestamp, str(getattr(run, "id", ""))

        return max(completed, key=order)

    @staticmethod
    def _terminal_publication_lifecycle(task: TaskRecord) -> str:
        try:
            status = TaskStatus(getattr(task, "status", None))
        except (TypeError, ValueError):
            return "failed"
        if not status.terminal:
            return "failed"
        return task_publication_lifecycle(status)

    @staticmethod
    def _terminal_publication_run_alias(task: TaskRecord, run: object) -> str | None:
        run_id = getattr(run, "id", None)
        if not isinstance(run_id, str):
            return None
        completed_at = getattr(task, "updated_at", None)
        if isinstance(completed_at, datetime):
            try:
                completed_text = completed_at.astimezone(timezone.utc).isoformat()
            except (OverflowError, ValueError):
                completed_text = ""
        else:
            completed_text = str(completed_at)
        seed = "\0".join(
            (
                "terminal-publication-v1",
                task.id,
                run_id,
                str(getattr(task, "status", "failed")),
                completed_text,
            )
        )
        return f"terminal-{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"

    def _terminal_snapshot_is_final(
        self,
        task: TaskRecord,
        snapshot: object,
    ) -> bool:
        if not isinstance(snapshot, Mapping):
            return False
        task_value = snapshot.get("task")
        if not isinstance(task_value, Mapping):
            return False
        if (
            task_value.get("taskId") != task.id
            or task_value.get("lifecycleState")
            != self._terminal_publication_lifecycle(task)
        ):
            return False
        completed_at = getattr(task, "updated_at", None)
        if not isinstance(completed_at, datetime):
            return True
        expected_completed = completed_at.astimezone(timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        return task_value.get("completedAt") == expected_completed

    def _terminal_publication_snapshot_run_id(
        self,
        task: TaskRecord,
        run: object,
    ) -> str | None:
        """Select the sealed terminal snapshot without reusing active evidence."""

        run_id = getattr(run, "id", None)
        alias = self._terminal_publication_run_alias(task, run)
        if not isinstance(run_id, str) or alias is None:
            return None
        try:
            terminal_snapshot = load_publication_snapshot(self.config, task.id, alias)
            if terminal_snapshot is not None:
                return alias if self._terminal_snapshot_is_final(task, terminal_snapshot) else None
            original_snapshot = load_publication_snapshot(self.config, task.id, run_id)
        except Exception:
            return None
        if original_snapshot is None or self._terminal_snapshot_is_final(task, original_snapshot):
            return run_id
        # An active snapshot is immutable historical evidence.  The terminal
        # preparation path must have persisted the distinct alias before seal.
        return alias

    def _terminal_publication_graph(
        self,
        task: TaskRecord,
        run: object,
        graph: object,
        terminal_run_id: str,
    ) -> dict[str, object] | None:
        """Detach a terminal graph and alias its latest run when required."""

        if not isinstance(graph, Mapping):
            return None
        task_value = graph.get("task")
        entries = graph.get("runs")
        if not isinstance(task_value, Mapping) or not isinstance(entries, (list, tuple)):
            return None
        original_run_id = getattr(run, "id", None)
        if not isinstance(original_run_id, str):
            return None
        terminal = dict(task_value)
        terminal["lifecycleState"] = self._terminal_publication_lifecycle(task)
        completed_at = getattr(task, "updated_at", None)
        if isinstance(completed_at, datetime):
            terminal["completedAt"] = completed_at.astimezone(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")
        replaced = False
        copied_entries: list[object] = []
        for entry in entries:
            wrapper = entry if isinstance(entry, Mapping) else None
            source = wrapper.get("source") if wrapper is not None else entry
            if not isinstance(source, AtifSource):
                copied_entries.append(dict(entry) if wrapper is not None else entry)
                continue
            run_value = source.run
            if isinstance(run_value, RunMetadata):
                if (
                    type(run_value) is not RunMetadata
                    or type(run_value.identity) is not RunIdentity
                    or type(run_value.lineage) is not RunLineage
                    or (run_value.usage is not None and type(run_value.usage) is not UsageSummary)
                ):
                    return None
                run_mapping = dict(RunMetadata.as_dict(run_value))
            elif isinstance(run_value, Mapping):
                run_mapping = dict(run_value)
            else:
                copied_entries.append(dict(wrapper) if wrapper is not None else entry)
                continue
            if run_mapping.get("runId") != original_run_id:
                copied_entries.append(dict(entry) if wrapper is not None else entry)
                continue
            run_mapping["runId"] = terminal_run_id
            documents = dict(source.documents) if isinstance(source.documents, Mapping) else {}
            run_document = documents.get("run.json")
            if isinstance(run_document, bytes):
                try:
                    decoded = json.loads(run_document.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return None
                if isinstance(decoded, Mapping) and decoded.get("runId") == original_run_id:
                    decoded = dict(decoded)
                    decoded["runId"] = terminal_run_id
                    documents["run.json"] = (
                        json.dumps(decoded, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                        + "\n"
                    ).encode("utf-8")
            copied_source = AtifSource(
                run=run_mapping,
                documents=documents,
                artifacts=source.artifacts,
            )
            if wrapper is None:
                copied_entries.append(copied_source)
            else:
                copied = dict(wrapper)
                copied["source"] = copied_source
                copied_entries.append(copied)
            replaced = True
        if not replaced:
            return None
        return {**dict(graph), "task": terminal, "runs": copied_entries}

    def _prepare_terminal_publication_snapshot(
        self,
        task: TaskRecord,
        run: object,
    ) -> bool:
        """Freeze a final source graph before the task archive is sealed."""

        run_id = getattr(run, "id", None)
        terminal_run_id = self._terminal_publication_run_alias(task, run)
        if not isinstance(run_id, str) or terminal_run_id is None:
            return False
        try:
            existing = load_publication_snapshot(self.config, task.id, run_id)
            if existing is not None and self._terminal_snapshot_is_final(task, existing):
                return True
            graph = self.executor._integration_publication_graph(task)
            snapshot_run_id = run_id
            if existing is not None or not self._terminal_snapshot_is_final(task, graph):
                snapshot_run_id = terminal_run_id
            if snapshot_run_id != run_id:
                graph = self._terminal_publication_graph(
                    task,
                    run,
                    graph,
                    snapshot_run_id,
                )
                if graph is None:
                    return False
            return _write_publication_snapshot(
                self.config,
                task.id,
                snapshot_run_id,
                graph,
            )
        except Exception as exc:
            self._log(
                "terminal publication snapshot unavailable "
                f"error={exc.__class__.__name__}"
            )
            return False

    def _terminal_publication_receipts_verified(
        self,
        task: TaskRecord,
        generation: PublicationGeneration,
    ) -> tuple[bool, str]:
        """Authenticate durable receipts against the immutable source graph."""

        if not isinstance(generation, PublicationGeneration):
            return False, "invalid_generation"
        publication_id = generation.publication_id
        try:
            receipts = list(self.store.list_publication_receipts(publication_id))
        except Exception:
            return False, "receipts_unavailable"

        source = self._publication_source(generation)
        if source is None:
            return False, "source_unavailable"
        try:
            composed = compose_publication_generation(
                source,
                task_id=task.id,
                **_publication_compose_kwargs(
                    getattr(getattr(self, "config", None), "publication", None)
                ),
            )
        except Exception:
            return False, "composition_failed"
        if not isinstance(composed, ComposedPublicationGeneration):
            return False, "composition_incomplete"
        payload = composed.payload
        task_value = payload.get("task") if isinstance(payload, Mapping) else None
        if (
            not isinstance(task_value, Mapping)
            or task_value.get("taskId") != task.id
            or task_value.get("lifecycleState")
            != self._terminal_publication_lifecycle(task)
        ):
            return False, "terminal_lifecycle_mismatch"
        head_intent = payload.get("headIntent") if isinstance(payload, Mapping) else None
        if (
            not isinstance(head_intent, Mapping)
            or head_intent.get("publicationId") != composed.publication_id
            or head_intent.get("taskId") != task.id
            or head_intent.get("state") != "visible"
        ):
            return False, "head_mismatch"

        if (
            generation.publication_id != composed.publication_id
            or generation.task_id != composed.task_id
            or generation.run_id != composed.run_id
            or generation.generation_boundary != composed.generation_boundary
            or generation.metadata_digest != composed.metadata_digest
            or generation.idempotency_key != composed.idempotency_key
        ):
            return False, "generation_mismatch"

        expected: dict[tuple[str, str], tuple[str, int, str | None]] = {}
        try:
            for item in composed.objects:
                expected[(ReceiptClass.public.value, item.public_key)] = (
                    item.sha256,
                    item.byte_size,
                    item.logical_path,
                )
            for item in composed.private_originals:
                key = private_original_key(item.task_id, item.run_id, item.sha256)
                expected[(ReceiptClass.private.value, key)] = (
                    item.sha256,
                    item.byte_size,
                    None,
                )
        except Exception:
            return False, "composition_incomplete"

        if (
            generation.objects != len(expected)
            or generation.artifacts != len(composed.objects)
        ):
            return False, "receipt_count_mismatch"

        actual: dict[tuple[str, str], tuple[str, int, str | None]] = {}
        try:
            for receipt in receipts:
                if not isinstance(receipt, PublicationReceipt):
                    return False, "receipt_invalid"
                receipt_class = receipt.receipt_class
                if receipt_class not in {ReceiptClass.public, ReceiptClass.private}:
                    return False, "receipt_invalid"
                identity = (receipt_class.value, receipt.content_key)
                if identity in actual:
                    return False, "receipt_duplicate"
                actual[identity] = (
                    receipt.sha256,
                    receipt.byte_size,
                    receipt.logical_path,
                )
        except Exception:
            return False, "receipt_invalid"
        if actual != expected:
            return False, "receipt_mismatch"
        return True, "verified"

    def _terminal_publication_gate(self, task: TaskRecord) -> bool:
        """Require the final durable generation and all verified receipts."""

        if self.config.dry_run or _task_is_dry_run(task):
            # Dry-run publication is explicitly not applicable.  No outbox row,
            # receipt wait, transport client, or cleanup intent is created.
            return True
        if not getattr(getattr(self.config, "publication", None), "enabled", False):
            return True
        run = self._terminal_publication_run(task.id)
        if run is None:
            return self._terminal_publication_block(task.id, "final_run_missing")
        run_id = getattr(run, "id", None)
        if not isinstance(run_id, str):
            return self._terminal_publication_block(task.id, "final_run_invalid")
        snapshot_run_id = self._terminal_publication_snapshot_run_id(task, run)
        if snapshot_run_id is None:
            return self._terminal_publication_block(task.id, "terminal_snapshot_invalid")
        enqueue_run = run
        if snapshot_run_id != run_id:
            enqueue_run = SimpleNamespace(
                id=snapshot_run_id,
                state=getattr(run, "state", None),
                completed_at=getattr(run, "completed_at", None),
            )
        try:
            queued = enqueue_materialized_publication(
                self.config,
                self.store,
                task,
                enqueue_run,
            )
        except Exception as exc:
            self._log(
                "terminal publication enqueue failed "
                f"error={exc.__class__.__name__}"
            )
            queued = None
        candidate = (
            queued.generation
            if isinstance(queued, PublicationOperationResult)
            else None
        )
        if candidate is None:
            try:
                matches = [
                    item
                    for item in self.store.list_publication_generations(
                        task_id=task.id,
                        limit=None,
                    )
                    if item.run_id == snapshot_run_id
                ]
            except Exception:
                matches = []
            if len(matches) == 1:
                candidate = matches[0]
        if not isinstance(candidate, PublicationGeneration):
            return self._terminal_publication_block(task.id, "final_generation_missing")
        publication_id = candidate.publication_id
        if candidate.task_id != task.id or candidate.run_id != snapshot_run_id:
            return self._terminal_publication_block(
                task.id,
                "final_generation_mismatch",
                publication_id=publication_id,
            )

        try:
            generation = self.store.get_publication_generation(publication_id)
        except Exception:
            generation = None
        if not isinstance(generation, PublicationGeneration):
            return self._terminal_publication_block(
                task.id,
                "final_generation_missing",
                publication_id=publication_id,
            )
        if (
            generation.task_id != task.id
            or generation.run_id != snapshot_run_id
            or generation.publication_id != publication_id
        ):
            return self._terminal_publication_block(
                task.id,
                "final_generation_mismatch",
                publication_id=publication_id,
            )
        if generation.state is not PublicationState.exposed:
            return self._terminal_publication_block(
                task.id,
                f"final_generation_{generation.state.value}",
                publication_id=publication_id,
            )
        if generation.exposed_at is None:
            return self._terminal_publication_block(
                task.id,
                "exposure_timestamp_missing",
                publication_id=publication_id,
            )
        verified, reason = self._terminal_publication_receipts_verified(task, generation)
        if not verified:
            return self._terminal_publication_block(
                task.id,
                reason,
                publication_id=publication_id,
            )
        return True

    def _terminal_publication_generation_for_cleanup(
        self, task: TaskRecord
    ) -> PublicationGeneration | None:
        """Return the exact exposed generation authenticated by the gate."""

        run = self._terminal_publication_run(task.id)
        if run is None:
            return None
        snapshot_run_id = self._terminal_publication_snapshot_run_id(task, run)
        if snapshot_run_id is None:
            return None
        try:
            matches = [
                item
                for item in self.store.list_publication_generations(
                    task_id=task.id,
                    limit=None,
                )
                if item.task_id == task.id
                and item.run_id == snapshot_run_id
                and item.state is PublicationState.exposed
            ]
        except Exception:
            return None
        if len(matches) != 1:
            return None
        candidate: PublicationGeneration = matches[0]
        try:
            generation = self.store.get_publication_generation(
                candidate.publication_id
            )
        except Exception:
            return None
        if (
            not isinstance(generation, PublicationGeneration)
            or generation.task_id != task.id
            or generation.run_id != snapshot_run_id
            or generation.publication_id != candidate.publication_id
            or generation.state is not PublicationState.exposed
        ):
            return None
        return generation

    def _cleanup_intents_for_task(self, task_id: str) -> list[CleanupIntent]:
        try:
            values = list(self.store.list_cleanup_intents(task_id=task_id))
        except Exception:
            return []
        return [item for item in values if item.task_id == task_id]

    def _cleanup_intent_for_task(self, task_id: str) -> CleanupIntent | None:
        intents = self._cleanup_intents_for_task(task_id)
        if not intents:
            return None
        # A completed intent is authoritative after a crash between the
        # durable completion and the task event.  Otherwise resume the oldest
        # pending intent deterministically.
        completed = [
            item for item in intents if item.state is CleanupState.completed
        ]
        if completed:
            return max(completed, key=lambda item: str(item.completed_at))
        return min(intents, key=lambda item: str(item.requested_at))

    def _create_terminal_cleanup_intent(
        self,
        task: TaskRecord,
        generation: PublicationGeneration,
        archive: TaskArchiveWriter,
        manifest_digest: str,
    ) -> CleanupIntent | None:
        if not isinstance(generation, PublicationGeneration):
            self._terminal_publication_block(task.id, "cleanup_generation_invalid")
            return None
        requested_at = utc_now()
        if generation.updated_at > requested_at:
            requested_at = generation.updated_at
        try:
            intent = CleanupIntent(
                task_id=task.id,
                publication_id=generation.publication_id,
                manifest_digest=manifest_digest,
                exact_path=str(archive.task_dir(task.id)),
                requested_at=requested_at,
            )
            result = self.store.create_cleanup_intent(intent)
        except Exception as exc:
            self._log(
                "terminal cleanup intent unavailable "
                f"error={exc.__class__.__name__}"
            )
            self._terminal_publication_block(task.id, "cleanup_intent_invalid")
            return None
        if not isinstance(result, PublicationOperationResult):
            self._terminal_publication_block(task.id, "cleanup_intent_invalid")
            return None
        if result.status not in {
            PublicationOperationStatus.enqueued,
            PublicationOperationStatus.existing,
        }:
            self._terminal_publication_block(task.id, "cleanup_intent_rejected")
            return None
        cleanup = result.cleanup
        if cleanup is not None and not isinstance(cleanup, CleanupIntent):
            self._terminal_publication_block(task.id, "cleanup_intent_invalid")
            return None
        return cleanup if cleanup is not None else intent

    def _delete_terminal_archive(
        self,
        task: TaskRecord,
        archive: TaskArchiveWriter,
        intent: CleanupIntent,
    ) -> bool:
        """Verify, remove, and durably complete one exact cleanup intent."""

        intent_id = intent.intent_id
        manifest_digest = intent.manifest_digest
        verified = intent.verified_at is not None
        deletion_observed = False
        if intent.state is CleanupState.blocked:
            return False
        try:
            if not verified:
                current_digest = archive.manifest_digest(task.id)
                if current_digest != manifest_digest:
                    raise ArchiveConflictError("terminal manifest digest changed")
                result = self.store.verify_cleanup_intent(
                    intent_id,
                    manifest_digest=manifest_digest,
                )
                if not isinstance(result, PublicationOperationResult):
                    return False
                if result.status not in {
                    PublicationOperationStatus.verified,
                    PublicationOperationStatus.existing,
                }:
                    return False
                verified_intent = result.cleanup
                if verified_intent is not None:
                    if not isinstance(verified_intent, CleanupIntent):
                        return False
                    intent = verified_intent
                verified = intent.verified_at is not None or result.status in {
                    PublicationOperationStatus.verified,
                    PublicationOperationStatus.existing,
                }

            # A verified intent may survive a crash while its exact archive is
            # still present.  Authenticate that replacement-sensitive path
            # before invoking the destructive primitive; absent archives remain
            # a valid post-intent recovery state.
            if verified:
                try:
                    archive.task_dir(task.id).lstat()
                except FileNotFoundError:
                    pass
                else:
                    current_digest = archive.manifest_digest(task.id)
                    if current_digest != manifest_digest:
                        raise ArchiveConflictError(
                            "terminal manifest digest changed after verification"
                        )

            # The deletion primitive performs a second manifest verification
            # immediately before removing the exact direct child.
            outcome = archive.delete_verified(
                task.id,
                allow_absent=verified,
                return_digest=True,
                expected_digest=manifest_digest,
            )
            deletion_observed = True
            if outcome not in {"absent", manifest_digest}:
                raise ArchiveConflictError("terminal manifest digest changed during deletion")
            completed = self.store.complete_cleanup_intent(
                intent_id,
                manifest_digest=manifest_digest,
            )
            if not isinstance(completed, PublicationOperationResult):
                return False
            if completed.status not in {
                PublicationOperationStatus.completed,
                PublicationOperationStatus.existing,
            }:
                return False
            return True
        except Exception as exc:
            self._log(
                "terminal archive deletion blocked "
                f"error={exc.__class__.__name__}"
            )
            if not deletion_observed:
                try:
                    archive.task_dir(task.id).lstat()
                except FileNotFoundError:
                    deletion_observed = True
            if not deletion_observed:
                try:
                    self.store.block_cleanup_intent(
                        intent_id,
                        reason="cleanup_failed",
                    )
                except Exception:
                    pass
            return False

    def _durable_publication_exposure(
        self, task: TaskRecord
    ) -> tuple[bool, PublicationGeneration | None]:
        """Return Store-owned exposure state without starting work."""

        try:
            generations = list(
                self.store.list_publication_generations(
                    task_id=task.id,
                    limit=None,
                )
            )
        except Exception:
            return False, None
        candidates = [
            generation
            for generation in generations
            if isinstance(generation, PublicationGeneration)
            and generation.task_id == task.id
            and generation.state
            in {PublicationState.exposed, PublicationState.terminal_cleaned}
            and generation.exposed_at is not None
        ]
        if not candidates:
            return True, None
        generation = max(
            candidates,
            key=lambda item: (
                str(item.exposed_at),
                str(item.updated_at),
                item.publication_id,
            ),
        )
        try:
            self.store.list_publication_receipts(generation.publication_id)
        except Exception:
            return False, None
        return True, generation

    def _record_terminal_publication_effect(
        self,
        task: TaskRecord,
        generation: PublicationGeneration,
    ) -> bool:
        """Represent the verified terminal exposure in the task ledger."""

        publication_id = getattr(generation, "publication_id", None)
        if not isinstance(publication_id, str) or not publication_id:
            return False
        try:
            self.store.record_publication_exposure_reconciled(
                task.id,
                publication_id=publication_id,
            )
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal cleanup requires durable publication effect evidence",
                {"reason": "publication_effect_invalid", "error": exc.__class__.__name__},
            )
            return False
        return True

    def _reconcile_durable_publication_exposure(self, task: TaskRecord) -> bool:
        """Recover local applied evidence before dry-run terminal handling."""

        try:
            if self.store.task_execution_mode(task.id) is not ExecutionMode.dry_run:
                return True
        except (AttributeError, KeyError, ValueError):
            return True
        readable, generation = self._durable_publication_exposure(task)
        if not readable:
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal cleanup requires readable publication exposure evidence",
                {"reason": "publication_exposure_unavailable"},
            )
            return False
        if generation is None:
            return True
        # This path is deliberately Store-only.  In particular it does not
        # enqueue, claim, retry, hide, expose, or otherwise contact a cloud
        # provider when startup has tightened the task to dry-run.
        return self._record_terminal_publication_effect(task, generation)

    def finalize_terminal_task(self, task_id: str) -> bool:
        """Seal immutable evidence, then converge terminal-only cleanup."""

        task = self.store.get(task_id)
        if not TaskStatus(task.status).terminal:
            return False
        try:
            execution = self.store.get_execution(task.id)
            pipeline_id = execution.owning_pipeline_id
            if pipeline_id is None:
                raise TaskLedgerOwnershipError(
                    "task execution has no owning pipeline"
                )
            owner_pipeline = self.store.get_pipeline(pipeline_id)
            if (
                owner_pipeline.task_id != task.id
                or owner_pipeline.execution_id != execution.id
            ):
                raise TaskLedgerOwnershipError("task execution owner is invalid")
        except (KeyError, TaskLedgerOwnershipError):
            return False
        events = self.store.events(task.id)
        try:
            mode = self.store.task_execution_mode(task.id)
        except (AttributeError, KeyError, ValueError):
            mode = None
        cleanup_state = self.store.cleanup_obligation_state(task.id)
        existing_intent = self._cleanup_intent_for_task(task.id)
        existing_state = existing_intent.state if existing_intent is not None else None
        if not self._reconcile_durable_publication_exposure(task):
            return False
        if cleanup_state is CleanupStatus.complete or existing_state is CleanupState.completed:
            try:
                self.store.finalize_effect_result(task.id)
            except (AttributeError, KeyError, TypeError, ValueError) as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_blocked",
                    "terminal cleanup requires valid external effect evidence",
                    {"reason": "effect_evidence_invalid", "error": exc.__class__.__name__},
                )
                return False
            if cleanup_state is not CleanupStatus.complete:
                self.store.add_event(
                    task.id,
                    "cleanup_complete",
                    "terminal archive deletion completed",
                )
            return True
        if existing_state is CleanupState.blocked:
            return False
        publication_enabled = bool(
            getattr(getattr(self.config, "publication", None), "enabled", False)
        ) and mode is ExecutionMode.live
        publication_generation: PublicationGeneration | None = None
        pipelines = self.store.list_pipelines(task.id)
        for pipeline in pipelines:
            active = self._unfinished_phase_event(task.id, pipeline.id)
            if active is not None:
                self.store.add_event(
                    task.id,
                    "cleanup_blocked",
                    "terminal cleanup requires all phase claims to resolve",
                    {
                        "pipeline_id": pipeline.id,
                        "phase": active.data.get("phase"),
                    },
                )
                return False
        explicit_terminal = any(
            event.kind in {"pipeline.ready_to_seal", "pipeline.blocked"}
            for event in events
        )
        if not explicit_terminal:
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal cleanup requires an explicit pipeline outcome",
            )
            return False
        if any(str(run.state) == "running" for run in self.store.list_runs(task.id)):
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal cleanup requires all runs to stop",
            )
            return False
        if publication_enabled:
            final_run = self._terminal_publication_run(task.id)
            if final_run is None:
                return self._terminal_publication_block(task.id, "final_run_missing")
            if not self._prepare_terminal_publication_snapshot(task, final_run):
                return self._terminal_publication_block(
                    task.id, "terminal_snapshot_invalid"
                )
            if not self._terminal_publication_gate(task):
                return False
            publication_generation = self._terminal_publication_generation_for_cleanup(task)
            if publication_generation is None:
                return self._terminal_publication_block(
                    task.id, "final_generation_unavailable"
                )

        if self.session_supervisor is not None:
            try:
                self.session_supervisor.stop_container(task.id, timeout=1)
            except Exception as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_retryable",
                    "terminal container stop incomplete",
                    {"step": "container-stop", "error": exc.__class__.__name__},
                )
                return False
        if publication_generation is not None and not self._record_terminal_publication_effect(
            task, publication_generation
        ):
            return False
        archive = TaskArchiveWriter(self.config)
        manifest = archive.task_dir(task.id) / "manifest.json"
        archive_absent_after_intent = False
        archive_missing_with_intent = False
        if existing_intent is not None and existing_state is CleanupState.pending:
            try:
                archive.task_dir(task.id).lstat()
            except FileNotFoundError:
                archive_missing_with_intent = True
                archive_absent_after_intent = existing_intent.verified_at is not None
        if archive_missing_with_intent and not archive_absent_after_intent:
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal archive is absent before deletion verification",
            )
            return False
        if not archive_absent_after_intent:
            try:
                if not manifest.exists():
                    completion_identity = f"completion-{task.id}-{pipeline_id}"
                    archive.create_task_from_record(
                        task,
                        pipeline=owner_pipeline,
                    )
                    for pipeline in pipelines:
                        runs = self.store.list_runs(
                            task.id,
                            pipeline_id=pipeline.id,
                        )
                        for run in runs:
                            archive.materialize_run(task.id, pipeline.id, run)
                        archive_pipeline = pipeline
                        if str(getattr(pipeline, "state", "")) in {"active", "interrupted"}:
                            terminal_pipeline_state = {
                                TaskStatus.succeeded.value: "succeeded",
                                TaskStatus.pushed.value: "succeeded",
                                TaskStatus.no_changes.value: "succeeded",
                                TaskStatus.blocked.value: "blocked",
                                TaskStatus.failed.value: "failed",
                                TaskStatus.cancelled.value: "cancelled",
                            }.get(str(task.status), "failed")
                            archive_pipeline = pipeline.model_copy(
                                update={
                                    "state": terminal_pipeline_state,
                                    "phase": "complete",
                                    "completed_at": task.updated_at,
                                },
                                deep=True,
                            )
                        archive.materialize_pipeline(
                            task.id,
                            archive_pipeline,
                            runs=runs,
                        )
                    effect_result = self.store.effect_result(task.id)
                    if effect_result is None:
                        effect_result = self.store.derive_effect_result(task.id)
                    effect_evidence = self.store.effect_evidence(task.id)
                    archive.materialize_effects(
                        task.id,
                        effect_evidence,
                        result=effect_result,
                        mode=(mode.value if mode is not None else "dry-run"),
                    )
                    archive.seal(
                        task.id,
                        str(task.status),
                        completion_identity=completion_identity,
                        completed_at=task.updated_at.astimezone(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        external_actions_complete=True,
                        writer_final=True,
                    )
                archive.verify_or_raise(task.id)
            except Exception as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_blocked",
                    "terminal archive is not ready to seal",
                    {"error": exc.__class__.__name__},
                )
                return False
        if cleanup_state is None:
            self.store.add_event(task.id, "cleanup_pending", "terminal manifest verified")
            cleanup_state = CleanupStatus.pending
        events = self.store.events(task.id)

        cleanup_intent = existing_intent
        cleanup_generation = publication_generation
        if publication_enabled:
            if not self._terminal_publication_gate(task):
                return False
            cleanup_generation = self._terminal_publication_generation_for_cleanup(task)
            if cleanup_generation is None:
                return self._terminal_publication_block(
                    task.id, "final_generation_unavailable"
                )
            if archive_absent_after_intent:
                manifest_digest = (
                    cleanup_intent.manifest_digest
                    if cleanup_intent is not None
                    else None
                )
            else:
                try:
                    manifest_digest = archive.manifest_digest(task.id)
                except Exception as exc:
                    self.store.add_event(
                        task.id,
                        "cleanup_blocked",
                        "terminal manifest could not be authenticated for deletion",
                        {"error": exc.__class__.__name__},
                    )
                    return False
            if not isinstance(manifest_digest, str):
                self._terminal_publication_block(task.id, "cleanup_manifest_missing")
                return False
            if cleanup_intent is not None:
                if (
                    cleanup_intent.publication_id != cleanup_generation.publication_id
                    or cleanup_intent.manifest_digest != manifest_digest
                    or cleanup_intent.exact_path != str(archive.task_dir(task.id))
                ):
                    self._terminal_publication_block(task.id, "cleanup_intent_mismatch")
                    return False
            else:
                cleanup_intent = self._create_terminal_cleanup_intent(
                    task,
                    cleanup_generation,
                    archive,
                    manifest_digest,
                )
                if cleanup_intent is None:
                    return False

        try:
            # The result is orthogonal to lifecycle status and is finalized
            # only after the archive and any durable publication cleanup intent
            # are ready alongside every other terminal prerequisite.  A
            # malformed or contradictory action ledger is never summarized.
            self.store.finalize_effect_result(task.id)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal cleanup requires valid external effect evidence",
                {"reason": "effect_evidence_invalid", "error": exc.__class__.__name__},
            )
            return False

        if not any(event.kind == "cleanup.container_removed" for event in events):
            try:
                if self.session_supervisor is not None:
                    self.session_supervisor.remove_container(task.id)
                self.store.add_event(
                    task.id,
                    "cleanup.container_removed",
                    "owned terminal container removed",
                )
            except Exception as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_retryable",
                    "terminal container removal incomplete",
                    {"step": "container-remove", "error": exc.__class__.__name__},
                )
                return False
        events = self.store.events(task.id)
        if not any(event.kind == "cleanup.worktree_removed" for event in events):
            try:
                if task.worktree_path is not None and task.worktree_path.exists():
                    self.executor.clean_finished_task_worktree(task)
                self.store.add_event(
                    task.id,
                    "cleanup.worktree_removed",
                    "disposable terminal worktree removed",
                )
            except Exception as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_retryable",
                    "terminal worktree removal incomplete",
                    {"step": "worktree-remove", "error": exc.__class__.__name__},
                )
                return False
        events = self.store.events(task.id)
        if not any(event.kind == "cleanup.session_homes_removed" for event in events):
            private_home = self.config.private_sessions_dir / task.id
            try:
                if private_home.exists():
                    resolved = private_home.resolve()
                    root = self.config.private_sessions_dir.resolve()
                    if root not in resolved.parents:
                        raise RuntimeError("private home escaped session root")
                    import shutil

                    shutil.rmtree(resolved)
                self.store.add_event(
                    task.id,
                    "cleanup.session_homes_removed",
                    "eligible private session homes removed",
                )
            except Exception as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_retryable",
                    "terminal session-home removal incomplete",
                    {"step": "session-home-remove", "error": exc.__class__.__name__},
                )
                return False
        if cleanup_generation is not None:
            if cleanup_intent is None or not self._delete_terminal_archive(
                task, archive, cleanup_intent
            ):
                return False
        else:
            try:
                archive.verify_or_raise(task.id)
            except Exception as exc:
                self.store.add_event(
                    task.id,
                    "cleanup_blocked",
                    "terminal archive changed during cleanup",
                    {"error": exc.__class__.__name__},
                )
                return False
        if cleanup_state is not CleanupStatus.complete:
            self.store.add_event(
                task.id,
                "cleanup_complete",
                "terminal archive deletion completed"
                if cleanup_generation is not None
                else "terminal private state removed",
            )
        return True

    seal_terminal_task = finalize_terminal_task

    def request_shutdown_from_signal(self, *, force: bool = False) -> None:
        """Set signal-safe shutdown intent without locks or persistent writes."""

        self.request_shutdown(force=force)

    def request_shutdown(self, *, force: bool = False) -> None:
        """Set shutdown intent without locks or persistent writes."""

        self._shutdown_event.set()
        if force:
            self._force_shutdown_event.set()
        if self.planner_session is not None and self._active_planner_run_id is not None:
            try:
                self.planner_session.interrupt(force=force)
            except Exception:
                pass

    def _enter_stopping(
        self, *, force: bool, deadline: float | None = None
    ) -> DaemonPublicationRevocationResult | None:
        """Persist stopping state after the cancellation fence is armed."""

        # Shutdown invalidates the local handle before worker cancellation; keep
        # this idempotent for callers that enter the lifecycle boundary directly.
        self._publication_authority = None
        revocation: DaemonPublicationRevocationResult | None = None
        with self._runtime_lock:
            self.runtime.lifecycle = DaemonLifecycleState.stopping
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.stopping_requested_at = utc_now()
            self.runtime.forced_stop = force
            self.runtime.heartbeat_at = utc_now()
        try:
            if deadline is None:
                self.store.set_daemon_lifecycle(
                    DaemonLifecycleState.stopping.value,
                    instance_id=self.runtime.instance_id,
                    state={
                        "forced": force,
                        "publication_worker_stopped": False,
                    },
                )
            else:
                result = self.store.revoke_daemon_publication_authority(
                    self.runtime.instance_id,
                    DaemonLifecycleState.stopping.value,
                    deadline=deadline,
                    state={
                        "forced": force,
                        "publication_worker_stopped": False,
                    },
                )
                revocation = result
                if getattr(result, "ownership_lost", False):
                    # Preserve the historical local stopping record when this
                    # daemon never claimed a row.  A present row is never
                    # rewritten after ownership loss, so a successor remains
                    # protected.
                    if self.store.get_daemon_state() is None:
                        try:
                            self.store.set_daemon_lifecycle(
                                DaemonLifecycleState.stopping.value,
                                instance_id=self.runtime.instance_id,
                                state={
                                    "forced": force,
                                    "publication_worker_stopped": False,
                                },
                            )
                        except ValueError as exc:
                            if str(exc) != "daemon instance is not the current owner":
                                raise
                    else:
                        self._log("daemon ownership lost before stopping lifecycle transition")
                elif getattr(result, "deadline_exhausted", False):
                    self._log("daemon stopping lifecycle transition exceeded shutdown deadline")
        except ValueError as exc:
            if str(exc) != "daemon instance is not the current owner":
                raise
            self._log("daemon ownership lost before stopping lifecycle transition")
        # During deadline-bound shutdown the daemon-state row is authoritative.
        # Runtime events are secondary and recoverable from the durable ledger;
        # do not start the fixed-timeout ledger transaction after revocation.
        if deadline is not None:
            return revocation
        try:
            self._control_loop_ledger.record_runtime(
                "stopping",
                {"instanceId": self.runtime.instance_id, "forced": force},
            )
            self._control_loop_wakeup.set()
        except Exception as exc:
            self._log(f"control-loop runtime stop lag error={exc.__class__.__name__}")
        return revocation
    stop = request_shutdown

    def shutdown(self, *, force: bool = False) -> ShutdownResult:
        """Stop workers and owned containers while retaining restart state."""

        self.request_shutdown(force=force)
        force = force or self._force_shutdown_event.is_set()
        shutdown_budget = (
            PUBLICATION_JOIN_TIMEOUT_SECONDS
            if force
            else float(self.config.shutdown_grace_seconds)
        )
        deadline = time.monotonic() + shutdown_budget
        # Cancel provider I/O before the lifecycle transition waits on the same
        # Store admission boundary held by an in-flight aggregate operation.
        self._publication_authority = None
        cancellation = self._request_publication_worker_stop(deadline=deadline)
        # Durable authority may be revoked only after every admitted D1
        # handoff operation has quiesced.  A timeout leaves the durable claim
        # untouched while the worker completes its own cleanup asynchronously.
        quiescence_proven = (
            cancellation is None
            or getattr(cancellation, "quiescent", False)
        )
        initial_revocation: DaemonPublicationRevocationResult | None = None
        if quiescence_proven:
            try:
                initial_revocation = self._enter_stopping(
                    force=force, deadline=deadline
                )
            finally:
                publication_worker_stopped = self._join_publication_worker(
                    deadline=deadline
                )
        else:
            publication_worker_stopped = self._join_publication_worker(
                deadline=deadline
            )
        control_loop_writer_stopped = self._stop_control_loop_writer(deadline=deadline)
        # A completed writer owns its final drain.  A live writer may still be
        # inside unbounded archive or ledger work, so leave its durable outbox
        # work for that writer or the next startup/ordinary drain.
        running_runs = [
            (run.task_id, run.id)
            for run in list(self.store.running_runs())
        ]
        tasks = sorted(list(self.store.iter_tasks()), key=lambda item: item.id)
        interrupted_runs = len(running_runs)
        if self.planner_session is not None and self._active_planner_run_id is not None:
            try:
                self.planner_session.interrupt(force=force)
            except Exception as exc:
                self._log(f"planner interrupt lag error={exc.__class__.__name__}")
        self._subprocess_owner.request_cancel(force=force)
        interrupt_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(len(running_runs), self.config.limits.max_active_tasks))
        ) if running_runs else None
        interrupt_futures: dict[str, concurrent.futures.Future[object]] = {}
        if interrupt_pool is not None:
            for _task_id, run_id in running_runs:
                interrupt_futures[run_id] = interrupt_pool.submit(
                    self._interrupt_run,
                    run_id,
                    force=force,
                    grace_seconds=max(0.0, deadline - time.monotonic()),
                )
        while interrupt_futures and not force:
            pending = [future for future in interrupt_futures.values() if not future.done()]
            if not pending:
                break
            if self._force_shutdown_event.is_set() or time.monotonic() >= deadline:
                force = True
                self._force_shutdown_event.set()
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if force and interrupt_futures:
            self._subprocess_owner.force_cancel()
            force_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, len(interrupt_futures))
            )
            forced_futures = [
                force_pool.submit(self._interrupt_run, run_id, force=True, grace_seconds=0.0)
                for run_id, future in interrupt_futures.items()
                if not future.done()
            ]
            if forced_futures:
                concurrent.futures.wait(
                    forced_futures,
                    timeout=max(0.0, deadline - time.monotonic()),
                )
            force_pool.shutdown(wait=False, cancel_futures=True)
        if interrupt_pool is not None:
            interrupt_pool.shutdown(wait=False, cancel_futures=True)
        # Stop containers after every phase owner has received cancellation;
        # this preserves stopped restart inputs while preventing credentials
        # from remaining live after ordinary daemon exit.
        stopped_container_count = 0
        container_stop_failures: list[str] = []
        stop_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(len(tasks), self.config.limits.max_active_tasks))
        ) if tasks and self.session_supervisor is not None else None
        if stop_pool is not None:
            stop_futures = {
                stop_pool.submit(self._stop_task_container, task.id): task.id
                for task in tasks
            }
            stopped, pending = concurrent.futures.wait(
                stop_futures,
                timeout=max(0.0, deadline - time.monotonic()),
            )
            for future in stopped:
                task_id = stop_futures[future]
                try:
                    if future.result():
                        stopped_container_count += 1
                except Exception:
                    container_stop_failures.append(task_id)
            for future in pending:
                container_stop_failures.append(stop_futures[future])
                future.cancel()
            stop_pool.shutdown(wait=False, cancel_futures=True)
        if self.planner_session is not None:
            runtime = getattr(self.planner_session.invoker, "runtime", None)
            if runtime is not None:
                try:
                    runtime.stop(
                        timeout=max(0.0, deadline - time.monotonic())
                    )
                except Exception as exc:
                    container_stop_failures.append("scheduler-planner")
                    self._log(
                        f"planner container stop failed error={exc.__class__.__name__}"
                    )
        with self._worker_pool_lock:
            pool = self._worker_pool
            self._worker_pool = None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
            while not force:
                with self._worker_pool_lock:
                    pending = [
                        future
                        for future in self._active_futures.values()
                        if not future.done()
                    ]
                if not pending:
                    break
                if self._force_shutdown_event.is_set():
                    force = True
                    self._subprocess_owner.force_cancel()
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    force = True
                    self._force_shutdown_event.set()
                    self._subprocess_owner.force_cancel()
                    break
                self._force_shutdown_event.wait(min(0.05, remaining))
            if force:
                with self._worker_pool_lock:
                    pending_after_force = [
                        future
                        for future in self._active_futures.values()
                        if not future.done()
                    ]
                if pending_after_force:
                    concurrent.futures.wait(
                        pending_after_force,
                        timeout=max(0.0, deadline - time.monotonic()),
                    )
        self._subprocess_owner.wait(timeout=max(0.0, deadline - time.monotonic()))
        self._stop_heartbeat_thread(deadline=deadline)
        lifecycle = (
            DaemonLifecycleState.stopping
            if (
                not quiescence_proven
                or container_stop_failures
                or not publication_worker_stopped
                or not control_loop_writer_stopped
                or getattr(initial_revocation, "deadline_exhausted", False)
            )
            else DaemonLifecycleState.stopped
        )
        with self._runtime_lock:
            self.runtime.lifecycle = lifecycle
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.heartbeat_at = utc_now()
        if quiescence_proven:
            try:
                result = self.store.revoke_daemon_publication_authority(
                    self.runtime.instance_id,
                    lifecycle.value,
                    deadline=deadline,
                    state={
                        "forced": force,
                        "interrupted_runs": interrupted_runs,
                        "container_stop_failures": len(container_stop_failures),
                        "publication_worker_stopped": publication_worker_stopped,
                        "control_loop_writer_stopped": control_loop_writer_stopped,
                    },
                )
                if getattr(result, "ownership_lost", False):
                    self._log("daemon ownership lost before final lifecycle transition")
                elif getattr(result, "deadline_exhausted", False):
                    # A lifecycle write that did not commit leaves the old claim
                    # usable by design; report unresolved stopping rather than a
                    # clean shutdown that falsely implies authority was revoked.
                    lifecycle = DaemonLifecycleState.stopping
                    with self._runtime_lock:
                        self.runtime.lifecycle = lifecycle
                        self.runtime.state = DaemonRuntimeState.stopping
                    self._log("daemon final lifecycle transition exceeded shutdown deadline")
            except ValueError as exc:
                if str(exc) != "daemon instance is not the current owner":
                    raise
                self._log("daemon ownership lost before final lifecycle transition")
        else:
            self._log(
                "daemon publication authority remains active until transport quiescence"
            )
        return ShutdownResult(
            state=lifecycle,
            forced=force,
            interrupted_runs=interrupted_runs,
            stopped_containers=stopped_container_count,
        )

    def _interrupt_run(self, run_id: str, *, force: bool, grace_seconds: float) -> None:
        if self.session_supervisor is not None:
            try:
                self.session_supervisor.interrupt(
                    run_id,
                    force=force or self._force_shutdown_event.is_set(),
                    grace_seconds=grace_seconds,
                )
                return
            except Exception:
                pass
        try:
            self.store.mark_run_interrupted(
                run_id,
                reason="forced daemon shutdown" if force else "daemon shutdown",
            )
        except Exception:
            pass

    def _stop_task_container(self, task_id: str) -> bool:
        if self.session_supervisor is None:
            return False
        stopped = self.session_supervisor.stop_container(task_id, timeout=1)
        return stopped is not False

    def tick(
        self,
        *,
        plan: bool = True,
        dispatch: bool = True,
        max_dispatch: int | None = None,
    ) -> TickResult:
        return self.run_cycle(
            plan=plan,
            dispatch=dispatch,
            max_dispatch=max_dispatch,
            reason="manual-tick",
        )

    def run_cycle(
        self,
        *,
        plan: bool = True,
        dispatch: bool = True,
        fetch_providers: list[str] | None = None,
        max_dispatch: int | None = None,
        reason: str = "scheduled",
    ) -> TickResult:
        with use_subprocess_owner(self._subprocess_owner):
            return self._run_cycle(
                plan=plan,
                dispatch=dispatch,
                fetch_providers=fetch_providers,
                max_dispatch=max_dispatch,
                reason=reason,
            )

    def _run_cycle(
        self,
        *,
        plan: bool = True,
        dispatch: bool = True,
        fetch_providers: list[str] | None = None,
        max_dispatch: int | None = None,
        reason: str = "scheduled",
    ) -> TickResult:
        result = TickResult()
        startup_was_complete = self._startup_complete
        if not self._startup_complete:
            self.startup_reconcile()
        if startup_was_complete:
            self._retry_cleanup_pending_tasks()
        pressure = self._refresh_resource_pressure()
        if pressure.get("state") == "resource_pressure":
            self._log("resource pressure active; admission is bounded")
        self._drain_control_loop_once()
        self._begin_cycle(reason)
        try:
            self._poll_adopted_runs()
            wakeups = self.store.pending_wakeups(limit=200)
            if wakeups:
                self.store.consume_wakeups([wakeup.id for wakeup in wakeups])
            plan, dispatch, max_dispatch, manual_event = _merge_manual_cycle_options(
                wakeups,
                plan=plan,
                dispatch=dispatch,
                max_dispatch=max_dispatch,
            )
            if manual_event is not None:
                self.store.add_event(
                    DAEMON_EVENT_TASK_ID,
                    "scheduler.manual_applied",
                    "manual scheduler options applied",
                    manual_event,
                )
            self._log(
                "cycle start "
                f"reason={reason} "
                f"wakeups={len(wakeups)} "
                f"plan={str(plan).lower()} "
                f"dispatch={str(dispatch).lower()} "
                f"max_dispatch={max_dispatch or '-'}"
            )
            if plan:
                explicit_fetch_providers = _fetch_providers_from_wakeups(
                    self.config, wakeups
                )
                if explicit_fetch_providers:
                    fetch_providers = explicit_fetch_providers
                requeued = self.store.requeue_failed_signal_items()
                if requeued:
                    self.store.add_event(
                        DAEMON_EVENT_TASK_ID,
                        "signals.requeued_failed",
                        f"requeued {requeued} failed signal item(s)",
                        {"count": requeued, "retry_after_hours": 24},
                    )
                    self._log(f"requeued failed signals count={requeued}")
                if fetch_providers:
                    self._fetch_signals(result, fetch_providers)
                else:
                    idle_providers = self._idle_fetch_provider_names()
                    if idle_providers:
                        self._log(
                            "signals idle fetch providers="
                            + ",".join(idle_providers)
                        )
                        self._fetch_signals(result, idle_providers)
                if self.admission_allowed():
                    self._plan_until_idle(result)
                else:
                    self._log("resource pressure: planner admission paused")
            if dispatch:
                if self.admission_allowed():
                    self._dispatch_queued(result, plan=plan, max_dispatch=max_dispatch)
                else:
                    self._log("resource pressure: task admission paused")
            self._log(
                "cycle finish "
                f"signal_fetches={result.signal_fetches} "
                f"signal_items={result.signal_items} "
                f"new_signal_items={result.new_signal_items} "
                f"planned={result.planned} "
                f"enqueued={result.enqueued} "
                f"dispatched={result.dispatched} "
                f"skipped={result.skipped}"
            )
        finally:
            self._complete_cycle(result, reason)
            self._drain_control_loop_once()
        return result

    def _dispatch_queued(
        self,
        result: TickResult,
        *,
        plan: bool,
        max_dispatch: int | None,
    ) -> None:
        with self._worker_pool_lock:
            concurrent_pool = self._worker_pool
        if concurrent_pool is not None:
            self._dispatch_queued_pool(result, concurrent_pool, max_dispatch=max_dispatch)
            return
        source_limit = (
            max_dispatch
            if max_dispatch is not None
            else self.config.limits.max_active_tasks
        )
        total_limit = max_dispatch
        snapshot = self.store.dispatch_snapshot(
            source_limit=max(0, source_limit),
            integration_limit=1,
            resumable_limit=0,
        )
        queued = list(snapshot.queued_tasks)
        source_capacity = max(
            0,
            self.config.limits.max_active_tasks - snapshot.source_active_count,
        )
        integration_active = snapshot.integration_active_count
        source_attempts = 0
        integration_attempted = False
        seen: set[str] = set()
        while queued:
            if total_limit is not None and result.dispatched + result.skipped >= total_limit:
                return
            task = queued.pop(0)
            if task.id in seen:
                continue
            is_integration = _is_integration_manager_task(task)
            if is_integration:
                if integration_attempted or integration_active > 0:
                    seen.add(task.id)
                    continue
                integration_attempted = True
                integration_active += 1
            else:
                if source_attempts >= source_limit or source_capacity <= 0:
                    seen.add(task.id)
                    continue
                source_attempts += 1
                source_capacity -= 1
            seen.add(task.id)
            if not self._task_admission_allowed(task):
                result.skipped += 1
                continue
            self._log(f"dispatch start {task.id} {_task_label(task)}")
            try:
                task_ok = self.drive_selected_task(task.id)
            except Exception as exc:  # pragma: no cover - daemon boundary guard.
                if isinstance(exc, TaskLedgerOwnershipError):
                    result.skipped += 1
                    self._log(
                        f"dispatch blocked {task.id} ownership={exc.__class__.__name__}"
                    )
                    continue
                if self._shutdown_event.is_set():
                    self.store.add_event(
                        task.id,
                        "daemon.shutdown_interrupted",
                        "task dispatch stopped during daemon shutdown",
                        {"error": exc.__class__.__name__},
                    )
                    return
                result.skipped += 1
                message = str(exc)[-2000:] or exc.__class__.__name__
                finished = self._fail_dispatch_exception(task.id, message)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=false "
                    f"error={exc.__class__.__name__}"
                )
                continue
            if self._shutdown_event.is_set():
                return
            if task_ok:
                result.dispatched += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=true"
                )
                if (
                    not is_integration
                    and (
                        total_limit is None
                        or result.dispatched + result.skipped < total_limit
                    )
                    and not self._shutdown_event.is_set()
                ):
                    continuation = self.store.find_active_dedupe(
                        f"integration:{task.id}"
                    )
                    if (
                        continuation is not None
                        and continuation.id not in seen
                        and TaskStatus(continuation.status) == TaskStatus.queued
                        and _is_integration_manager_task(continuation)
                    ):
                        queued.insert(0, continuation)
                if plan:
                    self._plan_until_idle(result)
            else:
                result.skipped += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=false"
                )

    def _dispatch_queued_pool(
        self,
        result: TickResult,
        pool: concurrent.futures.ThreadPoolExecutor,
        *,
        max_dispatch: int | None,
    ) -> None:
        capacity = max_dispatch if max_dispatch is not None else self.config.limits.max_active_tasks
        capacity = max(0, capacity)
        with self._worker_pool_lock:
            for task_id, future in list(self._active_futures.items()):
                if future.done():
                    self._active_futures.pop(task_id, None)
            active_future_ids = set(self._active_futures)
        available = max(0, self.config.limits.max_active_tasks - len(active_future_ids))
        budget = min(capacity, available)
        snapshot = self.store.dispatch_snapshot(
            source_limit=budget,
            integration_limit=1 if budget > 0 else 0,
            resumable_limit=(budget + len(active_future_ids)) if budget > 0 else 0,
        )
        source_capacity = max(
            0,
            self.config.limits.max_active_tasks - snapshot.source_active_count,
        )
        integration_capacity = max(0, 1 - snapshot.integration_active_count)
        seen = active_future_ids
        for task in [*snapshot.queued_tasks, *snapshot.resumable_tasks]:
            if budget <= 0 or task.id in seen:
                continue
            if not self._task_admission_allowed(task):
                continue
            queued = TaskStatus(task.status) == TaskStatus.queued
            if queued:
                if _is_integration_manager_task(task):
                    if integration_capacity <= 0:
                        continue
                    integration_capacity -= 1
                else:
                    if source_capacity <= 0:
                        continue
                    source_capacity -= 1
            future = pool.submit(self._run_task_worker, task.id)
            with self._worker_pool_lock:
                self._active_futures[task.id] = future
            result.dispatched += 1
            budget -= 1
            seen.add(task.id)
            self._log(f"dispatch scheduled {task.id} {_task_label(task)}")

    def _planner_config_with_admission_cap(self) -> StewardConfig:
        """Keep planner verifier capacity within the global active-task cap."""

        configured_limit = self.config.limits.max_active_tasks
        if configured_limit <= GLOBAL_ACTIVE_TASK_ADMISSION_CAP:
            return self.config
        return replace(
            self.config,
            limits=replace(
                self.config.limits,
                max_active_tasks=GLOBAL_ACTIVE_TASK_ADMISSION_CAP,
            ),
        )

    def drive_selected_task(self, task_id: str) -> bool:
        """Advance one selected task until a durable stopping point or shutdown."""

        integration = False
        try:
            selected = self.store.get(task_id)
            if not self._task_admission_allowed(selected):
                return False
            integration = _is_integration_manager_task(selected)
        except KeyError:
            return False
        while not self._shutdown_event.is_set():
            try:
                serialized = integration or self._task_phase_requires_serialization(task_id)
            except TaskLedgerOwnershipError:
                return False
            if serialized:
                self._integration_lock.acquire()
            try:
                # Re-read the Store-owned latch at every phase boundary. The
                # selected TaskRecord is only a dispatch snapshot and may have
                # become dry-run while the previous phase was completing.
                current = self.store.get(task_id)
                if not self._task_admission_allowed(current):
                    return False
                rerun = self._rerun_task_for_admission(current)
                if rerun is not None and not self._refresh_live_rerun_context(rerun):
                    return False
                with self.store.phase_admission(task_id):
                    with use_subprocess_owner(self._subprocess_owner):
                        outcome = self.executor.advance_once(task_id)
            except Exception as exc:
                if isinstance(exc, TaskLedgerOwnershipError):
                    return False
                if self._shutdown_event.is_set():
                    try:
                        self.store.add_event(
                            task_id,
                            "daemon.shutdown_interrupted",
                            "phase worker stopped during daemon shutdown",
                            {"error": exc.__class__.__name__},
                        )
                    except Exception:
                        pass
                    return False
                self._fail_dispatch_exception(task_id, str(exc)[-2000:])
                return False
            finally:
                if serialized:
                    self._integration_lock.release()
            try:
                if not self._task_admission_allowed(self.store.get(task_id)):
                    return False
            except KeyError:
                return False
            status = str(getattr(outcome, "status", ""))
            if status == "interrupted":
                return False
            if status in {"ready_to_seal", "terminal", "blocked"}:
                if (
                    status in {"ready_to_seal", "blocked"}
                    and not self._shutdown_event.is_set()
                ):
                    try:
                        if not self._task_admission_allowed(self.store.get(task_id)):
                            return False
                    except KeyError:
                        return False
                    self.finalize_terminal_task(task_id)
                return status in {"ready_to_seal", "terminal"}
            if status == "in_progress":
                self._shutdown_event.wait(0.05)
                continue
            if not getattr(outcome, "progressed", False) and getattr(outcome, "next_phase", None) is None:
                return False
        return False

    def _run_task_worker(self, task_id: str) -> bool:
        """Run the durable selected-task driver in a worker-pool future."""

        return self.drive_selected_task(task_id)

    def _start_heartbeat_thread(self) -> None:
        with self._runtime_lock:
            if self._heartbeat_thread is not None:
                return
            self._heartbeat_stop.clear()
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                name="steward-heartbeat",
                daemon=True,
            )
            self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(self._heartbeat_interval_seconds()):
            self._touch_heartbeat()

    def _stop_heartbeat_thread(self, *, deadline: float | None = None) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread is not threading.current_thread():
            timeout = 2.0
            if deadline is not None:
                timeout = max(0.0, deadline - time.monotonic())
            thread.join(timeout=timeout)
        self._heartbeat_thread = None

    def _task_phase_requires_serialization(self, task_id: str) -> bool:
        """Serialize integration, commit, and push actions across source tasks."""

        try:
            execution = self.store.get_execution(task_id)
        except KeyError as exc:
            raise TaskLedgerOwnershipError(
                "task execution ownership is unavailable"
            ) from exc
        pipeline_id = execution.owning_pipeline_id
        if pipeline_id is None:
            raise TaskLedgerOwnershipError(
                "task execution has no owning pipeline"
            )
        try:
            phase = self.executor._pipeline_cursor(task_id, pipeline_id)
        except (AttributeError, KeyError, IndexError, TypeError, ValueError):
            return False
        value = getattr(phase, "value", phase)
        return str(value) in {
            PipelineCursorPhase.integration.value,
            PipelineCursorPhase.commit.value,
            PipelineCursorPhase.push.value,
        }

    def _poll_adopted_runs(self) -> None:
        """Reconcile adopted wrappers until their durable result is consumable."""

        for task_id in sorted(tuple(self._adopted_runs)):
            try:
                outcome = self._reconcile_task(self.store.get(task_id))
            except KeyError:
                self._adopted_runs.pop(task_id, None)
                continue
            if outcome.disposition != ReconciliationDisposition.adopted:
                self._adopted_runs.pop(task_id, None)
                if outcome.disposition in {
                    ReconciliationDisposition.ingested,
                    ReconciliationDisposition.resumed,
                    ReconciliationDisposition.interrupted,
                }:
                    self._schedule_task_continuation(task_id)
            self._reconciliation = [
                item for item in self._reconciliation if item.task_id != task_id
            ]
            self._reconciliation.append(outcome)
            try:
                self.store.add_event(
                    task_id,
                    "daemon.reconciled",
                    outcome.disposition.value,
                    outcome.as_dict(),
                )
            except Exception:
                pass

    def _schedule_task_continuation(self, task_id: str) -> bool:
        """Wake an active task after an adopted run advances its cursor."""

        with self._worker_pool_lock:
            pool = self._worker_pool
            existing = self._active_futures.get(task_id)
            if pool is None or self._shutdown_event.is_set():
                return False
            if existing is not None and not existing.done():
                return False
            try:
                task = self.store.get(task_id)
            except KeyError:
                return False
            if not self._task_admission_allowed(task):
                return False
            if TaskStatus(task.status).terminal:
                return False
            future = pool.submit(self._run_task_worker, task_id)
            self._active_futures[task_id] = future
            return True

    def _fail_dispatch_exception(self, task_id: str, message: str) -> TaskRecord:
        summary = f"dispatch failed: {message}"
        current = self.store.get(task_id)
        current_status = TaskStatus(current.status)
        if current_status.terminal:
            task = current
        elif current_status == TaskStatus.queued:
            task = self.store.update_status(task_id, TaskStatus.failed, summary)
        else:
            task = self.store.finish_task(task_id, TaskStatus.failed, summary)
        self.store.add_event(
            task_id,
            "dispatch.failed",
            message,
            {"summary": summary},
        )
        if self.executor.clean_finished_task_worktree(task):
            task = self.store.get(task_id)
        return task

    def _idle_fetch_provider_names(self) -> list[str]:
        return idle_fetch_provider_names(scheduler_state(self.config, self.store))

    def _fetch_signals(self, result: TickResult, providers: list[str]) -> None:
        collections = collect_signal_items(self.config, provider_names=providers)
        for collection in collections:
            result.signal_fetches += 1
            fetch_run = collection.fetch.model_copy(
                update={
                    "status": (
                        SignalFetchStatus.error
                        if collection.fetch.error
                        else SignalFetchStatus.ok
                    ),
                    "item_count": len(collection.items),
                    "new_item_count": 0,
                }
            )
            provider_config = self.config.signal_providers.get(
                collection.fetch.provider
            )
            saved_items, _signals, created_items = self.store.ingest_signal_collection(
                fetch_run,
                collection.items,
                suppression_hours=(
                    provider_config.suppression_hours if provider_config else 24
                ),
            )
            fetch_run = fetch_run.model_copy(
                update={"item_count": len(saved_items), "new_item_count": created_items}
            )
            result.signal_items += len(saved_items)
            result.new_signal_items += created_items
            self.store.add_event(
                DAEMON_EVENT_TASK_ID,
                "signals.fetched",
                (
                    f"{collection.fetch.provider}: {created_items} new of "
                    f"{len(saved_items)} item(s)"
                ),
                {
                    "fetch_run_id": fetch_run.id,
                    "provider": collection.fetch.provider,
                    "item_count": len(saved_items),
                    "new_item_count": created_items,
                    "has_more": fetch_run.has_more,
                    "error": collection.fetch.error,
                },
            )
            self._log(
                "signals fetched "
                f"provider={collection.fetch.provider} "
                f"new={created_items} total={len(saved_items)} "
                f"has_more={str(fetch_run.has_more).lower()} "
                f"error={collection.fetch.error or '-'}"
            )

    def _plan_until_idle(self, result: TickResult) -> None:
        if self._active_planner_run_id is None:
            self._reconcile_interrupted_planner_runs()
        if self._control_loop_ledger.planning_blocked:
            self._log("planner blocked by control-loop reconciliation conflict")
            return
        turns = 0
        while turns < self.config.limits.max_active_tasks:
            global_active_count = self.store.active_count()
            if global_active_count >= GLOBAL_ACTIVE_TASK_ADMISSION_CAP:
                self._log(
                    "planner skipped global active task admission limit reached "
                    f"count={global_active_count}"
                )
                return
            source_active_count = self.store.source_active_count()
            if source_active_count >= self.config.limits.max_active_tasks:
                self._log("planner skipped active task limit reached")
                return
            available = min(
                self.config.limits.max_active_tasks - source_active_count,
                GLOBAL_ACTIVE_TASK_ADMISSION_CAP - global_active_count,
            )
            pending = self.store.pending_signal_items(
                limit=max(1, available)
            )
            if not pending:
                return
            retry = self._control_loop_ledger.pending_retry("planner")
            if retry is not None and retry[1] is not None and retry[1] > utc_now():
                current_signal_ids = set(self._canonical_signal_ids(pending))
                runs = self._control_loop_ledger.list_planner_runs()
                previous_signal_ids = set(runs[-1].input_signal_ids) if runs else set()
                if current_signal_ids != previous_signal_ids:
                    self._control_loop_ledger.reset_retry("planner")
                else:
                    self._log(
                        "planner retry deferred "
                        f"attempt={retry[0]} eligible_at={control_timestamp(retry[1])}"
                    )
                    return
            turns += 1
            before_pending = {item.id for item in pending}
            actionable, stale_reasons = revalidate_signal_items(self.config, pending)
            if stale_reasons:
                superseded = self.store.supersede_signal_items(
                    list(stale_reasons), planner_run_id="source-revalidation"
                )
                if superseded:
                    self.store.add_event(
                        DAEMON_EVENT_TASK_ID,
                        "signals.superseded_stale",
                        f"superseded {superseded} stale signal item(s)",
                        {"count": superseded, "reasons": stale_reasons},
                    )
                    self._log(f"superseded stale signals count={superseded}")
            if actionable:
                self._plan(result, actionable)
            after_pending = {
                item.id
                for item in self.store.pending_signal_items(
                    limit=self.config.limits.max_active_tasks
                )
            }
            if after_pending == before_pending:
                return

    def _plan(self, result: TickResult, inbox_items: list[SignalItem]) -> None:
        global_active_count = self.store.active_count()
        if global_active_count >= GLOBAL_ACTIVE_TASK_ADMISSION_CAP:
            self._log(
                "planner skipped global active task admission limit reached "
                f"count={global_active_count}"
            )
            return
        active_tasks, task_context = planner_task_context(self.store)
        signals = project_signals_from_items(self.config, inbox_items)
        active_count = self.store.source_active_count()
        planner_config = self._planner_config_with_admission_cap()
        self._log(
            "planner start "
            f"source_active={active_count} "
            f"task_context={len(task_context)} "
            f"inbox={len(inbox_items)}"
        )
        self.store.add_event(
            DAEMON_EVENT_TASK_ID,
            "planner.started",
            "planner turn started",
            {
                "active_task_count": active_count,
                "task_context_count": len(task_context),
                "inbox_item_ids": [item.id for item in inbox_items],
                "enabled_signals": list(self.config.enabled_signals),
            },
        )
        control_run_id = new_control_loop_id("planner")
        canonical_signal_ids = self._canonical_signal_ids(inbox_items)
        try:
            self._control_loop_ledger.claim_planner_run(
                control_run_id,
                canonical_signal_ids,
                [task.id for task in active_tasks],
                prompt={
                    "signalIds": canonical_signal_ids,
                    "signalItemIds": [item.id for item in inbox_items],
                    "activeTaskCount": len(active_tasks),
                },
            )
            self._active_planner_run_id = control_run_id
            self._control_loop_wakeup.set()
        except Exception as exc:
            self._log(f"planner claim failed error={exc.__class__.__name__}")
            return
        planner_run = None
        planner_error: Exception | None = None
        try:
            planner_run = run_planner(
                planner_config,
                signals,
                task_context,
                invocation=self.planner_session,
                run_id=control_run_id,
            )
        except Exception as exc:
            planner_error = exc
        run_id = control_run_id
        if planner_run is None:
            planner_run = _failed_planner_result(planner_error)
        result.planned += len(planner_run.planned)
        state = "succeeded" if planner_run.completed and not planner_run.invalid_output else "failed"
        if planner_run.diagnostics.get("interrupted") is True:
            state = "interrupted"
        if planner_error is not None:
            state = "failed"
        diagnostics = dict(planner_run.diagnostics)
        retry_after: timedelta | None = None
        if state in {"failed", "interrupted"}:
            diagnostics.update(
                {
                    "reason_code": (
                        "planner_interrupted"
                        if state == "interrupted"
                        else "planner_failed"
                    ),
                }
            )
        try:
            canonical_signal_by_item = {
                item.id: signal_id
                for item in inbox_items
                if (
                    signal_id := self._control_loop_ledger.canonical_signal_id(
                        item.provider, item.fingerprint
                    )
                )
                is not None
            }
            selected_item_ids_by_dedupe = {
                dedupe_key: selected_signal_item_ids(
                    spec.metadata or {}, planner_run.consumed_item_ids
                )
                for spec, dedupe_key in planner_run.planned
            }
            artifact_sources = self._planner_artifact_sources(
                planner_run,
                signals,
                task_context,
                run_id,
            )
            committed = self.store.commit_planner_decision(
                run_id,
                planned=planner_run.planned,
                planner_dispositions=planner_run.dispositions,
                consumed_item_ids=planner_run.consumed_item_ids,
                selected_item_ids_by_dedupe=selected_item_ids_by_dedupe,
                canonical_signal_by_item=canonical_signal_by_item,
                state=state,
                result={
                    "acceptedCount": planner_run.accepted_count,
                    "proposedCount": planner_run.proposed_count,
                    "consumedItemIds": planner_run.consumed_item_ids,
                },
                diagnostics=diagnostics,
                retry_after=retry_after,
                artifact_sources=artifact_sources,
                schedule_retry_key=(
                    "planner" if state in {"failed", "interrupted"} else None
                ),
            )
            completed = committed["completed"]
            diagnostics = dict(completed.diagnostics)
            planned_item_count = int(committed["planned_item_count"])
            superseded_count = int(committed["superseded_item_count"])
            consumed_count = planned_item_count + superseded_count
            for record, created in committed["records"]:
                if created:
                    result.enqueued += 1
                    self._log(f"enqueued {record.id} {_task_label(record)}")
                else:
                    result.skipped += 1
                    self._log(
                        f"skipped duplicate plan {record.id} "
                        f"dedupe={record.spec.metadata.get('dedupe_key')}"
                    )
            self._planner_publication_queue[run_id] = completed
            self._control_loop_wakeup.set()
        except Exception as exc:
            self._log(f"planner completion lag run={run_id} error={exc.__class__.__name__}")
            planned_item_count = 0
            superseded_count = 0
            consumed_count = 0
        self._active_planner_run_id = None
        self._control_loop_wakeup.set()
        self._log(
            "planner finish "
            f"completed={str(planner_run.completed).lower()} "
            f"exit={planner_run.exit_code} "
            f"verifier={planner_run.accepted_count}/{planner_run.proposed_count} "
            f"consumed={consumed_count}/{len(planner_run.consumed_item_ids)} "
            f"thread={planner_run.thread_id or '-'} "
            f"transcript={planner_run.transcript_path}"
        )
        self.store.add_event(
            DAEMON_EVENT_TASK_ID,
            "planner.finished",
            (
                f"accepted {planner_run.accepted_count} of "
                f"{planner_run.proposed_count} proposed task(s)"
            ),
            {
                "accepted_count": planner_run.accepted_count,
                "proposed_count": planner_run.proposed_count,
                "completed": planner_run.completed,
                "exit_code": planner_run.exit_code,
                "consumed_item_ids": planner_run.consumed_item_ids,
                "consumed_item_count": consumed_count,
                "planned_item_count": planned_item_count,
                "superseded_item_count": superseded_count,
                "run_id": run_id,
                "prompt_path": (
                    str(planner_run.prompt_path) if planner_run.prompt_path else None
                ),
                "transcript_path": str(planner_run.transcript_path),
                "thread_id": None,
                "diagnostics": diagnostics,
            },
        )

    def _canonical_signal_ids(self, items: list[SignalItem]) -> list[str]:
        ledger = self._control_loop_ledger
        values: list[str] = []
        for item in items:
            signal_id = ledger.canonical_signal_id(item.provider, item.fingerprint)
            if signal_id is not None and signal_id not in values:
                values.append(signal_id)
        return values

    def _planner_artifact_sources(
        self,
        planner_run: PlanningPlannerRun,
        signals,
        task_context: list[TaskRecord],
        run_id: str,
    ) -> dict[str, tuple[str, bool]]:
        fallback = self.config.private_sessions_dir / "planner-evidence" / run_id
        fallback.mkdir(parents=True, exist_ok=True, mode=0o700)
        prompt_path = planner_run.prompt_path
        if prompt_path is None or not Path(prompt_path).is_file():
            prompt_path = fallback / "prompt.md"
            prompt_path.write_text(
                render_planner_prompt(
                    signals,
                    summarize_active_tasks(task_context),
                    self.config,
                ),
                encoding="utf-8",
            )
        transcript_path = Path(planner_run.transcript_path)
        if not transcript_path.is_file():
            transcript_path = fallback / "codex.jsonl"
            transcript_path.touch(exist_ok=True)
        last_message_path = Path(planner_run.transcript_path).with_name("last-message.md")
        if not last_message_path.is_file():
            last_message_path = fallback / "last-message.md"
            last_message_path.write_text("", encoding="utf-8")
        sources: dict[str, tuple[str, bool]] = {
            "prompt.md": (str(prompt_path), True),
            "codex.jsonl": (str(transcript_path), True),
            "last-message.md": (str(last_message_path), True),
        }
        for name, path in (
            ("telemetry.json", Path(planner_run.transcript_path).with_name("telemetry.json")),
            ("activities.jsonl", Path(planner_run.transcript_path).with_name("activities.jsonl")),
            ("tool-changes/manifest.jsonl", Path(planner_run.transcript_path).parent / "tool-changes" / "manifest.jsonl"),
            ("tool-changes/summary.json", Path(planner_run.transcript_path).parent / "tool-changes" / "summary.json"),
        ):
            if path.is_file():
                sources[name] = (str(path), False)
        return sources

    def _planner_artifacts(self, completed: ControlPlannerRun) -> dict[str, bytes]:
        artifacts: dict[str, bytes] = {}
        for name, (path, required) in self._control_loop_ledger.planner_artifact_sources(
            completed.planner_run_id
        ).items():
            try:
                artifacts[name] = path.read_bytes()
            except OSError:
                if required:
                    raise
        artifacts["result.json"] = json.dumps(
            {
                "plannerRunId": completed.planner_run_id,
                "state": completed.state,
                "result": completed.result or {},
                "diagnostics": completed.diagnostics,
            },
            ensure_ascii=True,
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        missing = {"prompt.md", "codex.jsonl", "last-message.md"} - artifacts.keys()
        if missing:
            raise ArchiveError(
                "planner publication is missing required artifacts: "
                + ", ".join(sorted(missing))
            )
        return artifacts

    def run_forever(self) -> None:
        try:
            self.startup_reconcile()
            if self._shutdown_event.is_set():
                return
            self._start_heartbeat_thread()
            self._start_control_loop_writer()
            with self._worker_pool_lock:
                if self._worker_pool is None:
                    self._worker_pool = concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, self.config.limits.max_active_tasks),
                        thread_name_prefix="steward-task",
                    )
            while not self._shutdown_event.is_set():
                trigger = wait_for_scheduler_event(
                    self.config, self.store, stop_event=self._shutdown_event
                )
                if self._shutdown_event.is_set():
                    break
                self.run_cycle(
                    fetch_providers=trigger.providers,
                    max_dispatch=self.config.limits.max_active_tasks,
                    reason=trigger.reason,
                )
        finally:
            self._stop_control_loop_writer()
            if not self._shutdown_event.is_set():
                self.request_shutdown()
            self.shutdown(force=self._force_shutdown_event.is_set())

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(f"[steward] {message}")

    def _begin_cycle(self, reason: str) -> None:
        started_at = utc_now()
        with self._runtime_lock:
            if self._shutdown_event.is_set():
                raise RuntimeError("Steward daemon is stopping")
            self.runtime.heartbeat_at = started_at
            self.runtime.state = DaemonRuntimeState.active
            self.runtime.current_cycle_started_at = started_at
            self.runtime.current_cycle_reason = _bounded_cycle_reason(reason)
        self._current_control_cycle_id = new_control_loop_id("cycle")
        self._current_control_cycle_started_at = started_at
        try:
            self._control_loop_ledger.record_cycle(
                ControlLoopCycle(
                    cycleId=self._current_control_cycle_id,
                    reason=_bounded_cycle_reason(reason),
                    startedAt=started_at,
                    runtimeState="active",
                )
            )
            self._control_loop_wakeup.set()
        except Exception as exc:
            self._log(f"control-loop cycle start lag error={exc.__class__.__name__}")

    def _complete_cycle(self, result: TickResult, reason: str) -> None:
        completed_at = utc_now()
        summary = DaemonCycleSummary(
            completed_at=completed_at,
            reason=_bounded_cycle_reason(reason),
            result=DaemonCycleResult.model_validate(vars(result)),
        )
        with self._runtime_lock:
            self.runtime.heartbeat_at = completed_at
            self.runtime.state = DaemonRuntimeState.idle
            self.runtime.current_cycle_started_at = None
            self.runtime.current_cycle_reason = None
            self.runtime.last_completed_cycle = summary
        cycle_id = getattr(self, "_current_control_cycle_id", None)
        if cycle_id is not None:
            try:
                self._control_loop_ledger.record_cycle(
                    ControlLoopCycle(
                        cycleId=cycle_id,
                        reason=_bounded_cycle_reason(reason),
                        startedAt=getattr(
                            self,
                            "_current_control_cycle_started_at",
                            completed_at,
                        ),
                        completedAt=completed_at,
                        runtimeState="idle",
                    )
                )
                self._control_loop_wakeup.set()
            except Exception as exc:
                self._log(f"control-loop cycle finish lag error={exc.__class__.__name__}")

    def _touch_heartbeat(self) -> None:
        with self._runtime_lock:
            self.runtime.heartbeat_at = utc_now()

    def _runtime_snapshot(self) -> DaemonRuntime:
        with self._runtime_lock:
            return self.runtime.model_copy(deep=True)

    def _heartbeat_interval_seconds(self) -> int:
        with self._runtime_lock:
            return self.runtime.heartbeat_interval_seconds

def wait_for_scheduler_event(
    config: StewardConfig,
    store: TaskStore,
    *,
    stop_event: threading.Event | None = None,
) -> SchedulerTrigger:
    while True:
        if stop_event is not None and stop_event.is_set():
            return SchedulerTrigger(reason="stopping", providers=[])
        poll_result = scheduler_state(config, store)
        state = poll_result.state
        if state.pending_wakeups:
            return SchedulerTrigger(reason="wakeup", providers=[])
        due_providers = due_provider_names(poll_result)
        if due_providers:
            return SchedulerTrigger(reason="provider-due", providers=due_providers)
        idle_providers = idle_fetch_provider_names(
            poll_result,
            coalesce_window=timedelta(seconds=config.scheduler_wait_interval_sec),
        )
        if idle_providers:
            return SchedulerTrigger(reason="idle-fetch", providers=idle_providers)
        next_due = min((provider.next_due_at for provider in state.providers), default=None)
        if poll_result.idle:
            idle_due_at = [
                provider.idle_next_due_at
                for provider in state.providers
                if provider.idle_next_due_at is not None
            ]
            if idle_due_at:
                next_due = min(
                    [due for due in (next_due, min(idle_due_at)) if due is not None]
                )
        sleep_for = config.scheduler_wait_interval_sec
        if next_due is not None:
            sleep_for = min(
                sleep_for,
                max(0.0, (next_due - _now()).total_seconds()),
            )
        if stop_event is not None:
            stop_event.wait(max(0.1, sleep_for))
        else:
            time.sleep(max(0.1, sleep_for))


def _now() -> datetime:
    return datetime.now(timezone.utc)


_MISSING_MANUAL_OPTION = object()
_MAX_MANUAL_INVALID_FIELDS = 32


def _merge_manual_cycle_options(
    wakeups,
    *,
    plan: bool,
    dispatch: bool,
    max_dispatch: int | None,
) -> tuple[bool, bool, int | None, dict[str, object] | None]:
    manual_wakeups = [
        wakeup for wakeup in wakeups if wakeup.reason == "scheduler.manual"
    ]
    if not manual_wakeups:
        return plan, dispatch, max_dispatch, None

    manual_limits: list[int] = []
    invalid_fields: list[str] = []
    for wakeup in manual_wakeups:
        data = wakeup.data if isinstance(wakeup.data, Mapping) else {}
        requested_plan = data.get("plan", _MISSING_MANUAL_OPTION)
        if not isinstance(requested_plan, bool):
            plan = False
            invalid_fields.append("plan")
        else:
            plan = plan and requested_plan
        requested_dispatch = data.get("dispatch", _MISSING_MANUAL_OPTION)
        if not isinstance(requested_dispatch, bool):
            dispatch = False
            invalid_fields.append("dispatch")
        else:
            dispatch = dispatch and requested_dispatch
        requested_limit = data.get("max_dispatch")
        if requested_limit is None:
            continue
        if (
            isinstance(requested_limit, bool)
            or not isinstance(requested_limit, int)
            or requested_limit < 1
        ):
            dispatch = False
            invalid_fields.append("max_dispatch")
        else:
            manual_limits.append(requested_limit)

    limits = [limit for limit in [max_dispatch, *manual_limits] if limit is not None]
    effective_limit = min(limits) if limits else None
    return plan, dispatch, effective_limit, {
        "wakeup_ids": [wakeup.id for wakeup in wakeups],
        "plan": plan,
        "dispatch": dispatch,
        "max_dispatch": effective_limit,
        "invalid_fields": list(dict.fromkeys(invalid_fields))[
            :_MAX_MANUAL_INVALID_FIELDS
        ],
    }


def _fetch_providers_from_wakeups(config: StewardConfig, wakeups) -> list[str]:
    requested: list[str] = []
    enabled = set(config.enabled_signals)
    for wakeup in wakeups:
        if wakeup.reason != "signal.fetch":
            continue
        raw = wakeup.data.get("providers")
        values = raw if isinstance(raw, list) else list(config.enabled_signals)
        for value in values:
            if not isinstance(value, str) or value not in enabled:
                continue
            if value not in requested:
                requested.append(value)
    return requested


def _bounded_cycle_reason(reason: str) -> str:
    value = reason.strip()
    if not value or len(value) > 64:
        return "other"
    if any(
        character
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in value
    ):
        return "other"
    return value


def _task_label(task: TaskRecord) -> str:
    return f"kind={task.spec.kind} title={task.spec.title!r}"


def _is_integration_manager_task(task: TaskRecord) -> bool:
    return task.spec.worker == WorkerKind.integration_manager.value


def _is_identity_conflict(summary: str) -> bool:
    value = str(summary).lower()
    return any(
        marker in value
        for marker in (
            "identity",
            "conflict",
            "ownership",
            "checkpoint",
            "ancestry",
        )
    )


def _failed_planner_result(error: Exception | None) -> PlanningPlannerRun:
    message = str(error)[-2000:] if error is not None else "planner did not return a result"
    return PlanningPlannerRun(
        planned=[],
        accepted_count=0,
        proposed_count=0,
        completed=False,
        exit_code=1,
        prompt_path=None,
        transcript_path=Path("planner-unavailable.codex.jsonl"),
        thread_id=None,
        diagnostics={"reason_code": "planner_exception", "message": message},
    )

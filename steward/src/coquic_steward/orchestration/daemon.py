from __future__ import annotations

import concurrent.futures
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from ..core.config import StewardConfig
from ..core.lifecycle import (
    DaemonLifecycleState,
    ReconciliationDisposition,
    ReconciliationOutcome,
    ShutdownResult,
    TaskPhase,
)
from ..core.models import (
    DaemonCycleResult,
    DaemonCycleSummary,
    DaemonRuntime,
    DaemonRuntimeState,
    PublicMirrorFailureCategory,
    PublicMirrorHealth,
    PublicMirrorPublishState,
    SignalFetchStatus,
    SignalItem,
    TaskRecord,
    TaskStatus,
    utc_now,
    WorkerKind,
)
from ..execution.executor import StewardExecutor
from ..execution.session import SessionSupervisor, runtime_factory_for_config
from ..execution.task_archive import TaskArchiveWriter
from ..planning import run_planner
from ..public_mirror import (
    classify_publish_failure,
    publish_public_mirror,
    write_public_mirror_status,
)
from ..storage import (
    TaskStore,
    idle_fetch_provider_names,
    scheduler_state,
    store_is_idle_for_signal_fetch,
)
from ..signals import (
    collect_signal_items,
    project_signals_from_items,
    revalidate_signal_items,
)
from ..task_archive_sync import TaskArchiveSynchronizer
from .preflight import PreflightReport, preflight_remote_push, run_preflight

DAEMON_EVENT_TASK_ID = "daemon"
DAEMON_HEARTBEAT_INTERVAL_SECONDS = 30
PUBLIC_MIRROR_DEBOUNCE_SECONDS = 1.0
PUBLIC_MIRROR_RETRY_SECONDS = 30.0


@dataclass
class TickResult:
    recovered: int = 0
    signal_fetches: int = 0
    signal_items: int = 0
    new_signal_items: int = 0
    planned: int = 0
    enqueued: int = 0
    dispatched: int = 0
    skipped: int = 0


@dataclass(frozen=True)
class SchedulerTrigger:
    reason: str
    providers: list[str]


class StewardDaemon:
    def __init__(
        self,
        config: StewardConfig,
        store: TaskStore,
        *,
        logger: Callable[[str], None] | None = None,
        session_supervisor: SessionSupervisor | None = None,
    ):
        self.config = config
        self.store = store
        self.logger = logger
        self._lifecycle_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._force_shutdown_event = threading.Event()
        self._startup_complete = False
        self._reconciliation: list[ReconciliationOutcome] = []
        self._active_futures: dict[str, concurrent.futures.Future[object]] = {}
        self._worker_pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._worker_pool_lock = threading.RLock()
        self._integration_lock = threading.Lock()
        self._sync_thread: threading.Thread | None = None
        self._sync_stop = threading.Event()
        self._sync_wakeup = threading.Event()
        self._sync_lock = threading.Lock()
        self._sync_running = False
        self._sync_final_attempted = False
        self._sync_cycle_count = 0
        self._preflight_report: PreflightReport | None = None
        remote_push_ready = preflight_remote_push(config)
        if remote_push_ready:
            self._log(
                "remote push preflight ok "
                f"remote={config.git_remote} branch={config.main_branch}"
            )
        self.session_supervisor = session_supervisor
        if self.session_supervisor is None and config.task_image_digest:
            self.session_supervisor = SessionSupervisor(
                config,
                store,
                runtime_factory=runtime_factory_for_config(config),
                image_digest=config.task_image_digest,
                codex_identity=config.codex_identity or config.codex_bin,
            )
        self.executor = StewardExecutor(
            config,
            store,
            session_supervisor=self.session_supervisor,
        )
        self.runtime = DaemonRuntime(
            heartbeat_interval_seconds=DAEMON_HEARTBEAT_INTERVAL_SECONDS
        )
        self._runtime_lock = threading.Lock()
        self._public_mirror_local_digest: str | None = None
        self._public_mirror_remote_digest: str | None = None
        self._public_mirror_health = PublicMirrorHealth(
            state=(
                PublicMirrorPublishState.pending
                if config.public_mirror.enabled and config.public_mirror.publish
                else PublicMirrorPublishState.disabled
            )
        )
        self._public_mirror_update_lock = threading.Lock()
        self._public_mirror_thread_lock = threading.Lock()
        self._public_mirror_dirty = threading.Event()
        self._public_mirror_stop = threading.Event()
        self._public_mirror_thread: threading.Thread | None = None
        self._public_mirror_stopping = False
        if config.public_mirror.enabled and hasattr(store, "on_change"):
            store.on_change = self._public_mirror_store_changed
        # This is a local, bounded check. External integrations are checked
        # only when explicitly enabled; remote push remains the compatibility
        # preflight above for existing callers.
        # ``preflight_remote_push`` above is retained for the existing startup
        # log contract; avoid running the network-facing check a second time.
        report = run_preflight(
            config, store, check_remote_push=False
        )
        if remote_push_ready:
            report = PreflightReport(
                checks=(*report.checks, "remote-push"),
                warnings=report.warnings,
                configured_sync=report.configured_sync,
            )
        self._preflight_report = report
        if hasattr(store, "claim_daemon_instance"):
            store.claim_daemon_instance(
                self.runtime.instance_id if hasattr(self, "runtime") else "pending",
                lifecycle=DaemonLifecycleState.starting.value,
            )

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

    def startup_reconcile(self) -> tuple[ReconciliationOutcome, ...]:
        """Reconcile durable ownership before any new dispatch is allowed."""

        with self._lifecycle_lock:
            if self._startup_complete:
                return tuple(self._reconciliation)
            with self._runtime_lock:
                self.runtime.lifecycle = DaemonLifecycleState.reconciling
                self.runtime.state = DaemonRuntimeState.active
            if hasattr(self.store, "set_daemon_lifecycle"):
                self.store.set_daemon_lifecycle(
                    DaemonLifecycleState.reconciling.value,
                    instance_id=self.runtime.instance_id,
                )
            outcomes: list[ReconciliationOutcome] = []
            for task in sorted(self.store.list_tasks(limit=10000), key=lambda item: item.id):
                outcome = self._reconcile_task(task)
                outcomes.append(outcome)
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
            self._reconciliation = outcomes
            self._startup_complete = True
            with self._runtime_lock:
                self.runtime.lifecycle = DaemonLifecycleState.running
                self.runtime.state = DaemonRuntimeState.idle
                self.runtime.reconciliation_complete = True
                self.runtime.heartbeat_at = utc_now()
            if hasattr(self.store, "set_daemon_lifecycle"):
                self.store.set_daemon_lifecycle(
                    DaemonLifecycleState.running.value,
                    instance_id=self.runtime.instance_id,
                    state={"reconciliation_complete": True},
                )
            return tuple(outcomes)

    reconcile_startup = startup_reconcile
    reconcile = startup_reconcile

    def _reconcile_task(self, task: TaskRecord) -> ReconciliationOutcome:
        """Classify a task's persisted run without resetting any identity."""

        if TaskStatus(task.status).terminal:
            events = self.store.events(task.id)
            if any(event.kind == "cleanup_pending" for event in events) and not any(
                event.kind == "cleanup_complete" for event in events
            ):
                if self.finalize_terminal_task(task.id):
                    return ReconciliationOutcome(task.id, ReconciliationDisposition.cleaned, "terminal cleanup resumed")
                return ReconciliationOutcome(task.id, ReconciliationDisposition.blocked, "terminal cleanup remains pending")
        try:
            runs = self.store.list_runs(task.id)
        except (AttributeError, KeyError):
            runs = []
        running = [run for run in runs if str(run.state) == "running"]
        if not running:
            if TaskStatus(task.status).terminal:
                return ReconciliationOutcome(
                    task.id, ReconciliationDisposition.unchanged, "terminal task preserved"
                )
            return ReconciliationOutcome(task.id, ReconciliationDisposition.unchanged)
        for run in running:
            if self.session_supervisor is None:
                try:
                    self.store.mark_run_interrupted(run.id, reason="daemon restart")
                except Exception:
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
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.adopted,
                    "matching live wrapper adopted",
                    run_id=run.id,
                    container_id=getattr(inspection.container, "container_id", None),
                )
            try:
                self.store.mark_run_interrupted(run.id, reason="wrapper disappeared during daemon restart")
            except Exception as exc:
                return ReconciliationOutcome(
                    task.id,
                    ReconciliationDisposition.blocked,
                    "run interruption could not be persisted",
                    run_id=run.id,
                    evidence={"error": exc.__class__.__name__},
                )
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.interrupted,
                "partial run evidence preserved for resume or recovery",
                run_id=run.id,
            )
        return ReconciliationOutcome(task.id, ReconciliationDisposition.unchanged)

    def finalize_terminal_task(self, task_id: str) -> bool:
        """Seal immutable evidence, then retry each private cleanup action."""

        task = self.store.get(task_id)
        if not TaskStatus(task.status).terminal:
            return False
        events = self.store.events(task.id)
        cleanup_complete = any(event.kind == "cleanup_complete" for event in events)
        if cleanup_complete:
            return True
        archive = TaskArchiveWriter(self.config)
        manifest = archive.task_dir(task.id) / "manifest.json"
        try:
            if not manifest.exists():
                pipeline_id = None
                try:
                    pipeline_id = self.store.get_execution(task.id).owning_pipeline_id
                except Exception:
                    pass
                completion_identity = f"completion-{task.id}-{pipeline_id or 'legacy'}"
                archive.create_task_from_record(
                    task,
                    pipeline=self.store.get_pipeline(pipeline_id) if pipeline_id else None,
                )
                archive.seal(
                    task.id,
                    str(task.status),
                    completion_identity=completion_identity,
                    completed_at=task.completed_at.isoformat() if task.completed_at else utc_now().isoformat(),
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
        if not any(event.kind == "cleanup_pending" for event in events):
            self.store.add_event(task.id, "cleanup_pending", "terminal manifest verified")
        errors: list[str] = []
        if self.session_supervisor is not None:
            try:
                self.session_supervisor.stop_container(task.id, timeout=1)
            except Exception as exc:
                errors.append(f"container:{exc.__class__.__name__}")
        try:
            if task.worktree_path is not None and task.worktree_path.exists():
                self.executor.clean_finished_task_worktree(task)
        except Exception as exc:
            errors.append(f"worktree:{exc.__class__.__name__}")
        private_home = self.config.private_sessions_dir / task.id
        try:
            if private_home.exists():
                resolved = private_home.resolve()
                root = self.config.private_sessions_dir.resolve()
                if root not in resolved.parents:
                    raise RuntimeError("private home escaped session root")
                import shutil

                shutil.rmtree(resolved)
        except Exception as exc:
            errors.append(f"session-home:{exc.__class__.__name__}")
        if errors:
            self.store.add_event(task.id, "cleanup_retryable", "terminal cleanup incomplete", {"errors": errors})
            return False
        self.store.add_event(task.id, "cleanup_complete", "terminal private state removed")
        return True

    seal_terminal_task = finalize_terminal_task

    def request_shutdown(self, *, force: bool = False) -> None:
        """Request bounded shutdown; signal handlers call only this method."""

        self._shutdown_event.set()
        if force:
            self._force_shutdown_event.set()
        with self._runtime_lock:
            self.runtime.lifecycle = DaemonLifecycleState.stopping
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.stopping_requested_at = utc_now()
            self.runtime.forced_stop = force
            self.runtime.heartbeat_at = utc_now()
        if hasattr(self.store, "set_daemon_lifecycle"):
            self.store.set_daemon_lifecycle(
                DaemonLifecycleState.stopping.value,
                instance_id=self.runtime.instance_id,
                state={"forced": force},
            )
        self._sync_stop.set()
        self._sync_wakeup.set()

    stop = request_shutdown

    def shutdown(self, *, force: bool = False) -> ShutdownResult:
        """Stop workers and owned containers while retaining restart state."""

        self.request_shutdown(force=force)
        deadline = time.monotonic() if force else time.monotonic() + float(self.config.shutdown_grace_seconds)
        interrupted_runs = 0
        for task in sorted(self.store.list_tasks(limit=10000), key=lambda item: item.id):
            try:
                for run in self.store.list_runs(task.id):
                    if str(run.state) != "running":
                        continue
                    interrupted_runs += 1
                    if self.session_supervisor is not None:
                        try:
                            self.session_supervisor.interrupt(
                                run.id,
                                force=force or self._force_shutdown_event.is_set(),
                                grace_seconds=max(0.0, deadline - time.monotonic()),
                            )
                        except Exception:
                            try:
                                self.store.mark_run_interrupted(run.id, reason="daemon shutdown")
                            except Exception:
                                pass
                    else:
                        try:
                            self.store.mark_run_interrupted(
                                run.id, reason="daemon shutdown without session boundary"
                            )
                        except Exception:
                            pass
            except (AttributeError, KeyError):
                continue
            if time.monotonic() >= deadline and not force:
                force = True
                self._force_shutdown_event.set()
            if self.session_supervisor is not None:
                try:
                    self.session_supervisor.stop_container(task.id, timeout=1)
                except Exception:
                    pass
        with self._worker_pool_lock:
            pool = self._worker_pool
            self._worker_pool = None
        if pool is not None:
            pool.shutdown(wait=not force, cancel_futures=True)
        self._stop_task_sync(final=True)
        self._stop_public_mirror_sync()
        with self._runtime_lock:
            self.runtime.lifecycle = DaemonLifecycleState.stopped
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.heartbeat_at = utc_now()
        if hasattr(self.store, "set_daemon_lifecycle"):
            self.store.set_daemon_lifecycle(
                DaemonLifecycleState.stopped.value,
                instance_id=self.runtime.instance_id,
                state={"forced": force, "interrupted_runs": interrupted_runs},
            )
        return ShutdownResult(
            forced=force,
            interrupted_runs=interrupted_runs,
            stopped_containers=sum(1 for _ in self.store.list_tasks(limit=10000)),
            final_sync_attempted=self._sync_final_attempted,
        )

    def start_task_sync(self) -> None:
        """Start immediate and monotonic minute-cadence raw synchronization."""

        if not self.config.task_sync.enabled:
            return
        with self._sync_lock:
            if self._sync_thread is not None:
                return
            if hasattr(self.store, "reconcile_interrupted_task_archive_sync"):
                self.store.reconcile_interrupted_task_archive_sync()
            self._sync_stop.clear()
            self._sync_wakeup.clear()
            self._sync_final_attempted = False
            self._sync_thread = threading.Thread(
                target=self._task_sync_loop,
                name="steward-task-archive-sync",
                daemon=True,
            )
            self._sync_thread.start()

    _start_task_sync = start_task_sync

    def _task_sync_loop(self) -> None:
        next_due = time.monotonic()
        while not self._sync_stop.is_set():
            wait_for = max(0.0, next_due - time.monotonic())
            if self._sync_stop.wait(wait_for):
                return
            self._run_task_sync_cycle()
            # Coalesce missed ticks after a slow cycle instead of queuing work.
            next_due = max(next_due + 60.0, time.monotonic())

    def _run_task_sync_cycle(self) -> bool:
        if not self.config.task_sync.enabled or self._sync_stop.is_set() and self._sync_final_attempted:
            return False
        with self._sync_lock:
            if self._sync_running:
                return False
            self._sync_running = True
        try:
            sync_config = self.config.task_sync.to_archive_sync_config(self.config.tasks_dir)
            if sync_config is None:
                return False
            synchronizer = TaskArchiveSynchronizer(
                sync_config,
                self.store,
                cancel_event=self._sync_stop,
            )
            result = synchronizer.run_once()
            self._sync_cycle_count += 1
            self._log(f"task archive sync category={result.category} cycle={self._sync_cycle_count}")
            return bool(result.success)
        except Exception as exc:
            # Transport errors are health-only and must not affect task state.
            self._log(f"task archive sync health error={exc.__class__.__name__}")
            return False
        finally:
            with self._sync_lock:
                self._sync_running = False

    def _stop_task_sync(self, *, final: bool = False) -> None:
        if final and self.config.task_sync.enabled and not self._sync_final_attempted:
            self._sync_final_attempted = True
            self._sync_stop.clear()
            self._run_task_sync_cycle()
        self._sync_stop.set()
        thread = self._sync_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=min(5.0, float(self.config.task_sync.transfer_timeout_seconds) if self.config.task_sync.enabled else 5.0))
        with self._sync_lock:
            self._sync_thread = None

    stop_task_sync = _stop_task_sync

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
        result = TickResult()
        self._begin_cycle(reason)
        self._publish_public_mirror_if_changed()
        try:
            wakeups = self.store.pending_wakeups(limit=200)
            if wakeups:
                self.store.consume_wakeups([wakeup.id for wakeup in wakeups])
            explicit_fetch_providers = _fetch_providers_from_wakeups(
                self.config, wakeups
            )
            if explicit_fetch_providers:
                fetch_providers = explicit_fetch_providers
            self._log(
                "cycle start "
                f"reason={reason} "
                f"wakeups={len(wakeups)} "
                f"plan={str(plan).lower()} "
                f"dispatch={str(dispatch).lower()} "
                f"max_dispatch={max_dispatch or '-'}"
            )
            for task_id in self.store.recover_stale_active_tasks(
                stale_after_minutes=stale_task_minutes(self.config),
                status_stale_after_minutes=status_stale_minutes(self.config),
            ):
                result.recovered += 1
                self.executor.clean_finished_task_worktree(self.store.get(task_id))
                self.store.add_event(
                    task_id, "daemon.recovered_stale", "released stale active task"
                )
                self._log(f"recovered stale task {task_id}")
            if plan:
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
                self._plan_until_idle(result)
            if dispatch:
                self._dispatch_queued(result, plan=plan, max_dispatch=max_dispatch)
            self._log(
                "cycle finish "
                f"recovered={result.recovered} "
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
            self._publish_public_mirror_if_changed()
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
        source_limit = max_dispatch or self.config.limits.max_active_tasks
        total_limit = max_dispatch
        source_attempts = 0
        integration_attempted = False
        seen: set[str] = set()
        while True:
            if total_limit is not None and result.dispatched + result.skipped >= total_limit:
                return
            task = self._next_dispatchable_task(seen)
            if task is None:
                return
            is_integration = _is_integration_manager_task(task)
            if is_integration:
                if integration_attempted or self.store.integration_active_count() > 0:
                    seen.add(task.id)
                    continue
                integration_attempted = True
            else:
                if source_attempts >= source_limit:
                    seen.add(task.id)
                    continue
                if self.store.source_active_count() >= self.config.limits.max_active_tasks:
                    seen.add(task.id)
                    continue
                source_attempts += 1
            seen.add(task.id)
            self._log(f"dispatch start {task.id} {_task_label(task)}")
            try:
                task_ok = self.executor.run_task(task.id)
            except Exception as exc:  # pragma: no cover - daemon boundary guard.
                result.skipped += 1
                message = str(exc)[-2000:] or exc.__class__.__name__
                finished = self._fail_dispatch_exception(task.id, message)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=false "
                    f"error={exc.__class__.__name__}"
                )
                self._publish_public_mirror_if_changed()
                continue
            if task_ok:
                result.dispatched += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=true"
                )
                if plan:
                    self._plan_until_idle(result)
                self._publish_public_mirror_if_changed()
            else:
                result.skipped += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=false"
                )
                self._publish_public_mirror_if_changed()

    def _dispatch_queued_pool(
        self,
        result: TickResult,
        pool: concurrent.futures.ThreadPoolExecutor,
        *,
        max_dispatch: int | None,
    ) -> None:
        capacity = max_dispatch if max_dispatch is not None else self.config.limits.max_active_tasks
        with self._worker_pool_lock:
            for task_id, future in list(self._active_futures.items()):
                if future.done():
                    self._active_futures.pop(task_id, None)
        available = max(0, self.config.limits.max_active_tasks - len(self._active_futures))
        budget = min(capacity, available)
        seen = set(self._active_futures)
        for task in self.store.queued_tasks():
            if budget <= 0 or task.id in seen:
                continue
            if _is_integration_manager_task(task):
                if self.store.integration_active_count() > 0:
                    continue
            elif self.store.source_active_count() >= self.config.limits.max_active_tasks:
                continue
            future = pool.submit(self._run_task_worker, task.id)
            with self._worker_pool_lock:
                self._active_futures[task.id] = future
            result.dispatched += 1
            budget -= 1
            seen.add(task.id)
            self._log(f"dispatch scheduled {task.id} {_task_label(task)}")

    def _run_task_worker(self, task_id: str) -> bool:
        """Advance one task until a terminal/blocked cursor or shutdown."""

        integration = False
        try:
            integration = _is_integration_manager_task(self.store.get(task_id))
        except KeyError:
            return False
        while not self._shutdown_event.is_set():
            try:
                if integration:
                    with self._integration_lock:
                        outcome = self.executor.advance_once(task_id)
                else:
                    outcome = self.executor.advance_once(task_id)
            except Exception as exc:
                self._fail_dispatch_exception(task_id, str(exc)[-2000:])
                return False
            status = str(getattr(outcome, "status", ""))
            if status in {"ready_to_seal", "terminal", "blocked", "legacy_terminal"}:
                if status in {"ready_to_seal", "blocked", "legacy_terminal"}:
                    self.finalize_terminal_task(task_id)
                return status in {"ready_to_seal", "terminal", "legacy_terminal"}
            if status == "in_progress":
                self._shutdown_event.wait(0.05)
                continue
            if not getattr(outcome, "progressed", False) and getattr(outcome, "next_phase", None) is None:
                return False
        return False

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

    def _next_dispatchable_task(self, seen: set[str]) -> TaskRecord | None:
        for task in self.store.queued_tasks():
            if task.id in seen:
                continue
            return task
        return None

    def _should_fetch_signals_when_idle(self) -> bool:
        return store_is_idle_for_signal_fetch(self.store)

    def _idle_fetch_provider_names(self) -> list[str]:
        if not self._should_fetch_signals_when_idle():
            return []
        return idle_fetch_provider_names(
            scheduler_state(self.config, self.store)
        )

    def _fetch_signals(self, result: TickResult, providers: list[str]) -> None:
        try:
            collections = collect_signal_items(self.config, provider_names=providers)
        except TypeError as exc:
            if "provider_names" not in str(exc):
                raise
            collections = collect_signal_items(self.config)
        for collection in collections:
            result.signal_fetches += 1
            fetch_run = collection.fetch.model_copy(
                update={
                    "status": (
                        SignalFetchStatus.error
                        if collection.error
                        else SignalFetchStatus.ok
                    ),
                    "item_count": len(collection.items),
                    "new_item_count": 0,
                }
            )
            provider_config = self.config.signal_providers.get(collection.provider)
            saved_items, created_items = self.store.add_signal_items(
                collection.items,
                suppression_hours=(
                    provider_config.suppression_hours if provider_config else 24
                ),
            )
            fetch_run = fetch_run.model_copy(update={"new_item_count": created_items})
            self.store.add_signal_fetch_run(fetch_run)
            result.signal_items += len(saved_items)
            result.new_signal_items += created_items
            self.store.add_event(
                DAEMON_EVENT_TASK_ID,
                "signals.fetched",
                (
                    f"{collection.provider}: {created_items} new of "
                    f"{len(saved_items)} item(s)"
                ),
                {
                    "fetch_run_id": fetch_run.id,
                    "provider": collection.provider,
                    "item_count": len(saved_items),
                    "new_item_count": created_items,
                    "has_more": fetch_run.has_more,
                    "error": collection.error,
                },
            )
            self._log(
                "signals fetched "
                f"provider={collection.provider} "
                f"new={created_items} total={len(saved_items)} "
                f"has_more={str(fetch_run.has_more).lower()} "
                f"error={collection.error or '-'}"
            )

    def _plan_until_idle(self, result: TickResult) -> None:
        turns = 0
        while turns < self.config.limits.max_active_tasks:
            if self.store.source_active_count() >= self.config.limits.max_active_tasks:
                self._log("planner skipped active task limit reached")
                return
            available = self.config.limits.max_active_tasks - self.store.source_active_count()
            pending = self.store.pending_signal_items(
                limit=max(1, available)
            )
            if not pending:
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
        task_context = self.store.list_tasks(limit=200)
        signals = project_signals_from_items(self.config, inbox_items)
        active_count = self.store.source_active_count()
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
        try:
            planner_run = run_planner(
                self.config,
                signals,
                task_context,
                invocation=self.session_supervisor,
            )
        except TypeError as exc:
            # Preserve simple test doubles from the pre-boundary API. A real
            # invocation TypeError must still propagate unchanged.
            if "invocation" not in str(exc):
                raise
            planner_run = run_planner(self.config, signals, task_context)
        planned_item_count = 0
        planned_item_ids: set[str] = set()
        run_id = planner_run.run_id or planner_run.thread_id
        for spec, dedupe_key in planner_run.planned:
            result.planned += 1
            record, created = self.store.add_task(spec, dedupe_key=dedupe_key)
            if created:
                result.enqueued += 1
                selected_ids = _selected_item_ids(spec, planner_run.consumed_item_ids)
                planned_item_count += self.store.mark_signal_items_planned(
                    selected_ids,
                    planner_run_id=run_id,
                    task_id=record.id,
                )
                planned_item_ids.update(selected_ids)
                self._log(f"enqueued {record.id} {_task_label(record)}")
            else:
                result.skipped += 1
                self._log(
                    f"skipped duplicate plan {record.id} dedupe={dedupe_key}"
                )
        superseded_count = self.store.supersede_signal_items(
            [
                item_id
                for item_id in planner_run.consumed_item_ids
                if item_id not in planned_item_ids
            ],
            planner_run_id=run_id,
        )
        consumed_count = planned_item_count + superseded_count
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
                "run_id": planner_run.run_id,
                "prompt_path": (
                    str(planner_run.prompt_path) if planner_run.prompt_path else None
                ),
                "transcript_path": str(planner_run.transcript_path),
                "thread_id": planner_run.thread_id,
                "diagnostics": planner_run.diagnostics,
            },
        )

    def run_forever(self) -> None:
        self.startup_reconcile()
        self.start_task_sync()
        self._start_public_mirror_sync()
        with self._worker_pool_lock:
            if self._worker_pool is None:
                self._worker_pool = concurrent.futures.ThreadPoolExecutor(
                    max_workers=max(1, self.config.limits.max_active_tasks),
                    thread_name_prefix="steward-task",
                )
        try:
            while not self._shutdown_event.is_set():
                try:
                    trigger = wait_for_scheduler_event(
                        self.config, self.store, stop_event=self._shutdown_event
                    )
                except TypeError as exc:
                    if "stop_event" not in str(exc):
                        raise
                    trigger = wait_for_scheduler_event(self.config, self.store)
                if self._shutdown_event.is_set():
                    break
                self.run_cycle(
                    fetch_providers=trigger.providers,
                    max_dispatch=self.config.limits.max_active_tasks,
                    reason=trigger.reason,
                )
        finally:
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

    def _touch_heartbeat(self) -> None:
        with self._runtime_lock:
            self.runtime.heartbeat_at = utc_now()

    def _runtime_snapshot(self) -> DaemonRuntime:
        with self._runtime_lock:
            return self.runtime.model_copy(deep=True)

    def _heartbeat_interval_seconds(self) -> int:
        with self._runtime_lock:
            return self.runtime.heartbeat_interval_seconds

    def _start_public_mirror_sync(self) -> None:
        if not self.config.public_mirror.enabled:
            return
        with self._public_mirror_thread_lock:
            if self._public_mirror_thread is not None or self._public_mirror_stopping:
                return
            self._public_mirror_stop.clear()
            self._public_mirror_dirty.set()
            thread = threading.Thread(
                target=self._run_public_mirror_sync,
                name="steward-public-mirror",
                daemon=True,
            )
            self._public_mirror_thread = thread
            thread.start()

    def _stop_public_mirror_sync(self) -> None:
        with self._runtime_lock:
            self.runtime.heartbeat_at = utc_now()
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.current_cycle_started_at = None
            self.runtime.current_cycle_reason = None
        with self._public_mirror_thread_lock:
            thread = self._public_mirror_thread
            if thread is None:
                return
            self._public_mirror_stopping = True
            self._public_mirror_stop.set()
            self._public_mirror_dirty.set()
        thread.join()
        try:
            needs_final_publish = (
                self._public_mirror_remote_digest
                != self._public_mirror_local_digest
                or self._public_mirror_health.state
                in {
                    PublicMirrorPublishState.pending,
                    PublicMirrorPublishState.failed,
                }
            )
            if needs_final_publish:
                self._update_public_mirror_if_changed(publish=True)
        finally:
            with self._public_mirror_thread_lock:
                if self._public_mirror_thread is thread:
                    self._public_mirror_thread = None
                self._public_mirror_stopping = False

    def _run_public_mirror_sync(self) -> None:
        while True:
            dirty = self._public_mirror_dirty.wait(
                timeout=self._heartbeat_interval_seconds()
            )
            self._touch_heartbeat()
            stopping = self._public_mirror_stop.is_set()
            if not stopping and dirty and self._public_mirror_stop.wait(
                PUBLIC_MIRROR_DEBOUNCE_SECONDS
            ):
                stopping = True
            self._public_mirror_dirty.clear()
            synced = self._update_public_mirror_if_changed(publish=True)
            if stopping or self._public_mirror_stop.is_set():
                with self._public_mirror_thread_lock:
                    if self._public_mirror_dirty.is_set():
                        continue
                    if self._public_mirror_thread is threading.current_thread():
                        self._public_mirror_thread = None
                    return
            if synced:
                continue
            if self._public_mirror_stop.wait(self._public_mirror_retry_seconds()):
                self._public_mirror_dirty.set()
                continue
            self._public_mirror_dirty.set()

    def _public_mirror_store_changed(self) -> None:
        with self._public_mirror_thread_lock:
            if self._public_mirror_thread is not None:
                self._public_mirror_dirty.set()
                return
            if self._public_mirror_stopping:
                self._update_public_mirror_if_changed(publish=True)
                return
        self._write_public_mirror_if_changed()

    def _publish_public_mirror_if_changed(self) -> bool:
        with self._public_mirror_thread_lock:
            if self._public_mirror_thread is not None:
                self._public_mirror_dirty.set()
                return True
        return self._update_public_mirror_if_changed(publish=True)

    def _write_public_mirror_if_changed(self) -> bool:
        return self._update_public_mirror_if_changed(publish=False)

    def _update_public_mirror_if_changed(self, *, publish: bool) -> bool:
        if not self.config.public_mirror.enabled:
            return True
        with self._public_mirror_update_lock:
            try:
                should_publish = publish and self.config.public_mirror.publish
                if should_publish:
                    self._record_publish_attempt()
                runtime = self._runtime_snapshot()
                health = self._public_mirror_health.model_copy(deep=True)
                path, result = publish_public_mirror(
                    self.config,
                    self.store,
                    runtime=runtime,
                    publication=health,
                    publish=should_publish,
                )
                if result is not None and not result.ok:
                    category = classify_publish_failure(result)
                    self._record_publish_failure(category)
                    status_path = write_public_mirror_status(
                        self.config,
                        self.store,
                        runtime=runtime,
                        publication=self._public_mirror_health.model_copy(
                            deep=True
                        ),
                    )
                    self._public_mirror_local_digest = sha256(
                        status_path.read_bytes()
                    ).hexdigest()
                    self._log(f"public mirror publish failed category={category}")
                    return False
                status_path = write_public_mirror_status(
                    self.config,
                    self.store,
                    runtime=runtime,
                    publication=health,
                )
                digest = sha256(status_path.read_bytes()).hexdigest()
                self._public_mirror_local_digest = digest
                if result is not None:
                    self._record_publish_success(digest)
                    write_public_mirror_status(
                        self.config,
                        self.store,
                        runtime=runtime,
                        publication=self._public_mirror_health.model_copy(
                            deep=True
                        ),
                    )
                    self._public_mirror_remote_digest = digest
                    self._log(f"public mirror published path={path}")
                else:
                    self._log(f"public mirror written path={path}")
                return True
            except Exception as exc:  # pragma: no cover - daemon boundary guard.
                self._log(f"public mirror publish failed error={exc}")
                return False

    def _record_publish_attempt(self) -> None:
        now = utc_now()
        self._public_mirror_health.last_attempt_at = now
        self._public_mirror_health.state = PublicMirrorPublishState.pending

    def _record_publish_failure(self, category: PublicMirrorFailureCategory) -> None:
        health = self._public_mirror_health
        health.state = PublicMirrorPublishState.failed
        health.last_failure_at = utc_now()
        health.last_failure_category = category
        health.retry_count = min(10, health.retry_count + 1)

    def _record_publish_success(self, digest: str) -> None:
        health = self._public_mirror_health
        health.state = PublicMirrorPublishState.published
        health.last_success_at = utc_now()
        health.last_failure_at = None
        health.last_failure_category = None
        health.retry_count = 0
        health.last_accepted_digest = digest
        health.snapshot_id = digest

    def _public_mirror_retry_seconds(self) -> float:
        retry_count = self._public_mirror_health.retry_count
        initial = self.config.public_mirror.retry_initial_seconds
        if PUBLIC_MIRROR_RETRY_SECONDS != 30.0:
            initial = min(initial, PUBLIC_MIRROR_RETRY_SECONDS)
        maximum = self.config.public_mirror.retry_max_seconds
        return min(maximum, initial * (2 ** max(0, retry_count - 1)))


def stale_task_minutes(config: StewardConfig) -> int:
    if config.limits.stale_task_minutes is not None:
        return config.limits.stale_task_minutes
    return config.limits.worker_timeout_minutes + 5


def status_stale_minutes(config: StewardConfig) -> dict[str, int]:
    if config.limits.stale_task_minutes is not None:
        return {}
    return {
        TaskStatus.reviewing.value: config.limits.review_timeout_minutes + 5,
        TaskPhase.implementation_plan.value: config.limits.plan_timeout_minutes + 5,
        "validation": config.limits.validation_timeout_minutes + 5,
    }


def wait_for_scheduler_event(
    config: StewardConfig,
    store: TaskStore,
    *,
    stop_event: threading.Event | None = None,
) -> SchedulerTrigger:
    while True:
        if stop_event is not None and stop_event.is_set():
            return SchedulerTrigger(reason="stopping", providers=[])
        if store.pending_wakeups(limit=1):
            return SchedulerTrigger(reason="wakeup", providers=[])
        state = scheduler_state(config, store)
        due_providers = [provider.provider for provider in state.providers if provider.due]
        if due_providers:
            return SchedulerTrigger(reason="provider-due", providers=due_providers)
        if store_is_idle_for_signal_fetch(store):
            idle_providers = idle_fetch_provider_names(
                state,
                coalesce_window=timedelta(
                    seconds=config.scheduler_wait_interval_sec
                ),
            )
            if idle_providers:
                return SchedulerTrigger(reason="idle-fetch", providers=idle_providers)
        next_due = min((provider.next_due_at for provider in state.providers), default=None)
        if store_is_idle_for_signal_fetch(store):
            idle_due_at = [
                provider.idle_next_due_at
                for provider in state.providers
                if provider.idle_next_due_at is not None
            ]
            if idle_due_at:
                next_due = min([due for due in (next_due, min(idle_due_at)) if due is not None])
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


def _selected_item_ids(spec, consumed_item_ids: list[str]) -> list[str]:
    metadata = spec.metadata or {}
    selected = metadata.get("selected_signal_item_ids")
    candidates = selected if isinstance(selected, list) else consumed_item_ids
    ids: list[str] = []
    seen: set[str] = set()
    allowed = set(consumed_item_ids)
    for value in candidates:
        if not isinstance(value, str) or value in seen:
            continue
        if allowed and value not in allowed:
            continue
        ids.append(value)
        seen.add(value)
    return ids

from __future__ import annotations

import concurrent.futures
import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from ..core.config import StewardConfig
from ..core.lifecycle import (
    DaemonLifecycleState,
    DockerResourceManager,
    ResourcePressureController,
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
    PipelineCursorPhase,
    ResourcePressureState,
    SignalFetchStatus,
    SignalItem,
    TaskRecord,
    TaskStatus,
    utc_now,
    WorkerKind,
)
from ..execution.executor import StewardExecutor
from ..execution.container import bind_deployment_identity, deployment_runtime_factory
from ..execution.session import (
    FreshPlannerSession,
    InvocationStatus,
    ResumeCategory,
    SessionResult,
    SessionSupervisor,
    enqueue_materialized_publication,
    load_publication_snapshot,
    publication_graph_for_task,
    runtime_factory_for_config,
    planner_session_for_config,
)
from ..execution.task_archive import TaskArchiveWriter
from ..publication.d1 import D1PublicationClient
from ..publication.publisher import CloudPublisher
from ..publication.r2 import R2Client
from ..core.subprocesses import (
    ProcessGroupCancellationOwner,
    run_command,
    use_subprocess_owner,
)
from ..control_loop import (
    ArchiveConflictError,
    ArchiveError,
    ControlLoopArchive,
    CurrentState,
    Cycle as ControlLoopCycle,
    Epoch,
    PlannerRun as ControlPlannerRun,
    ProposalDisposition as ControlProposalDisposition,
    Wakeup as ControlWakeup,
    new_id as new_control_loop_id,
    timestamp as control_timestamp,
)
from ..planning import PlannerRun as PlanningPlannerRun, run_planner
from ..planning.planner import render_planner_prompt
from ..planning.verifier import summarize_active_tasks
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
from ..dataset_sync import StewardDatasetSynchronizer
from .preflight import PreflightReport, preflight_remote_push, run_preflight

DAEMON_EVENT_TASK_ID = "daemon"
DAEMON_HEARTBEAT_INTERVAL_SECONDS = 30
FINAL_SYNC_SHUTDOWN_TIMEOUT_SECONDS = 5.0
PUBLICATION_RETRY_INTERVAL_SECONDS = 5.0
PUBLICATION_JOIN_TIMEOUT_SECONDS = 1.0


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
        planner_session: FreshPlannerSession | None = None,
    ):
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
        self._sync_thread: threading.Thread | None = None
        self._sync_stop = threading.Event()
        self._sync_wakeup = threading.Event()
        self._sync_lock = threading.Lock()
        self._sync_running = False
        self._sync_final_attempted = False
        self._sync_cycle_count = 0
        self._preflight_report: PreflightReport | None = None
        self._publication_thread: threading.Thread | None = None
        self._publication_stop = threading.Event()
        self._publication_wakeup = threading.Event()
        self._publication_lock = threading.RLock()
        self._publication_previous_callback: Callable[[], None] | None = None
        self._publication_callback: Callable[[], None] | None = None
        self._publication_cancel: Callable[[], None] | None = None
        self._publication_deadline: float | None = None
        self._subprocess_owner = ProcessGroupCancellationOwner("steward-daemon")
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._control_loop_ledger = getattr(store, "control_loop_ledger", None)
        self._control_loop_archive = ControlLoopArchive(config, task_root=config)
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

        initial_pressure_state = ResourcePressureState.normal
        pressure_provider = getattr(store, "get_resource_pressure", None)
        if callable(pressure_provider):
            try:
                persisted_pressure = pressure_provider()
                if persisted_pressure is not None:
                    initial_pressure_state = ResourcePressureState(
                        str(persisted_pressure.get("state"))
                    )
            except (OSError, TypeError, ValueError):
                initial_pressure_state = ResourcePressureState.pressure
        self._resource_pressure = ResourcePressureController(
            config,
            usage_provider=usage_provider,
            initial_state=initial_pressure_state,
        )
        with use_subprocess_owner(self._subprocess_owner):
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
                runtime_factory=deployment_runtime_factory(
                    config, runtime_factory_for_config(config)
                ),
                image_digest=config.task_image_digest,
                codex_identity=config.codex_identity or config.codex_bin,
            )
        self.planner_session = planner_session
        if (
            self.planner_session is None
            and config.task_image_digest
            and not config.local_codex_test_harness
        ):
            self.planner_session = planner_session_for_config(config)
            bind_deployment_identity(self.planner_session.invoker.runtime, config)
        elif self.planner_session is None and config.local_codex_test_harness:
            self.planner_session = FreshPlannerSession(config)
        self.executor = StewardExecutor(
            config,
            store,
            session_supervisor=self.session_supervisor,
        )
        self.runtime = DaemonRuntime(
            heartbeat_interval_seconds=DAEMON_HEARTBEAT_INTERVAL_SECONDS
        )
        self._runtime_lock = threading.Lock()
        # This is a local, bounded check. External integrations are checked
        # only when explicitly enabled; remote push remains the compatibility
        # preflight above for existing callers.
        # ``preflight_remote_push`` above is retained for the existing startup
        # log contract; avoid running the network-facing check a second time.
        with use_subprocess_owner(self._subprocess_owner):
            report = run_preflight(config, store, check_remote_push=False)
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

    @property
    def resource_pressure(self) -> dict[str, Any]:
        return self._resource_pressure.measure().as_dict()

    def admission_allowed(self) -> bool:
        """Return whether a new planner/task claim may be admitted."""

        return self._resource_pressure.admission_allowed()

    def _refresh_resource_pressure(self) -> dict[str, Any]:
        self._reconcile_docker_resources()
        report = self._resource_pressure.measure()
        report_dict = report.as_dict()
        try:
            pending = 0
            for task in self.store.list_tasks(limit=10_000):
                events = self.store.events(task.id, limit=200)
                if any(event.kind == "cleanup_pending" for event in events) and not any(
                    event.kind == "cleanup_complete" for event in events
                ):
                    pending += 1
            report_dict["cleanupPending"] = pending
        except Exception:
            report_dict["cleanupPending"] = None
        recorder = getattr(self.store, "record_resource_pressure", None)
        if callable(recorder):
            try:
                recorder(
                    state=report_dict["state"],
                    home_free_bytes=report_dict.get("homeFreeBytes"),
                    owned_docker_bytes=report_dict.get("ownedBytes"),
                    cleanup_pending_count=int(report_dict.get("cleanupPending") or 0),
                    reason=report_dict.get("reason"),
                )
            except Exception as exc:
                self._log(f"resource pressure health write failed error={exc.__class__.__name__}")
        return report_dict

    def _reconcile_docker_resources(self) -> None:
        if self._docker_resources is None:
            return
        try:
            self._docker_resources.reconcile(self.store, self.config.deployment)
            self._resource_reconciliation_failed = False
        except Exception as exc:
            self._resource_reconciliation_failed = True
            self._log(f"owned Docker reconciliation failed error={exc.__class__.__name__}")

    def _retry_cleanup_pending_tasks(self) -> None:
        """Retry each durable terminal cleanup transaction once per cycle."""

        self.executor.retry_validation_cleanup_pending()
        for task in self.store.list_tasks(limit=10_000):
            if not TaskStatus(task.status).terminal:
                continue
            events = self.store.events(task.id)
            if any(event.kind == "cleanup_pending" for event in events) and not any(
                event.kind == "cleanup_complete" for event in events
            ):
                self.finalize_terminal_task(task.id)

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
            self.executor.retry_validation_cleanup_pending()
            self._reconcile_docker_resources()
            self._startup_reconcile_control_loop()
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
                if (
                    outcome.disposition is ReconciliationDisposition.blocked
                    and _is_identity_conflict(outcome.detail)
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
            if self._control_loop_ledger is not None:
                try:
                    self._control_loop_ledger.record_runtime(
                        "running", {"instanceId": self.runtime.instance_id}
                    )
                    self._control_loop_wakeup.set()
                except Exception as exc:
                    self._log(f"control-loop runtime start lag error={exc.__class__.__name__}")
            self._enqueue_materialized_publications()
            self._start_publication_worker()
            return tuple(outcomes)

    def _startup_reconcile_control_loop(self) -> None:
        """Establish the shared epoch and repair archive lag before dispatch."""

        if self._control_loop_ledger is None:
            return
        try:
            task_epoch = self.config.ensure_epoch()
            archive_epoch = self._control_loop_archive.ensure_task_epoch(task_epoch)
            if archive_epoch.epoch_id != self._control_loop_ledger.epoch_id:
                raise ArchiveConflictError("control-loop and ledger epochs differ")
            self._reconcile_interrupted_planner_runs()
            for run in self._control_loop_ledger.list_planner_runs():
                if run.completed_at is not None and not self._control_loop_archive.verify_planner_run(
                    run.planner_run_id
                ):
                    self._planner_publication_queue[run.planner_run_id] = run
            self._drain_control_loop_once()
        except Exception as exc:
            self._control_loop_ledger.set_planning_blocked(
                True, reason=f"control-loop startup reconciliation: {exc.__class__.__name__}"
            )
            self._log(f"control-loop reconciliation blocked error={exc.__class__.__name__}")

    def _reconcile_interrupted_planner_runs(self) -> None:
        ledger = self._control_loop_ledger
        if ledger is None:
            return
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
        if ledger is None:
            return None
        try:
            state = scheduler_state(self.config, self.store)
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

    def _drain_control_loop_once(self) -> dict[str, Any] | None:
        ledger = self._control_loop_ledger
        if ledger is None:
            return None
        with self._control_loop_lock:
            try:
                result = self._control_loop_archive.reconcile(
                    ledger,
                    current=self._build_control_loop_current(),
                )
            except Exception as exc:
                # A temporary writer failure must not stop task dispatch.  The
                # durable outbox remains pending for the next retry.
                self._log(f"control-loop archive lag error={exc.__class__.__name__}")
                return {"materialized": 0, "conflicts": 0, "error": exc.__class__.__name__}
            for run_id, run in list(self._planner_publication_queue.items()):
                try:
                    artifacts = self._planner_artifacts(run)
                    target = self._control_loop_archive.publish_planner_run(run, artifacts)
                    if self._control_loop_archive.verify_planner_run(run_id):
                        self._planner_publication_queue.pop(run_id, None)
                        self._log(f"planner archive sealed run={run_id} path={target}")
                except ArchiveConflictError as exc:
                    ledger.set_planning_blocked(True, reason="visible planner-run conflict")
                    self._log(f"planner archive blocked run={run_id} error={exc.__class__.__name__}")
                except (OSError, ArchiveError) as exc:
                    self._log(f"planner archive lag run={run_id} error={exc.__class__.__name__}")
            self._control_loop_wakeup.clear()
            return result

    def _start_control_loop_writer(self) -> None:
        if self._control_loop_ledger is None:
            return
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
            self._drain_control_loop_once()
            self._control_loop_wakeup.wait(1.0)

    def _stop_control_loop_writer(self) -> None:
        self._control_loop_stop.set()
        self._control_loop_wakeup.set()
        thread = self._control_loop_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if (
            thread is not None
            and not thread.is_alive()
            and self._control_loop_thread is thread
        ):
            self._control_loop_thread = None

    def _install_publication_change_callback(self) -> None:
        """Wake the publication worker after every committed local mutation."""

        if not getattr(self.config.publication, "enabled", False):
            return
        with self._publication_lock:
            if self._publication_callback is not None:
                return
            previous = getattr(self.store, "on_change", None)

            def on_change() -> None:
                try:
                    if callable(previous):
                        previous()
                finally:
                    self._publication_wakeup.set()

            try:
                self.store.on_change = on_change
            except (AttributeError, TypeError):
                # A narrow fake store may expose no callback slot.  The worker
                # still makes progress through its bounded periodic retry.
                return
            self._publication_previous_callback = previous if callable(previous) else None
            self._publication_callback = on_change

    def _build_publication_publisher(self) -> CloudPublisher:
        """Construct transport clients on the publication worker thread only."""

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
            for client in (r2, d1):
                close = getattr(client, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass
            raise
        lease_seconds = max(1, int(publication.lease_duration_seconds))
        retry_backoff_seconds = max(1, int(publication.retry_backoff_seconds))
        return CloudPublisher(
            self.store,
            r2,
            d1,
            worker_id=f"publication-{self.runtime.instance_id}",
            lease_seconds=lease_seconds,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    def _publication_retry_interval(self) -> float:
        configured = getattr(self.config.publication, "retry_backoff_seconds", None)
        try:
            value = float(configured)
        except (TypeError, ValueError):
            value = PUBLICATION_RETRY_INTERVAL_SECONDS
        return max(0.05, min(PUBLICATION_RETRY_INTERVAL_SECONDS, value))

    def _publication_source(self, generation: object) -> object | None:
        task_id = getattr(generation, "task_id", None)
        run_id = getattr(generation, "run_id", None)
        if not isinstance(task_id, str):
            return None
        try:
            if isinstance(run_id, str):
                snapshot = load_publication_snapshot(self.config, task_id, run_id)
                if snapshot is not None:
                    return snapshot
            task = self.store.get(task_id)
            graph_builder = getattr(self.executor, "_integration_publication_graph", None)
            if callable(graph_builder):
                return graph_builder(task)
            return publication_graph_for_task(self.config, self.store, task)
        except Exception as exc:
            self._log(f"publication source unavailable error={exc.__class__.__name__}")
            return None

    def _publish_next_generation(self, publisher: CloudPublisher) -> bool:
        listing = getattr(self.store, "list_publication_generations", None)
        if not callable(listing):
            listing = getattr(self.store, "list_generations", None)
        if not callable(listing):
            return False
        expire = getattr(self.store, "expire_publication_leases", None)
        if callable(expire):
            try:
                # Recovery is part of every worker cycle, not only startup.
                # The store performs the lease compare-and-set and preserves
                # all receipts while moving expired work to retry_wait.
                expire()
            except Exception as exc:
                self._log(
                    "publication lease reconciliation failed "
                    f"error={exc.__class__.__name__}"
                )
        try:
            generations = listing(
                states={"queued", "retry_wait"},
                limit=1,
            )
        except TypeError:
            generations = listing(limit=1)
        if not generations:
            return False
        generation = generations[0]
        publication_id = getattr(generation, "publication_id", None)
        if not isinstance(publication_id, str):
            return True
        source = self._publication_source(generation)
        try:
            publication = self.config.publication
            compose_kwargs = {
                "credential_sources": tuple(
                    path
                    for path in (
                        getattr(publication, "d1_token_path", None),
                        getattr(publication, "r2_access_key_id_path", None),
                        getattr(publication, "r2_secret_access_key_path", None),
                    )
                    if path is not None
                )
            }
            result = publisher.publish(
                publication_id,
                source=source,
                compose_kwargs=compose_kwargs,
            )
            status = getattr(result, "status", None)
            self._log(
                "publication worker processed "
                f"generation={publication_id} status={status or 'unknown'}"
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
        return str(status) == "exposed"

    def _publication_worker_loop(self) -> None:
        publisher: CloudPublisher | None = None
        clients: tuple[object, object] = ()
        clients_closed = threading.Event()

        def close_clients() -> None:
            if clients_closed.is_set():
                return
            clients_closed.set()
            for name in ("cancel", "close"):
                close_publisher = getattr(publisher, name, None)
                if callable(close_publisher):
                    try:
                        close_publisher()
                    except Exception:
                        pass
                    break
            for client in clients:
                close = getattr(client, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

        try:
            while not self._publication_stop.is_set():
                if publisher is None:
                    try:
                        publisher = self._build_publication_publisher()
                        clients = (
                            getattr(publisher, "r2", None),
                            getattr(publisher, "d1", None),
                        )
                        self._publication_cancel = close_clients
                    except Exception as exc:
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

    def _start_publication_worker(self) -> None:
        """Start the one daemon-owned publication worker when enabled."""

        if not getattr(self.config.publication, "enabled", False):
            return
        self._install_publication_change_callback()
        with self._publication_lock:
            if self._publication_thread is not None and self._publication_thread.is_alive():
                return
            try:
                expire = getattr(self.store, "expire_publication_leases", None)
                if callable(expire):
                    expire()
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

    def _stop_publication_worker(self, *, deadline: float | None = None) -> None:
        self._publication_stop.set()
        self._publication_wakeup.set()
        self._publication_deadline = deadline
        cancel = getattr(self, "_publication_cancel", None)
        if callable(cancel):
            # Closing the daemon-owned clients is the provider cancellation
            # boundary.  The worker still owns final cleanup in its finally.
            try:
                cancel()
            except Exception:
                pass
        thread = self._publication_thread
        if thread is None or thread is threading.current_thread():
            return
        timeout = PUBLICATION_JOIN_TIMEOUT_SECONDS
        if deadline is not None:
            timeout = max(0.0, deadline - time.monotonic())
        thread.join(timeout=timeout)
        if not thread.is_alive() and self._publication_thread is thread:
            self._publication_thread = None
            self._publication_cancel = None

    start_publication_worker = _start_publication_worker
    stop_publication_worker = _stop_publication_worker

    def _enqueue_materialized_publications(self) -> None:
        """Recover completion notifications missed before a daemon restart."""

        if not getattr(self.config.publication, "enabled", False):
            return
        for task in sorted(self.store.list_tasks(limit=10000), key=lambda item: item.id):
            try:
                runs = self.store.list_runs(task.id)
            except (AttributeError, KeyError):
                continue
            for run in runs:
                enqueue_materialized_publication(self.config, self.store, task, run)

    reconcile_startup = startup_reconcile
    reconcile = startup_reconcile

    def _reconcile_task(self, task: TaskRecord) -> ReconciliationOutcome:
        """Reconcile archive, ledger, process, Git, and cleanup identities."""

        events = self.store.events(task.id)
        terminal = TaskStatus(task.status).terminal
        if terminal and any(event.kind == "cleanup_complete" for event in events):
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.unchanged,
                "terminal cleanup already complete",
            )
        if terminal and any(event.kind == "cleanup_pending" for event in events):
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
        try:
            execution = self.store.get_execution(task.id)
            runs = self.store.list_runs(task.id)
        except (AttributeError, KeyError):
            # Rows without the normalized execution ledger retain the legacy
            # stale-task policy and have no 2.0 identities to reconcile here.
            return ReconciliationOutcome(
                task.id,
                ReconciliationDisposition.unchanged,
                "legacy task has no execution ledger",
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
            reconcile_container = getattr(
                self.session_supervisor, "reconcile_container", None
            )
            if callable(reconcile_container):
                try:
                    reconcile_container(task.id, ensure_running=True)
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
                    container_id=getattr(inspection.container, "container_id", None),
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
            if owner is not None and owner not in by_pipeline:
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
                    pipeline=by_pipeline.get(owner) if owner else pipelines[-1],
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
                if self.config.integration_mode == "push-main" and not self.config.local_only:
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
            return None
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
            next_phase = (
                PipelineCursorPhase.push
                if self.config.integration_mode == "push-main"
                and not self.config.local_only
                else PipelineCursorPhase.ready_to_seal
            )
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
        worktree = Path(task.worktree_path) if task.worktree_path else None
        if commit and worktree is not None and worktree.is_dir():
            remote = f"{self.config.git_remote}/{self.config.main_branch}"
            fetched = run_command(
                ["git", "fetch", "--quiet", self.config.git_remote, self.config.main_branch],
                cwd=worktree,
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
        if pushed and self.config.integration_mode == "push-main" and not self.config.local_only:
            remote = f"{self.config.git_remote}/{self.config.main_branch}"
            fetched = run_command(
                ["git", "fetch", "--quiet", self.config.git_remote, self.config.main_branch],
                cwd=worktree,
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
                        max_attempts=self.config.resume_attempt_limit,
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

    def finalize_terminal_task(self, task_id: str) -> bool:
        """Seal immutable evidence, then converge terminal-only cleanup."""

        task = self.store.get(task_id)
        if not TaskStatus(task.status).terminal:
            return False
        events = self.store.events(task.id)
        cleanup_complete = any(event.kind == "cleanup_complete" for event in events)
        if cleanup_complete:
            return True
        pipelines = []
        try:
            pipelines = self.store.list_pipelines(task.id)
        except (AttributeError, KeyError):
            pass
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
        if pipelines and not explicit_terminal:
            self.store.add_event(
                task.id,
                "cleanup_blocked",
                "terminal cleanup requires an explicit pipeline outcome",
            )
            return False
        try:
            if any(str(run.state) == "running" for run in self.store.list_runs(task.id)):
                self.store.add_event(
                    task.id,
                    "cleanup_blocked",
                    "terminal cleanup requires all runs to stop",
                )
                return False
        except (AttributeError, KeyError):
            pass

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
                for pipeline in pipelines:
                    runs = self.store.list_runs(
                        task.id,
                        pipeline_id=pipeline.id,
                    )
                    for run in runs:
                        archive.materialize_run(task.id, pipeline.id, run)
                    archive.materialize_pipeline(
                        task.id,
                        pipeline,
                        runs=runs,
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
        if not any(event.kind == "cleanup_pending" for event in events):
            self.store.add_event(task.id, "cleanup_pending", "terminal manifest verified")
        events = self.store.events(task.id)

        if not any(event.kind == "cleanup.container_removed" for event in events):
            try:
                if self.session_supervisor is not None:
                    remove = getattr(self.session_supervisor, "remove_container", None)
                    if not callable(remove):
                        raise RuntimeError("session boundary has no remove operation")
                    remove(task.id)
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
        self.store.add_event(task.id, "cleanup_complete", "terminal private state removed")
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

    def _enter_stopping(self, *, force: bool) -> None:
        """Persist stopping state after control has left any signal handler."""

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
        if self._control_loop_ledger is not None:
            try:
                self._control_loop_ledger.record_runtime(
                    "stopping",
                    {"instanceId": self.runtime.instance_id, "forced": force},
                )
                self._control_loop_wakeup.set()
            except Exception as exc:
                self._log(f"control-loop runtime stop lag error={exc.__class__.__name__}")
        self._sync_stop.set()
        self._sync_wakeup.set()

    stop = request_shutdown

    def shutdown(self, *, force: bool = False) -> ShutdownResult:
        """Stop workers and owned containers while retaining restart state."""

        self.request_shutdown(force=force)
        force = force or self._force_shutdown_event.is_set()
        self._enter_stopping(force=force)
        self._stop_control_loop_writer()
        self._drain_control_loop_once()
        deadline = time.monotonic() if force else time.monotonic() + float(self.config.shutdown_grace_seconds)
        self._stop_publication_worker(deadline=deadline)
        running_runs: list[tuple[str, str]] = []
        tasks = sorted(self.store.list_tasks(limit=10000), key=lambda item: item.id)
        for task in tasks:
            try:
                running_runs.extend(
                    (task.id, run.id)
                    for run in self.store.list_runs(task.id)
                    if str(run.state) == "running"
                )
            except (AttributeError, KeyError):
                continue
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
                concurrent.futures.wait(forced_futures, timeout=2.0)
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
                timeout=max(0.0, deadline - time.monotonic()) if not force else 2.0,
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
                        timeout=2.0 if force else max(0.0, deadline - time.monotonic())
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
                    concurrent.futures.wait(pending_after_force, timeout=0.25)
        self._subprocess_owner.wait(timeout=0.1 if force else max(0.0, deadline - time.monotonic()))
        self._stop_dataset_sync(
            final=not container_stop_failures,
            deadline=deadline,
        )
        self._stop_heartbeat_thread()
        lifecycle = (
            DaemonLifecycleState.stopping
            if container_stop_failures
            else DaemonLifecycleState.stopped
        )
        with self._runtime_lock:
            self.runtime.lifecycle = lifecycle
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.heartbeat_at = utc_now()
        if hasattr(self.store, "set_daemon_lifecycle"):
            self.store.set_daemon_lifecycle(
                lifecycle.value,
                instance_id=self.runtime.instance_id,
                state={
                    "forced": force,
                    "interrupted_runs": interrupted_runs,
                    "container_stop_failures": len(container_stop_failures),
                },
            )
        return ShutdownResult(
            state=lifecycle,
            forced=force,
            interrupted_runs=interrupted_runs,
            stopped_containers=stopped_container_count,
            final_sync_attempted=self._sync_final_attempted,
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

    def start_dataset_sync(self) -> None:
        """Start immediate and monotonic minute-cadence raw synchronization."""

        if not self.config.dataset_sync.enabled:
            return
        with self._sync_lock:
            if self._sync_thread is not None:
                return
            if hasattr(self.store, "reconcile_interrupted_dataset_sync"):
                self.store.reconcile_interrupted_dataset_sync()
            self._sync_stop.clear()
            self._sync_wakeup.clear()
            self._sync_final_attempted = False
            self._sync_thread = threading.Thread(
                target=self._dataset_sync_loop,
                name="steward-dataset-sync",
                daemon=True,
            )
            self._sync_thread.start()

    _start_dataset_sync = start_dataset_sync

    def _dataset_sync_loop(self) -> None:
        next_due = time.monotonic()
        while not self._sync_stop.is_set():
            wait_for = max(0.0, next_due - time.monotonic())
            if self._sync_stop.wait(wait_for):
                return
            self._run_dataset_sync_cycle()
            # Coalesce missed ticks after a slow cycle instead of queuing work.
            next_due = max(next_due + 60.0, time.monotonic())

    def _run_dataset_sync_cycle(self) -> bool:
        if not self.config.dataset_sync.enabled or self._sync_stop.is_set() and self._sync_final_attempted:
            return False
        with self._sync_lock:
            if self._sync_running:
                return False
            self._sync_running = True
        try:
            sync_config = self.config.dataset_sync.to_dataset_sync_config(
                self.config.tasks_dir, self.config.control_loop_dir
            )
            if sync_config is None:
                return False
            synchronizer = StewardDatasetSynchronizer(
                sync_config,
                self.store,
                cancel_event=self._sync_stop,
            )
            result = synchronizer.run_once()
            self._sync_cycle_count += 1
            self._log(f"dataset sync category={result.category} cycle={self._sync_cycle_count}")
            return bool(result.success)
        except Exception as exc:
            # Transport errors are health-only and must not affect task state.
            self._log(f"dataset sync health error={exc.__class__.__name__}")
            return False
        finally:
            with self._sync_lock:
                self._sync_running = False

    def _public_writers_quiescent(self) -> bool:
        """Return whether task and control-loop public writers are stopped."""

        control_thread = self._control_loop_thread
        if control_thread is not None and control_thread.is_alive():
            return False
        try:
            return (
                self.store.source_active_count() == 0
            )
        except Exception:
            # A missing introspection method is not proof of quiescence.
            return False

    def _stop_dataset_sync(
        self,
        *,
        final: bool = False,
        deadline: float | None = None,
    ) -> None:
        self._sync_stop.set()
        self._sync_wakeup.set()
        thread = self._sync_thread
        if thread is not None and thread is not threading.current_thread():
            join_timeout = min(
                FINAL_SYNC_SHUTDOWN_TIMEOUT_SECONDS,
                float(self.config.dataset_sync.transfer_timeout_seconds)
                if self.config.dataset_sync.enabled
                else FINAL_SYNC_SHUTDOWN_TIMEOUT_SECONDS,
            )
            if deadline is not None:
                join_timeout = min(
                    join_timeout,
                    max(0.0, deadline - time.monotonic()),
                )
            thread.join(timeout=join_timeout)
        periodic_still_running = bool(thread is not None and thread.is_alive())
        with self._sync_lock:
            self._sync_thread = None
        if final and self.config.dataset_sync.enabled and not self._sync_final_attempted:
            self._sync_final_attempted = True
            if periodic_still_running:
                self._log("final dataset sync skipped while cancellation is pending")
                return
            if not self._public_writers_quiescent():
                self._log("final dataset sync skipped while public writers are active")
                return
            final_deadline = time.monotonic() + min(
                FINAL_SYNC_SHUTDOWN_TIMEOUT_SECONDS,
                float(self.config.dataset_sync.transfer_timeout_seconds),
            )
            if deadline is not None:
                final_deadline = min(final_deadline, deadline)
            self._sync_stop.clear()
            final_thread = threading.Thread(
                target=self._run_dataset_sync_cycle,
                name="steward-final-dataset-sync",
                daemon=True,
            )
            final_thread.start()
            final_thread.join(timeout=max(0.0, final_deadline - time.monotonic()))
            self._sync_stop.set()
            if final_thread.is_alive():
                self._log("final dataset sync reached its shutdown deadline")

    stop_dataset_sync = _stop_dataset_sync

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
            self._record_control_loop_wakeups(wakeups)
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
            self._drain_control_loop_once()
        return result

    def _record_control_loop_wakeups(self, wakeups: list[object]) -> None:
        ledger = self._control_loop_ledger
        if ledger is None:
            return
        for wakeup in wakeups:
            try:
                data = getattr(wakeup, "data", {}) or {}
                input_ids = [
                    str(value)
                    for value in data.get("signal_ids", data.get("input_signal_ids", []))
                    if isinstance(value, str)
                ]
                ledger.record_wakeup(
                    ControlWakeup(
                        wakeupId=wakeup.id,
                        reason=wakeup.reason,
                        status="pending",
                        createdAt=wakeup.created_at,
                        inputSignalIds=input_ids,
                    )
                )
            except Exception as exc:
                self._log(f"control-loop wakeup lag id={getattr(wakeup, 'id', '-') } error={exc.__class__.__name__}")
        self._control_loop_wakeup.set()

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
                with use_subprocess_owner(self._subprocess_owner):
                    task_ok = self.executor.run_task(task.id)
            except Exception as exc:  # pragma: no cover - daemon boundary guard.
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
            if task_ok:
                result.dispatched += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=true"
                )
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
        with self._worker_pool_lock:
            for task_id, future in list(self._active_futures.items()):
                if future.done():
                    self._active_futures.pop(task_id, None)
        available = max(0, self.config.limits.max_active_tasks - len(self._active_futures))
        budget = min(capacity, available)
        seen = set(self._active_futures)
        queued = self.store.queued_tasks()
        active = [
            task
            for task in self.store.list_tasks(limit=10000)
            if not TaskStatus(task.status).terminal
            and TaskStatus(task.status) != TaskStatus.queued
        ]
        for task in [*queued, *active]:
            if budget <= 0 or task.id in seen:
                continue
            if _is_integration_manager_task(task):
                if self.store.integration_active_count() > 0:
                    continue
            elif TaskStatus(task.status) == TaskStatus.queued and self.store.source_active_count() >= self.config.limits.max_active_tasks:
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
            serialized = integration or self._task_phase_requires_serialization(task_id)
            if serialized:
                self._integration_lock.acquire()
            try:
                with use_subprocess_owner(self._subprocess_owner):
                    outcome = self.executor.advance_once(task_id)
            except Exception as exc:
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
            status = str(getattr(outcome, "status", ""))
            if status == "interrupted":
                return False
            if status in {"ready_to_seal", "terminal", "blocked", "legacy_terminal"}:
                if (
                    status in {"ready_to_seal", "blocked", "legacy_terminal"}
                    and not self._shutdown_event.is_set()
                ):
                    self.finalize_terminal_task(task_id)
                return status in {"ready_to_seal", "terminal", "legacy_terminal"}
            if status == "in_progress":
                self._shutdown_event.wait(0.05)
                continue
            if not getattr(outcome, "progressed", False) and getattr(outcome, "next_phase", None) is None:
                return False
        return False

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

    def _stop_heartbeat_thread(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._heartbeat_thread = None

    def _task_phase_requires_serialization(self, task_id: str) -> bool:
        """Serialize integration, commit, and push actions across source tasks."""

        try:
            execution = self.store.get_execution(task_id)
            pipeline_id = getattr(execution, "owning_pipeline_id", None)
            if pipeline_id is None:
                return False
            cursor = getattr(self.executor, "_pipeline_cursor", None)
            if callable(cursor):
                phase = cursor(task_id, pipeline_id)
            else:
                phase = getattr(self.store.get_pipeline(pipeline_id), "phase", None)
            value = getattr(phase, "value", phase)
            return str(value) in {
                PipelineCursorPhase.integration.value,
                PipelineCursorPhase.commit.value,
                PipelineCursorPhase.push.value,
            }
        except (AttributeError, KeyError, IndexError, TypeError, ValueError):
            return False

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
            ingest = getattr(self.store, "ingest_signal_collection", None)
            if callable(ingest):
                provider_config = self.config.signal_providers.get(collection.provider)
                ingested = ingest(
                    fetch_run,
                    collection.items,
                    suppression_hours=(
                        provider_config.suppression_hours if provider_config else 24
                    ),
                )
                if isinstance(ingested, tuple) and len(ingested) == 3:
                    saved_items, _signals, created_items = ingested
                    fetch_run = fetch_run.model_copy(
                        update={"item_count": len(saved_items), "new_item_count": created_items}
                    )
                else:
                    saved_items, _signals = ingested
                    created_items = sum(
                        1
                        for item in saved_items
                        if getattr(item, "dedupe_result", "new") == "new"
                    )
            else:
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
        if self._active_planner_run_id is None:
            self._reconcile_interrupted_planner_runs()
        if self._control_loop_ledger is not None and self._control_loop_ledger.planning_blocked:
            self._log("planner blocked by control-loop reconciliation conflict")
            return
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
            if self._control_loop_ledger is not None:
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
        control_run_id = new_control_loop_id("planner")
        canonical_signal_ids = self._canonical_signal_ids(inbox_items)
        control_claim = None
        if self._control_loop_ledger is not None:
            try:
                control_claim = self._control_loop_ledger.claim_planner_run(
                    control_run_id,
                    canonical_signal_ids,
                    [task.id for task in task_context if not TaskStatus(task.status).terminal],
                    prompt={
                        "signalIds": canonical_signal_ids,
                        "signalItemIds": [item.id for item in inbox_items],
                        "activeTaskCount": len(task_context),
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
            try:
                planner_run = run_planner(
                    self.config,
                    signals,
                    task_context,
                    invocation=self.planner_session,
                    run_id=control_run_id,
                )
            except TypeError as exc:
                # Preserve simple test doubles from the pre-boundary API. A
                # real invocation TypeError still propagates unchanged.
                if "invocation" not in str(exc) and "run_id" not in str(exc):
                    raise
                planner_run = run_planner(
                    self.config,
                    signals,
                    task_context,
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
        if self._control_loop_ledger is not None and control_claim is not None:
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
                    dedupe_key: _selected_item_ids(
                        spec, planner_run.consumed_item_ids
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
        else:
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
        if ledger is None:
            return []
        values: list[str] = []
        for item in items:
            signal_id = ledger.canonical_signal_id(item.provider, item.fingerprint)
            if signal_id is not None and signal_id not in values:
                values.append(signal_id)
        return values

    def _canonical_ids_for_items(
        self, items: list[SignalItem], item_ids: list[str]
    ) -> list[str]:
        selected = set(item_ids)
        return self._canonical_signal_ids([item for item in items if item.id in selected])

    def _control_loop_dispositions(
        self,
        planner_run,
        planner_run_id: str,
        items: list[SignalItem],
        task_ids_by_dedupe: Mapping[str, str],
    ) -> list[ControlProposalDisposition]:
        item_by_id = {item.id: item for item in items}
        dispositions: list[ControlProposalDisposition] = []
        for ordinal, disposition in enumerate(planner_run.dispositions, 1):
            proposal = getattr(disposition, "proposal", {}) or {}
            dedupe = getattr(disposition, "dedupe_key", None)
            task_id = task_ids_by_dedupe.get(dedupe) if dedupe else None
            signal_ids = self._canonical_ids_for_items(
                items,
                [value for value in getattr(disposition, "signal_ids", []) if value in item_by_id],
            )
            outcome = str(getattr(disposition, "outcome", "invalid"))
            reason_code = str(getattr(disposition, "reason_code", "invalid_output"))
            if outcome in {"accepted", "duplicate"} and task_id is None:
                outcome = "invalid"
                reason_code = "missing_covering_task"
            dispositions.append(
                ControlProposalDisposition(
                    proposalId=f"{planner_run_id}-proposal-{ordinal}",
                    plannerRunId=planner_run_id,
                    ordinal=ordinal,
                    outcome=outcome,
                    reasonCode=reason_code,
                    signalIds=signal_ids,
                    dedupeKey=dedupe,
                    taskId=task_id,
                    proposal=proposal,
                )
            )
        return dispositions

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
        if self._control_loop_ledger is None:
            raise ArchiveError("control-loop ledger is unavailable")
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
        self._start_heartbeat_thread()
        try:
            self.startup_reconcile()
            if self._shutdown_event.is_set():
                return
            self._start_control_loop_writer()
            self.start_dataset_sync()
            with self._worker_pool_lock:
                if self._worker_pool is None:
                    self._worker_pool = concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, self.config.limits.max_active_tasks),
                        thread_name_prefix="steward-task",
                    )
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
        if self._control_loop_ledger is not None:
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
        if self._control_loop_ledger is not None and cycle_id is not None:
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

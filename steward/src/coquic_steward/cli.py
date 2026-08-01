from __future__ import annotations

from pathlib import Path
from typing import Optional
import signal
import json
import os
import re

import typer

from .agents.catalog import AGENTS
from .core.config import load_config
from .orchestration import (
    DaemonAlreadyRunning,
    StewardDaemon,
    StewardPreflightError,
    acquire_daemon_lock,
)
from .execution.executor import StewardExecutor, default_worker_for_kind
from .execution.container import bind_deployment_identity, deployment_runtime_factory
from .execution.session import (
    FreshPlannerSession,
    SessionSupervisor,
    planner_session_for_config,
    publication_graph_for_task,
    runtime_factory_for_config,
)
from .core.models import (
    Priority,
    Risk,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskWorkflow,
    WorkerKind,
    default_workflow_for_kind,
)
from .planning import run_planner
from .control_loop import ControlLoopArchive
from .signals import (
    collect_signal_items,
    project_signals_from_items,
    revalidate_signal_items,
)
from .storage import TaskStore
from .publication.d1 import D1PublicationClient
from .publication.publisher import (
    CloudPublisher,
    PublicationHideStatus,
    PublicationStatus,
    publication_generation_views,
    publication_health_view,
)

app = typer.Typer(help="CoQUIC Steward maintenance manager.")
enqueue_app = typer.Typer(help="Enqueue tasks.")
app.add_typer(enqueue_app, name="enqueue")
publication_app = typer.Typer(help="Inspect and recover publication state.")
app.add_typer(publication_app, name="publication")

_PUBLICATION_LIMIT = 100
_PUBLICATION_HIDE_REASONS = frozenset(
    {
        "missing",
        "partial",
        "invalid_metadata",
        "source_finding",
        "patch_finding",
        "staging_unsafe",
        "scanner_failure",
        "ocr_failure",
        "unsafe_content",
        "irreparable",
        "integrity",
        "operator_blocked",
    }
)
_PUBLICATION_SAFE_REASONS = _PUBLICATION_HIDE_REASONS | frozenset(
    {
        "network",
        "quota",
        "authentication",
        "permission",
        "timeout",
        "transient",
        "provider",
        "lease_expired",
        "retry_exhausted",
        "cleanup_failed",
        "precondition",
        "unchanged",
        "unavailable",
    }
)
_PUBLICATION_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _context() -> tuple[TaskStore, object]:
    config = load_config()
    # A repository with no explicit container section is the historical local
    # CLI fixture. Production launches opt into the strict container boundary.
    if not config.container.enabled and not config.local_codex_test_harness:
        config = config.__class__(
            **{**config.__dict__, "local_codex_test_harness": True}
        )
    return TaskStore(config.db_path), config


def _configured_supervisor(config, store: TaskStore) -> SessionSupervisor | None:
    """Build the production session boundary for a locked task image."""

    if not getattr(config, "task_image_digest", None):
        return None
    return SessionSupervisor(
        config,
        store,
        runtime_factory=deployment_runtime_factory(
            config, runtime_factory_for_config(config)
        ),
        image_digest=config.task_image_digest,
        codex_identity=config.codex_identity or config.codex_bin,
    )


def _configured_planner_session(config) -> FreshPlannerSession:
    """Build the fresh one-shot boundary used by standalone planning."""

    if config.task_image_digest and not config.local_codex_test_harness:
        session = planner_session_for_config(config)
        bind_deployment_identity(session.invoker.runtime, config)
        return session
    return FreshPlannerSession(config)


def _publication_compose_kwargs(config) -> dict[str, object]:
    publication = getattr(config, "publication", None)
    sources = tuple(
        path
        for path in (
            getattr(publication, "d1_token_path", None),
            getattr(publication, "r2_access_key_id_path", None),
            getattr(publication, "r2_secret_access_key_path", None),
        )
        if path is not None
    )
    return {"credential_sources": sources}


def _current_publication_source(config, store: TaskStore, generation: object) -> object | None:
    """Build a fresh graph from current private task evidence."""

    task_id = getattr(generation, "task_id", None)
    if not isinstance(task_id, str) or not task_id:
        return None
    try:
        task = store.get(task_id)
        return publication_graph_for_task(config, store, task)
    except Exception:
        return None


def _build_cli_hide_publisher(config, store: TaskStore) -> tuple[CloudPublisher, object] | None:
    publication = getattr(config, "publication", None)
    if not getattr(publication, "enabled", False):
        return None
    d1: object | None = None
    try:
        d1 = D1PublicationClient(
            config=publication,
            timeout_seconds=float(getattr(publication, "network_timeout_seconds", 30.0)),
        )
        publisher = CloudPublisher(
            store,
            object(),
            d1,
            worker_id="publication-cli",
            retry_backoff_seconds=max(
                1, int(getattr(publication, "retry_backoff_seconds", 1))
            ),
        )
        return publisher, d1
    except Exception:
        close = getattr(d1, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        return None


def _emit_publication(value: object) -> None:
    typer.echo(json.dumps(value, ensure_ascii=True, separators=(",", ":")))


def _safe_publication_id(value: object) -> str | None:
    return value if isinstance(value, str) and _PUBLICATION_IDENTIFIER.fullmatch(value) else None


def _publication_result_output(result: object) -> dict[str, object]:
    status = getattr(result, "status", "blocked")
    if hasattr(status, "value"):
        status = status.value
    if not isinstance(status, str):
        status = "blocked"
    publication_id = getattr(result, "publication_id", None)
    publication_id = _safe_publication_id(publication_id)
    reason = getattr(result, "reason", None)
    if not isinstance(reason, str) or reason not in _PUBLICATION_SAFE_REASONS:
        reason = None
    values = getattr(result, "reason_codes", ())
    reason_codes: list[str] = []
    for value in values if isinstance(values, (tuple, list)) else ():
        if hasattr(value, "value"):
            value = value.value
        if isinstance(value, str) and value in _PUBLICATION_SAFE_REASONS and value not in reason_codes:
            reason_codes.append(value)
    if reason is not None and reason not in reason_codes:
        reason_codes.insert(0, reason)
    return {
        "status": status,
        "publicationId": publication_id,
        "reason": reason,
        "reasonCodes": reason_codes,
    }


def _publication_hide_result_output(result: object) -> dict[str, object]:
    status = getattr(result, "status", "blocked")
    if hasattr(status, "value"):
        status = status.value
    if not isinstance(status, str):
        status = "blocked"
    reason = getattr(result, "reason", None)
    if not isinstance(reason, str) or reason not in _PUBLICATION_SAFE_REASONS:
        reason = None
    return {
        "status": status,
        "taskId": _safe_publication_id(getattr(result, "task_id", None)),
        "publicationId": _safe_publication_id(getattr(result, "publication_id", None)),
        "reason": reason,
    }


@publication_app.command("status")
def publication_status() -> None:
    """Print bounded publication health facts."""

    store, _ = _context()
    try:
        _emit_publication(publication_health_view(store))
    except Exception:
        _emit_publication(
            {
                "queuedCount": 0,
                "blockedCount": 0,
                "cleanupPendingCount": 0,
                "cleanupPendingBytes": 0,
                "oldestQueuedAgeSeconds": 0,
                "updatedAgeSeconds": 0,
                "reason": "unavailable",
                "reasonCodes": ["unavailable"],
            }
        )
        raise typer.Exit(1)


@publication_app.command("list")
def publication_list(
    limit: int = typer.Option(
        20,
        "--limit",
        min=0,
        max=_PUBLICATION_LIMIT,
        help="Maximum generations to show.",
    ),
) -> None:
    """Print bounded publication generation summaries."""

    store, _ = _context()
    try:
        _emit_publication(publication_generation_views(store, limit=limit))
    except Exception:
        _emit_publication(
            {
                "status": "blocked",
                "reason": "unavailable",
                "reasonCodes": ["unavailable"],
            }
        )
        raise typer.Exit(1)


@publication_app.command("retry")
def publication_retry(publication_id: str) -> None:
    """Rebuild current evidence and enqueue a changed generation."""

    store, config = _context()
    try:
        generation = store.get_publication_generation(publication_id)
    except Exception:
        generation = None
    if generation is None:
        _emit_publication(
            {
                "status": PublicationStatus.blocked.value,
                "publicationId": _safe_publication_id(publication_id),
                "reason": "missing",
                "reasonCodes": ["missing"],
            }
        )
        raise typer.Exit(1)
    source = _current_publication_source(config, store, generation)
    publisher = CloudPublisher(
        store,
        object(),
        object(),
        worker_id="publication-cli",
    )
    try:
        result = publisher.retry_publication(
            publication_id,
            source,
            compose_kwargs=_publication_compose_kwargs(config),
        )
    except Exception:
        _emit_publication(
            {
                "status": PublicationStatus.blocked.value,
                "publicationId": _safe_publication_id(publication_id),
                "reason": "integrity",
                "reasonCodes": ["integrity"],
            }
        )
        raise typer.Exit(1)
    _emit_publication(_publication_result_output(result))
    if getattr(result, "status", None) in {
        PublicationStatus.blocked,
        PublicationStatus.repair_required,
    } or getattr(getattr(result, "status", None), "value", None) in {
        PublicationStatus.blocked.value,
        PublicationStatus.repair_required.value,
    }:
        raise typer.Exit(1)


@publication_app.command("hide")
def publication_hide(
    task_id: str,
    reason: str = typer.Option(
        "operator_blocked",
        "--reason",
        help="Allowlisted reason for hiding the task head.",
    ),
) -> None:
    """Hide a task head and reconcile its local publication state."""

    if reason not in _PUBLICATION_HIDE_REASONS:
        raise typer.BadParameter("unsupported reason", param_hint="--reason")
    store, config = _context()
    built = _build_cli_hide_publisher(config, store)
    if built is None:
        _emit_publication(
            {
                "status": PublicationHideStatus.blocked.value,
                "taskId": _safe_publication_id(task_id),
                "publicationId": None,
                "reason": "precondition",
            }
        )
        raise typer.Exit(1)
    publisher, client = built
    try:
        result = publisher.hide_task(task_id, reason)
    except Exception:
        _emit_publication(
            {
                "status": PublicationHideStatus.blocked.value,
                "taskId": _safe_publication_id(task_id),
                "publicationId": None,
                "reason": "integrity",
            }
        )
        raise typer.Exit(1)
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
    payload = _publication_hide_result_output(result)
    _emit_publication(payload)
    if getattr(result, "status", None) in {
        PublicationHideStatus.blocked,
        PublicationHideStatus.missing,
    } or getattr(getattr(result, "status", None), "value", None) in {
        PublicationHideStatus.blocked.value,
        PublicationHideStatus.missing.value,
    }:
        raise typer.Exit(1)


@app.command()
def agents() -> None:
    for agent in AGENTS.values():
        skills = ", ".join(agent.skills) if agent.skills else "-"
        mode = "read-only" if agent.read_only else "write-capable"
        typer.echo(f"{agent.worker}\t{mode}\t{skills}\t{agent.purpose}")


@app.command()
def status(limit: int = typer.Option(20, help="Maximum tasks to show.")) -> None:
    store, _ = _context()
    for task in store.list_tasks(limit=limit):
        typer.echo(
            f"{task.id}\t{task.status}\t{task.spec.workflow}\t"
            f"{task.spec.kind}\t{task.spec.title}"
        )


@app.command()
def run(task_id: str) -> None:
    store, config = _context()
    try:
        with acquire_daemon_lock(config):
            ok = StewardExecutor(
                config,
                store,
                session_supervisor=_configured_supervisor(config, store),
            ).run_task(task_id)
            task = store.get(task_id)
            typer.echo(f"{'ran' if ok else 'failed'} {task.id} status={task.status}")
            if not ok and TaskStatus(task.status) != TaskStatus.blocked:
                raise typer.Exit(1)
    except DaemonAlreadyRunning as exc:
        typer.echo(f"Steward daemon already running: {exc.lock_path}", err=True)
        if exc.owner:
            typer.echo(exc.owner, err=True)
        raise typer.Exit(1) from exc


@app.command()
def daemon(
    once: bool = typer.Option(False, help="Run one tick and exit."),
    no_plan: bool = typer.Option(False, help="Skip signal planning."),
    no_dispatch: bool = typer.Option(False, help="Skip running queued tasks."),
    max_dispatch: int | None = typer.Option(
        None, help="Maximum tasks to run this tick."
    ),
) -> None:
    store, config = _context()
    try:
        with acquire_daemon_lock(config):
            daemon_ = StewardDaemon(config, store, logger=typer.echo)
            if once:
                daemon_.startup_reconcile()
                result = daemon_.tick(
                    plan=not no_plan,
                    dispatch=not no_dispatch,
                    max_dispatch=max_dispatch,
                )
                typer.echo(result)
            else:
                _run_until_stopped(daemon_)
    except DaemonAlreadyRunning as exc:
        typer.echo(f"Steward daemon already running: {exc.lock_path}", err=True)
        if exc.owner:
            typer.echo(exc.owner, err=True)
        raise typer.Exit(1) from exc
    except StewardPreflightError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@app.command()
def plan(enqueue: bool = False) -> None:
    store, config = _context()
    for collection in collect_signal_items(config):
        provider_config = config.signal_providers.get(collection.provider)
        fetch = collection.fetch.model_copy(
            update={"item_count": len(collection.items), "new_item_count": 0}
        )
        store.ingest_signal_collection(
            fetch,
            collection.items,
            suppression_hours=(
                provider_config.suppression_hours if provider_config else 24
            ),
        )
    pending = store.pending_signal_items(limit=config.limits.max_active_tasks)
    actionable, stale_reasons = revalidate_signal_items(config, pending)
    if stale_reasons:
        store.supersede_signal_items(
            list(stale_reasons), planner_run_id="source-revalidation"
        )
    if not actionable:
        return
    planner_run = run_planner(
        config,
        project_signals_from_items(config, actionable),
        store.list_tasks(limit=200),
        invocation=_configured_planner_session(config),
    )
    planned_item_ids: set[str] = set()
    for spec, dedupe_key in planner_run.planned:
        typer.echo(spec.model_dump_json(indent=2))
        if enqueue:
            record, created = store.add_task(spec, dedupe_key=dedupe_key)
            if created:
                selected_item_ids = _selected_item_ids(
                    spec.metadata, planner_run.consumed_item_ids
                )
                store.mark_signal_items_planned(
                    selected_item_ids,
                    planner_run_id=planner_run.run_id or planner_run.thread_id,
                    task_id=record.id,
                )
                planned_item_ids.update(selected_item_ids)
            typer.echo(f"{'enqueued' if created else 'duplicate'} {record.id}")
    if enqueue:
        store.supersede_signal_items(
            [
                item_id
                for item_id in planner_run.consumed_item_ids
                if item_id not in planned_item_ids
            ],
            planner_run_id=planner_run.run_id or planner_run.thread_id,
        )


@app.command()
def timeline(task_id: str, limit: int = 100) -> None:
    store, _ = _context()
    for event in store.events(task_id, limit=limit):
        typer.echo(f"{event.created_at.isoformat()}\t{event.kind}\t{event.message}")


@app.command("fetch-signals")
def fetch_signals(
    provider: list[str] = typer.Option(
        None,
        "--provider",
        "-p",
        help="Signal provider to force-fetch; repeat for multiple providers.",
    ),
) -> None:
    store, config = _context()
    selected = _selected_providers(provider, config.enabled_signals)
    wakeup = store.request_wakeup("signal.fetch", {"providers": selected})
    typer.echo(f"requested {wakeup.id} providers={','.join(selected)}")


@app.command()
def tick(
    plan: bool = typer.Option(
        True,
        "--plan/--no-plan",
        help="Include signal planning in the requested scheduler tick.",
    ),
    dispatch: bool = typer.Option(
        True,
        "--dispatch/--no-dispatch",
        help="Include queued task dispatch in the requested scheduler tick.",
    ),
    max_dispatch: int | None = typer.Option(
        None,
        "--max-dispatch",
        min=1,
        help="Maximum tasks to dispatch in the requested scheduler tick.",
    ),
) -> None:
    store, _ = _context()
    wakeup = store.request_wakeup(
        "scheduler.manual",
        {"plan": plan, "dispatch": dispatch, "max_dispatch": max_dispatch},
    )
    typer.echo(
        f"requested {wakeup.id} "
        f"plan={str(plan).lower()} "
        f"dispatch={str(dispatch).lower()} "
        f"max_dispatch={max_dispatch if max_dispatch is not None else '-'}"
    )


@app.command("audit-invariants")
def audit_invariants() -> None:
    store, _ = _context()
    findings = store.audit()
    if not findings:
        typer.echo("ok")
        return
    for finding in findings:
        typer.echo(finding)
    raise typer.Exit(1)


@app.command()
def diagnostics() -> None:
    """Print bounded local scheduler and raw archive diagnostics."""

    store, config = _context()
    ledger = getattr(store, "control_loop_ledger", None)
    archive = ControlLoopArchive(config, task_root=config)
    visible_runs: list[str] = []
    invalid_runs: list[str] = []
    archive_epoch = None
    try:
        archive_epoch = archive.ensure_task_epoch(config.ensure_epoch())
        if archive.planner_runs_root.exists():
            visible_runs = sorted(
                path.name
                for path in archive.planner_runs_root.iterdir()
                if path.is_dir() and not path.name.startswith(".")
            )
            invalid_runs = [
                run_id for run_id in visible_runs if not archive.verify_planner_run(run_id)
            ]
    except Exception as exc:
        invalid_runs = [f"archive-error:{exc.__class__.__name__}"]
    retry = ledger.pending_retry("planner") if ledger else None
    dataset_health = None
    if hasattr(store, "get_dataset_sync_health"):
        try:
            health = store.get_dataset_sync_health()
            dataset_health = {
                "enabled": health.enabled,
                "active": health.active,
                "activeCycleId": health.active_cycle_id,
                "lastStartedAt": health.last_started_at.isoformat()
                if health.last_started_at is not None
                else None,
                "lastFinishedAt": health.last_finished_at.isoformat()
                if health.last_finished_at is not None
                else None,
                "lastSuccessAt": health.last_success_at.isoformat()
                if health.last_success_at is not None
                else None,
                "lastDurationSeconds": health.last_duration_seconds,
                "lastExitCode": health.last_exit_code,
                "lastCategory": health.last_category,
                "lastDetail": health.last_detail,
                "consecutiveFailureCount": health.consecutive_failure_count,
            }
        except Exception:
            dataset_health = None
    active_run = None
    last_materialized_sequence = None
    last_materialized_at = None
    event_count = 0
    planning_block_reason = None
    if ledger is not None:
        runs = ledger.list_planner_runs(include_terminal=False)
        active_run = runs[-1].planner_run_id if runs else None
        with ledger._connect() as connection:
            event_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM control_loop_events"
                ).fetchone()[0]
            )
            materialized = connection.execute(
                "SELECT sequence,materialized_at FROM control_loop_outbox "
                "WHERE materialized_at IS NOT NULL ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if materialized is not None:
                last_materialized_sequence = int(materialized[0])
                last_materialized_at = materialized[1]
            blocked = connection.execute(
                "SELECT value FROM control_loop_meta WHERE key='planning_block_reason'"
            ).fetchone()
            planning_block_reason = blocked[0] if blocked is not None else None
    payload = {
        "epochId": ledger.epoch_id if ledger is not None else None,
        "archiveFormatVersion": (
            archive_epoch.format_version if archive_epoch is not None else None
        ),
        "taskFormatVersion": (
            archive_epoch.task_format_version if archive_epoch is not None else None
        ),
        "planningBlocked": bool(ledger and ledger.planning_blocked),
        "planningBlockReason": planning_block_reason,
        "ledgerEventCount": event_count,
        "pendingArchiveEvents": len(ledger.outbox(limit=10_000)) if ledger else 0,
        "lastMaterializedSequence": last_materialized_sequence,
        "lastMaterializedAt": last_materialized_at,
        "activePlannerRunId": active_run,
        "plannerRetryAttempt": retry[0] if retry is not None else 0,
        "nextPlannerRetryAt": (
            retry[1].isoformat() if retry is not None and retry[1] is not None else None
        ),
        "archiveConflictCount": len(invalid_runs),
        "visiblePlannerRuns": visible_runs,
        "invalidPlannerRuns": invalid_runs,
        "datasetSync": dataset_health,
    }
    typer.echo(json.dumps(payload, sort_keys=True))


@app.command()
def health() -> None:
    """Return bounded local health facts for Compose and operators."""

    config = load_config()
    active_tasks = 0
    cleanup_pending = 0
    sync_active = False
    planner_active = False
    archive_pending = False
    database_healthy = False
    persisted_pressure: dict[str, object] | None = None
    container_counts = {"owned": 0, "active": 0, "cleanupPending": 0, "unknown": 0}
    try:
        store = TaskStore(config.db_path)
        active_tasks = int(store.active_count())
        for task in store.list_tasks(limit=10_000):
            events = store.events(task.id, limit=200)
            if any(event.kind == "cleanup_pending" for event in events) and not any(
                event.kind == "cleanup_complete" for event in events
            ):
                cleanup_pending += 1
        sync = store.get_dataset_sync_health()
        sync_active = bool(sync.active)
        ledger = getattr(store, "control_loop_ledger", None)
        planner_active = bool(ledger and ledger.list_planner_runs(include_terminal=False))
        archive_pending = bool(ledger and ledger.outbox(limit=1))
        persisted_pressure = store.get_resource_pressure()
        references = store.list_container_references()
        container_counts["owned"] = len(references)
        for reference in references:
            status = str(reference.get("cleanup_status", "active"))
            state = str(reference.get("state", "unknown"))
            if status in {"cleanup_pending", "cleanup_retryable"}:
                container_counts["cleanupPending"] += 1
            elif state in {"running", "created"}:
                container_counts["active"] += 1
            elif state not in {"exited", "dead", "created", "running"}:
                container_counts["unknown"] += 1
        database_healthy = True
    except Exception:
        # Health must remain safe and bounded when the database is unavailable.
        active_tasks = cleanup_pending = 0
        archive_pending = False
    free_bytes = None
    try:
        free_bytes = int(os.statvfs(config.coquic_home).f_bavail * os.statvfs(config.coquic_home).f_frsize)
    except OSError:
        pass
    pressure = (
        str(persisted_pressure.get("state", "resource_pressure"))
        if persisted_pressure is not None
        else "resource_pressure"
    )
    deployment = config.deployment
    if (
        deployment.enabled
        and free_bytes is not None
        and deployment.min_free_bytes is not None
        and free_bytes < deployment.min_free_bytes
    ):
        pressure = "resource_pressure"
    payload = {
        "lifecycle": "running" if database_healthy else "ambiguous",
        "heartbeat": "ok" if database_healthy else "degraded",
        "quiescent": database_healthy
        and not (
            active_tasks
            or cleanup_pending
            or sync_active
            or planner_active
            or archive_pending
        ),
        "activeTasks": active_tasks,
        "cleanupPending": cleanup_pending,
        "syncActive": sync_active,
        "plannerActive": planner_active,
        "archivePending": archive_pending,
        "pressure": pressure,
        "homeFreeBytes": free_bytes,
        "ownedDockerBytes": (
            persisted_pressure.get("owned_docker_bytes")
            if persisted_pressure is not None
            else None
        ),
        "resourceThresholds": {
            "minimumHomeFreeBytes": deployment.min_free_bytes,
            "maximumOwnedDockerBytes": deployment.max_owned_docker_bytes,
            "recoveryHomeFreeBytes": deployment.recovery_free_bytes,
            "recoveryOwnedDockerBytes": deployment.recovery_owned_docker_bytes,
        },
        "containerCounts": container_counts,
        "syncHealth": (
            {
                "active": bool(sync_active),
                "category": getattr(sync, "last_category", None),
                "consecutiveFailures": getattr(sync, "consecutive_failure_count", 0),
            }
            if database_healthy
            else None
        ),
        "release": deployment.release_id,
        "runtimeProtocol": config.runtime_protocol,
    }
    typer.echo(json.dumps(payload, sort_keys=True))
    if not database_healthy:
        raise typer.Exit(code=1)


def _run_until_stopped(daemon_: StewardDaemon) -> None:
    previous: dict[signal.Signals, object] = {}
    signal_count = 0

    def request_stop(signum, _frame) -> None:
        nonlocal signal_count
        signal_count += 1
        daemon_.request_shutdown_from_signal(force=signal_count > 1)

    try:
        for selected in (signal.SIGINT, signal.SIGTERM):
            previous[selected] = signal.getsignal(selected)
            signal.signal(selected, request_stop)
        daemon_.run_forever()
    except KeyboardInterrupt:
        daemon_.request_shutdown()
    finally:
        for selected, handler in previous.items():
            signal.signal(selected, handler)
        if not daemon_.lifecycle_state.value == "stopped":
            daemon_.shutdown(force=signal_count > 1)
        if not daemon_.lifecycle_state.value == "stopped":
            typer.echo(
                "Steward daemon shutdown incomplete; owned containers may still be running.",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo("Steward daemon stopped.")


@enqueue_app.command("code-quality")
def enqueue_code_quality() -> None:
    _enqueue(
        TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="Resolve current code quality findings",
            prompt="Fetch, triage, fix, validate, and re-check current CodeQL and Codacy findings.",
            priority=Priority.high,
            risk=Risk.medium,
            source="manual",
        ),
        "manual:code-quality",
    )


@enqueue_app.command("interop")
def enqueue_interop(run_id: str) -> None:
    _, config = _context()
    _enqueue(
        TaskSpec(
            kind=TaskKind.interop,
            worker=WorkerKind.interop_doctor,
            title=f"Debug failed interop run {run_id}",
            prompt=f"Investigate and fix https://github.com/{config.github_repository}/actions/runs/{run_id}.",
            priority=Priority.high,
            risk=Risk.high,
            source="manual",
            metadata={"run_id": run_id},
        ),
        f"manual:interop:{run_id}",
    )


@enqueue_app.command("custom")
def enqueue_custom(
    title: str,
    prompt_file: Optional[Path] = None,
    prompt: Optional[str] = None,
    kind: TaskKind = TaskKind.custom,
    worker: Optional[WorkerKind] = None,
    workflow: Optional[TaskWorkflow] = None,
) -> None:
    if prompt_file is None and prompt is None:
        raise typer.BadParameter("provide prompt_file or prompt")
    text = (
        prompt_file.read_text(encoding="utf-8")
        if prompt_file is not None
        else prompt or ""
    )
    selected_worker = worker or default_worker_for_kind(kind)
    selected_workflow = workflow or default_workflow_for_kind(kind)
    _enqueue(
        TaskSpec(
            kind=kind,
            workflow=selected_workflow,
            worker=selected_worker,
            title=title,
            prompt=text,
            source="manual",
        ),
        f"manual:custom:{kind}:{selected_worker}:{title}",
    )


def _enqueue(spec: TaskSpec, dedupe_key: str) -> None:
    store, _ = _context()
    record, created = store.add_task(spec, dedupe_key=dedupe_key)
    typer.echo(f"{'enqueued' if created else 'duplicate'} {record.id}")


def _selected_providers(values: list[str] | None, enabled: tuple[str, ...]) -> list[str]:
    if not values:
        return list(enabled)
    enabled_set = set(enabled)
    selected: list[str] = []
    for value in values:
        if value not in enabled_set:
            choices = ", ".join(enabled)
            raise typer.BadParameter(
                f"unknown provider {value!r}; expected one of: {choices}"
            )
        if value not in selected:
            selected.append(value)
    return selected


def _selected_item_ids(
    metadata: dict[str, object], consumed_item_ids: list[str]
) -> list[str]:
    selected = metadata.get("selected_signal_item_ids")
    candidates = selected if isinstance(selected, list) else consumed_item_ids
    allowed = set(consumed_item_ids)
    result: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        if not isinstance(value, str) or value in seen:
            continue
        if allowed and value not in allowed:
            continue
        result.append(value)
        seen.add(value)
    return result


if __name__ == "__main__":
    app()

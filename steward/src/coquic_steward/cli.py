from __future__ import annotations

from pathlib import Path
from typing import Optional

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
from .core.models import Priority, Risk, TaskKind, TaskSpec, TaskStatus, WorkerKind
from .planning import run_planner
from .signals import (
    collect_signal_items,
    project_signals_from_items,
)
from .storage import TaskStore
from .web.runtime import StewardWebRuntime

app = typer.Typer(help="CoQUIC Steward maintenance manager.")
enqueue_app = typer.Typer(help="Enqueue tasks.")
app.add_typer(enqueue_app, name="enqueue")


def _context() -> tuple[TaskStore, object]:
    config = load_config()
    return TaskStore(config.db_path), config


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
        typer.echo(f"{task.id}\t{task.status}\t{task.spec.kind}\t{task.spec.title}")


@app.command()
def run(task_id: str) -> None:
    store, config = _context()
    ok = StewardExecutor(config, store).run_task(task_id)
    task = store.get(task_id)
    typer.echo(f"{'ran' if ok else 'failed'} {task.id} status={task.status}")
    if not ok and TaskStatus(task.status) != TaskStatus.blocked:
        raise typer.Exit(1)


@app.command()
def daemon(
    once: bool = typer.Option(False, help="Run one tick and exit."),
    web_ui: bool = typer.Option(
        True,
        "--web/--no-web",
        help="Launch the loopback API and Next.js dashboard with the daemon.",
    ),
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
                result = daemon_.tick(
                    plan=not no_plan,
                    dispatch=not no_dispatch,
                    max_dispatch=max_dispatch,
                )
                typer.echo(result)
            elif web_ui:
                with StewardWebRuntime(log_dir=config.logs_dir) as runtime:
                    typer.echo(f"Steward API: {runtime.api_url}")
                    typer.echo(f"Steward Web UI: {runtime.ui_url}")
                    _run_until_stopped(daemon_)
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
        saved, created = store.add_signal_items(collection.items)
        store.add_signal_fetch_run(
            collection.fetch.model_copy(
                update={"item_count": len(saved), "new_item_count": created}
            )
        )
    pending = store.pending_signal_items(limit=config.limits.max_active_tasks)
    planner_run = run_planner(
        config,
        project_signals_from_items(config, pending),
        store.list_tasks(limit=200),
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
def web(host: str = "127.0.0.1", port: int = 8765) -> None:
    import uvicorn

    uvicorn.run(
        "coquic_steward.web.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=False,
    )


def _run_until_stopped(daemon_: StewardDaemon) -> None:
    try:
        daemon_.run_forever()
    except KeyboardInterrupt:
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
) -> None:
    if prompt_file is None and prompt is None:
        raise typer.BadParameter("provide prompt_file or prompt")
    text = (
        prompt_file.read_text(encoding="utf-8")
        if prompt_file is not None
        else prompt or ""
    )
    selected_worker = worker or default_worker_for_kind(kind)
    _enqueue(
        TaskSpec(
            kind=kind,
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

from __future__ import annotations

import asyncio
import json
import mimetypes
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)

from ..agents.diagnostics import diagnostics_for_paths
from ..core.config import load_config
from ..core.models import SignalMessageStatus, TaskKind, TaskSpec, WorkerKind
from ..execution import StewardExecutor, default_worker_for_kind
from ..orchestration import (
    DaemonAlreadyRunning,
    StewardDaemon,
    StewardPreflightError,
    acquire_daemon_lock,
)
from ..signals import project_signals_from_messages
from ..storage import TaskStore


TEXT_TAIL_BYTES = 256 * 1024
STREAM_POLL_SECONDS = 1.0
IMAGE_MIME_PREFIX = "image/"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def create_app() -> FastAPI:
    config = load_config()
    store = TaskStore(config.db_path)
    app = FastAPI(title="CoQUIC Steward API")

    _register_state_routes(app, config, store)
    _register_tick_route(app, config, store)
    _register_create_task_route(app, store)
    _register_run_task_route(app, config, store)
    _register_task_detail_routes(app, config, store)
    _register_task_file_route(app, config, store)
    _register_iteration_patch_route(app, config, store)
    _register_run_transcript_route(app, config, store)
    _register_validation_file_route(app, config, store)
    _register_task_asset_routes(app, config, store)
    _register_runtime_routes(app)
    _register_planner_routes(app, config)
    _register_ui_routes(app)

    return app


def _require_loopback(request: Request) -> None:
    if request.client is None or request.client.host not in LOOPBACK_HOSTS:
        raise HTTPException(status_code=403, detail="loopback only")


def _register_state_routes(app: FastAPI, config, store: TaskStore) -> None:

    @app.get("/api/state")
    def state(request: Request) -> JSONResponse:
        _require_loopback(request)
        return JSONResponse(_state_payload(config, store))

    @app.get("/api/stream")
    async def stream(request: Request) -> StreamingResponse:
        _require_loopback(request)

        async def events():
            last = ""
            while True:
                if await request.is_disconnected():
                    break
                payload = _state_payload(config, store)
                text = json.dumps(payload, sort_keys=True)
                if text != last:
                    last = text
                    yield f"event: state\ndata: {text}\n\n"
                await asyncio.sleep(STREAM_POLL_SECONDS)

        return StreamingResponse(events(), media_type="text/event-stream")


def _register_tick_route(app: FastAPI, config, store: TaskStore) -> None:

    @app.post("/api/actions/tick")
    async def tick(request: Request) -> JSONResponse:
        _require_loopback(request)
        body = await _body(request)
        try:
            with acquire_daemon_lock(config):
                result = StewardDaemon(config, store).tick(
                    plan=bool(body.get("plan", True)),
                    dispatch=bool(body.get("dispatch", False)),
                    max_dispatch=_positive_int(body.get("max_dispatch")),
                )
        except DaemonAlreadyRunning as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except StewardPreflightError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return JSONResponse(
            {
                "ok": True,
                "result": result.__dict__,
                "state": _state_payload(config, store),
            }
        )


def _register_create_task_route(app: FastAPI, store: TaskStore) -> None:

    @app.post("/api/tasks")
    async def create_task(request: Request) -> JSONResponse:
        _require_loopback(request)
        body = await _body(request)
        title = str(body.get("title", "")).strip()
        prompt = str(body.get("prompt", "")).strip()
        if not title or not prompt:
            raise HTTPException(status_code=400, detail="title and prompt are required")
        kind = TaskKind(str(body.get("kind", TaskKind.custom.value)))
        worker_value = body.get("worker") or default_worker_for_kind(kind)
        worker = WorkerKind(str(worker_value))
        task, created = store.add_task(
            TaskSpec(
                kind=kind, worker=worker, title=title, prompt=prompt, source="web"
            ),
            dedupe_key=f"web:{kind}:{worker}:{title}:{prompt[:80]}",
        )
        return JSONResponse(
            {"ok": True, "created": created, "task": task.model_dump(mode="json")}
        )


def _register_run_task_route(app: FastAPI, config, store: TaskStore) -> None:

    @app.post("/api/tasks/{task_id}/run")
    def run_task(request: Request, task_id: str) -> JSONResponse:
        _require_loopback(request)
        try:
            with acquire_daemon_lock(config):
                ok = StewardExecutor(config, store).run_task(task_id)
        except DaemonAlreadyRunning as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse(
            {"ok": ok, "task": store.get(task_id).model_dump(mode="json")}
        )


def _register_task_detail_routes(app: FastAPI, config, store: TaskStore) -> None:

    @app.get("/api/tasks/{task_id}")
    def task(request: Request, task_id: str) -> JSONResponse:
        _require_loopback(request)
        try:
            record = store.get(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="task not found") from exc
        return JSONResponse(
            {
                "task": record.model_dump(mode="json"),
                "events": [
                    event.model_dump(mode="json") for event in store.events(task_id)
                ],
                "files": _task_files(config, store, record),
                "attempts": _task_attempts(config, store, record),
                "remote": _task_remote(config, store, task_id),
            }
        )

    @app.get("/api/integrations/{integration_id}")
    def integration(request: Request, integration_id: str) -> JSONResponse:
        _require_loopback(request)
        try:
            record = store.get(integration_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="integration not found") from exc
        if not _is_integration_task(record):
            raise HTTPException(status_code=404, detail="integration not found")
        return JSONResponse(_integration_detail_payload(config, store, record))


def _register_task_file_route(app: FastAPI, config, store: TaskStore) -> None:

    @app.get("/api/tasks/{task_id}/files/{name}", response_class=PlainTextResponse)
    def task_file(request: Request, task_id: str, name: str) -> str:
        _require_loopback(request)
        try:
            record = store.get(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="task not found") from exc
        paths = {
            "transcript": record.transcript_path,
            "integration-transcript": _source_integration_transcript(config, store, task_id),
            "patch": record.patch_path,
            "last-message": record.last_message_path,
            "review-transcript": _latest_task_run_file(
                config.transcripts_dir / task_id, "reviewer-*", "codex.jsonl"
            ),
        }
        path = paths.get(name)
        if path is None or not path.exists():
            raise HTTPException(status_code=404, detail="file not found")
        if not _allowed_debug_file(path, config.state_dir):
            raise HTTPException(status_code=403, detail="file outside steward state")
        return tail_text(path, max_bytes=TEXT_TAIL_BYTES, line_aligned=True)


def _register_iteration_patch_route(app: FastAPI, config, store: TaskStore) -> None:

    @app.get(
        "/api/tasks/{task_id}/iterations/{iteration}/patch",
        response_class=PlainTextResponse,
    )
    def iteration_patch(request: Request, task_id: str, iteration: int) -> str:
        _require_loopback(request)
        try:
            item = store.get_iteration(task_id, iteration)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="iteration not found") from exc
        path = item.patch_path
        if path is None or not path.exists():
            raise HTTPException(status_code=404, detail="iteration patch not found")
        if not _allowed_debug_file(path, config.state_dir):
            raise HTTPException(status_code=403, detail="file outside steward state")
        return tail_text(path, max_bytes=TEXT_TAIL_BYTES, line_aligned=True)


def _register_run_transcript_route(app: FastAPI, config, store: TaskStore) -> None:

    @app.get(
        "/api/tasks/{task_id}/runs/{run_name}/transcript",
        response_class=PlainTextResponse,
    )
    def run_transcript(request: Request, task_id: str, run_name: str) -> str:
        _require_loopback(request)
        try:
            store.get(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="task not found") from exc
        if not _safe_run_name(run_name):
            raise HTTPException(status_code=400, detail="invalid run name")
        path = config.transcripts_dir / task_id / run_name / "codex.jsonl"
        if not path.exists():
            raise HTTPException(status_code=404, detail="run transcript not found")
        if not _allowed_debug_file(path, config.state_dir):
            raise HTTPException(status_code=403, detail="file outside steward state")
        return tail_text(path, max_bytes=TEXT_TAIL_BYTES, line_aligned=True)


def _register_validation_file_route(app: FastAPI, config, store: TaskStore) -> None:

    @app.get(
        "/api/tasks/{task_id}/validations/{index}", response_class=PlainTextResponse
    )
    def validation_file(request: Request, task_id: str, index: int) -> str:
        _require_loopback(request)
        try:
            record = store.get(task_id)
            validation = record.validations[index]
        except (KeyError, IndexError) as exc:
            raise HTTPException(status_code=404, detail="validation not found") from exc
        if not validation.output_path.exists():
            raise HTTPException(status_code=404, detail="validation log not found")
        if not _allowed_debug_file(validation.output_path, config.logs_dir):
            raise HTTPException(
                status_code=403, detail="validation log outside steward logs"
            )
        return tail_text(validation.output_path, max_bytes=TEXT_TAIL_BYTES)


def _register_task_asset_routes(app: FastAPI, config, store: TaskStore) -> None:

    @app.get("/api/tasks/{task_id}/assets")
    def task_asset(request: Request, task_id: str, path: str) -> FileResponse:
        _require_loopback(request)
        try:
            record = store.get(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="task not found") from exc
        asset_path = Path(path)
        if not asset_path.is_absolute():
            if record.worktree_path is None:
                raise HTTPException(status_code=404, detail="asset not found")
            asset_path = record.worktree_path / asset_path
        if not asset_path.exists() or not asset_path.is_file():
            raise HTTPException(status_code=404, detail="asset not found")
        if not _allowed_task_asset(asset_path, record, config.state_dir):
            raise HTTPException(status_code=403, detail="asset outside task scope")
        media_type = mimetypes.guess_type(asset_path.name)[0]
        if media_type is None or not media_type.startswith(IMAGE_MIME_PREFIX):
            raise HTTPException(status_code=415, detail="asset is not an image")
        return FileResponse(asset_path, media_type=media_type)


def _register_runtime_routes(app: FastAPI) -> None:

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.get("/api/runtime")
    def runtime(request: Request) -> JSONResponse:
        _require_loopback(request)
        return JSONResponse(
            {"api": "coquic-steward", "features": ["line-tail", "signal-inbox"]}
        )


def _register_planner_routes(app: FastAPI, config) -> None:

    @app.get("/api/planner/runs")
    def planner_runs(request: Request) -> JSONResponse:
        _require_loopback(request)
        return JSONResponse({"runs": _planner_runs_payload(config, limit=40)})

    @app.get("/api/planner/runs/{run_id}")
    def planner_run(request: Request, run_id: str) -> JSONResponse:
        _require_loopback(request)
        if not _safe_planner_run_id(run_id):
            raise HTTPException(status_code=400, detail="invalid planner run id")
        artifact = _planner_run_artifact_payload(config, run_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="planner run not found")
        return JSONResponse(artifact)


def _register_ui_routes(app: FastAPI) -> None:

    @app.get("/")
    def ui_redirect(request: Request) -> RedirectResponse:
        _require_loopback(request)
        return RedirectResponse("http://127.0.0.1:3000", status_code=307)


def _state_payload(config, store: TaskStore) -> dict[str, object]:
    tasks = store.list_tasks(limit=200)
    inbox = store.list_signal_messages(limit=200)
    items = store.list_signal_items(limit=200)
    pending = [
        message
        for message in inbox
        if str(message.status) == SignalMessageStatus.pending.value
    ]
    signals = project_signals_from_messages(config, pending)
    return {
        "tasks": [task.model_dump(mode="json") for task in tasks],
        "audit": store.audit(),
        "signals": signals.model_dump(mode="json"),
        "signal_inbox": {
            "messages": [message.model_dump(mode="json") for message in inbox],
            "items": [item.model_dump(mode="json") for item in items],
            "fetch_runs": [
                run.model_dump(mode="json")
                for run in store.list_signal_fetch_runs(limit=80)
            ],
        },
        "planned": [],
        "kinds": [kind.value for kind in TaskKind],
        "workers": [worker.value for worker in WorkerKind],
        "projects": _project_payload(config, tasks),
        "integration": _integration_payload(config, store, tasks),
        "config": {
            "repo_root": str(config.repo_root),
            "state_dir": str(config.state_dir),
            "worktrees_dir": str(config.worktrees_dir),
            "integration_mode": config.integration_mode,
            "local_only": config.local_only,
            "main_branch": config.main_branch,
            "github_repository": config.github_repository,
            "enabled_signals": list(config.enabled_signals),
        },
    }


def _project_payload(config, current_tasks) -> list[dict[str, object]]:
    repos_dir = config.steward_home / "repos"
    state_dirs = sorted(path for path in repos_dir.iterdir() if path.is_dir()) if repos_dir.exists() else []
    if config.state_dir not in state_dirs:
        state_dirs.insert(0, config.state_dir)
    projects: list[dict[str, object]] = []
    for state_dir in state_dirs:
        active = state_dir == config.state_dir
        db_path = state_dir / "steward.sqlite"
        task_count = len(current_tasks) if active else _stored_task_count(db_path)
        projects.append(
            {
                "id": state_dir.name,
                "label": config.github_repository if active else state_dir.name,
                "state_dir": str(state_dir),
                "active": active,
                "task_count": task_count,
            }
        )
    return projects


def _integration_payload(config, store: TaskStore, tasks) -> dict[str, object]:
    by_id = {task.id: task for task in tasks}
    integration_tasks = [
        task
        for task in tasks
        if task.spec.kind == TaskKind.integration.value
        or task.spec.worker == "integration-manager"
    ]
    queue_statuses = {"queued", "running", "integrating"}
    queue = []
    active = []
    for task in integration_tasks:
        source_task_id = task.spec.metadata.get("source_task_id")
        source = by_id.get(source_task_id) if isinstance(source_task_id, str) else None
        item = _integration_item(config, store, task, source)
        if task.status in queue_statuses:
            queue.append(item)
        if task.status in {"running", "integrating"}:
            active.append(item)
    source_integrating = [
        task
        for task in tasks
        if task.status == "integrating"
        and not (
            task.spec.kind == TaskKind.integration.value
            or task.spec.worker == "integration-manager"
        )
    ]
    queued_sources = {item.get("source_task_id") for item in queue}
    for task in source_integrating:
        if task.id in queued_sources:
            continue
        queue.append(_source_integration_item(config, store, task))
    commits_by_sha = {}
    for task in tasks:
        remote = _task_remote(config, store, task.id)
        sha = remote["commit"]
        if sha is None:
            continue
        commit = {
            "task_id": task.id,
            "title": task.spec.title,
            "status": str(task.status),
            "summary": task.summary,
            "commit": sha,
            "commit_url": remote["commit_url"],
            "updated_at": task.updated_at.isoformat(),
        }
        existing = commits_by_sha.get(sha)
        if existing is None or (
            _is_integration_task_id(by_id, str(existing["task_id"]))
            and not _is_integration_task(task)
        ):
            commits_by_sha[sha] = commit
    commits = sorted(
        commits_by_sha.values(), key=lambda item: str(item["updated_at"]), reverse=True
    )
    return {"queue": queue, "active": active, "commits": commits}


def _is_integration_task(task) -> bool:
    return (
        task.spec.kind == TaskKind.integration.value
        or task.spec.worker == "integration-manager"
    )


def _is_integration_task_id(tasks_by_id, task_id: str) -> bool:
    task = tasks_by_id.get(task_id)
    return bool(task and _is_integration_task(task))


def _integration_item(config, store: TaskStore, task, source) -> dict[str, object]:
    events = store.events(task.id, limit=40)
    source_remote = _task_remote(config, store, source.id) if source is not None else None
    return {
        "run_id": task.id,
        "task_id": task.id,
        "title": task.spec.title,
        "status": str(task.status),
        "summary": task.summary,
        "source_task_id": source.id if source is not None else task.spec.metadata.get("source_task_id"),
        "source_title": source.spec.title if source is not None else "",
        "source_status": str(source.status) if source is not None else "",
        "source_patch_path": str(source.patch_path) if source and source.patch_path else task.spec.metadata.get("source_patch_path"),
        "patch_path": str(task.patch_path) if task.patch_path else None,
        "transcript_path": str(task.transcript_path) if task.transcript_path else None,
        "worktree_path": str(task.worktree_path) if task.worktree_path else None,
        "updated_at": task.updated_at.isoformat(),
        "remote": source_remote or _task_remote(config, store, task.id),
        "events": [event.model_dump(mode="json") for event in events[-12:]],
    }


def _source_integration_item(config, store: TaskStore, task) -> dict[str, object]:
    queued = next(
        (
            event
            for event in reversed(store.events(task.id))
            if event.kind == "integration.queued"
        ),
        None,
    )
    integration_task_id = (
        queued.data.get("integration_task_id")
        if queued is not None and isinstance(queued.data.get("integration_task_id"), str)
        else None
    )
    return {
        "run_id": integration_task_id or "",
        "task_id": integration_task_id or "",
        "title": "Integration queued",
        "status": "queued" if integration_task_id else str(task.status),
        "summary": task.summary,
        "source_task_id": task.id,
        "source_title": task.spec.title,
        "source_status": str(task.status),
        "source_patch_path": str(task.patch_path) if task.patch_path else None,
        "patch_path": str(task.patch_path) if task.patch_path else None,
        "transcript_path": None,
        "worktree_path": None,
        "updated_at": task.updated_at.isoformat(),
        "remote": _task_remote(config, store, task.id),
        "events": [
            event.model_dump(mode="json")
            for event in store.events(task.id, limit=40)[-12:]
        ],
    }


def _integration_detail_payload(config, store: TaskStore, record) -> dict[str, object]:
    source = _source_task_for_integration(store, record)
    events = store.events(record.id)
    source_events = store.events(source.id) if source is not None else []
    item = _integration_item(config, store, record, source)
    item["events"] = [event.model_dump(mode="json") for event in events]
    return {
        "run": item,
        "source_task": source.model_dump(mode="json") if source is not None else None,
        "events": [event.model_dump(mode="json") for event in events],
        "source_events": [
            event.model_dump(mode="json")
            for event in source_events
            if event.kind.startswith("integration.") or event.kind == "main.pushed"
        ],
        "validations": [
            validation.model_dump(mode="json") | {"index": index}
            for index, validation in enumerate(record.validations)
        ],
        "remote": _task_remote(config, store, record.id),
    }


def _source_task_for_integration(store: TaskStore, record):
    source_task_id = record.spec.metadata.get("source_task_id")
    if not isinstance(source_task_id, str) or not source_task_id:
        return None
    try:
        return store.get(source_task_id)
    except KeyError:
        return None


def _stored_task_count(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    try:
        with sqlite3.connect(db_path) as connection:
            row = connection.execute("select count(*) from tasks").fetchone()
    except sqlite3.Error:
        return 0
    return int(row[0]) if row else 0


def _task_files(config, store: TaskStore, record) -> dict[str, str | None]:
    review_transcript = _latest_task_run_file(
        config.transcripts_dir / record.id, "reviewer-*", "codex.jsonl"
    )
    integration_transcript = _source_integration_transcript(config, store, record.id)
    return {
        "worktree": str(record.worktree_path) if record.worktree_path else None,
        "patch": str(record.patch_path) if record.patch_path else None,
        "transcript": str(record.transcript_path) if record.transcript_path else None,
        "integration_transcript": str(integration_transcript) if integration_transcript else None,
        "last_message": str(record.last_message_path)
        if record.last_message_path
        else None,
        "review_transcript": str(review_transcript) if review_transcript else None,
    }


def _source_integration_transcript(config, store: TaskStore, source_task_id: str) -> Path | None:
    runs = [
        task
        for task in store.list_tasks(limit=400)
        if _is_integration_task(task)
        and task.spec.metadata.get("source_task_id") == source_task_id
        and task.transcript_path is not None
        and task.transcript_path.exists()
    ]
    if not runs:
        return None
    runs.sort(key=lambda task: task.updated_at, reverse=True)
    path = runs[0].transcript_path
    if path is None or not _allowed_debug_file(path, config.state_dir):
        return None
    return path


def _task_remote(config, store: TaskStore, task_id: str) -> dict[str, str | None]:
    pushed = next(
        (event for event in reversed(store.events(task_id)) if event.kind == "main.pushed"),
        None,
    )
    if pushed is None:
        return {"commit": None, "commit_url": None}
    sha = pushed.message.strip()
    if not _safe_sha(sha):
        return {"commit": None, "commit_url": None}
    return {
        "commit": sha,
        "commit_url": f"https://github.com/{config.github_repository}/commit/{sha}",
    }


def _task_attempts(config, store: TaskStore, record) -> list[dict[str, object]]:
    iterations = store.iterations(record.id)
    if iterations:
        return _iteration_attempts(record, iterations)
    task_dir = config.transcripts_dir / record.id
    runs = _task_runs(task_dir)
    validations = [
        validation.model_dump(mode="json") | {"index": index}
        for index, validation in enumerate(record.validations)
    ]
    worker_runs = [run for run in runs if run["role"] == "worker"]
    attempts = [
        _attempt_payload(run, runs, validations, index)
        for index, run in enumerate(worker_runs)
    ]
    assigned = {
        validation["index"]
        for attempt in attempts
        for validation in attempt["validations"]
        if isinstance(validation.get("index"), int)
    }
    unassigned = [
        validation for validation in validations if validation["index"] not in assigned
    ]
    if unassigned or any(run["role"] == "reviewer" for run in runs) and not attempts:
        attempts.append(
            {
                "attempt": len(attempts),
                "label": "Unassigned",
                "worker": None,
                "reviewer": _reviewer_run(runs, len(attempts)),
                "validations": unassigned,
            }
        )
    return attempts


def _iteration_attempts(record, iterations) -> list[dict[str, object]]:
    task_dir = _iteration_task_dir(record, iterations)
    runs = _task_runs(task_dir) if task_dir else []
    validations = [
        validation.model_dump(mode="json") | {"index": index}
        for index, validation in enumerate(record.validations)
    ]
    attempts: list[dict[str, object]] = []
    for item in iterations:
        worker = (
            {
                "name": item.worker_name,
                "role": "worker",
                "attempt": item.iteration,
                "label": item.label,
                "transcript_path": str(item.worker_transcript_path),
                "prompt_path": str(item.worker_prompt_path)
                if item.worker_prompt_path
                else None,
                "last_message_path": str(item.worker_last_message_path)
                if item.worker_last_message_path
                else None,
                "updated_at": item.updated_at.isoformat(),
                "exit_code": item.worker_exit_code,
                "completed": item.worker_completed,
                "diagnostics": diagnostics_for_paths(
                    transcript_path=item.worker_transcript_path,
                    last_message_path=item.worker_last_message_path,
                    exit_code=item.worker_exit_code,
                    completed=item.worker_completed,
                ).model_dump(mode="json"),
            }
            if item.worker_name and item.worker_transcript_path
            else None
        )
        reviewer = (
            {
                "name": item.reviewer_name,
                "role": "reviewer",
                "attempt": item.iteration,
                "review_run": item.reviewer_run or 0,
                "label": f"Reviewer {item.iteration}",
                "transcript_path": str(item.reviewer_transcript_path),
                "prompt_path": str(item.reviewer_prompt_path)
                if item.reviewer_prompt_path
                else None,
                "last_message_path": str(item.reviewer_last_message_path)
                if item.reviewer_last_message_path
                else None,
                "updated_at": item.updated_at.isoformat(),
                "exit_code": item.reviewer_exit_code,
                "completed": item.reviewer_completed,
                "diagnostics": diagnostics_for_paths(
                    transcript_path=item.reviewer_transcript_path,
                    last_message_path=item.reviewer_last_message_path,
                    exit_code=item.reviewer_exit_code,
                    completed=item.reviewer_completed,
                ).model_dump(mode="json"),
            }
            if item.reviewer_name and item.reviewer_transcript_path
            else None
        )
        if reviewer is None and runs:
            reviewer = _reviewer_run(runs, item.iteration)
        attempts.append(
            {
                "attempt": item.iteration,
                "label": item.label,
                "worker": worker,
                "reviewer": reviewer,
                "review": item.review_json,
                "patch_path": str(item.patch_path) if item.patch_path else None,
                "validations": [
                    validation
                    for validation in validations
                    if validation.get("iteration") == item.iteration
                ],
            }
        )
    return attempts


def _iteration_task_dir(record, iterations) -> Path | None:
    if record.transcript_path:
        return record.transcript_path.parent.parent
    for item in iterations:
        for path in (item.worker_transcript_path, item.reviewer_transcript_path):
            if path is not None:
                return path.parent.parent
    return None


def _task_runs(task_dir: Path) -> list[dict[str, object]]:
    runs: list[dict[str, object]] = []
    if not task_dir.exists():
        return runs
    for transcript in task_dir.glob("*/codex.jsonl"):
        run_dir = transcript.parent
        name = run_dir.name
        parsed = _parse_task_run_name(name)
        if parsed is None:
            continue
        prompt = task_dir.parent.parent / "prompts" / task_dir.name / f"{name}.md"
        last_message = run_dir / "last-message.md"
        runs.append(
            {
                "name": name,
                "role": parsed["role"],
                "attempt": parsed["attempt"],
                "review_run": parsed.get("review_run", 0),
                "label": parsed["label"],
                "transcript_path": str(transcript),
                "prompt_path": str(prompt) if prompt.exists() else None,
                "last_message_path": str(last_message)
                if last_message.exists()
                else None,
                "updated_at": _mtime_iso(transcript),
                "diagnostics": diagnostics_for_paths(
                    transcript_path=transcript,
                    last_message_path=last_message,
                ).model_dump(mode="json"),
            }
        )
    return sorted(runs, key=lambda run: (int(run["attempt"]), str(run["role"])))


def _parse_task_run_name(name: str) -> dict[str, object] | None:
    if name == "worker":
        return {"role": "worker", "attempt": 0, "label": "Initial worker"}
    worker_match = re.fullmatch(r"worker-revision-(\d+)", name)
    if worker_match:
        revision = int(worker_match.group(1))
        return {
            "role": "worker",
            "attempt": revision,
            "label": f"Revision {revision}",
        }
    validation_match = re.fullmatch(r"worker-validation-revision-(\d+)", name)
    if validation_match:
        revision = int(validation_match.group(1))
        return {
            "role": "worker",
            "attempt": revision,
            "label": f"Validation revision {revision}",
        }
    reviewer_match = re.fullmatch(r"reviewer-(\d+)", name)
    if reviewer_match:
        attempt = int(reviewer_match.group(1))
        return {
            "role": "reviewer",
            "attempt": attempt,
            "review_run": 0,
            "label": f"Reviewer {attempt}",
        }
    reviewer_retry_match = re.fullmatch(r"reviewer-(\d+)-retry-(\d+)", name)
    if reviewer_retry_match:
        attempt = int(reviewer_retry_match.group(1))
        review_run = int(reviewer_retry_match.group(2))
        return {
            "role": "reviewer",
            "attempt": attempt,
            "review_run": review_run,
            "label": f"Reviewer {attempt} retry {review_run}",
        }
    return None


def _attempt_payload(
    worker: dict[str, object],
    runs: list[dict[str, object]],
    validations: list[dict[str, object]],
    index: int,
) -> dict[str, object]:
    attempt = int(worker["attempt"])
    next_worker = next(
        (
            run
            for run in runs
            if run["role"] == "worker" and int(run["attempt"]) > attempt
        ),
        None,
    )
    return {
        "attempt": attempt,
        "label": worker["label"] if attempt else "Initial attempt",
        "worker": worker,
        "reviewer": _reviewer_run(runs, attempt),
        "validations": _validations_between(
            validations,
            str(worker["updated_at"]),
            str(next_worker["updated_at"]) if next_worker else None,
            index == 0,
        ),
    }


def _reviewer_run(
    runs: list[dict[str, object]], attempt: int
) -> dict[str, object] | None:
    matches = [
        run
        for run in runs
        if run["role"] == "reviewer" and int(run["attempt"]) == attempt
    ]
    return max(
        matches,
        key=lambda run: int(run.get("review_run", 0)),
        default=None,
    )


def _validations_between(
    validations: list[dict[str, object]],
    start: str,
    end: str | None,
    include_unknown_before_start: bool,
) -> list[dict[str, object]]:
    assigned: list[dict[str, object]] = []
    start_time = _parse_iso_datetime(start)
    end_time = _parse_iso_datetime(end) if end else None
    for validation in validations:
        completed = _parse_iso_datetime(str(validation.get("completed_at") or ""))
        if completed is None:
            if include_unknown_before_start:
                assigned.append(validation)
            continue
        after_start = (
            start_time is None or completed >= start_time or include_unknown_before_start
        )
        before_end = end_time is None or completed < end_time
        if after_start and before_end:
            assigned.append(validation)
    return assigned


def _mtime_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _safe_run_name(value: str) -> bool:
    return _parse_task_run_name(value) is not None


def _safe_sha(value: str) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]{7,40}", value) is not None


def _latest_task_run_file(task_dir: Path, run_glob: str, file_name: str) -> Path | None:
    paths = sorted(
        task_dir.glob(f"{run_glob}/{file_name}"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return paths[0] if paths else None


def _planner_runs_payload(config, *, limit: int) -> list[dict[str, object]]:
    run_ids = {
        path.parent.name for path in config.prompts_dir.glob("planner-task-*/planner.md")
    }
    run_ids.update(
        path.parent.parent.name
        for path in config.transcripts_dir.glob("planner-task-*/planner/codex.jsonl")
    )
    runs = []
    for run_id in run_ids:
        prompt_path = config.prompts_dir / run_id / "planner.md"
        transcript_path = config.transcripts_dir / run_id / "planner" / "codex.jsonl"
        if not prompt_path.exists():
            prompt_path = None
        if not transcript_path.exists():
            transcript_path = None
        if prompt_path and not _allowed_debug_file(prompt_path, config.state_dir):
            prompt_path = None
        if transcript_path and not _allowed_debug_file(transcript_path, config.state_dir):
            transcript_path = None
        updated_at = max(
            [
                path.stat().st_mtime
                for path in (prompt_path, transcript_path)
                if path is not None
            ],
            default=0,
        )
        runs.append(
            {
                "run_id": run_id,
                "prompt_path": str(prompt_path) if prompt_path else None,
                "transcript_path": str(transcript_path) if transcript_path else None,
                "prompt_bytes": prompt_path.stat().st_size if prompt_path else 0,
                "transcript_bytes": transcript_path.stat().st_size if transcript_path else 0,
                "diagnostics": diagnostics_for_paths(
                    transcript_path=transcript_path,
                    last_message_path=config.transcripts_dir
                    / run_id
                    / "planner"
                    / "last-message.md",
                ).model_dump(mode="json"),
                "updated_at": datetime.fromtimestamp(updated_at, timezone.utc).isoformat()
                if updated_at
                else None,
                "_sort_key": _planner_run_sort_key(run_id, updated_at),
            }
        )
    runs.sort(key=lambda item: str(item["_sort_key"]), reverse=True)
    return [
        {key: value for key, value in run.items() if key != "_sort_key"}
        for run in runs[:limit]
    ]


def _planner_run_sort_key(run_id: str, updated_at: float) -> str:
    match = re.match(r"planner-task-(\d{14})-", run_id)
    if match:
        return match.group(1)
    return f"{updated_at:020.6f}"


def _planner_run_artifact_payload(config, run_id: str) -> dict[str, object] | None:
    prompt_path = config.prompts_dir / run_id / "planner.md"
    transcript_path = config.transcripts_dir / run_id / "planner" / "codex.jsonl"
    if not prompt_path.exists() and not transcript_path.exists():
        return None
    if prompt_path.exists() and not _allowed_debug_file(prompt_path, config.state_dir):
        prompt_path = None
    if transcript_path.exists() and not _allowed_debug_file(transcript_path, config.state_dir):
        transcript_path = None
    return {
        "run_id": run_id,
        "prompt": (
            tail_text(prompt_path, max_bytes=TEXT_TAIL_BYTES)
            if prompt_path and prompt_path.exists()
            else ""
        ),
        "transcript": (
            tail_text(transcript_path, max_bytes=TEXT_TAIL_BYTES, line_aligned=True)
            if transcript_path and transcript_path.exists()
            else ""
        ),
        "prompt_path": str(prompt_path) if prompt_path else None,
        "transcript_path": str(transcript_path) if transcript_path else None,
        "diagnostics": diagnostics_for_paths(
            transcript_path=transcript_path,
            last_message_path=config.transcripts_dir
            / run_id
            / "planner"
            / "last-message.md",
        ).model_dump(mode="json"),
    }


def _safe_planner_run_id(value: str) -> bool:
    return bool(re.fullmatch(r"planner-task-\d{14}-[0-9a-fA-F]{8}", value))


async def _body(request: Request) -> dict[str, object]:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        payload = await request.json()
        return payload if isinstance(payload, dict) else {}
    raw = (await request.body()).decode("utf-8", errors="replace")
    return {
        key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()
    }


def _positive_int(value: object) -> int | None:
    if value in {None, ""}:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def tail_text(path: Path, *, max_bytes: int, line_aligned: bool = False) -> str:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        start = max(0, size - max_bytes)
        handle.seek(start)
        data = handle.read(max_bytes)
    if line_aligned and start > 0:
        newline = data.find(b"\n")
        if newline >= 0:
            data = data[newline + 1 :]
    return data.decode("utf-8", errors="replace")


def _allowed_debug_file(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        resolved_root = root.resolve()
    except OSError:
        return False
    return resolved == resolved_root or resolved_root in resolved.parents


def _allowed_task_asset(path: Path, record, state_dir: Path) -> bool:
    roots = [state_dir]
    if record.worktree_path is not None:
        roots.append(record.worktree_path)
    return any(_allowed_debug_file(path, root) for root in roots)

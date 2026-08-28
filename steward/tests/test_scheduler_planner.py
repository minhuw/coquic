from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import inspect
import json
import sqlite3
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import threading
from urllib.request import (
    BaseHandler,
    HTTPDefaultErrorHandler,
    HTTPErrorProcessor,
    OpenerDirector,
)

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from coquic_steward.agents.catalog import (
    AGENTS,
    PLANNER_DISPATCH_POLICY,
    REMOTE_WRITE_AUTHORITY,
)
from coquic_steward.cli import app
from coquic_steward.core.config import StewardConfig, StewardLimits, load_config
from coquic_steward.core.models import (
    ProjectSignals,
    SignalFetchRun,
    SchedulerWakeupStatus,
    SignalFetchStatus,
    SignalItem,
    SignalItemStatus,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
    new_signal_fetch_id,
    utc_now,
)
from coquic_steward.core.subprocesses import CommandResult
from coquic_steward.execution import StewardExecutor
from coquic_steward.execution.container import PlannerContainerRuntime, SubprocessDockerClient
from coquic_steward.execution.container_config import PlannerContainerConfig
from coquic_steward.execution.session import (
    ContainerSessionInvoker,
    FreshPlannerSession,
    LocalSessionInvoker,
    _InvocationLaunchGate,
)
from coquic_steward.orchestration import StewardDaemon
from coquic_steward.orchestration.daemon import (
    DAEMON_EVENT_TASK_ID,
    SchedulerTrigger,
    wait_for_scheduler_event,
)
from coquic_steward.planning import PlannerRun, VerifiedPlan
from coquic_steward.planning.verifier import (
    ActiveTaskSummary,
    PlanVerifier,
    selected_signal_item_ids,
)
from coquic_steward.signals import (
    CodacyProvider,
    CodeScanningProvider,
    GitHubActionsCiProvider,
    GitHubActionsInteropProvider,
    GitHubActionsPerfProvider,
    GitHubFeatureIssuesProvider,
    ProviderSignalResult,
    collect_signal_items,
    project_signals_from_items,
    revalidate_signal_items,
)
from coquic_steward.signals.collector import PROVIDER_TYPES
from coquic_steward.storage import TaskStore, due_provider_names, scheduler_state
from coquic_steward.storage.schema import SignalItemRow, TaskRow


def _signals() -> ProjectSignals:
    return ProjectSignals(
        repository="synthetic/repository",
        enabled_signals=["synthetic"],
        items=[
            SignalItem(
                id="signal-item-1",
                provider="synthetic",
                kind="synthetic.alert",
                fingerprint="fingerprint-1",
                title="Synthetic alert",
                summary="A fake signal for planner verification",
            )
        ],
    )


def _proposal(
    dedupe: str,
    *,
    evidence: list[str] | None = None,
    worker: str = "custom",
) -> dict[str, object]:
    return {
        "dedupe_key": dedupe,
        "kind": "custom",
        "worker": worker,
        "title": "Handle synthetic alert",
        "prompt": "Investigate the synthetic alert and add focused validation.",
        "priority": "medium",
        "risk": "low",
        "evidence": evidence or ["signal-item-1"],
        "metadata": {"selected_signal_item_ids": ["signal-item-1"]},
    }




@pytest.mark.parametrize(
    ("metadata", "consumed_item_ids", "expected"),
    [
        (
            {"selected_signal_item_ids": ["item-2", "item-1"]},
            ["item-1", "item-2", "item-3"],
            ["item-2", "item-1"],
        ),
        (
            {"selected_signal_item_ids": "not-a-list"},
            ["item-2", "item-1"],
            ["item-2", "item-1"],
        ),
        ({"other": True}, ["item-2", "item-1"], ["item-2", "item-1"]),
        (
            {"selected_signal_item_ids": ["item-2", 42, "item-1", "item-2", None]},
            [],
            ["item-2", "item-1"],
        ),
        (
            {"selected_signal_item_ids": ["item-3", "item-1", "item-2"]},
            ["item-1", "item-2"],
            ["item-1", "item-2"],
        ),
        (
            {"selected_signal_item_ids": ["item-2", "item-1"]},
            [],
            ["item-2", "item-1"],
        ),
    ],
)
def test_selected_signal_item_ids_normalizes_metadata(
    metadata: dict[str, object], consumed_item_ids: list[str], expected: list[str]
) -> None:
    assert selected_signal_item_ids(metadata, consumed_item_ids) == expected


def test_zero_entry_remote_authority_rejects_remote_workers() -> None:
    assert not REMOTE_WRITE_AUTHORITY
    remote_workers = [
        worker
        for worker, agent in AGENTS.items()
        if worker in PLANNER_DISPATCH_POLICY.workers and agent.remote_writes
    ]
    assert remote_workers

    for ordinal, worker in enumerate(remote_workers):
        item = _proposal(f"remote-{ordinal}", worker=worker.value)
        result = PlanVerifier().verify_plan(
            json.dumps({"tasks": [item]}),
            _signals(),
            [],
        )
        assert result.planned == []
        assert result.consumed_item_ids == []
        assert result.dispositions[0].reason_code == "policy_remote_write_authority"


def test_verifier_preserves_invalid_duplicate_and_capacity_dispositions() -> None:
    verifier = PlanVerifier(max_tasks=1)
    result = verifier.verify_plan(
        __import__("json").dumps(
            {
                "consumed_item_ids": ["signal-item-1"],
                "tasks": [
                    _proposal("dedupe-1"),
                    _proposal("dedupe-1"),
                    _proposal("dedupe-3", evidence=["missing-signal"]),
                ],
            }
        ),
        _signals(),
        [],
        capacity=1,
    )
    assert isinstance(result, VerifiedPlan)
    assert [item.outcome for item in result.dispositions] == [
        "accepted",
        "duplicate",
        "invalid",
    ]
    assert result.dispositions[1].reason_code == "duplicate_dedupe"
    assert result.consumed_item_ids == []


def test_planner_prompt_boundary_contains_current_evidence_only() -> None:
    from coquic_steward.core.config import StewardConfig
    from coquic_steward.planning.planner import render_planner_prompt

    config = StewardConfig(repo_root=Path.cwd())
    prompt = render_planner_prompt(
        _signals(),
        [
            ActiveTaskSummary(
                id="task-active-1",
                kind="custom",
                worker="custom",
                title="Existing task",
                status="queued",
            )
        ],
        config,
    )
    assert "sealed prior planner-runs are read-only" in prompt
    assert "signal-item-1" in prompt
    assert "provider_session_id" not in prompt


@dataclass
class _FakeInvoker(LocalSessionInvoker):
    requests: list[object]

    def __post_init__(self) -> None:
        super().__init__()

    def invoke(
        self,
        request,
        *,
        api_key,
        append,
        observe=None,
        on_started=None,
        timeout_seconds,
        interrupt_grace_seconds,
        launch_gate=None,
    ):
        from coquic_steward.agents.invocation import InvocationOutcome

        self.requests.append(request)
        return InvocationOutcome(
            exit_code=0,
            stdout=b"",
            stderr=b"",
            incomplete_suffix=b"",
            events=(),
            provider_session_id=None,
        )


def test_fresh_planner_session_allocates_distinct_non_resumed_boundaries(config) -> None:
    invoker = _FakeInvoker([])
    session = FreshPlannerSession(config, invoker=invoker)
    first = session.allocate(
        "planner-run-one",
        prompt="synthetic prompt",
        output_last_message=config.private_sessions_dir / "one.md",
    )
    second = session.allocate(
        "planner-run-two",
        prompt="synthetic prompt",
        output_last_message=config.private_sessions_dir / "two.md",
    )
    assert first.session_id != second.session_id
    assert first.home != second.home
    assert first.resumed is False
    assert second.request.provider_session_id is None
    assert first.request.role == "planner"


def test_fresh_planner_session_does_not_launch_after_interrupt(config) -> None:
    invoker = _FakeInvoker([])
    session = FreshPlannerSession(config, invoker=invoker)

    session.interrupt()
    result = session.run("planner-run-interrupted-before-launch", prompt="synthetic prompt")

    assert invoker.requests == []
    assert result.status.value == "interrupted"
    assert result.outcome is not None
    assert result.outcome.interrupted is True
    assert result.prompt_path.read_text(encoding="utf-8") == "synthetic prompt"


def test_launch_gate_defers_same_thread_signal_interrupt_until_publication() -> None:
    interrupted = threading.Event()
    gate = _InvocationLaunchGate(interrupted)
    order: list[str] = []
    previous_handler = signal.signal(
        signal.SIGUSR1,
        lambda _signum, _frame: gate.interrupt(lambda: order.append("interrupt")),
    )

    def launch() -> str:
        order.append("launching")
        signal.raise_signal(signal.SIGUSR1)
        order.append("published")
        return "process"

    try:
        launched, result = gate.launch(launch)
    finally:
        signal.signal(signal.SIGUSR1, previous_handler)

    assert launched is True
    assert result == "process"
    assert interrupted.is_set()
    assert order == ["launching", "published", "interrupt"]


def test_launch_gate_establishes_state_before_interrupt_check() -> None:
    interrupted = threading.Event()
    gate = _InvocationLaunchGate(interrupted)
    order: list[str] = []
    launching_states: list[bool] = []
    armed = True
    source, start_line = inspect.getsourcelines(_InvocationLaunchGate.launch)
    check_line = next(
        start_line + offset
        for offset, line in enumerate(source)
        if line.strip() == "if self._interrupt_requested.is_set():"
    )

    def handle_signal(_signum, _frame) -> None:
        launching_states.append(gate._launching)
        gate.interrupt(lambda: order.append("interrupt"))

    def trace(frame, trace_event, _arg):
        nonlocal armed
        if (
            armed
            and trace_event == "line"
            and frame.f_code is _InvocationLaunchGate.launch.__code__
            and frame.f_lineno == check_line
        ):
            armed = False
            signal.raise_signal(signal.SIGUSR1)
        return trace

    previous_handler = signal.signal(signal.SIGUSR1, handle_signal)
    previous_trace = sys.gettrace()
    sys.settrace(trace)
    try:
        launched, result = gate.launch(lambda: order.append("exec"))
    finally:
        sys.settrace(previous_trace)
        signal.signal(signal.SIGUSR1, previous_handler)

    assert launched is False
    assert result is None
    assert interrupted.is_set()
    assert launching_states == [True]
    assert order == ["interrupt"]


def test_fresh_planner_interrupt_during_container_startup_prevents_exec(config) -> None:
    class BarrierRuntime(PlannerContainerRuntime):
        def __init__(self) -> None:
            roots = {
                "history": config.control_loop_dir / "barrier-history",
                "private": config.private_sessions_dir / "barrier-private",
                "output": config.private_dir / "barrier-output",
            }
            for root in roots.values():
                root.mkdir(parents=True, exist_ok=True)
            super().__init__(
                PlannerContainerConfig(
                    image="coquic-steward-task",
                    image_digest="sha256:" + "a" * 64,
                    history_root=roots["history"],
                    private_root=roots["private"],
                    output_root=roots["output"],
                ),
                client=SubprocessDockerClient(),
            )
            self.entered = threading.Event()
            self.release = threading.Event()
            self.exec_calls = 0

        def ensure_started(self) -> None:
            self.entered.set()
            assert self.release.wait(timeout=2)

        def exec_stream(
            self,
            role,
            *,
            session_uid,
            session_id,
            command,
            env=None,
            workdir=None,
        ):
            self.exec_calls += 1
            raise AssertionError("planner exec launched after interruption")

    runtime = BarrierRuntime()
    session = FreshPlannerSession(config, invoker=ContainerSessionInvoker(runtime))
    results = []
    failures = []

    def run() -> None:
        try:
            results.append(session.run("planner-run-startup-race", prompt="synthetic"))
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert runtime.entered.wait(timeout=2)
        session.interrupt()
    finally:
        runtime.release.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert failures == []
    assert runtime.exec_calls == 0
    assert len(results) == 1
    assert results[0].status.value == "interrupted"
    assert results[0].outcome is not None
    assert results[0].outcome.interrupted is True


def test_cli_plan_uses_fresh_planner_boundary(config, monkeypatch) -> None:
    store = TaskStore.create(config.db_path)
    active_task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="old active planner context",
            prompt="complete old active planner context",
        )
    )
    terminal_tasks = []
    for index in range(205):
        terminal, _ = store.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title=f"terminal planner context {index}",
                prompt="complete terminal planner context",
            )
        )
        store.finish_task(terminal.id, TaskStatus.succeeded, "terminal")
        terminal_tasks.append(terminal)
    item = _signals().items[0]
    store.ingest_signal_collection(
        SignalFetchRun(
            id="fetch-cli-plan",
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
    )
    invocations: list[object] = []
    contexts: list[list[object]] = []

    def fake_planner(_config, _signals, tasks, **kwargs):
        invocations.append(kwargs["invocation"])
        contexts.append(list(tasks))
        return PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.private_dir / "synthetic-cli-plan.jsonl",
            thread_id=None,
        )

    monkeypatch.setattr("coquic_steward.cli._context", lambda: (store, config))
    monkeypatch.setattr("coquic_steward.cli.collect_signal_items", lambda _config: [])
    monkeypatch.setattr(
        "coquic_steward.cli.revalidate_signal_items",
        lambda _config, items: (items, {}),
    )
    monkeypatch.setattr("coquic_steward.cli.run_planner", fake_planner)
    monkeypatch.setattr(
        store,
        "list_tasks",
        lambda **_kwargs: pytest.fail("planner used a capped task listing"),
    )

    result = CliRunner().invoke(app, ["plan"])

    assert result.exit_code == 0
    assert len(invocations) == 1
    assert isinstance(invocations[0], FreshPlannerSession)
    assert len(contexts) == 1
    context = contexts[0]
    assert context[0].id == active_task.id
    assert len(context) == 201
    terminal_context = [
        task for task in context if TaskStatus(task.status).terminal
    ]
    assert len(terminal_context) == 200
    expected_terminal = sorted(
        terminal_tasks,
        key=lambda task: (task.created_at, task.id),
        reverse=True,
    )[:200]
    assert [task.id for task in terminal_context] == [
        task.id for task in expected_terminal
    ]
    assert len({task.id for task in context}) == len(context)


def test_cli_diagnostics_normalizes_task_epoch_and_reports_control_state(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    monkeypatch.setattr("coquic_steward.cli._context", lambda: (store, config))

    result = CliRunner().invoke(app, ["diagnostics"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["archiveFormatVersion"] == "1.0"
    assert payload["taskFormatVersion"] == "1.0"
    assert payload["activePlannerRunId"] is None
    assert payload["plannerRetryAttempt"] == 0
    assert payload["lastMaterializedSequence"] is None
    assert payload["archiveConflictCount"] == 0

def ingest_test_signal(
    store: TaskStore,
    item: SignalItem,
    *,
    suppression_hours: int = 24,
) -> tuple[SignalItem, bool]:
    saved, _signals, created = store.ingest_signal_collection(
        SignalFetchRun(
            id=new_signal_fetch_id(),
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
        suppression_hours=suppression_hours,
    )
    return saved[0], bool(created)

def test_daemon_marks_dispatch_exception_failed(config: StewardConfig, monkeypatch) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree = config.worktrees_dir / task.id
    worktree.mkdir(parents=True)
    task.worktree_path = worktree
    store.save(task)

    def fail_after_start(self, task_id: str) -> bool:
        self.store.start_worker(task_id, "worker started")
        raise RuntimeError("codex stream crashed")

    monkeypatch.setattr(StewardExecutor, "advance_once", fail_after_start)

    result = StewardDaemon(config, store).tick(plan=False, max_dispatch=1)

    saved = store.get(task.id)
    assert result.dispatched == 0
    assert result.skipped == 1
    assert saved.status == TaskStatus.failed
    assert saved.summary == "dispatch failed: codex stream crashed"
    assert not worktree.exists()
    events = store.events(task.id)
    assert any(event.kind == "dispatch.failed" for event in events)
    assert any(event.kind == "worktree.cleaned" for event in events)

def test_daemon_marks_early_dispatch_exception_failed(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fail_before_start(self, _task_id: str) -> bool:
        raise RuntimeError("codex failed before start")

    monkeypatch.setattr(StewardExecutor, "advance_once", fail_before_start)

    result = StewardDaemon(config, store).tick(plan=False, max_dispatch=1)

    saved = store.get(task.id)
    assert result.skipped == 1
    assert saved.status == TaskStatus.failed
    assert saved.summary == "dispatch failed: codex failed before start"
    assert any(event.kind == "dispatch.failed" for event in store.events(task.id))

def test_store_tracks_signal_items_independently(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    item, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="SC2034 in scripts/fuzz-targets.sh:9",
            location={"path": "scripts/fuzz-targets.sh", "line": 9},
            payload={
                "rule_id": "shellcheck_SC2034",
            },
        )
    )
    duplicate, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-duplicate",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="SC2034 in scripts/fuzz-targets.sh:9",
        )
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate.id == item.id
    assert [pending.id for pending in store.pending_signal_items()] == ["wi-codacy-1"]

def test_store_preserves_repository_relative_signal_paths(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    expected_path = "steward/src/coquic_steward/public_mirror.py"
    ingest_test_signal(
        store,
        SignalItem(
            provider="codacy",
            kind="codacy.issue",
            fingerprint="codacy-public-mirror",
            title="Codacy issue",
            location={"path": expected_path, "line": 203},
        )
    )

    reopened = TaskStore.open(config.db_path)

    pending = reopened.pending_signal_items()
    assert len(pending) == 1
    assert pending[0].location == {"path": expected_path, "line": 203}

def test_store_records_scheduler_wakeups_for_actionable_changes(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, created = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    item, item_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy finding",
        )
    )

    assert created
    assert item_created
    wakeups = store.pending_wakeups()
    assert [wakeup.reason for wakeup in wakeups] == [
        "task.created",
        "signal.pending",
    ]
    assert wakeups[0].data["task_id"] == task.id
    assert wakeups[1].data["signal_item_id"] == item.id

    with sqlite3.connect(store.path) as connection:
        control_wakeups = {
            row[0]: row[1:]
            for row in connection.execute(
                "SELECT wakeup_id,reason,status,consumed_at,input_signal_ids_json "
                "FROM control_loop_wakeups"
            )
        }
        assert set(control_wakeups) == {wakeup.id for wakeup in wakeups}
        assert {
            wakeup_id: (reason, status, consumed_at, json.loads(input_ids))
            for wakeup_id, (reason, status, consumed_at, input_ids) in control_wakeups.items()
        } == {
            wakeups[0].id: ("task.created", "pending", None, []),
            wakeups[1].id: ("signal.pending", "pending", None, []),
        }
        assert connection.execute(
            "SELECT COUNT(*) FROM control_loop_events WHERE kind='scheduler.wakeup'"
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT COUNT(*) FROM control_loop_outbox"
        ).fetchone()[0] >= 2

    assert store.consume_wakeups([wakeup.id for wakeup in wakeups]) == 2
    assert store.pending_wakeups() == []
    assert [wakeup.status for wakeup in store.recent_wakeups()] == [
        SchedulerWakeupStatus.consumed,
        SchedulerWakeupStatus.consumed,
    ]
    with sqlite3.connect(store.path) as connection:
        assert [
            row[0]
            for row in connection.execute(
                "SELECT status FROM control_loop_wakeups ORDER BY wakeup_id"
            )
        ] == ["pending", "pending"]

def test_store_suppresses_recent_duplicate_signal_fingerprints(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )

    assert created
    assert not duplicate_created
    assert second.id == first.id
    assert len(store.pending_signal_items()) == 1

@pytest.mark.parametrize(
    "terminal_status",
    [TaskStatus.no_changes, TaskStatus.pushed, TaskStatus.succeeded],
)
def test_store_permanently_suppresses_resolved_planned_signal(
    config: StewardConfig, terminal_status: TaskStatus
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, terminal_status, str(terminal_status))
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        row = session.get(SignalItemRow, first.id)
        assert row is not None
        row.planned_at = old.isoformat()
        row.updated_at = old.isoformat()

    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )

    assert not duplicate_created
    assert second.id == first.id
    assert store.pending_signal_items() == []
    assert [item.id for item in store.list_signal_items()] == [first.id]

def test_store_matches_legacy_workflow_signal_by_run_attempt(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.ci, worker=WorkerKind.ci_doctor, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-ci-legacy",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="legacy-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100"},
        )
    )
    assert created
    with Session(store.engine) as session:
        first_row = session.get(SignalItemRow, first.id)
        assert first_row is not None
        assert first_row.workflow_run_id == "100"
        assert first_row.workflow_run_attempt == 1
        assert json.loads(first_row.payload_json) == {"run_id": "100"}
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.no_changes, "no changes")

    same_attempt, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-ci-stable",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="stable-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100", "run_attempt": 1},
        )
    )
    next_attempt, next_attempt_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-ci-attempt-2",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="attempt-2-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100", "run_attempt": 2},
        )
    )

    assert not duplicate_created
    assert same_attempt.id == first.id
    assert next_attempt_created
    assert next_attempt.id == "wi-ci-attempt-2"
    with Session(store.engine) as session:
        next_row = session.get(SignalItemRow, next_attempt.id)
        assert next_row is not None
        assert next_row.workflow_run_id == "100"
        assert next_row.workflow_run_attempt == 2

@pytest.mark.parametrize(
    ("provider", "payload"),
    [
        ("github-actions:ci", {"run_attempt": 2, "evidence": {"raw": "keep"}}),
        (
            "github-actions:ci",
            {"run_id": None, "run_attempt": 2, "evidence": {"raw": "keep"}},
        ),
        (
            "github-actions:ci",
            {"run_id": 100, "run_attempt": 2, "evidence": {"raw": "keep"}},
        ),
        (
            "codacy",
            {"run_id": "100", "run_attempt": 2, "evidence": {"raw": "keep"}},
        ),
    ],
)
def test_store_keeps_invalid_or_non_workflow_signal_identity_unindexed(
    config: StewardConfig, provider: str, payload: dict[str, object]
) -> None:
    store = TaskStore.create(config.db_path)
    item, created = ingest_test_signal(
        store,
        SignalItem(
            id="identity-case",
            provider=provider,
            kind="signal.test",
            fingerprint=f"identity-{provider}",
            title="Identity case",
            payload=payload,
        )
    )

    assert created
    with Session(store.engine) as session:
        row = session.get(SignalItemRow, item.id)
        assert row is not None
        assert row.workflow_run_id is None
        assert row.workflow_run_attempt is None
        assert json.loads(row.payload_json) == payload

def test_store_matches_workflow_signal_identity_with_one_bounded_query(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="bounded-first",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="bounded-first-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100"},
        )
    )
    assert created

    statements: list[str] = []

    def capture_statement(
        _connection, _cursor, statement, _parameters, _context, _executemany
    ) -> None:
        if "signal_items" in statement.lower():
            statements.append(statement)

    event.listen(store.engine, "before_cursor_execute", capture_statement)
    try:
        duplicate, duplicate_created = ingest_test_signal(
            store,
            SignalItem(
                id="bounded-second",
                provider="github-actions:ci",
                kind="github-actions.ci-failure",
                fingerprint="bounded-second-fingerprint",
                title="CI run 100 failed again",
                payload={"run_id": "100", "run_attempt": 1},
            )
        )
    finally:
        event.remove(store.engine, "before_cursor_execute", capture_statement)

    assert not duplicate_created
    assert duplicate.id == first.id
    signal_queries = [
        statement
        for statement in statements
        if "select" in statement.lower() and "from signal_items" in statement.lower()
    ]
    assert len(signal_queries) == 2
    identity_queries = [
        statement
        for statement in signal_queries
        if (
            "signal_items.workflow_run_id = ?" in statement
            and "signal_items.workflow_run_attempt = ?" in statement
        )
    ]
    assert len(identity_queries) == 1
    assert "limit" in identity_queries[0].lower()
    assert not any(
        "workflow_run_id" not in statement
        and "fingerprint" not in statement
        and "where signal_items.provider" in statement.lower()
        for statement in signal_queries
    )

def test_store_requeues_planned_signal_after_configured_suppression(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=2)
    with Session(store.engine) as session, session.begin():
        row = session.get(SignalItemRow, first.id)
        assert row is not None
        row.planned_at = old.isoformat()
        row.updated_at = old.isoformat()

    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )

    assert duplicate_created
    assert second.id != first.id
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    refreshed = store.list_signal_items(status=SignalItemStatus.planned)[0]
    assert refreshed.id == first.id

def test_store_requeues_failed_planned_signal_after_retry_window(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [signal.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()

    requeued = store.requeue_failed_signal_items()

    assert requeued == 1
    pending = store.pending_signal_items()
    assert [item.id for item in pending] == [signal.id]
    assert pending[0].planned_at is None
    assert pending[0].planner_run_id is None
    assert pending[0].planned_task_id is None

def test_store_preserves_failed_signal_coverage_for_dry_run_task(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path, dry_run=True)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-dry-run-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="dry-run-finding",
            title="Open dry-run finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [signal.id], planner_run_id="planner-dry-run", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()

    assert store.requeue_failed_signal_items() == 1
    assert store.list_signal_items(status=SignalItemStatus.planned) == []
    assert [item.id for item in store.pending_signal_items()] == [signal.id]

def test_store_skips_failed_signal_requeue_with_duplicate_pending(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, first.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )
    assert duplicate_created

    requeued = store.requeue_failed_signal_items()

    assert requeued == 0
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert [item.id for item in planned] == [first.id]

def test_store_skips_failed_signal_requeue_with_duplicate_planned(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    first_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T1", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=first_task.id
    )
    store.finish_task(first_task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, first.id)
        task_row = session.get(TaskRow, first_task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )
    assert duplicate_created
    second_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T2", prompt="P")
    )
    store.mark_signal_items_planned(
        [second.id], planner_run_id="planner-2", task_id=second_task.id
    )

    requeued = store.requeue_failed_signal_items()

    assert requeued == 0
    assert store.pending_signal_items() == []
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert {item.id for item in planned} == {first.id, second.id}

def test_store_requeues_failed_signal_with_stale_terminal_planned_duplicate(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    first_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T1", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=first_task.id
    )
    store.finish_task(first_task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=49)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, first.id)
        task_row = session.get(TaskRow, first_task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )
    assert duplicate_created
    second_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T2", prompt="P")
    )
    store.mark_signal_items_planned(
        [second.id], planner_run_id="planner-2", task_id=second_task.id
    )
    store.finish_task(second_task.id, TaskStatus.failed, "failed")
    retry_at = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, second.id)
        task_row = session.get(TaskRow, second_task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = retry_at.isoformat()
        signal_row.updated_at = retry_at.isoformat()
        task_row.updated_at = retry_at.isoformat()

    requeued = store.requeue_failed_signal_items()

    assert requeued == 1
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert [item.id for item in planned] == [first.id]

def test_store_does_not_requeue_recent_failed_signal(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [signal.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        assert signal_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
    store.finish_task(task.id, TaskStatus.failed, "failed")

    requeued = store.requeue_failed_signal_items()

    assert requeued == 0
    assert store.pending_signal_items() == []
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert [item.id for item in planned] == [signal.id]

def test_store_suppresses_planned_signal_while_task_is_active(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=2)
    with Session(store.engine) as session, session.begin():
        row = session.get(SignalItemRow, first.id)
        assert row is not None
        row.planned_at = old.isoformat()
        row.updated_at = old.isoformat()

    second, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )

    assert not duplicate_created
    assert second.id == first.id
    assert store.pending_signal_items() == []

def test_store_marks_signal_items_planned(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
        ),
    )

    marked = store.mark_signal_items_planned(
        ["wi-codeql-1"], planner_run_id="planner-1", task_id="task-1"
    )

    assert marked == 1
    item = store.list_signal_items()[0]
    assert item.status == SignalItemStatus.planned
    assert item.planner_run_id == "planner-1"
    assert item.planned_task_id == "task-1"
    assert item.planned_at is not None
    assert store.pending_signal_items() == []
    transition = next(
        event
        for event in store.control_loop.list_events()
        if event.kind == "signal.transition"
    )
    assert transition.payload["transition"]["toStatus"] == "planned"

def test_store_supersedes_consumed_signal_items_without_tasks(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
        ),
    )

    superseded = store.supersede_signal_items(
        ["wi-codeql-1"], planner_run_id="planner-1"
    )

    assert superseded == 1
    item = store.list_signal_items()[0]
    assert item.status == SignalItemStatus.superseded
    assert item.planner_run_id == "planner-1"
    assert store.pending_signal_items() == []
    transition = next(
        event
        for event in store.control_loop.list_events()
        if event.kind == "signal.transition"
    )
    assert transition.payload["transition"]["toStatus"] == "superseded"

def test_daemon_supersedes_stale_signals_before_planning(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    signal, _ = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-42",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-42",
            title="CodeQL alert 42",
            payload={"alert_number": 42},
        )
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.revalidate_signal_items",
        lambda _config, _items: ([], {signal.id: "source_not_open"}),
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: pytest.fail("planner should not run for stale signals"),
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.enqueued == 0
    saved = store.list_signal_items()[0]
    assert saved.status == SignalItemStatus.superseded
    assert saved.planner_run_id == "source-revalidation"
    event = next(
        event
        for event in store.events(DAEMON_EVENT_TASK_ID)
        if event.kind == "signals.superseded_stale"
    )
    assert event.data == {
        "count": 1,
        "reasons": {signal.id: "source_not_open"},
    }

def test_daemon_replans_expired_failed_signal_without_refetch(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, _ = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
        ),
    )
    store.mark_signal_items_planned(
        [signal.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
    store.consume_wakeups([wakeup.id for wakeup in store.pending_wakeups()])

    seen_inbox: list[list[str]] = []

    def fake_run_planner(_config, signals, _active, **_kwargs):
        seen_inbox.append([item.id for item in signals.items])
        return PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda *_args, **_kwargs: pytest.fail("signals should not be fetched"),
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        fake_run_planner,
    )

    result = StewardDaemon(config, store).tick(plan=True, dispatch=False)

    assert result.planned == 0
    assert seen_inbox == [[signal.id]]
    assert [item.id for item in store.pending_signal_items()] == [signal.id]
    assert any(
        event.kind == "signals.requeued_failed"
        for event in store.events(DAEMON_EVENT_TASK_ID)
    )
    assert any(
        event.kind == "signal.transition"
        and event.payload["transition"]["toStatus"] == "pending"
        for event in store.control_loop.list_events()
    )

def test_daemon_logs_planner_lifecycle_event(
    config: StewardConfig, monkeypatch, tmp_path: Path
) -> None:
    store = TaskStore.create(config.db_path)
    inbox_item, _ = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="Open CodeQL findings",
            payload={"id": "wi-codeql-1", "provider": "code-scanning", "kind": "codeql-alert"},
        ),
    )

    def fake_run_planner(_config, _signals, _active, **_kwargs):
        assert [item.id for item in _signals.items] == [inbox_item.id]
        return PlannerRun(
            planned=[
                (
                    TaskSpec(
                        kind=TaskKind.code_quality,
                        worker=WorkerKind.code_quality_janitor,
                        title="CodeQL",
                        prompt="Fix current CodeQL alerts.",
                        metadata={"selected_signal_item_ids": [inbox_item.id]},
                    ),
                    "codeql:open",
                )
            ],
            accepted_count=1,
            proposed_count=2,
            completed=True,
            exit_code=0,
            prompt_path=tmp_path / "planner.md",
            transcript_path=tmp_path / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[inbox_item.id],
            run_id="planner-run-1",
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        fake_run_planner,
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.enqueued == 1
    events = store.events(DAEMON_EVENT_TASK_ID)
    assert [event.kind for event in events] == ["planner.started", "planner.finished"]
    assert events[0].message == "planner turn started"
    assert events[0].data["active_task_count"] == 0
    assert events[0].data["inbox_item_ids"] == [inbox_item.id]
    assert events[1].message == "accepted 1 of 2 proposed task(s)"
    assert events[1].data["accepted_count"] == 1
    assert events[1].data["proposed_count"] == 2
    assert events[1].data["completed"] is True
    assert events[1].data["exit_code"] == 0
    assert events[1].data["prompt_path"].endswith("planner.md")
    assert events[1].data["transcript_path"].endswith("codex.jsonl")
    assert events[1].data["thread_id"] is None
    assert events[1].data["consumed_item_ids"] == [inbox_item.id]
    assert events[1].data["consumed_item_count"] == 1
    assert store.list_signal_items()[0].status == SignalItemStatus.planned

def test_daemon_streams_debug_lines_to_logger(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    lines: list[str] = []
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy findings",
        )
    )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda _config, _signals, _active: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id="planner-thread-1",
        ),
    )

    result = StewardDaemon(config, store, logger=lines.append).tick(dispatch=False)

    assert result.enqueued == 0
    assert any("cycle start" in line for line in lines)
    assert any("planner start" in line for line in lines)
    assert any("planner finish" in line for line in lines)
    assert any("verifier=0/0" in line for line in lines)
    assert any("transcript=" in line for line in lines)
    assert any("cycle finish" in line for line in lines)

def test_daemon_replans_after_successful_dispatch(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    queued, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    planned_specs = [
        [],
        [
            (
                TaskSpec(
                    kind=TaskKind.custom,
                    worker=WorkerKind.custom,
                    title="follow-up",
                    prompt="follow-up",
                ),
                "follow-up",
            )
        ],
    ]

    def fake_plan(_config, _signals, _active, **_kwargs):
        planned = planned_specs.pop(0)
        return PlannerRun(
            planned=planned,
            accepted_count=len(planned),
            proposed_count=len(planned),
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
        )

    def fake_advance(task_id: str) -> SimpleNamespace:
        store.update_status(task_id, TaskStatus.succeeded, "done")
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy findings",
        ),
    )
    monkeypatch.setattr("coquic_steward.orchestration.daemon.run_planner", fake_plan)
    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

    result = daemon.tick(plan=True, dispatch=True, max_dispatch=1)

    assert result.dispatched == 1
    assert result.planned == 1
    assert result.enqueued == 1
    assert store.get(queued.id).status == TaskStatus.succeeded

def test_daemon_dispatches_newly_queued_integration_continuation(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=1, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_advance(task_id: str) -> SimpleNamespace:
        task = store.get(task_id)
        if task.spec.worker == WorkerKind.integration_manager:
            store.finish_task(task.id, TaskStatus.succeeded, "integrated")
            store.finish_task(source.id, TaskStatus.succeeded, "integrated")
            return SimpleNamespace(status="terminal", progressed=True, next_phase=None)
        integration, _ = store.add_task(
            TaskSpec(
                kind=TaskKind.integration,
                worker=WorkerKind.integration_manager,
                title="integrate",
                prompt="integrate",
                metadata={"source_task_id": source.id},
            ),
            dedupe_key=f"integration:{source.id}",
        )
        store.start_integration(source.id, f"integration queued: {integration.id}")
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

    result = daemon.tick(plan=False, dispatch=True)

    integration_tasks = [
        task
        for task in store.list_tasks()
        if task.spec.worker == WorkerKind.integration_manager
    ]
    assert result.dispatched == 2
    assert len(integration_tasks) == 1
    assert integration_tasks[0].status == TaskStatus.succeeded
    assert store.get(source.id).status == TaskStatus.succeeded

def test_daemon_dispatch_exception_preserves_terminal_task_status(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_advance(task_id: str) -> SimpleNamespace:
        store.finish_task(task_id, TaskStatus.blocked, "blocked before crash")
        raise RuntimeError("after terminal update")

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

    result = daemon.tick(plan=False, dispatch=True)
    saved = store.get(task.id)

    assert result.skipped == 1
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "blocked before crash"
    assert any(event.kind == "dispatch.failed" for event in store.events(task.id))

def test_daemon_dispatch_skips_full_integration_lane_for_source_capacity(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=1, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    active_integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="active integration",
            prompt="integrate",
        )
    )
    store.update_status(active_integration.id, TaskStatus.running, "started")
    queued_integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="queued integration",
            prompt="integrate",
        )
    )
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    ran: list[str] = []

    def fake_advance(task_id: str) -> SimpleNamespace:
        ran.append(task_id)
        store.update_status(task_id, TaskStatus.succeeded, "done")
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

    result = daemon.tick(plan=False, dispatch=True)

    assert result.dispatched == 1
    assert ran == [source.id]
    assert store.get(queued_integration.id).status == TaskStatus.queued

def test_daemon_forever_dispatches_up_to_source_capacity_per_cycle(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.wait_for_scheduler_event",
        lambda *_args, **_kwargs: SchedulerTrigger(reason="wakeup", providers=[]),
    )

    def fake_run_cycle(**kwargs) -> None:
        calls.append(kwargs)
        raise StopIteration

    monkeypatch.setattr(daemon, "run_cycle", fake_run_cycle)

    with pytest.raises(StopIteration):
        daemon.run_forever()

    assert calls == [
        {
            "fetch_providers": [],
            "max_dispatch": config.limits.max_active_tasks,
            "reason": "wakeup",
        }
    ]

def test_daemon_skips_signal_fetch_when_active_capacity_is_full(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=1, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    active, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.update_status(active.id, TaskStatus.running, "started")
    called = False

    def fake_collect(_config):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: pytest.fail("planner should not run at capacity"),
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert called is False
    assert result.signal_fetches == 0
    assert result.enqueued == 0

def test_daemon_local_wakeup_fetches_idle_due_signals_when_idle(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("code-scanning", "codacy"),
            "signal_providers": {
                "code-scanning": config.signal_providers["code-scanning"].__class__(
                    poll_interval_minutes=360,
                    idle_poll_interval_minutes=1,
                ),
                "codacy": config.signal_providers["codacy"].__class__(
                    poll_interval_minutes=360,
                    idle_poll_interval_minutes=30,
                ),
            },
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=2)
    for provider in config.enabled_signals:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=fetched_at,
                completed_at=fetched_at,
                item_count=0,
                new_item_count=0,
                summary="none",
            )
        )
    store.request_wakeup("task.status", {"task_id": "task-1"})
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.transcripts_dir / "planner" / "codex.jsonl",
        ),
    )

    result = StewardDaemon(config, store).run_cycle(dispatch=False, reason="wakeup")

    assert fetched == [["code-scanning"]]
    assert result.signal_fetches == 0
    assert store.pending_wakeups() == []

def test_daemon_idle_signal_fetch_waits_for_existing_local_work(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    store.request_wakeup("task.status", {"task_id": "task-1"})
    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: pytest.fail("planner should not run before queued work"),
    )

    result = StewardDaemon(config, store).run_cycle(plan=True, dispatch=False, reason="wakeup")

    assert fetched == []
    assert result.signal_fetches == 0
    assert store.pending_wakeups() == []

def test_daemon_idle_signal_fetch_waits_for_pending_signal_items(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    store.request_wakeup("task.status", {"task_id": "task-1"})
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="pending",
            title="Pending finding",
        )
    )
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[],
        ),
    )

    result = StewardDaemon(config, store).run_cycle(plan=True, dispatch=False, reason="wakeup")

    assert fetched == []
    assert result.signal_fetches == 0
    assert result.planned == 0
    assert store.pending_wakeups() == []

def test_daemon_fetches_selected_providers_from_force_wakeup(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    store.request_wakeup("signal.fetch", {"providers": ["codacy"]})
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )

    result = StewardDaemon(config, store).run_cycle(dispatch=False, reason="wakeup")

    assert fetched == [["codacy"]]
    assert result.signal_fetches == 0
    assert store.pending_wakeups() == []

def test_scheduler_state_tracks_provider_due_times(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)

    initial = scheduler_state(config, store)

    assert due_provider_names(initial) == list(config.enabled_signals)
    assert initial.idle is True
    assert set(initial.state.model_dump()) == {
        "source_active",
        "source_capacity",
        "source_queued",
        "integration_active",
        "integration_queued",
        "pending_wakeups",
        "recent_wakeups",
        "providers",
    }
    assert all(provider.due for provider in initial.state.providers)

    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            item_count=0,
            new_item_count=0,
            summary="none",
        )
    )
    state = scheduler_state(config, store)
    codacy = next(
        provider
        for provider in state.state.providers
        if provider.provider == "codacy"
    )

    assert codacy.due is False
    assert codacy.poll_interval_minutes == 360
    assert codacy.idle_poll_interval_minutes == 30
    assert codacy.next_due_at > codacy.last_fetch_at
    assert codacy.idle_next_due_at == codacy.last_fetch_at + timedelta(minutes=30)
    assert codacy.idle_due is False

def test_scheduler_snapshot_bounds_wakeups_and_provider_fetches(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy", "code-scanning"),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)

    for index in range(25):
        store.request_wakeup(f"scheduler-{index}")
    old_fetch = utc_now() - timedelta(hours=2)
    new_fetch = utc_now() - timedelta(minutes=1)
    for provider in config.enabled_signals:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=old_fetch,
                completed_at=old_fetch,
            )
        )
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=new_fetch,
                completed_at=new_fetch,
            )
        )
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="disabled-provider",
            status=SignalFetchStatus.ok,
            started_at=new_fetch,
            completed_at=new_fetch,
        )
    )

    snapshot = store.scheduler_snapshot(config.enabled_signals)

    assert len(snapshot.pending_wakeups) == 20
    assert len(snapshot.recent_wakeups) == 20
    assert list(snapshot.latest_fetches) == list(config.enabled_signals)
    assert all(
        fetch is not None and fetch.completed_at == new_fetch
        for fetch in snapshot.latest_fetches.values()
    )
    assert all(
        left.created_at <= right.created_at
        for left, right in zip(snapshot.pending_wakeups, snapshot.pending_wakeups[1:])
    )
    assert all(
        left.created_at >= right.created_at
        for left, right in zip(snapshot.recent_wakeups, snapshot.recent_wakeups[1:])
    )

def test_scheduler_idle_excludes_signal_error_rows(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    ingest_test_signal(
        store,
        SignalItem(
            provider="codacy",
            kind="signal-error",
            fingerprint="error-only",
            title="Provider error",
        )
    )

    assert scheduler_state(config, store).idle is True

    ingest_test_signal(
        store,
        SignalItem(
            provider="codacy",
            kind="codacy.issue",
            fingerprint="ordinary-pending",
            title="Pending finding",
        )
    )

    assert scheduler_state(config, store).idle is False

def test_scheduler_idle_suppressed_by_active_source_task(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.update_status(task.id, TaskStatus.running, "started")

    result = scheduler_state(config, store)

    assert result.idle is False

def test_scheduler_state_uses_error_retry_timing(config: StewardConfig) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=2)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.error,
            started_at=fetched_at,
            completed_at=fetched_at,
            error="temporary",
        )
    )

    result = scheduler_state(config, store)
    provider = result.state.providers[0]

    retry_minutes = config.signal_providers["codacy"].error_retry_minutes
    regular_delta = provider.next_due_at - fetched_at
    assert provider.last_status == SignalFetchStatus.error
    assert timedelta(minutes=retry_minutes) <= regular_delta < timedelta(
        minutes=retry_minutes + 17
    )
    assert provider.idle_next_due_at == fetched_at + timedelta(minutes=retry_minutes)

def test_wait_for_scheduler_event_uses_one_snapshot_per_iteration(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() + timedelta(hours=1)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            started_at=fetched_at,
            completed_at=fetched_at,
        )
    )
    snapshot_calls: list[tuple[str, ...]] = []
    original_snapshot = store.scheduler_snapshot

    def scheduler_snapshot(providers=()):
        snapshot_calls.append(tuple(providers))
        return original_snapshot(providers)

    monkeypatch.setattr(store, "scheduler_snapshot", scheduler_snapshot)

    def fail_legacy_query(*_args, **_kwargs):
        raise AssertionError("scheduler wait used a legacy store query")

    for method in (
        "source_active_count",
        "pending_wakeups",
        "recent_wakeups",
        "pending_signal_items",
    ):
        monkeypatch.setattr(store, method, fail_legacy_query)

    def fake_sleep(_seconds: float) -> None:
        store.request_wakeup("scheduler-test")

    monkeypatch.setattr("coquic_steward.orchestration.daemon.time.sleep", fake_sleep)

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "wakeup"
    assert snapshot_calls == [config.enabled_signals, config.enabled_signals]

def test_wait_for_scheduler_event_returns_due_providers(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "provider-due"
    assert trigger.providers == list(config.enabled_signals)

def test_wait_for_scheduler_event_prioritizes_pending_wakeup(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    store.request_wakeup("task.created")

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "wakeup"
    assert trigger.providers == []

def test_wait_for_scheduler_event_fetches_signals_when_idle(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("code-scanning", "codacy"),
            "signal_providers": {},
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=31)
    for provider in config.enabled_signals:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=fetched_at,
                completed_at=fetched_at,
                item_count=0,
                new_item_count=0,
                summary="none",
            )
        )

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "idle-fetch"
    assert trigger.providers == list(config.enabled_signals)

def test_wait_for_scheduler_event_uses_configured_idle_poll_interval(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
            "signal_providers": {
                "codacy": config.signal_providers["codacy"].__class__(
                    poll_interval_minutes=360,
                    idle_poll_interval_minutes=1,
                )
            },
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=2)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            started_at=fetched_at,
            completed_at=fetched_at,
            item_count=0,
            new_item_count=0,
            summary="none",
        )
    )

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "idle-fetch"
    assert trigger.providers == ["codacy"]

def test_wait_for_scheduler_event_coalesces_near_idle_fetches(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("code-scanning", "codacy"),
            "signal_providers": {},
            "scheduler_wait_interval_sec": 2.0,
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    first_due = utc_now() - timedelta(minutes=31)
    second_due_soon = utc_now() - timedelta(minutes=30) + timedelta(seconds=1)
    for provider, fetched_at in [
        ("code-scanning", first_due),
        ("codacy", second_due_soon),
    ]:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=fetched_at,
                completed_at=fetched_at,
                item_count=0,
                new_item_count=0,
                summary="none",
            )
        )

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "idle-fetch"
    assert trigger.providers == ["code-scanning", "codacy"]

def test_wait_for_scheduler_event_does_not_idle_fetch_with_queued_work(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
            "signal_providers": {},
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            started_at=utc_now() - timedelta(minutes=31),
            completed_at=utc_now() - timedelta(minutes=31),
            item_count=0,
            new_item_count=0,
            summary="none",
        )
    )
    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.consume_wakeups([wakeup.id for wakeup in store.pending_wakeups()])
    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        raise StopIteration

    monkeypatch.setattr("coquic_steward.orchestration.daemon.time.sleep", fake_sleep)

    with pytest.raises(StopIteration):
        wait_for_scheduler_event(config, store)

    assert sleep_calls == [pytest.approx(config.scheduler_wait_interval_sec)]

def test_daemon_plans_bounded_signal_item_inbox(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=2, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    for index in range(5):
        ingest_test_signal(
            store,
            SignalItem(
                id=f"wi-codacy-{index}",
                provider="codacy",
                kind="codacy.issue",
                fingerprint=f"wi-codacy-{index}",
                title=f"Codacy finding {index}",
                payload={"id": f"wi-codacy-{index}", "kind": "codacy-issue"},
            ),
        )
    seen_batches: list[list[str]] = []

    def fake_plan(_config, signals, _active, **_kwargs):
        batch = [item.id for item in signals.items]
        seen_batches.append(batch)
        selected = batch[0]
        return PlannerRun(
            planned=[
                (
                    TaskSpec(
                        kind=TaskKind.code_quality,
                        worker=WorkerKind.code_quality_janitor,
                        title=f"Fix {selected}",
                        prompt=f"Fix {selected}",
                        metadata={"selected_signal_item_ids": [selected]},
                    ),
                    f"codacy:{selected}",
                )
            ],
            accepted_count=1,
            proposed_count=1,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[selected],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr("coquic_steward.orchestration.daemon.run_planner", fake_plan)

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.enqueued == 2
    assert seen_batches == [
        ["wi-codacy-0", "wi-codacy-1"],
        ["wi-codacy-1", "wi-codacy-2"],
    ]
    planned = {
        item.id for item in store.list_signal_items(status=SignalItemStatus.planned)
    }
    pending = {item.id for item in store.pending_signal_items()}
    assert planned == {"wi-codacy-0", "wi-codacy-1"}
    assert pending == {"wi-codacy-2", "wi-codacy-3", "wi-codacy-4"}

def test_plan_verifier_rejects_broken_and_duplicate_specs() -> None:
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[
            SignalItem(
                id="wi-codeql-1",
                provider="code-scanning",
                kind="code-scanning.alert",
                fingerprint="wi-codeql-1",
                title="Open CodeQL findings",
            )
        ],
    )
    active = [
        ActiveTaskSummary(
            id="task-1",
            kind="code-quality",
            worker="code-quality-janitor",
            title="Active CodeQL fix",
            status="running",
            dedupe_key="codeql:open",
        )
    ]

    verified = PlanVerifier().verify_plan(
        """
        {
          "tasks": [
            {
              "dedupe_key": "codeql:open",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Duplicate",
              "prompt": "Fix the current CodeQL alerts.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codeql-1"]
            },
            {
              "dedupe_key": "bad",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Bad evidence",
              "prompt": "Fix a made-up alert.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["codeql:missing"]
            }
          ]
        }
        """,
        signals,
        active,
    )

    assert verified.planned == []

def test_plan_verifier_accepts_valid_llm_proposal() -> None:
    item = SignalItem(
        id="wi-codeql-1",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="wi-codeql-1",
        title="cpp/use-after-free in src/main.cpp:12",
        summary="CodeQL sampled 1 open finding(s)",
        location={"path": "src/main.cpp", "line": 12},
        payload={"rule_id": "cpp/use-after-free"},
    )
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[item],
    )

    verified = PlanVerifier().verify_plan(
        """
        {
          "tasks": [
            {
              "dedupe_key": "codeql:open",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Fix current CodeQL alerts",
              "prompt": "Fetch current CodeQL alerts, fix source issues, and validate locally.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codeql-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-codeql-1"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert len(verified.planned) == 1
    spec, dedupe_key = verified.planned[0]
    assert spec.kind == TaskKind.code_quality
    assert dedupe_key == "codeql:open"
    assert spec.metadata["evidence"] == ["wi-codeql-1"]
    assert spec.metadata["source_context"]["selected_signal_item_ids"] == [
        "wi-codeql-1"
    ]
    assert spec.metadata["source_context"]["selected_signal_items"][0]["id"] == item.id

def test_plan_verifier_accepts_item_backed_llm_proposal() -> None:
    item = SignalItem(
        id="wi-codeql-1",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="wi-codeql-1",
        title="cpp/use-after-free in src/main.cpp:12",
        summary="CodeQL sampled 1 open finding(s)",
        location={"path": "src/main.cpp", "line": 12},
        payload={"rule_id": "cpp/use-after-free"},
    )
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[item],
    )

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-codeql-1"],
          "tasks": [
            {
              "dedupe_key": "codeql:wi-codeql-1",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Fix cpp/use-after-free in src/main.cpp",
              "prompt": "Fix the selected CodeQL finding and validate locally.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codeql-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-codeql-1"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.consumed_item_ids == ["wi-codeql-1"]
    assert len(verified.planned) == 1
    spec, dedupe_key = verified.planned[0]
    assert dedupe_key == "codeql:wi-codeql-1"
    assert spec.metadata["source_context"]["selected_signal_items"][0]["id"] == item.id

def test_plan_verifier_accepts_feature_issue_proposal() -> None:
    item = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42: Add QUIC DATAGRAM send API",
        summary="GitHub issue #42 requests feature work",
        links=[
            {
                "label": "Open GitHub issue",
                "url": "https://github.com/minhuw/coquic/issues/42",
            }
        ],
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
            "issue_title": "Add QUIC DATAGRAM send API",
            "labels": ["steward:enhancement"],
            "worker_context": {
                "recommended_task_kind": "feature",
                "recommended_worker": "feature-implementer",
            },
        },
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[item])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42 Add QUIC DATAGRAM send API",
              "prompt": "Implement GitHub issue #42 only: https://github.com/minhuw/coquic/issues/42. Add focused validation and do not mutate the issue remotely.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.consumed_item_ids == ["wi-feature-42"]
    assert len(verified.planned) == 1
    spec, dedupe_key = verified.planned[0]
    assert dedupe_key == "github-issue:42"
    assert spec.kind == TaskKind.feature
    assert spec.worker == WorkerKind.feature_implementer
    selected = spec.metadata["source_context"]["selected_signal_items"][0]
    assert selected["payload"]["issue_number"] == 42
    assert selected["payload"]["worker_context"]["recommended_worker"] == "feature-implementer"

def test_plan_verifier_rejects_mutating_worker_for_feature_issue() -> None:
    item = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[item])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "issue-implementer",
              "title": "Implement #42",
              "prompt": "Implement GitHub issue #42 locally.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []

def test_plan_verifier_rejects_multiple_feature_issues_in_one_task() -> None:
    first = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    second = SignalItem(
        id="wi-feature-43",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-43",
        title="Implement #43",
        summary="GitHub issue #43 requests feature work",
        payload={"issue_number": 43},
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[first, second])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42", "wi-feature-43"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42-43",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42 and #43",
              "prompt": "Implement both GitHub issues locally.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42", "wi-feature-43"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42", "wi-feature-43"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []

def test_plan_verifier_rejects_mixed_feature_issue_source_selection() -> None:
    feature = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    codacy = SignalItem(
        id="wi-codacy-1",
        provider="codacy",
        kind="codacy.issue",
        fingerprint="wi-codacy-1",
        title="Codacy issue",
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[feature, codacy])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42", "wi-codacy-1"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42 and fix Codacy",
              "prompt": "Implement GitHub issue #42 and fix the Codacy issue.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42", "wi-codacy-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42", "wi-codacy-1"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []

def test_plan_verifier_rejects_mismatched_feature_issue_evidence() -> None:
    feature = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    codacy = SignalItem(
        id="wi-codacy-1",
        provider="codacy",
        kind="codacy.issue",
        fingerprint="wi-codacy-1",
        title="Codacy issue",
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[feature, codacy])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-codacy-1"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42",
              "prompt": "Implement GitHub issue #42.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-codacy-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []

def test_plan_verifier_ignores_proposed_main_write_flags() -> None:
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[
            SignalItem(
                id="wi-codacy-1",
                provider="codacy",
                kind="codacy.issue",
                fingerprint="wi-codacy-1",
                title="Codacy issue",
            )
        ],
    )

    verified = PlanVerifier().verify_plan(
        """
        {
          "tasks": [
            {
              "dedupe_key": "codacy:open",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Fix current Codacy findings",
              "prompt": "Fix the selected Codacy source-context findings and validate locally.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codacy-1"],
              "metadata": {"selected_signal_item_ids": ["wi-codacy-1"]},
              "allow_main_write": true
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert len(verified.planned) == 1
    assert verified.planned[0][0].allow_main_write is False

def test_signal_collector_accepts_providers(config: StewardConfig) -> None:
    class FakeProvider(GitHubActionsCiProvider):
        name = "fake"

        def collect(
            self, _config: StewardConfig, *, max_items: int = 12
        ) -> ProviderSignalResult:
            return ProviderSignalResult(
                summary="fake signal",
                items=[
                    SignalItem(
                        id="wi-fake-1",
                        provider="fake",
                        kind="fake.item",
                        fingerprint="wi-fake-1",
                        title="Fake signal",
                    )
                ],
            )

    collection = collect_signal_items(config, providers=[FakeProvider()])[0]
    signals = project_signals_from_items(
        config,
        collection.items,
        fetches=[collection.fetch],
        enabled_signals=[collection.fetch.provider],
    )

    assert signals.repository == config.github_repository
    assert [item.id for item in signals.items] == ["wi-fake-1"]
    assert signals.summary == "fake signal"
    assert signals.enabled_signals == ["fake"]

def test_signal_fetch_errors_are_not_signal_items(
    config: StewardConfig,
) -> None:
    class FailingProvider(CodacyProvider):
        name = "codacy"

        def collect(
            self, _config: StewardConfig, *, max_items: int = 12
        ) -> ProviderSignalResult:
            raise OSError("dns failed")

    collection = collect_signal_items(config, providers=[FailingProvider()])[0]

    assert collection.fetch.error == "dns failed"
    assert collection.items == []

def test_signal_registry_exposes_only_concrete_github_actions_providers() -> None:
    assert "github-actions" not in PROVIDER_TYPES
    assert {
        "github-actions:ci",
        "github-actions:test",
        "github-actions:duvet",
        "github-actions:nightly-ci",
        "github-actions:deploy-demo",
        "github-actions:interop",
        "github-actions:perf",
    }.issubset(PROVIDER_TYPES)
    assert "github-issues:features" in PROVIDER_TYPES

def test_collect_signal_items_fetches_github_actions_alias_by_name(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **kwargs):
        captured["args"] = args
        captured["cwd"] = cwd
        captured["env"] = kwargs.get("env")
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 789,
                        "workflowName": "Per-Commit CI",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 2,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    collection = collect_signal_items(
        config, provider_names=["github-actions:ci"]
    )[0]

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "ci.yml"
    assert "--status" not in args
    assert args[args.index("--limit") + 1] == "1"
    assert captured["cwd"] == config.repo_root
    assert captured["env"] == {}
    assert collection.fetch.provider == "github-actions:ci"
    assert collection.fetch.item_count == 1
    assert collection.items[0].provider == "github-actions:ci"
    assert collection.items[0].kind == "github-actions.ci-failure"
    assert collection.items[0].payload["run_attempt"] == 2


def test_github_cli_provider_sites_use_per_call_auth_environment(
    config: StewardConfig, monkeypatch
) -> None:
    token = "github-provider-token-canary"
    calls: list[tuple[list[str], dict[str, str] | None]] = []
    helper_calls = 0

    def fake_github_cli_environment(_config):
        nonlocal helper_calls
        helper_calls += 1
        return {"GH_TOKEN": token}

    def fake_run_command(args, cwd, *, timeout=None, env=None, **_kwargs):
        calls.append((args, env))
        if args[:3] == ["gh", "run", "list"]:
            payload: object = [
                {
                    "databaseId": 101,
                    "workflowName": "Per-Commit CI",
                    "status": "completed",
                    "conclusion": "failure",
                    "attempt": 1,
                }
            ]
        elif args[:3] == ["gh", "search", "issues"]:
            payload = []
        elif args[:3] == ["gh", "issue", "view"]:
            payload = {
                "number": 42,
                "title": "Current feature",
                "url": "https://github.com/minhuw/coquic/issues/42",
                "body": "Current feature body",
                "labels": [{"name": "steward:feature"}],
                "state": "OPEN",
            }
        elif args[:3] == ["gh", "api", "-X"] and args[-1].endswith("/42"):
            payload = {
                "number": 42,
                "html_url": "https://github.com/minhuw/coquic/security/code-scanning/42",
                "url": "https://api.github.com/repos/minhuw/coquic/code-scanning/alerts/42",
                "state": "open",
                "rule": {"id": "cpp/use-after-free", "name": "Use after free"},
                "most_recent_instance": {
                    "location": {"path": "src/main.cpp", "region": {"start_line": 12}}
                },
            }
        elif args[:3] == ["gh", "api", "-X"]:
            payload = []
        else:  # pragma: no cover - protects the command contract.
            raise AssertionError(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.github_cli_environment",
        fake_github_cli_environment,
    )
    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    GitHubActionsCiProvider().collect(config)
    GitHubFeatureIssuesProvider().collect(config)
    GitHubFeatureIssuesProvider().revalidated_signal_item(
        config,
        SignalItem(
            id="stored-feature",
            provider="github-issues:features",
            kind="github-issues.feature-request",
            fingerprint="stored-feature",
            title="Feature",
            payload={"issue_number": 42},
        ),
    )
    CodeScanningProvider().collect(config)
    CodeScanningProvider().revalidated_signal_item(
        config,
        SignalItem(
            id="stored-codeql",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="stored-codeql",
            title="CodeQL alert",
            payload={"alert_number": 42},
        ),
    )

    assert len(calls) == 6
    assert helper_calls == 6
    assert [env for _args, env in calls] == [{"GH_TOKEN": token}] * 6
    assert all(token not in " ".join(args) for args, _env in calls)


def test_github_cli_provider_failure_uses_auth_without_leaking_token(
    config: StewardConfig, monkeypatch
) -> None:
    token = "github-failure-token-canary"
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "coquic_steward.signals.providers.github_cli_environment",
        lambda _config: {"GH_TOKEN": token},
    )

    def fake_run_command(args, cwd, *, timeout=None, env=None, **_kwargs):
        captured["args"] = args
        captured["env"] = env
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=1,
            stdout="",
            stderr="provider unavailable",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    collection = collect_signal_items(
        config, providers=[GitHubActionsCiProvider()]
    )[0]

    assert collection.fetch.error == "provider unavailable"
    assert captured["env"] == {"GH_TOKEN": token}
    assert token not in str(captured["args"])
    assert token not in collection.fetch.error


@pytest.mark.parametrize(
    ("status", "conclusion"),
    [("completed", "success"), ("in_progress", "")],
)
def test_github_actions_signal_ignores_latest_non_failure(
    config: StewardConfig, monkeypatch, status: str, conclusion: str
) -> None:
    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 790,
                        "workflowName": "Per-Commit CI",
                        "status": status,
                        "conclusion": conclusion,
                        "attempt": 1,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    collection = collect_signal_items(
        config, providers=[GitHubActionsCiProvider()]
    )[0]

    assert collection.items == []

def test_revalidation_passes_strict_to_registered_provider(
    config: StewardConfig, monkeypatch
) -> None:
    item = SignalItem(
        id="strict-contract",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="strict-contract",
        title="feature",
        payload={"issue_number": 42},
    )
    strict_values: list[bool] = []

    def stale_signal_reason(self, config, item, *, strict):
        strict_values.append(strict)
        return None

    monkeypatch.setattr(
        GitHubFeatureIssuesProvider, "stale_signal_reason", stale_signal_reason
    )

    assert revalidate_signal_items(config, [item], strict=False) == ([item], {})
    assert revalidate_signal_items(config, [item], strict=True) == ([item], {})
    assert strict_values == [False, True]

def test_strict_revalidation_rejects_legacy_provider_signature(
    config: StewardConfig, monkeypatch
) -> None:
    item = SignalItem(
        id="legacy-provider",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="legacy-provider",
        title="feature",
        payload={"issue_number": 42},
    )

    def stale_signal_reason(self, config, item):
        return None

    monkeypatch.setattr(
        GitHubFeatureIssuesProvider, "stale_signal_reason", stale_signal_reason
    )

    assert revalidate_signal_items(config, [item], strict=False) == ([item], {})
    assert revalidate_signal_items(config, [item], strict=True) == (
        [],
        {item.id: "provider_unavailable"},
    )

@pytest.mark.parametrize(
    ("provider", "item", "response", "expected"),
    [
        (
            "github-actions:ci",
            SignalItem(
                id="stored-ci",
                provider="github-actions:ci",
                kind="github-actions.ci-failure",
                fingerprint="stored-ci-fingerprint",
                title="old CI title",
                payload={"run_id": "100", "run_attempt": 1},
            ),
            [
                {
                    "databaseId": 100,
                    "workflowName": "Per-Commit CI",
                    "status": "completed",
                    "conclusion": "failure",
                    "attempt": 1,
                }
            ],
            ("title", "Per-Commit CI workflow failed"),
        ),
        (
            "github-issues:features",
            SignalItem(
                id="stored-feature",
                provider="github-issues:features",
                kind="github-issues.feature-request",
                fingerprint="stored-feature-fingerprint",
                title="old feature title",
                links=[
                    {
                        "label": "Open GitHub issue",
                        "url": "https://github.com/minhuw/coquic/issues/42",
                    }
                ],
                payload={
                    "issue_number": 42,
                    "issue_url": "https://github.com/minhuw/coquic/issues/42",
                },
            ),
            {
                "number": 42,
                "title": "Current feature title",
                "url": "https://github.com/minhuw/coquic/issues/42",
                "body": "Current feature body",
                "labels": [{"name": "steward:feature"}],
                "state": "OPEN",
            },
            ("title", "Implement #42: Current feature title"),
        ),
        (
            "code-scanning",
            SignalItem(
                id="stored-codeql",
                provider="code-scanning",
                kind="code-scanning.alert",
                fingerprint="stored-codeql-fingerprint",
                title="old CodeQL title",
                links=[
                    {
                        "label": "Open alert",
                        "url": "https://github.com/minhuw/coquic/security/code-scanning/42",
                    }
                ],
                payload={"alert_number": 42},
            ),
            {
                "number": 42,
                "html_url": "https://github.com/minhuw/coquic/security/code-scanning/42",
                "url": "https://api.github.com/repos/minhuw/coquic/code-scanning/alerts/42",
                "state": "open",
                "rule": {"id": "cpp/use-after-free", "name": "Use after free"},
                "most_recent_instance": {
                    "location": {"path": "src/main.cpp", "region": {"start_line": 12}}
                },
            },
            ("payload", {"rule_id": "cpp/use-after-free"}),
        ),
    ],
)
def test_strict_revalidation_hydrates_each_provider_once(
    config: StewardConfig,
    monkeypatch,
    provider: str,
    item: SignalItem,
    response: object,
    expected: tuple[str, object],
) -> None:
    from coquic_steward.signals.collector import revalidate_signal_items_with_context

    calls: list[list[str]] = []

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        calls.append(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(response),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    result = revalidate_signal_items_with_context(config, [item], strict=True)

    assert len(calls) == 1
    assert result.stale_reasons == {}
    current = result.refreshed[item.id]
    assert current.id == item.id
    assert current.fingerprint == item.fingerprint
    if expected[0] == "title":
        assert current.title == expected[1]
    else:
        assert current.payload["rule_id"] == expected[1]["rule_id"]
    assert result.actionable == [current]
    assert current.provider == provider

def test_strict_workflow_hydration_preserves_incomplete_response_reason(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.signals.providers import ProviderRevalidationError

    item = SignalItem(
        id="stored-ci",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="stored-ci-fingerprint",
        title="old CI title",
        payload={"run_id": "100", "run_attempt": 1},
    )
    calls: list[list[str]] = []

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        calls.append(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "workflowName": "Per-Commit CI",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    with pytest.raises(
        ProviderRevalidationError, match="provider_response_incomplete"
    ):
        GitHubActionsCiProvider().revalidated_signal_item(
            config, item, strict=True
        )

    assert len(calls) == 1

def test_strict_feature_hydration_validates_closed_response_identity(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.signals.providers import ProviderRevalidationError

    item = SignalItem(
        id="stored-feature",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="stored-feature-fingerprint",
        title="old feature title",
        links=[
            {
                "label": "Open GitHub issue",
                "url": "https://github.com/minhuw/coquic/issues/42",
            }
        ],
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
        },
    )
    calls: list[list[str]] = []

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        calls.append(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                {
                    "number": 99,
                    "title": "Foreign issue",
                    "url": "https://github.com/minhuw/coquic/issues/99",
                    "body": "Foreign body",
                    "labels": [{"name": "steward:feature"}],
                    "state": "CLOSED",
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    with pytest.raises(
        ProviderRevalidationError, match="provider_response_missing_issue_number"
    ):
        GitHubFeatureIssuesProvider().revalidated_signal_item(
            config, item, strict=True
        )

    assert len(calls) == 1

def test_strict_feature_hydration_uses_invalid_labels_for_missing_labels(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.signals.providers import ProviderRevalidationError

    item = SignalItem(
        id="stored-feature",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="stored-feature-fingerprint",
        title="old feature title",
        links=[
            {
                "label": "Open GitHub issue",
                "url": "https://github.com/minhuw/coquic/issues/42",
            }
        ],
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
        },
    )
    calls: list[list[str]] = []

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        calls.append(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                {
                    "number": 42,
                    "title": "Current feature title",
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "body": "Current feature body",
                    "state": "CLOSED",
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    with pytest.raises(
        ProviderRevalidationError, match="provider_response_invalid_labels"
    ):
        GitHubFeatureIssuesProvider().revalidated_signal_item(
            config, item, strict=True
        )

    assert len(calls) == 1

def test_revalidate_signal_items_filters_stale_sources(
    config: StewardConfig, monkeypatch
) -> None:
    workflow = SignalItem(
        id="wi-ci-100",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="wi-ci-100",
        title="CI run 100 failed",
        payload={"run_id": "100", "run_attempt": 1},
    )
    current_workflow = workflow.model_copy(
        update={
            "id": "wi-ci-101",
            "fingerprint": "wi-ci-101",
            "title": "CI run 101 failed",
            "payload": {"run_id": "101", "run_attempt": 1},
        }
    )
    codeql = SignalItem(
        id="wi-codeql-5954",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="wi-codeql-5954",
        title="CodeQL alert 5954",
        links=[
            {
                "label": "Open alert",
                "url": "https://github.com/minhuw/coquic/security/code-scanning/5954",
            }
        ],
    )
    current_codeql = codeql.model_copy(
        update={
            "id": "wi-codeql-5955",
            "fingerprint": "wi-codeql-5955",
            "title": "CodeQL alert 5955",
            "links": [
                {
                    "label": "Open alert",
                    "url": "https://github.com/minhuw/coquic/security/code-scanning/5955",
                }
            ],
        }
    )
    feature = SignalItem(
        id="wi-feature-7",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-7",
        title="Issue #7",
        payload={"issue_number": 7},
    )
    current_feature = feature.model_copy(
        update={
            "id": "wi-feature-8",
            "fingerprint": "wi-feature-8",
            "title": "Issue #8",
            "payload": {"issue_number": 8},
        }
    )
    codacy = SignalItem(
        id="wi-codacy-1",
        provider="codacy",
        kind="codacy.issue",
        fingerprint="wi-codacy-1",
        title="Codacy issue",
    )

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        if args[:3] == ["gh", "run", "list"]:
            payload = [
                {
                    "databaseId": 101,
                    "workflowName": "Per-Commit CI",
                    "status": "completed",
                    "conclusion": "failure",
                    "attempt": 1,
                }
            ]
        elif args[:3] == ["gh", "api", "-X"]:
            payload = {
                "state": "open" if args[-1].endswith("/5955") else "fixed"
            }
        elif args[:3] == ["gh", "issue", "view"]:
            payload = (
                {"state": "OPEN", "labels": [{"name": "steward:feature"}]}
                if args[3] == "8"
                else {"state": "CLOSED", "labels": []}
            )
        else:  # pragma: no cover - protects the command contract.
            raise AssertionError(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    actionable, stale = revalidate_signal_items(
        config,
        [
            workflow,
            current_workflow,
            codeql,
            current_codeql,
            feature,
            current_feature,
            codacy,
        ],
    )

    assert actionable == [current_workflow, current_codeql, current_feature, codacy]
    assert stale == {
        workflow.id: "superseded_by_newer_run",
        codeql.id: "source_not_open",
        feature.id: "source_closed",
    }

def test_revalidate_signal_items_treats_legacy_workflow_as_attempt_one(
    config: StewardConfig, monkeypatch
) -> None:
    item = SignalItem(
        id="wi-ci-100",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="wi-ci-100",
        title="CI run 100 failed",
        payload={"run_id": "100"},
    )

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 100,
                        "workflowName": "Per-Commit CI",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 2,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    actionable, stale = revalidate_signal_items(config, [item])

    assert actionable == []
    assert stale == {item.id: "superseded_by_newer_run"}

def test_revalidate_signal_items_fails_open(
    config: StewardConfig, monkeypatch
) -> None:
    item = SignalItem(
        id="wi-ci-100",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="wi-ci-100",
        title="CI run 100 failed",
        payload={"run_id": "100", "run_attempt": 1},
    )

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=1,
            stdout="",
            stderr="GitHub unavailable",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    actionable, stale = revalidate_signal_items(config, [item])

    assert actionable == [item]
    assert stale == {}

def test_github_actions_interop_signal_filters_workflow(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 123,
                        "workflowName": "Interop",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    collection = collect_signal_items(
        config, providers=[GitHubActionsInteropProvider()]
    )[0]

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "interop.yml"
    assert "--status" not in args
    assert captured["cwd"] == config.repo_root
    assert len(collection.items) == 1
    item = collection.items[0]
    assert item.provider == "github-actions:interop"
    assert item.id.startswith("wi-github-actions-interop-interop-failure-")
    assert item.kind == "github-actions.interop-failure"
    assert item.payload["run_id"] == "123"
    assert item.payload["run_attempt"] == 1
    assert item.payload["workflow_name"] == "Interop"
    assert item.payload["conclusion"] == "failure"
    assert item.payload["workflow_file"] == "interop.yml"
    assert item.payload["worker_context"]["recommended_worker"] == "interop-doctor"
    assert item.payload["worker_context"]["recommended_task_kind"] == "interop"
    assert "interop/run-official.sh" in " ".join(
        item.payload["worker_context"]["investigation_steps"]
    )

def test_github_actions_ci_signal_includes_worker_context(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 789,
                        "workflowName": "Per-Commit CI",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    collection = collect_signal_items(
        config, providers=[GitHubActionsCiProvider()]
    )[0]

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "ci.yml"
    item = collection.items[0]
    assert item.provider == "github-actions:ci"
    assert item.kind == "github-actions.ci-failure"
    assert item.payload["workflow_file"] == "ci.yml"
    context = item.payload["worker_context"]
    assert context["recommended_task_kind"] == "ci"
    assert context["recommended_worker"] == "ci-doctor"
    assert "RFC compliance" in context["workflow_purpose"]
    assert "nix develop -c ./scripts/compliance --ci" in context["local_validation"]

def test_github_actions_perf_signal_is_separate_provider(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 456,
                        "workflowName": "Perf",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    collection = collect_signal_items(
        config, providers=[GitHubActionsPerfProvider()]
    )[0]

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "perf.yml"
    assert collection.fetch.provider == "github-actions:perf"
    assert collection.items[0].provider == "github-actions:perf"
    assert collection.items[0].id.startswith("wi-github-actions-perf-perf-failure-")
    assert collection.items[0].kind == "github-actions.perf-failure"
    assert collection.items[0].payload["run_id"] == "456"
    assert (
        collection.items[0].payload["worker_context"]["workflow_file"]
        == "perf.yml"
    )

def test_github_feature_issue_signal_fetches_open_feature_issues(
    config: StewardConfig, monkeypatch
) -> None:
    calls: list[list[str]] = []

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        calls.append(args)
        label = args[args.index("--label") + 1]
        payload = []
        if label == "steward:enhancement":
            payload = [
                {
                    "number": 42,
                    "title": "Add QUIC DATAGRAM send API",
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "body": "Expose an application-facing datagram sender.",
                    "labels": [{"name": "steward:enhancement"}, {"name": "api"}],
                    "author": {"login": "alice"},
                    "createdAt": "2026-06-01T00:00:00Z",
                    "updatedAt": "2026-06-02T00:00:00Z",
                    "state": "open",
                }
            ]
        if label == "steward:feature":
            payload = [
                {
                    "number": 42,
                    "title": "Add QUIC DATAGRAM send API",
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "body": "Duplicate through steward feature label.",
                    "labels": [{"name": "steward:feature"}],
                    "author": {"login": "alice"},
                    "createdAt": "2026-06-01T00:00:00Z",
                    "updatedAt": "2026-06-03T00:00:00Z",
                    "state": "open",
                }
            ]
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    collection = collect_signal_items(
        config, providers=[GitHubFeatureIssuesProvider()]
    )[0]

    assert [call[:3] for call in calls] == [
        ["gh", "search", "issues"],
        ["gh", "search", "issues"],
    ]
    for call in calls:
        assert call[call.index("--repo") + 1] == "minhuw/coquic"
        assert call[call.index("--state") + 1] == "open"
        assert call[call.index("--limit") + 1] == "13"
        assert call[call.index("--json") + 1] == (
            "number,title,url,body,labels,author,createdAt,updatedAt,state"
        )
    assert [call[call.index("--label") + 1] for call in calls] == [
        "steward:enhancement",
        "steward:feature",
    ]
    assert collection.fetch.provider == "github-issues:features"
    assert collection.fetch.summary == "GitHub issues sampled 1 open feature request(s): #42"
    assert len(collection.items) == 1
    item = collection.items[0]
    assert item.id.startswith("wi-github-issues-features-feature-request-")
    assert item.provider == "github-issues:features"
    assert item.kind == "github-issues.feature-request"
    assert item.title == "Implement #42: Add QUIC DATAGRAM send API"
    assert item.summary == (
        "GitHub issue #42 requests feature work: Add QUIC DATAGRAM send API "
        "labels=steward:enhancement, api"
    )
    assert item.links == [
        {
            "label": "Open GitHub issue",
            "url": "https://github.com/minhuw/coquic/issues/42",
        }
    ]
    assert item.payload["issue_number"] == 42
    assert item.payload["issue_url"] == "https://github.com/minhuw/coquic/issues/42"
    assert item.payload["labels"] == ["steward:enhancement", "api"]
    assert item.payload["author"] == "alice"
    assert item.payload["body_excerpt"] == "Expose an application-facing datagram sender."
    assert item.payload["worker_context"]["recommended_task_kind"] == "feature"
    assert item.payload["worker_context"]["recommended_worker"] == "feature-implementer"
    assert "selected issue" in " ".join(
        item.payload["worker_context"]["implementation_steps"]
    )

def test_github_feature_issue_signal_reports_truncated_samples(
    config: StewardConfig, monkeypatch
) -> None:
    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        label = args[args.index("--label") + 1]
        payload = []
        if label == "steward:enhancement":
            payload = [
                {
                    "number": number,
                    "title": f"Feature {number}",
                    "url": f"https://github.com/minhuw/coquic/issues/{number}",
                    "labels": [{"name": "steward:enhancement"}],
                }
                for number in range(1, 4)
            ]
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    result = GitHubFeatureIssuesProvider().collect(config, max_items=2)

    assert len(result.items) == 2
    assert result.has_more is True

def test_github_feature_issue_signal_fingerprint_survives_title_edits(
    config: StewardConfig, monkeypatch
) -> None:
    titles = ["Initial title", "Edited title"]

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        label = args[args.index("--label") + 1]
        payload = []
        if label == "steward:enhancement":
            payload = [
                {
                    "number": 42,
                    "title": titles.pop(0),
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "labels": [{"name": "steward:enhancement"}],
                }
            ]
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )
    provider = GitHubFeatureIssuesProvider()

    first = provider.collect(config, max_items=1).items[0]
    second = provider.collect(config, max_items=1).items[0]

    assert first.title == "Implement #42: Initial title"
    assert second.title == "Implement #42: Edited title"
    assert first.id == second.id
    assert first.fingerprint == second.fingerprint

def test_codacy_signal_uses_public_issue_search_without_token(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.delenv("CODACY_API_TOKEN", raising=False)
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def read(self) -> bytes:
            return (
                b'{"data":[{"patternInfo":{"id":"Bandit_B310",'
                b'"level":"Warning"},"toolInfo":{"name":"Bandit"},'
                b'"filePath":"steward/src/coquic_steward/public_mirror.py",'
                b'"lineNumber":203}]}'
            )

    def fake_open_codacy_request(request, *, timeout):
        captured["method"] = request.get_method()
        captured["api-token"] = request.headers.get("Api-token")
        captured["url"] = request.full_url
        return FakeResponse()

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        fake_open_codacy_request,
    )

    collection = collect_signal_items(config, providers=[CodacyProvider()])[0]

    assert captured["method"] == "POST"
    assert captured["api-token"] is None
    assert captured["url"].endswith("/issues/search?limit=12")
    assert len(collection.items) == 1
    item = collection.items[0]
    assert item.id.startswith("wi-codacy-issue-")
    assert item.provider == "codacy"
    assert item.kind == "codacy.issue"
    assert item.severity == "Warning"
    assert item.location == {
        "path": "steward/src/coquic_steward/public_mirror.py",
        "line": 203,
    }
    assert item.payload == {"rule_id": "Bandit_B310", "tool": "Bandit"}

def test_codacy_signal_falls_back_to_public_analysis(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.delenv("CODACY_API_TOKEN", raising=False)
    urls = []

    class SearchFailure:
        def __enter__(self):
            raise OSError("search unavailable")

        def __exit__(self, *_exc):
            return None

    class AnalysisResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def read(self) -> bytes:
            return b'{"data":{"issuesCount":2}}'

    def fake_open_codacy_request(request, *, timeout):
        urls.append(request.full_url)
        if request.full_url.endswith("/issues/search?limit=12"):
            return SearchFailure()
        return AnalysisResponse()

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        fake_open_codacy_request,
    )

    collection = collect_signal_items(config, providers=[CodacyProvider()])[0]

    assert len(urls) == 2
    assert collection.fetch.summary == "Codacy issuesCount=2"
    assert collection.items == []
    assert collection.fetch.has_more is True

def test_codacy_signal_uses_tokened_issue_search(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.setenv("CODACY_API_TOKEN", "token")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def read(self) -> bytes:
            return (
                b'{"data":[{"patternInfo":{"id":"shellcheck_SC2034",'
                b'"level":"Warning"},"toolInfo":{"name":"ShellCheck"},'
                b'"filePath":"scripts/fuzz-targets.sh","lineNumber":9}]}'
            )

    def fake_open_codacy_request(request, *, timeout):
        captured["method"] = request.get_method()
        captured["api-token"] = request.headers.get("Api-token")
        return FakeResponse()

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        fake_open_codacy_request,
    )

    collection = collect_signal_items(config, providers=[CodacyProvider()])[0]

    assert captured["method"] == "POST"
    assert captured["api-token"] == "token"
    assert len(collection.items) == 1
    item = collection.items[0]
    assert item.id.startswith("wi-codacy-issue-")
    assert item.provider == "codacy"
    assert item.kind == "codacy.issue"
    assert item.severity == "Warning"
    assert item.location == {"path": "scripts/fuzz-targets.sh", "line": 9}
    assert item.payload == {"rule_id": "shellcheck_SC2034", "tool": "ShellCheck"}

def test_codacy_signal_records_error_after_non_2xx_issue_search(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.setenv("CODACY_API_TOKEN", "token")

    class ErrorResponse:
        code = 403
        msg = "Forbidden"
        headers = {}

        def info(self):
            return self.headers

        def close(self) -> None:
            return None

    class FakeHTTPSHandler(BaseHandler):
        def https_open(self, _request):
            return ErrorResponse()

    def fake_codacy_opener() -> OpenerDirector:
        opener = OpenerDirector()
        opener.add_handler(FakeHTTPSHandler())
        opener.add_handler(HTTPDefaultErrorHandler())
        opener.add_handler(HTTPErrorProcessor())
        return opener

    monkeypatch.setattr(
        "coquic_steward.signals.providers._codacy_opener",
        fake_codacy_opener,
    )

    collection = collect_signal_items(config, providers=[CodacyProvider()])[0]

    assert collection.fetch.error == (
        "HTTP Error 403: Forbidden; fallback: HTTP Error 403: Forbidden"
    )
    assert collection.items == []

def test_collect_signal_items_persists_provider_items(config: StewardConfig) -> None:
    class WorkItemProvider(CodacyProvider):
        name = "codacy"

        def collect(
            self, _config: StewardConfig, *, max_items: int = 12
        ) -> ProviderSignalResult:
            return ProviderSignalResult(
                summary="Codacy sampled 1 open finding(s)",
                items=[
                    SignalItem(
                        id="wi-codacy-1",
                        provider="codacy",
                        kind="codacy.issue",
                        fingerprint="wi-codacy-1",
                        title="SC2034 in scripts/fuzz-targets.sh:9",
                        location={"path": "scripts/fuzz-targets.sh", "line": 9},
                        payload={"rule_id": "shellcheck_SC2034"},
                    )
                ],
            )

    collection = collect_signal_items(config, providers=[WorkItemProvider()])[0]

    assert collection.fetch.summary == "Codacy sampled 1 open finding(s)"
    assert [item.id for item in collection.items] == ["wi-codacy-1"]
    assert collection.items[0].source_fetch_id == collection.fetch.id

def test_cli_plan_supersedes_stale_signals_before_planning(
    repo: Path, monkeypatch
) -> None:
    monkeypatch.chdir(repo)
    config = load_config()
    store = TaskStore.create(config.db_path)
    signal, _ = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-42",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-42",
            title="CodeQL alert 42",
            payload={"alert_number": 42},
        )
    )
    monkeypatch.setattr(
        "coquic_steward.cli.collect_signal_items", lambda _config: []
    )
    monkeypatch.setattr(
        "coquic_steward.cli.revalidate_signal_items",
        lambda _config, _items: ([], {signal.id: "source_not_open"}),
    )
    monkeypatch.setattr(
        "coquic_steward.cli.run_planner",
        lambda *_args: pytest.fail("planner should not run for stale signals"),
    )

    result = CliRunner().invoke(app, ["plan"])

    assert result.exit_code == 0
    saved = store.list_signal_items()[0]
    assert saved.status == SignalItemStatus.superseded
    assert saved.planner_run_id == "source-revalidation"

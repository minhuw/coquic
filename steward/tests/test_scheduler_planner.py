from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import signal
from types import SimpleNamespace
import threading

from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.models import (
    ProjectSignals,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
)
from coquic_steward.execution.session import (
    ContainerSessionInvoker,
    FreshPlannerSession,
    _InvocationLaunchGate,
)
from coquic_steward.planning import PlannerRun
from coquic_steward.planning.verifier import ActiveTaskSummary, PlanVerifier
from coquic_steward.storage import TaskStore


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


def _proposal(dedupe: str, *, evidence: list[str] | None = None) -> dict[str, object]:
    return {
        "dedupe_key": dedupe,
        "kind": "custom",
        "worker": "custom",
        "title": "Handle synthetic alert",
        "prompt": "Investigate the synthetic alert and add focused validation.",
        "priority": "medium",
        "risk": "low",
        "evidence": evidence or ["signal-item-1"],
        "metadata": {"selected_signal_item_ids": ["signal-item-1"]},
    }


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
class _FakeInvoker:
    requests: list[object]

    def invoke(self, request, **kwargs):
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


def test_fresh_planner_interrupt_during_container_startup_prevents_exec(config) -> None:
    class BarrierRuntime:
        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()
            self.exec_calls = 0
            self.config = SimpleNamespace(
                container_name="planner-test",
                container_path=lambda path, _role: path,
            )

        def ensure_started(self) -> None:
            self.entered.set()
            assert self.release.wait(timeout=2)

        def exec_stream(self, *_args, **_kwargs):
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
    store = TaskStore(config.db_path)
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

    def fake_planner(_config, _signals, _tasks, **kwargs):
        invocations.append(kwargs["invocation"])
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

    result = CliRunner().invoke(app, ["plan"])

    assert result.exit_code == 0
    assert len(invocations) == 1
    assert isinstance(invocations[0], FreshPlannerSession)


def test_cli_diagnostics_normalizes_task_epoch_and_reports_control_state(
    config, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
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

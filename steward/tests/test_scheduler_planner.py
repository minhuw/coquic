from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from coquic_steward.core.models import ProjectSignals, SignalItem
from coquic_steward.execution.session import FreshPlannerSession
from coquic_steward.planning.verifier import ActiveTaskSummary, PlanVerifier


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

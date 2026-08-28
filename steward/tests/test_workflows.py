from __future__ import annotations

import json
from pathlib import Path

import pytest

from coquic_steward.agents import CodexRunner
from coquic_steward.core.config import (
    CodexStageConfig,
    PathPolicyConfig,
    StewardConfig,
)
from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskWorkflow,
    WorkerKind,
)
from coquic_steward.execution import StewardExecutor
from coquic_steward.execution.implementation_plan import parse_implementation_plan
from coquic_steward.execution.review import parse_review, review_approved
from coquic_steward.storage import TaskStore
from durable_harness import drive_durable, passing_durable_gates, write_durable_codex

VALID_PLAN = {
    "summary": "Implement the scoped change.",
    "assumptions": ["The existing API remains compatible."],
    "steps": [
        {
            "title": "Update implementation",
            "detail": "Change the source and add focused coverage.",
            "files": ["README.md"],
        }
    ],
    "validation": ["run focused tests"],
    "risks": ["Behavioral regression"],
    "non_goals": ["Unrelated refactoring"],
}

def test_task_workflow_defaults_from_kind() -> None:
    feature = TaskSpec(
        kind=TaskKind.feature,
        worker=WorkerKind.feature_implementer,
        title="Feature",
        prompt="Implement it",
    )
    fix = TaskSpec(
        kind=TaskKind.ci,
        worker=WorkerKind.ci_doctor,
        title="Fix",
        prompt="Repair it",
    )

    assert feature.workflow == TaskWorkflow.feature
    assert fix.workflow == TaskWorkflow.fix

def test_stage_settings_override_global_defaults(config: StewardConfig) -> None:
    configured = config.__class__(
        **{
            **config.__dict__,
            "codex_model": "default-model",
            "codex_reasoning_effort": "medium",
            "codex_stages": {
                CodexStage.implementation_plan.value: CodexStageConfig(
                    model="plan-model", reasoning_effort="high"
                )
            },
        }
    )

    plan = configured.codex_settings(CodexStage.implementation_plan)
    code = configured.codex_settings(CodexStage.code)
    assert (plan.model, plan.reasoning_effort) == ("plan-model", "high")
    assert (code.model, code.reasoning_effort) == ("default-model", "medium")

    args = CodexRunner(configured)._args(
        configured.repo_root,
        configured.state_dir / "last.md",
        output_schema=None,
        resume_session=None,
        stage=CodexStage.implementation_plan,
        sandbox="read-only",
    )
    assert args[args.index("--model") + 1] == "plan-model"
    assert args[args.index("--sandbox") + 1] == "read-only"
    assert 'model_reasoning_effort="high"' in args

def test_plan_parser_rejects_frozen_and_generated_paths(config: StewardConfig) -> None:
    task = TaskStore.create(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="Implement it",
        )
    )[0]
    assert parse_implementation_plan(json.dumps(VALID_PLAN), task, config) == VALID_PLAN

    generated = json.loads(json.dumps(VALID_PLAN))
    generated["steps"][0]["files"] = ["zig-out/result"]
    assert parse_implementation_plan(json.dumps(generated), task, config) is None

    frozen_config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("README.md/",)}
            ),
        }
    )
    frozen = json.loads(json.dumps(VALID_PLAN))
    frozen["steps"][0]["files"] = ["README.md"]
    assert parse_implementation_plan(json.dumps(frozen), task, frozen_config) is None


def test_feature_plans_then_codes_in_separate_session(
    config: StewardConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = write_durable_codex(
        tmp_path,
        change="changed",
        commit='{"subject":"fix: durable workflow","body":"persist the durable workflow result"}',
        plan=json.dumps(VALID_PLAN),
        thread_events=True,
    )
    configured = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "codex_model": "default-model",
            "codex_stages": {
                CodexStage.implementation_plan.value: CodexStageConfig(
                    model="plan-model", reasoning_effort="high"
                ),
                CodexStage.code.value: CodexStageConfig(
                    model="code-model", reasoning_effort="medium"
                ),
                CodexStage.review.value: CodexStageConfig(
                    model="review-model", reasoning_effort="low"
                ),
            },
        }
    )
    configured.ensure_dirs()
    store = TaskStore.create(configured.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="Implement it",
        )
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(configured, store)
    assert drive_durable(executor, task.id, finalize=True)
    saved = store.get(task.id)
    plan_runs = store.plan_runs(task.id)
    iterations = store.iterations(task.id)
    events = store.events(task.id)

    assert saved.status == TaskStatus.succeeded
    assert any(
        event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("next_phase") == "implementation"
        for event in events
    )
    assert len(plan_runs) == 1
    assert plan_runs[0].plan_json == VALID_PLAN
    assert plan_runs[0].model == "plan-model"
    assert iterations[0].worker_model == "code-model"
    assert any(event.kind == "pipeline.review.raw" for event in events)
    worker_prompt = iterations[0].worker_prompt_path
    assert worker_prompt is not None
    assert json.dumps(VALID_PLAN, indent=2, sort_keys=True) in worker_prompt.read_text(
        encoding="utf-8"
    )
    assert any(
        event.kind == "pipeline.plan.result" and event.message == "accepted"
        for event in events
    )

def test_fix_workflow_skips_planning(
    config: StewardConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = write_durable_codex(
        tmp_path,
        change="changed",
        commit='{"subject":"fix: durable workflow","body":"persist the durable workflow result"}',
        thread_events=True,
    )
    configured = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    configured.ensure_dirs()
    store = TaskStore.create(configured.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="Fix",
            prompt="Repair it",
        )
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(configured, store)
    assert drive_durable(executor, task.id, finalize=True)
    assert store.plan_runs(task.id) == []
    assert not any(
        event.kind.startswith("implementation_plan.") for event in store.events(task.id)
    )

def test_invalid_feature_plan_retries_without_coding(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = write_durable_codex(
        tmp_path,
        change="changed",
        commit='{"subject":"fix: durable workflow","body":"persist the durable workflow result"}',
        plan="{}",
        thread_events=True,
    )
    configured = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    configured.ensure_dirs()
    store = TaskStore.create(configured.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="Implement it",
        )
    )

    executor = StewardExecutor(configured, store)
    assert not drive_durable(executor, task.id, finalize=True)
    assert store.get(task.id).status == TaskStatus.blocked
    assert len(store.plan_runs(task.id)) == 2
    assert store.iterations(task.id) == []

def test_review_verdict_uses_structured_output() -> None:
    approved = parse_review(
        json.dumps(
            {
                "verdict": "approve",
                "summary": "No findings.",
                "findings": [],
                "validation_gaps": [],
                "remaining_risk": "",
            }
        )
    )
    blocked = parse_review(
        json.dumps(
            {
                "verdict": "block",
                "summary": "Unsafe patch.",
                "findings": [
                    {
                        "severity": "high",
                        "title": "Incorrect behavior",
                        "file": "src/main.zig",
                        "line": 10,
                        "detail": "The patch changes unrelated behavior.",
                        "recommendation": "Keep the change scoped.",
                    }
                ],
                "validation_gaps": [],
                "remaining_risk": "Needs another pass.",
            }
        )
    )

    assert approved is not None
    assert review_approved(approved)
    approved_with_gap = approved | {"validation_gaps": ["zig build test was not run"]}
    assert review_approved(approved_with_gap)
    assert blocked is not None
    assert not review_approved(blocked)
    assert parse_review("APPROVE\n\nNo blocking findings.") is None
    assert (
        parse_review(
            json.dumps(
                {
                    "verdict": "block",
                    "summary": "Review not completed.",
                    "findings": [
                        {
                            "severity": "critical",
                            "title": "Invalid premature response",
                            "file": "",
                            "line": None,
                            "detail": (
                                "Internal error: accidentally attempted final "
                                "response prematurely."
                            ),
                            "recommendation": (
                                "Ignore this response; continuing review would "
                                "be required."
                            ),
                        }
                    ],
                    "validation_gaps": ["Review not completed."],
                    "remaining_risk": "Review not completed.",
                }
            )
        )
        is None
    )

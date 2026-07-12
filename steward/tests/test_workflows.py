from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from coquic_steward.agents import CodexRunner
from coquic_steward.core.config import CodexStageConfig, StewardConfig
from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskWorkflow,
    ValidationResult,
    WorkerKind,
)
from coquic_steward.execution import StewardExecutor
from coquic_steward.execution.implementation_plan import parse_implementation_plan
from coquic_steward.storage import TaskStore


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
    task = TaskStore(config.db_path).add_task(
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


def test_store_migrates_feature_workflow(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="Implement it",
        )
    )
    store.engine.dispose()
    with sqlite3.connect(config.db_path) as connection:
        connection.execute("ALTER TABLE tasks DROP COLUMN workflow")

    migrated = TaskStore(config.db_path)
    assert migrated.get(task.id).spec.workflow == TaskWorkflow.feature


def test_feature_plans_then_codes_in_separate_session(
    config: StewardConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _fake_codex(tmp_path, invalid_plan=False)
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
    store = TaskStore(configured.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="Implement it",
        )
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_gates
    )

    assert StewardExecutor(configured, store).run_task(task.id)
    saved = store.get(task.id)
    plan_runs = store.plan_runs(task.id)
    iterations = store.iterations(task.id)
    events = store.events(task.id)

    assert saved.status == TaskStatus.succeeded
    assert saved.spec.metadata["worker_thread_id"] == "worker-thread"
    assert len(plan_runs) == 1
    assert plan_runs[0].plan_json == VALID_PLAN
    assert plan_runs[0].model == "plan-model"
    assert iterations[0].worker_model == "code-model"
    assert iterations[0].reviewer_model == "review-model"
    worker_prompt = iterations[0].worker_prompt_path
    assert worker_prompt is not None
    assert json.dumps(VALID_PLAN, indent=2, sort_keys=True) in worker_prompt.read_text(
        encoding="utf-8"
    )
    assert any(event.kind == "implementation_plan.finished" for event in events)


def test_fix_workflow_skips_planning(
    config: StewardConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _fake_codex(tmp_path, invalid_plan=False)
    configured = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    configured.ensure_dirs()
    store = TaskStore(configured.db_path)
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
        "coquic_steward.execution.executor.run_gates", _passing_gates
    )

    assert StewardExecutor(configured, store).run_task(task.id)
    assert store.plan_runs(task.id) == []
    assert not any(
        event.kind.startswith("implementation_plan.") for event in store.events(task.id)
    )


def test_invalid_feature_plan_retries_without_coding(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = _fake_codex(tmp_path, invalid_plan=True)
    configured = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    configured.ensure_dirs()
    store = TaskStore(configured.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="Implement it",
        )
    )

    assert not StewardExecutor(configured, store).run_task(task.id)
    assert store.get(task.id).status == TaskStatus.failed
    assert len(store.plan_runs(task.id)) == 2
    assert store.iterations(task.id) == []


def _fake_codex(tmp_path: Path, *, invalid_plan: bool) -> Path:
    fake = tmp_path / ("codex-invalid-plan" if invalid_plan else "codex-workflow")
    plan_json = "{}" if invalid_plan else json.dumps(VALID_PLAN)
    fake.write_text(
        "#!/bin/sh\n"
        "last=\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'case "$last" in\n'
        f'  */implementation-plan-*) printf \'%s\\n\' \'{plan_json}\' > "$last"; printf \'{{"type":"thread.started","thread_id":"plan-thread"}}\\n\';;\n'
        '  */reviewer-*) printf \'%s\\n\' \'{"verdict":"approve","summary":"ok","findings":[],"validation_gaps":[],"remaining_risk":""}\' > "$last"; printf \'{"type":"thread.started","thread_id":"review-thread"}\\n\';;\n'
        '  *) printf \'changed\\n\' > README.md; printf \'done\\n\' > "$last"; printf \'{"type":"thread.started","thread_id":"worker-thread"}\\n\';;\n'
        "esac\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def _passing_gates(config, task_id, cwd, *, label=None):
    output = config.logs_dir / task_id / (label or "validation") / "fake.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("ok\n", encoding="utf-8")
    return [
        ValidationResult(
            command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
        )
    ]

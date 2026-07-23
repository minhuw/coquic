from __future__ import annotations

from pathlib import Path

from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    TaskWorkflow,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    PipelineCursorPhase,
    PipelineTrigger,
)
from coquic_steward.core.lifecycle import pipeline_transition_allowed
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.storage import TaskStore


class FakeRunner:
    def __init__(self, config):
        self.config = config

    def paths(self, task, *, name="worker"):
        path = self.config.transcripts_dir / task.id / name
        return path / "codex.jsonl", path / "last-message.md"

    def run(self, task, prompt, cwd, *, name="worker", stage=CodexStage.code, **kwargs):
        cwd = Path(cwd)
        transcript, last_message = self.paths(task, name=name)
        transcript.parent.mkdir(parents=True, exist_ok=True)
        if stage == CodexStage.review:
            message = '{"verdict":"approve","summary":"ok","findings":[],"validation_gaps":[],"remaining_risk":""}'
        elif stage == CodexStage.commit_message:
            message = '{"subject":"fix: durable pipeline","body":"persist the accepted tree"}'
        else:
            (cwd / "README.md").write_text("changed\n", encoding="utf-8")
            message = "done"
        transcript.write_text("{}\n", encoding="utf-8")
        last_message.write_text(message, encoding="utf-8")
        return WorkerResult(
            completed=True,
            command=["fake"],
            cwd=cwd,
            exit_code=0,
            transcript_path=transcript,
            last_message_path=last_message,
            final_message=message,
            stage=stage,
        )


def _passing_gates(config, task_id, cwd, **kwargs):
    output = config.logs_dir / task_id / "pipeline.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("ok\n", encoding="utf-8")
    return [
        ValidationResult(
            command=["fake-gate"], cwd=cwd, passed=True, exit_code=0, output_path=output
        )
    ]


def test_advance_once_is_idempotent_and_stops_at_ready_to_seal(config, monkeypatch) -> None:
    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", _passing_gates)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="durable task",
            prompt="change README",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))

    first = executor.advance_once(task.id)
    assert first.next_phase.value == "implementation"
    for _ in range(8):
        result = executor.advance_once(task.id)
        if result.status == "ready_to_seal":
            break
    else:
        raise AssertionError("pipeline did not reach ready_to_seal")

    repeated = executor.advance_once(task.id)
    assert repeated.status == "ready_to_seal"
    assert len(store.list_pipelines(task.id)) == 1
    assert not any(event.kind == "pipeline.blocked" for event in store.events(task.id))


def test_implementation_validation_patch_tree_full_gate_is_recorded(config, monkeypatch) -> None:
    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", _passing_gates)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, workflow=TaskWorkflow.fix, worker=WorkerKind.custom, title="identity", prompt="change")
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    executor.advance_once(task.id)
    executor.advance_once(task.id)
    pipeline = store.list_pipelines(task.id)[0]
    assert pipeline.base_identity
    assert pipeline.output_identity
    assert pipeline.patch_identity


def test_phase_transition_and_legacy_compatibility_are_bounded() -> None:
    assert pipeline_transition_allowed(
        PipelineCursorPhase.provisioned, PipelineCursorPhase.implementation
    )
    assert pipeline_transition_allowed(
        PipelineCursorPhase.validation,
        PipelineCursorPhase.repair,
        trigger=PipelineTrigger.validation_repair,
    )
    assert pipeline_transition_allowed(
        PipelineCursorPhase.provisioned,
        PipelineCursorPhase.implementation,
        trigger=PipelineTrigger.validation_repair,
    )
    assert not pipeline_transition_allowed(
        PipelineCursorPhase.review, PipelineCursorPhase.commit
    )


def test_child_pipeline_budget_and_no_progress_fingerprint_are_explicit(config) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, workflow=TaskWorkflow.fix, worker=WorkerKind.custom, title="budget", prompt="change")
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    parent = store.list_pipelines(task.id)[0]
    child = executor._new_child_pipeline(task, parent, PipelineTrigger.validation_repair, {"fingerprint": "same"})
    assert child.parent_pipeline_id == parent.id
    assert store.list_pipelines(task.id)[-1].trigger == PipelineTrigger.validation_repair.value


def test_integration_latest_main_rebase_conflict_remains_source_task() -> None:
    assert PipelineTrigger.integration_rebase.value == "integration-rebase"
    assert PipelineTrigger.integration_conflict.value == "integration-conflict"
    assert PipelineTrigger.push_race.value == "push-race"


def test_commit_message_push_race_ready_to_seal_authority() -> None:
    assert pipeline_transition_allowed(PipelineCursorPhase.commit_message, PipelineCursorPhase.commit)
    assert pipeline_transition_allowed(PipelineCursorPhase.commit, PipelineCursorPhase.push)
    assert pipeline_transition_allowed(PipelineCursorPhase.push, PipelineCursorPhase.ready_to_seal)

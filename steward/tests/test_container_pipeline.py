from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    TaskRun,
    TaskWorkflow,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    PipelineCursorPhase,
    PipelineTrigger,
)
from coquic_steward.core.lifecycle import pipeline_transition_allowed
from coquic_steward.execution.executor import (
    StewardExecutor,
    _validation_no_progress_fingerprint,
)
from coquic_steward.execution.task_archive import TaskArchiveWriter
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


@pytest.mark.parametrize(
    "trigger",
    [
        PipelineTrigger.validation_repair,
        PipelineTrigger.review_repair,
        PipelineTrigger.integration_rebase,
        PipelineTrigger.integration_conflict,
        PipelineTrigger.push_race,
    ],
)
def test_every_child_pipeline_can_validate_its_implementation(trigger) -> None:
    assert pipeline_transition_allowed(
        PipelineCursorPhase.implementation,
        PipelineCursorPhase.validation,
        trigger=trigger,
    )


def test_phase_claim_is_atomic_across_executor_instances(config) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="claim",
            prompt="claim once",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    barrier = threading.Barrier(2)
    errors = []

    def claim() -> None:
        executor = StewardExecutor(
            config, TaskStore(config.db_path), runner=FakeRunner(config)
        )
        barrier.wait()
        try:
            executor._phase_start(task, pipeline, PipelineCursorPhase.implementation)
        except RuntimeError as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    starts = [
        event
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.started"
    ]
    assert len(starts) == 1
    assert len(errors) == 1


def test_repair_prompt_inherits_plan_and_exact_child_packet(config, monkeypatch) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="repair",
            prompt="original intent",
        )
    )
    parent = store.list_pipelines(task.id)[0]
    plan = {"summary": "accepted plan", "steps": []}
    store.add_event(
        task.id,
        "pipeline.plan.result",
        "accepted",
        {"pipeline_id": parent.id, "plan": plan},
    )
    packet = {
        "validation": {
            "validations": [
                {"command": ["zig", "build", "test"], "exit_code": 1}
            ]
        }
    }
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    child = executor._new_child_pipeline(
        task, parent, PipelineTrigger.validation_repair, packet
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.render_worker_prompt",
        lambda _task, _config, accepted: json.dumps(accepted, sort_keys=True),
    )

    prompt = executor._implementation_prompt(task, child)

    assert "accepted plan" in prompt
    assert "original intent" in prompt
    assert "zig" in prompt
    assert "validation-repair" in prompt


def _advance_to_integration(config, monkeypatch):
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_gates
    )
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="integrate",
            prompt="change README",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    for _ in range(4):
        executor.advance_once(task.id)
    assert executor._pipeline_cursor(
        task.id, store.list_pipelines(task.id)[0].id
    ) == PipelineCursorPhase.integration
    return store, task, executor


def test_integration_applies_accepted_patch_to_latest_main(config, monkeypatch) -> None:
    store, task, executor = _advance_to_integration(config, monkeypatch)
    (config.repo_root / "LATEST.md").write_text("latest\n", encoding="utf-8")
    from coquic_steward.core.subprocesses import run_command

    run_command(["git", "add", "LATEST.md"], cwd=config.repo_root, check=True)
    run_command(
        ["git", "commit", "-m", "test: advance main"],
        cwd=config.repo_root,
        check=True,
    )
    latest = run_command(
        ["git", "rev-parse", "main"], cwd=config.repo_root, check=True
    ).stdout.strip()

    result = executor.advance_once(task.id)

    child = store.get_pipeline(result.pipeline_id)
    current_task = store.get(task.id)
    assert child.trigger == PipelineTrigger.integration_rebase.value
    assert child.base_identity == latest
    assert executor.worktrees.base_commit(current_task.worktree_path) == latest
    assert (current_task.worktree_path / "README.md").read_text() == "changed\n"
    assert (current_task.worktree_path / "LATEST.md").read_text() == "latest\n"

    provisioned = executor.advance_once(task.id)
    assert provisioned.next_phase == PipelineCursorPhase.validation
    validated = executor.advance_once(task.id)
    assert validated.next_phase == PipelineCursorPhase.review


def test_integration_apply_conflict_creates_bounded_conflict_child(
    config, monkeypatch
) -> None:
    store, task, executor = _advance_to_integration(config, monkeypatch)
    (config.repo_root / "README.md").write_text("upstream\n", encoding="utf-8")
    from coquic_steward.core.subprocesses import run_command

    run_command(["git", "add", "README.md"], cwd=config.repo_root, check=True)
    run_command(
        ["git", "commit", "-m", "test: conflict on main"],
        cwd=config.repo_root,
        check=True,
    )
    latest = run_command(
        ["git", "rev-parse", "main"], cwd=config.repo_root, check=True
    ).stdout.strip()

    result = executor.advance_once(task.id)

    child = store.get_pipeline(result.pipeline_id)
    current_task = store.get(task.id)
    packet = child.metadata["packet"]
    assert child.trigger == PipelineTrigger.integration_conflict.value
    assert child.base_identity == latest
    assert packet["conflict"] is True
    assert packet["accepted_patch_identity"]
    assert (current_task.worktree_path / "README.md").read_text() == "upstream\n"


def test_push_race_reapplies_committed_accepted_patch(config, monkeypatch) -> None:
    store, task, executor = _advance_to_integration(config, monkeypatch)
    executor.advance_once(task.id)
    executor.advance_once(task.id)
    executor.advance_once(task.id)
    parent = store.list_pipelines(task.id)[0]
    current_task = store.get(task.id)
    patch = executor._accepted_patch(current_task, parent)
    assert patch is not None

    (config.repo_root / "LATEST.md").write_text("latest\n", encoding="utf-8")
    from coquic_steward.core.subprocesses import run_command

    run_command(["git", "add", "LATEST.md"], cwd=config.repo_root, check=True)
    run_command(
        ["git", "commit", "-m", "test: push race"],
        cwd=config.repo_root,
        check=True,
    )
    latest = run_command(
        ["git", "rev-parse", "main"], cwd=config.repo_root, check=True
    ).stdout.strip()

    child = executor._prepare_base_change_child(
        current_task,
        parent,
        trigger=PipelineTrigger.push_race,
        latest_main=latest,
        accepted_patch=patch,
    )

    assert child.trigger == PipelineTrigger.push_race.value
    assert child.base_identity == latest
    assert child.metadata["packet"]["patch_applied"] is True
    assert (store.get(task.id).worktree_path / "README.md").read_text() == "changed\n"


def test_integration_blocks_tree_changed_after_review(config, monkeypatch) -> None:
    store, task, executor = _advance_to_integration(config, monkeypatch)
    worktree = store.get(task.id).worktree_path
    assert worktree is not None
    (worktree / "UNREVIEWED.md").write_text("not accepted\n", encoding="utf-8")

    result = executor.advance_once(task.id)

    assert result.status == "blocked"
    assert "accepted tree" in result.evidence["summary"]


def test_validation_uses_container_validation_role(config, monkeypatch) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="validation role",
            prompt="validate",
        )
    )
    calls = []

    class Runtime:
        def __init__(self):
            self.config = SimpleNamespace(
                scratch=config.private_dir / "task-scratch" / task.id,
                git_common_dir=config.repo_root / ".git",
                container_path=lambda path, _role: "/mapped/" + Path(path).name,
            )

        def ensure_started(self):
            return "container"

        def exec(self, role, **kwargs):
            calls.append((role, kwargs))
            return SimpleNamespace(exit_code=0, stdout=b"ok\n", stderr=b"")

    runtime = Runtime()
    supervisor = SimpleNamespace(_boundary_for=lambda _task: (runtime, object()))
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    executor.session_supervisor = supervisor
    runner = executor._container_validation_runner(task, store.list_pipelines(task.id)[0])

    worktree = config.repo_root.resolve()
    command = [
        "nix",
        "develop",
        f"git+{worktree.as_uri()}#lint",
        "-c",
        "bash",
        str(worktree / "scripts" / "run-validation-with-index.sh"),
        f"--root={worktree}",
    ]
    result = runner(command, config.repo_root, 10)

    assert result.ok
    assert calls[0][0].value == "validation"
    assert "GIT_OBJECT_DIRECTORY" in calls[0][1]["env"]
    assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" in calls[0][1]["env"]
    assert calls[0][1]["workdir"] == "/mapped/repo"
    assert calls[0][1]["command"] == [
        "nix",
        "develop",
        "git+file:///mapped/repo#lint",
        "-c",
        "bash",
        "/mapped/repo/scripts/run-validation-with-index.sh",
        "--root=/mapped/repo",
    ]


def test_validation_no_progress_fingerprint_ignores_attempt_metadata(tmp_path) -> None:
    first_log = tmp_path / "iteration-1" / "gate.txt"
    second_log = tmp_path / "iteration-2" / "gate.txt"
    first_log.parent.mkdir()
    second_log.parent.mkdir()
    first_log.write_text("same failure\n", encoding="utf-8")
    second_log.write_text("same failure\n", encoding="utf-8")
    first = ValidationResult(
        command=["bash", str(tmp_path / "worktree" / "scripts" / "gate.sh")],
        cwd=tmp_path / "worktree",
        passed=False,
        exit_code=1,
        output_path=first_log,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
    )
    second = first.model_copy(
        update={
            "output_path": second_log,
            "started_at": datetime(2026, 1, 2, tzinfo=timezone.utc),
            "completed_at": datetime(2026, 1, 2, 0, 0, 1, tzinfo=timezone.utc),
        }
    )

    assert _validation_no_progress_fingerprint("same-tree", [first]) == (
        _validation_no_progress_fingerprint("same-tree", [second])
    )


def test_archive_write_preserves_parent_and_child_pipeline_refs(
    config, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="archive",
            prompt="preserve history",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    archive = TaskArchiveWriter(config)
    runs = {}
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(
        store,
        "list_runs",
        lambda _task_id, pipeline_id=None: (
            runs.get(pipeline_id, [])
            if pipeline_id is not None
            else [run for values in runs.values() for run in values]
        ),
    )

    def add_completed_run(pipeline):
        run = TaskRun(
            id=f"run-{pipeline.ordinal}",
            task_id=task.id,
            pipeline_id=pipeline.id,
            session_id=f"session-{pipeline.ordinal}",
            role="implementation",
            role_ordinal=1,
            state="succeeded",
            exit_code=0,
            started_at=now,
            updated_at=now,
            completed_at=now,
        )
        runs[pipeline.id] = [run]
        archive.materialize_run(task.id, pipeline.id, run)

    parent = store.list_pipelines(task.id)[0]
    add_completed_run(parent)
    executor._archive_write(task, parent, "parent.json", {"attempt": 1})
    child = executor._new_child_pipeline(
        task, parent, PipelineTrigger.validation_repair, {"failure": "gate"}
    )
    add_completed_run(child)
    executor._archive_write(task, child, "child.json", {"attempt": 2})

    metadata = json.loads(archive.task_path(task.id, "task.json").read_text())
    assert {item["pipelineId"] for item in metadata["pipelines"]} == {
        parent.id,
        child.id,
    }
    for item in (parent, child):
        descriptor = archive.task_path(
            task.id, f"pipelines/{item.id}/pipeline.json"
        )
        assert descriptor.is_file()

    executor._archive_write(task, child, "child-repeat.json", {"attempt": 2})
    store.transition_pipeline(child.id, "blocked", phase="review")
    terminal_task = store.finish_task(task.id, "blocked", "blocked for archive test")
    terminal_child = store.get_pipeline(child.id)
    executor._prepare_archive_task(archive, terminal_task, terminal_child)
    archive._validate_task_graph(task.id, "blocked")


def test_validation_conflict_and_phase_budgets_are_explicit(config) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="budgets",
            prompt="bounded",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    executor.MAX_VALIDATIONS = 1
    store.add_event(
        task.id,
        "pipeline.validation.result",
        "failed",
        {"pipeline_id": store.list_pipelines(task.id)[0].id},
    )
    assert (
        executor._budget_failure(task.id, PipelineCursorPhase.validation)
        == "validation budget exhausted"
    )
    assert executor.MAX_CONFLICTS > 0


@pytest.mark.parametrize(
    ("detail", "race"),
    [
        ("! [rejected] HEAD -> main (non-fast-forward)", True),
        ("! [remote rejected] HEAD -> main (protected branch hook declined)", False),
        ("remote: permission denied; rejected", False),
    ],
)
def test_push_race_classifier_is_strict(detail, race) -> None:
    from coquic_steward.execution.executor import _is_non_fast_forward_push_failure

    assert _is_non_fast_forward_push_failure(detail) is race


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

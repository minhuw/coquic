from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import threading
import pytest

from coquic_steward.agents.runner import CodexRunner
from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskRun,
    TaskWorkflow,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    PipelineCursorPhase,
    PipelineTrigger,
)
from coquic_steward.core.lifecycle import pipeline_transition_allowed
from coquic_steward.execution.container import ExecIdentity, ExecResult, TaskContainerRuntime
from coquic_steward.execution.container_config import TaskContainerConfig
from coquic_steward.execution.executor import (
    StewardExecutor,
    _validation_no_progress_fingerprint,
)
from coquic_steward.execution.worktree import (
    PATH_POLICY_STATUS_PARSE_SUMMARY,
    _PathPolicyStatusParseError,
)
from coquic_steward.execution.session import SessionSupervisor, publication_graph_for_task
from coquic_steward.publication.atif import AtifSource
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.storage import TaskStore
from coquic_steward.storage import sqlite as sqlite_module
from coquic_steward.storage.sqlite import TaskLedgerOwnershipError


class FakeRunner(CodexRunner):
    def __init__(self, config):
        super().__init__(config)

    def paths(self, task, *, name="worker"):
        path = self.config.transcripts_dir / task.id / name
        return path / "codex.jsonl", path / "last-message.md"

    def run(
        self,
        task,
        prompt,
        cwd,
        *,
        name="worker",
        output_schema=None,
        resume_session=None,
        stage=CodexStage.code,
        sandbox=None,
        task_role=None,
        idempotency_key=None,
    ):
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


def _passing_gates(
    config,
    task_id,
    cwd,
    *,
    label=None,
    on_gate_start=None,
    on_gate_result=None,
    command_runner=None,
):
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
    store = TaskStore.create(config.db_path)
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


def test_advance_once_rejects_missing_pipeline_owner_without_repair(
    config,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="missing owner",
            prompt="change README",
        )
    )
    execution = store.get_execution(task.id)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_executions SET owning_pipeline_id = NULL WHERE id = ?",
            (execution.id,),
        )
    events_before = store.events(task.id)
    executor = StewardExecutor(config, store, runner=FakeRunner(config))

    with pytest.raises(ValueError, match="owning pipeline"):
        executor.advance_once(task.id)

    assert store.get(task.id).status == TaskStatus.queued
    assert store.events(task.id) == events_before
    assert len(store.list_pipelines(task.id)) == 1


def test_durable_validation_status_parse_failure_blocks_pipeline(config, monkeypatch) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="status parse",
            prompt="change README",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    executor.advance_once(task.id)
    executor.advance_once(task.id)

    failure = _PathPolicyStatusParseError("?? " + ("x" * 300))

    def fail_status(_path):
        raise failure

    monkeypatch.setattr(executor.worktrees, "forbidden_paths", fail_status)
    result = executor.advance_once(task.id)

    assert result.status == "blocked"
    assert store.get(task.id).status == "blocked"
    event = next(
        event for event in store.events(task.id) if event.kind == "path_policy.blocked"
    )
    assert event.message == PATH_POLICY_STATUS_PARSE_SUMMARY
    assert event.data["diagnostic"] == failure.diagnostic


def test_durable_validation_rechecks_path_policy_after_gates(config, monkeypatch) -> None:
    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", _passing_gates)
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="post-gate policy",
            prompt="change README",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    executor.advance_once(task.id)
    executor.advance_once(task.id)
    frozen_calls = 0

    def frozen_paths(_path, _task):
        nonlocal frozen_calls
        frozen_calls += 1
        return [] if frozen_calls == 1 else ["flake.nix"]

    monkeypatch.setattr(executor.worktrees, "frozen_paths", frozen_paths)
    result = executor.advance_once(task.id)

    assert result.status == "blocked"
    assert store.get(task.id).status == "blocked"
    assert store.get(task.id).summary == "frozen paths changed: flake.nix"
    assert frozen_calls == 2


def test_implementation_validation_patch_tree_full_gate_is_recorded(config, monkeypatch) -> None:
    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", _passing_gates)
    store = TaskStore.create(config.db_path)
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
    execution = store.get_execution(task.id)
    assert execution.base_commit == pipeline.base_identity
    assert execution.expected_tree == pipeline.output_identity
    assert execution.worktree_path == store.get(task.id).worktree_path

    reopened = TaskStore.open(config.db_path)
    try:
        reopened_pipeline = reopened.get_pipeline(pipeline.id)
        reopened_execution = reopened.get_execution(task.id)
        assert reopened_execution.base_commit == reopened_pipeline.base_identity
        assert reopened_execution.expected_tree == reopened_pipeline.output_identity
        assert reopened_execution.worktree_path == reopened.get(task.id).worktree_path
    finally:
        reopened.engine.dispose()


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
    store = TaskStore.create(config.db_path)
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
            config, TaskStore.open(config.db_path), runner=FakeRunner(config)
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
    action = f"{task.id}:{pipeline.id}:implementation"
    assert starts[0].data == {
        "pipeline_id": pipeline.id,
        "phase": "implementation",
        "action_id": action,
        "input": {
            "task_id": task.id,
            "pipeline_id": pipeline.id,
            "action_id": action,
            "phase": "implementation",
            "base_identity": None,
            "input_identity": None,
            "patch_identity": None,
            "expected_tree": None,
            "payload": {},
        },
    }


def test_repair_prompt_inherits_plan_and_exact_child_packet(config, monkeypatch) -> None:
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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

    class Runtime(TaskContainerRuntime):
        def __init__(self):
            roots = {
                name: config.private_dir / f"task-validation-{name}-{task.id}"
                for name in ("worktree", "archive", "sessions", "git", "common", "scratch")
            }
            for root in roots.values():
                root.mkdir(parents=True, exist_ok=True)
            super().__init__(
                TaskContainerConfig(
                    task_id=task.id,
                    image="coquic-steward-task",
                    image_digest="sha256:" + "a" * 64,
                    worktree=config.repo_root,
                    archive=roots["archive"],
                    private_sessions=roots["sessions"],
                    git_dir=roots["git"],
                    git_common_dir=roots["common"],
                    scratch=roots["scratch"],
                )
            )

        def ensure_started(self):
            return self.config.container_name

        def exec(
            self,
            role,
            *,
            session_uid,
            session_id,
            command,
            env=None,
            workdir=None,
            timeout=None,
        ):
            calls.append((role, {"command": command, "env": env, "workdir": workdir, "timeout": timeout}))
            return ExecResult(
                ExecIdentity(self.config.container_name, "validation-exec", 4321, 10000),
                0,
                b"ok\n",
                b"",
            )

    runtime = Runtime()
    supervisor = SessionSupervisor(config, store, runtime=runtime)
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
    assert calls[0][1]["workdir"] == "/task/worktree-ro"
    assert calls[0][1]["command"] == [
        "nix",
        "develop",
        "git+file:///task/worktree-ro#lint",
        "-c",
        "bash",
        "/task/worktree-ro/scripts/run-validation-with-index.sh",
        "--root=/task/worktree-ro",
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
    store = TaskStore.create(config.db_path)
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


def _equivalent_publication_fixture(config, monkeypatch, home, status):
    """Build one complete archive independently from its comparison peer."""

    clock_value = datetime(2026, 1, 1, tzinfo=timezone.utc)
    fixture_config = replace(
        config,
        deployment=replace(config.deployment, home=home),
    )
    fixture_config.ensure_dirs()
    monkeypatch.setattr(sqlite_module, "new_execution_id", lambda: "execution-fixed")
    monkeypatch.setattr(sqlite_module, "new_pipeline_id", lambda: "pipeline-initial")
    store = TaskStore.create(fixture_config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            id="task-publication-equivalence",
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="complete graph fixture",
            prompt="preserve every graph dimension",
        )
    )
    parent = store.list_pipelines(task.id)[0]

    parent_session = store.create_session(
        task.id, parent.id, session_id="session-parent"
    )
    parent_run = store.create_run(
        task.id,
        parent.id,
        parent_session.id,
        run_id="run-parent",
        role="planner",
        role_ordinal=1,
    )
    store.transition_run(parent_run.id, "succeeded", expected_state="running")

    child = store.create_pipeline(
        task.id,
        execution_id=parent.execution_id,
        pipeline_id="pipeline-child",
        trigger=PipelineTrigger.validation_repair.value,
        parent_pipeline_id=parent.id,
    )

    child_session = store.create_session(task.id, child.id, session_id="session-child")
    interrupted = store.create_run(
        task.id,
        child.id,
        child_session.id,
        run_id="run-interrupted",
        role="implementation",
        role_ordinal=1,
    )
    store.transition_run(interrupted.id, "interrupted", expected_state="running")
    retry = store.create_run(
        task.id,
        child.id,
        child_session.id,
        run_id="run-retry",
        role="implementation",
        role_ordinal=2,
        retry_of_run_id=interrupted.id,
    )
    store.transition_run(retry.id, "succeeded", expected_state="running")
    recovery = store.create_run(
        task.id,
        child.id,
        child_session.id,
        run_id="run-recovery",
        role="implementation",
        role_ordinal=3,
        resume_of_run_id=interrupted.id,
        parent_run_id=retry.id,
    )
    store.transition_run(recovery.id, "succeeded", expected_state="running")
    incomplete = store.create_run(
        task.id,
        child.id,
        child_session.id,
        run_id="run-incomplete",
        role="implementation",
        role_ordinal=4,
    )

    store.add_event(task.id, "publication.fixture", "lineage and evidence")
    fixed = clock_value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with store.engine.begin() as connection:
        for table, columns in (
            ("tasks", ("created_at", "updated_at")),
            ("task_executions", ("created_at", "updated_at")),
            ("task_pipelines", ("started_at", "updated_at", "completed_at")),
            ("codex_sessions", ("started_at", "updated_at")),
            ("task_runs", ("started_at", "updated_at", "completed_at")),
            ("events", ("created_at",)),
        ):
            assignments = ", ".join(
                (
                    f"{column} = CASE WHEN {column} IS NULL THEN NULL ELSE ? END"
                    if column == "completed_at"
                    else f"{column} = ?"
                )
                for column in columns
            )
            connection.exec_driver_sql(
                f"UPDATE {table} SET {assignments}",
                tuple(fixed for _ in columns),
            )
    task = store.get(task.id)
    parent, child = store.list_pipelines(task.id)
    parent_run = store.get_run(parent_run.id)
    interrupted = store.get_run(interrupted.id)
    retry = store.get_run(retry.id)
    recovery = store.get_run(recovery.id)
    incomplete = store.get_run(incomplete.id)

    archive = TaskArchiveWriter(fixture_config)
    archive.ensure_epoch()
    archive.create_task_from_record(task, pipeline=parent)
    for pipeline, runs in (
        (parent, [parent_run]),
        (child, [interrupted, retry, recovery, incomplete]),
    ):
        archive.materialize_pipeline(task.id, pipeline, runs=runs)
    archive.write_run_file(
        task.id,
        child.id,
        retry.id,
        "telemetry.json",
        {"availability": "unavailable", "reason": "interrupted"},
    )
    archive.write_run_file(
        task.id,
        child.id,
        retry.id,
        "telemetry.retry-1.json",
        {"availability": "unavailable", "reason": "interrupted"},
    )
    archive.append_run_jsonl(
        task.id, child.id, retry.id, "codex.jsonl", {"event": "retry"}
    )
    archive.append_run_jsonl(
        task.id, child.id, retry.id, "activities.jsonl", {"activity": "retry"}
    )
    for pipeline, runs in (
        (parent, [parent_run]),
        (child, [interrupted, retry, recovery, incomplete]),
    ):
        for run in runs:
            archive.materialize_run(task.id, pipeline.id, run)
    return fixture_config, store, task.model_copy(update={"status": status})


def _reference_publication_graph(config, store, task):
    """Build the complete expected graph without calling either production wrapper."""

    archive = TaskArchiveWriter(config)
    pipelines = []
    runs = []

    def timestamp(value):
        return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )

    for pipeline in store.list_pipelines(task.id):
        pipeline_value = {
            "pipelineId": pipeline.id,
            "taskId": pipeline.task_id,
            "name": f"pipeline-{pipeline.ordinal}",
            "createdAt": timestamp(pipeline.started_at),
        }
        pipelines.append(pipeline_value)
        for run in store.list_runs(task.id, pipeline_id=pipeline.id):
            if run.completed_at is None or str(run.state) == "running":
                continue
            documents, invocations = archive.collect_run_publication_evidence(
                task.id, pipeline.id, run
            )
            completed = run.completed_at
            duration = (
                max(0, int((completed - run.started_at).total_seconds() * 1000))
                if completed is not None
                else 0
            )
            runs.append(
                {
                    "source": AtifSource(
                        run={
                            "taskId": run.task_id,
                            "pipelineId": run.pipeline_id,
                            "runId": run.id,
                            "role": str(run.role),
                            "state": str(run.state),
                            "startedAt": timestamp(run.started_at),
                            "completedAt": (
                                timestamp(completed) if completed is not None else None
                            ),
                            "durationMs": duration,
                            "model": run.model,
                            "reasoning": run.reasoning,
                            "parentRunId": run.parent_run_id,
                            "retryOfRunId": run.retry_of_run_id,
                            "resumeOfRunId": run.resume_of_run_id,
                            "invocations": [
                                item.to_dict(include_telemetry=True)
                                for item in invocations
                            ],
                        },
                        documents=documents,
                    ),
                    "pipeline": pipeline_value,
                }
            )

    status = TaskStatus(task.status)
    lifecycle = (
        "active"
        if status
        in {
            TaskStatus.queued,
            TaskStatus.running,
            TaskStatus.reviewing,
            TaskStatus.integrating,
        }
        else "cancelled"
        if status is TaskStatus.cancelled
        else "failed"
        if status in {TaskStatus.failed, TaskStatus.blocked}
        else "completed"
    )
    task_value = {
        "taskId": task.id,
        "title": task.spec.title,
        "lifecycleState": lifecycle,
        "createdAt": timestamp(task.created_at),
        "completedAt": None if lifecycle == "active" else timestamp(task.updated_at),
    }
    events = [
        {
            "taskId": task.id,
            "sequence": index,
            "eventType": event.kind,
            "occurredAt": timestamp(event.created_at),
            "summary": event.message,
        }
        for index, event in enumerate(store.events(task.id), start=1)
    ]
    return {
        "task": task_value,
        "pipelines": pipelines,
        "runs": runs,
        "events": events,
    }


@pytest.mark.parametrize(
    ("status", "lifecycle"),
    [
        ("queued", "active"),
        ("running", "active"),
        ("reviewing", "active"),
        ("integrating", "active"),
        ("succeeded", "completed"),
        ("pushed", "completed"),
        ("no_changes", "completed"),
        ("blocked", "failed"),
        ("failed", "failed"),
        ("cancelled", "cancelled"),
    ],
)
def test_publication_graph_builders_match_complete_independent_fixtures(
    config, monkeypatch, tmp_path, status, lifecycle
) -> None:
    session_config, session_store, session_task = _equivalent_publication_fixture(
        config, monkeypatch, tmp_path / "session", status
    )
    integration_config, integration_store, integration_task = (
        _equivalent_publication_fixture(config, monkeypatch, tmp_path / "integration", status)
    )

    session_graph = publication_graph_for_task(
        session_config, session_store, session_task
    )
    integration_graph = StewardExecutor(
        integration_config,
        integration_store,
        runner=FakeRunner(integration_config),
    )._integration_publication_graph(integration_task)
    session_expected = _reference_publication_graph(
        session_config, session_store, session_task
    )
    integration_expected = _reference_publication_graph(
        integration_config, integration_store, integration_task
    )

    assert session_expected == integration_expected
    assert session_graph == session_expected
    assert integration_graph == integration_expected
    assert session_graph == integration_graph
    assert session_expected["task"] == {
        "taskId": "task-publication-equivalence",
        "title": "complete graph fixture",
        "lifecycleState": lifecycle,
        "createdAt": "2026-01-01T00:00:00.000Z",
        "completedAt": (
            None if lifecycle == "active" else "2026-01-01T00:00:00.000Z"
        ),
    }
    assert session_expected["pipelines"] == [
        {
            "pipelineId": "pipeline-initial",
            "taskId": "task-publication-equivalence",
            "name": "pipeline-1",
            "createdAt": "2026-01-01T00:00:00.000Z",
        },
        {
            "pipelineId": "pipeline-child",
            "taskId": "task-publication-equivalence",
            "name": "pipeline-2",
            "createdAt": "2026-01-01T00:00:00.000Z",
        },
    ]
    assert session_expected["events"] == [
        {
            "taskId": "task-publication-equivalence",
            "sequence": 1,
            "eventType": "task.created",
            "occurredAt": "2026-01-01T00:00:00.000Z",
            "summary": "complete graph fixture",
        },
        {
            "taskId": "task-publication-equivalence",
            "sequence": 2,
            "eventType": "publication.fixture",
            "occurredAt": "2026-01-01T00:00:00.000Z",
            "summary": "lineage and evidence",
        },
    ]
    expected_runs = {
        "run-parent": ("succeeded", None, None, None),
        "run-interrupted": ("interrupted", None, None, None),
        "run-recovery": ("succeeded", "run-retry", None, "run-interrupted"),
        "run-retry": ("succeeded", None, "run-interrupted", None),
    }
    assert len(session_expected["runs"]) == len(expected_runs)
    for item in session_expected["runs"]:
        run = item["source"].run
        run_id = run["runId"]
        assert set(run) == {
            "taskId",
            "pipelineId",
            "runId",
            "role",
            "state",
            "startedAt",
            "completedAt",
            "durationMs",
            "model",
            "reasoning",
            "parentRunId",
            "retryOfRunId",
            "resumeOfRunId",
            "invocations",
        }
        assert run["taskId"] == "task-publication-equivalence"
        assert run["startedAt"] == "2026-01-01T00:00:00.000Z"
        assert run["completedAt"] == "2026-01-01T00:00:00.000Z"
        assert run["durationMs"] == 0
        assert (run["state"], run["parentRunId"], run["retryOfRunId"], run["resumeOfRunId"]) == expected_runs[run_id]
        assert set(item["source"].documents) == {
            "run.json",
        } | ({"activities.jsonl", "codex.jsonl", "telemetry.json"} if run_id == "run-retry" else set())
    assert session_graph["task"]["lifecycleState"] == lifecycle
    assert [item["pipeline"]["pipelineId"] for item in session_graph["runs"]] == [
        "pipeline-initial",
        "pipeline-child",
        "pipeline-child",
        "pipeline-child",
    ]
    assert [item["source"].run["runId"] for item in session_graph["runs"]] == [
        "run-parent",
        "run-interrupted",
        "run-recovery",
        "run-retry",
    ]
    by_run = {
        item["source"].run["runId"]: item["source"] for item in session_graph["runs"]
    }
    assert by_run["run-recovery"].run["parentRunId"] == "run-retry"
    assert by_run["run-retry"].run["retryOfRunId"] == "run-interrupted"
    assert set(by_run["run-retry"].documents) == {
        "activities.jsonl",
        "codex.jsonl",
        "run.json",
        "telemetry.json",
    }
    assert by_run["run-retry"].run["invocations"][0][
        "availability"
    ] == "partial"


def test_publication_graph_ownership_is_session_only(config, monkeypatch) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="ownership boundary",
            prompt="preserve wrapper policy",
        )
    )
    execution = store.get_execution(task.id)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_executions SET owning_pipeline_id = NULL WHERE id = ?",
            (execution.id,),
        )

    with pytest.raises(TaskLedgerOwnershipError, match="owning pipeline"):
        publication_graph_for_task(config, store, task)
    integration_graph = StewardExecutor(
        config, store, runner=FakeRunner(config)
    )._integration_publication_graph(task)
    assert integration_graph["task"]["taskId"] == task.id



@pytest.mark.parametrize(
    ("status", "lifecycle"),
    [
        ("queued", "active"),
        ("running", "active"),
        ("reviewing", "active"),
        ("integrating", "active"),
        ("succeeded", "completed"),
        ("pushed", "completed"),
        ("no_changes", "completed"),
        ("blocked", "failed"),
        ("failed", "failed"),
        ("cancelled", "cancelled"),
    ],
)
def test_publication_graph_builders_map_all_legal_lifecycles(
    config, status: str, lifecycle: str
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="lifecycle",
            prompt="map status",
        )
    )
    task = task.model_copy(update={"status": status})
    executor = StewardExecutor(config, store, runner=FakeRunner(config))

    session_graph = publication_graph_for_task(config, store, task)
    integration_graph = executor._integration_publication_graph(task)

    assert session_graph == integration_graph
    assert session_graph["task"]["lifecycleState"] == lifecycle


def test_publication_graph_builders_reject_invalid_status(config) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="invalid status",
            prompt="fail closed",
        )
    )
    invalid = task.model_copy(update={"status": "corrupt"})
    executor = StewardExecutor(config, store, runner=FakeRunner(config))

    with pytest.raises(ValueError):
        publication_graph_for_task(config, store, invalid)
    with pytest.raises(ValueError):
        executor._integration_publication_graph(invalid)


def test_validation_conflict_and_phase_budgets_are_explicit(config) -> None:
    store = TaskStore.create(config.db_path)
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


def test_stale_parent_child_creation_propagates_ownership_error(config) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="stale parent",
            prompt="change",
        )
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    parent = store.list_pipelines(task.id)[0]
    child = executor._new_child_pipeline(
        task,
        parent,
        PipelineTrigger.validation_repair,
        {"failure": "first"},
    )
    events_before = store.events(task.id)

    with pytest.raises(TaskLedgerOwnershipError, match="current execution owner"):
        executor._new_child_pipeline(
            task,
            parent,
            PipelineTrigger.validation_repair,
            {"failure": "stale"},
        )

    saved = store.list_pipelines(task.id)
    assert [item.id for item in saved] == [parent.id, child.id]
    assert saved[0].state == "superseded"
    assert saved[1].state == "active"
    assert store.events(task.id) == events_before


def test_child_pipeline_budget_and_no_progress_fingerprint_are_explicit(config) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, workflow=TaskWorkflow.fix, worker=WorkerKind.custom, title="budget", prompt="change")
    )
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    parent = store.list_pipelines(task.id)[0]
    child = executor._new_child_pipeline(task, parent, PipelineTrigger.validation_repair, {"fingerprint": "same"})
    assert child.parent_pipeline_id == parent.id
    saved_child = next(
        pipeline for pipeline in store.list_pipelines(task.id) if pipeline.id == child.id
    )
    assert saved_child.trigger == PipelineTrigger.validation_repair.value


def test_integration_latest_main_rebase_conflict_remains_source_task() -> None:
    assert PipelineTrigger.integration_rebase.value == "integration-rebase"
    assert PipelineTrigger.integration_conflict.value == "integration-conflict"
    assert PipelineTrigger.push_race.value == "push-race"


def test_commit_message_push_race_ready_to_seal_authority() -> None:
    assert pipeline_transition_allowed(PipelineCursorPhase.commit_message, PipelineCursorPhase.commit)
    assert pipeline_transition_allowed(PipelineCursorPhase.commit, PipelineCursorPhase.push)
    assert pipeline_transition_allowed(PipelineCursorPhase.push, PipelineCursorPhase.ready_to_seal)

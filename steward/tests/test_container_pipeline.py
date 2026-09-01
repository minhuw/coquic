from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import threading

import pytest
from sqlalchemy.orm import Session

from coquic_steward.agents.runner import CodexRunner
from coquic_steward.core.config import PathPolicyConfig, StewardConfig
from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskRun,
    TaskRecord,
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
    _is_transient_push_failure,
    _validation_no_progress_fingerprint,
    frozen_patch_paths,
    parse_commit_message,
    render_commit_message_prompt,
)
from coquic_steward.execution.worktree import (
    PATH_POLICY_STATUS_PARSE_SUMMARY,
    _PathPolicyStatusParseError,
    _changed_paths_from_porcelain,
)
from coquic_steward.execution import Worktrees
from coquic_steward.execution import executor as executor_module
from coquic_steward.execution import worktree as worktree_module
from coquic_steward.execution.session import SessionSupervisor, publication_graph_for_task
from coquic_steward.orchestration import StewardDaemon
from coquic_steward.orchestration import daemon as daemon_module
from coquic_steward.publication.atif import AtifSource
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.storage import TaskStore
from coquic_steward.storage import sqlite as sqlite_module
from coquic_steward.storage.schema import ValidationRow
from coquic_steward.storage.sqlite import TaskLedgerOwnershipError
from coquic_steward.core.subprocesses import CommandResult, run_command
from durable_harness import (
    _advance_durable,
    _callback_gate_results,
    _durable_push_setup,
    drive_durable,
    passing_durable_gates,
    write_durable_codex,
)


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
    command = ["fake-gate"]
    if on_gate_start is not None:
        on_gate_start(0, "pipeline.txt", command)
    output = config.logs_dir / task_id / "pipeline.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("ok\n", encoding="utf-8")
    validation = ValidationResult(
        command=command, cwd=cwd, passed=True, exit_code=0, output_path=output
    )
    if on_gate_result is not None:
        on_gate_result(0, validation)
    return [validation]


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

def test_worktree_create_and_patch(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktrees = Worktrees(config)
    path, branch = worktrees.create(task)

    (path / "README.md").write_text("changed\n", encoding="utf-8")
    patch = config.patches_dir / "task.patch"
    worktrees.save_patch(path, patch)

    assert path.exists()
    assert branch.startswith("steward/")
    assert "changed" in patch.read_text(encoding="utf-8")
    assert worktrees.has_changes(path)


def test_local_remote_git_operations_keep_ambient_authentication(
    config: StewardConfig, monkeypatch
) -> None:
    local_config = replace(config, dry_run=False)
    commands: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_run_command(command, cwd, *, env=None, **_kwargs):
        commands.append((command, env))
        return CommandResult(command, cwd, 0, "", "")

    monkeypatch.setattr(worktree_module, "run_command", fake_run_command)

    assert Worktrees(local_config)._new_worktree_base() == "origin/main"
    assert commands == [(["git", "fetch", "origin", "main"], {})]


def test_worktree_create_uses_fresh_remote_main_when_local_main_diverges(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    upstream = tmp_path / "upstream"
    run_command(["git", "init", "--bare", str(remote)], cwd=tmp_path, check=True)
    run_command(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    run_command(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    run_command(
        ["git", "clone", "--branch", "main", str(remote), str(upstream)],
        cwd=tmp_path,
        check=True,
    )
    run_command(
        ["git", "config", "user.email", "steward@example.test"],
        cwd=upstream,
        check=True,
    )
    run_command(
        ["git", "config", "user.name", "Steward Test"],
        cwd=upstream,
        check=True,
    )
    (upstream / "README.md").write_text("remote\n", encoding="utf-8")
    run_command(["git", "add", "README.md"], cwd=upstream, check=True)
    run_command(["git", "commit", "-m", "remote change"], cwd=upstream, check=True)
    run_command(["git", "push", "origin", "main"], cwd=upstream, check=True)

    (config.repo_root / "LOCAL.md").write_text("local only\n", encoding="utf-8")
    run_command(["git", "add", "LOCAL.md"], cwd=config.repo_root, check=True)
    run_command(
        ["git", "commit", "-m", "local change"], cwd=config.repo_root, check=True
    )
    push_config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "dry_run": False,
        }
    )
    store = TaskStore.create(push_config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    commands: list[tuple[list[str], dict[str, str] | None]] = []
    original_run_command = worktree_module.run_command
    ssh_command = "ssh -i /tmp/strict-ssh"

    def recording_run_command(command, cwd, *, env=None, **kwargs):
        commands.append((command, env))
        return original_run_command(command, cwd, env=env, **kwargs)

    monkeypatch.setattr(
        worktree_module,
        "git_remote_environment",
        lambda _config: {
            "GIT_SSH_COMMAND": ssh_command,
            "GCM_INTERACTIVE": "never",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    monkeypatch.setattr(worktree_module, "run_command", recording_run_command)
    path, _ = Worktrees(push_config).create(task)

    fetch_env = next(
        env for command, env in commands if command[:2] == ["git", "fetch"]
    )
    assert fetch_env == {
        "GIT_SSH_COMMAND": ssh_command,
        "GCM_INTERACTIVE": "never",
        "GIT_TERMINAL_PROMPT": "0",
    }
    worktree_add_env = next(
        env for command, env in commands if command[:3] == ["git", "worktree", "add"]
    )
    assert worktree_add_env is None

    worktree_head = run_command(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True
    ).stdout.strip()
    remote_head = run_command(
        ["git", "rev-parse", "origin/main"], cwd=config.repo_root, check=True
    ).stdout.strip()
    assert worktree_head == remote_head
    assert (path / "README.md").read_text(encoding="utf-8") == "remote\n"
    assert not (path / "LOCAL.md").exists()

def test_worktree_reset_authenticates_fetch_but_not_local_reset(
    config: StewardConfig, monkeypatch
) -> None:
    commands: list[tuple[list[str], dict[str, str] | None]] = []
    ssh_command = "ssh -i /tmp/strict-ssh"

    def fake_run_command(command, cwd, *, env=None, **_kwargs):
        commands.append((command, env))
        return CommandResult(command, cwd, 0, "", "")

    monkeypatch.setattr(
        worktree_module,
        "git_remote_environment",
        lambda _config: {
            "GIT_SSH_COMMAND": ssh_command,
            "GCM_INTERACTIVE": "never",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    monkeypatch.setattr(worktree_module, "run_command", fake_run_command)

    Worktrees(config).reset_to_main(config.repo_root)

    assert commands[0][1] == {
        "GIT_SSH_COMMAND": ssh_command,
        "GCM_INTERACTIVE": "never",
        "GIT_TERMINAL_PROMPT": "0",
    }
    assert commands[1][0][:2] == ["git", "reset"]
    assert commands[1][1] is None


def test_executor_remote_fetch_authenticates_but_local_checks_do_not(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    commands: list[tuple[list[str], dict[str, str] | None]] = []
    ssh_command = "ssh -i /tmp/strict-ssh"

    def fake_run_command(command, cwd, *, env=None, **_kwargs):
        commands.append((command, env))
        stdout = "remote-tip\n" if command[1:2] == ["rev-parse"] else ""
        return CommandResult(command, cwd, 0, stdout, "")

    monkeypatch.setattr(
        executor_module,
        "git_remote_environment",
        lambda _config: {
            "GIT_SSH_COMMAND": ssh_command,
            "GCM_INTERACTIVE": "never",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    monkeypatch.setattr(executor_module, "run_command", fake_run_command)

    assert executor._latest_main_identity(config.repo_root, dry_run=False) == "remote-tip"
    assert executor._commit_reachable(config.repo_root, "commit")

    fetch_envs = [
        env for command, env in commands if command[:2] == ["git", "fetch"]
    ]
    assert fetch_envs == [
        {
            "GIT_SSH_COMMAND": ssh_command,
            "GCM_INTERACTIVE": "never",
            "GIT_TERMINAL_PROMPT": "0",
        }
    ] * 2
    local_envs = [
        env
        for command, env in commands
        if command[:2] == ["git", "rev-parse"]
        or command[:2] == ["git", "merge-base"]
    ]
    assert local_envs == [None, None]


def test_commit_all_skips_hooks_only_for_the_validated_tree(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    (path / "README.md").write_text("validated\n", encoding="utf-8")
    validated_tree = worktrees.stage_tree(path)
    hook_marker = tmp_path / "hook-ran"
    hook = config.repo_root / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        f"#!/bin/sh\ntouch '{hook_marker}'\nexit 1\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)

    sha = worktrees.commit_all(
        path,
        "test: commit validated tree",
        expected_tree=validated_tree,
    )

    assert sha is not None
    assert not hook_marker.exists()
    committed_tree = run_command(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=path, check=True
    ).stdout.strip()
    assert committed_tree == validated_tree

def test_commit_all_rejects_changes_after_validation(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    (path / "README.md").write_text("validated\n", encoding="utf-8")
    validated_tree = worktrees.stage_tree(path)
    head_before = run_command(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True
    ).stdout.strip()
    (path / "README.md").write_text("changed later\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="staged tree changed after validation"):
        worktrees.commit_all(
            path,
            "test: reject changed tree",
            expected_tree=validated_tree,
        )
    (path / "README.md").write_text("hello\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="staged tree changed after validation"):
        worktrees.commit_all(
            path,
            "test: reject reverted tree",
            expected_tree=validated_tree,
        )

    assert (
        run_command(["git", "rev-parse", "HEAD"], cwd=path, check=True).stdout.strip()
        == head_before
    )

def test_worktree_patch_includes_staged_and_untracked_changes(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom, worker=WorkerKind.custom, title="Source", prompt="P"
        )
    )
    target, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom, worker=WorkerKind.custom, title="Target", prompt="P"
        )
    )
    worktrees = Worktrees(config)
    source_path, _ = worktrees.create(source)
    target_path, _ = worktrees.create(target)

    (source_path / "README.md").write_text("staged\n", encoding="utf-8")
    run_command(["git", "add", "README.md"], cwd=source_path, check=True)
    untracked = source_path / "notes" / "new file.txt"
    untracked.parent.mkdir()
    untracked.write_text("untracked\n", encoding="utf-8")

    patch = worktrees.diff(source_path)
    worktrees.apply_patch(target_path, patch)

    assert (target_path / "README.md").read_text(encoding="utf-8") == "staged\n"
    assert (target_path / "notes" / "new file.txt").read_text(
        encoding="utf-8"
    ) == "untracked\n"
    assert "new file mode 100644" in patch

def test_worktree_reports_frozen_file_and_directory_changes(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={
                    TaskKind.feature.value: ("flake.nix", r".github\**")
                }
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    (path / "flake.nix").write_text("{}\n", encoding="utf-8")
    workflow = path / ".github" / "workflows" / "test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: test\n", encoding="utf-8")
    (path / "src").mkdir()
    (path / "src" / "main.cpp").write_text("int main() {}\n", encoding="utf-8")

    assert worktrees.frozen_paths(path, task) == [
        ".github/workflows/test.yml",
        "flake.nix",
    ]

def test_porcelain_z_parser_preserves_structural_utf8_paths() -> None:
    output = (
        "??  leading and trailing  \0"
        " M tab\tinside\t \0"
        "?? line\nbreak\0"
        '?? "quoted -> name"\0'
        "?? directory\\name\0"
        "?? literal -> arrow\0"
        "?? leading and trailing\0"
    )

    assert _changed_paths_from_porcelain(output) == [
        "leading and trailing",
        "tab\tinside",
        "line\nbreak",
        '"quoted -> name"',
        "directory/name",
        "literal -> arrow",
    ]

@pytest.mark.parametrize("status", ["R  ", "C  "])
def test_porcelain_z_parser_returns_rename_source_then_destination(status: str) -> None:
    assert _changed_paths_from_porcelain(
        f"{status}destination -> name\0source\\name\0"
    ) == ["source/name", "destination -> name"]

@pytest.mark.parametrize(
    "output",
    ["ZZ path\0", "  path\0", "?M path\0", "!M path\0"],
)
def test_porcelain_z_parser_rejects_invalid_status_fields(output: str) -> None:
    with pytest.raises(_PathPolicyStatusParseError):
        _changed_paths_from_porcelain(output)

def test_porcelain_z_parser_rejects_truncated_records_with_bounded_diagnostic() -> None:
    output = "?? " + ("x" * 300)

    with pytest.raises(_PathPolicyStatusParseError) as raised:
        _changed_paths_from_porcelain(output)

    error = raised.value
    assert str(error) == PATH_POLICY_STATUS_PARSE_SUMMARY
    assert error.diagnostic == {
        "raw_prefix": repr(output.encode("utf-8")[:256]),
        "byte_length": len(output.encode("utf-8")),
    }

def test_porcelain_z_parser_rejects_truncated_rename_record() -> None:
    with pytest.raises(_PathPolicyStatusParseError) as raised:
        _changed_paths_from_porcelain("R  destination\0")

    assert raised.value.diagnostic == {
        "raw_prefix": repr(b"R  destination\0"),
        "byte_length": len(b"R  destination\0"),
    }

def test_git_porcelain_z_reports_rename_destination_before_source(tmp_path: Path) -> None:
    repo = tmp_path / "status-repo"
    run_command(["git", "init", "-q", str(repo)], cwd=tmp_path, check=True)
    run_command(
        ["git", "config", "user.email", "steward@example.test"],
        cwd=repo,
        check=True,
    )
    run_command(
        ["git", "config", "user.name", "Steward Test"], cwd=repo, check=True
    )
    (repo / "source name.txt").write_text("source\n", encoding="utf-8")
    run_command(["git", "add", "source name.txt"], cwd=repo, check=True)
    run_command(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    run_command(
        ["git", "mv", "source name.txt", "destination -> name.txt"],
        cwd=repo,
        check=True,
    )

    output = run_command(
        [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
        cwd=repo,
        check=True,
    ).stdout

    assert output.split("\0")[:2] == [
        "R  destination -> name.txt",
        "source name.txt",
    ]
    assert _changed_paths_from_porcelain(output) == [
        "source name.txt",
        "destination -> name.txt",
    ]

def test_frozen_patch_paths_preserve_matching_contract(config: StewardConfig) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={
                    TaskKind.feature.value: (
                        "src/locked.txt/",
                        "docs/R*.md",
                        r"windows\path.txt",
                    )
                }
            ),
        }
    )
    task = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    patch = """\
diff --git a/src/locked.txt b/src/locked.txt
diff --git a/src/locked.txt/child.py b/src/locked.txt/child.py
diff --git a/docs/README.md b/docs/README.md
diff --git a/docs/readme.md b/docs/readme.md
diff --git a/windows/path.txt b/windows/path.txt
diff --git a/WINDOWS/path.txt b/WINDOWS/path.txt
diff --git a/src/open.txt b/src/open.txt
"""

    assert frozen_patch_paths(config, task, patch) == [
        "src/locked.txt",
        "src/locked.txt/child.py",
        "docs/README.md",
        "windows/path.txt",
    ]

def test_frozen_patch_paths_match_renamed_files(config: StewardConfig) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
        }
    )
    task = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    patch = """\
diff --git a/flake.nix b/config/flake.nix
similarity index 100%
rename from flake.nix
rename to config/flake.nix
"""

    assert frozen_patch_paths(config, task, patch) == ["flake.nix"]

def test_executor_no_changes_reaches_terminal_status(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'no changes\\n' > \"$last\"\\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    executor = StewardExecutor(config, store)
    assert drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.no_changes
    assert any(event.kind == "pipeline.ready_to_seal" for event in store.events(task.id))
    assert not any(event.kind == "pipeline.blocked" for event in store.events(task.id))

def test_executor_blocks_worker_patch_that_changes_frozen_path(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf '{}\n' > flake.nix\n"
        "printf 'changed frozen path\\n' > \"$last\"\\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.custom.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates",
        lambda *_args, **_kwargs: pytest.fail("validation should not run after a frozen path change"),
    )
    executor = StewardExecutor(config, store)
    assert not drive_durable(executor, task.id)

    saved = store.get(task.id)
    events = store.events(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert any(event.kind == "pipeline.blocked" for event in events)

def test_executor_blocks_frozen_path_written_by_validation(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'source change\n' > README.md\n"
        "printf 'changed source\\n' > \"$last\"\\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.custom.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_gates(_config, task_id, cwd, **_kwargs):
        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    executor = StewardExecutor(config, store)
    assert not drive_durable(executor, task.id)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert saved.patch_path is None
    assert any(event.kind == "pipeline.blocked" for event in store.events(task.id))

def test_executor_does_not_clean_external_finished_worktree(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    external = tmp_path / "external-worktree"
    external.mkdir()
    task.worktree_path = external
    store.save(task)
    store.update_status(task.id, TaskStatus.running, "started")

    store.finish_task(task.id, TaskStatus.failed, "failed")
    StewardExecutor(config, store).clean_finished_task_worktree(store.get(task.id))

    assert external.exists()
    assert not any(event.kind == "worktree.cleaned" for event in store.events(task.id))

def test_executor_marks_task_validation_running_before_gates(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="changed by steward")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    observed: dict[str, object] = {}

    def fake_gates(_config, task_id, cwd, **_kwargs):
        current = store.get(task_id)
        observed["status"] = current.status
        observed["summary"] = current.summary
        observed["phase"] = next(
            event.data["phase"]
            for event in reversed(store.events(task_id))
            if event.kind == "pipeline.phase.started"
        )
        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    executor = StewardExecutor(config, store)
    _advance_durable(executor, task.id, 3)

    assert observed["status"] == TaskStatus.running
    assert observed["phase"] == "validation"

def test_executor_records_validation_results_incrementally(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    observed: dict[str, object] = {}

    def fake_gates(
        _config,
        task_id,
        cwd,
        *,
        label=None,
        on_gate_start=None,
        on_gate_result=None,
        command_runner=None,
    ):
        assert on_gate_start is not None
        assert on_gate_result is not None
        results = []
        for position, command in enumerate((["gate-0"], ["gate-1"])):
            on_gate_start(position, f"gate-{position}.txt", command)
            output = _config.logs_dir / task_id / (label or "validation") / f"gate-{position}.txt"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(f"gate {position}\n", encoding="utf-8")
            validation = ValidationResult(
                command=command,
                cwd=cwd,
                passed=True,
                exit_code=0,
                output_path=output,
                summary=f"gate {position}",
            )
            results.append(validation)
            on_gate_result(position, validation)
            observed[f"after_gate_{position}"] = [
                item.command for item in store.get(task_id).validations
            ]
        return results

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    executor = StewardExecutor(config, store)
    _advance_durable(executor, task.id, 3)

    assert observed == {
        "after_gate_0": [["gate-0"]],
        "after_gate_1": [["gate-0"], ["gate-1"]],
    }
    with Session(store.engine) as session:
        rows = (
            session.query(ValidationRow)
            .filter_by(task_id=task.id)
            .order_by(ValidationRow.position)
            .all()
        )
    assert [json.loads(row.command_json) for row in rows] == [["gate-0"], ["gate-1"]]
    assert [row.position for row in rows] == [0, 1]
    assert [row.iteration for row in rows] == [0, 0]

    reopened = TaskStore.open(config.db_path)
    try:
        reopened_rows = reopened.get(task.id).validations
        assert [item.command for item in reopened_rows] == [["gate-0"], ["gate-1"]]
        assert [item.iteration for item in reopened_rows] == [0, 0]
    finally:
        reopened.engine.dispose()

def test_executor_persists_completed_gate_before_interruption(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=config.transcripts_dir / task.id / "worker" / "codex.jsonl",
        worker_last_message_path=config.transcripts_dir / task.id / "worker" / "last-message.md",
    )

    def interrupted_gates(
        configured,
        task_id,
        cwd,
        *,
        label=None,
        on_gate_start=None,
        on_gate_result=None,
        command_runner=None,
    ):
        command = ["gate-0"]
        output = configured.logs_dir / task_id / (label or "validation") / "gate-0.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("gate 0\n", encoding="utf-8")
        if on_gate_start is not None:
            on_gate_start(0, "gate-0.txt", command)
        validation = ValidationResult(
            command=command,
            cwd=cwd,
            passed=True,
            exit_code=0,
            output_path=output,
        )
        if on_gate_result is not None:
            on_gate_result(0, validation)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", interrupted_gates
    )
    executor = StewardExecutor(config, store)
    with pytest.raises(KeyboardInterrupt):
        executor._run_gates_for_iteration(task.id, config.repo_root, 0)

    reopened = TaskStore.open(config.db_path)
    try:
        saved = reopened.get(task.id)
        assert len(saved.validations) == 1
        assert saved.validations[0].command == ["gate-0"]
        finished = [
            event
            for event in reopened.events(task.id)
            if event.kind == "validation.command_finished"
        ]
        assert len(finished) == 1
        assert finished[0].data["position"] == 0
    finally:
        reopened.engine.dispose()

def test_executor_rejects_invalid_review_output(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, review="not-json")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert not drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert any(event.kind == "pipeline.review.raw" for event in store.events(task.id))
    assert any(event.kind == "pipeline.blocked" for event in store.events(task.id))

def test_executor_accepts_approved_review_with_validation_gaps(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(
        tmp_path,
        review='{"verdict":"approve","summary":"ok with gap","findings":[],"validation_gaps":["shellcheck unavailable"],"remaining_risk":"low"}',
    )
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    outcomes = _advance_durable(executor, task.id, 4)
    assert outcomes[-1].next_phase.value == "integration"
    assert any(
        event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("next_phase") == "integration"
        for event in store.events(task.id)
    )
    assert not any(event.kind == "pipeline.formality.effective" for event in store.events(task.id))

def test_executor_push_main_uses_durable_commit_phase(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "dry_run": True,
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path, dry_run=config.dry_run)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))
    assert not any(
        item.spec.worker == WorkerKind.integration_manager
        for item in store.list_tasks()
    )

def test_durable_dry_run_commit_proposes_remote_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, dry_run=True
    )
    assert drive_durable(executor, integration.id)
    assert store.get(integration.id).status == TaskStatus.succeeded
    assert store.get(source.id).status == TaskStatus.queued
    remote_text = subprocess.run(
        ["git", "show", "origin/main:README.md"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert remote_text == "hello\n"
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_dry_run_feature_issue_proposals_are_persisted(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,), dry_run=True
    )
    commands: list[list[str]] = []
    real_command = run_command

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            pytest.fail("dry-run issue proposals must not invoke GitHub")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert drive_durable(executor, integration.id)

    actions = [
        event.data["action"]
        for event in store.events(integration.id)
        if event.kind == "effect.proposed"
    ]
    assert actions == ["git.push", "github.issue.comment", "github.issue.close"]
    assert [
        event.kind
        for event in store.events(source.id)
        if event.kind in {"github.issue_comment_proposed", "github.issue_close_proposed"}
    ] == ["github.issue_comment_proposed", "github.issue_close_proposed"]
    assert commands == []

def test_dry_run_feature_issue_proposals_must_persist_before_ready_to_seal(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,), dry_run=True
    )
    real_command = run_command

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("dry-run issue proposals must not invoke GitHub")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    _advance_durable(executor, integration.id, 7)
    shutil.rmtree(config.transcripts_dir)
    config.transcripts_dir.write_text("transcript path collision\n", encoding="utf-8")

    outcome = executor.advance_once(integration.id)

    assert outcome.status == "advanced"
    assert outcome.next_phase.value == "push"
    assert not TaskStatus(store.get(integration.id).status).terminal
    assert not any(
        event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("next_phase") == "ready_to_seal"
        for event in store.events(integration.id)
    )
    proposals = [
        event
        for event in store.events(integration.id)
        if event.kind == "effect.proposed"
    ]
    assert [event.data["action"] for event in proposals] == ["git.push"]
    assert not any(
        event.kind in {"github.issue_comment_proposed", "github.issue_close_proposed"}
        for event in store.events(source.id)
    )
    assert any(
        event.kind == "github.issue_update_failed"
        for event in store.events(integration.id)
    )

def test_durable_push_blocks_when_main_push_budget_is_reached(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(
        config,
        tmp_path,
        monkeypatch,
        max_main_pushes_per_day=1,
    )
    store.add_event("prior-push", "main.pushed", "already-pushed")

    def unexpected_push(_worktree):
        raise AssertionError("push must be blocked by the daily budget")

    monkeypatch.setattr(Worktrees, "push_head_to_main", unexpected_push)
    assert not drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "main push budget reached"
    assert any(
        event.kind == "pipeline.push.blocked" for event in store.events(integration.id)
    )
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_durable_ordinary_push_uses_task_as_issue_source(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, _integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    source.spec.kind = TaskKind.custom
    source.spec.workflow = TaskWorkflow.fix
    source.spec.worker = WorkerKind.custom
    store.save(source)
    commands: list[list[str]] = []
    environments: list[dict[str, str] | None] = []
    real_command = run_command

    def command(argv, cwd, *, timeout=None, env=None, **_kwargs):
        if argv and argv[0] == "gh":
            commands.append(argv)
            environments.append(env)
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, env=env, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert drive_durable(executor, source.id), (
        f"status={store.get(source.id).status} "
        f"summary={store.get(source.id).summary} "
        f"events={[event.kind for event in store.events(source.id)]}"
    )

    assert store.get(source.id).status == TaskStatus.pushed
    assert any(event.kind == "pipeline.push" for event in store.events(source.id))
    assert [item[:3] for item in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    assert environments == [{}, {}]
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))


def test_durable_issue_updates_use_authenticated_cli_without_leaking_token(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    token = "github-executor-token-canary"
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    commands: list[tuple[list[str], dict[str, str] | None]] = []
    helper_calls = 0
    real_command = run_command

    def fake_github_cli_environment(_config):
        nonlocal helper_calls
        helper_calls += 1
        return {"GH_TOKEN": token}

    def command(argv, cwd, *, timeout=None, env=None, **_kwargs):
        if argv and argv[0] == "gh":
            commands.append((argv, env))
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, env=env, **_kwargs)

    monkeypatch.setattr(
        "coquic_steward.execution.executor.github_cli_environment",
        fake_github_cli_environment,
    )
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert drive_durable(executor, integration.id)

    assert [argv[:3] for argv, _env in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    assert helper_calls == 2
    assert [env for _argv, env in commands] == [{"GH_TOKEN": token}] * 2
    assert all(token not in " ".join(argv) for argv, _env in commands)
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None
    assert token not in transcript.read_text(encoding="utf-8")
    events = store.events(source.id) + store.events(integration.id)
    evidence = "\n".join(
        [event.message for event in events]
        + [json.dumps(event.data, sort_keys=True, default=str) for event in events]
    )
    assert token not in evidence


def test_durable_validation_blocks_frozen_path_before_commit(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, frozen_paths=("flake.nix",)
    )

    def gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "frozen.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return _callback_gate_results(
            [ValidationResult(command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output)],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    assert not drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert not any(event.kind == "pipeline.commit" for event in store.events(integration.id))

def test_durable_validation_blocks_frozen_path_before_repair_child(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, frozen_paths=("flake.nix",)
    )

    def gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "frozen-failure.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("failed\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return _callback_gate_results(
            [ValidationResult(command=["fake"], cwd=cwd, passed=False, exit_code=1, output_path=output)],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    assert not drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert len(store.list_pipelines(integration.id)) == 1

def test_commit_message_prompt_includes_patch_context(config: StewardConfig) -> None:
    source = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="Fix a focused batch of current Codacy findings",
            prompt="Fix the selected shellcheck finding.",
            metadata={
                "source_context": {
                    "selected_signal_items": [
                        {
                            "id": "wi-codacy-1",
                            "provider": "codacy",
                            "rule_id": "shellcheck_SC2034",
                            "file": "scripts/fuzz-targets.sh",
                            "line": 9,
                        }
                    ]
                }
            },
        )
    )
    validation_output = config.logs_dir / "task-1" / "fake.txt"
    validation = ValidationResult(
        command=["zig", "build", "test"],
        cwd=config.repo_root,
        passed=True,
        exit_code=0,
        output_path=validation_output,
        summary="ok",
    )
    patch_text = """\
diff --git a/scripts/fuzz-targets.sh b/scripts/fuzz-targets.sh
index 1111111..2222222 100644
--- a/scripts/fuzz-targets.sh
+++ b/scripts/fuzz-targets.sh
@@ -1 +1 @@
-old
+new
"""

    prompt = render_commit_message_prompt(
        source, patch_text, ["scripts/fuzz-targets.sh"], [validation]
    )

    assert "integration commit-message writer" in prompt
    assert "Fix the selected shellcheck finding." in prompt
    assert "shellcheck_SC2034" in prompt
    assert "zig" in prompt
    assert "scripts/fuzz-targets.sh" in prompt
    assert patch_text.strip() in prompt

def test_parse_commit_message_rejects_invalid_subject() -> None:
    assert parse_commit_message('{"subject":"fix: update rag","body":"Body"}') == {
        "subject": "fix: update rag",
        "body": "Body",
    }
    assert parse_commit_message('{"subject":"Fix rag","body":"Body"}') is None
    assert (
        parse_commit_message(
            '{"subject":"fix: '
            + ("x" * 80)
            + '","body":"Body"}'
        )
        is None
    )

def test_durable_push_persists_transport_retry_before_success(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    real_push = Worktrees.push_head_to_main
    real_command = run_command
    attempts = 0
    trace: list[str] = []

    def transient_push(worktrees, path):
        nonlocal attempts
        attempts += 1
        trace.append("push")
        if attempts == 1:
            raise RuntimeError("Could not resolve host: github.com")
        return real_push(worktrees, path)

    def command(argv, cwd, *, timeout=None, **_kwargs):
        if argv and argv[0] == "gh":
            trace.append(argv[2])
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", transient_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert drive_durable(executor, integration.id)

    saved = store.get(integration.id)
    events = store.events(integration.id)
    assert saved.status == TaskStatus.pushed
    assert attempts == 2
    assert any(event.kind == "pipeline.push.retry" for event in events)
    assert any(event.kind == "pipeline.push" for event in events)
    assert trace == ["push", "push", "comment", "close"]
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))

def test_durable_push_blocks_after_bounded_transport_failures(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    attempts = 0

    def fail_push(_worktrees, _path):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Could not resolve host: github.com")

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("unsuccessful durable push must not invoke GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", fail_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert not drive_durable(executor, integration.id)

    saved = store.get(integration.id)
    events = store.events(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "push made no progress"
    assert attempts == 2
    assert any(event.kind == "pipeline.push.failure" for event in events)
    assert any(event.kind == "pipeline.push.retry" for event in events)
    assert not any(event.kind == "pipeline.push" for event in events)
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))

def test_push_retry_classification_excludes_remote_rejection() -> None:
    assert _is_transient_push_failure("Could not resolve host: github.com")
    assert _is_transient_push_failure("unexpected status 503 Service Unavailable")
    assert not _is_transient_push_failure("remote rejected: permission denied")
    assert not _is_transient_push_failure("non-fast-forward update rejected")

def test_durable_push_rejection_does_not_update_feature_issue(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )

    def rejected_push(_worktrees, _path):
        raise RuntimeError("remote rejected: permission denied")

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("rejected durable push must not invoke GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", rejected_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert not drive_durable(executor, integration.id)

    saved = store.get(integration.id)
    events = store.events(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "push failed: remote rejected: permission denied"
    assert any(event.kind == "pipeline.push.failure" for event in events)
    assert not any(event.kind == "pipeline.push.retry" for event in events)
    assert not any(event.kind == "pipeline.push" for event in events)
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))

def test_durable_integration_rebase_does_not_update_feature_issue(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    _advance_durable(executor, integration.id, 4)
    (config.repo_root / "REMOTE.md").write_text("remote change\n", encoding="utf-8")
    run_command(["git", "add", "REMOTE.md"], cwd=config.repo_root, check=True)
    run_command(["git", "commit", "-m", "remote change"], cwd=config.repo_root, check=True)
    run_command(["git", "push", "origin", "main"], cwd=config.repo_root, check=True)

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("integration rebase must not update GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    outcome = executor.advance_once(integration.id)

    assert outcome.status == "child_pipeline"
    child = store.list_pipelines(integration.id)[-1]
    assert child.trigger == "integration-rebase"
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))

def test_durable_push_closes_one_feature_issue_after_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    commands: list[list[str]] = []

    def fake_run_command(command, cwd, *, timeout=None, **_kwargs):
        commands.append(command)
        return CommandResult(command, cwd, 0, "", "")

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", fake_run_command)
    assert drive_durable(executor, integration.id)

    comment = next(command for command in commands if command[:3] == ["gh", "issue", "comment"])
    close = next(command for command in commands if command[:3] == ["gh", "issue", "close"])
    assert comment[3] == "42"
    assert "Source task: " + source.id in comment[comment.index("--body") + 1]
    assert close[3] == "42"
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_closed: #42" in transcript.read_text(encoding="utf-8")

def test_durable_ambiguous_push_also_closes_feature_issue(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    real_push = Worktrees.push_head_to_main
    real_command = run_command
    commands: list[list[str]] = []

    def push_then_report_ambiguity(worktrees, path):
        result = real_push(worktrees, path)
        raise RuntimeError("connection lost after remote accepted the push")

    def command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            return CommandResult(command, cwd, 0, "", "")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", push_then_report_ambiguity)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert drive_durable(executor, integration.id)

    events = store.events(integration.id)
    assert any(event.kind == "pipeline.push.ambiguous_resolved" for event in events)
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))
    assert [item[0:3] for item in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and transcript.is_file()

def test_ambiguous_push_consumes_one_daily_budget_unit(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, first_integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, max_main_pushes_per_day=2
    )
    real_push = Worktrees.push_head_to_main
    push_calls = 0

    def push_first_then_report_ambiguity(worktrees, path):
        nonlocal push_calls
        push_calls += 1
        result = real_push(worktrees, path)
        if push_calls == 1:
            raise RuntimeError("connection lost after remote accepted the push")
        return result

    monkeypatch.setattr(Worktrees, "push_head_to_main", push_first_then_report_ambiguity)
    assert drive_durable(executor, first_integration.id)

    first_events = store.events(first_integration.id)
    assert sum(event.kind == "pipeline.push.ambiguous_resolved" for event in first_events) == 1
    assert not any(event.kind == "main.pushed" for event in first_events)

    run_command(
        ["git", "fetch", "origin", "main"], cwd=config.repo_root, check=True
    )
    fake_codex = Path(config.codex_bin)
    fake_codex.write_text(
        fake_codex.read_text(encoding="utf-8").replace(
            "durable push change", "second durable push change"
        ),
        encoding="utf-8",
    )
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Second feature source",
            prompt="Implement the second selected feature",
        )
    )
    second_integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate second feature",
            prompt="Integrate the second feature",
            metadata={"source_task_id": source.id},
        )
    )

    assert drive_durable(executor, second_integration.id)
    assert store.get(second_integration.id).status == TaskStatus.pushed
    assert not any(
        event.kind == "pipeline.push.blocked"
        for event in store.events(second_integration.id)
    )

def test_reconciled_push_updates_feature_issue_before_sealing(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config,
        tmp_path,
        monkeypatch,
        issue_numbers=(42,),
        max_main_pushes_per_day=1,
    )
    _advance_durable(executor, integration.id, 7)
    real_push = Worktrees.push_head_to_main

    def push_then_crash(worktrees, path):
        result = real_push(worktrees, path)
        raise KeyboardInterrupt("daemon stopped after remote acceptance")

    monkeypatch.setattr(Worktrees, "push_head_to_main", push_then_crash)
    with pytest.raises(KeyboardInterrupt):
        executor.advance_once(integration.id)

    commands: list[list[str]] = []
    real_command = run_command
    daemon_commands: list[tuple[list[str], dict[str, str] | None]] = []
    real_daemon_command = daemon_module.run_command
    ssh_command = "ssh -i /tmp/strict-ssh"

    def command(argv, cwd, *, timeout=None, **_kwargs):
        if argv and argv[0] == "gh":
            commands.append(argv)
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, **_kwargs)

    def daemon_command(argv, cwd, *, env=None, **kwargs):
        daemon_commands.append((argv, env))
        return real_daemon_command(argv, cwd, env=env, **kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    monkeypatch.setattr(
        daemon_module,
        "git_remote_environment",
        lambda _config: {
            "GIT_SSH_COMMAND": ssh_command,
            "GCM_INTERACTIVE": "never",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    monkeypatch.setattr(daemon_module, "run_command", daemon_command)
    daemon = StewardDaemon(config, store)
    task = store.get(integration.id)
    pipeline = store.list_pipelines(integration.id)[0]
    active = next(
        event
        for event in store.events(integration.id)
        if event.kind == "pipeline.phase.started"
        and event.data.get("phase") == "push"
    )
    outcome = daemon._reconcile_interrupted_push(
        task, pipeline, str(active.data["action_id"])
    )

    assert outcome.disposition.value == "ingested"
    assert store.get(integration.id).status == TaskStatus.pushed
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))
    assert daemon._reconcile_commit_and_remote(task, Path(task.worktree_path)) is None
    assert [item[:3] for item in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    expected_remote_env = {
        "GIT_SSH_COMMAND": ssh_command,
        "GCM_INTERACTIVE": "never",
        "GIT_TERMINAL_PROMPT": "0",
    }
    assert [
        env for argv, env in daemon_commands if argv[:2] == ["git", "fetch"]
    ] == [expected_remote_env] * 2
    assert [
        env for argv, env in daemon_commands if argv[:2] == ["git", "merge-base"]
    ] == [None] * 2
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_closed: #42" in transcript.read_text(encoding="utf-8")
    assert executor.advance_once(integration.id).status == "ready_to_seal"

def test_durable_push_remains_pushed_when_feature_issue_update_fails(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )

    real_command = run_command

    def failed_command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            return CommandResult(command, cwd, 1, "", "api unavailable")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", failed_command)
    assert drive_durable(executor, integration.id)

    assert store.get(integration.id).status == TaskStatus.pushed
    event = next(
        event for event in store.events(source.id) if event.kind == "github.issue_update_failed"
    )
    assert event.data["issue_number"] == 42
    assert event.data["step"] == "comment"
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_update_failed: #42 comment" in transcript.read_text(encoding="utf-8")

def test_durable_push_skips_multiple_feature_issues(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42, 43)
    )
    commands: list[list[str]] = []

    real_command = run_command

    def unexpected_command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            pytest.fail("multiple selected feature issues must not invoke GitHub")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_command)
    assert drive_durable(executor, integration.id)

    event = next(
        event for event in store.events(source.id) if event.kind == "github.issue_update_skipped"
    )
    assert event.data["issue_count"] == 2
    assert commands == []
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_update_skipped" in transcript.read_text(encoding="utf-8")

def test_durable_push_blocks_without_explicit_source_metadata(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    task = store.get(integration.id)
    task.spec.metadata.pop("source_task_id", None)
    store.save(task)
    pushes: list[object] = []

    def unexpected_push(_worktrees, _path):
        pushes.append(True)
        pytest.fail("missing integration source must not push")

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("missing integration source must not update GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", unexpected_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert not drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "integration source task missing"
    assert pushes == []
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))

def test_durable_push_skips_terminal_integration_source(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    store.finish_task(source.id, TaskStatus.failed, "source failed before integration")
    commands: list[list[str]] = []

    def unexpected_command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            pytest.fail("terminal integration source must not be mutated")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    def unexpected_push(_worktrees, _path):
        pytest.fail("terminal integration source must not be published")

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_command)
    monkeypatch.setattr(Worktrees, "push_head_to_main", unexpected_push)
    assert not drive_durable(executor, integration.id)

    assert store.get(source.id).status == TaskStatus.failed
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "integration source already terminal: failed"
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))
    assert commands == []

def test_durable_commit_message_failure_blocks_before_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    original_run = executor.runner.run

    def invalid_commit_message(task, prompt, cwd, **kwargs):
        result = original_run(task, prompt, cwd, **kwargs)
        stage = kwargs.get("stage")
        if getattr(stage, "value", stage) == "commit_message":
            result.final_message = '{"subject":"not conventional","body":"Body"}'
        return result

    monkeypatch.setattr(executor.runner, "run", invalid_commit_message)
    assert not drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "commit message generation failed"
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_durable_integration_phase_preserves_child_pipeline_boundaries(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    outcomes = _advance_durable(executor, integration.id, 4)
    assert outcomes[-1].next_phase.value == "integration"
    assert len(store.list_pipelines(integration.id)) == 1
    assert not any(event.kind == "integration.retry_requested" for event in store.events(integration.id))

def test_durable_integration_phase_uses_persisted_validation_boundary(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    outcomes = _advance_durable(executor, integration.id, 3)
    assert outcomes[-1].next_phase.value == "review"
    assert any(event.kind == "pipeline.validation.result" for event in store.events(integration.id))

def test_durable_integration_phase_records_accepted_tree_identity(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    _advance_durable(executor, integration.id, 4)
    pipeline = store.list_pipelines(integration.id)[0]
    assert pipeline.output_identity
    assert pipeline.patch_identity
    assert pipeline.phase == "integration"

def test_durable_integration_validation_failure_creates_repair_child(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)

    def failing_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "integration-failed.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("integration gate failed\n", encoding="utf-8")
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake"], cwd=cwd, passed=False, exit_code=1,
                    output_path=output, summary="integration gate failed"
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", failing_gates)
    outcomes = _advance_durable(executor, integration.id, 3)
    assert outcomes[-1].status == "child_pipeline"
    assert store.list_pipelines(integration.id)[-1].trigger == "validation-repair"

def test_durable_commit_failure_blocks_without_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)

    def fail_commit(_self, _path, _message, _body="", *, expected_tree=None):
        raise RuntimeError("commit hook failed")

    monkeypatch.setattr("coquic_steward.execution.worktree.Worktrees.commit_all", fail_commit)
    assert not drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert any(event.kind == "pipeline.blocked" for event in store.events(integration.id))
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_executor_drives_blocking_review_through_durable_repair(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "durable-review-repair-codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'case "$last" in\n'
        '  */reviewer-1/last-message.md) printf \'%s\\n\' \'{"verdict":"block","summary":"needs revision","findings":[{"severity":"high","title":"bad","file":"README.md","line":1,"detail":"bad text","recommendation":"fix it"}],"validation_gaps":[],"remaining_risk":""}\' > "$last" ;;\n'
        '  */formality-1/last-message.md) printf \'%s\\n\' \'{"dispositions":[{"sourceIndex":0,"disposition":"required","rationale":"bounded repair","followUp":null}]}\' > "$last" ;;\n'
        '  */reviewer-2/last-message.md) printf \'%s\\n\' \'{"verdict":"approve","summary":"repaired","findings":[],"validation_gaps":[],"remaining_risk":""}\' > "$last" ;;\n'
        '  */pipeline-2-implementation-1/last-message.md) printf \'repaired change\\n\' > README.md; printf \'done\\n\' > "$last" ;;\n'
        '  */commit-message-2/last-message.md) printf \'%s\\n\' \'{"subject":"fix: durable review repair","body":"persist the repaired tree"}\' > "$last" ;;\n'
        '  *) printf \'initial change\\n\' > README.md; printf \'done\\n\' > "$last" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert drive_durable(executor, task.id, finalize=True)

    iterations = store.iterations(task.id)
    assert [item.iteration for item in iterations] == [0, 1]
    assert all(item.patch_path is not None for item in iterations)
    assert store.get(task.id).status == TaskStatus.succeeded
    assert len(store.list_pipelines(task.id)) == 2
    assert any(event.kind == "pipeline.formality.effective" for event in store.events(task.id))
    assert any(event.kind == "pipeline.review.failure" for event in store.events(task.id))
    assert any(
        event.kind == "pipeline.child.created"
        and event.data.get("trigger") == "review-repair"
        for event in store.events(task.id)
    )
    assert sum(event.kind == "pipeline.review.raw" for event in store.events(task.id)) == 2

def test_executor_persists_durable_iteration_as_first_class_record(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="initial change")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert drive_durable(executor, task.id)
    iterations = store.iterations(task.id)
    assert [item.iteration for item in iterations] == [0]
    assert iterations[0].patch_path is not None
    review = next(event for event in store.events(task.id) if event.kind == "pipeline.review.raw")
    assert review.data["review"]["verdict"] == "approve"
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))

def test_executor_routes_validation_failure_to_durable_child_pipeline(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="bad")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def failing_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "validation-failed.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("validation failed\n", encoding="utf-8")
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake-validation"],
                    cwd=cwd,
                    passed=False,
                    exit_code=1,
                    output_path=output,
                    summary="validation failed",
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", failing_gates)
    executor = StewardExecutor(config, store)
    outcomes = _advance_durable(executor, task.id, 3)

    assert outcomes[-1].status == "child_pipeline"
    pipelines = store.list_pipelines(task.id)
    assert len(pipelines) == 2
    child = pipelines[-1]
    assert child.trigger == "validation-repair"
    assert child.metadata["packet"]["validation"]["validations"]
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))

def test_executor_blocks_unchanged_validation_revision(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="bad")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def failing_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "validation-failed.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("same failure\n", encoding="utf-8")
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake-validation"], cwd=cwd, passed=False, exit_code=1,
                    output_path=output, summary="same failure"
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", failing_gates)
    executor = StewardExecutor(config, store)
    assert not drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "validation made no progress"
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))

def test_executor_revalidates_unchanged_revision_after_gate_repairs_patch(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="formatted")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    gate_runs = 0

    def gates(configured, task_id, cwd, **_kwargs):
        nonlocal gate_runs
        gate_runs += 1
        output = configured.logs_dir / task_id / f"validation-{gate_runs}.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        if gate_runs == 1:
            (cwd / "README.md").write_text("gate repaired\n", encoding="utf-8")
        output.write_text("failed\n" if gate_runs == 1 else "ok\n", encoding="utf-8")
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake-format"], cwd=cwd, passed=gate_runs > 1,
                    exit_code=0 if gate_runs > 1 else 1, output_path=output,
                    summary="ok" if gate_runs > 1 else "formatted files"
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    executor = StewardExecutor(config, store)
    assert drive_durable(executor, task.id)
    assert gate_runs == 2
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))

def test_executor_blocks_repeated_patch_and_validation_failure(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="same patch")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    def repeated_failure_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "failure.txt"
        return _callback_gate_results(
            [
                ValidationResult(
                    command=["fake-validation"], cwd=cwd, passed=False, exit_code=1,
                    output_path=output, summary="same failure"
                )
            ],
            on_gate_start=_kwargs.get("on_gate_start"),
            on_gate_result=_kwargs.get("on_gate_result"),
        )

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", repeated_failure_gates
    )
    output = config.logs_dir / task.id / "failure.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("same failure\n", encoding="utf-8")

    executor = StewardExecutor(config, store)
    assert not drive_durable(executor, task.id)
    assert store.get(task.id).status == TaskStatus.blocked
    assert len(store.list_pipelines(task.id)) <= executor.MAX_PIPELINES
    assert any(event.kind == "pipeline.blocked" for event in store.events(task.id))

def test_executor_uses_durable_phase_order_for_validation_and_review(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = write_durable_codex(tmp_path, change="review fixed")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert drive_durable(executor, task.id)
    phases = [
        event.data["phase"]
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.started"
    ]
    assert phases[:6] == [
        "provisioned", "implementation", "validation", "review", "integration", "commit_message"
    ]
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))

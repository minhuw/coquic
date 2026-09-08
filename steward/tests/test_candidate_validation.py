from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from coquic_steward.core.subprocesses import CommandResult
from coquic_steward.execution.validation import default_gates, run_gates

DRIVER = Path(__file__).resolve().parents[1] / "containers" / "validate-candidate.py"


def candidate(repo: Path) -> None:
    source = repo / "steward/src/coquic_steward"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("VALUE = 'candidate'\n")
    (repo / "steward/tests").mkdir()


def invoke(repo: Path, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(DRIVER), str(repo)], cwd=repo,
        env={**os.environ, **environment}, capture_output=True, text=True,
    )


@pytest.mark.parametrize("failure", ["assert False, 'candidate-only failure'", "import missing_candidate_only_module"])
def test_candidate_only_failure_never_uses_passing_release(repo: Path, tmp_path: Path, failure: str) -> None:
    candidate(repo)
    release = tmp_path / "release/coquic_steward"
    release.mkdir(parents=True)
    (release / "__init__.py").write_text("VALUE = 'release'\n")
    release_tests = release.parent / "test_release.py"
    release_tests.write_text("def test_release(): assert True\n")
    passing = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", str(release_tests), "-q", "-p", "no:cacheprovider"],
        capture_output=True, text=True,
    )
    assert passing.returncode == 0, passing.stdout + passing.stderr
    (repo / "steward/tests/test_candidate.py").write_text(
        "from coquic_steward import VALUE\n"
        "def test_candidate():\n"
        "    assert VALUE == 'candidate'\n"
        f"    {failure}\n"
    )
    result = invoke(repo, PYTHONPATH=str(release.parent))
    assert result.returncode != 0
    assert "candidate-only failure" in result.stdout or "missing_candidate_only_module" in result.stdout
    assert not list(repo.rglob("__pycache__"))
    assert not list(repo.rglob(".pytest_cache"))
    assert not list((repo / ".zig-cache").iterdir())


@pytest.mark.parametrize("changed", ["steward/src/new.py", "contracts/steward-cloud/d1.sql", "scripts/check.sh", "flake.nix", "flake.lock", "build.zig", ".github/workflows/ci.yml"])
def test_shared_input_changes_require_candidate_tests(repo: Path, changed: str) -> None:
    path = repo / changed
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("changed\n")
    result = invoke(repo)
    assert result.returncode != 0
    assert "packaged fallback forbidden" in result.stderr


def test_unrelated_changes_skip_deterministically(repo: Path) -> None:
    (repo / "README.md").write_text("unrelated\n")
    for _ in range(2):
        result = invoke(repo)
        assert result.returncode == 0
        assert "skipped (no Steward/shared input changes)" in result.stdout
    assert not (repo / ".zig-cache").exists()


def test_git_fixture_writes_and_executables_stay_in_private_scratch(repo: Path, tmp_path: Path) -> None:
    candidate(repo)
    (repo / "steward/tests/test_fixture.py").write_text('''
import os
import pathlib
import subprocess

def test_fixture(tmp_path):
    assert tmp_path.is_relative_to(pathlib.Path.cwd() / '.zig-cache')
    assert os.environ['PYTHONDONTWRITEBYTECODE'] == '1'
    assert 'GIT_INDEX_FILE' not in os.environ
    subprocess.run(['git', 'init', str(tmp_path)], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'config', 'user.email', 'test@example.test'], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'config', 'user.name', 'Test'], check=True)
    executable = tmp_path / 'fake'
    executable.write_text('#!/bin/sh\\nexit 0\\n')
    executable.chmod(0o700)
    subprocess.run([str(executable)], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'fake'], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'commit', '-m', 'fixture'], check=True)
''')
    index = (repo / ".git/index").read_bytes()
    result = invoke(repo, GIT_INDEX_FILE=str(tmp_path / "forbidden-index"),
                    GIT_OBJECT_DIRECTORY=str(tmp_path / "forbidden-objects"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert (repo / ".git/index").read_bytes() == index
    assert not (tmp_path / "forbidden-index").exists()
    assert not (tmp_path / "forbidden-objects").exists()


def test_candidate_failure_is_a_normal_failed_gate(config) -> None:
    candidate(config.repo_root)
    (config.repo_root / "steward/tests/test_failure.py").write_text("def test_failure(): assert False\n")

    def runner(command, cwd, timeout):
        if command[0] != "steward-task-validate":
            return CommandResult(command, cwd, 0, "baseline gate", "")
        result = invoke(cwd)
        return CommandResult(command, cwd, result.returncode, result.stdout, result.stderr)

    results = run_gates(config, "candidate-task", config.repo_root, command_runner=runner)
    assert len(results) == len(default_gates(config.repo_root)) == 5
    assert all(result.passed for result in results[:4])
    assert not results[-1].passed
    assert results[-1].exit_code == 1
    assert "test_failure" in results[-1].output_path.read_text()


def test_candidate_gate_failure_prevents_commit_and_push(config, monkeypatch) -> None:
    from test_container_pipeline import FakeRunner
    from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
    from coquic_steward.execution.executor import StewardExecutor
    from coquic_steward.storage import TaskStore

    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom,
                                     title="candidate failure", prompt="test Steward"))
    executor = StewardExecutor(config, store, runner=FakeRunner(config))
    executor.advance_once(task.id)
    executor.advance_once(task.id)
    worktree = store.get(task.id).worktree_path
    candidate(worktree)
    (worktree / "steward/tests/test_failure.py").write_text("def test_failure(): assert False\n")

    def runner(command, cwd, timeout):
        if command[0] != "steward-task-validate":
            return CommandResult(command, cwd, 0, "baseline gate", "")
        result = invoke(cwd)
        return CommandResult(command, cwd, result.returncode, result.stdout, result.stderr)

    def gates(configured, task_id, cwd, **kwargs):
        kwargs["command_runner"] = runner
        return run_gates(configured, task_id, cwd, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("failed candidate reached commit/push")

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    monkeypatch.setattr(executor.worktrees, "commit_all", forbidden)
    monkeypatch.setattr(executor, "_durable_push", forbidden)
    result = executor.advance_once(task.id)
    assert result.status == "child_pipeline"
    assert store.list_pipelines(task.id)[-1].trigger == "validation-repair"
    failed = [item for item in store.get(task.id).validations if not item.passed]
    assert len(failed) == 1
    assert failed[0].command[0] == "steward-task-validate"
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))


@pytest.mark.parametrize("operation", ["delete", "rename"])
def test_deleted_or_renamed_steward_inputs_cannot_skip(repo: Path, operation: str) -> None:
    source = repo / "steward/old.py"
    source.parent.mkdir()
    source.write_text("original\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline Steward input"], cwd=repo, check=True)
    if operation == "delete":
        source.unlink()
    else:
        source.rename(repo / "unrelated.py")
    result = invoke(repo)
    assert result.returncode != 0
    assert "packaged fallback forbidden" in result.stderr

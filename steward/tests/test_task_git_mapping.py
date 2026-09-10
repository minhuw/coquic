"""Task Git mounts preserve linked-worktree ref lookup without writable metadata."""

from dataclasses import replace
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

from coquic_steward.execution.container import TaskContainerRuntime
from coquic_steward.execution.container_config import TaskContainerConfig, TaskRole


IMAGE = "sha256:c38e50975d01a726c7da9cae7918935cff78d1268b8bc51d57e8130648642d8d"


def git(cwd: Path, *args: str, env=None) -> str:
    return subprocess.run(
        ["git", "-c", "safe.directory=*", *args],
        cwd=cwd, env=env, check=True, capture_output=True, text=True,
    ).stdout


@pytest.fixture
def linked_config(repo: Path, tmp_path: Path) -> TaskContainerConfig:
    # Duplicate basenames force Git to choose an admin name unlike the worktree's.
    git(repo, "worktree", "add", "-b", "occupied", str(tmp_path / "first" / "task"))
    worktree = tmp_path / "second" / "task"
    git(repo, "worktree", "add", "-b", "probe", str(worktree))
    git_dir = Path(git(worktree, "rev-parse", "--absolute-git-dir").strip())
    assert git_dir.name != worktree.name
    archive, sessions = tmp_path / "archive", tmp_path / "sessions"
    archive.mkdir()
    sessions.mkdir()
    return TaskContainerConfig(
        task_id="git-mapping-" + uuid.uuid4().hex,
        image="coquic-steward-task",
        image_digest=IMAGE,
        worktree=worktree,
        archive=archive,
        private_sessions=sessions,
        git_dir=git_dir,
        git_common_dir=repo / ".git",
    )


@pytest.mark.parametrize(
    "git_path,common_target,override,expected",
    [
        ("common/worktrees/task17", "/task/git/common", None, "/task/git/common/worktrees/task17"),
        ("common/worktrees/task17", "/task/git/custom", None, "/task/git/custom/worktrees/task17"),
        ("common", "/task/git/common", None, "/task/git/common"),
        ("separate", "/task/git/common", None, "/task/git/linked"),
        ("worktree/.git", "/task/git/common", None, "/task/git/linked"),
        ("common/worktrees/task17", "/task/git/common", "/task/git/explicit", "/task/git/explicit"),
        ("common", "/task/git/common", "/task/git/linked", "/task/git/linked"),
    ],
)
def test_git_mapping_defaults_and_overrides(
    tmp_path, git_path, common_target, override, expected,
):
    # No paths need to exist: cleanup reconstructs worktree/.git after removal.
    config = TaskContainerConfig(
        task_id="mapping", image="coquic-steward-task", image_digest=IMAGE,
        worktree=tmp_path / "worktree", archive=tmp_path / "archive",
        private_sessions=tmp_path / "sessions", git_dir=tmp_path / git_path,
        git_common_dir=tmp_path / "common", container_git_common_dir=common_target,
        container_git_dir=override,
    )
    assert config.container_git_dir == expected
    for role in TaskRole:
        env = config.environment(role, session_uid=10000, session_id="probe")
        assert env["GIT_DIR"] == expected
        assert env["GIT_COMMON_DIR"] == common_target
        mounts = config.mounts_for(role)
        assert len({mount.target for mount in mounts}) == len(mounts)
        git_mounts = [mount for mount in mounts if mount.source in {
            config.git_dir, config.git_common_dir,
        }]
        assert {mount.target for mount in git_mounts} == {expected, common_target}
        assert all(mount.read_only for mount in git_mounts)


@pytest.mark.parametrize("role", [TaskRole.reviewer, TaskRole.implementation])
def test_real_linked_worktree_at_mapped_paths(linked_config, tmp_path, role):
    config = linked_config
    expected = f"/task/git/common/worktrees/{config.git_dir.name}"
    assert config.container_git_dir == expected
    assert config.container_path(config.git_dir / "HEAD", role) == expected + "/HEAD"
    assert config.container_path(config.git_common_dir / "refs", role) == "/task/git/common/refs"
    assert (config.git_dir / "commondir").read_text().strip() == "../.."
    # Copy the bind sources to a fake container root; do not rewrite Git metadata.
    root = tmp_path / "mapped"
    for mount in config.mounts_for(role):
        shutil.copytree(mount.source, root / mount.target.lstrip("/"), dirs_exist_ok=True)
    env = config.environment(role, session_uid=10000, session_id="probe")
    env = {key: str(root / value.lstrip("/")) for key, value in env.items()
           if key.startswith("GIT_")}
    linked = Path(env["GIT_DIR"])
    assert (linked / (linked / "commondir").read_text().strip()).resolve() == Path(env["GIT_COMMON_DIR"])
    env = {**os.environ, **env, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    worktree = Path(env["GIT_WORK_TREE"])
    assert git(worktree, "rev-parse", "--verify", "HEAD", env=env) == git(config.worktree, "rev-parse", "HEAD")
    assert git(worktree, "status", "--porcelain", env=env) == ""
    assert git(worktree, "show", "HEAD:README.md", env=env) == "hello\n"
    (worktree / "README.md").write_text("changed\n")
    assert git(worktree, "status", "--porcelain", env=env) == " M README.md\n"
    assert git(worktree, "diff", "--name-only", env=env) == "README.md\n"
    assert git(worktree, "diff", "--cached", env=env) == ""


def test_runtime_factory_mapping_and_removed_worktree_cleanup(config, linked_config, monkeypatch):
    from coquic_steward.core.models import TaskKind, TaskRecord, TaskSpec, WorkerKind
    from coquic_steward.execution.session import runtime_factory_for_config

    monkeypatch.setattr(TaskContainerRuntime, "provision_task_paths", lambda _self: None)
    config = replace(config, task_image_digest=IMAGE)
    task = TaskRecord(
        spec=TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom,
                      title="Git mapping", prompt="no model invocation"),
        worktree_path=linked_config.worktree,
    )
    runtime = runtime_factory_for_config(config)(task)
    assert runtime.config.git_dir == linked_config.git_dir
    assert runtime.config.container_git_dir == linked_config.container_git_dir

    task.worktree_path = linked_config.worktree.parent / "removed"
    cleanup = runtime_factory_for_config(config, provision_paths=False)(task)
    assert cleanup.config.git_dir == task.worktree_path / ".git"
    assert cleanup.config.container_git_dir == "/task/git/linked"
    assert not task.worktree_path.exists()


@pytest.mark.skipif(
    os.environ.get("COQUIC_TEST_TASK_GIT_DOCKER") != "1",
    reason="opt-in real Docker Git reads using the pinned local task image",
)
@pytest.mark.parametrize("layout", ["linked", "same-directory"])
def test_pinned_image_git_reads_and_metadata_stays_read_only(linked_config, layout):
    # Tiny local fixture only: no clone, pull/build, credentials, or model calls.
    config = linked_config
    if layout == "same-directory":
        config = replace(config, worktree=config.git_common_dir.parent,
                         git_dir=config.git_common_dir, container_git_dir=None)
    expected_head = git(config.worktree, "rev-parse", "--verify", "HEAD").strip()
    runtime = TaskContainerRuntime(config)
    runtime.client.run(["image", "inspect", IMAGE], timeout=10).check_returncode()
    runtime.provision_task_paths()
    identity = runtime.create()
    try:
        runtime.start(identity)
        mounts = {mount["Destination"]: mount for mount in runtime.inspect().raw["Mounts"]}
        for target in {config.container_git_dir, config.container_git_common_dir}:
            assert mounts[target]["RW"] is False
        assert mounts[config.container_worktree_ro]["RW"] is False
        for role in (TaskRole.reviewer, TaskRole.implementation):
            result = runtime.exec(
                role, session_uid=10000, session_id="probe", timeout=30,
                command=["python", "-c", '''
import errno, os, pathlib, subprocess, sys

def git(*args):
    return subprocess.run(["git", "-c", "safe.directory=*", *args],
                          check=True, capture_output=True, text=True).stdout

assert git("rev-parse", "--verify", "HEAD").strip() == sys.argv[1]
assert git("status", "--porcelain") == ""
assert git("show", "HEAD:README.md") == "hello\\n"
for name in ("GIT_DIR", "GIT_COMMON_DIR"):
    try:
        (pathlib.Path(os.environ[name]) / "forbidden").write_text("must fail")
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES), error
    else:
        raise AssertionError("Git metadata was writable: " + name)
worktree = pathlib.Path(os.environ["GIT_WORK_TREE"])
if os.environ["COQUIC_STEWARD_ROLE"] == "implementation":
    (worktree / "README.md").write_text("changed\\n")
    assert git("status", "--porcelain") == " M README.md\\n"
    assert git("diff", "--name-only") == "README.md\\n"
    assert git("diff", "--cached") == ""
    patch = git("diff", "--", "README.md")
    assert "-hello\\n+changed\\n" in patch, patch
else:
    try:
        (worktree / "forbidden").write_text("must fail")
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES), error
    else:
        raise AssertionError("reviewer worktree was writable")
print(git("--version").strip(), "git-mapping-ok")
''', expected_head],
            )
            assert result.exit_code == 0, result.stderr
            assert b"git-mapping-ok" in result.stdout
    finally:
        runtime.stop(identity, timeout=2)
        runtime.remove(identity)
    assert git(config.worktree, "rev-parse", "--verify", "HEAD").strip() == expected_head
    assert git(config.worktree, "status", "--porcelain") == " M README.md\n"
    assert not (config.git_dir / "forbidden").exists()
    assert not (config.git_common_dir / "forbidden").exists()

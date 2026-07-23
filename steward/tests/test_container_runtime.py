from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from coquic_steward.execution import (
    ContainerErrorCategory,
    TaskContainerConfig,
    TaskContainerRuntime,
    TaskRole,
)


class FakeDocker:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], **_kwargs):
        self.calls.append(argv)
        if argv[0] == "create":
            return subprocess.CompletedProcess(argv, 0, b"container-id\n", b"")
        if argv[0] == "inspect":
            labels = {
                "coquic.steward.task": "task-1",
                "coquic.steward.image-digest": "sha256:" + "a" * 64,
                "coquic.steward.runtime": "task-container-v1",
            }
            payload = {
                "Id": "container-id",
                "State": {"Status": "running", "Running": True, "Pid": 41},
                "Config": {"Image": "sha256:" + "a" * 64, "Labels": labels},
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps([payload]).encode(), b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


@pytest.fixture
def container_config(tmp_path: Path) -> TaskContainerConfig:
    return TaskContainerConfig(
        task_id="task-1",
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        worktree=tmp_path / "worktree",
        archive=tmp_path / "archive",
        private_sessions=tmp_path / "sessions",
        git_dir=tmp_path / "git-linked",
        git_common_dir=tmp_path / "git-common",
        scratch=tmp_path / "scratch",
    )


def test_create_argv_is_locked_and_task_scoped(container_config: TaskContainerConfig) -> None:
    runtime = TaskContainerRuntime(container_config, client=FakeDocker())
    argv = runtime.create_argv()
    assert argv[0] == "create"
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--read-only" in argv
    assert all("docker.sock" not in value for value in argv)
    assert all("CODEX_API_KEY" not in value for value in argv)


def test_role_mounts_and_git_environment_are_kernel_boundary_inputs(
    container_config: TaskContainerConfig,
) -> None:
    runtime = TaskContainerRuntime(container_config, client=FakeDocker())
    read_only = runtime.exec_argv(
        TaskRole.reviewer,
        session_uid=10000,
        command=["git", "status"],
    )
    implementation = runtime.exec_argv(
        TaskRole.implementation,
        session_uid=10001,
        command=["git", "status"],
    )
    assert "/task/worktree-ro" in read_only
    assert "/task/worktree" in implementation
    with pytest.raises(Exception):
        runtime.exec_argv(
            TaskRole.reviewer,
            session_uid=10000,
            command=["true"],
            env={"CODEX_API_KEY": "fake-only"},
        )


def test_inspect_rejects_identity_mismatch(container_config: TaskContainerConfig) -> None:
    fake = FakeDocker()
    runtime = TaskContainerRuntime(container_config, client=fake)
    inspection = runtime.adopt()
    assert inspection.running
    assert runtime.ensure_started() == "container-id"
    assert fake.calls[0][0] == "inspect"

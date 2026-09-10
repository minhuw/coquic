"""Cache mountpoint preparation at both validation launch boundaries."""

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import uuid

import pytest

from coquic_steward.execution.container import (
    ContainerBoundaryError,
    ContainerErrorCategory,
    ValidationContainerRuntime,
)
from coquic_steward.execution.container_config import ValidationContainerConfig


IMAGE = "sha256:7b3e9a36644367af4355762f90155b278743d155ba64cbd89c4d1df768e89c3d"
CACHES = (".zig-cache", "site/next", ".duvet")


@pytest.fixture
def config(tmp_path: Path) -> ValidationContainerConfig:
    worktree = tmp_path / "parent" / "worktree"
    worktree.mkdir(parents=True)
    output, store = tmp_path / "output", tmp_path / "store"
    output.mkdir()
    store.mkdir()
    return ValidationContainerConfig(
        run_id="mountpoints-" + uuid.uuid4().hex,
        image="coquic-steward-validation",
        image_digest=IMAGE,
        worktree=worktree,
        output=output,
        store=store,
    )


class RecordingDocker:
    def __init__(self, config):
        self.config = config
        self.calls = []

    def run(self, argv, **_kwargs):
        assert all((self.config.worktree / name).is_dir() for name in CACHES)
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"d" * 64 + b"\n", b"")


def launch(runtime, boundary):
    if boundary == "create":
        runtime.create()
    else:
        # The direct validation runner invokes the client, not runtime._run().
        runtime.client.run(runtime.run_argv(["true"]))


@pytest.mark.parametrize("boundary", ["create", "one-shot"])
def test_pristine_worktree_mountpoints(config, boundary):
    source = config.worktree / "source.txt"
    source.write_text("unchanged")
    source.chmod(0o640)
    before = source.stat()
    docker = RecordingDocker(config)
    runtime = ValidationContainerRuntime(config, client=docker)
    runtime.create_argv()
    assert sorted(path.name for path in config.worktree.iterdir()) == ["source.txt"]

    launch(runtime, boundary)
    launch(runtime, boundary)  # Existing directories are accepted without mutation.

    assert {str(path.relative_to(config.worktree)) for path in config.worktree.rglob("*")} == {
        "source.txt", "site", *CACHES,
    }
    assert source.read_text() == "unchanged"
    assert source.stat() == before
    argv = docker.calls[0]
    assert "--read-only" in argv
    for flag, value in (("--network", "none"), ("--cap-drop", "ALL"),
                        ("--security-opt", "no-new-privileges:true"),
                        ("--memory", str(config.limits.memory_bytes)),
                        ("--pids-limit", str(config.limits.pids))):
        assert argv[argv.index(flag) + 1] == value
    source_mounts = [value for value in argv if value.startswith(
        f"type=bind,src={config.worktree},"
    )]
    assert len(source_mounts) == 2
    assert all(value.endswith(",readonly") for value in source_mounts)


@pytest.mark.parametrize("boundary", ["create", "one-shot"])
@pytest.mark.parametrize("location", ["ancestor", "root", "site", *CACHES])
@pytest.mark.parametrize("kind", ["symlink", "file"])
def test_unsafe_mountpoints_rejected(config, tmp_path, boundary, location, kind):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("do not touch")
    before = sentinel.stat()
    if location == "ancestor":
        target = config.worktree.parent
        config.worktree.rmdir()
        target.rmdir()
    elif location == "root":
        target = config.worktree
        target.rmdir()
    else:
        target = config.worktree / location
        target.parent.mkdir(parents=True, exist_ok=True)
    if kind == "symlink":
        target.symlink_to(outside, target_is_directory=True)
    else:
        target.write_text("not a directory")
    target_before = target.lstat()
    docker = RecordingDocker(config)
    runtime = ValidationContainerRuntime(config, client=docker)

    with pytest.raises(ContainerBoundaryError) as error:
        launch(runtime, boundary)

    assert error.value.category is ContainerErrorCategory.invalid
    assert docker.calls == []
    assert target.lstat() == target_before
    assert list(outside.iterdir()) == [sentinel]
    assert sentinel.read_text() == "do not touch"
    assert sentinel.stat() == before


@pytest.mark.parametrize("boundary", ["create", "one-shot"])
def test_missing_worktree_is_not_created(config, boundary):
    config.worktree.rmdir()
    config.worktree.parent.rmdir()
    runtime = ValidationContainerRuntime(config, client=RecordingDocker(config))
    with pytest.raises(ContainerBoundaryError):
        launch(runtime, boundary)
    assert not config.worktree.parent.exists()


def test_existing_cache_content_and_modes_preserved(config):
    snapshots = {}
    for name in CACHES:
        path = config.worktree / name
        path.mkdir(parents=True)
        path.chmod(0o750)
        (path / "keep").write_text("source cache")
        snapshots[path] = path.stat()
        snapshots[path / "keep"] = (path / "keep").stat()
    runtime = ValidationContainerRuntime(config, client=RecordingDocker(config))
    launch(runtime, "create")
    assert all(path.stat() == before for path, before in snapshots.items())
    assert all((config.worktree / name / "keep").read_text() == "source cache" for name in CACHES)


@pytest.mark.skipif(
    os.environ.get("COQUIC_TEST_VALIDATION_DOCKER") != "1",
    reason="opt-in real Docker startup using the pinned local validation image",
)
@pytest.mark.parametrize("boundary", ["create", "one-shot"])
def test_real_validation_image_starts_on_pristine_worktree(config, boundary):
    # No image build/pull, credentials, model, or repository worktree required.
    config = replace(config, uid=os.getuid() or 10000, gid=os.getgid() or 10000)
    runtime = ValidationContainerRuntime(config)
    runtime.client.run(["image", "inspect", IMAGE], timeout=10).check_returncode()
    command = [
        "/bootstrap/sh", "-ec",
        "test -f /tmp/coquic-validation-ready; "
        "for dir in .zig-cache site/next .duvet; do "
        "touch /validation/worktree/$dir/probe; done; "
        "! touch /validation/worktree/forbidden; "
        f"! touch {config.worktree}/forbidden; "
        "printf 'mountpoints-ready\\n'",
    ]
    assert not any((config.worktree / name).exists() for name in CACHES)
    if boundary == "create":
        identity = runtime.create()
        try:
            runtime._run(["start", identity], timeout=30)
            runtime._wait_ready(identity)
            runtime._validate_inspection(runtime.inspect())
            result = runtime.exec(command, timeout=30)
            assert result.exit_code == 0, result.stderr
        finally:
            runtime.stop(identifier=identity, timeout=2)
            runtime.remove(identifier=identity)
    else:
        result = runtime.client.run(runtime.run_argv(command), timeout=180)
        assert result.returncode == 0, result.stderr
    assert b"mountpoints-ready" in result.stdout
    assert not (config.worktree / "forbidden").exists()
    assert all(not (config.worktree / name / "probe").exists() for name in CACHES)

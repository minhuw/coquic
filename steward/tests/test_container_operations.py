from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import coquic_steward.cli as cli_module
from coquic_steward.core.config import StewardConfig, StewardDeploymentConfig
from coquic_steward.core.lifecycle import DockerResourceManager
from coquic_steward.execution.container import (
    ContainerBoundaryError,
    ContainerErrorCategory,
    TaskContainerRuntime,
    ValidationContainerRuntime,
    bind_deployment_identity,
    deployment_runtime_factory,
)
from coquic_steward.execution.container_config import (
    ContainerLimits,
    TaskContainerConfig,
)
from coquic_steward.execution.container_config import ValidationContainerConfig
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.validation import _docker_validation_runner
from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
from coquic_steward.storage import TaskStore


def _deployment(tmp_path: Path, **overrides) -> StewardDeploymentConfig:
    values = {
        "enabled": True,
        "home": tmp_path,
        "repository": tmp_path / "repository",
        "host_uid": 1000,
        "host_gid": 1000,
        "docker_gid": 999,
        "codex_credential_path": tmp_path / "codex",
        "github_credential_path": tmp_path / "github",
        "dataset_identity_path": tmp_path / "dataset",
        "known_hosts_path": tmp_path / "known_hosts",
        "min_free_bytes": 1000,
        "max_owned_docker_bytes": 2000,
        "recovery_free_bytes": 1500,
        "recovery_owned_docker_bytes": 1000,
    }
    values.update(overrides)
    return StewardDeploymentConfig(**values)


def test_deployment_requires_hysteresis(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="recovery_free_bytes"):
        _deployment(tmp_path, recovery_free_bytes=1000)


def test_validation_container_is_no_network_and_separate_from_task_image(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    output = tmp_path / "output"
    store = tmp_path / "store"
    for path in (worktree, output, store):
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="validation-run",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=worktree,
        output=output,
        store=store,
    )
    argv = ValidationContainerRuntime(config).create_argv()
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--restart") + 1] == "no"
    assert "--read-only" in argv
    assert "/tmp:rw,noexec,nosuid,nodev,size=8589934592,mode=1777" in argv
    assert "/validation/worktree" in " ".join(argv)
    assert "/var/run/docker.sock" not in " ".join(argv)


def _validation_inspection(config: ValidationContainerConfig) -> dict[str, object]:
    return {
        "Id": "d" * 64,
        "Name": f"/{config.container_name}",
        "Image": config.image_digest,
        "State": {"Status": "running", "Running": True, "Pid": 41},
        "Config": {
            "Image": config.image_digest,
            "User": f"{config.uid}:{config.gid}",
            "Labels": config.labels,
            "Entrypoint": ["/bootstrap/sh"],
            "Cmd": ["/bootstrap/validation-entrypoint.sh", "--idle"],
            "WorkingDir": "/validation/worktree",
            "Env": [
                "NIX_REGISTRATION=/validation/closure-info/registration",
                "NIX_MATERIALIZED_STORE_PATHS=/validation/closure-info/materialized-store-paths",
                "NIX_STORE_PATHS=/validation/closure-info/store-paths",
                "PYTHONPATH=/nix/store/source/opt/coquic/steward/src",
                "ZIG_GLOBAL_CACHE_DIR=/tmp/zig-global-cache",
                "ZIG_LOCAL_CACHE_DIR=/tmp/zig-local-cache",
                f"VALIDATION_SOURCE_WORKTREE={config.worktree}",
                *(
                    [
                        f"VALIDATION_GIT_OBJECTS_DIR={config.git_common_dir / 'objects'}",
                        "VALIDATION_GIT_ALTERNATE_OBJECTS=/validation/git-common-ro/objects",
                    ]
                    if config.git_common_dir is not None
                    else []
                ),
            ],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "Privileged": False,
            "ReadonlyRootfs": True,
            "Init": True,
            "Memory": config.limits.memory_bytes,
            "PidsLimit": config.limits.pids,
            "RestartPolicy": {"Name": "no"},
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "LogConfig": {
                "Type": "local",
                "Config": {
                    "max-file": str(config.limits.log_max_files),
                    "max-size": f"{config.limits.log_max_bytes}b",
                },
            },
            "Tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=8589934592,mode=1777",
                "/run": "rw,noexec,nosuid,nodev,size=16m",
                "/validation/worktree/.zig-cache": "rw,exec,nosuid,nodev,size=8589934592,mode=0755,uid=10000,gid=10000",
                "/validation/worktree/site/next": "rw,noexec,nosuid,nodev,size=1g,mode=0755,uid=10000,gid=10000",
                "/validation/worktree/.duvet": "rw,noexec,nosuid,nodev,size=1g,mode=0755,uid=10000,gid=10000",
                "/nix/store": "rw,nosuid,nodev,size=8589934592,mode=0755,uid=10000,gid=10000",
                "/nix/var/log/nix": "rw,noexec,nosuid,nodev,size=64m,mode=0755,uid=10000,gid=10000",
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(mount.source),
                "Destination": mount.target,
                "RW": not mount.read_only,
            }
            for mount in config.mounts
        ],
    }


def test_validation_container_refuses_same_name_foreign_image(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="collision",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )
    payload = _validation_inspection(config)
    payload["Image"] = "sha256:" + "f" * 64

    class ForeignDocker:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def run(self, argv: list[str], **_kwargs):
            self.calls.append(argv)
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )

    docker = ForeignDocker()
    runtime = ValidationContainerRuntime(config, client=docker)

    with pytest.raises(ContainerBoundaryError) as error:
        runtime.ensure_started()

    assert error.value.category is ContainerErrorCategory.identity_mismatch
    assert [call[0] for call in docker.calls] == ["inspect"]


def test_validation_container_refuses_same_image_with_foreign_runtime(
    tmp_path: Path,
) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="collision-runtime",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )
    payload = _validation_inspection(config)
    payload["HostConfig"]["Memory"] = config.limits.memory_bytes // 2

    class ForeignDocker:
        def run(self, argv: list[str], **_kwargs):
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )

    runtime = ValidationContainerRuntime(config, client=ForeignDocker())

    with pytest.raises(ContainerBoundaryError) as error:
        runtime.ensure_started()

    assert error.value.category is ContainerErrorCategory.identity_mismatch


def test_validation_exec_returns_the_canonical_gate_exit_code(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="nonzero-gate",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )

    class NonzeroGateDocker:
        def run(self, argv: list[str], **_kwargs):
            return subprocess.CompletedProcess(argv, 23, b"gate output", b"gate failed")

    result = ValidationContainerRuntime(
        config, client=NonzeroGateDocker()
    ).exec(["false"])

    assert result.exit_code == 23
    assert result.stdout == b"gate output"
    assert result.stderr == b"gate failed"


def test_validation_container_waits_for_entrypoint_readiness(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="startup-readiness",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )

    class RecordingDocker:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def run(self, argv: list[str], **_kwargs):
            self.calls.append(argv)
            if argv[0] == "inspect":
                return subprocess.CompletedProcess(argv, 1, b"", b"No such container")
            if argv[0] == "create":
                return subprocess.CompletedProcess(argv, 0, ("d" * 64).encode(), b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    docker = RecordingDocker()

    assert ValidationContainerRuntime(config, client=docker).ensure_started() == "d" * 64
    assert [call[0] for call in docker.calls] == ["inspect", "create", "start", "exec"]
    assert docker.calls[-1][-3:] == [
        "/bootstrap/sh",
        "-c",
        "test -f /tmp/coquic-validation-ready",
    ]


def test_direct_validation_runner_uses_bootstrap_and_writable_nix_boundary(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "sha256:" + "c" * 64
    config = replace(
        config,
        validation_image="coquic-steward-validation",
        validation_image_digest=digest,
    )
    argv_calls: list[list[str]] = []

    def capture(argv, **_kwargs):
        argv_calls.append(argv)
        return subprocess.CompletedProcess(argv, 17, "", "canonical gate failed")

    monkeypatch.setattr(subprocess, "run", capture)
    runner = _docker_validation_runner(config, "integration-task", config.repo_root)
    result = runner(["nix", "flake", "check"], config.repo_root, 30)

    assert result.returncode == 17
    argv = argv_calls[0]
    assert "--read-only" in argv
    assert any("dst=/nix/var/nix" in value for value in argv)
    assert any(value.startswith("/nix/store:rw,") for value in argv)
    assert argv[argv.index(digest) + 1 :] == ["--exec", "nix", "flake", "check"]


def test_validation_cleanup_is_durable_before_start_and_retried_after_crash(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "sha256:" + "c" * 64
    deployment = replace(
        config.deployment,
        max_memory_bytes=5 * 1024**3,
        max_pids=321,
        max_scratch_bytes=6 * 1024**3,
        max_log_bytes=7 * 1024**2,
    )
    config = replace(
        config,
        validation_image="coquic-steward-validation",
        validation_image_digest=digest,
        deployment=deployment,
    )
    store = TaskStore(config.db_path)
    task, _created = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="validation cleanup",
            prompt="validate",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    store.claim_daemon_instance("daemon-before-crash")
    validation_worktree = config.private_dir / "disposable-worktree"
    validation_worktree.mkdir()
    git_common_dir = config.private_dir / "git-common"
    git_common_dir.mkdir()
    task.worktree_path = validation_worktree
    store.save(task)
    observed_pending: list[dict[str, object]] = []
    cleaned: list[str] = []
    runtime_configs: list[ValidationContainerConfig] = []

    class RecordingValidationRuntime:
        def __init__(self, runtime_config, **_kwargs) -> None:
            self.config = runtime_config
            runtime_configs.append(runtime_config)

        def ensure_started(self) -> str:
            observed_pending.extend(store.list_validation_cleanup_pending())
            return "d" * 64

        def cleanup_owned(self, *, timeout: float = 5) -> None:
            cleaned.append(self.config.container_name)

    monkeypatch.setattr(
        "coquic_steward.execution.container.ValidationContainerRuntime",
        RecordingValidationRuntime,
    )
    executor = StewardExecutor(config, store)
    monkeypatch.setattr(
        executor,
        "_validation_git_common_dir",
        lambda _worktree: git_common_dir,
    )
    executor._isolated_validation_runner(task, pipeline, digest)

    assert len(observed_pending) == 1
    assert observed_pending[0]["cleanup_ready"] is False
    assert digest in store.referenced_image_ids()
    root = Path(str(observed_pending[0]["root_path"]))
    assert root.is_dir()

    validation_worktree.rmdir()
    monkeypatch.setattr(
        executor,
        "_validation_git_common_dir",
        lambda _worktree: pytest.fail(
            "cleanup reconstructed Git identity from the removed worktree"
        ),
    )
    store.claim_daemon_instance("daemon-after-crash")
    assert executor.retry_validation_cleanup_pending() == 1
    assert store.list_validation_cleanup_pending() == []
    assert digest not in store.referenced_image_ids()
    assert not root.exists()
    assert cleaned == [str(observed_pending[0]["container_name"])]
    assert len(runtime_configs) == 2
    assert runtime_configs[0].limits == runtime_configs[1].limits
    assert runtime_configs[1].git_common_dir == git_common_dir
    assert runtime_configs[1].limits == ContainerLimits(
        memory_bytes=deployment.max_memory_bytes,
        pids=deployment.max_pids,
        scratch_bytes=deployment.max_scratch_bytes,
        log_max_bytes=deployment.max_log_bytes,
    )


def test_task_create_argv_has_bounded_restart_and_logs(tmp_path: Path) -> None:
    roots = [
        tmp_path / name
        for name in ("worktree", "archive", "sessions", "git", "common", "scratch")
    ]
    for root in roots:
        root.mkdir()
    config = TaskContainerConfig(
        task_id="task-ops",
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        worktree=roots[0],
        archive=roots[1],
        private_sessions=roots[2],
        git_dir=roots[3],
        git_common_dir=roots[4],
        scratch=roots[5],
        limits=ContainerLimits(log_max_bytes=1024, log_max_files=2),
    )
    argv = TaskContainerRuntime(config).create_argv()
    assert argv[argv.index("--restart") + 1] == "no"
    assert "local" in argv and "max-size=1024b" in argv
    assert "/run:rw,noexec,nosuid,nodev,size=16m" in argv


def test_deployment_runtime_factory_adds_exact_release_and_epoch_labels(
    tmp_path: Path,
) -> None:
    roots = [
        tmp_path / name for name in ("worktree", "archive", "sessions", "git", "common")
    ]
    for root in roots:
        root.mkdir()
    runtime = TaskContainerRuntime(
        TaskContainerConfig(
            task_id="task-deployment",
            image="coquic-steward-task",
            image_digest="sha256:" + "a" * 64,
            worktree=roots[0],
            archive=roots[1],
            private_sessions=roots[2],
            git_dir=roots[3],
            git_common_dir=roots[4],
        )
    )
    config = SimpleNamespace(
        deployment=_deployment(
            tmp_path,
            release_id="release-candidate",
            compose_project="steward-production",
            max_pids=64,
            max_memory_bytes=134_217_728,
            max_log_bytes=1024,
            max_scratch_bytes=2048,
        ),
        ensure_epoch=lambda: {"epochId": "epoch-production"},
    )
    factory = deployment_runtime_factory(config, lambda _task: runtime)

    configured = factory(object())

    assert configured.config.labels["coquic.steward.release"] == "release-candidate"
    assert configured.config.labels["coquic.steward.epoch"] == "epoch-production"
    assert configured.config.labels["coquic.steward.deployment"] == "steward-production"
    assert configured.config.limits.pids == 64
    assert configured.config.limits.memory_bytes == 134_217_728
    assert configured.config.limits.log_max_bytes == 1024
    assert configured.config.limits.scratch_bytes == 2048


def test_deployment_runtime_identity_requires_an_exact_release(tmp_path: Path) -> None:
    roots = [
        tmp_path / name for name in ("worktree", "archive", "sessions", "git", "common")
    ]
    for root in roots:
        root.mkdir()
    runtime = TaskContainerRuntime(
        TaskContainerConfig(
            task_id="task-deployment",
            image="coquic-steward-task",
            image_digest="sha256:" + "a" * 64,
            worktree=roots[0],
            archive=roots[1],
            private_sessions=roots[2],
            git_dir=roots[3],
            git_common_dir=roots[4],
        )
    )
    config = SimpleNamespace(
        deployment=_deployment(tmp_path),
        ensure_epoch=lambda: {"epochId": "epoch-production"},
    )

    with pytest.raises(ValueError, match="exact release identity"):
        bind_deployment_identity(runtime, config)


def test_production_cli_binds_task_and_planner_deployment_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repository = home / "repository"
    repository.mkdir(parents=True)
    config = StewardConfig(
        repo_root=repository,
        task_image_digest="sha256:" + "a" * 64,
        deployment=_deployment(home, release_id="release-cli"),
    )
    config.ensure_dirs()
    monkeypatch.setattr(
        "coquic_steward.execution.session._provision_group_tree",
        lambda _root, _gid: None,
    )
    store = TaskStore(config.db_path)
    supervisor = cli_module._configured_supervisor(config, store)
    assert supervisor is not None and supervisor.runtime_factory is not None
    task_runtime = supervisor.runtime_factory(
        SimpleNamespace(id="task-cli", worktree_path=repository)
    )
    planner = cli_module._configured_planner_session(config)
    planner_runtime = planner.invoker.runtime

    epoch_id = config.ensure_epoch()["epochId"]
    for runtime in (task_runtime, planner_runtime):
        assert runtime.config.labels["coquic.steward.release"] == "release-cli"
        assert runtime.config.labels["coquic.steward.epoch"] == epoch_id


def test_release_and_pressure_facts_are_private(tmp_path: Path) -> None:
    store = TaskStore(tmp_path / "steward.sqlite")
    store.record_image_release(
        "release-test",
        daemon_image_id="sha256:" + "a" * 64,
        task_image_id="sha256:" + "b" * 64,
        labels={"runtime": "task-container-v1"},
        current=True,
    )
    assert store.list_image_releases()[0]["release_id"] == "release-test"
    store.record_resource_pressure(
        state="resource_pressure",
        home_free_bytes=10,
        owned_docker_bytes=20,
        cleanup_pending_count=1,
        reason="threshold",
    )
    assert store.get_resource_pressure()["state"] == "resource_pressure"
    assert "secret" not in json.dumps(store.get_resource_pressure())


def test_labeled_docker_reconciliation_retains_references_and_reclaims_exact_image(
    tmp_path: Path,
) -> None:
    daemon_image = "sha256:" + "a" * 64
    task_image = "sha256:" + "b" * 64
    unused_image = "sha256:" + "c" * 64
    candidate_daemon = "sha256:" + "e" * 64
    candidate_task = "sha256:" + "f" * 64
    container_id = "d" * 64
    release_id = "release-owned"
    deployment = _deployment(
        tmp_path,
        release_id=release_id,
        daemon_image_id=daemon_image,
        task_image_id=task_image,
    )
    releases = tmp_path / "private" / "deployment" / "releases"
    releases.mkdir(parents=True)
    (releases.parent / "current").write_text(release_id + "\n", encoding="ascii")
    (releases / f"{release_id}.json").write_text(
        json.dumps(
            {
                "releaseId": release_id,
                "daemonImage": daemon_image,
                "daemonImageId": daemon_image,
                "taskImage": task_image,
                "taskImageId": task_image,
                "runtimeProtocol": "task-container-v1",
            }
        ),
        encoding="utf-8",
    )
    (releases / "release-candidate.json").write_text(
        json.dumps(
            {
                "releaseId": "release-candidate",
                "daemonImage": candidate_daemon,
                "daemonImageId": candidate_daemon,
                "taskImage": candidate_task,
                "taskImageId": candidate_task,
                "runtimeProtocol": "task-container-v1",
            }
        ),
        encoding="utf-8",
    )
    (releases / "release-old.json").write_text(
        json.dumps(
            {
                "releaseId": "release-old",
                "daemonImage": unused_image,
                "daemonImageId": unused_image,
                "taskImage": unused_image,
                "taskImageId": unused_image,
                "runtimeProtocol": "task-container-v1",
            }
        ),
        encoding="utf-8",
    )
    (releases.parent / "operation.journal").write_text(
        json.dumps(
            {
                "phase": "build",
                "outcome": "pending",
                "candidateRelease": "release-candidate",
            }
        ),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def runner(argv: list[str]):
        calls.append(argv)
        command = argv[1:]
        if command[:3] == ["container", "ls", "--all"]:
            assert "label=coquic.steward.deployment=coquic-steward" in command
            output = f"{container_id}\n"
            return subprocess.CompletedProcess(argv, 0, output.encode(), b"")
        if command[:3] == ["container", "inspect", "--size"]:
            payload = [
                {
                    "Id": container_id,
                    "Image": task_image,
                    "SizeRw": 11,
                    "State": {"Status": "exited"},
                    "Config": {
                        "Labels": {
                            "coquic.steward.owner": "steward",
                            "coquic.steward.deployment": "coquic-steward",
                            "coquic.steward.runtime": "task-container-v1",
                            "coquic.steward.release": release_id,
                            "coquic.steward.epoch": "epoch-owned",
                            "coquic.steward.task": "task-owned",
                        }
                    },
                },
            ]
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )
        if command[:2] == ["image", "inspect"]:
            sizes = {
                daemon_image: 20,
                task_image: 30,
                unused_image: 40,
                candidate_daemon: 50,
                candidate_task: 60,
            }
            image_id = command[2]
            payload = [
                {
                    "Id": image_id,
                    "Size": sizes[image_id],
                    "Config": {
                        "Labels": {
                            "coquic.steward.owner": "steward",
                            "coquic.steward.runtime-protocol": "task-container-v1",
                        }
                    },
                }
            ]
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )
        if command[:2] == ["image", "rm"]:
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)

    store = TaskStore(tmp_path / "steward.sqlite")
    result = DockerResourceManager(runner=runner).reconcile(store, deployment)

    assert result["ambiguous"] is False
    assert result["reclaimed"] == (unused_image,)
    assert store.list_container_references()[0]["image_id"] == task_image
    assert store.referenced_image_ids() == frozenset({daemon_image, task_image})
    assert ["docker", "image", "rm", unused_image] in calls
    assert not any(call[1:3] == ["image", "ls"] for call in calls)
    assert not any("prune" in value for call in calls for value in call)


def test_health_fails_closed_when_database_state_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()

    class BrokenStore:
        def __init__(self, _path: Path):
            raise OSError("private database detail")

    monkeypatch.setattr(cli_module, "load_config", lambda: config)
    monkeypatch.setattr(cli_module, "TaskStore", BrokenStore)
    result = CliRunner().invoke(cli_module.app, ["health"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["quiescent"] is False
    assert payload["lifecycle"] == "ambiguous"
    assert payload["heartbeat"] == "degraded"
    assert "private database detail" not in result.stdout


def test_health_is_not_quiescent_with_pending_archive_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    store.control_loop_ledger.record_runtime("running")
    assert store.control_loop_ledger.outbox(limit=1)

    monkeypatch.setattr(cli_module, "load_config", lambda: config)
    result = CliRunner().invoke(cli_module.app, ["health"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["archivePending"] is True
    assert payload["quiescent"] is False

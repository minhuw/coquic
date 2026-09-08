"""Real Docker boundary canary, launched by production-canary.sh, never a daemon service."""
from __future__ import annotations

import json
import os
from pathlib import Path

from coquic_steward.core.config import StewardConfig, StewardDeploymentConfig
from coquic_steward.core.models import CodexRunState, TaskKind, TaskSpec, WorkerKind
from coquic_steward.core.subprocesses import run_command
from coquic_steward.execution.container import ContainerBoundaryError, ValidationContainerRuntime
from coquic_steward.execution.container_config import TaskRole, ValidationContainerConfig
from coquic_steward.execution.session import InvocationStatus, session_supervisor_for_config, worktree_checkpoint
from coquic_steward.execution.validation import _docker_validation_runner, default_gates, run_validation
from coquic_steward.storage import TaskStore


def main() -> None:
    assert os.geteuid() == int(os.environ["STEWARD_UID"]) != 0
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status
    assert "NoNewPrivs:\t1" in status
    assert int(os.environ["STEWARD_DOCKER_GID"]) in os.getgroups()
    assert not Path("/run/secrets").exists()
    home = Path(os.environ["COQUIC_HOME"])
    repo = home / "repository"
    repo.mkdir()
    config = StewardConfig(
        repo_root=repo, dry_run=True, codex_identity="deterministic-canary",
        task_image_digest=os.environ["STEWARD_TASK_IMAGE"],
        validation_image_digest=os.environ["STEWARD_VALIDATION_IMAGE"],
        deployment=StewardDeploymentConfig(
            enabled=True, home=home, repository=repo,
            host_uid=os.getuid(), host_gid=os.getgid(),
            docker_gid=int(os.environ["STEWARD_DOCKER_GID"]),
            compose_project=os.environ["CANARY_NAME"], release_id=os.environ["CANARY_NAME"],
            min_free_bytes=1, recovery_free_bytes=2,
            max_owned_docker_bytes=2**40, recovery_owned_docker_bytes=2**39,
        ),
    )
    config.ensure_dirs()
    for command in (["init", "-b", "main"], ["config", "user.email", "canary@example.test"],
                    ["config", "user.name", "Canary"]):
        run_command(["git", *command], cwd=repo, check=True)
    (repo / "README.md").write_text("baseline\n")
    run_command(["git", "add", "."], cwd=repo, check=True)
    run_command(["git", "commit", "-m", "canary baseline"], cwd=repo, check=True)
    worktree = home / "candidate"
    run_command(["git", "worktree", "add", "-b", "canary", str(worktree)], cwd=repo, check=True)
    for relative in ("site/next", ".duvet", ".zig-cache", "steward/src/coquic_steward", "steward/tests"):
        (worktree / relative).mkdir(parents=True)
    (worktree / "steward/src/coquic_steward/__init__.py").write_text("CANDIDATE = True\n")
    (worktree / "steward/tests/test_candidate.py").write_text('''
from pathlib import Path
import pytest
from coquic_steward import CANDIDATE

def test_candidate_boundary():
    assert CANDIDATE
    assert not Path('/var/run/docker.sock').exists()
    assert not Path('/run/secrets').exists()
    with pytest.raises(OSError):
        Path('README.md').write_text('must remain read-only')
    assert False, 'deliberate candidate-only failure'
''')
    fake = worktree / "fake-codex"
    fake.write_text('''#!/bin/bash
set -eu
last=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output-last-message ]; then last="$2"; shift 2; else shift; fi
done
cat >/dev/null
test ! -S /var/run/docker.sock
test ! -e /run/secrets
if [ "$COQUIC_STEWARD_ROLE" = implementation ]; then
  printf 'model implementation\\n' >>/task/worktree/README.md
fi
printf '%s\\n' '{"type":"thread.started","thread_id":"canary-provider"}'
printf 'deterministic completion\\n' >"$last"
printf '%s\\n' '{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1}}'
''')
    fake.chmod(0o755)
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom,
                                     title="production boundary canary", prompt="no remote effects"))
    task.worktree_path = worktree
    store.save(task)
    pipeline = store.list_pipelines(task.id)[0]
    filename, command = default_gates(worktree)[-1]
    before = (worktree / "README.md").read_bytes()
    validation = run_validation(
        config, task.id, worktree, filename, command,
        command_runner=_docker_validation_runner(config, task.id, worktree),
    )
    validation_log = validation.output_path.read_text()
    assert not validation.passed and validation.exit_code == 1, validation_log
    assert "deliberate candidate-only failure" in validation_log, validation_log
    assert (worktree / "README.md").read_bytes() == before
    print("candidate validation container rejected deliberate failure; source remained read-only", flush=True)
    validation_root = home / "durable-validation"
    for child in ("output", "store"):
        (validation_root / child).mkdir(parents=True)
    validation_runtime = ValidationContainerRuntime(ValidationContainerConfig(
        run_id=os.environ["CANARY_NAME"] + "-env",
        image=config.validation_image, image_digest=config.validation_image_digest,
        worktree=worktree, output=validation_root / "output", store=validation_root / "store",
        git_common_dir=repo / ".git", uid=os.getuid(), gid=os.getgid(),
        labels={"coquic.steward.deployment": os.environ["CANARY_NAME"]},
    ))
    try:
        validation_runtime.ensure_started()
        # No exec environment injection or bootstrap wrapper: test persisted Config.Env.
        probe = validation_runtime.exec(["python", "-c", """
import json, os, subprocess, sys
from pathlib import Path
for key, value in json.loads(sys.argv[1]).items():
    assert os.environ[key] == value, key
assert 'NIX_CONFIG' not in os.environ
home_config = Path(os.environ['HOME']) / '.config/nix/nix.conf'
xdg_config = Path(os.environ['XDG_CONFIG_HOME']) / 'nix/nix.conf'
assert home_config.read_bytes() == xdg_config.read_bytes()
settings = json.loads(subprocess.check_output(['nix', 'config', 'show', '--json']))
assert settings['sandbox']['value'] is True
assert settings['substituters']['value'] == []
assert settings['trusted-public-keys']['value'] == []
assert {'nix-command', 'flakes'} <= set(settings['experimental-features']['value'])
print('durable Nix exec inherited fixed paths and offline sandbox policy')
""", json.dumps(dict(validation_runtime.config.environment))], timeout=30)
        assert probe.exit_code == 0, (probe.stdout, probe.stderr)
        print(probe.stdout.decode(), end="", flush=True)
    finally:
        validation_runtime.cleanup_owned(timeout=1)
    supervisor = session_supervisor_for_config(config, store)
    assert supervisor is not None and supervisor.runtime_factory is not None
    factory = supervisor.runtime_factory
    runtimes = []

    def fake_model_factory(record):
        # Never replace provisioning, identity, mounts, exec framing, or receipts.
        # The only fake is the model executable; the public factory runs first.
        runtime = factory(record)
        stream = runtime.exec_stream

        def fake_stream(role, **kwargs):
            command = list(kwargs["command"])
            assert command[:3] == ["/bin/task-entrypoint.sh", "run", "codex"]
            command[2] = "/task/worktree-ro/fake-codex"
            return stream(role, **{**kwargs, "command": command})

        runtime.exec_stream = fake_stream
        runtimes.append(runtime)
        return runtime

    supervisor.runtime_factory = fake_model_factory
    try:
        sessions = []
        for role in (TaskRole.implementation, TaskRole.reviewer):
            before_checkpoint = worktree_checkpoint(config, worktree)
            result = supervisor.start(task.id, pipeline.id, role=role, prompt="canary",
                                      cwd=worktree, timeout_seconds=30)
            assert result.status is InvocationStatus.succeeded and result.exit_code == 0, result
            assert result.last_message_path.read_text() == "deterministic completion\n"
            assert TaskStore.open(config.db_path).get_run(result.run_id).state == CodexRunState.succeeded
            receipt = json.loads(result.last_message_path.with_name("result.json").read_text())
            assert receipt["status"] == "available", receipt
            assert (receipt["task_id"], receipt["pipeline_id"], receipt["session_id"], receipt["run_id"]) == (
                task.id, pipeline.id, result.session_id, result.run_id,
            ), receipt
            assert receipt["output_checkpoint"] == worktree_checkpoint(config, worktree), receipt
            if role is TaskRole.implementation:
                assert receipt["output_checkpoint"] != before_checkpoint, receipt
            sessions.append(store.get_session(result.session_id))
        runtime = runtimes[0]
        inspection = runtime.adopt()
        assert inspection.raw["HostConfig"]["CapDrop"] == ["ALL"]
        assert all("docker.sock" not in mount["Source"] for mount in inspection.raw["Mounts"])
        implementation, reviewer = sessions

        def execute(session, command):
            return runtime.exec(session.owner_role, session_uid=session.home_uid,
                                session_id=session.id, command=command, timeout=10)

        execute(implementation, ["bash", "-c", "echo implementation >> /task/worktree/README.md"])
        for command in (
            ["bash", "-c", "echo forbidden >> /task/worktree/README.md"],
            ["cat", f"/task/session/{implementation.id}/config.toml"],
        ):
            try:
                result = execute(reviewer, command)
            except ContainerBoundaryError:
                continue
            assert result.exit_code != 0, "reviewer crossed role/session boundary"
        # No live provider or remote configured. Failed validation cannot be
        # mistaken for acceptance, even after reopening persisted session state.
        reopened = TaskStore.open(config.db_path)
        assert reopened.get_session(reviewer.id).id == reviewer.id
        assert not run_command(["git", "remote"], cwd=repo, check=True).stdout.strip()
        print("production canary passed: real provisioning, sessions, role isolation, candidate failure")
    finally:
        for runtime in runtimes:
            runtime.stop(timeout=1)
            runtime.remove()


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import getpass
import shutil
import socket
import sqlite3
import stat
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.dataset_sync import (
    DatasetSyncCategory,
    DatasetSyncReceiverError,
    FakeDatasetReceiver,
    StewardDatasetSynchronizer,
    build_forced_receiver_authorized_key,
    build_receiver_rsyncd_config,
    build_rsync_argv,
    classify_rsync_result,
    validate_forced_receiver_command,
    validate_receiver_relative_path,
    validate_rsync_argv,
)
from coquic_steward.dataset_sync_config import DatasetSyncConfig, validate_dataset_roots
from coquic_steward.storage import TaskStore


def _roots(tmp_path: Path, *, epoch: str = "epoch-test") -> tuple[Path, Path]:
    tasks = tmp_path / "tasks"
    control = tmp_path / "control-loop"
    tasks.mkdir()
    control.mkdir()
    (tasks / "epoch.json").write_text(
        json.dumps(
            {
                "epochId": epoch,
                "formatVersion": "1.0",
                "policy": "post-steward-2.0",
                "startedAt": "2026-01-01T00:00:00Z",
                "endedAt": None,
            }
        ),
        encoding="utf-8",
    )
    (control / "epoch.json").write_text(
        json.dumps(
            {
                "epochId": epoch,
                "formatVersion": "1.0",
                "taskFormatVersion": "1.0",
                "policy": "post-steward-2.0",
                "startedAt": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return tasks, control


def _config(tmp_path: Path, *, enabled: bool = True) -> DatasetSyncConfig:
    tasks, control = _roots(tmp_path)
    identity = tmp_path / "identity"
    identity.write_text("fake-private-key", encoding="utf-8")
    identity.chmod(stat.S_IRUSR | stat.S_IWUSR)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("receiver.example.test ssh-ed25519 fake", encoding="utf-8")
    known_hosts.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return DatasetSyncConfig(
        enabled=enabled,
        tasks_dir=tasks,
        control_loop_dir=control,
        remote_user="dataset",
        remote_host="receiver.example.test",
        remote_port=2222,
        identity_path=identity,
        known_hosts_path=known_hosts,
        connect_timeout_seconds=2,
        transfer_timeout_seconds=10,
    )


def test_config_requires_canonical_siblings_and_shared_epoch(tmp_path: Path) -> None:
    config = _config(tmp_path)
    assert config.destination == "steward-dataset"
    assert config.tasks_dir.name == "tasks"
    assert config.control_loop_dir.name == "control-loop"
    with pytest.raises(ValueError, match="steward-dataset"):
        DatasetSyncConfig(
            enabled=True,
            tasks_dir=config.tasks_dir,
            control_loop_dir=config.control_loop_dir,
            remote_user="dataset",
            remote_host="receiver.example.test",
            remote_port=22,
            identity_path=config.identity_path,
            known_hosts_path=config.known_hosts_path,
            destination="./",
        )

    mismatch = tmp_path / "mismatch"
    mismatch.mkdir()
    tasks, control = _roots(mismatch, epoch="one")
    control_epoch = json.loads((control / "epoch.json").read_text())
    control_epoch["epochId"] = "two"
    (control / "epoch.json").write_text(json.dumps(control_epoch))
    with pytest.raises(ValueError, match="epochs"):
        DatasetSyncConfig(
            enabled=True,
            tasks_dir=tasks,
            control_loop_dir=control,
            remote_user="dataset",
            remote_host="receiver.example.test",
            remote_port=22,
            identity_path=config.identity_path,
            known_hosts_path=config.known_hosts_path,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(endedAt="2026-01-02T00:00:00Z"),
        lambda value: value.update(unexpected="extra"),
    ],
)
def test_preflight_rejects_closed_or_extended_task_epoch_without_launch(
    tmp_path: Path, mutation
) -> None:
    config = _config(tmp_path)
    epoch_path = config.tasks_dir / "epoch.json"
    value = json.loads(epoch_path.read_text(encoding="utf-8"))
    mutation(value)
    epoch_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        validate_dataset_roots(config.tasks_dir, config.control_loop_dir)

    store = TaskStore(tmp_path / "state" / "state.sqlite")
    called = False

    def runner(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    # The immutable config was valid at construction time; the immediate
    # pre-launch validation must catch the changed schema and never call rsync.
    result = StewardDatasetSynchronizer(config, store, runner=runner).run_once()
    assert result.category == DatasetSyncCategory.source_invariant
    assert not called


def test_control_loop_epoch_rejects_forbidden_extra_fields(tmp_path: Path) -> None:
    config = _config(tmp_path)
    epoch_path = config.control_loop_dir / "epoch.json"
    value = json.loads(epoch_path.read_text(encoding="utf-8"))
    value["endedAt"] = None
    epoch_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        validate_dataset_roots(config.tasks_dir, config.control_loop_dir)


def test_partial_dataset_health_migration_is_rejected_without_canonical_row(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite"
    store = TaskStore(path)
    store.engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM dataset_sync_health")
        connection.execute(
            "INSERT INTO dataset_sync_health (id, enabled, consecutive_failure_count) "
            "VALUES ('partial-dataset-sync', 1, 2)"
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="ambiguous"):
        TaskStore(path)
    with sqlite3.connect(path) as connection:
        ids = [row[0] for row in connection.execute("SELECT id FROM dataset_sync_health")]
    assert ids == ["partial-dataset-sync"]


def test_valid_task_only_health_migration_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite"
    store = TaskStore(path)
    store.engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE dataset_sync_health SET id='task-archive-sync' WHERE id='dataset-sync'"
        )
        connection.execute("ALTER TABLE dataset_sync_health RENAME TO task_archive_sync_health")
        connection.commit()
    migrated = TaskStore(path)
    assert migrated.get_dataset_sync_health().enabled is False
    migrated.engine.dispose()
    reopened = TaskStore(path)
    assert reopened.get_dataset_sync_health().enabled is False
    reopened.engine.dispose()
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "task_archive_sync_health" not in tables
    assert "dataset_sync_health" in tables


def test_argv_has_exact_two_sources_and_fixed_relative_destination(tmp_path: Path) -> None:
    argv = build_rsync_argv(_config(tmp_path))
    assert argv[-3:] == [
        str(tmp_path / "tasks"),
        str(tmp_path / "control-loop"),
        "dataset@receiver.example.test::steward-dataset",
    ]
    assert "--recursive" in argv
    assert "--times" in argv
    assert "--modify-window=-1" in argv
    assert not any("delete" in token or "inplace" in token for token in argv)
    validate_rsync_argv(argv)
    with pytest.raises(DatasetSyncReceiverError):
        validate_rsync_argv([*argv[:-1], "dataset@receiver.example.test::other"])
    with pytest.raises(DatasetSyncReceiverError):
        validate_rsync_argv([*argv[:-3], "/private", *argv[-3:]])


def test_receiver_confines_top_level_names_and_forbidden_options(tmp_path: Path) -> None:
    receiver = tmp_path / "receiver"
    (receiver / "tasks").mkdir(parents=True)
    (receiver / "control-loop").mkdir()
    receiver.chmod(0o755)
    harness = FakeDatasetReceiver(receiver)
    assert "write only = yes" in build_receiver_rsyncd_config(receiver)
    assert harness.accept_upload("tasks/file.json") == receiver
    assert harness.accept_upload("control-loop/events.jsonl") == receiver
    with pytest.raises(DatasetSyncReceiverError):
        harness.accept_upload("cache/private")
    with pytest.raises(DatasetSyncReceiverError):
        harness.accept_upload("tasks/.hidden")
    with pytest.raises(DatasetSyncReceiverError):
        harness.accept_upload("tasks/file", options=("--delete",))
    line = build_forced_receiver_authorized_key("ssh-ed25519 AAAA-fake", receiver)
    assert line.startswith('restrict,command="')
    assert validate_forced_receiver_command(harness.forced_command)
    with pytest.raises(DatasetSyncReceiverError):
        validate_forced_receiver_command(
            "/usr/bin/rsync --server --daemon --config=/other.conf .",
            config_path="/other.conf",
        )


def test_real_rsync_two_root_transfer_through_forced_daemon(tmp_path: Path) -> None:
    """Exercise rsync 3.2.7's two-source daemon-over-SSH framing."""

    required = ("/usr/sbin/sshd", "ssh-keygen", "ssh-keyscan", "rsync")
    if any(shutil.which(item) is None for item in required):
        pytest.skip("OpenSSH and rsync are required for the daemon protocol fixture")
    if subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0:
        pytest.skip("passwordless sudo is required to install the fixed local fixture config")
    fixed_config = Path("/fixed/rsyncd.conf")
    if subprocess.run(["sudo", "-n", "test", "-e", str(fixed_config)], check=False).returncode == 0:
        pytest.skip("fixed receiver config is already managed by the host")

    source_base = tmp_path / "source"
    source_base.mkdir()
    source_tasks, source_control = _roots(source_base)
    receiver = tmp_path / "receiver"
    (receiver / "tasks").mkdir(parents=True)
    (receiver / "control-loop").mkdir()
    receiver.chmod(0o755)
    (source_tasks / "task.json").write_text("task\n", encoding="utf-8")
    (source_control / "event.jsonl").write_text("event\n", encoding="utf-8")
    identity = tmp_path / "identity"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(identity)],
        check=True,
    )
    host_key = tmp_path / "host-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
        check=True,
    )
    public_key = Path(f"{identity}.pub").read_text(encoding="utf-8").strip()
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_text(
        f'restrict,command="/usr/bin/rsync --server --daemon --config=/fixed/rsyncd.conf ." '
        f"{public_key}\n",
        encoding="utf-8",
    )
    authorized_keys.chmod(0o600)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text(
        "\n".join(
            (
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {host_key}",
                f"AuthorizedKeysFile {authorized_keys}",
                "StrictModes no",
                "PasswordAuthentication no",
                "PubkeyAuthentication yes",
                "UsePAM no",
                "PermitRootLogin no",
                f"AllowUsers {getpass.getuser()}",
                f"PidFile {tmp_path / 'sshd.pid'}",
                "LogLevel ERROR",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(["/usr/sbin/sshd", "-t", "-f", str(sshd_config)], check=True)
    daemon = subprocess.Popen(
        ["/usr/sbin/sshd", "-D", "-e", "-f", str(sshd_config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        receiver_config = build_receiver_rsyncd_config(receiver)
        subprocess.run(["sudo", "-n", "mkdir", "-p", "/fixed"], check=True)
        subprocess.run(
            ["sudo", "-n", "tee", str(fixed_config)],
            input=receiver_config.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(["sudo", "-n", "chmod", "644", str(fixed_config)], check=True)
        known_hosts = tmp_path / "known_hosts"
        scan = None
        for _ in range(80):
            time.sleep(0.05)
            result = subprocess.run(
                ["ssh-keyscan", "-T", "1", "-p", str(port), "127.0.0.1"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                scan = result.stdout
                break
        assert scan
        known_hosts.write_text(scan, encoding="utf-8")
        known_hosts.chmod(0o600)
        config = DatasetSyncConfig(
            enabled=True,
            tasks_dir=source_tasks,
            control_loop_dir=source_control,
            remote_user=getpass.getuser(),
            remote_host="127.0.0.1",
            remote_port=port,
            identity_path=identity,
            known_hosts_path=known_hosts,
            transfer_timeout_seconds=20,
        )
        argv = build_rsync_argv(config)
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        assert result.returncode == 0, result.stderr
        assert (receiver / "tasks" / "task.json").read_text(encoding="utf-8") == "task\n"
        assert (receiver / "control-loop" / "event.jsonl").read_text(encoding="utf-8") == "event\n"
    finally:
        daemon.terminate()
        daemon.wait(timeout=5)
        subprocess.run(["sudo", "-n", "rm", "-rf", "/fixed"], check=True)


def test_classification_keeps_exit24_retryable_and_output_bounded() -> None:
    assert classify_rsync_result(0).category == DatasetSyncCategory.success
    result = classify_rsync_result(24, stderr=b"private key and race")
    assert result.category == DatasetSyncCategory.incomplete
    assert result.retryable
    assert len(result.safe_detail) < 256


def test_run_once_claims_one_process_and_persists_health(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    calls: list[list[str]] = []

    def runner(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr=b"private output")

    result = StewardDatasetSynchronizer(config, store, runner=runner).run_once()
    assert result.success
    assert len(calls) == 1
    health = store.get_dataset_sync_health()
    assert health.last_category == "success"
    assert health.active_cycle_id is None
    assert "private output" not in str(health)


def test_run_once_rejects_epoch_mismatch_without_launch(tmp_path: Path) -> None:
    config = _config(tmp_path)
    control = config.control_loop_dir / "epoch.json"
    value = json.loads(control.read_text())
    value["epochId"] = "different"
    control.write_text(json.dumps(value))
    store = TaskStore(tmp_path / "state.sqlite")
    called = False

    def runner(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    result = StewardDatasetSynchronizer(config, store, runner=runner).run_once()
    assert result.category == DatasetSyncCategory.source_invariant
    assert not called
    assert store.get_dataset_sync_health().last_category == "source_invariant"


def test_concurrent_claim_is_busy(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    store.set_dataset_sync_enabled(True)
    assert store.claim_dataset_sync_cycle("active", require_enabled=True)
    result = StewardDatasetSynchronizer(
        config, store, runner=lambda *_args, **_kwargs: pytest.fail("busy launched")
    ).run_once()
    assert result.category == DatasetSyncCategory.busy

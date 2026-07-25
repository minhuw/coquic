from __future__ import annotations

import json
import getpass
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
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


def _public_bytes(*roots: Path) -> dict[Path, bytes]:
    result: dict[Path, bytes] = {}
    for root in roots:
        for path in root.rglob("*"):
            relative = path.relative_to(root)
            if any(part.startswith((".", "~")) for part in relative.parts):
                continue
            if stat.S_ISREG(path.lstat().st_mode):
                result[Path(root.name) / relative] = path.read_bytes()
    return result


def _copy_visible_dataset(
    argv: list[str],
    receiver: Path,
    *,
    manifests_only: bool = False,
) -> tuple[list[Path], int]:
    """Model rsync's visible-regular default temporary replacement."""

    validate_rsync_argv(argv)
    copied: list[Path] = []
    largest_temporary = 0
    for source_text in argv[-3:-1]:
        source = Path(source_text)
        for path in source.rglob("*"):
            relative = path.relative_to(source)
            if any(part.startswith((".", "~")) for part in relative.parts):
                continue
            destination = receiver / source.name / relative
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if manifests_only and path.name != "manifest.json":
                continue
            if destination.exists():
                destination_metadata = destination.stat()
                if (
                    destination_metadata.st_size == metadata.st_size
                    and destination_metadata.st_mtime_ns == metadata.st_mtime_ns
                ):
                    continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.rsync-tmp")
            shutil.copy2(path, temporary)
            largest_temporary = max(largest_temporary, temporary.stat().st_size)
            os.replace(temporary, destination)
            copied.append(Path(source.name) / relative)
    return copied, largest_temporary


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
        ids = [
            row[0] for row in connection.execute("SELECT id FROM dataset_sync_health")
        ]
    assert ids == ["partial-dataset-sync"]


def test_valid_task_only_health_migration_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite"
    store = TaskStore(path)
    store.engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE dataset_sync_health SET id='task-archive-sync' WHERE id='dataset-sync'"
        )
        connection.execute(
            "ALTER TABLE dataset_sync_health RENAME TO task_archive_sync_health"
        )
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


def test_argv_has_exact_two_sources_and_fixed_relative_destination(
    tmp_path: Path,
) -> None:
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


def test_receiver_confines_top_level_names_and_forbidden_options(
    tmp_path: Path,
) -> None:
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
    for option in ("--delete", "--archive", "-a", "-av", "-rlptgoD"):
        with pytest.raises(DatasetSyncReceiverError):
            harness.accept_upload("tasks/file", options=(option,))
    for option in ("--recursive", "--times", "-r", "-rtv"):
        assert harness.accept_upload("tasks/file", options=(option,)) == receiver
    line = build_forced_receiver_authorized_key("ssh-ed25519 AAAA-fake", receiver)
    assert line.startswith('restrict,command="')
    assert validate_forced_receiver_command(harness.forced_command)
    with pytest.raises(DatasetSyncReceiverError):
        validate_forced_receiver_command(
            "/usr/bin/rsync --server --daemon --config=/other.conf .",
            config_path="/other.conf",
        )


def test_direct_real_rsync_incremental_interrupted_storage_and_no_delete(
    tmp_path: Path,
) -> None:
    """Exercise rsync 3.2.7's two-source daemon-over-SSH framing."""

    required = ("/usr/sbin/sshd", "ssh-keygen", "ssh-keyscan", "rsync")
    if any(shutil.which(item) is None for item in required):
        pytest.skip("OpenSSH and rsync are required for the daemon protocol fixture")
    if subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0:
        pytest.skip(
            "passwordless sudo is required to install the fixed local fixture config"
        )
    fixed_config = Path("/fixed/rsyncd.conf")
    if (
        subprocess.run(
            ["sudo", "-n", "test", "-e", str(fixed_config)], check=False
        ).returncode
        == 0
    ):
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
    private = source_base / "private.sqlite"
    private.write_text("private\n", encoding="utf-8")
    retained = receiver / "tasks" / "retained.json"
    retained.write_text("history\n", encoding="utf-8")
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
        assert (receiver / "tasks" / "task.json").read_text(
            encoding="utf-8"
        ) == "task\n"
        assert (receiver / "control-loop" / "event.jsonl").read_text(
            encoding="utf-8"
        ) == "event\n"
        remote_task = receiver / "tasks" / "task.json"
        unchanged_inode = remote_task.stat().st_ino
        unchanged_mtime = remote_task.stat().st_mtime_ns
        repeated = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        assert repeated.returncode == 0, repeated.stderr
        assert remote_task.stat().st_ino == unchanged_inode
        assert remote_task.stat().st_mtime_ns == unchanged_mtime

        source_mtime = (source_tasks / "task.json").stat().st_mtime_ns
        (source_tasks / "task.json").write_text("TASK\n", encoding="utf-8")
        os.utime(source_tasks / "task.json", ns=(source_mtime + 1, source_mtime + 1))
        with (source_control / "event.jsonl").open("a", encoding="utf-8") as handle:
            handle.write("event-2\n")
        sealed = source_control / "planner-runs" / "run-1"
        sealed.mkdir(parents=True)
        (sealed / "manifest.json").write_text("manifest\n", encoding="utf-8")
        incremental = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        assert incremental.returncode == 0, incremental.stderr
        assert remote_task.read_text(encoding="utf-8") == "TASK\n"
        assert (receiver / "control-loop" / "event.jsonl").read_text(
            encoding="utf-8"
        ) == "event\nevent-2\n"
        assert (
            receiver / "control-loop" / "planner-runs" / "run-1" / "manifest.json"
        ).read_text(encoding="utf-8") == "manifest\n"
        assert retained.read_text(encoding="utf-8") == "history\n"
        assert not (receiver / private.name).exists()

        payload = b"x" * (4 * 1024 * 1024)
        large = source_tasks / "large.bin"
        large.write_bytes(payload)
        remote_large = receiver / "tasks" / large.name
        remote_large.write_bytes(b"old")
        slow_argv = list(argv)
        slow_argv[-3:-3] = ["--bwlimit=512"]
        process = subprocess.Popen(
            slow_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        largest_temporary = 0
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline:
                temporary_files = [
                    path
                    for path in remote_large.parent.iterdir()
                    if path.is_file() and path.name.startswith(f".{large.name}.")
                ]
                if temporary_files:
                    largest_temporary = max(
                        path.stat().st_size for path in temporary_files
                    )
                    if largest_temporary > 0:
                        break
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            assert process.poll() is None, process.communicate()[1]
            assert 0 < largest_temporary <= len(payload)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
        assert remote_large.read_bytes() == b"old"
        assert not any(receiver.rglob(".partial"))
        retry = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        assert retry.returncode == 0, retry.stderr
        assert remote_large.read_bytes() == payload
    finally:
        daemon.terminate()
        daemon.wait(timeout=5)
        subprocess.run(["sudo", "-n", "rm", "-rf", "/fixed"], check=True)


def test_monotonic_incremental_storage_has_no_projection_or_private_disclosure(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    config = _config(source)
    task = config.tasks_dir / "2026-07" / "task-1"
    task.mkdir(parents=True)
    task_events = task / "events.jsonl"
    task_events.write_bytes(b'{"event":1}\n')
    task_metadata = task / "metadata.json"
    task_metadata.write_bytes(b"AAAA")
    (task / "manifest.json").write_bytes(b'{"terminal":true}\n')
    control_events = config.control_loop_dir / "events" / "2026-07-25.jsonl"
    control_events.parent.mkdir()
    control_events.write_bytes(b'{"signal":1}\n')
    (config.control_loop_dir / "current.json").write_bytes(b"1111")

    private = source / "private.sqlite"
    private.write_bytes(b"must-not-transfer")
    (task / ".temporary").write_bytes(b"hidden")
    (task / "~draft").write_bytes(b"hidden")
    (task / "private-link").symlink_to(private)
    os.mkfifo(task / "stream.fifo")

    receiver = tmp_path / "receiver"
    (receiver / "tasks").mkdir(parents=True)
    (receiver / "control-loop").mkdir()
    (receiver / "cache").mkdir()
    cache_canary = receiver / "cache" / "site-v2.sqlite"
    cache_canary.write_bytes(b"cache")
    retained = receiver / "tasks" / "retained-history.json"
    retained.write_bytes(b"history")
    copied_cycles: list[list[Path]] = []
    temporary_bounds: list[int] = []
    process_argv: list[list[str]] = []

    def fake_transfer(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        process_argv.append(argv)
        copied, largest_temporary = _copy_visible_dataset(argv, receiver)
        copied_cycles.append(copied)
        temporary_bounds.append(largest_temporary)
        return SimpleNamespace(returncode=0, stderr=b"")

    store = TaskStore(tmp_path / "state.sqlite")
    synchronizer = StewardDatasetSynchronizer(config, store, runner=fake_transfer)
    assert synchronizer.run_once().success
    expected = _public_bytes(config.tasks_dir, config.control_loop_dir)
    for relative, payload in expected.items():
        assert (receiver / relative).read_bytes() == payload

    unchanged_source = _public_bytes(config.tasks_dir, config.control_loop_dir)
    assert synchronizer.run_once().success
    assert copied_cycles[-1] == []
    assert temporary_bounds[-1] == 0
    assert _public_bytes(config.tasks_dir, config.control_loop_dir) == unchanged_source

    with task_events.open("ab") as handle:
        handle.write(b'{"event":2}\n')
    with control_events.open("ab") as handle:
        handle.write(b'{"signal":2}\n')
    metadata_mtime = task_metadata.stat().st_mtime_ns
    task_metadata.write_bytes(b"BBBB")
    os.utime(task_metadata, ns=(metadata_mtime + 1, metadata_mtime + 1))
    current = config.control_loop_dir / "current.json"
    current_mtime = current.stat().st_mtime_ns
    current.write_bytes(b"2222")
    os.utime(current, ns=(current_mtime + 1, current_mtime + 1))
    planner_run = config.control_loop_dir / "planner-runs" / "run-1"
    planner_run.mkdir(parents=True)
    (planner_run / "result.json").write_bytes(b'{"result":1}\n')
    (planner_run / "manifest.json").write_bytes(b'{"sealed":true}\n')
    sealed_task = config.tasks_dir / "2026-07" / "task-2"
    sealed_task.mkdir()
    (sealed_task / "manifest.json").write_bytes(b'{"terminal":true}\n')

    assert synchronizer.run_once().success
    expected = _public_bytes(config.tasks_dir, config.control_loop_dir)
    for relative, payload in expected.items():
        assert (receiver / relative).read_bytes() == payload
    assert len(process_argv) == 3
    assert all(
        argv[-3:-1] == [str(config.tasks_dir), str(config.control_loop_dir)]
        for argv in process_argv
    )
    assert retained.read_bytes() == b"history"
    assert cache_canary.read_bytes() == b"cache"
    assert not (receiver / private.name).exists()
    assert not (receiver / "tasks" / "2026-07" / "task-1" / ".temporary").exists()
    assert not (receiver / "tasks" / "2026-07" / "task-1" / "~draft").exists()
    assert not (receiver / "tasks" / "2026-07" / "task-1" / "private-link").exists()
    assert not (receiver / "tasks" / "2026-07" / "task-1" / "stream.fifo").exists()
    assert all(bound <= max(map(len, expected.values())) for bound in temporary_bounds)
    assert not any(receiver.rglob("*.rsync-tmp"))
    assert not any(
        (source / name).exists()
        for name in ("raw-dataset", "projection", "revision", "stage", "cache")
    )


def test_manifest_first_ordering_and_interrupted_retry_converge(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    config = _config(source)
    task = config.tasks_dir / "2026-07" / "task-1"
    task.mkdir(parents=True)
    (task / "events.jsonl").write_bytes(b'{"event":1}\n')
    (task / "manifest.json").write_bytes(b'{"terminal":true}\n')
    planner = config.control_loop_dir / "planner-runs" / "run-1"
    planner.mkdir(parents=True)
    (planner / "result.json").write_bytes(b'{"result":1}\n')
    (planner / "manifest.json").write_bytes(b'{"sealed":true}\n')
    receiver = tmp_path / "receiver"
    (receiver / "tasks").mkdir(parents=True)
    (receiver / "control-loop").mkdir()
    calls = 0

    def interrupted_then_complete(
        argv: list[str], **_kwargs: object
    ) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        _copy_visible_dataset(argv, receiver, manifests_only=calls == 1)
        return SimpleNamespace(returncode=24 if calls == 1 else 0, stderr=b"")

    synchronizer = StewardDatasetSynchronizer(
        config,
        TaskStore(tmp_path / "state.sqlite"),
        runner=interrupted_then_complete,
    )
    interrupted = synchronizer.run_once()
    assert interrupted.category == DatasetSyncCategory.incomplete
    assert interrupted.retryable
    assert (receiver / "tasks" / "2026-07" / "task-1" / "manifest.json").exists()
    assert not (receiver / "tasks" / "2026-07" / "task-1" / "events.jsonl").exists()
    assert (
        receiver / "control-loop" / "planner-runs" / "run-1" / "manifest.json"
    ).exists()
    assert not (
        receiver / "control-loop" / "planner-runs" / "run-1" / "result.json"
    ).exists()

    assert synchronizer.run_once().success
    assert calls == 2
    for relative, payload in _public_bytes(
        config.tasks_dir, config.control_loop_dir
    ).items():
        assert (receiver / relative).read_bytes() == payload


def test_enospc_storage_failure_preserves_history_without_delete(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    retained = tmp_path / "remote-retained"
    retained.write_bytes(b"history")
    store = TaskStore(tmp_path / "state.sqlite")
    result = StewardDatasetSynchronizer(
        config,
        store,
        runner=lambda _argv, **_kwargs: SimpleNamespace(
            returncode=23,
            stderr=b"write failed: No space left on device (28) private-canary",
        ),
    ).run_once()
    assert result.category == DatasetSyncCategory.remote_space
    assert result.retryable
    assert retained.read_bytes() == b"history"
    health = store.get_dataset_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == DatasetSyncCategory.remote_space
    assert "private-canary" not in str(health)


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


def test_run_once_timeout_releases_claim_without_raw_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")

    def runner(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(
            argv,
            config.transfer_timeout_seconds,
            output=b"private-timeout-output",
            stderr=b"private-timeout-error",
        )

    result = StewardDatasetSynchronizer(config, store, runner=runner).run_once()

    assert result.category == DatasetSyncCategory.timeout
    assert result.retryable
    health = store.get_dataset_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == DatasetSyncCategory.timeout
    assert "private-timeout" not in str(result)
    assert "private-timeout" not in str(health)


def test_run_once_cancel_stops_active_child_and_releases_claim(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    cancelled = threading.Event()
    child: subprocess.Popen[bytes] | None = None
    timer: threading.Timer | None = None

    def runner(_argv: list[str], **_kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal child, timer
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        timer = threading.Timer(0.05, cancelled.set)
        timer.start()
        return child

    child_stopped = False
    try:
        result = StewardDatasetSynchronizer(
            config,
            store,
            runner=runner,
            cancel_event=cancelled,
        ).run_once()
        child_stopped = child is not None and child.poll() is not None
    finally:
        if timer is not None:
            timer.join()
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate()

    assert result.category == DatasetSyncCategory.cancelled
    assert child_stopped
    health = store.get_dataset_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == DatasetSyncCategory.cancelled


def test_run_once_contains_runner_exception_and_releases_claim(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")

    class UnexpectedRunnerError(Exception):
        pass

    def runner(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        raise UnexpectedRunnerError("private-runner-detail")

    result = StewardDatasetSynchronizer(config, store, runner=runner).run_once()

    assert result.category == DatasetSyncCategory.unknown
    assert result.retryable
    health = store.get_dataset_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == DatasetSyncCategory.unknown
    assert "private-runner-detail" not in str(result)
    assert "private-runner-detail" not in str(health)


def test_run_once_interrupt_stops_active_child_and_reconciles_health(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")

    class InterruptingProcess:
        def __init__(self) -> None:
            self.child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.interrupted = False

        @property
        def returncode(self) -> int | None:
            return self.child.returncode

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            return self.child.communicate(timeout=timeout)

        def poll(self) -> int | None:
            return self.child.poll()

        def terminate(self) -> None:
            self.child.terminate()

        def kill(self) -> None:
            self.child.kill()

    process = InterruptingProcess()
    child_stopped = False
    try:
        with pytest.raises(KeyboardInterrupt):
            StewardDatasetSynchronizer(
                config,
                store,
                runner=lambda _argv, **_kwargs: process,
            ).run_once()
        child_stopped = process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.child.communicate()

    assert child_stopped
    health = store.get_dataset_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == DatasetSyncCategory.interrupted
    assert health.last_detail == "cycle interrupted before completion"


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

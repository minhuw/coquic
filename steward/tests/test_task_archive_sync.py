from __future__ import annotations

import getpass
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.storage import TaskStore
from coquic_steward.task_archive_sync import (
    FakeTaskArchiveReceiver,
    TaskArchiveSyncCategory,
    TaskArchiveSyncReceiverError,
    TaskArchiveSynchronizer,
    build_forced_receiver_authorized_key,
    build_receiver_rsyncd_config,
    build_rsync_argv,
    classify_rsync_result,
    validate_forced_receiver_command,
    validate_source_tree,
)
from coquic_steward.task_archive_sync_config import TaskArchiveSyncConfig


def _config(tmp_path: Path, *, enabled: bool = True) -> TaskArchiveSyncConfig:
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    identity = tmp_path / "identity"
    identity.write_text("fake-private-key", encoding="utf-8")
    identity.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fake-host-key", encoding="utf-8")
    return TaskArchiveSyncConfig(
        enabled=enabled,
        tasks_dir=tasks,
        remote_user="archive",
        remote_host="receiver.example.test",
        remote_port=2222,
        identity_path=identity,
        known_hosts_path=known_hosts,
        connect_timeout_seconds=2,
        transfer_timeout_seconds=10,
    )


def test_config_rejects_symlink_and_non_private_identity(tmp_path: Path) -> None:
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    identity = tmp_path / "identity"
    identity.write_text("secret", encoding="utf-8")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host", encoding="utf-8")
    with pytest.raises(ValueError, match="group- or world-readable"):
        TaskArchiveSyncConfig(
            True,
            tasks,
            "archive",
            "receiver.example.test",
            22,
            identity,
            known_hosts,
        )
    identity.chmod(0o600)
    alias = tmp_path / "tasks-alias"
    alias.symlink_to(tasks, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink"):
        TaskArchiveSyncConfig(
            True,
            alias,
            "archive",
            "receiver.example.test",
            22,
            identity,
            known_hosts,
        )


def test_additive_health_claim_and_finish(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.db")
    store.set_task_archive_sync_enabled(True)
    assert store.claim_task_archive_sync_cycle("cycle-a", require_enabled=True)
    assert not store.claim_task_archive_sync_cycle("cycle-b", require_enabled=True)
    assert store.finish_task_archive_sync_failure(
        "cycle-a", category="incomplete", exit_code=24, safe_detail="retryable"
    )
    health = store.get_task_archive_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == "incomplete"
    assert health.consecutive_failure_count == 1
    assert store.claim_task_archive_sync_cycle("cycle-c", require_enabled=True)
    assert store.finish_task_archive_sync_success("cycle-c")
    assert store.get_task_archive_sync_health().consecutive_failure_count == 0
    assert config.tasks_dir.exists()


def test_health_interrupted_reconciliation(tmp_path: Path) -> None:
    store = TaskStore(tmp_path / "state.db")
    store.set_task_archive_sync_enabled(True)
    assert store.claim_task_archive_sync_cycle("stale", require_enabled=True)
    assert store.reconcile_interrupted_task_archive_sync()
    health = store.get_task_archive_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == "interrupted"
    assert health.consecutive_failure_count == 1


def test_claim_compare_and_set_across_threads(tmp_path: Path) -> None:
    store = TaskStore(tmp_path / "state.db")
    store.set_task_archive_sync_enabled(True)
    results: list[bool] = []
    barrier = threading.Barrier(2)

    def claim(cycle: str) -> None:
        barrier.wait()
        results.append(store.claim_task_archive_sync_cycle(cycle, require_enabled=True))

    threads = [threading.Thread(target=claim, args=(f"cycle-{i}",)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [False, True]


def test_argv_is_relative_restricted_and_nanosecond_aware(tmp_path: Path) -> None:
    argv = build_rsync_argv(_config(tmp_path))
    assert argv[0] == "rsync"
    assert "--recursive" in argv
    assert "--times" in argv
    assert "--protect-args" in argv
    assert "--modify-window=-1" in argv
    assert argv[-1] == "archive@receiver.example.test::steward-tasks"
    assert argv[-2].endswith("/tasks/")
    assert not any("delete" in token or "inplace" in token for token in argv)
    assert "ClearAllForwardings=yes" in argv[argv.index("--rsh") + 1]
    assert " -n " not in f" {argv[argv.index('--rsh') + 1]} "


def test_forced_receiver_rejects_escape_deletion_and_shell() -> None:
    assert validate_forced_receiver_command(
        "/usr/bin/rsync --server --daemon --config=/fixed/rsyncd.conf ."
    )
    with pytest.raises(TaskArchiveSyncReceiverError):
        validate_forced_receiver_command(
            "/usr/bin/rsync --server --daemon --config=/other.conf ."
        )
    with pytest.raises(TaskArchiveSyncReceiverError):
        validate_forced_receiver_command(
            "/usr/bin/rsync --server --daemon --config=/fixed/rsyncd.conf /fixed"
        )
    with pytest.raises(TaskArchiveSyncReceiverError):
        validate_forced_receiver_command("sh -c 'rsync --server ./ '")


def test_fake_key_line_has_no_generated_material(tmp_path: Path) -> None:
    line = build_forced_receiver_authorized_key(
        "ssh-ed25519 AAAA-fake receiver", tmp_path / "fixed" / "steward-tasks"
    )
    assert line.startswith("restrict,command=\"")
    assert "--server --daemon --config=/fixed/rsyncd.conf ." in line
    assert "AAAA-fake" in line


def test_fixed_receiver_config_and_harness_are_daemon_scoped(tmp_path: Path) -> None:
    root = tmp_path / "receiver"
    root.mkdir()
    config = build_receiver_rsyncd_config(root)
    assert "[steward-tasks]" in config
    assert f"path = {root}" in config
    assert "refuse options" in config
    harness = FakeTaskArchiveReceiver(root)
    assert harness.accept_command(harness.forced_command)[1:3] == (
        "--server",
        "--daemon",
    )
    assert harness.accept_upload("steward-tasks") == root
    with pytest.raises(TaskArchiveSyncReceiverError):
        harness.accept_upload("other-module")
    with pytest.raises(TaskArchiveSyncReceiverError):
        harness.accept_upload("steward-tasks", "../outside")
    with pytest.raises(TaskArchiveSyncReceiverError):
        harness.accept_upload("steward-tasks", options=("--delete",))


def test_fake_receiver_uses_real_rsync_daemon_over_ssh(tmp_path: Path) -> None:
    required = ("/usr/sbin/sshd", "ssh-keygen", "ssh-keyscan", "rsync")
    if any(shutil.which(item) is None for item in required):
        pytest.skip("OpenSSH and rsync are required for the daemon protocol fixture")
    source = tmp_path / "source"
    receiver = tmp_path / "receiver"
    source.mkdir()
    receiver.mkdir()
    (source / "visible.txt").write_text("payload\n", encoding="utf-8")
    (source / ".hidden").write_text("private\n", encoding="utf-8")
    (source / "link").symlink_to(source / "visible.txt")
    os.mkfifo(source / "pipe")
    identity = tmp_path / "identity"
    host_key = tmp_path / "host-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(identity)],
        check=True,
    )
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
        check=True,
    )
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    daemon_config = tmp_path / "rsyncd.conf"
    daemon_config.write_text(
        build_receiver_rsyncd_config(receiver), encoding="utf-8"
    )
    public_key = Path(f"{identity}.pub").read_text(encoding="utf-8").strip()
    authorized_keys = tmp_path / "authorized_keys"
    forced = f"/usr/bin/rsync --server --daemon --config={daemon_config} ."
    authorized_keys.write_text(
        f'restrict,command="{forced}" {public_key}\n', encoding="utf-8"
    )
    authorized_keys.chmod(0o600)
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text(
        "\n".join(
            [
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
            ]
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
        known_hosts = tmp_path / "known_hosts"
        scan = None
        for _ in range(60):
            time.sleep(0.05)
            scan = subprocess.run(
                [
                    "ssh-keyscan",
                    "-T",
                    "1",
                    "-p",
                    str(port),
                    "127.0.0.1",
                ],
                capture_output=True,
                text=True,
            )
            if scan.returncode == 0 and scan.stdout:
                break
        assert scan is not None and scan.stdout
        known_hosts.write_text(scan.stdout, encoding="utf-8")
        known_hosts.chmod(0o600)
        config = TaskArchiveSyncConfig(
            enabled=True,
            tasks_dir=source,
            remote_user=getpass.getuser(),
            remote_host="127.0.0.1",
            remote_port=port,
            identity_path=identity,
            known_hosts_path=known_hosts,
            transfer_timeout_seconds=20,
        )
        result = TaskArchiveSynchronizer(
            config, TaskStore(tmp_path / "state.sqlite")
        ).run_once()
        assert result.success
        assert (receiver / "visible.txt").read_text(encoding="utf-8") == "payload\n"
        assert not (receiver / ".hidden").exists()
        assert not (receiver / "link").exists()
        assert not (receiver / "pipe").exists()
    finally:
        daemon.terminate()
        daemon.wait(timeout=5)


def test_mixed_source_tree_is_valid_and_root_symlink_is_rejected(tmp_path: Path) -> None:
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    (tasks / "visible.jsonl").write_text("{}\n", encoding="utf-8")
    (tasks / ".temporary").write_text("private\n", encoding="utf-8")
    (tasks / "link").symlink_to(tasks / "visible.jsonl")
    validate_source_tree(tasks)
    os.mkfifo(tasks / "pipe")
    validate_source_tree(tasks)
    alias = tmp_path / "tasks-alias"
    alias.symlink_to(tasks, target_is_directory=True)
    with pytest.raises(Exception, match="directory"):
        validate_source_tree(alias)


def test_run_once_success_exit24_and_bounded_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.db")
    calls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr=b"private key should not persist")

    synchronizer = TaskArchiveSynchronizer(config, store, runner=run)
    result = synchronizer.run_once()
    assert result.success
    assert len(calls) == 1
    assert store.get_task_archive_sync_health().last_detail == "rsync completed"
    assert "private key" not in str(store.get_task_archive_sync_health())

    result = TaskArchiveSynchronizer(
        config,
        store,
        runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=24, stderr=b"race"),
    ).run_once()
    assert result.category == TaskArchiveSyncCategory.incomplete
    assert result.retryable


def test_run_once_busy_does_not_start_process(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.db")
    assert store.set_task_archive_sync_enabled(True)
    assert store.claim_task_archive_sync_cycle("already-running", require_enabled=True)
    called = False

    def run(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    result = TaskArchiveSynchronizer(config, store, runner=run).run_once()
    assert result.busy
    assert not called


@pytest.mark.parametrize(
    ("returncode", "stderr", "category"),
    [
        (30, b"timeout", TaskArchiveSyncCategory.timeout),
        (255, b"Permission denied (publickey)", TaskArchiveSyncCategory.ssh_auth),
        (23, b"No space left on device", TaskArchiveSyncCategory.remote_space),
        (12, b"receiver policy forbidden", TaskArchiveSyncCategory.receiver_policy),
    ],
)
def test_failure_categories_are_stable(
    returncode: int, stderr: bytes, category: str
) -> None:
    result = classify_rsync_result(returncode, stderr=stderr)
    assert result.category == category
    assert len(result.safe_detail) < 256


def test_exit_255_requires_authentication_evidence() -> None:
    assert classify_rsync_result(
        255, stderr=b"Permission denied (publickey)."
    ).category == TaskArchiveSyncCategory.ssh_auth
    for detail in (
        b"ssh: connect to host receiver port 22: Connection refused",
        b"ssh: Could not resolve hostname receiver: Name or service not known",
        b"ssh: connect to host receiver: No route to host",
        b"ssh: connection closed by remote host",
    ):
        assert classify_rsync_result(255, stderr=detail).category == TaskArchiveSyncCategory.transport

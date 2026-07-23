from __future__ import annotations

import getpass
import os
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

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
    validate_rsync_argv,
    validate_source_tree,
)
from coquic_steward.task_archive_sync_config import TaskArchiveSyncConfig


def _config(tmp_path: Path, *, enabled: bool = True) -> TaskArchiveSyncConfig:
    tasks = tmp_path / "tasks"
    tasks.mkdir(parents=True)
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


class _ProtocolReceiver:
    def __init__(
        self,
        config: TaskArchiveSyncConfig,
        source: Path,
        receiver: Path,
    ) -> None:
        self.config = config
        self.source = source
        self.receiver = receiver

    def run(
        self,
        *options: str,
        destination: str | None = None,
        source: Path | None = None,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        argv = build_rsync_argv(self.config)
        if source is not None:
            argv[-2] = f"{source}/" if source.is_dir() else str(source)
        if destination is not None:
            argv[-1] = destination
        argv[-2:-2] = options
        return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


@contextmanager
def _actual_receiver(tmp_path: Path) -> Iterator[_ProtocolReceiver]:
    required = ("/usr/sbin/sshd", "ssh-keygen", "ssh-keyscan", "rsync")
    if any(shutil.which(item) is None for item in required):
        pytest.skip("OpenSSH and rsync are required for the daemon protocol fixture")
    source = tmp_path / "source"
    receiver = tmp_path / "receiver"
    source.mkdir()
    receiver.mkdir()
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
    daemon_config.write_text(build_receiver_rsyncd_config(receiver), encoding="utf-8")
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
        yield _ProtocolReceiver(config, source, receiver)
    finally:
        daemon.terminate()
        daemon.wait(timeout=5)


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
    assert line.startswith('restrict,command="')
    assert "--server --daemon --config=/fixed/rsyncd.conf ." in line
    assert "AAAA-fake" in line


def test_fixed_receiver_config_and_harness_are_daemon_scoped(tmp_path: Path) -> None:
    root = tmp_path / "receiver"
    root.mkdir()
    config = build_receiver_rsyncd_config(root)
    assert "[steward-tasks]" in config
    assert f"path = {root}" in config
    refusal = next(
        line for line in config.splitlines() if line.startswith("refuse options")
    )
    assert "," not in refusal
    for option in ("delete", "remove-source-files", "inplace", "append"):
        assert option in refusal.split()
    assert 'pre-xfer exec = /usr/bin/test "$RSYNC_REQUEST" = "steward-tasks/"' in config
    assert [line for line in config.splitlines() if line.startswith("exclude =")] == [
        "exclude = .* .*/ ~*",
        "exclude = .* .*/ ~*",
    ]
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
    with _actual_receiver(tmp_path) as protocol:
        (protocol.source / "visible.txt").write_text("payload\n", encoding="utf-8")
        (protocol.source / ".hidden").write_text("private\n", encoding="utf-8")
        (protocol.source / "link").symlink_to(protocol.source / "visible.txt")
        os.mkfifo(protocol.source / "pipe")
        result = TaskArchiveSynchronizer(
            protocol.config, TaskStore(tmp_path / "state.sqlite")
        ).run_once()
        assert result.success
        assert (protocol.receiver / "visible.txt").read_text(
            encoding="utf-8"
        ) == "payload\n"
        assert not (protocol.receiver / ".hidden").exists()
        assert not (protocol.receiver / "link").exists()
        assert not (protocol.receiver / "pipe").exists()


def test_receiver_protocol_refuses_hidden_entries_without_sender_filters(
    tmp_path: Path,
) -> None:
    with _actual_receiver(tmp_path) as protocol:
        (protocol.source / "visible").write_text("public\n", encoding="utf-8")
        (protocol.source / ".dot-secret").write_text("private\n", encoding="utf-8")
        (protocol.source / "~tilde-secret").write_text("private\n", encoding="utf-8")
        nested = protocol.source / "nested"
        nested.mkdir()
        (nested / ".dot-secret").write_text("private\n", encoding="utf-8")
        (nested / "~tilde-secret").write_text("private\n", encoding="utf-8")

        argv = [
            token
            for token in build_rsync_argv(protocol.config)
            if not token.startswith("--exclude=")
        ]
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False)

        assert result.returncode == 23, result.stderr
        assert (protocol.receiver / "visible").read_text(encoding="utf-8") == "public\n"
        assert not (protocol.receiver / ".dot-secret").exists()
        assert not (protocol.receiver / "~tilde-secret").exists()
        assert not (protocol.receiver / "nested" / ".dot-secret").exists()
        assert not (protocol.receiver / "nested" / "~tilde-secret").exists()


def test_sender_copy_links_is_invisible_to_receiver_policy(tmp_path: Path) -> None:
    """A sender-only dereference arrives as an ordinary regular file."""

    with _actual_receiver(tmp_path) as protocol:
        target = protocol.source / "target.txt"
        target.write_text("target\n", encoding="utf-8")
        link = protocol.source / "dereferenced.txt"
        link.symlink_to(target)

        result = protocol.run("--copy-links")

        assert result.returncode == 0, result.stderr
        copied = protocol.receiver / link.name
        assert copied.is_file()
        assert not copied.is_symlink()
        assert copied.read_text(encoding="utf-8") == "target\n"


def test_receiver_protocol_refuses_dangerous_options(tmp_path: Path) -> None:
    with _actual_receiver(tmp_path) as protocol:
        (protocol.source / "visible").write_text("source", encoding="utf-8")
        (protocol.receiver / "obsolete").write_text("retain", encoding="utf-8")
        refused_options = (
            "--delete",
            "--delete-excluded",
            "--delete-delay",
            "--delete-before",
            "--delete-during",
            "--delete-after",
            "--remove-source-files",
            "--inplace",
            "--append",
            "--append-verify",
            "--partial",
            "--partial-dir=.partial",
            "--delay-updates",
            "--links",
            "--hard-links",
            "--specials",
            "--owner",
            "--group",
            "--perms",
            "--acls",
            "--xattrs",
        )
        failures: dict[str, tuple[int, bytes]] = {}
        for option in refused_options:
            result = protocol.run("--dry-run", option)
            if result.returncode == 0:
                failures[option] = (result.returncode, result.stderr)
        assert not failures
        device = protocol.source / "device"
        subprocess.run(["sudo", "-n", "mknod", str(device), "c", "1", "3"], check=True)
        device_result = protocol.run("--dry-run", "--devices")
        assert device_result.returncode != 0
        assert (protocol.receiver / "obsolete").read_text(encoding="utf-8") == "retain"
        assert (protocol.source / "visible").exists()


def test_client_rejects_sender_only_link_and_device_modes(tmp_path: Path) -> None:
    argv = build_rsync_argv(_config(tmp_path))
    for option in ("--copy-links", "-L", "--devices", "-D"):
        unsafe = [*argv[:-2], option, *argv[-2:]]
        with pytest.raises(TaskArchiveSyncReceiverError, match="forbidden option"):
            validate_rsync_argv(unsafe)


def test_receiver_protocol_accepts_only_module_root(tmp_path: Path) -> None:
    with _actual_receiver(tmp_path) as protocol:
        (protocol.source / "visible").write_text("source", encoding="utf-8")
        root_result = protocol.run("--dry-run")
        assert root_result.returncode == 0, root_result.stderr
        base_destination = build_rsync_argv(protocol.config)[-1]
        for destination in (
            f"{base_destination}/nested",
            f"{base_destination}/../escape",
            f"{base_destination}//absolute",
        ):
            result = protocol.run("--dry-run", destination=destination)
            assert result.returncode != 0, destination
            assert b"pre-xfer" in result.stderr.lower(), (destination, result.stderr)
        other_module = base_destination.rsplit("::", 1)[0] + "::other-module"
        result = protocol.run("--dry-run", destination=other_module)
        assert result.returncode != 0


def test_mixed_source_tree_is_valid_and_root_symlink_is_rejected(
    tmp_path: Path,
) -> None:
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
    assert (
        classify_rsync_result(255, stderr=b"Permission denied (publickey).").category
        == TaskArchiveSyncCategory.ssh_auth
    )
    for detail in (
        b"ssh: connect to host receiver port 22: Connection refused",
        b"ssh: Could not resolve hostname receiver: Name or service not known",
        b"ssh: connect to host receiver: No route to host",
        b"ssh: connection closed by remote host",
    ):
        assert (
            classify_rsync_result(255, stderr=detail).category
            == TaskArchiveSyncCategory.transport
        )


def test_run_once_timeout_cancel_exception_and_raw_output_secrecy(
    tmp_path: Path,
) -> None:
    private = "private-key-material archive-canary"

    timeout_config = _config(tmp_path / "timeout")
    timeout_store = TaskStore(tmp_path / "timeout.sqlite")

    def time_out(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(argv, 1, stderr=private.encode())

    timeout_result = TaskArchiveSynchronizer(
        timeout_config, timeout_store, runner=time_out
    ).run_once()
    assert timeout_result.category == TaskArchiveSyncCategory.timeout
    assert timeout_store.get_task_archive_sync_health().active_cycle_id is None
    assert private not in str(timeout_store.get_task_archive_sync_health())

    cancel_config = _config(tmp_path / "cancel")
    cancel_store = TaskStore(tmp_path / "cancel.sqlite")
    cancel_result = TaskArchiveSynchronizer(
        cancel_config,
        cancel_store,
        runner=lambda _argv: pytest.fail("cancelled cycle launched rsync"),
        cancellation=lambda: True,
    ).run_once()
    assert cancel_result.category == TaskArchiveSyncCategory.cancelled
    assert cancel_store.get_task_archive_sync_health().active_cycle_id is None

    exception_config = _config(tmp_path / "exception")
    exception_store = TaskStore(tmp_path / "exception.sqlite")

    def fail_privately(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        raise RuntimeError(private)

    exception_result = TaskArchiveSynchronizer(
        exception_config, exception_store, runner=fail_privately
    ).run_once()
    assert exception_result.category == TaskArchiveSyncCategory.unknown
    assert private not in str(exception_store.get_task_archive_sync_health())

    source_config = _config(tmp_path / "source")
    source_config.tasks_dir.rmdir()
    source_result = TaskArchiveSynchronizer(
        source_config,
        TaskStore(tmp_path / "source.sqlite"),
        runner=lambda _argv: pytest.fail("invalid source launched rsync"),
    ).run_once()
    assert source_result.category == TaskArchiveSyncCategory.source_invariant

    disabled_result = TaskArchiveSynchronizer(
        _config(tmp_path / "disabled", enabled=False),
        TaskStore(tmp_path / "disabled.sqlite"),
        runner=lambda _argv: pytest.fail("disabled cycle launched rsync"),
    ).run_once()
    assert disabled_result.category == TaskArchiveSyncCategory.disabled


def test_run_once_cancels_active_subprocess_and_finalizes_health(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    cancel_event = threading.Event()
    entered = threading.Event()
    terminated = threading.Event()
    results: list[object] = []

    class BlockingProcess:
        returncode: int | None = None

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            entered.set()
            if not terminated.wait(timeout):
                raise subprocess.TimeoutExpired("rsync", timeout)
            self.returncode = -15
            return b"", b"private cancellation output"

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            terminated.set()

        def kill(self) -> None:
            terminated.set()

    def start_process(_argv: list[str], **_kwargs: object) -> BlockingProcess:
        return BlockingProcess()

    worker = threading.Thread(
        target=lambda: results.append(
            TaskArchiveSynchronizer(
                config,
                store,
                runner=start_process,
                cancel_event=cancel_event,
            ).run_once()
        )
    )
    worker.start()
    assert entered.wait(timeout=5)
    cancel_event.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert terminated.is_set()
    assert len(results) == 1
    result = results[0]
    assert result.category == TaskArchiveSyncCategory.cancelled
    assert not result.success
    health = store.get_task_archive_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == TaskArchiveSyncCategory.cancelled
    assert "private" not in str(health)


@pytest.mark.parametrize(
    ("exception_type", "exception_args"),
    [(KeyboardInterrupt, ()), (SystemExit, (7,))],
)
def test_run_once_interruptions_finalize_health_and_reraise(
    tmp_path: Path,
    exception_type: type[BaseException],
    exception_args: tuple[object, ...],
) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    interruption = exception_type(*exception_args)
    calls = 0

    def interrupt(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        raise interruption

    with pytest.raises(exception_type) as raised:
        TaskArchiveSynchronizer(config, store, runner=interrupt).run_once()
    assert raised.value is interruption
    health = store.get_task_archive_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == TaskArchiveSyncCategory.interrupted
    assert health.last_finished_at is not None
    assert health.consecutive_failure_count == 1

    followup = TaskArchiveSynchronizer(
        config,
        store,
        runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stderr=b""),
    ).run_once()
    assert followup.success
    assert calls == 1


def test_run_once_interrupt_stops_live_child_before_releasing_health(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('ready', flush=True); time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert child.stdout is not None
    assert child.stdout.readline() == b"ready\n"

    class InterruptingProcess:
        def __init__(self, process: subprocess.Popen[bytes]) -> None:
            self.process = process
            self.interrupted = False

        @property
        def returncode(self) -> int | None:
            return self.process.returncode

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            return self.process.communicate(timeout=timeout)

        def poll(self) -> int | None:
            return self.process.poll()

        def terminate(self) -> None:
            self.process.terminate()

        def kill(self) -> None:
            self.process.kill()

    process = InterruptingProcess(child)
    try:
        with pytest.raises(KeyboardInterrupt):
            TaskArchiveSynchronizer(
                config,
                store,
                runner=lambda _argv, **_kwargs: process,
            ).run_once()

        assert child.poll() is not None
        health = store.get_task_archive_sync_health()
        assert health.active_cycle_id is None
        assert health.last_category == TaskArchiveSyncCategory.interrupted

        followup = TaskArchiveSynchronizer(
            config,
            store,
            runner=lambda _argv, **_kwargs: (
                pytest.fail("follow-up overlapped the interrupted child")
                if child.poll() is None
                else SimpleNamespace(returncode=0, stderr=b"")
            ),
        ).run_once()
        assert followup.success
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)


@pytest.mark.parametrize(
    ("returncode", "stderr", "category"),
    [
        (0, b"", TaskArchiveSyncCategory.success),
        (24, b"vanished", TaskArchiveSyncCategory.incomplete),
        (30, b"", TaskArchiveSyncCategory.timeout),
        (255, b"Permission denied (publickey)", TaskArchiveSyncCategory.ssh_auth),
        (
            255,
            b"REMOTE HOST IDENTIFICATION HAS CHANGED",
            TaskArchiveSyncCategory.host_key,
        ),
        (
            23,
            b"Permission denied writing destination",
            TaskArchiveSyncCategory.permission,
        ),
        (12, b"receiver policy forbidden", TaskArchiveSyncCategory.receiver_policy),
        (23, b"No space left on device", TaskArchiveSyncCategory.remote_space),
        (255, b"Connection refused", TaskArchiveSyncCategory.transport),
        (99, b"opaque failure private-canary", TaskArchiveSyncCategory.unknown),
    ],
)
def test_classify_all_stable_rsync_outcomes(
    returncode: int, stderr: bytes, category: str
) -> None:
    classification = classify_rsync_result(returncode, stderr=stderr)
    assert classification.category == category
    assert "private-canary" not in classification.safe_detail


def test_run_once_overlap_coalesces_without_blocking(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = TaskStore(tmp_path / "state.sqlite")
    entered = threading.Event()
    release = threading.Event()
    calls = 0
    first_results: list[object] = []

    def blocking_runner(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(timeout=5)
        return SimpleNamespace(returncode=0, stderr=b"")

    first = threading.Thread(
        target=lambda: first_results.append(
            TaskArchiveSynchronizer(config, store, runner=blocking_runner).run_once()
        )
    )
    first.start()
    assert entered.wait(timeout=5)
    started = time.monotonic()
    coalesced = TaskArchiveSynchronizer(
        config,
        store,
        runner=lambda _argv: pytest.fail("coalesced cycle launched rsync"),
    ).run_once()
    elapsed = time.monotonic() - started
    assert coalesced.category == TaskArchiveSyncCategory.busy
    assert elapsed < 1
    assert calls == 1
    release.set()
    first.join(timeout=5)
    assert not first.is_alive()
    assert first_results and first_results[0].success


@pytest.mark.parametrize("manifest_first", [True, False])
def test_terminal_manifest_order_converges_with_fake_receiver(
    tmp_path: Path, manifest_first: bool
) -> None:
    config = _config(tmp_path)
    task = config.tasks_dir / "2026-07" / "task-1"
    task.mkdir(parents=True)
    expected = {
        Path("2026-07/task-1/events.jsonl"): b'{"event":1}\n',
        Path("2026-07/task-1/metadata.json"): b'{"state":"done"}\n',
        Path("2026-07/task-1/manifest.json"): b'{"terminal":true}\n',
    }
    for relative, content in expected.items():
        (config.tasks_dir / relative).write_bytes(content)
    receiver = tmp_path / "fake-receiver"
    receiver.mkdir()
    manifest = Path("2026-07/task-1/manifest.json")
    order = sorted(expected, key=lambda path: (path != manifest) == manifest_first)

    def copy_in_receiver_order(_argv: list[str], **_kwargs: object) -> SimpleNamespace:
        for relative in order:
            destination = receiver / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(config.tasks_dir / relative, destination)
        return SimpleNamespace(returncode=0, stderr=b"")

    result = TaskArchiveSynchronizer(
        config,
        TaskStore(tmp_path / "state.sqlite"),
        runner=copy_in_receiver_order,
    ).run_once()
    assert result.success
    assert {path: (receiver / path).read_bytes() for path in expected} == expected


def test_direct_live_replacement_monotonic_storage_and_private_boundaries(
    tmp_path: Path,
) -> None:
    with _actual_receiver(tmp_path) as protocol:
        task = protocol.source / "2026-07" / "task-1"
        task.mkdir(parents=True)
        manifest = task / "manifest.json"
        events = task / "events.jsonl"
        metadata = task / "metadata.json"
        manifest.write_bytes(b'{"terminal":true}\n')
        (task / ".temporary").write_text("hidden", encoding="utf-8")
        (task / "~draft").write_text("hidden", encoding="utf-8")
        private = tmp_path / "private-canary"
        private.write_text("must-not-transfer", encoding="utf-8")
        (task / "private-link").symlink_to(private)
        fifo = task / "stream.fifo"
        os.mkfifo(fifo)
        unix_socket = socket.socket(socket.AF_UNIX)
        socket_path = protocol.source / "stream.sock"
        unix_socket.bind(str(socket_path))
        device = task / "device"
        try:
            os.mknod(device, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        except PermissionError:
            device = None
        (protocol.receiver / "retained-history").write_text("old", encoding="utf-8")
        store = TaskStore(tmp_path / "state.sqlite")
        synchronizer = TaskArchiveSynchronizer(protocol.config, store)
        try:
            assert synchronizer.run_once().success
            remote_task = protocol.receiver / "2026-07" / "task-1"
            assert (remote_task / "manifest.json").read_bytes() == manifest.read_bytes()
            assert not (remote_task / "events.jsonl").exists()

            events.write_bytes(b'{"event":1}\n')
            metadata.write_bytes(b"AAAA")
            assert synchronizer.run_once().success
            first_mtime = metadata.stat().st_mtime_ns
            events.write_bytes(events.read_bytes() + b'{"event":2}\n')
            metadata.write_bytes(b"BBBB")
            os.utime(metadata, ns=(first_mtime + 1, first_mtime + 1))
            assert synchronizer.run_once().success
            source_snapshot = {
                path.relative_to(protocol.source): path.lstat().st_mode
                for path in protocol.source.rglob("*")
            }
            assert synchronizer.run_once().success

            assert (remote_task / "events.jsonl").read_bytes() == events.read_bytes()
            assert (remote_task / "metadata.json").read_bytes() == b"BBBB"
            assert (protocol.receiver / "retained-history").read_text() == "old"
            for excluded in (
                ".temporary",
                "~draft",
                "private-link",
                "stream.fifo",
            ):
                assert not (remote_task / excluded).exists()
            assert not (protocol.receiver / socket_path.name).exists()
            if device is not None:
                assert not (remote_task / device.name).exists()
            assert not (protocol.receiver / private.name).exists()
            assert source_snapshot == {
                path.relative_to(protocol.source): path.lstat().st_mode
                for path in protocol.source.rglob("*")
            }
            assert not any(
                (protocol.source / name).exists()
                for name in ("raw-dataset", "current", "revision", "stage", "cache")
            )
        finally:
            unix_socket.close()


def test_interrupted_transfer_retry_and_receiver_temporary_storage_bound(
    tmp_path: Path,
) -> None:
    with _actual_receiver(tmp_path) as protocol:
        payload = b"x" * (8 * 1024 * 1024)
        large = protocol.source / "large.bin"
        large.write_bytes(payload)
        (protocol.receiver / large.name).write_bytes(b"old")
        argv = build_rsync_argv(protocol.config)
        argv[-2:-2] = ["--bwlimit=512"]
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        largest_temporary = 0
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline:
                temporary_files = [
                    path
                    for path in protocol.receiver.rglob("*")
                    if path.is_file() and path.name != large.name
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
            assert largest_temporary > 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
        assert largest_temporary <= len(payload)
        assert (protocol.receiver / large.name).read_bytes() == b"old"
        assert not any(path.is_dir() for path in protocol.receiver.rglob(".partial"))

        retry = TaskArchiveSynchronizer(
            protocol.config, TaskStore(tmp_path / "state.sqlite")
        ).run_once()
        assert retry.success
        assert (protocol.receiver / large.name).read_bytes() == payload


def test_enospc_is_stable_storage_failure_without_cleanup(tmp_path: Path) -> None:
    config = _config(tmp_path)
    retained = tmp_path / "remote-retained"
    retained.write_text("history", encoding="utf-8")
    store = TaskStore(tmp_path / "state.sqlite")
    result = TaskArchiveSynchronizer(
        config,
        store,
        runner=lambda _argv, **_kwargs: SimpleNamespace(
            returncode=23,
            stderr=b"write failed: No space left on device (28) private-canary",
        ),
    ).run_once()
    assert result.category == TaskArchiveSyncCategory.remote_space
    assert not result.success
    assert retained.read_text(encoding="utf-8") == "history"
    health = store.get_task_archive_sync_health()
    assert health.active_cycle_id is None
    assert health.last_category == TaskArchiveSyncCategory.remote_space
    assert "private-canary" not in str(health)

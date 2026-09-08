"""The sole Docker command boundary for task execution.

Only this module is allowed to construct Docker argv.  The default client uses
the Docker CLI so tests can substitute a recording fake without a Docker SDK.
"""

from __future__ import annotations

import fcntl
import inspect
import json
import os
import re
import secrets
import signal
import stat
import sys
import subprocess  # nosec B404 - explicit argv, shell=False below
import time
from collections.abc import Callable
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..core.config import StewardConfig
from ..core.models import TaskRecord
from ..core.subprocesses import (
    _communicate_bounded,
    _validate_capture_limit,
    current_subprocess_owner,
    use_subprocess_owner,
)
from .container_config import (
    ContainerMount,
    PlannerContainerConfig,
    TaskContainerConfig,
    TaskRole,
    ValidationContainerConfig,
)


_DOCKER_ID = re.compile(r"^[0-9a-f]{12,64}$")
# Allow Docker to acknowledge forced exit after the container grace period.
_DOCKER_STOP_ACK_SECONDS = 2


class ContainerErrorCategory(StrEnum):
    not_found = "not-found"
    runtime_unavailable = "runtime-unavailable"
    identity_mismatch = "identity-mismatch"
    timeout = "timeout"
    ambiguous = "ambiguous"
    invalid = "invalid"
    rejected = "rejected"


class ContainerBoundaryError(RuntimeError):
    def __init__(self, category: ContainerErrorCategory, message: str):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class ContainerInspection:
    container_id: str
    name: str
    state: str
    running: bool
    labels: dict[str, str]
    image: str | None = None
    image_digest: str | None = None
    pid: int | None = None
    raw: Any = None


@dataclass(frozen=True)
class ExecIdentity:
    container_id: str
    exec_id: str
    pid: int | None = None
    uid: int | None = None


@dataclass(frozen=True)
class ExecResult:
    identity: ExecIdentity
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""


class SubprocessDockerClient:
    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin

    def run(
        self,
        argv: list[str],
        *,
        input: bytes | None = None,
        timeout: float | None = None,
        max_output_bytes: int | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        _validate_capture_limit(max_output_bytes)
        owner = current_subprocess_owner()
        with owner.launch_guard() if owner is not None else nullcontext():
            process = subprocess.Popen(  # nosec B603 - argv is validated by caller
                [self.docker_bin, *argv],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input is not None else None,
                shell=False,
                start_new_session=True,
            )
            if owner is not None:
                owner.register(process)
        try:
            stdout, stderr, timed_out = _communicate_bounded(
                process,
                input_value=input,
                timeout=timeout,
                max_output_bytes=max_output_bytes,
                text=False,
                terminate=lambda sig: _terminate_docker_group(process, sig),
                timeout_grace=2.0,
            )
            if timed_out:
                raise subprocess.TimeoutExpired(
                    [self.docker_bin, *argv],
                    timeout,
                    output=stdout,
                    stderr=stderr,
                )
        finally:
            if owner is not None:
                owner.unregister(process)
        return subprocess.CompletedProcess(
            [self.docker_bin, *argv], process.returncode, stdout, stderr
        )

    def popen(self, argv: list[str]) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(  # nosec B603 - argv is validated by caller
            [self.docker_bin, *argv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        owner = current_subprocess_owner()
        if owner is not None:
            owner.register(process)

            def unregister() -> None:
                try:
                    process.wait()
                finally:
                    owner.unregister(process)

            import threading

            threading.Thread(
                target=unregister,
                name="steward-docker-exec-reaper",
                daemon=True,
            ).start()
        return process


# The same descriptor-anchored operations run locally and in the trusted helper.
# Keep this small and stdlib-only: the locked task image lacks the publication
# reader and this release. Nonblocking opens also reject raced-in FIFOs safely.
@contextmanager
def _handoff_directory(path: Path, *, create: bool = False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("handoff path must be absolute and normalized")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _read_handoff(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> bytes | None:
    if not 0 < max_bytes <= 16 * 1024 * 1024:
        raise ValueError("invalid handoff read limit")
    with _handoff_directory(Path(path).parent) as parent:
        try:
            fd = os.open(
                Path(path).name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent,
            )
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError("handoff must be a single-link regular file")
            if before.st_size > max_bytes:
                raise ValueError("handoff exceeds read limit")
            with os.fdopen(os.dup(fd), "rb") as handle:
                data = handle.read(max_bytes + 1)
            after = os.fstat(fd)
            current = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
            if (
                len(data) > max_bytes or len(data) != after.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                    after.st_ctime_ns)
                or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ValueError("handoff changed during capture")
            return data
        finally:
            os.close(fd)


def _write_handoff(path: Path, data: bytes, *, uid: int | None = None) -> None:
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("handoff exceeds write limit")
    with _handoff_directory(Path(path).parent) as parent:
        try:
            old = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None and (not stat.S_ISREG(old.st_mode) or old.st_nlink != 1):
            raise ValueError("handoff destination must be a single-link regular file")
        temporary = ".handoff-" + secrets.token_hex(16)
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                if uid is not None:
                    os.fchown(handle.fileno(), uid, uid)
                os.fsync(handle.fileno())
            os.replace(temporary, Path(path).name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


def _provision_tree(fd: int, uid: int, gid: int, *, worktree: bool, write_gid: int | None = None) -> None:
    """Never follow links; preserve daemon ownership and executable file bits."""
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) and (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
    ):
        raise ValueError("unsafe provisioning entry")
    os.fchown(fd, uid, gid)
    # Default ACLs preserve daemon access to files atomically created by
    # workers. Scratch additionally admits the implementation role only.
    entries = [(1, 7, 0xFFFFFFFF), (2, 7, uid), (4, 7, 0xFFFFFFFF)]
    if write_gid is not None:
        entries.append((8, 7, write_gid))
    entries.extend(((16, 7, 0xFFFFFFFF), (32, 5 if worktree else 0, 0xFFFFFFFF)))
    acl = (2).to_bytes(4, "little") + b"".join(
        tag.to_bytes(2, "little") + perms.to_bytes(2, "little") + identity.to_bytes(4, "little")
        for tag, perms, identity in entries
    )
    os.setxattr(fd, "system.posix_acl_access", acl)
    if stat.S_ISDIR(info.st_mode):
        os.fchmod(fd, 0o2775 if worktree else 0o2770)
        os.setxattr(fd, "system.posix_acl_default", acl)
        for name in os.listdir(fd):
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(entry.st_mode):
                continue
            child = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=fd,
            )
            try:
                _provision_tree(child, uid, gid, worktree=worktree, write_gid=write_gid)
                if worktree and name == ".git":
                    os.fchmod(child, 0o755 if stat.S_ISDIR(entry.st_mode) else 0o644)
            finally:
                os.close(child)
    else:
        executable = bool(info.st_mode & 0o111)
        os.fchmod(fd, (0o775 if executable else 0o664) if worktree
                  else (0o770 if executable else 0o660))


def _session_helper_main() -> None:
    operation, root, payload = sys.argv[1:]
    options = json.loads(payload)
    root = Path(root)
    if operation == "tree":
        with _handoff_directory(root) as fd:
            _provision_tree(fd, options["uid"], options["gid"], worktree=options["worktree"], write_gid=options.get("write_gid"))
        return
    home = root / options["session_id"]
    uid = options["session_uid"]
    with _handoff_directory(home) as fd:
        if operation == "provision":
            # Only daemon-authored inputs are handed over. Provider stores are
            # already owned by this session, including on exact-ID resume.
            os.fchown(fd, uid, uid)
            os.fchmod(fd, 0o700)
            try:
                os.stat("auth.json", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("auth.json is forbidden in private Codex homes")
            for name in os.listdir(fd):
                if name == "sessions":
                    with _handoff_directory(home / name) as store_fd:
                        os.fchown(store_fd, uid, uid)
                        os.fchmod(store_fd, 0o700)
                elif name == "config.toml" or name.startswith("output-schema"):
                    data = _read_handoff(home / name)
                    if data is None:
                        raise ValueError("session input disappeared")
                    _write_handoff(home / name, data, uid=uid)
        elif operation == "store":
            with _handoff_directory(home / "sessions") as store_fd:
                if not os.listdir(store_fd):
                    raise ValueError("session store is empty")
        elif operation == "read":
            data = _read_handoff(home / options["name"], max_bytes=options["max_bytes"])
            # Distinguish an absent optional file from an empty regular file.
            sys.stdout.buffer.write(b"0" if data is None else b"1" + data)
        elif operation == "write":
            data = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
            _write_handoff(home / options["name"], data, uid=uid)
        else:
            raise ValueError("unknown private session operation")


class TaskContainerRuntime:
    """Create/adopt one reusable task container and execute role processes."""

    def __init__(
        self,
        config: TaskContainerConfig,
        *,
        client: SubprocessDockerClient | None = None,
        docker_bin: str = "docker",
    ):
        self.config = config
        self.client = client or SubprocessDockerClient(docker_bin)

    @contextmanager
    def _file_helper_ledger(self):
        private = (self.config.private_root if isinstance(self.config, PlannerContainerConfig)
                   else self.config.private_sessions)
        ledger = private.parent / ".file-helper-cleanup"
        with _handoff_directory(ledger, create=True) as fd:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("helper cleanup ledger is not daemon-private")
            # ponytail: serialize short-lived filesystem helpers; shard by mount
            # root if contention becomes measurable. Cancellation never waits.
            deadline = None
            while True:
                owner = current_subprocess_owner()
                if owner is not None and owner.cancelled:
                    raise InterruptedError("private filesystem helper cancelled")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if deadline is None:
                        deadline = time.monotonic() + 120
                    if time.monotonic() >= deadline:
                        raise ContainerBoundaryError(ContainerErrorCategory.timeout, "private filesystem helper ledger is busy")
                    time.sleep(0.05)
            yield ledger, fd

    def _remove_file_helper(self, path: Path) -> bool:
        record = json.loads(_read_handoff(path, max_bytes=16384) or b"null")
        name = path.stem
        if (not re.fullmatch(r"coquic-steward-files-[0-9a-f]{32}", name)
                or not isinstance(record, dict) or record.get("name") != name):
            raise ValueError("invalid helper cleanup identity")
        identity = record.get("id")
        if identity is not None and not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise ValueError("invalid helper cleanup container ID")
        labels = {"coquic.steward.owner": "steward",
                  "coquic.steward.runtime": "session-files-v1",
                  "coquic.steward.helper": name}
        if record.get("labels") != labels:
            raise ValueError("invalid helper cleanup labels")
        target = identity or name
        with use_subprocess_owner(None):
            # Full inspect duplicates the embedded helper source in Args and
            # Config.Cmd. Project only ownership fields before bounded capture.
            inspected = self.client.run([
                "container", "inspect", "--format",
                '[{"Id":{{json .Id}},"Name":{{json .Name}},'
                '"Image":{{json .Image}},"Config":{"Labels":{{json .Config.Labels}}}}]',
                target,
            ], timeout=10, max_output_bytes=16384)
            if inspected.returncode:
                absent = inspected.stderr.strip() == (
                    f"Error response from daemon: No such container: {target}".encode()
                )
                if not absent:
                    raise RuntimeError("helper inspection failed")
                # A create request whose acknowledgement was lost may still
                # arrive. It cannot execute, but its cleanup intent must survive.
                return identity is not None
            objects = json.loads(inspected.stdout)
            if not isinstance(objects, list) or len(objects) != 1:
                raise ValueError("ambiguous helper inspection")
            found = objects[0]
            actual_id = found.get("Id", "")
            if (not re.fullmatch(r"[0-9a-f]{64}", actual_id)
                    or (identity is not None and actual_id != identity)
                    or found.get("Name") != "/" + name
                    or found.get("Image") != record.get("image_digest")
                    or any(found.get("Config", {}).get("Labels", {}).get(k) != v
                           for k, v in labels.items())):
                raise ValueError("helper cleanup ownership mismatch")
            removed = self.client.run(["rm", "--force", actual_id],
                                      timeout=10, max_output_bytes=4096)
            absent = removed.stderr.strip() == (
                f"Error response from daemon: No such container: {actual_id}".encode()
            )
            if removed.returncode and not absent:
                raise RuntimeError("helper removal failed")
            return True

    def _reconcile_file_helpers(self, ledger: Path, fd: int) -> None:
        for name in os.listdir(fd):
            if not re.fullmatch(r"coquic-steward-files-[0-9a-f]{32}\.json", name):
                continue
            if not self._remove_file_helper(ledger / name):
                raise ContainerBoundaryError(
                    ContainerErrorCategory.ambiguous, "private filesystem helper creation remains unacknowledged"
                )
            os.unlink(name, dir_fd=fd)
            os.fsync(fd)

    def reconcile_file_helpers(self) -> None:
        """Retry only daemon-journaled helper identities; never enumerate Docker."""
        with self._file_helper_ledger() as (ledger, fd):
            self._reconcile_file_helpers(ledger, fd)

    def _trusted_files(
        self, root: Path, operation: str, options: dict[str, Any],
        *, data: bytes | None = None,
    ) -> bytes:
        """Journal/create inert helper, acknowledge its ID, then attach/start.

        No credentials, network, socket, or worker code. Bind a daemon-controlled
        mount root; all descendant accesses use O_NOFOLLOW descriptors.
        """
        if "," in str(root):
            raise ValueError("invalid helper bind path")
        with _handoff_directory(root):
            pass
        source = "import os, stat, secrets, sys, json\nfrom pathlib import Path\nfrom contextlib import contextmanager\n"
        source += "\n\n".join(inspect.getsource(function) for function in (
            _handoff_directory, _read_handoff, _write_handoff,
            _provision_tree, _session_helper_main,
        ))
        source += "\n_session_helper_main()\n"
        read_only = operation in {"read", "store"}
        helper_name = "coquic-steward-files-" + secrets.token_hex(16)
        labels = {"coquic.steward.owner": "steward",
                  "coquic.steward.runtime": "session-files-v1",
                  "coquic.steward.helper": helper_name}
        argv = [
            "create", "--rm", "--name", helper_name, "--interactive", "--network", "none", "--read-only",
            "--user", "0:0", "--cap-drop", "ALL",
            "--cap-add", "DAC_OVERRIDE",
            *([] if read_only else ["--cap-add", "CHOWN", "--cap-add", "FOWNER"]),
            "--security-opt", "no-new-privileges:true", "--pids-limit", "32",
            "--memory", "256m", "--log-driver", "none",
            *[arg for key, value in labels.items() for arg in ("--label", f"{key}={value}")],
            "--mount", f"type=bind,src={root},dst=/boundary" + (",readonly" if read_only else ""),
            "--entrypoint", "python", self.config.image_digest, "-B", "-c", source,
            operation, "/boundary", json.dumps(options, sort_keys=True),
        ]
        with self._file_helper_ledger() as (ledger, fd):
            self._reconcile_file_helpers(ledger, fd)
            path = ledger / (helper_name + ".json")
            record = {"name": helper_name, "id": None, "labels": labels,
                      "image_digest": self.config.image_digest, "root": str(root)}
            _write_handoff(path, json.dumps(record, sort_keys=True).encode())
            try:
                created = self.client.run(argv, timeout=120, max_output_bytes=4096)
                identity = created.stdout.decode("ascii").strip()
                if created.returncode or not re.fullmatch(r"[0-9a-f]{64}", identity):
                    raise ContainerBoundaryError(ContainerErrorCategory.rejected, "private filesystem helper creation rejected")
                record["id"] = identity
                _write_handoff(path, json.dumps(record, sort_keys=True).encode())
                owner = current_subprocess_owner()
                if owner is not None and owner.cancelled:
                    raise InterruptedError("private filesystem helper start cancelled")
                # The client linearizes Popen against owner cancellation too.
                result = self.client.run(
                    ["start", "--attach", "--interactive", identity], input=data,
                    timeout=120, max_output_bytes=16 * 1024 * 1024 + 4096,
                )
                if result.returncode:
                    raise ContainerBoundaryError(
                        ContainerErrorCategory.rejected, "private filesystem boundary rejected handoff"
                    )
                return result.stdout
            except subprocess.TimeoutExpired as exc:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.timeout, "private filesystem helper timed out"
                ) from exc
            finally:
                # Includes BaseException cancellation. Never inherit the cancelled
                # owner and never discard an ambiguous create/removal receipt.
                try:
                    if not self._remove_file_helper(path):
                        raise RuntimeError("helper creation remains unacknowledged")
                    os.unlink(path.name, dir_fd=fd)
                    os.fsync(fd)
                except Exception as cleanup_error:
                    raise ContainerBoundaryError(
                        ContainerErrorCategory.ambiguous, "private filesystem helper cleanup is unverified"
                    ) from cleanup_error

    def provision_task_paths(self) -> None:
        """Provision worktree/scratch as host daemon owner plus exact role GID."""
        config = self.config
        if not isinstance(config, TaskContainerConfig):
            raise ValueError("planner has no task paths")
        self._trusted_files(config.worktree, "tree", {
            "uid": os.geteuid(), "gid": config.task_write_gid, "worktree": True,
        })
        if config.scratch is not None:
            self._trusted_files(config.scratch, "tree", {
                "uid": os.geteuid(), "gid": config.validation_gid, "worktree": False,
                "write_gid": config.task_write_gid,
            })

    def _session_files(
        self, operation: str, *, session_id: str, session_uid: int,
        name: str | None = None, data: bytes | None = None,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> bytes:
        self.config.environment(
            TaskRole.planner, session_uid=session_uid, session_id=session_id,
        )
        if session_uid == os.geteuid():
            raise ValueError("private session UID must differ from the daemon UID")
        if name is not None and (
            not name or Path(name).is_absolute() or ".." in Path(name).parts
            or "\x00" in name
        ):
            raise ValueError("invalid private session filename")
        if not 0 < max_bytes <= 16 * 1024 * 1024:
            raise ValueError("invalid handoff read limit")
        if data is not None and len(data) > 16 * 1024 * 1024:
            raise ValueError("handoff exceeds write limit")
        root = (self.config.private_root if isinstance(self.config, PlannerContainerConfig)
                else self.config.private_sessions)
        return self._trusted_files(root, operation, {
            "session_id": session_id, "session_uid": session_uid,
            "name": name, "max_bytes": max_bytes,
        }, data=data)

    def provision_session(self, *, session_id: str, session_uid: int) -> None:
        self._session_files("provision", session_id=session_id, session_uid=session_uid)

    def validate_session_store(self, *, session_id: str, session_uid: int) -> None:
        self._session_files("store", session_id=session_id, session_uid=session_uid)

    def read_session_file(
        self, name: str, *, session_id: str, session_uid: int,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> bytes | None:
        result = self._session_files("read", session_id=session_id,
                                     session_uid=session_uid, name=name, max_bytes=max_bytes)
        if result == b"0":
            return None
        if not result.startswith(b"1") or len(result) > max_bytes + 1:
            raise ContainerBoundaryError(ContainerErrorCategory.rejected, "invalid handoff response")
        return result[1:]

    def write_session_file(
        self, name: str, data: bytes, *, session_id: str, session_uid: int,
    ) -> None:
        self._session_files("write", session_id=session_id, session_uid=session_uid,
                            name=name, data=data)

    def create(self) -> str:
        argv = self.create_argv()
        result = self._run(argv)
        container_id = result.stdout.decode("utf-8", "replace").strip()
        if not container_id:
            raise ContainerBoundaryError(
                ContainerErrorCategory.ambiguous,
                "Docker create returned no container identity",
            )
        return container_id

    def create_argv(self) -> list[str]:
        config = self.config
        argv = [
            "create",
            "--name",
            config.container_name,
            "--init",
            "--network",
            config.network,
            "--restart",
            "no",
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            str(config.limits.pids),
            "--memory",
            str(config.limits.memory_bytes),
            "--stop-timeout",
            str(config.limits.stop_timeout_seconds),
            "--log-driver",
            "local",
            "--log-opt",
            f"max-size={config.limits.log_max_bytes}b",
            "--log-opt",
            f"max-file={config.limits.log_max_files}",
        ]
        for key in sorted(config.labels):
            argv.extend(["--label", f"{key}={config.labels[key]}"])
        # Both worktree views and the bounded scratch path are fixed at create
        # time. Kernel DAC plus the per-exec role group selects which
        # writable view a role can actually use.
        for mount in config.mounts_for(TaskRole.implementation):
            argv.extend(self._mount_argv(mount))
        # A private tmpfs is the only writable filesystem before a role exec.
        argv.extend(
            [
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=" + str(config.limits.scratch_bytes),
                "--tmpfs",
                "/run:rw,noexec,nosuid,nodev,size=16m",
            ]
        )
        argv.append(config.image_digest)
        return argv

    def adopt(self, *, expected_id: str | None = None) -> ContainerInspection:
        inspection = self.inspect()
        if expected_id is not None and inspection.container_id != expected_id:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "adopted container id does not match persisted identity",
            )
        self._validate_inspection(inspection)
        return inspection

    def start(self, container_id: str | None = None) -> None:
        identifier = container_id or self.config.container_name
        self._run(["start", identifier])

    def ensure_started(self) -> str:
        try:
            inspection = self.inspect()
        except ContainerBoundaryError as exc:
            if exc.category is not ContainerErrorCategory.not_found:
                raise
            identifier = self.create()
            self.start(identifier)
            return identifier
        self._validate_inspection(inspection)
        if not inspection.running:
            self.start(inspection.container_id)
        return inspection.container_id

    def inspect(self) -> ContainerInspection:
        result = self._run(
            [
                "inspect",
                "--format",
                "{{json .}}",
                self.config.container_name,
            ],
            allow_not_found=True,
        )
        if result.returncode != 0:
            if _not_found(result.stderr):
                raise ContainerBoundaryError(
                    ContainerErrorCategory.not_found,
                    f"task container not found: {self.config.container_name}",
                )
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )
        try:
            value = json.loads(result.stdout.decode("utf-8"))
            if isinstance(value, list):
                value = value[0]
            state = value.get("State") or {}
            config = value.get("Config") or {}
            labels = dict(config.get("Labels") or {})
            return ContainerInspection(
                container_id=str(value.get("Id") or ""),
                name=self.config.container_name,
                state=str(state.get("Status") or "unknown"),
                running=bool(state.get("Running")),
                labels={str(k): str(v) for k, v in labels.items()},
                image=str(config.get("Image")) if config.get("Image") else None,
                image_digest=labels.get("coquic.steward.image-digest"),
                pid=int(state["Pid"]) if state.get("Pid") else None,
                raw=value,
            )
        except (ValueError, KeyError, IndexError, AttributeError, json.JSONDecodeError) as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.ambiguous,
                "Docker inspect returned malformed task identity",
            ) from exc

    def exec_argv(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        interactive: bool = False,
    ) -> list[str]:
        if not command or any("\x00" in item for item in command):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "container exec command is empty or invalid",
            )
        selected = TaskRole(role)
        allowed = self.config.environment(
            selected, session_uid=session_uid, session_id=session_id
        )
        supplied = dict(env or {})
        for key, value in supplied.items():
            if key in {"CODEX_API_KEY", "HOME", "CODEX_HOME"}:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid,
                    f"caller cannot override protected environment {key}",
                )
            if "\x00" in key or "\x00" in value:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid, "invalid exec environment"
                )
            allowed[key] = value
        argv = [
            "exec",
            "--user",
            f"{session_uid}:{self._role_gid(selected, session_uid)}",
            "--workdir",
            workdir
            or (
                self.config.container_worktree_rw
                if selected.can_write_worktree
                else self.config.container_worktree_ro
            ),
        ]
        if interactive:
            argv.extend(["--interactive"])
        for key in sorted(allowed):
            argv.extend(["--env", f"{key}={allowed[key]}"])
        argv.extend([self.config.container_name, *command])
        return argv

    def _role_gid(self, role: TaskRole, session_uid: int) -> int:
        if role.can_write_worktree:
            return self.config.task_write_gid
        if role.needs_scratch:
            return self.config.validation_gid
        return session_uid

    def exec(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        timeout: float | None = None,
    ) -> ExecResult:
        argv = self.exec_argv(
            role,
            session_uid=session_uid,
            session_id=session_id,
            command=command,
            env=env,
            workdir=workdir,
        )
        result = self._run(argv, timeout=timeout)
        identity = ExecIdentity(
            self.config.container_name, _exec_id(result) or "unknown"
        )
        return ExecResult(identity, result.returncode, result.stdout, result.stderr)

    def exec_stream(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> subprocess.Popen[bytes]:
        argv = self.exec_argv(
            role,
            session_uid=session_uid,
            session_id=session_id,
            command=command,
            env=env,
            workdir=workdir,
            interactive=True,
        )
        return self.client.popen(argv)

    def signal(self, identity: ExecIdentity, sig: int | signal.Signals) -> None:
        self._validate_exec_identity(identity)
        # Docker has no portable signal-by-exec-id command. The trusted wrapper
        # records its in-container PID before replacing itself with Codex.
        self._run(
            [
                "exec",
                "--user",
                str(identity.uid),
                "--env",
                f"COQUIC_STEWARD_SIGNAL={int(sig)}",
                self.config.container_name,
                "/bin/task-entrypoint.sh",
                "signal",
                str(identity.pid),
            ]
        )

    def exec_is_live(self, identity: ExecIdentity) -> bool:
        """Probe the persisted wrapper PID without treating container liveness as enough."""

        self._validate_exec_identity(identity)
        result = self._run(
            [
                "exec",
                "--user",
                str(identity.uid),
                "--env",
                "COQUIC_STEWARD_SIGNAL=0",
                self.config.container_name,
                "/bin/task-entrypoint.sh",
                "signal",
                str(identity.pid),
            ],
            allow_not_found=True,
        )
        if result.returncode == 0:
            return True
        if _process_not_found(result.stderr):
            return False
        category = (
            ContainerErrorCategory.not_found
            if _not_found(result.stderr)
            else ContainerErrorCategory.runtime_unavailable
        )
        raise ContainerBoundaryError(category, _decode_error(result.stderr))

    def stop(
        self, container_id: str | None = None, *, timeout: float | None = None
    ) -> None:
        identifier = container_id or self.config.container_name
        grace = max(0, int(10 if timeout is None else timeout))
        result = self._run(
            ["stop", "--time", str(grace), identifier],
            allow_not_found=True,
            timeout=grace + _DOCKER_STOP_ACK_SECONDS,
        )
        if result.returncode and not _not_found(result.stderr):
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )

    def remove(self, container_id: str | None = None) -> None:
        """Remove one stopped, identity-validated task container.

        This is deliberately separate from :meth:`stop`: graceful daemon
        shutdown retains stopped containers, while terminal cleanup removes
        them only after the public archive has been sealed and verified.
        """

        identifier = container_id or self.config.container_name
        try:
            inspection = self.adopt(expected_id=container_id)
        except ContainerBoundaryError as exc:
            if exc.category is ContainerErrorCategory.not_found:
                return
            raise
        if inspection.running:
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "task container must be stopped before removal",
            )
        result = self._run(["rm", identifier], allow_not_found=True)
        if result.returncode and not _not_found(result.stderr):
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )

    def _mount_argv(self, mount: ContainerMount) -> list[str]:
        source = str(mount.source)
        if any(char in source for char in "\x00\n"):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "mount source contains control characters",
            )
        value = f"type=bind,src={source},dst={mount.target}"
        if mount.read_only:
            value += ",readonly"
        return ["--mount", value]

    def _validate_inspection(self, inspection: ContainerInspection) -> None:
        if inspection.name != self.config.container_name:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "container name does not match task identity",
            )
        expected = self.config.image_digest
        actual = inspection.image_digest
        if actual is not None and actual != expected:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "container image digest does not match locked task image",
            )
        for key, expected_value in self.config.labels.items():
            # Older persisted fake identities predate the ownership labels;
            # they are accepted for read-only tests, while any supplied value
            # is still checked exactly.
            if (
                key in {"coquic.steward.owner", "coquic.steward.restart-policy"}
                and key not in inspection.labels
            ):
                continue
            if inspection.labels.get(key) != expected_value:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.identity_mismatch,
                    f"container label mismatch: {key}",
                )

    def _validate_exec_identity(self, identity: ExecIdentity) -> None:
        if identity.container_id != self.config.container_name:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "exec identity belongs to another task container",
            )
        if (
            identity.pid is None
            or identity.pid <= 1
            or identity.uid is None
            or not 10000 <= identity.uid <= 60000
        ):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "exec identity does not contain a validated wrapper PID",
            )

    def _run(
        self,
        argv: list[str],
        *,
        input: bytes | None = None,
        timeout: float | None = None,
        allow_not_found: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            result = self.client.run(argv, input=input, timeout=timeout)
        except FileNotFoundError as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                "Docker executable is unavailable",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.timeout,
                "Docker command timed out",
            ) from exc
        if result.returncode and not allow_not_found:
            if _not_found(result.stderr):
                category = ContainerErrorCategory.not_found
            else:
                category = ContainerErrorCategory.runtime_unavailable
            raise ContainerBoundaryError(category, _decode_error(result.stderr))
        return result


class PlannerContainerRuntime(TaskContainerRuntime):
    """Reusable container with only sealed history and private planner mounts."""

    config: PlannerContainerConfig

    def __init__(
        self,
        config: PlannerContainerConfig,
        *,
        client: SubprocessDockerClient | None = None,
        docker_bin: str = "docker",
    ):
        self.config = config
        self.client = client or SubprocessDockerClient(docker_bin)

    def create_argv(self) -> list[str]:
        config = self.config
        argv = [
            "create",
            "--name",
            config.container_name,
            "--init",
            "--network",
            config.network,
            "--restart",
            "no",
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            str(config.limits.pids),
            "--memory",
            str(config.limits.memory_bytes),
            "--stop-timeout",
            str(config.limits.stop_timeout_seconds),
            "--log-driver",
            "local",
            "--log-opt",
            f"max-size={config.limits.log_max_bytes}b",
            "--log-opt",
            f"max-file={config.limits.log_max_files}",
        ]
        for key in sorted(config.labels):
            argv.extend(["--label", f"{key}={config.labels[key]}"])
        for mount in config.mounts:
            argv.extend(self._mount_argv(mount))
        argv.extend(
            [
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=" + str(config.limits.scratch_bytes),
                "--tmpfs",
                "/run:rw,noexec,nosuid,nodev,size=16m",
                config.image_digest,
            ]
        )
        return argv

    def exec_argv(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        interactive: bool = False,
    ) -> list[str]:
        if TaskRole(role) is not TaskRole.planner:
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "planner container accepts only planner executions",
            )
        if not command or any("\x00" in item for item in command):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "container exec command is empty or invalid",
            )
        allowed = self.config.environment(
            role, session_uid=session_uid, session_id=session_id
        )
        for key, value in dict(env or {}).items():
            if key in {"CODEX_API_KEY", "HOME", "CODEX_HOME"}:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid,
                    f"caller cannot override protected environment {key}",
                )
            if "\x00" in key or "\x00" in value:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid, "invalid exec environment"
                )
            allowed[key] = value
        argv = [
            "exec",
            "--user",
            f"{session_uid}:{session_uid}",
            "--workdir",
            workdir or self.config.container_history,
        ]
        if interactive:
            argv.append("--interactive")
        for key in sorted(allowed):
            argv.extend(["--env", f"{key}={allowed[key]}"])
        argv.extend([self.config.container_name, *command])
        return argv


class ValidationContainerRuntime:
    """Run canonical validation commands in a disposable isolated sibling."""

    def __init__(
        self,
        config: ValidationContainerConfig,
        *,
        client: SubprocessDockerClient | None = None,
        docker_bin: str = "docker",
    ) -> None:
        self.config = config
        self.client = client or SubprocessDockerClient(docker_bin)

    def _run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        allow_not_found: bool = False,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            result = self.client.run(argv, timeout=timeout)
        except FileNotFoundError as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                "Docker executable is unavailable",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.timeout, "Docker command timed out"
            ) from exc
        if result.returncode and not (allow_not_found or allow_failure):
            category = (
                ContainerErrorCategory.not_found
                if _not_found(result.stderr)
                else ContainerErrorCategory.runtime_unavailable
            )
            raise ContainerBoundaryError(category, _decode_error(result.stderr))
        return result

    def _mount_argv(self, mount: ContainerMount) -> list[str]:
        value = f"type=bind,src={mount.source},dst={mount.target}"
        if mount.read_only:
            value += ",readonly"
        return ["--mount", value]

    def _isolation_argv(self) -> list[str]:
        """Render the policy shared by one-shot and durable validation."""

        config = self.config
        argv = [
            "--network",
            config.network,
        ]
        if config.read_only:
            argv.append("--read-only")
        for option in config.security_options:
            argv.extend(["--security-opt", option])
        for capability in config.cap_drop:
            argv.extend(["--cap-drop", capability])
        argv.extend(
            [
                "--pids-limit",
                str(config.limits.pids),
                "--memory",
                str(config.limits.memory_bytes),
                "--user",
                f"{config.uid}:{config.gid}",
            ]
        )
        for mount in config.mounts:
            argv.extend(self._mount_argv(mount))
        for key, value in config.environment:
            argv.extend(["--env", f"{key}={value}"])
        for target, options in config.tmpfs:
            argv.extend(["--tmpfs", f"{target}:{options}"])
        return argv

    def create_argv(self) -> list[str]:
        config = self.config
        argv = [
            "create",
            "--name",
            config.container_name,
            "--init",
            *self._isolation_argv(),
            "--restart",
            "no",
            "--stop-timeout",
            str(config.limits.stop_timeout_seconds),
            "--log-driver",
            "local",
            "--log-opt",
            f"max-size={config.limits.log_max_bytes}b",
            "--log-opt",
            f"max-file={config.limits.log_max_files}",
        ]
        for key in sorted(config.labels):
            argv.extend(["--label", f"{key}={config.labels[key]}"])
        argv.extend(
            [
                "--entrypoint",
                "/bootstrap/sh",
                config.image_digest,
                "/bootstrap/validation-entrypoint.sh",
                "--idle",
            ]
        )
        return argv

    def run_argv(self, command: list[str]) -> list[str]:
        if not command or any("\x00" in value for value in command):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid, "validation command is empty or invalid"
            )
        return [
            "run",
            "--rm",
            *self._isolation_argv(),
            self.config.image_digest,
            "--exec",
            *command,
        ]

    def create(self) -> str:
        result = self._run(self.create_argv())
        identity = result.stdout.decode("utf-8", "replace").strip()
        if not identity:
            raise ContainerBoundaryError(
                ContainerErrorCategory.ambiguous,
                "Docker create returned no validation identity",
            )
        return identity

    def ensure_started(self) -> str:
        try:
            inspection = self.inspect()
        except ContainerBoundaryError as exc:
            if exc.category is not ContainerErrorCategory.not_found:
                raise
            identity = self.create()
            self._run(["start", identity])
            self._wait_ready(identity)
            return identity
        self._validate_inspection(inspection)
        if not inspection.running:
            self._run(["start", inspection.container_id])
        self._wait_ready(inspection.container_id)
        return inspection.container_id

    def _wait_ready(self, identifier: str) -> None:
        deadline = time.monotonic() + self.config.limits.timeout_seconds
        readiness = [
            "exec",
            "--user",
            f"{self.config.uid}:{self.config.gid}",
            identifier,
            "/bootstrap/sh",
            "-c",
            "test -f /tmp/coquic-validation-ready",
        ]
        while True:
            result = self._run(readiness, timeout=5, allow_failure=True)
            if result.returncode == 0:
                return
            inspection = self.inspect()
            self._validate_inspection(inspection)
            if inspection.container_id != identifier or not inspection.running:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.runtime_unavailable,
                    "validation container exited before becoming ready",
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.timeout,
                    "validation container readiness timed out",
                )
            time.sleep(min(0.1, remaining))

    def inspect(self) -> ContainerInspection:
        result = self._run(
            ["inspect", "--format", "{{json .}}", self.config.container_name],
            allow_not_found=True,
        )
        if result.returncode:
            if _not_found(result.stderr):
                raise ContainerBoundaryError(
                    ContainerErrorCategory.not_found,
                    f"validation container not found: {self.config.container_name}",
                )
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )
        try:
            value = json.loads(result.stdout.decode("utf-8"))
            if isinstance(value, list):
                value = value[0]
            state = value.get("State") or {}
            config = value.get("Config") or {}
            labels = dict(config.get("Labels") or {})
            name = str(value.get("Name") or "").removeprefix("/")
            return ContainerInspection(
                container_id=str(value.get("Id") or ""),
                name=name,
                state=str(state.get("Status") or "unknown"),
                running=bool(state.get("Running")),
                labels={str(key): str(item) for key, item in labels.items()},
                image=str(value.get("Image") or config.get("Image") or ""),
                image_digest=labels.get("coquic.steward.image-digest"),
                pid=int(state["Pid"]) if state.get("Pid") else None,
                raw=value,
            )
        except (
            IndexError,
            ValueError,
            AttributeError,
            json.JSONDecodeError,
        ) as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.ambiguous,
                "Docker inspect returned malformed validation identity",
            ) from exc

    def _validate_inspection(self, inspection: ContainerInspection) -> None:
        config = self.config
        raw = inspection.raw if isinstance(inspection.raw, dict) else {}
        host_config = raw.get("HostConfig") or {}
        container_config = raw.get("Config") or {}
        if (
            inspection.name != config.container_name
            or _DOCKER_ID.fullmatch(inspection.container_id) is None
            or inspection.image != config.image_digest
            or container_config.get("User") != f"{config.uid}:{config.gid}"
        ):
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "validation container identity or image is mismatched",
            )
        for key, expected in config.labels.items():
            if inspection.labels.get(key) != expected:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.identity_mismatch,
                    f"validation container label mismatch: {key}",
                )
        expected_mounts = {
            (str(mount.source), mount.target, not mount.read_only)
            for mount in config.mounts
        }
        actual_mounts = {
            (
                str(mount.get("Source") or ""),
                str(mount.get("Destination") or ""),
                bool(mount.get("RW")),
            )
            for mount in raw.get("Mounts") or []
            if mount.get("Type") == "bind"
        }
        security = [str(value) for value in host_config.get("SecurityOpt") or []]
        restart = str((host_config.get("RestartPolicy") or {}).get("Name") or "no")
        expected_environment = dict(config.environment)
        actual_environment: dict[str, str] = {}
        allowed_environment = {
            *config.image_environment_keys,
            *expected_environment,
        }
        for item in container_config.get("Env") or []:
            key, separator, value = str(item).partition("=")
            if not separator or key in actual_environment:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.identity_mismatch,
                    "validation container environment is malformed",
                )
            actual_environment[key] = value
        expected_tmpfs = dict(config.tmpfs)
        if (
            actual_mounts != expected_mounts
            or dict(host_config.get("Tmpfs") or {}) != expected_tmpfs
            or any(
                actual_environment.get(key) != value
                for key, value in expected_environment.items()
            )
            or set(actual_environment) != allowed_environment
            or container_config.get("Entrypoint") != ["/bootstrap/sh"]
            or container_config.get("Cmd")
            != ["/bootstrap/validation-entrypoint.sh", "--idle"]
            or container_config.get("WorkingDir") != "/validation/worktree"
            or host_config.get("NetworkMode") != config.network
            or bool(host_config.get("Privileged"))
            or host_config.get("ReadonlyRootfs") is not config.read_only
            or host_config.get("Init") is not True
            or int(host_config.get("Memory") or 0) != config.limits.memory_bytes
            or int(host_config.get("PidsLimit") or 0) != config.limits.pids
            or (host_config.get("LogConfig") or {}).get("Type") != "local"
            or (host_config.get("LogConfig") or {}).get("Config")
            != {
                "max-file": str(config.limits.log_max_files),
                "max-size": f"{config.limits.log_max_bytes}b",
            }
            or restart != "no"
            or not any(
                capability.upper()
                in [str(value).upper() for value in host_config.get("CapDrop") or []]
                for capability in config.cap_drop
            )
            or not any(
                any(value.startswith(option) for value in security)
                for option in config.security_options
            )
        ):
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "validation container isolation boundary is mismatched",
            )

    def exec_argv(
        self, command: list[str], *, workdir: str = "/validation/worktree"
    ) -> list[str]:
        if not command or any("\x00" in value for value in command):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid, "validation command is empty or invalid"
            )
        if not workdir.startswith("/validation/"):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "validation workdir is outside its boundary",
            )
        return [
            "exec",
            "--user",
            f"{self.config.uid}:{self.config.gid}",
            "--workdir",
            workdir,
            self.config.container_name,
            *command,
        ]

    def exec(
        self,
        command: list[str],
        *,
        workdir: str = "/validation/worktree",
        timeout: float | None = None,
    ) -> ExecResult:
        result = self._run(
            self.exec_argv(command, workdir=workdir),
            timeout=timeout,
            allow_failure=True,
        )
        return ExecResult(
            ExecIdentity(
                self.config.container_name,
                _exec_id(result) or "unknown",
                uid=self.config.uid,
            ),
            result.returncode,
            result.stdout,
            result.stderr,
        )

    def stop(
        self, *, identifier: str | None = None, timeout: float | None = None
    ) -> None:
        grace = max(
            0, int(self.config.limits.stop_timeout_seconds if timeout is None else timeout)
        )
        try:
            self._run(
                ["stop", "--time", str(grace), identifier or self.config.container_name],
                timeout=grace + _DOCKER_STOP_ACK_SECONDS,
            )
        except ContainerBoundaryError as exc:
            if exc.category is not ContainerErrorCategory.not_found:
                raise

    def remove(self, *, identifier: str | None = None) -> None:
        try:
            self._run(["rm", identifier or self.config.container_name])
        except ContainerBoundaryError as exc:
            if exc.category is not ContainerErrorCategory.not_found:
                raise

    def cleanup_owned(self, *, timeout: float = 5) -> None:
        """Remove only an exactly inspected validation sibling."""

        try:
            inspection = self.inspect()
        except ContainerBoundaryError as exc:
            if exc.category is ContainerErrorCategory.not_found:
                return
            raise
        self._validate_inspection(inspection)
        if inspection.running:
            self.stop(identifier=inspection.container_id, timeout=timeout)
        self.remove(identifier=inspection.container_id)


def bind_deployment_identity(
    runtime: TaskContainerRuntime,
    config: StewardConfig,
) -> TaskContainerRuntime:
    """Attach the configured Compose release identity before first use."""

    deployment = config.deployment
    if not deployment.enabled:
        return runtime
    release_id = deployment.release_id
    if release_id is None:
        raise ValueError("production container requires an exact release identity")
    epoch_id = str(config.ensure_epoch()["epochId"])
    expected = {
        "coquic.steward.epoch": epoch_id,
        "coquic.steward.release": release_id,
        "coquic.steward.deployment": deployment.compose_project,
    }
    labels = dict(runtime.config.labels)
    for key, value in expected.items():
        existing = labels.get(key)
        if existing is not None and existing != value:
            raise ValueError(f"production container has a conflicting {key} label")
        labels[key] = value
    limits = replace(
        runtime.config.limits,
        pids=deployment.max_pids,
        memory_bytes=deployment.max_memory_bytes,
        log_max_bytes=deployment.max_log_bytes,
        scratch_bytes=deployment.max_scratch_bytes,
    )
    runtime.config = replace(
        runtime.config,
        labels=labels,
        limits=limits,
        epoch_id=epoch_id,
        release_id=release_id,
    )
    return runtime


def deployment_runtime_factory(
    config: StewardConfig,
    factory: Callable[[TaskRecord], TaskContainerRuntime],
) -> Callable[[TaskRecord], TaskContainerRuntime]:
    """Decorate task runtimes with production-only deployment identity."""

    if not config.deployment.enabled:
        return factory

    def build(task: TaskRecord) -> TaskContainerRuntime:
        return bind_deployment_identity(factory(task), config)

    return build


def _not_found(value: bytes) -> bool:
    text = value.decode("utf-8", "replace").lower()
    return (
        "no such container" in text or "no such object" in text or "not found" in text
    )


def _terminate_docker_group(process: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def _process_not_found(value: bytes) -> bool:
    text = value.decode("utf-8", "replace").lower()
    return "no such process" in text


def _decode_error(value: bytes) -> str:
    return value.decode("utf-8", "replace").strip()[-2000:] or "Docker command failed"


def _exec_id(result: subprocess.CompletedProcess[bytes]) -> str | None:
    # A fake boundary may return the Docker exec identity as JSON or text.  The
    # real CLI output is intentionally not treated as a process identity.
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(value, dict) and isinstance(value.get("Id"), str):
        return value["Id"]
    return None

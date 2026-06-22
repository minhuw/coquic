from __future__ import annotations

import fcntl
import os
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from ..core.config import StewardConfig


class DaemonAlreadyRunning(RuntimeError):
    def __init__(self, lock_path: Path, owner: str = ""):
        message = f"another Steward daemon is already running for this repository: {lock_path}"
        if owner:
            message = f"{message} ({owner})"
        super().__init__(message)
        self.lock_path = lock_path
        self.owner = owner


@dataclass
class DaemonLock:
    path: Path
    handle: object | None = None

    def __enter__(self) -> DaemonLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.seek(0)
            owner = handle.read().strip()
            handle.close()
            raise DaemonAlreadyRunning(self.path, owner) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()}\n")
        handle.flush()
        self.handle = handle
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if self.handle is None:
            return
        handle = self.handle
        self.handle = None
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def acquire_daemon_lock(config: StewardConfig) -> DaemonLock:
    return DaemonLock(config.state_dir / "daemon.lock")

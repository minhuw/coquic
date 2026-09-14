"""Independent publication of the daemon's current scheduler state."""

from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..core.config import StewardConfig
from ..core.models import SchedulerStoreSnapshot, utc_now

LIVE_SNAPSHOT_TIMEOUT_SECONDS = 10.0
MAX_LIVE_SNAPSHOT_RESPONSE_BYTES = 16 * 1024
MAX_LIVE_SNAPSHOT_TOKEN_BYTES = 4096


class LiveSnapshotError(RuntimeError):
    """A bounded live-state publication failure without response details."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _read_token(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise LiveSnapshotError("credential_unavailable")
            raw = os.read(descriptor, MAX_LIVE_SNAPSHOT_TOKEN_BYTES + 1)
        finally:
            os.close(descriptor)
    except LiveSnapshotError:
        raise
    except OSError:
        raise LiveSnapshotError("credential_unavailable") from None
    if len(raw) > MAX_LIVE_SNAPSHOT_TOKEN_BYTES:
        raise LiveSnapshotError("credential_unavailable")
    try:
        token = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise LiveSnapshotError("credential_unavailable") from None
    if not token or any(character.isspace() or ord(character) < 0x20 for character in token):
        raise LiveSnapshotError("credential_unavailable")
    return token


def _counter(value: object) -> int:
    if type(value) is not int or value < 0:
        raise LiveSnapshotError("invalid_scheduler_snapshot")
    return value


def build_live_snapshot(
    config: StewardConfig | Any,
    snapshot: SchedulerStoreSnapshot,
    *,
    observed_at: datetime | None = None,
    stale_after_seconds: int,
) -> dict[str, object]:
    """Build the closed public payload from exact Store-owned facts."""

    if type(stale_after_seconds) is not int or not 30 <= stale_after_seconds <= 3600:
        raise LiveSnapshotError("invalid_stale_interval")
    observed = observed_at or utc_now()
    if observed.utcoffset() is None:
        raise LiveSnapshotError("invalid_observed_at")
    observed_text = (
        observed.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    planning_state = (
        "paused"
        if snapshot.planning_paused
        else "active"
        if snapshot.planning_active
        else "idle"
    )
    return {
        "schemaVersion": "1.0",
        "observedAt": observed_text,
        "staleAfterSeconds": stale_after_seconds,
        "daemon": {"mode": "dry-run" if config.dry_run else "production"},
        "signals": {"pending": _counter(snapshot.pending_signal_count)},
        "planning": {"state": planning_state},
        "tasks": {
            "active": _counter(snapshot.source_active),
            "queued": _counter(snapshot.source_queued),
        },
        "integration": {
            "active": _counter(snapshot.integration_active),
            "queued": _counter(snapshot.integration_queued),
        },
    }


class LiveSnapshotClient:
    def __init__(
        self,
        url: str,
        token_path: Path,
        *,
        open_request: Callable[..., Any] | None = None,
        timeout_seconds: float = LIVE_SNAPSHOT_TIMEOUT_SECONDS,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(
            timeout_seconds, (int, float)
        ) or not 0 < float(timeout_seconds) <= 15:
            raise ValueError("live snapshot timeout must be between zero and 15 seconds")
        self.url = url
        self.token_path = token_path
        self.timeout_seconds = float(timeout_seconds)
        self._open_request = open_request or build_opener(_NoRedirectHandler()).open

    def publish(self, payload: Mapping[str, object]) -> None:
        try:
            body = json.dumps(
                payload,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            request = Request(
                self.url,
                data=body,
                method="POST",
                headers={
                    "Authorization": f"Bearer {_read_token(self.token_path)}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "coquic-steward/0.1",
                },
            )
            with self._open_request(request, timeout=self.timeout_seconds) as response:
                response_body = response.read(MAX_LIVE_SNAPSHOT_RESPONSE_BYTES + 1)
                if len(response_body) > MAX_LIVE_SNAPSHOT_RESPONSE_BYTES:
                    raise LiveSnapshotError("response_too_large")
                status = int(getattr(response, "status", 0))
                if not 200 <= status < 300:
                    raise LiveSnapshotError("http_status_error")
        except LiveSnapshotError:
            raise
        except HTTPError as exc:
            try:
                exc.read(MAX_LIVE_SNAPSHOT_RESPONSE_BYTES + 1)
            except Exception:
                pass
            raise LiveSnapshotError("http_status_error") from None
        except Exception:
            raise LiveSnapshotError("request_failed") from None


class LiveSnapshotWorker:
    """One stoppable daemon thread, independent of heartbeat and archive publication."""

    def __init__(
        self,
        config: StewardConfig | Any,
        store: Any,
        client: LiveSnapshotClient | Any,
        *,
        interval_seconds: int,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.client = client
        self.interval_seconds = interval_seconds
        self.logger = logger
        self._stop = threading.Event()
        self._wakeup = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_alive:
            return
        self._stop.clear()
        self._wakeup.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="steward-live-snapshot",
            daemon=True,
        )
        self._thread.start()

    def wake(self) -> None:
        self._wakeup.set()

    def request_stop(self) -> None:
        self._stop.set()
        self._wakeup.set()

    def join(self, timeout: float | None = None) -> bool:
        thread = self._thread
        if thread is None:
            return True
        if thread is threading.current_thread():
            return False
        thread.join(timeout=timeout)
        if thread.is_alive():
            return False
        self._thread = None
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.request_stop()
        return self.join(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wakeup.clear()
            if self._stop.is_set():
                break
            try:
                snapshot = self.store.scheduler_snapshot()
                payload = build_live_snapshot(
                    self.config,
                    snapshot,
                    stale_after_seconds=min(self.interval_seconds * 3, 3600),
                )
                self.client.publish(payload)
            except Exception as exc:
                if self.logger is not None:
                    self.logger(
                        "live snapshot publication failed "
                        f"error={exc.__class__.__name__}"
                    )
            if self._stop.is_set():
                break
            self._wakeup.wait(self.interval_seconds)


__all__ = [
    "LiveSnapshotClient",
    "LiveSnapshotError",
    "LiveSnapshotWorker",
    "build_live_snapshot",
]

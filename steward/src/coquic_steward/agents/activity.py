"""Best-effort worker activity declarations.

Activity declarations are intentionally independent from Steward's lifecycle
and outcome evidence.  This module only accepts a small, agent-declared marker
grammar and records validated declarations in a private sidecar.
"""

from __future__ import annotations

import json
import os
import re
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable


ACTIVITY_SCHEMA_VERSION = 1
ACTIVITY_STAGE = "worker"
ACTIVITY_SOURCE = "agent_declared"
ACTIVITY_MARKER = "STEWARD_ACTIVITY "
ACTIVITY_MARKER_PREFIX = ACTIVITY_MARKER
ACTIVITY_VALUES = (
    "orient",
    "investigate",
    "edit",
    "self_validate",
    "self_review",
    "report",
)
ACTIVITIES = frozenset(ACTIVITY_VALUES)
ACTIVITY_MAX_SUMMARY_BYTES = 240
ACTIVITY_MAX_CAPTURE = 256
ACTIVITY_PUBLIC_MAX_EVENTS = 64
# Descriptive aliases used by callers that treat these as record limits.
ACTIVITY_MAX_RECORDS = ACTIVITY_MAX_CAPTURE
ACTIVITY_PUBLIC_LIMIT = ACTIVITY_PUBLIC_MAX_EVENTS
ACTIVITY_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ACTIVITY_RECORD_TYPES = frozenset({"header", "event", "summary"})
# Short aliases mirror the naming used by other private Steward recorders.
SCHEMA_VERSION = ACTIVITY_SCHEMA_VERSION
MAX_COMPLETED_RECORDS = ACTIVITY_MAX_CAPTURE
MAX_SUMMARY_BYTES = ACTIVITY_MAX_SUMMARY_BYTES
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

ACTIVITY_REPORTING_RULES = """Activity reporting (best effort): when your current internal activity changes, begin an agent message with exactly one standalone first line in this form:
STEWARD_ACTIVITY {\"activity\":\"investigate\",\"summary\":\"Trace closing-state packet generation\"}
Use only these activities: orient, investigate, edit, self_validate, self_review, report. The marker declares your current intent; it does not prove completion, success, validation, or review. Emit a marker only when the activity changes, and follow it with any human-readable message. Do not add outcome fields or extra JSON keys."""


def utc_timestamp(value: datetime | None = None) -> str:
    """Return a canonical UTC timestamp for private and public records."""

    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def is_safe_activity_id(value: object) -> bool:
    return isinstance(value, str) and bool(ACTIVITY_SAFE_ID_RE.fullmatch(value))


def is_safe_source_event_id(value: object) -> bool:
    return is_safe_activity_id(value)


def validate_activity_summary(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if any(unicodedata.category(character) == "Cc" for character in value):
        return None
    if len(value.encode("utf-8")) > ACTIVITY_MAX_SUMMARY_BYTES:
        return None
    return value


@dataclass(frozen=True)
class ActivityDeclaration:
    activity: str
    summary: str


def parse_activity_marker(text: object) -> ActivityDeclaration | None:
    """Parse a marker from the first line of an agent message.

    The marker must be the first line and the JSON payload must contain exactly
    ``activity`` and ``summary``.  A malformed lookalike is deliberately not
    treated as a declaration.
    """

    if not isinstance(text, str):
        return None
    lines = text.splitlines()
    first_line = lines[0] if lines else ""
    if not first_line.startswith(ACTIVITY_MARKER):
        return None
    encoded = first_line[len(ACTIVITY_MARKER) :]
    try:
        value = json.loads(encoded, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(value, dict) or set(value) != {"activity", "summary"}:
        return None
    activity = value.get("activity")
    summary = validate_activity_summary(value.get("summary"))
    if not isinstance(activity, str) or activity not in ACTIVITIES or summary is None:
        return None
    return ActivityDeclaration(activity=activity, summary=summary)


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate activity marker key")
        value[key] = item
    return value


def decode_activity_marker(text: object) -> dict[str, str] | None:
    """Dictionary-shaped compatibility helper for protocol consumers."""

    declaration = parse_activity_marker(text)
    if declaration is None:
        return None
    return {"activity": declaration.activity, "summary": declaration.summary}


def validate_activity_event(event: object) -> tuple[str, ActivityDeclaration] | None:
    """Return a safe source ID and declaration for a completed agent event."""

    if not isinstance(event, dict) or event.get("type") != "item.completed":
        return None
    item = event.get("item")
    if not isinstance(item, dict) or item.get("type") != "agent_message":
        return None
    source_event_id = item.get("id")
    if not is_safe_source_event_id(source_event_id):
        return None
    declaration = parse_activity_marker(item.get("text"))
    if declaration is None:
        return None
    return source_event_id, declaration


def parse_activity_event(event: object) -> ActivityDeclaration | None:
    decoded = validate_activity_event(event)
    return decoded[1] if decoded is not None else None


def activity_sidecar_path(transcript_path: Path) -> Path:
    return transcript_path.with_name("activities.jsonl")


class ActivityRecorder:
    """Append validated declarations and a final bounded summary.

    Recorder failures are represented as health state and never raised from
    ``observe`` or ``finalize``.  This keeps observability independent from
    Codex process and task outcomes.
    """

    def __init__(
        self,
        path: Path,
        *,
        stage: str = ACTIVITY_STAGE,
        max_events: int = ACTIVITY_MAX_CAPTURE,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.stage = stage
        self.max_events = max(0, min(int(max_events), ACTIVITY_MAX_CAPTURE))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._seen: set[str] = set()
        self._sequence = 0
        self._recorded = 0
        self._invalid = 0
        self._duplicate = 0
        self._omitted = 0
        self._truncated = False
        self._write_failed = False
        self._header_written = False
        self._finalized = False
        self._summary_written = False
        self._handle: BinaryIO | None = None
        self._io_lock = threading.Lock()
        self._abandoned = threading.Event()
        self._start_time = utc_timestamp(self._clock())
        self._open_header()

    @property
    def finalized(self) -> bool:
        return self._finalized

    @property
    def recorded(self) -> int:
        return self._recorded

    @property
    def invalid(self) -> int:
        return self._invalid

    @property
    def duplicate(self) -> int:
        return self._duplicate

    @property
    def omitted(self) -> int:
        return self._omitted

    @property
    def truncated(self) -> bool:
        return self._truncated

    @property
    def diagnostics(self) -> dict[str, object]:
        return self.diagnostics_dict()

    def _open_header(self) -> None:
        header = {
            "record_type": "header",
            "schema_version": ACTIVITY_SCHEMA_VERSION,
            "stage": self.stage,
            "capture_started_at": self._start_time,
            "source": ACTIVITY_SOURCE,
        }
        try:
            self.path.parent.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
            try:
                os.chmod(self.path.parent, PRIVATE_DIR_MODE)
            except OSError:
                pass
            flags = os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_WRONLY
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, PRIVATE_FILE_MODE)
            try:
                os.fchmod(descriptor, PRIVATE_FILE_MODE)
                if os.fstat(descriptor).st_mode & 0o777 != PRIVATE_FILE_MODE:
                    raise PermissionError("activity sidecar permissions are not private")
                self._handle = os.fdopen(descriptor, "ab")
            except Exception:
                os.close(descriptor)
                raise
            self._append_record(header)
            self._header_written = True
        except Exception:
            self._write_failed = True
            self._close_handle()

    def _append_record(self, value: dict[str, Any]) -> None:
        encoded = (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        if self._handle is None:
            raise OSError("activity sidecar is not open")
        self._handle.write(encoded)
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def _close_handle(self) -> None:
        if self._handle is None:
            return
        try:
            self._handle.close()
        except OSError:
            pass
        self._handle = None

    def observe(self, event: object) -> bool:
        """Observe one decoded transcript event; return whether it was recorded."""

        with self._io_lock:
            if self._finalized or self._write_failed or not self._header_written:
                return False
            try:
                decoded = validate_activity_event(event)
                if decoded is None:
                    self._invalid += 1
                    return False
                source_event_id, declaration = decoded
                if source_event_id in self._seen:
                    self._duplicate += 1
                    return False
                self._seen.add(source_event_id)
                if self._recorded >= self.max_events:
                    self._omitted += 1
                    self._truncated = True
                    return False
                self._sequence += 1
                record = {
                    "record_type": "event",
                    "schema_version": ACTIVITY_SCHEMA_VERSION,
                    "sequence": self._sequence,
                    "source_event_id": source_event_id,
                    "recorded_at": utc_timestamp(self._clock()),
                    "stage": self.stage,
                    "activity": declaration.activity,
                    "summary": declaration.summary,
                    "source": ACTIVITY_SOURCE,
                }
                self._append_record(record)
                if self._abandoned.is_set():
                    self._write_failed = True
                    return False
                self._recorded += 1
                return True
            except Exception:
                # A malformed marker or sidecar write failure must not leak raw
                # input, paths, or exception details into Codex diagnostics.
                self._write_failed = True
                return False
            finally:
                if self._abandoned.is_set():
                    self._close_handle()

    record_event = observe
    record = observe
    consume_event = observe
    handle = observe
    on_event = observe
    observe_event = observe

    def abandon(self) -> None:
        """Stop capture without waiting for a blocked metadata write."""

        self._abandoned.set()
        self._write_failed = True
        self._finalized = True
        if self._io_lock.acquire(blocking=False):
            try:
                self._close_handle()
            finally:
                self._io_lock.release()

    def finalize(self) -> dict[str, object]:
        if self._finalized:
            return self.diagnostics_dict()
        with self._io_lock:
            if self._finalized:
                return self.diagnostics_dict()
            self._finalized = True
            summary = {
                "record_type": "summary",
                "schema_version": ACTIVITY_SCHEMA_VERSION,
                "capture_state": "partial" if self._write_failed else "complete",
                "recorded": self._recorded,
                "invalid": self._invalid,
                "duplicate": self._duplicate,
                "omitted": self._omitted,
                "truncated": self._truncated,
            }
            if self._header_written and not self._summary_written:
                try:
                    self._append_record(summary)
                    self._summary_written = True
                except Exception:
                    self._write_failed = True
            self._close_handle()
            return self.diagnostics_dict()

    close = finalize

    def diagnostics_dict(self) -> dict[str, object]:
        return {
            "schema_version": ACTIVITY_SCHEMA_VERSION,
            "capture_state": "partial" if self._write_failed else "complete",
            "recorded": self._recorded,
            "invalid": self._invalid,
            "duplicate": self._duplicate,
            "omitted": self._omitted,
            "truncated": self._truncated,
        }


def activity_diagnostics_unavailable() -> dict[str, object]:
    return {
        "schema_version": ACTIVITY_SCHEMA_VERSION,
        "capture_state": "partial",
        "recorded": 0,
        "invalid": 0,
        "duplicate": 0,
        "omitted": 0,
        "truncated": False,
    }


__all__ = [
    "ACTIVITIES",
    "ACTIVITY_MARKER",
    "ACTIVITY_MARKER_PREFIX",
    "ACTIVITY_MAX_CAPTURE",
    "ACTIVITY_MAX_RECORDS",
    "ACTIVITY_MAX_SUMMARY_BYTES",
    "ACTIVITY_PUBLIC_LIMIT",
    "ACTIVITY_PUBLIC_MAX_EVENTS",
    "ACTIVITY_REPORTING_RULES",
    "ACTIVITY_RECORD_TYPES",
    "ACTIVITY_SAFE_ID_RE",
    "ACTIVITY_SCHEMA_VERSION",
    "ACTIVITY_SOURCE",
    "ACTIVITY_STAGE",
    "ACTIVITY_VALUES",
    "MAX_COMPLETED_RECORDS",
    "MAX_SUMMARY_BYTES",
    "SCHEMA_VERSION",
    "ActivityDeclaration",
    "ActivityRecorder",
    "activity_diagnostics_unavailable",
    "activity_sidecar_path",
    "decode_activity_marker",
    "is_safe_activity_id",
    "is_safe_source_event_id",
    "parse_activity_marker",
    "parse_activity_event",
    "utc_timestamp",
    "validate_activity_event",
    "validate_activity_summary",
]

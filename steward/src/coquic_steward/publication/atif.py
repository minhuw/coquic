"""Conversion of a completed Steward run into canonical ATIF v1.7.

The converter is intentionally transport-free.  It consumes the immutable
publication snapshot values, understands the private Codex sidecar shapes, and
returns a validated ATIF value without importing Harbor or calling a network
service.  Redaction and publication are owned by later stages.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, NoReturn

from jsonschema import Draft202012Validator

from .models import (
    AtifDocument,
    LogicalArtifact,
    PublicationError,
    PublicationSnapshot,
    PublicBundleComponent,
    ReasonCode,
    RunIdentity,
    RunLineage,
    RunMetadata,
    SourceDocument,
    StableRead,
    UsageSummary,
)


ATIF_SCHEMA_VERSION: Final[str] = "ATIF-v1.7"
SUPPORTED_IMAGE_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {"image/jpeg", "image/png", "image/gif", "image/webp"}
)
_MAX_RECORDS = 100_000
_MAX_TEXT = 64 * 1024 * 1024
_MAX_SOURCE_FACTS = 4_096
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_NAME_RE = re.compile(
    r"(?:bucket|objectkey|credential|secret|password|token|authorization|apikey|private)",
    re.IGNORECASE,
)
_PRIVATE_VALUE_RE = re.compile(
    r"(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?)://|"
    r"^(?:~[/\\]|[A-Za-z]:[/\\]|\\\\)|"
    r"(?:^|[-_])(private|internal|secret)[-_](bucket|object(?:[-_]key)?|url|path)(?:$|[-_])",
    re.IGNORECASE,
)
_SOURCE_BASENAMES = frozenset(
    {"codex.jsonl", "activities.jsonl", "telemetry.json", "run.json"}
)
_ACTIVITY_VALUES = frozenset(
    {"orient", "investigate", "edit", "self_validate", "self_review", "report"}
)
_ACTIVITY_MARKER = "STEWARD_ACTIVITY "
_RAW_ACTIVITY_TYPES = frozenset(
    {
        "error",
        "item.completed",
        "item.created",
        "item.delta",
        "item.failed",
        "item.started",
        "item.updated",
        "keep_alive",
        "response.completed",
        "response.created",
        "response.output_text.delta",
        "session.completed",
        "session.started",
        "stderr",
        "thread.completed",
        "thread.started",
        "turn.completed",
        "turn.started",
    }
)
_MISSING = object()


class AtifConversionError(PublicationError):
    """A bounded conversion failure without source values in its message."""


@dataclass(frozen=True, slots=True)
class AtifSource:
    """Convenient input boundary for callers that do not use PublicationSnapshot."""

    run: RunMetadata | Mapping[str, Any] | None = None
    documents: Mapping[str, Any] | Sequence[Any] = field(default_factory=dict)
    artifacts: tuple[LogicalArtifact, ...] = ()

    def __post_init__(self) -> None:
        values = tuple(self.artifacts)
        if any(not isinstance(item, LogicalArtifact) for item in values):
            raise AtifConversionError(ReasonCode.invalid_metadata)
        object.__setattr__(self, "artifacts", values)


# Names used by different publication callers all describe the same source
# boundary.  Keeping aliases here avoids forcing transport stages to know the
# internal class name.
CompletedRun = AtifSource
CompletedRunSnapshot = AtifSource


@dataclass(slots=True)
class _ArtifactState:
    artifact_id: str
    media_type: str
    sha256: str
    byte_size: int
    owner_step_id: int | str | None
    referenced: bool = False
    backing: bytes | None = field(default=None, repr=False)
    logical_path: str | None = None


@dataclass(slots=True)
class _MappedStep:
    value: dict[str, Any]
    record_index: int
    source_identity: str | None = None


def _fail(code: ReasonCode = ReasonCode.invalid_metadata) -> NoReturn:
    raise AtifConversionError(code)


def _canonical_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _fail(ReasonCode.invalid_metadata)


def canonical_atif_bytes(document: Mapping[str, Any]) -> bytes:
    """Serialize an ATIF document using the public canonical byte contract."""

    if isinstance(document, AtifDocument):
        return document.content
    if not isinstance(document, Mapping):
        _fail(ReasonCode.invalid_metadata)
    return _canonical_json(document)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(ReasonCode.invalid_jsonl)
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    _fail(ReasonCode.invalid_jsonl)


def _parse_json_bytes(value: bytes, *, code: ReasonCode = ReasonCode.invalid_metadata) -> Any:
    if not isinstance(value, bytes) or len(value) > _MAX_TEXT:
        _fail(ReasonCode.oversized)
    try:
        text = value.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except AtifConversionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _fail(code)


def _parse_jsonl_bytes(value: bytes, *, label: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, bytes) or len(value) > _MAX_TEXT:
        _fail(ReasonCode.oversized)
    if not value or not value.endswith(b"\n"):
        _fail(ReasonCode.partial)
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        _fail(ReasonCode.invalid_utf8)
    records: list[dict[str, Any]] = []
    for line in text.splitlines(keepends=True):
        if not line.endswith("\n"):
            _fail(ReasonCode.partial)
        encoded = line[:-1]
        if encoded.endswith("\r"):
            encoded = encoded[:-1]
        if not encoded.strip():
            _fail(ReasonCode.partial)
        try:
            value = json.loads(
                encoded,
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_constant,
            )
        except AtifConversionError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
            _fail(ReasonCode.invalid_jsonl)
        if not isinstance(value, dict):
            _fail(ReasonCode.invalid_jsonl)
        records.append(value)
        if len(records) > _MAX_RECORDS:
            _fail(ReasonCode.oversized)
    if not records:
        _fail(ReasonCode.partial)
    return tuple(records)


def _copy_json(value: Any) -> Any:
    """Detach frozen StableRead records without permitting custom objects."""

    if isinstance(value, Mapping):
        return {str(key): _copy_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_copy_json(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    _fail(ReasonCode.invalid_metadata)


def _document_name(name: object) -> str:
    if not isinstance(name, str) or not name:
        _fail(ReasonCode.invalid_path)
    return name.rsplit("/", 1)[-1]


def _document_content(value: Any) -> bytes:
    if isinstance(value, StableRead):
        return value.content
    if isinstance(value, SourceDocument):
        return value.content
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        if "content" in value:
            return _document_content(value["content"])
        return _canonical_json(_copy_json(value))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        # A sequence of decoded JSONL records is accepted at this private
        # boundary, then canonicalized exactly like a stable file read.
        records = [_copy_json(item) for item in value]
        if any(not isinstance(item, dict) for item in records):
            _fail(ReasonCode.invalid_jsonl)
        return b"".join(_canonical_json(item) for item in records)
    _fail(ReasonCode.invalid_metadata)


def _documents_from(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, PublicationSnapshot):
        return {document.logical_path: document for document in value.documents}
    if isinstance(value, AtifSource):
        return _documents_from(value.documents)
    if isinstance(value, Mapping):
        return {str(name): item for name, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        result: dict[str, Any] = {}
        for item in value:
            if isinstance(item, SourceDocument):
                result[item.logical_path] = item
            elif isinstance(item, StableRead):
                _fail(ReasonCode.invalid_metadata)
            else:
                _fail(ReasonCode.invalid_metadata)
        return result
    _fail(ReasonCode.invalid_metadata)


def _pick_document(documents: Mapping[str, Any], basename: str) -> Any:
    matches: list[Any] = []
    for name, value in documents.items():
        stem = _document_name(name)
        if stem == basename or stem == basename.removesuffix(".jsonl").removesuffix(".json"):
            matches.append(value)
    if len(matches) > 1:
        _fail(ReasonCode.invalid_metadata)
    if matches:
        return matches[0]
    return _MISSING


def _parse_document_jsonl(value: Any, *, label: str) -> tuple[dict[str, Any], ...]:
    if value is _MISSING:
        return ()
    if isinstance(value, StableRead) and value.records:
        records = tuple(_copy_json(item) for item in value.records)
        if not all(isinstance(item, dict) for item in records):
            _fail(ReasonCode.invalid_jsonl)
        # StableRead already checked the bytes; parsing them again ensures the
        # mapper never trusts a caller-provided records tuple over source bytes.
    return _parse_jsonl_bytes(_document_content(value), label=label)


def _activity_marker(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value.startswith(_ACTIVITY_MARKER):
        return None
    try:
        marker = json.loads(
            value[len(_ACTIVITY_MARKER) :].splitlines()[0],
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, IndexError, TypeError, ValueError):
        return None
    if not isinstance(marker, Mapping) or set(marker) != {"activity", "summary"}:
        return None
    activity = marker.get("activity")
    summary = marker.get("summary")
    if (
        not isinstance(activity, str)
        or activity not in _ACTIVITY_VALUES
        or not isinstance(summary, str)
        or not summary
        or len(summary.encode("utf-8")) > 240
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in summary)
    ):
        return None
    return activity, summary


def _validate_raw_activity_records(records: Sequence[Mapping[str, Any]]) -> None:
    if not records:
        _fail(ReasonCode.partial)
    completed_agent_message = False
    for record in records:
        record_type = record.get("type")
        if not isinstance(record_type, str) or not record_type or len(record_type) > 128:
            _fail(ReasonCode.partial)
        lowered = record_type.lower()
        if lowered not in _RAW_ACTIVITY_TYPES:
            _fail(ReasonCode.partial)
        item = record.get("item")
        if lowered.startswith("item."):
            if not isinstance(item, Mapping):
                _fail(ReasonCode.invalid_metadata)
            item_type = item.get("type")
            if not isinstance(item_type, str) or not item_type or len(item_type) > 128:
                _fail(ReasonCode.invalid_metadata)
            source_id = item.get("id")
            if not isinstance(source_id, str) or not _ID_RE.fullmatch(source_id):
                _fail(ReasonCode.invalid_identifier)
            if lowered == "item.completed" and item_type == "agent_message":
                text = item.get("text")
                if not isinstance(text, str) or not text:
                    _fail(ReasonCode.invalid_metadata)
                completed_agent_message = True
                # A marker is optional for a raw session envelope, but a
                # malformed marker is never silently published as an
                # activity fact.
                if text.startswith(_ACTIVITY_MARKER) and _activity_marker(text) is None:
                    _fail(ReasonCode.invalid_metadata)
        elif item is not None and not isinstance(item, Mapping):
            _fail(ReasonCode.invalid_metadata)
        _event_timestamp(record, item if isinstance(item, Mapping) else None)
        _event_duration(record, item if isinstance(item, Mapping) else None)
    if not completed_agent_message:
        _fail(ReasonCode.partial)


def _validate_activity_records(records: Sequence[Mapping[str, Any]]) -> str:
    """Validate one of the two producer activity envelopes.

    The recorder sidecar has a header/event/summary envelope.  Recovery and
    older session paths can hand the mapper the newline-terminated completed
    agent events directly; those events are validated without inventing a
    header or summary.
    """

    if not records:
        _fail(ReasonCode.partial)
    if records[0].get("record_type") == "header" or records[-1].get("record_type") == "summary":
        if records[0].get("record_type") != "header" or records[-1].get("record_type") != "summary":
            _fail(ReasonCode.partial)
        if records[0].get("schema_version") != 1 or records[-1].get("schema_version") != 1:
            _fail(ReasonCode.invalid_metadata)
        expected_sequence = 1
        for record in records[1:-1]:
            if record.get("record_type") != "event" or record.get("schema_version") != 1:
                _fail(ReasonCode.invalid_metadata)
            sequence = record.get("sequence")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != expected_sequence:
                _fail(ReasonCode.invalid_metadata)
            source_id = record.get("source_event_id")
            if not isinstance(source_id, str) or not _ID_RE.fullmatch(source_id):
                _fail(ReasonCode.invalid_identifier)
            if "recorded_at" in record:
                _timestamp(record["recorded_at"])
            if "activity" in record and record["activity"] not in _ACTIVITY_VALUES:
                _fail(ReasonCode.invalid_metadata)
            if "summary" in record and (
                not isinstance(record["summary"], str)
                or not record["summary"]
                or len(record["summary"].encode("utf-8")) > 240
            ):
                _fail(ReasonCode.invalid_metadata)
            expected_sequence += 1
        summary = records[-1]
        if summary.get("capture_state") != "complete":
            _fail(ReasonCode.partial)
        for key in ("recorded", "invalid", "duplicate", "omitted"):
            value = summary.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                _fail(ReasonCode.invalid_metadata)
        if not isinstance(summary.get("truncated"), bool):
            _fail(ReasonCode.invalid_metadata)
        if summary["recorded"] != len(records) - 2:
            _fail(ReasonCode.partial)
        if summary["omitted"] or summary["truncated"]:
            _fail(ReasonCode.partial)
        return "sidecar"
    _validate_raw_activity_records(records)
    return "raw"


def _parse_activity_document(
    value: Any, *, expected_transcript_sha256: str | None = None
) -> tuple[tuple[dict[str, Any], ...], str]:
    if value is _MISSING:
        _fail(ReasonCode.partial)
    content = _document_content(value)
    try:
        parsed = _parse_json_bytes(content)
    except AtifConversionError:
        parsed = _MISSING
    if isinstance(parsed, Mapping) and parsed.get("availability") == "unavailable":
        if set(parsed) - {"availability", "reason"}:
            _fail(ReasonCode.invalid_metadata)
        reason = parsed.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason or len(reason) > 256):
            _fail(ReasonCode.invalid_metadata)
        return (), "unavailable"
    records = _parse_jsonl_bytes(content, label="activities.jsonl")
    envelope = _validate_activity_records(records)
    if envelope == "sidecar" and "transcript_sha256" in records[-1]:
        digest = records[-1]["transcript_sha256"]
        if (
            not isinstance(digest, str)
            or not _DIGEST_RE.fullmatch(digest)
            or expected_transcript_sha256 is None
            or digest != expected_transcript_sha256
        ):
            _fail(ReasonCode.invalid_metadata)
    return records, envelope


def _parse_document_json(value: Any, *, label: str) -> dict[str, Any] | None:
    if value is _MISSING:
        return None
    parsed = _parse_json_bytes(_document_content(value))
    if not isinstance(parsed, dict):
        _fail(ReasonCode.invalid_metadata)
    return parsed


def _safe_id(value: Any, *, fallback: str | None = None) -> str:
    if isinstance(value, str) and _ID_RE.fullmatch(value):
        return value
    if fallback is not None:
        return fallback
    _fail(ReasonCode.invalid_identifier)


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            _fail(ReasonCode.invalid_metadata)
    else:
        _fail(ReasonCode.invalid_metadata)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(ReasonCode.invalid_metadata)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    if value < 0:
        return None
    return value


def _private_key(key: object) -> bool:
    if not isinstance(key, str):
        return True
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    return bool(_PRIVATE_NAME_RE.search(compact)) or compact in {
        "url",
        "uri",
        "endpoint",
        "baseurl",
        "baseuri",
        "trajectorypath",
        "filepath",
        "credentialpath",
        "privatepath",
    }


def _private_value(value: object, *, key: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    if value.startswith("/") or _PRIVATE_VALUE_RE.search(value):
        return True
    if key is not None and key.lower().endswith("path") and key.lower().replace("_", "") != "logicalpath" and not value.startswith("artifact:"):
        return True
    return False


def _known_logical_path_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    return compact in {
        "path",
        "filepath",
        "filename",
        "logicalpath",
        "logicalfilepath",
    }


def _logical_source_path(value: object) -> str:
    """Validate a producer path and keep only a logical relative reference."""

    if not isinstance(value, str) or not value or len(value) > 1024:
        _fail(ReasonCode.unsafe_content)
    if (
        value.startswith("/")
        or value.startswith("\\")
        or "\\" in value
        or "://" in value
        or "\x00" in value
    ):
        _fail(ReasonCode.unsafe_content)
    parts = value.split("/")
    if any(
        not part
        or part in {".", ".."}
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", part)
        for part in parts
    ):
        _fail(ReasonCode.unsafe_content)
    return value


def _safe_source(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Keep only bounded, public-safe producer facts under ``extra.coquic``."""

    if depth > 8:
        _fail(ReasonCode.oversized)
    if _known_logical_path_key(key):
        value = _logical_source_path(value)
        key = "logicalPath"
    if key is not None and _private_key(key):
        _fail(ReasonCode.unsafe_content)
    if _private_value(value, key=key):
        _fail(ReasonCode.unsafe_content)
    if isinstance(value, Mapping):
        if len(value) > _MAX_SOURCE_FACTS:
            _fail(ReasonCode.oversized)
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            child_key = str(raw_key)
            output_key = "logicalPath" if _known_logical_path_key(child_key) else child_key
            if output_key in result:
                _fail(ReasonCode.invalid_metadata)
            result[output_key] = _safe_source(child, key=output_key, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_SOURCE_FACTS:
            _fail(ReasonCode.oversized)
        return [_safe_source(child, depth=depth + 1) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, float) and not math.isfinite(value):
            _fail(ReasonCode.invalid_metadata)
        return value
    _fail(ReasonCode.invalid_metadata)


def _source_identity(value: Any) -> str | None:
    for key in ("id", "item_id", "itemId", "event_id", "eventId", "call_id", "callId", "tool_call_id"):
        candidate = value.get(key) if isinstance(value, Mapping) else None
        if isinstance(candidate, str) and candidate:
            if _PRIVATE_VALUE_RE.search(candidate) or candidate.startswith("/"):
                return None
            return candidate[:128]
    return None


def _record_type(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> str:
    value = item.get("type") if item is not None else None
    if not isinstance(value, str) or not value:
        value = record.get("type") or record.get("record_type") or record.get("event")
    return value if isinstance(value, str) else "unknown"


def _item(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = record.get("item")
    return value if isinstance(value, Mapping) else None


def _event_timestamp(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> str | None:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        for key in ("timestamp", "created_at", "createdAt", "recorded_at", "recordedAt", "occurred_at", "occurredAt"):
            if key in source:
                return _timestamp(source[key])
    return None


def _event_duration(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> int | float | None:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        for key in ("duration_ms", "durationMs", "duration"):
            if key in source:
                value = _number(source[key])
                if value is None:
                    _fail(ReasonCode.invalid_metadata)
                return value
    return None


def _is_lifecycle(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> bool:
    value = _record_type(record, item).lower()
    return value in {
        "thread.started",
        "thread.completed",
        "turn.started",
        "turn.completed",
        "response.created",
        "response.completed",
        "session.started",
        "session.completed",
        "keep_alive",
        "stderr",
    }


def _is_result_type(record_type: str) -> bool:
    value = record_type.lower()
    return (
        "output" in value
        or value in {"tool_result", "tool_response", "observation", "result", "function_result", "custom_tool_result"}
        or value.endswith(".result")
    )


def _is_call_type(record_type: str) -> bool:
    value = record_type.lower()
    return value in {
        "function_call",
        "custom_tool_call",
        "tool_call",
        "command_execution",
        "command",
        "function",
    } or value.endswith(".call")


def _role(record: Mapping[str, Any], item: Mapping[str, Any] | None, record_type: str) -> str:
    for source in (item, record):
        if isinstance(source, Mapping) and isinstance(source.get("role"), str):
            role = source["role"].lower()
            if role in {"system", "user"}:
                return role
            if role in {"assistant", "agent", "tool", "developer"}:
                return "agent"
    value = record_type.lower()
    if value in {"system", "system_message", "developer_message"} or "system" in value:
        return "system"
    if value in {"user", "user_message", "input", "input_message", "prompt"} or value.endswith(".input"):
        return "user"
    return "agent"


def _text_value(value: Any) -> str | None:
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_TEXT:
            _fail(ReasonCode.oversized)
        return value
    if value is None:
        return None
    return None


def _find_content(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> Any:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        for key in ("message", "content", "text", "output", "aggregated_output", "aggregatedOutput", "result", "value"):
            if key in source:
                return source[key]
    return None


def _source_ref(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value


def _call_source_id(record: Mapping[str, Any], item: Mapping[str, Any] | None, *, include_item_id: bool = True) -> str | None:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        keys = ("call_id", "callId", "tool_call_id", "toolCallId")
        if include_item_id:
            keys += ("id", "item_id", "itemId")
        for key in keys:
            value = _source_ref(source.get(key))
            if value is not None:
                return value
    return None


def _arguments(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        result = _safe_arguments(value)
        return result if isinstance(result, dict) else {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value, object_pairs_hook=_object_without_duplicates, parse_constant=_reject_constant)
        except (AtifConversionError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
            parsed = value
        if isinstance(parsed, Mapping):
            result = _safe_arguments(parsed)
            return result if isinstance(result, dict) else {}
        return {"input": _safe_source(parsed)}
    return {"input": _safe_source(value)}


def _safe_arguments(value: Mapping[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Keep tool arguments structured while making path fields logical-only."""

    if depth > 8 or len(value) > _MAX_SOURCE_FACTS:
        _fail(ReasonCode.oversized)
    result: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        compact = re.sub(r"[^a-z0-9]", "", key.lower())
        if compact in {"path", "filepath", "cwd", "workingdirectory", "directory"}:
            if not isinstance(raw_value, str) or not raw_value or raw_value.startswith("/") or _PRIVATE_VALUE_RE.search(raw_value):
                _fail(ReasonCode.unsafe_content)
            key = "logicalPath"
        elif _private_key(key):
            _fail(ReasonCode.unsafe_content)
        if isinstance(raw_value, Mapping):
            result[key] = _safe_arguments(raw_value, depth=depth + 1)
        elif isinstance(raw_value, (list, tuple)):
            result[key] = [
                _safe_arguments(item, depth=depth + 1) if isinstance(item, Mapping) else _safe_source(item, depth=depth + 1)
                for item in raw_value
            ]
        else:
            result[key] = _safe_source(raw_value, key=key, depth=depth + 1)
    return result


def _function_name(record: Mapping[str, Any], item: Mapping[str, Any] | None, record_type: str) -> str:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        for key in ("function_name", "functionName", "name", "tool_name", "toolName", "command"):
            value = source.get(key)
            if isinstance(value, str) and value:
                if key == "command" and len(value) > 128:
                    return "command_execution"
                if _PRIVATE_VALUE_RE.search(value) or value.startswith("/"):
                    _fail(ReasonCode.unsafe_content)
                return value[:128]
    return record_type[:128] or "tool"


def _decode_inline_image(value: Any) -> tuple[bytes, str] | None:
    if isinstance(value, bytes):
        if not value or len(value) > 64 * 1024 * 1024:
            return None
        return value, ""
    if not isinstance(value, str):
        return None
    encoded = value
    media = ""
    if encoded.startswith("data:"):
        if "," not in encoded:
            return None
        header, encoded = encoded.split(",", 1)
        parameters = header[5:].split(";")
        media = parameters[0].lower()
        if not media or "base64" not in parameters[1:]:
            return None
    else:
        # Bare base64 is accepted for the older producer shape.  Its media
        # type must come from the surrounding image descriptor.
        if len(encoded) > (64 * 1024 * 1024) * 2:
            return None
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not content or len(content) > 64 * 1024 * 1024:
        return None
    return content, media


_IMAGE_SUFFIXES: Final[dict[str, str]] = {
    "image/gif": "gif",
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}


def _inline_image_path(artifact_id: str, media_type: str) -> str:
    suffix = _IMAGE_SUFFIXES.get(media_type)
    if suffix is None:
        _fail(ReasonCode.invalid_media_type)
    return f"artifacts/{artifact_id}.{suffix}"


def _image_part(
    value: Mapping[str, Any],
    *,
    owner_step_id: int,
    artifacts: dict[str, _ArtifactState],
) -> dict[str, Any]:
    source = value.get("source") if isinstance(value.get("source"), Mapping) else value
    if isinstance(source, Mapping) and isinstance(source.get("image_url"), Mapping):
        nested = source["image_url"]
        source = {**source, **nested}
        if "data" not in source:
            nested_url = nested.get("url")
            if nested_url is not None:
                source = {**source, "data": nested_url}
    if isinstance(source, Mapping) and isinstance(source.get("imageUrl"), Mapping):
        nested = source["imageUrl"]
        source = {**source, **nested}
        if "data" not in source:
            nested_url = nested.get("url")
            if nested_url is not None:
                source = {**source, "data": nested_url}
    media = None
    for key in ("media_type", "mediaType", "mime_type", "mimeType", "type"):
        candidate = source.get(key) if isinstance(source, Mapping) else None
        if isinstance(candidate, str) and candidate.startswith("image/"):
            media = candidate
            break
    artifact_id: str | None = None
    for key in ("artifact_id", "artifactId", "id"):
        candidate = source.get(key) if isinstance(source, Mapping) else None
        if isinstance(candidate, str):
            artifact_id = candidate.removeprefix("artifact:")
            break
    logical = source.get("path") if isinstance(source, Mapping) else None
    if artifact_id is None and isinstance(logical, str) and logical.startswith("artifact:"):
        artifact_id = logical.removeprefix("artifact:")
    inline = None
    for key in ("data", "base64", "image_data", "imageData"):
        if isinstance(source, Mapping) and key in source:
            inline = _decode_inline_image(source[key])
            break
    if inline is None and isinstance(source, Mapping):
        for key in ("image_url", "imageUrl", "url"):
            candidate = source.get(key)
            if isinstance(candidate, str) and candidate.startswith("data:"):
                inline = _decode_inline_image(candidate)
                if inline is None:
                    _fail(ReasonCode.invalid_media_type)
                break
    if artifact_id is None and inline is not None:
        content, inline_media = inline
        if inline_media:
            media = inline_media
        if media not in SUPPORTED_IMAGE_MEDIA_TYPES:
            _fail(ReasonCode.invalid_media_type)
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = f"image-{digest[:24]}"
        existing = artifacts.get(artifact_id)
        if existing is None:
            artifacts[artifact_id] = _ArtifactState(
                artifact_id,
                media,
                digest,
                len(content),
                owner_step_id,
                backing=content,
                logical_path=_inline_image_path(artifact_id, media),
            )
        elif (
            existing.media_type != media
            or existing.sha256 != digest
            or existing.byte_size != len(content)
        ):
            _fail(ReasonCode.invalid_metadata)
        else:
            existing.backing = content
    elif inline is not None:
        content, inline_media = inline
        if inline_media:
            if media is not None and media != inline_media:
                _fail(ReasonCode.invalid_media_type)
            media = inline_media
        if media not in SUPPORTED_IMAGE_MEDIA_TYPES:
            _fail(ReasonCode.invalid_media_type)
        digest = hashlib.sha256(content).hexdigest()
        descriptor = artifacts.get(artifact_id or "")
        if descriptor is None:
            _fail(ReasonCode.invalid_path)
        if descriptor.sha256 != digest or descriptor.byte_size != len(content) or descriptor.media_type != media:
            _fail(ReasonCode.invalid_metadata)
        descriptor.backing = content
    if media not in SUPPORTED_IMAGE_MEDIA_TYPES:
        _fail(ReasonCode.invalid_media_type)
    if artifact_id is None or not _ID_RE.fullmatch(artifact_id):
        _fail(ReasonCode.invalid_path)
    descriptor = artifacts.get(artifact_id)
    if descriptor is None:
        _fail(ReasonCode.invalid_path)
    if descriptor.owner_step_id == 0:
        descriptor.owner_step_id = owner_step_id
    if descriptor.media_type != media:
        _fail(ReasonCode.invalid_media_type)
    if isinstance(descriptor.owner_step_id, int) and descriptor.owner_step_id != owner_step_id:
        _fail(ReasonCode.invalid_metadata)
    descriptor.referenced = True
    return {"type": "image", "source": {"media_type": media, "path": f"artifact:{artifact_id}"}}


def _content(
    value: Any,
    *,
    owner_step_id: int,
    artifacts: dict[str, _ArtifactState],
) -> str | list[dict[str, Any]]:
    if value is None:
        return ""
    if isinstance(value, str):
        _text_value(value)
        return value
    if isinstance(value, Mapping):
        value_type = str(value.get("type") or "").lower()
        if value_type in {"image", "input_image", "output_image"} or any(
            key in value for key in ("image_url", "imageUrl", "base64", "image_data", "imageData")
        ):
            image = dict(value)
            if "source" not in image:
                image["source"] = {
                    "media_type": image.get("media_type") or image.get("mime_type") or image.get("mimeType"),
                    "path": image.get("path") or image.get("image_url") or image.get("imageUrl"),
                    **({"data": image.get("base64")} if image.get("base64") is not None else {}),
                }
            return [_image_part(image, owner_step_id=owner_step_id, artifacts=artifacts)]
        for key in ("text", "value", "message", "content"):
            if isinstance(value.get(key), str):
                return str(value[key])
        _fail(ReasonCode.invalid_metadata)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, str):
                parts.append({"type": "text", "text": item})
            elif isinstance(item, Mapping):
                item_type = str(item.get("type") or "").lower()
                if item_type in {"image", "input_image", "output_image"} or "source" in item or "image_url" in item or "imageUrl" in item:
                    parts.append(_image_part(item, owner_step_id=owner_step_id, artifacts=artifacts))
                else:
                    text = _find_content(item, None)
                    if not isinstance(text, str):
                        _fail(ReasonCode.invalid_metadata)
                    parts.append({"type": "text", "text": text})
            else:
                _fail(ReasonCode.invalid_metadata)
        return parts
    _fail(ReasonCode.invalid_metadata)


def _collapse_events(records: Sequence[Mapping[str, Any]]) -> tuple[tuple[int, Mapping[str, Any]], ...]:
    """Prefer completed item records while retaining first source position."""

    selected: dict[str, tuple[int, Mapping[str, Any], bool]] = {}
    order: list[str] = []
    result: list[tuple[int, Mapping[str, Any]]] = []
    for index, record in enumerate(records):
        item = _item(record)
        if item is None:
            if not _is_lifecycle(record, None):
                result.append((index, record))
            continue
        item_id = item.get("id")
        event_type = str(record.get("type") or "").lower()
        completed = event_type.endswith("completed") or event_type.endswith("complete")
        if not isinstance(item_id, str) or not item_id:
            if not _is_lifecycle(record, item):
                result.append((index, record))
            continue
        if item_id not in selected:
            selected[item_id] = (index, record, completed)
            order.append(item_id)
        elif completed and not selected[item_id][2]:
            first_index = selected[item_id][0]
            selected[item_id] = (first_index, record, True)
        elif completed and selected[item_id][2]:
            # A second completed record with the same source identity is a
            # distinct observation.  Keeping it lets owner resolution reject
            # an ambiguous descriptor instead of silently choosing the first.
            result.append((index, record))
    result.extend((selected[item_id][0], selected[item_id][1]) for item_id in order)
    return tuple(sorted(result, key=lambda item: item[0]))


def _record_provenance(index: int, record: Mapping[str, Any], item: Mapping[str, Any] | None, *, unpaired: bool = False) -> dict[str, Any]:
    record_type = _record_type(record, item)
    value: dict[str, Any] = {"recordIndex": index, "recordType": record_type}
    source_id = _source_identity(item or record)
    if source_id is not None:
        value["sourceId"] = source_id
    else:
        value["sourceIdentityDigest"] = hashlib.sha256(_canonical_json(_copy_json(record))).hexdigest()
    if unpaired:
        value["unpaired"] = True
    facts = _producer_facts(record, item)
    if facts:
        value["facts"] = facts
    return value


def _producer_facts(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> dict[str, Any]:
    """Preserve unknown safe fields without copying provider/private handles."""

    ignored = {
        "type", "record_type", "event", "item", "id", "item_id", "itemId",
        "event_id", "eventId", "call_id", "callId", "tool_call_id", "toolCallId",
        "timestamp", "created_at", "createdAt", "recorded_at", "recordedAt",
    }
    result: dict[str, Any] = {}
    for source in (record, item):
        if not isinstance(source, Mapping):
            continue
        for key, value in source.items():
            name = str(key)
            if name in ignored:
                continue
            if name in {"thread_id", "threadId", "session_id", "sessionId", "provider_session_id", "providerSessionId", "provider_id", "providerId"}:
                continue
            # Known transcript content belongs in the Harbor message fields.
            if name in {"text", "message", "content", "output", "aggregated_output", "aggregatedOutput", "result", "arguments", "args", "input", "parameters", "command", "name", "function_name", "functionName", "tool_name", "toolName", "role", "metrics", "usage", "model_name", "modelName", "reasoning_effort", "reasoningEffort"}:
                continue
            result[name] = value
    if not result:
        return {}
    safe = _safe_source(result)
    return safe if isinstance(safe, dict) else {}


def _extra_step(
    index: int,
    record: Mapping[str, Any],
    item: Mapping[str, Any] | None,
    *,
    unpaired: bool = False,
    duration: int | float | None = None,
    artifacts: Sequence[str] = (),
) -> dict[str, Any]:
    coqui: dict[str, Any] = {"source": _record_provenance(index, record, item, unpaired=unpaired)}
    if duration is not None:
        coqui["timing"] = {"durationMs": duration}
    if artifacts:
        coqui["artifactIds"] = list(dict.fromkeys(artifacts))
    return {"coquic": coqui}


def _call_id(source_id: str | None, record: Mapping[str, Any], index: int, used: set[str]) -> str:
    if source_id and _ID_RE.fullmatch(source_id) and not _PRIVATE_VALUE_RE.search(source_id):
        candidate = source_id
    else:
        digest = hashlib.sha256(_canonical_json(_copy_json(record))).hexdigest()[:24]
        candidate = f"call-{digest}"
    if candidate not in used:
        used.add(candidate)
        return candidate
    ordinal = 2
    while f"{candidate}-{ordinal}" in used:
        ordinal += 1
    candidate = f"{candidate}-{ordinal}"
    used.add(candidate)
    return candidate


def _tool_arguments(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> Any:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        for key in ("arguments", "args", "input", "parameters", "command"):
            if key in source:
                value = source[key]
                if key == "command" and isinstance(value, str):
                    return {"command": value}
                return _arguments(value)
    return {}


def _tool_output(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> Any:
    for source in (item, record):
        if not isinstance(source, Mapping):
            continue
        for key in ("output", "aggregated_output", "aggregatedOutput", "result", "content", "text", "value"):
            if key in source:
                return source[key]
    return None


def _observation_content(
    value: Any,
    *,
    owner_step_id: int,
    artifacts: dict[str, _ArtifactState],
) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, list)):
        return _content(value, owner_step_id=owner_step_id, artifacts=artifacts)
    if isinstance(value, Mapping):
        try:
            return _content(value, owner_step_id=owner_step_id, artifacts=artifacts)
        except AtifConversionError as error:
            if error.code is not ReasonCode.invalid_metadata:
                raise
        # ATIF observations allow text or multimodal parts only.  Preserve a
        # structured producer result as canonical JSON text when it has no
        # supported content shape.
        return _canonical_json(_safe_source(value)).decode("utf-8").rstrip("\n")
    return _canonical_json(_safe_source(value)).decode("utf-8").rstrip("\n")


def _map_steps(
    records: Sequence[Mapping[str, Any]],
    *,
    artifacts: dict[str, _ArtifactState],
) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, list[dict[str, Any]]], tuple[_MappedStep, ...]]:
    calls: dict[str, str] = {}
    used_call_ids: set[str] = set()
    pending_calls: list[str] = []
    unpaired: dict[str, list[dict[str, Any]]] = {"results": []}
    mapped: list[_MappedStep] = []
    events = _collapse_events(records)
    for index, record in events:
        item = _item(record)
        record_type = _record_type(record, item)
        lowered = record_type.lower()
        role = _role(record, item, record_type)
        is_result = _is_result_type(record_type)
        is_call = _is_call_type(record_type)
        # A command/function call may carry its own output; it is represented as
        # one ordered step with both the action and observation.
        call_source = _call_source_id(record, item, include_item_id=not is_result)
        if is_call and not is_result:
            call_id = _call_id(call_source, record, index, used_call_ids)
            if call_source is not None:
                calls.setdefault(call_source, call_id)
            pending_calls.append(call_id)
            step_id = len(mapped) + 1
            call: dict[str, Any] = {
                "tool_call_id": call_id,
                "function_name": _function_name(record, item, record_type),
                "arguments": _tool_arguments(record, item),
            }
            timestamp = _event_timestamp(record, item)
            message_value = _find_content(record, item)
            message: Any = ""
            # Tool records can include descriptive text, but never flatten a
            # multimodal value into a string.
            if isinstance(message_value, (str, list, Mapping)) and not isinstance(message_value, str):
                message = _content(message_value, owner_step_id=step_id, artifacts=artifacts)
            elif isinstance(message_value, str) and lowered not in {"command_execution", "command"}:
                message = message_value
            artifact_refs = _artifact_refs_for_step(artifacts, step_id)
            step: dict[str, Any] = {
                "step_id": step_id,
                "source": "agent",
                "message": message,
                "tool_calls": [call],
                "extra": _extra_step(index, record, item, duration=_event_duration(record, item), artifacts=artifact_refs),
            }
            if timestamp is not None:
                step["timestamp"] = timestamp
            output = _tool_output(record, item)
            if output is not None and any(key in (item or record) for key in ("output", "aggregated_output", "aggregatedOutput", "result")):
                step["observation"] = {"results": [{"source_call_id": call_id, "content": _observation_content(output, owner_step_id=step_id, artifacts=artifacts)}]}
                if call_id in pending_calls:
                    pending_calls.remove(call_id)
            mapped.append(_MappedStep(step, index, _source_identity(item or record)))
            continue
        if is_result:
            step_id = len(mapped) + 1
            resolved = calls.get(call_source) if call_source is not None else None
            if resolved is None and call_source is None and pending_calls:
                resolved = pending_calls.pop(0)
            elif resolved is not None and resolved in pending_calls:
                pending_calls.remove(resolved)
            output = _tool_output(record, item)
            content = _observation_content(output, owner_step_id=step_id, artifacts=artifacts)
            result: dict[str, Any] = {"content": content}
            if resolved is not None:
                result["source_call_id"] = resolved
            else:
                provenance = _record_provenance(index, record, item, unpaired=True)
                unpaired["results"].append(provenance)
            step = {
                "step_id": step_id,
                "source": "agent",
                "message": "",
                "observation": {"results": [result]},
                "extra": _extra_step(index, record, item, unpaired=resolved is None, duration=_event_duration(record, item), artifacts=_artifact_refs_for_step(artifacts, step_id)),
            }
            timestamp = _event_timestamp(record, item)
            if timestamp is not None:
                step["timestamp"] = timestamp
            mapped.append(_MappedStep(step, index, _source_identity(item or record)))
            continue
        # Plain message, reasoning, or an unknown safe producer record.
        step_id = len(mapped) + 1
        content_value = _find_content(record, item)
        reasoning_value = None
        if lowered in {"reasoning", "analysis", "assistant_reasoning"}:
            reasoning_value = content_value if isinstance(content_value, str) else None
            content_value = ""
        if content_value is None:
            content_value = ""
        message = _content(content_value, owner_step_id=step_id, artifacts=artifacts)
        step = {
            "step_id": step_id,
            "source": role,
            "message": message,
            "extra": _extra_step(index, record, item, duration=_event_duration(record, item), artifacts=_artifact_refs_for_step(artifacts, step_id)),
        }
        if reasoning_value is not None:
            step["reasoning_content"] = reasoning_value
        timestamp = _event_timestamp(record, item)
        if timestamp is not None:
            step["timestamp"] = timestamp
        model = (item or record).get("model_name") if isinstance(item or record, Mapping) else None
        if isinstance(model, str) and model:
            step["model_name"] = model
        effort = (item or record).get("reasoning_effort") if isinstance(item or record, Mapping) else None
        if isinstance(effort, (str, int, float)) and not isinstance(effort, bool):
            step["reasoning_effort"] = effort
        metrics = _step_metrics(record, item)
        if metrics:
            step["metrics"] = metrics
        mapped.append(_MappedStep(step, index, _source_identity(item or record)))
    if not mapped:
        _fail(ReasonCode.partial)
    return [item.value for item in mapped], calls, unpaired, tuple(mapped)


def _artifact_refs_for_step(artifacts: Mapping[str, _ArtifactState], step_id: int) -> list[str]:
    return [item.artifact_id for item in artifacts.values() if item.owner_step_id == step_id and item.referenced]


def _step_metrics(record: Mapping[str, Any], item: Mapping[str, Any] | None) -> dict[str, Any]:
    source: Mapping[str, Any] = item if isinstance(item, Mapping) and isinstance(item.get("metrics"), Mapping) else record
    raw = source.get("metrics") if source is not record else source.get("metrics")
    if not isinstance(raw, Mapping):
        raw = source.get("usage") if isinstance(source.get("usage"), Mapping) else None
    if not isinstance(raw, Mapping):
        return {}
    usage: dict[str, Any] = {}
    for incoming, outgoing in (
        ("prompt_tokens", "prompt_tokens"),
        ("input_tokens", "prompt_tokens"),
        ("completion_tokens", "completion_tokens"),
        ("output_tokens", "completion_tokens"),
        ("cached_tokens", "cached_tokens"),
        ("cached_input_tokens", "cached_tokens"),
        ("total_tokens", "total"),
        ("cost_usd", "cost_usd"),
    ):
        value = raw.get(incoming)
        if incoming != outgoing and outgoing in usage:
            continue
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0:
            usage[{"prompt_tokens": "prompt", "completion_tokens": "completion", "cached_tokens": "cached"}.get(outgoing, outgoing)] = value
    return {"extra": {"usage": usage}} if usage else {}


def _run_from_mapping(value: Mapping[str, Any]) -> RunMetadata:
    identity_value = value.get("identity") if isinstance(value.get("identity"), Mapping) else value
    task_id = identity_value.get("taskId", identity_value.get("task_id"))
    pipeline_id = identity_value.get("pipelineId", identity_value.get("pipeline_id"))
    run_id = identity_value.get("runId", identity_value.get("run_id", identity_value.get("id")))
    identity = RunIdentity(_safe_id(task_id), _safe_id(pipeline_id), _safe_id(run_id))
    state = value.get("state", value.get("runState", "succeeded"))
    if state == "interrupted":
        state = "failed"
    if not isinstance(state, str) or state == "running":
        _fail(ReasonCode.partial)
    started = _timestamp(value.get("startedAt", value.get("started_at")))
    completed = _timestamp(value.get("completedAt", value.get("completed_at")))
    if started is None or completed is None:
        _fail(ReasonCode.partial)
    duration = value.get("durationMs", value.get("duration_ms"))
    if duration is None:
        duration = max(0, int((datetime.fromisoformat(completed.replace("Z", "+00:00")) - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds() * 1000))
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration < 0:
        _fail(ReasonCode.invalid_metadata)
    raw_usage = value.get("usage")
    usage = None
    if isinstance(raw_usage, Mapping):
        usage = UsageSummary(
            prompt_tokens=_optional_counter(raw_usage, "promptTokens", "prompt_tokens", "input_tokens"),
            completion_tokens=_optional_counter(raw_usage, "completionTokens", "completion_tokens", "output_tokens"),
            total_tokens=_optional_counter(raw_usage, "totalTokens", "total_tokens"),
            cached_input_tokens=_optional_counter(raw_usage, "cachedInputTokens", "cached_input_tokens", "cached_tokens"),
            reasoning_output_tokens=_optional_counter(raw_usage, "reasoningOutputTokens", "reasoning_output_tokens"),
        )
    lineage_value = value.get("lineage") if isinstance(value.get("lineage"), Mapping) else value
    lineage = RunLineage(
        parent_run_id=_optional_id(lineage_value, "parentRunId", "parent_run_id"),
        retry_of_run_id=_optional_id(lineage_value, "retryOfRunId", "retry_of_run_id"),
        resume_of_run_id=_optional_id(lineage_value, "resumeOfRunId", "resume_of_run_id"),
    )
    return RunMetadata(
        identity=identity,
        role=str(value.get("role", "unknown")),
        state=state,
        started_at=started,
        completed_at=completed,
        duration_ms=int(duration),
        model=value.get("model"),
        reasoning=value.get("reasoning", value.get("reasoning_effort")),
        lineage=lineage,
        usage=usage,
    )


def _optional_id(value: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in value and value[key] is not None:
            return _safe_id(value[key])
    return None


def _optional_counter(value: Mapping[str, Any], *keys: str) -> int | None:
    for key in keys:
        candidate = value.get(key)
        if candidate is not None:
            if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 0:
                _fail(ReasonCode.invalid_metadata)
            return candidate
    return None


def _coerce_source(
    source: Any,
    *,
    snapshot: Any = None,
    run: Any = None,
    documents: Any = None,
    codex: Any = _MISSING,
    activities: Any = _MISSING,
    telemetry: Any = _MISSING,
    run_document: Any = _MISSING,
    artifacts: Any = None,
) -> tuple[RunMetadata, dict[str, Any], tuple[LogicalArtifact, ...]]:
    selected = snapshot if snapshot is not None else source
    source_artifacts: tuple[LogicalArtifact, ...] = ()
    if isinstance(selected, PublicationSnapshot):
        selected_run: Any = selected.run
        selected_documents = _documents_from(selected)
        source_artifacts = tuple(selected.artifacts)
    elif isinstance(selected, AtifSource):
        selected_run = selected.run
        selected_documents = _documents_from(selected.documents)
        source_artifacts = tuple(selected.artifacts)
    elif isinstance(selected, Mapping) and any(key in selected for key in ("run", "documents", "codex", "activities", "telemetry", "run_document")):
        selected_run = selected.get("run")
        selected_documents = _documents_from(selected.get("documents"))
        source_artifacts = tuple(selected.get("artifacts") or ())
        if codex is _MISSING:
            codex = selected.get("codex", _MISSING)
        if activities is _MISSING:
            activities = selected.get("activities", _MISSING)
        if telemetry is _MISSING:
            telemetry = selected.get("telemetry", _MISSING)
        if run_document is _MISSING:
            run_document = selected.get("run_document", selected.get("runDocument", _MISSING))
    else:
        selected_run = None
        selected_documents = _documents_from(documents)
    if run is not None:
        selected_run = run
    if documents is not None:
        selected_documents = _documents_from(documents)
    for name, value in (("codex.jsonl", codex), ("activities.jsonl", activities), ("telemetry.json", telemetry), ("run.json", run_document)):
        if value is not _MISSING and value is not None:
            selected_documents[name] = value
    if artifacts is not None:
        source_artifacts = tuple(artifacts)
    if any(not isinstance(item, LogicalArtifact) for item in source_artifacts):
        _fail(ReasonCode.invalid_metadata)
    run_value = selected_run
    run_doc = _pick_document(selected_documents, "run.json")
    parsed_run_doc = _parse_document_json(run_doc, label="run.json")
    if run_value is None:
        if parsed_run_doc is None:
            _fail(ReasonCode.partial)
        run_value = parsed_run_doc
    if isinstance(run_value, RunMetadata):
        metadata = run_value
    elif isinstance(run_value, Mapping):
        metadata = _run_from_mapping(run_value)
    else:
        _fail(ReasonCode.invalid_metadata)
    if metadata.state == "running":
        _fail(ReasonCode.partial)
    return metadata, selected_documents, source_artifacts


def _artifact_states(
    artifacts: Sequence[LogicalArtifact],
    *,
    step_count: int,
) -> dict[str, _ArtifactState]:
    states: dict[str, _ArtifactState] = {}
    for artifact in artifacts:
        if artifact.logical_path.rsplit("/", 1)[-1] in _SOURCE_BASENAMES:
            continue
        if artifact.artifact_id in states:
            _fail(ReasonCode.invalid_metadata)
        owner = artifact.owner_step_id
        if isinstance(owner, int) and owner < 0:
            _fail(ReasonCode.invalid_metadata)
        states[artifact.artifact_id] = _ArtifactState(
            artifact.artifact_id,
            artifact.media_type,
            artifact.sha256,
            artifact.byte_size,
            owner,
            logical_path=artifact.logical_path,
        )
    return states


def _resolve_artifact_owners(
    artifacts: Mapping[str, _ArtifactState], mapped: Sequence[_MappedStep]
) -> None:
    """Resolve logical source identities only when they name one step."""

    identities: dict[str, list[int]] = {}
    for step_id, step in enumerate(mapped, start=1):
        if step.source_identity is not None:
            identities.setdefault(step.source_identity, []).append(step_id)
    for artifact in artifacts.values():
        owner = artifact.owner_step_id
        if isinstance(owner, str):
            candidates = identities.get(owner, [])
            if len(candidates) != 1:
                _fail(ReasonCode.invalid_metadata)
            artifact.owner_step_id = candidates[0]
        elif isinstance(owner, int):
            if owner < 1 or owner > len(mapped):
                _fail(ReasonCode.invalid_metadata)
        else:
            _fail(ReasonCode.invalid_metadata)


def _attach_referenced_artifacts(
    steps: Sequence[dict[str, Any]], artifacts: Mapping[str, _ArtifactState]
) -> None:
    for artifact in artifacts.values():
        if not artifact.referenced or not isinstance(artifact.owner_step_id, int):
            continue
        owner = steps[artifact.owner_step_id - 1]
        coqui = owner.setdefault("extra", {}).setdefault("coquic", {})
        references = coqui.setdefault("artifactIds", [])
        if artifact.artifact_id not in references:
            references.append(artifact.artifact_id)


def _retained_artifact_components(
    artifacts: Mapping[str, _ArtifactState],
) -> tuple[PublicBundleComponent, ...]:
    """Pair decoded payloads with their resolved logical descriptors."""

    components: list[PublicBundleComponent] = []
    for item in sorted(artifacts.values(), key=lambda value: value.artifact_id):
        if item.backing is None:
            continue
        if not item.referenced or not isinstance(item.owner_step_id, int):
            _fail(ReasonCode.invalid_metadata)
        logical_path = item.logical_path or _inline_image_path(item.artifact_id, item.media_type)
        descriptor = LogicalArtifact(
            item.artifact_id,
            logical_path,
            item.media_type,
            item.byte_size,
            item.sha256,
            owner_step_id=item.owner_step_id,
        )
        components.append(PublicBundleComponent(descriptor, item.backing))
    return tuple(components)


def _source_facts(
    records: Sequence[Mapping[str, Any]],
    activities: Sequence[Mapping[str, Any]],
    telemetry: Mapping[str, Any] | None,
    run_document: Mapping[str, Any] | None,
    *,
    activity_state: str = "available",
) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "codex": {"recordCount": len(records), "recordTypes": sorted({_record_type(item, _item(item)) for item in records})},
    }
    if activity_state == "unavailable":
        facts["activities"] = {"availability": "unavailable"}
    elif activities:
        events = []
        raw_envelope = activities[0].get("record_type") != "header"
        if raw_envelope:
            for index, record in enumerate(activities):
                item = record.get("item")
                event = _record_provenance(index, record, item)
                event["recordType"] = record["type"]
                marker = _activity_marker(item.get("text")) if isinstance(item, Mapping) else None
                if marker is not None:
                    event["activity"], event["summary"] = marker
                events.append(_safe_source(event))
        else:
            for index, record in enumerate(activities):
                record_type = record.get("record_type", record.get("type"))
                if record_type == "event":
                    event = {"recordIndex": index}
                    for key in ("sequence", "source_event_id", "stage", "activity", "summary", "recorded_at"):
                        if key in record:
                            event[{"source_event_id": "sourceEventId", "recorded_at": "recordedAt"}.get(key, key)] = record[key]
                    events.append(_safe_source(event))
        facts["activities"] = {"recordCount": len(activities), "events": events}
    else:
        facts["activities"] = {"availability": "available", "recordCount": 0, "events": []}
    facts["telemetry"] = _telemetry_public(telemetry)
    if run_document is not None:
        selected = {key: run_document[key] for key in ("role", "state", "roleOrdinal", "result", "exit") if key in run_document}
        # Exit reasons and result summaries are evidence, but not private paths.
        if isinstance(selected.get("result"), Mapping):
            selected["result"] = {key: selected["result"][key] for key in ("status", "summary") if key in selected["result"]}
        if isinstance(selected.get("exit"), Mapping):
            selected["exit"] = {key: selected["exit"][key] for key in ("code", "signal") if key in selected["exit"]}
        facts["run"] = _safe_source(selected)
    return facts


def _metric(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(ReasonCode.invalid_metadata)
    return value


def _validate_telemetry_aggregate(value: object, *, turns_present: bool) -> dict[str, int | None]:
    if not isinstance(value, Mapping):
        _fail(ReasonCode.invalid_metadata)
    allowed = {
        "completed_turns",
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "total_tokens",
    }
    if set(value) - allowed:
        _fail(ReasonCode.invalid_metadata)
    aggregate = {key: _metric(value.get(key)) for key in allowed if key in value}
    input_tokens = aggregate.get("input_tokens")
    cached = aggregate.get("cached_input_tokens")
    uncached = aggregate.get("uncached_input_tokens")
    output_tokens = aggregate.get("output_tokens")
    reasoning = aggregate.get("reasoning_output_tokens")
    total = aggregate.get("total_tokens")
    if input_tokens is not None and cached is not None and cached > input_tokens:
        _fail(ReasonCode.invalid_metadata)
    if input_tokens is not None and cached is not None and uncached is not None and uncached != input_tokens - cached:
        _fail(ReasonCode.invalid_metadata)
    if output_tokens is not None and reasoning is not None and reasoning > output_tokens:
        _fail(ReasonCode.invalid_metadata)
    if input_tokens is not None and output_tokens is not None and total is not None and total != input_tokens + output_tokens:
        _fail(ReasonCode.invalid_metadata)
    if turns_present and set(value) != allowed:
        _fail(ReasonCode.invalid_metadata)
    return aggregate


def _validate_telemetry(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate the documented telemetry sidecar without importing its writer."""

    availability = value.get("availability")
    if availability == "unavailable":
        if set(value) - {"availability", "reason"}:
            _fail(ReasonCode.invalid_metadata)
        reason = value.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason or len(reason) > 256):
            _fail(ReasonCode.invalid_metadata)
        return value
    if availability is not None and availability != "available":
        _fail(ReasonCode.invalid_metadata)
    if value.get("schema_version") != 1:
        _fail(ReasonCode.invalid_metadata)
    provenance = value.get("provenance")
    if not isinstance(provenance, str) or not provenance or len(provenance) > 128:
        _fail(ReasonCode.invalid_metadata)
    completeness = value.get("completeness")
    if completeness != "complete":
        _fail(ReasonCode.partial if completeness == "partial" else ReasonCode.invalid_metadata)

    full_sidecar = any(
        key in value
        for key in (
            "invocation_id",
            "started_at",
            "completed_at",
            "duration_ms",
            "process_outcome",
            "billing_mode",
            "issues",
        )
    )
    if full_sidecar and "turns" not in value:
        _fail(ReasonCode.invalid_metadata)
    for key in ("invocation_id", "task_id", "run_name", "stage", "process_outcome"):
        if key in value and (not isinstance(value[key], str) or not value[key] or len(value[key]) > 256):
            _fail(ReasonCode.invalid_metadata)
    if "retry_ordinal" in value and _metric(value["retry_ordinal"]) is None:
        _fail(ReasonCode.invalid_metadata)
    for key in ("configured_model", "reasoning_effort"):
        if key in value and value[key] is not None and not isinstance(value[key], str):
            _fail(ReasonCode.invalid_metadata)
    if "billing_mode" in value and value["billing_mode"] not in {"unknown", "chatgpt", "api"}:
        _fail(ReasonCode.invalid_metadata)

    timing_keys = {"started_at", "completed_at", "duration_ms", "first_agent_message_completed_ms"}
    if timing_keys.intersection(value):
        if not timing_keys.issubset(value):
            _fail(ReasonCode.invalid_metadata)
        started = _timestamp(value["started_at"])
        completed = _timestamp(value["completed_at"])
        if started is None or completed is None:
            _fail(ReasonCode.invalid_metadata)
        duration = _metric(value["duration_ms"])
        first = _metric(value["first_agent_message_completed_ms"])
        if duration is None or completed < started:
            _fail(ReasonCode.invalid_metadata)
        if first is not None and first > duration:
            _fail(ReasonCode.invalid_metadata)

    turns_present = "turns" in value
    if turns_present:
        turns = value.get("turns")
        if not isinstance(turns, list) or len(turns) > _MAX_RECORDS:
            _fail(ReasonCode.invalid_metadata)
        for ordinal, turn in enumerate(turns, start=1):
            if not isinstance(turn, Mapping):
                _fail(ReasonCode.invalid_metadata)
            required = {
                "ordinal",
                "input_tokens",
                "cached_input_tokens",
                "uncached_input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
                "total_tokens",
            }
            if set(turn) != required or turn.get("ordinal") != ordinal:
                _fail(ReasonCode.invalid_metadata)
            input_tokens = _metric(turn.get("input_tokens"))
            cached = _metric(turn.get("cached_input_tokens"))
            uncached = _metric(turn.get("uncached_input_tokens"))
            output_tokens = _metric(turn.get("output_tokens"))
            reasoning = _metric(turn.get("reasoning_output_tokens"))
            total = _metric(turn.get("total_tokens"))
            if input_tokens is None or cached is None or uncached is None or output_tokens is None or reasoning is None or total is None:
                _fail(ReasonCode.invalid_metadata)
            if cached > input_tokens or uncached != input_tokens - cached or reasoning > output_tokens or total != input_tokens + output_tokens:
                _fail(ReasonCode.invalid_metadata)
    if "aggregate" not in value:
        _fail(ReasonCode.invalid_metadata)
    aggregate = _validate_telemetry_aggregate(value["aggregate"], turns_present=turns_present)
    if turns_present:
        expected = {
            "completed_turns": len(value["turns"]),
            "input_tokens": sum(int(turn["input_tokens"]) for turn in value["turns"]),
            "cached_input_tokens": sum(int(turn["cached_input_tokens"]) for turn in value["turns"]),
            "uncached_input_tokens": sum(int(turn["uncached_input_tokens"]) for turn in value["turns"]),
            "output_tokens": sum(int(turn["output_tokens"]) for turn in value["turns"]),
            "reasoning_output_tokens": sum(int(turn["reasoning_output_tokens"]) for turn in value["turns"]),
            "total_tokens": sum(int(turn["total_tokens"]) for turn in value["turns"]),
        }
        if aggregate != expected:
            _fail(ReasonCode.invalid_metadata)

    cost = value.get("cost")
    if not isinstance(cost, Mapping) or cost.get("status") not in {"estimated", "unavailable"}:
        _fail(ReasonCode.invalid_metadata)
    if cost["status"] == "estimated":
        micro_usd = _metric(cost.get("micro_usd"))
        if micro_usd is None:
            _fail(ReasonCode.invalid_metadata)
    elif "micro_usd" in cost and cost.get("micro_usd") is not None:
        _fail(ReasonCode.invalid_metadata)
    if "reason" in cost and (not isinstance(cost["reason"], str) or not cost["reason"] or len(cost["reason"]) > 256):
        _fail(ReasonCode.invalid_metadata)
    if "issues" in value:
        issues = value["issues"]
        if not isinstance(issues, list) or len(issues) > 32:
            _fail(ReasonCode.invalid_metadata)
        for issue in issues:
            if (
                not isinstance(issue, Mapping)
                or set(issue) != {"category", "count"}
                or not isinstance(issue.get("category"), str)
                or not issue["category"]
                or len(issue["category"]) > 80
                or _metric(issue.get("count")) is None
            ):
                _fail(ReasonCode.invalid_metadata)
    return value


def _telemetry_public(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None or value.get("availability") == "unavailable":
        result: dict[str, Any] = {"availability": "unavailable"}
        if isinstance(value, Mapping) and isinstance(value.get("reason"), str):
            result["reason"] = value["reason"]
        return result
    result = {
        "availability": "available",
        "provenance": value["provenance"],
        "completeness": value["completeness"],
    }
    for source_key in ("started_at", "completed_at", "duration_ms", "first_agent_message_completed_ms", "process_outcome", "configured_model", "reasoning_effort", "billing_mode"):
        if source_key in value and value[source_key] is not None:
            result[source_key] = value[source_key]
    aggregate = value.get("aggregate")
    if isinstance(aggregate, Mapping):
        usage = {
            output_key: aggregate[input_key]
            for input_key, output_key in (
                ("input_tokens", "prompt"),
                ("cached_input_tokens", "cached"),
                ("uncached_input_tokens", "uncached"),
                ("output_tokens", "completion"),
                ("reasoning_output_tokens", "reasoning"),
                ("total_tokens", "total"),
                ("completed_turns", "turns"),
            )
            if input_key in aggregate and aggregate[input_key] is not None
        }
        result["aggregate"] = {"usage": usage}
    turns = value.get("turns")
    if isinstance(turns, list):
        result["turns"] = [
            {
                "ordinal": turn["ordinal"],
                "input": turn["input_tokens"],
                "cached": turn["cached_input_tokens"],
                "uncached": turn["uncached_input_tokens"],
                "output": turn["output_tokens"],
                "reasoning": turn["reasoning_output_tokens"],
                "total": turn["total_tokens"],
            }
            for turn in turns
        ]
    cost = value.get("cost")
    if isinstance(cost, Mapping):
        public_cost = {
            key: cost[key]
            for key in ("status", "micro_usd", "reason")
            if key in cost and cost[key] is not None
        }
        price_entry = cost.get("price_entry")
        if isinstance(price_entry, Mapping):
            public_entry = {
                key: price_entry[key]
                for key in ("entry_id", "model", "effective_from", "effective_until")
                if key in price_entry and price_entry[key] is not None
            }
            source = price_entry.get("source")
            if isinstance(source, Mapping) and isinstance(source.get("label"), str):
                public_entry["source"] = {"label": source["label"]}
            if public_entry:
                public_cost["price_entry"] = public_entry
        result["cost"] = public_cost
    issues = value.get("issues")
    if isinstance(issues, list):
        result["issues"] = [
            {"category": item["category"], "count": item["count"]}
            for item in issues
            if isinstance(item, Mapping) and isinstance(item.get("category"), str) and isinstance(item.get("count"), int)
        ]
    return _safe_source(result)


def _validate_telemetry_against_run(metadata: RunMetadata, telemetry: Mapping[str, Any]) -> None:
    if telemetry.get("availability") == "unavailable":
        return
    aggregate = telemetry.get("aggregate")
    if not isinstance(aggregate, Mapping) or metadata.usage is None:
        return
    for name, keys in (
        ("prompt_tokens", ("input_tokens", "prompt_tokens")),
        ("completion_tokens", ("output_tokens", "completion_tokens")),
        ("cached_input_tokens", ("cached_input_tokens", "cached_tokens")),
        ("reasoning_output_tokens", ("reasoning_output_tokens",)),
        ("total_tokens", ("total_tokens",)),
    ):
        expected = getattr(metadata.usage, name)
        for key in keys:
            if key in aggregate and aggregate[key] is not None:
                if expected is not None and aggregate[key] != expected:
                    _fail(ReasonCode.invalid_metadata)
                break


def _final_metrics(metadata: RunMetadata, telemetry: Mapping[str, Any] | None, step_count: int) -> dict[str, Any] | None:
    usage = metadata.usage
    aggregate = telemetry.get("aggregate") if isinstance(telemetry, Mapping) else None
    if usage is None and isinstance(aggregate, Mapping):
        usage = UsageSummary(
            prompt_tokens=_optional_counter(aggregate, "input_tokens", "prompt_tokens"),
            completion_tokens=_optional_counter(aggregate, "output_tokens", "completion_tokens"),
            total_tokens=_optional_counter(aggregate, "total_tokens"),
            cached_input_tokens=_optional_counter(aggregate, "cached_input_tokens"),
            reasoning_output_tokens=_optional_counter(aggregate, "reasoning_output_tokens"),
        )
    values: dict[str, Any] = {"total_steps": step_count}
    usage_values: dict[str, Any] = {}
    if usage is not None:
        for field_name, output_name in (
            ("prompt_tokens", "total_prompt_tokens"),
            ("completion_tokens", "total_completion_tokens"),
            ("cached_input_tokens", "total_cached_tokens"),
        ):
            value = getattr(usage, field_name)
            if value is not None:
                usage_values[{"total_prompt_tokens": "prompt", "total_completion_tokens": "completion", "total_cached_tokens": "cached"}[output_name]] = value
        if usage.reasoning_output_tokens is not None:
            usage_values["reasoning"] = usage.reasoning_output_tokens
        if usage.total_tokens is not None:
            usage_values["total"] = usage.total_tokens
    if isinstance(telemetry, Mapping):
        cost = telemetry.get("cost")
        if isinstance(cost, Mapping) and cost.get("status") == "estimated" and isinstance(cost.get("micro_usd"), int):
            usage_values["costUsd"] = cost["micro_usd"] / 1_000_000
    if usage_values:
        values["extra"] = {"usage": usage_values}
    return values or None


def _root_document(
    metadata: RunMetadata,
    steps: list[dict[str, Any]],
    artifacts: Mapping[str, _ArtifactState],
    source_facts: Mapping[str, Any],
    telemetry: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if any(not item.referenced for item in artifacts.values()):
        # Every logical descriptor must have an owning step reference.  Attach
        # otherwise-unreferenced archive artifacts to their declared owner.
        for item in artifacts.values():
            if not item.referenced:
                item.referenced = True
                owner = steps[item.owner_step_id - 1]
                coqui = owner.setdefault("extra", {}).setdefault("coquic", {})
                refs = coqui.setdefault("artifactIds", [])
                if item.artifact_id not in refs:
                    refs.append(item.artifact_id)
    provenance: dict[str, Any] = {
        **metadata.identity.as_dict(),
        "role": metadata.role,
        "startedAt": metadata.started_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "completedAt": metadata.completed_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "durationMs": metadata.duration_ms,
        "disclosure": {"redactionApplied": False, "originalRetained": True},
        "artifacts": [
            {
                "artifactId": item.artifact_id,
                "mediaType": item.media_type,
                "sha256": item.sha256,
                "byteSize": item.byte_size,
                "ownerStepId": item.owner_step_id,
            }
            for item in artifacts.values()
        ],
        "source": dict(source_facts),
    }
    lineage = metadata.lineage.as_dict()
    if any(value is not None for value in lineage.values()):
        provenance["lineage"] = lineage
    if metadata.model is not None:
        provenance["model"] = metadata.model
    if metadata.reasoning is not None:
        provenance["reasoning"] = metadata.reasoning
    document: dict[str, Any] = {
        "schema_version": ATIF_SCHEMA_VERSION,
        "agent": {"name": "coquic-steward", "version": "1", **({"model_name": metadata.model} if metadata.model else {})},
        "session_id": metadata.identity.run_id,
        "steps": steps,
        "extra": {"coquic": provenance},
    }
    metrics = _final_metrics(metadata, telemetry, len(steps))
    if metrics:
        document["final_metrics"] = metrics
    return document


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[4] / "contracts" / "steward-cloud" / "atif-v1.7.schema.json"


def _semantic_issues(document: Mapping[str, Any]) -> list[str]:
    issues: list[str] = []
    if document.get("schema_version") != ATIF_SCHEMA_VERSION:
        issues.append("root-schema-version")
    steps = document.get("steps")
    if not isinstance(steps, list) or [item.get("step_id") for item in steps if isinstance(item, Mapping)] != list(range(1, len(steps) + 1)):
        issues.append("step-sequence")
    calls: set[str] = set()
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            for call in step.get("tool_calls", ()) if isinstance(step.get("tool_calls"), list) else ():
                if not isinstance(call, Mapping) or not isinstance(call.get("tool_call_id"), str) or not call.get("tool_call_id"):
                    issues.append("tool-call-id")
                elif call["tool_call_id"] in calls:
                    issues.append("tool-call-unique")
                else:
                    calls.add(call["tool_call_id"])
            observation = step.get("observation")
            if isinstance(observation, Mapping):
                for result in observation.get("results", ()) if isinstance(observation.get("results"), list) else ():
                    if isinstance(result, Mapping) and result.get("source_call_id") is not None and result.get("source_call_id") not in calls:
                        issues.append("observation-reference")
    extra = document.get("extra")
    coqui = extra.get("coquic") if isinstance(extra, Mapping) else None
    if not isinstance(coqui, Mapping):
        issues.append("provenance-shape")
        return issues
    required = {"taskId", "pipelineId", "runId", "role", "startedAt", "completedAt", "durationMs", "disclosure", "artifacts"}
    issues.extend(f"provenance-field:{field}" for field in sorted(required - set(coqui)))
    disclosure = coqui.get("disclosure")
    if not isinstance(disclosure, Mapping) or set(disclosure) != {"redactionApplied", "originalRetained"} or any(type(disclosure.get(key)) is not bool for key in disclosure):
        issues.append("disclosure")
    artifacts = coqui.get("artifacts")
    artifact_map: dict[str, Mapping[str, Any]] = {}
    if not isinstance(artifacts, list):
        issues.append("artifact-shape")
    else:
        step_ids = {step.get("step_id") for step in steps if isinstance(step, Mapping)} if isinstance(steps, list) else set()
        referenced: set[str] = set()
        for item in artifacts:
            if not isinstance(item, Mapping) or set(item) != {"artifactId", "mediaType", "sha256", "byteSize", "ownerStepId"}:
                issues.append("artifact-shape")
                continue
            artifact_id = item.get("artifactId")
            artifact_map[str(artifact_id)] = item
            if not isinstance(artifact_id, str) or not _ID_RE.fullmatch(artifact_id):
                issues.append("artifact-id")
            if not isinstance(item.get("sha256"), str) or not _DIGEST_RE.fullmatch(item.get("sha256", "")):
                issues.append("artifact-digest")
            if not isinstance(item.get("byteSize"), int) or isinstance(item.get("byteSize"), bool) or item.get("byteSize", -1) < 0:
                issues.append("artifact-size")
            if item.get("ownerStepId") not in step_ids:
                issues.append("artifact-owner")
        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, Mapping):
                    continue
                step_coqui = step.get("extra", {}).get("coquic") if isinstance(step.get("extra"), Mapping) else None
                for ref in step_coqui.get("artifactIds", ()) if isinstance(step_coqui, Mapping) and isinstance(step_coqui.get("artifactIds"), list) else ():
                    if ref not in artifact_map:
                        issues.append("artifact-reference")
                    else:
                        referenced.add(ref)
                        if artifact_map[ref].get("ownerStepId") != step.get("step_id"):
                            issues.append("artifact-owner")
                _collect_image_refs(step.get("message"), artifact_map, referenced, issues, step_id=step.get("step_id"))
                observation = step.get("observation")
                if isinstance(observation, Mapping):
                    for result in observation.get("results", ()) if isinstance(observation.get("results"), list) else ():
                        if isinstance(result, Mapping):
                            _collect_image_refs(
                                result.get("content"),
                                artifact_map,
                                referenced,
                                issues,
                                step_id=step.get("step_id"),
                            )
        issues.extend("artifact-unreferenced" for artifact_id in artifact_map if artifact_id not in referenced)
    _semantic_private_scan(document, issues)
    return issues


def _collect_image_refs(
    value: Any,
    artifacts: Mapping[str, Mapping[str, Any]],
    referenced: set[str],
    issues: list[str],
    *,
    step_id: Any,
) -> None:
    if not isinstance(value, list):
        return
    for part in value:
        if not isinstance(part, Mapping) or part.get("type") != "image":
            continue
        source = part.get("source")
        if not isinstance(source, Mapping) or source.get("media_type") not in SUPPORTED_IMAGE_MEDIA_TYPES:
            issues.append("media-type")
        path = source.get("path") if isinstance(source, Mapping) else None
        if not isinstance(path, str) or not path.startswith("artifact:"):
            issues.append("artifact-reference")
            continue
        artifact_id = path.removeprefix("artifact:")
        if artifact_id not in artifacts:
            issues.append("artifact-reference")
        else:
            referenced.add(artifact_id)
            if artifacts[artifact_id].get("ownerStepId") != step_id:
                issues.append("artifact-owner")


def _semantic_private_scan(value: Any, issues: list[str], key: str | None = None) -> None:
    if key is not None and _private_key(key):
        issues.append("private-field")
        return
    if _private_value(value, key=key):
        issues.append("private-locator")
        return
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            _semantic_private_scan(child, issues, str(child_key))
    elif isinstance(value, list):
        for child in value:
            _semantic_private_scan(child, issues, key)


def validate_atif_document(document: Mapping[str, Any]) -> None:
    """Validate Harbor structure and CoQUIC cross-field semantics."""

    if isinstance(document, AtifDocument):
        document = document.document
    if not isinstance(document, Mapping):
        _fail(ReasonCode.invalid_metadata)
    try:
        validator = Draft202012Validator(json.loads(_schema_path().read_text(encoding="utf-8")))
        schema_errors = list(validator.iter_errors(document))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        _fail(ReasonCode.invalid_metadata)
    semantic = _semantic_issues(document)
    if schema_errors or semantic:
        _fail(ReasonCode.invalid_metadata)


def convert_completed_run(
    source: Any = None,
    *,
    snapshot: Any = None,
    run: Any = None,
    documents: Any = None,
    codex: Any = _MISSING,
    activities: Any = _MISSING,
    telemetry: Any = _MISSING,
    run_document: Any = _MISSING,
    artifacts: Any = None,
) -> AtifDocument:
    """Convert one complete terminal run into validated canonical ATIF bytes."""

    metadata, source_documents, source_artifacts = _coerce_source(
        source,
        snapshot=snapshot,
        run=run,
        documents=documents,
        codex=codex,
        activities=activities,
        telemetry=telemetry,
        run_document=run_document,
        artifacts=artifacts,
    )
    required_documents = ("codex.jsonl", "activities.jsonl", "telemetry.json", "run.json")
    selected_values = {name: _pick_document(source_documents, name) for name in required_documents}
    codex_value = selected_values["codex.jsonl"]
    if codex_value is _MISSING:
        _fail(ReasonCode.partial)
    records = _parse_document_jsonl(codex_value, label="codex.jsonl")
    activity_value = selected_values["activities.jsonl"]
    activity_records, activity_state = (
        _parse_activity_document(
            activity_value,
            expected_transcript_sha256=hashlib.sha256(_document_content(codex_value)).hexdigest(),
        )
        if activity_value is not _MISSING
        else ((), "unavailable")
    )
    telemetry_document = selected_values["telemetry.json"]
    telemetry_value = (
        _parse_document_json(telemetry_document, label="telemetry.json")
        if telemetry_document is not _MISSING
        else None
    )
    if telemetry_value is not None:
        telemetry_value = dict(_validate_telemetry(telemetry_value))
    run_document = selected_values["run.json"]
    run_doc = (
        _parse_document_json(run_document, label="run.json")
        if run_document is not _MISSING
        else None
    )
    if any(value is _MISSING for value in selected_values.values()) or telemetry_value is None or run_doc is None:
        _fail(ReasonCode.partial)
    # A supplied run.json is a second immutable identity witness.  It may add
    # evidence, but cannot turn a partial/running source into a completed one.
    if run_doc is not None:
        state = run_doc.get("state")
        if any(key not in run_doc for key in ("taskId", "pipelineId", "runId", "state", "startedAt", "completedAt")):
            _fail(ReasonCode.partial)
        if state == "running" or run_doc.get("completedAt") is None:
            _fail(ReasonCode.partial)
        _timestamp(run_doc.get("startedAt"))
        _timestamp(run_doc.get("completedAt"))
        for key, expected in (("taskId", metadata.identity.task_id), ("pipelineId", metadata.identity.pipeline_id), ("runId", metadata.identity.run_id)):
            if key in run_doc and run_doc[key] != expected:
                _fail(ReasonCode.invalid_metadata)
        if "role" in run_doc and run_doc["role"] != metadata.role:
            _fail(ReasonCode.invalid_metadata)
        document_state = run_doc.get("state")
        normalized_states = {"succeeded": "succeeded", "completed": "succeeded", "pushed": "succeeded", "no_changes": "succeeded", "failed": "failed", "cancelled": "cancelled", "blocked": "blocked", "interrupted": "failed"}
        if isinstance(document_state, str) and normalized_states.get(document_state) != normalized_states.get(metadata.state):
            _fail(ReasonCode.invalid_metadata)
        if "startedAt" in run_doc and _timestamp(run_doc["startedAt"]) != metadata.started_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"):
            _fail(ReasonCode.invalid_metadata)
        if "completedAt" in run_doc and _timestamp(run_doc["completedAt"]) != metadata.completed_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"):
            _fail(ReasonCode.invalid_metadata)
        if "durationMs" in run_doc and run_doc["durationMs"] != metadata.duration_ms:
            _fail(ReasonCode.invalid_metadata)
    _validate_telemetry_against_run(metadata, telemetry_value)
    states = _artifact_states(source_artifacts, step_count=1)
    steps, _calls, _unpaired, mapped_steps = _map_steps(records, artifacts=states)
    # Resolve source identities after mapping, when contiguous step IDs are final.
    # ``_map_steps`` retains source identities internally for this purpose.
    _resolve_artifact_owners(states, mapped_steps)
    _attach_referenced_artifacts(steps, states)
    for step in steps:
        coqui = step.get("extra", {}).get("coquic") if isinstance(step.get("extra"), Mapping) else None
        if isinstance(coqui, Mapping):
            refs = [ref for ref in coqui.get("artifactIds", []) if ref in states]
            coqui["artifactIds"] = refs
    source_facts = _source_facts(
        records,
        activity_records,
        telemetry_value,
        run_doc,
        activity_state=activity_state,
    )
    document = _root_document(metadata, steps, states, source_facts, telemetry_value)
    validate_atif_document(document)
    content = canonical_atif_bytes(document)
    # Validate the exact bytes as a final guard against a non-canonical custom
    # mapping implementation or a future serializer change.
    parsed = _parse_json_bytes(content)
    if parsed != document:
        _fail(ReasonCode.invalid_metadata)
    return AtifDocument(document, content, artifacts=_retained_artifact_components(states))


def convert_run(*args: Any, **kwargs: Any) -> AtifDocument:
    return convert_completed_run(*args, **kwargs)


def to_atif(*args: Any, **kwargs: Any) -> AtifDocument:
    return convert_completed_run(*args, **kwargs)


def map_completed_run(*args: Any, **kwargs: Any) -> AtifDocument:
    return convert_completed_run(*args, **kwargs)


def convert_snapshot(*args: Any, **kwargs: Any) -> AtifDocument:
    return convert_completed_run(*args, **kwargs)


def build_atif(*args: Any, **kwargs: Any) -> AtifDocument:
    return convert_completed_run(*args, **kwargs)


__all__ = [
    "ATIF_SCHEMA_VERSION",
    "SUPPORTED_IMAGE_MEDIA_TYPES",
    "AtifConversionError",
    "AtifSource",
    "CompletedRun",
    "CompletedRunSnapshot",
    "canonical_atif_bytes",
    "convert_completed_run",
    "convert_run",
    "convert_snapshot",
    "build_atif",
    "map_completed_run",
    "to_atif",
    "validate_atif_document",
]

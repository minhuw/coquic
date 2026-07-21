"""Private Codex ``exec --json`` usage telemetry.

The telemetry producer is deliberately independent from the transcript and
from the public monitor schema.  It only accepts fields documented in Codex's
JSONL ``turn.completed`` usage envelope and treats everything else as
unavailable evidence.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from urllib.parse import urlsplit
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4


TELEMETRY_SCHEMA_VERSION = 1
TELEMETRY_PROVENANCE = "codex_exec_jsonl"
TELEMETRY_MAX_SIDECAR_BYTES = 512 * 1024
TELEMETRY_MAX_TURNS = 4096
TELEMETRY_MAX_ISSUES = 32
TELEMETRY_MAX_ISSUE_CATEGORY_BYTES = 80
TELEMETRY_MAX_MODEL_BYTES = 256
TELEMETRY_MAX_STAGE_BYTES = 80
TELEMETRY_MAX_TASK_ID_BYTES = 160
TELEMETRY_MAX_RUN_NAME_BYTES = 160
TELEMETRY_MAX_SOURCE_LABEL_BYTES = 160
TELEMETRY_MAX_SOURCE_URL_BYTES = 512
_UTC = timezone.utc
_MODEL_RE = re.compile(r"^[^\x00\r\n]{1,256}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


class BillingMode(StrEnum):
    unknown = "unknown"
    chatgpt = "chatgpt"
    api = "api"


class TelemetryCompleteness(StrEnum):
    complete = "complete"
    partial = "partial"
    unavailable = "unavailable"


class CostStatus(StrEnum):
    estimated = "estimated"
    unavailable = "unavailable"


@dataclass(frozen=True)
class TelemetryTurn:
    """One validated ``turn.completed`` usage record."""

    ordinal: int
    input_tokens: int
    cached_input_tokens: int
    uncached_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int
    total_tokens: int

    @classmethod
    def from_usage(cls, usage: object, *, ordinal: int = 1) -> "TelemetryTurn":
        if type(ordinal) is not int or ordinal < 1:
            raise ValueError("invalid turn ordinal")
        if not isinstance(usage, dict):
            raise ValueError("usage must be an object")
        required = (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        )
        if set(usage) != set(required):
            raise ValueError("usage keys")
        values: dict[str, int] = {}
        for key in required:
            value = usage.get(key)
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid {key}")
            values[key] = value
        if values["cached_input_tokens"] > values["input_tokens"]:
            raise ValueError("cached input exceeds input")
        if values["reasoning_output_tokens"] > values["output_tokens"]:
            raise ValueError("reasoning output exceeds output")
        return cls(
            ordinal=ordinal,
            input_tokens=values["input_tokens"],
            cached_input_tokens=values["cached_input_tokens"],
            uncached_input_tokens=values["input_tokens"]
            - values["cached_input_tokens"],
            output_tokens=values["output_tokens"],
            reasoning_output_tokens=values["reasoning_output_tokens"],
            total_tokens=values["input_tokens"] + values["output_tokens"],
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "ordinal": self.ordinal,
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "uncached_input_tokens": self.uncached_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_output_tokens": self.reasoning_output_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True)
class TelemetryAggregate:
    completed_turns: int = 0
    input_tokens: int = 0
    cached_input_tokens: int = 0
    uncached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_output_tokens: int = 0
    total_tokens: int = 0

    @classmethod
    def from_turns(cls, turns: Iterable[TelemetryTurn]) -> "TelemetryAggregate":
        selected = list(turns)
        return cls(
            completed_turns=len(selected),
            input_tokens=sum(item.input_tokens for item in selected),
            cached_input_tokens=sum(item.cached_input_tokens for item in selected),
            uncached_input_tokens=sum(item.uncached_input_tokens for item in selected),
            output_tokens=sum(item.output_tokens for item in selected),
            reasoning_output_tokens=sum(
                item.reasoning_output_tokens for item in selected
            ),
            total_tokens=sum(item.total_tokens for item in selected),
        )

    @classmethod
    def from_dict(cls, value: object) -> "TelemetryAggregate":
        if not isinstance(value, dict):
            raise ValueError("aggregate must be an object")
        keys = (
            "completed_turns",
            "input_tokens",
            "cached_input_tokens",
            "uncached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
            "total_tokens",
        )
        parsed: dict[str, int] = {}
        for key in keys:
            number = value.get(key)
            if type(number) is not int or number < 0:
                raise ValueError(f"invalid aggregate {key}")
            parsed[key] = number
        if parsed["cached_input_tokens"] > parsed["input_tokens"]:
            raise ValueError("aggregate cached input exceeds input")
        if parsed["uncached_input_tokens"] != (
            parsed["input_tokens"] - parsed["cached_input_tokens"]
        ):
            raise ValueError("aggregate uncached input mismatch")
        if parsed["reasoning_output_tokens"] > parsed["output_tokens"]:
            raise ValueError("aggregate reasoning exceeds output")
        if parsed["total_tokens"] != parsed["input_tokens"] + parsed["output_tokens"]:
            raise ValueError("aggregate total mismatch")
        return cls(**parsed)

    def to_dict(self) -> dict[str, int]:
        return {
            "completed_turns": self.completed_turns,
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "uncached_input_tokens": self.uncached_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_output_tokens": self.reasoning_output_tokens,
            "total_tokens": self.total_tokens,
        }

    def add(self, other: "TelemetryAggregate") -> "TelemetryAggregate":
        return TelemetryAggregate(
            completed_turns=self.completed_turns + other.completed_turns,
            input_tokens=self.input_tokens + other.input_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
            uncached_input_tokens=self.uncached_input_tokens
            + other.uncached_input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            reasoning_output_tokens=self.reasoning_output_tokens
            + other.reasoning_output_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


@dataclass(frozen=True)
class PriceEntry:
    entry_id: str
    model: str
    effective_from: datetime
    effective_until: datetime | None
    input_micro_usd_per_million: int
    cached_input_micro_usd_per_million: int
    output_micro_usd_per_million: int
    source_label: str
    source_url: str

    def covers(self, model: str, when: datetime) -> bool:
        return self.model == model and self.effective_from <= when and (
            self.effective_until is None or when < self.effective_until
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "entry_id": self.entry_id,
            "model": self.model,
            "effective_from": _format_utc(self.effective_from),
            "effective_until": (
                _format_utc(self.effective_until)
                if self.effective_until is not None
                else None
            ),
            "source": {"label": self.source_label, "url": self.source_url},
        }


@dataclass(frozen=True)
class PriceCatalog:
    entries: tuple[PriceEntry, ...] = ()

    @classmethod
    def from_path(cls, path: Path) -> "PriceCatalog":
        if not isinstance(path, Path):
            path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, value: object) -> "PriceCatalog":
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("price catalog schema")
        raw_entries = value.get("entries")
        if not isinstance(raw_entries, list) or len(raw_entries) > 256:
            raise ValueError("price catalog entries")
        entries = tuple(_parse_price_entry(item) for item in raw_entries)
        _reject_price_overlaps(entries)
        return cls(entries=entries)

    @classmethod
    def empty(cls) -> "PriceCatalog":
        return cls(())

    def find(self, model: str | None, when: datetime) -> PriceEntry | None:
        if not isinstance(model, str):
            return None
        when = _as_utc(when)
        return next((entry for entry in self.entries if entry.covers(model, when)), None)


@dataclass(frozen=True)
class CostEstimate:
    status: CostStatus
    reason: str | None = None
    micro_usd: int | None = None
    price_entry: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"status": self.status.value}
        if self.reason is not None:
            result["reason"] = self.reason
        if self.micro_usd is not None:
            result["micro_usd"] = self.micro_usd
        if self.price_entry is not None:
            result["price_entry"] = self.price_entry
        return result


@dataclass(frozen=True)
class TelemetryTiming:
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    first_agent_message_completed_ms: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "started_at": _format_utc(self.started_at),
            "completed_at": _format_utc(self.completed_at),
            "duration_ms": self.duration_ms,
            "first_agent_message_completed_ms": self.first_agent_message_completed_ms,
        }


@dataclass(frozen=True)
class TelemetryCoverage:
    completeness: TelemetryCompleteness
    issues: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "completeness": self.completeness.value,
            "issues": [dict(issue) for issue in self.issues],
        }


@dataclass(frozen=True)
class TelemetryInvocation:
    """Validated invocation envelope for consumers that need a typed model."""

    payload: dict[str, object]

    @classmethod
    def from_dict(cls, value: object) -> "TelemetryInvocation":
        return cls(validate_sidecar(value))

    @property
    def invocation_id(self) -> str:
        return str(self.payload["invocation_id"])

    @property
    def aggregate(self) -> TelemetryAggregate:
        return TelemetryAggregate.from_dict(self.payload["aggregate"])

    def to_dict(self) -> dict[str, object]:
        return json.loads(json.dumps(self.payload))


def estimate_cost(
    aggregate: TelemetryAggregate,
    *,
    billing_mode: str | BillingMode,
    configured_model: str | None,
    started_at: datetime,
    catalog: PriceCatalog | None,
) -> CostEstimate:
    """Estimate API cost using integer micro-USD arithmetic only."""

    try:
        mode = BillingMode(billing_mode)
    except (TypeError, ValueError):
        return CostEstimate(CostStatus.unavailable, "billing_mode_unknown")
    if mode == BillingMode.chatgpt:
        return CostEstimate(CostStatus.unavailable, "chatgpt_cost_unavailable")
    if mode == BillingMode.unknown:
        return CostEstimate(CostStatus.unavailable, "billing_mode_unknown")
    if not isinstance(configured_model, str) or not configured_model:
        return CostEstimate(CostStatus.unavailable, "configured_model_missing")
    if catalog is None:
        return CostEstimate(CostStatus.unavailable, "price_catalog_unavailable")
    entry = catalog.find(configured_model, started_at)
    if entry is None:
        return CostEstimate(CostStatus.unavailable, "price_entry_unmatched")
    micro_usd = (
        _round_micro_usd(
            aggregate.uncached_input_tokens, entry.input_micro_usd_per_million
        )
        + _round_micro_usd(
            aggregate.cached_input_tokens,
            entry.cached_input_micro_usd_per_million,
        )
        + _round_micro_usd(
            aggregate.output_tokens, entry.output_micro_usd_per_million
        )
    )
    return CostEstimate(
        CostStatus.estimated,
        micro_usd=micro_usd,
        price_entry=entry.to_public_dict(),
    )


@dataclass
class TelemetryRecorder:
    """In-memory observer and atomic sidecar writer for one invocation."""

    path: Path
    task_id: str
    run_name: str
    stage: str
    retry_ordinal: int
    configured_model: str | None
    reasoning_effort: str | None
    billing_mode: str | BillingMode = BillingMode.unknown
    catalog: PriceCatalog | None = None
    started_at: datetime | None = None
    started_monotonic_ns: int | None = None
    wall_clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(timezone.utc), repr=False
    )
    monotonic_ns: Callable[[], int] = field(
        default=lambda: __import__("time").monotonic_ns(), repr=False
    )
    invocation_id: str = field(default_factory=lambda: uuid4().hex)
    turns: list[TelemetryTurn] = field(default_factory=list, init=False)
    issues: Counter[str] = field(default_factory=Counter, init=False)
    first_agent_message_completed_ms: int | None = field(default=None, init=False)
    process_outcome: str = field(default="unknown", init=False)
    _finalized: bool = field(default=False, init=False, repr=False)
    _write_succeeded: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.task_id = _bounded_text(self.task_id, TELEMETRY_MAX_TASK_ID_BYTES)
        self.run_name = _bounded_text(self.run_name, TELEMETRY_MAX_RUN_NAME_BYTES)
        self.stage = _bounded_text(self.stage, TELEMETRY_MAX_STAGE_BYTES)
        if type(self.retry_ordinal) is not int or self.retry_ordinal < 0:
            raise ValueError("retry ordinal")
        if not _SAFE_ID_RE.fullmatch(self.invocation_id):
            raise ValueError("invocation id")
        if self.configured_model is not None:
            self.configured_model = _bounded_text(
                self.configured_model, TELEMETRY_MAX_MODEL_BYTES
            )
        if self.reasoning_effort is not None:
            self.reasoning_effort = _bounded_text(self.reasoning_effort, 32)
        self.billing_mode = BillingMode(self.billing_mode)
        if self.started_at is None:
            self.started_at = _as_utc(self.wall_clock())
        else:
            self.started_at = _as_utc(self.started_at)
        if self.started_monotonic_ns is None:
            self.started_monotonic_ns = int(self.monotonic_ns())
        if type(self.started_monotonic_ns) is not int or self.started_monotonic_ns < 0:
            raise ValueError("started monotonic timestamp")

    @property
    def aggregate(self) -> TelemetryAggregate:
        return TelemetryAggregate.from_turns(self.turns)

    def observe(self, event: object) -> bool:
        """Observe one decoded event without raising to the stream reader."""

        try:
            if not isinstance(event, dict):
                self.add_issue("invalid_event")
                return False
            event_type = event.get("type")
            if event_type == "turn.completed":
                usage = event.get("usage")
                if usage is None:
                    self.add_issue("turn_usage_missing")
                    return False
                try:
                    turn = TelemetryTurn.from_usage(usage, ordinal=len(self.turns) + 1)
                except ValueError as exc:
                    self.add_issue(_issue_category(str(exc)))
                    return False
                if len(self.turns) >= TELEMETRY_MAX_TURNS:
                    self.add_issue("turn_bound")
                    return False
                self.turns.append(turn)
                return True
            if event_type == "item.completed" and _is_agent_message(event):
                self._record_first_agent_message()
            elif event_type == "agent_message":
                self._record_first_agent_message()
        except Exception:
            self.add_issue("observer_failure")
        return False

    def note_malformed_line(self) -> None:
        self.add_issue("malformed_jsonl")

    def note_observer_failure(self) -> None:
        self.add_issue("observer_failure")

    def add_issue(self, category: str) -> None:
        category = _bounded_text(category, TELEMETRY_MAX_ISSUE_CATEGORY_BYTES)
        if category:
            self.issues[category] += 1

    def set_process_outcome(self, outcome: str) -> None:
        if isinstance(outcome, str) and outcome:
            self.process_outcome = _bounded_text(outcome, 48)
        else:
            self.process_outcome = "unknown"

    def finalize(self, *, process_outcome: str | None = None) -> dict[str, object]:
        if self._finalized:
            return self.summary()
        if process_outcome is not None:
            self.set_process_outcome(process_outcome)
        completed_at = _as_utc(self.wall_clock())
        now_ns = int(self.monotonic_ns())
        duration_ms = max(0, (now_ns - int(self.started_monotonic_ns or now_ns)) // 1_000_000)
        aggregate = self.aggregate
        completeness = self._completeness()
        cost = estimate_cost(
            aggregate,
            billing_mode=self.billing_mode,
            configured_model=self.configured_model,
            started_at=self.started_at or completed_at,
            catalog=self.catalog,
        )
        payload = {
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "provenance": TELEMETRY_PROVENANCE,
            "invocation_id": self.invocation_id,
            "task_id": self.task_id,
            "run_name": self.run_name,
            "stage": self.stage,
            "retry_ordinal": self.retry_ordinal,
            "configured_model": self.configured_model,
            "reasoning_effort": self.reasoning_effort,
            "billing_mode": self.billing_mode.value,
            "started_at": _format_utc(self.started_at or completed_at),
            "completed_at": _format_utc(completed_at),
            "duration_ms": duration_ms,
            "first_agent_message_completed_ms": self.first_agent_message_completed_ms,
            "process_outcome": self.process_outcome,
            "turns": [item.to_dict() for item in self.turns],
            "aggregate": aggregate.to_dict(),
            "cost": cost.to_dict(),
            "completeness": completeness.value,
            "issues": _issues_payload(self.issues),
        }
        try:
            _atomic_write_json(self.path, payload)
            self._write_succeeded = True
        except Exception:
            self.add_issue("sidecar_write_failure")
            payload["completeness"] = TelemetryCompleteness.unavailable.value
            payload["issues"] = _issues_payload(self.issues)
            # Retain the bounded in-memory summary for diagnostics while never
            # changing the Codex process result.
        self._finalized = True
        return payload

    def summary(self) -> dict[str, object]:
        return {
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "availability": (
                "available" if self._write_succeeded and self.path.is_file() else "unavailable"
            ),
            "completeness": self._completeness().value,
            "completed_turns": len(self.turns),
            "issues": _issues_payload(self.issues),
        }

    def _record_first_agent_message(self) -> None:
        if self.first_agent_message_completed_ms is not None:
            return
        elapsed = int(self.monotonic_ns()) - int(self.started_monotonic_ns or 0)
        self.first_agent_message_completed_ms = max(0, elapsed // 1_000_000)

    def _completeness(self) -> TelemetryCompleteness:
        capture_issues = [
            category
            for category in self.issues
            if not category.startswith("price_catalog_")
        ]
        if not self.turns:
            return (
                TelemetryCompleteness.partial
                if capture_issues
                else TelemetryCompleteness.unavailable
            )
        return (
            TelemetryCompleteness.partial
            if capture_issues
            else TelemetryCompleteness.complete
        )


def validate_sidecar(value: object) -> dict[str, object]:
    """Strictly validate a persisted sidecar and return a detached object."""

    if not isinstance(value, dict):
        raise ValueError("telemetry sidecar must be an object")
    required = {
        "schema_version",
        "provenance",
        "invocation_id",
        "task_id",
        "run_name",
        "stage",
        "retry_ordinal",
        "configured_model",
        "reasoning_effort",
        "billing_mode",
        "started_at",
        "completed_at",
        "duration_ms",
        "first_agent_message_completed_ms",
        "process_outcome",
        "turns",
        "aggregate",
        "cost",
        "completeness",
        "issues",
    }
    if set(value) != required:
        raise ValueError("telemetry sidecar keys")
    if value["schema_version"] != TELEMETRY_SCHEMA_VERSION:
        raise ValueError("telemetry schema")
    if value["provenance"] != TELEMETRY_PROVENANCE:
        raise ValueError("telemetry provenance")
    for key, limit in (
        ("invocation_id", 160),
        ("task_id", TELEMETRY_MAX_TASK_ID_BYTES),
        ("run_name", TELEMETRY_MAX_RUN_NAME_BYTES),
        ("stage", TELEMETRY_MAX_STAGE_BYTES),
        ("process_outcome", 48),
    ):
        item = value[key]
        if not isinstance(item, str) or not item or len(item.encode()) > limit:
            raise ValueError(f"telemetry {key}")
    if not _SAFE_ID_RE.fullmatch(str(value["invocation_id"])):
        raise ValueError("telemetry invocation id")
    for key in ("configured_model", "reasoning_effort"):
        if value[key] is not None and not isinstance(value[key], str):
            raise ValueError(f"telemetry {key}")
    BillingMode(value["billing_mode"])
    started = _parse_utc(value["started_at"])
    completed = _parse_utc(value["completed_at"])
    if completed < started:
        raise ValueError("telemetry interval")
    for key in ("retry_ordinal", "duration_ms"):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError(f"telemetry {key}")
    first = value["first_agent_message_completed_ms"]
    if first is not None and (type(first) is not int or first < 0 or first > value["duration_ms"]):
        raise ValueError("telemetry first message timing")
    raw_turns = value["turns"]
    if not isinstance(raw_turns, list) or len(raw_turns) > TELEMETRY_MAX_TURNS:
        raise ValueError("telemetry turns")
    turns: list[TelemetryTurn] = []
    for expected, raw in enumerate(raw_turns, start=1):
        if not isinstance(raw, dict):
            raise ValueError("telemetry turn")
        usage = {
            key: raw.get(key)
            for key in (
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
            )
        }
        turn = TelemetryTurn.from_usage(usage, ordinal=raw.get("ordinal", expected))
        if set(raw) != set(turn.to_dict()):
            raise ValueError("telemetry turn keys")
        if raw != turn.to_dict():
            raise ValueError("telemetry turn derived fields")
        turns.append(turn)
    aggregate = TelemetryAggregate.from_dict(value["aggregate"])
    expected_aggregate = TelemetryAggregate.from_turns(turns)
    if aggregate != expected_aggregate:
        raise ValueError("telemetry aggregate mismatch")
    _validate_cost(value["cost"])
    if value["completeness"] not in {item.value for item in TelemetryCompleteness}:
        raise ValueError("telemetry completeness")
    _validate_issues(value["issues"])
    return json.loads(json.dumps(value))


def load_sidecar(path: Path) -> dict[str, object]:
    """Read and validate a bounded sidecar without following a symlink."""

    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_nlink != 1:
        raise ValueError("telemetry sidecar is not a regular file")
    if info.st_size < 0 or info.st_size > TELEMETRY_MAX_SIDECAR_BYTES:
        raise ValueError("telemetry sidecar exceeds bound")
    value = json.loads(path.read_text(encoding="utf-8"))
    return validate_sidecar(value)


def telemetry_sidecar_path(transcript_path: Path) -> Path:
    return Path(transcript_path).with_name("telemetry.json")


def aggregate_sidecars(values: Iterable[dict[str, object]]) -> dict[str, object]:
    """Merge validated sidecars, deduplicating invocation IDs."""

    selected: dict[str, dict[str, object]] = {}
    for value in values:
        selected.setdefault(str(value["invocation_id"]), value)
    ordered = sorted(selected.values(), key=lambda item: (item["started_at"], item["invocation_id"]))
    aggregate = TelemetryAggregate()
    turns: list[dict[str, int]] = []
    issues: Counter[str] = Counter()
    complete = True
    for value in ordered:
        aggregate = aggregate.add(TelemetryAggregate.from_dict(value["aggregate"]))
        for turn in value["turns"]:
            if len(turns) < 100:
                turns.append(dict(turn))
        if value["completeness"] != TelemetryCompleteness.complete.value:
            complete = False
        for issue in value["issues"]:
            issues[str(issue["category"])] += int(issue["count"])
    return {
        "availability": "available" if ordered else "not_produced",
        "provenance": TELEMETRY_PROVENANCE,
        "invocation_count": len(ordered),
        "configured_model": _common_value(ordered, "configured_model"),
        "reasoning_effort": _common_value(ordered, "reasoning_effort"),
        "billing_mode": _common_value(ordered, "billing_mode") or BillingMode.unknown.value,
        "started_at": ordered[0]["started_at"] if ordered else None,
        "completed_at": ordered[-1]["completed_at"] if ordered else None,
        "duration_ms": sum(int(value["duration_ms"]) for value in ordered),
        "aggregate": aggregate.to_dict(),
        "turns": turns,
        "turns_truncated": sum(len(value["turns"]) for value in ordered) > len(turns),
        "completeness": "complete" if complete and ordered else ("unavailable" if not ordered else "partial"),
        "issues": _issues_payload(issues),
        "cost": _merge_costs(ordered),
        "unavailable": _unavailable_descriptors(),
    }


def _merge_costs(values: list[dict[str, object]]) -> dict[str, object]:
    estimates = [item["cost"] for item in values if isinstance(item.get("cost"), dict)]
    usable = [item for item in estimates if item.get("status") == CostStatus.estimated.value]
    if not values:
        return {"status": CostStatus.unavailable.value, "reason": "no_telemetry"}
    if len(usable) != len(values):
        reasons = {
            str(item.get("reason"))
            for item in estimates
            if item.get("status") == CostStatus.unavailable.value
            and isinstance(item.get("reason"), str)
        }
        return {
            "status": CostStatus.unavailable.value,
            "reason": next(iter(reasons)) if len(reasons) == 1 else "incomplete_cost_basis",
        }
    total = sum(int(item.get("micro_usd", 0)) for item in usable)
    result: dict[str, object] = {"status": CostStatus.estimated.value, "micro_usd": total}
    entries = [item.get("price_entry") for item in usable if isinstance(item.get("price_entry"), dict)]
    if len(entries) == 1:
        result["price_entry"] = entries[0]
    elif entries:
        result["price_entries"] = entries[:32]
    return result


def _unavailable_descriptors() -> dict[str, dict[str, str]]:
    reason = "not_exposed_by_codex_exec"
    return {
        "model_requests": {"availability": "unavailable", "reason": reason},
        "ttft_ms": {"availability": "unavailable", "reason": reason},
        "output_tokens_per_second": {"availability": "unavailable", "reason": reason},
    }


def _parse_price_entry(value: object) -> PriceEntry:
    if not isinstance(value, dict):
        raise ValueError("price entry")
    required = {
        "id",
        "model",
        "effective_from",
        "input_micro_usd_per_million",
        "cached_input_micro_usd_per_million",
        "output_micro_usd_per_million",
        "source",
    }
    if set(value) - (required | {"effective_until"}) or not required <= set(value):
        raise ValueError("price entry keys")
    entry_id = value["id"]
    model = value["model"]
    if not isinstance(entry_id, str) or not _SAFE_ID_RE.fullmatch(entry_id):
        raise ValueError("price entry id")
    if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
        raise ValueError("price entry model")
    effective_from = _parse_utc(value["effective_from"])
    effective_until = (
        _parse_utc(value["effective_until"])
        if value.get("effective_until") is not None
        else None
    )
    if effective_until is not None and effective_until <= effective_from:
        raise ValueError("price entry interval")
    rates: dict[str, int] = {}
    for key in (
        "input_micro_usd_per_million",
        "cached_input_micro_usd_per_million",
        "output_micro_usd_per_million",
    ):
        rate = value[key]
        if type(rate) is not int or rate < 0:
            raise ValueError(f"price entry {key}")
        rates[key] = rate
    source = value["source"]
    if not isinstance(source, dict) or set(source) != {"label", "url"}:
        raise ValueError("price entry source")
    label = source["label"]
    url = source["url"]
    if (
        not isinstance(label, str)
        or not label.strip()
        or len(label.encode()) > TELEMETRY_MAX_SOURCE_LABEL_BYTES
        or any(character in label for character in "\x00\r\n")
        or not isinstance(url, str)
        or not url.startswith("https://")
        or len(url.encode()) > TELEMETRY_MAX_SOURCE_URL_BYTES
        or any(character in url for character in "\x00\r\n")
    ):
        raise ValueError("price entry source")
    parsed_url = urlsplit(url)
    if not parsed_url.hostname or parsed_url.username or parsed_url.password:
        raise ValueError("price entry source")
    return PriceEntry(
        entry_id=entry_id,
        model=model,
        effective_from=effective_from,
        effective_until=effective_until,
        source_label=label.strip(),
        source_url=url,
        **rates,
    )


def _reject_price_overlaps(entries: tuple[PriceEntry, ...]) -> None:
    by_model: dict[str, list[PriceEntry]] = {}
    for entry in entries:
        by_model.setdefault(entry.model, []).append(entry)
    for model_entries in by_model.values():
        ordered = sorted(model_entries, key=lambda item: item.effective_from)
        for left, right in zip(ordered, ordered[1:]):
            if left.effective_until is None or right.effective_from < left.effective_until:
                raise ValueError("overlapping price entries")


def _round_micro_usd(tokens: int, rate: int) -> int:
    return (tokens * rate + 500_000) // 1_000_000


def _validate_cost(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("telemetry cost")
    status = value.get("status")
    if status not in {item.value for item in CostStatus}:
        raise ValueError("telemetry cost status")
    if status == CostStatus.estimated.value:
        micro = value.get("micro_usd")
        if type(micro) is not int or micro < 0:
            raise ValueError("telemetry cost amount")
        price = value.get("price_entry")
        if not isinstance(price, dict):
            raise ValueError("telemetry cost provenance")
    elif "micro_usd" in value:
        raise ValueError("unavailable cost amount")
    reason = value.get("reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 96):
        raise ValueError("telemetry cost reason")


def _validate_issues(value: object) -> None:
    if not isinstance(value, list) or len(value) > TELEMETRY_MAX_ISSUES:
        raise ValueError("telemetry issues")
    for issue in value:
        if not isinstance(issue, dict) or set(issue) != {"category", "count"}:
            raise ValueError("telemetry issue")
        category = issue["category"]
        count = issue["count"]
        if (
            not isinstance(category, str)
            or not category
            or len(category.encode()) > TELEMETRY_MAX_ISSUE_CATEGORY_BYTES
            or type(count) is not int
            or count < 1
        ):
            raise ValueError("telemetry issue")


def _issues_payload(issues: Counter[str]) -> list[dict[str, object]]:
    return [
        {"category": category[:TELEMETRY_MAX_ISSUE_CATEGORY_BYTES], "count": count}
        for category, count in sorted(issues.items())
        if count > 0
    ][:TELEMETRY_MAX_ISSUES]


def _issue_category(message: str) -> str:
    normalized = message.lower().replace(" ", "_")
    for prefix in ("invalid_", "aggregate_"):
        if normalized.startswith(prefix):
            return normalized[:80]
    return normalized[:80] or "invalid_usage"


def _is_agent_message(event: dict[str, object]) -> bool:
    item = event.get("item")
    return isinstance(item, dict) and item.get("type") == "agent_message"


def _common_value(values: list[dict[str, object]], key: str) -> object:
    if not values:
        return None
    selected = {value.get(key) for value in values}
    return next(iter(selected)) if len(selected) == 1 else None


def _bounded_text(value: object, limit: int) -> str:
    text = str(value)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore")


def _as_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("expected datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=_UTC)
    return value.astimezone(_UTC)


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("expected UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("invalid UTC timestamp") from None
    return _as_utc(parsed)


def _format_utc(value: datetime | None) -> str:
    return _as_utc(value or datetime.now(_UTC)).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            json.dump(value, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


__all__ = [
    "BillingMode",
    "CostEstimate",
    "CostStatus",
    "PriceCatalog",
    "PriceEntry",
    "TELEMETRY_MAX_SIDECAR_BYTES",
    "TELEMETRY_PROVENANCE",
    "TELEMETRY_SCHEMA_VERSION",
    "TelemetryAggregate",
    "TelemetryCompleteness",
    "TelemetryCoverage",
    "TelemetryInvocation",
    "TelemetryRecorder",
    "TelemetryTiming",
    "TelemetryTurn",
    "aggregate_sidecars",
    "estimate_cost",
    "load_sidecar",
    "telemetry_sidecar_path",
    "validate_sidecar",
]

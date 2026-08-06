#!/usr/bin/env python3
"""Read-only, on-demand check of the public Steward cloud publication."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
import ipaddress
import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
CLOUD_SCHEMA_PATH = ROOT / "site-v2" / "schemas" / "steward-cloud.schema.json"

CLOUD_SCHEMA_VERSION = "3.0"
TRAJECTORY_SCHEMA_VERSION = "4.0"
DEFAULT_MAX_LATENCY_MS = 2_000.0
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAME_ORIGIN_ARTIFACT_PATTERN = re.compile(
    r"^/api/steward/tasks/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/artifact\?path="
    r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~!$'()*+,;=@-])+$"
)
PUBLIC_KEY_PATTERN = re.compile(
    r"^v1/tasks/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/objects/sha256/[0-9a-f]{2}/[0-9a-f]{64}$"
)

PRIVATE_PATH_PATTERN = re.compile(
    r"(?i)(?:file://|(?:^|[\s\"'(<>=,:;])(?:~[/\\]|"
    r"/(?:home|media|tmp|worktrees|transcripts|patches)(?:/|$)|[A-Za-z]:[\\/]))"
)
PRIVATE_CREDENTIAL_PATTERN = re.compile(
    r"(?i)begin private key|authorization\s*:\s*bearer|"
    r"(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]"
)
PRIVATE_THREAD_PATTERN = re.compile(r"(?i)\bthread(?:[_ .-]?id|\.started)\b")
PRIVATE_RAW_PATTERN = re.compile(r'(?i)"mode"\s*:\s*"raw"|\braw[_ -]?transcript\b')
PRIVATE_URL_PATTERN = re.compile(r"(?i)\b(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?)://")

SENSITIVE_KEYS = {
    "accesstoken",
    "apikey",
    "authorization",
    "password",
    "privatekey",
    "prompt",
    "secret",
    "systemprompt",
    "threadid",
    "token",
    "userprompt",
}
PUBLIC_METRIC_KEYS = {
    "cachedtokens",
    "completiontokens",
    "prompttokens",
    "totalcachedtokens",
    "totalcompletiontokens",
    "totalprompttokens",
}


class ContractError(ValueError):
    """Raised when a response cannot be treated as a public cloud contract."""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


OPENER = build_opener(NoRedirectHandler)


@dataclass(frozen=True)
class FetchResult:
    status_code: int | None
    headers: dict[str, str]
    body: bytes
    latency_ms: float
    error: str | None = None


def _parse_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _parse_base_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base URL must use http or https and include a host")
    if parsed.username or parsed.password:
        raise ValueError("base URL must not contain user information")
    if parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain a query or fragment")
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _url(base_url: str, path: str) -> str:
    if not path.startswith("/") or "://" in path:
        raise ContractError("route is not fixed and same-origin")
    return f"{base_url.rstrip('/')}{path}"


def _read_bounded(response) -> tuple[bytes, str | None]:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_RESPONSE_BYTES:
                return b"", "body_too_large"
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, MAX_RESPONSE_BYTES - total + 1))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            return b"", "body_too_large"
    return b"".join(chunks), None


def _fetch(base_url: str, path: str, timeout_seconds: float) -> FetchResult:
    request = Request(
        _url(base_url, path),
        headers={
            "Accept": "text/html, application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
        method="GET",
    )
    started = time.monotonic()
    try:
        with OPENER.open(request, timeout=timeout_seconds) as response:
            body, read_error = _read_bounded(response)
            return FetchResult(
                status_code=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=body,
                latency_ms=round((time.monotonic() - started) * 1000, 3),
                error=read_error,
            )
    except HTTPError as error:
        error_headers = error.headers or {}
        return FetchResult(
            status_code=error.code,
            headers={key.lower(): value for key, value in error_headers.items()},
            body=b"",
            latency_ms=round((time.monotonic() - started) * 1000, 3),
            error=f"http_{error.code}",
        )
    except (OSError, URLError, TimeoutError):
        return FetchResult(
            status_code=None,
            headers={},
            body=b"",
            latency_ms=round((time.monotonic() - started) * 1000, 3),
            error="network_error",
        )


def _decode_json(body: bytes) -> object | None:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _has_value(value: object) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _scan_text(text: str, *, strict_urls: bool) -> str | None:
    if PRIVATE_PATH_PATTERN.search(text):
        return "private_path"
    if PRIVATE_CREDENTIAL_PATTERN.search(text):
        return "credential"
    if PRIVATE_THREAD_PATTERN.search(text):
        return "thread_marker"
    if PRIVATE_RAW_PATTERN.search(text):
        return "raw_payload"
    if strict_urls and PRIVATE_URL_PATTERN.search(text):
        return "private_locator"
    return None


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def _scan_private_values(value: object, *, key: str | None = None, strict_urls: bool = True) -> str | None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            normalized = _normalized_key(child_key)
            if normalized in SENSITIVE_KEYS and normalized not in PUBLIC_METRIC_KEYS and _has_value(child):
                return "credential" if normalized not in {"prompt", "systemprompt", "userprompt"} else "prompt"
            if normalized == "raw" and _has_value(child):
                return "raw_payload"
            if normalized in {"href", "location"} and isinstance(child, str):
                if normalized == "href" and SAME_ORIGIN_ARTIFACT_PATTERN.fullmatch(child):
                    pass
                elif normalized == "location":
                    # Redirect destinations are checked against the validated public key separately.
                    pass
                elif strict_urls:
                    return "private_locator"
            finding = _scan_private_values(child, key=str(child_key), strict_urls=strict_urls)
            if finding:
                return finding
        return None
    if isinstance(value, list):
        for child in value:
            finding = _scan_private_values(child, strict_urls=strict_urls)
            if finding:
                return finding
        return None
    if isinstance(value, str):
        if key == "href" and SAME_ORIGIN_ARTIFACT_PATTERN.fullmatch(value):
            return None
        return _scan_text(value, strict_urls=strict_urls)
    return None


def _scan_response(body: bytes, document: object | None = None, *, strict_urls: bool = True) -> str | None:
    if document is not None:
        finding = _scan_private_values(document, strict_urls=strict_urls)
        if finding:
            return finding
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return "invalid_utf8"
    return _scan_text(text, strict_urls=strict_urls)


@dataclass
class _UsageRow:
    cells: list[str]
    disclosures: list[dict[str, str]]
    selected: bool = False


@dataclass
class _UsageTable:
    rows: list[_UsageRow]


class _UsageHTMLParser(HTMLParser):
    """Parse only bounded table/disclosure structure from a rendered page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible_parts: list[str] = []
        self.usage_states: list[str] = []
        self.tables: list[_UsageTable] = []
        self._ignored_depth = 0
        self._table: list[_UsageRow] | None = None
        self._row: _UsageRow | None = None
        self._cell: list[str] | None = None
        self._disclosure: dict[str, str] | None = None
        self._definition_label: list[str] | None = None
        self._definition_value: list[str] | None = None
        self._pending_label: str | None = None

    @staticmethod
    def _text(parts: list[str] | None) -> str:
        if not parts:
            return ""
        return " ".join(" ".join(parts).split())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.lower()
        attributes = {key.lower(): value for key, value in attrs}
        if normalized in {"script", "style"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        self.visible_parts.append("")
        usage_state = attributes.get("data-usage-state")
        if usage_state is not None:
            self.usage_states.append(usage_state)
        if normalized == "table":
            self._table = []
        elif normalized == "tr" and self._table is not None:
            self._row = _UsageRow([], [])
        elif normalized in {"th", "td"} and self._row is not None:
            self._cell = []
        elif normalized == "a" and self._row is not None:
            if (attributes.get("aria-current") or "").lower() == "page":
                self._row.selected = True
        elif normalized == "details" and self._row is not None:
            self._disclosure = {}
        elif normalized == "dt" and self._disclosure is not None:
            self._definition_label = []
        elif normalized == "dd" and self._disclosure is not None:
            self._definition_value = []

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if normalized in {"script", "style"}:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if self._ignored_depth:
            return
        if normalized in {"th", "td"} and self._cell is not None and self._row is not None:
            self._row.cells.append(self._text(self._cell))
            self._cell = None
        elif normalized == "tr" and self._row is not None and self._table is not None:
            if self._row.cells:
                self._table.append(self._row)
            self._row = None
        elif normalized == "table" and self._table is not None:
            self.tables.append(_UsageTable(self._table))
            self._table = None
        elif normalized == "dt" and self._definition_label is not None:
            self._pending_label = self._text(self._definition_label)
            self._definition_label = None
        elif normalized == "dd" and self._definition_value is not None and self._disclosure is not None:
            label = self._pending_label or ""
            if label:
                self._disclosure[label] = self._text(self._definition_value)
            self._definition_value = None
            self._pending_label = None
        elif normalized == "details" and self._disclosure is not None and self._row is not None:
            if self._disclosure:
                self._row.disclosures.append(self._disclosure)
            self._disclosure = None
            self._definition_label = None
            self._definition_value = None
            self._pending_label = None

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        self.visible_parts.append(data)
        if self._cell is not None:
            self._cell.append(data)
        if self._definition_label is not None:
            self._definition_label.append(data)
        if self._definition_value is not None:
            self._definition_value.append(data)

    @property
    def visible_text(self) -> str:
        return " ".join(" ".join(self.visible_parts).split())


def _parse_usage_html(body: bytes) -> _UsageHTMLParser | None:
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parser = _UsageHTMLParser()
    try:
        parser.feed(decoded)
        parser.close()
    except (ValueError, TypeError):
        return None
    return parser


_USAGE_TOKEN_LABELS = {
    "prompt tokens",
    "cached tokens",
    "uncached tokens",
    "completion tokens",
    "reasoning tokens",
    "total tokens",
}
_USAGE_COST_LABELS = {
    "uncached input cost",
    "cached input cost",
    "output cost",
    "total cost",
}


def _usage_number(value: str, *, cost: bool = False) -> int | None:
    normalized = value.strip()
    if normalized in {"N.A.", "Unavailable"}:
        return None
    if cost:
        match = re.fullmatch(r"\$([0-9][0-9,]*)\.([0-9]{6})", normalized)
        if match is None:
            return None
        parsed = int(match.group(1).replace(",", "")) * 1_000_000 + int(match.group(2))
        return parsed if parsed <= 9_007_199_254_740_991 else None
    if re.fullmatch(r"[0-9][0-9,]*", normalized) is None:
        return None
    parsed = int(normalized.replace(",", ""))
    return parsed if parsed <= 9_007_199_254_740_991 else None


def _usage_coverage(value: str, count_word: str) -> bool:
    match = re.fullmatch(
        rf"(Complete|Partial|Unavailable|N\.A\.)(?: - ([0-9][0-9,]*)/([0-9][0-9,]*) {count_word})?",
        value.strip(),
    )
    if match is None:
        return False
    label, covered, expected = match.groups()
    if covered is None:
        return label in {"Unavailable", "N.A."}
    covered_count = int(covered.replace(",", ""))
    expected_count = int(expected.replace(",", ""))
    if covered_count > expected_count:
        return False
    return label != "Complete" or covered_count == expected_count


def _validate_usage_disclosure(disclosure: dict[str, str]) -> bool:
    normalized = {" ".join(key.lower().split()): value for key, value in disclosure.items()}
    if not _USAGE_TOKEN_LABELS <= set(normalized) or not _USAGE_COST_LABELS <= set(normalized):
        return False
    tokens = [_usage_number(normalized[label]) for label in sorted(_USAGE_TOKEN_LABELS)]
    if any(value is None for value in tokens):
        known_tokens = [value for value in tokens if value is not None]
    else:
        prompt, cached, completion, reasoning, total, uncached = (
            normalized[label] and _usage_number(normalized[label])
            for label in ("prompt tokens", "cached tokens", "completion tokens", "reasoning tokens", "total tokens", "uncached tokens")
        )
        if cached > prompt or uncached != prompt - cached or reasoning > completion or total != prompt + completion:
            return False
        known_tokens = tokens
    costs = [_usage_number(normalized[label], cost=True) for label in sorted(_USAGE_COST_LABELS)]
    if any(value is None for value in costs) and not all(value is None for value in costs):
        return False
    return bool(known_tokens or all(value is None for value in costs))


def _row_disclosure_matches(row: _UsageRow, token_text: str, cost_text: str) -> bool:
    disclosure = _usage_disclosure(row)
    if disclosure is None:
        return False
    displayed_token = _usage_number(token_text)
    disclosed_token = _usage_number(disclosure["total tokens"])
    if displayed_token is None and disclosed_token is not None and token_text.strip() in {"N.A.", "Unavailable"}:
        return False
    if displayed_token is not None and disclosed_token is not None and displayed_token != disclosed_token:
        return False
    displayed_cost = _usage_number(cost_text, cost=True)
    disclosed_cost = _usage_number(disclosure["total cost"], cost=True)
    if displayed_cost is None and disclosed_cost is not None and cost_text.strip() in {"N.A.", "Unavailable"}:
        return False
    if displayed_cost is not None and disclosed_cost is not None and displayed_cost != disclosed_cost:
        return False
    return True


def _usage_disclosure(row: _UsageRow) -> dict[str, str] | None:
    for disclosure in row.disclosures:
        if _validate_usage_disclosure(disclosure):
            return {" ".join(key.lower().split()): value for key, value in disclosure.items()}
    return None


def _usage_identity(row: _UsageRow, index: int) -> str | None:
    if len(row.cells) <= index:
        return None
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]{0,127})", row.cells[index].strip())
    return match.group(1) if match else None


def _usage_metrics(row: _UsageRow) -> tuple[tuple[int | None, ...], tuple[int | None, ...]] | None:
    disclosure = _usage_disclosure(row)
    if disclosure is None:
        return None
    tokens = tuple(_usage_number(disclosure[label]) for label in (
        "prompt tokens", "cached tokens", "uncached tokens", "completion tokens", "reasoning tokens", "total tokens",
    ))
    costs = tuple(_usage_number(disclosure[label], cost=True) for label in (
        "uncached input cost", "cached input cost", "output cost", "total cost",
    ))
    return tokens, costs


def _usage_coverage_counts(value: str) -> tuple[str, int | None, int | None] | None:
    match = re.fullmatch(
        r"(Complete|Partial|Unavailable|N\.A\.)(?: - ([0-9][0-9,]*)/([0-9][0-9,]*) (?:turns|invocations))?",
        value.strip(),
    )
    if match is None:
        return None
    label, covered, expected = match.groups()
    if covered is None:
        return label, None, None
    covered_count = int(covered.replace(",", ""))
    expected_count = int(expected.replace(",", ""))
    if covered_count > expected_count:
        return None
    return label, covered_count, expected_count


def _usage_rollup_matches(parent: _UsageRow, turns: list[_UsageRow], coverage_index: int) -> bool:
    if len(parent.cells) <= coverage_index:
        return False
    coverage = _usage_coverage_counts(parent.cells[coverage_index])
    if coverage is None:
        return False
    status, covered, expected = coverage
    if status in {"Unavailable", "N.A."}:
        return True
    if covered is None or expected is None or covered != len(turns):
        return False
    if status == "Complete" and covered != expected:
        return False
    parent_metrics = _usage_metrics(parent)
    child_metrics = [_usage_metrics(turn) for turn in turns]
    if parent_metrics is None:
        return False
    parent_tokens, parent_costs = parent_metrics
    for index, expected_value in enumerate(parent_tokens):
        values = [metrics[0][index] for metrics in child_metrics if metrics is not None]
        if expected_value is None:
            if status == "Complete" and any(value is not None for value in values):
                return False
            continue
        if len(values) != len(child_metrics) or any(value is None for value in values):
            return False
        if expected_value != sum(value for value in values if value is not None):
            return False
    for index, expected_value in enumerate(parent_costs):
        values = [metrics[1][index] for metrics in child_metrics if metrics is not None]
        if expected_value is None:
            if status == "Complete" and any(value is not None for value in values):
                return False
            continue
        if len(values) != len(child_metrics) or any(value is None for value in values):
            return False
        if expected_value != sum(value for value in values if value is not None):
            return False
    return True


def _table_with_headers(parser: _UsageHTMLParser, required: tuple[str, ...]) -> tuple[_UsageTable, dict[str, int]] | None:
    for table in parser.tables:
        if not table.rows:
            continue
        headers = {" ".join(cell.lower().split()): index for index, cell in enumerate(table.rows[0].cells)}
        if all(item in headers for item in required) and len(table.rows) > 1:
            return table, headers
    return None


def _validate_usage_tables(
    parser: _UsageHTMLParser,
    *,
    label: str,
    task_id: str | None,
) -> tuple[bool, str | None]:
    if "ready" not in {state.lower() for state in parser.usage_states}:
        return False, "usage_surface_incomplete"
    if label == "usage_global":
        selected = _table_with_headers(
            parser,
            ("model", "ownership", "token", "estimated cost", "coverage", "details"),
        )
        if selected is None:
            return False, "global_usage_table_missing"
        table, headers = selected
        token_index = headers["token"]
        cost_index = headers["estimated cost"]
        coverage_index = headers["coverage"]
        owner_index = headers["ownership"]
        for row in table.rows[1:]:
            if len(row.cells) <= max(token_index, cost_index, coverage_index, owner_index):
                return False, "global_usage_row_incomplete"
            if row.cells[owner_index] not in {"Task-owned", "Steward overhead"}:
                return False, "global_usage_ownership_invalid"
            if _usage_number(row.cells[token_index]) is None and row.cells[token_index] not in {"N.A.", "Unavailable"}:
                return False, "global_usage_token_invalid"
            if _usage_number(row.cells[cost_index], cost=True) is None and row.cells[cost_index] not in {"N.A.", "Unavailable"}:
                return False, "global_usage_cost_invalid"
            if not _usage_coverage(row.cells[coverage_index], "invocations"):
                return False, "global_usage_coverage_invalid"
            if not _row_disclosure_matches(row, row.cells[token_index], row.cells[cost_index]):
                return False, "global_usage_components_invalid"
    else:
        selected = _table_with_headers(
            parser,
            ("invocation / retry", "role", "model", "utc start", "outcome", "token", "estimated cost", "coverage", "details"),
        )
        turns = _table_with_headers(
            parser,
            ("turn", "turn id", "utc start", "model", "coverage", "token", "estimated cost", "price", "details"),
        )
        if selected is None or turns is None:
            return False, "task_usage_table_missing"
        invocation_table, invocation_headers = selected
        invocation_rows = invocation_table.rows[1:]
        invocation_ids: set[str] = set()
        selected_rows: list[_UsageRow] = []
        for row in invocation_rows:
            if len(row.cells) <= max(invocation_headers.values()):
                return False, "task_usage_row_incomplete"
            invocation_id = _usage_identity(row, invocation_headers["invocation / retry"])
            if invocation_id is None or invocation_id in invocation_ids:
                return False, "task_usage_identity_invalid"
            invocation_ids.add(invocation_id)
            if row.selected:
                selected_rows.append(row)
            if re.search(r"\bRetry [0-9]+\b", row.cells[invocation_headers["invocation / retry"]]) is None:
                return False, "task_usage_retry_missing"
            if _usage_number(row.cells[invocation_headers["token"]]) is None and row.cells[invocation_headers["token"]] not in {"N.A.", "Unavailable"}:
                return False, "task_usage_token_invalid"
            if _usage_number(row.cells[invocation_headers["estimated cost"]], cost=True) is None and row.cells[invocation_headers["estimated cost"]] not in {"N.A.", "Unavailable"}:
                return False, "task_usage_cost_invalid"
            if not _usage_coverage(row.cells[invocation_headers["coverage"]], "turns"):
                return False, "task_usage_coverage_invalid"
            if not _row_disclosure_matches(
                row,
                row.cells[invocation_headers["token"]],
                row.cells[invocation_headers["estimated cost"]],
            ):
                return False, "task_usage_components_invalid"
        turn_table, turn_headers = turns
        turn_rows = turn_table.rows[1:]
        turn_ids: set[str] = set()
        for row in turn_rows:
            if len(row.cells) <= max(turn_headers.values()):
                return False, "task_turn_row_incomplete"
            if re.fullmatch(r"[1-9][0-9,]*", row.cells[turn_headers["turn"]]) is None:
                return False, "task_turn_ordinal_invalid"
            turn_id = _usage_identity(row, turn_headers["turn id"])
            if turn_id is None or turn_id in turn_ids:
                return False, "task_turn_id_missing"
            turn_ids.add(turn_id)
            if _usage_number(row.cells[turn_headers["token"]]) is None and row.cells[turn_headers["token"]] not in {"N.A.", "Unavailable"}:
                return False, "task_turn_token_invalid"
            if _usage_number(row.cells[turn_headers["estimated cost"]], cost=True) is None and row.cells[turn_headers["estimated cost"]] not in {"N.A.", "Unavailable"}:
                return False, "task_turn_cost_invalid"
            if not _usage_coverage(row.cells[turn_headers["coverage"]], "turns"):
                return False, "task_turn_coverage_invalid"
            if not _row_disclosure_matches(
                row,
                row.cells[turn_headers["token"]],
                row.cells[turn_headers["estimated cost"]],
            ):
                return False, "task_turn_components_invalid"
        if len(selected_rows) > 1:
            return False, "task_usage_identity_invalid"
        if len(invocation_rows) > 1 and not selected_rows:
            return False, "task_usage_identity_invalid"
        selected_parent = selected_rows[0] if selected_rows else (invocation_rows[0] if invocation_rows else None)
        if selected_parent is None or not _usage_rollup_matches(selected_parent, turn_rows, invocation_headers["coverage"]):
            return False, "task_usage_rollup_invalid"
    disclosures = [disclosure for table in parser.tables for row in table.rows for disclosure in row.disclosures]
    if not disclosures or not any(_validate_usage_disclosure(disclosure) for disclosure in disclosures):
        return False, "usage_components_invalid"
    if task_id is not None and task_id not in parser.visible_text:
        return False, "task_ownership_missing"
    return True, None


def _record_usage_surface(
    result: dict[str, Any],
    label: str,
    response: FetchResult,
    max_latency_ms: float,
    *,
    task_id: str | None = None,
) -> bool:
    """Check the rendered, read-only usage proof without parsing provider data."""

    if response.status_code != 200 or response.error is not None:
        _add_check(result, f"{label}_endpoint", "fail", detail=response.error or f"http_{response.status_code}")
        _add_check(result, f"{label}_headers", "skip", detail="surface_unavailable")
        _add_check(result, f"{label}_privacy", "skip", detail="surface_unavailable")
        _add_check(result, f"{label}_structure", "skip", detail="surface_unavailable")
        _add_latency(result, f"{label}_latency", response, max_latency_ms)
        return False

    _add_check(result, f"{label}_endpoint", "pass", status_code=200)
    header_problems = _header_problems(response.headers, "text/html")
    if header_problems:
        _add_check(result, f"{label}_headers", "fail", detail="invalid_headers", problems=header_problems)
    else:
        _add_check(result, f"{label}_headers", "pass")
    finding = _scan_response(response.body, strict_urls=False)
    if finding:
        _add_check(result, f"{label}_privacy", "fail", detail=finding)
    else:
        _add_check(result, f"{label}_privacy", "pass")
    parser = _parse_usage_html(response.body)
    if parser is None:
        _add_check(result, f"{label}_structure", "fail", detail="invalid_utf8")
        _add_latency(result, f"{label}_latency", response, max_latency_ms)
        return False
    valid, detail = _validate_usage_tables(parser, label=label, task_id=task_id)
    _add_check(result, f"{label}_structure", "pass" if valid else "fail", detail=detail)
    _add_check(result, f"{label}_coverage", "pass" if valid else "fail", detail=None if valid else "coverage_or_structure_invalid")
    _add_check(result, f"{label}_metrics", "pass" if valid else "fail", detail=None if valid else "token_or_cost_invalid")
    if label == "usage_global":
        _add_check(result, f"{label}_ownership", "pass" if valid else "fail", detail=None if valid else "ownership_or_structure_invalid")
    else:
        _add_check(result, f"{label}_ownership", "pass" if valid else "fail", detail=None if valid else "ownership_or_structure_invalid")
        _add_check(result, f"{label}_retries", "pass" if valid else "fail", detail=None if valid else "retry_or_structure_invalid")
        _add_check(result, f"{label}_turns", "pass" if valid else "fail", detail=None if valid else "turn_or_structure_invalid")
    if task_id is not None and task_id not in parser.visible_text:
        _add_check(result, f"{label}_task", "fail", detail="task_ownership_missing")
    _add_latency(result, f"{label}_latency", response, max_latency_ms)
    return not any(
        check["status"] == "fail"
        for check in result["checks"]
        if check["name"].startswith(f"{label}_")
    )


def _header_problems(
    headers: dict[str, str],
    content_type: str,
    *,
    require_nosniff: bool = False,
) -> list[str]:
    problems: list[str] = []
    cache_control = {part.strip().lower() for part in headers.get("cache-control", "").split(",")}
    if "no-store" not in cache_control:
        problems.append("cache_control")
    if not headers.get("content-type", "").lower().startswith(content_type):
        problems.append("content_type")
    if require_nosniff and headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        problems.append("nosniff")
    return problems


def _load_cloud_schema() -> dict[str, Any]:
    try:
        schema = json.loads(CLOUD_SCHEMA_PATH.read_text(encoding="utf-8"))
        if not isinstance(schema, dict):
            raise ContractError("cloud schema is not an object")
        Draft202012Validator.check_schema(schema)
        if not isinstance(schema.get("$defs"), dict):
            raise ContractError("cloud schema has no definitions")
        return schema
    except Exception:
        raise ContractError("cloud schema unavailable") from None


def _validate_document(document: object, schema: dict[str, Any], definition: str) -> bool:
    target = {
        "$schema": schema.get("$schema", "https://json-schema.org/draft/2020-12/schema"),
        "$ref": f"#/$defs/{definition}",
        "$defs": schema["$defs"],
    }
    try:
        validator = Draft202012Validator(target, format_checker=FormatChecker())
        return not any(validator.iter_errors(document))
    except (KeyError, TypeError, ValueError):
        return False


def _add_check(
    result: dict[str, Any],
    name: str,
    status: str,
    *,
    detail: str | None = None,
    **fields: Any,
) -> None:
    check: dict[str, Any] = {"name": name, "status": status}
    if detail is not None:
        check["detail"] = detail
    check.update(fields)
    result["checks"].append(check)


def _add_latency(result: dict[str, Any], name: str, response: FetchResult, max_latency_ms: float) -> None:
    if response.latency_ms > max_latency_ms:
        _add_check(result, name, "fail", latency_ms=response.latency_ms)
    else:
        _add_check(result, name, "pass", latency_ms=response.latency_ms)


def _record_page(
    result: dict[str, Any],
    label: str,
    response: FetchResult,
    schema: dict[str, Any],
    definition: str,
    max_latency_ms: float,
    *,
    content_type: str = "application/json",
) -> object | None:
    if response.status_code == 200 and response.error is None:
        _add_check(result, f"{label}_endpoint", "pass", status_code=200)
        header_problems = _header_problems(response.headers, content_type)
        if header_problems:
            _add_check(result, f"{label}_headers", "fail", detail="invalid_headers", problems=header_problems)
        else:
            _add_check(result, f"{label}_headers", "pass")
        document = _decode_json(response.body)
        if document is None:
            _add_check(result, f"{label}_schema", "fail", detail="malformed_json")
        elif not isinstance(document, dict) or document.get("schemaVersion") not in {
            CLOUD_SCHEMA_VERSION,
            TRAJECTORY_SCHEMA_VERSION,
        }:
            _add_check(result, f"{label}_schema", "fail", detail="schema_incompatible")
        elif not _validate_document(document, schema, definition):
            _add_check(result, f"{label}_schema", "fail", detail="schema_invalid")
        else:
            _add_check(result, f"{label}_schema", "pass", schemaVersion=document["schemaVersion"])
        finding = _scan_response(response.body, document)
        if finding:
            _add_check(result, f"{label}_privacy", "fail", detail=finding)
        else:
            _add_check(result, f"{label}_privacy", "pass")
        _add_latency(result, f"{label}_latency", response, max_latency_ms)
        schema_check = next(
            check for check in reversed(result["checks"])
            if check["name"] == f"{label}_schema"
        )
        privacy_check = next(
            check for check in reversed(result["checks"])
            if check["name"] == f"{label}_privacy"
        )
        if schema_check["status"] == "pass" and privacy_check["status"] == "pass":
            return document
        return None

    detail = response.error or f"http_{response.status_code}"
    _add_check(result, f"{label}_endpoint", "fail", detail=detail)
    _add_check(result, f"{label}_headers", "skip", detail="endpoint_unavailable")
    _add_check(result, f"{label}_schema", "skip", detail="endpoint_unavailable")
    _add_check(result, f"{label}_privacy", "skip", detail="endpoint_unavailable")
    _add_latency(result, f"{label}_latency", response, max_latency_ms)
    return None


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and IDENTIFIER_PATTERN.fullmatch(value) is not None


def _public_key_matches(value: object, task_id: str, digest: object) -> bool:
    if not isinstance(value, str) or not isinstance(digest, str):
        return False
    match = re.fullmatch(
        r"v1/tasks/([^/]+)/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})",
        value,
    )
    return bool(match and match.group(1) == task_id and match.group(2) == digest[:2] and match.group(3) == digest)


def _detail_ownership_is_valid(data: object, task_id: str) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("task"), dict):
        return False
    task = data["task"]
    if task.get("taskId") != task_id:
        return False
    pipelines = data.get("pipelines")
    runs = data.get("runs")
    events = data.get("events")
    artifacts = data.get("artifacts")
    if not all(isinstance(value, list) for value in (pipelines, runs, events, artifacts)):
        return False
    pipeline_ids = {item.get("pipelineId") for item in pipelines if isinstance(item, dict)}
    run_ids = {item.get("runId") for item in runs if isinstance(item, dict)}
    artifact_ids = {item.get("artifactId") for item in artifacts if isinstance(item, dict)}
    if (
        len(pipeline_ids) != len(pipelines)
        or len(run_ids) != len(runs)
        or len(artifact_ids) != len(artifacts)
        or task.get("eventCount") != len(events)
        or task.get("artifactCount") != len(artifacts)
    ):
        return False
    for pipeline in pipelines:
        if not isinstance(pipeline, dict) or pipeline.get("taskId") != task_id:
            return False
    for run in runs:
        if not isinstance(run, dict) or run.get("taskId") != task_id or run.get("pipelineId") not in pipeline_ids:
            return False
    for sequence, event in enumerate(events, start=1):
        if (
            not isinstance(event, dict)
            or event.get("taskId") != task_id
            or event.get("sequence") != sequence
        ):
            return False
    if task.get("pipelineId") is not None and task.get("pipelineId") not in pipeline_ids:
        return False
    if task.get("completedRunId") is not None and task.get("completedRunId") not in run_ids:
        return False
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or artifact.get("taskId") != task_id
            or artifact.get("runId") not in run_ids
            or not _public_key_matches(artifact.get("publicKey"), task_id, artifact.get("sha256"))
        ):
            return False
    trajectory = data.get("trajectory")
    if trajectory is not None:
        matching_run = next(
            (run for run in runs if isinstance(run, dict) and run.get("runId") == trajectory.get("runId")),
            None,
        )
        if (
            not isinstance(trajectory, dict)
            or trajectory.get("taskId") != task_id
            or trajectory.get("runId") not in run_ids
            or trajectory.get("pipelineId") not in pipeline_ids
            or trajectory.get("runState") != "completed"
            or matching_run is None
            or trajectory.get("role") != matching_run.get("role")
            or trajectory.get("startedAt") != matching_run.get("startedAt")
            or trajectory.get("completedAt") != matching_run.get("completedAt")
            or trajectory.get("durationMs") != matching_run.get("durationMs")
            or trajectory.get("sha256") != matching_run.get("atifDigest")
            or not _public_key_matches(trajectory.get("publicKey"), task_id, trajectory.get("sha256"))
        ):
            return False
    return True


def _fixed_artifact_path(task_id: str, logical_path: str) -> str:
    encoded_path = quote(logical_path, safe="-_.!~*'()")
    return f"/api/steward/tasks/{quote(task_id, safe='')}/artifact?path={encoded_path}"


def _safe_public_redirect(location: str, public_key: str) -> bool:
    if not PUBLIC_KEY_PATTERN.fullmatch(public_key):
        return False
    try:
        parsed = urlsplit(location)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        return False
    if parsed.query or parsed.fragment:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    lowered = hostname.lower().rstrip(".")
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if any(character in parsed.path for character in "\\\x00\r\n"):
        return False
    try:
        decoded_path = unquote(parsed.path)
    except Exception:
        return False
    if any(
        segment in {".", ".."} or any(ord(character) < 0x20 for character in segment)
        for segment in decoded_path.split("/")
    ) or "\\" in decoded_path:
        return False
    expected_segments = public_key.split("/")
    actual_segments = decoded_path.rstrip("/").split("/")
    return len(actual_segments) >= len(expected_segments) and actual_segments[-len(expected_segments):] == expected_segments


def _select_artifact_action(
    trajectory_data: object,
    task_id: str,
    run_id: str,
    detail_data: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not isinstance(trajectory_data, dict) or not isinstance(trajectory_data.get("artifacts"), list):
        return None
    detail_artifacts = {
        artifact.get("artifactId"): artifact
        for artifact in detail_data.get("artifacts", [])
        if isinstance(artifact, dict)
    }
    for display_artifact in trajectory_data["artifacts"]:
        if not isinstance(display_artifact, dict):
            continue
        action = display_artifact.get("action")
        if not isinstance(action, dict) or action.get("kind") == "unavailable":
            continue
        if action.get("kind") not in {"image", "download"}:
            return {"invalid": True}, {}
        artifact_id = display_artifact.get("artifactId")
        detail_artifact = detail_artifacts.get(artifact_id)
        logical_path = action.get("logicalPath")
        if (
            not isinstance(detail_artifact, dict)
            or action.get("artifactId") != artifact_id
            or action.get("taskId") != task_id
            or action.get("runId") != run_id
            or not isinstance(logical_path, str)
            or action.get("href") != _fixed_artifact_path(task_id, logical_path)
            or not SAME_ORIGIN_ARTIFACT_PATTERN.fullmatch(action.get("href", ""))
            or detail_artifact.get("taskId") != task_id
            or detail_artifact.get("runId") != run_id
            or detail_artifact.get("logicalPath") != logical_path
            or detail_artifact.get("mediaType") != action.get("mediaType")
            or detail_artifact.get("availability") != "available"
            or not PUBLIC_KEY_PATTERN.fullmatch(str(detail_artifact.get("publicKey", "")))
        ):
            return {"invalid": True}, {}
        return action, detail_artifact
    return None


def _add_task_skips(result: dict[str, Any], detail: str) -> None:
    _add_check(result, "task_detail", "skip", detail=detail)
    _add_check(result, "task_trajectory", "skip", detail=detail)
    _add_check(result, "task_artifact", "skip", detail=detail)


def run_check(
    *,
    base_url: str,
    now: datetime,
    max_latency_ms: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": False,
        "checked_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "schemaVersions": {"cloud": CLOUD_SCHEMA_VERSION, "trajectory": TRAJECTORY_SCHEMA_VERSION},
        "thresholds": {
            "max_latency_ms": max_latency_ms,
            "timeout_seconds": timeout_seconds,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
        "checks": [],
    }
    try:
        schema = _load_cloud_schema()
    except ContractError as error:
        _add_check(result, "cloud_schema", "fail", detail=str(error))
        return result
    _add_check(result, "cloud_schema", "pass")

    dashboard = _fetch(base_url, "/steward", timeout_seconds)
    if dashboard.status_code == 200 and dashboard.error is None:
        _add_check(result, "dashboard", "pass", status_code=200)
        header_problems = _header_problems(dashboard.headers, "text/html")
        if header_problems:
            _add_check(result, "dashboard_headers", "fail", detail="invalid_headers", problems=header_problems)
        else:
            _add_check(result, "dashboard_headers", "pass")
        finding = _scan_response(dashboard.body, strict_urls=False)
        if finding:
            _add_check(result, "dashboard_privacy", "fail", detail=finding)
        else:
            _add_check(result, "dashboard_privacy", "pass")
    else:
        _add_check(result, "dashboard", "fail", detail=dashboard.error or f"http_{dashboard.status_code}")
        _add_check(result, "dashboard_headers", "skip", detail="dashboard_unavailable")
        _add_check(result, "dashboard_privacy", "skip", detail="dashboard_unavailable")
    _add_latency(result, "dashboard_latency", dashboard, max_latency_ms)

    status_response = _fetch(base_url, "/api/steward/status", timeout_seconds)
    status_document = _record_page(
        result,
        "status",
        status_response,
        schema,
        "statusResponse",
        max_latency_ms,
    )
    status_data = status_document.get("data") if isinstance(status_document, dict) else None
    if isinstance(status_data, dict):
        if status_data.get("state") == "unavailable":
            _add_check(result, "status_state", "fail", detail="unavailable")
        else:
            _add_check(result, "status_state", "pass")
    else:
        _add_check(result, "status_state", "skip", detail="status_unavailable")

    tasks_response = _fetch(base_url, "/api/steward/tasks", timeout_seconds)
    tasks_document = _record_page(
        result,
        "tasks",
        tasks_response,
        schema,
        "taskPageResponse",
        max_latency_ms,
    )
    tasks_data = tasks_document.get("data") if isinstance(tasks_document, dict) else None
    task_items: list[object] = []
    if isinstance(tasks_data, dict) and isinstance(tasks_data.get("items"), list) and isinstance(tasks_data.get("pagination"), dict):
        task_items = tasks_data["items"]
        pagination = tasks_data["pagination"]
        total = pagination.get("total")
        if total == 0 and (task_items or pagination.get("hasNextPage") is not False):
            _add_check(result, "task_collection", "fail", detail="pagination_mismatch")
        elif total > 0 and not task_items:
            _add_check(result, "task_collection", "fail", detail="missing_first_page_task")
        else:
            _add_check(result, "task_collection", "pass")
    else:
        _add_check(result, "task_collection", "skip", detail="tasks_unavailable")

    if isinstance(status_data, dict) and isinstance(tasks_data, dict):
        state = status_data.get("state")
        total = tasks_data.get("pagination", {}).get("total") if isinstance(tasks_data.get("pagination"), dict) else None
        task_count = status_data.get("taskCount")
        if state == "empty" and (total != 0 or task_items):
            _add_check(result, "publication_state", "fail", detail="empty_state_mismatch")
        elif state == "empty":
            if task_count == 0:
                _add_check(result, "publication_state", "pass")
            else:
                _add_check(result, "publication_state", "fail", detail="empty_state_mismatch")
        elif state == "available":
            first_task_selectable = bool(
                task_items
                and isinstance(task_items[0], dict)
                and _valid_identifier(task_items[0].get("taskId"))
            )
            if task_count > 0 and total == task_count and first_task_selectable:
                _add_check(result, "publication_state", "pass")
            else:
                _add_check(result, "publication_state", "fail", detail="available_state_mismatch")
        else:
            _add_check(result, "publication_state", "pass")
    else:
        _add_check(result, "publication_state", "skip", detail="status_or_tasks_unavailable")

    if isinstance(status_data, dict) and status_data.get("state") == "available":
        _record_usage_surface(result, "usage_global", dashboard, max_latency_ms)
    else:
        _add_check(result, "usage_global_structure", "skip", detail="no_real_task")
        _add_check(result, "usage_global_coverage", "skip", detail="no_real_task")
        _add_check(result, "usage_global_metrics", "skip", detail="no_real_task")
        _add_check(result, "usage_global_ownership", "skip", detail="no_real_task")

    selected_task: dict[str, Any] | None = None
    task_id: str | None = None
    if task_items:
        candidate = task_items[0]
        if isinstance(candidate, dict) and _valid_identifier(candidate.get("taskId")):
            selected_task = candidate
            task_id = candidate["taskId"]
            _add_check(result, "task_selection", "pass")
        else:
            _add_check(result, "task_selection", "fail", detail="invalid_identifier")
    else:
        _add_check(result, "task_selection", "skip", detail="no_public_task")

    if task_id is None or selected_task is None:
        _add_task_skips(result, "no_public_task")
    else:
        detail_path = f"/api/steward/tasks/{quote(task_id, safe='')}"
        detail_response = _fetch(base_url, detail_path, timeout_seconds)
        detail_document = _record_page(
            result,
            "task_detail",
            detail_response,
            schema,
            "taskDetailResponse",
            max_latency_ms,
        )
        detail_data = detail_document.get("data") if isinstance(detail_document, dict) else None
        if detail_data is not None and not _detail_ownership_is_valid(detail_data, task_id):
            _add_check(result, "task_detail_ownership", "fail", detail="ownership_mismatch")
            detail_data = None
        elif detail_data is not None:
            _add_check(result, "task_detail_ownership", "pass")
        else:
            _add_check(result, "task_detail_ownership", "skip", detail="detail_unavailable")

        task_surface_path = f"/steward/tasks/{quote(task_id, safe='')}"
        task_surface_response = _fetch(base_url, task_surface_path, timeout_seconds)
        _record_usage_surface(
            result,
            "usage_task",
            task_surface_response,
            max_latency_ms,
            task_id=task_id,
        )

        trajectory_data: object | None = None
        trajectory_run_id: str | None = None
        if isinstance(detail_data, dict) and isinstance(detail_data.get("trajectory"), dict):
            descriptor = detail_data["trajectory"]
            if _valid_identifier(descriptor.get("runId")) and descriptor.get("runState") == "completed":
                trajectory_run_id = descriptor["runId"]
            else:
                _add_check(result, "task_trajectory", "fail", detail="invalid_run_identifier")
        elif isinstance(detail_data, dict):
            _add_check(result, "task_trajectory", "skip", detail="no_public_run")

        if trajectory_run_id is not None and isinstance(detail_data, dict):
            trajectory_path = (
                f"/api/steward/tasks/{quote(task_id, safe='')}/transcript?run="
                f"{quote(trajectory_run_id, safe='')}"
            )
            trajectory_response = _fetch(base_url, trajectory_path, timeout_seconds)
            trajectory_document = _record_page(
                result,
                "task_trajectory",
                trajectory_response,
                schema,
                "completeTrajectoryResponse",
                max_latency_ms,
            )
            trajectory_data = trajectory_document.get("data") if isinstance(trajectory_document, dict) else None
            if isinstance(trajectory_data, dict):
                if (
                    trajectory_data.get("taskId") != task_id
                    or trajectory_data.get("runId") != trajectory_run_id
                    or trajectory_data.get("pipelineId") != detail_data["trajectory"].get("pipelineId")
                ):
                    _add_check(result, "task_trajectory_ownership", "fail", detail="ownership_mismatch")
                    trajectory_data = None
                else:
                    _add_check(result, "task_trajectory_ownership", "pass")
            else:
                _add_check(result, "task_trajectory_ownership", "skip", detail="trajectory_unavailable")

        if isinstance(trajectory_data, dict) and isinstance(detail_data, dict) and trajectory_run_id is not None:
            action_selection = _select_artifact_action(trajectory_data, task_id, trajectory_run_id, detail_data)
            if action_selection is None:
                _add_check(result, "task_artifact", "skip", detail="no_public_artifact")
            elif action_selection[0].get("invalid"):
                _add_check(result, "task_artifact", "fail", detail="invalid_action")
            else:
                action, detail_artifact = action_selection
                artifact_path = _fixed_artifact_path(task_id, action["logicalPath"])
                artifact_response = _fetch(base_url, artifact_path, timeout_seconds)
                if artifact_response.status_code == 307 and artifact_response.error == "http_307":
                    _add_check(result, "task_artifact", "pass", status_code=307)
                    header_problems = _header_problems(
                        artifact_response.headers,
                        "application/octet-stream",
                        require_nosniff=True,
                    )
                    if header_problems:
                        _add_check(result, "task_artifact_headers", "fail", detail="invalid_headers", problems=header_problems)
                    else:
                        _add_check(result, "task_artifact_headers", "pass")
                    location = artifact_response.headers.get("location")
                    if not location or not _safe_public_redirect(location, detail_artifact["publicKey"]):
                        _add_check(result, "task_artifact_redirect", "fail", detail="unsafe_redirect")
                    else:
                        _add_check(result, "task_artifact_redirect", "pass", detail="unfollowed")
                else:
                    _add_check(
                        result,
                        "task_artifact",
                        "fail",
                        detail=artifact_response.error or f"http_{artifact_response.status_code}",
                    )
                    _add_check(result, "task_artifact_headers", "skip", detail="redirect_unavailable")
                    _add_check(result, "task_artifact_redirect", "skip", detail="redirect_unavailable")
                _add_latency(result, "task_artifact_latency", artifact_response, max_latency_ms)
        elif trajectory_run_id is not None and not isinstance(trajectory_data, dict):
            _add_check(result, "task_artifact", "skip", detail="trajectory_unavailable")
        elif isinstance(detail_data, dict) and trajectory_run_id is None and not any(
            check["name"] == "task_artifact" for check in result["checks"]
        ):
            _add_check(result, "task_artifact", "skip", detail="no_public_run")
        elif not isinstance(detail_data, dict):
            _add_check(result, "task_trajectory", "skip", detail="detail_unavailable")
            _add_check(result, "task_artifact", "skip", detail="detail_unavailable")

    result["ok"] = not any(check["status"] == "fail" for check in result["checks"])
    return result


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Explicit site origin to check")
    parser.add_argument("--output", type=Path, help="Write the sanitized JSON result to this path")
    parser.add_argument("--max-latency-ms", type=_positive_float, default=DEFAULT_MAX_LATENCY_MS)
    parser.add_argument("--timeout-seconds", type=_positive_float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--now", help="UTC timestamp override for deterministic fixture checks")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        base_url = _parse_base_url(args.base_url)
        now = _parse_timestamp(args.now) if args.now else datetime.now(timezone.utc)
    except ValueError as error:
        parser.error(str(error))

    result = run_check(
        base_url=base_url,
        now=now,
        max_latency_ms=args.max_latency_ms,
        timeout_seconds=args.timeout_seconds,
    )
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(encoded, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

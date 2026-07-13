#!/usr/bin/env python3
"""Read-only synthetic check for the deployed Steward monitor contract."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from steward.schema.validate import (  # noqa: E402
    SchemaValidationError,
    load_public_monitor_schema_version,
    validate_public_monitor,
)

DEFAULT_MAX_AGE_SECONDS = 120.0
DEFAULT_MAX_LATENCY_MS = 2_000.0
DEFAULT_CLOCK_SKEW_SECONDS = 30.0
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
PUBLIC_TASK_DETAIL_SCHEMA_VERSION = 2

PRIVATE_PATH_PATTERN = re.compile(
    r"(?i)(?:/home/|/media/|/tmp/|/worktrees/|/transcripts/|/patches/|file://)"
)
PRIVATE_CREDENTIAL_PATTERN = re.compile(
    r"(?i)begin private key|authorization\s*:\s*bearer|"
    r"(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]"
)
PRIVATE_THREAD_PATTERN = re.compile(r"(?i)\bthread(?:[_ .-]?id|\.started)\b")
RAW_TRANSCRIPT_PATTERN = re.compile(
    r'(?i)"mode"\s*:\s*"raw"|\braw[_ -]?transcript\b'
)
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "password",
    "private_key",
    "prompt",
    "secret",
    "system_prompt",
    "thread_id",
    "token",
    "user_prompt",
}


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
        headers={"Accept": "text/html, application/json", "Cache-Control": "no-cache"},
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


def _scan_text(text: str) -> str | None:
    if PRIVATE_PATH_PATTERN.search(text):
        return "private_path"
    if PRIVATE_CREDENTIAL_PATTERN.search(text):
        return "credential"
    if PRIVATE_THREAD_PATTERN.search(text):
        return "thread_marker"
    if RAW_TRANSCRIPT_PATTERN.search(text):
        return "raw_transcript"
    return None


def _scan_private_values(value: object) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).strip().lower().replace("-", "_")
            if normalized_key in SENSITIVE_KEYS and _has_value(child):
                if normalized_key in {"prompt", "system_prompt", "user_prompt"}:
                    return "prompt"
                if normalized_key in {"thread_id"}:
                    return "thread_marker"
                return "credential"
            if normalized_key == "mode" and child == "raw":
                return "raw_transcript"
            finding = _scan_private_values(child)
            if finding:
                return finding
        return None
    if isinstance(value, list):
        for child in value:
            finding = _scan_private_values(child)
            if finding:
                return finding
        return None
    if isinstance(value, str):
        return _scan_text(value)
    return None


def _scan_response(body: bytes, document: object | None = None) -> str | None:
    if document is not None:
        finding = _scan_private_values(document)
        if finding:
            return finding
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return "invalid_utf8"
    return _scan_text(text)


def _header_problems(headers: dict[str, str], content_type: str) -> list[str]:
    problems: list[str] = []
    if headers.get("cache-control", "").strip().lower() != "no-store":
        problems.append("cache_control")
    if not headers.get("content-type", "").lower().startswith(content_type):
        problems.append("content_type")
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        problems.append("nosniff")
    return problems


def _content_type_problems(headers: dict[str, str], content_type: str) -> list[str]:
    if headers.get("content-type", "").lower().startswith(content_type):
        return []
    return ["content_type"]


def _task_detail_is_well_formed(document: object, task_id: str) -> bool:
    if not isinstance(document, dict):
        return False
    if document.get("schema_version") != PUBLIC_TASK_DETAIL_SCHEMA_VERSION:
        return False
    if not isinstance(document.get("task"), dict):
        return False
    if document["task"].get("id") != task_id:
        return False
    return all(isinstance(document.get(field), expected) for field, expected in (
        ("events", list),
        ("attempts", list),
        ("validations", list),
        ("artifacts", dict),
    ))


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


def run_monitor(
    *,
    base_url: str,
    now: datetime,
    max_age_seconds: float,
    max_latency_ms: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    expected_schema_version = load_public_monitor_schema_version()
    result: dict[str, Any] = {
        "ok": False,
        "checked_at": now.isoformat().replace("+00:00", "Z"),
        "expected_schema_version": expected_schema_version,
        "thresholds": {
            "max_age_seconds": max_age_seconds,
            "max_latency_ms": max_latency_ms,
        },
        "checks": [],
    }

    dashboard = _fetch(base_url, "/steward", timeout_seconds)
    if dashboard.status_code == 200 and dashboard.error is None:
        _add_check(result, "dashboard", "pass", status_code=dashboard.status_code)
        dashboard_headers = _content_type_problems(dashboard.headers, "text/html")
        if dashboard_headers:
            _add_check(result, "dashboard_headers", "fail", detail="invalid_headers", problems=dashboard_headers)
        else:
            _add_check(result, "dashboard_headers", "pass")
        dashboard_finding = _scan_response(dashboard.body)
        if dashboard_finding:
            _add_check(result, "dashboard_privacy", "fail", detail=dashboard_finding)
        else:
            _add_check(result, "dashboard_privacy", "pass")
    else:
        _add_check(result, "dashboard", "fail", detail=dashboard.error or f"http_{dashboard.status_code}")
        _add_check(result, "dashboard_headers", "skip", detail="dashboard_unavailable")
        _add_check(result, "dashboard_privacy", "skip", detail="dashboard_unavailable")
    if dashboard.latency_ms > max_latency_ms:
        _add_check(result, "dashboard_latency", "fail", latency_ms=dashboard.latency_ms)
    else:
        _add_check(result, "dashboard_latency", "pass", latency_ms=dashboard.latency_ms)

    status_response = _fetch(base_url, "/steward/status", timeout_seconds)
    document: object | None = None
    if status_response.status_code == 200 and status_response.error is None:
        _add_check(result, "status_endpoint", "pass", status_code=status_response.status_code)
        header_problems = _header_problems(status_response.headers, "application/json")
        if header_problems:
            _add_check(result, "status_headers", "fail", detail="invalid_headers", problems=header_problems)
        else:
            _add_check(result, "status_headers", "pass")
        document = _decode_json(status_response.body)
        if document is None:
            _add_check(result, "status_schema", "fail", detail="malformed_json")
        elif not isinstance(document, dict) or document.get("schema_version") != expected_schema_version:
            _add_check(result, "status_schema", "fail", detail="schema_incompatible")
        else:
            try:
                validate_public_monitor(document)
            except SchemaValidationError:
                _add_check(result, "status_schema", "fail", detail="schema_invalid")
            else:
                _add_check(result, "status_schema", "pass", schema_version=expected_schema_version)
        status_finding = _scan_response(status_response.body, document)
        if status_finding:
            _add_check(result, "status_privacy", "fail", detail=status_finding)
        else:
            _add_check(result, "status_privacy", "pass")
    else:
        _add_check(result, "status_endpoint", "fail", detail=status_response.error or f"http_{status_response.status_code}")
        _add_check(result, "status_headers", "skip", detail="status_unavailable")
        _add_check(result, "status_schema", "skip", detail="status_unavailable")
        _add_check(result, "status_privacy", "skip", detail="status_unavailable")
    if status_response.latency_ms > max_latency_ms:
        _add_check(result, "status_latency", "fail", latency_ms=status_response.latency_ms)
    else:
        _add_check(result, "status_latency", "pass", latency_ms=status_response.latency_ms)

    if isinstance(document, dict) and document.get("schema_version") == expected_schema_version:
        timestamps: list[datetime] = []
        timestamp_error = False
        runtime = document.get("runtime")
        heartbeat_at = runtime.get("heartbeat_at") if isinstance(runtime, dict) else None
        for value in (document.get("generated_at"), heartbeat_at):
            if not isinstance(value, str):
                timestamp_error = True
                continue
            try:
                timestamps.append(_parse_timestamp(value))
            except ValueError:
                timestamp_error = True
        if timestamp_error or len(timestamps) != 2:
            _add_check(result, "status_freshness", "fail", detail="invalid_timestamp")
        else:
            age_seconds = max((now - timestamp).total_seconds() for timestamp in timestamps)
            if age_seconds < -DEFAULT_CLOCK_SKEW_SECONDS:
                _add_check(result, "status_freshness", "fail", detail="clock_skew", age_seconds=round(age_seconds, 3))
            elif age_seconds > max_age_seconds:
                _add_check(result, "status_freshness", "fail", detail="stale", age_seconds=round(age_seconds, 3))
            else:
                _add_check(result, "status_freshness", "pass", age_seconds=round(max(0.0, age_seconds), 3))
    else:
        _add_check(result, "status_freshness", "skip", detail="status_schema_unavailable")

    task_id: str | None = None
    if isinstance(document, dict) and isinstance(document.get("tasks"), list):
        for task in document["tasks"]:
            if isinstance(task, dict) and isinstance(task.get("id"), str) and task["id"]:
                task_id = task["id"]
                break

    if task_id is None:
        _add_check(result, "task_artifact", "skip", detail="no_public_task")
    else:
        task_path = f"/steward/data/tasks/{quote(task_id, safe='')}.json"
        artifact_response = _fetch(base_url, task_path, timeout_seconds)
        if artifact_response.status_code == 404:
            _add_check(result, "task_artifact", "skip", detail="not_published", status_code=404)
        elif artifact_response.status_code != 200 or artifact_response.error is not None:
            _add_check(result, "task_artifact", "fail", detail=artifact_response.error or f"http_{artifact_response.status_code}")
        else:
            header_problems = _header_problems(artifact_response.headers, "application/json")
            if header_problems:
                _add_check(result, "task_artifact_headers", "fail", detail="invalid_headers", problems=header_problems)
            else:
                _add_check(result, "task_artifact_headers", "pass")
            artifact_document = _decode_json(artifact_response.body)
            artifact_finding = _scan_response(artifact_response.body, artifact_document)
            if artifact_finding:
                _add_check(result, "task_artifact_privacy", "fail", detail=artifact_finding)
            else:
                _add_check(result, "task_artifact_privacy", "pass")
            if artifact_document is None:
                _add_check(result, "task_artifact", "fail", detail="malformed_json", status_code=200)
            elif not _task_detail_is_well_formed(artifact_document, task_id):
                _add_check(result, "task_artifact", "fail", detail="invalid_task_detail", status_code=200)
            else:
                _add_check(result, "task_artifact", "pass", status_code=200, schema_version=PUBLIC_TASK_DETAIL_SCHEMA_VERSION)
        if artifact_response.latency_ms > max_latency_ms:
            _add_check(result, "task_artifact_latency", "fail", latency_ms=artifact_response.latency_ms)
        else:
            _add_check(result, "task_artifact_latency", "pass", latency_ms=artifact_response.latency_ms)

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
    parser.add_argument("--max-age-seconds", type=_positive_float, default=DEFAULT_MAX_AGE_SECONDS)
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

    result = run_monitor(
        base_url=base_url,
        now=now,
        max_age_seconds=args.max_age_seconds,
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

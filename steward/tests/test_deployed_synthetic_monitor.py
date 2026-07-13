from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-steward-deployment.py"
FIXTURE_DIR = ROOT / "steward" / "schema" / "fixtures"
NOW = "2026-07-13T12:00:30Z"
TASK_ID = "task-20260713115945-a1b2c3d4"


@dataclass
class ResponseSpec:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay_seconds: float = 0.0


class FixtureServer:
    def __init__(self, responses: dict[str, ResponseSpec]):
        self.responses = responses
        responses_ref = responses

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                response = responses_ref.get(urlsplit(self.path).path)
                if response is None:
                    response = ResponseSpec(status=404, body=b"not found")
                if response.delay_seconds:
                    time.sleep(response.delay_seconds)
                self.send_response(response.status)
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(response.body)))
                self.end_headers()
                self.wfile.write(response.body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> "FixtureServer":
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _json_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / "public-monitor-v3" / f"{name}.json").read_text())


def _json_bytes(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode()


def _headers(content_type: str) -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Content-Type": content_type,
        "X-Content-Type-Options": "nosniff",
    }


def _responses(status: dict | None = None, detail: dict | None = None) -> dict[str, ResponseSpec]:
    status = status or _json_fixture("active")
    responses = {
        "/steward": ResponseSpec(
            body=b"<!doctype html><html><body>CoQUIC Steward</body></html>",
            headers=_headers("text/html; charset=utf-8"),
        ),
        "/steward/status": ResponseSpec(
            body=_json_bytes(status),
            headers=_headers("application/json; charset=utf-8"),
        ),
    }
    if detail is not None:
        responses[f"/steward/data/tasks/{TASK_ID}.json"] = ResponseSpec(
            body=_json_bytes(detail),
            headers=_headers("application/json; charset=utf-8"),
        )
    return responses


def _run_check(base_url: str, tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    output = tmp_path / "synthetic-result.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--base-url",
            base_url,
            "--now",
            NOW,
            "--output",
            str(output),
            *extra,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    result = json.loads(completed.stdout)
    assert json.loads(output.read_text()) == result
    return completed, result


def _statuses(result: dict, name: str) -> list[str]:
    return [check["status"] for check in result["checks"] if check["name"] == name]


def test_current_contract_and_available_task_artifact_pass(tmp_path: Path) -> None:
    detail = json.loads((FIXTURE_DIR / "public-task-v2" / "feature.json").read_text())
    with FixtureServer(_responses(_json_fixture("active"), detail)) as server:
        completed, result = _run_check(server.base_url, tmp_path)

    assert completed.returncode == 0
    assert result["ok"] is True
    assert _statuses(result, "status_schema") == ["pass"]
    assert _statuses(result, "status_freshness") == ["pass"]
    assert _statuses(result, "task_artifact") == ["pass"]
    assert "contract-seeded-secret" not in completed.stdout


@pytest.mark.parametrize("case", ["missing", "cached", "stale", "malformed", "incompatible", "privacy"])
def test_contract_regressions_fail_without_logging_response_values(
    case: str, tmp_path: Path
) -> None:
    status = _json_fixture("active")
    responses = _responses(status)
    if case == "missing":
        del responses["/steward/status"]
    elif case == "cached":
        responses["/steward/status"].headers["Cache-Control"] = "public, max-age=60"
    elif case == "stale":
        status = _json_fixture("stale")
        responses = _responses(status)
    elif case == "malformed":
        responses["/steward/status"].body = b"{"
    elif case == "incompatible":
        status["schema_version"] = 2
        responses = _responses(status)
    elif case == "privacy":
        status["runtime"]["current_cycle_reason"] = (
            "/home/private/worktree api_key=fixture-secret"
        )
        responses = _responses(status)

    with FixtureServer(responses) as server:
        completed, result = _run_check(server.base_url, tmp_path)

    assert completed.returncode == 1
    assert result["ok"] is False
    assert all("/home/private" not in check.get("detail", "") for check in result["checks"])
    assert "fixture-secret" not in completed.stdout
    if case == "missing":
        assert _statuses(result, "status_endpoint") == ["fail"]
    elif case == "cached":
        assert _statuses(result, "status_headers") == ["fail"]
    elif case == "stale":
        assert _statuses(result, "status_freshness") == ["fail"]
    elif case == "malformed":
        assert _statuses(result, "status_schema") == ["fail"]
    elif case == "incompatible":
        assert _statuses(result, "status_schema") == ["fail"]
    else:
        assert _statuses(result, "status_privacy") == ["fail"]


def test_task_artifact_redaction_and_latency_are_enforced(tmp_path: Path) -> None:
    detail = json.loads((FIXTURE_DIR / "public-task-v2" / "feature.json").read_text())
    detail["attempts"][0]["worker"]["transcript"]["mode"] = "raw"
    responses = _responses(_json_fixture("active"), detail)
    responses["/steward/status"].delay_seconds = 0.03

    with FixtureServer(responses) as server:
        completed, result = _run_check(server.base_url, tmp_path, "--max-latency-ms", "5")

    assert completed.returncode == 1
    assert _statuses(result, "status_latency") == ["fail"]
    assert _statuses(result, "task_artifact_privacy") == ["fail"]


def test_mixed_timestamp_future_skew_fails_independently(tmp_path: Path) -> None:
    status = _json_fixture("active")
    status["runtime"]["heartbeat_at"] = "2026-07-13T12:01:31Z"

    with FixtureServer(_responses(status)) as server:
        completed, result = _run_check(server.base_url, tmp_path)

    assert completed.returncode == 1
    freshness = next(check for check in result["checks"] if check["name"] == "status_freshness")
    assert freshness == {
        "detail": "clock_skew",
        "fields": ["runtime.heartbeat_at"],
        "name": "status_freshness",
        "status": "fail",
    }


def test_publish_outage_then_recovery_is_read_only(tmp_path: Path) -> None:
    detail = json.loads((FIXTURE_DIR / "public-task-v2" / "feature.json").read_text())
    responses = _responses(_json_fixture("active"), detail)
    responses["/steward/status"] = ResponseSpec(
        status=503,
        body=b'{"status":"unavailable","reason":"missing"}',
        headers=_headers("application/json; charset=utf-8"),
    )

    with FixtureServer(responses) as server:
        failed, failed_result = _run_check(server.base_url, tmp_path)
        responses["/steward/status"] = ResponseSpec(
            body=_json_bytes(_json_fixture("active")),
            headers=_headers("application/json; charset=utf-8"),
        )
        recovered, recovered_result = _run_check(server.base_url, tmp_path)

    assert failed.returncode == 1
    assert failed_result["ok"] is False
    assert recovered.returncode == 0
    assert recovered_result["ok"] is True

from __future__ import annotations

import copy
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
CLOUD_EXAMPLE_DIR = ROOT / "site-v2" / "examples" / "steward-cloud"
NOW = "2026-07-28T00:00:03Z"


@dataclass
class ResponseSpec:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay_seconds: float = 0.0


class FixtureServer:
    def __init__(self, responses: dict[str, ResponseSpec]):
        self.responses = responses
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        responses_ref = responses
        requests_ref = self.requests

        class Handler(BaseHTTPRequestHandler):
            def _serve(self) -> None:
                requests_ref.append(
                    (self.command, self.path, {key.lower(): value for key, value in self.headers.items()})
                )
                response = responses_ref.get(self.path)
                if response is None:
                    response = responses_ref.get(urlsplit(self.path).path)
                if response is None:
                    response = ResponseSpec(status=404, body=b"not found", headers=_headers("text/plain"))
                if response.delay_seconds:
                    time.sleep(response.delay_seconds)
                self.send_response(response.status)
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(response.body)))
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(response.body)
                    except (BrokenPipeError, ConnectionResetError):
                        return

            def do_GET(self) -> None:  # noqa: N802
                self._serve()

            def do_POST(self) -> None:  # noqa: N802
                self._serve()

            def do_PUT(self) -> None:  # noqa: N802
                self._serve()

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


def _json_example(name: str) -> dict:
    return json.loads((CLOUD_EXAMPLE_DIR / name).read_text(encoding="utf-8"))


def _json_bytes(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def _headers(content_type: str) -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Content-Type": content_type,
    }


def _dashboard() -> ResponseSpec:
    return ResponseSpec(
        body=b"<!doctype html><html><body>CoQUIC Steward</body></html>",
        headers=_headers("text/html; charset=utf-8"),
    )


def _status(*, empty: bool) -> dict:
    return {
        "schemaVersion": "3.0",
        "generatedAt": NOW,
        "data": {
            "state": "empty" if empty else "available",
            "taskCount": 0 if empty else 1,
            "latestPublicationAt": None if empty else "2026-07-28T00:00:02Z",
        },
    }


def _task_page(detail: dict | None) -> dict:
    task = detail["data"]["task"] if detail is not None else None
    return {
        "schemaVersion": "3.0",
        "generatedAt": NOW,
        "data": {
            "items": [] if task is None else [copy.deepcopy(task)],
            "pagination": {
                "page": 1,
                "pageSize": 50,
                "total": 0 if task is None else 1,
                "hasNextPage": False,
            },
        },
    }


def _empty_responses() -> dict[str, ResponseSpec]:
    return {
        "/steward": _dashboard(),
        "/api/steward/status": ResponseSpec(body=_json_bytes(_status(empty=True)), headers=_headers("application/json; charset=utf-8")),
        "/api/steward/tasks": ResponseSpec(body=_json_bytes(_task_page(None)), headers=_headers("application/json; charset=utf-8")),
    }


def _populated_responses() -> dict[str, ResponseSpec]:
    detail = _json_example("redacted-publication.json")
    trajectory = _json_example("complete-trajectory-redacted-multimodal.json")
    task_id = detail["data"]["task"]["taskId"]
    run_id = detail["data"]["trajectory"]["runId"]
    action = next(
        item["action"]
        for item in trajectory["data"]["artifacts"]
        if item["action"]["kind"] != "unavailable"
    )
    public_key = next(
        artifact["publicKey"]
        for artifact in detail["data"]["artifacts"]
        if artifact["artifactId"] == action["artifactId"]
    )
    return {
        "/steward": _dashboard(),
        "/api/steward/status": ResponseSpec(body=_json_bytes(_status(empty=False)), headers=_headers("application/json; charset=utf-8")),
        "/api/steward/tasks": ResponseSpec(body=_json_bytes(_task_page(detail)), headers=_headers("application/json; charset=utf-8")),
        f"/api/steward/tasks/{task_id}": ResponseSpec(body=_json_bytes(detail), headers=_headers("application/json; charset=utf-8")),
        f"/api/steward/tasks/{task_id}/transcript?run={run_id}": ResponseSpec(
            body=_json_bytes(trajectory), headers=_headers("application/json; charset=utf-8")
        ),
        action["href"]: ResponseSpec(
            status=307,
            headers={
                "Cache-Control": "no-store",
                "Content-Type": "application/octet-stream",
                "X-Content-Type-Options": "nosniff",
                "Location": f"https://objects.example/{public_key}",
            },
        ),
    }


def _run_check(base_url: str, tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    output = tmp_path / "result.json"
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
    assert json.loads(output.read_text(encoding="utf-8")) == result
    return completed, result


def _statuses(result: dict, name: str) -> list[str]:
    return [check["status"] for check in result["checks"] if check["name"] == name]


def test_empty_publication_passes_with_explicit_skips(tmp_path: Path) -> None:
    with FixtureServer(_empty_responses()) as server:
        completed, result = _run_check(server.base_url, tmp_path)

    assert completed.returncode == 0
    assert result["ok"] is True
    assert _statuses(result, "status_schema") == ["pass"]
    assert _statuses(result, "tasks_schema") == ["pass"]
    assert _statuses(result, "task_selection") == ["skip"]
    assert _statuses(result, "task_detail") == ["skip"]
    assert _statuses(result, "task_trajectory") == ["skip"]
    assert _statuses(result, "task_artifact") == ["skip"]


def test_populated_publication_checks_detail_trajectory_and_one_redirect(tmp_path: Path) -> None:
    responses = _populated_responses()
    with FixtureServer(responses) as server:
        completed, result = _run_check(server.base_url, tmp_path)

    assert completed.returncode == 0
    assert result["ok"] is True
    assert _statuses(result, "task_detail_schema") == ["pass"]
    assert _statuses(result, "task_trajectory_schema") == ["pass"]
    assert _statuses(result, "task_artifact_redirect") == ["pass"]
    assert _statuses(result, "task_artifact") == ["pass"]
    assert sum(path.startswith("/api/steward/tasks/") and "/artifact?" in path for _, path, _ in server.requests) == 1
    assert all(method == "GET" for method, _, _ in server.requests)
    assert all(headers.get("cache-control") == "no-store" for _, _, headers in server.requests)
    assert "objects.example" not in completed.stdout


@pytest.mark.parametrize("case", ["missing", "wrong_version", "malformed", "private", "oversize", "slow"])
def test_invalid_publication_paths_fail_without_response_values(case: str, tmp_path: Path) -> None:
    responses = _empty_responses()
    status_response = responses["/api/steward/status"]
    if case == "missing":
        del responses["/api/steward/status"]
    elif case == "wrong_version":
        document = _status(empty=True)
        document["schemaVersion"] = "2.0"
        status_response.body = _json_bytes(document)
    elif case == "malformed":
        status_response.body = b"{"
    elif case == "private":
        document = _status(empty=True)
        document["data"]["latestPublicationAt"] = "/home/private api_key=fixture-secret"
        status_response.body = _json_bytes(document)
    elif case == "oversize":
        status_response.body = b"x" * (4 * 1024 * 1024 + 1)
    elif case == "slow":
        status_response.delay_seconds = 0.03

    with FixtureServer(responses) as server:
        extra = ("--max-latency-ms", "5") if case == "slow" else ()
        completed, result = _run_check(server.base_url, tmp_path, *extra)

    assert completed.returncode == 1
    assert result["ok"] is False
    assert "fixture-secret" not in completed.stdout
    assert "/home/private" not in completed.stdout
    if case == "missing":
        assert _statuses(result, "status_endpoint") == ["fail"]
    elif case in {"wrong_version", "malformed", "private"}:
        assert _statuses(result, "status_schema") == ["fail"]
    elif case == "oversize":
        assert _statuses(result, "status_endpoint") == ["fail"]
    else:
        assert _statuses(result, "status_latency") == ["fail"]


def test_bad_headers_and_unsafe_redirect_are_terminal(tmp_path: Path) -> None:
    responses = _populated_responses()
    responses["/api/steward/tasks"].headers["Cache-Control"] = "public, max-age=60"
    with FixtureServer(responses) as server:
        completed, result = _run_check(server.base_url, tmp_path)
    assert completed.returncode == 1
    assert _statuses(result, "tasks_headers") == ["fail"]

    responses = _populated_responses()
    artifact_path = next(path for path in responses if "/artifact?" in path)
    responses[artifact_path].headers["Location"] = "http://127.0.0.1/private/object"
    with FixtureServer(responses) as server:
        completed, result = _run_check(server.base_url, tmp_path)
    assert completed.returncode == 1
    assert _statuses(result, "task_artifact_redirect") == ["fail"]
    assert not any(path.startswith("/private/") for _, path, _ in server.requests)


def test_outage_recovery_is_read_only_and_does_not_retry(tmp_path: Path) -> None:
    responses = _empty_responses()
    responses["/api/steward/status"] = ResponseSpec(
        status=503,
        body=b'{"problem":"unavailable"}',
        headers=_headers("application/json; charset=utf-8"),
    )
    with FixtureServer(responses) as server:
        failed, failed_result = _run_check(server.base_url, tmp_path)
        first_status_requests = [path for _, path, _ in server.requests if path == "/api/steward/status"]
        responses["/api/steward/status"] = ResponseSpec(
            body=_json_bytes(_status(empty=True)),
            headers=_headers("application/json; charset=utf-8"),
        )
        recovered, recovered_result = _run_check(server.base_url, tmp_path)

    assert failed.returncode == 1
    assert failed_result["ok"] is False
    assert recovered.returncode == 0
    assert recovered_result["ok"] is True
    assert len(first_status_requests) == 1


def test_private_and_arbitrary_action_hrefs_are_rejected(tmp_path: Path) -> None:
    responses = _populated_responses()
    trajectory_path = next(path for path in responses if "/transcript?run=" in path)
    trajectory = json.loads(responses[trajectory_path].body)
    for item in trajectory["data"]["artifacts"]:
        action = item.get("action")
        if action and action.get("kind") != "unavailable":
            action["href"] = "https://attacker.example/private"
            break
    responses[trajectory_path].body = _json_bytes(trajectory)

    with FixtureServer(responses) as server:
        completed, result = _run_check(server.base_url, tmp_path)

    assert completed.returncode == 1
    assert result["ok"] is False
    assert _statuses(result, "task_trajectory_schema") == ["fail"]
    assert not any("/artifact?" in path for _, path, _ in server.requests)

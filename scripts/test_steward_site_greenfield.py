"""Credential-free greenfield contract gate for Steward publication and Site V2.

The provider in this file is deliberately small: it implements the bounded D1
HTTP response shape and serves immutable R2 bytes over localhost.  The data is
created by the current Steward publisher and consumed by the real Site V2 route
handlers in ``site-v2/scripts/test_greenfield_contract.ts``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
from collections.abc import Mapping
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Lock, Thread
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

from coquic_steward.publication import AtifSource, RunIdentity, RunMetadata
from coquic_steward.publication.d1 import D1PublicationClient
from coquic_steward.publication.generation import PublicationComposer, PublicationGeneration, compose_publication_generation
from coquic_steward.publication.publisher import CloudPublisher, PublicationStatus
from coquic_steward.publication.outbox import PublicationRetryPolicy
from coquic_steward.publication.r2 import R2Client, R2ValidationError
from coquic_steward.storage import SQLiteTaskStore


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "steward-cloud" / "d1.sql"
ACCOUNT_ID = "a" * 32
DATABASE_ID = "12345678-1234-4abc-8def-1234567890ab"
READ_TOKEN = "greenfield-read-token"
TASK_ID = "task-greenfield"
PIPELINE_ID = "pipeline-greenfield"
RUN_ID = "run-greenfield"


class LoopbackProvider:
    """SQLite D1 and an in-memory R2 object store behind one loopback origin."""

    def __init__(self, database_path: Path) -> None:
        self.connection = sqlite3.connect(database_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.create_function("sha256", 1, lambda value: hashlib.sha256(str(value).encode("utf-8")).hexdigest(), deterministic=True)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA.read_text(encoding="utf-8"))
        self.objects: dict[tuple[str, str], tuple[bytes, dict[str, str]]] = {}
        self.lock = Lock()
        self.unavailable = False

    def close(self) -> None:
        self.connection.close()

    def execute(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if self.unavailable:
            return 503, {"success": False, "errors": [{"code": "temporarily-unavailable"}]}
        raw_statements = body.get("batch")
        if raw_statements is None:
            raw_statements = [{"sql": body.get("sql"), "params": body.get("params", [])}]
        if "batch" in body:
            if set(body) != {"batch"}:
                return 400, {"success": False, "errors": [{"code": "invalid-request"}]}
            raw_statements = body["batch"]
        else:
            if set(body) != {"sql", "params"}:
                return 400, {"success": False, "errors": [{"code": "invalid-request"}]}
            raw_statements = [{"sql": body["sql"], "params": body["params"]}]
        if not isinstance(raw_statements, list) or not raw_statements or len(raw_statements) > MAX_BATCH_STATEMENTS:
            return 400, {"success": False, "errors": [{"code": "invalid-request"}]}
        results: list[dict[str, Any]] = []
        total_params = 0
        with self.lock:
            try:
                self.connection.execute("BEGIN")
                for statement in raw_statements:
                    if not isinstance(statement, dict) or set(statement) != {"sql", "params"} or not isinstance(statement["sql"], str) or not statement["sql"].strip():
                        raise sqlite3.Error("invalid statement")
                    params = statement["params"]
                    if not isinstance(params, list):
                        raise sqlite3.Error("invalid params")
                    total_params += len(params)
                    if total_params > MAX_BATCH_PARAMETERS or any(isinstance(item, (dict, list, bytes, bytearray)) or not isinstance(item, (str, int, float, bool, type(None))) or (isinstance(item, float) and not math.isfinite(item)) for item in params):
                        raise sqlite3.Error("invalid params")
                    cursor = self.connection.execute(statement["sql"], params)
                    rows = [dict(row) for row in cursor.fetchall()] if cursor.description else []
                    if sum(len(item["results"]) for item in results) + len(rows) > MAX_RESULT_ROWS:
                        raise sqlite3.Error("result limit")
                    results.append({"success": True, "results": rows, "meta": {"changes": max(cursor.rowcount, 0)}})
                self.connection.commit()
            except (sqlite3.Error, TypeError, ValueError):
                self.connection.rollback()
                return 400, {"success": False, "errors": [{"code": "query-failed"}]}
            if len(json.dumps({"success": True, "errors": [], "result": results}, separators=(",", ":")).encode("utf-8")) > MAX_RESPONSE_BODY:
                return 500, {"success": False, "errors": [{"code": "response-too-large"}]}
        return 200, {"success": True, "errors": [], "result": results}

    def snapshot(self) -> str:
        """Return a value-free digest of every D1 row and R2 descriptor."""

        tables = [row[0] for row in self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        rows: list[dict[str, Any]] = []
        with self.lock:
            for table in tables:
                values = [dict(row) for row in self.connection.execute(f'SELECT * FROM "{table}"').fetchall()]
                rows.append({"table": table, "rows": values})
            objects = sorted((bucket, key, hashlib.sha256(value).hexdigest(), len(value), metadata)
                             for (bucket, key), (value, metadata) in self.objects.items())
        payload = {"d1": rows, "r2": objects}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def corrupt_dangling(self) -> str:
        with self.lock:
            original = str(self.connection.execute(
                "SELECT run_id FROM publication_generations WHERE task_id = ?", (TASK_ID,)
            ).fetchone()[0])
            self.connection.execute("PRAGMA foreign_keys = OFF")
            try:
                self.connection.execute("UPDATE publication_generations SET run_id = ? WHERE task_id = ?", ("dangling/run", TASK_ID))
                self.connection.commit()
            finally:
                self.connection.execute("PRAGMA foreign_keys = ON")
        return original

    def restore_dangling(self, original: str) -> None:
        with self.lock:
            self.connection.execute("UPDATE publication_generations SET run_id = ? WHERE task_id = ?", (original, TASK_ID))
            self.connection.commit()

    def corrupt_private_field(self) -> str:
        with self.lock:
            original = str(self.connection.execute("SELECT idempotency_key FROM publication_generations WHERE task_id = ?", (TASK_ID,)).fetchone()[0])
            self.connection.execute("UPDATE publication_generations SET idempotency_key = ? WHERE task_id = ?", ("file:///private/idempotency", TASK_ID))
            self.connection.commit()
        return original

    def restore_private_field(self, original: str) -> None:
        with self.lock:
            self.connection.execute("UPDATE publication_generations SET idempotency_key = ? WHERE task_id = ?", (original, TASK_ID))
            self.connection.commit()


MAX_REQUEST_BODY = 1 * 1024 * 1024
MAX_RESPONSE_BODY = 2 * 1024 * 1024
MAX_RESULT_ROWS = 4_096
MAX_BATCH_STATEMENTS = 64
MAX_BATCH_PARAMETERS = 99
PUBLIC_BUCKET = "greenfield-public"
PRIVATE_BUCKET = "greenfield-private"
D1_TOKENS = frozenset({READ_TOKEN})


class ProviderServer(ThreadingHTTPServer):
    provider: LoopbackProvider
    daemon_threads = True


class ProviderHandler(BaseHTTPRequestHandler):
    server: ProviderServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/plain", headers: Mapping[str, str] | None = None) -> None:
        if len(body) > MAX_RESPONSE_BODY:
            status, body = 500, b"response-too-large"
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", (headers or {}).get("Content-Length", str(len(body))))
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            if key.casefold() != "content-length": self.send_header(key, value)
        self.end_headers()
        if body: self.wfile.write(body)

    def _guard(self, method: str) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            self._send(400); return False
        try:
            parsed_host = urlsplit("//" + hosts[0].strip())
            port = parsed_host.port
        except ValueError:
            self._send(400); return False
        if parsed_host.hostname != "127.0.0.1" or port not in {None, self.server.server_port} or parsed_host.username or parsed_host.password or parsed_host.path not in {"", "/"} or parsed_host.query or parsed_host.fragment:
            self._send(421); return False
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment or method not in {"POST", "PUT", "GET", "HEAD", "DELETE"}:
            self._send(400 if parsed.query or parsed.fragment else 405); return False
        if self.headers.get_all("Transfer-Encoding", []):
            self._send(400); return False
        if method in {"GET", "HEAD", "DELETE"}:
            lengths = self.headers.get_all("Content-Length", [])
            if lengths and (len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) != 0):
                self._send(400); return False
        return True

    def _body(self) -> bytes | None:
        if self.headers.get("Transfer-Encoding"):
            self._send(400); return None
        values = self.headers.get_all("Content-Length", [])
        if len(values) != 1 or not values[0].isdigit():
            self._send(400); return None
        length = int(values[0])
        if length > MAX_REQUEST_BODY:
            self._send(413); return None
        body = self.rfile.read(length)
        if len(body) != length:
            self._send(400); return None
        return body

    @staticmethod
    def _r2_path(path: str) -> tuple[str, str] | None:
        parts = path.split("/")
        if len(parts) < 4 or parts[:2] != ["", "r2"]: return None
        decoded = [unquote(part) for part in parts[2:]]
        if decoded[0] in {PUBLIC_BUCKET, PRIVATE_BUCKET}:
            bucket, key_parts = decoded[0], decoded[1:]
        else:
            bucket, key_parts = PUBLIC_BUCKET, decoded
        key = "/".join(key_parts)
        if bucket not in {PUBLIC_BUCKET, PRIVATE_BUCKET} or not key or key.startswith("/") or ".." in key or "//" in key: return None
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in key): return None
        return bucket, key

    def _r2(self) -> tuple[str, str] | None:
        result = self._r2_path(urlsplit(self.path).path)
        if result is None: self._send(404)
        return result

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard("POST"):
            return
        if urlsplit(self.path).path != "/d1/query":
            self._send(404)
            return
        authorization = self.headers.get("Authorization", "")
        token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        if not any(hmac.compare_digest(token, candidate) for candidate in D1_TOKENS):
            self._send(401); return
        raw = self._body()
        if raw is None: return
        try:
            body = json.loads(raw.decode("utf-8"), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._send(400); return
        if not isinstance(body, dict): self._send(400); return
        status, response = self.server.provider.execute(body)
        self._send(status, json.dumps(response, separators=(",", ":")).encode(), "application/json")

    def do_PUT(self) -> None:  # noqa: N802
        if not self._guard("PUT"): return
        route, raw = self._r2(), self._body()
        if route is None or raw is None: return
        metadata = {name[11:].casefold(): value for name, value in self.headers.items() if name.casefold().startswith("x-amz-meta-")}
        with self.server.provider.lock:
            if self.server.provider.unavailable: self._send(503); return
            if self.headers.get("If-None-Match") == "*" and route in self.server.provider.objects: self._send(412); return
            self.server.provider.objects[route] = (bytes(raw), metadata)
        self._send(200)

    def _serve(self, head: bool) -> None:
        if not self._guard("HEAD" if head else "GET"): return
        route = self._r2()
        if route is None: return
        with self.server.provider.lock:
            if self.server.provider.unavailable: self._send(503); return
            stored = self.server.provider.objects.get(route)
        if stored is None: self._send(404); return
        content, metadata = stored
        digest = hashlib.sha256(content).hexdigest()
        headers = {"Content-Length": str(len(content)), "ETag": f'"{hashlib.md5(content, usedforsecurity=False).hexdigest()}"', "x-amz-checksum-sha256": base64.b64encode(bytes.fromhex(digest)).decode("ascii")}
        headers.update({f"x-amz-meta-{key}": value for key, value in metadata.items()})
        self._send(200, b"" if head else content, "application/octet-stream", headers)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(True)

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._guard("DELETE"): return
        route = self._r2()
        if route is None: return
        with self.server.provider.lock:
            self.server.provider.objects.pop(route, None)
        self._send(204)


class LoopbackD1Client:
    """D1 client adapter that forwards the producer's requests to localhost."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client()

    def post(self, _url: str, **kwargs: Any) -> httpx.Response:
        return self.client.post(f"{self.base_url}/d1/query", **kwargs)

    def close(self) -> None:
        self.client.close()


class S3PreconditionError(Exception):
    response = {"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}


class S3NotFoundError(Exception):
    response = {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}}


class HttpR2Transport:
    """S3-shaped adapter exercising the provider's R2 PUT and HEAD operations."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client()

    def _url(self, bucket: str, key: str) -> str:
        from urllib.parse import quote
        return f"{self.base_url}/r2/{quote(bucket, safe='')}/{quote(key, safe='')}"

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        bucket, key, body, metadata = kwargs.get("Bucket"), kwargs.get("Key"), kwargs.get("Body"), kwargs.get("Metadata")
        headers = {f"x-amz-meta-{name.casefold()}": str(value) for name, value in (metadata or {}).items()}
        if kwargs.get("IfNoneMatch") is not None: headers["If-None-Match"] = str(kwargs["IfNoneMatch"])
        response = self.client.put(self._url(bucket, key), content=body, headers=headers)
        if response.status_code == 412: raise S3PreconditionError()
        if response.status_code != 200: raise RuntimeError("R2 PUT failed")
        return {}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        response = self.client.head(self._url(kwargs["Bucket"], kwargs["Key"]))
        if response.status_code == 404: raise S3NotFoundError()
        if response.status_code != 200: raise RuntimeError("R2 HEAD failed")
        return {"ContentLength": int(response.headers["content-length"]), "Metadata": {name[11:].casefold(): value for name, value in response.headers.items() if name.casefold().startswith("x-amz-meta-")}, "ETag": response.headers["etag"], "ChecksumSHA256": response.headers["x-amz-checksum-sha256"]}

    def close(self) -> None:
        self.client.close()


def json_native(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): json_native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_native(item) for item in value]
    return value


class ThawingD1Provider:
    """Pass immutable producer envelopes as JSON-native D1 request values."""

    def __init__(self, client: D1PublicationClient) -> None:
        self.client = client

    def stage(self, source: Mapping[str, Any]) -> object:
        return self.client.stage(json_native(source))  # type: ignore[arg-type]

    def expose(self, source: Mapping[str, Any]) -> object:
        return self.client.expose(json_native(source))  # type: ignore[arg-type]


def clean_scanner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    del kwargs
    return subprocess.CompletedProcess(argv, 0, b"", b"")


def source() -> AtifSource:
    started = "2026-07-28T12:00:00.000Z"
    completed = "2026-07-28T12:00:01.000Z"
    identity = RunIdentity(TASK_ID, PIPELINE_ID, RUN_ID)
    run = RunMetadata(
        identity,
        "planning",
        "succeeded",
        # Keep the fixture entirely synthetic and deterministic.
        datetime.fromisoformat(started.replace("Z", "+00:00")),
        datetime.fromisoformat(completed.replace("Z", "+00:00")),
        1_000,
    )
    documents = {
        "codex.jsonl": b'{"type":"item.completed","item":{"id":"message-1","type":"agent_message","text":"greenfield complete"}}\n',
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"event","schema_version":1,"sequence":1,"source_event_id":"activity-1",'
            b'"activity":"investigate","summary":"Complete the task","recorded_at":"2026-07-28T12:00:00.100Z"}\n'
            b'{"record_type":"summary","schema_version":1,"capture_state":"complete","recorded":1,'
            b'"invalid":0,"duplicate":0,"omitted":0,"truncated":false}\n'
        ),
        "telemetry.json": b'{"schema_version":1,"provenance":"codex_exec","completeness":"complete","aggregate":{},"cost":{"status":"unavailable"}}',
        "run.json": json.dumps(
            {
                **identity.as_dict(),
                "role": "planning",
                "state": "succeeded",
                "startedAt": started,
                "completedAt": completed,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n",
    }
    return AtifSource(run=run, documents=documents)


def graph() -> dict[str, Any]:
    return {
        "task": {
            "taskId": TASK_ID,
            "title": "Greenfield publication",
            "lifecycleState": "completed",
            "createdAt": "2026-07-28T12:00:00Z",
            "completedAt": "2026-07-28T12:00:01Z",
        },
        "pipelines": [{
            "pipelineId": PIPELINE_ID,
            "taskId": TASK_ID,
            "name": "Greenfield pipeline",
            "createdAt": "2026-07-28T12:00:00Z",
        }],
        "runs": [source()],
        "events": [
            {
                "taskId": TASK_ID,
                "sequence": 1,
                "eventType": "started",
                "occurredAt": "2026-07-28T12:00:00Z",
                "summary": "Planning started",
            },
            {
                "taskId": TASK_ID,
                "sequence": 2,
                "eventType": "completed",
                "occurredAt": "2026-07-28T12:00:01Z",
                "summary": "Planning completed",
            },
        ],
    }


def run_site_case(base_url: str, case: str) -> None:
    environment = os.environ.copy()
    environment["COQUIC_GREENFIELD_PROVIDER_BASE_URL"] = base_url
    site_root = ROOT / "site-v2"
    tsx = site_root / "node_modules" / ".bin" / "tsx"
    command = [str(tsx), str(site_root / "scripts" / "test_greenfield_contract.ts"), case] if tsx.exists() else ["npm", "exec", "--prefix", str(site_root), "--", "tsx", "scripts/test_greenfield_contract.ts", case]
    process = subprocess.Popen(command, cwd=site_root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    oversized = {"stdout": False, "stderr": False}
    def drain(stream: Any, target: list[bytes], limit: int, name: str) -> None:
        total = 0
        while True:
            chunk = stream.read(8192)
            if not chunk: break
            if total + len(chunk) > limit:
                oversized[name] = True
                remaining = max(0, limit - total)
                if remaining: target.append(chunk[:remaining])
                total = limit
            elif total < limit:
                target.append(chunk)
                total += len(chunk)
    threads = [Thread(target=drain, args=(process.stdout, stdout, 4096, "stdout")), Thread(target=drain, args=(process.stderr, stderr, 65536, "stderr"))]
    for item in threads: item.start()
    try:
        process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.terminate()
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
        raise RuntimeError(f"Site contract case {case} timed out")
    finally:
        for item in threads: item.join(timeout=2)
        if process.poll() is None:
            process.kill(); process.wait()
    output = b"".join(stdout)
    if oversized["stdout"] or oversized["stderr"] or process.returncode != 0 or len(output) > 4096 or not output.endswith(b"\n") or output.count(b"\n") != 1:
        raise RuntimeError(f"Site contract case {case} failed")
    try: payload = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error: raise RuntimeError(f"Site contract case {case} emitted invalid JSON") from error
    if set(payload) != {"case", "ok"} or payload.get("case") != case or payload.get("ok") is not True:
        raise RuntimeError(f"Site contract case {case} emitted an invalid summary")


def assert_d1_authentication(base_url: str, client: httpx.Client) -> None:
    body = {"sql": "SELECT 1", "params": []}
    missing = client.post(f"{base_url}/d1/query", json=body)
    wrong = client.post(f"{base_url}/d1/query", headers={"Authorization": "Bearer wrong-greenfield-token"}, json=body)
    if missing.status_code != 401 or wrong.status_code != 401:
        raise RuntimeError("loopback D1 accepted a missing or incorrect bearer credential")


def assert_r2_boundary(r2: R2Client, provider: LoopbackProvider) -> None:
    before = dict(provider.objects)
    try: r2.put_object("not-a-contract-key", b"invalid")
    except R2ValidationError: pass
    else: raise RuntimeError("R2 boundary accepted an invalid object key")
    if provider.objects != before: raise RuntimeError("invalid R2 object key changed local state")


def require_generation(value: object) -> PublicationGeneration:
    if not isinstance(value, PublicationGeneration):
        reasons = getattr(value, "reason_codes", ())
        raise RuntimeError(f"current producer could not compose a publication: {tuple(str(item) for item in reasons)}")
    return value


def compose_for_transport(value: object, **kwargs: object) -> object:
    """Detach the producer envelope into JSON-native values for D1 params."""

    result = compose_publication_generation(value, **kwargs)
    if isinstance(result, PublicationGeneration):
        return PublicationGeneration(result.as_dict(), result.objects, result.private_originals)
    return result


TRANSPORT_COMPOSER = PublicationComposer(compose_for_transport)


def close_store(store: SQLiteTaskStore) -> None:
    store.engine.dispose()


CASE_ALIASES = {
    "empty", "published", "replay", "reopen", "reopen/replay", "reopen-replay",
    "hidden", "unavailable", "hidden/unavailable", "failure", "failures",
    "dangling-head", "dangling_head", "digest-mismatch", "digest_mismatch", "private-field", "private_field",
}
DEFAULT_CASES = ("empty", "published", "replay", "unavailable", "dangling-head", "digest-mismatch", "private-field", "hidden")


def parse_cases() -> list[str]:
    parser = argparse.ArgumentParser(description="Run the bounded greenfield Steward-to-Site contract gate")
    parser.add_argument("--case", action="append", dest="cases", help="run only this named case; repeatable")
    args = parser.parse_args()
    cases = args.cases or list(DEFAULT_CASES)
    if any(case not in CASE_ALIASES for case in cases):
        parser.error("unsupported case")
    if len(set(cases)) != len(cases):
        parser.error("duplicate case")
    return cases


def assert_r2_http_operations(base_url: str) -> None:
    digest = hashlib.sha256(b"r2-boundary").hexdigest()
    key = f"v1/tasks/{TASK_ID}/objects/sha256/{digest[:2]}/{digest}"
    url = f"{base_url}/r2/{PUBLIC_BUCKET}/{key}"
    with httpx.Client() as client:
        if client.put(url, content=b"r2-boundary").status_code != 200: raise RuntimeError("R2 PUT failed")
        head = client.head(url)
        if head.status_code != 200 or head.headers.get("content-length") != "11": raise RuntimeError("R2 HEAD failed")
        if client.get(url).content != b"r2-boundary": raise RuntimeError("R2 GET failed")
        if client.delete(url).status_code != 204 or client.delete(url).status_code != 204: raise RuntimeError("R2 DELETE failed")


def emit_child(base_url: str, case: str, summaries: list[dict[str, object]]) -> None:
    run_site_case(base_url, case)
    summaries.append({"case": case, "ok": True})


def main() -> int:
    cases = parse_cases()
    summaries: list[dict[str, object]] = []
    temporary_root: Path | None = None
    with TemporaryDirectory(prefix="coquic-greenfield-") as temporary:
        temporary_root = Path(temporary)
        provider: LoopbackProvider | None = None
        server: ProviderServer | None = None
        thread: Thread | None = None
        d1_transport: LoopbackD1Client | None = None
        d1: D1PublicationClient | None = None
        r2_transport: HttpR2Transport | None = None
        store: SQLiteTaskStore | None = None
        reopened: SQLiteTaskStore | None = None
        try:
            provider = LoopbackProvider(temporary_root / "provider.sqlite")
            server = ProviderServer(("127.0.0.1", 0), ProviderHandler)
            server.provider = provider
            thread = Thread(target=server.serve_forever, name="greenfield-provider", daemon=True)
            thread.start()
            if server.server_address[0] != "127.0.0.1" or server.server_port == 0: raise RuntimeError("provider was not loopback-bound")
            base_url = f"http://127.0.0.1:{server.server_port}"
            d1_transport = LoopbackD1Client(base_url)
            d1 = D1PublicationClient(account_id=ACCOUNT_ID, database_id=DATABASE_ID, token=READ_TOKEN, http_client=d1_transport)
            r2_transport = HttpR2Transport(base_url)
            r2 = R2Client("https://r2.local", public_bucket=PUBLIC_BUCKET, private_bucket=PRIVATE_BUCKET, client=r2_transport)
            assert_d1_authentication(base_url, d1_transport.client)
            assert_r2_http_operations(base_url)
            assert_r2_boundary(r2, provider)
            if "empty" in cases: emit_child(base_url, "empty", summaries)
            needs_publication = any(case != "empty" for case in cases)
            if needs_publication:
                store_path = temporary_root / "tasks.sqlite"
                store = SQLiteTaskStore.create(store_path)
                publication = require_generation(compose_for_transport(graph(), scanner_runner=clean_scanner))
                queued = store.enqueue_publication(publication.outbox_record)
                if queued.status.value not in {"enqueued", "existing"}: raise RuntimeError("publication was not queued")
                d1_provider = ThawingD1Provider(d1)
                publisher = CloudPublisher(store, r2, d1_provider, worker_id="greenfield-worker", compose=TRANSPORT_COMPOSER, retry_policy=PublicationRetryPolicy())
                result = publisher.publish(publication.publication_id, graph(), compose_kwargs={"scanner_runner": clean_scanner})
                if result.status is not PublicationStatus.exposed: raise RuntimeError(f"publication was not exposed: {result.status} {result.reason} {result.phase}")
                if "published" in cases: emit_child(base_url, "published", summaries)
                replay_cases = [case for case in cases if case in {"replay", "reopen", "reopen/replay", "reopen-replay"}]
                if replay_cases:
                    if store is None: raise RuntimeError("replay requires producer state")
                    before = provider.snapshot()
                    close_store(store); store = None
                    for suffix in ("-wal", "-shm"):
                        sidecar = store_path.with_name(store_path.name + suffix)
                        if not sidecar.exists(): sidecar.touch()
                    reopened = SQLiteTaskStore.open(store_path)
                    replay = CloudPublisher(reopened, r2, d1_provider, worker_id="greenfield-worker", compose=TRANSPORT_COMPOSER, retry_policy=PublicationRetryPolicy()).publish(publication.publication_id, graph(), compose_kwargs={"scanner_runner": clean_scanner})
                    if replay.status is not PublicationStatus.exposed or provider.snapshot() != before: raise RuntimeError("publication replay changed visible state")
                    close_store(reopened); reopened = None
                    for case in replay_cases: emit_child(base_url, case, summaries)
                for case in cases:
                    if case in {"unavailable", "failure", "failures"}:
                        provider.unavailable = True
                        try: emit_child(base_url, case, summaries)
                        finally: provider.unavailable = False
                    elif case in {"dangling-head", "dangling_head"}:
                        original = provider.corrupt_dangling()
                        try: emit_child(base_url, case, summaries)
                        finally: provider.restore_dangling(original)
                    elif case in {"private-field", "private_field"}:
                        original = provider.corrupt_private_field()
                        try: emit_child(base_url, case, summaries)
                        finally: provider.restore_private_field(original)
                    elif case in {"digest-mismatch", "digest_mismatch"}:
                        public_key, (content, metadata) = next((key, value) for (bucket, key), value in provider.objects.items() if bucket == PUBLIC_BUCKET)
                        provider.objects[(PUBLIC_BUCKET, public_key)] = (content + b"corrupt", metadata)
                        try: emit_child(base_url, case, summaries)
                        finally: provider.objects[(PUBLIC_BUCKET, public_key)] = (content, metadata)
                if "hidden" in cases or "hidden/unavailable" in cases:
                    d1.hide_task(TASK_ID, "operator_blocked")
                    if "hidden" in cases: emit_child(base_url, "hidden", summaries)
                    if "hidden/unavailable" in cases:
                        provider.unavailable = True
                        try: emit_child(base_url, "hidden/unavailable", summaries)
                        finally: provider.unavailable = False
            if len(summaries) != len(cases): raise RuntimeError("not every requested case was executed")
        finally:
            if reopened is not None: close_store(reopened)
            if store is not None: close_store(store)
            if r2_transport is not None: r2_transport.close()
            if d1 is not None: d1.close()
            if d1_transport is not None: d1_transport.close()
            if server is not None:
                server.shutdown(); server.server_close()
            if thread is not None:
                thread.join(timeout=2)
                if thread.is_alive(): raise RuntimeError("provider thread did not stop")
            if provider is not None: provider.close()
    if temporary_root is not None and temporary_root.exists(): raise RuntimeError("temporary state was not removed")
    for summary in summaries: print(json.dumps(summary, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError) as error:
        print(f"greenfield contract gate failed: {error}", file=sys.stderr)
        raise SystemExit(1)

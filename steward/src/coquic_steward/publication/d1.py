"""Bounded, public-safe staging for the Steward Cloudflare D1 schema.

The publisher hands this module one already-sanitized publication envelope.  This
module owns the transport boundary and the visibility protocol only: SQL is fixed
in this file, all values are bound parameters, staging is replayable, and the
single final batch is the only operation that can change a public head.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, TypeAlias
from urllib.parse import quote

import httpx


MAX_BATCH_PARAMETERS = 99
MAX_BATCH_BYTES = 100_000
MAX_BATCH_STATEMENTS = 64
MAX_RESPONSE_BYTES = 1_048_576
MAX_RESULT_SETS = MAX_BATCH_STATEMENTS
MAX_RESULT_ROWS = 4_096
MAX_TOKEN_LENGTH = 4_096
MAX_TIMEOUT_SECONDS = 120.0

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")
_MEDIA = re.compile(r"^[^\s\x00-\x1f\x7f]{1,128}$")
_PATH = re.compile(r"^(?!/)(?!.*://)(?!.*\.\.)[^\x00-\x1f]{1,1024}$")
_PUBLIC_KEY = re.compile(r"^v1/tasks/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PRIVATE_LOCATOR = re.compile(
    r"(?:"
    r"[a-z][a-z0-9+.-]*://|"
    r"(?:^|[\\/])(?:private|credential|credentials|secret|token)(?:[\\/]|$)|"
    r"(?:^|[A-Za-z]:)[\\/]|"
    r"^(?:~[/\\]|\\\\)|"
    r"(?:^|[-_])(?:private|internal|secret)[-_](?:bucket|object(?:[-_]key)?|url|path)(?:$|[-_])"
    r")",
    re.IGNORECASE,
)

_METADATA_FIELDS = ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts")


class D1ErrorCode(StrEnum):
    """Stable, non-sensitive failure categories for the D1 boundary."""

    invalid_request = "invalid_request"
    private_value = "private_value"
    authentication = "authentication"
    quota = "quota"
    timeout = "timeout"
    network = "network"
    provider = "provider"
    malformed_response = "malformed_response"
    response_too_large = "response_too_large"
    result_limit = "result_limit"
    generation_conflict = "generation_conflict"
    generation_state = "generation_state"
    count_mismatch = "count_mismatch"
    digest_mismatch = "digest_mismatch"

    # Descriptive aliases used by transport callers.
    auth = "authentication"
    unauthorized = "authentication"
    rate_limited = "quota"
    network_error = "network"
    provider_error = "provider"
    malformed = "malformed_response"


class D1Error(RuntimeError):
    """An error whose text contains only an enumerated category."""

    def __init__(self, code: D1ErrorCode | str):
        try:
            normalized = D1ErrorCode(code)
        except (TypeError, ValueError):
            normalized = D1ErrorCode.provider
        self.code = normalized
        self.category = normalized
        self.reason_code = normalized
        self.kind = normalized
        super().__init__(normalized.value)


Scalar: TypeAlias = str | int | float | bool | None
Statement: TypeAlias = tuple[str, tuple[Scalar, ...]]


class D1Response(Protocol):
    status_code: int
    headers: Mapping[str, str]

    @property
    def content(self) -> bytes: ...


class D1HttpClient(Protocol):
    def post(self, url: str, **kwargs: Any) -> D1Response: ...


@dataclass(frozen=True, slots=True)
class StageReceipt:
    publication_id: str
    task_id: str
    run_id: str
    staged: bool = True


@dataclass(frozen=True, slots=True)
class ExposureReceipt:
    publication_id: str
    task_id: str
    state: str = "visible"


@dataclass(frozen=True, slots=True)
class HideReceipt:
    task_id: str
    publication_id: str | None
    state: str = "hidden"
    changed: bool = True


_TOP_LEVEL = frozenset(
    {
        "schemaVersion",
        "publicationId",
        "taskId",
        "generation",
        "headIntent",
        "task",
        "pipelines",
        "runs",
        "events",
        "artifacts",
    }
)
_GENERATION = frozenset(
    {
        "publicationId",
        "taskId",
        "runId",
        "metadataDigest",
        "idempotencyKey",
        "state",
        "expectedCounts",
        "createdAt",
    }
)
_COUNTS = frozenset({"tasks", "pipelines", "runs", "events", "artifacts"})
_HEAD = frozenset({"publicationId", "taskId", "state", "updatedAt"})
_TASK = frozenset({"taskId", "title", "lifecycleState", "createdAt", "completedAt"})
_PIPELINE = frozenset({"pipelineId", "taskId", "name", "createdAt"})
_RUN = frozenset(
    {
        "runId",
        "taskId",
        "pipelineId",
        "role",
        "runState",
        "startedAt",
        "completedAt",
        "durationMs",
        "atifDigest",
        "atifArtifactId",
    }
)
_EVENT = frozenset({"taskId", "sequence", "eventType", "occurredAt", "summary"})
_ARTIFACT = frozenset(
    {
        "artifactId",
        "taskId",
        "runId",
        "logicalPath",
        "publicKey",
        "mediaType",
        "byteSize",
        "sha256",
        "availability",
        "disclosure",
    }
)
_DISCLOSURE = frozenset({"redactionApplied", "originalRetained"})


def _invalid(code: D1ErrorCode = D1ErrorCode.invalid_request) -> None:
    raise D1Error(code)


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _invalid()
    return value


def _keys(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        _invalid()


def _text(value: object, *, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value):
        _invalid()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        _invalid()
    if _PRIVATE_LOCATOR.search(value):
        _invalid(D1ErrorCode.private_value)
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _invalid()
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _invalid()
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _invalid()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _invalid()
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _invalid()
    return value


def _integer(value: object, *, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _invalid()
    return value


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        _invalid()
    return value


def _safe_value(value: object, *, key: str = "") -> None:
    """Reject private locator-shaped leaves without treating prose as a locator."""

    if isinstance(value, str):
        if key and any(token in key.lower() for token in ("credential", "private", "secret", "token", "url", "uri", "endpoint")):
            _invalid(D1ErrorCode.private_value)
        if _PRIVATE_LOCATOR.search(value):
            _invalid(D1ErrorCode.private_value)
    elif isinstance(value, Mapping):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                _invalid()
            _safe_value(child_value, key=child_key)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        for child in value:
            _safe_value(child, key=key)


def _metadata_digest(payload: Mapping[str, Any]) -> str:
    metadata = {key: payload[key] for key in _METADATA_FIELDS}
    canonical = (
        json.dumps(metadata, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_payload(source: Mapping[str, Any]) -> dict[str, Any]:
    payload = _mapping(source)
    _keys(payload, _TOP_LEVEL)
    _safe_value(payload)
    if payload["schemaVersion"] != "1.0":
        _invalid()
    publication_id = _id(payload["publicationId"])
    task_id = _id(payload["taskId"])

    generation = _mapping(payload["generation"])
    _keys(generation, _GENERATION)
    if _id(generation["publicationId"]) != publication_id or _id(generation["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    generation_run_id = _id(generation["runId"])
    if generation["state"] != "staged":
        _invalid(D1ErrorCode.generation_state)
    _digest(generation["metadataDigest"])
    _id(generation["idempotencyKey"])
    _timestamp(generation["createdAt"])
    counts = _mapping(generation["expectedCounts"])
    _keys(counts, _COUNTS)
    if _integer(counts["tasks"]) != 1:
        _invalid()
    for key in ("pipelines", "runs", "events", "artifacts"):
        _integer(counts[key])

    head = _mapping(payload["headIntent"])
    _keys(head, _HEAD)
    if _id(head["publicationId"]) != publication_id or _id(head["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    if head["state"] not in {"visible", "hidden"}:
        _invalid()
    _timestamp(head["updatedAt"])

    task = _mapping(payload["task"])
    _keys(task, _TASK)
    if _id(task["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    _text(task["title"], maximum=512)
    if task["lifecycleState"] not in {"active", "completed", "failed", "cancelled"}:
        _invalid()
    _timestamp(task["createdAt"])
    if task["completedAt"] is not None:
        _timestamp(task["completedAt"])

    pipelines = payload["pipelines"]
    runs = payload["runs"]
    events = payload["events"]
    artifacts = payload["artifacts"]
    for values in (pipelines, runs, events, artifacts):
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not values:
            _invalid()
    if len(pipelines) != counts["pipelines"] or len(runs) != counts["runs"] or len(events) != counts["events"] or len(artifacts) != counts["artifacts"]:
        _invalid(D1ErrorCode.count_mismatch)

    pipeline_ids: set[str] = set()
    for item in pipelines:
        row = _mapping(item)
        _keys(row, _PIPELINE)
        pipeline_id = _id(row["pipelineId"])
        if pipeline_id in pipeline_ids or _id(row["taskId"]) != task_id:
            _invalid(D1ErrorCode.generation_conflict)
        pipeline_ids.add(pipeline_id)
        _text(row["name"], maximum=256)
        _timestamp(row["createdAt"])

    run_ids: set[str] = set()
    atif_artifact_ids: set[str] = set()
    for item in runs:
        row = _mapping(item)
        _keys(row, _RUN)
        run_id = _id(row["runId"])
        if run_id in run_ids or _id(row["taskId"]) != task_id or _id(row["pipelineId"]) not in pipeline_ids:
            _invalid(D1ErrorCode.generation_conflict)
        run_ids.add(run_id)
        _text(row["role"], maximum=128)
        if row["runState"] not in {"completed", "failed", "cancelled"}:
            _invalid()
        _timestamp(row["startedAt"])
        _timestamp(row["completedAt"])
        if datetime.fromisoformat(row["completedAt"].replace("Z", "+00:00")) < datetime.fromisoformat(row["startedAt"].replace("Z", "+00:00")):
            _invalid()
        _integer(row["durationMs"])
        _digest(row["atifDigest"])
        atif_artifact_ids.add(_id(row["atifArtifactId"]))

    sequences: set[int] = set()
    for item in events:
        row = _mapping(item)
        _keys(row, _EVENT)
        if _id(row["taskId"]) != task_id:
            _invalid(D1ErrorCode.generation_conflict)
        sequence = _integer(row["sequence"], minimum=1)
        if sequence in sequences:
            _invalid(D1ErrorCode.generation_conflict)
        sequences.add(sequence)
        _text(row["eventType"], maximum=128)
        _timestamp(row["occurredAt"])
        _text(row["summary"], maximum=4096, allow_empty=True)

    artifact_ids: set[str] = set()
    logical_paths: set[str] = set()
    for item in artifacts:
        row = _mapping(item)
        _keys(row, _ARTIFACT)
        artifact_id = _id(row["artifactId"])
        logical_path = _text(row["logicalPath"], maximum=1024)
        if _PATH.fullmatch(logical_path) is None:
            _invalid()
        if artifact_id in artifact_ids or logical_path in logical_paths:
            _invalid(D1ErrorCode.generation_conflict)
        artifact_ids.add(artifact_id)
        logical_paths.add(logical_path)
        if _id(row["taskId"]) != task_id or _id(row["runId"]) not in run_ids:
            _invalid(D1ErrorCode.generation_conflict)
        public_key = _text(row["publicKey"], maximum=256)
        key_match = _PUBLIC_KEY.fullmatch(public_key)
        if key_match is None or key_match.group(1) != task_id or key_match.group(2) != key_match.group(3)[:2]:
            _invalid(D1ErrorCode.private_value if _PRIVATE_LOCATOR.search(public_key) else D1ErrorCode.invalid_request)
        _text(row["mediaType"], maximum=128)
        if _MEDIA.fullmatch(row["mediaType"]) is None:
            _invalid()
        _integer(row["byteSize"])
        _digest(row["sha256"])
        if key_match.group(3) != row["sha256"]:
            _invalid(D1ErrorCode.digest_mismatch)
        if row["availability"] not in {"available", "unavailable"}:
            _invalid()
        disclosure = _mapping(row["disclosure"])
        _keys(disclosure, _DISCLOSURE)
        _bool(disclosure["redactionApplied"])
        _bool(disclosure["originalRetained"])

    artifact_by_id = {item["artifactId"]: item for item in artifacts}
    for item in runs:
        atif = artifact_by_id.get(item["atifArtifactId"])
        if atif is None or atif["runId"] != item["runId"] or atif["sha256"] != item["atifDigest"]:
            _invalid(D1ErrorCode.digest_mismatch)
    if not atif_artifact_ids.issubset(artifact_ids):
        _invalid(D1ErrorCode.generation_conflict)
    if generation_run_id not in run_ids:
        _invalid(D1ErrorCode.generation_conflict)
    if generation["metadataDigest"] != _metadata_digest(payload):
        _invalid(D1ErrorCode.digest_mismatch)
    # Keep the returned object detached from mutable caller containers.
    return json.loads(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _statement(sql: str, *params: Scalar) -> Statement:
    if len(params) > MAX_BATCH_PARAMETERS:
        _invalid()
    return sql, tuple(params)


_GENERATION_INSERT = (
    "INSERT INTO publication_generations "
    "(publication_id, task_id, run_id, metadata_digest, idempotency_key, state, "
    "expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, "
    "expected_artifact_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(publication_id) DO NOTHING"
)
_TASK_INSERT = (
    "INSERT INTO tasks (publication_id, task_id, title, lifecycle_state, created_at, completed_at) "
    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, task_id) DO NOTHING"
)
_PIPELINE_INSERT = (
    "INSERT INTO pipelines (publication_id, pipeline_id, task_id, name, created_at) "
    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(publication_id, pipeline_id) DO NOTHING"
)
_RUN_INSERT = (
    "INSERT INTO runs (publication_id, run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, run_id) DO NOTHING"
)
_EVENT_INSERT = (
    "INSERT INTO task_events (publication_id, task_id, sequence, event_type, occurred_at, summary) "
    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, task_id, sequence) DO NOTHING"
)
_ARTIFACT_INSERT = (
    "INSERT INTO artifacts (publication_id, artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, artifact_id) DO NOTHING"
)
_GENERATION_SELECT = (
    "SELECT task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, "
    "expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at "
    "FROM publication_generations WHERE publication_id = ? AND task_id = ?"
)
_GENERATION_RUN_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND run_id = ?"
_GENERATION_KEY_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND idempotency_key = ?"
_VERIFY_COUNTS = (
    "SELECT p.state, p.metadata_digest, p.expected_task_count, p.expected_pipeline_count, "
    "p.expected_run_count, p.expected_event_count, p.expected_artifact_count, "
    "(SELECT count(*) FROM tasks WHERE publication_id = p.publication_id) AS task_count, "
    "(SELECT count(*) FROM pipelines WHERE publication_id = p.publication_id) AS pipeline_count, "
    "(SELECT count(*) FROM runs WHERE publication_id = p.publication_id) AS run_count, "
    "(SELECT count(*) FROM task_events WHERE publication_id = p.publication_id) AS event_count, "
    "(SELECT count(*) FROM artifacts WHERE publication_id = p.publication_id) AS artifact_count "
    "FROM publication_generations AS p WHERE p.publication_id = ? AND p.task_id = ?"
)
_TASK_SELECT = "SELECT task_id, title, lifecycle_state, created_at, completed_at FROM tasks WHERE publication_id = ? ORDER BY task_id"
_PIPELINE_SELECT = "SELECT pipeline_id, task_id, name, created_at FROM pipelines WHERE publication_id = ? ORDER BY pipeline_id"
_RUN_SELECT = "SELECT run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest FROM runs WHERE publication_id = ? ORDER BY run_id"
_EVENT_SELECT = "SELECT task_id, sequence, event_type, occurred_at, summary FROM task_events WHERE publication_id = ? ORDER BY task_id, sequence"
_ARTIFACT_SELECT = "SELECT artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained FROM artifacts WHERE publication_id = ? ORDER BY artifact_id"
_HEAD_SELECT = "SELECT publication_id, state FROM task_heads WHERE task_id = ?"
_VISIBLE_GENERATION_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND state = 'visible' ORDER BY exposed_at DESC, publication_id DESC LIMIT 1"
_EXPOSE_OLD = "UPDATE publication_generations SET state = 'superseded' WHERE task_id = ? AND state = 'visible' AND publication_id <> ?"
_EXPOSE_NEW = "UPDATE publication_generations SET state = 'visible', exposed_at = ? WHERE publication_id = ? AND task_id = ? AND state = 'staged'"
_HEAD_UPSERT = (
    "INSERT INTO task_heads (task_id, publication_id, state, updated_at) VALUES (?, ?, 'visible', ?) "
    "ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, state = 'visible', updated_at = excluded.updated_at"
)
_HIDE_UPSERT = (
    "INSERT INTO task_heads (task_id, publication_id, state, updated_at) VALUES (?, ?, 'hidden', ?) "
    "ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, state = 'hidden', updated_at = excluded.updated_at"
)
_VISIBLE_HEAD_SELECT = "SELECT publication_id, state FROM task_heads WHERE task_id = ?"


def _row_values(row: object) -> Mapping[str, Any]:
    if not isinstance(row, Mapping):
        _invalid(D1ErrorCode.malformed_response)
    return row


class D1PublicationClient:
    """A narrow D1 REST client for one staged publication envelope."""

    def __init__(
        self,
        config: object | None = None,
        database_id: str | None = None,
        token: str | None = None,
        *,
        account_id: str | None = None,
        transport: httpx.BaseTransport | None = None,
        http_client: D1HttpClient | None = None,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        account, database, credential = self._config_values(config, account_id, database_id, token)
        if not isinstance(account, str) or re.fullmatch(r"[0-9a-fA-F]{32}", account) is None:
            _invalid()
        if not isinstance(database, str) or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", database) is None:
            _invalid()
        if not isinstance(credential, str) or not 1 <= len(credential.strip()) <= MAX_TOKEN_LENGTH or any(ord(char) <= 0x20 for char in credential):
            _invalid()
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < float(timeout_seconds) <= MAX_TIMEOUT_SECONDS:
            _invalid()
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 0 < max_response_bytes <= MAX_RESPONSE_BYTES:
            _invalid()
        self.account_id = account.lower()
        self.database_id = database.lower()
        self._token = credential
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self._owned_client = http_client is None
        self._client: D1HttpClient = http_client or httpx.Client(transport=transport, timeout=self.timeout_seconds)

    @staticmethod
    def _config_values(config: object | None, account_id: str | None, database_id: str | None, token: str | None) -> tuple[object, object, object]:
        if account_id is not None or database_id is not None or token is not None:
            if config is not None:
                _invalid()
            return account_id, database_id, token
        if isinstance(config, Mapping):
            values = config
            credential = values.get("d1_token", values.get("token"))
            if credential is None and values.get("d1_token_path") is not None:
                try:
                    credential = Path(values["d1_token_path"]).read_text(encoding="utf-8").strip()
                except (OSError, UnicodeError):
                    _invalid()
            return (
                values.get("account_id", values.get("cloudflare_account_id")),
                values.get("d1_database_id", values.get("database_id", values.get("cloudflare_database_id"))),
                credential,
            )
        account = getattr(config, "account_id", getattr(config, "cloudflare_account_id", None))
        database = getattr(config, "d1_database_id", getattr(config, "database_id", getattr(config, "cloudflare_database_id", None)))
        credential = getattr(config, "d1_token", getattr(config, "token", None))
        path = getattr(config, "d1_token_path", None)
        if credential is None and path is not None:
            try:
                credential = Path(path).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                _invalid()
        return account, database, credential

    @property
    def endpoint(self) -> str:
        return (
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{quote(self.account_id, safe='')}/d1/database/{quote(self.database_id, safe='')}/query"
        )

    def close(self) -> None:
        if self._owned_client and hasattr(self._client, "close"):
            self._client.close()  # type: ignore[attr-defined]

    def __enter__(self) -> "D1PublicationClient":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def _post(self, statements: Sequence[Statement]) -> list[Mapping[str, Any]]:
        if not statements or len(statements) > MAX_BATCH_STATEMENTS:
            _invalid()
        total_params = sum(len(params) for _, params in statements)
        if total_params > MAX_BATCH_PARAMETERS:
            _invalid()
        body: dict[str, Any]
        if len(statements) == 1:
            sql, params = statements[0]
            body = {"sql": sql, "params": list(params)}
        else:
            body = {"batch": [{"sql": sql, "params": list(params)} for sql, params in statements]}
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > self.max_response_bytes or len(encoded) > MAX_BATCH_BYTES:
            _invalid()
        try:
            response = self._client.post(
                self.endpoint,
                headers={"Accept": "application/json", "Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
                content=encoded,
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException:
            raise D1Error(D1ErrorCode.timeout) from None
        except httpx.HTTPError:
            raise D1Error(D1ErrorCode.network) from None
        except (TimeoutError, OSError):
            raise D1Error(D1ErrorCode.network) from None
        status = int(getattr(response, "status_code", 0))
        if status in {401, 403}:
            _invalid(D1ErrorCode.authentication)
        if status == 408:
            _invalid(D1ErrorCode.timeout)
        if status in {425, 429, 509}:
            _invalid(D1ErrorCode.quota)
        if status >= 500:
            _invalid(D1ErrorCode.provider)
        if status < 200 or status >= 300:
            _invalid(D1ErrorCode.network)
        try:
            content_length = response.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > self.max_response_bytes:
                _invalid(D1ErrorCode.response_too_large)
            raw = bytes(response.content)
        except D1Error:
            raise
        except Exception:
            _invalid(D1ErrorCode.malformed_response)
        if len(raw) > self.max_response_bytes:
            _invalid(D1ErrorCode.response_too_large)
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _invalid(D1ErrorCode.malformed_response)
        if not isinstance(document, Mapping):
            _invalid(D1ErrorCode.malformed_response)
        if document.get("success") is False:
            _invalid(D1ErrorCode.provider)
        if document.get("success") is not True or not isinstance(document.get("errors"), list):
            _invalid(D1ErrorCode.malformed_response)
        if document["errors"]:
            _invalid(D1ErrorCode.provider)
        result = document.get("result")
        if not isinstance(result, list) or len(result) != len(statements) or len(result) > MAX_RESULT_SETS:
            _invalid(D1ErrorCode.malformed_response)
        rows: list[Mapping[str, Any]] = []
        for entry in result:
            if not isinstance(entry, Mapping) or entry.get("success") is not True or not isinstance(entry.get("results"), list) or not isinstance(entry.get("meta"), Mapping):
                _invalid(D1ErrorCode.malformed_response)
            for row in entry["results"]:
                rows.append(_row_values(row))
                if len(rows) > MAX_RESULT_ROWS:
                    _invalid(D1ErrorCode.result_limit)
        return [entry for entry in result]  # type: ignore[return-value]

    def _query(self, statement: Statement) -> list[Mapping[str, Any]]:
        result = self._post((statement,))
        entry = result[0]
        return [_row_values(row) for row in entry["results"]]

    def _batch(self, statements: Sequence[Statement]) -> list[Mapping[str, Any]]:
        return self._post(statements)

    @staticmethod
    def _chunks(statements: Sequence[Statement]) -> tuple[tuple[Statement, ...], ...]:
        chunks: list[tuple[Statement, ...]] = []
        current: list[Statement] = []
        params = 0
        for item in statements:
            candidate = current + [item]
            encoded = json.dumps(
                {"batch": [{"sql": sql, "params": list(values)} for sql, values in candidate]},
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            if current and (len(candidate) > MAX_BATCH_STATEMENTS or params + len(item[1]) > MAX_BATCH_PARAMETERS or len(encoded) > MAX_BATCH_BYTES):
                chunks.append(tuple(current))
                current = []
                params = 0
            if len(item[1]) > MAX_BATCH_PARAMETERS:
                _invalid()
            current.append(item)
            params += len(item[1])
        if current:
            chunks.append(tuple(current))
        return tuple(chunks)

    @staticmethod
    def _generation_expected(payload: Mapping[str, Any]) -> tuple[Any, ...]:
        generation = payload["generation"]
        counts = generation["expectedCounts"]
        return (
            payload["taskId"],
            generation["runId"],
            generation["metadataDigest"],
            generation["idempotencyKey"],
            "staged",
            counts["tasks"],
            counts["pipelines"],
            counts["runs"],
            counts["events"],
            counts["artifacts"],
            generation["createdAt"],
        )

    def _verify_generation(self, payload: Mapping[str, Any]) -> str:
        rows = self._query(_statement(_GENERATION_SELECT, payload["publicationId"], payload["taskId"]))
        if not rows:
            _invalid(D1ErrorCode.generation_state)
        row = rows[0]
        actual = tuple(row.get(key) for key in ("task_id", "run_id", "metadata_digest", "idempotency_key", "state", "expected_task_count", "expected_pipeline_count", "expected_run_count", "expected_event_count", "expected_artifact_count", "created_at"))
        expected = self._generation_expected(payload)
        if actual != expected and not (actual[:4] == expected[:4] and actual[5:] == expected[5:] and actual[4] == "visible"):
            _invalid(D1ErrorCode.generation_conflict)
        if actual[4] not in {"staged", "visible"}:
            _invalid(D1ErrorCode.generation_state)
        return actual[4]

    def _stage_statements(self, payload: Mapping[str, Any]) -> tuple[Statement, ...]:
        publication_id = payload["publicationId"]
        generation = payload["generation"]
        counts = generation["expectedCounts"]
        statements: list[Statement] = [
            _statement(
                _GENERATION_INSERT,
                publication_id,
                payload["taskId"],
                generation["runId"],
                generation["metadataDigest"],
                generation["idempotencyKey"],
                counts["tasks"],
                counts["pipelines"],
                counts["runs"],
                counts["events"],
                counts["artifacts"],
                generation["createdAt"],
            )
        ]
        task = payload["task"]
        statements.append(_statement(_TASK_INSERT, publication_id, task["taskId"], task["title"], task["lifecycleState"], task["createdAt"], task["completedAt"]))
        for item in payload["pipelines"]:
            statements.append(_statement(_PIPELINE_INSERT, publication_id, item["pipelineId"], item["taskId"], item["name"], item["createdAt"]))
        for item in payload["runs"]:
            statements.append(_statement(_RUN_INSERT, publication_id, item["runId"], item["taskId"], item["pipelineId"], item["role"], item["runState"], item["startedAt"], item["completedAt"], item["durationMs"], item["atifDigest"]))
        for item in payload["events"]:
            statements.append(_statement(_EVENT_INSERT, publication_id, item["taskId"], item["sequence"], item["eventType"], item["occurredAt"], item["summary"]))
        for item in payload["artifacts"]:
            disclosure = item["disclosure"]
            statements.append(_statement(_ARTIFACT_INSERT, publication_id, item["artifactId"], item["taskId"], item["runId"], item["logicalPath"], item["publicKey"], item["mediaType"], item["byteSize"], item["sha256"], item["availability"], int(disclosure["redactionApplied"]), int(disclosure["originalRetained"])))
        return tuple(statements)

    def _verify_rows(self, payload: Mapping[str, Any]) -> None:
        publication_id = payload["publicationId"]
        generation = payload["generation"]
        rows = self._query(_statement(_VERIFY_COUNTS, publication_id, payload["taskId"]))
        if len(rows) != 1:
            _invalid(D1ErrorCode.generation_state)
        row = rows[0]
        expected = generation["expectedCounts"]
        if row.get("state") not in {"staged", "visible"} or row.get("metadata_digest") != generation["metadataDigest"]:
            _invalid(D1ErrorCode.generation_state)
        for column, actual_column, key in (
            ("expected_task_count", "task_count", "tasks"),
            ("expected_pipeline_count", "pipeline_count", "pipelines"),
            ("expected_run_count", "run_count", "runs"),
            ("expected_event_count", "event_count", "events"),
            ("expected_artifact_count", "artifact_count", "artifacts"),
        ):
            if row.get(column) != expected[key] or row.get(actual_column) != expected[key]:
                _invalid(D1ErrorCode.count_mismatch)
        checks: tuple[tuple[str, Statement, tuple[tuple[Any, ...], ...]], ...] = (
            ("tasks", _statement(_TASK_SELECT, publication_id), tuple((item["taskId"], item["title"], item["lifecycleState"], item["createdAt"], item["completedAt"]) for item in (payload["task"],))),
            ("pipelines", _statement(_PIPELINE_SELECT, publication_id), tuple((item["pipelineId"], item["taskId"], item["name"], item["createdAt"]) for item in payload["pipelines"])),
            ("runs", _statement(_RUN_SELECT, publication_id), tuple((item["runId"], item["taskId"], item["pipelineId"], item["role"], item["runState"], item["startedAt"], item["completedAt"], item["durationMs"], item["atifDigest"]) for item in payload["runs"])),
            ("events", _statement(_EVENT_SELECT, publication_id), tuple((item["taskId"], item["sequence"], item["eventType"], item["occurredAt"], item["summary"]) for item in payload["events"])),
            ("artifacts", _statement(_ARTIFACT_SELECT, publication_id), tuple((item["artifactId"], item["taskId"], item["runId"], item["logicalPath"], item["publicKey"], item["mediaType"], item["byteSize"], item["sha256"], item["availability"], int(item["disclosure"]["redactionApplied"]), int(item["disclosure"]["originalRetained"])) for item in payload["artifacts"])),
        )
        for name, statement, expected_rows in checks:
            actual_rows = self._query(statement)
            actual = tuple(tuple(item.get(column) for column in self._columns(statement[0])) for item in actual_rows)
            if name == "events":
                expected_rows = tuple(sorted(expected_rows, key=lambda row: (row[0], row[1])))
            else:
                expected_rows = tuple(sorted(expected_rows, key=lambda row: row[0]))
            if actual != expected_rows:
                _invalid(D1ErrorCode.generation_conflict)

    @staticmethod
    def _columns(sql: str) -> tuple[str, ...]:
        if sql == _TASK_SELECT:
            return ("task_id", "title", "lifecycle_state", "created_at", "completed_at")
        if sql == _PIPELINE_SELECT:
            return ("pipeline_id", "task_id", "name", "created_at")
        if sql == _RUN_SELECT:
            return ("run_id", "task_id", "pipeline_id", "role", "run_state", "started_at", "completed_at", "duration_ms", "atif_digest")
        if sql == _EVENT_SELECT:
            return ("task_id", "sequence", "event_type", "occurred_at", "summary")
        return ("artifact_id", "task_id", "run_id", "logical_path", "public_key", "media_type", "byte_size", "sha256", "availability", "redaction_applied", "original_retained")

    def stage(self, source: Mapping[str, Any]) -> StageReceipt:
        payload = _validate_payload(source)
        self._verify_existing_generation(payload)
        self._verify_unique_generation_keys(payload)
        for chunk in self._chunks(self._stage_statements(payload)):
            self._batch(chunk)
        self._verify_generation(payload)
        self._verify_rows(payload)
        return StageReceipt(payload["publicationId"], payload["taskId"], payload["generation"]["runId"])

    def _verify_existing_generation(self, payload: Mapping[str, Any]) -> None:
        rows = self._query(_statement(_GENERATION_SELECT, payload["publicationId"], payload["taskId"]))
        if rows:
            row = rows[0]
            expected = self._generation_expected(payload)
            actual = tuple(row.get(key) for key in ("task_id", "run_id", "metadata_digest", "idempotency_key", "state", "expected_task_count", "expected_pipeline_count", "expected_run_count", "expected_event_count", "expected_artifact_count", "created_at"))
            if actual != expected and not (actual[:4] == expected[:4] and actual[5:] == expected[5:] and actual[4] == "visible"):
                _invalid(D1ErrorCode.generation_conflict)
            if row.get("state") not in {"staged", "visible"}:
                _invalid(D1ErrorCode.generation_state)

    def _verify_unique_generation_keys(self, payload: Mapping[str, Any]) -> None:
        generation = payload["generation"]
        for statement, params in (
            (_GENERATION_RUN_SELECT, (payload["taskId"], generation["runId"])),
            (_GENERATION_KEY_SELECT, (payload["taskId"], generation["idempotencyKey"])),
        ):
            rows = self._query(_statement(statement, *params))
            if any(row.get("publication_id") != payload["publicationId"] for row in rows):
                _invalid(D1ErrorCode.generation_conflict)

    def expose(self, source: Mapping[str, Any]) -> ExposureReceipt:
        payload = _validate_payload(source)
        if payload["headIntent"]["state"] != "visible":
            _invalid(D1ErrorCode.generation_state)
        generation_state = self._verify_generation(payload)
        self._verify_rows(payload)
        current = self._query(_statement(_VISIBLE_HEAD_SELECT, payload["taskId"]))
        if current and current[0].get("publication_id") == payload["publicationId"]:
            if current[0].get("state") == "visible":
                return ExposureReceipt(payload["publicationId"], payload["taskId"])
            if current[0].get("state") == "hidden":
                return ExposureReceipt(payload["publicationId"], payload["taskId"], state="hidden")
            _invalid(D1ErrorCode.generation_state)
        if generation_state != "staged":
            _invalid(D1ErrorCode.generation_state)
        updated_at = payload["headIntent"]["updatedAt"]
        self._batch(
            (
                _statement(_EXPOSE_OLD, payload["taskId"], payload["publicationId"]),
                _statement(_EXPOSE_NEW, updated_at, payload["publicationId"], payload["taskId"]),
                _statement(_HEAD_UPSERT, payload["taskId"], payload["publicationId"], updated_at),
            )
        )
        visible = self._query(_statement(_VERIFY_COUNTS, payload["publicationId"], payload["taskId"]))
        head = self._query(_statement(_VISIBLE_HEAD_SELECT, payload["taskId"]))
        if len(visible) != 1 or visible[0].get("state") != "visible" or len(head) != 1 or head[0].get("publication_id") != payload["publicationId"] or head[0].get("state") != "visible":
            _invalid(D1ErrorCode.generation_state)
        return ExposureReceipt(payload["publicationId"], payload["taskId"])

    def publish(self, source: Mapping[str, Any]) -> ExposureReceipt:
        payload = _validate_payload(source)
        self.stage(payload)
        return self.expose(payload)

    def hide_task(self, task_id: str, reason_code: str) -> HideReceipt:
        task_id = _id(task_id)
        if not isinstance(reason_code, str) or _REASON.fullmatch(reason_code) is None or _PRIVATE_LOCATOR.search(reason_code):
            _invalid()
        current = self._query(_statement(_HEAD_SELECT, task_id))
        publication_id: str | None = None
        state: str | None = None
        if current:
            publication_id = _id(current[0].get("publication_id"))
            state = current[0].get("state") if current[0].get("state") in {"visible", "hidden"} else None
        if publication_id is None:
            rows = self._query(_statement(_VISIBLE_GENERATION_SELECT, task_id))
            if rows:
                publication_id = _id(rows[0].get("publication_id"))
        if publication_id is None:
            return HideReceipt(task_id, None, changed=False)
        if state == "hidden":
            return HideReceipt(task_id, publication_id, changed=False)
        self._batch((_statement(_HIDE_UPSERT, task_id, publication_id, _timestamp_now()),))
        head = self._query(_statement(_HEAD_SELECT, task_id))
        if len(head) != 1 or head[0].get("publication_id") != publication_id or head[0].get("state") != "hidden":
            _invalid(D1ErrorCode.generation_state)
        return HideReceipt(task_id, publication_id)


D1Client = D1PublicationClient
PublicationD1Client = D1PublicationClient


__all__ = [
    "D1Client",
    "D1Error",
    "D1ErrorCode",
    "D1PublicationClient",
    "ExposureReceipt",
    "HideReceipt",
    "MAX_BATCH_BYTES",
    "MAX_BATCH_PARAMETERS",
    "MAX_BATCH_STATEMENTS",
    "MAX_RESPONSE_BYTES",
    "PublicationD1Client",
    "StageReceipt",
]

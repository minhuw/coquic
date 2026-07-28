#!/usr/bin/env python3
from __future__ import annotations
import argparse
import copy
import json
import math
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from jsonschema import Draft202012Validator
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "steward-cloud" / "atif-v1.7.schema.json"
D1_SCHEMA_PATH = ROOT / "contracts" / "steward-cloud" / "d1.sql"
SUPPORTED_IMAGES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_KEY_PATTERN = re.compile(
    r"^v1/tasks/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})$"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"^v1/originals/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/sha256/([0-9a-f]{64})\.jsonl$"
)
PRIVATE_NAME = re.compile(
    r"(?:bucket|objectkey|credential|secret|password|token|authorization|apikey|private)",
    re.IGNORECASE,
)
EXPECTED_D1_TABLES = {
    "publication_generations", "task_heads", "tasks", "pipelines", "runs", "task_events", "artifacts",
}
PRIVATE_VALUE = re.compile(
    r"(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?)://|"
    r"^(?:~[/\\]|[A-Za-z]:[/\\]|\\\\)|"
    r"(?:^|[-_])(private|internal|secret)[-_](bucket|object(?:[-_]key)?|url|path)(?:$|[-_])",
    re.IGNORECASE,
)
@dataclass(frozen=True)
class Issue:
    rule: str
    path: tuple[Any, ...] = ()
    def rendered(self) -> str:
        value = "$"
        for part in self.path:
            value += f"[{part}]" if isinstance(part, int) else f".{part}"
        return f"{self.rule} at {value}"
class DuplicateKey(ValueError):
    pass
def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey
        result[key] = value
    return result
def canonical_bytes(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
def _add(issues: set[Issue], rule: str, path: Iterable[Any] = ()) -> None:
    issues.add(Issue(rule, tuple(path)))
def _nonempty_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_PATTERN.fullmatch(value))
def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
def _private_scan(value: Any, path: tuple[Any, ...], issues: set[Issue], key: str | None = None) -> None:
    if key is not None:
        compact = re.sub(r"[^a-z0-9]", "", key.lower())
        if PRIVATE_NAME.search(compact) or compact in {"url", "uri", "endpoint", "baseurl", "baseuri"}:
            _add(issues, "private-field", path)
        if compact in {"trajectorypath", "filepath", "credentialpath", "privatepath"}:
            _add(issues, "private-locator", path)
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _private_scan(child_value, path + (child_key,), issues, str(child_key))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _private_scan(child, path + (index,), issues, key)
        return
    if isinstance(value, str):
        if value.startswith("/") or (key is not None and compact == "mediatype" and value.lower().startswith("image/") and value not in SUPPORTED_IMAGES): _add(issues, "private-locator" if value.startswith("/") else "media-type", path)
        if PRIVATE_VALUE.search(value):
            _add(issues, "private-locator", path)
        if key is not None and key.lower().endswith("path") and not value.startswith("artifact:"):
            _add(issues, "private-locator", path)
def _schema_issues(document: Any, validator: Draft202012Validator) -> set[Issue]:
    issues: set[Issue] = set()
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.validator),
    )
    for error in errors:
        _add(issues, f"schema-{error.validator}", error.absolute_path)
    return issues
def _check_content(
    content: Any, path: tuple[Any, ...], step_id: int,
    artifacts: dict[str, tuple[dict[str, Any], tuple[Any, ...]]], referenced: set[str], issues: set[Issue],
) -> None:
    if not isinstance(content, list):
        return
    for index, part in enumerate(content):
        part_path = path + (index,)
        if not isinstance(part, dict):
            continue
        part_type = part.get("type")
        if part_type == "text":
            if not isinstance(part.get("text"), str) or part.get("source") is not None:
                _add(issues, "content-shape", part_path)
            continue
        if part_type != "image":
            continue
        source = part.get("source")
        if not isinstance(source, dict):
            _add(issues, "media-type", part_path + ("source",))
            continue
        media_type = source.get("media_type")
        if media_type not in SUPPORTED_IMAGES:
            _add(issues, "media-type", part_path + ("source", "media_type"))
        logical = source.get("path")
        if not isinstance(logical, str) or not logical.startswith("artifact:"):
            _add(issues, "artifact-reference", part_path + ("source", "path"))
            continue
        artifact_id = logical.removeprefix("artifact:")
        descriptor = artifacts.get(artifact_id)
        if descriptor is None:
            _add(issues, "artifact-reference", part_path + ("source", "path"))
            continue
        referenced.add(artifact_id)
        item, item_path = descriptor
        if item.get("ownerStepId") != step_id:
            _add(issues, "artifact-owner", item_path + ("ownerStepId",))
        if item.get("mediaType") != media_type:
            _add(issues, "artifact-media-type", item_path + ("mediaType",))
def _check_artifacts(
    coqui: dict[str, Any], steps: list[Any], issues: set[Issue],
) -> None:
    raw_artifacts = coqui.get("artifacts")
    if not isinstance(raw_artifacts, list):
        _add(issues, "artifact-shape", ("extra", "coquic", "artifacts"))
        return
    artifacts: dict[str, tuple[dict[str, Any], tuple[Any, ...]]] = {}
    step_ids = {step.get("step_id") for step in steps if isinstance(step, dict)}
    for index, item in enumerate(raw_artifacts):
        item_path = ("extra", "coquic", "artifacts", index)
        if not isinstance(item, dict):
            _add(issues, "artifact-shape", item_path)
            continue
        required = {"artifactId", "mediaType", "sha256", "byteSize", "ownerStepId"}
        if set(item) != required:
            _add(issues, "artifact-shape", item_path)
        artifact_id = item.get("artifactId")
        if not _nonempty_id(artifact_id):
            _add(issues, "artifact-id", item_path + ("artifactId",))
        elif artifact_id in artifacts:
            _add(issues, "artifact-unique", item_path + ("artifactId",))
        else:
            artifacts[artifact_id] = (item, item_path)
        media_type = item.get("mediaType")
        if not isinstance(media_type, str) or not media_type or any(char.isspace() for char in media_type):
            _add(issues, "artifact-media-type", item_path + ("mediaType",))
        elif media_type.startswith("image/") and media_type not in SUPPORTED_IMAGES:
            _add(issues, "media-type", item_path + ("mediaType",))
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            _add(issues, "artifact-digest", item_path + ("sha256",))
        size = item.get("byteSize")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            _add(issues, "artifact-size", item_path + ("byteSize",))
        owner = item.get("ownerStepId")
        if not isinstance(owner, int) or isinstance(owner, bool) or owner not in step_ids:
            _add(issues, "artifact-owner", item_path + ("ownerStepId",))

    referenced: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        step_id = step.get("step_id")
        step_extra = step.get("extra")
        step_extra = step_extra if isinstance(step_extra, dict) and isinstance(step_extra.get("coquic"), dict) else {"coquic": {}}
        if not isinstance(step_extra, dict):
            continue
        step_coqui = step_extra.get("coquic")
        if not isinstance(step_coqui, dict):
            continue
        refs = step_coqui.get("artifactIds", [])
        if not isinstance(refs, list):
            _add(issues, "artifact-reference", ("steps", index, "extra", "coquic", "artifactIds"))
        else:
            for ref_index, artifact_id in enumerate(refs):
                ref_path = ("steps", index, "extra", "coquic", "artifactIds", ref_index)
                if not isinstance(artifact_id, str) or artifact_id not in artifacts:
                    _add(issues, "artifact-reference", ref_path)
                    continue
                referenced.add(artifact_id)
                item, item_path = artifacts[artifact_id]
                if item.get("ownerStepId") != step_id:
                    _add(issues, "artifact-owner", item_path + ("ownerStepId",))
        _check_content(step.get("message"), ("steps", index, "message"), step_id, artifacts, referenced, issues)
        observation = step.get("observation")
        if isinstance(observation, dict):
            for result_index, result in enumerate(observation.get("results", [])):
                if isinstance(result, dict):
                    _check_content(
                        result.get("content"),
                        ("steps", index, "observation", "results", result_index, "content"), step_id, artifacts, referenced, issues,
                    )
    for artifact_id, (_, item_path) in artifacts.items():
        if artifact_id not in referenced:
            _add(issues, "artifact-unreferenced", item_path)
def _check_trajectory(document: Any, issues: set[Issue], *, embedded: bool = False) -> None:
    if not isinstance(document, dict):
        return
    if document.get("schema_version") != "ATIF-v1.7":
        _add(issues, "root-schema-version", ("schema_version",))
    if document.get("continued_trajectory_ref") not in (None,):
        _add(issues, "partial-run", ("continued_trajectory_ref",))
    if embedded and not _nonempty_id(document.get("trajectory_id")):
        _add(issues, "trajectory-id", ("trajectory_id",))

    steps = document.get("steps")
    if not isinstance(steps, list):
        return
    expected = list(range(1, len(steps) + 1))
    actual = [step.get("step_id") for step in steps if isinstance(step, dict)]
    if actual != expected:
        _add(issues, "step-sequence", ("steps",))
    call_ids: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        calls = step.get("tool_calls")
        if isinstance(calls, list):
            for call_index, call in enumerate(calls):
                if not isinstance(call, dict):
                    continue
                call_id = call.get("tool_call_id")
                call_path = ("steps", index, "tool_calls", call_index, "tool_call_id")
                if not isinstance(call_id, str) or not call_id:
                    _add(issues, "tool-call-id", call_path)
                elif call_id in call_ids:
                    _add(issues, "tool-call-unique", call_path)
                else:
                    call_ids.add(call_id)
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        observation = step.get("observation")
        if isinstance(observation, dict) and isinstance(observation.get("results"), list):
            for result_index, result in enumerate(observation["results"]):
                if not isinstance(result, dict):
                    continue
                source = result.get("source_call_id")
                if source is not None and source not in call_ids:
                    _add(
                        issues,
                        "observation-reference",
                        ("steps", index, "observation", "results", result_index, "source_call_id"),
                    )
    extra = document.get("extra")
    coqui = extra.get("coquic") if isinstance(extra, dict) else None
    if not isinstance(coqui, dict):
        _add(issues, "provenance-shape", ("extra", "coquic"))
    else:
        required = {"taskId", "pipelineId", "runId", "role", "startedAt", "completedAt", "durationMs", "disclosure", "artifacts"}
        for field in sorted(required - set(coqui)):
            _add(issues, "provenance-field", ("extra", "coquic", field))
        for field in ("taskId", "pipelineId", "runId"):
            if field in coqui and not _nonempty_id(coqui[field]):
                _add(issues, "provenance-id", ("extra", "coquic", field))
        if "role" in coqui and (not isinstance(coqui["role"], str) or not coqui["role"]):
            _add(issues, "provenance-role", ("extra", "coquic", "role"))
        started = _timestamp(coqui.get("startedAt"))
        completed = _timestamp(coqui.get("completedAt"))
        if started is None or completed is None:
            _add(issues, "timing", ("extra", "coquic"))
        elif completed < started:
            _add(issues, "timing-order", ("extra", "coquic", "completedAt"))
        if not _is_number(coqui.get("durationMs")) or coqui["durationMs"] < 0:
            _add(issues, "duration", ("extra", "coquic", "durationMs"))
        disclosure = coqui.get("disclosure")
        if not isinstance(disclosure, dict) or set(disclosure) != {"redactionApplied", "originalRetained"} or any(
            type(disclosure.get(key)) is not bool for key in ("redactionApplied", "originalRetained")
        ):
            _add(issues, "disclosure", ("extra", "coquic", "disclosure"))
        _check_artifacts(coqui, steps, issues)
    children = document.get("subagent_trajectories")
    child_ids: set[str] = set()
    if isinstance(children, list):
        for index, child in enumerate(children):
            child_path = ("subagent_trajectories", index)
            if not isinstance(child, dict):
                continue
            child_id = child.get("trajectory_id")
            if not _nonempty_id(child_id):
                _add(issues, "trajectory-id", child_path + ("trajectory_id",))
            elif child_id in child_ids:
                _add(issues, "trajectory-unique", child_path + ("trajectory_id",))
            else:
                child_ids.add(child_id)
            _check_trajectory(child, issues, embedded=True)
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not isinstance(step.get("observation"), dict):
            continue
        for result_index, result in enumerate(step["observation"].get("results", [])):
            if not isinstance(result, dict):
                continue
            refs = result.get("subagent_trajectory_ref")
            if not isinstance(refs, list):
                continue
            for ref_index, ref in enumerate(refs):
                ref_path = ("steps", index, "observation", "results", result_index, "subagent_trajectory_ref", ref_index)
                if not isinstance(ref, dict):
                    continue
                trajectory_id = ref.get("trajectory_id")
                trajectory_path = ref.get("trajectory_path")
                if trajectory_id is None and trajectory_path is None:
                    _add(issues, "subagent-reference", ref_path)
                if trajectory_id is not None and trajectory_id not in child_ids:
                    _add(issues, "subagent-reference", ref_path + ("trajectory_id",))
                if trajectory_path is not None:
                    _add(issues, "private-locator", ref_path + ("trajectory_path",))
def validate_atif_document(
    document: Any,
    validator: Draft202012Validator,
    raw: bytes | None = None,
) -> list[Issue]:
    issues = _schema_issues(document, validator)
    _private_scan(document, (), issues)
    _check_trajectory(document, issues)
    if raw is not None:
        try:
            if raw != canonical_bytes(document):
                _add(issues, "canonicalization")
        except (TypeError, ValueError, UnicodeEncodeError):
            _add(issues, "canonicalization")
    return sorted(issues, key=lambda issue: (issue.path, issue.rule))
def validate_atif_bytes(raw: bytes, validator: Draft202012Validator) -> tuple[Any | None, list[Issue]]:
    try:
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_object_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey, ValueError):
        return None, [Issue("canonicalization")]
    issues = validate_atif_document(document, validator, raw)
    return document, issues


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(DIGEST_PATTERN.fullmatch(value))


def _valid_public_key(value: Any, task_id: str | None = None, digest: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    match = PUBLIC_KEY_PATTERN.fullmatch(value)
    return bool(match and match.group(2) == match.group(3)[:2]
        and (task_id is None or match.group(1) == task_id)
        and (digest is None or match.group(3) == digest))


def _valid_private_key(value: Any) -> bool:
    return isinstance(value, str) and bool(PRIVATE_KEY_PATTERN.fullmatch(value))


def _private_d1_column(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return compact not in {"publickey", "logicalpath"} and (
        bool(PRIVATE_NAME.search(compact))
        or compact in {"url", "uri", "endpoint", "baseurl", "baseuri", "filepath", "credentialpath", "privatepath"}
    )


def _d1_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(D1_SCHEMA_PATH.read_text(encoding="utf-8"))
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise RuntimeError("foreign keys are disabled")
    return connection


def _d1_public_rows(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute(
        """
        SELECT h.task_id, p.publication_id, t.title, r.run_id
          FROM task_heads AS h
          JOIN publication_generations AS p
            ON p.publication_id = h.publication_id AND p.state = 'visible'
          JOIN tasks AS t
            ON t.publication_id = p.publication_id AND t.task_id = h.task_id
          JOIN runs AS r
            ON r.publication_id = p.publication_id AND r.task_id = h.task_id
         WHERE h.state = 'visible'
         ORDER BY h.task_id
        """
    ).fetchall()


def _d1_stage(
    connection: sqlite3.Connection,
    publication_id: str,
    task_id: str,
    run_id: str,
    metadata_digest: str,
    *,
    artifact_rows: int = 2,
    expected_artifact_count: int = 2,
) -> None:
    key_digest = "0" * 64
    public_key = f"v1/tasks/{task_id}/objects/sha256/{key_digest[:2]}/{key_digest}"
    expected_generation = (task_id, run_id, metadata_digest, f"retry-{publication_id}", "staged", 1, 1, 1, 1, expected_artifact_count, "2026-07-28T00:00:00Z")
    generation_sql = "SELECT task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at FROM publication_generations WHERE publication_id = ?"
    existing_generation = connection.execute(generation_sql, (publication_id,)).fetchone()
    if existing_generation is not None and existing_generation != expected_generation:
        raise ValueError("generation-conflict")
    expected_children = (("tasks", "task_id,title,lifecycle_state,created_at,completed_at", ((task_id, "Example task", "completed", "2026-07-28T00:00:00Z", None),)), ("pipelines", "pipeline_id,task_id,name,created_at", ((f"pipeline-{publication_id}", task_id, "Example pipeline", "2026-07-28T00:00:00Z"),)), ("runs", "run_id,task_id,pipeline_id,role,run_state,started_at,completed_at,duration_ms,atif_digest", ((run_id, task_id, f"pipeline-{publication_id}", "implementation", "completed", "2026-07-28T00:00:00Z", "2026-07-28T00:00:01Z", 1000, "f" * 64),)), ("task_events", "task_id,sequence,event_type,occurred_at,summary", ((task_id, 1, "completed", "2026-07-28T00:00:01Z", "Run completed"),)), ("artifacts", "artifact_id,task_id,run_id,logical_path,public_key,media_type,byte_size,sha256,availability,redaction_applied,original_retained", tuple((f"artifact-{publication_id}-{index}", task_id, run_id, f"steps/1/output-{index}.txt", public_key, "text/plain", 12 + index, key_digest, "available", 0, 1) for index in range(expected_artifact_count))))
    if any(any(row not in expected for row in connection.execute(f"SELECT {columns} FROM {table} WHERE publication_id = ?", (publication_id,)).fetchall()) for table, columns, expected in expected_children):
        raise ValueError("child-conflict")
    statements = [
        (
            "INSERT INTO publication_generations "
            "(publication_id, task_id, run_id, metadata_digest, idempotency_key, state, "
            "expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, "
            "expected_artifact_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', 1, 1, 1, 1, ?, ?)",
            (publication_id, task_id, run_id, metadata_digest, f"retry-{publication_id}", expected_artifact_count, "2026-07-28T00:00:00Z"),
        ),
        (
            "INSERT INTO tasks (publication_id, task_id, title, lifecycle_state, created_at) VALUES (?, ?, ?, 'completed', ?)",
            (publication_id, task_id, "Example task", "2026-07-28T00:00:00Z"),
        ),
        (
            "INSERT INTO pipelines (publication_id, pipeline_id, task_id, name, created_at) VALUES (?, ?, ?, ?, ?)",
            (publication_id, f"pipeline-{publication_id}", task_id, "Example pipeline", "2026-07-28T00:00:00Z"),
        ),
        (
            "INSERT INTO runs (publication_id, run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest) "
            "VALUES (?, ?, ?, ?, 'implementation', 'completed', ?, ?, 1000, ?)",
            (publication_id, run_id, task_id, f"pipeline-{publication_id}", "2026-07-28T00:00:00Z", "2026-07-28T00:00:01Z", "f" * 64),
        ),
        (
            "INSERT INTO task_events (publication_id, task_id, sequence, event_type, occurred_at, summary) VALUES (?, ?, 1, 'completed', ?, ?)",
            (publication_id, task_id, "2026-07-28T00:00:01Z", "Run completed"),
        ),
    ]
    for statement, parameters in statements:
        connection.execute("BEGIN")
        connection.execute(statement.replace("INSERT INTO", "INSERT OR IGNORE INTO"), parameters)
        connection.commit()
    for index in range(artifact_rows):
        connection.execute("BEGIN")
        connection.execute(
            "INSERT OR IGNORE INTO artifacts (publication_id, artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained) "
            "VALUES (?, ?, ?, ?, ?, ?, 'text/plain', ?, ?, 'available', 0, 1)",
            (publication_id, f"artifact-{publication_id}-{index}", task_id, run_id, f"steps/1/output-{index}.txt", public_key, 12 + index, key_digest),
        )
        connection.commit()
    if connection.execute(generation_sql, (publication_id,)).fetchone() != expected_generation:
        raise ValueError("generation-conflict")

def _d1_expose(
    connection: sqlite3.Connection,
    task_id: str,
    publication_id: str,
    *,
    inject_failure: bool = False,
) -> None:
    expected_tables = (
        ("tasks", "expected_task_count"),
        ("pipelines", "expected_pipeline_count"),
        ("runs", "expected_run_count"),
        ("task_events", "expected_event_count"),
        ("artifacts", "expected_artifact_count"),
    )
    connection.execute("BEGIN IMMEDIATE")
    try:
        row = connection.execute(
            "SELECT state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count "
            "FROM publication_generations WHERE publication_id = ? AND task_id = ?",
            (publication_id, task_id),
        ).fetchone()
        if row is None or row[0] != "staged":
            raise ValueError("generation-state")
        for (table, _), expected in zip(expected_tables, row[1:]):
            actual = connection.execute(f"SELECT count(*) FROM {table} WHERE publication_id = ?", (publication_id,)).fetchone()[0]
            if actual != expected:
                raise ValueError("row-count")
        connection.execute(
            "UPDATE publication_generations SET state = 'superseded' WHERE task_id = ? AND state = 'visible' AND publication_id <> ?",
            (task_id, publication_id),
        )
        changed = connection.execute(
            "UPDATE publication_generations SET state = 'visible', exposed_at = ? WHERE publication_id = ? AND state = 'staged'",
            ("2026-07-28T00:00:02Z", publication_id),
        ).rowcount
        if changed != 1:
            raise ValueError("generation-state")
        if inject_failure:
            raise RuntimeError("injected-swap-failure")
        connection.execute(
            "INSERT INTO task_heads (task_id, publication_id, state, updated_at) VALUES (?, ?, 'visible', ?) "
            "ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, state = 'visible', updated_at = excluded.updated_at",
            (task_id, publication_id, "2026-07-28T00:00:02Z"),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _d1_rejected(connection: sqlite3.Connection, statement: str, parameters: tuple[Any, ...]) -> bool:
    connection.execute("BEGIN")
    try:
        connection.execute(statement, parameters)
    except sqlite3.IntegrityError:
        connection.rollback()
        return True
    connection.rollback()
    return False

def _d1_stage_rejected(connection: sqlite3.Connection, *arguments: Any) -> bool:
    try: _d1_stage(connection, *arguments)
    except ValueError: return True
    return False


def _run_d1_cases() -> tuple[int, int]:
    checks: list[tuple[str, bool]] = []
    connection: sqlite3.Connection | None = None

    def record(name: str, result: bool) -> None:
        checks.append((name, result))

    try:
        connection = _d1_connection()
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        record("schema-load", EXPECTED_D1_TABLES <= tables)
        record("foreign-keys", connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1)
        columns = [
            column[1]
            for table in sorted(EXPECTED_D1_TABLES)
            for column in connection.execute(f"PRAGMA table_info({table})")
        ]
        record("private-locator-denial", not any(_private_d1_column(column) for column in columns))
        record(
            "key-grammar",
            _valid_public_key("v1/tasks/task-1/objects/sha256/00/" + "0" * 64, "task-1", "0" * 64)
            and _valid_private_key("v1/originals/task-1/run-1/sha256/" + "a" * 64 + ".jsonl")
            and not _valid_public_key("v1/originals/task-1/run-1/sha256/" + "a" * 64 + ".jsonl")
            and not _valid_public_key("v1/tasks/task-1/objects/sha256/AA/" + "A" * 64)
            and not _valid_public_key("v1/tasks/task-1/objects/sha256/01/" + "0" * 64) and not _valid_public_key("v1/tasks/other-task/objects/sha256/00/" + "0" * 64, "task-1", "0" * 64)
            and _valid_digest("0" * 64)
            and not _valid_digest("A" * 64),
        )
        _d1_stage(connection, "pub-1", "task-1", "run-1", "a" * 64)
        record("staged-hidden", _d1_public_rows(connection) == [])
        _d1_expose(connection, "task-1", "pub-1")
        record("initial-expose", _d1_public_rows(connection) == [("task-1", "pub-1", "Example task", "run-1")])
        _d1_stage(connection, "pub-2", "task-1", "run-2", "b" * 64, artifact_rows=1)
        _d1_stage(connection, "pub-2", "task-1", "run-2", "b" * 64)
        record("staging-isolation", _d1_public_rows(connection)[0][1] == "pub-1")
        record(
            "object-key-reuse",
            connection.execute(
                "SELECT count(DISTINCT public_key), count(DISTINCT logical_path) FROM artifacts WHERE publication_id = 'pub-2'"
            ).fetchone() == (1, 2)
            and connection.execute(
                "SELECT a.public_key = b.public_key FROM artifacts AS a JOIN artifacts AS b ON a.artifact_id <> b.artifact_id "
                "WHERE a.publication_id = 'pub-1' AND b.publication_id = 'pub-2' LIMIT 1"
            ).fetchone()[0] == 1,
        )
        record(
            "idempotency-denial",
            _d1_rejected(
                connection,
                "INSERT INTO publication_generations "
                "(publication_id, task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'staged', 1, 1, 1, 1, 0, ?)",
                ("pub-duplicate", "task-1", "run-duplicate", "d" * 64, "retry-pub-2", "2026-07-28T00:00:00Z"),
            ),
        )
        try:
            _d1_expose(connection, "task-1", "pub-2", inject_failure=True)
        except RuntimeError:
            pass
        record(
            "swap-rollback",
            _d1_public_rows(connection)[0][1] == "pub-1"
            and connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-1'").fetchone()[0] == "visible"
            and connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-2'").fetchone()[0] == "staged",
        )
        _d1_expose(connection, "task-1", "pub-2")
        record(
            "supersede-and-repoint",
            _d1_public_rows(connection)[0][1] == "pub-2"
            and connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-1'").fetchone()[0] == "superseded",
        )
        _d1_stage(connection, "pub-bad", "task-1", "run-bad", "c" * 64, artifact_rows=1)
        try:
            _d1_expose(connection, "task-1", "pub-bad")
        except ValueError as error:
            record("row-count-denial", str(error) == "row-count")
        else:
            record("row-count-denial", False)
        connection.execute("UPDATE tasks SET title = 'CONFLICTING TITLE' WHERE publication_id = 'pub-bad'")
        connection.commit()
        record("child-conflict-denial", connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-bad'").fetchone()[0] == "staged" and _d1_stage_rejected(connection, "pub-bad", "task-1", "run-bad", "d" * 64) and _d1_stage_rejected(connection, "pub-bad", "task-1", "run-bad", "c" * 64) and _d1_public_rows(connection)[0][1] == "pub-2")
        record("invalid-state-denial", _d1_rejected(connection, "UPDATE publication_generations SET state = 'invalid' WHERE publication_id = ?", ("pub-2",)))
        record("invalid-digest-denial", _d1_rejected(connection, "UPDATE artifacts SET sha256 = ? WHERE publication_id = ?", ("A" * 64, "pub-2")))
        record("invalid-key-denial", _d1_rejected(connection, "UPDATE artifacts SET public_key = ? WHERE publication_id = ?", ("private://object", "pub-2")) and _d1_rejected(connection, "UPDATE artifacts SET public_key = ? WHERE publication_id = ?", ("v1/tasks/not-task/objects/sha256/bb/" + "b" * 64, "pub-2")) and _d1_rejected(connection, "UPDATE artifacts SET public_key = ? WHERE publication_id = ?", ("v1/tasks/TASK-1/objects/sha256/00/" + "0" * 64, "pub-2")))
        record("private-name-denial", _private_d1_column("private_locator") and _private_d1_column("credential_url") and _d1_rejected(connection, "INSERT INTO task_heads (task_id, publication_id, state, updated_at) VALUES (?, ?, 'visible', ?)", ("other-task", "pub-2", "2026-07-28T00:00:00Z")))
        connection.execute("BEGIN")
        connection.execute("UPDATE task_heads SET state = 'hidden' WHERE task_id = ?", ("task-1",))
        connection.commit()
        record("hide-task", _d1_public_rows(connection) == [])
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as error:
        record("d1-execution", False)
        print(f"FAIL d1 execution: {type(error).__name__}", file=sys.stderr)
    finally:
        if connection is not None:
            connection.close()
    passed = sum(result for _, result in checks)
    failed = len(checks) - passed
    summary = ", ".join(f"{name}={'ok' if result else 'FAIL'}" for name, result in checks)
    print(f"D1 checks: {summary}")
    return passed, failed
def _example() -> dict[str, Any]:
    return {
        "schema_version": "ATIF-v1.7",
        "agent": {"name": "codex", "version": "1"},
        "steps": [
            {"step_id": 1, "source": "user", "message": "Inspect the task."},
            {
                "step_id": 2,
                "source": "agent",
                "message": [
                    {"type": "text", "text": "The result is ready."},
                    {"type": "image", "source": {"media_type": "image/png", "path": "artifact:plot-1"}},
                ],
                "tool_calls": [{"tool_call_id": "call-1", "function_name": "inspect", "arguments": {}}],
                "observation": {
                    "results": [
                        {"source_call_id": "call-1", "content": "Inspection complete."}
                    ]
                },
                "extra": {"coquic": {"artifactIds": ["plot-1", "log-1"]}},
            },
        ],
        "extra": {
            "coquic": {
                "taskId": "task-example",
                "pipelineId": "pipeline-example",
                "runId": "run-example",
                "role": "implementation",
                "startedAt": "2026-07-28T00:00:00Z",
                "completedAt": "2026-07-28T00:00:01Z",
                "durationMs": 1000,
                "disclosure": {"redactionApplied": False, "originalRetained": True},
                "artifacts": [
                    {
                        "artifactId": "plot-1",
                        "mediaType": "image/png",
                        "sha256": "0" * 64,
                        "byteSize": 12,
                        "ownerStepId": 2,
                    },
                    {
                        "artifactId": "log-1",
                        "mediaType": "text/plain",
                        "sha256": "1" * 64,
                        "byteSize": 8,
                        "ownerStepId": 2,
                    },
                ],
            }
        },
    }
def _run_cases(validator: Draft202012Validator) -> tuple[int, int]:
    clean = _example()
    redacted = copy.deepcopy(clean)
    redacted["extra"]["coquic"]["disclosure"] = {"redactionApplied": True, "originalRetained": True}
    positives = {"clean": clean, "redacted": redacted}
    negatives: dict[str, tuple[dict[str, Any], str]] = {}
    mutated = copy.deepcopy(clean); mutated["schema_version"] = "ATIF-v1.6"; negatives["schema-version"] = (mutated, "root-schema-version")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["completedAt"] = None; negatives["partial-run"] = (mutated, "timing")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["step_id"] = 3; negatives["step-sequence"] = (mutated, "step-sequence")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["tool_calls"].append(copy.deepcopy(mutated["steps"][1]["tool_calls"][0])); negatives["duplicate-call"] = (mutated, "tool-call-unique")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["observation"]["results"][0]["source_call_id"] = "missing"; negatives["dangling-observation"] = (mutated, "observation-reference")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["message"][1]["source"]["media_type"] = "image/tiff"; negatives["unsupported-image"] = (mutated, "media-type")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["artifacts"] = []; negatives["missing-artifact"] = (mutated, "artifact-reference")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["message"][1]["source"]["path"] = "https://private.example/object"; negatives["private-locator"] = (mutated, "private-locator")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["accessToken"] = "not printed"; negatives["token-metadata"] = (mutated, "private-field")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["disclosure"]["redactionApplied"] = "false"; negatives["disclosure-type"] = (mutated, "disclosure")
    passed = 0
    failed = 0
    for name, document in positives.items():
        _, issues = validate_atif_bytes(canonical_bytes(document), validator)
        if issues:
            print(f"FAIL accepted {name}: {', '.join(issue.rendered() for issue in issues)}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
    for name, (document, expected_rule) in negatives.items():
        _, issues = validate_atif_bytes(canonical_bytes(document), validator)
        if not any(issue.rule == expected_rule for issue in issues):
            print(f"FAIL rejected {name}: missing {expected_rule}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
    noncanonical = json.dumps(clean, ensure_ascii=False).encode("utf-8")
    _, issues = validate_atif_bytes(noncanonical, validator)
    if not any(issue.rule == "canonicalization" for issue in issues):
        print("FAIL rejected noncanonical: missing canonicalization", file=sys.stderr)
        failed += 1
    else:
        passed += 1
    print(f"ATIF checks: {passed} accepted cases, {failed} failed cases")
    return passed, failed
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Steward cloud contracts")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--atif-only", action="store_true", help="run the ATIF contract checks")
    modes.add_argument("--d1-only", action="store_true", help="run the clean D1 contract checks")
    args = parser.parse_args(argv)
    if args.d1_only:
        try:
            _, failed = _run_d1_cases()
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            print("D1 validator could not load its clean schema", file=sys.stderr)
            return 1
        return 1 if failed else 0
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        _, failed = _run_cases(validator)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        print("ATIF validator could not load its pinned schema", file=sys.stderr)
        return 1
    return 1 if failed else 0
if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.models import (
    Event,
    SignalFetchRun,
    SignalItem,
    TaskIteration,
    TaskRecord,
    TaskSpec,
    ValidationResult,
)
from .schema import (
    EventRow,
    SignalFetchRunRow,
    SignalItemRow,
    TaskIterationRow,
    TaskRow,
    ValidationRow,
)


class PathCodec:
    _RELATIVE_ROOTS = frozenset(
        {"logs", "patches", "prompts", "schemas", "transcripts", "worktrees"}
    )
    _PATH_KEYS = frozenset({"cwd", "log", "logs", "path", "paths"})

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir.resolve()

    def dump(self, value: Path | None) -> str | None:
        if value is None:
            return None
        path = value.expanduser()
        if not path.is_absolute():
            return path.as_posix()
        try:
            return path.resolve().relative_to(self.base_dir).as_posix()
        except ValueError:
            return str(path)

    def load(self, value: str | None) -> Path | None:
        if not value:
            return None
        path = Path(value)
        return path if path.is_absolute() else self.base_dir / path

    def is_portable(self, value: str | None) -> bool:
        if not value:
            return True
        return not Path(value).is_absolute()

    def dump_text_path(self, value: str) -> str:
        return self._dump_string(value)

    def load_text_path(self, value: str) -> str:
        return self._load_string(value)

    def dump_json(self, value: Any, *, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {
                item_key: self.dump_json(item, key=item_key)
                for item_key, item in value.items()
            }
        if isinstance(value, list):
            return [self.dump_json(item, key=key) for item in value]
        if isinstance(value, str) and self._is_path_key(key):
            return self._dump_string(value)
        return value

    def load_json(self, value: Any, *, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {
                item_key: self.load_json(item, key=item_key)
                for item_key, item in value.items()
            }
        if isinstance(value, list):
            return [self.load_json(item, key=key) for item in value]
        if isinstance(value, str) and self._is_path_key(key):
            return self._load_string(value)
        return value

    def _dump_string(self, value: str) -> str:
        path = Path(value).expanduser()
        if not path.is_absolute():
            return value
        dumped = self.dump(path)
        return dumped if dumped is not None else value

    def _load_string(self, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or not self._looks_like_state_path(path):
            return value
        return str(self.base_dir / path)

    def _looks_like_state_path(self, path: Path) -> bool:
        parts = path.parts
        return bool(parts) and parts[0] in self._RELATIVE_ROOTS

    def _is_path_key(self, key: str | None) -> bool:
        if key is None:
            return False
        return key in self._PATH_KEYS or key.endswith("_path") or key.endswith("_paths")


def task_to_row(
    record: TaskRecord, *, dedupe_key: str | None = None, path_codec: PathCodec
) -> TaskRow:
    return TaskRow(
        id=record.id,
        kind=str(record.spec.kind),
        worker=str(record.spec.worker),
        title=record.spec.title,
        prompt=record.spec.prompt,
        priority=str(record.spec.priority),
        risk=str(record.spec.risk),
        source=record.spec.source,
        allow_main_write=record.spec.allow_main_write,
        metadata_json=_dump_json(record.spec.metadata, path_codec=path_codec),
        dedupe_key=dedupe_key or _dedupe_key(record),
        status=str(record.status),
        summary=record.summary,
        created_at=_dump_datetime(record.created_at),
        updated_at=_dump_datetime(record.updated_at),
        worktree_path=path_codec.dump(record.worktree_path),
        branch_name=record.branch_name,
        transcript_path=path_codec.dump(record.transcript_path),
        last_message_path=path_codec.dump(record.last_message_path),
        patch_path=path_codec.dump(record.patch_path),
        validations=[
            validation_to_row(record.id, index, item, path_codec=path_codec)
            for index, item in enumerate(record.validations)
        ],
    )


def update_task_row(row: TaskRow, record: TaskRecord, *, path_codec: PathCodec) -> None:
    row.kind = str(record.spec.kind)
    row.worker = str(record.spec.worker)
    row.title = record.spec.title
    row.prompt = record.spec.prompt
    row.priority = str(record.spec.priority)
    row.risk = str(record.spec.risk)
    row.source = record.spec.source
    row.allow_main_write = record.spec.allow_main_write
    row.metadata_json = _dump_json(record.spec.metadata, path_codec=path_codec)
    row.dedupe_key = _dedupe_key(record)
    row.created_at = _dump_datetime(record.created_at)
    row.updated_at = _dump_datetime(record.updated_at)
    row.worktree_path = path_codec.dump(record.worktree_path)
    row.branch_name = record.branch_name
    row.transcript_path = path_codec.dump(record.transcript_path)
    row.last_message_path = path_codec.dump(record.last_message_path)
    row.patch_path = path_codec.dump(record.patch_path)
    row.validations = [
        validation_to_row(record.id, index, item, path_codec=path_codec)
        for index, item in enumerate(record.validations)
    ]


def row_to_task(row: TaskRow, *, path_codec: PathCodec) -> TaskRecord:
    metadata = _loads_dict(row.metadata_json, path_codec=path_codec)
    spec = TaskSpec(
        id=row.id,
        kind=row.kind,
        worker=row.worker,
        title=row.title,
        prompt=row.prompt,
        priority=row.priority,
        risk=row.risk,
        source=row.source,
        allow_main_write=row.allow_main_write,
        metadata=metadata,
    )
    return TaskRecord(
        spec=spec,
        status=row.status,
        summary=row.summary,
        created_at=_load_datetime(row.created_at),
        updated_at=_load_datetime(row.updated_at),
        worktree_path=path_codec.load(row.worktree_path),
        branch_name=row.branch_name,
        transcript_path=path_codec.load(row.transcript_path),
        last_message_path=path_codec.load(row.last_message_path),
        patch_path=path_codec.load(row.patch_path),
        validations=[
            row_to_validation(item, path_codec=path_codec) for item in row.validations
        ],
    )


def validation_to_row(
    task_id: str,
    position: int,
    result: ValidationResult,
    *,
    iteration: int | None = None,
    path_codec: PathCodec,
) -> ValidationRow:
    return ValidationRow(
        task_id=task_id,
        iteration=iteration if iteration is not None else result.iteration,
        position=position,
        command_json=json.dumps(result.command),
        cwd=path_codec.dump(result.cwd) or str(result.cwd),
        passed=result.passed,
        exit_code=result.exit_code,
        output_path=path_codec.dump(result.output_path) or "",
        summary=result.summary,
        started_at=_dump_datetime(result.started_at),
        completed_at=_dump_datetime(result.completed_at),
    )


def iteration_to_row(iteration: TaskIteration, *, path_codec: PathCodec) -> TaskIterationRow:
    return TaskIterationRow(
        task_id=iteration.task_id,
        iteration=iteration.iteration,
        label=iteration.label,
        worker_name=iteration.worker_name,
        worker_prompt_path=path_codec.dump(iteration.worker_prompt_path),
        worker_transcript_path=path_codec.dump(iteration.worker_transcript_path),
        worker_last_message_path=path_codec.dump(iteration.worker_last_message_path),
        worker_exit_code=iteration.worker_exit_code,
        worker_completed=iteration.worker_completed,
        reviewer_name=iteration.reviewer_name,
        reviewer_prompt_path=path_codec.dump(iteration.reviewer_prompt_path),
        reviewer_transcript_path=path_codec.dump(iteration.reviewer_transcript_path),
        reviewer_last_message_path=path_codec.dump(iteration.reviewer_last_message_path),
        reviewer_exit_code=iteration.reviewer_exit_code,
        reviewer_completed=iteration.reviewer_completed,
        reviewer_run=iteration.reviewer_run,
        review_json=_dump_json(iteration.review_json),
        patch_path=path_codec.dump(iteration.patch_path),
        started_at=_dump_datetime(iteration.started_at),
        updated_at=_dump_datetime(iteration.updated_at),
    )


def update_iteration_row(
    row: TaskIterationRow, iteration: TaskIteration, *, path_codec: PathCodec
) -> None:
    row.label = iteration.label
    row.worker_name = iteration.worker_name
    row.worker_prompt_path = path_codec.dump(iteration.worker_prompt_path)
    row.worker_transcript_path = path_codec.dump(iteration.worker_transcript_path)
    row.worker_last_message_path = path_codec.dump(iteration.worker_last_message_path)
    row.worker_exit_code = iteration.worker_exit_code
    row.worker_completed = iteration.worker_completed
    row.reviewer_name = iteration.reviewer_name
    row.reviewer_prompt_path = path_codec.dump(iteration.reviewer_prompt_path)
    row.reviewer_transcript_path = path_codec.dump(iteration.reviewer_transcript_path)
    row.reviewer_last_message_path = path_codec.dump(iteration.reviewer_last_message_path)
    row.reviewer_exit_code = iteration.reviewer_exit_code
    row.reviewer_completed = iteration.reviewer_completed
    row.reviewer_run = iteration.reviewer_run
    row.review_json = _dump_json(iteration.review_json)
    row.patch_path = path_codec.dump(iteration.patch_path)
    row.started_at = _dump_datetime(iteration.started_at)
    row.updated_at = _dump_datetime(iteration.updated_at)


def row_to_iteration(row: TaskIterationRow, *, path_codec: PathCodec) -> TaskIteration:
    return TaskIteration(
        task_id=row.task_id,
        iteration=row.iteration,
        label=row.label,
        worker_name=row.worker_name,
        worker_prompt_path=path_codec.load(row.worker_prompt_path),
        worker_transcript_path=path_codec.load(row.worker_transcript_path),
        worker_last_message_path=path_codec.load(row.worker_last_message_path),
        worker_exit_code=row.worker_exit_code,
        worker_completed=row.worker_completed,
        reviewer_name=row.reviewer_name,
        reviewer_prompt_path=path_codec.load(row.reviewer_prompt_path),
        reviewer_transcript_path=path_codec.load(row.reviewer_transcript_path),
        reviewer_last_message_path=path_codec.load(row.reviewer_last_message_path),
        reviewer_exit_code=row.reviewer_exit_code,
        reviewer_completed=row.reviewer_completed,
        reviewer_run=row.reviewer_run,
        review_json=_loads_optional_dict(row.review_json),
        patch_path=path_codec.load(row.patch_path),
        started_at=_load_datetime(row.started_at),
        updated_at=_load_datetime(row.updated_at),
    )


def row_to_validation(row: ValidationRow, *, path_codec: PathCodec) -> ValidationResult:
    return ValidationResult(
        command=json.loads(row.command_json),
        cwd=path_codec.load(row.cwd) or Path(row.cwd),
        passed=row.passed,
        exit_code=row.exit_code,
        output_path=path_codec.load(row.output_path) or Path(row.output_path),
        summary=row.summary,
        iteration=row.iteration,
        started_at=_load_datetime(row.started_at),
        completed_at=_load_datetime(row.completed_at),
    )


def event_to_row(event: Event, *, path_codec: PathCodec) -> EventRow:
    return EventRow(
        task_id=event.task_id,
        kind=event.kind,
        message=path_codec.dump_text_path(event.message),
        created_at=_dump_datetime(event.created_at),
        data_json=_dump_json(event.data, path_codec=path_codec),
    )


def row_to_event(row: EventRow, *, path_codec: PathCodec) -> Event:
    return Event(
        task_id=row.task_id,
        kind=row.kind,
        message=path_codec.load_text_path(row.message),
        created_at=_load_datetime(row.created_at),
        data=_loads_dict(row.data_json, path_codec=path_codec),
    )


def signal_item_to_row(item: SignalItem, *, path_codec: PathCodec) -> SignalItemRow:
    return SignalItemRow(
        id=item.id,
        provider=item.provider,
        kind=item.kind,
        fingerprint=item.fingerprint,
        title=item.title,
        summary=item.summary,
        severity=item.severity,
        location_json=_dump_json(item.location, path_codec=path_codec),
        links_json=_dump_list(item.links, path_codec=path_codec),
        payload_json=_dump_json(item.payload, path_codec=path_codec) or "{}",
        status=str(item.status),
        created_at=_dump_datetime(item.created_at),
        updated_at=_dump_datetime(item.updated_at),
        planned_at=_dump_datetime(item.planned_at) if item.planned_at else None,
        planner_run_id=item.planner_run_id,
        planned_task_id=item.planned_task_id,
        source_fetch_id=item.source_fetch_id,
    )


def row_to_signal_item(row: SignalItemRow, *, path_codec: PathCodec) -> SignalItem:
    return SignalItem(
        id=row.id,
        provider=row.provider,
        kind=row.kind,
        fingerprint=row.fingerprint,
        title=row.title,
        summary=row.summary,
        severity=row.severity,
        location=_loads_optional_dict(row.location_json, path_codec=path_codec),
        links=_loads_list(row.links_json, path_codec=path_codec),
        payload=_loads_dict(row.payload_json, path_codec=path_codec),
        status=row.status,
        created_at=_load_datetime(row.created_at),
        updated_at=_load_datetime(row.updated_at),
        planned_at=_load_datetime(row.planned_at) if row.planned_at else None,
        planner_run_id=row.planner_run_id,
        planned_task_id=row.planned_task_id,
        source_fetch_id=row.source_fetch_id,
    )


def signal_fetch_run_to_row(run: SignalFetchRun) -> SignalFetchRunRow:
    return SignalFetchRunRow(
        id=run.id,
        provider=run.provider,
        status=str(run.status),
        started_at=_dump_datetime(run.started_at),
        completed_at=_dump_datetime(run.completed_at),
        item_count=run.item_count,
        new_item_count=run.new_item_count,
        has_more=run.has_more,
        error=run.error,
        summary=run.summary,
    )


def row_to_signal_fetch_run(row: SignalFetchRunRow) -> SignalFetchRun:
    return SignalFetchRun(
        id=row.id,
        provider=row.provider,
        status=row.status,
        started_at=_load_datetime(row.started_at),
        completed_at=_load_datetime(row.completed_at),
        item_count=row.item_count,
        new_item_count=row.new_item_count,
        has_more=row.has_more,
        error=row.error,
        summary=row.summary,
    )


def _dedupe_key(record: TaskRecord) -> str | None:
    value = record.spec.metadata.get("dedupe_key")
    return str(value) if value is not None else None


def _dump_datetime(value: datetime) -> str:
    return value.isoformat()


def _load_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _loads_dict(value: str, *, path_codec: PathCodec | None = None) -> dict[str, Any]:
    loaded = json.loads(value or "{}")
    if path_codec is not None:
        loaded = path_codec.load_json(loaded)
    return loaded if isinstance(loaded, dict) else {}


def _loads_optional_dict(
    value: str | None, *, path_codec: PathCodec | None = None
) -> dict[str, Any] | None:
    if not value:
        return None
    loaded = json.loads(value)
    if path_codec is not None:
        loaded = path_codec.load_json(loaded)
    return loaded if isinstance(loaded, dict) else None


def _loads_list(value: str | None, *, path_codec: PathCodec | None = None) -> list[Any]:
    if not value:
        return []
    loaded = json.loads(value)
    if path_codec is not None:
        loaded = path_codec.load_json(loaded)
    return loaded if isinstance(loaded, list) else []


def _dump_json(
    value: dict[str, Any] | None, *, path_codec: PathCodec | None = None
) -> str | None:
    if value is None:
        return None
    if path_codec is not None:
        value = path_codec.dump_json(value)
    return json.dumps(value, sort_keys=True) if value is not None else None


def _dump_list(
    value: list[dict[str, str]], *, path_codec: PathCodec | None = None
) -> str:
    dumped: Any = value
    if path_codec is not None:
        dumped = path_codec.dump_json(dumped)
    return json.dumps(dumped, sort_keys=True)

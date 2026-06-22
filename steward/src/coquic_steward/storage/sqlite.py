from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import Select, create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..core.lifecycle import (
    TaskPhase,
    TaskTransition,
    integration_started,
    recovery_failed,
    require_transition_allowed,
    review_started,
    terminal_status,
    validation_started,
    worker_started,
)
from ..core.models import (
    ACTIVE_STATUSES,
    Event,
    SignalFetchRun,
    SignalItem,
    SignalItemStatus,
    TaskIteration,
    TaskRecord,
    TaskSpec,
    TaskStatus,
    ValidationResult,
    WorkerResult,
    utc_now,
)
from .mappers import (
    PathCodec,
    event_to_row,
    iteration_to_row,
    row_to_event,
    row_to_signal_fetch_run,
    row_to_signal_item,
    row_to_iteration,
    row_to_task,
    signal_fetch_run_to_row,
    signal_item_to_row,
    task_to_row,
    update_iteration_row,
    update_task_row,
    validation_to_row,
)
from .schema import (
    Base,
    EventRow,
    SignalFetchRunRow,
    SignalItemRow,
    TaskIterationRow,
    TaskRow,
    ValidationRow,
)

PRIORITY_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
WORKER_REVISION_STARTED_EVENTS = {
    "worker.revision_requested",
    "worker.validation_revision_requested",
}
WORKER_REVISION_FINISHED_EVENTS = {
    "worker.revision_finished",
    "worker.validation_revision_finished",
}
REVIEW_FINISHED_EVENTS = {
    "review.failed",
    "review.finished",
    "review.invalid_output",
}


class SQLiteTaskStore:
    """SQLite-backed store hidden behind Steward's TaskStore API."""

    def __init__(self, path: Path):
        self.path = path
        self.path_codec = PathCodec(path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}", future=True)
        event.listen(self.engine, "connect", _configure_sqlite)
        Base.metadata.create_all(self.engine)
        self._migrate_schema()
        self._migrate_portable_paths()
        self._migrate_legacy_json()

    def add_task(
        self, spec: TaskSpec, *, dedupe_key: str | None = None
    ) -> tuple[TaskRecord, bool]:
        metadata = dict(spec.metadata)
        if dedupe_key is not None:
            existing = self._find_active_dedupe(dedupe_key)
            if existing is not None:
                return existing, False
            metadata["dedupe_key"] = dedupe_key
            spec = spec.model_copy(update={"metadata": metadata}, deep=True)
        record = TaskRecord(spec=spec)
        row = task_to_row(record, dedupe_key=dedupe_key, path_codec=self.path_codec)
        event_row = event_to_row(
            Event(task_id=record.id, kind="task.created", message=record.spec.title),
            path_codec=self.path_codec,
        )
        with Session(self.engine) as session, session.begin():
            try:
                session.add(row)
                session.add(event_row)
                session.flush()
            except IntegrityError:
                session.rollback()
                if dedupe_key is None:
                    raise
                existing = self._find_active_dedupe(dedupe_key)
                if existing is None:
                    raise
                return existing, False
        return record, True

    def get(self, task_id: str) -> TaskRecord:
        with Session(self.engine) as session:
            row = session.scalar(_task_query().where(TaskRow.id == task_id))
            if row is None:
                raise KeyError(task_id)
            return row_to_task(row, path_codec=self.path_codec)

    def save(self, record: TaskRecord) -> None:
        record.updated_at = utc_now()
        with Session(self.engine) as session, session.begin():
            row = session.scalar(_task_query().where(TaskRow.id == record.id))
            if row is None:
                raise KeyError(record.id)
            row.validations.clear()
            session.flush()
            update_task_row(row, record, path_codec=self.path_codec)

    def update_status(
        self, task_id: str, status: TaskStatus, summary: str = ""
    ) -> TaskRecord:
        return self.transition_task(
            task_id,
            _transition_for_status(TaskStatus(status), summary),
        )

    def transition_task(
        self, task_id: str, transition: TaskTransition
    ) -> TaskRecord:
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            row = session.scalar(_task_query().where(TaskRow.id == task_id))
            if row is None:
                raise KeyError(task_id)
            current = TaskStatus(row.status)
            require_transition_allowed(current, transition)
            row.status = transition.status.value
            row.summary = transition.summary
            row.updated_at = now
            session.add(
                event_to_row(
                    Event(
                        task_id=task_id,
                        kind="task.status",
                        message=transition.status.value,
                        data={
                            "summary": transition.summary,
                            "phase": transition.phase.value,
                        },
                    ),
                    path_codec=self.path_codec,
                )
            )
        return self.get(task_id)

    def start_worker(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, worker_started(summary))

    def start_validation(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, validation_started(summary))

    def start_review(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, review_started(summary))

    def start_integration(self, task_id: str, summary: str) -> TaskRecord:
        return self.transition_task(task_id, integration_started(summary))

    def finish_task(
        self, task_id: str, status: TaskStatus, summary: str = ""
    ) -> TaskRecord:
        return self.transition_task(task_id, terminal_status(TaskStatus(status), summary))

    def touch_active_task(self, task_id: str) -> bool:
        active_statuses = {status.value for status in ACTIVE_STATUSES}
        with Session(self.engine) as session, session.begin():
            row = session.get(TaskRow, task_id)
            if row is None or row.status not in active_statuses:
                return False
            row.updated_at = utc_now().isoformat()
            return True

    def add_event(
        self,
        task_id: str,
        kind: str,
        message: str,
        data: dict[str, object] | None = None,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            session.add(
                event_to_row(
                    Event(task_id=task_id, kind=kind, message=message, data=data or {}),
                    path_codec=self.path_codec,
                )
            )

    def add_signal_fetch_run(self, run: SignalFetchRun) -> None:
        with Session(self.engine) as session, session.begin():
            session.add(signal_fetch_run_to_row(run))

    def list_signal_fetch_runs(
        self, *, limit: int | None = None
    ) -> list[SignalFetchRun]:
        statement = select(SignalFetchRunRow).order_by(
            SignalFetchRunRow.started_at.desc()
        )
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_signal_fetch_run(row)
                for row in session.scalars(statement).all()
            ]

    def add_signal_item(self, item: SignalItem) -> tuple[SignalItem, bool]:
        now = utc_now()
        item = item.model_copy(
            update={"created_at": item.created_at, "updated_at": now}
        )
        active_item_statuses = {
            SignalItemStatus.pending.value,
            SignalItemStatus.planned.value,
        }
        with Session(self.engine) as session, session.begin():
            existing = session.scalar(
                select(SignalItemRow)
                .where(
                    SignalItemRow.provider == item.provider,
                    SignalItemRow.fingerprint == item.fingerprint,
                    SignalItemRow.status.in_(active_item_statuses),
                )
                .order_by(SignalItemRow.created_at.desc())
                .limit(1)
            )
            if existing is not None:
                existing.updated_at = now.isoformat()
                if item.source_fetch_id:
                    existing.source_fetch_id = item.source_fetch_id
                return row_to_signal_item(existing, path_codec=self.path_codec), False
            session.add(signal_item_to_row(item, path_codec=self.path_codec))
        return item, True

    def add_signal_items(self, items: list[SignalItem]) -> tuple[list[SignalItem], int]:
        saved: list[SignalItem] = []
        created = 0
        for item in items:
            saved_item, was_created = self.add_signal_item(item)
            saved.append(saved_item)
            if was_created:
                created += 1
        return saved, created

    def list_signal_items(
        self,
        *,
        include_errors: bool = False,
        status: SignalItemStatus | str | None = None,
        limit: int | None = None,
    ) -> list[SignalItem]:
        statement = select(SignalItemRow).order_by(SignalItemRow.created_at.desc())
        if not include_errors:
            statement = statement.where(SignalItemRow.kind != "signal-error")
        if status is not None:
            statement = statement.where(SignalItemRow.status == str(status))
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_signal_item(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def pending_signal_items(
        self, *, include_errors: bool = False, limit: int | None = None
    ) -> list[SignalItem]:
        statement = (
            select(SignalItemRow)
            .where(SignalItemRow.status == SignalItemStatus.pending.value)
            .order_by(SignalItemRow.created_at)
        )
        if not include_errors:
            statement = statement.where(SignalItemRow.kind != "signal-error")
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_signal_item(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def mark_signal_items_planned(
        self,
        ids: list[str],
        *,
        planner_run_id: str | None,
        task_id: str | None,
    ) -> int:
        if not ids:
            return 0
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                select(SignalItemRow).where(
                    SignalItemRow.id.in_(ids),
                    SignalItemRow.status == SignalItemStatus.pending.value,
                )
            ).all()
            for row in rows:
                row.status = SignalItemStatus.planned.value
                row.planned_at = now
                row.updated_at = now
                row.planner_run_id = planner_run_id
                row.planned_task_id = task_id
            return len(rows)

    def supersede_signal_items(
        self, ids: list[str], *, planner_run_id: str | None
    ) -> int:
        if not ids:
            return 0
        now = utc_now().isoformat()
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                select(SignalItemRow).where(
                    SignalItemRow.id.in_(ids),
                    SignalItemRow.status == SignalItemStatus.pending.value,
                )
            ).all()
            for row in rows:
                row.status = SignalItemStatus.superseded.value
                row.updated_at = now
                row.planner_run_id = planner_run_id
            return len(rows)

    def begin_iteration(
        self,
        task_id: str,
        iteration: int,
        label: str,
        *,
        worker_name: str,
        worker_prompt_path: Path | None,
        worker_transcript_path: Path,
        worker_last_message_path: Path,
        running_summary: str | None = None,
    ) -> TaskIteration:
        now = utc_now()
        item = TaskIteration(
            task_id=task_id,
            iteration=iteration,
            label=label,
            worker_name=worker_name,
            worker_prompt_path=worker_prompt_path,
            worker_transcript_path=worker_transcript_path,
            worker_last_message_path=worker_last_message_path,
            started_at=now,
            updated_at=now,
        )
        self._upsert_iteration(
            item,
            running_summary=running_summary if iteration > 0 else None,
        )
        return item

    def finish_iteration_worker(
        self, task_id: str, iteration: int, result: WorkerResult
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.worker_prompt_path = result.prompt_path
        item.worker_transcript_path = result.transcript_path
        item.worker_last_message_path = result.last_message_path
        item.worker_exit_code = result.exit_code
        item.worker_completed = result.completed
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def record_iteration_validations(
        self,
        task_id: str,
        iteration: int,
        validations: list[ValidationResult],
    ) -> None:
        with Session(self.engine) as session, session.begin():
            now = utc_now().isoformat()
            existing_count = (
                session.scalar(
                    select(func.count())
                    .select_from(ValidationRow)
                    .where(ValidationRow.task_id == task_id)
                )
                or 0
            )
            rows = [
                validation_to_row(
                    task_id,
                    existing_count + index,
                    validation,
                    iteration=iteration,
                    path_codec=self.path_codec,
                )
                for index, validation in enumerate(validations)
            ]
            session.add_all(rows)
            row = session.scalar(
                select(TaskIterationRow).where(
                    TaskIterationRow.task_id == task_id,
                    TaskIterationRow.iteration == iteration,
                )
            )
            if row is not None:
                row.updated_at = now
            task = session.get(TaskRow, task_id)
            if task is not None:
                task.updated_at = now

    def record_iteration_patch(
        self, task_id: str, iteration: int, patch_path: Path
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.patch_path = patch_path
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def start_iteration_review(
        self,
        task_id: str,
        iteration: int,
        *,
        reviewer_name: str,
        reviewer_prompt_path: Path,
        reviewer_transcript_path: Path,
        reviewer_last_message_path: Path,
        review_run: int,
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.reviewer_name = reviewer_name
        item.reviewer_prompt_path = reviewer_prompt_path
        item.reviewer_transcript_path = reviewer_transcript_path
        item.reviewer_last_message_path = reviewer_last_message_path
        item.reviewer_exit_code = None
        item.reviewer_completed = False
        item.reviewer_run = review_run
        item.review_json = None
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def record_iteration_review(
        self,
        task_id: str,
        iteration: int,
        result: WorkerResult,
        *,
        reviewer_name: str,
        review_run: int,
        review: dict[str, object] | None,
    ) -> None:
        item = self.get_iteration(task_id, iteration)
        item.reviewer_name = reviewer_name
        item.reviewer_prompt_path = result.prompt_path
        item.reviewer_transcript_path = result.transcript_path
        item.reviewer_last_message_path = result.last_message_path
        item.reviewer_exit_code = result.exit_code
        item.reviewer_completed = result.completed
        item.reviewer_run = review_run
        item.review_json = review
        item.updated_at = utc_now()
        self._upsert_iteration(item)

    def get_iteration(self, task_id: str, iteration: int) -> TaskIteration:
        with Session(self.engine) as session:
            row = session.scalar(
                select(TaskIterationRow).where(
                    TaskIterationRow.task_id == task_id,
                    TaskIterationRow.iteration == iteration,
                )
            )
            if row is None:
                raise KeyError(f"{task_id}:{iteration}")
            return row_to_iteration(row, path_codec=self.path_codec)

    def iterations(self, task_id: str) -> list[TaskIteration]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(TaskIterationRow)
                .where(TaskIterationRow.task_id == task_id)
                .order_by(TaskIterationRow.iteration)
            ).all()
            return [row_to_iteration(row, path_codec=self.path_codec) for row in rows]

    def list_tasks(self, *, limit: int | None = None) -> list[TaskRecord]:
        statement = _task_query().order_by(TaskRow.created_at.desc())
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_task(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def queued_tasks(self, *, limit: int | None = None) -> list[TaskRecord]:
        tasks = self._tasks_by_status(TaskStatus.queued)
        tasks.sort(
            key=lambda task: (
                0 if task.spec.worker == "integration-manager" else 1,
                PRIORITY_ORDER.get(str(task.spec.priority), 99),
                task.created_at,
            )
        )
        return tasks if limit is None else tasks[:limit]

    def active_count(self) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(TaskRow)
                    .where(TaskRow.status.in_(ACTIVE_STATUSES))
                )
                or 0
            )

    def events(self, task_id: str, *, limit: int | None = None) -> list[Event]:
        statement = (
            select(EventRow)
            .where(EventRow.task_id == task_id)
            .order_by(EventRow.created_at)
        )
        if limit is not None:
            statement = statement.limit(limit)
        with Session(self.engine) as session:
            return [
                row_to_event(row, path_codec=self.path_codec)
                for row in session.scalars(statement).all()
            ]

    def count_events(self, kind: str) -> int:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(func.count())
                    .select_from(EventRow)
                    .where(EventRow.kind == kind)
                )
                or 0
            )

    def recover_stale_active_tasks(
        self,
        *,
        stale_after_minutes: int,
        status_stale_after_minutes: dict[str, int] | None = None,
    ) -> list[str]:
        recovered: list[str] = []
        active_statuses = [
            status.value for status in ACTIVE_STATUSES if status != TaskStatus.queued
        ]
        status_stale_after_minutes = status_stale_after_minutes or {}
        with Session(self.engine) as session, session.begin():
            rows = session.scalars(
                _task_query().where(TaskRow.status.in_(active_statuses))
            ).all()
            for row in rows:
                events = session.scalars(
                    select(EventRow)
                    .where(EventRow.task_id == row.id)
                    .order_by(EventRow.id)
                ).all()
                effective_status = _effective_stale_status(row, events)
                stale_after = status_stale_after_minutes.get(
                    effective_status, stale_after_minutes
                )
                cutoff = utc_now() - timedelta(minutes=stale_after)
                if datetime.fromisoformat(row.updated_at) >= cutoff:
                    continue
                previous_status = row.status
                summary = f"stale active task recovered after {stale_after} minutes"
                transition = recovery_failed(summary)
                require_transition_allowed(TaskStatus(row.status), transition)
                row.status = transition.status.value
                row.summary = transition.summary
                row.updated_at = utc_now().isoformat()
                session.add(
                    event_to_row(
                        Event(
                            task_id=row.id,
                            kind="task.recovered_stale",
                            message=transition.summary,
                            data={
                                "previous_status": previous_status,
                                "effective_status": effective_status,
                                "phase": transition.phase.value,
                                "stale_after_minutes": stale_after,
                            },
                        ),
                        path_codec=self.path_codec,
                    )
                )
                recovered.append(row.id)
        return recovered

    def audit(self) -> list[str]:
        findings: list[str] = []
        seen: set[str] = set()
        for task in self.list_tasks():
            if task.id in seen:
                findings.append(f"duplicate task id: {task.id}")
            seen.add(task.id)
            if (
                TaskStatus(task.status) == TaskStatus.succeeded
                and task.patch_path is None
            ):
                findings.append(f"{task.id}: succeeded without a saved patch")
            if TaskStatus(task.status) == TaskStatus.pushed and task.patch_path is None:
                findings.append(f"{task.id}: pushed without a saved patch")
        return findings

    def _tasks_by_status(self, status: TaskStatus) -> list[TaskRecord]:
        with Session(self.engine) as session:
            rows = session.scalars(
                _task_query().where(TaskRow.status == status.value)
            ).all()
            return [row_to_task(row, path_codec=self.path_codec) for row in rows]

    def _find_active_dedupe(self, dedupe_key: str) -> TaskRecord | None:
        with Session(self.engine) as session:
            row = session.scalar(
                _task_query()
                .where(
                    TaskRow.dedupe_key == dedupe_key,
                    TaskRow.status.in_(ACTIVE_STATUSES),
                )
                .limit(1)
            )
            return row_to_task(row, path_codec=self.path_codec) if row is not None else None

    def _migrate_legacy_json(self) -> None:
        legacy = self.path.with_suffix(".json")
        if not legacy.exists() or self.list_tasks():
            return
        raw = json.loads(legacy.read_text(encoding="utf-8"))
        tasks = [TaskRecord.model_validate(item) for item in raw.get("tasks", [])]
        events = [Event.model_validate(item) for item in raw.get("events", [])]
        with Session(self.engine) as session, session.begin():
            session.add_all(
                task_to_row(task, path_codec=self.path_codec) for task in tasks
            )
            session.add_all(
                event_to_row(item, path_codec=self.path_codec) for item in events
            )

    def _upsert_iteration(
        self, item: TaskIteration, *, running_summary: str | None = None
    ) -> None:
        with Session(self.engine) as session, session.begin():
            row = session.scalar(
                select(TaskIterationRow).where(
                    TaskIterationRow.task_id == item.task_id,
                    TaskIterationRow.iteration == item.iteration,
                )
            )
            if row is None:
                session.add(iteration_to_row(item, path_codec=self.path_codec))
            else:
                update_iteration_row(row, item, path_codec=self.path_codec)
            task = session.get(TaskRow, item.task_id)
            if task is not None:
                if (
                    running_summary is not None
                    and task.status == TaskStatus.reviewing.value
                ):
                    transition = worker_started(running_summary)
                    require_transition_allowed(TaskStatus(task.status), transition)
                    task.status = transition.status.value
                    task.summary = transition.summary
                    session.add(
                        event_to_row(
                            Event(
                                task_id=item.task_id,
                                kind="task.status",
                                message=transition.status.value,
                                data={
                                    "summary": transition.summary,
                                    "phase": transition.phase.value,
                                    "source": "begin_iteration",
                                },
                            ),
                            path_codec=self.path_codec,
                        )
                    )
                task.updated_at = item.updated_at.isoformat()

    def _migrate_schema(self) -> None:
        with self.engine.begin() as connection:
            item_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(signal_items)")
            }
            if item_columns and (
                "evidence_id" in item_columns
                or "location_json" not in item_columns
                or "links_json" not in item_columns
            ):
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_items")
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_messages")
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_fetch_runs")
                Base.metadata.create_all(connection)
            fetch_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(signal_fetch_runs)")
            }
            if fetch_columns and (
                "message_count" in fetch_columns
                or "item_count" not in fetch_columns
                or "has_more" not in fetch_columns
            ):
                connection.exec_driver_sql("DROP TABLE IF EXISTS signal_fetch_runs")
                Base.metadata.create_all(connection)
            connection.exec_driver_sql("DROP TABLE IF EXISTS signal_messages")
            validation_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(validations)")
            }
            if "iteration" not in validation_columns:
                connection.exec_driver_sql(
                    "ALTER TABLE validations ADD COLUMN iteration INTEGER"
                )

    def _migrate_portable_paths(self) -> None:
        task_columns = (
            "worktree_path",
            "transcript_path",
            "last_message_path",
            "patch_path",
        )
        iteration_columns = (
            "worker_prompt_path",
            "worker_transcript_path",
            "worker_last_message_path",
            "reviewer_prompt_path",
            "reviewer_transcript_path",
            "reviewer_last_message_path",
            "patch_path",
        )
        with Session(self.engine) as session, session.begin():
            for row in session.scalars(select(TaskRow)).all():
                for column in task_columns:
                    setattr(row, column, self._portable_path(getattr(row, column)))
                row.metadata_json = self._portable_json(row.metadata_json)
            for row in session.scalars(select(TaskIterationRow)).all():
                for column in iteration_columns:
                    setattr(row, column, self._portable_path(getattr(row, column)))
            for row in session.scalars(select(ValidationRow)).all():
                row.output_path = self._portable_path(row.output_path) or row.output_path
                row.cwd = self._portable_path(row.cwd) or row.cwd
            for row in session.scalars(select(EventRow)).all():
                row.message = self._portable_path(row.message) or row.message
                row.data_json = self._portable_json(row.data_json)
            for row in session.scalars(select(SignalItemRow)).all():
                row.payload_json = self._portable_json(row.payload_json)
                if row.location_json:
                    row.location_json = self._portable_json(row.location_json)

    def _portable_path(self, value: str | None) -> str | None:
        if self.path_codec.is_portable(value):
            return value
        return self.path_codec.dump(Path(value))

    def _portable_json(self, value: str) -> str:
        try:
            loaded = json.loads(value or "{}")
        except json.JSONDecodeError:
            return value
        if not isinstance(loaded, dict):
            return value
        return json.dumps(self.path_codec.dump_json(loaded), sort_keys=True)


def _task_query() -> Select[tuple[TaskRow]]:
    return select(TaskRow).options(selectinload(TaskRow.validations))


def _transition_for_status(status: TaskStatus, summary: str) -> TaskTransition:
    if status == TaskStatus.running:
        return worker_started(summary)
    if status == TaskStatus.reviewing:
        return review_started(summary)
    if status == TaskStatus.integrating:
        return integration_started(summary)
    if status.terminal:
        return terminal_status(status, summary)
    return TaskTransition(status, summary, TaskPhase.dispatch)


def _effective_stale_status(row: TaskRow, events: list[EventRow]) -> str:
    latest_worker_start = _latest_event_id(events, WORKER_REVISION_STARTED_EVENTS)
    latest_worker_finish = _latest_event_id(events, WORKER_REVISION_FINISHED_EVENTS)
    if latest_worker_start is not None and (
        latest_worker_finish is None or latest_worker_start > latest_worker_finish
    ):
        return TaskStatus.running.value

    latest_review_start = _latest_review_start_id(events)
    latest_review_finish = _latest_event_id(
        events, REVIEW_FINISHED_EVENTS | WORKER_REVISION_STARTED_EVENTS
    )
    if latest_review_start is not None and (
        latest_review_finish is None or latest_review_start > latest_review_finish
    ):
        return TaskStatus.reviewing.value

    return row.status


def _latest_event_id(events: list[EventRow], kinds: set[str]) -> int | None:
    matching = [event.id for event in events if event.kind in kinds]
    return max(matching) if matching else None


def _latest_review_start_id(events: list[EventRow]) -> int | None:
    matching = [
        event.id
        for event in events
        if event.kind == "task.status" and event.message == TaskStatus.reviewing.value
    ]
    return max(matching) if matching else None


def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

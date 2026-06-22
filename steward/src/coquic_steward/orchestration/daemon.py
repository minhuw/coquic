from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ..core.config import StewardConfig
from ..core.models import (
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    SignalMessage,
    TaskRecord,
    TaskStatus,
)
from ..execution.executor import StewardExecutor
from ..planning import run_planner
from ..signals import collect_signal_messages, project_signals_from_items
from ..storage import TaskStore

DAEMON_EVENT_TASK_ID = "daemon"


@dataclass
class TickResult:
    recovered: int = 0
    signal_fetches: int = 0
    signal_messages: int = 0
    new_signal_messages: int = 0
    signal_items: int = 0
    new_signal_items: int = 0
    planned: int = 0
    enqueued: int = 0
    dispatched: int = 0
    skipped: int = 0


class StewardDaemon:
    def __init__(
        self,
        config: StewardConfig,
        store: TaskStore,
        *,
        logger: Callable[[str], None] | None = None,
    ):
        self.config = config
        self.store = store
        self.logger = logger
        self.executor = StewardExecutor(config, store)

    def tick(
        self,
        *,
        plan: bool = True,
        dispatch: bool = True,
        max_dispatch: int | None = None,
    ) -> TickResult:
        result = TickResult()
        self._log(
            "tick start "
            f"plan={str(plan).lower()} "
            f"dispatch={str(dispatch).lower()} "
            f"max_dispatch={max_dispatch or '-'}"
        )
        for task_id in self.store.recover_stale_active_tasks(
            stale_after_minutes=stale_task_minutes(self.config),
            status_stale_after_minutes=status_stale_minutes(self.config),
        ):
            result.recovered += 1
            self.store.add_event(
                task_id, "daemon.recovered_stale", "released stale active task"
            )
            self._log(f"recovered stale task {task_id}")
        if plan:
            self._poll_and_plan(result)
        if dispatch:
            limit = max_dispatch or self.config.limits.max_active_tasks
            for task in self.store.queued_tasks(limit=limit):
                self._log(f"dispatch start {task.id} {_task_label(task)}")
                if self.executor.run_task(task.id):
                    result.dispatched += 1
                    finished = self.store.get(task.id)
                    self._log(
                        f"dispatch finish {task.id} status={finished.status} ok=true"
                    )
                    if plan:
                        self._plan_until_idle(result)
                else:
                    result.skipped += 1
                    finished = self.store.get(task.id)
                    self._log(
                        f"dispatch finish {task.id} status={finished.status} ok=false"
                    )
        self._log(
            "tick finish "
            f"recovered={result.recovered} "
            f"signal_fetches={result.signal_fetches} "
            f"signal_messages={result.signal_messages} "
            f"new_signal_messages={result.new_signal_messages} "
            f"signal_items={result.signal_items} "
            f"new_signal_items={result.new_signal_items} "
            f"planned={result.planned} "
            f"enqueued={result.enqueued} "
            f"dispatched={result.dispatched} "
            f"skipped={result.skipped}"
        )
        return result

    def _poll_and_plan(self, result: TickResult) -> None:
        if self.store.active_count() >= self.config.limits.max_active_tasks:
            self._log("signals skipped active task limit reached")
            self._log("planner skipped active task limit reached")
            return
        self._fetch_signals(result)
        self._plan_until_idle(result)

    def _fetch_signals(self, result: TickResult) -> None:
        for collection in collect_signal_messages(self.config):
            if self.store.active_count() >= self.config.limits.max_active_tasks:
                self._log("signals poll stopped active task limit reached")
                return
            result.signal_fetches += 1
            fetch_run = SignalFetchRun(
                provider=collection.provider,
                status=(
                    SignalFetchStatus.error
                    if collection.error
                    else SignalFetchStatus.ok
                ),
                started_at=collection.started_at,
                completed_at=collection.completed_at,
                message_count=len(collection.messages),
                new_message_count=0,
                error=collection.error,
                summary=collection.signals.summary,
            )
            messages = [
                message.model_copy(
                    update={"source_fetch_id": fetch_run.id},
                    deep=True,
                )
                for message in collection.messages
            ]
            saved, created = self.store.add_signal_messages(messages)
            items = _items_for_saved_messages(collection.items, saved)
            saved_items, created_items = self.store.add_signal_items(items)
            fetch_run = fetch_run.model_copy(update={"new_message_count": created})
            self.store.add_signal_fetch_run(fetch_run)
            result.signal_messages += len(saved)
            result.new_signal_messages += created
            result.signal_items += len(saved_items)
            result.new_signal_items += created_items
            self.store.add_event(
                DAEMON_EVENT_TASK_ID,
                "signals.fetched",
                (
                    f"{collection.provider}: {created_items} new of "
                    f"{len(saved_items)} item(s)"
                ),
                {
                    "fetch_run_id": fetch_run.id,
                    "provider": collection.provider,
                    "message_count": len(saved),
                    "new_message_count": created,
                    "item_count": len(saved_items),
                    "new_item_count": created_items,
                    "error": collection.error,
                },
            )
            self._log(
                "signals fetched "
                f"provider={collection.provider} "
                f"new={created_items} total={len(saved_items)} "
                f"messages={len(saved)} "
                f"error={collection.error or '-'}"
            )

    def _plan_until_idle(self, result: TickResult) -> None:
        turns = 0
        while turns < self.config.limits.max_active_tasks:
            if self.store.active_count() >= self.config.limits.max_active_tasks:
                self._log("planner skipped active task limit reached")
                return
            pending = self.store.pending_signal_items(
                limit=self.config.limits.max_active_tasks
            )
            if not pending:
                return
            turns += 1
            before_pending = {item.id for item in pending}
            self._plan(result, pending)
            after_pending = {
                item.id
                for item in self.store.pending_signal_items(
                    limit=self.config.limits.max_active_tasks
                )
            }
            if after_pending == before_pending:
                return

    def _plan(self, result: TickResult, inbox_items: list[SignalItem]) -> None:
        active_tasks = self.store.list_tasks(limit=200)
        signals = project_signals_from_items(self.config, inbox_items)
        self._log(
            "planner start "
            f"active_tasks={len(active_tasks)} "
            f"inbox={len(inbox_items)} "
            f"code_quality={str(signals.has_code_quality_findings).lower()} "
            f"workflow={signals.failed_workflow_run_id or '-'} "
            f"interop={signals.failed_interop_run_id or '-'}"
        )
        self.store.add_event(
            DAEMON_EVENT_TASK_ID,
            "planner.started",
            "planner turn started",
            {
                "active_task_count": len(active_tasks),
                "inbox_item_ids": [item.id for item in inbox_items],
                "enabled_signals": list(self.config.enabled_signals),
                "has_code_quality_findings": signals.has_code_quality_findings,
                "failed_workflow_run_id": signals.failed_workflow_run_id,
                "failed_interop_run_id": signals.failed_interop_run_id,
            },
        )
        planner_run = run_planner(self.config, signals, active_tasks)
        planned_item_count = 0
        planned_item_ids: set[str] = set()
        run_id = planner_run.run_id or planner_run.thread_id
        for spec, dedupe_key in planner_run.planned:
            result.planned += 1
            record, created = self.store.add_task(spec, dedupe_key=dedupe_key)
            if created:
                result.enqueued += 1
                selected_ids = _selected_item_ids(spec, planner_run.consumed_item_ids)
                planned_item_count += self.store.mark_signal_items_planned(
                    selected_ids,
                    planner_run_id=run_id,
                    task_id=record.id,
                )
                planned_item_ids.update(selected_ids)
                self._log(f"enqueued {record.id} {_task_label(record)}")
            else:
                result.skipped += 1
                self._log(
                    f"skipped duplicate plan {record.id} dedupe={dedupe_key}"
                )
        superseded_count = self.store.supersede_signal_items(
            [
                item_id
                for item_id in planner_run.consumed_item_ids
                if item_id not in planned_item_ids
            ],
            planner_run_id=run_id,
        )
        consumed_count = planned_item_count + superseded_count
        self._log(
            "planner finish "
            f"completed={str(planner_run.completed).lower()} "
            f"exit={planner_run.exit_code} "
            f"verifier={planner_run.accepted_count}/{planner_run.proposed_count} "
            f"consumed={consumed_count}/{len(planner_run.consumed_item_ids)} "
            f"thread={planner_run.thread_id or '-'} "
            f"transcript={planner_run.transcript_path}"
        )
        self.store.add_event(
            DAEMON_EVENT_TASK_ID,
            "planner.finished",
            (
                f"accepted {planner_run.accepted_count} of "
                f"{planner_run.proposed_count} proposed task(s)"
            ),
            {
                "accepted_count": planner_run.accepted_count,
                "proposed_count": planner_run.proposed_count,
                "completed": planner_run.completed,
                "exit_code": planner_run.exit_code,
                "consumed_item_ids": planner_run.consumed_item_ids,
                "consumed_item_count": consumed_count,
                "planned_item_count": planned_item_count,
                "superseded_item_count": superseded_count,
                "run_id": planner_run.run_id,
                "prompt_path": (
                    str(planner_run.prompt_path) if planner_run.prompt_path else None
                ),
                "transcript_path": str(planner_run.transcript_path),
                "thread_id": planner_run.thread_id,
                "diagnostics": planner_run.diagnostics,
            },
        )

    def run_forever(self) -> None:
        while True:
            self.tick()
            time.sleep(self.config.daemon_poll_interval_sec)

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(f"[steward] {message}")


def stale_task_minutes(config: StewardConfig) -> int:
    if config.limits.stale_task_minutes is not None:
        return config.limits.stale_task_minutes
    poll_minutes = max(1, config.daemon_poll_interval_sec // 60)
    return config.limits.worker_timeout_minutes + poll_minutes


def status_stale_minutes(config: StewardConfig) -> dict[str, int]:
    if config.limits.stale_task_minutes is not None:
        return {}
    poll_minutes = max(1, config.daemon_poll_interval_sec // 60)
    return {
        TaskStatus.reviewing.value: config.limits.review_timeout_minutes + poll_minutes
    }


def _task_label(task: TaskRecord) -> str:
    return f"kind={task.spec.kind} title={task.spec.title!r}"


def _items_for_saved_messages(
    items: list[SignalItem], messages: list[SignalMessage]
) -> list[SignalItem]:
    if not items:
        return []
    messages_by_evidence = {
        message.evidence_id: message for message in messages if message.evidence_id
    }
    messages_by_provider = {message.provider: message for message in messages}
    result: list[SignalItem] = []
    for item in items:
        source = None
        if item.evidence_id:
            source = messages_by_evidence.get(item.evidence_id)
        if source is None:
            source = messages_by_provider.get(item.provider)
        updates = {}
        if source is not None:
            updates["source_message_id"] = source.id
            updates["source_fetch_id"] = source.source_fetch_id
        result.append(item.model_copy(update=updates))
    return result


def _selected_item_ids(spec, consumed_item_ids: list[str]) -> list[str]:
    metadata = spec.metadata or {}
    selected = metadata.get("selected_work_item_ids")
    candidates = selected if isinstance(selected, list) else consumed_item_ids
    ids: list[str] = []
    seen: set[str] = set()
    allowed = set(consumed_item_ids)
    for value in candidates:
        if not isinstance(value, str) or value in seen:
            continue
        if allowed and value not in allowed:
            continue
        ids.append(value)
        seen.add(value)
    return ids

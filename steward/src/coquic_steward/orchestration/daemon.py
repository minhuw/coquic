from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..core.config import StewardConfig
from ..core.lifecycle import TaskPhase
from ..core.models import (
    DaemonCycleResult,
    DaemonCycleSummary,
    DaemonRuntime,
    DaemonRuntimeState,
    PublicMirrorFailureCategory,
    PublicMirrorHealth,
    PublicMirrorPublishState,
    SignalFetchStatus,
    SignalItem,
    TaskRecord,
    TaskStatus,
    utc_now,
    WorkerKind,
)
from ..execution.executor import StewardExecutor
from ..planning import run_planner
from ..public_mirror import (
    classify_publish_failure,
    public_mirror_digest,
    publish_public_mirror,
    write_public_mirror,
)
from ..storage import (
    TaskStore,
    idle_fetch_provider_names,
    scheduler_state,
    store_is_idle_for_signal_fetch,
)
from ..signals import (
    collect_signal_items,
    project_signals_from_items,
    revalidate_signal_items,
)
from .preflight import preflight_remote_push

DAEMON_EVENT_TASK_ID = "daemon"
DAEMON_HEARTBEAT_INTERVAL_SECONDS = 30
PUBLIC_MIRROR_DEBOUNCE_SECONDS = 1.0
PUBLIC_MIRROR_RETRY_SECONDS = 30.0


@dataclass
class TickResult:
    recovered: int = 0
    signal_fetches: int = 0
    signal_items: int = 0
    new_signal_items: int = 0
    planned: int = 0
    enqueued: int = 0
    dispatched: int = 0
    skipped: int = 0


@dataclass(frozen=True)
class SchedulerTrigger:
    reason: str
    providers: list[str]


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
        if preflight_remote_push(config):
            self._log(
                "remote push preflight ok "
                f"remote={config.git_remote} branch={config.main_branch}"
            )
        self.executor = StewardExecutor(config, store)
        self.runtime = DaemonRuntime(
            heartbeat_interval_seconds=DAEMON_HEARTBEAT_INTERVAL_SECONDS
        )
        self._runtime_lock = threading.Lock()
        self._public_mirror_local_digest: str | None = None
        self._public_mirror_remote_digest: str | None = None
        self._public_mirror_health = PublicMirrorHealth(
            state=(
                PublicMirrorPublishState.pending
                if config.public_mirror.enabled and config.public_mirror.publish
                else PublicMirrorPublishState.disabled
            )
        )
        self._public_mirror_update_lock = threading.Lock()
        self._public_mirror_thread_lock = threading.Lock()
        self._public_mirror_dirty = threading.Event()
        self._public_mirror_stop = threading.Event()
        self._public_mirror_thread: threading.Thread | None = None
        self._public_mirror_stopping = False
        if config.public_mirror.enabled and hasattr(store, "on_change"):
            store.on_change = self._public_mirror_store_changed

    def tick(
        self,
        *,
        plan: bool = True,
        dispatch: bool = True,
        max_dispatch: int | None = None,
    ) -> TickResult:
        return self.run_cycle(
            plan=plan,
            dispatch=dispatch,
            max_dispatch=max_dispatch,
            reason="manual-tick",
        )

    def run_cycle(
        self,
        *,
        plan: bool = True,
        dispatch: bool = True,
        fetch_providers: list[str] | None = None,
        max_dispatch: int | None = None,
        reason: str = "scheduled",
    ) -> TickResult:
        result = TickResult()
        self._begin_cycle(reason)
        self._publish_public_mirror_if_changed()
        try:
            wakeups = self.store.pending_wakeups(limit=200)
            if wakeups:
                self.store.consume_wakeups([wakeup.id for wakeup in wakeups])
            explicit_fetch_providers = _fetch_providers_from_wakeups(
                self.config, wakeups
            )
            if explicit_fetch_providers:
                fetch_providers = explicit_fetch_providers
            self._log(
                "cycle start "
                f"reason={reason} "
                f"wakeups={len(wakeups)} "
                f"plan={str(plan).lower()} "
                f"dispatch={str(dispatch).lower()} "
                f"max_dispatch={max_dispatch or '-'}"
            )
            for task_id in self.store.recover_stale_active_tasks(
                stale_after_minutes=stale_task_minutes(self.config),
                status_stale_after_minutes=status_stale_minutes(self.config),
            ):
                result.recovered += 1
                self.executor.clean_finished_task_worktree(self.store.get(task_id))
                self.store.add_event(
                    task_id, "daemon.recovered_stale", "released stale active task"
                )
                self._log(f"recovered stale task {task_id}")
            if plan:
                requeued = self.store.requeue_failed_signal_items()
                if requeued:
                    self.store.add_event(
                        DAEMON_EVENT_TASK_ID,
                        "signals.requeued_failed",
                        f"requeued {requeued} failed signal item(s)",
                        {"count": requeued, "retry_after_hours": 24},
                    )
                    self._log(f"requeued failed signals count={requeued}")
                if fetch_providers:
                    self._fetch_signals(result, fetch_providers)
                else:
                    idle_providers = self._idle_fetch_provider_names()
                    if idle_providers:
                        self._log(
                            "signals idle fetch providers="
                            + ",".join(idle_providers)
                        )
                        self._fetch_signals(result, idle_providers)
                self._plan_until_idle(result)
            if dispatch:
                self._dispatch_queued(result, plan=plan, max_dispatch=max_dispatch)
            self._log(
                "cycle finish "
                f"recovered={result.recovered} "
                f"signal_fetches={result.signal_fetches} "
                f"signal_items={result.signal_items} "
                f"new_signal_items={result.new_signal_items} "
                f"planned={result.planned} "
                f"enqueued={result.enqueued} "
                f"dispatched={result.dispatched} "
                f"skipped={result.skipped}"
            )
        finally:
            self._complete_cycle(result, reason)
            self._publish_public_mirror_if_changed()
        return result

    def _dispatch_queued(
        self,
        result: TickResult,
        *,
        plan: bool,
        max_dispatch: int | None,
    ) -> None:
        source_limit = max_dispatch or self.config.limits.max_active_tasks
        total_limit = max_dispatch
        source_attempts = 0
        integration_attempted = False
        seen: set[str] = set()
        while True:
            if total_limit is not None and result.dispatched + result.skipped >= total_limit:
                return
            task = self._next_dispatchable_task(seen)
            if task is None:
                return
            is_integration = _is_integration_manager_task(task)
            if is_integration:
                if integration_attempted or self.store.integration_active_count() > 0:
                    seen.add(task.id)
                    continue
                integration_attempted = True
            else:
                if source_attempts >= source_limit:
                    seen.add(task.id)
                    continue
                if self.store.source_active_count() >= self.config.limits.max_active_tasks:
                    seen.add(task.id)
                    continue
                source_attempts += 1
            seen.add(task.id)
            self._log(f"dispatch start {task.id} {_task_label(task)}")
            try:
                task_ok = self.executor.run_task(task.id)
            except Exception as exc:  # pragma: no cover - daemon boundary guard.
                result.skipped += 1
                message = str(exc)[-2000:] or exc.__class__.__name__
                finished = self._fail_dispatch_exception(task.id, message)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=false "
                    f"error={exc.__class__.__name__}"
                )
                self._publish_public_mirror_if_changed()
                continue
            if task_ok:
                result.dispatched += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=true"
                )
                if plan:
                    self._plan_until_idle(result)
                self._publish_public_mirror_if_changed()
            else:
                result.skipped += 1
                finished = self.store.get(task.id)
                self._log(
                    f"dispatch finish {task.id} status={finished.status} ok=false"
                )
                self._publish_public_mirror_if_changed()

    def _fail_dispatch_exception(self, task_id: str, message: str) -> TaskRecord:
        summary = f"dispatch failed: {message}"
        current = self.store.get(task_id)
        current_status = TaskStatus(current.status)
        if current_status.terminal:
            task = current
        elif current_status == TaskStatus.queued:
            task = self.store.update_status(task_id, TaskStatus.failed, summary)
        else:
            task = self.store.finish_task(task_id, TaskStatus.failed, summary)
        self.store.add_event(
            task_id,
            "dispatch.failed",
            message,
            {"summary": summary},
        )
        if self.executor.clean_finished_task_worktree(task):
            task = self.store.get(task_id)
        return task

    def _next_dispatchable_task(self, seen: set[str]) -> TaskRecord | None:
        for task in self.store.queued_tasks():
            if task.id in seen:
                continue
            return task
        return None

    def _should_fetch_signals_when_idle(self) -> bool:
        return store_is_idle_for_signal_fetch(self.store)

    def _idle_fetch_provider_names(self) -> list[str]:
        if not self._should_fetch_signals_when_idle():
            return []
        return idle_fetch_provider_names(
            scheduler_state(self.config, self.store)
        )

    def _fetch_signals(self, result: TickResult, providers: list[str]) -> None:
        try:
            collections = collect_signal_items(self.config, provider_names=providers)
        except TypeError as exc:
            if "provider_names" not in str(exc):
                raise
            collections = collect_signal_items(self.config)
        for collection in collections:
            result.signal_fetches += 1
            fetch_run = collection.fetch.model_copy(
                update={
                    "status": (
                        SignalFetchStatus.error
                        if collection.error
                        else SignalFetchStatus.ok
                    ),
                    "item_count": len(collection.items),
                    "new_item_count": 0,
                }
            )
            provider_config = self.config.signal_providers.get(collection.provider)
            saved_items, created_items = self.store.add_signal_items(
                collection.items,
                suppression_hours=(
                    provider_config.suppression_hours if provider_config else 24
                ),
            )
            fetch_run = fetch_run.model_copy(update={"new_item_count": created_items})
            self.store.add_signal_fetch_run(fetch_run)
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
                    "item_count": len(saved_items),
                    "new_item_count": created_items,
                    "has_more": fetch_run.has_more,
                    "error": collection.error,
                },
            )
            self._log(
                "signals fetched "
                f"provider={collection.provider} "
                f"new={created_items} total={len(saved_items)} "
                f"has_more={str(fetch_run.has_more).lower()} "
                f"error={collection.error or '-'}"
            )

    def _plan_until_idle(self, result: TickResult) -> None:
        turns = 0
        while turns < self.config.limits.max_active_tasks:
            if self.store.source_active_count() >= self.config.limits.max_active_tasks:
                self._log("planner skipped active task limit reached")
                return
            available = self.config.limits.max_active_tasks - self.store.source_active_count()
            pending = self.store.pending_signal_items(
                limit=max(1, available)
            )
            if not pending:
                return
            turns += 1
            before_pending = {item.id for item in pending}
            actionable, stale_reasons = revalidate_signal_items(self.config, pending)
            if stale_reasons:
                superseded = self.store.supersede_signal_items(
                    list(stale_reasons), planner_run_id="source-revalidation"
                )
                if superseded:
                    self.store.add_event(
                        DAEMON_EVENT_TASK_ID,
                        "signals.superseded_stale",
                        f"superseded {superseded} stale signal item(s)",
                        {"count": superseded, "reasons": stale_reasons},
                    )
                    self._log(f"superseded stale signals count={superseded}")
            if actionable:
                self._plan(result, actionable)
            after_pending = {
                item.id
                for item in self.store.pending_signal_items(
                    limit=self.config.limits.max_active_tasks
                )
            }
            if after_pending == before_pending:
                return

    def _plan(self, result: TickResult, inbox_items: list[SignalItem]) -> None:
        task_context = self.store.list_tasks(limit=200)
        signals = project_signals_from_items(self.config, inbox_items)
        active_count = self.store.source_active_count()
        self._log(
            "planner start "
            f"source_active={active_count} "
            f"task_context={len(task_context)} "
            f"inbox={len(inbox_items)}"
        )
        self.store.add_event(
            DAEMON_EVENT_TASK_ID,
            "planner.started",
            "planner turn started",
            {
                "active_task_count": active_count,
                "task_context_count": len(task_context),
                "inbox_item_ids": [item.id for item in inbox_items],
                "enabled_signals": list(self.config.enabled_signals),
            },
        )
        planner_run = run_planner(self.config, signals, task_context)
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
        self._start_public_mirror_sync()
        try:
            while True:
                trigger = wait_for_scheduler_event(self.config, self.store)
                self.run_cycle(
                    fetch_providers=trigger.providers,
                    max_dispatch=1,
                    reason=trigger.reason,
                )
        finally:
            self._stop_public_mirror_sync()

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(f"[steward] {message}")

    def _begin_cycle(self, reason: str) -> None:
        started_at = utc_now()
        with self._runtime_lock:
            self.runtime.heartbeat_at = started_at
            self.runtime.state = DaemonRuntimeState.active
            self.runtime.current_cycle_started_at = started_at
            self.runtime.current_cycle_reason = _bounded_cycle_reason(reason)

    def _complete_cycle(self, result: TickResult, reason: str) -> None:
        completed_at = utc_now()
        summary = DaemonCycleSummary(
            completed_at=completed_at,
            reason=_bounded_cycle_reason(reason),
            result=DaemonCycleResult.model_validate(vars(result)),
        )
        with self._runtime_lock:
            self.runtime.heartbeat_at = completed_at
            self.runtime.state = DaemonRuntimeState.idle
            self.runtime.current_cycle_started_at = None
            self.runtime.current_cycle_reason = None
            self.runtime.last_completed_cycle = summary

    def _touch_heartbeat(self) -> None:
        with self._runtime_lock:
            self.runtime.heartbeat_at = utc_now()

    def _runtime_snapshot(self) -> DaemonRuntime:
        with self._runtime_lock:
            return self.runtime.model_copy(deep=True)

    def _heartbeat_interval_seconds(self) -> int:
        with self._runtime_lock:
            return self.runtime.heartbeat_interval_seconds

    def _start_public_mirror_sync(self) -> None:
        if not self.config.public_mirror.enabled:
            return
        with self._public_mirror_thread_lock:
            if self._public_mirror_thread is not None or self._public_mirror_stopping:
                return
            self._public_mirror_stop.clear()
            self._public_mirror_dirty.set()
            thread = threading.Thread(
                target=self._run_public_mirror_sync,
                name="steward-public-mirror",
                daemon=True,
            )
            self._public_mirror_thread = thread
            thread.start()

    def _stop_public_mirror_sync(self) -> None:
        with self._runtime_lock:
            self.runtime.heartbeat_at = utc_now()
            self.runtime.state = DaemonRuntimeState.stopping
            self.runtime.current_cycle_started_at = None
            self.runtime.current_cycle_reason = None
        with self._public_mirror_thread_lock:
            thread = self._public_mirror_thread
            if thread is None:
                return
            self._public_mirror_stopping = True
            self._public_mirror_stop.set()
            self._public_mirror_dirty.set()
        thread.join()
        try:
            needs_final_publish = (
                self._public_mirror_remote_digest
                != self._public_mirror_local_digest
                or self._public_mirror_health.state
                in {
                    PublicMirrorPublishState.pending,
                    PublicMirrorPublishState.failed,
                }
            )
            if needs_final_publish:
                self._update_public_mirror_if_changed(publish=True)
        finally:
            with self._public_mirror_thread_lock:
                if self._public_mirror_thread is thread:
                    self._public_mirror_thread = None
                self._public_mirror_stopping = False

    def _run_public_mirror_sync(self) -> None:
        while True:
            dirty = self._public_mirror_dirty.wait(
                timeout=self._heartbeat_interval_seconds()
            )
            if not dirty:
                self._touch_heartbeat()
            stopping = self._public_mirror_stop.is_set()
            if not stopping and dirty and self._public_mirror_stop.wait(
                PUBLIC_MIRROR_DEBOUNCE_SECONDS
            ):
                stopping = True
            self._public_mirror_dirty.clear()
            synced = self._update_public_mirror_if_changed(publish=True)
            if stopping or self._public_mirror_stop.is_set():
                with self._public_mirror_thread_lock:
                    if self._public_mirror_dirty.is_set():
                        continue
                    if self._public_mirror_thread is threading.current_thread():
                        self._public_mirror_thread = None
                    return
            if synced:
                continue
            if self._public_mirror_stop.wait(self._public_mirror_retry_seconds()):
                self._public_mirror_dirty.set()
                continue
            self._public_mirror_dirty.set()

    def _public_mirror_store_changed(self) -> None:
        with self._public_mirror_thread_lock:
            if self._public_mirror_thread is not None:
                self._public_mirror_dirty.set()
                return
            if self._public_mirror_stopping:
                self._update_public_mirror_if_changed(publish=True)
                return
        self._write_public_mirror_if_changed()

    def _publish_public_mirror_if_changed(self) -> bool:
        with self._public_mirror_thread_lock:
            if self._public_mirror_thread is not None:
                self._public_mirror_dirty.set()
                return True
        return self._update_public_mirror_if_changed(publish=True)

    def _write_public_mirror_if_changed(self) -> bool:
        return self._update_public_mirror_if_changed(publish=False)

    def _update_public_mirror_if_changed(self, *, publish: bool) -> bool:
        if not self.config.public_mirror.enabled:
            return True
        with self._public_mirror_update_lock:
            try:
                should_publish = publish and self.config.public_mirror.publish
                if should_publish:
                    self._record_publish_attempt()
                runtime = self._runtime_snapshot()
                health = self._public_mirror_health.model_copy(deep=True)
                digest = public_mirror_digest(
                    self.config,
                    self.store,
                    runtime=runtime,
                    publication=health,
                )
                current_digest = (
                    self._public_mirror_remote_digest
                    if publish and self.config.public_mirror.publish
                    else self._public_mirror_local_digest
                )
                if digest == current_digest and not (
                    should_publish
                    and self._public_mirror_health.state
                    in {
                        PublicMirrorPublishState.pending,
                        PublicMirrorPublishState.failed,
                    }
                ):
                    return True
                path, result = publish_public_mirror(
                    self.config,
                    self.store,
                    runtime=runtime,
                    publication=health,
                    publish=should_publish,
                )
                self._public_mirror_local_digest = digest
                if result is not None and not result.ok:
                    category = classify_publish_failure(result)
                    self._record_publish_failure(category)
                    write_public_mirror(
                        self.config,
                        self.store,
                        runtime=runtime,
                        publication=self._public_mirror_health.model_copy(
                            deep=True
                        ),
                    )
                    self._log(f"public mirror publish failed category={category}")
                    return False
                if result is not None:
                    self._record_publish_success(digest)
                    write_public_mirror(
                        self.config,
                        self.store,
                        runtime=runtime,
                        publication=self._public_mirror_health.model_copy(
                            deep=True
                        ),
                    )
                    self._public_mirror_remote_digest = digest
                    self._log(f"public mirror published path={path}")
                else:
                    self._log(f"public mirror written path={path}")
                return True
            except Exception as exc:  # pragma: no cover - daemon boundary guard.
                self._log(f"public mirror publish failed error={exc}")
                return False

    def _record_publish_attempt(self) -> None:
        now = utc_now()
        self._public_mirror_health.last_attempt_at = now
        self._public_mirror_health.state = PublicMirrorPublishState.pending

    def _record_publish_failure(self, category: PublicMirrorFailureCategory) -> None:
        health = self._public_mirror_health
        health.state = PublicMirrorPublishState.failed
        health.last_failure_at = utc_now()
        health.last_failure_category = category
        health.retry_count = min(10, health.retry_count + 1)

    def _record_publish_success(self, digest: str) -> None:
        health = self._public_mirror_health
        health.state = PublicMirrorPublishState.published
        health.last_success_at = utc_now()
        health.last_failure_at = None
        health.last_failure_category = None
        health.retry_count = 0
        health.last_accepted_digest = digest
        health.snapshot_id = digest

    def _public_mirror_retry_seconds(self) -> float:
        retry_count = self._public_mirror_health.retry_count
        initial = self.config.public_mirror.retry_initial_seconds
        if PUBLIC_MIRROR_RETRY_SECONDS != 30.0:
            initial = min(initial, PUBLIC_MIRROR_RETRY_SECONDS)
        maximum = self.config.public_mirror.retry_max_seconds
        return min(maximum, initial * (2 ** max(0, retry_count - 1)))


def stale_task_minutes(config: StewardConfig) -> int:
    if config.limits.stale_task_minutes is not None:
        return config.limits.stale_task_minutes
    return config.limits.worker_timeout_minutes + 5


def status_stale_minutes(config: StewardConfig) -> dict[str, int]:
    if config.limits.stale_task_minutes is not None:
        return {}
    return {
        TaskStatus.reviewing.value: config.limits.review_timeout_minutes + 5,
        TaskPhase.implementation_plan.value: config.limits.plan_timeout_minutes + 5,
        "validation": config.limits.validation_timeout_minutes + 5,
    }


def wait_for_scheduler_event(config: StewardConfig, store: TaskStore) -> SchedulerTrigger:
    while True:
        if store.pending_wakeups(limit=1):
            return SchedulerTrigger(reason="wakeup", providers=[])
        state = scheduler_state(config, store)
        due_providers = [provider.provider for provider in state.providers if provider.due]
        if due_providers:
            return SchedulerTrigger(reason="provider-due", providers=due_providers)
        if store_is_idle_for_signal_fetch(store):
            idle_providers = idle_fetch_provider_names(
                state,
                coalesce_window=timedelta(
                    seconds=config.scheduler_wait_interval_sec
                ),
            )
            if idle_providers:
                return SchedulerTrigger(reason="idle-fetch", providers=idle_providers)
        next_due = min((provider.next_due_at for provider in state.providers), default=None)
        if store_is_idle_for_signal_fetch(store):
            idle_due_at = [
                provider.idle_next_due_at
                for provider in state.providers
                if provider.idle_next_due_at is not None
            ]
            if idle_due_at:
                next_due = min([due for due in (next_due, min(idle_due_at)) if due is not None])
        sleep_for = config.scheduler_wait_interval_sec
        if next_due is not None:
            sleep_for = min(
                sleep_for,
                max(0.0, (next_due - _now()).total_seconds()),
            )
        time.sleep(max(0.1, sleep_for))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fetch_providers_from_wakeups(config: StewardConfig, wakeups) -> list[str]:
    requested: list[str] = []
    enabled = set(config.enabled_signals)
    for wakeup in wakeups:
        if wakeup.reason != "signal.fetch":
            continue
        raw = wakeup.data.get("providers")
        values = raw if isinstance(raw, list) else list(config.enabled_signals)
        for value in values:
            if not isinstance(value, str) or value not in enabled:
                continue
            if value not in requested:
                requested.append(value)
    return requested


def _bounded_cycle_reason(reason: str) -> str:
    value = reason.strip()
    if not value or len(value) > 64:
        return "other"
    if any(
        character
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in value
    ):
        return "other"
    return value


def _task_label(task: TaskRecord) -> str:
    return f"kind={task.spec.kind} title={task.spec.title!r}"


def _is_integration_manager_task(task: TaskRecord) -> bool:
    return task.spec.worker == WorkerKind.integration_manager.value


def _selected_item_ids(spec, consumed_item_ids: list[str]) -> list[str]:
    metadata = spec.metadata or {}
    selected = metadata.get("selected_signal_item_ids")
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

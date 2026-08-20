from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from ..core.config import SignalProviderConfig, StewardConfig
from ..core.models import (
    SchedulerPollResult,
    SchedulerProviderState,
    SchedulerState,
    SignalFetchRun,
    SignalFetchStatus,
)
from .sqlite import (
    CURRENT_SCHEMA_CATALOG_DIGEST,
    SQLITE_USER_VERSION,
    SQLiteStoreLifecycleError,
    SQLiteTaskStore,
    StoreRecoveryResult,
)
from ..control_loop import ControlLoopLedger
from .schema import (
    CodexSessionRow,
    ControlLoopOverheadUsageRow,
    ControlLoopOverheadUsageRunRow,
    TaskExecutionRow,
    TaskPipelineRow,
    TaskRunRow,
    TaskWorktreeCheckpointRow,
    DaemonStateRow,
    StewardImageReleaseRow,
    StewardContainerReferenceRow,
    StewardValidationCleanupRow,
    StewardResourcePressureRow,
)

TaskStore = SQLiteTaskStore


def scheduler_state(config: StewardConfig, store: TaskStore) -> SchedulerPollResult:
    snapshot = store.scheduler_snapshot(config.enabled_signals)
    now = _now()
    source_active = snapshot.source_active
    state = SchedulerState(
        source_active=source_active,
        source_capacity=max(0, config.limits.max_active_tasks - source_active),
        source_queued=snapshot.source_queued,
        integration_active=snapshot.integration_active,
        integration_queued=snapshot.integration_queued,
        pending_wakeups=list(snapshot.pending_wakeups),
        recent_wakeups=list(snapshot.recent_wakeups),
        providers=[
            _provider_state(
                config,
                name,
                snapshot.latest_fetches.get(name),
                now,
            )
            for name in config.enabled_signals
        ],
    )
    return SchedulerPollResult(
        state=state,
        idle=(
            snapshot.source_active == 0
            and snapshot.source_queued == 0
            and not snapshot.pending_signal
        ),
    )


def due_provider_names(result: SchedulerPollResult) -> list[str]:
    return [
        provider.provider for provider in result.state.providers if provider.due
    ]


def idle_fetch_provider_names(
    result: SchedulerPollResult, *, coalesce_window: timedelta = timedelta(0)
) -> list[str]:
    if not result.idle:
        return []
    now = _now()
    cutoff = now + coalesce_window
    return [
        provider.provider
        for provider in result.state.providers
        if provider.idle_next_due_at is not None
        and provider.idle_next_due_at <= cutoff
    ]


def _provider_state(
    config: StewardConfig,
    provider: str,
    latest: SignalFetchRun | None,
    now: datetime,
) -> SchedulerProviderState:
    provider_config = config.signal_providers[provider]
    if latest is None:
        next_due = now
        return SchedulerProviderState(
            provider=provider,
            poll_interval_minutes=provider_config.poll_interval_minutes,
            error_retry_minutes=provider_config.error_retry_minutes,
            idle_poll_interval_minutes=provider_config.idle_poll_interval_minutes,
            suppression_hours=provider_config.suppression_hours,
            max_items=provider_config.max_items,
            next_due_at=next_due,
            idle_next_due_at=next_due,
            due=True,
            idle_due=True,
        )
    interval = (
        provider_config.error_retry_minutes
        if latest.status == SignalFetchStatus.error
        else provider_config.poll_interval_minutes
    )
    next_due = latest.completed_at + timedelta(minutes=interval)
    next_due = next_due + _provider_jitter(config, provider)
    idle_next_due = _provider_idle_fetch_due_at(
        provider_config, latest.completed_at, latest.status
    )
    return SchedulerProviderState(
        provider=provider,
        poll_interval_minutes=provider_config.poll_interval_minutes,
        error_retry_minutes=provider_config.error_retry_minutes,
        idle_poll_interval_minutes=provider_config.idle_poll_interval_minutes,
        suppression_hours=provider_config.suppression_hours,
        max_items=provider_config.max_items,
        last_fetch_at=latest.completed_at,
        last_status=latest.status,
        last_error=latest.error,
        next_due_at=next_due,
        idle_next_due_at=idle_next_due,
        due=next_due <= now,
        idle_due=idle_next_due <= now,
    )


def _provider_jitter(config: StewardConfig, provider: str) -> timedelta:
    seed = f"{config.state_dir.name}:{provider}".encode("utf-8")
    value = int(hashlib.sha256(seed).hexdigest()[:8], 16)
    minutes = value % 17
    return timedelta(minutes=minutes)


def _provider_idle_fetch_due_at(
    provider: SignalProviderConfig | SchedulerProviderState,
    last_fetch_at: datetime | None = None,
    last_status: SignalFetchStatus | None = None,
) -> datetime | None:
    completed_at = last_fetch_at
    if completed_at is None and isinstance(provider, SchedulerProviderState):
        completed_at = provider.last_fetch_at
    status = last_status
    if status is None and isinstance(provider, SchedulerProviderState):
        status = provider.last_status
    if completed_at is None:
        return None
    interval = (
        provider.error_retry_minutes
        if status == SignalFetchStatus.error
        else min(provider.poll_interval_minutes, provider.idle_poll_interval_minutes)
    )
    return completed_at + timedelta(minutes=interval)


def _now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "SQLiteTaskStore",
    "CURRENT_SCHEMA_CATALOG_DIGEST",
    "SQLITE_USER_VERSION",
    "SQLiteStoreLifecycleError",
    "StoreRecoveryResult",
    "ControlLoopLedger",
    "ControlLoopOverheadUsageRow",
    "ControlLoopOverheadUsageRunRow",
    "TaskStore",
    "CodexSessionRow",
    "TaskExecutionRow",
    "TaskPipelineRow",
    "TaskRunRow",
    "TaskWorktreeCheckpointRow",
    "DaemonStateRow",
    "StewardImageReleaseRow",
    "StewardContainerReferenceRow",
    "StewardValidationCleanupRow",
    "StewardResourcePressureRow",
    "due_provider_names",
    "idle_fetch_provider_names",
    "scheduler_state",
    "SchedulerPollResult",
]

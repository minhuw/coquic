from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from ..core.config import SignalProviderConfig, StewardConfig
from ..core.models import (
    SchedulerProviderState,
    SchedulerState,
    SignalFetchStatus,
)
from .sqlite import SQLiteTaskStore

TaskStore = SQLiteTaskStore


def scheduler_state(config: StewardConfig, store: TaskStore) -> SchedulerState:
    source_active = store.source_active_count()
    return SchedulerState(
        source_active=source_active,
        source_capacity=max(0, config.limits.max_active_tasks - source_active),
        source_queued=store.source_queued_count(),
        integration_active=store.integration_active_count(),
        integration_queued=store.integration_queued_count(),
        pending_wakeups=store.pending_wakeups(limit=20),
        recent_wakeups=store.recent_wakeups(limit=20),
        providers=[
            _provider_state(config, store, name) for name in config.enabled_signals
        ],
    )


def due_provider_names(config: StewardConfig, store: TaskStore) -> list[str]:
    return [
        provider.provider
        for provider in scheduler_state(config, store).providers
        if provider.due
    ]


def store_is_idle_for_signal_fetch(store: TaskStore) -> bool:
    return (
        store.source_active_count() == 0
        and store.source_queued_count() == 0
        and not store.pending_signal_items(limit=1)
    )


def idle_fetch_provider_names(
    state: SchedulerState, *, coalesce_window: timedelta = timedelta(0)
) -> list[str]:
    now = _now()
    cutoff = now + coalesce_window
    return [
        provider.provider
        for provider in state.providers
        if provider.idle_next_due_at is not None
        and provider.idle_next_due_at <= cutoff
    ]


def _provider_state(
    config: StewardConfig, store: TaskStore, provider: str
) -> SchedulerProviderState:
    provider_config = config.signal_providers[provider]
    latest = store.latest_signal_fetch_run(provider)
    now = _now()
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
    "TaskStore",
    "due_provider_names",
    "idle_fetch_provider_names",
    "scheduler_state",
    "store_is_idle_for_signal_fetch",
]

from __future__ import annotations

import pytest

from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import (
    CleanupStatus,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
)
from coquic_steward.storage import TaskStore
from coquic_steward.storage.schema import TaskRow


def _task(store: TaskStore, title: str):
    return store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title=title,
            prompt="prompt",
        )
    )[0]


def test_task_pages_are_complete_and_stable_for_tied_timestamps(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    tasks = [_task(store, f"task-{index}") for index in range(7)]
    tied_timestamp = "2026-01-01T00:00:00+00:00"
    with store.engine.begin() as connection:
        connection.execute(
            TaskRow.__table__.update().where(
                TaskRow.id.in_([task.id for task in tasks])
            ).values(created_at=tied_timestamp)
        )

    expected = sorted(tasks, key=lambda task: (tied_timestamp, task.id), reverse=True)
    seen = []
    cursor = None
    while True:
        page = store.list_tasks_page(limit=2, cursor=cursor)
        seen.extend(page.items)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor

    assert [task.id for task in seen] == [task.id for task in expected]
    assert len({task.id for task in seen}) == len(tasks)
    assert [task.id for task in store.iter_tasks(page_size=2)] == [
        task.id for task in expected
    ]

    store.start_worker(tasks[0].id, "running")
    running = store.list_tasks_page(status=TaskStatus.running, limit=2)
    assert [task.id for task in running.items] == [tasks[0].id]
    assert store.list_tasks_page(statuses=[]).items == []


def test_running_runs_are_discovered_without_a_task_window(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    oldest = _task(store, "oldest")
    pipeline = store.list_pipelines(oldest.id)[0]
    session = store.create_session(oldest.id, pipeline.id)
    running = store.create_run(oldest.id, pipeline.id, session.id, role="implementation")

    for index in range(205):
        _task(store, f"history-{index}")

    discovered = store.running_runs()
    assert [run.id for run in discovered] == [running.id]
    assert [run.id for run in store.running_runs(task_id=oldest.id)] == [
        running.id
    ]

    store.mark_run_interrupted(running.id, reason="test")
    assert store.running_runs() == []


def test_cleanup_queries_use_all_events_and_latest_completion(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    no_obligation = _task(store, "no-obligation")
    pending_only = _task(store, "pending-only")
    retryable_only = _task(store, "retryable-only")
    completed = _task(store, "completed")
    retryable_completed = _task(store, "retryable-completed")
    completed_retryable = _task(store, "completed-retryable")
    retryable_pending = _task(store, "retryable-pending")
    pending_retryable = _task(store, "pending-retryable")
    duplicate = _task(store, "duplicate")
    reopened = _task(store, "reopened")
    reopened_after_completion = _task(store, "reopened-after-completion")
    late_completion = _task(store, "late-completion")
    terminal_retryable = _task(store, "terminal-retryable")

    store.add_event(pending_only.id, "cleanup_pending", "pending")
    store.add_event(retryable_only.id, "cleanup_retryable", "retryable")
    store.add_event(completed.id, "cleanup_pending", "pending")
    store.add_event(completed.id, "cleanup_complete", "complete")
    store.add_event(retryable_completed.id, "cleanup_retryable", "retryable")
    store.add_event(retryable_completed.id, "cleanup_complete", "complete")
    store.add_event(completed_retryable.id, "cleanup_complete", "complete first")
    store.add_event(completed_retryable.id, "cleanup_retryable", "retryable reopened")
    store.add_event(retryable_pending.id, "cleanup_retryable", "retryable first")
    store.add_event(retryable_pending.id, "cleanup_pending", "pending reopened")
    store.add_event(pending_retryable.id, "cleanup_pending", "pending first")
    store.add_event(pending_retryable.id, "cleanup_retryable", "retryable reopened")
    store.add_event(duplicate.id, "cleanup_pending", "pending")
    store.add_event(duplicate.id, "cleanup_pending", "pending again")
    store.add_event(reopened.id, "cleanup_complete", "complete first")
    store.add_event(reopened.id, "cleanup_pending", "pending again")
    store.add_event(
        reopened_after_completion.id,
        "cleanup_pending",
        "pending first",
    )
    store.add_event(
        reopened_after_completion.id,
        "cleanup_complete",
        "complete first",
    )
    store.add_event(
        reopened_after_completion.id,
        "cleanup_pending",
        "pending reopened",
    )

    for index in range(205):
        store.add_event(late_completion.id, "cleanup_retryable", f"retryable {index}")
    store.add_event(late_completion.id, "cleanup_complete", "late completion")
    store.finish_task(terminal_retryable.id, TaskStatus.failed, "terminal")
    store.add_event(terminal_retryable.id, "cleanup_retryable", "terminal retry")

    expected_tasks = [
        pending_only,
        retryable_only,
        completed_retryable,
        retryable_pending,
        pending_retryable,
        duplicate,
        reopened,
        reopened_after_completion,
        terminal_retryable,
    ]
    expected_tasks.sort(key=lambda task: (task.created_at, task.id))
    expected_ids = [task.id for task in expected_tasks]
    assert store.cleanup_pending_task_ids() == expected_ids
    assert [task.id for task in store.cleanup_pending_tasks()] == expected_ids
    assert store.cleanup_pending_task_ids(limit=2) == expected_ids[:2]
    assert [task.id for task in store.cleanup_pending_tasks(limit=2)] == expected_ids[:2]
    assert [task.id for task in store.cleanup_pending_tasks(status=TaskStatus.failed)] == [
        terminal_retryable.id
    ]
    assert [
        task.id
        for task in store.cleanup_pending_tasks(statuses=(TaskStatus.failed.value,))
    ] == [terminal_retryable.id]
    assert store.cleanup_pending_tasks(statuses=[]) == []
    with pytest.raises(ValueError, match="mutually exclusive"):
        store.cleanup_pending_tasks(status=TaskStatus.failed, statuses=[])

    states = {
        task.id: store.cleanup_obligation_state(task.id)
        for task in (
            no_obligation,
            pending_only,
            retryable_only,
            completed,
            retryable_completed,
            completed_retryable,
            retryable_pending,
            pending_retryable,
            duplicate,
            reopened,
            reopened_after_completion,
            late_completion,
            terminal_retryable,
        )
    }
    assert states == {
        no_obligation.id: None,
        pending_only.id: CleanupStatus.pending,
        retryable_only.id: CleanupStatus.retryable,
        completed.id: CleanupStatus.complete,
        retryable_completed.id: CleanupStatus.complete,
        completed_retryable.id: CleanupStatus.retryable,
        retryable_pending.id: CleanupStatus.pending,
        pending_retryable.id: CleanupStatus.retryable,
        duplicate.id: CleanupStatus.pending,
        reopened.id: CleanupStatus.pending,
        reopened_after_completion.id: CleanupStatus.pending,
        late_completion.id: CleanupStatus.complete,
        terminal_retryable.id: CleanupStatus.retryable,
    }
    assert store.cleanup_pending_count() == len(expected_ids)
    for task in expected_tasks:
        assert store.has_cleanup_pending(task.id)
    for task in (no_obligation, completed, retryable_completed, late_completion):
        assert not store.has_cleanup_pending(task.id)
    assert store.event_exists(late_completion.id, "cleanup_complete")
    assert store.count_task_events(late_completion.id, "cleanup_retryable") == 205

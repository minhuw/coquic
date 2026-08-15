from __future__ import annotations

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
    completed = _task(store, "completed")
    duplicate = _task(store, "duplicate")
    reopened = _task(store, "reopened")
    reopened_after_completion = _task(store, "reopened-after-completion")
    late_completion = _task(store, "late-completion")

    store.add_event(pending_only.id, "cleanup_pending", "pending")
    store.add_event(completed.id, "cleanup_pending", "pending")
    store.add_event(completed.id, "cleanup_complete", "complete")
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
        store.add_event(late_completion.id, "cleanup_pending", f"pending {index}")
    store.add_event(late_completion.id, "cleanup_complete", "late completion")

    pending_ids = set(store.cleanup_pending_task_ids())
    assert pending_ids == {
        pending_only.id,
        duplicate.id,
        reopened.id,
        reopened_after_completion.id,
    }
    states = {
        task.id: store.cleanup_obligation_state(task.id)
        for task in (
            no_obligation,
            pending_only,
            completed,
            duplicate,
            reopened,
            reopened_after_completion,
            late_completion,
        )
    }
    assert states == {
        no_obligation.id: None,
        pending_only.id: CleanupStatus.pending,
        completed.id: CleanupStatus.complete,
        duplicate.id: CleanupStatus.pending,
        reopened.id: CleanupStatus.pending,
        reopened_after_completion.id: CleanupStatus.pending,
        late_completion.id: CleanupStatus.complete,
    }
    assert {
        task_id
        for task_id, state in states.items()
        if state is CleanupStatus.pending
    } == pending_ids
    assert {task.id for task in store.cleanup_pending_tasks()} == pending_ids
    assert store.cleanup_pending_count() == 4
    assert store.cleanup_pending_count() == 4
    assert store.cleanup_pending_count() == 4
    assert store.has_cleanup_pending(pending_only.id)
    assert store.has_cleanup_pending(reopened.id)
    assert not store.has_cleanup_pending(completed.id)
    assert not store.has_cleanup_pending(late_completion.id)
    assert store.event_exists(late_completion.id, "cleanup_complete")
    assert store.event_exists(late_completion.id, "cleanup_complete")
    assert store.count_task_events(late_completion.id, "cleanup_pending") == 205

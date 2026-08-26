"""Private assembly of the publication graph from the task archive."""

from __future__ import annotations

from datetime import timezone
from ..core.models import TaskRecord, TaskStatus, TaskRun
from ..publication.atif import AtifSource
from ..storage import TaskStore
from .task_archive import TaskArchive


def _publication_timestamp(value: object) -> str:
    """Serialize one store timestamp for the detached publication graph."""

    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def task_publication_lifecycle(status: TaskStatus | str) -> str:
    """Map one legal task status to its public lifecycle state."""

    status = TaskStatus(status)
    if status in {
        TaskStatus.queued,
        TaskStatus.running,
        TaskStatus.reviewing,
        TaskStatus.integrating,
    }:
        return "active"
    if status is TaskStatus.cancelled:
        return "cancelled"
    if status in {TaskStatus.failed, TaskStatus.blocked}:
        return "failed"
    return "completed"


def assemble_publication_graph(
    store: TaskStore, task: TaskRecord, archive: TaskArchive
) -> dict[str, object]:
    """Assemble the private, stable archive view consumed by the pure builder."""

    pipelines: list[dict[str, object]] = []
    runs: list[dict[str, object]] = []

    def run_mapping(
        run: TaskRun, invocations: tuple[object, ...]
    ) -> dict[str, object]:
        completed = run.completed_at
        duration = (
            max(0, int((completed - run.started_at).total_seconds() * 1000))
            if completed is not None
            else 0
        )
        return {
            "taskId": run.task_id,
            "pipelineId": run.pipeline_id,
            "runId": run.id,
            "role": str(run.role),
            "state": str(run.state),
            "startedAt": _publication_timestamp(run.started_at),
            "completedAt": (
                _publication_timestamp(completed) if completed is not None else None
            ),
            "durationMs": duration,
            "model": run.model,
            "reasoning": run.reasoning,
            "parentRunId": run.parent_run_id,
            "retryOfRunId": run.retry_of_run_id,
            "resumeOfRunId": run.resume_of_run_id,
            "invocations": [
                item.to_dict(include_telemetry=True) for item in invocations
            ],
        }

    for pipeline in store.list_pipelines(task.id):
        pipeline_value = {
            "pipelineId": pipeline.id,
            "taskId": pipeline.task_id,
            "name": f"pipeline-{pipeline.ordinal}",
            "createdAt": _publication_timestamp(pipeline.started_at),
        }
        pipelines.append(pipeline_value)
        for run in store.list_runs(task.id, pipeline_id=pipeline.id):
            if run.completed_at is None or str(run.state) == "running":
                continue
            documents, invocations = archive.collect_run_publication_evidence(
                task.id,
                pipeline.id,
                run,
            )
            runs.append(
                {
                    "source": AtifSource(
                        run=run_mapping(run, invocations), documents=documents
                    ),
                    "pipeline": pipeline_value,
                }
            )

    lifecycle = task_publication_lifecycle(task.status)
    task_value = {
        "taskId": task.id,
        "title": task.spec.title,
        "lifecycleState": lifecycle,
        "createdAt": _publication_timestamp(task.created_at),
        "completedAt": (
            None
            if lifecycle == "active"
            else _publication_timestamp(task.updated_at)
        ),
    }
    events = [
        {
            "taskId": task.id,
            "sequence": index,
            "eventType": event.kind,
            "occurredAt": _publication_timestamp(event.created_at),
            "summary": event.message,
        }
        for index, event in enumerate(store.events(task.id), start=1)
    ]
    return {
        "task": task_value,
        "pipelines": pipelines,
        "runs": runs,
        "events": events,
    }

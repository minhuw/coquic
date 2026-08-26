from __future__ import annotations

from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
from coquic_steward.publication.generation import PublicationComposer
from coquic_steward.publication.outbox import PublicationGeneration
from coquic_steward.storage import TaskStore


def enqueue_publication(store: TaskStore, generation: PublicationGeneration):
    try:
        store.get(generation.task_id)
    except KeyError:
        store.add_task(
            TaskSpec(
                id=generation.task_id,
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title="publication fixture",
                prompt="publication fixture",
            )
        )
    return store.enqueue_publication(generation)


def returning_composer(result: object):
    def compose(_source: object, **_kwargs: object) -> object:
        return result

    return PublicationComposer(compose)

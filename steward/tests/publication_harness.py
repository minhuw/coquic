from __future__ import annotations

from pathlib import Path

from coquic_steward.core.config import StewardPublicationConfig
from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
from coquic_steward.publication.generation import PublicationComposer
from coquic_steward.publication.outbox import PublicationGeneration
from coquic_steward.storage import TaskStore


def enabled_publication_config(
    tmp_path: Path, credential: str
) -> StewardPublicationConfig:
    paths = []
    for name, value in (
        ("d1-token", credential),
        ("r2-access-key", "worker-access-key"),
        ("r2-secret-key", "worker-secret-key"),
    ):
        path = tmp_path / name
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(0o600)
        paths.append(path)
    staging = tmp_path / "publication-staging"
    staging.mkdir(mode=0o700)
    return StewardPublicationConfig(
        enabled=True,
        account_id="a" * 32,
        d1_database_id="00000000-0000-4000-8000-000000000000",
        d1_token_path=paths[0],
        r2_endpoint="https://example.r2.cloudflarestorage.com",
        r2_access_key_id_path=paths[1],
        r2_secret_access_key_path=paths[2],
        public_bucket="publication-public",
        private_bucket="publication-private",
        public_base_url="https://publication.example.test",
        staging_root=staging,
    )


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

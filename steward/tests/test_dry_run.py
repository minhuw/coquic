from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.config import StewardConfig, load_config
from coquic_steward.core.models import (
    EffectActionKind,
    EffectDecisionKind,
    EffectProposal,
    EXECUTION_MODE_METADATA_KEY,
    ExecutionMode,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    TaskKind,
    TaskSpec,
    WorkerKind,
)
from coquic_steward.execution.session import enqueue_materialized_publication
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    PublicationGeneration,
    PublicationOperationStatus,
)
from coquic_steward.storage import TaskStore


def _spec(**metadata: object) -> TaskSpec:
    return TaskSpec(
        kind=TaskKind.custom,
        worker=WorkerKind.custom,
        title="dry-run task",
        prompt="inspect only",
        metadata=dict(metadata),
    )


def test_config_defaults_to_dry_run_and_validates_boolean(repo: Path, tmp_path: Path) -> None:
    config = load_config(repo_root=repo)
    assert config.dry_run is True
    assert config.dry_run_enabled is True

    path = tmp_path / "invalid-bool.toml"
    path.write_text('[steward]\ndry_run = "false"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="dry_run must be a boolean"):
        load_config(repo_root=repo, config_path=path)


def test_store_latch_is_owned_and_monotonic(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=True)
    task, created = store.add_task(
        _spec(**{EXECUTION_MODE_METADATA_KEY: ExecutionMode.live.value})
    )
    assert created
    assert store.task_execution_mode(task.id) is ExecutionMode.dry_run

    mutable = store.get(task.id)
    mutable.spec.metadata[EXECUTION_MODE_METADATA_KEY] = ExecutionMode.live.value
    store.save(mutable)
    assert store.task_execution_mode(task.id) is ExecutionMode.dry_run

    reopened = TaskStore.open(database, dry_run=False)
    assert reopened.task_execution_mode(task.id) is ExecutionMode.dry_run


def test_missing_latch_adopts_startup_and_tightens(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=False)
    task, _ = store.add_task(_spec())
    store.resolve_task_execution_mode(task.id, True)
    assert store.task_execution_mode(task.id) is ExecutionMode.dry_run
    assert store.resolve_execution_modes(False) == 0
    assert store.task_execution_mode(task.id) is ExecutionMode.dry_run


def test_effect_proposal_is_bounded_and_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=True)
    task, _ = store.add_task(_spec())

    first = store.effect_decision(
        task.id,
        action=EffectActionKind.git_push.value,
        action_id="push-task-1",
        target="origin/main",
        payload={"commit": "a" * 40},
        reason="dry-run push",
    )
    second = store.effect_decision(
        task.id,
        action=EffectActionKind.git_push.value,
        action_id="push-task-1",
        target="origin/main",
        payload={"commit": "a" * 40},
        reason="dry-run push",
    )

    assert first.kind is EffectDecisionKind.proposal_required
    assert second.proposal is not None
    assert first.proposal is not None
    assert first.proposal.identity == second.proposal.identity
    assert len(store.events(task.id)) == 2  # creation plus one idempotent proposal
    with pytest.raises(ValueError):
        EffectProposal(
            action=EffectActionKind.git_push,
            action_id="unsafe",
            target="origin/main",
            payload={"private_path": "/secret"},
            reason="dry-run",
        )


def test_live_effect_is_allowed(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=False)
    task, _ = store.add_task(_spec())
    decision = store.effect_decision(
        task.id,
        action=EffectActionKind.git_push.value,
        action_id="live-push",
        target="origin/main",
        payload={"commit": "a" * 40},
    )
    assert decision.kind is EffectDecisionKind.allow
    assert decision.proposal is None


def test_dry_run_tasks_are_dispatchable(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=True)
    running, _ = store.add_task(_spec(title="running"))
    store.start_worker(running.id, "running")
    queued, _ = store.add_task(_spec(title="queued"))

    snapshot = store.dispatch_snapshot(
        source_limit=10,
        integration_limit=1,
        resumable_limit=10,
    )
    assert store.active_count() == 2
    assert snapshot.source_active_count == 1
    assert queued.id in {task.id for task in snapshot.queued_tasks}


def test_daemon_allows_local_dry_run_phase(repo: Path, tmp_path: Path, monkeypatch) -> None:
    config = StewardConfig(repo_root=repo, dry_run=True, local_codex_test_harness=True)
    config.ensure_dirs()
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=True)
    task, _ = store.add_task(_spec())
    daemon = StewardDaemon(config, store)
    calls: list[str] = []
    daemon.executor.advance_once = lambda task_id: (
        calls.append(task_id)
        or SimpleNamespace(status="ready_to_seal", progressed=True, next_phase=None)
    )
    daemon.finalize_terminal_task = lambda _task_id: False

    assert daemon.drive_selected_task(task.id) is True
    assert calls == [task.id]
    assert not any(event.kind == "effect.proposed" for event in store.events(task.id))


def test_publication_enqueue_rechecks_persisted_latch(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=False)
    task, _ = store.add_task(_spec())
    identity = GenerationIdentity(task.id, "boundary-stale")
    generation = PublicationGeneration(
        publication_id=identity.publication_id,
        task_id=task.id,
        run_id="run-stale",
        generation_boundary=identity.stable_boundary,
        metadata_digest="a" * 64,
        idempotency_key=identity.idempotency_key,
    )

    TaskStore.open(database, dry_run=True)
    result = store.enqueue_publication(generation)
    assert result.status is PublicationOperationStatus.precondition
    assert store.get_publication_generation(generation.publication_id) is None


def test_session_publication_uses_current_store_latch(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=False)
    task, _ = store.add_task(_spec())
    restarted = TaskStore.open(database, dry_run=True)
    config = SimpleNamespace(
        dry_run=False,
        publication=SimpleNamespace(enabled=True),
    )
    run = SimpleNamespace(id="run-stale", state="succeeded", completed_at=object())

    assert enqueue_materialized_publication(config, restarted, task, run) is None


def test_dry_run_publication_cli_does_not_construct_mutator(monkeypatch) -> None:
    import coquic_steward.cli as cli

    config = StewardConfig(repo_root=Path.cwd(), dry_run=True)
    monkeypatch.setattr(cli, "_context", lambda: (SimpleNamespace(), config))
    monkeypatch.setattr(
        cli,
        "_build_cli_retry_publisher",
        lambda *_args, **_kwargs: pytest.fail("dry-run built a publisher"),
    )
    result = CliRunner().invoke(app, ["publication", "retry", "pub-" + "a" * 64])
    assert result.exit_code == 1
    assert '"reason":"dry_run"' in result.stdout

    monkeypatch.setattr(
        cli,
        "_build_cli_hide_publisher",
        lambda *_args, **_kwargs: pytest.fail("dry-run built a publisher"),
    )
    result = CliRunner().invoke(app, ["publication", "hide", "task-preview"])
    assert result.exit_code == 1
    assert '"reason":"dry_run"' in result.stdout

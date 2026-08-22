from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.config import StewardConfig, load_config
from coquic_steward.core.models import (
    EffectActionKind,
    EffectDecisionKind,
    EffectProposal,
    EffectResult,
    EXECUTION_MODE_METADATA_KEY,
    ExecutionMode,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
)
from coquic_steward.execution.session import enqueue_materialized_publication
from coquic_steward.orchestration.daemon import (
    LiveRerunRejected,
    StewardDaemon,
    create_live_rerun,
)
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


def test_effect_result_is_typed_write_once_and_contradictions_fail(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    dry_store = TaskStore.create(database, dry_run=True)
    task, _ = dry_store.add_task(_spec())
    dry_store.effect_decision(
        task.id,
        action=EffectActionKind.git_push.value,
        action_id="push-result",
        target="origin/main",
        payload={"commit": "a" * 40},
    )
    assert dry_store.derive_effect_result(task.id) is EffectResult.not_applied
    assert dry_store.finalize_effect_result(task.id) is EffectResult.not_applied
    assert dry_store.finalize_effect_result(task.id) is EffectResult.not_applied
    detached = dry_store.get(task.id)
    detached.spec.metadata["effect_result"] = EffectResult.applied.value
    with pytest.raises(ValueError, match="write-once"):
        dry_store.save(detached)
    assert dry_store.effect_result(task.id) is EffectResult.not_applied
    with pytest.raises(ValueError, match="contradict"):
        dry_store.finalize_effect_result(task.id, EffectResult.applied)

    live = TaskStore.create(tmp_path / "live.sqlite", dry_run=False)
    live_task, _ = live.add_task(_spec())
    live.record_effect_applied(
        live_task.id,
        action=EffectActionKind.git_push.value,
        action_id="push-applied",
    )
    assert live.finalize_effect_result(live_task.id) is EffectResult.applied


def test_historical_live_effect_survives_dry_run_restart(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    live = TaskStore.create(database, dry_run=False)
    task, _ = live.add_task(_spec())
    live.record_effect_applied(
        task.id,
        action=EffectActionKind.git_push.value,
        action_id="restart-live-effect",
    )
    live._finalize_exact_store()

    restarted = TaskStore.open(database, dry_run=True)
    assert restarted.task_execution_mode(task.id) is ExecutionMode.dry_run
    evidence = restarted.effect_evidence(task.id)
    assert len(evidence) == 1
    assert evidence[0].mode is ExecutionMode.live
    assert restarted.finalize_effect_result(task.id) is EffectResult.applied
    assert restarted.effect_result(task.id) is EffectResult.applied


def test_finalized_effect_result_rejects_late_applied_evidence(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=False)
    task, _ = store.add_task(_spec())
    assert store.finalize_effect_result(task.id) is EffectResult.not_applicable
    event_count = len(store.events(task.id))

    with pytest.raises(ValueError, match="already finalized"):
        store.record_effect_applied(
            task.id,
            action=EffectActionKind.git_push.value,
            action_id="late-live-effect",
        )
    assert len(store.events(task.id)) == event_count
    assert store.effect_result(task.id) is EffectResult.not_applicable


def test_proposal_bookkeeping_failure_is_not_external_effect_evidence(
    tmp_path: Path,
) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=True)
    task, _ = store.add_task(_spec())
    store.add_event(
        task.id,
        "github.issue_update_failed",
        "credentials and /private/path must not become an action id",
        {"step": "proposal"},
    )

    assert store.effect_evidence(task.id) == ()
    assert store.finalize_effect_result(task.id) is EffectResult.not_applicable


def test_bookkeeping_failure_does_not_poison_confirmed_push_result(
    tmp_path: Path,
) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=False)
    task, _ = store.add_task(_spec())
    store.record_effect_applied(
        task.id,
        action=EffectActionKind.git_push.value,
        action_id="push-with-bookkeeping-diagnostic",
    )
    store.finish_task(task.id, TaskStatus.pushed, "pushed")
    store.add_event(
        task.id,
        "github.issue_update_failed",
        "post-push bookkeeping failed",
        {"integration_task_id": task.id, "step": "bookkeeping"},
    )

    assert any(
        event.kind == "github.issue_update_failed"
        and event.data.get("step") == "bookkeeping"
        for event in store.events(task.id)
    )
    evidence = store.effect_evidence(task.id)
    assert len(evidence) == 1
    assert evidence[0].result is EffectResult.applied
    assert store.finalize_effect_result(task.id) is EffectResult.applied
    assert store.finalize_effect_result(task.id) is EffectResult.applied


def test_push_budget_legacy_evidence_uses_safe_identity(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=False)
    task, _ = store.add_task(_spec())
    store.add_event(
        task.id,
        "pipeline.push.blocked",
        "main push budget reached; command=/private/secret token=credential",
        {"pipeline_id": "pipeline-safe"},
    )

    evidence = store.effect_evidence(task.id)
    assert len(evidence) == 1
    assert evidence[0].action is EffectActionKind.git_push
    assert evidence[0].action_id != (
        "git-push:main push budget reached; command=/private/secret token=credential"
    )
    assert len(evidence[0].action_id) <= 160
    from coquic_steward.execution.task_archive import TaskArchive

    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task(task.id, "prompt", pipeline_id="pipeline-safe")
    archive.materialize_effects(
        task.id,
        evidence,
        result=EffectResult.not_applied,
        mode=ExecutionMode.live.value,
    )
    assert archive.effect_records(task.id)[0]["actionId"] == evidence[0].action_id
    assert store.finalize_effect_result(task.id) is EffectResult.not_applied


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


def test_dry_run_finalization_seals_and_retains_without_proposals(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    config = StewardConfig(repo_root=repo, dry_run=True, local_codex_test_harness=True)
    config.ensure_dirs()
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=True)
    task, _ = store.add_task(_spec())
    pipeline = store.list_pipelines(task.id)[0]
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "no changes",
        {"pipeline_id": pipeline.id, "terminal_status": TaskStatus.no_changes.value},
    )
    store.finish_task(task.id, TaskStatus.no_changes, "no changes")
    seal_calls: list[str] = []

    from coquic_steward.execution.task_archive import TaskArchiveWriter

    real_seal = TaskArchiveWriter.seal

    def record_seal(self, task_id, *args, **kwargs):
        seal_calls.append(task_id)
        return real_seal(self, task_id, *args, **kwargs)

    monkeypatch.setattr(TaskArchiveWriter, "seal", record_seal)
    daemon = StewardDaemon(config, store)

    assert daemon.finalize_terminal_task(task.id) is True
    assert seal_calls == [task.id]
    assert not any(event.kind == "effect.proposed" for event in store.events(task.id))
    assert store.effect_result(task.id).value == "not-applicable"
    archive = TaskArchiveWriter(config)
    assert archive.verify(task.id)
    effect_records = archive.effect_records(task.id)
    assert len(effect_records) == 1
    assert effect_records[0]["result"] == "not-applicable"
    assert effect_records[0]["actionId"] == "none"
    assert [
        event.kind
        for event in store.events(task.id)
        if event.kind in {"cleanup_pending", "cleanup_complete"}
    ] == ["cleanup_pending", "cleanup_complete"]


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


def test_status_reports_mode_and_external_effect_separately(tmp_path: Path, monkeypatch) -> None:
    import coquic_steward.cli as cli

    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=True)
    task, _ = store.add_task(_spec())
    store.finish_task(task.id, TaskStatus.succeeded, "validated")
    store.finalize_effect_result(task.id)
    monkeypatch.setattr(cli, "_context", lambda: (store, SimpleNamespace()))
    result = CliRunner().invoke(app, ["status"])
    assert result.exit_code == 0, result.stdout
    assert "mode=dry-run" in result.stdout
    assert "effect=not-applicable" in result.stdout
    assert "validated; no external operation applicable" in result.stdout


def test_status_and_timeline_do_not_validate_failed_dry_run_tasks(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.cli as cli

    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=True)
    tasks = []
    for status in (TaskStatus.failed, TaskStatus.blocked, TaskStatus.cancelled):
        task, _ = store.add_task(_spec(title=status.value))
        store.finish_task(task.id, status, status.value)
        store.finalize_effect_result(task.id)
        tasks.append(task)
    monkeypatch.setattr(cli, "_context", lambda: (store, SimpleNamespace()))

    status_output = CliRunner().invoke(app, ["status"])
    assert status_output.exit_code == 0, status_output.stdout
    assert "validated;" not in status_output.stdout
    for task in tasks:
        timeline_output = CliRunner().invoke(app, ["timeline", task.id])
        assert timeline_output.exit_code == 0, timeline_output.stdout
        assert "validated;" not in timeline_output.stdout


def _sealed_dry_run_source(config: StewardConfig, store: TaskStore, spec: TaskSpec | None = None):
    task, _ = store.add_task(spec or _spec())
    pipeline = store.list_pipelines(task.id)[0]
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "no changes",
        {"pipeline_id": pipeline.id, "terminal_status": TaskStatus.no_changes.value},
    )
    store.finish_task(task.id, TaskStatus.no_changes, "no changes")
    assert StewardDaemon(config, store).finalize_terminal_task(task.id)
    return task


def test_live_rerun_manual_source_is_fresh_idempotent_and_archive_immutable(tmp_path: Path) -> None:
    dry_config = StewardConfig(
        repo_root=tmp_path / "repo",
        dry_run=True,
        local_codex_test_harness=True,
    )
    dry_config.repo_root.mkdir()
    store = TaskStore.create(dry_config.db_path, dry_run=True)
    source = _sealed_dry_run_source(dry_config, store)
    archive = dry_config.tasks_dir / source.id
    before = {path.relative_to(archive): path.read_bytes() for path in archive.rglob("*") if path.is_file()}

    live_config = replace(dry_config, dry_run=False)
    first = create_live_rerun(live_config, TaskStore.open(store.path), source.id)
    second = create_live_rerun(live_config, TaskStore.open(store.path), source.id)

    assert first.created is True
    assert second.created is False
    assert first.task is not None and second.task is not None
    assert first.task.id != source.id
    assert second.task.id == first.task.id
    assert first.task.dry_run_of_task_id == source.id
    assert first.task.spec.source == "rerun-live"
    assert first.task.spec.metadata[EXECUTION_MODE_METADATA_KEY] == ExecutionMode.live.value
    assert [
        path.relative_to(archive) for path in archive.rglob("*") if path.is_file()
    ]
    assert {path.relative_to(archive): path.read_bytes() for path in archive.rglob("*") if path.is_file()} == before
    assert len([item for item in store.pending_wakeups() if item.reason == "task.live_rerun"]) == 1


def test_live_rerun_rejects_all_stale_without_mutation(tmp_path: Path, monkeypatch) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(
        repo_root=tmp_path / "repo",
        dry_run=True,
        local_codex_test_harness=True,
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="stale-fingerprint",
        title="stale issue",
        payload={"issue_number": 1, "issue_url": "https://github.com/minhuw/coquic/issues/1"},
    )
    fetch = SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok)
    store.ingest_signal_collection(fetch, [item])
    saved = store.list_signal_items()[0]
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="feature",
            prompt="implement",
            metadata={"selected_signal_item_ids": [saved.id]},
        ),
    )
    store.mark_signal_items_planned([saved.id], planner_run_id="planner", task_id=source.id)
    before_tasks = [(task.id, task.status) for task in store.list_tasks()]
    before_wakeups = [(item.id, item.reason) for item in store.pending_wakeups()]
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "stale_signal_reason",
        lambda self, config, item: "source_closed",
    )

    with pytest.raises(LiveRerunRejected, match="all_source_signals_stale"):
        create_live_rerun(replace(config, dry_run=False), TaskStore.open(store.path), source.id)

    assert [(task.id, task.status) for task in store.list_tasks()] == before_tasks
    assert [(item.id, item.reason) for item in store.pending_wakeups()] == before_wakeups
    assert store.signal_items_by_id([saved.id])[0].planned_task_id == source.id


def test_live_rerun_mixed_signals_rebinds_only_actionable(tmp_path: Path, monkeypatch) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True)
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    items = [
        SignalItem(
            provider="github-issues:features",
            kind="github-issues.feature-request",
            fingerprint=f"mixed-{number}",
            title=f"issue {number}",
            payload={"issue_number": number, "issue_url": f"https://github.com/minhuw/coquic/issues/{number}"},
        )
        for number in (1, 2)
    ]
    store.ingest_signal_collection(
        SignalFetchRun(provider=items[0].provider, status=SignalFetchStatus.ok), items
    )
    saved = sorted(store.list_signal_items(), key=lambda item: item.payload["issue_number"])
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="features",
            prompt="implement",
            metadata={"selected_signal_item_ids": [item.id for item in saved]},
        ),
    )
    store.mark_signal_items_planned(
        [item.id for item in saved], planner_run_id="planner", task_id=source.id
    )
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "stale_signal_reason",
        lambda self, config, item: "source_closed" if item.payload["issue_number"] == 1 else None,
    )

    outcome = create_live_rerun(replace(config, dry_run=False), TaskStore.open(store.path), source.id)
    assert outcome.created is True
    assert outcome.retained_signal_count == 1
    assert outcome.stale_signal_count == 1
    assert outcome.task is not None
    assert outcome.task.spec.metadata["selected_signal_item_ids"] == [saved[1].id]
    assert store.signal_items_by_id([saved[0].id])[0].planned_task_id == source.id
    assert store.signal_items_by_id([saved[1].id])[0].planned_task_id == outcome.task.id
    event = [item for item in store.events(outcome.task.id) if item.kind == "task.live_rerun"][0]
    assert event.data["stale_reasons"] == {saved[0].id: "source_closed"}


def test_live_rerun_provider_error_fails_closed(tmp_path: Path, monkeypatch) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True)
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="provider-error",
        title="ci",
        payload={"run_id": "123", "run_attempt": 1},
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
    saved = store.list_signal_items()[0]
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.ci,
            worker=WorkerKind.ci_doctor,
            title="ci",
            prompt="fix",
            metadata={"selected_signal_item_ids": [saved.id]},
        ),
    )
    store.mark_signal_items_planned([saved.id], planner_run_id="planner", task_id=source.id)
    monkeypatch.setattr(
        providers.GitHubActionsCiProvider,
        "_latest_run",
        lambda self, config: (None, "network unavailable"),
    )

    with pytest.raises(LiveRerunRejected, match="signal_provider_unavailable"):
        create_live_rerun(replace(config, dry_run=False), TaskStore.open(store.path), source.id)


def test_live_rerun_atomic_allocation_rolls_back(monkeypatch, tmp_path: Path) -> None:
    config = StewardConfig(repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True)
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    source = _sealed_dry_run_source(config, store)
    before_ids = {task.id for task in store.list_tasks()}
    before_wakeups = {item.id for item in store.pending_wakeups()}
    original_edge = store.control_loop._edge

    def fail_after_lineage(connection, edge_type, source_id, target_id):
        if edge_type == "task_rerun":
            raise RuntimeError("injected rerun allocation failure")
        return original_edge(connection, edge_type, source_id, target_id)

    monkeypatch.setattr(store.control_loop, "_edge", fail_after_lineage)
    with pytest.raises(RuntimeError, match="injected rerun allocation failure"):
        store.allocate_live_rerun(source.id)
    assert {task.id for task in store.list_tasks()} == before_ids
    assert {item.id for item in store.pending_wakeups()} == before_wakeups


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

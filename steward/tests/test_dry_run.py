from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.config import (
    StewardConfig,
    StewardDeploymentConfig,
    load_config,
)
from coquic_steward.core.models import (
    EffectActionKind,
    EffectDecisionKind,
    EffectProposal,
    EffectResult,
    DRY_RUN_OF_TASK_ID_METADATA_KEY,
    EFFECT_RESULT_METADATA_KEY,
    EXECUTION_MODE_METADATA_KEY,
    LEGACY_EFFECT_RESULT_METADATA_KEY,
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
    TickResult,
    create_live_rerun,
)
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    PublicationGeneration,
    PublicationOperationStatus,
    PublicationState,
)
from coquic_steward.storage import TaskStore
from coquic_steward.storage.sqlite import DaemonPublicationAuthority


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

    path = tmp_path / "invalid-bool.toml"
    path.write_text('[steward]\ndry_run = "false"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="dry_run must be a boolean"):
        load_config(repo_root=repo, config_path=path)


def test_daemon_publication_authority_is_durable_and_fail_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "daemon-authority.sqlite"
    store = TaskStore.create(database, dry_run=False)
    store.claim_daemon_instance(
        "daemon-one",
        lifecycle="running",
        state={
            "publication_execution_mode": ExecutionMode.dry_run.value,
            "publication_claim_id": "caller-selected",
        },
    )
    state = store.get_daemon_state()
    assert state is not None
    assert state["publication_execution_mode"] == ExecutionMode.live.value
    assert state["publication_claim_id"] != "caller-selected"
    authority = store.get_daemon_publication_authority("daemon-one")
    assert authority is not None

    with store.daemon_publication_admission(
        authority,
        action=EffectActionKind.publication_overhead.value,
        action_id="publication-overhead:test",
        target="cloudflare-d1",
    ) as decision:
        assert decision.allowed

    foreign = DaemonPublicationAuthority("foreign", authority.claim_id, authority.mode)
    with store.daemon_publication_admission(
        foreign,
        action=EffectActionKind.publication_overhead.value,
        action_id="publication-overhead:foreign",
        target="cloudflare-d1",
    ) as decision:
        assert not decision.allowed

    successor = TaskStore.open(database, dry_run=False)
    successor.claim_daemon_instance("daemon-two", lifecycle="running")
    with store.daemon_publication_admission(
        authority,
        action=EffectActionKind.publication_overhead.value,
        action_id="publication-overhead:stale",
        target="cloudflare-d1",
    ) as decision:
        assert not decision.allowed

    successor.set_daemon_lifecycle("stopped", instance_id="daemon-two")
    with successor.daemon_publication_admission(
        successor.get_daemon_publication_authority("daemon-two"),
        action=EffectActionKind.publication_overhead.value,
        action_id="publication-overhead:stopped",
        target="cloudflare-d1",
    ) as decision:
        assert not decision.allowed

    dry_run = TaskStore.open(database, dry_run=True)
    assert dry_run.get_daemon_publication_authority() is None
    assert dry_run.get_daemon_state()["publication_execution_mode"] == ExecutionMode.dry_run.value
    with store.daemon_publication_admission(
        authority,
        action=EffectActionKind.publication_overhead.value,
        action_id="publication-overhead:dry-run",
        target="cloudflare-d1",
    ) as decision:
        assert not decision.allowed


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


@pytest.mark.parametrize(
    "reserved_key",
    [
        EXECUTION_MODE_METADATA_KEY,
        EFFECT_RESULT_METADATA_KEY,
        LEGACY_EFFECT_RESULT_METADATA_KEY,
    ],
)
def test_manual_allocation_drops_store_owned_metadata(
    tmp_path: Path, reserved_key: str
) -> None:
    store = TaskStore.create(tmp_path / "manual-allocation.sqlite", dry_run=True)
    task, created = store.add_task(
        _spec(**{reserved_key: "live" if reserved_key == EXECUTION_MODE_METADATA_KEY else "applied"})
    )

    assert created
    assert task.spec.metadata[EXECUTION_MODE_METADATA_KEY] == ExecutionMode.dry_run.value
    assert EFFECT_RESULT_METADATA_KEY not in task.spec.metadata
    assert LEGACY_EFFECT_RESULT_METADATA_KEY not in task.spec.metadata
    assert store.effect_result(task.id) is None
    store.engine.dispose()


def test_planner_allocation_drops_reserved_metadata_and_preserves_dedupe(
    tmp_path: Path,
) -> None:
    store = TaskStore.create(tmp_path / "planner-allocation.sqlite", dry_run=False)
    dedupe_key = "planner-owned-allocation"

    def allocate(run_id: str, spec: TaskSpec):
        store.control_loop.claim_planner_run(run_id, [])
        committed = store.commit_planner_decision(
            run_id,
            planned=[(spec, dedupe_key)],
            planner_dispositions=[
                SimpleNamespace(
                    outcome="accepted",
                    reason_code="accepted",
                    dedupe_key=dedupe_key,
                    signal_ids=[],
                    proposal={"title": spec.title},
                )
            ],
            consumed_item_ids=[],
            selected_item_ids_by_dedupe={},
            canonical_signal_by_item={},
            state="succeeded",
            result={},
            diagnostics={},
            retry_after=None,
            artifact_sources={},
        )
        return committed["records"][0][0]

    first = allocate(
        "planner-allocation-first",
        _spec(
            **{
                EXECUTION_MODE_METADATA_KEY: ExecutionMode.dry_run.value,
                EFFECT_RESULT_METADATA_KEY: EffectResult.not_applicable.value,
                LEGACY_EFFECT_RESULT_METADATA_KEY: EffectResult.applied.value,
                "ordinary_metadata": "first",
            }
        ),
    )
    stored_first = store.get(first.id)
    assert store.task_execution_mode(first.id) is ExecutionMode.live
    assert store.effect_result(first.id) is None
    assert stored_first.spec.metadata["ordinary_metadata"] == "first"
    assert EFFECT_RESULT_METADATA_KEY not in stored_first.spec.metadata
    assert LEGACY_EFFECT_RESULT_METADATA_KEY not in stored_first.spec.metadata

    store.record_effect_applied(
        first.id,
        action=EffectActionKind.git_push.value,
        action_id="planner-allocation-applied",
    )
    assert store.finalize_effect_result(first.id) is EffectResult.applied

    duplicate = allocate(
        "planner-allocation-duplicate",
        _spec(
            **{
                EFFECT_RESULT_METADATA_KEY: EffectResult.not_applicable.value,
                "ordinary_metadata": "duplicate must not rewrite",
            }
        ),
    )
    assert duplicate.id == first.id
    persisted = store.get(first.id)
    assert persisted.spec.metadata["ordinary_metadata"] == "first"
    assert store.effect_result(first.id) is EffectResult.applied


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


def test_exposed_publication_reconciles_after_dry_run_restart(
    repo: Path, tmp_path: Path
) -> None:
    config = StewardConfig(
        repo_root=repo,
        dry_run=True,
        local_codex_test_harness=True,
        deployment=StewardDeploymentConfig(home=tmp_path / "coquic-home"),
    )
    config.ensure_dirs()
    database = tmp_path / "exposed.sqlite"
    live = TaskStore.create(database, dry_run=False)
    task, _ = live.add_task(_spec())
    pipeline = live.list_pipelines(task.id)[0]
    live.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "terminal publication",
        {"pipeline_id": pipeline.id, "terminal_status": TaskStatus.failed.value},
    )
    live.transition_pipeline(pipeline.id, TaskStatus.failed.value, phase="complete")
    live.finish_task(task.id, TaskStatus.failed, "terminal publication")
    identity = GenerationIdentity(task.id, "terminal-publication")
    generation = PublicationGeneration(
        publication_id=identity.publication_id,
        task_id=task.id,
        run_id="run-terminal-publication",
        generation_boundary=identity.generation_boundary,
        metadata_digest="a" * 64,
        idempotency_key=identity.idempotency_key,
    )
    assert live.enqueue_publication(generation).status is PublicationOperationStatus.enqueued
    exposed_at = (
        datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
    )
    with live.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE publication_generations SET state='exposed',"
            "exposed_at=:exposed_at,updated_at=:exposed_at "
            "WHERE publication_id=:publication_id",
            {
                "exposed_at": exposed_at,
                "publication_id": generation.publication_id,
            },
        )
    live._finalize_exact_store()

    restarted = TaskStore.open(database, dry_run=True)
    daemon = StewardDaemon(config, restarted)

    assert restarted.task_execution_mode(task.id) is ExecutionMode.dry_run
    assert restarted.effect_result(task.id) is None
    with restarted.effect_admission(
        task.id,
        action=EffectActionKind.publication_enqueue.value,
        action_id="publication-enqueue:later-run",
        target=task.id,
        payload={"run_id": "later-run"},
    ) as decision:
        assert decision.proposal_required
    assert daemon.finalize_terminal_task(task.id) is True
    assert restarted.effect_result(task.id) is EffectResult.applied
    assert restarted.get_publication_generation(generation.publication_id).state is PublicationState.exposed
    assert [event.kind for event in restarted.events(task.id) if event.kind.startswith("effect.")] == [
        "effect.proposed",
        "effect.applied",
        "effect.result.finalized",
    ]
    assert [
        event.data.get("actionId")
        for event in restarted.events(task.id)
        if event.kind == "effect.applied"
    ] == [f"publication-d1-expose:{generation.publication_id}"]


@pytest.mark.parametrize("startup_dry_run", [False, True])
def test_taskless_publication_enqueue_is_side_effect_free(
    tmp_path: Path, startup_dry_run: bool
) -> None:
    store = TaskStore.create(
        tmp_path / f"taskless-{startup_dry_run}.sqlite",
        dry_run=startup_dry_run,
    )
    identity = GenerationIdentity("missing-task", "boundary-taskless")
    generation = PublicationGeneration(
        publication_id=identity.publication_id,
        task_id=identity.task_id,
        run_id="run-taskless",
        generation_boundary=identity.generation_boundary,
        metadata_digest="a" * 64,
        idempotency_key=identity.idempotency_key,
    )
    changes: list[object] = []
    store.on_change = lambda: changes.append(object())

    result = store.enqueue_publication(generation)

    assert result.status is PublicationOperationStatus.precondition
    assert store.get_publication_generation(generation.publication_id) is None
    assert store.list_publication_generations() == []
    assert store.get_publication_health().queued_count == 0
    assert changes == []


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


def test_live_rerun_preserves_integration_source_task_id(tmp_path: Path) -> None:
    from coquic_steward.execution.executor import StewardExecutor

    config = StewardConfig(
        repo_root=tmp_path / "repo",
        dry_run=True,
        local_codex_test_harness=True,
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    integration_source, _ = store.add_task(_spec(title="integration source"))
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="integration rerun source",
            prompt="integrate the source task",
            metadata={"source_task_id": integration_source.id},
        ),
    )

    live_config = replace(config, dry_run=False)
    outcome = create_live_rerun(live_config, TaskStore.open(store.path), source.id)

    assert outcome.task is not None
    assert outcome.task.spec.metadata["source_task_id"] == integration_source.id
    executor = StewardExecutor(
        live_config,
        TaskStore.open(store.path, dry_run=False),
        runner=SimpleNamespace(),
    )
    resolved = executor._source_task_for_integration(outcome.task)
    assert resolved is not None
    assert resolved.id == integration_source.id


def test_store_rejects_signal_less_non_manual_live_rerun_without_mutation(
    tmp_path: Path,
) -> None:
    config = StewardConfig(
        repo_root=tmp_path / "repo",
        dry_run=True,
        local_codex_test_harness=True,
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="planner source",
            prompt="implement the planned feature",
            source="planner",
        ),
    )
    live_store = TaskStore.open(store.path, dry_run=False)
    before_tasks = [(task.id, task.status) for task in live_store.list_tasks()]
    before_events = [
        (event.task_id, event.kind, event.data)
        for task in live_store.list_tasks()
        for event in live_store.events(task.id)
    ]
    before_wakeups = [(item.id, item.reason) for item in live_store.pending_wakeups()]
    with live_store.engine.connect() as connection:
        before_edges = connection.exec_driver_sql(
            "SELECT edge_type, source_id, target_id FROM control_loop_edges "
            "ORDER BY edge_id"
        ).fetchall()

    with pytest.raises(ValueError, match="selected signals"):
        live_store.allocate_live_rerun(source.id)

    assert [(task.id, task.status) for task in live_store.list_tasks()] == before_tasks
    assert [
        (event.task_id, event.kind, event.data)
        for task in live_store.list_tasks()
        for event in live_store.events(task.id)
    ] == before_events
    assert [(item.id, item.reason) for item in live_store.pending_wakeups()] == before_wakeups
    with live_store.engine.connect() as connection:
        after_edges = connection.exec_driver_sql(
            "SELECT edge_type, source_id, target_id FROM control_loop_edges "
            "ORDER BY edge_id"
        ).fetchall()
    assert after_edges == before_edges


def test_store_allows_manual_signal_less_live_rerun(tmp_path: Path) -> None:
    config = StewardConfig(
        repo_root=tmp_path / "repo",
        dry_run=True,
        local_codex_test_harness=True,
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    source = _sealed_dry_run_source(config, store)
    live_store = TaskStore.open(store.path, dry_run=False)

    allocation = live_store.allocate_live_rerun(source.id)

    assert allocation.created is True
    assert allocation.task.spec.metadata.get("selected_signal_item_ids") is None
    assert allocation.wakeup is not None
    assert allocation.wakeup.data["retained_signal_count"] == 0
    assert allocation.wakeup.data["stale_signal_count"] == 0


def test_live_rerun_duplicate_skips_provider_revalidation(
    tmp_path: Path, monkeypatch
) -> None:
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
        fingerprint="duplicate-provider",
        title="feature",
        payload={"issue_number": 17},
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    provider_calls: list[str] = []
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "stale_signal_reason",
        lambda self, config, item: provider_calls.append("stale") or None,
    )
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "revalidated_signal_item",
        lambda self, config, item, **kwargs: provider_calls.append("refresh") or item,
    )

    live_config = replace(config, dry_run=False)
    first = create_live_rerun(live_config, TaskStore.open(store.path), source.id)
    assert first.created is True
    assert provider_calls == ["stale", "refresh"]

    provider_calls.clear()
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "stale_signal_reason",
        lambda self, config, item: provider_calls.append("unavailable")
        or "provider_unavailable",
    )
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "revalidated_signal_item",
        lambda *args, **kwargs: pytest.fail("duplicate contacted the provider"),
    )

    second = create_live_rerun(live_config, TaskStore.open(store.path), source.id)

    assert second.created is False
    assert second.task is not None and first.task is not None
    assert second.task.id == first.task.id
    assert second.retained_signal_count == first.retained_signal_count == 1
    assert second.stale_signal_count == first.stale_signal_count == 0
    assert provider_calls == []


def test_live_rerun_race_reports_durable_winning_counts(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.orchestration.daemon as daemon

    config = StewardConfig(
        repo_root=tmp_path / "repo",
        dry_run=True,
        local_codex_test_harness=True,
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    items = [
        SignalItem(
            provider="github-issues:features",
            kind="github-issues.feature-request",
            fingerprint=f"race-{number}",
            title=f"issue {number}",
            payload={"issue_number": number},
        )
        for number in (1, 2, 3)
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
            title="race source",
            prompt="implement",
            metadata={"selected_signal_item_ids": [item.id for item in saved]},
        ),
    )
    store.mark_signal_items_planned(
        [item.id for item in saved], planner_run_id="race-planner", task_id=source.id
    )
    archive = config.tasks_dir / source.id
    archive_before = {
        path.relative_to(archive): path.read_bytes()
        for path in archive.rglob("*")
        if path.is_file()
    }
    source_record_before = store.get(source.id)
    source_before = (
        source_record_before.status,
        source_record_before.spec.source,
        dict(source_record_before.spec.metadata),
        source_record_before.dry_run_of_task_id,
    )

    live_config = replace(config, dry_run=False)
    active_lookup_barrier = threading.Barrier(2)
    revalidation_barrier = threading.Barrier(2)
    coordination_lock = threading.Lock()
    revalidation_number = 0
    timeline: list[str] = []
    outcomes = []
    errors: list[Exception] = []

    original_active_lookup = TaskStore.active_live_rerun

    def synchronized_active_lookup(self, source_task_id):
        existing = original_active_lookup(self, source_task_id)
        with coordination_lock:
            timeline.append("active:hit" if existing is not None else "active:miss")
        active_lookup_barrier.wait(timeout=5)
        return existing

    monkeypatch.setattr(TaskStore, "active_live_rerun", synchronized_active_lookup)

    def fake_revalidation(_config, linked, *, strict):
        nonlocal revalidation_number
        with coordination_lock:
            number = revalidation_number
            revalidation_number += 1
            timeline.append("provider")
        assert strict is True
        assert {item.id for item in linked} == {item.id for item in saved}
        revalidation_barrier.wait(timeout=5)
        selected = [saved[0]] if number == 0 else [saved[0], saved[1]]
        stale_reasons = {} if number == 0 else {saved[2].id: "source_closed"}
        return SimpleNamespace(
            actionable=selected,
            stale_reasons=stale_reasons,
            refreshed={item.id: item for item in selected},
        )

    monkeypatch.setattr(daemon, "revalidate_signal_items_with_context", fake_revalidation)
    original_allocate = TaskStore.allocate_live_rerun

    def recording_allocate(self, *args, **kwargs):
        allocation = original_allocate(self, *args, **kwargs)
        with coordination_lock:
            timeline.append("allocation:created" if allocation.created else "allocation:duplicate")
        return allocation

    monkeypatch.setattr(TaskStore, "allocate_live_rerun", recording_allocate)

    def invoke(slot: int) -> None:
        thread_store = None
        try:
            thread_store = TaskStore.open(store.path, dry_run=False)
            outcome = create_live_rerun(live_config, thread_store, source.id)
            with coordination_lock:
                outcomes.append((slot, outcome))
        except Exception as exc:
            with coordination_lock:
                errors.append(exc)
        finally:
            if thread_store is not None:
                thread_store.engine.dispose()

    threads = [
        threading.Thread(target=invoke, args=(slot,), daemon=True)
        for slot in (0, 1)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert not errors, errors
    assert len(outcomes) == 2
    assert revalidation_number == 2

    outcome_values = [outcome for _slot, outcome in outcomes]
    winners = [outcome for outcome in outcome_values if outcome.created]
    losers = [outcome for outcome in outcome_values if not outcome.created]
    assert len(winners) == 1
    assert len(losers) == 1
    winner = winners[0]
    loser = losers[0]
    assert winner.task is not None and loser.task is not None
    assert loser.task.id == winner.task.id

    final_store = TaskStore.open(store.path, dry_run=False)
    try:
        descendants = final_store.active_live_descendants(source.id)
        assert [task.id for task in descendants] == [winner.task.id]
        rerun_events = [
            event
            for event in final_store.events(winner.task.id)
            if event.kind == "task.live_rerun"
        ]
        assert len(rerun_events) == 1
        event = rerun_events[0]
        winning_counts = (
            len(event.data["selected_signal_ids"]),
            len(event.data["stale_signal_ids"]),
        )
        assert (
            winner.retained_signal_count,
            winner.stale_signal_count,
        ) == winning_counts
        assert (
            loser.retained_signal_count,
            loser.stale_signal_count,
        ) == winning_counts
        assert len(
            [item for item in final_store.pending_wakeups() if item.reason == "task.live_rerun"]
        ) == 1

        source_after = final_store.get(source.id)
        assert (
            source_after.status,
            source_after.spec.source,
            source_after.spec.metadata,
            source_after.dry_run_of_task_id,
        ) == source_before
    finally:
        final_store.engine.dispose()

    assert {
        path.relative_to(archive): path.read_bytes()
        for path in archive.rglob("*")
        if path.is_file()
    } == archive_before
    duplicate_index = timeline.index("allocation:duplicate")
    assert timeline.count("active:miss") == 2
    assert timeline[:duplicate_index].count("provider") == 2
    assert "provider" not in timeline[duplicate_index + 1 :]


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
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "revalidated_signal_item",
        lambda self, config, item, **kwargs: item,
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
    assert {
        item.id for item in store.selected_signal_items_for_task(source.id)
    } == {saved[0].id, saved[1].id}


def test_live_rerun_does_not_copy_historical_signal_payload(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True)
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="historical-payload",
        title="OLD TITLE FROM DRY RUN",
        summary="OLD BODY FROM DRY RUN",
        payload={
            "issue_number": 7,
            "issue_title": "OLD TITLE FROM DRY RUN",
            "body_excerpt": "OLD BODY FROM DRY RUN",
        },
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
    saved = store.list_signal_items()[0]
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="feature",
            prompt="implement",
            metadata={
                "selected_signal_item_ids": [saved.id],
                "source_context": {
                    "selected_signal_item_ids": [saved.id],
                    "selected_signal_items": [saved.model_dump(mode="json")],
                },
            },
        ),
    )
    store.mark_signal_items_planned([saved.id], planner_run_id="planner", task_id=source.id)
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "stale_signal_reason",
        lambda self, config, item: None,
    )
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "revalidated_signal_item",
        lambda self, config, item, **kwargs: item.model_copy(
            update={
                "title": "CURRENT TITLE",
                "summary": "CURRENT SUMMARY",
                "payload": {
                    **item.payload,
                    "issue_title": "CURRENT TITLE",
                    "body_excerpt": "CURRENT BODY",
                },
            },
            deep=True,
        ),
    )

    outcome = create_live_rerun(
        replace(config, dry_run=False), TaskStore.open(store.path), source.id
    )

    assert outcome.task is not None
    selected = outcome.task.spec.metadata["source_context"]["selected_signal_items"][0]
    assert selected["payload"]["issue_title"] == "CURRENT TITLE"
    assert selected["payload"]["body_excerpt"] == "CURRENT BODY"
    serialized = json.dumps(outcome.task.spec.metadata, sort_keys=True)
    assert "OLD TITLE FROM DRY RUN" not in serialized
    assert "OLD BODY FROM DRY RUN" not in serialized


def test_live_rerun_revalidates_before_dispatch_after_issue_closes(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="dispatch-issue-42",
        title="Implement issue 42",
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
        },
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    current_issue = {
        "number": 42,
        "title": "Current issue",
        "url": "https://github.com/minhuw/coquic/issues/42",
        "body": "Current body",
        "labels": [{"name": "steward:enhancement"}],
        "author": {"login": "maintainer"},
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-02T00:00:00Z",
        "state": "OPEN",
    }
    monkeypatch.setattr(
        providers,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, stdout=json.dumps(current_issue), stderr=""
        ),
    )
    outcome = create_live_rerun(
        replace(config, dry_run=False), TaskStore.open(store.path), source.id
    )
    assert outcome.task is not None

    provider_calls: list[list[str]] = []
    closed_issue = {**current_issue, "state": "CLOSED", "labels": []}

    def closed_provider(command, **kwargs):
        provider_calls.append(command)
        return SimpleNamespace(ok=True, stdout=json.dumps(closed_issue), stderr="")

    monkeypatch.setattr(providers, "run_command", closed_provider)
    daemon = StewardDaemon(replace(config, dry_run=False), TaskStore.open(store.path))
    worker_calls: list[str] = []
    daemon.executor.advance_once = lambda task_id: worker_calls.append(task_id)

    result = TickResult()
    daemon._dispatch_queued(result, plan=False, max_dispatch=1)
    assert result.dispatched == 0
    assert result.skipped == 1
    assert worker_calls == []
    assert provider_calls == [
        [
            "gh",
            "issue",
            "view",
            "42",
            "-R",
            daemon.config.github_repository,
            "--json",
            "number,title,url,body,labels,author,createdAt,updatedAt,state",
        ]
    ]
    assert TaskStore.open(store.path).get(outcome.task.id).status == TaskStatus.queued

    import coquic_steward.execution.executor as executor_module
    from coquic_steward.execution.executor import IntegrationTranscript

    monkeypatch.setattr(
        executor_module,
        "run_command",
        lambda *args, **kwargs: pytest.fail("stale rerun reached an external effect"),
    )
    with pytest.raises(RuntimeError, match="live rerun signal revalidation failed"):
        daemon.executor._update_feature_issues_after_push(
            outcome.task,
            outcome.task,
            "a" * 40,
            IntegrationTranscript(tmp_path / "integration.txt"),
        )
    assert len(provider_calls) == 2


def test_live_rerun_dispatch_uses_newly_hydrated_context(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="dispatch-refresh-42",
        title="Old issue title",
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
        },
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    old_issue = {
        "number": 42,
        "title": "Old issue title",
        "url": "https://github.com/minhuw/coquic/issues/42",
        "body": "Old body",
        "labels": [{"name": "steward:enhancement"}],
        "author": {"login": "maintainer"},
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-02T00:00:00Z",
        "state": "OPEN",
    }
    new_issue = {**old_issue, "title": "New issue title", "body": "New body"}
    response_count = 0

    def current_provider(*args, **kwargs):
        nonlocal response_count
        response_count += 1
        response = old_issue if response_count == 1 else new_issue
        return SimpleNamespace(ok=True, stdout=json.dumps(response), stderr="")

    monkeypatch.setattr(providers, "run_command", current_provider)
    outcome = create_live_rerun(
        replace(config, dry_run=False), TaskStore.open(store.path), source.id
    )
    assert outcome.task is not None

    observed: dict[str, object] = {}
    daemon = StewardDaemon(replace(config, dry_run=False), TaskStore.open(store.path))

    def observe_context(task_id: str):
        current = TaskStore.open(store.path).get(task_id)
        selected = current.spec.metadata["source_context"]["selected_signal_items"][0]
        observed["title"] = selected["payload"]["issue_title"]
        observed["body"] = selected["payload"]["body_excerpt"]
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

    daemon.executor.advance_once = observe_context
    result = TickResult()
    daemon._dispatch_queued(result, plan=False, max_dispatch=1)

    assert observed == {"title": "New issue title", "body": "New body"}
    assert result.dispatched == 1
    assert result.skipped == 0


def test_live_rerun_hydrates_current_feature_context_for_post_push_effects(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.execution.executor as executor_module
    import coquic_steward.signals.providers as providers
    from coquic_steward.execution.executor import IntegrationTranscript, StewardExecutor

    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="issue-42-identity",
        title="OLD TITLE",
        summary="OLD SUMMARY",
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
            "issue_title": "OLD TITLE",
            "body_excerpt": "OLD BODY",
        },
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    current_issue = {
        "number": 42,
        "title": "CURRENT TITLE",
        "url": "https://github.com/minhuw/coquic/issues/42",
        "body": "CURRENT BODY",
        "labels": [{"name": "steward:enhancement"}],
        "author": {"login": "maintainer"},
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-02T00:00:00Z",
        "state": "OPEN",
    }
    monkeypatch.setattr(
        providers,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, stdout=json.dumps(current_issue), stderr=""
        ),
    )

    outcome = create_live_rerun(
        replace(config, dry_run=False), TaskStore.open(store.path), source.id
    )
    assert outcome.task is not None
    selected = outcome.task.spec.metadata["source_context"]["selected_signal_items"][0]
    assert selected["payload"]["issue_title"] == "CURRENT TITLE"
    assert selected["payload"]["body_excerpt"] == "CURRENT BODY"
    serialized = json.dumps(outcome.task.spec.metadata, sort_keys=True)
    assert "OLD TITLE" not in serialized
    assert "OLD BODY" not in serialized

    commands: list[list[str]] = []
    monkeypatch.setattr(
        executor_module,
        "run_command",
        lambda command, **kwargs: commands.append(command)
        or SimpleNamespace(ok=True, stdout="", stderr=""),
    )
    executor = StewardExecutor(replace(config, dry_run=False), TaskStore.open(store.path))
    transcript = IntegrationTranscript(tmp_path / "integration.txt")
    executor._update_feature_issues_after_push(
        outcome.task, outcome.task, "a" * 40, transcript
    )
    assert [command[:4] for command in commands] == [
        ["gh", "issue", "comment", "42"],
        ["gh", "issue", "close", "42"],
    ]
    assert any(
        event.kind == "github.issue_closed"
        for event in TaskStore.open(store.path).events(outcome.task.id)
    )


def test_live_rerun_rejects_partial_hydration_without_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="partial-hydration",
        title="feature",
        payload={"issue_number": 42},
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    before_events = [(event.kind, event.data) for event in store.events(source.id)]
    before_wakeups = [(item.id, item.reason) for item in store.pending_wakeups()]
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "stale_signal_reason",
        lambda self, config, item: None,
    )
    monkeypatch.setattr(
        providers.GitHubFeatureIssuesProvider,
        "revalidated_signal_item",
        lambda self, config, item, **kwargs: None,
    )

    with pytest.raises(LiveRerunRejected, match="signal_provider_unavailable"):
        create_live_rerun(replace(config, dry_run=False), TaskStore.open(store.path), source.id)

    assert [(task.id, task.status) for task in store.list_tasks()] == before_tasks
    assert [(event.kind, event.data) for event in store.events(source.id)] == before_events
    assert [(item.id, item.reason) for item in store.pending_wakeups()] == before_wakeups
    assert store.signal_items_by_id([saved.id])[0].planned_task_id == source.id


def test_live_rerun_rejects_incomplete_feature_response_without_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True)
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="incomplete-provider-response",
        title="feature",
        payload={"issue_number": 8},
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    before_events = [(event.task_id, event.kind, event.data) for event in store.events(source.id)]
    before_wakeups = [(wakeup.id, wakeup.reason) for wakeup in store.pending_wakeups()]
    monkeypatch.setattr(
        providers,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, stdout=json.dumps({"state": "open"}), stderr=""
        ),
    )

    with pytest.raises(LiveRerunRejected, match="signal_provider_unavailable"):
        create_live_rerun(
            replace(config, dry_run=False), TaskStore.open(store.path), source.id
        )

    assert [(task.id, task.status) for task in store.list_tasks()] == before_tasks
    assert [(event.task_id, event.kind, event.data) for event in store.events(source.id)] == before_events
    assert [(wakeup.id, wakeup.reason) for wakeup in store.pending_wakeups()] == before_wakeups
    assert store.signal_items_by_id([saved.id])[0].planned_task_id == source.id


@pytest.mark.parametrize(
    "response",
    [
        {"state": "open"},
        {
            "number": 43,
            "html_url": "https://github.com/minhuw/coquic/security/code-scanning/43",
            "state": "open",
            "rule": {"id": "cpp/use-after-free", "name": "Use after free"},
            "most_recent_instance": {"location": {"path": "src/main.cpp"}},
        },
        {
            "number": 42,
            "html_url": "https://github.com/other/repo/security/code-scanning/42",
            "url": "https://api.github.com/repos/other/repo/code-scanning/alerts/42",
            "state": "open",
            "rule": {"id": "cpp/use-after-free", "name": "Use after free"},
            "most_recent_instance": {"location": {"path": "src/main.cpp"}},
        },
    ],
)
def test_live_rerun_rejects_incomplete_or_mismatched_codeql_response(
    tmp_path: Path, monkeypatch, response: dict[str, object]
) -> None:
    import coquic_steward.signals.providers as providers

    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="codeql-42",
        title="CodeQL alert 42",
        links=[
            {
                "label": "Open alert",
                "url": "https://github.com/minhuw/coquic/security/code-scanning/42",
            }
        ],
        payload={"alert_number": 42},
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
    saved = store.list_signal_items()[0]
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="CodeQL",
            prompt="fix CodeQL",
            metadata={"selected_signal_item_ids": [saved.id]},
        ),
    )
    store.mark_signal_items_planned([saved.id], planner_run_id="planner", task_id=source.id)
    before_tasks = [(task.id, task.status) for task in store.list_tasks()]
    before_wakeups = [(wakeup.id, wakeup.reason) for wakeup in store.pending_wakeups()]
    monkeypatch.setattr(
        providers,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, stdout=json.dumps(response), stderr=""
        ),
    )

    with pytest.raises(LiveRerunRejected, match="signal_provider_unavailable"):
        create_live_rerun(replace(config, dry_run=False), TaskStore.open(store.path), source.id)

    assert [(task.id, task.status) for task in store.list_tasks()] == before_tasks
    assert [(wakeup.id, wakeup.reason) for wakeup in store.pending_wakeups()] == before_wakeups
    assert store.signal_items_by_id([saved.id])[0].planned_task_id == source.id


def test_strict_codeql_hydration_accepts_matching_alert(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.signals.collector import revalidate_signal_items_with_context
    import coquic_steward.signals.providers as providers

    item = SignalItem(
        id="codeql-42",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="codeql-42",
        title="CodeQL alert 42",
        links=[
            {
                "label": "Open alert",
                "url": "https://github.com/minhuw/coquic/security/code-scanning/42",
            }
        ],
        payload={"alert_number": 42},
    )
    response = {
        "number": 42,
        "html_url": "https://github.com/minhuw/coquic/security/code-scanning/42",
        "url": "https://api.github.com/repos/minhuw/coquic/code-scanning/alerts/42",
        "state": "open",
        "rule": {"id": "cpp/use-after-free", "name": "Use after free"},
        "most_recent_instance": {
            "location": {"path": "src/main.cpp", "region": {"start_line": 12}}
        },
    }
    monkeypatch.setattr(
        providers,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, stdout=json.dumps(response), stderr=""
        ),
    )

    result = revalidate_signal_items_with_context(config, [item], strict=True)

    assert result.stale_reasons == {}
    assert [current.id for current in result.actionable] == [item.id]
    assert result.refreshed[item.id].payload["alert_number"] == 42
    assert result.refreshed[item.id].payload["rule_id"] == "cpp/use-after-free"


def test_strict_feature_issue_hydration_rejects_foreign_repository(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.signals.collector import revalidate_signal_items_with_context
    import coquic_steward.signals.providers as providers

    item = SignalItem(
        id="feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="feature-42",
        title="Feature issue 42",
        links=[
            {
                "label": "Open GitHub issue",
                "url": "https://github.com/minhuw/coquic/issues/42",
            }
        ],
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
        },
    )
    response = {
        "number": 42,
        "url": "https://github.com/other/repo/issues/42",
        "state": "OPEN",
        "labels": [{"name": "steward:feature"}],
    }
    monkeypatch.setattr(
        providers,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, stdout=json.dumps(response), stderr=""
        ),
    )

    result = revalidate_signal_items_with_context(config, [item], strict=True)

    assert result.actionable == []
    assert result.stale_reasons == {item.id: "provider_unavailable"}
    assert result.refreshed == {}


def test_live_rerun_drops_source_artifact_aliases_from_metadata_and_prompt(
    tmp_path: Path,
) -> None:
    from coquic_steward.agents import render_worker_prompt

    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    source = _sealed_dry_run_source(
        config,
        store,
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="artifact source",
            prompt="use only the canonical specification",
            metadata={
                "source_patch_path": "/old/source.patch",
                "source_worktree_path": "/old/source-worktree",
                "source_commit": "old-commit",
                "source_commit_sha": "old-sha",
                "source_commit_path": "/old/commit",
                "patch_path": "/old/patch",
                "worktree_path": "/old/worktree",
                "commit": "old-commit",
                "benign_metadata": "retain me",
            },
        ),
    )

    outcome = create_live_rerun(
        replace(config, dry_run=False), TaskStore.open(store.path), source.id
    )
    assert outcome.task is not None
    descendant = TaskStore.open(store.path).get(outcome.task.id)
    metadata = descendant.spec.metadata
    for key in (
        "source_patch_path",
        "source_worktree_path",
        "source_commit",
        "source_commit_sha",
        "source_commit_path",
        "patch_path",
        "worktree_path",
        "commit",
    ):
        assert key not in metadata
    assert metadata["benign_metadata"] == "retain me"
    prompt = render_worker_prompt(descendant, replace(config, dry_run=False))
    assert "/old/source.patch" not in prompt
    assert "/old/source-worktree" not in prompt
    assert "old-commit" not in prompt
    assert "old-sha" not in prompt


def test_live_rerun_rejects_forged_signal_owner_lineage(
    tmp_path: Path,
) -> None:
    config = StewardConfig(repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True)
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    item = SignalItem(
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="forged-owner",
        title="feature",
        payload={"issue_number": 9},
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
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
    spoof, _ = store.add_task(
        _spec(**{DRY_RUN_OF_TASK_ID_METADATA_KEY: source.id})
    )
    store.mark_signal_items_planned([saved.id], planner_run_id="spoof", task_id=spoof.id)
    before_tasks = [(task.id, task.status) for task in store.list_tasks()]
    before_wakeups = [(wakeup.id, wakeup.reason) for wakeup in store.pending_wakeups()]

    with pytest.raises(LiveRerunRejected, match="source_signal_links_invalid"):
        create_live_rerun(
            replace(config, dry_run=False), TaskStore.open(store.path), source.id
        )

    assert [(task.id, task.status) for task in store.list_tasks()] == before_tasks
    assert [(wakeup.id, wakeup.reason) for wakeup in store.pending_wakeups()] == before_wakeups
    assert store.signal_items_by_id([saved.id])[0].planned_task_id == spoof.id


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
    live_store = TaskStore.open(store.path, dry_run=False)
    before_ids = {task.id for task in live_store.list_tasks()}
    before_wakeups = {item.id for item in live_store.pending_wakeups()}
    original_edge = live_store.control_loop._edge

    def fail_after_lineage(connection, edge_type, source_id, target_id):
        if edge_type == "task_rerun":
            raise RuntimeError("injected rerun allocation failure")
        return original_edge(connection, edge_type, source_id, target_id)

    monkeypatch.setattr(live_store.control_loop, "_edge", fail_after_lineage)
    with pytest.raises(RuntimeError, match="injected rerun allocation failure"):
        live_store.allocate_live_rerun(source.id)
    assert {task.id for task in live_store.list_tasks()} == before_ids
    assert {item.id for item in live_store.pending_wakeups()} == before_wakeups


def test_store_rejects_live_rerun_under_dry_run_startup_without_mutation(
    tmp_path: Path,
) -> None:
    config = StewardConfig(
        repo_root=tmp_path / "repo", dry_run=True, local_codex_test_harness=True
    )
    config.repo_root.mkdir()
    store = TaskStore.create(config.db_path, dry_run=True)
    source = _sealed_dry_run_source(config, store)
    before_tasks = [(task.id, task.status) for task in store.list_tasks()]
    before_events = [
        (event.task_id, event.kind, event.data)
        for task in store.list_tasks()
        for event in store.events(task.id)
    ]
    before_wakeups = [(item.id, item.reason) for item in store.pending_wakeups()]

    with pytest.raises(ValueError, match="dry-run startup"):
        store.allocate_live_rerun(source.id)

    assert [(task.id, task.status) for task in store.list_tasks()] == before_tasks
    assert [
        (event.task_id, event.kind, event.data)
        for task in store.list_tasks()
        for event in store.events(task.id)
    ] == before_events
    assert [(item.id, item.reason) for item in store.pending_wakeups()] == before_wakeups


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

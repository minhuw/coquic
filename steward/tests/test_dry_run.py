from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.config import StewardConfig, load_config
from coquic_steward.core.models import (
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
from coquic_steward.storage import TaskStore
from coquic_steward.storage.schema import TaskRow
from sqlalchemy.orm import Session


def _spec(**metadata: object) -> TaskSpec:
    return TaskSpec(
        kind=TaskKind.custom,
        worker=WorkerKind.custom,
        title="dry-run task",
        prompt="inspect only",
        metadata=dict(metadata),
    )


def test_config_defaults_to_dry_run_and_rejects_legacy_keys(
    repo: Path, tmp_path: Path
) -> None:
    config = load_config(repo_root=repo)
    assert config.dry_run is True
    assert config.dry_run_enabled is True

    for key, value in (("integration_mode", '"push-main"'), ("local_only", "false")):
        path = tmp_path / f"{key}.toml"
        path.write_text(f"[steward]\n{key} = {value}\n", encoding="utf-8")
        with pytest.raises(ValueError, match=f"{key} is no longer accepted"):
            load_config(repo_root=repo, config_path=path)

    path = tmp_path / "invalid-bool.toml"
    path.write_text('[steward]\ndry_run = "false"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="dry_run must be a boolean"):
        load_config(repo_root=repo, config_path=path)


def test_manual_latch_is_store_owned_and_monotonic(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=True)
    task, created = store.add_task(
        _spec(**{EXECUTION_MODE_METADATA_KEY: ExecutionMode.live.value})
    )
    assert created
    assert store.get(task.id).spec.metadata[EXECUTION_MODE_METADATA_KEY] == "dry-run"

    mutable = store.get(task.id)
    mutable.spec.metadata[EXECUTION_MODE_METADATA_KEY] = ExecutionMode.live.value
    store.save(mutable)
    assert store.get(task.id).spec.metadata[EXECUTION_MODE_METADATA_KEY] == "dry-run"

    reopened = TaskStore.open(database, dry_run=False)
    assert reopened.get(task.id).spec.metadata[EXECUTION_MODE_METADATA_KEY] == "dry-run"


def test_missing_latch_adopts_startup_and_live_tightens(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=False)
    task, _ = store.add_task(_spec())
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.metadata_json = "{}"

    reopened = TaskStore.open(database, dry_run=True)
    assert reopened.get(task.id).spec.metadata[EXECUTION_MODE_METADATA_KEY] == "dry-run"
    assert reopened.resolve_execution_modes(False) == 0
    assert reopened.get(task.id).spec.metadata[EXECUTION_MODE_METADATA_KEY] == "dry-run"


def test_planner_allocation_preserves_preview_signal_coverage(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=True)
    item = SignalItem(
        id="signal-item-preview",
        provider="synthetic",
        kind="synthetic.alert",
        fingerprint="preview-fingerprint",
        title="preview",
    )
    store.ingest_signal_collection(
        SignalFetchRun(
            id="fetch-preview",
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
    )
    canonical = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert canonical is not None
    store.control_loop.claim_planner_run("planner-preview", [canonical])
    spec = _spec()
    committed = store.commit_planner_decision(
        "planner-preview",
        planned=[(spec, "preview-dedupe")],
        planner_dispositions=[],
        consumed_item_ids=[item.id],
        selected_item_ids_by_dedupe={"preview-dedupe": [item.id]},
        canonical_signal_by_item={item.id: canonical},
        state="succeeded",
        result={},
        diagnostics={},
        retry_after=None,
        artifact_sources={},
    )
    record, created = committed["records"][0]
    assert created
    assert record.spec.metadata[EXECUTION_MODE_METADATA_KEY] == "dry-run"
    assert record.spec.metadata["selected_signal_item_ids"] == [item.id]
    assert store.list_signal_items(status="planned")[0].planned_task_id == record.id


def test_dry_run_dispatch_and_publication_are_paused(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    config = StewardConfig(
        repo_root=repo,
        dry_run=True,
        local_codex_test_harness=True,
    )
    config.ensure_dirs()
    store = TaskStore.create(tmp_path / "steward.sqlite", dry_run=True)
    task, _ = store.add_task(_spec())
    daemon = StewardDaemon(config, store)

    monkeypatch.setattr(
        daemon.executor,
        "advance_once",
        lambda *_args, **_kwargs: pytest.fail("dry-run advanced a task"),
    )
    assert daemon.drive_selected_task(task.id) is False
    assert any(event.kind == "task.dry_run_paused" for event in store.events(task.id))

    queued: list[object] = []
    publication_config = SimpleNamespace(
        dry_run=True,
        publication=SimpleNamespace(enabled=True),
    )
    run = SimpleNamespace(id="run-preview", state="succeeded", completed_at=object())
    assert enqueue_materialized_publication(publication_config, store, task, run) is None
    assert queued == []


def test_dry_run_publication_cli_does_not_construct_mutator(monkeypatch) -> None:
    import coquic_steward.cli as cli

    config = StewardConfig(repo_root=Path.cwd(), dry_run=True)
    monkeypatch.setattr(cli, "_context", lambda: (SimpleNamespace(), config))
    monkeypatch.setattr(
        cli,
        "_build_cli_retry_publisher",
        lambda *_args, **_kwargs: pytest.fail("dry-run built a publisher"),
    )
    result = CliRunner().invoke(
        app,
        ["publication", "retry", "pub-" + "a" * 64],
    )
    assert result.exit_code == 1
    assert '"reason":"dry_run"' in result.stdout

    monkeypatch.setattr(
        cli,
        "_build_cli_hide_publisher",
        lambda *_args, **_kwargs: pytest.fail("dry-run built a hide publisher"),
    )
    result = CliRunner().invoke(app, ["publication", "hide", "task-preview"])
    assert result.exit_code == 1
    assert '"reason":"dry_run"' in result.stdout

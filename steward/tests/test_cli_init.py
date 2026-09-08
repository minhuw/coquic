from __future__ import annotations

import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.core.config import load_config
from coquic_steward.orchestration import acquire_daemon_lock
from coquic_steward.storage import TaskStore


def _invoke(repo: Path, monkeypatch, *arguments: str):
    monkeypatch.chdir(repo)
    return CliRunner().invoke(app, list(arguments))


def _snapshot(paths: tuple[Path, ...]) -> dict[Path, tuple[bytes, int]]:
    return {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in paths
        if path.exists()
    }


def _dispose(store: TaskStore) -> None:
    store.engine.dispose()


def test_init_creates_the_exact_store_and_unblocks_ordinary_cli(
    repo: Path, monkeypatch
) -> None:
    result = _invoke(repo, monkeypatch, "init")

    assert result.exit_code == 0, result.output
    assert "initialized" in result.output
    config = load_config()
    assert config.db_path.is_file()
    assert config.epoch_path.is_file()
    assert config.db_path.with_name("steward.sqlite-wal").is_file()
    assert config.db_path.with_name("steward.sqlite-shm").is_file()

    status = _invoke(repo, monkeypatch, "status")
    assert status.exit_code == 0, status.output


def test_repeated_init_opens_without_rewriting_application_state(
    repo: Path, monkeypatch
) -> None:
    first = _invoke(repo, monkeypatch, "init")
    assert first.exit_code == 0, first.output
    config = load_config()
    paths = (
        config.db_path,
        config.db_path.with_name("steward.sqlite-wal"),
        config.db_path.with_name("steward.sqlite-shm"),
        config.epoch_path,
    )
    before = _snapshot(paths)

    second = _invoke(repo, monkeypatch, "init")

    assert second.exit_code == 0, second.output
    assert "already initialized" in second.output
    assert _snapshot(paths) == before


def test_config_loading_and_init_leave_unrelated_database_untouched(
    repo: Path, monkeypatch
) -> None:
    config = load_config()
    historic_database = (
        config.coquic_home / "historic-steward" / "steward.sqlite"
    )
    historic = TaskStore.create(historic_database)
    try:
        with historic.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS historic_canary (value TEXT)"
            )
            connection.exec_driver_sql(
                "INSERT INTO historic_canary(value) VALUES ('untouched')"
            )
    finally:
        _dispose(historic)
    historic_paths = (
        historic_database,
        historic_database.with_name("steward.sqlite-wal"),
        historic_database.with_name("steward.sqlite-shm"),
    )
    before = _snapshot(historic_paths)

    loaded = load_config()
    assert loaded.db_path != historic_database
    assert not loaded.db_path.exists()
    assert _snapshot(historic_paths) == before

    result = _invoke(repo, monkeypatch, "init")

    assert result.exit_code == 0, result.output
    assert _snapshot(historic_paths) == before


def test_init_refuses_to_run_while_the_daemon_lock_is_held(
    repo: Path, monkeypatch
) -> None:
    config = load_config()
    with acquire_daemon_lock(config):
        result = _invoke(repo, monkeypatch, "init")

    assert result.exit_code == 1
    assert "already running" in result.output
    assert not config.db_path.exists()


def test_init_refuses_a_mismatched_store_without_repair(
    repo: Path, monkeypatch
) -> None:
    created = _invoke(repo, monkeypatch, "init")
    assert created.exit_code == 0, created.output
    config = load_config()
    with sqlite3.connect(config.db_path) as connection:
        connection.execute("PRAGMA user_version = 999")
        connection.commit()
    paths = (config.db_path, config.epoch_path)
    before = _snapshot(paths)
    assert config.db_path.with_name("steward.sqlite-wal").is_file()
    assert config.db_path.with_name("steward.sqlite-shm").is_file()

    result = _invoke(repo, monkeypatch, "init")

    assert result.exit_code == 1
    assert "initialization refused" in result.output
    assert _snapshot(paths) == before


def test_ordinary_cli_and_health_refuse_absent_store_without_creating_it(
    repo: Path, monkeypatch
) -> None:
    status = _invoke(repo, monkeypatch, "status")
    health = _invoke(repo, monkeypatch, "health")
    readiness = _invoke(repo, monkeypatch, "health", "--store-only")

    assert status.exit_code != 0
    assert health.exit_code == 1
    assert readiness.exit_code == 1
    config = load_config()
    assert not config.db_path.exists()

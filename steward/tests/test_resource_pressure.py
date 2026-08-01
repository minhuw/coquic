from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from coquic_steward.core.config import StewardConfig, StewardDeploymentConfig
from coquic_steward.core.lifecycle import (
    DockerResourceManager,
    ResourcePressureController,
)
from coquic_steward.core.models import (
    OwnedDockerUsage,
    ResourcePressureState,
    evaluate_resource_pressure,
)
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.orchestration.preflight import PreflightReport
from coquic_steward.storage import TaskStore


def test_high_pressure_blocks_admission() -> None:
    report = evaluate_resource_pressure(
        home_free_bytes=10,
        owned=OwnedDockerUsage(container_bytes=10),
        minimum_free_bytes=100,
        maximum_owned_bytes=1000,
        recovery_free_bytes=150,
        recovery_owned_bytes=500,
    )
    assert report.state is ResourcePressureState.pressure
    assert not report.admission_allowed


def test_pressure_hysteresis_requires_free_headroom_and_lower_owned_usage() -> None:
    report = evaluate_resource_pressure(
        home_free_bytes=120,
        owned=OwnedDockerUsage(container_bytes=600),
        minimum_free_bytes=100,
        maximum_owned_bytes=1000,
        recovery_free_bytes=150,
        recovery_owned_bytes=500,
        previous=ResourcePressureState.pressure,
    )
    assert report.state is ResourcePressureState.pressure
    recovered = evaluate_resource_pressure(
        home_free_bytes=160,
        owned=OwnedDockerUsage(container_bytes=400),
        minimum_free_bytes=100,
        maximum_owned_bytes=1000,
        recovery_free_bytes=150,
        recovery_owned_bytes=500,
        previous=ResourcePressureState.pressure,
    )
    assert recovered.state is ResourcePressureState.normal


def test_unchanged_free_space_in_hysteresis_band_does_not_oscillate() -> None:
    facts = dict(
        home_free_bytes=120,
        owned=OwnedDockerUsage(container_bytes=400),
        minimum_free_bytes=100,
        maximum_owned_bytes=1000,
        recovery_free_bytes=150,
        recovery_owned_bytes=500,
    )
    first = evaluate_resource_pressure(**facts)
    second = evaluate_resource_pressure(**facts, previous=first.state)
    assert first.state is second.state is ResourcePressureState.normal


def test_controller_treats_unknown_docker_usage_as_pressure(tmp_path: Path) -> None:
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=tmp_path,
        repository=tmp_path / "repository",
        min_free_bytes=100,
        max_owned_docker_bytes=1000,
        recovery_free_bytes=150,
        recovery_owned_docker_bytes=500,
    )
    config = type("Config", (), {"deployment": deployment, "coquic_home": tmp_path})()
    report = ResourcePressureController(config).measure()
    assert report.state is ResourcePressureState.pressure
    assert not report.admission_allowed


def test_controller_accepts_label_filtered_usage(tmp_path: Path) -> None:
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=tmp_path,
        repository=tmp_path / "repository",
        min_free_bytes=10,
        max_owned_docker_bytes=1000,
        recovery_free_bytes=20,
        recovery_owned_docker_bytes=500,
    )
    config = type("Config", (), {"deployment": deployment, "coquic_home": tmp_path})()
    controller = ResourcePressureController(
        config,
        usage_provider=lambda: {"container_bytes": 1, "image_bytes": 1, "ambiguous": False},
    )
    report = controller.measure()
    assert report.owned.bytes == 2


def test_production_daemon_wires_label_filtered_owned_usage(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    repository = home / "repository"
    repository.mkdir(parents=True)
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=home,
        repository=repository,
        min_free_bytes=100,
        max_owned_docker_bytes=1000,
        recovery_free_bytes=200,
        recovery_owned_docker_bytes=500,
    )
    config = StewardConfig(
        repo_root=repository,
        deployment=deployment,
        local_codex_test_harness=True,
    )
    config.ensure_dirs()
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.preflight_remote_push",
        lambda _config: False,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_preflight",
        lambda *_args, **_kwargs: PreflightReport(),
    )
    monkeypatch.setattr(
        DockerResourceManager,
        "owned_usage",
        lambda _self: OwnedDockerUsage(container_bytes=1, image_bytes=1),
    )
    daemon = StewardDaemon(config, TaskStore(config.db_path))
    report = daemon.resource_pressure
    assert report["state"] == "normal"
    assert report["ownedBytes"] == 2
    assert report["admissionAllowed"] is True


def test_production_daemon_restores_pressure_hysteresis_after_restart(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    repository = home / "repository"
    repository.mkdir(parents=True)
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=home,
        repository=repository,
        min_free_bytes=100,
        max_owned_docker_bytes=1000,
        recovery_free_bytes=200,
        recovery_owned_docker_bytes=500,
    )
    config = StewardConfig(
        repo_root=repository,
        deployment=deployment,
        local_codex_test_harness=True,
    )
    config.ensure_dirs()
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.preflight_remote_push",
        lambda _config: False,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_preflight",
        lambda *_args, **_kwargs: PreflightReport(),
    )
    monkeypatch.setattr(
        DockerResourceManager,
        "owned_usage",
        lambda _self: OwnedDockerUsage(container_bytes=800),
    )
    store = TaskStore(config.db_path)
    store.record_resource_pressure(
        state="resource_pressure",
        home_free_bytes=1000,
        owned_docker_bytes=800,
        cleanup_pending_count=0,
        reason="threshold",
    )

    daemon = StewardDaemon(config, store)
    report = daemon.resource_pressure

    assert report["state"] == "resource_pressure"
    assert report["ownedBytes"] == 800
    assert report["admissionAllowed"] is False


def test_daemon_projects_bounded_publication_health() -> None:
    recorded: list[dict[str, object]] = []

    class Store:
        def list_tasks(self, *, limit: int):
            assert limit == 10_000
            return []

        def get_publication_health(self):
            return SimpleNamespace(
                as_dict=lambda: {
                    "queuedCount": 2**40,
                    "blockedCount": 3,
                    "cleanupPendingCount": 4,
                    "cleanupPendingBytes": 2**40,
                    "oldestQueuedAgeSeconds": 5,
                }
            )

        def record_resource_pressure(self, **kwargs: object) -> None:
            recorded.append(kwargs)

    report = SimpleNamespace(
        as_dict=lambda: {
            "state": "normal",
            "homeFreeBytes": 100,
            "ownedBytes": 1,
            "admissionAllowed": True,
        },
        state="normal",
    )
    daemon = object.__new__(StewardDaemon)
    daemon._docker_resources = None
    daemon._resource_pressure = SimpleNamespace(measure=lambda: report)
    daemon.store = Store()
    daemon._log = lambda *_args, **_kwargs: None

    projected = daemon.resource_pressure

    assert projected["publicationQueuedCount"] == 2**31 - 1
    assert projected["publicationCleanupPendingCount"] == 4
    assert projected["publicationRetainedBytes"] == 2**31 - 1
    assert projected["admissionAllowed"] is True
    assert recorded[-1]["cleanup_pending_count"] == 4

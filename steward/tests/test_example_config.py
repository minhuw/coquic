from __future__ import annotations

import shutil
from pathlib import Path

from coquic_steward.core.config import load_config


def test_steward_example_config_loads_with_raw_archive_settings(repo: Path) -> None:
    example = Path(__file__).resolve().parents[1] / "steward.example.toml"

    config = load_config(repo_root=repo, config_path=example)

    assert config.scheduler_wait_interval_sec == 1.0
    assert config.control_loop_dir == config.coquic_home / "control-loop"
    assert config.tasks_dir == config.coquic_home / "tasks"
    assert Path(config.dataset_sync.ssh_bin).is_absolute()
    assert Path(config.dataset_sync.rsync_bin).is_absolute()
    assert Path(config.dataset_sync.ssh_bin).name == "ssh"
    assert Path(config.dataset_sync.rsync_bin).name == "rsync"


def test_explicit_runtime_repository_loads_config_outside_a_checkout(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "steward.toml"
    config_path.write_text("[steward]\nlocal_codex_test_harness = true\n", encoding="utf-8")
    outside = tmp_path / "runtime-working-directory"
    outside.mkdir()
    monkeypatch.chdir(outside)
    monkeypatch.setenv("COQUIC_REPOSITORY", str(repo))
    monkeypatch.setenv("STEWARD_CONFIG_PATH", str(config_path))

    config = load_config()

    assert config.repo_root == repo.resolve()


def test_compose_release_environment_selects_exact_runtime_pair(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "deployment-home"
    canonical = home / "repository"
    home.mkdir()
    shutil.copytree(repo, canonical)
    config_path = tmp_path / "deployment.toml"
    config_path.write_text(
        f"""
[steward]
local_codex_test_harness = true

[steward.container]
enabled = true
repository_host_path = {str(canonical)!r}
state_host_path = {str(home)!r}
codex_api_key_path = "/run/secrets/codex-api"

[steward.deployment]
enabled = true
home = {str(home)!r}
repository = {str(canonical)!r}
min_free_bytes = 100
recovery_free_bytes = 200
max_owned_docker_bytes = 1000
recovery_owned_docker_bytes = 500
""",
        encoding="utf-8",
    )
    daemon_id = "sha256:" + "a" * 64
    task_id = "sha256:" + "b" * 64
    monkeypatch.setenv("STEWARD_RELEASE_ID", "release-compose")
    monkeypatch.setenv("STEWARD_DAEMON_IMAGE", daemon_id)
    monkeypatch.setenv("STEWARD_TASK_IMAGE", task_id)

    config = load_config(repo_root=canonical, config_path=config_path)

    assert config.daemon_image == config.daemon_image_digest == daemon_id
    assert config.task_image == config.task_image_digest == task_id
    assert config.container.image == config.container.image_digest == task_id
    assert config.deployment.release_id == "release-compose"

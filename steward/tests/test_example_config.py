from __future__ import annotations

from pathlib import Path

from coquic_steward.core.config import load_config


def test_steward_example_config_loads_with_raw_archive_settings(repo: Path) -> None:
    example = Path(__file__).resolve().parents[1] / "steward.example.toml"

    config = load_config(repo_root=repo, config_path=example)

    assert config.scheduler_wait_interval_sec == 1.0
    assert config.control_loop_dir == config.coquic_home / "control-loop"
    assert config.tasks_dir == config.coquic_home / "tasks"
    assert Path(config.task_sync.ssh_bin).is_absolute()
    assert Path(config.task_sync.rsync_bin).is_absolute()
    assert Path(config.task_sync.ssh_bin).name == "ssh"
    assert Path(config.task_sync.rsync_bin).name == "rsync"

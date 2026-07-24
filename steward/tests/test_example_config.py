from __future__ import annotations

from pathlib import Path

from coquic_steward.core.config import load_config


def test_steward_example_config_loads_with_site_mirror_settings(repo: Path) -> None:
    example = Path(__file__).resolve().parents[1] / "steward.example.toml"

    config = load_config(repo_root=repo, config_path=example)

    assert config.scheduler_wait_interval_sec == 1.0
    assert config.public_mirror.enabled is True
    assert config.public_mirror.output_path == Path("public/steward/status.json")
    assert config.public_mirror.publish is False
    assert config.public_mirror.transcript_mode == "redacted"
    assert config.public_mirror.remote_user == "minhuw"
    assert config.public_mirror.remote_host == "coquic.minhuw.dev"
    assert config.public_mirror.remote_port == 22
    assert (
        config.public_mirror.remote_path
        == "/opt/coquic-demo/current/app/public/steward/status.json"
    )
    assert config.public_mirror.ssh_key_path == Path(
        "~/.ssh/coquic-demo.key"
    ).expanduser()
    assert config.public_mirror.known_hosts_path == Path(
        "~/.ssh/known_hosts"
    ).expanduser()
    assert config.public_mirror.connect_timeout_seconds == 10
    assert config.public_mirror.retry_initial_seconds == 30
    assert config.public_mirror.retry_max_seconds == 300
    assert Path(config.task_sync.ssh_bin).is_absolute()
    assert Path(config.task_sync.rsync_bin).is_absolute()
    assert Path(config.task_sync.ssh_bin).name == "ssh"
    assert Path(config.task_sync.rsync_bin).name == "rsync"

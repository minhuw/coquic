from __future__ import annotations

import shutil
from pathlib import Path

import pytest

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
    assert config.publication.enabled is False
    assert config.publication.account_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert config.publication.d1_database_id == "12345678-1234-4abc-8def-1234567890ab"


def _write_publication_config(
    tmp_path: Path,
    *,
    publication_overrides: str = "",
    dataset_enabled: bool = False,
) -> tuple[Path, tuple[Path, Path, Path], Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    credentials = tuple(tmp_path / name for name in ("d1-token", "access-key", "secret-key"))
    for path in credentials:
        path.write_text("credential-value\n", encoding="utf-8")
        path.chmod(0o600)
    staging = tmp_path / "publication-staging"
    staging.mkdir()
    staging.chmod(0o700)
    dataset_values = (
        "remote_user = \"archive\"\n"
        "remote_host = \"receiver.example.test\"\n"
        f"identity_path = {str(credentials[1])!r}\n"
        f"known_hosts_path = {str(credentials[2])!r}\n"
        if dataset_enabled
        else ""
    )
    config_path = tmp_path / "publication.toml"
    config_path.write_text(
        f"""
[steward.publication]
enabled = true
account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
d1_database_id = "12345678-1234-4abc-8def-1234567890ab"
d1_token_path = {str(credentials[0])!r}
r2_endpoint = "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.r2.cloudflarestorage.com"
r2_access_key_id_path = {str(credentials[1])!r}
r2_secret_access_key_path = {str(credentials[2])!r}
public_bucket = "coquic-public"
private_bucket = "coquic-private"
public_base_url = "https://objects.example.test/coquic/"
staging_root = {str(staging)!r}
{publication_overrides}

[steward.dataset_sync]
enabled = {str(dataset_enabled).lower()}
{dataset_values}
""",
        encoding="utf-8",
    )
    return config_path, credentials, staging


def test_enabled_publication_validates_metadata_without_reading_credentials(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    config_path, credentials, staging = _write_publication_config(tmp_path)

    def fail_read(*_args, **_kwargs):
        raise AssertionError("publication config must not read credential bytes")

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    config = load_config(repo_root=repo, config_path=config_path)

    assert config.publication.enabled is True
    assert config.publication.d1_token_path == credentials[0]
    assert config.publication.r2_access_key_id_path == credentials[1]
    assert config.publication.r2_secret_access_key_path == credentials[2]
    assert config.publication.staging_root == staging


@pytest.mark.parametrize("unsafe_kind", ("symlink", "directory", "permissive"))
def test_enabled_publication_rejects_unsafe_credential_files(
    repo: Path, tmp_path: Path, unsafe_kind: str
) -> None:
    config_path, credentials, _staging = _write_publication_config(tmp_path)
    candidate = credentials[0]
    if unsafe_kind == "symlink":
        candidate.unlink()
        candidate.symlink_to(credentials[1])
    elif unsafe_kind == "directory":
        candidate.unlink()
        candidate.mkdir()
    else:
        candidate.chmod(0o644)

    with pytest.raises(ValueError, match="publication.d1_token_path"):
        load_config(repo_root=repo, config_path=config_path)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("d1_token_path", "relative-token"),
        ("public_base_url", "http://objects.example.test/"),
        ("account_id", "not-an-account"),
        ("public_bucket", "same_bucket"),
    ),
)
def test_enabled_publication_rejects_unsafe_values(
    repo: Path, tmp_path: Path, field: str, value: str
) -> None:
    config_path, _credentials, _staging = _write_publication_config(
        tmp_path,
        publication_overrides=f"{field} = {value!r}",
    )

    with pytest.raises(ValueError):
        load_config(repo_root=repo, config_path=config_path)


def test_publication_rejects_unknown_keys_and_dual_transport(
    repo: Path, tmp_path: Path
) -> None:
    unknown_path, _credentials, _staging = _write_publication_config(
        tmp_path,
        publication_overrides="unexpected = true",
    )
    with pytest.raises(ValueError, match="unsupported keys"):
        load_config(repo_root=repo, config_path=unknown_path)

    dual_path, _credentials, _staging = _write_publication_config(
        tmp_path / "dual",
        dataset_enabled=True,
    )
    with pytest.raises(ValueError, match="cannot both be enabled"):
        load_config(repo_root=repo, config_path=dual_path)


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

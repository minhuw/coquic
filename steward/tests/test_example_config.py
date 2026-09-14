from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from coquic_steward.core.config import (
    StewardConfig,
    StewardDeploymentConfig,
    load_config,
)
from coquic_steward.core.models import TaskKind
from coquic_steward.orchestration import preflight as preflight_module
from coquic_steward.orchestration.preflight import (
    StewardPreflightError,
    run_preflight,
)


def test_steward_example_config_loads_with_publication_settings(repo: Path) -> None:
    example = Path(__file__).resolve().parents[1] / "steward.example.toml"

    config = load_config(repo_root=repo, config_path=example)

    assert config.scheduler_wait_interval_sec == 1.0
    assert config.dry_run is True
    assert config.local_codex_test_harness is True
    assert config.control_loop_dir == config.coquic_home / "control-loop"
    assert config.tasks_dir == config.coquic_home / "tasks"
    assert config.publication.enabled is False
    assert config.publication.account_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert config.publication.d1_database_id == "12345678-1234-4abc-8def-1234567890ab"
    assert config.publication.live_snapshot_enabled is False
    assert config.publication.live_snapshot_url == "https://live.coquic.minhuw.dev/api/steward/live"
    assert config.publication.live_snapshot_interval_seconds == 60
    assert config.telemetry.billing_mode == "unknown"
    assert config.authentication.proxy_url is None
    assert config.read_codex_api_key_bytes() is None


def test_telemetry_billing_mode_is_normalized(repo: Path, tmp_path: Path) -> None:
    config_path = tmp_path / "telemetry.toml"
    config_path.write_text(
        '[steward.telemetry]\nbilling_mode = "API"\n',
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.telemetry.billing_mode == "api"


@pytest.mark.parametrize(
    ("key", "toml_value"),
    (
        ("price_" + "catalog_path", '"ignored.json"'),
        ("unknown_sentinel", "true"),
    ),
)
def test_telemetry_rejects_unknown_keys(
    repo: Path, tmp_path: Path, key: str, toml_value: str
) -> None:
    config_path = tmp_path / f"telemetry-{key}.toml"
    config_path.write_text(
        f"[steward.telemetry]\n{key} = {toml_value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=rf"telemetry has unsupported keys: {key}"):
        load_config(repo_root=repo, config_path=config_path)


def test_production_remote_push_rejects_pushurl_before_network(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/org/repo.git"],
        cwd=repo,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "config",
            "remote.origin.pushurl",
            "file:///tmp/forbidden.git",
        ],
        cwd=repo,
        check=True,
    )
    home = tmp_path / "home"
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=home,
        repository=home / "repository",
        min_free_bytes=1,
        max_owned_docker_bytes=2,
        recovery_free_bytes=2,
        recovery_owned_docker_bytes=1,
    )
    config = StewardConfig(
        repo_root=repo,
        dry_run=False,
        deployment=deployment,
    )
    commands: list[list[str]] = []
    original_run_command = preflight_module.run_command

    def recording_run_command(command, cwd, **kwargs):
        commands.append(command)
        return original_run_command(command, cwd, **kwargs)

    monkeypatch.setattr(preflight_module, "run_command", recording_run_command)
    with pytest.raises(StewardPreflightError, match="credential-free GitHub HTTPS"):
        preflight_module.preflight_remote_push(config)
    assert not any(command[:2] == ["git", "fetch"] for command in commands)


def test_enabled_publication_runs_preflight_without_deployment_credentials(
    repo: Path, tmp_path: Path
) -> None:
    config_path, _credentials, _staging = _write_publication_config(tmp_path)

    config = load_config(repo_root=repo, config_path=config_path)
    report = run_preflight(config, check_remote_push=False)

    assert config.publication.enabled is True
    assert config.deployment.enabled is False
    assert "deployment" not in report.checks


def _write_publication_config(
    tmp_path: Path,
    *,
    publication_overrides: str = "",
) -> tuple[Path, tuple[Path, Path, Path], Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    credentials = tuple(tmp_path / name for name in ("d1-token", "access-key", "secret-key"))
    for path in credentials:
        path.write_text("credential-value\n", encoding="utf-8")
        path.chmod(0o600)
    staging = tmp_path / "publication-staging"
    staging.mkdir()
    staging.chmod(0o700)
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


@pytest.mark.parametrize(("retries", "attempts"), ((0, 1), (3, 4), (20, 21)))
def test_publication_retry_configuration_preserves_attempt_semantics(
    repo: Path, tmp_path: Path, retries: int, attempts: int
) -> None:
    config_path, _credentials, _staging = _write_publication_config(
        tmp_path,
        publication_overrides=f"max_retries = {retries}",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.publication.max_retries == retries
    assert config.publication.max_retries + 1 == attempts


@pytest.mark.parametrize("value", (True, 21, -1))
def test_publication_retry_configuration_rejects_invalid_budgets(
    repo: Path, tmp_path: Path, value: object
) -> None:
    toml_value = "true" if value is True else str(value)
    config_path, _credentials, _staging = _write_publication_config(
        tmp_path,
        publication_overrides=f"max_retries = {toml_value}",
    )

    with pytest.raises(ValueError):
        load_config(repo_root=repo, config_path=config_path)


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


def test_publication_rejects_unknown_keys_and_unknown_section(
    repo: Path, tmp_path: Path
) -> None:
    unknown_path, _credentials, _staging = _write_publication_config(
        tmp_path,
        publication_overrides="unexpected = true",
    )
    with pytest.raises(ValueError, match="unsupported keys"):
        load_config(repo_root=repo, config_path=unknown_path)

    unsupported_path = tmp_path / "unsupported.toml"
    unsupported_path.write_text(
        "[steward.unsupported]\nenabled = false\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown configuration section"):
        load_config(repo_root=repo, config_path=unsupported_path)


@pytest.mark.parametrize(
    "removed_key",
    (
        "cloudflare_account_id",
        "cloudflare_database_id",
        "database_id",
        "d1_read_token_path",
        "d1_api_token_path",
        "d1_token_file",
        "d1_read_token_file",
        "r2_endpoint_url",
        "access_key_id_path",
        "secret_access_key_path",
        "access_key_file",
        "secret_key_file",
        "r2_access_key_path",
        "r2_secret_key_path",
        "r2_access_key_file",
        "r2_secret_key_file",
        "public_r2_bucket",
        "private_r2_bucket",
        "public_bucket_name",
        "private_bucket_name",
        "public_r2_base_url",
        "staging_dir",
        "staging_path",
        "trusted_staging_root",
        "build_timeout_seconds",
        "lease_seconds",
        "lease_duration",
        "retry_limit",
        "max_retry_count",
    ),
)
def test_publication_rejects_removed_keys(
    repo: Path, tmp_path: Path, removed_key: str
) -> None:
    config_path, _credentials, _staging = _write_publication_config(
        tmp_path,
        publication_overrides=f"{removed_key} = true",
    )

    with pytest.raises(ValueError, match=rf"unsupported keys: {removed_key}"):
        load_config(repo_root=repo, config_path=config_path)


@pytest.mark.parametrize("removed_section", ("cloud_publication",))
def test_publication_rejects_removed_sections(
    repo: Path, tmp_path: Path, removed_section: str
) -> None:
    config_path = tmp_path / "removed-section.toml"
    config_path.write_text(
        f"[steward.{removed_section}]\nenabled = false\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=rf"unknown configuration section: steward\.{removed_section}",
    ):
        load_config(repo_root=repo, config_path=config_path)


@pytest.mark.parametrize(
    "removed_root_entry",
    (
        "containers = {}",
        "task" + "_container = {}",
        "container" + "_operations = {}",
        "task_image = \"unsupported-task\"",
        "task_image_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        "enabled_signals = [\"codacy\"]",
        "resume_attempt_limit = 2",
        "unknown_root_key = true",
    ),
)
def test_config_rejects_removed_root_keys(
    repo: Path, tmp_path: Path, removed_root_entry: str
) -> None:
    config_path = tmp_path / "removed-root.toml"
    config_path.write_text(
        f"[steward]\n{removed_root_entry}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_config(repo_root=repo, config_path=config_path)


@pytest.mark.parametrize(
    "removed_container_key",
    (
        "repository_path",
        "state_path",
        "api_key_path",
        "task_image",
        "task_image_digest",
        "unknown_container_key",
    ),
)
def test_config_rejects_removed_container_keys(
    repo: Path, tmp_path: Path, removed_container_key: str
) -> None:
    config_path = tmp_path / "removed-container.toml"
    value = "true" if removed_container_key == "unknown_container_key" else "\"unsupported\""
    config_path.write_text(
        f"[steward.container]\n{removed_container_key} = {value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=rf"unsupported keys: {removed_container_key}"):
        load_config(repo_root=repo, config_path=config_path)


@pytest.mark.parametrize(
    "removed_deployment_key",
    (
        "coquic_home",
        "repository_path",
        "socket",
        "git_remote",
        "main_branch",
        "codex_api_key_path",
        "github_identity_path",
        "github_credential_path",
        "task_concurrency",
        "max_active_tasks",
        "unknown_deployment_key",
    ),
)
def test_config_rejects_removed_deployment_keys(
    repo: Path, tmp_path: Path, removed_deployment_key: str
) -> None:
    config_path = tmp_path / "removed-deployment.toml"
    value = "true" if removed_deployment_key == "unknown_deployment_key" else "\"unsupported\""
    config_path.write_text(
        f"[steward.deployment]\n{removed_deployment_key} = {value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=rf"unsupported keys: {removed_deployment_key}"):
        load_config(repo_root=repo, config_path=config_path)


def test_deployment_rejects_legacy_github_token_path(repo, tmp_path):
    path = tmp_path / "legacy.toml"
    path.write_text('[steward.deployment]\ngithub_token_path = "/private/token"\n')
    with pytest.raises(ValueError, match=r"authentication.*github_token"):
        load_config(repo_root=repo, config_path=path)


def test_config_rejects_unknown_limits_keys(repo: Path, tmp_path: Path) -> None:
    config_path = tmp_path / "unknown-limits.toml"
    config_path.write_text(
        "[steward.limits]\nunknown_limits_key = true\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported keys: unknown_limits_key"):
        load_config(repo_root=repo, config_path=config_path)


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


def _write_compose_config(
    config_path: Path,
    home: Path,
    canonical: Path,
    *,
    container_enabled: bool = True,
    deployment_enabled: bool = True,
    local_codex_test_harness: bool = False,
) -> None:
    config_path.write_text(
        f"""
[steward]
local_codex_test_harness = {str(local_codex_test_harness).lower()}

[steward.authentication]
proxy_url = "http://proxy.test:8080/v1"
api_key = "compose-test-key"
github_token = "compose-github-token"

[steward.container]
enabled = {str(container_enabled).lower()}
repository_host_path = {str(canonical)!r}
state_host_path = {str(home)!r}

[steward.deployment]
enabled = {str(deployment_enabled).lower()}
home = {str(home)!r}
repository = {str(canonical)!r}
min_free_bytes = 100
recovery_free_bytes = 200
max_owned_docker_bytes = 1000
recovery_owned_docker_bytes = 500
""",
        encoding="utf-8",
    )
    config_path.chmod(0o600)


def _set_compose_image_environment(monkeypatch) -> None:
    monkeypatch.setenv("STEWARD_RELEASE_ID", "release-compose")
    monkeypatch.setenv("STEWARD_DAEMON_IMAGE", "sha256:" + "a" * 64)
    monkeypatch.setenv("STEWARD_TASK_IMAGE", "sha256:" + "b" * 64)
    monkeypatch.setenv("STEWARD_VALIDATION_IMAGE", "sha256:" + "c" * 64)


def test_compose_release_environment_selects_exact_runtime_pair(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "deployment-home"
    canonical = home / "repository"
    home.mkdir()
    shutil.copytree(repo, canonical)
    config_path = tmp_path / "deployment.toml"
    _write_compose_config(config_path, home, canonical)
    _set_compose_image_environment(monkeypatch)

    config = load_config(repo_root=canonical, config_path=config_path)

    assert config.local_codex_test_harness is False
    assert config.daemon_image_digest == "sha256:" + "a" * 64
    assert config.task_image_digest == "sha256:" + "b" * 64
    assert config.validation_image_digest == "sha256:" + "c" * 64
    assert config.container.image_digest == config.task_image_digest
    assert config.deployment.release_id == "release-compose"
    assert config.authentication.proxy_url == "http://proxy.test:8080/v1"
    assert config.read_codex_api_key_bytes() == b"compose-test-key"


@pytest.mark.parametrize(
    "unsafe_runtime",
    (
        "deployment_disabled",
        "container_disabled",
        "harness_enabled",
        "daemon_image_missing",
        "task_image_missing",
        "validation_image_missing",
    ),
)
def test_compose_release_environment_rejects_unsafe_runtime(
    repo: Path, tmp_path: Path, monkeypatch, unsafe_runtime: str
) -> None:
    home = tmp_path / "deployment-home"
    canonical = home / "repository"
    home.mkdir()
    shutil.copytree(repo, canonical)
    config_path = tmp_path / "deployment.toml"
    _write_compose_config(
        config_path,
        home,
        canonical,
        container_enabled=unsafe_runtime != "container_disabled",
        deployment_enabled=unsafe_runtime != "deployment_disabled",
        local_codex_test_harness=unsafe_runtime == "harness_enabled",
    )
    _set_compose_image_environment(monkeypatch)
    missing_image = {
        "daemon_image_missing": "STEWARD_DAEMON_IMAGE",
        "task_image_missing": "STEWARD_TASK_IMAGE",
        "validation_image_missing": "STEWARD_VALIDATION_IMAGE",
    }.get(unsafe_runtime)
    if missing_image is not None:
        monkeypatch.delenv(missing_image)

    with pytest.raises(
        ValueError, match="STEWARD_RELEASE_ID requires a production runtime"
    ):
        load_config(repo_root=canonical, config_path=config_path)


def test_config_defaults_from_repo(repo: Path, coquic_home: Path) -> None:
    config = load_config(repo_root=repo)
    assert config.repo_root == repo
    assert config.steward_home == coquic_home / "steward"
    assert config.state_dir == coquic_home / "steward"
    assert config.db_path == coquic_home / "steward.sqlite"
    assert config.db_path.name == "steward.sqlite"
    assert config.worktrees_dir == coquic_home / "worktrees"
    assert config.tasks_dir == coquic_home / "tasks"
    assert config.private_root == coquic_home / "private"
    assert config.transcripts_dir == config.state_dir / "transcripts"
    assert config.dry_run is True
    assert config.enabled_signals == (
        "github-actions:ci",
        "github-actions:test",
        "github-actions:duvet",
        "github-actions:nightly-ci",
        "github-actions:deploy-demo",
        "github-actions:interop",
        "github-actions:perf",
        "github-issues:features",
        "code-scanning",
        "codacy",
    )
    assert config.signal_providers["github-actions:ci"].poll_interval_minutes == 30
    assert config.signal_providers["github-actions:test"].poll_interval_minutes == 30
    assert config.signal_providers["github-actions:duvet"].poll_interval_minutes == 1440
    assert (
        config.signal_providers["github-actions:nightly-ci"].idle_poll_interval_minutes
        == 1440
    )
    assert config.signal_providers["github-issues:features"].poll_interval_minutes == 360
    assert config.signal_providers["code-scanning"].poll_interval_minutes == 360
    assert config.signal_providers["codacy"].poll_interval_minutes == 360

def test_config_selects_enabled_signals(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.signals]
enabled = ["codacy"]
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.enabled_signals == ("codacy",)

def test_config_reads_signal_provider_polling(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.signals]
enabled = ["codacy"]

[steward.signals.codacy]
poll_interval_minutes = 720
error_retry_minutes = 45
idle_poll_interval_minutes = 5
suppression_hours = 12
max_items = 25
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)
    provider = config.signal_providers["codacy"]

    assert provider.poll_interval_minutes == 720
    assert provider.error_retry_minutes == 45
    assert provider.idle_poll_interval_minutes == 5
    assert provider.suppression_hours == 12
    assert provider.max_items == 25

def test_config_reads_global_and_kind_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy]
frozen = [".github/**", "flake.nix"]

[steward.path_policy.feature]
frozen = [".clang-tidy", "scripts/run-clang-tidy.sh"]
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.path_policy.frozen == (".github/**", "flake.nix")
    assert config.path_policy.frozen_for_kind(TaskKind.feature) == (
        ".github/**",
        "flake.nix",
        ".clang-tidy",
        "scripts/run-clang-tidy.sh",
    )
    assert config.path_policy.frozen_for_kind(TaskKind.ci) == (
        ".github/**",
        "flake.nix",
    )

def test_example_config_freezes_validation_gate_runner(repo: Path) -> None:
    config = load_config(
        repo_root=repo,
        config_path=Path(__file__).resolve().parents[1] / "steward.example.toml",
    )

    assert "scripts/run-validation-with-index.sh" in config.path_policy.frozen

def test_config_rejects_absolute_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy]
frozen = ["/etc/passwd"]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="repository-relative"):
        load_config(repo_root=repo, config_path=config_path)

def test_config_rejects_blank_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy]
frozen = [""]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must not be empty"):
        load_config(repo_root=repo, config_path=config_path)

def test_config_rejects_blank_kind_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy.feature]
frozen = ["   "]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must not be empty"):
        load_config(repo_root=repo, config_path=config_path)

def test_config_reads_review_timeout_limit(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.limits]
review_timeout_minutes = 7
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.limits.review_timeout_minutes == 7

def test_config_reads_validation_timeout_limit(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.limits]
validation_timeout_minutes = 9
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.limits.validation_timeout_minutes == 9

def test_config_resolves_codex_bin_from_path(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    config_path = tmp_path / "steward.toml"
    config_path.write_text(
        """
[steward]
codex_bin = "codex"
github_repository = "minhuw/coquic"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.codex_bin == str(fake)

def test_config_reads_codex_model_and_reasoning_effort(
    repo: Path, tmp_path: Path
) -> None:
    config_path = tmp_path / "steward.toml"
    config_path.write_text(
        """
[steward]
codex_model = "gpt-5.6-terra"
codex_reasoning_effort = "medium"
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.codex_model == "gpt-5.6-terra"
    assert config.codex_reasoning_effort == "medium"

def test_config_reads_only_global_file_by_default(
    repo: Path, coquic_home: Path
) -> None:
    global_config = coquic_home / "steward.toml"
    global_config.parent.mkdir(parents=True, exist_ok=True)
    global_config.write_text(
        """
[steward]
codex_sandbox = "read-only"
github_repository = "minhuw/global"

[steward.signals]
enabled = ["codacy"]
""",
        encoding="utf-8",
    )
    repo_config = repo / "steward" / "steward.toml"
    repo_config.parent.mkdir(parents=True, exist_ok=True)
    repo_config.write_text(
        """
[steward]
github_repository = "minhuw/coquic"
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo)

    assert config.codex_sandbox == "read-only"
    assert config.github_repository == "minhuw/global"
    assert config.enabled_signals == ("codacy",)


@pytest.mark.parametrize("legacy_key", ("git_ssh_key_path", "git_known_hosts_path"))
def test_legacy_git_credentials_have_bounded_migration_guidance(repo, tmp_path, legacy_key):
    path = tmp_path / "legacy.toml"
    path.write_text(f'[steward.deployment]\n{legacy_key} = "private-value-not-for-errors"\n')
    with pytest.raises(ValueError) as error:
        load_config(repo_root=repo, config_path=path)
    message = str(error.value)
    assert "[steward.authentication].github_token" in message
    assert "https://github.com/OWNER/REPO" in message
    assert "private-value-not-for-errors" not in message
    assert len(message) < 300

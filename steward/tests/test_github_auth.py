from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest

from coquic_steward.core.config import StewardConfig, StewardDeploymentConfig
from coquic_steward.core.github_auth import (
    MAX_GITHUB_TOKEN_BYTES,
    git_environment,
    git_remote_environment,
    github_cli_environment,
    validate_ssh_remote,
)


def _config(tmp_path: Path, *, token: str = "token-value") -> StewardConfig:
    paths = {
        "github_token_path": tmp_path / "github-token",
        "git_ssh_key_path": tmp_path / "key with spaces;safe",
        "git_known_hosts_path": tmp_path / "known hosts",
    }
    paths["github_token_path"].write_text(token, encoding="utf-8")
    for path in paths.values():
        path.touch(exist_ok=True)
        path.chmod(0o600)
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=tmp_path,
        repository=tmp_path / "repository",
        codex_credential_path=tmp_path / "codex",
        min_free_bytes=100,
        max_owned_docker_bytes=200,
        recovery_free_bytes=150,
        recovery_owned_docker_bytes=100,
        **paths,
    )
    return StewardConfig(repo_root=tmp_path, deployment=deployment)


def test_local_mode_keeps_ambient_authentication(tmp_path: Path) -> None:
    config = StewardConfig(repo_root=tmp_path)

    assert github_cli_environment(config) == {}
    assert git_environment(config) == {}
    assert git_remote_environment(config) == {}


def test_git_remote_environment_preserves_production_controls(tmp_path: Path) -> None:
    config = _config(tmp_path)

    assert git_remote_environment(config) == {
        "GCM_INTERACTIVE": "never",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_SSH_COMMAND": git_environment(config)["GIT_SSH_COMMAND"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_PARAMETERS": "",
    }


def test_github_cli_environment_reads_one_token_per_call(tmp_path: Path) -> None:
    config = _config(tmp_path, token="first-token\n")

    assert github_cli_environment(config) == {"GH_TOKEN": "first-token"}
    config.github_token_path.write_text("second-token\n", encoding="utf-8")
    config.github_token_path.chmod(0o600)
    assert github_cli_environment(config) == {"GH_TOKEN": "second-token"}


@pytest.mark.parametrize(
    "contents",
    (
        "\n",
        "token\nsecond\n",
        "x" * (MAX_GITHUB_TOKEN_BYTES + 1),
        " token\n",
        "token \n",
    ),
)
def test_github_cli_environment_rejects_malformed_tokens(
    tmp_path: Path, contents: str
) -> None:
    config = _config(tmp_path, token=contents)

    with pytest.raises(ValueError, match="GitHub token"):
        github_cli_environment(config)


def test_github_cli_environment_rejects_unreadable_token(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.github_token_path.unlink()

    with pytest.raises(ValueError, match="GitHub token file"):
        github_cli_environment(config)


def test_git_environment_quotes_paths_and_sets_strict_ssh_options(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)

    command = shlex.split(git_environment(config)["GIT_SSH_COMMAND"])

    assert command == [
        "ssh",
        "-i",
        str(config.git_ssh_key_path),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config.git_known_hosts_path}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
    ]
    effective = subprocess.run(
        [*command, "-G", "github.com"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    options = dict(line.split(maxsplit=1) for line in effective)
    assert options["userknownhostsfile"] == str(config.git_known_hosts_path)
    assert options["globalknownhostsfile"] == "/dev/null"
    assert "first-token" not in git_environment(config)["GIT_SSH_COMMAND"]


@pytest.mark.parametrize(
    "remote",
    (
        "git@github.com:minhuw/coquic.git",
        "git@github.com:org/repo@branch:variant.git",
        "git@[::1]:minhuw/coquic.git",
        "ssh://git@github.com/minhuw/coquic.git",
        "ssh://github.com:2222/minhuw/coquic.git",
        "ssh://[::1]/minhuw/coquic.git",
    ),
)
def test_validate_ssh_remote_accepts_credential_free_transports(remote: str) -> None:
    assert validate_ssh_remote(remote) == remote


@pytest.mark.parametrize(
    "remote",
    (
        "https://github.com/minhuw/coquic.git",
        "file:///srv/coquic.git",
        "ssh://git:password@github.com/minhuw/coquic.git",
        "ssh://-oProxyCommand=evil@github.com/minhuw/coquic.git",
        "git:password@github.com:minhuw/coquic.git",
        "-oProxyCommand=evil@github.com:minhuw/coquic.git",
        "ext::/bin/sh",
        "/srv/coquic.git",
    ),
)
def test_validate_ssh_remote_rejects_other_or_credential_bearing_transports(
    remote: str,
) -> None:
    with pytest.raises(ValueError, match="credential-free SSH"):
        validate_ssh_remote(remote)

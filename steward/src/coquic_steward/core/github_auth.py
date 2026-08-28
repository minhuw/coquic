from __future__ import annotations

import re
import shlex
import stat
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .config import StewardConfig, StewardDeploymentConfig


MAX_GITHUB_TOKEN_BYTES = 4096
_SSH_USER = re.compile(r"^[A-Za-z0-9._-]+$")
_SSH_HOST = re.compile(r"^(?:[A-Za-z0-9.-]+|[0-9A-Fa-f:.]+)$")
_SCP_REMOTE = re.compile(
    r"^(?:(?P<user>[A-Za-z0-9._-]+)@)?"
    r"(?P<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):"
    r"(?P<path>[^\s\x00-\x1f]+)$"
)
_SCP_CREDENTIAL_FRAGMENT = re.compile(
    r"@(?:localhost|(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+):"
)


def _deployment(config: StewardConfig | StewardDeploymentConfig):
    return getattr(config, "deployment", config)


def _required_path(
    config: StewardConfig | StewardDeploymentConfig, name: str
) -> Path:
    value = getattr(_deployment(config), name, None)
    if value is None:
        raise ValueError(f"deployment.{name} is required")
    return Path(value)


def github_cli_environment(
    config: StewardConfig | StewardDeploymentConfig,
) -> dict[str, str]:
    """Return the per-call GitHub CLI environment for the trusted daemon."""

    deployment = _deployment(config)
    if not deployment.enabled:
        return {}
    token = _read_github_token(_required_path(config, "github_token_path"))
    return {"GH_TOKEN": token}


def git_environment(
    config: StewardConfig | StewardDeploymentConfig,
) -> dict[str, str]:
    """Return strict, per-call SSH settings for the trusted daemon."""

    deployment = _deployment(config)
    if not deployment.enabled:
        return {}
    key = _required_path(config, "git_ssh_key_path")
    known_hosts = _required_path(config, "git_known_hosts_path")
    command = shlex.join(
        [
            "ssh",
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
        ]
    )
    return {"GIT_SSH_COMMAND": command}


def _read_github_token(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("GitHub token file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("GitHub token file must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("GitHub token file permissions are unsafe")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_GITHUB_TOKEN_BYTES + 2)
    except OSError as exc:
        raise ValueError("GitHub token file is unreadable") from exc
    token_bytes = raw[:-1] if raw.endswith(b"\n") else raw
    if (
        len(token_bytes) > MAX_GITHUB_TOKEN_BYTES
        or b"\n" in token_bytes
        or b"\r" in token_bytes
    ):
        raise ValueError("GitHub token must be one bounded line")
    try:
        token = token_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("GitHub token must be one bounded line") from exc
    if not token or token != token.strip() or any(
        character.isspace() or ord(character) < 0x20 for character in token
    ):
        raise ValueError("GitHub token must be one bounded nonempty line")
    return token


def validate_ssh_remote(value: str) -> str:
    """Validate a credential-free SSH or SCP-style Git remote."""

    if not isinstance(value, str) or not value or any(
        character.isspace() or ord(character) < 0x20 for character in value
    ):
        raise ValueError("Git remote must be a credential-free SSH URL")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            parsed.port
        except ValueError as exc:
            raise ValueError("Git remote must be a credential-free SSH URL") from exc
        if (
            parsed.scheme.lower() != "ssh"
            or not hostname
            or hostname.startswith("-")
            or not _SSH_HOST.fullmatch(hostname)
            or (
                parsed.username is not None
                and (
                    _SSH_USER.fullmatch(parsed.username) is None
                    or parsed.username.startswith("-")
                )
            )
            or not parsed.path
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "%" in parsed.netloc
        ):
            raise ValueError("Git remote must be a credential-free SSH URL")
        return value
    match = _SCP_REMOTE.fullmatch(value)
    if (
        match is None
        or match.group("host").startswith("-")
        or (match.group("user") is not None and match.group("user").startswith("-"))
        or "::" in value.replace(match.group("host"), "", 1)
        or _SCP_CREDENTIAL_FRAGMENT.search(match.group("path")) is not None
    ):
        raise ValueError("Git remote must be a credential-free SSH URL")
    return value


def is_ssh_remote(value: str) -> bool:
    try:
        validate_ssh_remote(value)
    except ValueError:
        return False
    return True


# Short aliases keep call sites focused on the environment contract.
github_cli_env = github_cli_environment
git_env = git_environment

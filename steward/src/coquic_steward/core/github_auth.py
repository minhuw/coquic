from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if __package__:
    from .private_config import _read_toml
else:  # Direct host script: no application or third-party dependencies.
    from private_config import _read_toml

if TYPE_CHECKING:
    from .config import StewardConfig


MAX_GITHUB_TOKEN_BYTES = 4096
_GITHUB_REMOTE = re.compile(
    r"https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+"
)
_REMOTE_ERROR = "Git remote must be a credential-free https://github.com/OWNER/REPO URL"


def validate_github_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_GITHUB_TOKEN_BYTES
        or any(not 0x21 <= ord(character) <= 0x7e for character in value)
    ):
        raise ValueError("GitHub token must be nonempty ASCII without whitespace, at most 4096 bytes")
    return value


def validate_authentication_section(raw: object) -> None:
    if (
        not isinstance(raw, dict)
        or not raw
        or set(raw) - {"proxy_url", "api_key", "github_token"}
        or ("proxy_url" in raw) != ("api_key" in raw)
        or any(value is None for value in raw.values())
    ):
        raise ValueError("invalid steward.authentication: use optional github_token and paired proxy_url/api_key")
    if "github_token" in raw:
        validate_github_token(raw["github_token"])


def read_config_github_token(path: Path) -> str:
    data = _read_toml(path, required=True)
    steward = data.get("steward", data)
    raw = steward.get("authentication") if isinstance(steward, dict) else None
    validate_authentication_section(raw)
    return validate_github_token(raw.get("github_token"))


def github_cli_environment(config: StewardConfig) -> dict[str, str | None]:
    """Use only the explicit inline token, never ambient GitHub authentication."""
    token = config.authentication.github_token
    if token is None:
        if config.deployment.enabled:
            raise ValueError("production requires [steward.authentication].github_token")
        return {}
    return {
        "GH_TOKEN": validate_github_token(token.get_secret_value()),
        "GITHUB_TOKEN": None,
        "GH_ENTERPRISE_TOKEN": None,
        "GITHUB_ENTERPRISE_TOKEN": None,
        "GH_HOST": "github.com",
        "GH_CONFIG_DIR": "/dev",
        "GH_PROMPT_DISABLED": "1",
        "GH_DEBUG": None,
    }


def _tool(name: str) -> str:
    # PATH is the host/daemon toolchain boundary, never a repository helper.
    selected = shutil.which(name)
    if selected is None:
        raise ValueError(f"required {name} executable is unavailable")
    try:
        return str(Path(selected).resolve(strict=True))
    except OSError:
        raise ValueError(f"required {name} executable is unavailable") from None


def token_git_environment(token: str) -> dict[str, str | None]:
    """Per-call overrides, safe even when merged into the daemon environment.

    Git and its native gh helper receive the token only via their environment.
    Git config contains a trusted executable path, not credentials; neither
    helper setup nor auth is persisted. None-valued overrides delete inherited
    keys. Preflight rejects repository URL rewrites, HTTP and credential config.
    """

    token = validate_github_token(token)
    helper = "!" + shlex.quote(_tool("gh")) + " auth git-credential"
    settings = (
        ("credential.helper", ""),
        ("credential.https://github.com.helper", ""),
        ("credential.https://github.com.helper", helper),
        ("credential.interactive", "false"),
        ("core.askPass", ""),
        ("http.followRedirects", "false"),
        ("http.https://github.com.followRedirects", "false"),
        ("http.extraHeader", ""),
        ("http.https://github.com.extraHeader", ""),
        ("http.sslVerify", "true"),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("trace2.normalTarget", "0"),
        ("trace2.eventTarget", "0"),
        ("trace2.perfTarget", "0"),
        ("trace2.envVars", ""),
        ("trace2.configParams", ""),
    )
    environment: dict[str, str | None] = {
        "GH_TOKEN": token,
        "GITHUB_TOKEN": "",
        "GH_ENTERPRISE_TOKEN": "",
        "GITHUB_ENTERPRISE_TOKEN": "",
        "GH_HOST": "github.com",
        "GH_CONFIG_DIR": "/dev",
        "GH_PROMPT_DISABLED": "1",
        "GH_DEBUG": "",
        "GCM_INTERACTIVE": "never",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_CONFIG": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_PARAMETERS": "",
        "GIT_CONFIG_COUNT": str(len(settings)),
        "GIT_CURL_VERBOSE": "0",
        # Git treats ANY value (including "0") as disabling verification.
        "GIT_SSL_NO_VERIFY": None,
        "GIT_SSL_CAINFO": None,
        "GIT_SSL_CAPATH": None,
        "GIT_PROXY_SSL_CAINFO": None,
        "GIT_PROXY_SSL_CAPATH": None,
        "SSL_CERT_FILE": None,
        "SSL_CERT_DIR": None,
        "CURL_CA_BUNDLE": None,
        "GIT_TRACE_REDACT": "1",
    }
    # Trace2 can log selected environment variables, including GH_TOKEN.
    for name in os.environ:
        if name.startswith(("GIT_SSL_", "GIT_PROXY_SSL_")):
            environment[name] = None
        elif name.startswith("GIT_TRACE"):
            environment[name] = "0"
        elif name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            environment[name] = ""
    environment.update({
        "GIT_TRACE_REDACT": "1",
        "GIT_TRACE2_ENV_VARS": "",
        "GIT_TRACE2_CONFIG_PARAMS": "",
    })
    for index, (key, value) in enumerate(settings):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def git_environment(config: StewardConfig) -> dict[str, str | None]:
    """Return explicit HTTPS authentication, preserving local ambient mode."""
    environment = github_cli_environment(config)
    return token_git_environment(environment["GH_TOKEN"]) if environment else {}


def git_remote_environment(config: StewardConfig) -> dict[str, str | None]:
    return git_environment(config)


def validate_https_remote(value: str) -> str:
    """Accept only canonical GitHub HTTPS repository URLs, never credentials."""

    if (
        not isinstance(value, str)
        or len(value) > 2048
        or _GITHUB_REMOTE.fullmatch(value) is None
        or value.rsplit("/", 1)[-1] in {".", "..", ".git", "..git", "...git"}
    ):
        raise ValueError(_REMOTE_ERROR)
    return value


def is_https_remote(value: str) -> bool:
    try:
        validate_https_remote(value)
    except ValueError:
        return False
    return True


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's default error echoes untrusted arguments (possibly secrets).
        self.exit(2, "invalid GitHub HTTPS command arguments\n")


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="Trusted GitHub HTTPS clone boundary")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-remote")
    validate.add_argument("remote")
    validate_config = commands.add_parser("validate-config")
    validate_config.add_argument("--config", type=Path, required=True)
    clone = commands.add_parser("clone")
    clone.add_argument("--config", type=Path, required=True)
    clone.add_argument("--branch", required=True)
    clone.add_argument("--remote", required=True)
    clone.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-config":
            read_config_github_token(args.config)
            return 0
        remote = validate_https_remote(args.remote)
        if args.command == "validate-remote":
            return 0
        if args.branch != "main":
            raise ValueError("clone branch must be main")
        overrides = token_git_environment(read_config_github_token(args.config))
        # Host clone also drops inherited repository/tool selectors entirely.
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("GIT_", "GH_", "GITHUB_"))
            and key != "SSH_ASKPASS"
        }
        for key, value in overrides.items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        result = subprocess.run(
            [_tool("git"), "clone", "--branch", args.branch, "--single-branch",
             "--", remote, str(args.destination.absolute())],
            env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode:
            raise ValueError("GitHub HTTPS clone failed")
        return 0
    except (ValueError, OSError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "GitHub HTTPS clone is unavailable"
        print(message, file=sys.stderr)
        return 1


# Short aliases keep call sites focused on the environment contract.
github_cli_env = github_cli_environment
git_env = git_environment
git_remote_env = git_remote_environment


if __name__ == "__main__":
    raise SystemExit(main())

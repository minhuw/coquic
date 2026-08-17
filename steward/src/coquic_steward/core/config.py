from __future__ import annotations

import json
import math
import os
import re
import secrets
import shutil
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import CodexStage, IntegrationMode


VALID_INTEGRATION_MODES = {mode.value for mode in IntegrationMode}
DEFAULT_ENABLED_SIGNALS = (
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
DEFAULT_COQUIC_HOME = "~/.coquic"
ARCHIVE_FORMAT_VERSION = "1.0"
ARCHIVE_POLICY = "post-steward-2.0"
DEFAULT_SIGNAL_POLL_INTERVAL_MINUTES = {
    "github-actions:ci": 30,
    "github-actions:test": 30,
    "github-actions:duvet": 1440,
    "github-actions:nightly-ci": 1440,
    "github-actions:deploy-demo": 30,
    "github-actions:interop": 1440,
    "github-actions:perf": 1440,
    "github-issues:features": 360,
    "code-scanning": 360,
    "codacy": 360,
}
DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES_BY_PROVIDER = {
    "github-actions:ci": 30,
    "github-actions:test": 30,
    "github-actions:duvet": 1440,
    "github-actions:nightly-ci": 1440,
    "github-actions:deploy-demo": 30,
    "github-actions:interop": 1440,
    "github-actions:perf": 1440,
    "github-issues:features": 360,
}
DEFAULT_SIGNAL_ERROR_RETRY_MINUTES = 30
DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES = 30
DEFAULT_SIGNAL_SUPPRESSION_HOURS = 24
DEFAULT_SIGNAL_MAX_ITEMS = 12
VALID_REASONING_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}
VALID_TELEMETRY_BILLING_MODES = {"unknown", "chatgpt", "api"}
_SAFE_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CLOUDFLARE_ACCOUNT_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_CLOUDFLARE_DATABASE_ID = re.compile(
    r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"
)
_R2_BUCKET_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$")
_MAX_PUBLICATION_URL_LENGTH = 2048
_MAX_PUBLICATION_TIMEOUT_SECONDS = 86400.0
_MAX_PUBLICATION_RETRIES = 20
_KNOWN_STEWARD_SECTIONS = frozenset(
    {
        "limits",
        "signals",
        "telemetry",
        "path_policy",
        "codex",
        "container",
        "publication",
        "deployment",
    }
)
_ROOT_ALLOWED_KEYS = frozenset(
    {
        "codex_bin",
        "codex_model",
        "codex_reasoning_effort",
        "codex_profile",
        "codex_sandbox",
        "daemon_image",
        "daemon_image_digest",
        "validation_image",
        "validation_image_digest",
        "validation_runtime",
        "runtime_protocol",
        "local_codex_test_harness",
        "integration_mode",
        "local_only",
        "git_remote",
        "main_branch",
        "github_repository",
        "scheduler_wait_interval_sec",
        "shutdown_grace_seconds",
        "limits",
        "signals",
        "telemetry",
        "path_policy",
        "codex",
        "container",
        "publication",
        "deployment",
    }
)
_CONTAINER_ALLOWED_KEYS = frozenset(
    {
        "enabled",
        "image",
        "image_digest",
        "repository_host_path",
        "state_host_path",
        "codex_api_key_path",
        "docker_bin",
        "network",
        "runtime_protocol",
    }
)
_DEPLOYMENT_ALLOWED_KEYS = frozenset(
    {
        "enabled",
        "home",
        "repository",
        "docker_socket",
        "host_uid",
        "host_gid",
        "docker_gid",
        "expected_remote",
        "expected_branch",
        "compose_project",
        "codex_credential_path",
        "github_credential_path",
        "release_id",
        "daemon_image",
        "daemon_image_id",
        "task_image",
        "task_image_id",
        "validation_image",
        "validation_image_id",
        "validation_runtime",
        "stop_grace_seconds",
        "max_pids",
        "max_memory_bytes",
        "max_log_bytes",
        "max_scratch_bytes",
        "min_free_bytes",
        "max_owned_docker_bytes",
        "recovery_free_bytes",
        "recovery_owned_docker_bytes",
    }
)
_LIMITS_ALLOWED_KEYS = frozenset(
    {
        "max_active_tasks",
        "max_main_pushes_per_day",
        "plan_timeout_minutes",
        "worker_timeout_minutes",
        "review_timeout_minutes",
        "validation_timeout_minutes",
    }
)
_TELEMETRY_ALLOWED_KEYS = frozenset({"billing_mode"})


def _require_allowed_keys(
    section: str, data: object, allowed: frozenset[str]
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError(f"{section} must be a table")
    unknown = sorted(str(key) for key in data if key not in allowed)
    if unknown:
        raise ValueError(f"{section} has unsupported keys: {', '.join(unknown)}")
    return data


def _bounded_token(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    result = value.strip()
    if not result and not allow_empty:
        raise ValueError(f"{label} must not be empty")
    if len(result) > 256 or any(character in result for character in "\x00\r\n"):
        raise ValueError(f"{label} is invalid or too long")
    return result


def _absolute_path(value: object, label: str) -> Path:
    if value in (None, ""):
        raise ValueError(f"{label} is required")
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    return path


@dataclass(frozen=True)
class StewardContainerConfig:
    """Daemon-owned settings used to construct task-scoped containers.

    This is intentionally distinct from ``execution.container_config``: that
    type describes one task's fully resolved mounts, while this type describes
    the host-side launch boundary shared by all tasks.
    """

    enabled: bool = False
    image: str = "coquic-steward-task"
    image_digest: str | None = None
    repository_host_path: Path | None = None
    state_host_path: Path | None = None
    codex_api_key_path: Path | None = None
    docker_bin: str = "docker"
    network: str = "bridge"
    runtime_protocol: str = "task-container-v1"

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("container.enabled must be a boolean")
        image = _bounded_token(self.image, "container.image")
        object.__setattr__(self, "image", image)
        if self.image_digest is not None and not _valid_sha256_digest(self.image_digest):
            raise ValueError("container.image_digest must be a sha256 digest")
        if self.enabled:
            if self.repository_host_path is None or self.state_host_path is None:
                raise ValueError(
                    "enabled container configuration requires repository and state paths"
                )
            object.__setattr__(
                self, "repository_host_path", _absolute_path(self.repository_host_path, "container.repository_host_path")
            )
            object.__setattr__(
                self, "state_host_path", _absolute_path(self.state_host_path, "container.state_host_path")
            )
            if self.codex_api_key_path is None:
                raise ValueError("enabled container configuration requires codex_api_key_path")
            key = _absolute_path(self.codex_api_key_path, "container.codex_api_key_path")
            object.__setattr__(self, "codex_api_key_path", key)
        else:
            if self.repository_host_path is not None:
                object.__setattr__(self, "repository_host_path", Path(self.repository_host_path).expanduser())
            if self.state_host_path is not None:
                object.__setattr__(self, "state_host_path", Path(self.state_host_path).expanduser())
        if self.runtime_protocol != "task-container-v1":
            raise ValueError("unsupported container runtime protocol")
        object.__setattr__(self, "docker_bin", _bounded_token(self.docker_bin, "container.docker_bin"))
        object.__setattr__(self, "network", _bounded_token(self.network, "container.network"))


def _publication_optional_path(value: object, label: str) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        raise ValueError(f"publication.{label} must be an absolute path")
    if ".." in path.parts:
        raise ValueError(f"publication.{label} must not contain parent traversal")
    return path


def _publication_credential_path(value: object, label: str) -> Path:
    path = _publication_optional_path(value, label)
    if path is None:
        raise ValueError(f"publication.{label} is required")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(
            f"publication.{label} must reference a regular non-symlink file"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(
            f"publication.{label} must reference a regular non-symlink file"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"publication.{label} must use a private file mode")
    return path


def _publication_staging_root(value: object) -> Path:
    path = _publication_optional_path(value, "staging_root")
    if path is None:
        raise ValueError("publication.staging_root is required")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(
            "publication.staging_root must reference a private directory"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("publication.staging_root must reference a private directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("publication.staging_root must use a private directory mode")
    return path


def _publication_url(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"publication.{label} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > _MAX_PUBLICATION_URL_LENGTH:
        raise ValueError(f"publication.{label} must be a bounded HTTPS URL")
    if any(character.isspace() or ord(character) < 0x20 for character in normalized):
        raise ValueError(f"publication.{label} must be a bounded HTTPS URL")
    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError(f"publication.{label} must be a bounded HTTPS URL") from exc
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"publication.{label} must be a bounded HTTPS URL")
    if any(part in {".", ".."} for part in parsed.path.split("/")):
        raise ValueError(f"publication.{label} contains an unsafe path")
    return normalized


def _publication_bucket(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"publication.{label} must be a string")
    normalized = value.strip()
    if _R2_BUCKET_NAME.fullmatch(normalized) is None:
        raise ValueError(f"publication.{label} is not a valid R2 bucket name")
    return normalized


def _publication_float(value: object, label: str, *, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"publication.{label} must be a finite positive number")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized <= maximum:
        raise ValueError(
            f"publication.{label} must be greater than zero and at most {maximum:g}"
        )
    return normalized


def _publication_int(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"publication.{label} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(
            f"publication.{label} must be between zero and {maximum}"
        )
    return value


@dataclass(frozen=True)
class StewardPublicationConfig:
    """Strict, daemon-only Cloudflare D1/R2 publication settings.

    The object stores credential *paths* only.  Validation uses ``lstat`` for
    metadata and never reads credential bytes; transport workers own that
    boundary once a trusted daemon explicitly starts publication.
    """

    enabled: bool = False
    account_id: str = ""
    d1_database_id: str = ""
    d1_token_path: Path | None = None
    r2_endpoint: str = ""
    r2_access_key_id_path: Path | None = None
    r2_secret_access_key_path: Path | None = None
    public_bucket: str = ""
    private_bucket: str = ""
    public_base_url: str = ""
    staging_root: Path | None = None
    build_timeout_seconds: float = 300.0
    network_timeout_seconds: float = 30.0
    lease_duration_seconds: float = 300.0
    max_retries: int = 3
    retry_backoff_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("publication.enabled must be a boolean")

        account = self.account_id
        database = self.d1_database_id
        token_path = self.d1_token_path
        endpoint = self.r2_endpoint
        access_path = self.r2_access_key_id_path
        secret_path = self.r2_secret_access_key_path
        public_bucket = self.public_bucket
        private_bucket = self.private_bucket
        public_url = self.public_base_url
        staging = self.staging_root
        lease = self.lease_duration_seconds
        retries = self.max_retries

        for value, label in (
            (account, "account_id"),
            (database, "d1_database_id"),
            (endpoint, "r2_endpoint"),
            (public_bucket, "public_bucket"),
            (private_bucket, "private_bucket"),
            (public_url, "public_base_url"),
        ):
            if value not in (None, "") and not isinstance(value, str):
                raise ValueError(f"publication.{label} must be a string")
        account = account.strip() if isinstance(account, str) else ""
        database = database.strip() if isinstance(database, str) else ""
        endpoint = endpoint.strip() if isinstance(endpoint, str) else ""
        public_bucket = public_bucket.strip() if isinstance(public_bucket, str) else ""
        private_bucket = private_bucket.strip() if isinstance(private_bucket, str) else ""
        public_url = public_url.strip() if isinstance(public_url, str) else ""
        token_path = _publication_optional_path(token_path, "d1_token_path")
        access_path = _publication_optional_path(
            access_path, "r2_access_key_id_path"
        )
        secret_path = _publication_optional_path(
            secret_path, "r2_secret_access_key_path"
        )
        staging = _publication_optional_path(staging, "staging_root")

        if account:
            if _CLOUDFLARE_ACCOUNT_ID.fullmatch(account) is None:
                raise ValueError("publication.account_id must be a 32-character hexadecimal ID")
            account = account.lower()
        if database:
            if _CLOUDFLARE_DATABASE_ID.fullmatch(database) is None:
                raise ValueError("publication.d1_database_id must be a UUID")
            database = database.lower()
        if endpoint:
            endpoint = _publication_url(endpoint, "r2_endpoint")
        if public_url:
            public_url = _publication_url(public_url, "public_base_url")
        if public_bucket:
            public_bucket = _publication_bucket(public_bucket, "public_bucket")
        if private_bucket:
            private_bucket = _publication_bucket(private_bucket, "private_bucket")
        if public_bucket and private_bucket and public_bucket == private_bucket:
            raise ValueError("publication.public_bucket and private_bucket must differ")

        build_timeout = _publication_float(
            self.build_timeout_seconds,
            "build_timeout_seconds",
            maximum=_MAX_PUBLICATION_TIMEOUT_SECONDS,
        )
        network_timeout = _publication_float(
            self.network_timeout_seconds,
            "network_timeout_seconds",
            maximum=_MAX_PUBLICATION_TIMEOUT_SECONDS,
        )
        lease_seconds = _publication_float(
            lease,
            "lease_duration_seconds",
            maximum=_MAX_PUBLICATION_TIMEOUT_SECONDS,
        )
        retry_count = _publication_int(retries, "max_retries", maximum=_MAX_PUBLICATION_RETRIES)
        retry_backoff = _publication_float(
            self.retry_backoff_seconds,
            "retry_backoff_seconds",
            maximum=_MAX_PUBLICATION_TIMEOUT_SECONDS,
        )

        if self.enabled:
            required = (
                (account, "account_id"),
                (database, "d1_database_id"),
                (endpoint, "r2_endpoint"),
                (public_bucket, "public_bucket"),
                (private_bucket, "private_bucket"),
                (public_url, "public_base_url"),
            )
            missing = [label for value, label in required if not value]
            if missing:
                raise ValueError(
                    "enabled publication requires " + ", ".join(missing)
                )
            token_path = _publication_credential_path(token_path, "d1_token_path")
            access_path = _publication_credential_path(
                access_path, "r2_access_key_id_path"
            )
            secret_path = _publication_credential_path(
                secret_path, "r2_secret_access_key_path"
            )
            staging = _publication_staging_root(staging)
            credential_paths = {token_path, access_path, secret_path}
            if len(credential_paths) != 3:
                raise ValueError("publication credential paths must be separate files")
        object.__setattr__(self, "account_id", account)
        object.__setattr__(self, "d1_database_id", database)
        object.__setattr__(self, "d1_token_path", token_path)
        object.__setattr__(self, "r2_endpoint", endpoint)
        object.__setattr__(self, "r2_access_key_id_path", access_path)
        object.__setattr__(self, "r2_secret_access_key_path", secret_path)
        object.__setattr__(self, "public_bucket", public_bucket)
        object.__setattr__(self, "private_bucket", private_bucket)
        object.__setattr__(self, "public_base_url", public_url)
        object.__setattr__(self, "staging_root", staging)
        object.__setattr__(self, "build_timeout_seconds", build_timeout)
        object.__setattr__(self, "network_timeout_seconds", network_timeout)
        object.__setattr__(self, "lease_duration_seconds", lease_seconds)
        object.__setattr__(self, "max_retries", retry_count)
        object.__setattr__(self, "retry_backoff_seconds", retry_backoff)


@dataclass(frozen=True)
class StewardDeploymentConfig:
    """The host-side Docker Compose contract for the trusted daemon.

    Values are deliberately boring primitives so this object can be populated
    from TOML and inspected by the shell management boundary without exposing
    credential contents.  ``enabled`` is false for the historical local test
    configuration; production Compose sets every path and threshold
    explicitly.
    """

    enabled: bool = False
    home: Path | None = None
    repository: Path | None = None
    docker_socket: Path = Path("/var/run/docker.sock")
    host_uid: int | None = None
    host_gid: int | None = None
    docker_gid: int | None = None
    expected_remote: str = "origin"
    expected_branch: str = "main"
    compose_project: str = "coquic-steward"
    codex_credential_path: Path | None = None
    github_credential_path: Path | None = None
    release_id: str | None = None
    daemon_image: str = "coquic-steward-daemon"
    daemon_image_id: str | None = None
    task_image: str = "coquic-steward-task"
    task_image_id: str | None = None
    validation_image: str = "coquic-steward-validation"
    validation_image_id: str | None = None
    validation_runtime: str = "validation-container-v1"
    stop_grace_seconds: int = 45
    max_pids: int = 512
    max_memory_bytes: int = 4 * 1024 * 1024 * 1024
    max_log_bytes: int = 64 * 1024 * 1024
    max_scratch_bytes: int = 8 * 1024 * 1024 * 1024
    min_free_bytes: int | None = None
    max_owned_docker_bytes: int | None = None
    recovery_free_bytes: int | None = None
    recovery_owned_docker_bytes: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("deployment.enabled must be a boolean")
        for name in ("home", "repository", "codex_credential_path", "github_credential_path"):
            value = getattr(self, name)
            if value is not None:
                path = _absolute_path(value, f"deployment.{name}")
                if path.is_symlink():
                    raise ValueError(f"deployment.{name} must not be a symlink")
                object.__setattr__(self, name, path)
        socket = _absolute_path(self.docker_socket, "deployment.docker_socket")
        object.__setattr__(self, "docker_socket", socket)
        if self.enabled and (self.home is None or self.repository is None):
            raise ValueError("deployment requires an absolute home and repository")
        if self.repository is not None and self.home is not None:
            expected = self.home / "repository"
            if self.repository != expected:
                raise ValueError("deployment.repository must be COQUIC_HOME/repository")
        for name in ("host_uid", "host_gid", "docker_gid"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535):
                raise ValueError(f"deployment.{name} must be a numeric UID/GID")
        for name in ("stop_grace_seconds", "max_pids", "max_memory_bytes", "max_log_bytes", "max_scratch_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"deployment.{name} must be a positive bounded integer")
        if self.stop_grace_seconds < 31 or self.stop_grace_seconds > 3600:
            raise ValueError("deployment.stop_grace_seconds must exceed daemon shutdown grace")
        thresholds = ("min_free_bytes", "max_owned_docker_bytes", "recovery_free_bytes", "recovery_owned_docker_bytes")
        for name in thresholds:
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
                raise ValueError(f"deployment.{name} must be a positive integer")
        if self.enabled and any(getattr(self, name) is None for name in ("min_free_bytes", "max_owned_docker_bytes", "recovery_free_bytes", "recovery_owned_docker_bytes")):
            raise ValueError("production deployment requires explicit resource thresholds")
        if self.min_free_bytes is not None and self.recovery_free_bytes is not None and self.recovery_free_bytes <= self.min_free_bytes:
            raise ValueError("deployment.recovery_free_bytes must be above min_free_bytes")
        if self.max_owned_docker_bytes is not None and self.recovery_owned_docker_bytes is not None and self.recovery_owned_docker_bytes >= self.max_owned_docker_bytes:
            raise ValueError("deployment.recovery_owned_docker_bytes must be below max_owned_docker_bytes")
        for name in ("expected_remote", "expected_branch", "compose_project", "daemon_image", "task_image", "validation_image", "validation_runtime"):
            value = _bounded_token(getattr(self, name), f"deployment.{name}")
            object.__setattr__(self, name, value)
        if self.release_id is not None:
            release = _bounded_token(self.release_id, "deployment.release_id")
            if _SAFE_RELEASE.fullmatch(release) is None:
                raise ValueError("deployment.release_id is not a safe release identity")
            object.__setattr__(self, "release_id", release)
        for name in ("daemon_image_id", "task_image_id", "validation_image_id"):
            value = getattr(self, name)
            if value is not None and not _valid_sha256_digest(value):
                raise ValueError(f"deployment.{name} must be a sha256 image ID")
        if self.validation_runtime != "validation-container-v1":
            raise ValueError("deployment.validation_runtime is unsupported")

    @property
    def credentials_dir(self) -> Path | None:
        return self.home / "private" / "credentials" if self.home is not None else None

    @property
    def deployment_dir(self) -> Path | None:
        return self.home / "private" / "deployment" if self.home is not None else None

    @property
    def current_release_path(self) -> Path | None:
        return self.deployment_dir / "current" if self.deployment_dir is not None else None

    @property
    def previous_release_path(self) -> Path | None:
        return self.deployment_dir / "previous" if self.deployment_dir is not None else None


def _valid_sha256_digest(value: str) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(
        character in "0123456789abcdef" for character in value[7:]
    )


@dataclass(frozen=True)
class StewardLimits:
    max_active_tasks: int = 4
    max_main_pushes_per_day: int = 10
    plan_timeout_minutes: int = 30
    worker_timeout_minutes: int = 120
    review_timeout_minutes: int = 20
    validation_timeout_minutes: int = 30


@dataclass(frozen=True)
class PathPolicyConfig:
    frozen: tuple[str, ...] = ()
    frozen_by_kind: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def frozen_for_kind(self, kind: object) -> tuple[str, ...]:
        kind_value = str(kind)
        paths = [*self.frozen, *self.frozen_by_kind.get(kind_value, ())]
        return tuple(dict.fromkeys(paths))


@dataclass(frozen=True)
class SignalProviderConfig:
    poll_interval_minutes: int
    error_retry_minutes: int = DEFAULT_SIGNAL_ERROR_RETRY_MINUTES
    idle_poll_interval_minutes: int = DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES
    suppression_hours: int = DEFAULT_SIGNAL_SUPPRESSION_HOURS
    max_items: int = DEFAULT_SIGNAL_MAX_ITEMS


@dataclass(frozen=True)
class CodexStageConfig:
    model: str | None = None
    reasoning_effort: str | None = None


@dataclass(frozen=True)
class CodexRunSettings:
    stage: CodexStage
    model: str | None
    reasoning_effort: str | None


@dataclass(frozen=True)
class TelemetryConfig:
    """Telemetry settings."""

    billing_mode: str = "unknown"

    def __post_init__(self) -> None:
        if self.billing_mode not in VALID_TELEMETRY_BILLING_MODES:
            choices = ", ".join(sorted(VALID_TELEMETRY_BILLING_MODES))
            raise ValueError(
                f"invalid telemetry.billing_mode {self.billing_mode!r}; "
                f"expected {choices}"
            )


@dataclass(frozen=True)
class StewardConfig:
    repo_root: Path
    codex_bin: str = "codex"
    codex_model: str | None = None
    codex_reasoning_effort: str | None = None
    codex_stages: dict[str, CodexStageConfig] = field(default_factory=dict)
    codex_profile: str | None = None
    codex_sandbox: str = "workspace-write"
    codex_identity: str | None = None
    task_image: str = "coquic-steward-task"
    task_image_digest: str | None = None
    daemon_image: str = "coquic-steward-daemon"
    daemon_image_digest: str | None = None
    validation_image: str = "coquic-steward-validation"
    validation_image_digest: str | None = None
    validation_runtime: str = "validation-container-v1"
    runtime_protocol: str = "task-container-v1"
    local_codex_test_harness: bool = False
    integration_mode: str = IntegrationMode.local_only.value
    local_only: bool = False
    git_remote: str = "origin"
    main_branch: str = "main"
    github_repository: str = "minhuw/coquic"
    enabled_signals: tuple[str, ...] = DEFAULT_ENABLED_SIGNALS
    signal_providers: dict[str, SignalProviderConfig] = field(default_factory=dict)
    scheduler_wait_interval_sec: float = 1.0
    limits: StewardLimits = field(default_factory=StewardLimits)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    path_policy: PathPolicyConfig = field(default_factory=PathPolicyConfig)
    container: StewardContainerConfig = field(default_factory=StewardContainerConfig)
    publication: StewardPublicationConfig = field(default_factory=StewardPublicationConfig)
    deployment: StewardDeploymentConfig = field(default_factory=StewardDeploymentConfig)
    shutdown_grace_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.deployment.enabled and self.deployment.stop_grace_seconds <= self.shutdown_grace_seconds:
            raise ValueError(
                "deployment.stop_grace_seconds must exceed shutdown_grace_seconds"
            )
        if self.container.enabled:
            if (
                self.task_image_digest is not None
                and self.task_image_digest != self.container.image_digest
            ):
                raise ValueError(
                    "task_image_digest conflicts with container.image_digest"
                )
            if self.task_image not in {
                "coquic-steward-task",
                self.container.image,
            }:
                raise ValueError("task_image conflicts with container.image")
            if self.runtime_protocol != self.container.runtime_protocol:
                raise ValueError(
                    "runtime_protocol conflicts with container.runtime_protocol"
                )
            object.__setattr__(self, "task_image", self.container.image)
            object.__setattr__(
                self, "task_image_digest", self.container.image_digest
            )
            object.__setattr__(
                self, "runtime_protocol", self.container.runtime_protocol
            )
        if self.integration_mode not in VALID_INTEGRATION_MODES:
            choices = ", ".join(sorted(VALID_INTEGRATION_MODES))
            raise ValueError(
                f"invalid integration_mode {self.integration_mode!r}; expected {choices}"
            )
        _validate_github_repository(self.github_repository)
        if isinstance(self.shutdown_grace_seconds, bool) or not isinstance(
            self.shutdown_grace_seconds, (int, float)
        ) or not 5 <= float(self.shutdown_grace_seconds) <= 300:
            raise ValueError("shutdown_grace_seconds must be between 5 and 300")
        if not self.task_image or "\n" in self.task_image:
            raise ValueError("task_image must be non-empty and single-line")
        if self.task_image_digest is not None and not _valid_sha256_digest(self.task_image_digest):
            raise ValueError("task_image_digest must be a sha256 digest")
        if self.daemon_image_digest is not None and not _valid_sha256_digest(self.daemon_image_digest):
            raise ValueError("daemon_image_digest must be a sha256 digest")
        if self.validation_image_digest is not None and not _valid_sha256_digest(self.validation_image_digest):
            raise ValueError("validation_image_digest must be a sha256 digest")
        if self.runtime_protocol != "task-container-v1":
            raise ValueError("unsupported task runtime protocol")
        if self.validation_runtime != "validation-container-v1":
            raise ValueError("unsupported validation runtime protocol")
        _validate_reasoning_effort(
            self.codex_reasoning_effort, "codex_reasoning_effort"
        )
        for stage, stage_config in self.codex_stages.items():
            CodexStage(stage)
            _validate_reasoning_effort(
                stage_config.reasoning_effort,
                f"codex.{stage}.reasoning_effort",
            )
        providers = dict(self.signal_providers)
        for name in self.enabled_signals:
            providers.setdefault(name, default_signal_provider_config(name))
        object.__setattr__(self, "signal_providers", providers)

    @property
    def codex_api_key_path(self) -> Path | None:
        """Daemon-only path for the configured Codex credential."""

        return self.container.codex_api_key_path

    def read_codex_api_key_bytes(self) -> bytes | None:
        """Read the configured key without consulting the daemon environment.

        The byte sequence is intentionally returned unchanged.  The session
        boundary decides how those bytes are delivered to a task wrapper; no
        caller should place them in prompts, normalized metadata, or logs.
        """

        path = self.codex_api_key_path
        if not self.container.enabled or path is None:
            return None
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("configured Codex API key file is not private")
        value = path.read_bytes()
        if not value:
            raise ValueError("configured Codex API key file is empty")
        return value

    @property
    def coquic_home(self) -> Path:
        configured = self.deployment.home
        if configured is not None:
            return configured
        return Path(os.getenv("COQUIC_HOME", DEFAULT_COQUIC_HOME)).expanduser()

    @property
    def repository_path(self) -> Path:
        """The only canonical clone accepted by the Compose deployment."""

        return self.deployment.repository or (self.coquic_home / "repository")

    @property
    def docker_socket(self) -> Path:
        return self.deployment.docker_socket

    @property
    def repository_host_path(self) -> Path:
        return self.repository_path

    @property
    def codex_credential_path(self) -> Path | None:
        return self.deployment.codex_credential_path

    @property
    def github_credential_path(self) -> Path | None:
        return self.deployment.github_credential_path

    @property
    def host_uid(self) -> int | None:
        return self.deployment.host_uid

    @property
    def host_gid(self) -> int | None:
        return self.deployment.host_gid

    @property
    def docker_gid(self) -> int | None:
        return self.deployment.docker_gid

    @property
    def credentials_dir(self) -> Path:
        return self.deployment.credentials_dir or (self.private_dir / "credentials")

    @property
    def deployment_dir(self) -> Path:
        return self.deployment.deployment_dir or (self.private_dir / "deployment")

    @property
    def steward_home(self) -> Path:
        if self.deployment.enabled:
            return self.private_dir / "runtime"
        return self.coquic_home / "steward"

    @property
    def state_dir(self) -> Path:
        return self.steward_home

    @property
    def worktrees_dir(self) -> Path:
        return self.coquic_home / "worktrees"

    @property
    def tasks_dir(self) -> Path:
        return self.coquic_home / "tasks"

    @property
    def control_loop_dir(self) -> Path:
        """Canonical public-by-placement scheduler control-loop root."""

        return self.coquic_home / "control-loop"

    @property
    def private_dir(self) -> Path:
        return self.coquic_home / "private"

    @property
    def private_root(self) -> Path:
        return self.private_dir

    @property
    def private_sessions_dir(self) -> Path:
        return self.private_dir / "codex-sessions"

    @property
    def transcripts_dir(self) -> Path:
        return self.state_dir / "transcripts"

    @property
    def db_path(self) -> Path:
        return self.coquic_home / "steward.sqlite"

    @property
    def epoch_path(self) -> Path:
        return self.tasks_dir / "epoch.json"

    @property
    def logs_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def prompts_dir(self) -> Path:
        return self.state_dir / "prompts"

    @property
    def patches_dir(self) -> Path:
        return self.state_dir / "patches"

    @property
    def implementation_plans_dir(self) -> Path:
        return self.state_dir / "implementation-plans"

    def codex_settings(self, stage: CodexStage | str) -> CodexRunSettings:
        selected = CodexStage(stage)
        override = self.codex_stages.get(selected.value, CodexStageConfig())
        return CodexRunSettings(
            stage=selected,
            model=override.model or self.codex_model,
            reasoning_effort=(
                override.reasoning_effort or self.codex_reasoning_effort
            ),
        )

    def ensure_dirs(self) -> None:
        roots = (
            self.coquic_home,
            self.worktrees_dir,
            self.tasks_dir,
            self.control_loop_dir,
            self.private_dir,
            self.private_sessions_dir,
            self.state_dir,
            self.transcripts_dir,
            self.logs_dir,
            self.prompts_dir,
            self.patches_dir,
            self.implementation_plans_dir,
        )
        if self.deployment.enabled:
            roots = roots + (self.credentials_dir, self.deployment_dir)
        _ensure_controlled_roots(roots)

    def ensure_epoch(self) -> dict[str, Any]:
        """Create or verify the single immutable post-2.0 archive epoch."""
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        path = self.epoch_path
        if path.is_symlink():
            raise RuntimeError(f"archive epoch is a symlink: {path}")
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid archive epoch: {path}") from exc
            if not _valid_epoch(data):
                raise RuntimeError("archive epoch does not match post-steward-2.0")
            return data
        data = {
            "epochId": f"epoch-{secrets.token_hex(12)}",
            "formatVersion": ARCHIVE_FORMAT_VERSION,
            "policy": ARCHIVE_POLICY,
            "startedAt": _utc_timestamp(),
            "endedAt": None,
        }
        temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
        temporary.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        _fsync_file(temporary)
        try:
            try:
                os.link(temporary, path)
            except FileExistsError:
                # Another allocator won the epoch race.  Its exact immutable
                # bytes are authoritative and are verified on the next read.
                pass
        finally:
            temporary.unlink(missing_ok=True)
        _fsync_directory(path.parent)
        if path.is_symlink():
            raise RuntimeError(f"archive epoch is a symlink: {path}")
        result = json.loads(path.read_text(encoding="utf-8"))
        if not _valid_epoch(result):
            raise RuntimeError("archive epoch does not match post-steward-2.0")
        return result


def load_config(
    repo_root: Path | None = None,
    config_path: Path | None = None,
) -> StewardConfig:
    if config_path is None:
        configured_path = os.getenv("COQUIC_STEWARD_CONFIG_PATH") or os.getenv("STEWARD_CONFIG_PATH")
        if configured_path:
            config_path = Path(configured_path)
    configured_repository = os.getenv("COQUIC_REPOSITORY")
    root = find_repo_root(
        repo_root
        or (Path(configured_repository) if configured_repository else Path.cwd())
    )
    data = _read_config(root, config_path)
    steward = data.get("steward", data)
    if not isinstance(steward, dict):
        raise ValueError("steward configuration must be a table")
    if "cloud_publication" in steward:
        raise ValueError("unknown configuration section: steward.cloud_publication")
    for section_name, section_value in steward.items():
        if isinstance(section_value, dict) and section_name not in _KNOWN_STEWARD_SECTIONS:
            raise ValueError(f"unknown configuration section: steward.{section_name}")
    _require_allowed_keys("steward", steward, _ROOT_ALLOWED_KEYS)
    limits_data = _require_allowed_keys(
        "steward.limits", steward.get("limits", {}), _LIMITS_ALLOWED_KEYS
    )
    signals_data = steward.get("signals", {})
    telemetry_data = steward.get("telemetry", {})
    path_policy_data = steward.get("path_policy", {})
    codex_data = steward.get("codex", {})
    container_data = _require_allowed_keys(
        "steward.container", steward.get("container", {}), _CONTAINER_ALLOWED_KEYS
    )
    publication_data = steward.get("publication", {})
    deployment_data = _require_allowed_keys(
        "steward.deployment", steward.get("deployment", {}), _DEPLOYMENT_ALLOWED_KEYS
    )
    _reject_embedded_secrets(steward)
    deployment_config = _deployment_config(deployment_data, root)
    selected_task_image = (
        deployment_config.task_image_id if deployment_config.enabled else None
    )
    selected_daemon_image = (
        deployment_config.daemon_image_id if deployment_config.enabled else None
    )
    selected_validation_image = (
        deployment_config.validation_image_id if deployment_config.enabled else None
    )
    runtime_container_data = dict(container_data)
    if selected_task_image is not None:
        runtime_container_data["image"] = selected_task_image
        runtime_container_data["image_digest"] = selected_task_image
    container_config = _container_config(runtime_container_data, root)
    enabled_signals = _string_tuple(
        signals_data.get("enabled", DEFAULT_ENABLED_SIGNALS)
    )
    config = StewardConfig(
        repo_root=root,
        codex_bin=_resolve_executable(str(steward.get("codex_bin", "codex"))),
        codex_model=steward.get("codex_model")
        or os.getenv("COQUIC_STEWARD_CODEX_MODEL")
        or None,
        codex_reasoning_effort=steward.get("codex_reasoning_effort")
        or os.getenv("COQUIC_STEWARD_CODEX_REASONING_EFFORT")
        or None,
        codex_stages=_codex_stage_configs(codex_data),
        codex_profile=steward.get("codex_profile")
        or os.getenv("COQUIC_STEWARD_CODEX_PROFILE")
        or None,
        codex_sandbox=str(steward.get("codex_sandbox", "workspace-write")),
        codex_identity=(
            str(codex_data.get("identity"))
            if isinstance(codex_data, dict) and codex_data.get("identity") is not None
            else None
        ),
        task_image=container_config.image,
        task_image_digest=container_config.image_digest,
        daemon_image=selected_daemon_image
        or str(steward.get("daemon_image", "coquic-steward-daemon")),
        daemon_image_digest=(
            selected_daemon_image or str(steward.get("daemon_image_digest"))
            if selected_daemon_image is not None
            or steward.get("daemon_image_digest") is not None
            else None
        ),
        validation_image=selected_validation_image
        or str(steward.get("validation_image", "coquic-steward-validation")),
        validation_image_digest=(
            selected_validation_image or str(steward.get("validation_image_digest"))
            if selected_validation_image is not None
            or steward.get("validation_image_digest") is not None
            else None
        ),
        validation_runtime=str(steward.get("validation_runtime", "validation-container-v1")),
        runtime_protocol=str(steward.get("runtime_protocol", "task-container-v1")),
        local_codex_test_harness=bool(
            steward.get("local_codex_test_harness", False)
        ),
        integration_mode=str(
            steward.get("integration_mode", IntegrationMode.local_only.value)
        ),
        local_only=bool(steward.get("local_only", False)),
        git_remote=str(steward.get("git_remote", "origin")),
        main_branch=str(steward.get("main_branch", "main")),
        github_repository=str(steward.get("github_repository", "minhuw/coquic")),
        enabled_signals=enabled_signals,
        signal_providers=_signal_provider_configs(signals_data, enabled_signals),
        scheduler_wait_interval_sec=float(
            steward.get("scheduler_wait_interval_sec", 1.0)
        ),
        limits=StewardLimits(
            max_active_tasks=int(limits_data.get("max_active_tasks", 4)),
            max_main_pushes_per_day=int(limits_data.get("max_main_pushes_per_day", 10)),
            plan_timeout_minutes=int(limits_data.get("plan_timeout_minutes", 30)),
            worker_timeout_minutes=int(limits_data.get("worker_timeout_minutes", 120)),
            review_timeout_minutes=int(limits_data.get("review_timeout_minutes", 20)),
            validation_timeout_minutes=int(
                limits_data.get("validation_timeout_minutes", 30)
            ),
        ),
        telemetry=_telemetry_config(telemetry_data),
        path_policy=_path_policy_config(path_policy_data),
        container=container_config,
        publication=_publication_config(publication_data),
        deployment=deployment_config,
        shutdown_grace_seconds=float(steward.get("shutdown_grace_seconds", 30.0)),
    )
    config.ensure_dirs()
    return config


_SECRET_KEY_PARTS = (
    "secret",
    "token",
    "password",
    "credential",
    "api_key",
    "apikey",
    "private_key",
)


def _reject_embedded_secrets(value: object, path: str = "steward") -> None:
    """Reject credentials in TOML while allowing paths to secret files."""

    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in _SECRET_KEY_PARTS):
                if not normalized.endswith(("_path", "_file", "_identity")):
                    raise ValueError(
                        f"{path}.{key} must reference a secret file, not a secret value"
                    )
            _reject_embedded_secrets(child, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, child in enumerate(value):
            _reject_embedded_secrets(child, f"{path}[{index}]")


def _container_config(raw: object, root: Path) -> StewardContainerConfig:
    data = _require_allowed_keys("steward.container", raw, _CONTAINER_ALLOWED_KEYS)
    enabled = bool(data.get("enabled", False))
    repository = data.get("repository_host_path")
    state = data.get("state_host_path")
    if repository is None and enabled:
        repository = str(root)
    if state is None and enabled:
        state = str(Path(os.getenv("COQUIC_HOME", DEFAULT_COQUIC_HOME)).expanduser())
    key = data.get("codex_api_key_path")
    image_digest = data.get("image_digest")
    return StewardContainerConfig(
        enabled=enabled,
        image=str(data.get("image", "coquic-steward-task")),
        image_digest=str(image_digest) if image_digest is not None else None,
        repository_host_path=Path(repository).expanduser() if repository is not None else None,
        state_host_path=Path(state).expanduser() if state is not None else None,
        codex_api_key_path=Path(key).expanduser() if key is not None else None,
        docker_bin=_resolve_executable(str(data.get("docker_bin", "docker"))),
        network=str(data.get("network", "bridge")),
        runtime_protocol=str(data.get("runtime_protocol", "task-container-v1")),
    )


def _deployment_config(raw: object, root: Path) -> StewardDeploymentConfig:
    data = _require_allowed_keys("steward.deployment", raw, _DEPLOYMENT_ALLOWED_KEYS)
    enabled = bool(data.get("enabled", False))
    home_value = data.get("home")
    if home_value is None and enabled:
        home_value = os.getenv("COQUIC_HOME")
    home = Path(home_value).expanduser() if home_value is not None else None
    repository_value = data.get("repository")
    if repository_value is None and home is not None:
        repository_value = home / "repository"
    return StewardDeploymentConfig(
        enabled=enabled,
        home=home,
        repository=Path(repository_value).expanduser() if repository_value is not None else None,
        docker_socket=Path(data.get("docker_socket", "/var/run/docker.sock")).expanduser(),
        host_uid=int(data["host_uid"]) if "host_uid" in data else None,
        host_gid=int(data["host_gid"]) if "host_gid" in data else None,
        docker_gid=int(data["docker_gid"]) if "docker_gid" in data else None,
        expected_remote=str(data.get("expected_remote", "origin")),
        expected_branch=str(data.get("expected_branch", "main")),
        compose_project=str(data.get("compose_project", "coquic-steward")),
        codex_credential_path=(
            Path(data["codex_credential_path"]).expanduser()
            if data.get("codex_credential_path") is not None
            else None
        ),
        github_credential_path=(
            Path(data["github_credential_path"]).expanduser()
            if data.get("github_credential_path") is not None
            else None
        ),
        release_id=(
            os.getenv("STEWARD_RELEASE_ID")
            if enabled and os.getenv("STEWARD_RELEASE_ID")
            else str(data["release_id"])
            if data.get("release_id") is not None
            else None
        ),
        daemon_image=str(data.get("daemon_image", "coquic-steward-daemon")),
        daemon_image_id=(
            os.getenv("STEWARD_DAEMON_IMAGE")
            if enabled and os.getenv("STEWARD_DAEMON_IMAGE")
            else str(data["daemon_image_id"])
            if data.get("daemon_image_id") is not None
            else None
        ),
        task_image=str(data.get("task_image", "coquic-steward-task")),
        task_image_id=(
            os.getenv("STEWARD_TASK_IMAGE")
            if enabled and os.getenv("STEWARD_TASK_IMAGE")
            else str(data["task_image_id"])
            if data.get("task_image_id") is not None
            else None
        ),
        validation_image=str(data.get("validation_image", "coquic-steward-validation")),
        validation_image_id=(
            os.getenv("STEWARD_VALIDATION_IMAGE")
            if enabled and os.getenv("STEWARD_VALIDATION_IMAGE")
            else str(data["validation_image_id"])
            if data.get("validation_image_id") is not None
            else None
        ),
        validation_runtime=str(data.get("validation_runtime", "validation-container-v1")),
        stop_grace_seconds=int(data.get("stop_grace_seconds", 45)),
        max_pids=int(data.get("max_pids", 512)),
        max_memory_bytes=int(data.get("max_memory_bytes", 4 * 1024 * 1024 * 1024)),
        max_log_bytes=int(data.get("max_log_bytes", 64 * 1024 * 1024)),
        max_scratch_bytes=int(data.get("max_scratch_bytes", 8 * 1024 * 1024 * 1024)),
        min_free_bytes=(int(data["min_free_bytes"]) if "min_free_bytes" in data else None),
        max_owned_docker_bytes=(int(data["max_owned_docker_bytes"]) if "max_owned_docker_bytes" in data else None),
        recovery_free_bytes=(int(data["recovery_free_bytes"]) if "recovery_free_bytes" in data else None),
        recovery_owned_docker_bytes=(int(data["recovery_owned_docker_bytes"]) if "recovery_owned_docker_bytes" in data else None),
    )


def _publication_config(raw: object) -> StewardPublicationConfig:
    data = raw if isinstance(raw, dict) else {}
    allowed = {
        "enabled",
        "account_id",
        "d1_database_id",
        "d1_token_path",
        "r2_endpoint",
        "r2_access_key_id_path",
        "r2_secret_access_key_path",
        "public_bucket",
        "private_bucket",
        "public_base_url",
        "staging_root",
        "build_timeout_seconds",
        "network_timeout_seconds",
        "lease_duration_seconds",
        "max_retries",
        "retry_backoff_seconds",
    }
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(
            "publication accepts only fixed cloud transport settings; unsupported keys: "
            + ", ".join(str(value) for value in unknown)
        )
    enabled = data.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("publication.enabled must be a boolean")
    return StewardPublicationConfig(
        enabled=enabled,
        account_id=data.get("account_id", ""),
        d1_database_id=data.get("d1_database_id", ""),
        d1_token_path=data.get("d1_token_path"),
        r2_endpoint=data.get("r2_endpoint", ""),
        r2_access_key_id_path=data.get("r2_access_key_id_path"),
        r2_secret_access_key_path=data.get("r2_secret_access_key_path"),
        public_bucket=data.get("public_bucket", ""),
        private_bucket=data.get("private_bucket", ""),
        public_base_url=data.get("public_base_url", ""),
        staging_root=data.get("staging_root"),
        build_timeout_seconds=data.get("build_timeout_seconds", 300.0),
        network_timeout_seconds=data.get("network_timeout_seconds", 30.0),
        lease_duration_seconds=data.get("lease_duration_seconds", 300.0),
        max_retries=data.get("max_retries", 3),
        retry_backoff_seconds=data.get("retry_backoff_seconds", 5.0),
    )


def _codex_stage_configs(raw: object) -> dict[str, CodexStageConfig]:
    data = raw if isinstance(raw, dict) else {}
    configs: dict[str, CodexStageConfig] = {}
    for stage in CodexStage:
        value = data.get(stage.value, {})
        if not isinstance(value, dict):
            raise ValueError(f"expected [steward.codex.{stage.value}] table")
        model = value.get("model")
        reasoning = value.get("reasoning_effort")
        if model is not None and (not isinstance(model, str) or not model.strip()):
            raise ValueError(f"codex.{stage.value}.model must be a non-empty string")
        if reasoning is not None and not isinstance(reasoning, str):
            raise ValueError(
                f"codex.{stage.value}.reasoning_effort must be a string"
            )
        if model is not None or reasoning is not None:
            configs[stage.value] = CodexStageConfig(
                model=model.strip() if isinstance(model, str) else None,
                reasoning_effort=(
                    reasoning.strip() if isinstance(reasoning, str) else None
                ),
            )
    return configs


def _validate_reasoning_effort(value: str | None, label: str) -> None:
    if value is None:
        return
    if value not in VALID_REASONING_EFFORTS:
        choices = ", ".join(sorted(VALID_REASONING_EFFORTS))
        raise ValueError(f"invalid {label} {value!r}; expected one of {choices}")


def find_repo_root(start: Path) -> Path:
    path = start.resolve()
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError(f"unable to find git repository root from {path}")


def _read_config(root: Path, config_path: Path | None) -> dict[str, Any]:
    if config_path is not None:
        path = config_path if config_path.is_absolute() else root / config_path
        return _read_toml(path, required=True)
    return _read_toml(_global_config_path(), required=False)


def _global_config_path() -> Path:
    return (
        Path(os.getenv("COQUIC_HOME", DEFAULT_COQUIC_HOME)).expanduser()
        / "steward.toml"
    )


def _read_toml(path: Path, *, required: bool) -> dict[str, Any]:
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _resolve_executable(value: str) -> str:
    path = Path(value).expanduser()
    if path.is_absolute() or os.sep in value:
        return str(path)
    resolved = shutil.which(value)
    return resolved or value


def _string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, list | tuple):
        return tuple(str(part).strip() for part in value if str(part).strip())
    raise ValueError(f"expected string or list of strings, got {type(value).__name__}")


def _path_patterns(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        raw_patterns: tuple[object, ...] = tuple(value.split(","))
    elif isinstance(value, list | tuple):
        raw_patterns = tuple(value)
    else:
        raise ValueError(
            f"expected string or list of path patterns, got {type(value).__name__}"
        )
    return tuple(_normalize_path_pattern(pattern) for pattern in raw_patterns)


def _normalize_path_pattern(value: object) -> str:
    pattern = str(value).strip().replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    if not pattern:
        raise ValueError("path policy patterns must not be empty")
    if pattern.startswith("/"):
        raise ValueError(
            f"path policy pattern {pattern!r} must be repository-relative"
        )
    if any(part == ".." for part in pattern.split("/")):
        raise ValueError(f"path policy pattern {pattern!r} must not contain '..'")
    return pattern.rstrip("/") or pattern


def _path_policy_config(raw: object) -> PathPolicyConfig:
    data = raw if isinstance(raw, dict) else {}
    frozen = _path_patterns(data.get("frozen", ()))
    frozen_by_kind: dict[str, tuple[str, ...]] = {}
    for key, value in data.items():
        if key == "frozen" or not isinstance(value, dict):
            continue
        frozen_for_kind = _path_patterns(value.get("frozen", ()))
        if frozen_for_kind:
            frozen_by_kind[str(key)] = frozen_for_kind
    return PathPolicyConfig(frozen=frozen, frozen_by_kind=frozen_by_kind)


def _signal_provider_configs(
    signals_data: object, enabled: tuple[str, ...]
) -> dict[str, SignalProviderConfig]:
    data = signals_data if isinstance(signals_data, dict) else {}
    providers: dict[str, SignalProviderConfig] = {}
    for name in enabled:
        raw = data.get(name, {}) if isinstance(data.get(name, {}), dict) else {}
        default = default_signal_provider_config(name)
        providers[name] = SignalProviderConfig(
            poll_interval_minutes=int(raw.get("poll_interval_minutes", default.poll_interval_minutes)),
            error_retry_minutes=int(
                raw.get("error_retry_minutes", default.error_retry_minutes)
            ),
            idle_poll_interval_minutes=int(
                raw.get(
                    "idle_poll_interval_minutes",
                    default.idle_poll_interval_minutes,
                )
            ),
            suppression_hours=int(raw.get("suppression_hours", default.suppression_hours)),
            max_items=int(raw.get("max_items", default.max_items)),
        )
    return providers


def _telemetry_config(raw: object) -> TelemetryConfig:
    data = _require_allowed_keys("telemetry", raw, _TELEMETRY_ALLOWED_KEYS)
    return TelemetryConfig(
        billing_mode=str(data.get("billing_mode", "unknown")).strip().lower(),
    )


def _utc_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _valid_epoch(value: object) -> bool:
    required = {"epochId", "formatVersion", "policy", "startedAt"}
    allowed = required | {"endedAt"}
    return (
        isinstance(value, dict)
        and required.issubset(value)
        and set(value).issubset(allowed)
        and value.get("formatVersion") == ARCHIVE_FORMAT_VERSION
        and value.get("policy") == ARCHIVE_POLICY
        and isinstance(value.get("epochId"), str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["epochId"])
        is not None
        and _valid_utc_timestamp(value.get("startedAt"))
        and value.get("endedAt") is None
    )


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        from datetime import datetime

        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None


def _ensure_controlled_roots(paths: tuple[Path, ...]) -> None:
    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"Steward path must not be a symlink: {path}")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            # A read-only fixture can still be inspected; mkdir/stat errors are
            # surfaced by the operation that needs the path.
            pass


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def default_signal_provider_config(name: str) -> SignalProviderConfig:
    return SignalProviderConfig(
        poll_interval_minutes=DEFAULT_SIGNAL_POLL_INTERVAL_MINUTES.get(name, 360),
        idle_poll_interval_minutes=(
            DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES_BY_PROVIDER.get(
                name, DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES
            )
        ),
    )


def _validate_github_repository(value: str) -> None:
    parts = value.split("/")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
    if len(parts) == 2 and all(parts) and all(set(part) <= allowed for part in parts):
        return
    raise ValueError(f"invalid github_repository {value!r}; expected owner/repo")

from __future__ import annotations

import os
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import IntegrationMode


VALID_INTEGRATION_MODES = {mode.value for mode in IntegrationMode}
DEFAULT_ENABLED_SIGNALS = (
    "github-actions:ci",
    "github-actions:test",
    "github-actions:duvet",
    "github-actions:nightly-ci",
    "github-actions:deploy-demo",
    "github-actions:interop",
    "github-actions:perf",
    "code-scanning",
    "codacy",
)
DEFAULT_COQUIC_HOME = "~/.coquic"
DEFAULT_SIGNAL_POLL_INTERVAL_MINUTES = {
    "github-actions:ci": 30,
    "github-actions:test": 30,
    "github-actions:duvet": 1440,
    "github-actions:nightly-ci": 1440,
    "github-actions:deploy-demo": 30,
    "github-actions:interop": 1440,
    "github-actions:perf": 1440,
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
}
DEFAULT_SIGNAL_ERROR_RETRY_MINUTES = 30
DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES = 30
DEFAULT_SIGNAL_SUPPRESSION_HOURS = 24
DEFAULT_SIGNAL_MAX_ITEMS = 12


@dataclass(frozen=True)
class StewardLimits:
    max_active_tasks: int = 4
    max_main_pushes_per_day: int = 10
    worker_timeout_minutes: int = 120
    review_timeout_minutes: int = 20
    validation_timeout_minutes: int = 30
    stale_task_minutes: int | None = None


@dataclass(frozen=True)
class SignalProviderConfig:
    poll_interval_minutes: int
    error_retry_minutes: int = DEFAULT_SIGNAL_ERROR_RETRY_MINUTES
    idle_poll_interval_minutes: int = DEFAULT_SIGNAL_IDLE_POLL_INTERVAL_MINUTES
    suppression_hours: int = DEFAULT_SIGNAL_SUPPRESSION_HOURS
    max_items: int = DEFAULT_SIGNAL_MAX_ITEMS


@dataclass(frozen=True)
class StewardConfig:
    repo_root: Path
    codex_bin: str = "codex"
    codex_model: str | None = None
    codex_profile: str | None = None
    codex_sandbox: str = "workspace-write"
    integration_mode: str = IntegrationMode.local_only.value
    local_only: bool = False
    git_remote: str = "origin"
    main_branch: str = "main"
    github_repository: str = "minhuw/coquic"
    enabled_signals: tuple[str, ...] = DEFAULT_ENABLED_SIGNALS
    signal_providers: dict[str, SignalProviderConfig] = field(default_factory=dict)
    scheduler_wait_interval_sec: float = 1.0
    limits: StewardLimits = field(default_factory=StewardLimits)

    def __post_init__(self) -> None:
        if self.integration_mode not in VALID_INTEGRATION_MODES:
            choices = ", ".join(sorted(VALID_INTEGRATION_MODES))
            raise ValueError(
                f"invalid integration_mode {self.integration_mode!r}; expected {choices}"
            )
        _validate_github_repository(self.github_repository)
        providers = dict(self.signal_providers)
        for name in self.enabled_signals:
            providers.setdefault(name, default_signal_provider_config(name))
        object.__setattr__(self, "signal_providers", providers)

    @property
    def coquic_home(self) -> Path:
        return (
            Path(os.getenv("COQUIC_HOME", DEFAULT_COQUIC_HOME)).expanduser().resolve()
        )

    @property
    def steward_home(self) -> Path:
        return self.coquic_home / "steward"

    @property
    def state_dir(self) -> Path:
        return self.steward_home

    @property
    def worktrees_dir(self) -> Path:
        return self.state_dir / "worktrees"

    @property
    def transcripts_dir(self) -> Path:
        return self.state_dir / "transcripts"

    @property
    def db_path(self) -> Path:
        return self.state_dir / "steward.sqlite"

    @property
    def legacy_json_path(self) -> Path:
        return self.state_dir / "steward.json"

    @property
    def logs_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def prompts_dir(self) -> Path:
        return self.state_dir / "prompts"

    @property
    def patches_dir(self) -> Path:
        return self.state_dir / "patches"

    def ensure_dirs(self) -> None:
        for path in (
            self.state_dir,
            self.worktrees_dir,
            self.transcripts_dir,
            self.logs_dir,
            self.prompts_dir,
            self.patches_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def load_config(
    repo_root: Path | None = None, config_path: Path | None = None
) -> StewardConfig:
    root = find_repo_root(repo_root or Path.cwd())
    data = _read_config(root, config_path)
    steward = data.get("steward", data)
    limits_data = steward.get("limits", {})
    signals_data = steward.get("signals", {})
    enabled_signals = _string_tuple(
        signals_data.get(
            "enabled", steward.get("enabled_signals", DEFAULT_ENABLED_SIGNALS)
        )
    )
    config = StewardConfig(
        repo_root=root,
        codex_bin=_resolve_executable(str(steward.get("codex_bin", "codex"))),
        codex_model=steward.get("codex_model")
        or os.getenv("COQUIC_STEWARD_CODEX_MODEL")
        or None,
        codex_profile=steward.get("codex_profile")
        or os.getenv("COQUIC_STEWARD_CODEX_PROFILE")
        or None,
        codex_sandbox=str(steward.get("codex_sandbox", "workspace-write")),
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
            worker_timeout_minutes=int(limits_data.get("worker_timeout_minutes", 120)),
            review_timeout_minutes=int(limits_data.get("review_timeout_minutes", 20)),
            validation_timeout_minutes=int(
                limits_data.get("validation_timeout_minutes", 30)
            ),
            stale_task_minutes=(
                int(limits_data["stale_task_minutes"])
                if "stale_task_minutes" in limits_data
                else None
            ),
        ),
    )
    config.ensure_dirs()
    return config


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

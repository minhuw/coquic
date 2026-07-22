from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
DEFAULT_PUBLIC_MIRROR_OUTPUT = "public/steward/status.json"
DEFAULT_PUBLIC_MIRROR_REMOTE_PATH = (
    "/opt/coquic-demo/current/app/public/steward/status.json"
)
VALID_PUBLIC_MIRROR_TRANSCRIPT_MODES = {"none", "redacted", "raw"}
VALID_REASONING_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}
VALID_TELEMETRY_BILLING_MODES = {"unknown", "chatgpt", "api"}


@dataclass(frozen=True)
class StewardLimits:
    max_active_tasks: int = 4
    max_main_pushes_per_day: int = 10
    plan_timeout_minutes: int = 30
    worker_timeout_minutes: int = 120
    review_timeout_minutes: int = 20
    validation_timeout_minutes: int = 30
    stale_task_minutes: int | None = None


@dataclass(frozen=True)
class PublicMirrorConfig:
    enabled: bool = False
    output_path: Path | None = None
    publish: bool = False
    transcript_mode: str = "redacted"
    remote_user: str = "minhuw"
    remote_host: str = "coquic.minhuw.dev"
    remote_port: int = 22
    remote_path: str = DEFAULT_PUBLIC_MIRROR_REMOTE_PATH
    ssh_key_path: Path | None = None
    known_hosts_path: Path | None = None
    connect_timeout_seconds: int = 10
    retry_initial_seconds: int = 30
    retry_max_seconds: int = 300

    def __post_init__(self) -> None:
        if self.publish and self.transcript_mode == "raw":
            raise ValueError(
                "public_mirror.transcript_mode=raw cannot be used with publish=true"
            )


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
    billing_mode: str = "unknown"
    price_catalog_path: Path | None = None

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
    integration_mode: str = IntegrationMode.local_only.value
    local_only: bool = False
    git_remote: str = "origin"
    main_branch: str = "main"
    github_repository: str = "minhuw/coquic"
    enabled_signals: tuple[str, ...] = DEFAULT_ENABLED_SIGNALS
    signal_providers: dict[str, SignalProviderConfig] = field(default_factory=dict)
    scheduler_wait_interval_sec: float = 1.0
    limits: StewardLimits = field(default_factory=StewardLimits)
    public_mirror: PublicMirrorConfig = field(default_factory=PublicMirrorConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    path_policy: PathPolicyConfig = field(default_factory=PathPolicyConfig)

    def __post_init__(self) -> None:
        if self.integration_mode not in VALID_INTEGRATION_MODES:
            choices = ", ".join(sorted(VALID_INTEGRATION_MODES))
            raise ValueError(
                f"invalid integration_mode {self.integration_mode!r}; expected {choices}"
            )
        _validate_github_repository(self.github_repository)
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
    def coquic_home(self) -> Path:
        # Keep the lexical path so migration can detect a symlinked root before
        # resolving it into an apparently safe directory.
        return Path(os.getenv("COQUIC_HOME", DEFAULT_COQUIC_HOME)).expanduser()

    @property
    def steward_home(self) -> Path:
        return self.coquic_home / "steward"

    @property
    def legacy_steward_home(self) -> Path:
        """The pre-2.0 private root, retained for compatibility reads."""
        return self.steward_home

    @property
    def state_dir(self) -> Path:
        # Existing workers still use this root for private compatibility files.
        # New operational state is exposed through the explicit properties below.
        return self.steward_home

    @property
    def worktrees_dir(self) -> Path:
        return self.coquic_home / "worktrees"

    @property
    def tasks_dir(self) -> Path:
        return self.coquic_home / "tasks"

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
    def legacy_db_path(self) -> Path:
        return self.legacy_steward_home / "steward.sqlite"

    @property
    def legacy_worktrees_dir(self) -> Path:
        return self.legacy_steward_home / "worktrees"

    @property
    def legacy_transcripts_dir(self) -> Path:
        return self.legacy_steward_home / "transcripts"

    @property
    def migration_marker_path(self) -> Path:
        return self.coquic_home / ".steward-2.0-migration.json"

    @property
    def legacy_migration_marker_path(self) -> Path:
        return self.legacy_steward_home / "steward.sqlite.pre-2.0.json"

    @property
    def legacy_backup_path(self) -> Path:
        return self.legacy_db_path.with_name("steward.sqlite.pre-2.0.bak")

    @property
    def epoch_path(self) -> Path:
        return self.tasks_dir / "epoch.json"

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
        # Keep old private directories available to existing readers while all
        # 2.0 roots are created directly below COQUIC_HOME.  This method is
        # intentionally migration-free; callers must request migration
        # explicitly after stopping the daemon.
        roots = (
            self.coquic_home,
            self.worktrees_dir,
            self.tasks_dir,
            self.private_dir,
            self.private_sessions_dir,
            self.state_dir,
            self.transcripts_dir,
            self.logs_dir,
            self.prompts_dir,
            self.patches_dir,
            self.implementation_plans_dir,
        )
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

    def migrate_legacy_database(
        self, *, daemon_running: bool = False, require_epoch: bool = False
    ) -> Path:
        """Copy the legacy SQLite database to the 2.0 root without data loss.

        Migration is deliberately explicit.  The source remains intact until
        the destination passes SQLite integrity checks, then it is moved to a
        read-only, provenance-marked backup.
        """
        _reject_symlink_roots(self.coquic_home, self.legacy_steward_home)
        self.coquic_home.mkdir(parents=True, exist_ok=True)
        source = self.legacy_db_path
        destination = self.db_path
        marker = self.migration_marker_path
        legacy_marker = self.legacy_migration_marker_path
        if require_epoch:
            self.ensure_epoch()
        if source.is_symlink() or destination.is_symlink():
            raise RuntimeError("Steward database paths must not be symlinks")
        _validate_private_mode(self.legacy_steward_home)
        backup = self.legacy_backup_path
        migration_marked = marker.exists() or legacy_marker.exists()
        if (
            not source.exists()
            and destination.exists()
            and backup.exists()
            and migration_marked
            and _legacy_backup_is_complete(self, destination, backup)
        ):
            return destination
        if daemon_running:
            raise RuntimeError("cannot migrate Steward state while daemon is running")
        if (self.state_dir / "daemon.lock").exists():
            raise RuntimeError("cannot migrate Steward state while daemon lock exists")
        if destination.exists() and source.exists():
            if not _same_sqlite_content(source, destination):
                raise RuntimeError("ambiguous differing active Steward databases")
            # Identical copies are safe to make authoritative; still preserve
            # the source below as a marked backup when migration is incomplete.
        if not source.exists():
            if destination.exists():
                _validate_sqlite(destination)
                if backup.exists():
                    _finish_legacy_backup(self, destination, backup)
                elif marker.exists() or legacy_marker.exists():
                    raise RuntimeError("Steward migration provenance has no legacy backup")
                return destination
            return destination
        _validate_private_mode(self.coquic_home)
        temporary = destination.with_name(f".{destination.name}.copy-{secrets.token_hex(8)}")
        temporary.unlink(missing_ok=True)
        try:
            _sqlite_backup(source, temporary)
            _validate_sqlite(temporary)
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            _fsync_directory(destination.parent)
        finally:
            temporary.unlink(missing_ok=True)
        _checkpoint_sqlite(source)
        if not _same_sqlite_content(source, destination):
            raise RuntimeError("verified Steward destination differs from legacy source")
        if source.exists() and source != backup:
            if backup.exists():
                if not _same_sqlite_content(source, backup):
                    raise RuntimeError("legacy database backup conflicts with source")
                source.unlink()
            else:
                os.replace(source, backup)
        _finish_legacy_backup(self, destination, backup)
        return destination

    # Compatibility spellings used by migration callers and tests.
    migrate_legacy_state = migrate_legacy_database
    migrate_database = migrate_legacy_database


def load_config(
    repo_root: Path | None = None, config_path: Path | None = None
) -> StewardConfig:
    root = find_repo_root(repo_root or Path.cwd())
    data = _read_config(root, config_path)
    steward = data.get("steward", data)
    limits_data = steward.get("limits", {})
    signals_data = steward.get("signals", {})
    mirror_data = steward.get("public_mirror", {})
    telemetry_data = steward.get("telemetry", {})
    path_policy_data = steward.get("path_policy", {})
    codex_data = steward.get("codex", {})
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
        codex_reasoning_effort=steward.get("codex_reasoning_effort")
        or os.getenv("COQUIC_STEWARD_CODEX_REASONING_EFFORT")
        or None,
        codex_stages=_codex_stage_configs(codex_data),
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
            plan_timeout_minutes=int(limits_data.get("plan_timeout_minutes", 30)),
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
        public_mirror=_public_mirror_config(mirror_data),
        telemetry=_telemetry_config(telemetry_data),
        path_policy=_path_policy_config(path_policy_data),
    )
    # Configuration loading is the ordinary process-start boundary. The
    # migrator performs a read-only completeness check before requiring the
    # offline boundary for any pending legacy handoff.
    if config.legacy_db_path.exists() or config.legacy_backup_path.exists():
        config.migrate_legacy_database()
    config.ensure_dirs()
    return config


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


def _public_mirror_config(raw: object) -> PublicMirrorConfig:
    data = raw if isinstance(raw, dict) else {}
    output = _optional_path(data.get("output_path", DEFAULT_PUBLIC_MIRROR_OUTPUT))
    ssh_key = _optional_path(
        data.get("ssh_key_path") or os.getenv("COQUIC_DEMO_REMOTE_SSH_KEY_PATH")
    )
    known_hosts = _optional_path(data.get("known_hosts_path"))
    transcript_mode = str(data.get("transcript_mode", "redacted")).strip().lower()
    if transcript_mode not in VALID_PUBLIC_MIRROR_TRANSCRIPT_MODES:
        choices = ", ".join(sorted(VALID_PUBLIC_MIRROR_TRANSCRIPT_MODES))
        raise ValueError(
            f"invalid public_mirror.transcript_mode {transcript_mode!r}; "
            f"expected {choices}"
        )
    return PublicMirrorConfig(
        enabled=bool(data.get("enabled", False)),
        output_path=output,
        publish=bool(data.get("publish", False)),
        transcript_mode=transcript_mode,
        remote_user=str(data.get("remote_user", "minhuw")),
        remote_host=str(data.get("remote_host", "coquic.minhuw.dev")),
        remote_port=int(data.get("remote_port", 22)),
        remote_path=str(
            data.get("remote_path", DEFAULT_PUBLIC_MIRROR_REMOTE_PATH)
        ),
        ssh_key_path=ssh_key,
        known_hosts_path=known_hosts,
        connect_timeout_seconds=int(data.get("connect_timeout_seconds", 10)),
        retry_initial_seconds=max(1, int(data.get("retry_initial_seconds", 30))),
        retry_max_seconds=max(
            int(data.get("retry_initial_seconds", 30)),
            int(data.get("retry_max_seconds", 300)),
        ),
    )


def _telemetry_config(raw: object) -> TelemetryConfig:
    data = raw if isinstance(raw, dict) else {}
    return TelemetryConfig(
        billing_mode=str(data.get("billing_mode", "unknown")).strip().lower(),
        price_catalog_path=_optional_path(data.get("price_catalog_path")),
    )


def _optional_path(value: object) -> Path | None:
    if value in (None, ""):
        return None
    return Path(str(value)).expanduser()


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


def _reject_symlink_roots(*paths: Path) -> None:
    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"Steward root must not be a symlink: {path}")


def _validate_private_mode(path: Path) -> None:
    if not path.exists():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IRWXO):
        raise PermissionError(f"unsafe permissions on Steward root: {path}")


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


def _validate_sqlite(path: Path) -> None:
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if not result or result[0] != "ok":
                raise RuntimeError(f"SQLite integrity check failed for {path}")
            connection.execute("PRAGMA schema_version").fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError(f"invalid SQLite database: {path}") from exc


def _sqlite_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()


def _checkpoint_sqlite(path: Path) -> None:
    """Fold committed WAL bytes into the legacy database after copy validation."""
    try:
        with sqlite3.connect(path) as connection:
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError(f"could not checkpoint legacy SQLite database: {path}") from exc
    if result is not None and result[0] != 0:
        raise RuntimeError(f"legacy SQLite database is busy: {path}")


def _finish_legacy_backup(
    config: StewardConfig, destination: Path, backup: Path
) -> None:
    """Finish the restartable database/sidecar rename before marking migration."""
    source = config.legacy_db_path
    interrupted = backup.with_name(f"{backup.name}.interrupted")
    if not backup.exists():
        if not interrupted.exists():
            raise RuntimeError("legacy Steward database backup is missing")
        if not stat.S_ISREG(interrupted.lstat().st_mode):
            raise RuntimeError("interrupted legacy backup is not a regular file")
        _rebuild_legacy_backup(destination, backup)
    if backup.is_symlink() or interrupted.is_symlink():
        raise RuntimeError("legacy Steward database backup is unsafe")
    for suffix in ("-wal", "-shm"):
        sidecar = source.with_name(source.name + suffix)
        sidecar_backup = backup.with_name(backup.name + suffix)
        if sidecar.is_symlink() or sidecar_backup.is_symlink():
            raise RuntimeError("legacy SQLite sidecars must not be symlinks")
        if sidecar.exists():
            if sidecar_backup.exists():
                if sidecar.read_bytes() != sidecar_backup.read_bytes():
                    raise RuntimeError("legacy SQLite sidecar backup conflicts")
                sidecar.unlink()
            else:
                os.replace(sidecar, sidecar_backup)
        if sidecar_backup.exists():
            os.chmod(sidecar_backup, stat.S_IRUSR | stat.S_IRGRP)
    if not _same_sqlite_content(backup, destination):
        if interrupted.exists():
            raise RuntimeError("multiple interrupted legacy backups conflict")
        for suffix in ("-wal", "-shm"):
            sidecar_backup = backup.with_name(backup.name + suffix)
            if sidecar_backup.exists():
                interrupted_sidecar = interrupted.with_name(interrupted.name + suffix)
                if interrupted_sidecar.is_symlink():
                    raise RuntimeError("interrupted legacy sidecar is unsafe")
                if interrupted_sidecar.exists():
                    if sidecar_backup.read_bytes() != interrupted_sidecar.read_bytes():
                        raise RuntimeError("interrupted legacy sidecar conflicts")
                    sidecar_backup.unlink()
                else:
                    os.replace(sidecar_backup, interrupted_sidecar)
                os.chmod(interrupted_sidecar, stat.S_IRUSR | stat.S_IRGRP)
        os.replace(backup, interrupted)
        os.chmod(interrupted, stat.S_IRUSR | stat.S_IRGRP)
        _rebuild_legacy_backup(destination, backup)
    if not _same_sqlite_content(backup, destination):
        raise RuntimeError("legacy Steward backup differs from verified destination")
    os.chmod(backup, stat.S_IRUSR | stat.S_IRGRP)
    _fsync_directory(backup.parent)
    _write_migration_provenance(config, destination, backup)


def _legacy_backup_is_complete(
    config: StewardConfig, destination: Path, backup: Path
) -> bool:
    if backup.is_symlink():
        return False
    for suffix in ("-wal", "-shm"):
        source_sidecar = config.legacy_db_path.with_name(
            config.legacy_db_path.name + suffix
        )
        backup_sidecar = backup.with_name(backup.name + suffix)
        if source_sidecar.exists() or source_sidecar.is_symlink() or backup_sidecar.is_symlink():
            return False
    return _same_sqlite_content(backup, destination)


def _rebuild_legacy_backup(destination: Path, backup: Path) -> None:
    temporary = backup.with_name(f".{backup.name}.copy-{secrets.token_hex(8)}")
    try:
        _sqlite_backup(destination, temporary)
        _validate_sqlite(temporary)
        os.replace(temporary, backup)
        _fsync_directory(backup.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _same_sqlite_content(left: Path, right: Path) -> bool:
    try:
        _validate_sqlite(left)
        _validate_sqlite(right)
    except RuntimeError:
        return False
    left_connection = sqlite3.connect(f"file:{left}?mode=ro", uri=True)
    right_connection = sqlite3.connect(f"file:{right}?mode=ro", uri=True)
    try:
        left_tables = left_connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        right_tables = right_connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        if left_tables != right_tables:
            return False
        for table, _ in left_tables:
            if table.startswith("sqlite_"):
                continue
            left_rows = left_connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
            right_rows = right_connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
            if left_rows != right_rows:
                return False
        return True
    except sqlite3.Error:
        return False
    finally:
        left_connection.close()
        right_connection.close()


def _write_migration_provenance(
    config: StewardConfig, destination: Path, backup: Path
) -> None:
    provenance = {
        "formatVersion": ARCHIVE_FORMAT_VERSION,
        "source": str(backup.relative_to(config.coquic_home)),
        "destination": str(destination.relative_to(config.coquic_home)),
        "migratedAt": _utc_timestamp(),
    }
    markers = (config.migration_marker_path, config.legacy_migration_marker_path)
    for marker in markers:
        temporary_marker = marker.with_name(
            f".{marker.name}.tmp-{secrets.token_hex(8)}"
        )
        try:
            temporary_marker.write_text(
                json.dumps(provenance, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            _fsync_file(temporary_marker)
            os.replace(temporary_marker, marker)
            _fsync_directory(marker.parent)
        finally:
            temporary_marker.unlink(missing_ok=True)


def migrate_legacy_database(
    config: StewardConfig, *, daemon_running: bool = False, require_epoch: bool = False
) -> Path:
    """Module-level compatibility wrapper for explicit state migration."""
    return config.migrate_legacy_database(
        daemon_running=daemon_running, require_epoch=require_epoch
    )


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

"""Validated, non-secret configuration for the Cloudflare publication stack."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
import re
from typing import Any

import pulumi


PUBLIC_HOSTNAME = "artifacts.coquic.minhuw.dev"
LIVE_HOSTNAME = "live.coquic.minhuw.dev"
LIVE_PATH = "/api/steward/live"
PRIVATE_RETENTION_SECONDS = 2_592_000

_CLOUDFLARE_ID = re.compile(r"^[0-9a-f]{32}$")
_RESOURCE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CANONICAL_FIELDS = frozenset(
    {
        "account_id",
        "zone_id",
        "database_name",
        "public_bucket_name",
        "private_bucket_name",
        "public_hostname",
        "live_hostname",
        "private_retention_seconds",
    }
)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    return value.strip()


def _cloudflare_id(value: Any, field: str) -> str:
    value = _text(value, field).lower()
    if not _CLOUDFLARE_ID.fullmatch(value):
        raise ValueError(f"{field} must be a 32-character hexadecimal ID")
    return value


def _resource_name(value: Any, field: str) -> str:
    value = _text(value, field).lower()
    if not _RESOURCE_NAME.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase DNS-style resource name")
    return value


@dataclass(frozen=True)
class CloudflareConfig:
    """The complete non-secret topology input for the production stack."""

    account_id: str
    zone_id: str
    database_name: str
    public_bucket_name: str
    private_bucket_name: str
    public_hostname: str
    live_hostname: str
    private_retention_seconds: int

    def __post_init__(self) -> None:
        account_id = _cloudflare_id(self.account_id, "account_id")
        zone_id = _cloudflare_id(self.zone_id, "zone_id")
        database_name = _resource_name(self.database_name, "database_name")
        public_bucket_name = _resource_name(
            self.public_bucket_name, "public_bucket_name"
        )
        private_bucket_name = _resource_name(
            self.private_bucket_name, "private_bucket_name"
        )
        public_hostname = _text(self.public_hostname, "public_hostname")
        live_hostname = _text(self.live_hostname, "live_hostname")

        if public_bucket_name == private_bucket_name:
            raise ValueError("public_bucket_name and private_bucket_name must differ")
        if public_hostname != PUBLIC_HOSTNAME:
            raise ValueError(f"public_hostname must be exactly {PUBLIC_HOSTNAME}")
        if live_hostname != LIVE_HOSTNAME:
            raise ValueError(f"live_hostname must be exactly {LIVE_HOSTNAME}")
        if isinstance(self.private_retention_seconds, bool) or not isinstance(
            self.private_retention_seconds, int
        ):
            raise ValueError("private_retention_seconds must be an integer")
        if self.private_retention_seconds != PRIVATE_RETENTION_SECONDS:
            raise ValueError(
                "private_retention_seconds must be 2592000 seconds (30 days)"
            )

        object.__setattr__(self, "account_id", account_id)
        object.__setattr__(self, "zone_id", zone_id)
        object.__setattr__(self, "database_name", database_name)
        object.__setattr__(self, "public_bucket_name", public_bucket_name)
        object.__setattr__(self, "private_bucket_name", private_bucket_name)
        object.__setattr__(self, "public_hostname", public_hostname)
        object.__setattr__(self, "live_hostname", live_hostname)

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "CloudflareConfig":
        """Build a configuration from the closed canonical key set."""

        values = dict(values)
        values.setdefault("live_hostname", LIVE_HOSTNAME)
        unexpected = sorted(set(values) - _CANONICAL_FIELDS)
        if unexpected:
            names = ", ".join(unexpected)
            raise ValueError(f"unexpected configuration key(s): {names}")

        missing = sorted(
            field
            for field in _CANONICAL_FIELDS
            if field not in values or values[field] is None
        )
        if missing:
            raise ValueError(f"{missing[0]} is required")

        retention = values["private_retention_seconds"]
        if isinstance(retention, str):
            try:
                retention = int(retention, 10)
            except ValueError as exc:
                raise ValueError(
                    "private_retention_seconds must be an integer"
                ) from exc

        return cls(
            account_id=values["account_id"],
            zone_id=values["zone_id"],
            database_name=values["database_name"],
            public_bucket_name=values["public_bucket_name"],
            private_bucket_name=values["private_bucket_name"],
            public_hostname=values["public_hostname"],
            live_hostname=values["live_hostname"],
            private_retention_seconds=retention,
        )

    @property
    def public_base_url(self) -> str:
        return f"https://{self.public_hostname}"

    @property
    def live_url(self) -> str:
        return f"https://{self.live_hostname}{LIVE_PATH}"


def _pulumi_runtime_values(stack_config: pulumi.Config) -> Mapping[str, Any]:
    """Enumerate the complete project bag on Pulumi versions without Config.all."""

    namespace = f"{stack_config.name}:"
    values: dict[str, Any] = {}
    runtime_values = pulumi.runtime.config.CONFIG.get()
    if not isinstance(runtime_values, Mapping):
        raise ValueError("Pulumi configuration is not a mapping")
    for full_key, value in runtime_values.items():
        if not isinstance(full_key, str):
            raise ValueError("Pulumi configuration contains an invalid key")
        if full_key.startswith(namespace):
            key = full_key[len(namespace) :]
            if key:
                values[key] = value

    environment_prefix = pulumi.runtime.get_config_env_key(namespace)
    for environment_key, value in os.environ.items():
        if environment_key.startswith(environment_prefix):
            key = environment_key[len(environment_prefix) :].lower()
            if key:
                values.setdefault(key, value)

    environment_values = pulumi.runtime.get_config_env()
    if not isinstance(environment_values, Mapping):
        raise ValueError("Pulumi configuration is not a mapping")
    for full_key, value in environment_values.items():
        if not isinstance(full_key, str):
            raise ValueError("Pulumi configuration contains an invalid key")
        if full_key.startswith(namespace):
            key = full_key[len(namespace) :]
            if key:
                values.setdefault(key, value)
    return values


def load_config(
    config: pulumi.Config | Mapping[str, Any] | None = None,
) -> CloudflareConfig:
    """Load and validate stack configuration without reading credentials."""

    if isinstance(config, Mapping):
        return CloudflareConfig.from_mapping(config)

    stack_config = config or pulumi.Config()
    try:
        values = stack_config.all()
    except AttributeError:
        if isinstance(stack_config, pulumi.Config):
            values = _pulumi_runtime_values(stack_config)
        else:
            values = {}
            for field in sorted(_CANONICAL_FIELDS):
                value = stack_config.get(field)
                if value is not None:
                    values[field] = value
    if not isinstance(values, Mapping):
        raise ValueError("Pulumi configuration is not a mapping")
    return CloudflareConfig.from_mapping(values)

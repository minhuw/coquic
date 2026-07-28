"""Validated, non-secret configuration for the Cloudflare publication stack."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

import pulumi


PUBLIC_HOSTNAME = "artifacts.coquic.minhuw.dev"
PRIVATE_RETENTION_SECONDS = 2_592_000

_CLOUDFLARE_ID = re.compile(r"^[0-9a-f]{32}$")
_RESOURCE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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

        if public_bucket_name == private_bucket_name:
            raise ValueError("public_bucket_name and private_bucket_name must differ")
        if public_hostname != PUBLIC_HOSTNAME:
            raise ValueError(
                f"public_hostname must be exactly {PUBLIC_HOSTNAME}"
            )
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

    @property
    def public_base_url(self) -> str:
        return f"https://{self.public_hostname}"

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "CloudflareConfig":
        """Build a configuration from stack-like key/value data."""

        def required(*names: str) -> Any:
            for name in names:
                if name in values and values[name] is not None:
                    return values[name]
            raise ValueError(f"{names[0]} is required")

        retention = required(
            "private_retention_seconds", "private_retention_age_seconds"
        )
        if isinstance(retention, str):
            try:
                retention = int(retention, 10)
            except ValueError as exc:
                raise ValueError("private_retention_seconds must be an integer") from exc

        return cls(
            account_id=required("account_id", "accountId"),
            zone_id=required("zone_id", "zoneId"),
            database_name=required("database_name", "d1_database_name"),
            public_bucket_name=required(
                "public_bucket_name", "public_r2_bucket_name"
            ),
            private_bucket_name=required(
                "private_bucket_name", "private_r2_bucket_name"
            ),
            public_hostname=required("public_hostname", "hostname"),
            private_retention_seconds=retention,
        )


def load_config(config: pulumi.Config | Mapping[str, Any] | None = None) -> CloudflareConfig:
    """Load and validate stack configuration without reading any credentials."""

    if isinstance(config, Mapping):
        return CloudflareConfig.from_mapping(config)

    stack_config = config or pulumi.Config()
    values: dict[str, Any] = {}

    def read(*names: str) -> Any:
        for name in names:
            value = stack_config.get(name)
            if value is not None:
                return value
        return None

    values.update(
        {
            "account_id": read("account_id", "accountId"),
            "zone_id": read("zone_id", "zoneId"),
            "database_name": read("database_name", "d1_database_name"),
            "public_bucket_name": read(
                "public_bucket_name", "public_r2_bucket_name"
            ),
            "private_bucket_name": read(
                "private_bucket_name", "private_r2_bucket_name"
            ),
            "public_hostname": read("public_hostname", "hostname"),
            "private_retention_seconds": read(
                "private_retention_seconds", "private_retention_age_seconds"
            ),
        }
    )
    return CloudflareConfig.from_mapping(values)

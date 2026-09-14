"""Pulumi program for the public publication storage and credentials."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

import pulumi
import pulumi_cloudflare as cloudflare

try:
    from .config import CloudflareConfig, load_config
except ImportError:  # Pulumi executes this file as a script.
    from config import CloudflareConfig, load_config


@dataclass(frozen=True)
class StorageResources:
    """Handles for the dependent credential configuration."""

    database: cloudflare.D1Database
    public_bucket: cloudflare.R2Bucket
    private_bucket: cloudflare.R2Bucket
    public_domain: cloudflare.R2CustomDomain
    private_lifecycle: cloudflare.R2BucketLifecycle
    live_worker: cloudflare.WorkersScript
    live_domain: cloudflare.WorkersCustomDomain


STEWARD_TOKEN_NAME = "coquic-steward-publication"
SITE_TOKEN_NAME = "coquic-site-reader"
LIVE_WORKER_NAME = "coquic-steward-live"
LIVE_STATE_CLASS = "LiveState"

_D1_READ = "D1 Read"
_D1_WRITE = "D1 Write"
_R2_READ = "Workers R2 Storage Read"
_R2_WRITE = "Workers R2 Storage Write"
_STEWARD_PERMISSION_GROUPS = (_D1_READ, _D1_WRITE, _R2_READ, _R2_WRITE)
_SITE_PERMISSION_GROUPS = (_D1_READ,)


def _account_resource_selector(account_id: str) -> str:
    """Return the account-wide selector required by AccountToken policies."""

    # Cloudflare returns compact JSON; the provider compares this as a string.
    return json.dumps(
        {f"com.cloudflare.api.account.{account_id}": "*"},
        sort_keys=True,
        separators=(",", ":"),
    )


def _result_value(result: Any, key: str) -> Any:
    if isinstance(result, dict):
        return result.get(key)
    return getattr(result, key, None)


def _resolve_permission_group_ids(
    account_id: str,
    names: Iterable[str],
) -> dict[str, str]:
    """Resolve each exact permission group name, failing closed on drift."""

    resolved: dict[str, str] = {}
    for name in names:
        # AccountToken policies use API-token groups, not IAM permission groups.
        result = cloudflare.get_account_api_token_permission_groups_list(
            account_id=account_id,
            name=name,
            scope="com.cloudflare.api.account",
            max_items=2,
        )
        matches = result.results
        if not isinstance(matches, list) or len(matches) != 1:
            raise ValueError(
                f"Cloudflare permission group {name!r} must resolve to exactly one result"
            )
        match = matches[0]
        actual_name = _result_value(match, "name")
        group_id = _result_value(match, "id")
        if actual_name != name:
            raise ValueError(
                f"Cloudflare permission group lookup for {name!r} returned {actual_name!r}"
            )
        if not isinstance(group_id, str) or not group_id.strip():
            raise ValueError(f"Cloudflare permission group {name!r} has no ID")
        group_id = group_id.strip()
        if group_id in resolved.values():
            raise ValueError(
                f"Cloudflare permission group ID {group_id!r} is assigned to multiple names"
            )
        resolved[name] = group_id
    return resolved


def _allow_policy(
    account_id: str,
    permission_group_ids: dict[str, str],
    names: Iterable[str],
) -> dict[str, Any]:
    """Construct one explicit account-scoped allow policy."""

    selected_names = tuple(names)
    if not selected_names or any(
        name not in permission_group_ids for name in selected_names
    ):
        raise ValueError("token policy contains an unresolved permission group")
    # Match the provider's canonical ordering, not permission lookup order.
    selected_ids = sorted(permission_group_ids[name] for name in selected_names)
    if len(set(selected_ids)) != len(selected_ids):
        raise ValueError("token policy contains duplicate permission group IDs")
    return {
        "effect": "allow",
        "permission_groups": [{"id": group_id} for group_id in selected_ids],
        "resources": _account_resource_selector(account_id),
    }


def _derive_s3_secret_access_key(value: str) -> str:
    """Derive the deterministic lower-case S3 secret from a token value."""

    if not isinstance(value, str) or not value:
        raise ValueError(
            "Cloudflare token value is required for S3 credential derivation"
        )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive_live_write_token(value: str) -> str:
    """Derive a domain-separated Steward live-state credential."""

    if not isinstance(value, str) or not value:
        raise ValueError(
            "Cloudflare token value is required for live token derivation"
        )
    return hashlib.sha256(
        b"coquic-steward-live-write\0" + value.encode("utf-8")
    ).hexdigest()


def _live_worker_source() -> str:
    return Path(__file__).with_name("live-state-worker.mjs").read_text(
        encoding="utf-8"
    )


def _secret_object(**values: Any) -> pulumi.Output[dict[str, Any]]:
    """Build and explicitly mark a composite credential output as secret."""

    return pulumi.Output.secret(
        pulumi.Output.all(**values).apply(lambda resolved: dict(resolved))
    )


def _protected_options() -> pulumi.ResourceOptions:
    # Data resources must require an explicit review before they can be removed.
    return pulumi.ResourceOptions(protect=True)


def build_stack(config: CloudflareConfig | None = None) -> StorageResources:
    """Construct storage, least-privilege tokens, and secret config exports."""

    config = config or load_config()

    database = cloudflare.D1Database(
        "publicationDatabase",
        account_id=config.account_id,
        name=config.database_name,
        opts=_protected_options(),
    )
    public_bucket = cloudflare.R2Bucket(
        "publicArtifacts",
        account_id=config.account_id,
        name=config.public_bucket_name,
        opts=_protected_options(),
    )
    private_bucket = cloudflare.R2Bucket(
        "privateOriginals",
        account_id=config.account_id,
        name=config.private_bucket_name,
        opts=_protected_options(),
    )
    public_domain = cloudflare.R2CustomDomain(
        "publicArtifactsDomain",
        account_id=config.account_id,
        bucket_name=public_bucket.name,
        domain=config.public_hostname,
        enabled=True,
        zone_id=config.zone_id,
        opts=_protected_options(),
    )
    private_lifecycle = cloudflare.R2BucketLifecycle(
        "privateOriginalsLifecycle",
        account_id=config.account_id,
        bucket_name=private_bucket.name,
        rules=[
            {
                "id": "expire-all-private-objects",
                "enabled": True,
                "conditions": {"prefix": ""},
                "delete_objects_transition": {
                    "condition": {
                        "type": "Age",
                        "max_age": config.private_retention_seconds,
                    }
                },
            }
        ],
        opts=_protected_options(),
    )

    permission_group_ids = _resolve_permission_group_ids(
        config.account_id,
        _STEWARD_PERMISSION_GROUPS,
    )
    steward_token = cloudflare.AccountToken(
        "stewardPublicationToken",
        account_id=config.account_id,
        name=STEWARD_TOKEN_NAME,
        policies=[
            _allow_policy(
                config.account_id,
                permission_group_ids,
                _STEWARD_PERMISSION_GROUPS,
            )
        ],
        opts=_protected_options(),
    )
    site_token = cloudflare.AccountToken(
        "siteReaderToken",
        account_id=config.account_id,
        name=SITE_TOKEN_NAME,
        policies=[
            _allow_policy(
                config.account_id,
                permission_group_ids,
                _SITE_PERMISSION_GROUPS,
            )
        ],
        opts=_protected_options(),
    )

    live_write_token = pulumi.Output.secret(
        steward_token.value.apply(_derive_live_write_token)
    )
    live_worker = cloudflare.WorkersScript(
        "stewardLiveGateway",
        account_id=config.account_id,
        script_name=LIVE_WORKER_NAME,
        content=_live_worker_source(),
        main_module="live-state-worker.mjs",
        compatibility_date="2026-06-12",
        bindings=[
            {
                "name": "LIVE_STATE",
                "type": "durable_object_namespace",
                "class_name": LIVE_STATE_CLASS,
            },
            {
                "name": "WRITE_TOKEN",
                "type": "secret_text",
                "text": live_write_token,
            },
        ],
        migrations={
            "new_tag": "v1",
            "new_sqlite_classes": [LIVE_STATE_CLASS],
        },
        opts=_protected_options(),
    )
    live_domain = cloudflare.WorkersCustomDomain(
        "stewardLiveDomain",
        account_id=config.account_id,
        hostname=config.live_hostname,
        service=live_worker.script_name,
        zone_id=config.zone_id,
        opts=_protected_options(),
    )

    steward_s3_access_key_id = pulumi.Output.secret(steward_token.id)
    steward_s3_secret_access_key = pulumi.Output.secret(
        steward_token.value.apply(_derive_s3_secret_access_key)
    )
    steward_config = _secret_object(
        account_id=config.account_id,
        d1_database_id=database.id,
        d1_token=steward_token.value,
        public_bucket_name=public_bucket.name,
        private_bucket_name=private_bucket.name,
        s3_access_key_id=steward_s3_access_key_id,
        s3_secret_access_key=steward_s3_secret_access_key,
        live_url=config.live_url,
        live_write_token=live_write_token,
    )
    site_config = _secret_object(
        account_id=config.account_id,
        d1_database_id=database.id,
        d1_read_token=site_token.value,
        public_base_url=config.public_base_url,
        live_url=config.live_url,
    )

    pulumi.export("d1_database_id", database.id)
    pulumi.export("public_bucket_name", public_bucket.name)
    pulumi.export("public_base_url", config.public_base_url)
    pulumi.export("live_url", config.live_url)
    pulumi.export("steward_config", steward_config)
    pulumi.export("site_config", site_config)
    pulumi.export("steward_d1_token", pulumi.Output.secret(steward_token.value))
    pulumi.export("steward_s3_access_key_id", steward_s3_access_key_id)
    pulumi.export("steward_s3_secret_access_key", steward_s3_secret_access_key)
    pulumi.export("steward_live_write_token", live_write_token)
    pulumi.export("site_d1_read_token", pulumi.Output.secret(site_token.value))

    return StorageResources(
        database=database,
        public_bucket=public_bucket,
        private_bucket=private_bucket,
        public_domain=public_domain,
        private_lifecycle=private_lifecycle,
        live_worker=live_worker,
        live_domain=live_domain,
    )


if __name__ == "__main__":
    build_stack()

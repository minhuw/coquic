"""Pulumi program for the public publication storage and credentials."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable

import pulumi
import pulumi_cloudflare as cloudflare

try:
    from .config import CloudflareConfig, load_config
except ImportError:  # Pulumi executes this file as a script.
    from config import CloudflareConfig, load_config


@dataclass(frozen=True)
class StorageResources:
    """Handles retained for the dependent credential configuration."""

    database: cloudflare.D1Database
    public_bucket: cloudflare.R2Bucket
    private_bucket: cloudflare.R2Bucket
    public_domain: cloudflare.R2CustomDomain
    private_lifecycle: cloudflare.R2BucketLifecycle


STEWARD_TOKEN_NAME = "coquic-steward-publication"
SITE_TOKEN_NAME = "coquic-site-reader"

_D1_READ = "D1 Read"
_D1_EDIT = "D1 Edit"
_R2_READ = "Workers R2 Storage Read"
_R2_WRITE = "Workers R2 Storage Write"
_STEWARD_PERMISSION_GROUPS = (_D1_READ, _D1_EDIT, _R2_READ, _R2_WRITE)
_SITE_PERMISSION_GROUPS = (_D1_READ,)


def _account_resource_selector(account_id: str) -> str:
    """Return the account-wide selector required by AccountToken policies."""

    return json.dumps(
        {f"com.cloudflare.api.account.{account_id}": "*"},
        sort_keys=True,
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
        result = cloudflare.get_account_permission_groups(
            account_id=account_id,
            name=name,
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
    selected_ids = [permission_group_ids[name] for name in selected_names]
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
    )
    site_config = _secret_object(
        account_id=config.account_id,
        d1_database_id=database.id,
        d1_read_token=site_token.value,
        public_base_url=config.public_base_url,
    )

    pulumi.export("d1_database_id", database.id)
    pulumi.export("public_bucket_name", public_bucket.name)
    pulumi.export("public_base_url", config.public_base_url)
    pulumi.export("steward_config", steward_config)
    pulumi.export("site_config", site_config)
    pulumi.export("steward_d1_token", pulumi.Output.secret(steward_token.value))
    pulumi.export("steward_s3_access_key_id", steward_s3_access_key_id)
    pulumi.export("steward_s3_secret_access_key", steward_s3_secret_access_key)
    pulumi.export("site_d1_read_token", pulumi.Output.secret(site_token.value))

    return StorageResources(
        database=database,
        public_bucket=public_bucket,
        private_bucket=private_bucket,
        public_domain=public_domain,
        private_lifecycle=private_lifecycle,
    )


if __name__ == "__main__":
    build_stack()

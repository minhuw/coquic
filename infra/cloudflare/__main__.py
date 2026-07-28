"""Pulumi program for the public publication storage topology."""

from __future__ import annotations

from dataclasses import dataclass

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


def _protected_options() -> pulumi.ResourceOptions:
    # Data resources must require an explicit review before they can be removed.
    return pulumi.ResourceOptions(protect=True)


def build_stack(config: CloudflareConfig | None = None) -> StorageResources:
    """Construct the five-resource graph and its non-credential exports."""

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

    pulumi.export("d1_database_id", database.id)
    pulumi.export("public_bucket_name", public_bucket.name)
    pulumi.export("public_base_url", config.public_base_url)

    return StorageResources(
        database=database,
        public_bucket=public_bucket,
        private_bucket=private_bucket,
        public_domain=public_domain,
        private_lifecycle=private_lifecycle,
    )


if __name__ == "__main__":
    build_stack()

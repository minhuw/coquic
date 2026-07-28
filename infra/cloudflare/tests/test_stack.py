from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys
from typing import Any

import pulumi
from pulumi.runtime import MockCallArgs, MockResourceArgs, Mocks, set_mocks

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from infra.cloudflare.__main__ import build_stack
from infra.cloudflare.config import (
    CloudflareConfig,
    PRIVATE_RETENTION_SECONDS,
    PUBLIC_HOSTNAME,
)


def valid_values() -> dict[str, Any]:
    return {
        "account_id": "a" * 32,
        "zone_id": "b" * 32,
        "database_name": "coquic-publication",
        "public_bucket_name": "coquic-public-artifacts",
        "private_bucket_name": "coquic-private-originals",
        "public_hostname": PUBLIC_HOSTNAME,
        "private_retention_seconds": PRIVATE_RETENTION_SECONDS,
    }


def test_config_accepts_valid_values() -> None:
    config = CloudflareConfig.from_mapping(valid_values())
    assert config.public_base_url == "https://artifacts.coquic.minhuw.dev"


def test_config_rejects_missing_values() -> None:
    values = valid_values()
    values.pop("account_id")
    try:
        CloudflareConfig.from_mapping(values)
    except ValueError as exc:
        assert "account_id" in str(exc)
    else:
        raise AssertionError("missing account ID was accepted")


def test_config_rejects_identical_buckets() -> None:
    values = valid_values()
    values["private_bucket_name"] = values["public_bucket_name"]
    try:
        CloudflareConfig.from_mapping(values)
    except ValueError as exc:
        assert "must differ" in str(exc)
    else:
        raise AssertionError("identical bucket names were accepted")


def test_config_rejects_wrong_hostname() -> None:
    values = valid_values()
    values["public_hostname"] = "objects.example.test"
    try:
        CloudflareConfig.from_mapping(values)
    except ValueError as exc:
        assert PUBLIC_HOSTNAME in str(exc)
    else:
        raise AssertionError("an unexpected public hostname was accepted")


def test_config_rejects_retention_drift() -> None:
    values = valid_values()
    values["private_retention_seconds"] = 30 * 24 * 60 * 60 + 1
    try:
        CloudflareConfig.from_mapping(values)
    except ValueError as exc:
        assert "2592000" in str(exc)
    else:
        raise AssertionError("retention drift was accepted")


class RecordingMocks(Mocks):
    def __init__(self) -> None:
        self.resources: list[MockResourceArgs] = []

    def new_resource(self, args: MockResourceArgs) -> tuple[str, dict[str, Any]]:
        self.resources.append(args)
        state = dict(args.inputs)
        if args.typ == "cloudflare:index/d1Database:D1Database":
            state["uuid"] = "c" * 32
        return f"mock-{len(self.resources)}", state

    def call(self, args: MockCallArgs) -> tuple[dict[str, Any], None]:
        raise AssertionError(f"unexpected provider call: {args.token}")


def run_mock_stack() -> RecordingMocks:
    mocks = RecordingMocks()
    set_mocks(mocks, project="coquic-cloudflare", stack="test", preview=True)
    config = CloudflareConfig.from_mapping(valid_values())

    @pulumi.runtime.test
    def program() -> None:
        build_stack(config)

    program()
    return mocks


def test_resources_match_storage_topology() -> None:
    mocks = run_mock_stack()
    resources = [
        resource
        for resource in mocks.resources
        if resource.typ.startswith("cloudflare:index/")
    ]
    counts = Counter(resource.typ for resource in resources)
    assert counts == Counter(
        {
            "cloudflare:index/d1Database:D1Database": 1,
            "cloudflare:index/r2Bucket:R2Bucket": 2,
            "cloudflare:index/r2CustomDomain:R2CustomDomain": 1,
            "cloudflare:index/r2BucketLifecycle:R2BucketLifecycle": 1,
        }
    )

    by_type = {resource.typ: resource for resource in resources if resource.typ != "cloudflare:index/r2Bucket:R2Bucket"}
    domain = by_type["cloudflare:index/r2CustomDomain:R2CustomDomain"]
    assert domain.inputs["domain"] == PUBLIC_HOSTNAME
    assert domain.inputs["enabled"] is True
    assert domain.inputs["bucketName"] == "coquic-public-artifacts"

    lifecycle = by_type["cloudflare:index/r2BucketLifecycle:R2BucketLifecycle"]
    assert lifecycle.inputs["bucketName"] == "coquic-private-originals"
    assert lifecycle.inputs["rules"] == [
        {
            "id": "expire-all-private-objects",
            "enabled": True,
            "conditions": {"prefix": ""},
            "deleteObjectsTransition": {
                "condition": {"type": "Age", "maxAge": PRIVATE_RETENTION_SECONDS}
            },
        }
    ]

    assert all("token" not in resource.inputs for resource in resources)
    assert all("credential" not in resource.inputs for resource in resources)

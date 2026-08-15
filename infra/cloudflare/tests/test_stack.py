from __future__ import annotations

import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import pulumi
import pytest
from pulumi.runtime import MockCallArgs, MockResourceArgs, Mocks, set_mocks

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from infra.cloudflare.__main__ import (  # noqa: E402
    SITE_TOKEN_NAME,
    STEWARD_TOKEN_NAME,
    _derive_s3_secret_access_key,
    build_stack,
)
from infra.cloudflare.config import (  # noqa: E402
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


def test_config_accepts_only_canonical_values() -> None:
    config = CloudflareConfig.from_mapping(valid_values())
    assert config.public_base_url == "https://artifacts.coquic.minhuw.dev"


@pytest.mark.parametrize(
    "key",
    [
        "accountId",
        "zoneId",
        "d1_database_name",
        "public_r2_bucket_name",
        "private_r2_bucket_name",
        "hostname",
        "private_retention_age_seconds",
        "unexpected",
    ],
)
def test_config_rejects_noncanonical_keys(key: str) -> None:
    values = valid_values()
    values[key] = "not-used"
    with pytest.raises(ValueError, match="unexpected configuration"):
        CloudflareConfig.from_mapping(values)


def test_config_rejects_missing_values() -> None:
    values = valid_values()
    values.pop("account_id")
    with pytest.raises(ValueError, match="account_id"):
        CloudflareConfig.from_mapping(values)


def test_config_rejects_identical_buckets() -> None:
    values = valid_values()
    values["private_bucket_name"] = values["public_bucket_name"]
    with pytest.raises(ValueError, match="must differ"):
        CloudflareConfig.from_mapping(values)


def test_config_rejects_wrong_hostname() -> None:
    values = valid_values()
    values["public_hostname"] = "objects.example.test"
    with pytest.raises(ValueError, match=PUBLIC_HOSTNAME):
        CloudflareConfig.from_mapping(values)


def test_config_rejects_retention_drift() -> None:
    values = valid_values()
    values["private_retention_seconds"] = PRIVATE_RETENTION_SECONDS + 1
    with pytest.raises(ValueError, match="2592000"):
        CloudflareConfig.from_mapping(values)


class RecordingMocks(Mocks):
    def __init__(self) -> None:
        self.resources: list[MockResourceArgs] = []
        self.calls: list[MockCallArgs] = []

    def new_resource(self, args: MockResourceArgs) -> tuple[str, dict[str, Any]]:
        self.resources.append(args)
        state = dict(args.inputs)
        if args.typ == "cloudflare:index/d1Database:D1Database":
            state["uuid"] = "c" * 32
        if args.typ == "cloudflare:index/accountToken:AccountToken":
            state["value"] = f"mock-value-{args.name}"
        return f"mock-{len(self.resources)}", state

    def call(self, args: MockCallArgs) -> dict[str, Any]:
        self.calls.append(args)
        if args.token != (
            "cloudflare:index/getAccountPermissionGroups:getAccountPermissionGroups"
        ):
            raise AssertionError(f"unexpected provider call: {args.token}")
        names = {
            "D1 Read": "1" * 32,
            "D1 Edit": "2" * 32,
            "Workers R2 Storage Read": "3" * 32,
            "Workers R2 Storage Write": "4" * 32,
        }
        name = args.args.get("name")
        if name not in names:
            raise AssertionError(f"unexpected permission group: {name!r}")
        return {
            "accountId": args.args["accountId"],
            "name": name,
            "maxItems": args.args.get("maxItems"),
            "results": [{"id": names[name], "name": name}],
        }


def run_mock_stack() -> RecordingMocks:
    mocks = RecordingMocks()
    set_mocks(mocks, project="coquic-cloudflare", stack="test", preview=True)
    config = CloudflareConfig.from_mapping(valid_values())

    @pulumi.runtime.test
    def program() -> None:
        build_stack(config)

    program()
    return mocks


def run_mock_stack_with_exports() -> tuple[RecordingMocks, dict[str, Any]]:
    mocks = RecordingMocks()
    set_mocks(mocks, project="coquic-cloudflare", stack="test-exports", preview=True)
    exports: dict[str, Any] = {}
    original_export = pulumi.export
    pulumi.export = lambda name, value: exports.__setitem__(name, value)
    try:
        config = CloudflareConfig.from_mapping(valid_values())

        @pulumi.runtime.test
        def program() -> None:
            build_stack(config)

        program()
    finally:
        pulumi.export = original_export
    return mocks, exports


def test_resources_match_single_database_topology() -> None:
    mocks = run_mock_stack()
    resources = [
        resource
        for resource in mocks.resources
        if resource.typ.startswith("cloudflare:index/")
    ]
    counts = Counter(resource.typ for resource in resources)
    assert counts == Counter(
        {
            "cloudflare:index/accountToken:AccountToken": 2,
            "cloudflare:index/d1Database:D1Database": 1,
            "cloudflare:index/r2Bucket:R2Bucket": 2,
            "cloudflare:index/r2CustomDomain:R2CustomDomain": 1,
            "cloudflare:index/r2BucketLifecycle:R2BucketLifecycle": 1,
        }
    )

    databases = [
        resource
        for resource in resources
        if resource.typ == "cloudflare:index/d1Database:D1Database"
    ]
    assert [resource.name for resource in databases] == ["publicationDatabase"]
    assert [resource.inputs["name"] for resource in databases] == [
        "coquic-publication"
    ]

    by_type = {
        resource.typ: resource
        for resource in resources
        if resource.typ
        not in {
            "cloudflare:index/r2Bucket:R2Bucket",
            "cloudflare:index/accountToken:AccountToken",
        }
    }
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

    assert all("credential" not in resource.inputs for resource in resources)


def test_tokens_and_permissions_are_least_privilege() -> None:
    mocks = run_mock_stack()
    assert [call.args["name"] for call in mocks.calls] == [
        "D1 Read",
        "D1 Edit",
        "Workers R2 Storage Read",
        "Workers R2 Storage Write",
    ]
    assert all(call.args["maxItems"] == 2.0 for call in mocks.calls)

    tokens = {
        resource.inputs["name"]: resource
        for resource in mocks.resources
        if resource.typ == "cloudflare:index/accountToken:AccountToken"
    }
    assert set(tokens) == {STEWARD_TOKEN_NAME, SITE_TOKEN_NAME}
    selector = json.dumps(
        {"com.cloudflare.api.account." + "a" * 32: "*"},
        sort_keys=True,
    )
    steward_policy = tokens[STEWARD_TOKEN_NAME].inputs["policies"][0]
    assert steward_policy["effect"] == "allow"
    assert steward_policy["resources"] == selector
    assert [item["id"] for item in steward_policy["permissionGroups"]] == [
        "1" * 32,
        "2" * 32,
        "3" * 32,
        "4" * 32,
    ]

    site_policy = tokens[SITE_TOKEN_NAME].inputs["policies"][0]
    assert site_policy["effect"] == "allow"
    assert site_policy["resources"] == selector
    assert site_policy["permissionGroups"] == [{"id": "1" * 32}]


def test_tokens_and_outputs_derive_lower_case_sha256() -> None:
    value = "one-time-token-value"
    assert _derive_s3_secret_access_key(value) == hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def test_tokens_and_outputs_are_secret_and_field_limited() -> None:
    _, exports = run_mock_stack_with_exports()
    assert set(exports) == {
        "d1_database_id",
        "public_bucket_name",
        "public_base_url",
        "steward_config",
        "site_config",
        "steward_d1_token",
        "steward_s3_access_key_id",
        "steward_s3_secret_access_key",
        "site_d1_read_token",
    }
    secret_exports = {
        "steward_config",
        "site_config",
        "steward_d1_token",
        "steward_s3_access_key_id",
        "steward_s3_secret_access_key",
        "site_d1_read_token",
    }
    for name in secret_exports:
        assert asyncio.run(exports[name].is_secret()) is True

    steward = asyncio.run(exports["steward_config"].future())
    assert set(steward) == {
        "account_id",
        "d1_database_id",
        "d1_token",
        "public_bucket_name",
        "private_bucket_name",
        "s3_access_key_id",
        "s3_secret_access_key",
    }
    assert steward["s3_secret_access_key"] == _derive_s3_secret_access_key(
        steward["d1_token"]
    )

    site = asyncio.run(exports["site_config"].future())
    assert set(site) == {
        "account_id",
        "d1_database_id",
        "d1_read_token",
        "public_base_url",
    }
    assert steward["d1_database_id"] == site["d1_database_id"]
    assert all("private" not in key.lower() for key in site)
    assert all("bucket" not in key.lower() for key in site)

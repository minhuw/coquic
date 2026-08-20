from __future__ import annotations

import copy

import httpx
import pytest

from coquic_steward.publication.d1 import D1Error, D1ErrorCode, D1PublicationClient
from coquic_steward.publication.envelope import (
    EnvelopeError,
    EnvelopeErrorCode,
    publication_metadata_digest,
    usage_metadata_digest,
    validate_publication_envelope,
)
from test_publication_d1 import publication, usage_replacement


ACCOUNT = "a" * 32
DATABASE = "12345678-1234-4abc-8def-1234567890ab"
TOKEN = "test-token"


def test_digests_and_detached_copy_match_d1() -> None:
    payload = publication("publication-envelope-characterization")

    assert publication_metadata_digest(payload) == payload["generation"]["metadataDigest"]
    assert usage_metadata_digest(payload) == payload["usage"]["generation"]["metadataDigest"]

    detached = validate_publication_envelope(payload)
    assert detached == payload
    assert detached is not payload
    assert detached["usage"] is not payload["usage"]
    detached["task"]["title"] = "detached"
    assert payload["task"]["title"] == "Clean publication"


def test_codes_and_replacement_match_d1() -> None:
    payload = publication("publication-envelope-codes")

    count_mismatch = copy.deepcopy(payload)
    count_mismatch["generation"]["expectedCounts"]["events"] += 1
    with pytest.raises(EnvelopeError) as error:
        validate_publication_envelope(count_mismatch)
    assert error.value.code == EnvelopeErrorCode.count_mismatch

    private_value = copy.deepcopy(payload)
    private_value["task"]["title"] = "https://private.example.invalid/object"
    with pytest.raises(EnvelopeError) as error:
        validate_publication_envelope(private_value)
    assert error.value.code == EnvelopeErrorCode.private_value

    replacement = usage_replacement(payload, "replacement")
    with pytest.raises(EnvelopeError) as error:
        validate_publication_envelope(replacement)
    assert error.value.code == EnvelopeErrorCode.digest_mismatch
    assert validate_publication_envelope(replacement, allow_usage_replacement=True) == replacement

    unsupported_leaf = copy.deepcopy(payload)
    unsupported_leaf["task"]["title"] = object()
    with pytest.raises(EnvelopeError) as error:
        validate_publication_envelope(unsupported_leaf)
    assert error.value.code == EnvelopeErrorCode.invalid_request
    assert str(error.value) == EnvelopeErrorCode.invalid_request.value


def test_boundaries_preserve_fail_closed_mapping() -> None:
    payload = publication("publication-envelope-boundary")
    payload.pop("task")

    def unexpected_request(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("validation must fail before HTTP")

    with D1PublicationClient(
        account_id=ACCOUNT,
        database_id=DATABASE,
        token=TOKEN,
        transport=httpx.MockTransport(unexpected_request),
    ) as d1:
        with pytest.raises(D1Error) as error:
            d1.stage(payload)

    assert error.value.code == D1ErrorCode.invalid_request

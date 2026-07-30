from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from coquic_steward.publication.r2 import (
    R2Client,
    R2Error,
    R2ErrorCategory,
    R2ObjectClass,
    R2PutStatus,
    R2ValidationError,
    private_original_key,
    public_object_key,
)


BODY = b"immutable publication\n"
DIGEST = hashlib.sha256(BODY).hexdigest()
ETAG = f'"{hashlib.md5(BODY, usedforsecurity=False).hexdigest()}"'
CHECKSUM_SHA256 = base64.b64encode(bytes.fromhex(DIGEST)).decode("ascii")
PUBLIC_KEY = public_object_key("task-1", DIGEST)
PRIVATE_KEY = private_original_key("task-1", "run-1", DIGEST)


def _client_error(code: str, status: int) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "secret response body"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "PutObject",
    )


class FakeS3:
    def __init__(self, *, put_error: Exception | None = None, head: dict | None = None) -> None:
        self.put_error = put_error
        self.head = head or {}
        self.calls: list[tuple[str, dict]] = []

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs))
        if self.put_error is not None:
            raise self.put_error
        return {}

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        return self.head


def _head(
    *,
    digest: str = DIGEST,
    length: int = len(BODY),
    klass: str = "public",
    etag: str | None = ETAG,
    checksum_sha256: str | None = None,
    metadata: dict[str, str] | None = None,
) -> dict:
    response = {
        "ContentLength": length,
        "Metadata": metadata
        or {"sha256": digest, "byte-size": str(length), "object-class": klass},
    }
    if etag is not None:
        response["ETag"] = etag
    if checksum_sha256 is not None:
        response["ChecksumSHA256"] = checksum_sha256
    return response


def _r2(fake: FakeS3) -> R2Client:
    return R2Client(
        "https://r2.example.test",
        public_bucket="public-bucket",
        private_bucket="private-bucket",
        client=fake,
    )


def test_new_object_is_single_part_conditional_and_head_verified() -> None:
    fake = FakeS3(head=_head())
    result = _r2(fake).put_object(PUBLIC_KEY, BODY)
    assert result.status is R2PutStatus.uploaded
    assert [name for name, _ in fake.calls] == ["put_object", "head_object"]
    request = fake.calls[0][1]
    assert request["Bucket"] == "public-bucket"
    assert request["Key"] == PUBLIC_KEY
    assert request["Body"] == BODY
    assert request["IfNoneMatch"] == "*"
    assert request["ContentMD5"] == base64.b64encode(
        hashlib.md5(BODY, usedforsecurity=False).digest()
    ).decode()
    assert request["Metadata"] == {
        "sha256": DIGEST,
        "byte-size": str(len(BODY)),
        "object-class": "public",
    }
    assert not any(name in request for name in ("UploadId", "PartNumber", "ACL", "Delete"))


def test_matching_precondition_replay_is_success_and_private_uses_private_bucket() -> None:
    fake = FakeS3(put_error=_client_error("PreconditionFailed", 412), head=_head())
    result = _r2(fake).put_or_verify(PUBLIC_KEY, BODY)
    assert result.status is R2PutStatus.existing
    assert fake.calls[1][1]["Bucket"] == "public-bucket"

    private_fake = FakeS3(head=_head(klass="private"))
    private_result = _r2(private_fake).put_object(PRIVATE_KEY, BODY, R2ObjectClass.private)
    assert private_result.status is R2PutStatus.uploaded
    assert private_fake.calls[0][1]["Bucket"] == "private-bucket"
    assert private_fake.calls[0][1]["Metadata"]["object-class"] == "private"


def test_mismatched_replay_is_fail_closed_integrity() -> None:
    fake = FakeS3(put_error=_client_error("PreconditionFailed", 412), head=_head(digest="0" * 64))
    with pytest.raises(R2Error) as error:
        _r2(fake).put_object(PUBLIC_KEY, BODY)
    assert error.value.category is R2ErrorCategory.integrity
    assert not error.value.retryable
    assert "secret response body" not in repr(error.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ETag", f'"{"0" * 32}"'),
        ("ChecksumSHA256", "0" * len(CHECKSUM_SHA256)),
    ],
)
def test_mismatched_provider_digest_is_fail_closed_integrity(field: str, value: str) -> None:
    head = _head(checksum_sha256=CHECKSUM_SHA256)
    head[field] = value
    fake = FakeS3(put_error=_client_error("PreconditionFailed", 412), head=head)
    with pytest.raises(R2Error) as error:
        _r2(fake).put_object(PUBLIC_KEY, BODY)
    assert error.value.category is R2ErrorCategory.integrity


def test_missing_provider_digest_is_fail_closed_integrity() -> None:
    fake = FakeS3(
        put_error=_client_error("PreconditionFailed", 412),
        head=_head(etag=None),
    )
    with pytest.raises(R2Error) as error:
        _r2(fake).put_object(PUBLIC_KEY, BODY)
    assert error.value.category is R2ErrorCategory.integrity


def test_metadata_case_is_canonicalized_but_underscores_are_not() -> None:
    uppercase = _head(
        metadata={
            "SHA256": DIGEST,
            "BYTE-SIZE": str(len(BODY)),
            "OBJECT-CLASS": "public",
        }
    )
    uppercase_fake = FakeS3(
        put_error=_client_error("PreconditionFailed", 412),
        head=uppercase,
    )
    assert _r2(uppercase_fake).put_object(PUBLIC_KEY, BODY).status is R2PutStatus.existing

    underscored = _head(
        metadata={
            "sha256": DIGEST,
            "byte_size": str(len(BODY)),
            "object_class": "public",
        }
    )
    underscored_fake = FakeS3(
        put_error=_client_error("PreconditionFailed", 412),
        head=underscored,
    )
    with pytest.raises(R2Error) as error:
        _r2(underscored_fake).put_object(PUBLIC_KEY, BODY)
    assert error.value.category is R2ErrorCategory.integrity


@pytest.mark.parametrize(
    ("exception", "category", "retryable"),
    [
        (_client_error("AccessDenied", 403), R2ErrorCategory.permission, False),
        (_client_error("InvalidAccessKeyId", 403), R2ErrorCategory.auth, False),
        (_client_error("SlowDown", 503), R2ErrorCategory.quota, True),
        (TimeoutError("private timeout"), R2ErrorCategory.network, True),
    ],
)
def test_provider_failures_are_bounded_categories(exception, category, retryable) -> None:
    fake = FakeS3(put_error=exception)
    with pytest.raises(R2Error) as error:
        _r2(fake).put_object(PUBLIC_KEY, BODY)
    assert error.value.category is category
    assert error.value.retryable is retryable
    assert "private" not in str(error.value)


def test_key_payload_and_class_contracts_fail_before_provider_call() -> None:
    fake = FakeS3(head=_head())
    client = _r2(fake)
    with pytest.raises(R2ValidationError):
        client.put_object("v1/tasks/task-1/objects/sha256/00/" + DIGEST, BODY)
    with pytest.raises(R2ValidationError):
        client.put_object(PUBLIC_KEY, b"different")
    with pytest.raises(R2ValidationError):
        client.put_object(PRIVATE_KEY, BODY, R2ObjectClass.public)
    with pytest.raises(R2ValidationError):
        client.put_object(PUBLIC_KEY, BODY, metadata={"sha256": "0" * 64})
    with pytest.raises(R2ValidationError):
        client.put_object(PUBLIC_KEY, BODY, metadata={"byte_size": str(len(BODY))})
    assert not fake.calls


def test_credentials_are_read_only_at_construction_and_not_retained(
    tmp_path: Path, monkeypatch
) -> None:
    access = tmp_path / "access"
    secret = tmp_path / "secret"
    access.write_text("access-value\n", encoding="ascii")
    secret.write_text("secret-value\n", encoding="ascii")
    access.chmod(0o600)
    secret.chmod(0o600)
    captured = {}

    def factory(*args, **kwargs):
        captured.update(kwargs)
        return FakeS3(head=_head())

    monkeypatch.setattr("coquic_steward.publication.r2.boto3.client", factory)
    client = R2Client(
        "https://r2.example.test",
        access,
        secret,
        "public-bucket",
        "private-bucket",
    )
    assert captured["aws_access_key_id"] == "access-value"
    assert captured["aws_secret_access_key"] == "secret-value"
    assert "secret-value" not in repr(client)
    assert client.put_object(PUBLIC_KEY, BODY).verified

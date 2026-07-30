"""Strict, immutable Cloudflare R2 object publication.

The transport accepts only the content-addressed keys from the public cloud
contract.  Every put is conditional and is followed by a descriptor check, so
an interrupted upload can be replayed without ever overwriting an object.
Provider details are deliberately reduced to a small error vocabulary.
"""

from __future__ import annotations

import base64
import hashlib
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import urlsplit

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError


MAX_R2_OBJECT_BYTES: Final[int] = 64 * 1024 * 1024
# S3 keys are bounded at 1 KiB here; the public D1 grammar is narrower while
# private original keys also contain both task and run identities.
MAX_R2_KEY_LENGTH: Final[int] = 1024
MAX_R2_METADATA_VALUE_LENGTH: Final[int] = 256
MAX_R2_CREDENTIAL_BYTES: Final[int] = 4096

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_KEY_RE = re.compile(
    r"^v1/tasks/(?P<task>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/"
    r"objects/sha256/(?P<prefix>[0-9a-f]{2})/(?P<digest>[0-9a-f]{64})$"
)
_PRIVATE_KEY_RE = re.compile(
    r"^v1/originals/(?P<task>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/"
    r"(?P<run>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/sha256/"
    r"(?P<digest>[0-9a-f]{64})\.jsonl$"
)
_METADATA_KEY_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_BUCKET_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$")


class R2ObjectClass(StrEnum):
    """The only object classes accepted by this boundary."""

    public = "public"
    private = "private"


class R2PutStatus(StrEnum):
    uploaded = "uploaded"
    existing = "existing"


class R2ErrorCategory(StrEnum):
    """Bounded provider categories; values never contain provider text."""

    network = "network"
    quota = "quota"
    auth = "auth"
    permission = "permission"
    precondition = "precondition"
    integrity = "integrity"
    validation = "validation"


class R2ValidationError(ValueError):
    """A local contract violation without the offending value in its text."""

    category = R2ErrorCategory.validation
    retryable = False

    def __init__(self, reason: str = "invalid object") -> None:
        # Keep diagnostics bounded and independent of keys, payloads, and
        # credential contents.
        allowed = {"invalid object", "invalid credential", "invalid endpoint", "invalid bucket"}
        super().__init__(reason if reason in allowed else "invalid object")


class R2Error(RuntimeError):
    """A provider failure reduced to a retryable category."""

    def __init__(self, category: R2ErrorCategory | str) -> None:
        self.category = R2ErrorCategory(category)
        self.code = self.category
        self.retryable = self.category in {
            R2ErrorCategory.network,
            R2ErrorCategory.quota,
            R2ErrorCategory.precondition,
        }
        super().__init__(self.category.value)

    @property
    def permanent(self) -> bool:
        return not self.retryable

    @property
    def kind(self) -> R2ErrorCategory:
        return self.category


@dataclass(frozen=True, slots=True)
class R2PutRequest:
    """The complete fixed single-part request sent to boto3."""

    bucket: str
    key: str
    body: bytes = field(repr=False)
    content_md5: str
    metadata: Mapping[str, str]
    object_class: R2ObjectClass

    def __post_init__(self) -> None:
        if not isinstance(self.body, bytes) or not isinstance(self.metadata, Mapping):
            _validation()
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def as_kwargs(self) -> dict[str, Any]:
        """Return only immutable PutObject fields; no multipart/delete knobs."""

        return {
            "Bucket": self.bucket,
            "Key": self.key,
            "Body": self.body,
            "ContentMD5": self.content_md5,
            "IfNoneMatch": "*",
            "Metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class R2PutResult:
    """Verified object identity returned after a put or matching replay."""

    status: R2PutStatus
    key: str
    object_class: R2ObjectClass
    byte_size: int
    sha256: str

    @property
    def uploaded(self) -> bool:
        return self.status is R2PutStatus.uploaded

    @property
    def existing(self) -> bool:
        return self.status is R2PutStatus.existing

    @property
    def created(self) -> bool:
        return self.uploaded

    @property
    def replayed(self) -> bool:
        return self.existing

    @property
    def verified(self) -> bool:
        return True


# Descriptive aliases keep the boundary easy to discover for callers.
ObjectClass = R2ObjectClass
R2FailureCategory = R2ErrorCategory
R2ResultStatus = R2PutStatus
R2Request = R2PutRequest
R2Result = R2PutResult
R2UploadError = R2Error


def _validation(reason: str = "invalid object") -> None:
    raise R2ValidationError(reason) from None


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _validation()
    return value


def _object_class(value: object) -> R2ObjectClass:
    try:
        return R2ObjectClass(value)
    except (TypeError, ValueError):
        _validation()
    raise AssertionError("unreachable")


def validate_object_key(key: object, object_class: R2ObjectClass | str) -> str:
    """Validate a contract key and return its embedded digest."""

    klass = _object_class(object_class)
    if not isinstance(key, str) or not 1 <= len(key) <= MAX_R2_KEY_LENGTH:
        _validation()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
        _validation()
    pattern = _PUBLIC_KEY_RE if klass is R2ObjectClass.public else _PRIVATE_KEY_RE
    match = pattern.fullmatch(key)
    if match is None:
        _validation()
    digest = match.group("digest")
    if klass is R2ObjectClass.public and match.group("prefix") != digest[:2]:
        _validation()
    return digest


def public_object_key(task_id: str, sha256: str) -> str:
    if not isinstance(task_id, str) or _IDENTIFIER_RE.fullmatch(task_id) is None:
        _validation()
    digest = _digest(sha256)
    return f"v1/tasks/{task_id}/objects/sha256/{digest[:2]}/{digest}"


def private_original_key(task_id: str, run_id: str, sha256: str) -> str:
    if not isinstance(task_id, str) or _IDENTIFIER_RE.fullmatch(task_id) is None:
        _validation()
    if not isinstance(run_id, str) or _IDENTIFIER_RE.fullmatch(run_id) is None:
        _validation()
    digest = _digest(sha256)
    return f"v1/originals/{task_id}/{run_id}/sha256/{digest}.jsonl"


def _metadata(
    value: Mapping[str, str] | None,
    *,
    digest: str,
    byte_size: int,
    object_class: R2ObjectClass,
) -> dict[str, str]:
    expected = {
        "sha256": digest,
        "byte-size": str(byte_size),
        "object-class": object_class.value,
    }
    if value is None:
        return expected
    if not isinstance(value, Mapping) or len(value) > len(expected):
        _validation()
    seen: set[str] = set()
    for key, actual in value.items():
        if not isinstance(key, str) or not isinstance(actual, str):
            _validation()
        normalized = key.casefold()
        if _METADATA_KEY_RE.fullmatch(normalized) is None or normalized not in expected:
            _validation()
        if normalized in seen:
            _validation()
        seen.add(normalized)
        if len(actual) > MAX_R2_METADATA_VALUE_LENGTH or any(
            ord(char) < 0x20 or ord(char) == 0x7F for char in actual
        ):
            _validation()
        if actual != expected[normalized]:
            _validation()
    return expected


def _provider_details(error: BaseException) -> tuple[str | None, int | None]:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return None, None
    raw_error = response.get("Error")
    code = raw_error.get("Code") if isinstance(raw_error, Mapping) else None
    status = response.get("ResponseMetadata")
    status_code = status.get("HTTPStatusCode") if isinstance(status, Mapping) else None
    if not isinstance(code, str):
        code = None
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        status_code = None
    return code.casefold() if code is not None else None, status_code


def classify_provider_error(error: BaseException) -> R2ErrorCategory:
    """Classify without formatting or retaining the provider response."""

    code, status = _provider_details(error)
    if code in {
        "invalidaccesskeyid",
        "signaturedoesnotmatch",
        "invalidtoken",
        "expiredtoken",
        "unauthorized",
    } or status == 401:
        return R2ErrorCategory.auth
    if code in {"accessdenied", "forbidden", "accountisdisabled"} or status == 403:
        return R2ErrorCategory.permission
    if code in {
        "slowdown",
        "throttling",
        "throttlingexception",
        "requestlimitexceeded",
        "toomanyrequests",
    } or status in {429, 503}:
        return R2ErrorCategory.quota
    if code in {
        "preconditionfailed",
        "conditionalrequestconflict",
        "operationaborted",
    } or status in {409, 412}:
        return R2ErrorCategory.precondition
    if isinstance(error, (BotoCoreError, OSError, TimeoutError, ConnectionError)):
        return R2ErrorCategory.network
    # Unknown SDK failures are treated as transient network failures, but their
    # response text is never propagated.
    return R2ErrorCategory.network


def _not_found(error: BaseException) -> bool:
    code, status = _provider_details(error)
    return code in {"nosuchkey", "notfound", "nosuchbucket"} or status == 404


def _credential(path: object) -> str:
    try:
        credential_path = Path(path)
        metadata = credential_path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_R2_CREDENTIAL_BYTES
        ):
            _validation("invalid credential")
        raw = credential_path.read_bytes()
    except R2ValidationError:
        raise
    except (OSError, TypeError, ValueError):
        _validation("invalid credential")
    if not raw or len(raw) > MAX_R2_CREDENTIAL_BYTES:
        _validation("invalid credential")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        _validation("invalid credential")
    if not value or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        _validation("invalid credential")
    return value


def _endpoint(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        _validation("invalid endpoint")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        _validation("invalid endpoint")
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        _validation("invalid endpoint")
    return value


def _bucket(value: object) -> str:
    if not isinstance(value, str) or _BUCKET_RE.fullmatch(value) is None:
        _validation("invalid bucket")
    return value


class R2Client:
    """Daemon-side boto3 client for conditional, single-part R2 writes."""

    def __init__(
        self,
        endpoint: str | object | None = None,
        access_key_id_path: Path | None = None,
        secret_access_key_path: Path | None = None,
        public_bucket: str | None = None,
        private_bucket: str | None = None,
        *,
        config: object | None = None,
        client: Any | None = None,
        s3_client: Any | None = None,
        session: Any | None = None,
        timeout_seconds: float = 30.0,
        region_name: str = "auto",
    ) -> None:
        source = config if config is not None else endpoint
        if source is not None and not isinstance(source, str):
            endpoint = getattr(source, "r2_endpoint", None) or getattr(
                source, "r2_endpoint_url", None
            )
            access_key_id_path = (
                access_key_id_path
                or getattr(source, "r2_access_key_id_path", None)
                or getattr(source, "r2_access_key_path", None)
            )
            secret_access_key_path = (
                secret_access_key_path
                or getattr(source, "r2_secret_access_key_path", None)
                or getattr(source, "r2_secret_key_path", None)
            )
            public_bucket = (
                public_bucket
                or getattr(source, "public_bucket", None)
                or getattr(source, "public_r2_bucket", None)
            )
            private_bucket = (
                private_bucket
                or getattr(source, "private_bucket", None)
                or getattr(source, "private_r2_bucket", None)
            )
        if client is not None and s3_client is not None:
            _validation()
        self._endpoint = _endpoint(endpoint)
        self._public_bucket = _bucket(public_bucket)
        self._private_bucket = _bucket(private_bucket)
        if self._public_bucket == self._private_bucket:
            _validation("invalid bucket")
        supplied_client = client if client is not None else s3_client
        if supplied_client is not None:
            self._client = supplied_client
            return
        if access_key_id_path is None or secret_access_key_path is None:
            _validation("invalid credential")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= 86400
        ):
            _validation()
        access_key_id = _credential(access_key_id_path)
        secret_access_key = _credential(secret_access_key_path)
        client_factory = session.client if session is not None else boto3.client
        try:
            self._client = client_factory(
                "s3",
                endpoint_url=self._endpoint,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=region_name,
                config=BotoConfig(
                    connect_timeout=float(timeout_seconds),
                    read_timeout=float(timeout_seconds),
                    retries={"max_attempts": 1, "mode": "standard"},
                ),
            )
        except Exception:
            raise R2Error(R2ErrorCategory.network) from None
        finally:
            # Do not retain credential values in this boundary after client
            # construction.  boto3 owns its signing state internally.
            del access_key_id
            del secret_access_key

    def _prepare(
        self,
        key: object,
        content: object,
        object_class: R2ObjectClass | str,
        metadata: Mapping[str, str] | None,
        expected_sha256: str | None,
        expected_size: int | None,
    ) -> tuple[str, R2ObjectClass, bytes, str, str, dict[str, str]]:
        klass = _object_class(object_class)
        digest_in_key = validate_object_key(key, klass)
        if not isinstance(content, bytes) or len(content) > MAX_R2_OBJECT_BYTES:
            _validation()
        digest = hashlib.sha256(content).hexdigest()
        if digest != digest_in_key:
            _validation()
        if expected_sha256 is not None and _digest(expected_sha256) != digest:
            _validation()
        if expected_size is not None and (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size != len(content)
        ):
            _validation()
        md5 = base64.b64encode(hashlib.md5(content, usedforsecurity=False).digest()).decode("ascii")
        return (
            key,
            klass,
            content,
            digest,
            md5,
            _metadata(
                metadata,
                digest=digest,
                byte_size=len(content),
                object_class=klass,
            ),
        )

    def put_object(
        self,
        key: str,
        content: bytes,
        object_class: R2ObjectClass | str = R2ObjectClass.public,
        *,
        metadata: Mapping[str, str] | None = None,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> R2PutResult:
        """Conditionally put one object and verify its final descriptor."""

        key, klass, content, digest, md5, expected_metadata = self._prepare(
            key, content, object_class, metadata, expected_sha256, expected_size
        )
        bucket = self._public_bucket if klass is R2ObjectClass.public else self._private_bucket
        request = R2PutRequest(
            bucket=bucket,
            key=key,
            body=content,
            content_md5=md5,
            metadata=expected_metadata,
            object_class=klass,
        )
        try:
            self._client.put_object(**request.as_kwargs())
        except Exception as error:
            category = classify_provider_error(error)
            if category is not R2ErrorCategory.precondition:
                raise R2Error(category) from None
            return self._head_and_verify(
                bucket,
                key,
                klass,
                len(content),
                digest,
                md5,
                expected_metadata,
                conflict=True,
            )
        return self._head_and_verify(
            bucket,
            key,
            klass,
            len(content),
            digest,
            md5,
            expected_metadata,
            conflict=False,
            uploaded=True,
        )

    def _head_and_verify(
        self,
        bucket: str,
        key: str,
        klass: R2ObjectClass,
        byte_size: int,
        digest: str,
        content_md5: str,
        expected_metadata: Mapping[str, str],
        *,
        conflict: bool,
        uploaded: bool = False,
    ) -> R2PutResult:
        try:
            response = self._client.head_object(Bucket=bucket, Key=key)
        except Exception as error:
            if conflict and _not_found(error):
                raise R2Error(R2ErrorCategory.precondition) from None
            category = classify_provider_error(error)
            if _not_found(error):
                category = R2ErrorCategory.integrity
            raise R2Error(category) from None
        if not isinstance(response, Mapping):
            raise R2Error(R2ErrorCategory.integrity)
        length = response.get("ContentLength")
        metadata = response.get("Metadata")
        if isinstance(length, bool) or not isinstance(length, int) or length != byte_size:
            raise R2Error(R2ErrorCategory.integrity)
        if not isinstance(metadata, Mapping):
            raise R2Error(R2ErrorCategory.integrity)
        normalized: dict[str, str] = {}
        for name, value in metadata.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise R2Error(R2ErrorCategory.integrity)
            canonical_name = name.casefold()
            if canonical_name in normalized:
                raise R2Error(R2ErrorCategory.integrity)
            normalized[canonical_name] = value
        if normalized != dict(expected_metadata) or normalized.get("sha256") != digest:
            raise R2Error(R2ErrorCategory.integrity)
        expected_etag = base64.b64decode(content_md5).hex()
        expected_checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
        descriptors = 0
        if "ETag" in response:
            etag = response["ETag"]
            if not isinstance(etag, str) or etag not in {
                expected_etag,
                f'"{expected_etag}"',
            }:
                raise R2Error(R2ErrorCategory.integrity)
            descriptors += 1
        if "ChecksumSHA256" in response:
            checksum = response["ChecksumSHA256"]
            if not isinstance(checksum, str) or checksum != expected_checksum:
                raise R2Error(R2ErrorCategory.integrity)
            descriptors += 1
        if descriptors == 0:
            raise R2Error(R2ErrorCategory.integrity)
        return R2PutResult(
            R2PutStatus.uploaded if uploaded else R2PutStatus.existing,
            key,
            klass,
            byte_size,
            digest,
        )

    def put_or_verify(self, *args: Any, **kwargs: Any) -> R2PutResult:
        return self.put_object(*args, **kwargs)

    def put_immutable(self, *args: Any, **kwargs: Any) -> R2PutResult:
        return self.put_object(*args, **kwargs)

    def upload(self, *args: Any, **kwargs: Any) -> R2PutResult:
        return self.put_object(*args, **kwargs)

    def verify_object(
        self,
        key: str,
        content: bytes,
        object_class: R2ObjectClass | str = R2ObjectClass.public,
        *,
        metadata: Mapping[str, str] | None = None,
    ) -> R2PutResult:
        key, klass, content, _digest_value, content_md5, expected_metadata = self._prepare(
            key, content, object_class, metadata, None, None
        )
        bucket = self._public_bucket if klass is R2ObjectClass.public else self._private_bucket
        return self._head_and_verify(
            bucket,
            key,
            klass,
            len(content),
            _digest_value,
            content_md5,
            expected_metadata,
            conflict=False,
        )

    head_and_verify = verify_object


__all__ = [
    "MAX_R2_CREDENTIAL_BYTES",
    "MAX_R2_KEY_LENGTH",
    "MAX_R2_METADATA_VALUE_LENGTH",
    "MAX_R2_OBJECT_BYTES",
    "ObjectClass",
    "R2Client",
    "R2Error",
    "R2ErrorCategory",
    "R2FailureCategory",
    "R2ObjectClass",
    "R2PutRequest",
    "R2PutResult",
    "R2PutStatus",
    "R2Request",
    "R2Result",
    "R2ResultStatus",
    "R2UploadError",
    "R2ValidationError",
    "classify_provider_error",
    "private_original_key",
    "public_object_key",
    "validate_object_key",
]

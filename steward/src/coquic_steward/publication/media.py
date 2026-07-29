"""Fail-closed inspection of publication media.

The media gate is deliberately transport-free.  It accepts immutable bytes (or
one of the publication input values), proves that supported images can be
decoded completely, and returns the original bytes only after metadata and OCR
have passed the existing text-security boundary.  No inspected value is kept
in a report or an exception message.
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess  # nosec B404 - fixed local Tesseract argv below
import warnings
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Final

from PIL import Image, UnidentifiedImageError
from PIL.Image import DecompressionBombError, DecompressionBombWarning

from .models import (
    AtifDocument,
    MAX_FINDINGS,
    PublicationError,
    PublicBundle,
    PublicBundleComponent,
    ReasonCode,
    SourceDocument,
    StableRead,
    private_staging,
    read_stable_file,
)
from .redaction import discover_secrets
from .scanner import (
    MAX_SCANNER_TIMEOUT_SECONDS,
    CorpusEntry,
    ScannerReport,
    run_trufflehog,
)


SUPPORTED_IMAGE_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {"image/jpeg", "image/png", "image/gif", "image/webp"}
)
SUPPORTED_IMAGE_FORMATS: Final[dict[str, str]] = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/gif": "GIF",
    "image/webp": "WEBP",
}

# These limits are intentionally independent of Pillow's global defaults.
MAX_MEDIA_BYTES: Final[int] = 64 * 1024 * 1024
MAX_IMAGE_DIMENSION: Final[int] = 16_384
MAX_IMAGE_PIXELS: Final[int] = 64 * 1024 * 1024
MAX_IMAGE_FRAMES: Final[int] = 128
MAX_METADATA_ENTRIES: Final[int] = 4_096
MAX_METADATA_BYTES: Final[int] = 4 * 1024 * 1024
MAX_OCR_OUTPUT_BYTES: Final[int] = 256 * 1024
MAX_OCR_TIMEOUT_SECONDS: Final[float] = 30.0

# Text media are explicitly allowlisted.  An arbitrary application/octet-stream
# is never accepted merely because it happens to decode as UTF-8.
SUPPORTED_TEXT_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "application/json",
        "application/jsonl",
        "application/ld+json",
        "application/toml",
        "application/typescript",
        "application/xml",
        "application/x-javascript",
        "application/x-sh",
        "application/x-yaml",
        "application/yaml",
        "text/css",
        "text/csv",
        "text/html",
        "text/javascript",
        "text/markdown",
        "text/plain",
        "text/typescript",
        "text/xml",
        "text/yaml",
    }
)

_MAX_SECRETS = MAX_FINDINGS * 8
_MISSING = object()


class MediaInspectionError(PublicationError):
    """A bounded media failure without parser, scanner, or path details."""


@dataclass(frozen=True, slots=True)
class MediaInspection:
    """A typed media decision and the bytes approved by that decision.

    ``content`` is omitted from repr and from :meth:`as_dict`; it is available
    only through ``bytes``/``data`` for the next in-process publication stage.
    """

    status: str
    category: str
    media_type: str
    byte_size: int
    sha256: str
    frame_count: int = 0
    metadata_count: int = 0
    ocr_frame_count: int = 0
    finding_count: int = 0
    reason: ReasonCode | None = None
    content: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.status not in {"approved", "fail_closed"}:
            raise MediaInspectionError(ReasonCode.invalid_metadata)
        if self.category not in {"text", "image", "handler", "binary"}:
            raise MediaInspectionError(ReasonCode.invalid_metadata)
        if not isinstance(self.media_type, str) or not self.media_type or len(self.media_type) > 128:
            raise MediaInspectionError(ReasonCode.invalid_media_type)
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in self.media_type):
            raise MediaInspectionError(ReasonCode.invalid_media_type)
        for value in (
            self.byte_size,
            self.frame_count,
            self.metadata_count,
            self.ocr_frame_count,
            self.finding_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**31 - 1:
                raise MediaInspectionError(ReasonCode.invalid_metadata)
        if not isinstance(self.sha256, str) or len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256):
            raise MediaInspectionError(ReasonCode.invalid_digest)
        if self.reason is not None:
            try:
                reason = ReasonCode(self.reason)
            except (TypeError, ValueError):
                raise MediaInspectionError(ReasonCode.invalid_metadata) from None
            object.__setattr__(self, "reason", reason)
        if self.status == "approved":
            if self.reason is not None or not isinstance(self.content, bytes):
                raise MediaInspectionError(ReasonCode.invalid_metadata)
            if self.byte_size != len(self.content) or hashlib.sha256(self.content).hexdigest() != self.sha256:
                raise MediaInspectionError(ReasonCode.digest_mismatch)
        elif self.reason is None or self.content is not None:
            raise MediaInspectionError(ReasonCode.invalid_metadata)

    @property
    def approved(self) -> bool:
        return self.status == "approved"

    @property
    def clean(self) -> bool:
        return self.approved

    @property
    def bytes(self) -> bytes | None:
        return self.content

    @property
    def data(self) -> bytes | None:
        return self.content

    @property
    def reason_code(self) -> ReasonCode | None:
        return self.reason

    @property
    def media_category(self) -> str:
        return self.category

    @property
    def frame_total(self) -> int:
        return self.frame_count

    @property
    def metadata_items(self) -> int:
        return self.metadata_count

    @property
    def ocr_frames(self) -> int:
        return self.ocr_frame_count

    @property
    def reason_codes(self) -> tuple[ReasonCode, ...]:
        return () if self.reason is None else (self.reason,)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "category": self.category,
            "mediaType": self.media_type,
            "byteSize": self.byte_size,
            "sha256": self.sha256,
            "frameCount": self.frame_count,
            "metadataCount": self.metadata_count,
            "ocrFrameCount": self.ocr_frame_count,
            "findingCount": self.finding_count,
        }
        if self.reason is not None:
            value["reason"] = self.reason.value
        return value

    @classmethod
    def approved_result(
        cls,
        *,
        category: str,
        media_type: str,
        content: bytes,
        frame_count: int = 0,
        metadata_count: int = 0,
        ocr_frame_count: int = 0,
        finding_count: int = 0,
    ) -> "MediaInspection":
        return cls(
            "approved",
            category,
            media_type,
            len(content),
            hashlib.sha256(content).hexdigest(),
            frame_count,
            metadata_count,
            ocr_frame_count,
            finding_count,
            None,
            content,
        )

    @classmethod
    def failed_result(
        cls,
        *,
        category: str,
        media_type: str,
        content: bytes,
        reason: ReasonCode,
        frame_count: int = 0,
        metadata_count: int = 0,
        ocr_frame_count: int = 0,
        finding_count: int = 0,
    ) -> "MediaInspection":
        return cls(
            "fail_closed",
            category,
            media_type,
            len(content),
            hashlib.sha256(content).hexdigest(),
            frame_count,
            metadata_count,
            ocr_frame_count,
            finding_count,
            reason,
            None,
        )


# Descriptive compatibility spellings used by later publication stages.
MediaInspectionResult = MediaInspection
MediaResult = MediaInspection
MediaInspectionOutcome = MediaInspection


@dataclass(frozen=True, slots=True)
class MediaInspectionReport:
    """Bounded aggregate decision for one completed ATIF bundle."""

    results: tuple[MediaInspection, ...] = ()

    def __post_init__(self) -> None:
        values = tuple(self.results)
        if len(values) > 4_096 or any(not isinstance(item, MediaInspection) for item in values):
            raise MediaInspectionError(ReasonCode.invalid_metadata)
        object.__setattr__(self, "results", values)

    @property
    def approved(self) -> bool:
        return all(item.approved for item in self.results)

    @property
    def clean(self) -> bool:
        return self.approved

    @property
    def status(self) -> str:
        return "approved" if self.approved else "fail_closed"

    @property
    def reason_codes(self) -> tuple[ReasonCode, ...]:
        return tuple(dict.fromkeys(item.reason for item in self.results if item.reason is not None))

    @property
    def failures(self) -> tuple[MediaInspection, ...]:
        return tuple(item for item in self.results if not item.approved)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "count": len(self.results),
            "approvedCount": sum(item.approved for item in self.results),
            "failureCount": sum(not item.approved for item in self.results),
            "results": [item.as_dict() for item in self.results],
        }
        if self.reason_codes:
            value["reasonCodes"] = [reason.value for reason in self.reason_codes]
        return value


MediaReport = MediaInspectionReport
MediaSecurityReport = MediaInspectionReport


MediaHandler = Callable[[bytes, str], MediaInspection]
_HANDLERS: dict[str, MediaHandler] = {}


def _base_media_type(media_type: object) -> str | None:
    if not isinstance(media_type, str) or not media_type or len(media_type) > 128:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in media_type):
        return None
    base = media_type.partition(";")[0].strip().casefold()
    return base or None


def classify_media(media_type: object, content: bytes | None = None) -> str:
    """Classify a declared media type without looking at its bytes."""

    base = _base_media_type(media_type)
    if base in SUPPORTED_IMAGE_MEDIA_TYPES:
        return "image"
    if base in SUPPORTED_TEXT_MEDIA_TYPES or (base is not None and base.startswith("text/")):
        return "text"
    return "binary"


def register_media_handler(media_type: str, handler: MediaHandler) -> MediaHandler:
    """Register a bounded handler for one otherwise opaque media type."""

    base = _base_media_type(media_type)
    if base is None or base in SUPPORTED_IMAGE_MEDIA_TYPES or classify_media(base) == "text" or not callable(handler):
        raise MediaInspectionError(ReasonCode.invalid_metadata)
    _HANDLERS[base] = handler
    return handler


def unregister_media_handler(media_type: str) -> None:
    base = _base_media_type(media_type)
    if base is None:
        raise MediaInspectionError(ReasonCode.invalid_media_type)
    _HANDLERS.pop(base, None)


def registered_media_handlers() -> tuple[str, ...]:
    return tuple(sorted(_HANDLERS))


@dataclass(frozen=True, slots=True)
class _Source:
    content: bytes
    media_type: str
    expected_size: int | None = None
    expected_sha256: str | None = None
    path: Path | None = None


@dataclass(frozen=True, slots=True)
class _FrameInspection:
    frame: Image.Image = field(repr=False)
    metadata: tuple[str, ...] = field(repr=False)
    raw_metadata: tuple[bytes, ...] = field(repr=False)
    metadata_count: int
    width: int
    height: int


def _failure(
    content: bytes,
    media_type: str,
    category: str,
    reason: ReasonCode,
    *,
    frame_count: int = 0,
    metadata_count: int = 0,
    ocr_frame_count: int = 0,
    finding_count: int = 0,
) -> MediaInspection:
    return MediaInspection.failed_result(
        category=category,
        media_type=media_type,
        content=content,
        reason=reason,
        frame_count=frame_count,
        metadata_count=metadata_count,
        ocr_frame_count=ocr_frame_count,
        finding_count=finding_count,
    )


def _safe_media_type(value: object) -> str:
    base = _base_media_type(value)
    return base or "application/octet-stream"


def _coerce_source(source: object, media_type: object) -> tuple[_Source | None, ReasonCode | None]:
    path: Path | None = None
    expected_size: int | None = None
    expected_sha256: str | None = None
    content: object = source
    declared: object = media_type
    if isinstance(source, PublicBundleComponent):
        content = source.content
        declared = source.artifact.media_type if media_type is None else media_type
        expected_size = source.artifact.byte_size
        expected_sha256 = source.artifact.sha256
    elif isinstance(source, SourceDocument):
        content = source.content
        declared = source.media_type if media_type is None else media_type
        expected_size = source.byte_size
        expected_sha256 = source.sha256
    elif isinstance(source, StableRead):
        content = source.content
        expected_size = source.byte_size
        expected_sha256 = source.sha256
        declared = "application/octet-stream" if media_type is None else media_type
    elif isinstance(source, Path):
        path = source
        declared = "application/octet-stream" if media_type is None else media_type
        try:
            stable = read_stable_file(path, max_bytes=MAX_MEDIA_BYTES)
        except PublicationError as exc:
            return None, exc.code
        content = stable.content
        expected_size = stable.byte_size
        expected_sha256 = stable.sha256
    if not isinstance(content, bytes):
        return None, ReasonCode.invalid_metadata
    base = _base_media_type(declared)
    if base is None:
        return None, ReasonCode.invalid_media_type
    if len(content) > MAX_MEDIA_BYTES:
        return None, ReasonCode.oversized
    digest = hashlib.sha256(content).hexdigest()
    if expected_size is not None and expected_size != len(content):
        return None, ReasonCode.size_mismatch
    if expected_sha256 is not None and expected_sha256 != digest:
        return None, ReasonCode.digest_mismatch
    return _Source(content, base, expected_size, expected_sha256, path), None


def _verify_path(source: _Source) -> ReasonCode | None:
    if source.path is None:
        return None
    try:
        stable = read_stable_file(
            source.path,
            max_bytes=MAX_MEDIA_BYTES,
            expected_size=source.expected_size,
            expected_sha256=source.expected_sha256,
        )
    except PublicationError as exc:
        return exc.code
    if stable.content != source.content:
        return ReasonCode.changing
    return None


def _metadata_values(value: object, texts: list[str], raw: list[bytes], state: list[int], depth: int = 0) -> None:
    if depth > 32:
        raise MediaInspectionError(ReasonCode.unsafe_content)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_METADATA_BYTES:
            raise MediaInspectionError(ReasonCode.oversized)
        state[0] += 1
        state[1] += len(encoded)
        if state[0] > MAX_METADATA_ENTRIES or state[1] > MAX_METADATA_BYTES:
            raise MediaInspectionError(ReasonCode.oversized)
        texts.append(value)
        return
    if isinstance(value, bytes):
        if len(value) > MAX_METADATA_BYTES:
            raise MediaInspectionError(ReasonCode.oversized)
        state[0] += 1
        state[1] += len(value)
        if state[0] > MAX_METADATA_ENTRIES or state[1] > MAX_METADATA_BYTES:
            raise MediaInspectionError(ReasonCode.oversized)
        raw.append(value)
        try:
            texts.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                _metadata_values(key, texts, raw, state, depth + 1)
            _metadata_values(child, texts, raw, state, depth + 1)
        return
    if isinstance(value, (tuple, list)):
        for child in value:
            _metadata_values(child, texts, raw, state, depth + 1)


def _extract_metadata(image: Image.Image) -> tuple[tuple[str, ...], tuple[bytes, ...], int]:
    texts: list[str] = []
    raw: list[bytes] = []
    state = [0, 0]
    try:
        _metadata_values(image.info, texts, raw, state)
        exif = image.getexif()
        if exif:
            _metadata_values(dict(exif), texts, raw, state)
    except MediaInspectionError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, MemoryError, RecursionError):
        raise MediaInspectionError(ReasonCode.unsafe_content) from None
    return tuple(texts), tuple(raw), state[0]


def _complete_stream(content: bytes, media_type: str) -> bool:
    """Require the format's terminal marker to be the final input byte."""

    if media_type == "image/gif":
        return _gif_complete(content)
    if media_type == "image/jpeg":
        return _jpeg_complete(content)
    if media_type == "image/webp":
        return len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP" and int.from_bytes(content[4:8], "little") == len(content) - 8
    if media_type == "image/png":
        if not content.startswith(b"\x89PNG\r\n\x1a\n"):
            return False
        offset = 8
        saw_end = False
        while offset + 12 <= len(content):
            length = int.from_bytes(content[offset : offset + 4], "big")
            end = offset + 12 + length
            if end > len(content):
                return False
            chunk_length = length
            chunk = content[offset + 4 : offset + 8]
            offset = end
            if chunk == b"IEND":
                if chunk_length != 0:
                    return False
                saw_end = True
                break
        return saw_end and offset == len(content)
    return False


def _jpeg_complete(content: bytes) -> bool:
    """Parse JPEG markers far enough to distinguish a real EOI from a suffix."""

    if len(content) < 4 or content[:2] != b"\xff\xd8":
        return False
    position = 2
    while position < len(content):
        if content[position] != 0xFF:
            return False
        while position < len(content) and content[position] == 0xFF:
            position += 1
        if position >= len(content):
            return False
        marker = content[position]
        position += 1
        if marker == 0xD9:
            return position == len(content)
        if marker in {0xD8, 0x01} or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > len(content):
            return False
        length = int.from_bytes(content[position : position + 2], "big")
        if length < 2 or position + length > len(content):
            return False
        position += length
        if marker != 0xDA:
            continue
        # Entropy-coded bytes use 0xff00 for a literal 0xff and restart
        # markers for block boundaries.  A different marker before EOI would
        # require a second scan, which is deliberately rejected here.
        while position < len(content):
            if content[position] != 0xFF:
                position += 1
                continue
            position += 1
            while position < len(content) and content[position] == 0xFF:
                position += 1
            if position >= len(content):
                return False
            marker = content[position]
            position += 1
            if marker == 0x00 or 0xD0 <= marker <= 0xD7:
                continue
            return marker == 0xD9 and position == len(content)
        return False
    return False


def _gif_complete(content: bytes) -> bool:
    """Walk GIF blocks so bytes after the actual trailer cannot hide."""

    if len(content) < 13 or content[:6] not in {b"GIF87a", b"GIF89a"}:
        return False
    position = 6
    packed = content[position + 4]
    position += 7
    if packed & 0x80:
        table_size = 3 * (2 ** ((packed & 0x07) + 1))
        position += table_size
    while position < len(content):
        block = content[position]
        position += 1
        if block == 0x3B:
            return position == len(content)
        if block == 0x2C:
            if position + 9 > len(content):
                return False
            image_packed = content[position + 8]
            position += 9
            if image_packed & 0x80:
                table_size = 3 * (2 ** ((image_packed & 0x07) + 1))
                position += table_size
            if position >= len(content):
                return False
            position += 1  # LZW minimum code size.
        elif block == 0x21:
            if position >= len(content):
                return False
            position += 1  # Extension label.
        else:
            return False
        while True:
            if position >= len(content):
                return False
            size = content[position]
            position += 1
            if size == 0:
                break
            position += size
            if position > len(content):
                return False
    return False


def _decode_frames(content: bytes, media_type: str) -> tuple[tuple[_FrameInspection, ...], int] | ReasonCode:
    expected_format = SUPPORTED_IMAGE_FORMATS[media_type]
    stream = io.BytesIO(content)
    first: Image.Image | None = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", DecompressionBombWarning)
            first = Image.open(stream)
            if first.format != expected_format:
                return ReasonCode.invalid_media_type
            first.verify()
        stream.seek(0)
        with warnings.catch_warnings():
            warnings.simplefilter("error", DecompressionBombWarning)
            image = Image.open(stream)
            if image.format != expected_format:
                return ReasonCode.invalid_media_type
            try:
                frame_total = int(getattr(image, "n_frames", 1))
            except (AttributeError, TypeError, ValueError, OSError):
                return ReasonCode.unsafe_content
            if frame_total < 1 or frame_total > MAX_IMAGE_FRAMES:
                return ReasonCode.oversized
            frames: list[_FrameInspection] = []
            total_pixels = 0
            for index in range(frame_total):
                try:
                    image.seek(index)
                    width, height = image.size
                    if (
                        isinstance(width, bool)
                        or isinstance(height, bool)
                        or not isinstance(width, int)
                        or not isinstance(height, int)
                        or width < 1
                        or height < 1
                        or width > MAX_IMAGE_DIMENSION
                        or height > MAX_IMAGE_DIMENSION
                        or width * height > MAX_IMAGE_PIXELS
                    ):
                        return ReasonCode.oversized
                    total_pixels += width * height
                    if total_pixels > MAX_IMAGE_PIXELS:
                        return ReasonCode.oversized
                    image.load()
                    metadata, raw_metadata, metadata_count = _extract_metadata(image)
                    frames.append(_FrameInspection(image.copy(), metadata, raw_metadata, metadata_count, width, height))
                except (EOFError, OSError, ValueError, SyntaxError, UnidentifiedImageError):
                    return ReasonCode.unsafe_content
            # Pillow normally consumes the complete stream when every frame is
            # loaded.  A remaining suffix is a polyglot or unverified payload.
            if not _complete_stream(content, media_type):
                return ReasonCode.unsafe_content
            return tuple(frames), sum(item.metadata_count for item in frames)
    except (DecompressionBombError, DecompressionBombWarning):
        return ReasonCode.oversized
    except (EOFError, OSError, ValueError, SyntaxError, UnidentifiedImageError, MemoryError, RecursionError):
        return ReasonCode.unsafe_content
    finally:
        if first is not None:
            try:
                first.close()
            except Exception:
                pass
        try:
            stream.close()
        except Exception:
            pass


def _normalise_secrets(secrets: object, credential_sources: object) -> tuple[str, ...]:
    values: list[str] = []
    if credential_sources is not None:
        values.extend(discover_secrets(credential_sources))
    if secrets is not None:
        if isinstance(secrets, str):
            candidates: Sequence[object] = (secrets,)
        else:
            try:
                candidates = tuple(secrets)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                raise MediaInspectionError(ReasonCode.invalid_metadata) from None
        for candidate in candidates:
            if not isinstance(candidate, str):
                raise MediaInspectionError(ReasonCode.invalid_metadata)
            try:
                encoded = candidate.encode("utf-8")
            except UnicodeEncodeError:
                raise MediaInspectionError(ReasonCode.invalid_metadata) from None
            if not candidate or len(encoded) > MAX_METADATA_BYTES:
                raise MediaInspectionError(ReasonCode.oversized)
            values.append(candidate)
    unique = sorted(set(values), key=lambda value: (-len(value.encode("utf-8")), value))
    if len(unique) > _MAX_SECRETS:
        raise MediaInspectionError(ReasonCode.oversized)
    return tuple(unique)


def _contains_secret(values: Sequence[bytes | str], secrets: Sequence[str]) -> bool:
    if not secrets:
        return False
    for value in values:
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        if any(secret.encode("utf-8") in encoded for secret in secrets):
            return True
    return False


def _ocr_env(root: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(root),
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_ocr(
    frames: Sequence[_FrameInspection],
    *,
    runner: Callable[..., Any] | None,
    timeout: float,
) -> tuple[tuple[str, ...], int, ReasonCode | None]:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > MAX_OCR_TIMEOUT_SECONDS:
        return (), 0, ReasonCode.ocr_failure
    texts: list[str] = []
    selected = runner or subprocess.run
    try:
        with TemporaryDirectory(prefix="coquic-publication-ocr-") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            with private_staging(root) as staging:
                descriptor = getattr(staging, "_fd", None)
                if not isinstance(descriptor, int):
                    return (), 0, ReasonCode.ocr_failure
                for index, item in enumerate(frames):
                    rendered = io.BytesIO()
                    try:
                        item.frame.convert("RGB").save(rendered, format="PNG", optimize=False)
                    except (OSError, ValueError, MemoryError):
                        return (), index, ReasonCode.ocr_failure
                    name = f"frame-{index:04d}.png"
                    staging.write_bytes(name, rendered.getvalue())
                    argv = [
                        "tesseract",
                        f"/proc/self/fd/{descriptor}/{name}",
                        "stdout",
                        "--psm",
                        "6",
                        "--oem",
                        "1",
                    ]
                    try:
                        result = selected(
                            argv,
                            capture_output=True,
                            text=False,
                            timeout=float(timeout),
                            check=False,
                            pass_fds=(descriptor,),
                            env=_ocr_env(root),
                        )
                        returncode = getattr(result, "returncode", _MISSING)
                        stdout = getattr(result, "stdout", _MISSING)
                        if isinstance(returncode, bool) or not isinstance(returncode, int) or returncode != 0:
                            return (), index, ReasonCode.ocr_failure
                        if isinstance(stdout, str):
                            output = stdout.encode("utf-8")
                        elif isinstance(stdout, bytes):
                            output = stdout
                        else:
                            return (), index, ReasonCode.ocr_failure
                        if len(output) > MAX_OCR_OUTPUT_BYTES:
                            return (), index, ReasonCode.ocr_failure
                        try:
                            texts.append(output.decode("utf-8"))
                        except UnicodeDecodeError:
                            return (), index, ReasonCode.ocr_failure
                    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError, TypeError, MemoryError):
                        return (), index, ReasonCode.ocr_failure
                    except Exception:
                        return (), index, ReasonCode.ocr_failure
                    finally:
                        rendered.close()
                return tuple(texts), len(frames), None
    except (OSError, PublicationError, MemoryError):
        return (), 0, ReasonCode.ocr_failure


def _scan_metadata_ocr(
    entries: Sequence[CorpusEntry],
    *,
    raw_metadata: Sequence[bytes] = (),
    secrets: Sequence[str],
    scanner_runner: Callable[..., Any] | None,
    scanner_timeout: float,
) -> tuple[int, ReasonCode | None]:
    if _contains_secret([entry.content for entry in entries] + list(raw_metadata), secrets):
        return 1, ReasonCode.unsafe_content
    try:
        report: ScannerReport = run_trufflehog(
            entries,
            timeout=scanner_timeout,
            runner=scanner_runner,
        )
    except (PublicationError, TypeError, ValueError, MemoryError):
        return 0, ReasonCode.scanner_failure
    if report.failure is not None or report.returncode != 0:
        return 0, ReasonCode.scanner_failure
    if report.findings:
        return len(report.findings), ReasonCode.unsafe_content
    return 0, None


def _inspect_image(
    source: _Source,
    *,
    secrets: Sequence[str],
    scanner_runner: Callable[..., Any] | None,
    scanner_timeout: float,
    ocr_runner: Callable[..., Any] | None,
    ocr_timeout: float,
) -> MediaInspection:
    decoded = _decode_frames(source.content, source.media_type)
    if isinstance(decoded, ReasonCode):
        return _failure(source.content, source.media_type, "image", decoded)
    frames, metadata_count = decoded
    metadata_texts: list[str] = []
    raw_metadata: list[bytes] = []
    for frame in frames:
        metadata_texts.extend(frame.metadata)
        raw_metadata.extend(frame.raw_metadata)
    try:
        ocr_texts, ocr_count, ocr_reason = _run_ocr(frames, runner=ocr_runner, timeout=ocr_timeout)
    finally:
        for frame in frames:
            try:
                frame.frame.close()
            except Exception:
                pass
    if ocr_reason is not None:
        return _failure(
            source.content,
            source.media_type,
            "image",
            ocr_reason,
            frame_count=len(frames),
            metadata_count=metadata_count,
            ocr_frame_count=ocr_count,
        )
    entries: list[CorpusEntry] = []
    for index, text in enumerate(metadata_texts):
        entries.append(CorpusEntry(f"media-metadata-{index:04d}.txt", text.encode("utf-8"), "text"))
    for index, text in enumerate(ocr_texts):
        entries.append(CorpusEntry(f"media-ocr-{index:04d}.txt", text.encode("utf-8"), "text"))
    finding_count, reason = _scan_metadata_ocr(
        entries,
        raw_metadata=raw_metadata,
        secrets=secrets,
        scanner_runner=scanner_runner,
        scanner_timeout=scanner_timeout,
    )
    if reason is not None:
        return _failure(
            source.content,
            source.media_type,
            "image",
            reason,
            frame_count=len(frames),
            metadata_count=metadata_count,
            ocr_frame_count=ocr_count,
            finding_count=finding_count,
        )
    changed = _verify_path(source)
    if changed is not None:
        return _failure(
            source.content,
            source.media_type,
            "image",
            changed,
            frame_count=len(frames),
            metadata_count=metadata_count,
            ocr_frame_count=ocr_count,
        )
    return MediaInspection.approved_result(
        category="image",
        media_type=source.media_type,
        content=source.content,
        frame_count=len(frames),
        metadata_count=metadata_count,
        ocr_frame_count=ocr_count,
    )


def inspect_media(
    source: object,
    media_type: str | None = None,
    *,
    secrets: Sequence[str] | str | None = None,
    known_secrets: Sequence[str] | str | None = None,
    credential_sources: object = None,
    scanner_runner: Callable[..., Any] | None = None,
    scanner: Callable[..., Any] | None = None,
    scanner_timeout: float = MAX_SCANNER_TIMEOUT_SECONDS,
    ocr_runner: Callable[..., Any] | None = None,
    ocr: Callable[..., Any] | None = None,
    ocr_timeout: float = MAX_OCR_TIMEOUT_SECONDS,
) -> MediaInspection:
    """Classify and inspect one publication payload.

    The result is always typed and fail-closed.  Callers must explicitly use
    ``result.bytes`` after checking ``result.approved``.
    """

    # Accept the natural ``(media_type, content)`` spelling as well as the
    # primary ``(content, media_type)`` boundary used by publication models.
    if isinstance(source, str) and isinstance(media_type, bytes):
        source, media_type = media_type, source
    if secrets is None:
        secrets = known_secrets
    if scanner_runner is None:
        scanner_runner = scanner
    if ocr_runner is None:
        ocr_runner = ocr
    safe_type = _safe_media_type(media_type)
    source_value, source_error = _coerce_source(source, media_type)
    if source_value is None:
        raw = source.content if isinstance(source, (PublicBundleComponent, SourceDocument, StableRead)) else source if isinstance(source, bytes) else b""
        return _failure(raw, safe_type, classify_media(safe_type), source_error or ReasonCode.invalid_metadata)
    source = source_value
    category = classify_media(source.media_type)
    try:
        normalized_secrets = _normalise_secrets(secrets, credential_sources)
    except PublicationError as exc:
        return _failure(source.content, source.media_type, category, exc.code)
    if category == "text":
        try:
            source.content.decode("utf-8")
        except UnicodeDecodeError:
            return _failure(source.content, source.media_type, "text", ReasonCode.invalid_utf8)
        changed = _verify_path(source)
        if changed is not None:
            return _failure(source.content, source.media_type, "text", changed)
        return MediaInspection.approved_result(category="text", media_type=source.media_type, content=source.content)
    if category == "image":
        return _inspect_image(
            source,
            secrets=normalized_secrets,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
            ocr_runner=ocr_runner,
            ocr_timeout=ocr_timeout,
        )
    handler = _HANDLERS.get(source.media_type)
    if handler is None:
        return _failure(source.content, source.media_type, "binary", ReasonCode.uninspectable_binary)
    try:
        result = handler(source.content, source.media_type)
    except (PublicationError, TypeError, ValueError, OSError, MemoryError):
        return _failure(source.content, source.media_type, "handler", ReasonCode.unsafe_content)
    except Exception:
        return _failure(source.content, source.media_type, "handler", ReasonCode.unsafe_content)
    if (
        not isinstance(result, MediaInspection)
        or not result.approved
        or result.content != source.content
        or result.media_type != source.media_type
        or result.sha256 != hashlib.sha256(source.content).hexdigest()
    ):
        return _failure(source.content, source.media_type, "handler", ReasonCode.unsafe_content)
    changed = _verify_path(source)
    if changed is not None:
        return _failure(source.content, source.media_type, "handler", changed)
    return result


inspect_artifact = inspect_media
inspect_component = inspect_media
inspect_publication_artifact = inspect_media
inspect_image = inspect_media
inspect_media_artifact = inspect_media
validate_media = inspect_media
register_inspectable_handler = register_media_handler


def inspect_publication_media(
    source: AtifDocument | PublicBundle | Sequence[PublicBundleComponent] | Sequence[SourceDocument] | object,
    **kwargs: Any,
) -> MediaInspectionReport:
    """Inspect every retained artifact in a bundle and fail closed as a whole."""

    if isinstance(source, AtifDocument):
        values: Sequence[object] = source.artifacts
    elif isinstance(source, PublicBundle):
        values = source.components
    elif isinstance(source, (bytes, bytearray, str, Path, PublicBundleComponent, SourceDocument, StableRead)):
        values = (source,)
    else:
        try:
            values = tuple(source)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            values = (source,)
    results: list[MediaInspection] = []
    for value in values:
        results.append(inspect_media(value, **kwargs))
    return MediaInspectionReport(tuple(results))


inspect_publication = inspect_publication_media
inspect_media_bundle = inspect_publication_media


__all__ = [
    "MAX_IMAGE_DIMENSION",
    "MAX_IMAGE_FRAMES",
    "MAX_IMAGE_PIXELS",
    "MAX_MEDIA_BYTES",
    "MAX_METADATA_BYTES",
    "MAX_METADATA_ENTRIES",
    "MAX_OCR_OUTPUT_BYTES",
    "MAX_OCR_TIMEOUT_SECONDS",
    "SUPPORTED_IMAGE_FORMATS",
    "SUPPORTED_IMAGE_MEDIA_TYPES",
    "SUPPORTED_TEXT_MEDIA_TYPES",
    "MediaHandler",
    "MediaInspection",
    "MediaInspectionError",
    "MediaInspectionReport",
    "MediaInspectionResult",
    "MediaInspectionOutcome",
    "MediaReport",
    "MediaResult",
    "MediaSecurityReport",
    "classify_media",
    "inspect_artifact",
    "inspect_component",
    "inspect_media",
    "inspect_media_bundle",
    "inspect_publication",
    "inspect_publication_artifact",
    "inspect_publication_media",
    "inspect_image",
    "inspect_media_artifact",
    "validate_media",
    "register_media_handler",
    "register_inspectable_handler",
    "registered_media_handlers",
    "unregister_media_handler",
]

from __future__ import annotations

import hashlib
import json
import subprocess
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from coquic_steward.publication import (
    MAX_MEDIA_BYTES,
    MAX_OCR_OUTPUT_BYTES,
    MediaInspection,
    ReasonCode,
    SUPPORTED_IMAGE_MEDIA_TYPES,
    classify_media,
    inspect_media,
    inspect_publication_media,
    register_media_handler,
    unregister_media_handler,
)


def _image(media_type: str, *, frames: int = 1, metadata: str | None = None) -> bytes:
    fmt = {
        "image/jpeg": "JPEG",
        "image/png": "PNG",
        "image/gif": "GIF",
        "image/webp": "WEBP",
    }[media_type]
    values = [Image.new("RGB", (12, 8), (index * 40, 20, 80)) for index in range(frames)]
    output = BytesIO()
    kwargs: dict[str, object] = {}
    if frames > 1:
        kwargs.update(save_all=True, append_images=values[1:], duration=20, loop=0)
    if metadata is not None and fmt == "PNG":
        info = PngImagePlugin.PngInfo()
        info.add_text("comment", metadata)
        kwargs["pnginfo"] = info
    values[0].save(output, format=fmt, **kwargs)
    for value in values:
        value.close()
    return output.getvalue()


def _runner(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, 0, b"", b"")


def _scanner_finding(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
    if argv and argv[0] == "trufflehog":
        record = {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "entry-0000.txt"}}},
            "Raw": "comment",
            "DetectorName": "TestDetector",
        }
        return subprocess.CompletedProcess(argv, 0, (json.dumps(record) + "\n").encode(), b"")
    return subprocess.CompletedProcess(argv, 0, b"", b"")


def _inspect(payload: bytes, media_type: str, **kwargs: object):
    return inspect_media(payload, media_type, ocr_runner=_runner, scanner_runner=_runner, **kwargs)


@pytest.mark.parametrize("media_type", sorted(SUPPORTED_IMAGE_MEDIA_TYPES))
def test_format_clean_images_are_byte_identical(media_type: str) -> None:
    payload = _image(media_type)
    result = _inspect(payload, media_type)
    assert result.approved
    assert result.bytes == payload
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.frame_count == 1


def test_format_multiframe_images_inspect_every_frame() -> None:
    for media_type in ("image/gif", "image/webp"):
        payload = _image(media_type, frames=3)
        result = _inspect(payload, media_type)
        assert result.approved
        assert result.frame_count == 3
        assert result.ocr_frame_count == 3


@pytest.mark.parametrize(
    ("payload", "media_type", "reason"),
    [
        (b"not an image", "image/png", ReasonCode.unsafe_content),
        (_image("image/png") + b"polyglot", "image/png", ReasonCode.unsafe_content),
        (_image("image/jpeg"), "image/png", ReasonCode.invalid_media_type),
        (b"x" * (MAX_MEDIA_BYTES + 1), "image/png", ReasonCode.oversized),
    ],
)
def test_bounds_and_structure_fail_closed(payload: bytes, media_type: str, reason: ReasonCode) -> None:
    result = _inspect(payload, media_type)
    assert not result.approved
    assert result.reason == reason
    assert result.bytes is None


def test_metadata_secret_blocks_without_leaking_value() -> None:
    secret = "metadata-secret-value"
    payload = _image("image/png", metadata=secret)
    result = _inspect(payload, "image/png", secrets=(secret,))
    assert result.reason == ReasonCode.unsafe_content
    assert secret not in repr(result)
    assert secret not in json.dumps(result.as_dict())


def test_metadata_scanner_finding_is_marker_only() -> None:
    payload = _image("image/png", metadata="ordinary metadata")
    result = inspect_media(payload, "image/png", ocr_runner=_runner, scanner_runner=_scanner_finding)
    assert result.reason == ReasonCode.unsafe_content
    assert result.finding_count == 1
    assert "comment" not in repr(result)
    assert "TestDetector" not in repr(result)


def test_ocr_text_is_scanned_without_mutating_original() -> None:
    secret = "ocr-secret-value"

    def ocr(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, secret.encode(), b"")

    payload = _image("image/png")
    result = inspect_media(payload, "image/png", ocr_runner=ocr, scanner_runner=_runner, secrets=(secret,))
    assert result.reason == ReasonCode.unsafe_content
    assert payload == _image("image/png")
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "ocr",
    [
        lambda argv, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(argv, 1)),
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, b"", b"failed"),
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, b"x" * (MAX_OCR_OUTPUT_BYTES + 1), b""),
    ],
)
def test_ocr_failure_timeout_and_output_overflow_fail_closed(ocr) -> None:
    result = inspect_media(_image("image/png"), "image/png", ocr_runner=ocr, scanner_runner=_runner)
    assert result.reason == ReasonCode.ocr_failure
    assert result.bytes is None


def test_unknown_binary_requires_registered_handler() -> None:
    payload = b"opaque binary\x00payload"
    assert classify_media("application/octet-stream") == "binary"
    denied = inspect_media(payload, "application/octet-stream")
    assert denied.reason == ReasonCode.uninspectable_binary

    register_media_handler(
        "application/x-test-binary",
        lambda content, media_type: MediaInspection.approved_result(
            category="handler", media_type=media_type, content=content
        ),
    )
    try:
        approved = inspect_media(payload, "application/x-test-binary")
        assert approved.approved
        assert approved.bytes == payload
    finally:
        unregister_media_handler("application/x-test-binary")


def test_text_allowlist_requires_utf8_and_preserves_bytes() -> None:
    payload = "utf-8 text\n".encode()
    result = inspect_media(payload, "text/plain; charset=utf-8")
    assert result.approved
    assert result.bytes == payload
    assert inspect_media(b"\xff", "text/plain").reason == ReasonCode.invalid_utf8
    assert inspect_media(b"ok", "application/octet-stream").reason == ReasonCode.uninspectable_binary


def test_bundle_report_hides_failed_payloads() -> None:
    clean = _image("image/png")
    report = inspect_publication_media(
        (clean, b"unknown"),
        media_type="image/png",
        ocr_runner=_runner,
        scanner_runner=_runner,
    )
    assert not report.approved
    assert len(report.results) == 2
    assert report.results[0].bytes == clean
    assert report.results[1].bytes is None
    assert report.as_dict()["failureCount"] == 1

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import zlib
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

import coquic_steward.publication.media as media_module

from coquic_steward.publication import (
    MAX_MEDIA_BYTES,
    MAX_OCR_OUTPUT_BYTES,
    FileIdentity,
    MediaInspection,
    ReasonCode,
    StableRead,
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


def _webp_chunks(payload: bytes) -> list[tuple[bytes, bytes]]:
    chunks: list[tuple[bytes, bytes]] = []
    position = 12
    while position < len(payload):
        length = int.from_bytes(payload[position + 4 : position + 8], "little")
        end = position + 8 + length + (length & 1)
        chunks.append((payload[position : position + 4], payload[position + 8 : position + 8 + length]))
        position = end
    assert position == len(payload)
    return chunks


def _replace_webp_chunk(payload: bytes, target: bytes, replacement: bytes, occurrence: int = 0) -> bytes:
    output = bytearray(payload[:12])
    seen = 0
    position = 12
    while position < len(payload):
        chunk = payload[position : position + 4]
        length = int.from_bytes(payload[position + 4 : position + 8], "little")
        end = position + 8 + length + (length & 1)
        value = payload[position + 8 : position + 8 + length]
        if chunk == target and seen == occurrence:
            value = replacement
            seen += 1
        elif chunk == target:
            seen += 1
        output.extend(chunk)
        output.extend(len(value).to_bytes(4, "little"))
        output.extend(value)
        if len(value) & 1:
            output.append(0)
        position = end
    assert seen > occurrence
    output[4:8] = (len(output) - 8).to_bytes(4, "little")
    return bytes(output)


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


def test_webp_animation_control_payload_is_scanned() -> None:
    payload = _image("image/webp", frames=2)
    mutated = _replace_webp_chunk(payload, b"ANIM", b"ABCDEF")
    result = _inspect(mutated, "image/webp", secrets=("ABCDEF",))
    assert not result.approved
    assert result.reason == ReasonCode.unsafe_content
    assert result.bytes is None


def test_webp_animation_frame_control_payload_is_scanned() -> None:
    payload = _image("image/webp", frames=2)
    frame = next(value for chunk, value in _webp_chunks(payload) if chunk == b"ANMF")
    mutated_frame = frame[:12] + b"ABC" + frame[15:]
    mutated = _replace_webp_chunk(payload, b"ANMF", mutated_frame)
    result = _inspect(mutated, "image/webp", secrets=("ABC",))
    assert not result.approved
    assert result.reason == ReasonCode.unsafe_content
    assert result.bytes is None


def test_webp_unknown_nested_animation_channel_fails_closed() -> None:
    payload = _image("image/webp", frames=2)
    frame = next(value for chunk, value in _webp_chunks(payload) if chunk == b"ANMF")
    nested = frame + b"JUNK" + (4).to_bytes(4, "little") + b"safe"
    mutated = _replace_webp_chunk(payload, b"ANMF", nested)
    result = _inspect(mutated, "image/webp")
    assert not result.approved
    assert result.reason == ReasonCode.unsafe_content
    assert result.bytes is None


def test_progressive_jpeg_is_completely_inspected() -> None:
    output = BytesIO()
    image = Image.new("RGB", (24, 16), (30, 40, 50))
    image.save(output, format="JPEG", progressive=True)
    image.close()
    payload = output.getvalue()
    result = _inspect(payload, "image/jpeg")
    assert result.approved
    assert result.bytes == payload


def test_jpeg_app2_channel_is_scanned() -> None:
    secret = b"opaque-jpeg-secret"
    output = BytesIO()
    image = Image.new("RGB", (8, 8), (1, 2, 3))
    image.save(output, format="JPEG")
    image.close()
    payload = output.getvalue()
    segment = b"\xff\xe2" + struct.pack(">H", len(secret) + 2) + secret
    result = _inspect(payload[:2] + segment + payload[2:], "image/jpeg", secrets=(secret.decode(),))
    assert not result.approved
    assert result.reason == ReasonCode.unsafe_content
    assert result.bytes is None


def test_png_ancillary_channel_is_scanned() -> None:
    secret = b"opaque-png-secret"
    payload = _image("image/png")
    end = payload.rfind(b"IEND") - 4
    chunk_type = b"abCd"
    chunk_data = secret
    chunk = (
        struct.pack(">I", len(chunk_data))
        + chunk_type
        + chunk_data
        + struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
    )
    result = _inspect(payload[:end] + chunk + payload[end:], "image/png", secrets=(secret.decode(),))
    assert not result.approved
    assert result.reason == ReasonCode.unsafe_content
    assert result.bytes is None


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
    assert classify_media("text/x-unregistered") == "binary"
    assert inspect_media(b"ok", "text/x-unregistered").reason == ReasonCode.uninspectable_binary


def test_path_identity_change_blocks_even_when_bytes_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"stable bytes"
    path = tmp_path / "artifact.txt"
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    initial = StableRead(payload, FileIdentity(1, 2, len(payload), 3), len(payload), digest)
    final = StableRead(payload, FileIdentity(1, 2, len(payload), 4), len(payload), digest)
    reads = iter((initial, final))
    monkeypatch.setattr(media_module, "read_stable_file", lambda *_args, **_kwargs: next(reads))
    result = inspect_media(path, "text/plain")
    assert not result.approved
    assert result.reason == ReasonCode.changing


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

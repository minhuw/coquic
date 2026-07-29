"""Fail-closed, local-only TruffleHog integration for publication text.

The scanner boundary deliberately exposes only bounded categories and logical
corpus identities.  Raw detector records are consumed in memory and are never
returned, logged, or included in an exception message.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - fixed local scanner argv below
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, Final

from .models import (
    MAX_FINDINGS,
    MAX_LOGICAL_PATH_LENGTH,
    MAX_RUN_BYTES,
    PublicationError,
    ReasonCode,
    private_staging,
)


REDACTION_MARKER: Final[str] = "[REDACTED_SECRET]"
MAX_SCANNER_OUTPUT_BYTES: Final[int] = 8 * 1024 * 1024
MAX_SCANNER_RAW_BYTES: Final[int] = 256 * 1024
MAX_SCANNER_TIMEOUT_SECONDS: Final[float] = 120.0
MAX_CORPUS_ENTRIES: Final[int] = 4_096
_REAL_SUBPROCESS_RUN = subprocess.run


class ScannerProtocolError(PublicationError):
    """A scanner output or execution failure without private details."""


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """One text value copied into the private scanner corpus."""

    logical_path: str
    content: bytes = field(repr=False)
    category: str = "text"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.logical_path, str)
            or not self.logical_path
            or len(self.logical_path) > MAX_LOGICAL_PATH_LENGTH
            or "\x00" in self.logical_path
            or "\\" in self.logical_path
            or self.logical_path.startswith("/")
            or ".." in PurePosixPath(self.logical_path).parts
        ):
            raise ScannerProtocolError(ReasonCode.invalid_path)
        if not isinstance(self.content, bytes) or len(self.content) > MAX_RUN_BYTES:
            raise ScannerProtocolError(ReasonCode.oversized)
        if self.category not in {"text", "source", "patch"}:
            raise ScannerProtocolError(ReasonCode.invalid_metadata)


@dataclass(frozen=True, slots=True)
class ScannerFinding:
    """A mapped finding; the matched bytes are intentionally non-repr data."""

    corpus_path: str
    raw: bytes = field(repr=False)
    category: str = "text"
    detector: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.corpus_path, str) or not self.corpus_path:
            raise ScannerProtocolError(ReasonCode.invalid_path)
        if not isinstance(self.raw, bytes) or not self.raw or len(self.raw) > MAX_SCANNER_RAW_BYTES:
            raise ScannerProtocolError(ReasonCode.scanner_failure)
        try:
            self.raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ScannerProtocolError(ReasonCode.scanner_failure) from None
        if self.category not in {"text", "source", "patch"}:
            raise ScannerProtocolError(ReasonCode.scanner_failure)
        if self.detector is not None and (
            not isinstance(self.detector, str) or len(self.detector) > 128 or any(ord(c) < 0x20 for c in self.detector)
        ):
            raise ScannerProtocolError(ReasonCode.scanner_failure)


@dataclass(frozen=True, slots=True)
class ScannerReport:
    """Bounded outcome of one scanner process invocation."""

    findings: tuple[ScannerFinding, ...] = ()
    returncode: int = 0
    failure: ReasonCode | None = None

    def __post_init__(self) -> None:
        findings = tuple(self.findings)
        if len(findings) > MAX_FINDINGS or any(not isinstance(item, ScannerFinding) for item in findings):
            raise ScannerProtocolError(ReasonCode.scanner_failure)
        if isinstance(self.returncode, bool) or not isinstance(self.returncode, int):
            raise ScannerProtocolError(ReasonCode.scanner_failure)
        if self.failure is not None and self.failure is not ReasonCode.scanner_failure:
            raise ScannerProtocolError(ReasonCode.scanner_failure)
        object.__setattr__(self, "findings", findings)

    @property
    def clean(self) -> bool:
        return self.failure is None and not self.findings and self.returncode == 0


def _protocol_fail() -> None:
    raise ScannerProtocolError(ReasonCode.scanner_failure) from None


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _protocol_fail()
        result[key] = value
    return result


def _json_constant(_value: str) -> None:
    _protocol_fail()


def _as_text(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def _finding_path(record: Mapping[str, Any]) -> str | None:
    metadata = record.get("SourceMetadata")
    if isinstance(metadata, Mapping):
        data = metadata.get("Data")
        if isinstance(data, Mapping):
            filesystem = data.get("Filesystem")
            if isinstance(filesystem, Mapping):
                path = filesystem.get("file")
                if isinstance(path, str):
                    return path
    # A small compatibility allowance for mocked local scanner records.  It is
    # still required to be a string and is mapped against the private corpus.
    for key in ("path", "file", "File"):
        path = record.get(key)
        if isinstance(path, str):
            return path
    return None


def _finding_raw(record: Mapping[str, Any]) -> tuple[bytes | None, bool]:
    for key in ("Raw", "raw"):
        value = _as_text(record.get(key))
        if value is None:
            continue
        if value == REDACTION_MARKER:
            return b"", True
        if not value:
            return None, False
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return None, False
        if len(encoded) > MAX_SCANNER_RAW_BYTES:
            return None, False
        return encoded, False
    return None, False


def parse_trufflehog_json(output: bytes | str) -> tuple[ScannerFinding, ...]:
    """Parse every JSONL scanner record, rejecting malformed or partial data."""

    if isinstance(output, bytes):
        if len(output) > MAX_SCANNER_OUTPUT_BYTES:
            _protocol_fail()
        try:
            text = output.decode("utf-8")
        except UnicodeDecodeError:
            _protocol_fail()
    elif isinstance(output, str):
        if len(output.encode("utf-8")) > MAX_SCANNER_OUTPUT_BYTES:
            _protocol_fail()
        text = output
    else:
        _protocol_fail()
    if not text:
        return ()
    findings: list[ScannerFinding] = []
    for line in text.splitlines(keepends=True):
        if not line.endswith(("\n", "\r")):
            _protocol_fail()
        encoded = line.rstrip("\r\n")
        if not encoded.strip():
            _protocol_fail()
        try:
            record = json.loads(
                encoded,
                object_pairs_hook=_json_object,
                parse_constant=_json_constant,
            )
        except ScannerProtocolError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError, UnicodeError, MemoryError):
            _protocol_fail()
        if not isinstance(record, Mapping):
            _protocol_fail()
        path = _finding_path(record)
        raw, marker_only = _finding_raw(record)
        if marker_only:
            continue
        if path is None or raw is None or len(path) > MAX_LOGICAL_PATH_LENGTH or "\x00" in path or "\\" in path:
            _protocol_fail()
        detector = record.get("DetectorName")
        if detector is not None and not isinstance(detector, str):
            _protocol_fail()
        findings.append(ScannerFinding(_basename(path), raw, detector=detector))
        if len(findings) > MAX_FINDINGS:
            _protocol_fail()
    return tuple(findings)


def _basename(path: str) -> str:
    # TruffleHog emits an absolute path for filesystem scans.  Only the final
    # generated entry name is used for identity mapping; directory components
    # are never returned to a caller.
    if not isinstance(path, str) or not path:
        _protocol_fail()
    normalized = path.replace("\\", "/")
    name = PurePosixPath(normalized).name
    if not name or name in {".", ".."} or "\x00" in name:
        _protocol_fail()
    return name


def _map_findings(findings: Sequence[ScannerFinding], entries: Mapping[str, CorpusEntry]) -> tuple[ScannerFinding, ...]:
    mapped: list[ScannerFinding] = []
    for finding in findings:
        key = _basename(finding.corpus_path)
        entry = entries.get(key)
        if entry is None:
            _protocol_fail()
        if finding.raw not in entry.content:
            _protocol_fail()
        mapped.append(
            ScannerFinding(
                entry.logical_path,
                finding.raw,
                category=entry.category,
                detector=finding.detector,
            )
        )
    return tuple(mapped)


def _process_result(result: Any) -> tuple[int, bytes | str]:
    try:
        returncode = result.returncode
        stdout = result.stdout
    except AttributeError:
        _protocol_fail()
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        _protocol_fail()
    if not isinstance(stdout, (bytes, str)):
        _protocol_fail()
    return returncode, stdout


def _invoke(
    argv: list[str],
    *,
    timeout: float,
    runner: Callable[..., Any] | None,
    pass_fds: tuple[int, ...],
) -> Any:
    selected = runner or subprocess.run
    env = os.environ.copy()
    # TruffleHog's filesystem mode is local-only.  Keep the policy in the
    # explicit argv flags below; environment aliases are deliberately omitted
    # because recent releases reject a flag supplied by both sources.
    try:
        return selected(
            argv,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
            pass_fds=pass_fds,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise ScannerProtocolError(ReasonCode.scanner_failure) from None
    except FileNotFoundError:
        raise ScannerProtocolError(ReasonCode.scanner_failure) from None
    except (subprocess.SubprocessError, OSError, TypeError, ValueError):
        raise ScannerProtocolError(ReasonCode.scanner_failure) from None
    except Exception:
        raise ScannerProtocolError(ReasonCode.scanner_failure) from None


def _scanner_executable(*, injected_runner: bool) -> str:
    """Use the wrapped binary directly when Nix already adds ``--no-update``."""

    if injected_runner:
        return "trufflehog"
    selected = shutil.which("trufflehog")
    if selected is None:
        return "trufflehog"
    wrapper = Path(selected)
    try:
        text = wrapper.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return selected
    direct = wrapper.with_name(".trufflehog-wrapped")
    if "--no-update" in text and direct.is_file() and os.access(direct, os.X_OK):
        return str(direct)
    return selected


def run_trufflehog(
    entries: Sequence[CorpusEntry],
    *,
    staging_root: Path | None = None,
    timeout: float = MAX_SCANNER_TIMEOUT_SECONDS,
    runner: Callable[..., Any] | None = None,
) -> ScannerReport:
    """Scan entries from a descriptor-anchored private staging directory."""

    values = tuple(entries)
    if len(values) > MAX_CORPUS_ENTRIES or any(not isinstance(item, CorpusEntry) for item in values):
        _protocol_fail()
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > MAX_SCANNER_TIMEOUT_SECONDS:
        _protocol_fail()
    names: dict[str, CorpusEntry] = {}
    for index, entry in enumerate(values):
        name = f"entry-{index:04d}.txt"
        names[name] = entry

    def scan(root: Path) -> ScannerReport:
        try:
            with private_staging(root) as staging:
                for name, entry in names.items():
                    staging.write_bytes(name, entry.content)
                descriptor = getattr(staging, "_fd", None)
                if not isinstance(descriptor, int):
                    _protocol_fail()
                corpus = f"/proc/self/fd/{descriptor}"
                argv = [
                    _scanner_executable(injected_runner=runner is not None or subprocess.run is not _REAL_SUBPROCESS_RUN),
                    "filesystem",
                    "--json",
                    "--no-update",
                    "--no-verification",
                    "--directory",
                    corpus,
                ]
                result = _invoke(argv, timeout=float(timeout), runner=runner, pass_fds=(descriptor,))
                returncode, stdout = _process_result(result)
                if returncode != 0:
                    return ScannerReport(returncode=returncode, failure=ReasonCode.scanner_failure)
                findings = parse_trufflehog_json(stdout)
                return ScannerReport(findings=_map_findings(findings, names), returncode=returncode)
        except ScannerProtocolError:
            return ScannerReport(failure=ReasonCode.scanner_failure)
        except PublicationError:
            return ScannerReport(failure=ReasonCode.scanner_failure)

    if staging_root is not None:
        return scan(Path(staging_root))
    try:
        with TemporaryDirectory(prefix="coquic-publication-") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            return scan(root)
    except OSError:
        return ScannerReport(failure=ReasonCode.scanner_failure)


# Compatibility spellings used by transport stages and focused tests.
scan_trufflehog = run_trufflehog
scan_corpus = run_trufflehog
scan_publication_corpus = run_trufflehog
run_secret_scanner = run_trufflehog
ScannerResult = ScannerReport
SecretFinding = ScannerFinding
parse_scanner_output = parse_trufflehog_json
parse_trufflehog_output = parse_trufflehog_json


__all__ = [
    "CorpusEntry",
    "MAX_SCANNER_OUTPUT_BYTES",
    "MAX_SCANNER_RAW_BYTES",
    "MAX_SCANNER_TIMEOUT_SECONDS",
    "MAX_CORPUS_ENTRIES",
    "REDACTION_MARKER",
    "ScannerFinding",
    "SecretFinding",
    "ScannerProtocolError",
    "ScannerReport",
    "ScannerResult",
    "parse_scanner_output",
    "parse_trufflehog_json",
    "parse_trufflehog_output",
    "run_trufflehog",
    "scan_corpus",
    "scan_publication_corpus",
    "scan_trufflehog",
    "run_secret_scanner",
]

"""Deterministic public-text redaction and local scanner repair."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from .atif import canonical_atif_bytes, validate_atif_document
from .models import (
    AtifDocument,
    MAX_COUNTER,
    LogicalArtifact,
    PublicationError,
    PublicBundleComponent,
    ReasonCode,
    SanitizationResult,
    read_stable_file,
)
from .scanner import (
    MAX_SCANNER_TIMEOUT_SECONDS,
    REDACTION_MARKER,
    CorpusEntry,
    ScannerFinding,
    ScannerReport,
    run_trufflehog,
)


MAX_CREDENTIAL_SOURCE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_SECRET_BYTES: Final[int] = 256 * 1024
MIN_SECRET_BYTES: Final[int] = 8
MAX_REPAIR_PASSES: Final[int] = 3

_KEY_RE = re.compile(r"[^a-z0-9]+")
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "apikey",
        "accesstoken",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "password",
        "privatekey",
        "secret",
        "token",
    }
)
_PLACEHOLDERS = frozenset(
    {
        "none",
        "null",
        "false",
        "true",
        "changeme",
        "example",
        "redacted",
        "placeholder",
        REDACTION_MARKER.lower(),
    }
)
_PROTECTED_KEYS = frozenset(
    {
        "artifactid",
        "bytesize",
        "completedat",
        "durationms",
        "logicalpath",
        "mediatype",
        "ownerstepid",
        "path",
        "pipelineid",
        "runid",
        "schema",
        "schemaversion",
        "sequence",
        "sha256",
        "startedat",
        "stepid",
        "taskid",
        "toolcallid",
    }
)
_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".mjs",
        ".py",
        ".rs",
        ".sh",
        ".sql",
        ".swift",
        ".ts",
        ".tsx",
        ".zig",
    }
)
_PATCH_SUFFIXES = frozenset({".diff", ".patch", ".rej"})
_SOURCE_MEDIA_TYPES = frozenset(
    {
        "application/javascript",
        "application/typescript",
        "application/x-c",
        "application/x-c++",
        "application/x-go",
        "application/x-java",
        "application/x-python",
        "application/x-rust",
        "application/x-sh",
        "application/x-zig",
        "text/javascript",
        "text/typescript",
    }
)


class RedactionError(PublicationError):
    """Bounded local redaction failure without source details."""


def _fail(code: ReasonCode) -> None:
    raise RedactionError(code) from None


def _key_name(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return _KEY_RE.sub("", value.casefold())


def _is_sensitive_key(value: object) -> bool:
    normalized = _key_name(value)
    if not normalized:
        return False
    return normalized in _SENSITIVE_KEY_PARTS or any(
        normalized.endswith(part) for part in _SENSITIVE_KEY_PARTS if len(part) >= 6
    )


def _is_protected_key(value: object) -> bool:
    normalized = _key_name(value)
    return normalized in _PROTECTED_KEYS or normalized.endswith("id")


def _valid_secret(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if value == REDACTION_MARKER:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded) < MIN_SECRET_BYTES or len(encoded) > MAX_SECRET_BYTES:
        return False
    stripped = value.strip()
    if not stripped or stripped.casefold() in _PLACEHOLDERS:
        return False
    if all(char.isspace() for char in value):
        return False
    if any(ord(char) < 0x20 and char not in "\t\r\n" for char in value):
        return False
    return True


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(ReasonCode.invalid_metadata)
        result[key] = value
    return result


def _json_constant(_value: str) -> None:
    _fail(ReasonCode.invalid_metadata)


def _parse_structured(content: bytes, suffix: str) -> Any:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        _fail(ReasonCode.unsafe_content)
    if suffix in {".json", ".jsonl"}:
        try:
            if suffix == ".jsonl":
                records: list[Any] = []
                for line in text.splitlines():
                    if not line.strip():
                        _fail(ReasonCode.invalid_metadata)
                    records.append(json.loads(line, object_pairs_hook=_json_pairs, parse_constant=_json_constant))
                if not records:
                    _fail(ReasonCode.partial)
                return records
            return json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_json_constant)
        except RedactionError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError, UnicodeError):
            _fail(ReasonCode.invalid_metadata)
    if suffix == ".toml":
        try:
            return tomllib.loads(text)
        except (tomllib.TOMLDecodeError, TypeError, ValueError, RecursionError, UnicodeError):
            _fail(ReasonCode.invalid_metadata)
    return None


def _walk_sensitive(value: Any, *, sensitive: bool = False) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk_sensitive(child, sensitive=sensitive or _is_sensitive_key(key))
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_sensitive(child, sensitive=sensitive)
    elif sensitive and isinstance(value, str) and _valid_secret(value):
        yield value


def _plain_single_value(content: bytes) -> str | None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        _fail(ReasonCode.unsafe_content)
    stripped = text.strip("\r\n")
    if "\n" in stripped or "\r" in stripped or "\x00" in stripped:
        return None
    return stripped if _valid_secret(stripped) else None


def _source_paths(sources: object) -> tuple[Path, ...]:
    if sources is None:
        return ()
    values: list[object]
    if isinstance(sources, Mapping):
        values = list(sources.values())
    elif isinstance(sources, (str, bytes, Path)):
        values = [sources]
    else:
        try:
            values = list(sources)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            _fail(ReasonCode.invalid_path)
    paths: list[Path] = []
    for value in values:
        if isinstance(value, bytes):
            _fail(ReasonCode.unsafe_content)
        try:
            path = value if isinstance(value, Path) else Path(value)  # type: ignore[arg-type]
        except (OSError, TypeError, ValueError):
            _fail(ReasonCode.invalid_path)
        paths.append(path)
    return tuple(paths)


def discover_secrets(sources: object) -> tuple[str, ...]:
    """Read only explicitly declared private files and return stable values."""

    values: set[str] = set()
    for path in _source_paths(sources):
        try:
            stable = read_stable_file(path, max_bytes=MAX_CREDENTIAL_SOURCE_BYTES, require_private=True)
        except PublicationError:
            _fail(ReasonCode.unsafe_content)
        content = stable.content
        suffix = path.suffix.casefold()
        structured = _parse_structured(content, suffix) if suffix in {".json", ".jsonl", ".toml"} else None
        if structured is not None:
            values.update(_walk_sensitive(structured))
            # A JSON/TOML scalar is an explicitly declared single-value
            # credential and is safe to retain as a candidate.
            if isinstance(structured, str) and _valid_secret(structured):
                values.add(structured)
        elif suffix in {".json", ".jsonl", ".toml"}:
            _fail(ReasonCode.invalid_metadata)
        else:
            single = _plain_single_value(content)
            if single is not None:
                values.add(single)
    return tuple(sorted(values, key=lambda item: (-len(item.encode("utf-8")), item)))


collect_known_secrets = discover_secrets
load_credential_values = discover_secrets


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    if isinstance(value, list):
        return [_thaw(child) for child in value]
    return value


def _replace_string(value: str, secrets: Sequence[str]) -> tuple[str, int]:
    count = 0
    result = value
    for secret in secrets:
        if not secret or secret == REDACTION_MARKER:
            continue
        # Preserve existing markers while replacing secrets that happen to be
        # substrings of the marker itself.
        segments = result.split(REDACTION_MARKER)
        for index, segment in enumerate(segments):
            occurrences = segment.count(secret)
            if occurrences:
                segments[index] = segment.replace(secret, REDACTION_MARKER)
                count += occurrences
        result = REDACTION_MARKER.join(segments)
    return result, count


def _replace_value(value: Any, secrets: Sequence[str], *, protected: bool = False) -> tuple[Any, int, bool]:
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        count = 0
        protected_hit = False
        for key, child in value.items():
            if isinstance(key, str) and any(secret in key for secret in secrets if secret != REDACTION_MARKER):
                protected_hit = True
            child_protected = protected or _is_protected_key(key)
            replaced, changed, hit = _replace_value(child, secrets, protected=child_protected)
            result[key] = replaced
            count += changed
            protected_hit = protected_hit or hit
        return result, count, protected_hit
    if isinstance(value, list):
        result_list: list[Any] = []
        count = 0
        protected_hit = False
        for child in value:
            replaced, changed, hit = _replace_value(child, secrets, protected=protected)
            result_list.append(replaced)
            count += changed
            protected_hit = protected_hit or hit
        return result_list, count, protected_hit
    if isinstance(value, str):
        if protected:
            return value, 0, any(secret in value for secret in secrets if secret != REDACTION_MARKER)
        replaced, count = _replace_string(value, secrets)
        return replaced, count, False
    return value, 0, False


def _base_media_type(media_type: str) -> str:
    """Return the case-folded MIME type without optional parameters."""

    return media_type.partition(";")[0].strip().casefold()


def _text_media(media_type: str) -> bool:
    lowered = _base_media_type(media_type)
    return lowered.startswith("text/") or lowered in {
        "application/json",
        "application/jsonl",
        "application/ld+json",
        "application/xml",
        "application/x-diff",
        "application/x-patch",
    } or lowered in _SOURCE_MEDIA_TYPES or lowered.endswith("+json")


def _replace_artifact(content: bytes, media_type: str, secrets: Sequence[str]) -> tuple[bytes, int, bool]:
    if not _text_media(media_type):
        return content, 0, False
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content, 0, True
    lowered = _base_media_type(media_type)
    structured_media = lowered in {"application/json", "application/ld+json", "application/jsonl", "application/xml"} or lowered.endswith("+json")
    if structured_media:
        try:
            if lowered == "application/jsonl":
                parsed_records = [
                    json.loads(line, object_pairs_hook=_json_pairs, parse_constant=_json_constant)
                    for line in text.splitlines()
                ]
                if not parsed_records:
                    return content, 0, True
                replaced_records: list[Any] = []
                count = 0
                protected_hit = False
                for record in parsed_records:
                    replaced_record, changed, record_protected = _replace_value(record, secrets)
                    replaced_records.append(replaced_record)
                    count += changed
                    protected_hit = protected_hit or record_protected
                if protected_hit:
                    return content, count, True
                if count:
                    encoded_records = [
                        json.dumps(
                            record,
                            ensure_ascii=False,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        for record in replaced_records
                    ]
                    encoded = "\n".join(encoded_records)
                    if text.endswith(("\n", "\r")):
                        encoded += "\n"
                    return encoded.encode("utf-8"), count, False
                return content, 0, False
            else:
                parsed = json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_json_constant)
        except RedactionError:
            return content, 0, True
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError, UnicodeError):
            return content, 0, True
        replaced_value, count, protected_hit = _replace_value(parsed, secrets)
        if protected_hit:
            return content, count, True
        if count:
            encoded = json.dumps(
                replaced_value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if text.endswith(("\n", "\r")):
                encoded += "\n"
            return encoded.encode("utf-8"), count, False
        return content, 0, False
    replaced, count = _replace_string(text, secrets)
    return replaced.encode("utf-8"), count, False


def _update_artifact_descriptors(value: Any, updates: Mapping[str, LogicalArtifact]) -> Any:
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        artifact_id = value.get("artifactId")
        for key, child in value.items():
            result[key] = _update_artifact_descriptors(child, updates)
        if isinstance(artifact_id, str) and artifact_id in updates:
            descriptor = updates[artifact_id]
            if "sha256" in result:
                result["sha256"] = descriptor.sha256
            if "byteSize" in result:
                result["byteSize"] = descriptor.byte_size
        return result
    if isinstance(value, list):
        return [_update_artifact_descriptors(child, updates) for child in value]
    return value


def _mark_disclosure(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Record the allowed public disclosure bit after a replacement."""

    result = dict(value)
    extra = result.get("extra")
    if not isinstance(extra, Mapping):
        return result
    coqui = extra.get("coquic")
    if not isinstance(coqui, Mapping):
        return result
    disclosure = coqui.get("disclosure")
    if not isinstance(disclosure, Mapping):
        return result
    updated_disclosure = dict(disclosure)
    if "redactionApplied" in updated_disclosure:
        updated_disclosure["redactionApplied"] = True
    updated_coqui = dict(coqui)
    updated_coqui["disclosure"] = updated_disclosure
    updated_extra = dict(extra)
    updated_extra["coquic"] = updated_coqui
    result["extra"] = updated_extra
    return result


def _rebuild(
    document: AtifDocument,
    mapping: Mapping[str, Any],
    components: Sequence[PublicBundleComponent],
) -> AtifDocument:
    candidate = dict(mapping)
    content = canonical_atif_bytes(candidate)
    rebuilt = AtifDocument(candidate, content, artifacts=tuple(components))
    try:
        # Validate the thawed JSON mapping.  ``AtifDocument`` freezes lists to
        # tuples for immutability, while the schema contract intentionally
        # validates the wire-shaped list representation.
        validate_atif_document(candidate)
    except PublicationError as exc:
        raise RedactionError(exc.code) from None
    return rebuilt


def _literal_rebuild(document: AtifDocument, secrets: Sequence[str]) -> tuple[AtifDocument, int]:
    if not isinstance(document, AtifDocument):
        _fail(ReasonCode.invalid_metadata)
    ordered = tuple(sorted({secret for secret in secrets if _valid_secret(secret)}, key=lambda item: (-len(item.encode("utf-8")), item)))
    if not ordered:
        # Even without declared values, declared structured/text media must be
        # decodable and parseable before it can be considered public.
        for component in document.artifacts:
            _, _, unsafe = _replace_artifact(component.content, component.artifact.media_type, ())
            if unsafe:
                _fail(ReasonCode.unsafe_content)
        return document, 0
    mapping = _thaw(document.document)
    replaced_mapping, count, protected_hit = _replace_value(mapping, ordered)
    components: list[PublicBundleComponent] = []
    updates: dict[str, LogicalArtifact] = {}
    for component in document.artifacts:
        content, changed, artifact_protected = _replace_artifact(component.content, component.artifact.media_type, ordered)
        count += changed
        protected_hit = protected_hit or artifact_protected
        if content == component.content:
            components.append(component)
            continue
        descriptor = LogicalArtifact(
            component.artifact.artifact_id,
            component.artifact.logical_path,
            component.artifact.media_type,
            len(content),
            hashlib.sha256(content).hexdigest(),
            component.artifact.owner_step_id,
        )
        updates[descriptor.artifact_id] = descriptor
        components.append(PublicBundleComponent(descriptor, content))
    if protected_hit:
        _fail(ReasonCode.unsafe_content)
    if not count:
        return document, 0
    updated_mapping = _update_artifact_descriptors(replaced_mapping, updates)
    if not isinstance(updated_mapping, Mapping):
        _fail(ReasonCode.invalid_metadata)
    updated_mapping = _mark_disclosure(updated_mapping)
    return _rebuild(document, updated_mapping, components), count


def redact_atif_document(
    document: AtifDocument,
    credential_sources: object = None,
    *,
    secrets: Sequence[str] | None = None,
    credential_files: object = None,
    credential_paths: object = None,
    known_secrets: Sequence[str] | None = None,
) -> SanitizationResult:
    """Apply deterministic literal replacement without invoking a scanner."""

    try:
        selected_sources = credential_sources
        if selected_sources is None:
            selected_sources = credential_files if credential_files is not None else credential_paths
        selected_secrets = secrets if secrets is not None else known_secrets
        candidates = tuple(selected_secrets) if selected_secrets is not None else discover_secrets(selected_sources)
        rebuilt, count = _literal_rebuild(document, candidates)
        return SanitizationResult.clean(rebuilt, replacement_count=count)
    except PublicationError as exc:
        code = exc.code if exc.code in {ReasonCode.invalid_metadata, ReasonCode.unsafe_content, ReasonCode.invalid_path} else ReasonCode.unsafe_content
        return SanitizationResult.failed(code)
    except (MemoryError, OSError, TypeError, ValueError, UnicodeError):
        return SanitizationResult.failed(ReasonCode.unsafe_content)


def _classify(logical_path: str, media_type: str = "") -> str:
    lowered = logical_path.casefold()
    name = lowered.rsplit("/", 1)[-1]
    suffix = Path(name).suffix
    media = _base_media_type(media_type)
    if (
        suffix in _PATCH_SUFFIXES
        or any(part in {"patch", "diff", "changes"} for part in lowered.split("/"))
        or "diff" in media
        or "patch" in media
    ):
        return "patch"
    if (
        any(part in {"source", "src"} for part in lowered.split("/"))
        or suffix in _SOURCE_SUFFIXES
        or media in _SOURCE_MEDIA_TYPES
        or media.startswith("text/x-")
    ):
        return "source"
    return "text"


def _corpus_entries(document: AtifDocument) -> tuple[CorpusEntry, ...]:
    entries = [CorpusEntry("trajectory.json", document.content, "text")]
    for component in document.artifacts:
        if _text_media(component.artifact.media_type):
            try:
                component.content.decode("utf-8")
            except UnicodeDecodeError:
                _fail(ReasonCode.unsafe_content)
            entries.append(
                CorpusEntry(
                    component.artifact.logical_path,
                    component.content,
                    _classify(component.artifact.logical_path, component.artifact.media_type),
                )
            )
    return tuple(entries)


def _reason_for_finding(finding: ScannerFinding) -> ReasonCode | None:
    if finding.category == "patch":
        return ReasonCode.patch_finding
    if finding.category == "source":
        return ReasonCode.source_finding
    return None


def _repair_atif(document: AtifDocument, findings: Sequence[ScannerFinding]) -> tuple[AtifDocument, int]:
    secrets = tuple(sorted({finding.raw.decode("utf-8") for finding in findings}, key=lambda item: (-len(item.encode("utf-8")), item)))
    if not secrets:
        _fail(ReasonCode.irreparable)
    # Scanner findings are exact bytes; using the same parsed-value replacer
    # prevents a detector from changing IDs, keys, paths, or numeric metadata.
    return _literal_rebuild(document, secrets)


def sanitize_publication(
    document: AtifDocument,
    credential_sources: object = None,
    *,
    secrets: Sequence[str] | None = None,
    credential_files: object = None,
    credential_paths: object = None,
    known_secrets: Sequence[str] | None = None,
    run_scanner: bool = True,
    scanner_runner: Any = None,
    scanner_timeout: float = MAX_SCANNER_TIMEOUT_SECONDS,
    max_repair_passes: int = MAX_REPAIR_PASSES,
) -> SanitizationResult:
    """Redact known values, then locally repair and rescan mapped findings."""

    literal = redact_atif_document(
        document,
        credential_sources,
        secrets=secrets,
        credential_files=credential_files,
        credential_paths=credential_paths,
        known_secrets=known_secrets,
    )
    if literal.status != "clean" or literal.document is None:
        return literal
    if not run_scanner:
        return literal
    if isinstance(max_repair_passes, bool) or not isinstance(max_repair_passes, int) or max_repair_passes < 1 or max_repair_passes > MAX_REPAIR_PASSES:
        return SanitizationResult.failed(ReasonCode.invalid_metadata)
    current = literal.document
    total_replacements = literal.replacement_count
    for pass_index in range(max_repair_passes):
        try:
            report: ScannerReport = run_trufflehog(
                _corpus_entries(current),
                timeout=scanner_timeout,
                runner=scanner_runner,
            )
        except PublicationError as exc:
            code = exc.code if exc.code in {ReasonCode.unsafe_content, ReasonCode.scanner_failure} else ReasonCode.scanner_failure
            return SanitizationResult.failed(code)
        if report.failure is not None or report.returncode != 0:
            return SanitizationResult.failed(ReasonCode.scanner_failure)
        findings = tuple(report.findings)
        if not findings:
            return SanitizationResult.clean(current, replacement_count=total_replacements)
        reasons = tuple(dict.fromkeys(reason for reason in (_reason_for_finding(item) for item in findings) if reason is not None))
        if reasons:
            reason = reasons[0]
            count = sum(1 for item in findings if _reason_for_finding(item) == reason)
            return SanitizationResult.repair(reason, count=count)
        if pass_index >= max_repair_passes - 1:
            return SanitizationResult.failed(ReasonCode.irreparable)
        try:
            repaired, count = _repair_atif(current, findings)
        except PublicationError:
            return SanitizationResult.failed(ReasonCode.irreparable)
        if count <= 0:
            return SanitizationResult.failed(ReasonCode.irreparable)
        current = repaired
        total_replacements += count
        if total_replacements > MAX_COUNTER:
            return SanitizationResult.failed(ReasonCode.oversized)
    return SanitizationResult.failed(ReasonCode.irreparable)


# Focused names for callers that separate literal and scanner stages.
sanitize_atif_document = sanitize_publication
sanitize_publication_text = sanitize_publication
redact_document = redact_atif_document
redact_atif = redact_atif_document


__all__ = [
    "MAX_CREDENTIAL_SOURCE_BYTES",
    "MAX_REPAIR_PASSES",
    "MAX_SECRET_BYTES",
    "MIN_SECRET_BYTES",
    "REDACTION_MARKER",
    "RedactionError",
    "discover_secrets",
    "collect_known_secrets",
    "load_credential_values",
    "redact_atif",
    "redact_atif_document",
    "redact_document",
    "sanitize_atif_document",
    "sanitize_publication",
    "sanitize_publication_text",
]

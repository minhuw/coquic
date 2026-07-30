"""Assemble one fully inspected, transport-free publication bundle.

The stages in this module intentionally stop before any archive, database, or
cloud operation.  Conversion and sanitization produce immutable public bytes;
media inspection then proves byte identity for every retained component before
the result is wrapped in the bounded publication models.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from .atif import (
    AtifSource,
    canonical_atif_bytes,
    convert_completed_run,
    validate_atif_document,
)
from .media import MAX_OCR_TIMEOUT_SECONDS, MediaInspection, inspect_media
from .models import (
    AtifDocument,
    FailClosed,
    FindingSummary,
    LogicalArtifact,
    PrivateOriginal,
    PublicationError,
    PublicationOutcome,
    PublicationSnapshot,
    PublicBundle,
    PublicBundleComponent,
    Publishable,
    ReasonCode,
    RepairRequired,
    RunMetadata,
    RunIdentity,
    RunLineage,
    SanitizationResult,
    SourceDocument,
    StableRead,
    UsageSummary,
)
from .redaction import MAX_REPAIR_PASSES, sanitize_publication
from .scanner import MAX_SCANNER_TIMEOUT_SECONDS


_MISSING: Final = object()
_TRAJECTORY_ARTIFACT_ID: Final[str] = "artifact-atif"


def _failure(code: ReasonCode) -> FailClosed:
    """Reduce all stage failures to the public bounded failure vocabulary."""

    try:
        reason = ReasonCode(code)
    except (TypeError, ValueError):
        reason = ReasonCode.invalid_metadata
    return FailClosed((reason,))


def _content(value: object) -> bytes:
    """Coerce one already-bounded document value without retaining its source."""

    if isinstance(value, StableRead):
        return value.content
    if isinstance(value, SourceDocument):
        return value.content
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        if "content" in value:
            return _content(value["content"])
        try:
            encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            raise PublicationError(ReasonCode.invalid_metadata) from None
        return encoded.encode("utf-8")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        records: list[bytes] = []
        for item in value:
            if not isinstance(item, Mapping):
                raise PublicationError(ReasonCode.invalid_jsonl) from None
            try:
                records.append(
                    json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    + b"\n"
                )
            except (TypeError, ValueError, RecursionError):
                raise PublicationError(ReasonCode.invalid_jsonl) from None
        return b"".join(records)
    raise PublicationError(ReasonCode.invalid_metadata) from None


def _documents_from(value: object) -> Mapping[str, object]:
    if value is None:
        return {}
    if isinstance(value, PublicationSnapshot):
        return {item.logical_path: item for item in value.documents}
    if isinstance(value, AtifSource):
        return _documents_from(value.documents)
    if isinstance(value, Mapping):
        return {str(name): item for name, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        result: dict[str, object] = {}
        for item in value:
            if not isinstance(item, SourceDocument):
                raise PublicationError(ReasonCode.invalid_metadata) from None
            result[item.logical_path] = item
        return result
    raise PublicationError(ReasonCode.invalid_metadata) from None


def _source_documents(
    source: object,
    *,
    snapshot: object,
    documents: object,
    codex: object,
) -> Mapping[str, object]:
    selected: object = snapshot if snapshot is not None else source
    values: Mapping[str, object] = {}
    if documents is not None:
        values = {}
    elif isinstance(selected, Mapping):
        nested = selected.get("documents")
        if nested is not None:
            values = _documents_from(nested)
        else:
            values = {}
        for name, item in (
            ("codex.jsonl", selected.get("codex", _MISSING)),
            ("activities.jsonl", selected.get("activities", _MISSING)),
            ("telemetry.json", selected.get("telemetry", _MISSING)),
            ("run.json", selected.get("run_document", selected.get("runDocument", _MISSING))),
        ):
            if item is not _MISSING and item is not None:
                values = {**values, name: item}
    elif isinstance(selected, (PublicationSnapshot, AtifSource, Sequence)) and not isinstance(selected, (str, bytes, bytearray)):
        values = _documents_from(selected)
    if documents is not None:
        values = _documents_from(documents)
    if codex is not _MISSING and codex is not None:
        values = {**values, "codex.jsonl": codex}
    return values


def _find_document(documents: Mapping[str, object], basename: str) -> object:
    matches = [value for name, value in documents.items() if str(name).rsplit("/", 1)[-1] == basename]
    if len(matches) > 1:
        raise PublicationError(ReasonCode.invalid_metadata) from None
    return matches[0] if matches else _MISSING


def _validate_staging_root(value: object) -> Path | None:
    if value is None:
        return None
    try:
        root = Path(value)
        metadata = root.lstat()
    except (OSError, TypeError, ValueError):
        raise PublicationError(ReasonCode.staging_unsafe) from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PublicationError(ReasonCode.staging_unsafe) from None
    return root


def _disclosure_document(document: AtifDocument, *, atif_changed: bool) -> AtifDocument:
    """Set disclosure bits from canonical ATIF byte comparison only."""

    mapping = document.as_dict()
    try:
        extra = mapping["extra"]
        coqui = extra["coquic"]
        coqui["disclosure"] = {
            "redactionApplied": bool(atif_changed),
            "originalRetained": bool(atif_changed),
        }
    except (KeyError, TypeError):
        raise PublicationError(ReasonCode.invalid_metadata) from None
    validate_atif_document(mapping)
    content = canonical_atif_bytes(mapping)
    return AtifDocument(mapping, content, artifacts=document.artifacts)


def _normalized_transcript(document: AtifDocument) -> bytes:
    """Ignore descriptor bookkeeping when deciding whether the transcript changed."""

    mapping = document.as_dict()
    try:
        coqui = mapping["extra"]["coquic"]
        coqui["disclosure"] = {"redactionApplied": False, "originalRetained": False}
        descriptors = coqui.get("artifacts")
        if isinstance(descriptors, list):
            for descriptor in descriptors:
                if isinstance(descriptor, Mapping):
                    descriptor.pop("sha256", None)
                    descriptor.pop("byteSize", None)
    except (KeyError, TypeError):
        raise PublicationError(ReasonCode.invalid_metadata) from None
    return canonical_atif_bytes(mapping)


def _changed_artifact_ids(before: AtifDocument, after: AtifDocument) -> frozenset[str]:
    before_components = {item.artifact.artifact_id: item.content for item in before.artifacts}
    return frozenset(
        item.artifact.artifact_id
        for item in after.artifacts
        if before_components.get(item.artifact.artifact_id) != item.content
    )


def _validate_declared_artifacts(document: AtifDocument) -> None:
    """Require one exact retained component for every ATIF artifact descriptor."""

    try:
        provenance = document.as_dict()["extra"]["coquic"]
        descriptors = provenance["artifacts"]
    except (KeyError, TypeError):
        raise PublicationError(ReasonCode.invalid_metadata) from None
    if not isinstance(descriptors, list):
        raise PublicationError(ReasonCode.invalid_metadata)

    declared: dict[str, Mapping[str, Any]] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, Mapping):
            raise PublicationError(ReasonCode.invalid_metadata)
        artifact_id = descriptor.get("artifactId")
        if not isinstance(artifact_id, str) or artifact_id in declared:
            raise PublicationError(ReasonCode.invalid_metadata)
        declared[artifact_id] = descriptor

    retained = {item.artifact.artifact_id: item for item in document.artifacts}
    if set(declared) != set(retained):
        raise PublicationError(ReasonCode.partial)
    for artifact_id, descriptor in declared.items():
        component = retained[artifact_id].artifact
        if (
            descriptor.get("mediaType") != component.media_type
            or descriptor.get("sha256") != component.sha256
            or descriptor.get("byteSize") != component.byte_size
            or descriptor.get("ownerStepId") != component.owner_step_id
        ):
            raise PublicationError(ReasonCode.invalid_metadata)


def _inspect_component(
    component: PublicBundleComponent,
    *,
    credential_sources: object,
    known_secrets: Sequence[str] | None,
    scanner_runner: Any,
    scanner_timeout: float,
    ocr_runner: Any,
    ocr_timeout: float,
) -> PublicBundleComponent | ReasonCode:
    try:
        result: MediaInspection = inspect_media(
            component.content,
            component.artifact.media_type,
            credential_sources=credential_sources,
            known_secrets=known_secrets,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
            ocr_runner=ocr_runner,
            ocr_timeout=ocr_timeout,
        )
    except PublicationError as exc:
        return exc.code
    except (MemoryError, OSError, TypeError, ValueError):
        return ReasonCode.unsafe_content
    if (
        not isinstance(result, MediaInspection)
        or not result.approved
        or result.bytes != component.content
        or result.byte_size != component.artifact.byte_size
        or result.sha256 != component.artifact.sha256
        or result.media_type != component.artifact.media_type
    ):
        return result.reason if isinstance(result, MediaInspection) and result.reason is not None else ReasonCode.unsafe_content
    return PublicBundleComponent(
        component.artifact,
        component.content,
        inspection=result,
        redaction_applied=component.redaction_applied,
        original_retained=component.original_retained,
    )


def _findings(result: SanitizationResult) -> tuple[FindingSummary, ...]:
    if result.findings:
        return result.findings
    return tuple(FindingSummary(code, 1) for code in result.reason_codes)


def _build_source(
    stable_run: object,
    *,
    snapshot: object,
    documents: object,
    codex: object,
    activities: object,
    telemetry: object,
    run_document: object,
    artifacts: object,
) -> tuple[object, dict[str, object]]:
    """Prepare converter arguments while preserving the stable-run boundary."""

    source: object | None = None
    run_value: object | None = None
    if snapshot is not None:
        source = None
    elif isinstance(stable_run, (PublicationSnapshot, AtifSource, Mapping)):
        source = stable_run
    elif stable_run is not None:
        run_value = stable_run
    kwargs: dict[str, object] = {
        "snapshot": snapshot if snapshot is not None else None,
        "run": run_value,
        "documents": documents,
        "artifacts": artifacts,
    }
    for name, value in (
        ("codex", codex),
        ("activities", activities),
        ("telemetry", telemetry),
        ("run_document", run_document),
    ):
        if value is not _MISSING:
            kwargs[name] = value
    return source, kwargs


def build_publication_bundle(
    stable_run: object = None,
    credential_sources: object = None,
    staging_root: object = None,
    *,
    run: object = _MISSING,
    completed_run: object = _MISSING,
    snapshot: object = None,
    documents: object = None,
    codex: object = _MISSING,
    activities: object = _MISSING,
    telemetry: object = _MISSING,
    run_document: object = _MISSING,
    artifacts: object = None,
    credential_files: object = None,
    credential_paths: object = None,
    credentials: object = None,
    known_secrets: Sequence[str] | str | None = None,
    run_scanner: bool = True,
    scanner_runner: Any = None,
    scanner_timeout: float = MAX_SCANNER_TIMEOUT_SECONDS,
    max_repair_passes: int = MAX_REPAIR_PASSES,
    ocr_runner: Any = None,
    ocr_timeout: float = MAX_OCR_TIMEOUT_SECONDS,
) -> PublicationOutcome:
    """Build one deterministic publishable bundle or bounded non-publishable outcome."""

    try:
        if run is not _MISSING and completed_run is not _MISSING:
            return _failure(ReasonCode.invalid_metadata)
        if run is not _MISSING:
            if stable_run is not None:
                return _failure(ReasonCode.invalid_metadata)
            stable_run = run
        elif completed_run is not _MISSING:
            if stable_run is not None:
                return _failure(ReasonCode.invalid_metadata)
            stable_run = completed_run
        _validate_staging_root(staging_root)
        selected_credentials = credential_sources
        if selected_credentials is None:
            selected_credentials = credentials
        if selected_credentials is None:
            selected_credentials = credential_files if credential_files is not None else credential_paths
        selected_secrets: Sequence[str] | None
        if isinstance(known_secrets, str):
            selected_secrets = (known_secrets,)
        else:
            selected_secrets = known_secrets

        source, converter_kwargs = _build_source(
            stable_run,
            snapshot=snapshot,
            documents=documents,
            codex=codex,
            activities=activities,
            telemetry=telemetry,
            run_document=run_document,
            artifacts=artifacts,
        )
        original_documents = _source_documents(
            stable_run,
            snapshot=snapshot,
            documents=documents,
            codex=codex,
        )
        original_codex_value = _find_document(original_documents, "codex.jsonl")
        original_codex = None if original_codex_value is _MISSING else _content(original_codex_value)

        converted = convert_completed_run(source, **converter_kwargs)
        # ``run_scanner`` is retained as an inert compatibility keyword.  The
        # final builder always performs the network-disabled scanner pass;
        # tests and trusted callers may inject only the runner implementation.
        _ = run_scanner
        sanitization = sanitize_publication(
            converted,
            selected_credentials,
            secrets=selected_secrets,
            run_scanner=True,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
            max_repair_passes=max_repair_passes,
        )
        if sanitization.status == "repair_required":
            return RepairRequired(tuple(sanitization.reason_codes), findings=_findings(sanitization))
        if sanitization.status != "clean" or sanitization.document is None:
            return FailClosed(tuple(sanitization.reason_codes), findings=_findings(sanitization))

        atif_changed = _normalized_transcript(sanitization.document) != _normalized_transcript(converted)
        changed_artifacts = _changed_artifact_ids(converted, sanitization.document)
        if atif_changed and original_codex is None:
            return _failure(ReasonCode.partial)
        finalized = _disclosure_document(sanitization.document, atif_changed=atif_changed)
        _validate_declared_artifacts(finalized)

        trajectory = LogicalArtifact(
            _TRAJECTORY_ARTIFACT_ID,
            f"runs/{finalized.as_dict()['extra']['coquic']['runId']}/trajectory.json",
            "application/json",
            finalized.byte_size,
            finalized.sha256,
        )
        if any(item.artifact.artifact_id == trajectory.artifact_id for item in finalized.artifacts):
            return _failure(ReasonCode.invalid_metadata)
        pending = [
            PublicBundleComponent(
                trajectory,
                finalized.content,
                redaction_applied=atif_changed,
                original_retained=atif_changed,
            )
        ]
        pending.extend(
            PublicBundleComponent(
                item.artifact,
                item.content,
                redaction_applied=item.artifact.artifact_id in changed_artifacts,
            )
            for item in finalized.artifacts
        )

        inspected: list[PublicBundleComponent] = []
        reasons: list[ReasonCode] = []
        for component in pending:
            result = _inspect_component(
                component,
                credential_sources=selected_credentials,
                known_secrets=selected_secrets,
                scanner_runner=scanner_runner,
                scanner_timeout=scanner_timeout,
                ocr_runner=ocr_runner,
                ocr_timeout=ocr_timeout,
            )
            if isinstance(result, ReasonCode):
                if result not in reasons:
                    reasons.append(result)
            else:
                inspected.append(result)
        if reasons:
            return FailClosed(tuple(reasons))
        if len(inspected) != len(pending):
            return _failure(ReasonCode.unsafe_content)

        public_bundle = PublicBundle(tuple(inspected))
        if not public_bundle.inspected:
            return _failure(ReasonCode.invalid_metadata)
        trajectory_document = SourceDocument(trajectory.logical_path, finalized.content, trajectory.media_type)
        private_original = PrivateOriginal(original_codex) if atif_changed and original_codex is not None else None
        publication = PublicationSnapshot(
            _run_for_output(stable_run, snapshot=snapshot, document=finalized),
            documents=(trajectory_document,),
            artifacts=tuple(item.artifact for item in inspected),
            public_bundle=public_bundle,
            private_original=private_original,
        )
        return Publishable(publication)
    except PublicationError as exc:
        return _failure(exc.code)
    except (MemoryError, OSError, TypeError, ValueError, KeyError, RecursionError):
        return _failure(ReasonCode.invalid_metadata)
    except Exception:
        # Dependencies already reduce expected failures to bounded values; a
        # future implementation error must still never expose a traceback or
        # partial bytes through this public boundary.
        return _failure(ReasonCode.invalid_metadata)


def _run_for_output(stable_run: object, *, snapshot: object, document: AtifDocument) -> RunMetadata:
    candidate: object = snapshot if snapshot is not None else stable_run
    if isinstance(candidate, PublicationSnapshot):
        return candidate.run
    if isinstance(candidate, AtifSource):
        candidate = candidate.run
    elif isinstance(candidate, Mapping) and isinstance(candidate.get("run"), (RunMetadata, Mapping)):
        candidate = candidate["run"]
    if isinstance(candidate, RunMetadata):
        return candidate
    if isinstance(candidate, Mapping):
        return _run_from_mapping(candidate)
    return _run_from_atif(document)


def _run_from_mapping(value: Mapping[str, Any]) -> RunMetadata:
    try:
        identity_value = value.get("identity") if isinstance(value.get("identity"), Mapping) else value
        lineage_value = value.get("lineage") if isinstance(value.get("lineage"), Mapping) else value
        usage_value = value.get("usage")
        usage = None
        if isinstance(usage_value, Mapping):
            usage = UsageSummary(
                prompt_tokens=usage_value.get("promptTokens", usage_value.get("prompt_tokens", usage_value.get("input_tokens"))),
                completion_tokens=usage_value.get("completionTokens", usage_value.get("completion_tokens", usage_value.get("output_tokens"))),
                total_tokens=usage_value.get("totalTokens", usage_value.get("total_tokens")),
                cached_input_tokens=usage_value.get("cachedInputTokens", usage_value.get("cached_input_tokens", usage_value.get("cached_tokens"))),
                reasoning_output_tokens=usage_value.get("reasoningOutputTokens", usage_value.get("reasoning_output_tokens")),
            )
        return RunMetadata(
            identity=RunIdentity(
                identity_value["taskId"] if "taskId" in identity_value else identity_value["task_id"],
                identity_value["pipelineId"] if "pipelineId" in identity_value else identity_value["pipeline_id"],
                identity_value["runId"] if "runId" in identity_value else identity_value.get("run_id", identity_value.get("id")),
            ),
            role=value.get("role", "unknown"),
            state=value.get("state", value.get("runState", "succeeded")),
            started_at=value.get("startedAt", value.get("started_at")),
            completed_at=value.get("completedAt", value.get("completed_at")),
            duration_ms=value.get("durationMs", value.get("duration_ms", 0)),
            model=value.get("model"),
            reasoning=value.get("reasoning", value.get("reasoning_effort")),
            lineage=RunLineage(
                parent_run_id=lineage_value.get("parentRunId", lineage_value.get("parent_run_id")),
                retry_of_run_id=lineage_value.get("retryOfRunId", lineage_value.get("retry_of_run_id")),
                resume_of_run_id=lineage_value.get("resumeOfRunId", lineage_value.get("resume_of_run_id")),
            ),
            usage=usage,
        )
    except (KeyError, TypeError, ValueError, PublicationError):
        raise PublicationError(ReasonCode.invalid_metadata) from None


def _run_from_atif(document: AtifDocument) -> RunMetadata:
    try:
        provenance = document.as_dict()["extra"]["coquic"]
        return _run_from_mapping(provenance)
    except (KeyError, TypeError, ValueError, PublicationError):
        raise PublicationError(ReasonCode.invalid_metadata) from None


# Compatibility spellings for transport callers that use the operation name.
assemble_publication_bundle = build_publication_bundle
build_publication = build_publication_bundle
assemble_publication = build_publication_bundle


__all__ = [
    "assemble_publication",
    "assemble_publication_bundle",
    "build_publication",
    "build_publication_bundle",
]

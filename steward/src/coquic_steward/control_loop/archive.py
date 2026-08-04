"""Atomic public-by-placement materialization for the control-loop ledger."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .ledger import ControlLoopLedger, LedgerConflictError
from .models import (
    CONTROL_LOOP_FORMAT_VERSION,
    CONTROL_LOOP_POLICY,
    Artifact,
    CurrentState,
    Epoch,
    Event,
    Manifest,
    PlannerRun,
    artifact_from_bytes,
    timestamp,
    validate_id,
    validate_relative_path,
)


class ArchiveError(RuntimeError):
    pass


class ArchiveConflictError(ArchiveError):
    pass


class ArchiveValidationError(ArchiveError):
    pass


_DATE = re.compile(r"^\d{4}/\d{2}/\d{2}\.jsonl$")


def _json_bytes(value: Mapping[str, Any] | list[Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _accepted_prefix(data: bytes) -> bytes:
    """Return complete JSONL records, excluding a torn final record."""

    if data.endswith(b"\n"):
        return data
    return data[: data.rfind(b"\n") + 1] if b"\n" in data else b""


def _fsync(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class ControlLoopArchive:
    """One writer for ``$COQUIC_HOME/control-loop``."""

    format_version = CONTROL_LOOP_FORMAT_VERSION
    policy = CONTROL_LOOP_POLICY

    def __init__(self, root: Path | str | Any, *, task_root: Path | str | Any | None = None, epoch_id: str | None = None):
        configured = getattr(root, "control_loop_dir", None)
        raw_root = Path(configured if configured is not None else root).expanduser()
        if raw_root.is_symlink():
            raise ArchiveValidationError("control-loop root must not be a symlink")
        if raw_root.exists() and not raw_root.is_dir():
            raise ArchiveValidationError("control-loop root must be a directory")
        self.root = raw_root
        self.task_root = Path(
            getattr(task_root, "tasks_dir", task_root) if task_root is not None else self.root.parent / "tasks"
        ).expanduser()
        self._epoch_id = validate_id(epoch_id) if epoch_id else None
        self._epoch: Epoch | None = None
        self._verified_append_context: dict[str, Any] | None = None
        # This is deliberately process-local.  Archive bytes and the ledger
        # remain authoritative; the snapshot is only a performance hint after
        # a successful canonical verification pass.
        self._verified_snapshot: dict[str, Any] | None = None
        # Direct appends that occur before a ledger-backed audit still retain a
        # process-local watermark. It is discarded whenever verified trust is
        # invalidated and is never persisted.
        self._append_high_watermark: int | None = None
        self._verification_counters: dict[str, int] = {
            "eventFiles": 0,
            "eventBytes": 0,
            "eventHashes": 0,
            "plannerRuns": 0,
            "plannerBytes": 0,
            "plannerHashes": 0,
        }

    @property
    def verification_counters(self) -> dict[str, int]:
        """Return cumulative structural verification counters."""

        return dict(self._verification_counters)

    @property
    def verification_stats(self) -> dict[str, int]:
        """Compatibility alias for callers inspecting verification work."""

        return self.verification_counters

    def reset_verification_counters(self) -> None:
        for key in self._verification_counters:
            self._verification_counters[key] = 0

    @staticmethod
    def _path_identity(path: Path) -> tuple[int, int, int, int, int] | None:
        """Return an lstat identity that detects replacement and metadata edits."""

        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_mode),
            int(info.st_size),
            int(info.st_mtime_ns),
        )

    def _event_file_identities(self) -> dict[Path, tuple[int, int, int, int, int]]:
        identities: dict[Path, tuple[int, int, int, int, int]] = {}
        if not self.events_root.exists():
            return identities
        for path in self.events_root.rglob("*.jsonl"):
            identity = self._path_identity(path)
            if identity is None:
                continue
            mode = identity[2]
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise ArchiveValidationError("event archive contains a special path")
            identities[path] = identity
        return identities

    def _planner_tree_identity(self, target: Path) -> dict[str, Any] | None:
        """Stat a visible planner run without reading any artifact bytes."""

        root_identity = self._path_identity(target)
        if root_identity is None:
            return None
        if stat.S_ISLNK(root_identity[2]) or not stat.S_ISDIR(root_identity[2]):
            return None
        entries: dict[str, tuple[int, int, int, int, int]] = {"": root_identity}
        for path in target.rglob("*"):
            identity = self._path_identity(path)
            if identity is None:
                return None
            entries[path.relative_to(target).as_posix()] = identity
        return {"root": root_identity, "entries": entries}

    @property
    def epoch_path(self) -> Path:
        return self.root / "epoch.json"

    @property
    def current_path(self) -> Path:
        return self.root / "current.json"

    @property
    def events_root(self) -> Path:
        return self.root / "events"

    @property
    def planner_runs_root(self) -> Path:
        return self.root / "planner-runs"

    def _safe_root(self) -> None:
        if self.root.is_symlink():
            raise ArchiveValidationError("control-loop root must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in (self.events_root, self.planner_runs_root):
            if path.exists() and (path.is_symlink() or not path.is_dir()):
                raise ArchiveValidationError(f"archive path is not a directory: {path.name}")
            path.mkdir(parents=True, exist_ok=True, mode=0o700)

    def ensure_epoch(self, authoritative: Mapping[str, Any] | Epoch | None = None) -> Epoch:
        self._safe_root()
        task_epoch: dict[str, Any] | None = None
        task_epoch_path = self.task_root / "epoch.json"
        if task_epoch_path.exists():
            try:
                task_epoch = json.loads(task_epoch_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveValidationError("task epoch is invalid") from exc
        if isinstance(authoritative, Epoch):
            value = authoritative.model_dump(by_alias=True, mode="json")
        elif authoritative is not None:
            value = dict(authoritative)
        elif task_epoch is not None:
            value = {
                "epochId": task_epoch.get("epochId"),
                "formatVersion": CONTROL_LOOP_FORMAT_VERSION,
                "taskFormatVersion": task_epoch.get("formatVersion"),
                "policy": task_epoch.get("policy"),
                "startedAt": task_epoch.get("startedAt"),
            }
        else:
            value = {}
        if not value:
            value = {
                "epochId": self._epoch_id or f"epoch-{sha256(os.urandom(16)).hexdigest()[:20]}",
                "formatVersion": "1.0",
                "taskFormatVersion": "1.0",
                "policy": CONTROL_LOOP_POLICY,
                "startedAt": timestamp(),
            }
        if task_epoch is not None and value.get("epochId") != task_epoch.get("epochId"):
            raise ArchiveConflictError("control-loop epoch does not match task epoch")
        if self._epoch_id is not None and value.get("epochId") != self._epoch_id:
            raise ArchiveConflictError("control-loop epoch id mismatch")
        try:
            epoch = Epoch.model_validate(value)
        except Exception as exc:
            raise ArchiveValidationError("invalid control-loop epoch") from exc
        # The control-loop format is deliberately independent of the task
        # archive format, even though the epoch ID is shared.
        epoch_payload = epoch.model_dump(by_alias=True, mode="json")
        if self.epoch_path.exists():
            if self.epoch_path.is_symlink():
                raise ArchiveValidationError("epoch.json must not be a symlink")
            try:
                existing = json.loads(self.epoch_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ArchiveValidationError("invalid control-loop epoch") from exc
            if existing != epoch_payload:
                raise ArchiveConflictError("visible control-loop epoch differs")
        else:
            self._atomic_write(self.epoch_path, _json_bytes(epoch_payload), mode=0o600)
        self._epoch = epoch
        self._epoch_id = epoch.epoch_id
        return epoch

    def ensure_task_epoch(self, task_epoch: Mapping[str, Any]) -> Epoch:
        """Create or verify the peer epoch from the authoritative task epoch."""

        required = ("epochId", "formatVersion", "policy", "startedAt")
        if any(key not in task_epoch for key in required):
            raise ArchiveValidationError("task epoch is missing required metadata")
        return self.ensure_epoch(
            authoritative={
                "epochId": task_epoch["epochId"],
                "formatVersion": CONTROL_LOOP_FORMAT_VERSION,
                "taskFormatVersion": task_epoch["formatVersion"],
                "policy": task_epoch["policy"],
                "startedAt": task_epoch["startedAt"],
            }
        )

    def _require_epoch(self) -> Epoch:
        return self._epoch or self.ensure_epoch()

    def _atomic_write(self, path: Path, content: bytes, *, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _event_path(self, occurred_at: datetime | str) -> Path:
        if isinstance(occurred_at, str):
            value = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        else:
            value = occurred_at
        value = value.astimezone(timezone.utc)
        return self.events_root / f"{value:%Y}" / f"{value:%m}" / f"{value:%d}.jsonl"

    def append_event(self, event: Event | Mapping[str, Any]) -> int:
        self._require_epoch()
        item = event if isinstance(event, Event) else Event.model_validate(event)
        if item.epoch_id != self._epoch_id:
            raise ArchiveConflictError("event epoch does not match archive")
        path = self._event_path(item.occurred_at)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ArchiveValidationError("event path must be a regular file")
        content = _json_bytes(item.model_dump(by_alias=True, mode="json"))
        context = self._verified_append_context
        if context is not None:
            verified_files = context["files"]
            facts = verified_files.get(path)
            if facts is None:
                facts = self._empty_verified_event_file(path)
                verified_files[path] = facts
            return self._append_verified_event(item, path, content, facts, context)
        # A caller may append between reconciles.  Reuse the last successful
        # audit only when every event-file identity is still unchanged; an
        # identity change must be repaired through reconcile with ledger
        # authority instead of silently scanning unverified bytes.
        snapshot = self._verified_snapshot
        if snapshot is not None and snapshot.get("events") is not None:
            prior_events = snapshot["events"]
            facts = prior_events.get(path)
            current_identity = self._path_identity(path)
            if facts is None:
                # A new target is safe only while it is still absent. Existing
                # bytes have not been ledger-verified and require reconcile.
                if current_identity is not None:
                    self._verified_snapshot = None
                    self._append_high_watermark = None
                    raise ArchiveConflictError("event file appeared after verification")
                facts = self._empty_verified_event_file(path)
            elif current_identity != facts.get("identity"):
                self._verified_snapshot = None
                self._append_high_watermark = None
                raise ArchiveConflictError("event archive changed after verification")
            verified_files = deepcopy(prior_events)
            verified_files[path] = deepcopy(facts)
            facts = verified_files[path]
            append_context = {
                "files": verified_files,
                "highWatermark": snapshot.get("highWatermark", -1),
            }
            result = self._append_verified_event(item, path, content, facts, append_context)
            updated_snapshot = deepcopy(snapshot)
            updated_snapshot["events"] = verified_files
            updated_snapshot["highWatermark"] = append_context["highWatermark"]
            self._verified_snapshot = updated_snapshot
            self._append_high_watermark = append_context["highWatermark"]
            return result
        existing = path.read_bytes() if path.exists() else b""
        # Complete records are the append boundary.  A torn final line may be
        # discarded only when it is not a complete JSON record.
        accepted = _accepted_prefix(existing)
        if accepted != existing:
            self._atomic_write(path, accepted)
        prior_sequences: list[int] = []
        for line in accepted.splitlines():
            try:
                prior = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ArchiveConflictError("event file has malformed accepted prefix") from exc
            if prior.get("epochId") != self._epoch_id:
                raise ArchiveConflictError("event file contains a conflicting epoch")
            try:
                prior_sequences.append(int(prior["sequence"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise ArchiveConflictError("event file contains an invalid sequence") from exc
            if prior.get("eventId") == item.event_id:
                if line != content.rstrip(b"\n"):
                    raise ArchiveConflictError("event ID has conflicting visible bytes")
                self._append_high_watermark = max(
                    self._append_high_watermark
                    if self._append_high_watermark is not None
                    else -1,
                    max(prior_sequences, default=-1),
                )
                return len(accepted)
        visible_max = max(
            max(prior_sequences, default=-1),
            self._append_high_watermark
            if self._append_high_watermark is not None
            else -1,
        )
        self._append_high_watermark = visible_max
        if visible_max >= 0 and item.sequence <= visible_max:
            raise ArchiveConflictError("event sequence is not monotonically increasing")
        with path.open("ab") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(path.parent)
        self._append_high_watermark = item.sequence
        return len(accepted) + len(content)

    def _empty_verified_event_file(self, path: Path) -> dict[str, Any]:
        try:
            relative_path = path.relative_to(self.events_root).as_posix()
        except ValueError:
            relative_path = path.as_posix()
        return {
            "path": relative_path,
            "sha256": sha256(b"").hexdigest(),
            "byteSize": 0,
            "eventCount": 0,
            "sequences": [],
            "eventIds": [],
            "sequenceStart": None,
            "sequenceEnd": None,
            "highWatermark": None,
        }

    def _append_verified_event(
        self,
        item: Event,
        path: Path,
        content: bytes,
        facts: dict[str, Any],
        context: dict[str, Any],
    ) -> int:
        """Append a row using a byte-verified in-memory file snapshot."""

        expected_identity = facts.get("identity")
        current_identity = self._path_identity(path)
        if expected_identity is not None and current_identity != expected_identity:
            raise ArchiveConflictError("event file changed after verification")
        buffers = context.setdefault("_accepted_bytes", {})
        if (
            "_append_identity" in facts
            and facts["_append_identity"] == current_identity
            and path in buffers
        ):
            existing = None
            accepted = buffers[path]
            accepted_size = len(accepted)
        else:
            existing = path.read_bytes() if path.exists() else b""
            accepted = _accepted_prefix(existing)
            if (
                len(accepted) != facts.get("byteSize")
                or sha256(accepted).hexdigest() != facts.get("sha256")
            ):
                raise ArchiveConflictError("event file changed after verification")
            accepted_size = len(accepted)
            facts["_append_identity"] = current_identity
            buffers[path] = accepted
        if existing is not None and accepted != existing:
            self._atomic_write(path, accepted)

        context_high = context.get("highWatermark")
        facts_high = facts.get("highWatermark")
        visible_max = max(
            context_high if context_high is not None else -1,
            facts_high if facts_high is not None else -1,
            self._append_high_watermark
            if self._append_high_watermark is not None
            else -1,
        )
        context["highWatermark"] = visible_max
        self._append_high_watermark = visible_max
        event_ids = facts.get("eventIds", [])
        if item.event_id in event_ids:
            index = event_ids.index(item.event_id)
            sequences = facts.get("sequences", [])
            if index >= len(sequences) or sequences[index] != item.sequence:
                raise ArchiveConflictError("event ID has conflicting visible bytes")
            return accepted_size
        if item.sequence <= visible_max:
            raise ArchiveConflictError("event sequence is not monotonically increasing")

        with path.open("ab") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(path.parent)

        updated = accepted + content
        updated_size = len(updated)
        facts["sha256"] = sha256(updated).hexdigest()
        facts["byteSize"] = updated_size
        facts["eventCount"] = int(facts.get("eventCount", 0)) + 1
        facts.setdefault("sequences", []).append(item.sequence)
        facts.setdefault("eventIds", []).append(item.event_id)
        if facts.get("sequenceStart") is None:
            facts["sequenceStart"] = item.sequence
        facts["sequenceEnd"] = item.sequence
        facts["highWatermark"] = item.sequence
        context["highWatermark"] = max(context.get("highWatermark", -1), item.sequence)
        self._append_high_watermark = context["highWatermark"]
        facts["identity"] = self._path_identity(path)
        facts["_append_identity"] = facts["identity"]
        buffers[path] = updated
        return updated_size

    def write_current(self, state: CurrentState | Mapping[str, Any]) -> Path:
        epoch = self._require_epoch()
        item = state if isinstance(state, CurrentState) else CurrentState.model_validate(state)
        if item.epoch_id != epoch.epoch_id:
            raise ArchiveConflictError("current projection epoch mismatch")
        self._atomic_write(self.current_path, _json_bytes(item.model_dump(by_alias=True, mode="json")))
        return self.current_path

    def _run_dir(self, planner_run_id: str) -> Path:
        return self.planner_runs_root / validate_id(planner_run_id)

    def _manifest(self, run: PlannerRun, files: Mapping[str, bytes]) -> Manifest:
        descriptors = [artifact_from_bytes(path, content) for path, content in sorted(files.items())]
        return Manifest(
            epochId=self._require_epoch().epoch_id,
            plannerRunId=run.planner_run_id,
            terminalState=run.state,
            completedAt=run.completed_at or datetime.now(timezone.utc),
            files=descriptors,
        )

    def publish_planner_run(
        self,
        run: PlannerRun | Mapping[str, Any],
        artifacts: Mapping[str, bytes | str],
    ) -> Path:
        """Publish a terminal planner run by hidden stage + atomic placement."""

        epoch = self._require_epoch()
        item = run if isinstance(run, PlannerRun) else PlannerRun.model_validate(run)
        if item.epoch_id != epoch.epoch_id:
            raise ArchiveConflictError("planner run epoch mismatch")
        if item.state not in {"succeeded", "failed", "interrupted", "cancelled"}:
            raise ArchiveValidationError("only terminal planner runs can be published")
        normalized: dict[str, bytes] = {}
        for raw_path, value in artifacts.items():
            path = validate_relative_path(raw_path)
            if path == "manifest.json":
                raise ArchiveValidationError("manifest is writer-owned")
            normalized[path] = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        manifest = self._manifest(item, normalized)
        manifest_bytes = _json_bytes(manifest.model_dump(by_alias=True, mode="json"))
        target = self._run_dir(item.planner_run_id)
        if target.is_symlink():
            raise ArchiveValidationError("planner-run directory must not be a symlink")
        if target.exists():
            if self._visible_run_matches(target, normalized, manifest_bytes):
                return target
            raise ArchiveConflictError("visible planner-run directory conflicts with sealed manifest")
        stage = self.planner_runs_root / f".{item.planner_run_id}.stage-{os.getpid()}-{sha256(os.urandom(8)).hexdigest()[:8]}"
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True, mode=0o700)
        try:
            for path, content in normalized.items():
                destination = stage / path
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                destination.write_bytes(content)
                os.chmod(destination, 0o600)
                _fsync(destination)
            manifest_path = stage / "manifest.json"
            manifest_path.write_bytes(manifest_bytes)
            os.chmod(manifest_path, 0o600)
            _fsync(manifest_path)
            _fsync_dir(stage)
            try:
                os.replace(stage, target)
            except FileExistsError:
                # Another writer may have won the placement race.  Only adopt
                # it when its exact sealed bytes match this publication.
                if not self._visible_run_matches(target, normalized, manifest_bytes):
                    raise ArchiveConflictError("planner-run placement race has conflicting bytes")
            _fsync_dir(target.parent)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        return target

    def _verify_planner_run_facts(self, planner_run_id: str) -> dict[str, Any] | None:
        """Verify one sealed run and return byte/hash facts for reuse."""

        target = self._run_dir(planner_run_id)
        identity = self._planner_tree_identity(target)
        if identity is None:
            return None
        manifest_path = target / "manifest.json"
        manifest_identity = self._path_identity(manifest_path)
        if (
            manifest_identity is None
            or stat.S_ISLNK(manifest_identity[2])
            or not stat.S_ISREG(manifest_identity[2])
        ):
            return None
        try:
            manifest_bytes = manifest_path.read_bytes()
            self._verification_counters["plannerBytes"] += len(manifest_bytes)
            self._verification_counters["plannerHashes"] += 1
            manifest = Manifest.model_validate(json.loads(manifest_bytes))
        except (json.JSONDecodeError, ValueError):
            return None
        if manifest.epoch_id != self._require_epoch().epoch_id or manifest.planner_run_id != planner_run_id:
            return None
        descriptors = {item.path: item for item in manifest.files}
        actual: dict[str, Path] = {}
        for path in target.rglob("*"):
            path_identity = self._path_identity(path)
            if path_identity is None or stat.S_ISLNK(path_identity[2]):
                return None
            if stat.S_ISREG(path_identity[2]) and path.name != "manifest.json":
                actual[path.relative_to(target).as_posix()] = path
            elif not stat.S_ISDIR(path_identity[2]) and path.name != "manifest.json":
                return None
        if set(actual) != set(descriptors):
            return None
        artifacts: dict[str, dict[str, Any]] = {}
        for relative, path in actual.items():
            content = path.read_bytes()
            self._verification_counters["plannerBytes"] += len(content)
            self._verification_counters["plannerHashes"] += 1
            descriptor = descriptors[relative]
            if len(content) != descriptor.byte_size or sha256(content).hexdigest() != descriptor.sha256:
                return None
            artifacts[relative] = {
                "identity": self._path_identity(path),
                "byteSize": len(content),
                "sha256": descriptor.sha256,
            }
        self._verification_counters["plannerRuns"] += 1
        return {
            "identity": identity,
            "manifest": {
                "identity": manifest_identity,
                "byteSize": len(manifest_bytes),
                "sha256": sha256(manifest_bytes).hexdigest(),
            },
            "artifacts": artifacts,
        }

    def verify_planner_run(self, planner_run_id: str) -> bool:
        try:
            facts = self._verify_planner_run_facts(planner_run_id)
        except (OSError, ArchiveValidationError):
            return False
        if facts is not None and self._verified_snapshot is not None:
            self._verified_snapshot.setdefault("plannerRuns", {})[planner_run_id] = facts
        return facts is not None

    def planner_run_is_verified(self, planner_run_id: str) -> bool:
        """Check cached planner-run trust using stat identities only."""

        snapshot = self._verified_snapshot
        if snapshot is None:
            return False
        facts = snapshot.get("plannerRuns", {}).get(planner_run_id)
        if facts is None:
            return False
        return facts.get("identity") == self._planner_tree_identity(
            self._run_dir(planner_run_id)
        )

    def _visible_run_matches(
        self, target: Path, artifacts: Mapping[str, bytes], manifest_bytes: bytes
    ) -> bool:
        """Compare an already-visible run with the bytes this writer expects."""

        if not target.is_dir() or target.is_symlink():
            return False
        manifest_path = target / "manifest.json"
        try:
            if manifest_path.is_symlink() or manifest_path.read_bytes() != manifest_bytes:
                return False
        except OSError:
            return False
        expected = {validate_relative_path(path): bytes(value) for path, value in artifacts.items()}
        actual: dict[str, bytes] = {}
        for path in target.rglob("*"):
            if path.is_symlink():
                return False
            if path.is_file():
                relative = path.relative_to(target).as_posix()
                if relative == "manifest.json":
                    continue
                try:
                    actual[relative] = path.read_bytes()
                except OSError:
                    return False
            elif not path.is_dir():
                return False
        return actual == expected

    def _verified_event_snapshot(
        self,
        ledger: ControlLoopLedger,
        *,
        force_full_audit: bool,
    ) -> tuple[dict[Path, dict[str, Any]], int]:
        """Return verified event facts, rechecking only changed identities."""

        identities = self._event_file_identities()
        prior = self._verified_snapshot
        if (
            force_full_audit
            or prior is None
            or prior.get("epochId") != self._epoch_id
            or prior.get("ledgerEpoch") != ledger.epoch_id
        ):
            prior_events: Mapping[Path, dict[str, Any]] = {}
        else:
            prior_events = prior.get("events", {})

        if prior_events and set(prior_events) - set(identities):
            raise ArchiveConflictError("verified event file disappeared")

        verified: dict[Path, dict[str, Any]] = {}
        for path, identity in identities.items():
            facts = prior_events.get(path)
            if facts is not None and facts.get("identity") == identity:
                verified[path] = deepcopy(facts)
                continue
            facts = self._assert_confirmed_event_file(path, ledger)
            if facts is not None and prior_events.get(path) is not None:
                previous = prior_events[path]
                if (
                    facts.get("byteSize", 0) < previous.get("byteSize", 0)
                    or facts.get("eventCount", 0) < previous.get("eventCount", 0)
                ):
                    raise ArchiveConflictError("verified event file was truncated")
            facts["identity"] = identity
            verified[path] = facts
        high_watermark = max(
            (
                facts["highWatermark"]
                if facts.get("highWatermark") is not None
                else -1
                for facts in verified.values()
            ),
            default=-1,
        )
        return verified, high_watermark

    def _verified_planner_snapshot(
        self, *, force_full_audit: bool
    ) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
        """Return verified planner facts and visible/invalid run IDs."""

        hidden_stages = sorted(
            path.name
            for path in self.planner_runs_root.iterdir()
            if path.name.startswith(".")
        )
        runs = sorted(
            path.name
            for path in self.planner_runs_root.iterdir()
            if path.is_dir() and not path.name.startswith(".")
        )
        prior = self._verified_snapshot
        prior_runs: Mapping[str, dict[str, Any]] = {}
        if not force_full_audit and prior is not None and prior.get("epochId") == self._epoch_id:
            prior_runs = prior.get("plannerRuns", {})
            disappeared = sorted(set(prior_runs) - set(runs))
            if disappeared:
                raise ArchiveConflictError(
                    "verified planner run disappeared: " + ", ".join(disappeared)
                )

        verified: dict[str, dict[str, Any]] = {}
        invalid: list[str] = []
        for run_id in runs:
            target = self._run_dir(run_id)
            identity = self._planner_tree_identity(target)
            facts = prior_runs.get(run_id)
            if identity is not None and facts is not None and facts.get("identity") == identity:
                verified[run_id] = deepcopy(facts)
                continue
            checked = self._verify_planner_run_facts(run_id)
            if checked is None:
                invalid.append(run_id)
                continue
            verified[run_id] = checked
        return verified, runs, invalid

    def reconcile(
        self,
        ledger: ControlLoopLedger | None = None,
        *,
        current: CurrentState | Mapping[str, Any] | None = None,
        limit: int = 100,
        full_audit: bool = False,
        force_full_audit: bool = False,
    ) -> dict[str, Any]:
        """Drain durable outbox records and verify visible archive evidence.

        Startup and callers that explicitly request ``full_audit`` rebuild all
        facts from bytes and ledger rows.  Ordinary calls stat archive paths and
        reuse facts whose identities are unchanged.
        """

        force = full_audit or force_full_audit
        self._require_epoch()
        if force and ledger is None:
            # Event bytes can only be trusted when they are compared with the
            # authoritative ledger. Reject a ledgerless full audit and drop
            # any process-local trust that might otherwise be reused.
            self._verified_snapshot = None
            self._append_high_watermark = None
            raise ArchiveValidationError("full archive audit requires ledger authority")
        counters_before = self.verification_counters
        materialized = 0
        conflicts = 0
        event_snapshot: dict[Path, dict[str, Any]] | None = None
        high_watermark = -1
        event_trust_lost = False
        event_audit_incomplete = False
        pending_outbox = False
        outbox_error = False

        if ledger is not None:
            try:
                event_snapshot, high_watermark = self._verified_event_snapshot(
                    ledger, force_full_audit=force
                )
                self._append_high_watermark = high_watermark
            except (ArchiveConflictError, ArchiveValidationError):
                conflicts += 1
                event_trust_lost = True
                self._verified_snapshot = None
                ledger.set_planning_blocked(True, reason="visible event conflict")
            else:
                verification_context = {
                    "files": event_snapshot,
                    "highWatermark": high_watermark,
                }
                self._verified_append_context = verification_context
                try:
                    outbox_rows = ledger.outbox(limit=limit)
                    for row in outbox_rows:
                        try:
                            self._assert_confirmed_event_prefix(
                                row["event"], ledger, verified_files=event_snapshot
                            )
                            self.append_event(row["event"])
                        except ArchiveConflictError:
                            conflicts += 1
                            event_trust_lost = True
                            outbox_error = True
                            ledger.set_planning_blocked(True, reason="visible event conflict")
                            break
                        except OSError:
                            # A filesystem error is lag, not an epoch/identity
                            # conflict.  The daemon's asynchronous writer retries it
                            # on its next wakeup.
                            outbox_error = True
                            break
                        except ArchiveValidationError:
                            conflicts += 1
                            event_trust_lost = True
                            outbox_error = True
                            ledger.set_planning_blocked(True, reason="visible event path conflict")
                            break
                        ledger.mark_materialized(row["sequence"], event_id=row["event_id"])
                        materialized += 1
                    pending_outbox = outbox_error or len(outbox_rows) >= limit
                    # Appends mutate the context in place. Carry its final
                    # watermark into the snapshot and returned result rather
                    # than retaining the pre-drain audit value.
                    high_watermark = max(
                        high_watermark,
                        int(verification_context.get("highWatermark", -1)),
                    )
                    if force and outbox_error:
                        event_audit_incomplete = True
                        self._verified_snapshot = None
                        self._append_high_watermark = None
                        ledger.set_planning_blocked(
                            True, reason="control-loop event audit incomplete"
                        )
                finally:
                    self._verified_append_context = None

        if current is not None:
            try:
                self.write_current(current)
            except ArchiveConflictError:
                conflicts += 1

        planner_trust_lost = False
        planner_audit_incomplete = False
        planner_audit_error: Exception | None = None
        try:
            planner_snapshot, runs, invalid_runs = self._verified_planner_snapshot(
                force_full_audit=force
            )
        except (ArchiveConflictError, ArchiveValidationError, OSError) as exc:
            conflicts += 1
            planner_snapshot = None
            runs = []
            invalid_runs = []
            planner_trust_lost = True
            planner_audit_incomplete = True
            planner_audit_error = exc
            if ledger is not None:
                ledger.set_planning_blocked(
                    True, reason="control-loop planner audit incomplete"
                )

        hidden_stages = sorted(
            path.name
            for path in self.planner_runs_root.iterdir()
            if path.name.startswith(".")
        )
        if hidden_stages:
            conflicts += len(hidden_stages)
            if ledger is not None:
                ledger.set_planning_blocked(
                    True,
                    reason="hidden planner-run stage requires operator reconciliation",
                )
        if invalid_runs:
            conflicts += len(invalid_runs)
            if ledger is not None:
                ledger.set_planning_blocked(True, reason="visible planner-run conflict")

        if (
            not event_trust_lost
            and not event_audit_incomplete
            and not planner_trust_lost
            and not planner_audit_incomplete
            and (
                ledger is not None or planner_snapshot is not None
            )
        ):
            updated_snapshot = deepcopy(self._verified_snapshot or {})
            updated_snapshot["epochId"] = self._epoch_id
            updated_snapshot["plannerRuns"] = deepcopy(planner_snapshot or {})
            if ledger is not None:
                updated_snapshot.update(
                    {
                        "ledgerEpoch": ledger.epoch_id,
                        "events": deepcopy(event_snapshot or {}),
                        "highWatermark": high_watermark,
                    }
                )
            self._verified_snapshot = updated_snapshot
        elif event_trust_lost or event_audit_incomplete:
            self._verified_snapshot = None
        elif planner_trust_lost and self._verified_snapshot is not None:
            # Keep event trust only when planner stat/read failure did not
            # affect the event files; the affected planner facts are discarded.
            self._verified_snapshot["plannerRuns"] = {}
        if event_trust_lost:
            self._append_high_watermark = None

        counters_after = self.verification_counters
        verification = {
            key: counters_after[key] - counters_before[key]
            for key in counters_after
        }
        result = {
            "materialized": materialized,
            "conflicts": conflicts,
            "visibleRuns": len(runs),
            "visibleRunIds": runs,
            "invalidRuns": invalid_runs,
            "hiddenStages": hidden_stages,
            "highWatermark": high_watermark,
            "pending": pending_outbox,
            "verification": verification,
            "auditIncomplete": event_audit_incomplete or planner_audit_incomplete,
            "eventAuditIncomplete": event_audit_incomplete,
            "plannerAuditIncomplete": planner_audit_incomplete,
        }
        if planner_audit_error is not None:
            result["error"] = planner_audit_error.__class__.__name__
        return result

    def full_audit(
        self,
        ledger: ControlLoopLedger | None = None,
        *,
        current: CurrentState | Mapping[str, Any] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Force one complete byte/ledger verification pass."""

        if ledger is None:
            self._verified_snapshot = None
            self._append_high_watermark = None
            raise ArchiveValidationError("full archive audit requires ledger authority")

        return self.reconcile(
            ledger,
            current=current,
            limit=limit,
            full_audit=True,
        )

    def _assert_confirmed_event_prefix(
        self,
        event: Mapping[str, Any],
        ledger: ControlLoopLedger,
        *,
        verified_files: dict[Path, dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Reject a visible complete prefix that is not ledger-confirmed."""

        occurred_at = event.get("occurredAt")
        if not isinstance(occurred_at, str):
            raise ArchiveValidationError("event occurredAt is invalid")
        path = self._event_path(occurred_at)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ArchiveValidationError("event path must be a regular file")
        if not path.exists():
            if verified_files is not None and path in verified_files:
                verified_files.pop(path, None)
                raise ArchiveConflictError("verified event file disappeared")
            return None
        if verified_files is not None and path in verified_files:
            facts = verified_files[path]
            if self._path_identity(path) == facts.get("identity"):
                return facts
            verified_files.pop(path, None)
        facts = self._assert_confirmed_event_file(path, ledger)
        if verified_files is not None:
            verified_files[path] = facts
        return facts

    def _assert_confirmed_event_file(
        self, path: Path, ledger: ControlLoopLedger
    ) -> dict[str, Any]:
        """Verify one accepted event-file prefix against ledger bytes.

        The returned facts are intentionally in-memory only.  They identify
        the verified file and its sequence range so a later incremental plan
        can reconstruct a snapshot without introducing a second persistent
        source of truth.
        """

        epoch = self._require_epoch()
        identity_before = self._path_identity(path)
        if identity_before is None:
            raise ArchiveConflictError("event file disappeared during verification")
        data = path.read_bytes()
        self._verification_counters["eventBytes"] += len(data)
        accepted = _accepted_prefix(data)
        records: list[tuple[bytes, Event]] = []
        seen_sequences: set[int] = set()
        seen_event_ids: set[str] = set()
        previous_sequence: int | None = None
        for line in accepted.splitlines():
            try:
                payload = json.loads(line)
                event = Event.model_validate(payload)
            except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
                raise ArchiveConflictError("event file has malformed accepted prefix") from exc
            if event.epoch_id != epoch.epoch_id:
                raise ArchiveConflictError("event file contains a conflicting epoch")
            if event.sequence in seen_sequences:
                raise ArchiveConflictError("event file contains a duplicate sequence")
            if previous_sequence is not None and event.sequence < previous_sequence:
                raise ArchiveConflictError("event file contains an out-of-order sequence")
            if event.event_id in seen_event_ids:
                raise ArchiveConflictError("event file contains a duplicate event ID")
            seen_sequences.add(event.sequence)
            seen_event_ids.add(event.event_id)
            previous_sequence = event.sequence
            records.append((line, event))

        sequences = [event.sequence for _, event in records]
        try:
            confirmed_events = ledger.events_at(sequences)
        except LedgerConflictError as exc:
            raise ArchiveConflictError(
                f"event file ledger verification failed: {exc}"
            ) from exc
        for line, event in records:
            confirmed = confirmed_events[event.sequence]
            if (
                _json_bytes(confirmed.model_dump(by_alias=True, mode="json")).rstrip(b"\n")
                != line
            ):
                raise ArchiveConflictError("event file contains an unconfirmed accepted prefix")

        try:
            relative_path = path.relative_to(self.events_root).as_posix()
        except ValueError:
            relative_path = path.as_posix()
        digest = sha256(accepted).hexdigest()
        self._verification_counters["eventHashes"] += 1
        identity_after = self._path_identity(path)
        if identity_after != identity_before:
            raise ArchiveConflictError("event file changed during verification")
        self._verification_counters["eventFiles"] += 1
        first_sequence = sequences[0] if sequences else None
        last_sequence = sequences[-1] if sequences else None
        return {
            "path": relative_path,
            "identity": identity_after,
            "sha256": digest,
            "byteSize": len(accepted),
            "eventCount": len(records),
            "sequences": sequences,
            "eventIds": [event.event_id for _, event in records],
            "sequenceStart": first_sequence,
            "sequenceEnd": last_sequence,
            "highWatermark": last_sequence,
        }


ArchiveWriter = ControlLoopArchive


__all__ = ["ArchiveConflictError", "ArchiveError", "ArchiveValidationError", "ArchiveWriter", "ControlLoopArchive"]

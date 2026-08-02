from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
import json
import os
import re
import subprocess  # nosec B404 - fixed Docker argv below
from typing import Any, Callable, Mapping

from .models import (
    PipelineCursorPhase,
    PipelinePhase,
    PipelineState,
    PipelineTrigger,
    TaskStatus,
    TERMINAL_STATUSES,
    DaemonLifecycleState,
    OwnedDockerUsage,
    ResourcePressure,
    ResourcePressureState,
    evaluate_resource_pressure,
)


class ResourcePressureController:
    """Measure exact owned usage and apply configured high/low hysteresis.

    The Docker callback is intentionally injected. Production supplies a
    label-filtered API implementation; tests can provide deterministic facts.
    No method scans Docker's data root or treats host-wide usage as owned.
    """

    def __init__(
        self,
        config: object,
        *,
        usage_provider: object | None = None,
        initial_state: ResourcePressureState = ResourcePressureState.normal,
    ):
        self.config = config
        self.usage_provider = usage_provider
        self.state = initial_state
        self.last = ResourcePressure(
            state=initial_state,
            admission_allowed=initial_state is ResourcePressureState.normal,
        )

    def measure(self) -> ResourcePressure:
        deployment = getattr(self.config, "deployment", None)
        if deployment is None or not getattr(deployment, "enabled", False):
            self.last = ResourcePressure()
            self.state = self.last.state
            return self.last
        home = getattr(self.config, "coquic_home", None)
        free_bytes: int | None = None
        if home is not None:
            try:
                info = os.statvfs(home)
                free_bytes = int(info.f_bavail * info.f_frsize)
            except OSError:
                free_bytes = None
        owned = OwnedDockerUsage(ambiguous=True)
        provider = self.usage_provider
        if callable(provider):
            try:
                value = provider()
                if isinstance(value, OwnedDockerUsage):
                    owned = value
                elif isinstance(value, Mapping):
                    owned = OwnedDockerUsage(
                        container_bytes=int(value.get("container_bytes", value.get("containerBytes", 0))),
                        image_bytes=int(value.get("image_bytes", value.get("imageBytes", 0))),
                        scratch_bytes=int(value.get("scratch_bytes", value.get("scratchBytes", 0))),
                        container_count=int(value.get("container_count", value.get("containerCount", 0))),
                        image_count=int(value.get("image_count", value.get("imageCount", 0))),
                        ambiguous=bool(value.get("ambiguous", False)),
                    )
            except Exception:
                owned = OwnedDockerUsage(ambiguous=True)
        minimum = getattr(deployment, "min_free_bytes", None)
        maximum = getattr(deployment, "max_owned_docker_bytes", None)
        recovery_free = getattr(deployment, "recovery_free_bytes", None)
        recovery_owned = getattr(deployment, "recovery_owned_docker_bytes", None)
        if None in (minimum, maximum, recovery_free, recovery_owned):
            self.last = ResourcePressure(ResourcePressureState.pressure, free_bytes, owned, "threshold_unconfigured", False)
        else:
            self.last = evaluate_resource_pressure(
                home_free_bytes=free_bytes,
                owned=owned,
                minimum_free_bytes=minimum,
                maximum_owned_bytes=maximum,
                recovery_free_bytes=recovery_free,
                recovery_owned_bytes=recovery_owned,
                previous=self.state,
            )
        self.state = self.last.state
        return self.last

    def admission_allowed(self) -> bool:
        return self.measure().admission_allowed

    def health(self) -> dict[str, Any]:
        return self.last.as_dict()


_DOCKER_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_DOCKER_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class DockerResourceManager:
    """Account and reconcile only exact label-owned Docker objects."""

    def __init__(
        self,
        docker_bin: str = "docker",
        *,
        deployment_id: str | None = None,
        runner: Callable[[list[str]], object] | None = None,
    ) -> None:
        self.docker_bin = docker_bin
        self.deployment_id = deployment_id
        self.runner = runner
        self._known_image_ids: frozenset[str] = frozenset()

    def owned_usage(self) -> OwnedDockerUsage:
        usage, _references, _images, _active_releases, _complete = self._snapshot(
            self._known_image_ids
        )
        return usage

    def reconcile(self, store: object, deployment: object) -> dict[str, object]:
        """Persist complete references and reclaim exact unreferenced images."""

        self.deployment_id = str(getattr(deployment, "compose_project", ""))
        release_images, in_flight_releases = self._record_deployment_releases(
            store, deployment
        )
        self._known_image_ids = frozenset(
            image_id for pair in release_images.values() for image_id in pair
        )
        usage, references, images, active_releases, complete = self._snapshot(
            self._known_image_ids
        )
        if not complete:
            return {"usage": usage, "reclaimed": (), "ambiguous": True}
        replace = getattr(store, "replace_container_references", None)
        if callable(replace):
            replace(references)
        retained_provider = getattr(store, "referenced_image_ids", None)
        retained = (
            frozenset(retained_provider())
            if callable(retained_provider)
            else frozenset()
        )
        retained = frozenset(
            {
                *retained,
                *(
                    image_id
                    for release_id in active_releases | in_flight_releases
                    for image_id in release_images.get(release_id, ())
                ),
            }
        )
        owned_ids = {str(item["image_id"]) for item in images}
        candidates = reclaimable_image_ids(
            owned_ids,
            retained=retained,
            steward_owned=owned_ids,
        )
        reclaimed: list[str] = []
        for image_id in sorted(candidates):
            result = self._run(["image", "rm", image_id])
            if int(getattr(result, "returncode", 1)) == 0:
                reclaimed.append(image_id)
        return {
            "usage": usage,
            "reclaimed": tuple(reclaimed),
            "ambiguous": usage.ambiguous,
        }

    def _snapshot(
        self, image_ids: frozenset[str]
    ) -> tuple[
        OwnedDockerUsage,
        list[dict[str, object]],
        list[dict[str, object]],
        frozenset[str],
        bool,
    ]:
        deployment_id = self.deployment_id
        if not deployment_id or "\n" in deployment_id:
            return OwnedDockerUsage(ambiguous=True), [], [], frozenset(), False
        try:
            container_ids = self._list_ids(
                [
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    "label=coquic.steward.owner=steward",
                    "--filter",
                    f"label=coquic.steward.deployment={deployment_id}",
                ],
                _DOCKER_CONTAINER_ID,
            )
            containers = self._inspect("container", container_ids, size=True)
            images = self._inspect_known_images(image_ids)
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
            return OwnedDockerUsage(ambiguous=True), [], [], frozenset(), False

        ambiguous = False
        container_bytes = 0
        references: list[dict[str, object]] = []
        active_releases: set[str] = set()
        for value in containers:
            labels = value.get("Config", {}).get("Labels", {})
            image_id = str(value.get("Image", ""))
            container_id = str(value.get("Id", ""))
            runtime = labels.get("coquic.steward.runtime")
            release = labels.get("coquic.steward.release")
            size = value.get("SizeRw")
            valid = (
                labels.get("coquic.steward.owner") == "steward"
                and labels.get("coquic.steward.deployment") == deployment_id
                and _DOCKER_CONTAINER_ID.fullmatch(container_id) is not None
                and _DOCKER_IMAGE_ID.fullmatch(image_id) is not None
                and isinstance(release, str)
                and bool(release)
                and runtime
                in {"task-container-v1", "planner-container-v1", "validation-container-v1", "daemon-compose-v1"}
                and isinstance(size, int)
                and size >= 0
            )
            if not valid:
                ambiguous = True
                continue
            container_bytes += size
            if runtime == "daemon-compose-v1":
                active_releases.add(release)
                continue
            epoch = labels.get("coquic.steward.epoch")
            task_id = labels.get("coquic.steward.task")
            planner = labels.get("coquic.steward.planner") == "true"
            if not isinstance(epoch, str) or not epoch or not (task_id or planner):
                ambiguous = True
                continue
            references.append(
                {
                    "container_id": container_id,
                    "task_id": str(task_id) if task_id else None,
                    "image_id": image_id,
                    "epoch_id": epoch,
                    "state": str(value.get("State", {}).get("Status", "unknown")),
                    "cleanup_status": "active",
                    "size_bytes": size,
                }
            )

        image_bytes = 0
        owned_images: list[dict[str, object]] = []
        for value in images:
            labels = value.get("Config", {}).get("Labels", {})
            image_id = str(value.get("Id", ""))
            size = value.get("Size")
            valid = (
                labels.get("coquic.steward.owner") == "steward"
                and labels.get("coquic.steward.runtime-protocol") == "task-container-v1"
                and _DOCKER_IMAGE_ID.fullmatch(image_id) is not None
                and isinstance(size, int)
                and size >= 0
            )
            if not valid:
                ambiguous = True
                continue
            image_bytes += size
            owned_images.append({"image_id": image_id, "size_bytes": size})
        usage = OwnedDockerUsage(
            container_bytes=container_bytes,
            image_bytes=image_bytes,
            container_count=len(references)
            + sum(
                1
                for value in containers
                if value.get("Config", {})
                .get("Labels", {})
                .get("coquic.steward.runtime")
                == "daemon-compose-v1"
            ),
            image_count=len(owned_images),
            ambiguous=ambiguous,
        )
        return usage, references, owned_images, frozenset(active_releases), True

    def _list_ids(self, argv: list[str], pattern: re.Pattern[str]) -> list[str]:
        result = self._run(argv)
        if int(getattr(result, "returncode", 1)) != 0:
            raise OSError("Docker object listing failed")
        values = sorted(set(self._stdout(result).splitlines()))
        if any(pattern.fullmatch(value) is None for value in values):
            raise ValueError("Docker returned an invalid exact identity")
        return values

    def _inspect(
        self, kind: str, identities: list[str], *, size: bool = False
    ) -> list[dict[str, Any]]:
        if not identities:
            return []
        argv = [kind, "inspect"]
        if size:
            argv.append("--size")
        argv.extend(identities)
        result = self._run(argv)
        if int(getattr(result, "returncode", 1)) != 0:
            raise OSError("Docker object inspection failed")
        value = json.loads(self._stdout(result))
        if not isinstance(value, list) or not all(
            isinstance(item, dict) for item in value
        ):
            raise ValueError("Docker inspection result is malformed")
        if {str(item.get("Id", "")) for item in value} != set(identities):
            raise ValueError("Docker inspection returned an unexpected identity")
        return value

    def _inspect_known_images(
        self, identities: frozenset[str]
    ) -> list[dict[str, Any]]:
        images: list[dict[str, Any]] = []
        for identity in sorted(identities):
            result = self._run(["image", "inspect", identity])
            if int(getattr(result, "returncode", 1)) != 0:
                error = getattr(result, "stderr", b"")
                text = (
                    error.decode("utf-8", "replace")
                    if isinstance(error, bytes)
                    else str(error)
                ).lower()
                if any(
                    marker in text
                    for marker in ("no such image", "no such object", "not found")
                ):
                    continue
                raise OSError("Docker image inspection failed")
            value = json.loads(self._stdout(result))
            if (
                not isinstance(value, list)
                or len(value) != 1
                or not isinstance(value[0], dict)
                or str(value[0].get("Id", "")) != identity
            ):
                raise ValueError("Docker image inspection returned an unexpected identity")
            images.append(value[0])
        return images

    def _run(self, argv: list[str]) -> object:
        command = [self.docker_bin, *argv]
        if self.runner is not None:
            return self.runner(command)
        return subprocess.run(  # nosec B603 - fixed Docker argv and validated IDs
            command,
            check=False,
            capture_output=True,
            timeout=10,
        )

    @staticmethod
    def _stdout(result: object) -> str:
        value = getattr(result, "stdout", b"")
        return (
            value.decode("utf-8", "strict") if isinstance(value, bytes) else str(value)
        )

    @staticmethod
    def _record_deployment_releases(
        store: object, deployment: object
    ) -> tuple[dict[str, tuple[str, ...]], frozenset[str]]:
        record_release = getattr(store, "record_image_release", None)
        deployment_dir = getattr(deployment, "deployment_dir", None)
        if not callable(record_release) or deployment_dir is None:
            return {}, frozenset()
        selected_releases: dict[str, str] = {}
        for selector in ("current", "previous"):
            selector_path = deployment_dir / selector
            if selector_path.is_file():
                selected_releases[selector] = selector_path.read_text(
                    encoding="utf-8"
                ).strip()
        release_images: dict[str, tuple[str, ...]] = {}
        release_dir = deployment_dir / "releases"
        for record_path in sorted(release_dir.glob("*.json")):
            value = json.loads(record_path.read_text(encoding="utf-8"))
            release_id = str(value.get("releaseId", ""))
            daemon_id = value.get("daemonImageId")
            task_id = value.get("taskImageId")
            validation_id = value.get("validationImageId")
            if (
                record_path.name != f"{release_id}.json"
                or value.get("runtimeProtocol") != "task-container-v1"
                or _DOCKER_IMAGE_ID.fullmatch(str(daemon_id)) is None
                or _DOCKER_IMAGE_ID.fullmatch(str(task_id)) is None
                or (validation_id is not None and _DOCKER_IMAGE_ID.fullmatch(str(validation_id)) is None)
            ):
                raise ValueError("deployment release record is incompatible")
            image_pair = (str(daemon_id), str(task_id))
            if validation_id is not None:
                image_pair = (*image_pair, str(validation_id))
            release_images[release_id] = image_pair
            record_release(
                release_id,
                daemon_image_id=str(daemon_id),
                task_image_id=str(task_id),
                validation_image_id=str(validation_id) if validation_id is not None else None,
                labels={"runtimeProtocol": "task-container-v1"},
                current=selected_releases.get("current") == release_id,
                previous=selected_releases.get("previous") == release_id,
            )
        if any(value not in release_images for value in selected_releases.values()):
            raise ValueError("deployment selector has no verified release record")
        in_flight: frozenset[str] = frozenset()
        journal_path = deployment_dir / "operation.journal"
        if journal_path.is_file():
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            if not isinstance(journal, dict):
                raise ValueError("deployment operation journal is malformed")
            if (
                journal.get("outcome") == "pending"
                and journal.get("phase") in {"build", "recreate"}
            ):
                candidate = journal.get("candidateRelease")
                if candidate is not None and not isinstance(candidate, str):
                    raise ValueError("deployment candidate release is malformed")
                if candidate in release_images:
                    in_flight = frozenset({candidate})
        return release_images, in_flight


def retained_image_ids(
    *,
    current: set[str] | frozenset[str] = frozenset(),
    previous: set[str] | frozenset[str] = frozenset(),
    ledger_references: set[str] | frozenset[str] = frozenset(),
    container_references: set[str] | frozenset[str] = frozenset(),
) -> frozenset[str]:
    """Return image IDs protected by any recovery or deployment reference."""

    return frozenset({*current, *previous, *ledger_references, *container_references})


def reclaimable_image_ids(
    image_ids: set[str] | frozenset[str],
    *,
    retained: set[str] | frozenset[str],
    steward_owned: set[str] | frozenset[str],
) -> frozenset[str]:
    """Select only exact owned IDs absent from every retention source."""

    return frozenset(set(image_ids) & set(steward_owned) - set(retained))


class TaskPhase(StrEnum):
    dispatch = "dispatch"
    implementation_plan = "implementation_plan"
    worker = "worker"
    validation = "validation"
    review = "review"
    integration = "integration"
    terminal = "terminal"
    recovery = "recovery"


class ReconciliationDisposition(StrEnum):
    adopted = "adopted"
    resumed = "resumed"
    interrupted = "interrupted"
    blocked = "blocked"
    ingested = "ingested"
    cleaned = "cleaned"
    unchanged = "unchanged"


@dataclass(frozen=True)
class ReconciliationOutcome:
    task_id: str
    disposition: ReconciliationDisposition | str
    detail: str = ""
    run_id: str | None = None
    container_id: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "disposition": str(self.disposition),
            "detail": self.detail[:256],
            "run_id": self.run_id,
            "container_id": self.container_id,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class ShutdownResult:
    state: DaemonLifecycleState = DaemonLifecycleState.stopped
    forced: bool = False
    interrupted_runs: int = 0
    stopped_containers: int = 0


@dataclass(frozen=True)
class SyncScheduleState:
    next_due_monotonic: float | None = None
    cycle_active: bool = False
    pending_tick: bool = False
    final_attempted: bool = False


@dataclass(frozen=True)
class TaskTransition:
    status: TaskStatus
    summary: str
    phase: TaskPhase


class InvalidTaskTransition(ValueError):
    def __init__(self, current: TaskStatus, transition: TaskTransition):
        super().__init__(
            f"invalid task transition {current.value} -> "
            f"{transition.status.value} ({transition.phase.value})"
        )
        self.current = current
        self.transition = transition


@dataclass(frozen=True)
class PhaseInput:
    """Immutable input identity captured before a phase has side effects."""

    task_id: str
    pipeline_id: str
    action_id: str
    phase: PipelineCursorPhase | str
    base_identity: str | None = None
    input_identity: str | None = None
    patch_identity: str | None = None
    expected_tree: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "pipeline_id": self.pipeline_id,
            "action_id": self.action_id,
            "phase": str(self.phase),
            "base_identity": self.base_identity,
            "input_identity": self.input_identity,
            "patch_identity": self.patch_identity,
            "expected_tree": self.expected_tree,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class PhaseOutput:
    """Result identity captured after a phase action completes."""

    action_id: str
    phase: PipelineCursorPhase | str
    next_phase: PipelineCursorPhase | str | None
    state: PipelineState | str = PipelineState.active
    output_identity: str | None = None
    patch_identity: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "phase": str(self.phase),
            "next_phase": str(self.next_phase) if self.next_phase is not None else None,
            "state": str(self.state),
            "output_identity": self.output_identity,
            "patch_identity": self.patch_identity,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class AdvanceResult:
    """Outcome of one claimed durable pipeline action."""

    task_id: str
    pipeline_id: str
    phase: PipelineCursorPhase | str
    next_phase: PipelineCursorPhase | str | None
    status: str
    action_id: str | None = None
    progressed: bool = False
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PipelineTransition:
    current: PipelineCursorPhase | str
    target: PipelineCursorPhase | str
    trigger: PipelineTrigger | str = PipelineTrigger.initial


class InvalidPipelineTransition(ValueError):
    def __init__(self, transition: PipelineTransition):
        super().__init__(
            f"invalid pipeline transition {transition.current!s} -> "
            f"{transition.target!s} ({transition.trigger!s})"
        )
        self.transition = transition


_PIPELINE_TRANSITIONS: dict[PipelineCursorPhase, frozenset[PipelineCursorPhase]] = {
    PipelineCursorPhase.provisioned: frozenset(
        {
            PipelineCursorPhase.planning,
            PipelineCursorPhase.implementation,
            PipelineCursorPhase.validation,
        }
    ),
    PipelineCursorPhase.planning: frozenset({PipelineCursorPhase.implementation}),
    PipelineCursorPhase.implementation: frozenset(
        {PipelineCursorPhase.validation, PipelineCursorPhase.ready_to_seal}
    ),
    PipelineCursorPhase.validation: frozenset(
        {PipelineCursorPhase.review, PipelineCursorPhase.repair}
    ),
    PipelineCursorPhase.review: frozenset(
        {PipelineCursorPhase.formality, PipelineCursorPhase.integration, PipelineCursorPhase.repair}
    ),
    PipelineCursorPhase.formality: frozenset(
        {PipelineCursorPhase.integration, PipelineCursorPhase.repair}
    ),
    PipelineCursorPhase.repair: frozenset({PipelineCursorPhase.implementation}),
    PipelineCursorPhase.integration: frozenset({PipelineCursorPhase.commit_message}),
    PipelineCursorPhase.commit_message: frozenset({PipelineCursorPhase.commit}),
    PipelineCursorPhase.commit: frozenset({PipelineCursorPhase.push, PipelineCursorPhase.ready_to_seal}),
    PipelineCursorPhase.push: frozenset({PipelineCursorPhase.ready_to_seal}),
    PipelineCursorPhase.ready_to_seal: frozenset(),
}


def pipeline_transition_allowed(
    current: PipelineCursorPhase | str,
    target: PipelineCursorPhase | str,
    *,
    trigger: PipelineTrigger | str = PipelineTrigger.initial,
) -> bool:
    try:
        source = PipelineCursorPhase(current)
        destination = PipelineCursorPhase(target)
        selected_trigger = PipelineTrigger(trigger)
    except ValueError:
        return False
    if source == destination:
        return True
    # A trigger describes why a child pipeline exists; it does not replace the
    # child's normal phase graph. Trigger-specific repair edges are already
    # represented in the graph and every child must be able to validate and
    # review its implementation.
    _ = selected_trigger
    return destination in _PIPELINE_TRANSITIONS.get(source, frozenset())


def require_pipeline_transition(
    current: PipelineCursorPhase | str,
    target: PipelineCursorPhase | str,
    *,
    trigger: PipelineTrigger | str = PipelineTrigger.initial,
) -> None:
    transition = PipelineTransition(current, target, trigger)
    if not pipeline_transition_allowed(current, target, trigger=trigger):
        raise InvalidPipelineTransition(transition)


def coarse_phase(phase: PipelineCursorPhase | str) -> PipelinePhase:
    """Map a fine cursor to the compatibility phase persisted by Plan 002."""

    selected = PipelineCursorPhase(phase)
    if selected in {PipelineCursorPhase.provisioned, PipelineCursorPhase.planning}:
        return PipelinePhase.planning
    if selected in {PipelineCursorPhase.implementation, PipelineCursorPhase.repair}:
        return PipelinePhase.implementation
    if selected == PipelineCursorPhase.validation:
        return PipelinePhase.validation
    if selected in {PipelineCursorPhase.review, PipelineCursorPhase.formality}:
        return PipelinePhase.review
    if selected in {
        PipelineCursorPhase.integration,
        PipelineCursorPhase.commit_message,
        PipelineCursorPhase.commit,
        PipelineCursorPhase.push,
    }:
        return PipelinePhase.integration
    return PipelinePhase.complete


def action_identity(task_id: str, pipeline_id: str, phase: PipelineCursorPhase | str) -> str:
    try:
        selected = PipelineCursorPhase(phase).value
    except ValueError:
        selected = str(phase)
    return f"{task_id}:{pipeline_id}:{selected}"


def bounded_fingerprint(*values: Any, limit: int = 128) -> str:
    """Return a stable, bounded fingerprint suitable for no-progress guards."""

    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8", errors="replace")).hexdigest()[:limit]


def worker_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.worker)


def implementation_plan_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.implementation_plan)


def validation_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.validation)


def review_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.reviewing, summary, TaskPhase.review)


def integration_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.integrating, summary, TaskPhase.integration)


def terminal_status(status: TaskStatus, summary: str) -> TaskTransition:
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"{status.value} is not terminal")
    return TaskTransition(status, summary, TaskPhase.terminal)


def recovery_failed(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.failed, summary, TaskPhase.recovery)


def transition_allowed(current: TaskStatus, transition: TaskTransition) -> bool:
    target = transition.status
    if current in TERMINAL_STATUSES:
        return current == target
    if target in TERMINAL_STATUSES:
        return current != TaskStatus.queued or transition.phase in {
            TaskPhase.dispatch,
            TaskPhase.terminal,
        }
    if current == TaskStatus.queued:
        return target in {TaskStatus.running, TaskStatus.integrating}
    if current == TaskStatus.running:
        return target in {
            TaskStatus.running,
            TaskStatus.reviewing,
            TaskStatus.integrating,
        }
    if current == TaskStatus.reviewing:
        return target in {TaskStatus.running, TaskStatus.reviewing, TaskStatus.integrating}
    if current == TaskStatus.integrating:
        return target in {TaskStatus.running, TaskStatus.integrating}
    return False


def require_transition_allowed(
    current: TaskStatus, transition: TaskTransition
) -> None:
    if not transition_allowed(current, transition):
        raise InvalidTaskTransition(current, transition)

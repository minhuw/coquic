"""Private Codex session allocation and exact-ID recovery primitives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import signal
import threading
import time
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Protocol

from ..agents.invocation import (
    InvocationOutcome,
    InvocationRequest,
    launch_local,
    stream_process,
)
from ..core.config import StewardConfig
from ..core.models import (
    CodexRunState,
    CodexSession,
    CodexStage,
    TaskRecord,
    TaskRun,
    TaskStatus,
    WorkerResult,
)
from ..core.subprocesses import run_command
from ..storage import TaskStore
from .container import (
    ContainerBoundaryError,
    ContainerErrorCategory,
    ExecIdentity,
    TaskContainerRuntime,
    PlannerContainerRuntime,
)
from .container_config import PlannerContainerConfig, TaskContainerConfig, TaskRole
from .task_archive import ArchiveError, TaskArchiveWriter
from .worktree import Worktrees


class ResumeCategory(StrEnum):
    missing_provider_id = "missing-provider-id"
    unavailable_store = "unavailable-store"
    corrupt_store = "corrupt-store"
    incompatible_cli = "incompatible-cli"
    checkpoint_drift = "checkpoint-drift"
    identity_mismatch = "identity-mismatch"
    rejected = "rejected"
    transient_provider = "transient-provider"
    success = "success"


class InvocationStatus(StrEnum):
    succeeded = "succeeded"
    failed = "failed"
    interrupted = "interrupted"
    forced = "forced"
    unavailable = "unavailable"


@dataclass(frozen=True)
class FreshPlannerRequest:
    """Private identity allocated for one global scheduler-planner process."""

    run_id: str
    session_id: str
    home: Path
    request: InvocationRequest

    @property
    def resumed(self) -> bool:
        return self.request.provider_session_id is not None


@dataclass(frozen=True)
class FreshPlannerResult:
    request: FreshPlannerRequest
    outcome: InvocationOutcome | None
    status: InvocationStatus
    prompt_path: Path
    transcript_path: Path
    last_message_path: Path


def build_fresh_planner_request(
    config: StewardConfig,
    *,
    run_id: str,
    prompt: str,
    output_last_message: Path | None = None,
    output_schema: Path | None = None,
    history_root: Path | None = None,
    model: str | None = None,
    reasoning_effort: str | None = None,
) -> FreshPlannerRequest:
    """Build a planner request with no provider-session or resume argument."""

    safe_run = re.sub(r"[^A-Za-z0-9_.-]", "-", run_id).strip("-") or "planner"
    session_id = f"planner-session-{secrets.token_hex(10)}"
    home = config.private_sessions_dir / "planner" / safe_run / session_id
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    session_uid = 10000 + int(hashlib.sha256(session_id.encode("ascii")).hexdigest()[:4], 16) % 50001
    try:
        os.chown(home, session_uid, session_uid)
    except PermissionError:
        if not config.local_codex_test_harness:
            raise
    selected_last_message = output_last_message or home / "last-message.md"
    selected_schema = output_schema
    if output_schema is not None:
        selected_schema = home / "output-schema.json"
        selected_schema.write_bytes(output_schema.read_bytes())
        try:
            os.chown(selected_schema, session_uid, session_uid)
        except PermissionError:
            if not config.local_codex_test_harness:
                raise
    # The Codex process receives a clean private home.  Sealed history is
    # mounted by the planner container runtime; it is intentionally absent
    # from the request's host cwd and environment.
    request = InvocationRequest(
        codex_bin=config.codex_bin,
        cwd=history_root or config.private_sessions_dir,
        prompt=prompt,
        output_last_message=selected_last_message,
        stage=CodexStage.signal_planner,
        model=model,
        reasoning_effort=reasoning_effort,
        output_schema=selected_schema,
        sandbox="read-only",
        provider_session_id=None,
        role="planner",
        session_uid=session_uid,
        session_id=session_id,
        run_id=run_id,
    )
    return FreshPlannerRequest(run_id=run_id, session_id=session_id, home=home, request=request)


class FreshPlannerSession:
    """One-shot global planner boundary; every call allocates new identities."""

    def __init__(self, config: StewardConfig, *, invoker: SessionInvoker | None = None):
        self.config = config
        self.invoker = invoker or LocalSessionInvoker()
        self._interrupt_requested = threading.Event()

    def allocate(
        self,
        run_id: str,
        *,
        prompt: str,
        output_last_message: Path | None = None,
        output_schema: Path | None = None,
        history_root: Path | None = None,
    ) -> FreshPlannerRequest:
        settings = self.config.codex_settings(CodexStage.signal_planner)
        return build_fresh_planner_request(
            self.config,
            run_id=run_id,
            prompt=prompt,
            output_last_message=output_last_message,
            output_schema=output_schema,
            history_root=history_root,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
        )

    def run(
        self,
        run_id: str,
        *,
        prompt: str,
        output_last_message: Path | None = None,
        output_schema: Path | None = None,
        history_root: Path | None = None,
        api_key: bytes | str | None = None,
        timeout_seconds: float = 1800,
    ) -> FreshPlannerResult:
        request = self.allocate(
            run_id,
            prompt=prompt,
            output_last_message=output_last_message,
            output_schema=output_schema,
            history_root=history_root,
        )
        prompt_path = request.home / "prompt.md"
        transcript_path = request.home / "codex.jsonl"
        prompt_path.write_text(prompt, encoding="utf-8")

        def append(value: bytes) -> None:
            with transcript_path.open("ab") as handle:
                handle.write(value)

        if self._interrupt_requested.is_set():
            outcome = InvocationOutcome(
                exit_code=130,
                stdout=b"",
                stderr=b"",
                incomplete_suffix=b"",
                events=(),
                provider_session_id=None,
                interrupted=True,
            )
        else:
            outcome = self.invoker.invoke(
                request.request,
                api_key=api_key,
                append=append,
                timeout_seconds=timeout_seconds,
                interrupt_grace_seconds=2.0,
            )
        if self._interrupt_requested.is_set() and not outcome.completed:
            outcome = replace(outcome, interrupted=True)
        status = (
            InvocationStatus.succeeded
            if outcome.completed
            else InvocationStatus.interrupted
            if outcome.interrupted
            else InvocationStatus.failed
        )
        return FreshPlannerResult(
            request=request,
            outcome=outcome,
            status=status,
            prompt_path=prompt_path,
            transcript_path=transcript_path,
            last_message_path=request.request.output_last_message,
        )

    def interrupt(self, *, force: bool = False) -> None:
        self._interrupt_requested.set()
        interrupt = getattr(self.invoker, "interrupt", None)
        if callable(interrupt):
            interrupt(force=force)


def planner_session_for_config(config: StewardConfig) -> FreshPlannerSession:
    """Build the daemon-owned isolated scheduler-planner boundary."""

    if not config.task_image_digest:
        raise ValueError("task_image_digest must be configured for production planning")
    history = config.control_loop_dir / "planner-runs"
    private = config.private_sessions_dir / "planner"
    output = config.private_dir / "planner-output"
    for path in (history, private, output):
        path.mkdir(parents=True, exist_ok=True)
    private.chmod(0o711)
    output.chmod(0o711)
    runtime = PlannerContainerRuntime(
        PlannerContainerConfig(
            image=config.task_image,
            image_digest=config.task_image_digest,
            history_root=history,
            private_root=private,
            output_root=output,
        )
    )
    return FreshPlannerSession(config, invoker=ContainerSessionInvoker(runtime))


@dataclass(frozen=True)
class SessionResult:
    task_id: str
    pipeline_id: str
    session_id: str
    run_id: str
    status: InvocationStatus
    exit_code: int
    provider_session_id: str | None
    transcript_path: Path
    last_message_path: Path
    incomplete_suffix: bytes = b""
    diagnostics: dict[str, Any] | None = None


@dataclass(frozen=True)
class ResumeResult:
    category: ResumeCategory
    result: SessionResult | None = None
    evidence: dict[str, Any] | None = None


@dataclass(frozen=True)
class RecoveryPacket:
    predecessor_run_id: str
    role: str
    task_intent: str
    accepted_plan: dict[str, Any] | None
    transcript_descriptor: str | None
    diff_descriptor: str | None
    inline_tail: str
    interruption: dict[str, Any]
    tree_identity: str | None = None
    worktree_identity: str | None = None
    current_diff: str = ""

    def prompt(self) -> str:
        value = {
            "recovery": {
                "role": self.role,
                "task_intent": self.task_intent,
                "accepted_plan": self.accepted_plan,
                "transcript": self.transcript_descriptor,
                "diff": self.diff_descriptor,
                "tree_identity": self.tree_identity,
                "worktree_identity": self.worktree_identity,
                "current_diff": self.current_diff[-4000:],
                "tail": self.inline_tail[-4000:],
                "interruption": self.interruption,
            }
        }
        return _redact_recovery_text(
            json.dumps(value, sort_keys=True, ensure_ascii=True)
        )


@dataclass(frozen=True)
class InspectionResult:
    run_id: str
    live: bool
    container: Any = None
    identity: ExecIdentity | None = None


@dataclass(frozen=True)
class InterruptionResult:
    run_id: str
    status: InvocationStatus
    forced: bool
    exit_code: int | None
    suffix: bytes = b""


class SessionInvoker(Protocol):
    def invoke(
        self,
        request: InvocationRequest,
        *,
        api_key: bytes | str | None,
        append: Any,
        observe: Any = None,
        on_started: Any = None,
        timeout_seconds: float,
        interrupt_grace_seconds: float,
    ) -> InvocationOutcome: ...


class LocalSessionInvoker:
    """Explicit unit-test harness; never selected by production construction."""

    def invoke(
        self,
        request: InvocationRequest,
        *,
        api_key: bytes | str | None,
        append: Any,
        observe: Any = None,
        on_started: Any = None,
        timeout_seconds: float,
        interrupt_grace_seconds: float,
    ) -> InvocationOutcome:
        process = launch_local(request, api_key=api_key)
        self.process = process
        if on_started is not None:
            on_started(
                ExecIdentity(
                    "local",
                    request.run_id or "local",
                    process.pid,
                    request.session_uid,
                )
            )
        try:
            return stream_process(
                process,
                request,
                append=append,
                observe=observe,
                timeout_seconds=timeout_seconds,
                interrupt_grace_seconds=interrupt_grace_seconds,
            )
        finally:
            self.process = None

    def interrupt(self, *, force: bool = False) -> None:
        process = getattr(self, "process", None)
        if process is None:
            return
        if force:
            process.kill()
        else:
            process.send_signal(signal.SIGTERM)


class ContainerSessionInvoker:
    """Trusted wrapper invocation through the reusable task container."""

    def __init__(self, runtime: TaskContainerRuntime):
        self.runtime = runtime
        self.process = None

    def invoke(
        self,
        request: InvocationRequest,
        *,
        api_key: bytes | str | None,
        append: Any,
        observe: Any = None,
        on_started: Any = None,
        timeout_seconds: float,
        interrupt_grace_seconds: float,
    ) -> InvocationOutcome:
        if request.session_uid is None or request.session_id is None or request.run_id is None:
            raise ValueError("container invocation requires session and run identities")
        role = TaskRole(request.role)
        self.runtime.ensure_started()
        path_mapper = lambda path: self.runtime.config.container_path(path, role)
        process = self.runtime.exec_stream(
            role,
            session_uid=request.session_uid,
            session_id=request.session_id,
            command=[
                "/bin/task-entrypoint.sh",
                "run",
                *request.argv(codex_bin="codex", path_mapper=path_mapper),
            ],
            env={"COQUIC_STEWARD_RUN_ID": request.run_id},
            workdir=path_mapper(request.cwd),
        )
        # The wrapper consumes this control prefix before forwarding the prompt
        # to Codex.  It is never part of stdout, argv, environment, or logs.
        if process.stdin is not None:
            key = _api_key_bytes(api_key)
            process.stdin.write(len(key).to_bytes(4, "big") + key)
            process.stdin.flush()
        identity = self._identity(request, process)
        self.identity = identity
        supervised_process = _ContainerProcess(process, self.runtime, identity)
        self.process = supervised_process
        if on_started is not None:
            on_started(identity)
        try:
            return stream_process(
                supervised_process,
                request,
                append=append,
                observe=observe,
                timeout_seconds=timeout_seconds,
                interrupt_grace_seconds=interrupt_grace_seconds,
            )
        finally:
            self.process = None

    def _identity(self, request: InvocationRequest, process: Any) -> ExecIdentity:
        pid_path = request.output_last_message.parent / f"wrapper-{request.run_id}.pid"
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                pid = int(pid_path.read_text(encoding="ascii").strip())
            except (FileNotFoundError, ValueError, OSError):
                if process.poll() is not None:
                    break
                time.sleep(0.01)
                continue
            if pid > 1:
                return ExecIdentity(
                    self.runtime.config.container_name,
                    request.run_id or "",
                    pid,
                    request.session_uid,
                )
            break
        raise RuntimeError("trusted wrapper did not publish a valid process identity")

    def interrupt(self, *, force: bool = False) -> None:
        process = self.process
        if process is not None:
            process.kill() if force else process.send_signal(signal.SIGTERM)


class _ContainerProcess:
    """Stream a Docker exec while signaling the validated in-container PID."""

    def __init__(
        self,
        process: Any,
        runtime: TaskContainerRuntime,
        identity: ExecIdentity,
    ) -> None:
        self._process = process
        self._runtime = runtime
        self._identity = identity
        self.stdin = process.stdin
        self.stdout = process.stdout
        self.stderr = process.stderr

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._process.wait(timeout=timeout)

    def send_signal(self, sig: int) -> None:
        self._runtime.signal(self._identity, sig)

    def kill(self) -> None:
        self._runtime.signal(self._identity, signal.SIGKILL)


class SessionSupervisor:
    """Own session/run allocation and process lifecycle inside one task home."""

    def __init__(
        self,
        config: StewardConfig,
        store: TaskStore,
        *,
        runtime: TaskContainerRuntime | None = None,
        runtime_factory: Callable[[TaskRecord], TaskContainerRuntime] | None = None,
        archive: TaskArchiveWriter | None = None,
        invoker: SessionInvoker | None = None,
        image_digest: str | None = None,
        codex_identity: str | None = None,
        provider_store_identity: str | None = None,
        runtime_identity: str = "task-runtime-v1",
        require_boundary: bool = True,
    ):
        if require_boundary and runtime is None and runtime_factory is None and invoker is None:
            raise ValueError(
                "SessionSupervisor requires an injected task-container runtime"
            )
        self.config = config
        self.store = store
        self.runtime = runtime
        self.runtime_factory = runtime_factory
        self.archive = archive or TaskArchiveWriter(config)
        self.invoker = invoker or (ContainerSessionInvoker(runtime) if runtime is not None else None)
        self._runtimes: dict[str, TaskContainerRuntime] = {}
        self._invokers: dict[str, SessionInvoker] = {}
        self.image_digest = image_digest or getattr(config, "task_image_digest", None)
        self.codex_identity = codex_identity or getattr(config, "codex_identity", None)
        self.provider_store_identity = provider_store_identity or "codex-sessions-v1"
        self.runtime_identity = runtime_identity
        self._active: dict[str, Any] = {}
        self._active_lock = threading.RLock()

    def start(
        self,
        task_id: str,
        pipeline_id: str,
        *,
        role: TaskRole | str,
        prompt: str,
        cwd: Path,
        api_key: bytes | str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        output_schema: Path | None = None,
        stage: CodexStage = CodexStage.code,
        checkpoint_id: str | None = None,
        image_digest: str | None = None,
        codex_identity: str | None = None,
        idempotency_key: str | None = None,
        retry_of_run_id: str | None = None,
        timeout_seconds: float | None = None,
        sandbox: str | None = None,
        run_id: str | None = None,
    ) -> SessionResult:
        selected_role = _normalize_role(role)
        api_key = self._configured_api_key(api_key)
        task = self.store.get(task_id)
        runtime, invoker = self._boundary_for(task)
        pipeline = self.store.get_pipeline(pipeline_id)
        if pipeline.task_id != task_id:
            raise ValueError("session pipeline does not belong to task")
        selected_image = image_digest or self.image_digest
        if not selected_image:
            raise ValueError("a resolved task image digest is required")
        selected_codex = codex_identity or self.codex_identity or self.config.codex_bin
        session, run = self._allocate(
            task,
            pipeline_id,
            selected_role,
            cwd=cwd,
            checkpoint_id=checkpoint_id,
            image_digest=selected_image,
            codex_identity=selected_codex,
            idempotency_key=idempotency_key,
            retry_of_run_id=retry_of_run_id,
            model=model,
            reasoning_effort=reasoning_effort,
            run_id=run_id,
        )
        request = InvocationRequest(
            codex_bin=self.config.codex_bin,
            cwd=cwd,
            prompt=prompt,
            output_last_message=self._private_last_message_path(session, run.id),
            stage=stage,
            model=model,
            reasoning_effort=reasoning_effort,
            output_schema=self._copy_private_schema(session, run.id, output_schema),
            sandbox=sandbox or self.config.codex_sandbox,
            role=selected_role,
            session_uid=session.home_uid,
            session_id=session.id,
            run_id=run.id,
        )
        return self._execute(
            task,
            session,
            run,
            request,
            runtime=runtime,
            invoker=invoker,
            api_key=api_key,
            timeout_seconds=timeout_seconds
            or self._timeout_seconds(stage),
        )

    def resume(
        self,
        predecessor_run_id: str,
        *,
        prompt: str,
        api_key: bytes | str | None = None,
        image_digest: str | None = None,
        codex_identity: str | None = None,
        cwd: Path | None = None,
        checkpoint_id: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        output_schema: Path | None = None,
        timeout_seconds: float | None = None,
    ) -> ResumeResult:
        api_key = self._configured_api_key(api_key)
        try:
            predecessor = self.store.get_run(predecessor_run_id)
            session = self.store.get_session(predecessor.session_id)
        except KeyError as exc:
            return ResumeResult(ResumeCategory.unavailable_store, evidence={"error": str(exc)})
        if predecessor.state != CodexRunState.interrupted.value:
            return ResumeResult(ResumeCategory.rejected, evidence={"reason": "predecessor is not interrupted"})
        if predecessor.role not in {"planner", "planning", "implementation", "reviewer", "review"}:
            return ResumeResult(ResumeCategory.rejected, evidence={"reason": "role is not resumable"})
        if not session.provider_session_id:
            return ResumeResult(ResumeCategory.missing_provider_id)
        if not session.private_home_path or not session.private_home_path.exists():
            return ResumeResult(ResumeCategory.unavailable_store, evidence={"reason": "private home missing"})
        store_path = session.private_home_path / "sessions"
        if not store_path.exists() or not store_path.is_dir():
            return ResumeResult(ResumeCategory.corrupt_store, evidence={"reason": "session store missing"})
        if not any(store_path.iterdir()):
            return ResumeResult(ResumeCategory.corrupt_store, evidence={"reason": "session store is empty"})
        expected_image = image_digest or self.image_digest
        if expected_image and session.image_digest and expected_image != session.image_digest:
            return ResumeResult(ResumeCategory.identity_mismatch, evidence={"field": "image_digest"})
        expected_codex = codex_identity or self.codex_identity or self.config.codex_bin
        if session.codex_identity and expected_codex != session.codex_identity:
            return ResumeResult(ResumeCategory.incompatible_cli, evidence={"field": "codex_identity"})
        expected_cwd = cwd or session.cwd
        if expected_cwd is None:
            return ResumeResult(ResumeCategory.identity_mismatch, evidence={"field": "cwd"})
        if session.cwd is not None and Path(expected_cwd).resolve() != session.cwd.resolve():
            return ResumeResult(ResumeCategory.checkpoint_drift, evidence={"field": "cwd"})
        if not _is_unambiguous_checkpoint(checkpoint_id):
            return ResumeResult(
                ResumeCategory.checkpoint_drift,
                evidence={
                    "field": "checkpoint_id",
                    "reason": "an exact current checkpoint is required",
                },
            )
        if not _is_unambiguous_checkpoint(session.checkpoint_id):
            return ResumeResult(
                ResumeCategory.checkpoint_drift,
                evidence={
                    "field": "checkpoint_id",
                    "reason": "the persisted checkpoint is unavailable",
                },
            )
        if session.checkpoint_id != checkpoint_id:
            return ResumeResult(
                ResumeCategory.checkpoint_drift,
                evidence={"field": "checkpoint_id", "reason": "checkpoint mismatch"},
            )
        if session.checkpoint_id == session.idempotency_key:
            return ResumeResult(
                ResumeCategory.checkpoint_drift,
                evidence={
                    "field": "checkpoint_id",
                    "reason": "a phase action is not a worktree checkpoint",
                },
            )
        if session.checkpoint_id.startswith("worktree-v1-"):
            try:
                current_checkpoint = worktree_checkpoint(self.config, Path(expected_cwd))
            except (OSError, RuntimeError):
                return ResumeResult(
                    ResumeCategory.checkpoint_drift,
                    evidence={
                        "field": "checkpoint_id",
                        "reason": "current worktree checkpoint is unavailable",
                    },
                )
            if current_checkpoint != session.checkpoint_id:
                return ResumeResult(
                    ResumeCategory.checkpoint_drift,
                    evidence={
                        "field": "checkpoint_id",
                        "reason": "worktree changed after interruption",
                    },
                )
        try:
            existing = next(
                (
                    candidate
                    for candidate in self.store.list_runs(predecessor.task_id, pipeline_id=predecessor.pipeline_id)
                    if candidate.resume_of_run_id == predecessor.id
                ),
                None,
            )
            if existing is not None:
                retries = [
                    candidate
                    for candidate in self.store.list_runs(
                        predecessor.task_id,
                        pipeline_id=predecessor.pipeline_id,
                    )
                    if candidate.retry_of_run_id == existing.id
                ]
                latest = retries[-1] if retries else existing
                if latest.state == CodexRunState.succeeded.value:
                    return ResumeResult(
                        ResumeCategory.success,
                        result=self._persisted_session_result(latest),
                    )
                if latest.state == CodexRunState.running.value:
                    return ResumeResult(
                        ResumeCategory.rejected,
                        evidence={"reason": "resume attempt is already running"},
                    )
                if retries:
                    return ResumeResult(
                        ResumeCategory.transient_provider,
                        result=self._persisted_session_result(latest),
                        evidence={"reason": "resume attempts exhausted"},
                    )
                run = self.store.create_run(
                    predecessor.task_id,
                    predecessor.pipeline_id,
                    predecessor.session_id,
                    role=predecessor.role,
                    parent_run_id=existing.id,
                    retry_of_run_id=existing.id,
                    idempotency_key=f"resume-retry:{predecessor.id}",
                    model=model or predecessor.model,
                    reasoning=reasoning_effort or predecessor.reasoning,
                    image_version=session.image_digest,
                    runtime_version=self.runtime_identity,
                    checkpoint_id=session.checkpoint_id,
                    provider_store_identity=session.provider_store_identity,
                )
            else:
                run = self.store.create_run(
                    predecessor.task_id,
                    predecessor.pipeline_id,
                    predecessor.session_id,
                    role=predecessor.role,
                    resume_of_run_id=predecessor.id,
                    model=model or predecessor.model,
                    reasoning=reasoning_effort or predecessor.reasoning,
                    image_version=session.image_digest,
                    runtime_version=self.runtime_identity,
                    checkpoint_id=session.checkpoint_id,
                    provider_store_identity=session.provider_store_identity,
                )
        except (ValueError, KeyError) as exc:
            return ResumeResult(ResumeCategory.rejected, evidence={"error": str(exc)})
        request = InvocationRequest(
            codex_bin=self.config.codex_bin,
            cwd=Path(expected_cwd),
            prompt=prompt,
            output_last_message=self._private_last_message_path(session, run.id),
            stage=CodexStage.review if predecessor.role in {"review", "reviewer"} else CodexStage.code,
            model=model or predecessor.model,
            reasoning_effort=reasoning_effort or predecessor.reasoning,
            output_schema=self._copy_private_schema(session, run.id, output_schema),
            provider_session_id=session.provider_session_id,
            role=_runtime_role(predecessor.role),
            session_uid=session.home_uid,
            session_id=session.id,
            run_id=run.id,
        )
        task = self.store.get(predecessor.task_id)
        runtime, invoker = self._boundary_for(task)
        result = self._execute(
            task,
            session,
            run,
            request,
            runtime=runtime,
            invoker=invoker,
            api_key=api_key,
            timeout_seconds=timeout_seconds or self._timeout_seconds(request.stage),
        )
        return ResumeResult(
            ResumeCategory.success
            if result.status is InvocationStatus.succeeded
            else ResumeCategory.transient_provider,
            result=result,
        )

    def resume_with_retries(
        self,
        predecessor_run_id: str,
        *,
        prompt: str,
        max_attempts: int = 2,
        **kwargs: Any,
    ) -> ResumeResult:
        """Attempt explicit-ID resume at most twice for transient failures."""

        attempts = max(1, min(2, int(max_attempts)))
        last: ResumeResult | None = None
        for ordinal in range(attempts):
            last = self.resume(predecessor_run_id, prompt=prompt, **kwargs)
            if last.category is not ResumeCategory.transient_provider:
                return last
            if ordinal + 1 < attempts:
                self.store.add_event(
                    self.store.get_run(predecessor_run_id).task_id,
                    "session.resume_retry",
                    "transient provider resume failure",
                    {"attempt": ordinal + 1, "max_attempts": attempts},
                )
        return last or ResumeResult(ResumeCategory.unavailable_store)

    def build_recovery_packet(self, predecessor_run_id: str) -> RecoveryPacket:
        predecessor = self.store.get_run(predecessor_run_id)
        task = self.store.get(predecessor.task_id)
        session = self.store.get_session(predecessor.session_id)
        transcript: Path | None = None
        try:
            transcript = self.archive.run_transcript_path(task.id, predecessor.id)
        except Exception:
            transcript = None
        if transcript is None or not transcript.exists():
            transcript = task.transcript_path
        tail = ""
        if transcript is not None and transcript.exists():
            try:
                tail = transcript.read_text(encoding="utf-8", errors="replace")[-4000:]
            except OSError:
                tail = ""
        try:
            provider_id = self.store.get_session(predecessor.session_id).provider_session_id
            if provider_id:
                tail = tail.replace(provider_id, "<provider-session-redacted>")
        except Exception:
            pass
        diff = task.patch_path
        current_diff = ""
        tree_identity: str | None = None
        worktree_identity: str | None = None
        worktree = task.worktree_path or session.cwd
        if worktree is not None and Path(worktree).is_dir():
            try:
                tree_identity = run_command(
                    ["git", "rev-parse", "HEAD^{tree}"], cwd=Path(worktree)
                ).stdout.strip() or None
                worktree_identity = worktree_checkpoint(self.config, Path(worktree))
                current_diff = run_command(
                    ["git", "diff", "--binary", "--no-ext-diff", "--"],
                    cwd=Path(worktree),
                ).stdout[-8000:]
            except (OSError, RuntimeError):
                current_diff = ""
        descriptor = _archive_descriptor(self.config.tasks_dir, transcript)
        diff_descriptor = _archive_descriptor(self.config.tasks_dir, diff)
        if current_diff:
            try:
                archived_diff = self.archive.write_run_file(
                    task.id,
                    predecessor.pipeline_id,
                    predecessor.id,
                    "recovery/current.diff",
                    current_diff,
                )
                diff_descriptor = _archive_descriptor(
                    self.config.tasks_dir, archived_diff
                )
            except Exception:
                # The bounded inline copy remains available even when a
                # partially written archive cannot accept another file.
                pass
        accepted_plan = None
        for event in reversed(self.store.events(task.id)):
            if event.kind == "pipeline.plan.result" and isinstance(event.data.get("plan"), dict):
                accepted_plan = dict(event.data["plan"])
                break
        return RecoveryPacket(
            predecessor_run_id=predecessor.id,
            role=predecessor.role,
            task_intent=task.spec.prompt,
            accepted_plan=accepted_plan,
            transcript_descriptor=descriptor,
            diff_descriptor=diff_descriptor,
            tree_identity=tree_identity,
            worktree_identity=worktree_identity,
            current_diff=current_diff,
            inline_tail=tail,
            interruption={
                "state": predecessor.state,
                "exit_code": predecessor.exit_code,
                "exit_signal": predecessor.exit_signal,
                "exit_reason": predecessor.exit_reason,
            },
        )

    def recover(
        self,
        predecessor_run_id: str,
        *,
        api_key: bytes | str | None = None,
        max_attempts: int = 2,
        **kwargs: Any,
    ) -> ResumeResult:
        """Build an evidence-rich fresh session after resume is unavailable."""

        api_key = self._configured_api_key(api_key)
        packet = self.build_recovery_packet(predecessor_run_id)
        predecessor = self.store.get_run(predecessor_run_id)
        session = self.store.get_session(predecessor.session_id)
        task = self.store.get(predecessor.task_id)
        recovery_key = f"fresh-recovery:{predecessor.id}"
        existing_session = next(
            (
                candidate
                for candidate in self.store.list_sessions(
                    predecessor.task_id,
                    pipeline_id=predecessor.pipeline_id,
                )
                if candidate.idempotency_key == recovery_key
            ),
            None,
        )
        if existing_session is not None:
            existing_run = next(
                (
                    candidate
                    for candidate in self.store.list_runs(
                        predecessor.task_id,
                        pipeline_id=predecessor.pipeline_id,
                    )
                    if candidate.session_id == existing_session.id
                ),
                None,
            )
            if existing_run is not None:
                if existing_run.state == CodexRunState.succeeded.value:
                    return ResumeResult(
                        ResumeCategory.success,
                        result=self._persisted_session_result(existing_run),
                        evidence={"recovery": True, "adopted": True},
                    )
                if existing_run.state == CodexRunState.running.value:
                    return ResumeResult(
                        ResumeCategory.rejected,
                        evidence={"recovery": True, "reason": "already running"},
                    )
                return ResumeResult(
                    ResumeCategory.transient_provider,
                    result=self._persisted_session_result(existing_run),
                    evidence={"recovery": True, "reason": "attempt already completed"},
                )
        cwd = Path(kwargs.pop("cwd", None) or session.cwd or task.worktree_path or self.config.repo_root)
        role = _runtime_role(predecessor.role)
        stage = (
            CodexStage.review
            if predecessor.role in {"review", "reviewer", "formality"}
            else CodexStage.commit_message
            if predecessor.role == "commit-message"
            else CodexStage.implementation_plan
            if predecessor.role in {"planner", "planning"}
            else CodexStage.code
        )
        settings = self.config.codex_settings(stage)
        result = self.start(
            task.id,
            predecessor.pipeline_id,
            role=role,
            prompt=packet.prompt(),
            cwd=cwd,
            api_key=api_key,
            model=kwargs.pop("model", None) or predecessor.model or settings.model,
            reasoning_effort=kwargs.pop("reasoning_effort", None) or predecessor.reasoning or settings.reasoning_effort,
            stage=stage,
            checkpoint_id=session.checkpoint_id,
            image_digest=kwargs.pop("image_digest", None) or session.image_digest,
            codex_identity=kwargs.pop("codex_identity", None) or session.codex_identity,
            output_schema=kwargs.pop("output_schema", None),
            timeout_seconds=kwargs.pop("timeout_seconds", None),
            idempotency_key=recovery_key,
            retry_of_run_id=predecessor_run_id,
        )
        self.store.add_event(
            task.id,
            "session.recovery_started",
            "fresh recovery session started",
            {"predecessor_run_id": predecessor.id, "role": predecessor.role},
        )
        return ResumeResult(
            ResumeCategory.success if result.status is InvocationStatus.succeeded else ResumeCategory.transient_provider,
            result=result,
            evidence={"recovery": True},
        )

    def _persisted_session_result(self, run: TaskRun) -> SessionResult:
        run_dir = self.archive.task_dir(run.task_id) / "pipelines" / run.pipeline_id / "runs" / run.id
        status = (
            InvocationStatus.succeeded
            if run.state == CodexRunState.succeeded.value
            else InvocationStatus.interrupted
            if run.state == CodexRunState.interrupted.value
            else InvocationStatus.failed
        )
        return SessionResult(
            run.task_id,
            run.pipeline_id,
            run.session_id,
            run.id,
            status,
            run.exit_code or 0,
            None,
            run_dir / "codex.jsonl",
            run_dir / "last-message.md",
        )

    def _configured_api_key(self, supplied: bytes | str | None) -> bytes | str | None:
        """Use the daemon-owned key file and never inherit a credential env var."""

        if supplied is not None:
            return supplied
        reader = getattr(self.config, "read_codex_api_key_bytes", None)
        if callable(reader):
            configured = reader()
            if configured is not None:
                return configured
        # The local invoker is an explicit test-only boundary.  Preserve its
        # historical fixture contract without allowing production sessions to
        # consult the daemon environment for credentials.
        if getattr(self.config, "local_codex_test_harness", False):
            return os.environ.get("CODEX_API_KEY")
        return None

    def interrupt(
        self,
        run_id: str,
        *,
        force: bool = False,
        grace_seconds: float = 2.0,
    ) -> InterruptionResult:
        with self._active_lock:
            active = self._active.get(run_id)
        if active is None:
            run = self.store.get_run(run_id)
            if run.state == CodexRunState.interrupted.value:
                return InterruptionResult(run_id, InvocationStatus.interrupted, force, run.exit_code)
            if run.state != CodexRunState.running.value:
                raise KeyError(run_id)
            runtime, identity = self._persisted_boundary(run)
            active = {"runtime": runtime, "identity": identity}
        forced = force
        invoker = active.get("invoker")
        runtime = active.get("runtime")
        process = active.get("process") or getattr(invoker, "process", None)
        identity = active.get("identity") or getattr(invoker, "identity", None)
        if runtime is not None and identity is not None:
            runtime.signal(identity, signal.SIGKILL if force else signal.SIGTERM)
            exited = self._wait_for_exec_exit(
                runtime, identity, timeout=grace_seconds
            )
            if not exited and not force:
                forced = True
                runtime.signal(identity, signal.SIGKILL)
                exited = self._wait_for_exec_exit(
                    runtime, identity, timeout=grace_seconds
                )
            if not exited:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.timeout,
                    "invocation remained live after forced interruption",
                )
        else:
            try:
                if process is not None:
                    process.kill() if force else process.send_signal(signal.SIGTERM)
                elif hasattr(invoker, "interrupt"):
                    invoker.interrupt(force=force)
                if process is not None and not force:
                    try:
                        process.wait(timeout=grace_seconds)
                    except Exception:
                        forced = True
                        process.kill()
            except (OSError, ContainerBoundaryError):
                forced = True
        result = self.store.mark_run_interrupted(
            run_id,
            reason="forced termination" if forced else "cooperative interruption",
        )
        return InterruptionResult(
            run_id,
            InvocationStatus.forced if forced else InvocationStatus.interrupted,
            forced,
            result.exit_code,
        )

    @staticmethod
    def _wait_for_exec_exit(
        runtime: TaskContainerRuntime,
        identity: ExecIdentity,
        *,
        timeout: float,
    ) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            try:
                live = runtime.exec_is_live(identity)
            except ContainerBoundaryError:
                # A failed runtime probe leaves liveness unknown. Keep the run
                # active through the grace window so the caller still escalates.
                live = True
            if not live:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.05, remaining))

    def inspect(self, run_id: str) -> InspectionResult:
        with self._active_lock:
            active = self._active.get(run_id)
        container = None
        identity = active.get("identity") if active is not None else None
        runtime = active.get("runtime") if active is not None else None
        if active is None:
            run = self.store.get_run(run_id)
            if run.state != CodexRunState.running.value:
                return InspectionResult(run_id, False)
            try:
                runtime, identity = self._persisted_boundary(run)
            except (KeyError, ValueError, ContainerBoundaryError):
                return InspectionResult(run_id, False)
        if runtime is not None:
            try:
                container = runtime.inspect()
            except ContainerBoundaryError:
                container = None
        if active is None:
            live = bool(
                runtime is not None
                and identity is not None
                and container is not None
                and container.running
                and runtime.exec_is_live(identity)
            )
            return InspectionResult(run_id, live, container, identity)
        process = active.get("process") or getattr(active.get("invoker"), "process", None)
        live = bool(
            identity is not None
            and process is not None
            and process.poll() is None
        )
        return InspectionResult(run_id, live, container, identity)

    def _persisted_boundary(
        self, run: TaskRun
    ) -> tuple[TaskContainerRuntime, ExecIdentity]:
        session = self.store.get_session(run.session_id)
        if run.wrapper_pid is None or run.exec_identity is None or session.home_uid is None:
            raise ValueError("run does not have a persisted wrapper identity")
        task = self.store.get(run.task_id)
        runtime, _ = self._boundary_for(task)
        if runtime is None:
            raise ValueError("persisted invocation does not have a container runtime")
        return runtime, ExecIdentity(
            runtime.config.container_name,
            run.exec_identity,
            run.wrapper_pid,
            session.home_uid,
        )

    def stop_container(
        self, task_id: str | None = None, *, timeout: float | None = None
    ) -> bool:
        runtime = self.runtime
        if runtime is not None:
            runtime.stop(timeout=timeout)
            inspection = runtime.inspect()
            if inspection.running:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.timeout,
                    "task container remained running after stop",
                )
            return True
        if task_id is None:
            raise ValueError("task_id is required for a task-scoped runtime")
        runtime = self._runtimes.get(task_id)
        if runtime is None and self.runtime_factory is not None:
            task = self.store.get(task_id)
            if task.worktree_path is None:
                return False
            runtime = self.runtime_factory(task)
            self._runtimes[task_id] = runtime
        if runtime is None:
            return False
        runtime.stop(timeout=timeout)
        inspection = runtime.inspect()
        if inspection.running:
            raise ContainerBoundaryError(
                ContainerErrorCategory.timeout,
                "task container remained running after stop",
            )
        return True

    def reconcile_container(
        self,
        task_id: str,
        *,
        ensure_running: bool = True,
    ) -> Any:
        """Adopt, restart, or recreate one exactly matching task container."""

        task = self.store.get(task_id)
        runtime, _ = self._boundary_for(task)
        if runtime is None:
            return None
        try:
            inspection = runtime.adopt()
        except ContainerBoundaryError as exc:
            if exc.category is not ContainerErrorCategory.not_found:
                raise
            if not ensure_running:
                return None
            runtime.ensure_started()
            return runtime.adopt()
        if ensure_running and not inspection.running:
            runtime.start(inspection.container_id)
            return runtime.adopt(expected_id=inspection.container_id)
        return inspection

    def remove_container(self, task_id: str) -> None:
        """Remove a stopped task container after terminal archive sealing."""

        task = self.store.get(task_id)
        runtime = self.runtime or self._runtimes.get(task_id)
        if runtime is None:
            runtime, _ = self._boundary_for(task)
        if runtime is None:
            return
        runtime.remove()
        self._runtimes.pop(task_id, None)
        self._invokers.pop(task_id, None)

    def run(
        self,
        task: TaskRecord,
        prompt: str,
        cwd: Path,
        *,
        name: str = "planner",
        output_schema: Path | None = None,
        resume_session: str | None = None,
        stage: CodexStage = CodexStage.signal_planner,
        sandbox: str | None = None,
        run_id: str | None = None,
    ) -> WorkerResult:
        """Run a daemon planner turn through the injected invocation boundary."""

        if resume_session is not None:
            raise ValueError("planner turns never use ordinary session resume")
        task = self._ensure_planner_task(task)
        runtime, _ = self._boundary_for(task)
        effective_cwd = runtime.config.worktree if runtime is not None else cwd
        checkpoint_id = worktree_checkpoint(self.config, effective_cwd)
        execution = self.store.get_execution(task.id)
        pipeline_id = execution.owning_pipeline_id
        if pipeline_id is None:
            pipelines = self.store.list_pipelines(task.id)
            if not pipelines:
                raise RuntimeError("planner task does not have a canonical pipeline")
            pipeline_id = pipelines[-1].id
        settings = self.config.codex_settings(stage)
        result = self.start(
            task.id,
            pipeline_id,
            role=TaskRole.planner,
            prompt=prompt,
            cwd=effective_cwd,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
            output_schema=output_schema,
            stage=stage,
            sandbox=sandbox or self.config.codex_sandbox,
            checkpoint_id=checkpoint_id,
            run_id=run_id,
        )
        message = (
            result.last_message_path.read_text(encoding="utf-8")
            if result.last_message_path.exists()
            else ""
        )
        return WorkerResult(
            completed=result.status is InvocationStatus.succeeded,
            command=[self.config.codex_bin, "exec", "--json"],
            cwd=effective_cwd,
            exit_code=result.exit_code,
            transcript_path=result.transcript_path,
            last_message_path=result.last_message_path,
            final_message=message,
            thread_id=None,
            session_id=result.session_id,
            run_id=result.run_id,
            pipeline_id=result.pipeline_id,
            stage=stage,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
            diagnostics=result.diagnostics or {},
        )

    def _ensure_planner_task(self, requested: TaskRecord) -> TaskRecord:
        try:
            task = self.store.get(requested.id)
        except KeyError:
            task, created = self.store.add_task(requested.spec)
            if not created:
                raise RuntimeError("planner task allocation was ambiguous")
            task.status = TaskStatus.succeeded
        if task.spec.source != "planner":
            raise ValueError("planner task identity belongs to a non-planner task")
        if task.worktree_path is None:
            task.worktree_path = requested.worktree_path
        elif (
            requested.worktree_path is not None
            and task.worktree_path.resolve() != requested.worktree_path.resolve()
        ):
            raise ValueError("planner task worktree identity changed")
        self.store.save(task)
        return self.store.get(task.id)

    def _allocate(
        self,
        task: TaskRecord,
        pipeline_id: str,
        role: str,
        *,
        cwd: Path,
        checkpoint_id: str | None,
        image_digest: str,
        codex_identity: str,
        idempotency_key: str | None,
        retry_of_run_id: str | None,
        model: str | None,
        reasoning_effort: str | None,
        run_id: str | None = None,
    ) -> tuple[CodexSession, TaskRun]:
        session_id = f"session-{secrets.token_hex(12)}"
        relative = f"{task.id}/{session_id}"
        private_home = self.config.private_sessions_dir / relative
        session, run = self.store.create_session_with_run(
            task.id,
            pipeline_id,
            session_id=session_id,
            private_home_path=private_home,
            private_home_relative_path=relative,
            image_digest=image_digest,
            codex_identity=codex_identity,
            cwd=cwd,
            checkpoint_id=checkpoint_id,
            provider_store_identity=self.provider_store_identity,
            owner_role=role,
            session_idempotency_key=idempotency_key,
            role=role,
            model=model,
            reasoning=reasoning_effort,
            image_version=image_digest,
            runtime_version=self.runtime_identity,
            run_checkpoint_id=checkpoint_id,
            run_provider_store_identity=self.provider_store_identity,
            run_id=run_id,
            retry_of_run_id=retry_of_run_id,
        )
        try:
            self._prepare_home(session)
        except Exception:
            self.store.mark_run_interrupted(
                run.id, reason="private session home preparation failed"
            )
            raise
        try:
            self.archive.ensure_epoch()
            pipeline = self.store.get_pipeline(pipeline_id)
            self.archive.create_task_from_record(task, pipeline=pipeline)
            self.archive.materialize_run(task.id, pipeline_id, run)
        except ArchiveError:
            self.store.mark_run_interrupted(run.id, reason="required archive allocation failed")
            raise
        return session, run

    def _boundary_for(
        self, task: TaskRecord
    ) -> tuple[TaskContainerRuntime | None, SessionInvoker]:
        if self.invoker is not None and self.runtime_factory is None:
            return self.runtime, self.invoker
        if self.runtime is not None:
            invoker = self._invokers.setdefault(
                task.id, ContainerSessionInvoker(self.runtime)
            )
            return self.runtime, invoker
        if self.runtime_factory is None:
            raise RuntimeError("no invocation boundary is configured")
        runtime = self._runtimes.get(task.id)
        if runtime is None:
            runtime = self.runtime_factory(task)
            self._runtimes[task.id] = runtime
        invoker = self._invokers.get(task.id)
        if invoker is None:
            invoker = ContainerSessionInvoker(runtime)
            self._invokers[task.id] = invoker
        return runtime, invoker

    def _execute(
        self,
        task: TaskRecord,
        session: CodexSession,
        run: TaskRun,
        request: InvocationRequest,
        *,
        runtime: TaskContainerRuntime | None,
        invoker: SessionInvoker,
        api_key: str | None,
        timeout_seconds: float,
    ) -> SessionResult:
        transcript = self.archive.task_path(
            task.id,
            f"pipelines/{run.pipeline_id}/runs/{run.id}/codex.jsonl",
        )
        private_last_message = request.output_last_message
        last_message = self._last_message_path(task, run.pipeline_id, run.id)
        transcript.parent.mkdir(parents=True, exist_ok=True)

        def append(line: bytes) -> None:
            self.archive.append_run_jsonl(
                task.id, run.pipeline_id, run.id, "codex.jsonl", line
            )

        def observe(event: dict[str, Any]) -> None:
            self.archive.append_run_jsonl(
                task.id,
                run.pipeline_id,
                run.id,
                "activities.jsonl",
                _public_event(event),
            )

        def on_started(identity: ExecIdentity) -> None:
            self.store.update_run(
                run.id,
                wrapper_pid=identity.pid,
                exec_identity=identity.exec_id,
            )
            with self._active_lock:
                active = self._active.get(run.id)
                if active is not None:
                    active["identity"] = identity
                    active["process"] = getattr(invoker, "process", None)

        with self._active_lock:
            self._active[run.id] = {
                "live": True,
                "invoker": invoker,
                "runtime": runtime,
            }
        try:
            outcome = invoker.invoke(
                request,
                api_key=api_key,
                append=append,
                observe=observe,
                on_started=on_started,
                timeout_seconds=timeout_seconds,
                interrupt_grace_seconds=2.0,
            )
        except Exception as exc:
            self.store.transition_run(
                run.id,
                CodexRunState.failed.value,
                expected_state=CodexRunState.running.value,
                exit_code=1,
                exit_reason=str(exc)[-2000:],
            )
            with self._active_lock:
                self._active.pop(run.id, None)
            return SessionResult(
                task.id,
                run.pipeline_id,
                session.id,
                run.id,
                InvocationStatus.unavailable,
                1,
                None,
                transcript,
                last_message,
                diagnostics={"error": str(exc)},
            )
        provider_id = outcome.provider_session_id
        if provider_id:
            session = self.store.update_session(session.id, provider_session_id=provider_id)
        state = (
            CodexRunState.interrupted.value
            if outcome.interrupted or outcome.forced
            else CodexRunState.succeeded.value
            if outcome.completed
            else CodexRunState.failed.value
        )
        if (
            (outcome.interrupted or outcome.forced)
            and session.checkpoint_id is not None
            and session.checkpoint_id.startswith("worktree-v1-")
        ):
            try:
                checkpoint_id = worktree_checkpoint(self.config, request.cwd)
            except (OSError, RuntimeError):
                checkpoint_id = None
            if checkpoint_id is not None:
                session = self.store.update_session(
                    session.id, checkpoint_id=checkpoint_id
                )
                run = self.store.update_run(run.id, checkpoint_id=checkpoint_id)
        try:
            self.store.transition_run(
                run.id,
                state,
                expected_state=CodexRunState.running.value,
                exit_code=outcome.exit_code,
                exit_reason=("forced termination" if outcome.forced else "interrupted" if outcome.interrupted else None),
                result_summary=(
                    "completed" if outcome.completed else "forced termination" if outcome.forced else "interrupted" if outcome.interrupted else "Codex invocation failed"
                ),
            )
        except ValueError:
            # A concurrent interrupt() may have won the compare-and-set. Keep
            # its terminal outcome and preserve the completed transcript prefix.
            self.store.get_run(run.id)
        if outcome.interrupted or outcome.forced:
            if session.private_home_path is not None:
                control = session.private_home_path / "interruption.json"
                control.write_text(
                    json.dumps(
                        {
                            "runId": run.id,
                            "forced": outcome.forced,
                            "exitCode": outcome.exit_code,
                            "incompleteBytes": len(outcome.incomplete_suffix),
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                os.chmod(control, 0o600)
        if private_last_message.exists():
            self.archive.write_run_file(
                task.id,
                run.pipeline_id,
                run.id,
                "last-message.md",
                private_last_message.read_bytes(),
            )
        for event in outcome.events:
            observe(event)
        self.archive.write_run_file(
            task.id,
            run.pipeline_id,
            run.id,
            "telemetry.json",
            {
                "availability": "unavailable",
                "reason": "provider telemetry was not produced",
            },
        )
        self.archive.write_run_file(
            task.id,
            run.pipeline_id,
            run.id,
            "result.json",
            {
                "status": "available" if outcome.completed else "partial" if outcome.interrupted or outcome.forced else "unavailable",
                "summary": "completed" if outcome.completed else "interrupted" if outcome.interrupted else "forced termination" if outcome.forced else "invocation failed",
                "path": None,
            },
        )
        self.archive.materialize_run(task.id, run.pipeline_id, self.store.get_run(run.id))
        with self._active_lock:
            self._active.pop(run.id, None)
        saved_run = self.store.get_run(run.id)
        externally_interrupted = saved_run.state == CodexRunState.interrupted.value
        return SessionResult(
            task.id,
            run.pipeline_id,
            session.id,
            run.id,
            InvocationStatus.forced
            if outcome.forced or saved_run.exit_reason == "forced termination"
            else InvocationStatus.interrupted
            if outcome.interrupted or externally_interrupted
            else InvocationStatus.succeeded
            if outcome.completed
            else InvocationStatus.failed,
            outcome.exit_code,
            provider_id,
            transcript,
            last_message,
            outcome.incomplete_suffix,
            {"malformed_lines": outcome.malformed_lines},
        )

    def _prepare_home(self, session: CodexSession) -> None:
        assert session.private_home_path is not None
        home = session.private_home_path
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(home, 0o700)
        sessions = home / "sessions"
        sessions.mkdir(mode=0o700, exist_ok=True)
        os.chmod(sessions, 0o700)
        config_path = home / "config.toml"
        config_path.write_text(
            'shell_environment_policy = { inherit = "none" }\n',
            encoding="utf-8",
        )
        os.chmod(config_path, 0o600)
        auth = home / "auth.json"
        if auth.exists():
            raise RuntimeError("auth.json is forbidden in private Codex homes")
        if session.home_uid is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
            for path in (home, sessions, config_path):
                os.chown(path, session.home_uid, session.home_uid)

    def _last_message_path(self, task: TaskRecord, pipeline_id: str, run_id: str) -> Path:
        return self.archive.task_path(
            task.id,
            f"pipelines/{pipeline_id}/runs/{run_id}/last-message.md",
        )

    def _private_last_message_path(self, session: CodexSession, run_id: str) -> Path:
        if session.private_home_path is None:
            raise RuntimeError("session private home is unavailable")
        return session.private_home_path / f"last-message-{run_id}.md"

    def _copy_private_schema(
        self, session: CodexSession, run_id: str, source: Path | None
    ) -> Path | None:
        if source is None:
            return None
        if session.private_home_path is None:
            raise RuntimeError("session private home is unavailable")
        return _copy_optional_file(
            source, session.private_home_path / f"output-schema-{run_id}.json"
        )

    def _timeout_seconds(self, stage: CodexStage) -> float:
        limits = self.config.limits
        minutes = (
            limits.plan_timeout_minutes
            if stage == CodexStage.implementation_plan
            else limits.review_timeout_minutes
            if stage == CodexStage.review
            else limits.worker_timeout_minutes
        )
        return minutes * 60


SessionSupervisorError = RuntimeError
CodexSessionSupervisor = SessionSupervisor
SessionRuntime = SessionSupervisor


def runtime_factory_for_config(config: StewardConfig) -> Callable[[TaskRecord], TaskContainerRuntime]:
    """Return a lazy task-scoped runtime constructor for daemon/CLI wiring."""

    if not config.task_image_digest:
        raise ValueError("task_image_digest must be configured for production execution")

    def build(task: TaskRecord) -> TaskContainerRuntime:
        if task.worktree_path is None:
            raise ValueError("task worktree must exist before creating its container")
        if task.id == "steward-planner" and not task.worktree_path.exists():
            task.worktree_path.parent.mkdir(parents=True, exist_ok=True)
            run_command(
                [
                    "git",
                    "worktree",
                    "add",
                    "--detach",
                    str(task.worktree_path),
                    "HEAD",
                ],
                cwd=config.repo_root,
                check=True,
            )
        worktree = task.worktree_path.resolve()
        linked_git = worktree / ".git"
        if linked_git.is_file():
            text = linked_git.read_text(encoding="utf-8").strip()
            if text.startswith("gitdir:"):
                linked_git = Path(text.split(":", 1)[1].strip()).resolve()
        common_git = (config.repo_root / ".git").resolve()
        scratch = config.private_dir / "task-scratch" / task.id
        archive = config.tasks_dir / task.id
        private_sessions = config.private_sessions_dir / task.id
        archive.mkdir(parents=True, exist_ok=True)
        private_sessions.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(private_sessions, 0o711)
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        task_write_gid = _task_group(task.id, 100000)
        validation_gid = _task_group(task.id, 200000)
        _provision_group_tree(worktree, task_write_gid)
        _provision_group_tree(scratch, validation_gid)
        container_config = TaskContainerConfig(
            task_id=task.id,
            image=config.task_image,
            image_digest=config.task_image_digest,
            worktree=worktree,
            archive=archive,
            private_sessions=private_sessions,
            git_dir=linked_git,
            git_common_dir=common_git,
            repo_root=config.repo_root,
            scratch=scratch,
            network=config.container.network,
            labels={"coquic.steward.codex": config.codex_identity or config.codex_bin},
            task_write_gid=task_write_gid,
            validation_gid=validation_gid,
        )
        return TaskContainerRuntime(
            container_config,
            docker_bin=config.container.docker_bin,
        )

    return build


def worktree_checkpoint(config: StewardConfig, path: Path) -> str:
    """Return an opaque identity for the current commit, tree, and patch."""

    base, tree, patch = Worktrees(config).snapshot(path)
    identity = "\0".join((base, tree, patch)).encode(
        "utf-8", errors="surrogateescape"
    )
    return f"worktree-v1-{hashlib.sha256(identity).hexdigest()}"


def _is_unambiguous_checkpoint(value: str | None) -> bool:
    return bool(
        value
        and len(value) <= 256
        and not any(character.isspace() or character == "\x00" for character in value)
    )


def _copy_optional_file(source: Path | None, destination: Path) -> Path | None:
    if source is None:
        return None
    destination.write_bytes(Path(source).read_bytes())
    os.chmod(destination, 0o600)
    return destination


def _task_group(task_id: str, base: int) -> int:
    return base + int(hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:4], 16)


def _provision_group_tree(root: Path, gid: int) -> None:
    """Give one daemon-owned tree to a role group without world access."""

    paths = [root, *root.rglob("*")]
    for path in paths:
        if path.is_symlink():
            continue
        try:
            os.chown(path, -1, gid)
            mode = path.stat().st_mode & 0o777
            owner_bits = (mode & 0o700) >> 3
            group_bits = owner_bits & 0o070
            if path == root / ".git":
                os.chmod(path, mode & ~0o022)
            elif path.is_dir():
                os.chmod(path, mode | group_bits | 0o2000)
            else:
                os.chmod(path, mode | group_bits)
        except PermissionError as exc:
            raise RuntimeError(
                f"cannot provision task role group {gid} for {root}"
            ) from exc


def _public_event(value: object) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _public_event(item)
            for key, item in value.items()
            if str(key).lower()
            not in {
                "thread_id",
                "threadid",
                "session_id",
                "sessionid",
                "provider_session_id",
                "providerid",
            }
        }
    if isinstance(value, list):
        return [_public_event(item) for item in value]
    return value


def _normalize_role(role: TaskRole | str) -> str:
    return TaskRole(role).value


def _runtime_role(role: str) -> str:
    return {
        "planning": TaskRole.planner.value,
        "review": TaskRole.reviewer.value,
    }.get(role, role)


_RECOVERY_URL_RE = re.compile(r"(?i)\b(?:https?|ssh|git)://[^\s\"']+")
_RECOVERY_SECRET_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|authorization|bearer|credential|"
    r"password|private[_-]?key|secret|token)\b\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,}]+)"
)
_RECOVERY_TOKEN_RE = re.compile(
    r"(?i)\b(?:ghp_|glpat-|github_pat_|sk-[A-Za-z0-9_-]{8,})[A-Za-z0-9._-]+"
)


def _archive_descriptor(root: Path, path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _redact_recovery_text(value: str) -> str:
    """Keep recovery prompts useful without copying credential material."""

    value = _RECOVERY_URL_RE.sub("<redacted-url>", value)
    value = _RECOVERY_SECRET_RE.sub(r"\1<redacted-secret>", value)
    value = _RECOVERY_TOKEN_RE.sub("<redacted-secret>", value)
    return value


def _api_key_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("Codex API key must be bytes, text, or None")

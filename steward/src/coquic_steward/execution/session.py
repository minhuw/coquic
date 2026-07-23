"""Private Codex session allocation and exact-ID recovery primitives."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import signal
import threading
import time
from dataclasses import dataclass
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
from ..core.models import CodexRunState, CodexSession, CodexStage, TaskRecord, TaskRun, WorkerResult
from ..core.subprocesses import run_command
from ..storage import TaskStore
from .container import ContainerBoundaryError, ExecIdentity, TaskContainerRuntime
from .container_config import TaskContainerConfig, TaskRole
from .task_archive import ArchiveError, TaskArchiveWriter


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
        api_key: str | None,
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
        api_key: str | None,
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
        api_key: str | None,
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
            key = (api_key or "").encode("utf-8")
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
        api_key: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        output_schema: Path | None = None,
        stage: CodexStage = CodexStage.code,
        checkpoint_id: str | None = None,
        image_digest: str | None = None,
        codex_identity: str | None = None,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
        sandbox: str | None = None,
    ) -> SessionResult:
        selected_role = _normalize_role(role)
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
            model=model,
            reasoning_effort=reasoning_effort,
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
        api_key: str | None = None,
        image_digest: str | None = None,
        codex_identity: str | None = None,
        cwd: Path | None = None,
        checkpoint_id: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        output_schema: Path | None = None,
        timeout_seconds: float | None = None,
    ) -> ResumeResult:
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
        if checkpoint_id is not None and session.checkpoint_id != checkpoint_id:
            return ResumeResult(ResumeCategory.checkpoint_drift, evidence={"field": "checkpoint_id"})
        try:
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
        try:
            if runtime is not None and identity is not None:
                runtime.signal(identity, signal.SIGKILL if force else signal.SIGTERM)
            elif process is not None:
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
        live = process.poll() is None if process is not None else bool(active.get("live", True))
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

    def stop_container(self, task_id: str | None = None, *, timeout: float | None = None) -> None:
        if self.runtime is not None:
            self.runtime.stop(timeout=timeout)
            return
        if task_id is None:
            raise ValueError("task_id is required for a task-scoped runtime")
        runtime = self._runtimes.get(task_id)
        if runtime is not None:
            runtime.stop(timeout=timeout)

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
    ) -> WorkerResult:
        """Run a daemon planner turn through the injected invocation boundary."""

        if resume_session is not None:
            raise ValueError("planner turns never use ordinary session resume")
        runtime, invoker = self._boundary_for(task)
        effective_cwd = runtime.config.worktree if runtime is not None else cwd
        private_run = self.config.private_sessions_dir / task.id / secrets.token_hex(8)
        private_run.mkdir(parents=True, exist_ok=True, mode=0o700)
        request = InvocationRequest(
            codex_bin=self.config.codex_bin,
            cwd=effective_cwd,
            prompt=prompt,
            output_last_message=private_run / "last-message.md",
            stage=stage,
            output_schema=_copy_optional_file(
                output_schema, private_run / "output-schema.json"
            ),
            sandbox=sandbox or self.config.codex_sandbox,
            role=TaskRole.planner.value,
            session_uid=10000,
            session_id=private_run.name,
            run_id=private_run.name,
        )
        raw = private_run / "codex.jsonl"
        outcome = invoker.invoke(
            request,
            api_key=os.getenv("CODEX_API_KEY"),
            append=lambda line: _append_private(raw, line),
            observe=None,
            on_started=None,
            timeout_seconds=self._timeout_seconds(stage),
            interrupt_grace_seconds=2.0,
        )
        message = (
            request.output_last_message.read_text(encoding="utf-8")
            if request.output_last_message.exists()
            else ""
        )
        return WorkerResult(
            completed=outcome.completed,
            command=request.argv(),
            cwd=effective_cwd,
            exit_code=outcome.exit_code,
            transcript_path=raw,
            last_message_path=request.output_last_message,
            final_message=message,
            thread_id=outcome.provider_session_id,
            stage=stage,
            diagnostics={"malformed_lines": outcome.malformed_lines},
        )

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
        model: str | None,
        reasoning_effort: str | None,
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
            labels={"coquic.steward.codex": config.codex_identity or config.codex_bin},
            task_write_gid=task_write_gid,
            validation_gid=validation_gid,
        )
        return TaskContainerRuntime(container_config)

    return build


def _append_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("ab") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


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

from __future__ import annotations

import fcntl
import fnmatch
import json
import os
import re
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from datetime import timezone
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..agents import (
    CodexRunner,
    render_implementation_plan_prompt,
    render_worker_prompt,
)
from ..core.config import StewardConfig
from ..core.models import (
    IntegrationMode,
    CodexStage,
    Event,
    TaskRecord,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskWorkflow,
    PipelineCursorPhase,
    PipelinePhase,
    PipelineState,
    PipelineTrigger,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    utc_now,
)
from ..core.subprocesses import CommandResult, run_command
from ..storage import TaskStore
from ..storage.mappers import event_to_row
from ..storage.schema import EventRow
from .review import (
    parse_review,
    render_review_prompt,
    render_review_revision_prompt,
    review_approved,
    review_schema_path,
    summarize_review,
)
from .formality import (
    FormalityError,
    formality_schema_path,
    parse_formality,
    render_formality_prompt,
)
from .implementation_plan import (
    MAX_PLAN_RUN_ATTEMPTS,
    implementation_plan_schema_path,
    parse_implementation_plan,
    save_implementation_plan,
    deterministic_plan_skip_reason,
    implementation_plan_required,
)
from .validation import render_validation_revision_prompt, run_gates
from .worktree import Worktrees
from .session import (
    InvocationStatus,
    SessionResult,
    SessionSupervisor,
    runtime_factory_for_config,
    worktree_checkpoint,
)
from .container_config import TaskRole
from ..core.lifecycle import (
    AdvanceResult,
    PhaseInput,
    PhaseOutput,
    action_identity,
    bounded_fingerprint,
    coarse_phase,
    require_pipeline_transition,
)

MAX_TASK_REVISIONS = 100
MAX_REVIEW_RUN_ATTEMPTS = 2
WORKER_HEARTBEAT_SECONDS = 30
PUSH_RETRY_DELAYS_SECONDS = (5.0, 20.0)

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_GTEST_DURATION_RE = re.compile(
    r"(?m)^(\[[^\]\r\n]+\].*?)\(\d+(?:\.\d+)? ms(?: total)?\)$"
)
_NIX_BUSY_WARNING_RE = re.compile(
    r"(?m)^error \(ignored\): SQLite database .+ is busy\r?\n?"
)
_ZIG_CACHE_OBJECT_RE = re.compile(r"\.zig-cache/o/[0-9a-fA-F]+")
_ZIG_SEED_RE = re.compile(r"--seed 0x[0-9a-fA-F]+")
_ZIG_BUILD_NONCE_RE = re.compile(r"(?<!\w)-Z[0-9a-fA-F]+")
_GTEST_FAILURE_BLOCK_RE = re.compile(
    r"(?ms)^(?:[^\n]+:\d+|unknown file): Failure\n"
    r".*?^\[  FAILED  \] [^\n]+$"
)
_GTEST_FAILED_TEST_RE = re.compile(
    r"(?m)^\[  FAILED  \] (?!\d+ tests?\b)[^\n]+$"
)
_TRANSIENT_PUSH_PATTERNS = (
    "could not resolve host",
    "temporary failure in name resolution",
    "connection timed out",
    "connection reset by peer",
    "failed to connect",
    "remote end hung up unexpectedly",
    "tls connection was non-properly terminated",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
)
_TRANSIENT_PUSH_HTTP_STATUS_RE = re.compile(
    r"\b(?:http(?: status)?|status(?: code)?|unexpected status)\s*[:=]?\s*5\d\d\b",
    re.IGNORECASE,
)


class _PhaseAlreadyClaimed(RuntimeError):
    def __init__(self, action_id: str):
        super().__init__(f"phase action already claimed: {action_id}")
        self.action_id = action_id


class PatchPreparationResult(StrEnum):
    ready = "ready"
    no_changes = "no_changes"
    validation_failed = "validation_failed"
    terminal_failure = "terminal_failure"


class _SessionRunnerAdapter:
    """Keep executor observability APIs while delegating execution to sessions."""

    def __init__(self, config: StewardConfig, store: TaskStore, supervisor: SessionSupervisor):
        self.config = config
        self.store = store
        self.supervisor = supervisor

    def paths(self, task: TaskRecord, *, name: str = "worker") -> tuple[Path, Path]:
        execution = self.store.get_execution(task.id)
        pipeline_id = execution.owning_pipeline_id or self.store.list_pipelines(task.id)[-1].id
        # The session supervisor allocates the canonical run path.  This stable
        # placeholder is used only before begin_iteration records the result.
        base = self.config.tasks_dir / task.id / "pipelines" / pipeline_id / "runs" / name
        return base / "codex.jsonl", base / "last-message.md"

    def run(
        self,
        task: TaskRecord,
        prompt: str,
        cwd: Path,
        *,
        name: str = "worker",
        output_schema: Path | None = None,
        resume_session: str | None = None,
        stage: CodexStage = CodexStage.code,
        sandbox: str | None = None,
        task_role: TaskRole | str | None = None,
        idempotency_key: str | None = None,
    ) -> WorkerResult:
        if resume_session is not None:
            raise ValueError("ordinary executor roles cannot resume sessions")
        role = TaskRole(task_role) if task_role is not None else (
            TaskRole.planner
            if stage == CodexStage.implementation_plan
            else TaskRole.reviewer
            if stage == CodexStage.review
            else TaskRole.commit_message
            if stage == CodexStage.commit_message
            else TaskRole.implementation
        )
        settings = self.config.codex_settings(stage)
        pipeline_id = self.store.get_execution(task.id).owning_pipeline_id
        if pipeline_id is None:
            pipeline_id = self.store.list_pipelines(task.id)[-1].id
        result = self.supervisor.start(
            task.id,
            pipeline_id,
            role=role,
            prompt=prompt,
            cwd=cwd,
            api_key=os.getenv("CODEX_API_KEY"),
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
            output_schema=output_schema,
            stage=stage,
            checkpoint_id=worktree_checkpoint(self.config, cwd),
            sandbox=sandbox,
            idempotency_key=idempotency_key,
        )
        return WorkerResult(
            completed=result.status.value == "succeeded",
            command=[self.config.codex_bin, "exec", "--json"],
            cwd=cwd,
            exit_code=result.exit_code,
            transcript_path=result.transcript_path,
            last_message_path=result.last_message_path,
            final_message=(
                result.last_message_path.read_text(encoding="utf-8")
                if result.last_message_path.exists()
                else ""
            ),
            thread_id=result.provider_session_id,
            session_id=getattr(result, "session_id", None),
            run_id=getattr(result, "run_id", None),
            pipeline_id=getattr(result, "pipeline_id", None),
            stage=stage,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
            diagnostics={
                **(result.diagnostics or {}),
                "status": result.status.value,
            },
        )

    def run_review(
        self,
        task: TaskRecord,
        prompt: str,
        cwd: Path,
        *,
        name: str = "reviewer",
        output_schema: Path,
    ) -> WorkerResult:
        return self.run(
            task,
            prompt,
            cwd,
            name=name,
            output_schema=output_schema,
            stage=CodexStage.review,
        )

    def reconcile_tool_changes(
        self, transcript_path: Path, *, final_patch_path: Path | None = None
    ) -> dict[str, object]:
        return {"state": "container-boundary", "transcript_path": str(transcript_path)}


class StewardExecutor:
    _durable_locks: dict[str, threading.RLock] = {}
    _durable_locks_guard = threading.Lock()
    MAX_PIPELINES = 32
    MAX_RUNS = 128
    MAX_VALIDATIONS = 256
    MAX_REVIEWS = 64
    MAX_FORMALITY = 32
    MAX_CONFLICTS = 8
    MAX_TRANSPORT_RETRIES = 3

    def __init__(
        self,
        config: StewardConfig,
        store: TaskStore,
        *,
        session_supervisor: SessionSupervisor | None = None,
        runner: CodexRunner | None = None,
    ):
        self.config = config
        self.store = store
        if session_supervisor is not None and runner is not None:
            raise ValueError("provide either session_supervisor or runner, not both")
        if (
            session_supervisor is None
            and runner is None
            and config.container.enabled
        ):
            session_supervisor = SessionSupervisor(
                config,
                store,
                runtime_factory=runtime_factory_for_config(config),
                image_digest=config.task_image_digest,
                codex_identity=config.codex_identity or config.codex_bin,
            )
        if (
            session_supervisor is None
            and runner is None
            and not config.local_codex_test_harness
        ):
            raise ValueError(
                "StewardExecutor requires an injected task-container session supervisor"
            )
        self.session_supervisor = session_supervisor
        self.runner = (
            _SessionRunnerAdapter(config, store, session_supervisor)
            if session_supervisor is not None
            else runner or CodexRunner(config)
        )
        self.worktrees = Worktrees(config)
        self._latest_failed_validations: dict[str, list[ValidationResult]] = {}

    # ------------------------------------------------------------------
    # Durable pipeline execution

    def advance_once(self, task_id: str) -> AdvanceResult:
        """Claim and execute at most one persisted pipeline action.

        The action-start event is written before any external boundary.  A
        second caller either observes the completed action or reports that the
        first caller is still in progress; it never starts a duplicate run.
        """

        lock = self._durable_lock(task_id)
        if not lock.acquire(blocking=False):
            try:
                execution = self.store.get_execution(task_id)
                pipeline_id = execution.owning_pipeline_id or self.store.list_pipelines(task_id)[-1].id
                phase = self._pipeline_cursor(task_id, pipeline_id)
            except (KeyError, IndexError):
                pipeline_id = "unknown"
                phase = PipelineCursorPhase.provisioned
            return AdvanceResult(
                task_id,
                pipeline_id,
                phase,
                None,
                "in_progress",
                progressed=False,
            )
        try:
            return self._advance_once_locked(task_id)
        finally:
            lock.release()

    def reconcile_session_result(
        self,
        predecessor_run_id: str,
        result: SessionResult,
    ) -> AdvanceResult | None:
        """Ingest one completed recovered run into its claimed phase once."""

        predecessor = self.store.get_run(predecessor_run_id)
        task = self.store.get(predecessor.task_id)
        pipeline = self.store.get_pipeline(predecessor.pipeline_id)
        try:
            action = self.store.get_session(predecessor.session_id).idempotency_key
        except KeyError:
            action = None
        action = action or predecessor.checkpoint_id
        if action and any(
            event.kind == "pipeline.phase.finished"
            and event.data.get("pipeline_id") == pipeline.id
            and event.data.get("output", {}).get("action_id") == action
            for event in self.store.events(task.id)
        ):
            return None
        phase = self._pipeline_cursor(task.id, pipeline.id)
        in_progress = self._in_progress_action(task.id, pipeline.id, phase)
        if in_progress is None:
            return None
        if action is not None and in_progress.action_id != action:
            raise RuntimeError("recovered run does not own the active phase action")
        if result.status is not InvocationStatus.succeeded:
            raise RuntimeError("only a complete recovered result can be ingested")
        worker = self._worker_result_from_session(predecessor, result)
        role = predecessor.role
        if phase == PipelineCursorPhase.planning and role in {"planner", "planning"}:
            plan = parse_implementation_plan(worker.final_message, task, self.config)
            if plan is None or self.worktrees.has_changes(self._require_worktree(task)):
                return self._block_pipeline(
                    task, pipeline, "recovered implementation plan is invalid"
                )
            self.store.add_event(
                task.id,
                "pipeline.plan.result",
                "accepted",
                {
                    "pipeline_id": pipeline.id,
                    "action_id": in_progress.action_id,
                    "plan": plan,
                    "recovered_run_id": result.run_id,
                },
            )
            self._archive_write(task, pipeline, "plans/recovered-plan.json", plan)
            adopted = self._phase_finish(
                task,
                pipeline,
                phase,
                PipelineCursorPhase.implementation,
                evidence={"plan": plan, "recovered_run_id": result.run_id},
            )
        elif phase == PipelineCursorPhase.implementation and role == "implementation":
            iterations = self.store.iterations(task.id)
            if not iterations:
                raise RuntimeError("recovered implementation has no iteration ledger")
            iteration = iterations[-1].iteration
            self.store.finish_iteration_worker(task.id, iteration, worker)
            worktree = self._require_worktree(task)
            base, output_tree, patch = self.worktrees.snapshot(worktree)
            self._set_identity(
                pipeline,
                base_identity=base,
                input_identity=pipeline.input_identity or base,
                output_identity=output_tree,
                patch_identity=patch,
                expected_tree=output_tree,
                phase=coarse_phase(PipelineCursorPhase.validation),
            )
            if patch == sha256(b"").hexdigest() or not self.worktrees.has_changes(
                worktree
            ):
                self.store.finish_task(
                    task.id,
                    TaskStatus.no_changes,
                    "recovered implementation produced no changes",
                )
                next_phase = PipelineCursorPhase.ready_to_seal
            else:
                next_phase = PipelineCursorPhase.validation
            adopted = self._phase_finish(
                task,
                pipeline,
                phase,
                next_phase,
                output_identity=output_tree,
                patch_identity=patch,
                evidence={"recovered_run_id": result.run_id},
            )
        elif phase == PipelineCursorPhase.review and role in {"review", "reviewer"}:
            review = parse_review(worker.final_message)
            if review is None:
                return self._block_pipeline(task, pipeline, "recovered review is invalid")
            raw = dict(review)
            self._record_review_artifacts(
                task,
                pipeline,
                raw,
                kind="raw",
                action_id=in_progress.action_id or "recovered",
            )
            self.store.add_event(
                task.id,
                "pipeline.review.raw",
                "recovered review captured",
                {
                    "pipeline_id": pipeline.id,
                    "action_id": in_progress.action_id,
                    "review": raw,
                    "recovered_run_id": result.run_id,
                },
            )
            next_phase = (
                PipelineCursorPhase.integration
                if review_approved(review)
                else PipelineCursorPhase.formality
            )
            adopted = self._phase_finish(
                task,
                pipeline,
                phase,
                next_phase,
                evidence={"review": raw, "recovered_run_id": result.run_id},
            )
        elif phase == PipelineCursorPhase.formality and role == "formality":
            raw = self._latest_raw_review(task.id, pipeline.id)
            if raw is None:
                return self._block_pipeline(
                    task, pipeline, "recovered formality has no raw review"
                )
            try:
                examined = parse_formality(worker.final_message, raw)
            except FormalityError as exc:
                return self._block_pipeline(
                    task, pipeline, f"recovered formality is invalid: {exc}"
                )
            self._record_review_artifacts(
                task,
                pipeline,
                examined.effective_review,
                kind="effective",
                action_id=in_progress.action_id or "recovered",
            )
            self.store.add_event(
                task.id,
                "pipeline.formality.effective",
                "recovered effective review built",
                {
                    "pipeline_id": pipeline.id,
                    "action_id": in_progress.action_id,
                    "result": examined.as_dict(),
                    "recovered_run_id": result.run_id,
                },
            )
            if examined.escalated:
                return self._block_pipeline(
                    task, pipeline, "formality escalated a review finding"
                )
            if examined.blocking:
                packet = {
                    "review": examined.effective_review,
                    "dispositions": [
                        item.as_dict() for item in examined.dispositions
                    ],
                }
                fingerprint = _review_no_progress_fingerprint(
                    pipeline.output_identity or pipeline.patch_identity,
                    raw,
                    examined.dispositions,
                )
                packet["fingerprint"] = fingerprint
                child = self._new_child_pipeline(
                    task,
                    pipeline,
                    PipelineTrigger.review_repair,
                    packet,
                )
                adopted = AdvanceResult(
                    task.id,
                    child.id,
                    PipelineCursorPhase.provisioned,
                    PipelineCursorPhase.implementation,
                    "child_pipeline",
                    progressed=True,
                    evidence=examined.as_dict(),
                )
            else:
                adopted = self._phase_finish(
                    task,
                    pipeline,
                    phase,
                    PipelineCursorPhase.integration,
                    evidence={
                        **examined.as_dict(),
                        "recovered_run_id": result.run_id,
                    },
                )
        elif phase == PipelineCursorPhase.commit_message and role == "commit-message":
            message = parse_commit_message(worker.final_message)
            if message is None:
                return self._block_pipeline(
                    task, pipeline, "recovered commit message is invalid"
                )
            self.store.add_event(
                task.id,
                "pipeline.commit_message",
                message["subject"],
                {
                    "pipeline_id": pipeline.id,
                    "action_id": in_progress.action_id,
                    **message,
                    "recovered_run_id": result.run_id,
                },
            )
            adopted = self._phase_finish(
                task,
                pipeline,
                phase,
                PipelineCursorPhase.commit,
                evidence={**message, "recovered_run_id": result.run_id},
            )
        else:
            raise RuntimeError(
                f"recovered role {role!r} does not match phase {phase.value!r}"
            )
        self.store.add_event(
            task.id,
            "session.recovery.ingested",
            "recovered run ingested into durable phase",
            {
                "predecessor_run_id": predecessor.id,
                "recovered_run_id": result.run_id,
                "pipeline_id": pipeline.id,
                "phase": phase.value,
            },
        )
        return adopted

    def _worker_result_from_session(
        self,
        predecessor: Any,
        result: SessionResult,
    ) -> WorkerResult:
        try:
            message = result.last_message_path.read_text(encoding="utf-8")
        except OSError:
            message = ""
        stage = (
            CodexStage.implementation_plan
            if predecessor.role in {"planner", "planning"}
            else CodexStage.review
            if predecessor.role in {"review", "reviewer", "formality"}
            else CodexStage.commit_message
            if predecessor.role == "commit-message"
            else CodexStage.code
        )
        return WorkerResult(
            completed=True,
            command=[self.config.codex_bin, "exec", "resume"],
            cwd=self.store.get_session(predecessor.session_id).cwd
            or self.config.repo_root,
            exit_code=result.exit_code,
            transcript_path=result.transcript_path,
            last_message_path=result.last_message_path,
            final_message=message,
            session_id=result.session_id,
            run_id=result.run_id,
            pipeline_id=result.pipeline_id,
            stage=stage,
            model=predecessor.model,
            reasoning_effort=predecessor.reasoning,
            diagnostics={"recovered": True},
        )

    @classmethod
    def _durable_lock(cls, task_id: str) -> threading.RLock:
        with cls._durable_locks_guard:
            return cls._durable_locks.setdefault(task_id, threading.RLock())

    def _advance_once_locked(self, task_id: str) -> AdvanceResult:
        task = self.store.get(task_id)
        try:
            execution = self.store.get_execution(task_id)
        except KeyError:
            execution = self.store.ensure_execution(task_id)
        pipelines = self.store.list_pipelines(task_id)
        if not pipelines:
            pipeline = self.store.create_pipeline(task_id, execution_id=execution.id)
        else:
            pipeline_id = execution.owning_pipeline_id or pipelines[-1].id
            pipeline = self.store.get_pipeline(pipeline_id)
        if TaskStatus(task.status).terminal and not any(
            event.kind == "pipeline.phase.started"
            and event.data.get("pipeline_id") == pipeline.id
            for event in self.store.events(task_id)
        ):
            return AdvanceResult(
                task_id,
                pipeline.id,
                PipelineCursorPhase.ready_to_seal,
                None,
                "legacy_terminal",
                progressed=False,
                evidence={"task_status": str(task.status)},
            )
        cursor = self._pipeline_cursor(task_id, pipeline.id)
        if cursor == PipelineCursorPhase.ready_to_seal:
            return self._seal_ready(task, pipeline)
        budget_failure = self._budget_failure(task_id, cursor)
        if budget_failure is not None:
            return self._block_pipeline(task, pipeline, budget_failure)
        in_progress = self._in_progress_action(task_id, pipeline.id, cursor)
        if in_progress is not None:
            return in_progress
        try:
            return self._dispatch_durable_phase(task, pipeline, cursor)
        except _PhaseAlreadyClaimed as exc:
            return AdvanceResult(
                task.id,
                pipeline.id,
                cursor,
                None,
                "in_progress",
                action_id=exc.action_id,
                progressed=False,
            )
        except Exception as exc:
            # The durable action has already recorded its input identity. Keep
            # the worktree untouched and make the ambiguity visible for the
            # lifecycle reconciler instead of inventing success.
            detail = str(exc).strip()[-2_000:] or exc.__class__.__name__
            return self._block_pipeline(task, pipeline, f"phase {cursor} failed: {detail}")

    def _dispatch_durable_phase(
        self, task: TaskRecord, pipeline: Any, phase: PipelineCursorPhase
    ) -> AdvanceResult:
        handlers = {
            PipelineCursorPhase.provisioned: self._durable_provision,
            PipelineCursorPhase.planning: self._durable_plan,
            PipelineCursorPhase.implementation: self._durable_implementation,
            PipelineCursorPhase.validation: self._durable_validation,
            PipelineCursorPhase.review: self._durable_review,
            PipelineCursorPhase.formality: self._durable_formality,
            PipelineCursorPhase.integration: self._durable_integration,
            PipelineCursorPhase.commit_message: self._durable_commit_message,
            PipelineCursorPhase.commit: self._durable_commit,
            PipelineCursorPhase.push: self._durable_push,
        }
        handler = handlers.get(phase)
        if handler is None:
            return self._block_pipeline(task, pipeline, f"unsupported pipeline phase {phase}")
        return handler(task, pipeline)

    def _durable_provision(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.provisioned
        path = task.worktree_path or self.config.worktrees_dir / task.id
        self._phase_start(task, pipeline, phase, payload={"path": str(path)})
        if TaskStatus(task.status) == TaskStatus.queued:
            self.store.start_worker(task.id, "durable pipeline provisioned")
            task = self.store.get(task.id)
        worktree, branch = self.worktrees.create(task)
        base, tree, patch = self.worktrees.snapshot(worktree)
        task.worktree_path = worktree
        task.branch_name = branch
        self.store.save(task)
        self._set_identity(
            pipeline,
            base_identity=pipeline.base_identity or base,
            input_identity=pipeline.input_identity or tree,
            output_identity=tree,
            patch_identity=patch,
            worktree_path=worktree,
            phase=coarse_phase(PipelineCursorPhase.planning),
        )
        packet = self._child_packet(task.id, pipeline)
        patch_already_applied = bool(packet and packet.get("patch_applied"))
        if patch_already_applied:
            next_phase = PipelineCursorPhase.validation
        elif PipelineTrigger(pipeline.trigger) != PipelineTrigger.initial:
            next_phase = PipelineCursorPhase.implementation
        elif implementation_plan_required(task):
            next_phase = PipelineCursorPhase.planning
        else:
            next_phase = PipelineCursorPhase.implementation
        return self._phase_finish(
            task,
            pipeline,
            phase,
            next_phase,
            output_identity=tree,
            evidence={
                "base_identity": base,
                "input_tree": tree,
                "output_tree": tree,
                "patch_identity": patch,
                "branch": branch,
                "plan_required": implementation_plan_required(task)
                and PipelineTrigger(pipeline.trigger) == PipelineTrigger.initial,
                "patch_already_applied": patch_already_applied,
                "plan_skip_reason": None
                if implementation_plan_required(task)
                else deterministic_plan_skip_reason(task),
            },
        )

    def _durable_plan(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.planning
        if not implementation_plan_required(task):
            return self._phase_finish(
                task,
                pipeline,
                phase,
                PipelineCursorPhase.implementation,
                evidence={"skipped": True, "reason": deterministic_plan_skip_reason(task)},
            )
        worktree = self._require_worktree(task)
        attempt = self._phase_attempt(task.id, pipeline.id, phase)
        action = action_identity(task.id, pipeline.id, f"{phase.value}-{attempt}")
        self._phase_start(
            task,
            pipeline,
            phase,
            action_id=action,
            payload={"attempt": attempt, "worktree": str(worktree)},
        )
        self.store.start_implementation_plan(task.id, "durable implementation planning")
        settings = self.config.codex_settings(CodexStage.implementation_plan)
        name = f"implementation-plan-{attempt}"
        transcript, last_message = self.runner.paths(task, name=name)
        prompt = render_implementation_plan_prompt(task, self.config)
        schema = implementation_plan_schema_path(self.config)
        prompt_path = self.config.prompts_dir / task.id / f"{name}.md"
        try:
            self.store.begin_plan_run(
                task.id,
                attempt,
                prompt_path=prompt_path,
                transcript_path=transcript,
                last_message_path=last_message,
                model=settings.model,
                reasoning_effort=settings.reasoning_effort,
            )
        except (AttributeError, ValueError):
            pass
        result = self._durable_runner(
            task,
            prompt,
            worktree,
            name=name,
            output_schema=schema,
            stage=CodexStage.implementation_plan,
            sandbox="read-only",
            idempotency_key=action,
        )
        changed = self.worktrees.has_changes(worktree)
        plan = (
            parse_implementation_plan(result.final_message, task, self.config)
            if result.completed and not changed
            else None
        )
        plan_path = save_implementation_plan(self.config, task.id, attempt, plan) if plan is not None else None
        try:
            self.store.finish_plan_run(
                task.id,
                attempt,
                result,
                plan=plan,
                plan_path=plan_path,
            )
        except (AttributeError, KeyError, ValueError):
            pass
        self.store.add_event(
            task.id,
            "pipeline.plan.result",
            "accepted" if plan is not None else "rejected",
            {
                "pipeline_id": pipeline.id,
                "action_id": action,
                "attempt": attempt,
                "plan": plan,
                "plan_path": str(plan_path) if plan_path else None,
                "changed_worktree": changed,
                "exit_code": result.exit_code,
                "diagnostics": result.diagnostics,
            },
        )
        if plan is not None:
            self._archive_write(task, pipeline, f"plans/plan-{attempt}.json", plan)
        if plan is not None:
            return self._phase_finish(
                task,
                pipeline,
                phase,
                PipelineCursorPhase.implementation,
                evidence={"plan": plan, "plan_path": str(plan_path)},
            )
        if changed or attempt + 1 >= MAX_PLAN_RUN_ATTEMPTS:
            return self._block_pipeline(task, pipeline, "implementation planning failed")
        return self._phase_finish(
            task,
            pipeline,
            phase,
            phase,
            evidence={"retry": attempt + 1, "exit_code": result.exit_code},
        )

    def _durable_implementation(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.implementation
        worktree = self._require_worktree(task)
        iteration = len(self.store.iterations(task.id))
        action = action_identity(task.id, pipeline.id, f"{phase.value}-{iteration}")
        prompt = self._implementation_prompt(task, pipeline)
        transcript, last_message = self.runner.paths(task, name=f"pipeline-{pipeline.ordinal}-implementation-{iteration}")
        self._phase_start(
            task,
            pipeline,
            phase,
            action_id=action,
            payload={"iteration": iteration, "worktree": str(worktree)},
        )
        self.store.start_worker(task.id, "durable implementation")
        if not self._iteration_exists(task.id, iteration):
            self.store.begin_iteration(
                task.id,
                iteration,
                "Initial implementation" if iteration == 0 else f"Implementation repair {iteration}",
                worker_name="implementation",
                worker_prompt_path=self.config.prompts_dir / task.id / f"pipeline-{pipeline.ordinal}-implementation-{iteration}.md",
                worker_transcript_path=transcript,
                worker_last_message_path=last_message,
            )
        result = self._durable_runner(
            task,
            prompt,
            worktree,
            name=f"pipeline-{pipeline.ordinal}-implementation-{iteration}",
            stage=CodexStage.code,
            idempotency_key=action,
        )
        self.store.finish_iteration_worker(task.id, iteration, result)
        if _worker_was_interrupted(result):
            self.store.add_event(
                task.id,
                "pipeline.phase.interrupted",
                "implementation interrupted for daemon shutdown",
                {
                    "pipeline_id": pipeline.id,
                    "phase": phase.value,
                    "action_id": action,
                    "run_id": result.run_id,
                },
            )
            return AdvanceResult(
                task.id,
                pipeline.id,
                phase,
                phase,
                "interrupted",
                action_id=action,
                progressed=False,
                evidence={"run_id": result.run_id},
            )
        if not result.completed:
            return self._block_pipeline(task, pipeline, result.final_message or "implementation failed")
        base, output_tree, patch = self.worktrees.snapshot(worktree)
        self._set_identity(
            pipeline,
            base_identity=base,
            input_identity=pipeline.input_identity or base,
            output_identity=output_tree,
            patch_identity=patch,
            expected_tree=output_tree,
            phase=coarse_phase(PipelineCursorPhase.validation),
        )
        if patch == sha256(b"").hexdigest() or not self.worktrees.has_changes(worktree):
            if PipelineTrigger(pipeline.trigger) != PipelineTrigger.initial:
                fingerprint = bounded_fingerprint(
                    pipeline.input_identity,
                    self._child_packet(task.id, pipeline),
                    "implementation-no-changes",
                )
                self.store.add_event(
                    task.id,
                    "pipeline.implementation.no_progress",
                    "repair implementation produced no changes",
                    {"pipeline_id": pipeline.id, "fingerprint": fingerprint},
                )
                return self._block_pipeline(
                    task, pipeline, "repair implementation made no progress"
                )
            self.store.finish_task(task.id, TaskStatus.no_changes, "implementation produced no changes")
            return self._phase_finish(
                task,
                pipeline,
                phase,
                PipelineCursorPhase.ready_to_seal,
                output_identity=output_tree,
                evidence={"no_changes": True, "output_tree": output_tree},
            )
        return self._phase_finish(
            task,
            pipeline,
            phase,
            PipelineCursorPhase.validation,
            output_identity=output_tree,
            patch_identity=patch,
            evidence={"output_tree": output_tree, "patch_identity": patch, "run": result.run_id},
        )

    def _durable_validation(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.validation
        worktree = self._require_worktree(task)
        iteration = max(0, len(self.store.iterations(task.id)) - 1)
        action = action_identity(task.id, pipeline.id, phase)
        self._phase_start(task, pipeline, phase, action_id=action, payload={"iteration": iteration})
        self.store.start_validation(task.id, "durable validation")
        forbidden = self.worktrees.forbidden_paths(worktree)
        frozen = self.worktrees.frozen_paths(worktree, task)
        if forbidden or frozen:
            message = "forbidden paths changed: " + ", ".join(forbidden or frozen)
            return self._block_pipeline(task, pipeline, message)
        validations = self._run_gates_for_iteration(
            task.id,
            worktree,
            iteration,
            pipeline=pipeline,
        )
        task = self.store.get(task.id)
        failed = [item for item in validations if not item.passed]
        base, output_tree, patch = self.worktrees.snapshot(worktree)
        patch_path = self.config.patches_dir / task.id / f"pipeline-{pipeline.ordinal}-iteration-{iteration}.patch"
        self.worktrees.save_patch(worktree, patch_path)
        self.store.record_iteration_patch(task.id, iteration, patch_path)
        self._archive_write(task, pipeline, f"validations/gates-{iteration}.json", {"validations": [self._validation_evidence(item) for item in validations]})
        self._archive_bytes(task, pipeline, f"patches/iteration-{iteration}.patch", patch_path.read_bytes())
        task.patch_path = patch_path
        task.validations.extend(validations)
        self.store.save(task)
        self._set_identity(
            pipeline,
            base_identity=base,
            output_identity=output_tree,
            patch_identity=patch,
            expected_tree=output_tree,
            phase=coarse_phase(PipelineCursorPhase.review),
        )
        evidence = {
            "validations": [self._validation_evidence(item) for item in validations],
            "output_tree": output_tree,
            "patch_identity": patch,
            "patch_path": str(patch_path),
        }
        self.store.add_event(
            task.id,
            "pipeline.validation.result",
            "failed" if failed else "passed",
            {"pipeline_id": pipeline.id, **evidence},
        )
        if failed:
            fingerprint = _validation_no_progress_fingerprint(output_tree, failed)
            self.store.add_event(task.id, "pipeline.validation.failure", "validation failed", {"pipeline_id": pipeline.id, "fingerprint": fingerprint, **evidence})
            if self._fingerprint_seen(task.id, fingerprint):
                return self._block_pipeline(task, pipeline, "validation made no progress")
            child = self._new_child_pipeline(task, pipeline, PipelineTrigger.validation_repair, {"validation": evidence, "fingerprint": fingerprint})
            return AdvanceResult(task.id, child.id, PipelineCursorPhase.provisioned, PipelineCursorPhase.implementation, "child_pipeline", progressed=True, evidence=evidence)
        return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.review, output_identity=output_tree, patch_identity=patch, evidence=evidence)

    def _durable_review(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.review
        worktree = self._require_worktree(task)
        patch_text = self.worktrees.diff(worktree)
        tree = self.worktrees.tree(worktree)
        action = action_identity(task.id, pipeline.id, phase)
        self._phase_start(task, pipeline, phase, action_id=action, payload={"tree": tree, "patch_identity": sha256(patch_text.encode()).hexdigest()})
        self.store.start_review(task.id, "durable review")
        plan = self._latest_plan(task.id, pipeline.id)
        validations = [self._validation_evidence(item) for item in task.validations]
        prompt = render_review_prompt(
            task,
            self.config,
            implementation_plan=plan,
            patch_text=patch_text,
            tree_identity=tree,
            validation_evidence=validations,
            declared_scope=self._declared_scope(task, plan),
        )
        schema = review_schema_path(self.config)
        result = self._durable_runner(
            task,
            prompt,
            worktree,
            name=f"reviewer-{pipeline.ordinal}",
            output_schema=schema,
            stage=CodexStage.review,
            sandbox="read-only",
            idempotency_key=action,
            task_role=TaskRole.reviewer,
        )
        review = parse_review(result.final_message) if result.completed else None
        raw = review or {"verdict": "block", "summary": result.final_message or "review failed", "findings": [], "validation_gaps": [], "remaining_risk": "review invocation failed"}
        self._record_review_artifacts(task, pipeline, raw, kind="raw", action_id=action)
        self.store.add_event(task.id, "pipeline.review.raw", "review captured", {"pipeline_id": pipeline.id, "action_id": action, "review": raw, "tree": tree})
        if review is None:
            return self._block_pipeline(task, pipeline, "review output was malformed or unavailable")
        if review_approved(review):
            return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.integration, evidence={"review": review, "tree": tree, "formality": "skipped"})
        return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.formality, evidence={"review": review, "tree": tree})

    def _durable_formality(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.formality
        raw = self._latest_raw_review(task.id, pipeline.id)
        if raw is None:
            return self._block_pipeline(task, pipeline, "formality has no raw review")
        action = action_identity(task.id, pipeline.id, phase)
        self._phase_start(task, pipeline, phase, action_id=action, payload={"finding_count": len(raw.get("findings", []))})
        worktree = self._require_worktree(task)
        result = self._durable_runner(
            task,
            render_formality_prompt(task, raw, implementation_plan=self._latest_plan(task.id, pipeline.id), declared_scope=self._declared_scope(task, self._latest_plan(task.id, pipeline.id))),
            worktree,
            name=f"formality-{pipeline.ordinal}",
            output_schema=formality_schema_path(self.config),
            stage=CodexStage.review,
            sandbox="read-only",
            task_role=TaskRole.formality,
            idempotency_key=action,
        )
        if not result.completed:
            return self._block_pipeline(task, pipeline, result.final_message or "formality examination failed")
        try:
            examined = parse_formality(result.final_message, raw)
        except FormalityError as exc:
            self.store.add_event(task.id, "pipeline.formality.malformed", str(exc), {"pipeline_id": pipeline.id, "action_id": action})
            return self._block_pipeline(task, pipeline, f"malformed formality output: {exc}")
        self._record_review_artifacts(task, pipeline, examined.effective_review, kind="effective", action_id=action)
        self.store.add_event(task.id, "pipeline.formality.effective", "effective review built", {"pipeline_id": pipeline.id, "action_id": action, "result": examined.as_dict()})
        if examined.escalated:
            return self._block_pipeline(task, pipeline, "formality escalated a review finding")
        if examined.blocking:
            packet = {
                "review": examined.effective_review,
                "dispositions": [item.as_dict() for item in examined.dispositions],
            }
            fingerprint = _review_no_progress_fingerprint(
                pipeline.output_identity or pipeline.patch_identity,
                raw,
                examined.dispositions,
            )
            self.store.add_event(
                task.id,
                "pipeline.review.failure",
                "effective review remains blocking",
                {
                    "pipeline_id": pipeline.id,
                    "fingerprint": fingerprint,
                    **packet,
                },
            )
            if self._fingerprint_seen(task.id, fingerprint):
                return self._block_pipeline(task, pipeline, "review repair made no progress")
            packet["fingerprint"] = fingerprint
            child = self._new_child_pipeline(
                task, pipeline, PipelineTrigger.review_repair, packet
            )
            return AdvanceResult(task.id, child.id, PipelineCursorPhase.provisioned, PipelineCursorPhase.implementation, "child_pipeline", progressed=True, evidence=examined.as_dict())
        return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.integration, evidence=examined.as_dict())

    def _durable_integration(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.integration
        worktree = self._require_worktree(task)
        action = action_identity(task.id, pipeline.id, phase)
        self._phase_start(task, pipeline, phase, action_id=action, payload={"base": pipeline.base_identity})
        self.store.start_integration(task.id, "durable integration")
        with _integration_lock(self.config.state_dir):
            tree = self.worktrees.tree(worktree)
            patch = self.worktrees.patch_identity(worktree)
            if pipeline.output_identity is None or tree != pipeline.output_identity:
                return self._block_pipeline(
                    task,
                    pipeline,
                    "integration worktree differs from the accepted tree",
                )
            if pipeline.patch_identity is None or patch != pipeline.patch_identity:
                return self._block_pipeline(
                    task,
                    pipeline,
                    "integration patch differs from the accepted patch",
                )
            remote_tip = self._latest_main_identity(worktree)
            base = pipeline.base_identity or self.worktrees.base_commit(worktree)
            if remote_tip and remote_tip != base:
                accepted_patch = self._accepted_patch(task, pipeline)
                if accepted_patch is None:
                    return self._block_pipeline(
                        task, pipeline, "base change has no accepted patch evidence"
                    )
                child = self._prepare_base_change_child(
                    task,
                    pipeline,
                    trigger=PipelineTrigger.integration_rebase,
                    latest_main=remote_tip,
                    accepted_patch=accepted_patch,
                )
                if isinstance(child, AdvanceResult):
                    return child
                return AdvanceResult(task.id, child.id, PipelineCursorPhase.provisioned, PipelineCursorPhase.implementation, "child_pipeline", progressed=True, evidence={"base": base, "latest_main": remote_tip})
            self._set_identity(pipeline, output_identity=tree, patch_identity=patch, phase=coarse_phase(PipelineCursorPhase.commit_message))
            return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.commit_message, output_identity=tree, patch_identity=patch, evidence={"latest_main": remote_tip, "tree": tree, "patch_identity": patch})

    def _durable_commit_message(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.commit_message
        worktree = self._require_worktree(task)
        patch_text = self.worktrees.diff(worktree)
        validations = list(task.validations)
        action = action_identity(task.id, pipeline.id, phase)
        self._phase_start(task, pipeline, phase, action_id=action, payload={"tree": self.worktrees.tree(worktree)})
        prompt = render_commit_message_prompt(task, patch_text, _patch_paths(patch_text), validations)
        result = self._durable_runner(task, prompt, worktree, name=f"commit-message-{pipeline.ordinal}", output_schema=commit_message_schema_path(self.config), stage=CodexStage.commit_message, sandbox="read-only", task_role=TaskRole.commit_message, idempotency_key=action)
        data = parse_commit_message(result.final_message) if result.completed else None
        if data is None:
            return self._block_pipeline(task, pipeline, "commit message generation failed")
        self.store.add_event(task.id, "pipeline.commit_message", data["subject"], {"pipeline_id": pipeline.id, "action_id": action, "subject": data["subject"], "body": data["body"]})
        return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.commit, evidence=data)

    def _durable_commit(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.commit
        worktree = self._require_worktree(task)
        message = self._latest_commit_message(task.id, pipeline.id)
        if message is None:
            return self._block_pipeline(task, pipeline, "commit has no accepted message")
        action = action_identity(task.id, pipeline.id, phase)
        expected_tree = pipeline.output_identity or self.worktrees.tree(worktree)
        self._phase_start(task, pipeline, phase, payload={"expected_tree": expected_tree, "message": message})
        sha = self.worktrees.commit_all(worktree, message["subject"], message["body"], expected_tree=expected_tree)
        if sha is None:
            self.store.finish_task(task.id, TaskStatus.no_changes, "accepted tree already committed")
            return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.ready_to_seal, evidence={"no_changes": True, "tree": expected_tree})
        self.store.add_event(task.id, "pipeline.commit", sha, {"pipeline_id": pipeline.id, "action_id": action, "commit": sha, "tree": expected_tree})
        self._archive_write(task, pipeline, "commit.json", {"commit": sha, "tree": expected_tree, "message": message})
        next_phase = PipelineCursorPhase.ready_to_seal if self.config.local_only or self.config.integration_mode != IntegrationMode.push_main.value else PipelineCursorPhase.push
        return self._phase_finish(task, pipeline, phase, next_phase, evidence={"commit": sha, "tree": expected_tree})

    def _durable_push(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        phase = PipelineCursorPhase.push
        worktree = self._require_worktree(task)
        commit = self._latest_commit(task.id, pipeline.id)
        if commit is None:
            return self._block_pipeline(task, pipeline, "push has no accepted commit")
        action = action_identity(task.id, pipeline.id, phase)
        attempt = self._phase_attempt(task.id, pipeline.id, phase)
        self._phase_start(task, pipeline, phase, action_id=f"{action}-{attempt}", payload={"commit": commit, "attempt": attempt})
        try:
            result = self.worktrees.push_head_to_main(worktree)
        except RuntimeError as exc:
            detail = str(exc)[-2_000:]
            if self._commit_reachable(worktree, commit):
                self.store.add_event(task.id, "pipeline.push.ambiguous_resolved", commit, {"pipeline_id": pipeline.id, "commit": commit, "detail": detail})
                self.store.finish_task(task.id, TaskStatus.pushed, f"pushed {commit}")
                return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.ready_to_seal, evidence={"commit": commit, "ambiguous": True})
            fingerprint = bounded_fingerprint(
                commit, _stable_push_failure(detail)
            )
            self.store.add_event(
                task.id,
                "pipeline.push.failure",
                detail,
                {
                    "pipeline_id": pipeline.id,
                    "attempt": attempt,
                    "commit": commit,
                    "fingerprint": fingerprint,
                },
            )
            if self._fingerprint_seen(task.id, fingerprint):
                return self._block_pipeline(task, pipeline, "push made no progress")
            if _is_transient_push_failure(detail) and attempt < self.MAX_TRANSPORT_RETRIES:
                self.store.add_event(task.id, "pipeline.push.retry", detail, {"pipeline_id": pipeline.id, "attempt": attempt, "commit": commit})
                return self._phase_finish(task, pipeline, phase, phase, evidence={"retry": attempt + 1, "detail": detail})
            if _is_non_fast_forward_push_failure(detail):
                with _integration_lock(self.config.state_dir):
                    latest_main = self._latest_main_identity(worktree)
                    if latest_main is None:
                        return self._block_pipeline(
                            task, pipeline, "push race could not resolve latest main"
                        )
                    accepted_patch = self._accepted_patch(task, pipeline)
                    if accepted_patch is None:
                        return self._block_pipeline(
                            task, pipeline, "push race has no accepted patch evidence"
                        )
                    child = self._prepare_base_change_child(
                        task,
                        pipeline,
                        trigger=PipelineTrigger.push_race,
                        latest_main=latest_main,
                        accepted_patch=accepted_patch,
                        extra_evidence={"commit": commit, "detail": detail},
                    )
                if isinstance(child, AdvanceResult):
                    return child
                return AdvanceResult(task.id, child.id, PipelineCursorPhase.provisioned, PipelineCursorPhase.implementation, "child_pipeline", progressed=True, evidence={"commit": commit, "detail": detail})
            return self._block_pipeline(task, pipeline, f"push failed: {detail}")
        self.store.add_event(task.id, "pipeline.push", commit, {"pipeline_id": pipeline.id, "action_id": action, "commit": commit, "result": _command_result_text(result)})
        self._archive_write(task, pipeline, "push.json", {"commit": commit, "result": _command_result_text(result)})
        self.store.finish_task(task.id, TaskStatus.pushed, f"pushed {commit}")
        return self._phase_finish(task, pipeline, phase, PipelineCursorPhase.ready_to_seal, evidence={"commit": commit})

    def _pipeline_cursor(self, task_id: str, pipeline_id: str) -> PipelineCursorPhase:
        cursor = PipelineCursorPhase.provisioned
        for event in self.store.events(task_id):
            if event.kind == "pipeline.phase.finished" and event.data.get("pipeline_id") == pipeline_id:
                value = event.data.get("output", {}).get("next_phase")
                if value is not None:
                    try:
                        cursor = PipelineCursorPhase(value)
                    except ValueError:
                        return cursor
        return cursor

    def _phase_attempt(self, task_id: str, pipeline_id: str, phase: PipelineCursorPhase) -> int:
        return sum(
            1
            for event in self.store.events(task_id)
            if event.kind == "pipeline.phase.started"
            and event.data.get("pipeline_id") == pipeline_id
            and str(event.data.get("phase")) == phase.value
        )

    def _in_progress_action(
        self, task_id: str, pipeline_id: str, phase: PipelineCursorPhase
    ) -> AdvanceResult | None:
        states: dict[str, str] = {}
        starts: dict[str, Any] = {}
        for event in self.store.events(task_id):
            if event.data.get("pipeline_id") != pipeline_id:
                continue
            if event.kind == "pipeline.phase.started" and event.data.get("phase") == phase.value:
                action = event.data.get("action_id")
                if action:
                    starts[str(action)] = event
                    states[str(action)] = "active"
            elif event.kind == "pipeline.phase.finished":
                action = event.data.get("output", {}).get("action_id")
                if action:
                    states[str(action)] = "finished"
            elif event.kind == "pipeline.phase.interrupted":
                action = event.data.get("action_id")
                if action:
                    states[str(action)] = "interrupted"
        for action, event in starts.items():
            if states.get(action) == "active":
                return AdvanceResult(
                    task_id,
                    pipeline_id,
                    phase,
                    None,
                    "in_progress",
                    action_id=action,
                    progressed=False,
                    evidence={"started_at": event.created_at.isoformat()},
                )
        return None

    def _phase_start(
        self,
        task: TaskRecord,
        pipeline: Any,
        phase: PipelineCursorPhase,
        *,
        action_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> PhaseInput:
        selected_action = action_id or action_identity(task.id, pipeline.id, phase)
        current_tree = None
        if task.worktree_path is not None and task.worktree_path.exists():
            try:
                current_tree = self.worktrees.tree(task.worktree_path)
            except (OSError, RuntimeError):
                current_tree = None
        value = PhaseInput(
            task.id,
            pipeline.id,
            selected_action,
            phase,
            base_identity=pipeline.base_identity,
            input_identity=pipeline.input_identity,
            patch_identity=pipeline.patch_identity,
            expected_tree=current_tree,
            payload=payload or {},
        )
        data = {
            "pipeline_id": pipeline.id,
            "phase": phase.value,
            "action_id": selected_action,
            "input": self._json_safe(value.as_dict()),
        }
        if not self._claim_phase_event(task.id, pipeline.id, phase, selected_action, data):
            raise _PhaseAlreadyClaimed(selected_action)
        self._archive_write(task, pipeline, f"phases/{phase.value}-{_safe_filename(selected_action)}-input.json", value.as_dict())
        return value

    def _claim_phase_event(
        self,
        task_id: str,
        pipeline_id: str,
        phase: PipelineCursorPhase,
        action_id: str,
        data: dict[str, Any],
    ) -> bool:
        """Atomically persist one phase claim across daemon processes."""

        engine = getattr(self.store, "engine", None)
        path_codec = getattr(self.store, "path_codec", None)
        if engine is None or path_codec is None:
            if self._in_progress_action(task_id, pipeline_id, phase) is not None:
                return False
            self.store.add_event(
                task_id, "pipeline.phase.started", phase.value, data
            )
            return True
        event = Event(
            task_id=task_id,
            kind="pipeline.phase.started",
            message=phase.value,
            data=data,
        )
        row = event_to_row(event, path_codec=path_codec)
        with engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                records = connection.execute(
                    select(EventRow.kind, EventRow.data_json).where(
                        EventRow.task_id == task_id,
                        EventRow.kind.in_(
                            (
                                "pipeline.phase.started",
                                "pipeline.phase.finished",
                                "pipeline.phase.interrupted",
                            )
                        ),
                    )
                ).all()
                states: dict[str, str] = {}
                for kind, data_json in records:
                    try:
                        payload = json.loads(data_json)
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if payload.get("pipeline_id") != pipeline_id:
                        continue
                    if kind == "pipeline.phase.started" and payload.get("phase") == phase.value:
                        claimed = payload.get("action_id")
                        if claimed:
                            states[str(claimed)] = "active"
                    elif kind == "pipeline.phase.finished":
                        completed = payload.get("output", {}).get("action_id")
                        if completed:
                            states[str(completed)] = "finished"
                    elif kind == "pipeline.phase.interrupted":
                        interrupted = payload.get("action_id")
                        if interrupted:
                            states[str(interrupted)] = "interrupted"
                if any(state == "active" for state in states.values()) or states.get(
                    action_id
                ) == "finished":
                    connection.rollback()
                    return False
                connection.execute(
                    EventRow.__table__.insert().values(
                        task_id=row.task_id,
                        kind=row.kind,
                        message=row.message,
                        created_at=row.created_at,
                        data_json=row.data_json,
                    )
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        notify = getattr(self.store, "_notify_change", None)
        if callable(notify):
            notify()
        return True

    def _phase_finish(
        self,
        task: TaskRecord,
        pipeline: Any,
        phase: PipelineCursorPhase,
        next_phase: PipelineCursorPhase,
        *,
        output_identity: str | None = None,
        patch_identity: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> AdvanceResult:
        if next_phase != phase:
            require_pipeline_transition(phase, next_phase, trigger=pipeline.trigger)
        action = self._latest_started_action(task.id, pipeline.id, phase)
        selected_action = action or action_identity(task.id, pipeline.id, phase)
        output = PhaseOutput(
            selected_action,
            phase,
            next_phase,
            PipelineState.active,
            output_identity=output_identity,
            patch_identity=patch_identity,
            evidence=evidence or {},
        )
        self.store.add_event(
            task.id,
            "pipeline.phase.finished",
            phase.value,
            {
                "pipeline_id": pipeline.id,
                "phase": phase.value,
                "output": self._json_safe(output.as_dict()),
            },
        )
        self._archive_write(task, pipeline, f"phases/{phase.value}-{_safe_filename(selected_action)}-output.json", output.as_dict())
        if next_phase != phase:
            try:
                self.store.transition_pipeline(
                    pipeline.id,
                    PipelineState.active.value,
                    expected_state=PipelineState.active.value,
                    phase=coarse_phase(next_phase).value,
                )
            except (TypeError, ValueError):
                # A narrow fake store used by unit tests may expose only the
                # basic transition signature; the event remains authoritative.
                self.store.transition_pipeline(
                    pipeline.id,
                    PipelineState.active.value,
                    phase=coarse_phase(next_phase).value,
                )
        return AdvanceResult(
            task.id,
            pipeline.id,
            phase,
            next_phase,
            "advanced",
            action_id=selected_action,
            progressed=True,
            evidence=evidence or {},
        )

    def _latest_started_action(self, task_id: str, pipeline_id: str, phase: PipelineCursorPhase) -> str | None:
        selected = None
        for event in self.store.events(task_id):
            if event.kind == "pipeline.phase.started" and event.data.get("pipeline_id") == pipeline_id and event.data.get("phase") == phase.value:
                selected = event.data.get("action_id")
        return str(selected) if selected else None

    def _set_identity(self, pipeline: Any, **values: Any) -> None:
        """Update identity columns through the dependency ledger boundary.

        Plan 002 deliberately keeps this method small; older test doubles do
        not implement it, so event evidence remains the fallback.
        """

        allowed = {
            "base_identity",
            "input_identity",
            "output_identity",
            "patch_identity",
            "expected_tree",
            "worktree_path",
            "phase",
        }
        selected = {key: value for key, value in values.items() if key in allowed and value is not None}
        if not selected:
            return
        for key, value in selected.items():
            try:
                setattr(pipeline, key, value)
            except Exception:
                pass
        engine = getattr(self.store, "engine", None)
        if engine is None:
            for key, value in selected.items():
                try:
                    setattr(pipeline, key, value)
                except Exception:
                    pass
            return
        assignments: list[str] = []
        parameters: dict[str, Any] = {"pipeline_id": pipeline.id}
        pipeline_selected = {
            key: value
            for key, value in selected.items()
            if key not in {"worktree_path", "expected_tree"}
        }
        for key, value in pipeline_selected.items():
            column = "phase" if key == "phase" else key
            if key == "worktree_path":
                value = str(value)
            assignments.append(f"{column} = :{column}")
            parameters[column] = str(value)
        assignments.append("updated_at = :updated_at")
        parameters["updated_at"] = utc_now().isoformat()
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"UPDATE task_pipelines SET {', '.join(assignments)} WHERE id = :pipeline_id",
                parameters,
            )
            if "base_identity" in selected or "expected_tree" in selected or "worktree_path" in selected:
                execution = self.store.get_execution(pipeline.task_id)
                execution_assignments = []
                execution_parameters: dict[str, Any] = {"execution_id": execution.id}
                for source, column in (("base_identity", "base_commit"), ("expected_tree", "expected_tree"), ("worktree_path", "worktree_path")):
                    if source in selected:
                        value = str(selected[source])
                        execution_assignments.append(f"{column} = :{column}")
                        execution_parameters[column] = value
                execution_assignments.append("updated_at = :updated_at")
                execution_parameters["updated_at"] = parameters["updated_at"]
                connection.exec_driver_sql(
                    f"UPDATE task_executions SET {', '.join(execution_assignments)} WHERE id = :execution_id",
                    execution_parameters,
                )

    def _budget_failure(
        self, task_id: str, phase: PipelineCursorPhase | None = None
    ) -> str | None:
        try:
            if len(self.store.list_pipelines(task_id)) > self.MAX_PIPELINES:
                return "pipeline budget exhausted"
            if phase in {
                PipelineCursorPhase.planning,
                PipelineCursorPhase.implementation,
                PipelineCursorPhase.review,
                PipelineCursorPhase.formality,
                PipelineCursorPhase.commit_message,
            } and len(self.store.list_runs(task_id)) >= self.MAX_RUNS:
                return "run budget exhausted"
        except (AttributeError, KeyError):
            pass
        events = self.store.events(task_id)
        if phase == PipelineCursorPhase.validation and sum(
            1 for event in events if event.kind == "pipeline.validation.result"
        ) >= self.MAX_VALIDATIONS:
            return "validation budget exhausted"
        if phase == PipelineCursorPhase.formality and sum(
            1 for event in events if event.kind == "pipeline.formality.effective"
        ) >= self.MAX_FORMALITY:
            return "formality budget exhausted"
        if phase == PipelineCursorPhase.review and sum(
            1 for event in events if event.kind == "pipeline.review.raw"
        ) >= self.MAX_REVIEWS:
            return "review budget exhausted"
        if phase == PipelineCursorPhase.push and sum(
            1
            for event in events
            if event.kind == "pipeline.phase.started"
            and event.data.get("phase") == PipelineCursorPhase.push.value
        ) >= self.MAX_TRANSPORT_RETRIES + 1:
            return "transport budget exhausted"
        return None

    def _block_pipeline(self, task: TaskRecord, pipeline: Any, summary: str) -> AdvanceResult:
        self.store.add_event(task.id, "pipeline.blocked", summary, {"pipeline_id": pipeline.id, "phase": self._pipeline_cursor(task.id, pipeline.id).value, "fingerprint": bounded_fingerprint(summary)})
        try:
            self.store.transition_pipeline(pipeline.id, PipelineState.blocked.value, phase=coarse_phase(self._pipeline_cursor(task.id, pipeline.id)).value)
        except ValueError:
            pass
        self.store.finish_task(task.id, TaskStatus.blocked, summary)
        try:
            execution = self.store.get_execution(task.id)
            self.store.transition_execution(execution.id, "complete", expected_state="active", phase=PipelinePhase.complete.value, pipeline_id=pipeline.id)
        except (KeyError, ValueError):
            pass
        phase = self._pipeline_cursor(task.id, pipeline.id)
        return AdvanceResult(task.id, pipeline.id, phase, None, "blocked", progressed=False, evidence={"summary": summary})

    def _seal_ready(self, task: TaskRecord, pipeline: Any) -> AdvanceResult:
        status = TaskStatus(task.status)
        if status not in {TaskStatus.no_changes, TaskStatus.pushed}:
            status = TaskStatus.succeeded
            self.store.finish_task(task.id, status, "ready to seal")
        try:
            self.store.transition_pipeline(pipeline.id, PipelineState.succeeded.value, phase=PipelinePhase.complete.value)
        except ValueError:
            pass
        try:
            execution = self.store.get_execution(task.id)
            self.store.transition_execution(execution.id, "complete", expected_state="active", phase=PipelinePhase.complete.value, pipeline_id=pipeline.id)
        except (KeyError, ValueError):
            pass
        self.store.add_event(task.id, "pipeline.ready_to_seal", status.value, {"pipeline_id": pipeline.id, "terminal_status": status.value})
        return AdvanceResult(task.id, pipeline.id, PipelineCursorPhase.ready_to_seal, None, "ready_to_seal", progressed=True, evidence={"terminal_status": status.value})

    def _new_child_pipeline(
        self,
        task: TaskRecord,
        parent: Any,
        trigger: PipelineTrigger,
        evidence: dict[str, Any],
        *,
        base_identity: str | None = None,
        input_identity: str | None = None,
        output_identity: str | None = None,
        patch_identity: str | None = None,
    ) -> Any:
        if len(self.store.list_pipelines(task.id)) >= self.MAX_PIPELINES:
            raise RuntimeError("pipeline budget exhausted")
        if trigger == PipelineTrigger.integration_conflict or evidence.get("conflict"):
            conflicts = sum(
                1
                for event in self.store.events(task.id)
                if event.kind == "pipeline.integration.conflict"
            )
            current_fingerprint = evidence.get("fingerprint")
            current_recorded = bool(
                current_fingerprint
                and any(
                    event.kind == "pipeline.integration.conflict"
                    and event.data.get("fingerprint") == current_fingerprint
                    for event in self.store.events(task.id)
                )
            )
            if conflicts - int(current_recorded) >= self.MAX_CONFLICTS:
                raise RuntimeError("conflict budget exhausted")
        try:
            self.store.transition_pipeline(parent.id, PipelineState.superseded.value, phase=coarse_phase(self._pipeline_cursor(task.id, parent.id)).value)
        except ValueError:
            pass
        child = self.store.create_pipeline(
            task.id,
            execution_id=parent.execution_id,
            trigger=trigger.value,
            parent_pipeline_id=parent.id,
            base_identity=base_identity or parent.base_identity,
            input_identity=input_identity or parent.output_identity or parent.input_identity,
            output_identity=output_identity,
            patch_identity=patch_identity or parent.patch_identity,
            metadata={"packet": self._json_safe(evidence)},
        )
        self.store.add_event(task.id, "pipeline.child.created", trigger.value, {"pipeline_id": child.id, "parent_pipeline_id": parent.id, "trigger": trigger.value, "evidence": evidence})
        return child

    def _require_worktree(self, task: TaskRecord) -> Path:
        if task.worktree_path is None:
            raise RuntimeError("durable phase requires a worktree")
        path = Path(task.worktree_path)
        if not path.exists():
            raise RuntimeError(f"durable worktree is unavailable: {path}")
        return path

    def _durable_runner(self, task: TaskRecord, prompt: str, cwd: Path, **kwargs: Any) -> WorkerResult:
        try:
            return self.runner.run(task, prompt, cwd, **kwargs)
        except TypeError as exc:
            unsupported = {"idempotency_key", "task_role"}
            if not any(name in str(exc) for name in unsupported):
                raise
            kwargs = {key: value for key, value in kwargs.items() if key not in unsupported}
            return self.runner.run(task, prompt, cwd, **kwargs)

    def _implementation_prompt(self, task: TaskRecord, pipeline: Any) -> str:
        plan = self._latest_plan(task.id, pipeline.id)
        prompt = render_worker_prompt(task, self.config, plan)
        packet = self._child_packet(task.id, pipeline)
        if packet is None:
            return prompt
        context = {
            "trigger": str(pipeline.trigger),
            "original_intent": task.spec.prompt,
            "accepted_plan": plan,
            "base_identity": pipeline.base_identity,
            "input_identity": pipeline.input_identity,
            "output_identity": pipeline.output_identity,
            "patch_identity": pipeline.patch_identity,
            "failure_packet": packet,
        }
        return (
            prompt
            + "\n\nDurable child pipeline context (authoritative and scope-bounded):\n"
            + json.dumps(self._json_safe(context), indent=2, sort_keys=True)
            + "\n\nAddress only the exact failure packet while preserving the original intent and accepted plan."
        )

    def _latest_plan(self, task_id: str, pipeline_id: str) -> dict[str, Any] | None:
        lineage: set[str] = set()
        selected_pipeline = self.store.get_pipeline(pipeline_id)
        while True:
            lineage.add(selected_pipeline.id)
            if selected_pipeline.parent_pipeline_id is None:
                break
            selected_pipeline = self.store.get_pipeline(
                selected_pipeline.parent_pipeline_id
            )
        selected = None
        for event in self.store.events(task_id):
            if event.kind == "pipeline.plan.result" and event.data.get("pipeline_id") in lineage:
                plan = event.data.get("plan")
                if isinstance(plan, dict):
                    selected = plan
        return selected

    def _child_packet(self, task_id: str, pipeline: Any) -> dict[str, Any] | None:
        metadata = getattr(pipeline, "metadata", {})
        if isinstance(metadata, dict) and isinstance(metadata.get("packet"), dict):
            return dict(metadata["packet"])
        selected = None
        for event in self.store.events(task_id):
            if (
                event.kind == "pipeline.child.created"
                and event.data.get("pipeline_id") == pipeline.id
                and isinstance(event.data.get("evidence"), dict)
            ):
                selected = dict(event.data["evidence"])
        return selected

    def _declared_scope(self, task: TaskRecord, plan: dict[str, Any] | None) -> list[str]:
        if not plan:
            return []
        paths: list[str] = []
        for step in plan.get("steps", []):
            if isinstance(step, dict):
                paths.extend(path for path in step.get("files", []) if isinstance(path, str))
        return list(dict.fromkeys(paths))

    def _iteration_exists(self, task_id: str, iteration: int) -> bool:
        try:
            self.store.get_iteration(task_id, iteration)
            return True
        except KeyError:
            return False

    def _validation_evidence(self, validation: ValidationResult) -> dict[str, Any]:
        try:
            output = validation.output_path.read_text(encoding="utf-8")
        except OSError:
            output = ""
        return {
            "command": validation.command,
            "cwd": str(validation.cwd),
            "passed": validation.passed,
            "exit_code": validation.exit_code,
            "output_path": str(validation.output_path),
            "summary": validation.summary,
            "output": output,
            "started_at": validation.started_at.isoformat(),
            "completed_at": validation.completed_at.isoformat(),
        }

    def _latest_raw_review(self, task_id: str, pipeline_id: str) -> dict[str, Any] | None:
        selected = None
        for event in self.store.events(task_id):
            if event.kind == "pipeline.review.raw" and event.data.get("pipeline_id") == pipeline_id:
                value = event.data.get("review")
                if isinstance(value, dict):
                    selected = value
        return selected

    def _record_review_artifacts(self, task: TaskRecord, pipeline: Any, review: dict[str, Any], *, kind: str, action_id: str) -> None:
        payload = dict(review)
        payload["kind"] = kind
        self._archive_write(task, pipeline, f"reviews/{kind}-{_safe_filename(action_id)}.json", payload)
        try:
            findings = payload.get("findings", [])
            values = [json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item) for item in findings]
            from .task_archive import TaskArchiveWriter

            TaskArchiveWriter(self.config).materialize_review(task.id, pipeline.id, {"verdict": payload.get("verdict", "unknown"), "findings": values, "state": "available"}, review_id=f"{kind}-{_safe_filename(action_id)}", kind=kind)
        except Exception:
            pass

    def _latest_commit_message(self, task_id: str, pipeline_id: str) -> dict[str, str] | None:
        selected = None
        for event in self.store.events(task_id):
            if event.kind == "pipeline.commit_message" and event.data.get("pipeline_id") == pipeline_id:
                subject, body = event.data.get("subject"), event.data.get("body")
                if isinstance(subject, str) and isinstance(body, str):
                    selected = {"subject": subject, "body": body}
        return selected

    def _latest_commit(self, task_id: str, pipeline_id: str) -> str | None:
        selected = None
        for event in self.store.events(task_id):
            if event.kind == "pipeline.commit" and event.data.get("pipeline_id") == pipeline_id:
                value = event.data.get("commit")
                if isinstance(value, str):
                    selected = value
        return selected

    def _latest_main_identity(self, worktree: Path) -> str | None:
        if self.config.integration_mode == IntegrationMode.push_main.value and not self.config.local_only:
            fetched = run_command(["git", "fetch", self.config.git_remote, self.config.main_branch], cwd=worktree)
            if not fetched.ok:
                raise RuntimeError(fetched.stderr[-2_000:] or "git fetch failed")
            result = run_command(["git", "rev-parse", f"{self.config.git_remote}/{self.config.main_branch}"], cwd=worktree)
        else:
            result = run_command(["git", "rev-parse", self.config.main_branch], cwd=worktree)
        return result.stdout.strip() if result.ok else None

    def _prepare_base_change_child(
        self,
        task: TaskRecord,
        parent: Any,
        *,
        trigger: PipelineTrigger,
        latest_main: str,
        accepted_patch: str,
        extra_evidence: dict[str, Any] | None = None,
    ) -> Any | AdvanceResult:
        digest = sha256(
            accepted_patch.encode("utf-8", errors="surrogateescape")
        ).hexdigest()
        if parent.patch_identity is None or digest != parent.patch_identity:
            return self._block_pipeline(
                task, parent, "accepted patch evidence does not match its identity"
            )
        ordinal = max(item.ordinal for item in self.store.list_pipelines(task.id)) + 1
        prepared = self.worktrees.prepare_patch_worktree(
            task,
            ordinal=ordinal,
            base_identity=latest_main,
            patch_text=accepted_patch,
            accepted_tree=parent.output_identity,
        )
        conflict = not prepared.applied
        if conflict and sum(
            1
            for event in self.store.events(task.id)
            if event.kind == "pipeline.integration.conflict"
        ) >= self.MAX_CONFLICTS:
            return self._block_pipeline(task, parent, "conflict budget exhausted")
        selected_trigger = (
            PipelineTrigger.integration_conflict
            if conflict and trigger == PipelineTrigger.integration_rebase
            else trigger
        )
        evidence = {
            "base": parent.base_identity,
            "latest_main": latest_main,
            "accepted_tree": parent.output_identity,
            "accepted_patch_identity": digest,
            "prepared_input_tree": prepared.input_identity,
            "prepared_output_tree": prepared.output_identity,
            "prepared_patch_identity": prepared.patch_identity,
            "patch_applied": prepared.applied,
            "conflict": conflict,
            "apply_detail": prepared.detail,
            **(extra_evidence or {}),
        }
        fingerprint = _integration_no_progress_fingerprint(
            selected_trigger,
            latest_main,
            digest,
            prepared.applied,
        )
        evidence["fingerprint"] = fingerprint
        event_kind = (
            "pipeline.integration.conflict"
            if conflict
            else "pipeline.integration.base_changed"
        )
        self.store.add_event(
            task.id,
            event_kind,
            "accepted patch conflicted with latest main"
            if conflict
            else "accepted patch applied to latest main",
            {"pipeline_id": parent.id, **evidence},
        )
        if self._fingerprint_seen(task.id, fingerprint):
            return self._block_pipeline(
                task, parent, "base-change repair made no progress"
            )
        task.worktree_path = prepared.path
        task.branch_name = prepared.branch
        self.store.save(task)
        return self._new_child_pipeline(
            task,
            parent,
            selected_trigger,
            evidence,
            base_identity=prepared.base_identity,
            input_identity=prepared.input_identity,
            output_identity=prepared.output_identity,
            patch_identity=prepared.patch_identity,
        )

    def _accepted_patch(self, task: TaskRecord, pipeline: Any) -> str | None:
        if task.patch_path is None or not Path(task.patch_path).is_file():
            return None
        try:
            value = Path(task.patch_path).read_text(encoding="utf-8")
        except OSError:
            return None
        digest = sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()
        return value if digest == pipeline.patch_identity else None

    def _container_validation_runner(
        self, task: TaskRecord, pipeline: Any
    ) -> Callable[[list[str], Path, float], CommandResult]:
        if self.session_supervisor is None:
            raise RuntimeError("durable validation requires a task container")
        runtime, _ = self.session_supervisor._boundary_for(task)
        if runtime is None:
            raise RuntimeError("durable validation has no task container runtime")
        runtime.ensure_started()
        role = TaskRole.validation
        scratch = getattr(runtime.config, "scratch", None)
        if scratch is None:
            raise RuntimeError("validation role requires task scratch storage")
        scratch_path = Path(scratch) / "validation" / pipeline.id
        object_directory = scratch_path / "objects"
        object_directory.mkdir(parents=True, exist_ok=True)
        alternate = Path(runtime.config.git_common_dir) / "objects"
        container_objects = runtime.config.container_path(object_directory, role)
        container_alternate = runtime.config.container_path(alternate, role)
        session_id = f"validation-{sha256(f'{task.id}:{pipeline.id}'.encode()).hexdigest()[:16]}"
        session_uid = 10_000 + int(
            sha256(task.id.encode()).hexdigest()[:8], 16
        ) % 50_001
        validation_gid = getattr(runtime.config, "validation_gid", session_uid)
        validation_home = getattr(runtime.config, "private_sessions", None)
        writable_paths = [scratch_path, object_directory]
        if validation_home is not None:
            home = Path(validation_home) / session_id
            home.mkdir(parents=True, exist_ok=True)
            writable_paths.append(home)
        for path in writable_paths:
            os.chmod(path, 0o770)
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                os.chown(path, session_uid, validation_gid)

        def execute(command: list[str], cwd: Path, timeout: float) -> CommandResult:
            container_workdir = runtime.config.container_path(cwd, role)
            container_command = [
                _rewrite_mounted_argument(item, cwd, container_workdir)
                for item in command
            ]
            result = runtime.exec(
                role,
                session_uid=session_uid,
                session_id=session_id,
                command=container_command,
                env={
                    "GIT_OBJECT_DIRECTORY": container_objects,
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES": container_alternate,
                },
                workdir=container_workdir,
                timeout=timeout,
            )
            return CommandResult(
                args=command,
                cwd=cwd,
                returncode=result.exit_code,
                stdout=result.stdout.decode("utf-8", errors="replace"),
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )

        return execute

    def _commit_reachable(self, worktree: Path, commit: str) -> bool:
        remote = f"{self.config.git_remote}/{self.config.main_branch}"
        fetched = run_command(["git", "fetch", self.config.git_remote, self.config.main_branch], cwd=worktree)
        if not fetched.ok:
            return False
        result = run_command(["git", "merge-base", "--is-ancestor", commit, remote], cwd=worktree)
        return result.ok

    def _fingerprint_seen(self, task_id: str, fingerprint: str) -> bool:
        return sum(
            1
            for event in self.store.events(task_id)
            if event.data.get("fingerprint") == fingerprint
        ) >= 2

    def _archive_write(self, task: TaskRecord, pipeline: Any, relative: str, value: Any) -> None:
        try:
            from .task_archive import TaskArchiveWriter

            archive = TaskArchiveWriter(self.config)
            self._prepare_archive_task(archive, task, pipeline)
            archive.write_json(task.id, f"pipelines/{pipeline.id}/{relative}", self._json_safe(value))
        except Exception as exc:
            self.store.add_event(task.id, "pipeline.archive.warning", str(exc)[-500:], {"pipeline_id": pipeline.id, "path": relative})

    def _archive_bytes(self, task: TaskRecord, pipeline: Any, relative: str, value: bytes) -> None:
        try:
            from .task_archive import TaskArchiveWriter

            archive = TaskArchiveWriter(self.config)
            self._prepare_archive_task(archive, task, pipeline)
            archive.write_bytes(task.id, f"pipelines/{pipeline.id}/{relative}", value)
        except Exception as exc:
            self.store.add_event(task.id, "pipeline.archive.warning", str(exc)[-500:], {"pipeline_id": pipeline.id, "path": relative})

    def _prepare_archive_task(
        self, archive: Any, task: TaskRecord, pipeline: Any
    ) -> None:
        archive.ensure_epoch()
        task_path = archive.task_path(task.id, "task.json")
        pipelines = self.store.list_pipelines(task.id)
        runs_by_pipeline = {
            item.id: self.store.list_runs(task.id, pipeline_id=item.id)
            for item in pipelines
        }
        if not task_path.is_file():
            if not runs_by_pipeline.get(pipeline.id):
                raise RuntimeError("cannot archive a pipeline before its first run")
            archive.create_task_from_record(task, pipeline=pipeline)
        materialized = set()
        for item in pipelines:
            runs = runs_by_pipeline[item.id]
            if not runs:
                continue
            archive.materialize_pipeline(task.id, item, runs=runs)
            materialized.add(item.id)
        if not materialized:
            raise RuntimeError("cannot archive a task before its first pipeline run")
        metadata = json.loads(task_path.read_text(encoding="utf-8"))
        metadata["pipelines"] = [
            reference
            for reference in metadata.get("pipelines", [])
            if reference.get("pipelineId") in materialized
        ]
        metadata["status"] = str(task.status)
        metadata["updatedAt"] = task.updated_at.isoformat().replace("+00:00", "Z")
        if pipeline.id in materialized:
            metadata["currentPipelineId"] = pipeline.id
        elif metadata.get("currentPipelineId") not in materialized:
            metadata["currentPipelineId"] = max(
                (item for item in pipelines if item.id in materialized),
                key=lambda item: item.ordinal,
            ).id
        metadata["summary"] = {
            "title": task.spec.title,
            "text": task.summary or task.spec.prompt,
        }
        archive.write_json(task.id, "task.json", metadata)

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict):
            return {str(key): StewardExecutor._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [StewardExecutor._json_safe(item) for item in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if hasattr(value, "value"):
            return str(value.value)
        return str(value)

    def run_task(self, task_id: str) -> bool:
        task = self.store.get(task_id)
        if TaskStatus(task.status) != TaskStatus.queued:
            self.store.add_event(task.id, "task.skipped", f"status is {task.status}")
            return False
        if _is_integration_task(task):
            return self._run_integration_task(task.id)

        self.store.start_worker(task.id, "worker started")
        task = self.store.get(task.id)
        worktree, branch = self.worktrees.create(task)
        transcript_path, last_message_path = self.runner.paths(task)
        task.worktree_path = worktree
        task.branch_name = branch
        task.transcript_path = transcript_path
        task.last_message_path = last_message_path
        self.store.save(task)
        self.store.add_event(
            task.id, "worktree.ready", str(worktree), {"branch": branch}
        )
        implementation_plan = None
        if TaskWorkflow(task.spec.workflow) == TaskWorkflow.feature:
            implementation_plan = self._run_implementation_plan(task.id)
            if implementation_plan is None:
                return False
            self.store.start_worker(task.id, "implementation plan ready; worker started")
            task = self.store.get(task.id)
        self.store.begin_iteration(
            task.id,
            0,
            "Initial attempt",
            worker_name="worker",
            worker_prompt_path=self.config.prompts_dir / task.id / "worker.md",
            worker_transcript_path=transcript_path,
            worker_last_message_path=last_message_path,
        )

        result = self._run_with_heartbeat(
            task.id,
            lambda: self.runner.run(
                task,
                render_worker_prompt(task, self.config, implementation_plan),
                worktree,
            ),
        )
        self.store.add_event(
            task.id,
            "worker.finished",
            str(result.exit_code),
            {"diagnostics": result.diagnostics},
        )
        self.store.finish_iteration_worker(task.id, 0, result)
        if not self._record_worker_result(task.id, result, "worker failed"):
            return False
        revisions = 0
        prepared, revisions = self._prepare_patch_with_validation_revisions(
            task.id, "initial", revisions, iteration=0
        )
        if not prepared:
            return TaskStatus(self.store.get(task.id).status) == TaskStatus.no_changes

        revisions = self._review_and_revise_until_approved(task.id, revisions)
        if revisions is None:
            return False
        return self._queue_or_finish_integration(task.id)

    def _run_implementation_plan(self, task_id: str) -> dict[str, Any] | None:
        task = self.store.get(task_id)
        if task.worktree_path is None:
            self._finish_task(task.id, TaskStatus.failed, "planning requested without worktree")
            return None
        if self.worktrees.has_changes(task.worktree_path):
            self._finish_task(task.id, TaskStatus.failed, "planning worktree was not clean")
            return None
        prompt = render_implementation_plan_prompt(task, self.config)
        schema_path = implementation_plan_schema_path(self.config)
        settings = self.config.codex_settings(CodexStage.implementation_plan)
        for run in range(MAX_PLAN_RUN_ATTEMPTS):
            name = f"implementation-plan-{run}"
            transcript_path, last_message_path = self.runner.paths(task, name=name)
            prompt_path = self.config.prompts_dir / task.id / f"{name}.md"
            self.store.start_implementation_plan(
                task.id,
                "implementation planning"
                if run == 0
                else f"implementation planning retry {run}",
            )
            self.store.begin_plan_run(
                task.id,
                run,
                prompt_path=prompt_path,
                transcript_path=transcript_path,
                last_message_path=last_message_path,
                model=settings.model,
                reasoning_effort=settings.reasoning_effort,
            )
            self.store.add_event(
                task.id,
                "implementation_plan.started",
                name,
                {
                    "run": run,
                    "model": settings.model,
                    "reasoning_effort": settings.reasoning_effort,
                },
            )
            result = self._run_with_heartbeat(
                task.id,
                lambda: self.runner.run(
                    task,
                    prompt,
                    task.worktree_path,
                    name=name,
                    output_schema=schema_path,
                    stage=CodexStage.implementation_plan,
                    sandbox="read-only",
                ),
            )
            changed = self.worktrees.has_changes(task.worktree_path)
            plan = (
                parse_implementation_plan(result.final_message, task, self.config)
                if result.completed and not changed
                else None
            )
            plan_path = (
                save_implementation_plan(self.config, task.id, run, plan)
                if plan is not None
                else None
            )
            self.store.finish_plan_run(
                task.id,
                run,
                result,
                plan=plan,
                plan_path=plan_path,
            )
            retryable = run + 1 < MAX_PLAN_RUN_ATTEMPTS
            if changed:
                self.store.add_event(
                    task.id,
                    "implementation_plan.failed",
                    "implementation planner changed the worktree",
                    {"run": run, "retryable": False},
                )
                self._finish_task(
                    task.id,
                    TaskStatus.failed,
                    "implementation planner changed the worktree",
                )
                return None
            if plan is not None and plan_path is not None:
                self.store.add_event(
                    task.id,
                    "implementation_plan.finished",
                    str(plan_path),
                    {
                        "run": run,
                        "plan_path": str(plan_path),
                        "model": result.model,
                        "reasoning_effort": result.reasoning_effort,
                    },
                )
                return plan
            event_kind = (
                "implementation_plan.invalid_output"
                if result.completed
                else "implementation_plan.failed"
            )
            self.store.add_event(
                task.id,
                event_kind,
                result.final_message[-2000:] or f"plan exited {result.exit_code}",
                {
                    "run": run,
                    "retryable": retryable,
                    "exit_code": result.exit_code,
                    "diagnostics": result.diagnostics,
                },
            )
            if not retryable:
                self._finish_task(
                    task.id,
                    TaskStatus.failed,
                    "implementation planning failed",
                )
                return None
        return None

    def _review_and_revise_until_approved(
        self, task_id: str, revisions: int
    ) -> int | None:
        while True:
            review = self._review(task_id, attempt=revisions)
            if review is None:
                return None
            if review_approved(review):
                return revisions
            if revisions >= MAX_TASK_REVISIONS:
                self._finish_task(
                    task_id,
                    TaskStatus.blocked,
                    f"revision budget exhausted after {MAX_TASK_REVISIONS} revision(s): "
                    + summarize_review(review),
                )
                return None
            revisions += 1
            if not self._revise_from_review(task_id, review, revisions):
                return None
            prepared, revisions = self._prepare_patch_with_validation_revisions(
                task_id,
                f"review revision {revisions}",
                revisions,
                iteration=revisions,
                no_changes_status=TaskStatus.failed,
            )
            if not prepared:
                return None

    def _record_worker_result(
        self, task_id: str, result: WorkerResult, failure_summary: str
    ) -> bool:
        task = self.store.get(task_id)
        task.transcript_path = result.transcript_path
        task.last_message_path = result.last_message_path
        if self.session_supervisor is None and result.thread_id:
            # Legacy in-process harness compatibility only. Production
            # container sessions keep provider IDs in private ledger state.
            metadata = dict(task.spec.metadata)
            metadata["worker_thread_id"] = result.thread_id
            task.spec.metadata = metadata
        self.store.save(task)
        if result.completed:
            return True
        self._finish_task(
            task.id, TaskStatus.failed, result.final_message or failure_summary
        )
        return False

    def _finish_task(
        self, task_id: str, status: TaskStatus, summary: str = ""
    ) -> TaskRecord:
        task = self.store.finish_task(task_id, status, summary)
        self.clean_finished_task_worktree(task)
        return task

    def clean_finished_task_worktree(self, task: TaskRecord) -> bool:
        if task.worktree_path is None:
            return False
        if _is_steward_owned_worktree(self.config, task.worktree_path):
            branch = (
                None if self._preserves_finished_task_branch(task) else task.branch_name
            )
            self.worktrees.remove(task.worktree_path, branch)
            self.store.add_event(
                task.id,
                "worktree.cleaned",
                str(task.worktree_path),
                {
                    "status": str(task.status),
                    "branch": task.branch_name or "",
                    "branch_preserved": branch is None and task.branch_name is not None,
                },
            )
            return True
        return False

    def _preserves_finished_task_branch(self, task: TaskRecord) -> bool:
        if not _is_integration_task(task):
            return False
        event_kinds = {event.kind for event in self.store.events(task.id)}
        if "main.pushed" in event_kinds:
            return False
        if "integration.commit_created" in event_kinds:
            return True
        if task.branch_name and self.worktrees.branch_has_commits_not_on_main(
            task.branch_name
        ):
            return True
        return task.summary.startswith("local-only integration commit ") or (
            TaskStatus(task.status) == TaskStatus.failed
            and task.summary == "push failed"
        )

    def _prepare_patch(
        self,
        task_id: str,
        label: str,
        *,
        iteration: int,
        no_changes_status: TaskStatus,
    ) -> PatchPreparationResult:
        task = self.store.get(task_id)
        if task.worktree_path is None:
            self._finish_task(
                task.id, TaskStatus.failed, "patch preparation requested without worktree"
            )
            return PatchPreparationResult.terminal_failure
        if not self.worktrees.has_changes(task.worktree_path):
            self._finish_task(
                task.id, no_changes_status, "worker produced no source changes"
            )
            return PatchPreparationResult.no_changes

        forbidden = self.worktrees.forbidden_paths(task.worktree_path)
        if forbidden:
            self._finish_task(
                task.id,
                TaskStatus.failed,
                "generated state changed: " + ", ".join(forbidden),
            )
            return PatchPreparationResult.terminal_failure
        if self._block_task_for_frozen_paths(task, task.worktree_path):
            return PatchPreparationResult.terminal_failure

        patch_path = self.config.patches_dir / task.id / f"{_iteration_log_label(iteration)}.patch"
        self._save_authoritative_patch(task, iteration, patch_path)
        self.store.record_iteration_patch(task.id, iteration, patch_path)
        self.store.start_validation(task.id, f"validation running: {label}")
        validations = self._run_gates_for_iteration(
            task.id, task.worktree_path, iteration
        )
        task = self.store.get(task.id)
        if self._block_task_for_frozen_paths(task, task.worktree_path):
            return PatchPreparationResult.terminal_failure
        if any(not validation.passed for validation in validations):
            self._save_authoritative_patch(task, iteration, patch_path)
            self.store.record_iteration_patch(task.id, iteration, patch_path)
            failed = [validation for validation in validations if not validation.passed]
            self._latest_failed_validations[task.id] = failed
            self.store.add_event(
                task.id,
                "validation.failed",
                _summarize_validations(validations),
                {
                    "label": label,
                    "failed": [
                        {
                            "command": validation.command,
                            "exit_code": validation.exit_code,
                            "summary": validation.summary,
                            "output_path": str(validation.output_path),
                        }
                        for validation in failed
                    ],
                    "patch_path": str(patch_path),
                },
            )
            return PatchPreparationResult.validation_failed

        self._latest_failed_validations.pop(task.id, None)
        self._save_authoritative_patch(task, iteration, patch_path)
        task = self.store.get(task.id)
        task.patch_path = patch_path
        self.store.save(task)
        self.store.record_iteration_patch(task.id, iteration, patch_path)
        self.store.add_event(task.id, "patch.saved", str(patch_path), {"label": label})
        return PatchPreparationResult.ready

    def _save_authoritative_patch(
        self, task: TaskRecord, iteration: int, patch_path: Path
    ) -> None:
        """Save the executor-owned patch, then refresh private trajectory evidence."""

        assert task.worktree_path is not None
        self.worktrees.save_patch(task.worktree_path, patch_path)
        try:
            iteration_record = self.store.get_iteration(task.id, iteration)
            transcript_path = iteration_record.worker_transcript_path or task.transcript_path
            if transcript_path is not None:
                self.runner.reconcile_tool_changes(
                    transcript_path, final_patch_path=patch_path
                )
        except Exception:
            # Trajectory capture is evidence-only and must never alter patch
            # ownership, validation, retries, or task state.
            return

    def _block_task_for_frozen_paths(self, task: TaskRecord, worktree: Path) -> bool:
        frozen = self.worktrees.frozen_paths(worktree, task)
        if not frozen:
            return False
        message = "frozen paths changed: " + ", ".join(frozen)
        self._finish_task(task.id, TaskStatus.blocked, message)
        self.store.add_event(
            task.id,
            "path_policy.blocked",
            message,
            {"paths": frozen},
        )
        return True

    def _prepare_patch_with_validation_revisions(
        self,
        task_id: str,
        initial_label: str,
        revisions: int,
        *,
        iteration: int,
        no_changes_status: TaskStatus = TaskStatus.no_changes,
    ) -> tuple[bool, int]:
        prepared = self._prepare_patch(
            task_id,
            initial_label,
            iteration=iteration,
            no_changes_status=no_changes_status,
        )
        if prepared == PatchPreparationResult.ready:
            return True, revisions
        if prepared != PatchPreparationResult.validation_failed:
            return False, revisions

        seen_failure_states = {self._validation_failure_state(task_id)}
        while revisions < MAX_TASK_REVISIONS:
            revisions += 1
            failed = self._latest_failed_validations.get(task_id, [])
            task = self.store.get(task_id)
            if task.worktree_path is None:
                self._finish_task(
                    task.id,
                    TaskStatus.failed,
                    "validation revision requested without worktree",
                )
                return False, revisions
            before_revision = sha256(
                self.worktrees.diff(task.worktree_path).encode("utf-8")
            ).hexdigest()
            if not self._revise_from_validation(task_id, failed, revisions):
                return False, revisions
            task = self.store.get(task_id)
            if task.worktree_path is None:
                return False, revisions
            after_revision = sha256(
                self.worktrees.diff(task.worktree_path).encode("utf-8")
            ).hexdigest()
            revision_changed = after_revision != before_revision
            prepared = self._prepare_patch(
                task_id,
                f"validation revision {revisions}",
                iteration=revisions,
                no_changes_status=TaskStatus.failed,
            )
            if prepared == PatchPreparationResult.ready:
                return True, revisions
            if prepared != PatchPreparationResult.validation_failed:
                return False, revisions
            failure_state = self._validation_failure_state(task_id)
            if failure_state in seen_failure_states:
                self._block_stalled_validation_revision(
                    task_id,
                    revisions,
                    self._latest_failed_validations.get(task_id, []),
                    (
                        "repeated a prior patch and failure"
                        if revision_changed
                        else "produced no patch changes"
                    ),
                )
                return False, revisions
            seen_failure_states.add(failure_state)
        self._finish_task(
            task_id,
            TaskStatus.blocked,
            f"revision budget exhausted after {MAX_TASK_REVISIONS} revision(s)",
        )
        return False, revisions

    def _validation_failure_state(self, task_id: str) -> tuple[str, str]:
        task = self.store.get(task_id)
        if task.worktree_path is None:
            return "", ""
        patch_digest = sha256(
            self.worktrees.diff(task.worktree_path).encode("utf-8")
        ).hexdigest()
        failures = [
            {
                "command": validation.command,
                "exit_code": validation.exit_code,
                "output_sha256": sha256(
                    _stable_validation_diagnostics(validation).encode("utf-8")
                ).hexdigest(),
            }
            for validation in self._latest_failed_validations.get(task_id, [])
            if not validation.passed
        ]
        failure_digest = sha256(
            json.dumps(failures, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return patch_digest, failure_digest

    def _block_stalled_validation_revision(
        self,
        task_id: str,
        revision: int,
        validations: list[ValidationResult],
        reason: str,
    ) -> None:
        summary = (
            f"validation revision {revision} {reason}; unresolved: "
            f"{_summarize_validations(validations)}"
        )
        self._finish_task(task_id, TaskStatus.blocked, summary)
        self.store.add_event(
            task_id,
            "validation.revision_stalled",
            summary,
            {
                "revision": revision,
                "reason": reason,
                "failed": [
                    _validation_context(validation)
                    for validation in validations
                    if not validation.passed
                ],
            },
        )

    def _review(self, task_id: str, *, attempt: int) -> dict[str, Any] | None:
        task = self.store.get(task_id)
        if task.patch_path is None or task.worktree_path is None:
            self._finish_task(
                task.id, TaskStatus.failed, "review requested without patch/worktree"
            )
            return None
        prompt = render_review_prompt(task, self.config)
        schema_path = review_schema_path(self.config)
        for review_run in range(MAX_REVIEW_RUN_ATTEMPTS):
            reviewer_name = _reviewer_name(attempt, review_run)
            retryable = review_run + 1 < MAX_REVIEW_RUN_ATTEMPTS
            self.store.start_review(
                task.id,
                "review started" if review_run == 0 else f"review retry {review_run}",
            )
            transcript_path, last_message_path = self.runner.paths(
                task, name=reviewer_name
            )
            self.store.start_iteration_review(
                task.id,
                attempt,
                reviewer_name=reviewer_name,
                reviewer_prompt_path=self.config.prompts_dir
                / task.id
                / f"{reviewer_name}.md",
                reviewer_transcript_path=transcript_path,
                reviewer_last_message_path=last_message_path,
                review_run=review_run,
            )
            result = self._run_with_heartbeat(
                task.id,
                lambda: self.runner.run_review(
                    task,
                    prompt,
                    task.worktree_path,
                    name=reviewer_name,
                    output_schema=schema_path,
                ),
            )
            if not result.completed:
                self.store.record_iteration_review(
                    task.id,
                    attempt,
                    result,
                    reviewer_name=reviewer_name,
                    review_run=review_run,
                    review=None,
                )
                self.store.add_event(
                    task.id,
                    "review.failed",
                    result.final_message[-2000:] or f"review exited {result.exit_code}",
                    {
                        "attempt": attempt,
                        "review_run": review_run,
                        "retryable": retryable,
                        "exit_code": result.exit_code,
                        "command": result.command,
                        "diagnostics": result.diagnostics,
                    },
                )
                if retryable:
                    continue
                self._finish_task(
                    task.id, TaskStatus.failed, result.final_message or "review failed"
                )
                return None
            review = parse_review(result.final_message)
            if review is None:
                self.store.record_iteration_review(
                    task.id,
                    attempt,
                    result,
                    reviewer_name=reviewer_name,
                    review_run=review_run,
                    review=None,
                )
                self.store.add_event(
                    task.id,
                    "review.invalid_output",
                    result.final_message[-2000:],
                    {
                        "attempt": attempt,
                        "review_run": review_run,
                        "retryable": retryable,
                        "command": result.command,
                        "diagnostics": result.diagnostics,
                    },
                )
                if retryable:
                    continue
                self._finish_task(
                    task.id, TaskStatus.failed, "review invalid output"
                )
                return None
            self.store.record_iteration_review(
                task.id,
                attempt,
                result,
                reviewer_name=reviewer_name,
                review_run=review_run,
                review=review,
            )
            self.store.add_event(
                task.id,
                "review.finished",
                json.dumps(review, sort_keys=True),
                {
                    "review": review,
                    "attempt": attempt,
                    "review_run": review_run,
                    "diagnostics": result.diagnostics,
                },
            )
            if review_approved(review):
                self.store.start_worker(task.id, "review approved")
            return review
        return None

    def _revise_from_review(
        self, task_id: str, review: dict[str, Any], revision: int
    ) -> bool:
        task = self.store.get(task_id)
        if task.worktree_path is None:
            self._finish_task(
                task.id, TaskStatus.failed, "revision requested without worktree"
            )
            return False
        self.store.start_worker(
            task.id, f"addressing review revision {revision}"
        )
        self.store.add_event(
            task.id,
            "worker.revision_requested",
            summarize_review(review),
            {"revision": revision, "review": review},
        )
        task = self.store.get(task.id)
        transcript_path, last_message_path = self.runner.paths(
            task, name=f"worker-revision-{revision}"
        )
        task.transcript_path = transcript_path
        task.last_message_path = last_message_path
        self.store.save(task)
        self.store.begin_iteration(
            task.id,
            revision,
            f"Review revision {revision}",
            worker_name=f"worker-revision-{revision}",
            worker_prompt_path=self.config.prompts_dir
            / task.id
            / f"worker-revision-{revision}.md",
            worker_transcript_path=transcript_path,
            worker_last_message_path=last_message_path,
            running_summary=f"addressing review revision {revision}",
        )
        result = self._run_with_heartbeat(
            task.id,
            lambda: self.runner.run(
                task,
                render_review_revision_prompt(task, review, self.config),
                task.worktree_path,
                name=f"worker-revision-{revision}",
            ),
        )
        self.store.add_event(
            task.id,
            "worker.revision_finished",
            str(result.exit_code),
            {"revision": revision, "diagnostics": result.diagnostics},
        )
        self.store.finish_iteration_worker(task.id, revision, result)
        return self._record_worker_result(
            task.id, result, f"worker revision {revision} failed"
        )

    def _revise_from_validation(
        self, task_id: str, validations: list[ValidationResult], revision: int
    ) -> bool:
        task = self.store.get(task_id)
        if task.worktree_path is None:
            self._finish_task(
                task.id, TaskStatus.failed, "validation revision requested without worktree"
            )
            return False
        self.store.start_worker(
            task.id, f"addressing validation revision {revision}"
        )
        self.store.add_event(
            task.id,
            "worker.validation_revision_requested",
            _summarize_validations(validations),
            {
                "revision": revision,
                "failed": [
                    {
                        "command": validation.command,
                        "exit_code": validation.exit_code,
                        "summary": validation.summary,
                        "output_path": str(validation.output_path),
                    }
                    for validation in validations
                    if not validation.passed
                ],
            },
        )
        task = self.store.get(task.id)
        name = f"worker-validation-revision-{revision}"
        transcript_path, last_message_path = self.runner.paths(task, name=name)
        task.transcript_path = transcript_path
        task.last_message_path = last_message_path
        self.store.save(task)
        self.store.begin_iteration(
            task.id,
            revision,
            f"Validation revision {revision}",
            worker_name=name,
            worker_prompt_path=self.config.prompts_dir / task.id / f"{name}.md",
            worker_transcript_path=transcript_path,
            worker_last_message_path=last_message_path,
            running_summary=f"addressing validation revision {revision}",
        )
        result = self._run_with_heartbeat(
            task.id,
            lambda: self.runner.run(
                task,
                render_validation_revision_prompt(task, validations, self.config),
                task.worktree_path,
                name=name,
            ),
        )
        self.store.add_event(
            task.id,
            "worker.validation_revision_finished",
            str(result.exit_code),
            {"revision": revision, "diagnostics": result.diagnostics},
        )
        self.store.finish_iteration_worker(task.id, revision, result)
        return self._record_worker_result(
            task.id, result, f"worker validation revision {revision} failed"
        )

    def _revise_from_integration_conflict(
        self,
        task_id: str,
        conflict: str,
        failed_patch: str,
        revision: int,
    ) -> bool:
        task = self.store.get(task_id)
        if task.worktree_path is None:
            self._finish_task(
                task.id, TaskStatus.failed, "integration repair requested without worktree"
            )
            return False
        self.store.start_worker(
            task.id, f"addressing integration conflict revision {revision}"
        )
        self.store.add_event(
            task.id,
            "worker.integration_revision_requested",
            "patch conflict on latest main",
            {"revision": revision, "conflict": conflict[-4000:]},
        )
        try:
            self.worktrees.reset_to_main(task.worktree_path)
        except (OSError, RuntimeError) as exc:
            message = str(exc)[-4000:]
            self.store.add_event(
                task.id,
                "integration.repair_reset_failed",
                message,
                {"revision": revision},
            )
            self._finish_task(
                task.id, TaskStatus.blocked, "integration repair reset failed"
            )
            return False
        task = self.store.get(task.id)
        name = f"worker-integration-revision-{revision}"
        transcript_path, last_message_path = self.runner.paths(task, name=name)
        task.transcript_path = transcript_path
        task.last_message_path = last_message_path
        self.store.save(task)
        self.store.begin_iteration(
            task.id,
            revision,
            f"Integration conflict revision {revision}",
            worker_name=name,
            worker_prompt_path=self.config.prompts_dir / task.id / f"{name}.md",
            worker_transcript_path=transcript_path,
            worker_last_message_path=last_message_path,
            running_summary=f"addressing integration conflict revision {revision}",
        )
        result = self._run_with_heartbeat(
            task.id,
            lambda: self.runner.run(
                task,
                render_integration_revision_prompt(task, conflict, failed_patch),
                task.worktree_path,
                name=name,
            ),
        )
        self.store.add_event(
            task.id,
            "worker.integration_revision_finished",
            str(result.exit_code),
            {"revision": revision, "diagnostics": result.diagnostics},
        )
        self.store.finish_iteration_worker(task.id, revision, result)
        return self._record_worker_result(
            task.id, result, f"worker integration revision {revision} failed"
        )

    def _repair_integration_conflict(
        self,
        source_task_id: str,
        conflict: str,
        failed_patch: str,
        integration_task_id: str,
    ) -> bool:
        revisions = _next_revision(self.store, source_task_id)
        if revisions > MAX_TASK_REVISIONS:
            self._finish_task(
                source_task_id,
                TaskStatus.blocked,
                f"revision budget exhausted after {MAX_TASK_REVISIONS} revision(s)",
            )
            return False
        if not self._revise_from_integration_conflict(
            source_task_id, conflict, failed_patch, revisions
        ):
            return False
        prepared, revisions = self._prepare_patch_with_validation_revisions(
            source_task_id,
            f"integration conflict revision {revisions}",
            revisions,
            iteration=revisions,
            no_changes_status=TaskStatus.no_changes,
        )
        if not prepared:
            return (
                TaskStatus(self.store.get(source_task_id).status)
                == TaskStatus.no_changes
            )
        approved_revision = self._review_and_revise_until_approved(
            source_task_id, revisions
        )
        if approved_revision is None:
            return False
        source = self.store.get(source_task_id)
        self.store.add_event(
            source.id,
            "integration.retry_requested",
            integration_task_id,
            {
                "failed_integration_task_id": integration_task_id,
                "revision": approved_revision,
            },
        )
        return self._queue_or_finish_integration(source.id)

    def _repair_integration_validation_failure(
        self,
        source_task_id: str,
        failed_validations: list[ValidationResult],
        rebased_patch: str,
        integration_task_id: str,
    ) -> bool:
        revisions = _next_revision(self.store, source_task_id)
        if revisions > MAX_TASK_REVISIONS:
            self._finish_task(
                source_task_id,
                TaskStatus.blocked,
                f"revision budget exhausted after {MAX_TASK_REVISIONS} revision(s)",
            )
            return False
        source = self.store.get(source_task_id)
        if source.worktree_path is None:
            self._finish_task(
                source_task_id,
                TaskStatus.failed,
                "integration validation repair requested without worktree",
            )
            return False
        self.worktrees.reset_to_main(source.worktree_path)
        self.worktrees.apply_patch(source.worktree_path, rebased_patch)
        self._latest_failed_validations[source_task_id] = failed_validations
        if not self._revise_from_validation(
            source_task_id, failed_validations, revisions
        ):
            return False
        prepared, revisions = self._prepare_patch_with_validation_revisions(
            source_task_id,
            f"integration validation revision {revisions}",
            revisions,
            iteration=revisions,
            no_changes_status=TaskStatus.failed,
        )
        if not prepared:
            return False
        approved_revision = self._review_and_revise_until_approved(
            source_task_id, revisions
        )
        if approved_revision is None:
            return False
        self.store.add_event(
            source_task_id,
            "integration.retry_requested",
            integration_task_id,
            {
                "failed_integration_task_id": integration_task_id,
                "revision": approved_revision,
            },
        )
        return self._queue_or_finish_integration(source_task_id)

    def _run_with_heartbeat(
        self, task_id: str, run: Callable[[], WorkerResult]
    ) -> WorkerResult:
        stop = threading.Event()
        thread = threading.Thread(
            target=self._heartbeat_active_task,
            args=(task_id, stop),
            daemon=True,
        )
        thread.start()
        try:
            result = run()
            self._record_codex_retries(task_id, result)
            return result
        finally:
            stop.set()
            thread.join(timeout=1)

    def _record_codex_retries(self, task_id: str, result: WorkerResult) -> None:
        retries = result.diagnostics.get("retries")
        if not isinstance(retries, list):
            return
        for retry in retries:
            if not isinstance(retry, dict):
                continue
            self.store.add_event(
                task_id,
                "codex.retry",
                f"{result.stage} retry attempt {retry.get('next_attempt', '?')}",
                {"stage": str(result.stage), **retry},
            )

    def _heartbeat_active_task(self, task_id: str, stop: threading.Event) -> None:
        while not stop.wait(WORKER_HEARTBEAT_SECONDS):
            self.store.touch_active_task(task_id)

    def _queue_or_finish_integration(self, task_id: str) -> bool:
        task = self.store.get(task_id)
        if task.patch_path is None or task.worktree_path is None:
            self._finish_task(
                task.id,
                TaskStatus.failed,
                "integration requested without patch/worktree",
            )
            return False
        if self.config.integration_mode == IntegrationMode.local_only.value:
            self._finish_task(
                task.id, TaskStatus.succeeded, "validated patch ready"
            )
            return True

        integration, created = self._enqueue_integration_task(task)
        task = self.store.get(task.id)
        self.store.start_integration(
            task.id,
            f"integration queued: {integration.id}",
        )
        self.store.add_event(
            task.id,
            "integration.queued",
            integration.id,
            {"integration_task_id": integration.id, "created": created},
        )
        return True

    def _enqueue_integration_task(self, source: TaskRecord) -> tuple[TaskRecord, bool]:
        assert source.patch_path is not None
        spec = TaskSpec(
            kind=TaskKind.integration,
            workflow=source.spec.workflow,
            worker=WorkerKind.integration_manager,
            title=f"Integrate {source.spec.title}",
            prompt=(
                f"Apply, validate, commit, and push reviewed patch for {source.id}."
            ),
            priority=source.spec.priority,
            risk=source.spec.risk,
            source="integration",
            allow_main_write=True,
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(source.patch_path),
                "source_worktree_path": str(source.worktree_path)
                if source.worktree_path
                else "",
                "dedupe_key": f"integration:{source.id}",
            },
        )
        return self.store.add_task(spec, dedupe_key=f"integration:{source.id}")

    def _run_integration_task(self, task_id: str) -> bool:
        task = self.store.get(task_id)
        with _integration_lock(self.config.state_dir):
            task = self.store.get(task.id)
            transcript = IntegrationTranscript(
                self.config.transcripts_dir / task.id / "integration" / "transcript.txt"
            )
            task.transcript_path = transcript.path
            self.store.save(task)
            transcript.write(
                "start",
                f"Integration run {task.id} started for {task.spec.metadata.get('source_task_id', '-')}",
            )
            self.store.start_integration(
                task.id, "integration started"
            )
            source = self._source_task_for_integration(task)
            if source is None:
                transcript.write("error", "integration source task missing")
                self._finish_task(
                    task.id, TaskStatus.failed, "integration source task missing"
                )
                return False
            if TaskStatus(source.status).terminal:
                transcript.write(
                    "skip",
                    f"integration source already terminal: {source.status}",
                )
                self._finish_task(
                    task.id,
                    TaskStatus.no_changes,
                    f"integration source already {source.status}",
                )
                self.store.add_event(
                    source.id,
                    "integration.skipped",
                    f"stale integration task {task.id} skipped",
                    {
                        "integration_task_id": task.id,
                        "source_status": str(source.status),
                    },
                )
                return True
            transcript.write("source", f"{source.id} - {source.spec.title}")
            ok = self._integrate_source_task(task.id, source.id, transcript)
            transcript.write(
                "finish",
                f"Integration run finished with status {self.store.get(task.id).status}",
            )
            return ok

    def _source_task_for_integration(self, task: TaskRecord) -> TaskRecord | None:
        source_task_id = task.spec.metadata.get("source_task_id")
        if not isinstance(source_task_id, str) or not source_task_id:
            return None
        try:
            return self.store.get(source_task_id)
        except KeyError:
            return None

    def _integrate_source_task(
        self,
        integration_task_id: str,
        source_task_id: str,
        transcript: "IntegrationTranscript",
    ) -> bool:
        task = self.store.get(integration_task_id)
        source = self.store.get(source_task_id)
        preflight_result = self._integration_preflight(task, source, transcript)
        if preflight_result is not None:
            return preflight_result

        worktree = self._start_integration_worktree(task, source, transcript)
        patch_text, patch_result = self._apply_source_patch_for_integration(
            task, source, worktree, transcript
        )
        if patch_result is not None:
            return patch_result

        task, validations = self._run_integration_validations(
            task, worktree, transcript
        )
        block_result = self._block_integration_for_frozen_paths(
            task, source, worktree, transcript
        )
        if block_result is not None:
            return block_result
        validation_result = self._handle_integration_validation_failure(
            task, source, validations, worktree, transcript
        )
        if validation_result is not None:
            return validation_result

        validated_tree = self.worktrees.stage_tree(worktree)
        transcript.write("validation", f"validated tree: {validated_tree}")
        commit_message = self._integration_commit_message(
            task, source, patch_text, validations, transcript
        )
        if commit_message is None:
            return False
        block_result = self._block_integration_for_frozen_paths(
            task, source, worktree, transcript
        )
        if block_result is not None:
            return block_result

        sha, commit_result = self._commit_integration_patch(
            task,
            source,
            worktree,
            commit_message,
            validated_tree,
            transcript,
        )
        if commit_result is not None:
            return commit_result

        assert sha is not None
        return self._finish_or_push_integration_commit(
            task, source, worktree, sha, transcript
        )

    def _integration_preflight(
        self,
        task: TaskRecord,
        source: TaskRecord,
        transcript: "IntegrationTranscript",
    ) -> bool | None:
        if source.patch_path is None:
            transcript.write("error", "source task has no patch")
            self._finish_task(
                task.id, TaskStatus.failed, "source task has no patch"
            )
            self._finish_task(
                source.id, TaskStatus.failed, "integration failed: no patch"
            )
            return False
        transcript.write("patch", f"source patch: {source.patch_path}")
        if self.config.integration_mode == IntegrationMode.local_only.value:
            transcript.write(
                "skip",
                "remote integration disabled; leaving source patch validated and ready",
            )
            self._finish_task(
                task.id, TaskStatus.no_changes, "remote integration disabled"
            )
            self._finish_task(
                source.id, TaskStatus.succeeded, "validated patch ready"
            )
            return True
        today = utc_now().astimezone(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        if self.store.count_events_since(
            "main.pushed", today
        ) >= self.config.limits.max_main_pushes_per_day:
            transcript.write("blocked", "main push budget reached")
            self._finish_task(
                task.id, TaskStatus.blocked, "main push budget reached"
            )
            self._finish_task(
                source.id, TaskStatus.blocked, "main push budget reached"
            )
            return False
        return None

    def _start_integration_worktree(
        self,
        task: TaskRecord,
        source: TaskRecord,
        transcript: "IntegrationTranscript",
    ) -> Path:
        worktree, branch = self.worktrees.create(task)
        transcript.write("worktree", f"{worktree} on {branch}")
        task.worktree_path = worktree
        task.branch_name = branch
        task.patch_path = source.patch_path
        self.store.save(task)
        self.store.add_event(
            task.id,
            "integration.source",
            source.id,
            {"source_task_id": source.id, "source_patch_path": str(source.patch_path)},
        )
        self.store.add_event(
            source.id,
            "integration.started",
            task.id,
            {"integration_task_id": task.id},
        )
        return worktree

    def _apply_source_patch_for_integration(
        self,
        task: TaskRecord,
        source: TaskRecord,
        worktree: Path,
        transcript: "IntegrationTranscript",
    ) -> tuple[str, bool | None]:
        patch_text = ""
        try:
            patch_text = source.patch_path.read_text(encoding="utf-8")
            transcript.write(
                "reset",
                f"resetting worktree to {self.config.git_remote}/{self.config.main_branch}",
            )
            self.worktrees.reset_to_main(worktree)
        except (OSError, RuntimeError) as exc:
            message = str(exc)[-4000:]
            transcript.write("reset_failed", message[-2000:])
            self._finish_task(
                task.id, TaskStatus.blocked, "integration reset failed"
            )
            self._finish_task(
                source.id, TaskStatus.blocked, "integration reset failed"
            )
            self.store.add_event(
                source.id,
                "integration.reset_failed",
                message,
                {"integration_task_id": task.id},
            )
            return patch_text, False
        try:
            transcript.write("apply", "applying reviewed patch")
            frozen = frozen_patch_paths(self.config, source, patch_text)
            if frozen:
                message = "frozen paths changed: " + ", ".join(frozen)
                transcript.write("path_policy_blocked", message)
                self._finish_task(task.id, TaskStatus.blocked, message)
                self._finish_task(source.id, TaskStatus.blocked, message)
                self.store.add_event(
                    source.id,
                    "path_policy.blocked",
                    message,
                    {"integration_task_id": task.id, "paths": frozen},
                )
                return patch_text, False
            self.worktrees.apply_patch(worktree, patch_text)
        except (OSError, RuntimeError) as exc:
            conflict = str(exc)[-4000:]
            transcript.write("conflict", conflict[-2000:])
            self._finish_task(
                task.id, TaskStatus.blocked, "patch conflict on latest main"
            )
            self.store.add_event(
                source.id,
                "integration.conflict",
                conflict,
                {"integration_task_id": task.id},
            )
            transcript.write(
                "repair", "requesting source worker integration conflict repair"
            )
            return patch_text, self._repair_integration_conflict(
                source.id, conflict, patch_text, task.id
            )
        return patch_text, None

    def _run_integration_validations(
        self,
        task: TaskRecord,
        worktree: Path,
        transcript: "IntegrationTranscript",
    ) -> tuple[TaskRecord, list[ValidationResult]]:
        transcript.write("validate", "running integration validation gates")
        validations = run_gates(self.config, task.id, worktree)
        for validation in validations:
            status = "passed" if validation.passed else "failed"
            transcript.write(
                "validation",
                f"{status}: {' '.join(validation.command)} (exit {validation.exit_code}) log={validation.output_path}",
            )
        task = self.store.get(task.id)
        task.validations.extend(validations)
        self.store.save(task)
        return task, validations

    def _block_integration_for_frozen_paths(
        self,
        task: TaskRecord,
        source: TaskRecord,
        worktree: Path,
        transcript: "IntegrationTranscript",
    ) -> bool | None:
        frozen = self.worktrees.frozen_paths(worktree, source)
        if not frozen:
            return None
        message = "frozen paths changed: " + ", ".join(frozen)
        transcript.write("path_policy_blocked", message)
        self._finish_task(task.id, TaskStatus.blocked, message)
        self._finish_task(source.id, TaskStatus.blocked, message)
        self.store.add_event(
            source.id,
            "path_policy.blocked",
            message,
            {"integration_task_id": task.id, "paths": frozen},
        )
        return False

    def _run_gates_for_iteration(
        self,
        task_id: str,
        worktree: Path,
        iteration: int,
        *,
        pipeline: Any | None = None,
    ) -> list[ValidationResult]:
        label = _iteration_log_label(iteration)
        command_runner = None
        if pipeline is not None and self.session_supervisor is not None:
            command_runner = self._container_validation_runner(
                self.store.get(task_id), pipeline
            )

        def on_gate_start(
            position: int, filename: str, command: list[str]
        ) -> None:
            self.store.add_event(
                task_id,
                "validation.command_started",
                " ".join(command),
                {
                    "iteration": iteration,
                    "position": position,
                    "command": command,
                    "output_path": str(
                        self.config.logs_dir / task_id / label / filename
                    ),
                },
            )

        def on_gate_result(position: int, validation: ValidationResult) -> None:
            validation = validation.model_copy(update={"iteration": iteration})
            self.store.record_iteration_validations(task_id, iteration, [validation])
            status = "passed" if validation.passed else "failed"
            self.store.add_event(
                task_id,
                "validation.command_finished",
                f"{status}: {' '.join(validation.command)}",
                {
                    "iteration": iteration,
                    "position": position,
                    "exit_code": validation.exit_code,
                    "passed": validation.passed,
                    "output_path": str(validation.output_path),
                },
            )

        try:
            gate_kwargs: dict[str, object] = {
                "label": label,
                "on_gate_start": on_gate_start,
                "on_gate_result": on_gate_result,
            }
            if command_runner is not None:
                gate_kwargs["command_runner"] = command_runner
            return [
                validation.model_copy(update={"iteration": iteration})
                for validation in run_gates(
                    self.config,
                    task_id,
                    worktree,
                    **gate_kwargs,
                )
            ]
        except TypeError as exc:
            message = str(exc)
            unsupported = next(
                (
                    name
                    for name in (
                        "command_runner",
                        "on_gate_start",
                        "on_gate_result",
                        "label",
                    )
                    if name in message
                ),
                None,
            )
            if unsupported is None:
                raise
            gate_kwargs.pop(unsupported, None)
            while gate_kwargs:
                try:
                    validations = run_gates(
                        self.config, task_id, worktree, **gate_kwargs
                    )
                    break
                except TypeError as retry_exc:
                    retry_message = str(retry_exc)
                    retry_unsupported = next(
                        (
                            name
                            for name in (
                                "command_runner",
                                "on_gate_start",
                                "on_gate_result",
                                "label",
                            )
                            if name in retry_message
                        ),
                        None,
                    )
                    if retry_unsupported is None:
                        raise
                    gate_kwargs.pop(retry_unsupported, None)
            else:
                validations = run_gates(self.config, task_id, worktree)
            validations = [
                validation.model_copy(update={"iteration": iteration})
                for validation in validations
            ]
            self.store.record_iteration_validations(task_id, iteration, validations)
            return validations

    def _handle_integration_validation_failure(
        self,
        task: TaskRecord,
        source: TaskRecord,
        validations: list[ValidationResult],
        worktree: Path,
        transcript: "IntegrationTranscript",
    ) -> bool | None:
        failed_validations = [
            validation for validation in validations if not validation.passed
        ]
        if not failed_validations:
            return None
        transcript.write("error", "validation failed after rebase")
        rebased_patch = self.worktrees.diff(worktree)
        self._finish_task(
            task.id, TaskStatus.blocked, "validation failed after rebase"
        )
        self.store.add_event(
            source.id,
            "integration.validation_failed",
            _summarize_validations(validations),
            {
                "integration_task_id": task.id,
                "failed": [
                    {
                        "command": validation.command,
                        "exit_code": validation.exit_code,
                        "summary": validation.summary,
                        "output_path": str(validation.output_path),
                    }
                    for validation in failed_validations
                ],
            },
        )
        transcript.write(
            "repair", "requesting source worker integration validation repair"
        )
        return self._repair_integration_validation_failure(
            source.id, failed_validations, rebased_patch, task.id
        )

    def _integration_commit_message(
        self,
        task: TaskRecord,
        source: TaskRecord,
        patch_text: str,
        validations: list[ValidationResult],
        transcript: "IntegrationTranscript",
    ) -> tuple[str, str] | None:
        try:
            return self._commit_message_for_integration(
                task, source, patch_text, validations, transcript
            )
        except CommitMessageGenerationError as exc:
            message = str(exc)[-2000:]
            transcript.write("commit_message_failed", message)
            self._finish_task(
                task.id, TaskStatus.failed, "commit message generation failed"
            )
            self._finish_task(
                source.id, TaskStatus.failed, "commit message generation failed"
            )
            self.store.add_event(
                source.id,
                "integration.commit_message_failed",
                message,
                {"integration_task_id": task.id, **exc.data},
            )
            return None

    def _commit_integration_patch(
        self,
        task: TaskRecord,
        source: TaskRecord,
        worktree: Path,
        commit_message: tuple[str, str],
        validated_tree: str,
        transcript: "IntegrationTranscript",
    ) -> tuple[str | None, bool | None]:
        commit_subject, commit_body = commit_message
        commit_body = _append_steward_task_trailer(self.config, commit_body, source.id)
        transcript.write("commit", f"creating commit: {commit_subject}")
        try:
            sha = self.worktrees.commit_all(
                worktree,
                commit_subject,
                commit_body,
                expected_tree=validated_tree,
            )
        except RuntimeError as exc:
            message = str(exc)[-2000:]
            transcript.write("commit_failed", message)
            self._finish_task(task.id, TaskStatus.failed, "commit failed")
            self._finish_task(source.id, TaskStatus.failed, "commit failed")
            self.store.add_event(
                source.id,
                "integration.commit_failed",
                message,
                {"integration_task_id": task.id},
            )
            return None, False
        if sha is None:
            transcript.write("no_changes", "patch already present on main")
            self._finish_task(
                task.id, TaskStatus.no_changes, "patch already present on main"
            )
            self._finish_task(
                source.id, TaskStatus.no_changes, "patch already present on main"
            )
            return None, True
        transcript.write("commit", f"created {sha}")
        self.store.add_event(
            task.id,
            "integration.commit_created",
            sha,
            {"commit": sha},
        )
        return sha, None

    def _finish_or_push_integration_commit(
        self,
        task: TaskRecord,
        source: TaskRecord,
        worktree: Path,
        sha: str,
        transcript: "IntegrationTranscript",
    ) -> bool:
        if self.config.local_only:
            return self._finish_local_integration_commit(
                task, source, sha, transcript
            )
        return self._push_integration_commit(task, source, worktree, sha, transcript)

    def _finish_local_integration_commit(
        self,
        task: TaskRecord,
        source: TaskRecord,
        sha: str,
        transcript: "IntegrationTranscript",
    ) -> bool:
        transcript.write(
            "local_only",
            f"external writes disabled; keeping local integration commit {sha}",
        )
        self._finish_task(
            task.id, TaskStatus.succeeded, f"local-only integration commit {sha}"
        )
        self._finish_task(
            source.id, TaskStatus.succeeded, f"local-only integration commit {sha}"
        )
        self.store.add_event(
            source.id,
            "integration.local_only",
            "external writes disabled by local_only",
            {"integration_task_id": task.id, "commit": sha},
        )
        return True

    def _push_integration_commit(
        self,
        task: TaskRecord,
        source: TaskRecord,
        worktree: Path,
        sha: str,
        transcript: "IntegrationTranscript",
    ) -> bool:
        self.store.start_integration(task.id, "pushing to main")
        transcript.write(
            "push",
            f"pushing {sha} to {self.config.git_remote}/{self.config.main_branch}",
        )
        push_result = None
        retry_count = 0
        for attempt in range(len(PUSH_RETRY_DELAYS_SECONDS) + 1):
            try:
                push_result = self.worktrees.push_head_to_main(worktree)
                break
            except RuntimeError as exc:
                message = str(exc)[-2000:]
                retryable = _is_transient_push_failure(message)
                if retryable and attempt < len(PUSH_RETRY_DELAYS_SECONDS):
                    delay = PUSH_RETRY_DELAYS_SECONDS[attempt]
                    retry_count += 1
                    retry_log_path = _write_integration_command_log(
                        self.config,
                        task.id,
                        f"git-push-attempt-{attempt + 1}.txt",
                        message,
                    )
                    transcript.write(
                        "push_retry",
                        f"attempt {attempt + 1} failed; retrying in {delay:g}s\n{message}",
                    )
                    self.store.add_event(
                        source.id,
                        "integration.push_retry",
                        message,
                        {
                            "integration_task_id": task.id,
                            "commit": sha,
                            "attempt": attempt + 1,
                            "next_attempt": attempt + 2,
                            "delay_seconds": delay,
                            "output_path": str(retry_log_path),
                        },
                    )
                    time.sleep(delay)
                    continue

                log_path = _write_integration_command_log(
                    self.config, task.id, "git-push.txt", message
                )
                transcript.write("push_failed", message)
                self._finish_task(task.id, TaskStatus.failed, "push failed")
                self._finish_task(source.id, TaskStatus.failed, "push failed")
                self.store.add_event(
                    source.id,
                    "integration.push_failed",
                    message,
                    {
                        "integration_task_id": task.id,
                        "commit": sha,
                        "output_path": str(log_path),
                        "retry_count": retry_count,
                        "retryable": retryable,
                    },
                )
                return False
        assert push_result is not None
        push_log_path = _write_integration_command_log(
            self.config,
            task.id,
            "git-push.txt",
            _command_result_text(push_result),
        )
        self.store.add_event(task.id, "main.pushed", sha)
        transcript.write("pushed", sha)
        self.store.add_event(
            source.id,
            "main.pushed",
            sha,
            {"integration_task_id": task.id, "output_path": str(push_log_path)},
        )
        self._update_feature_issues_after_push(task, source, sha, transcript)
        self._finish_task(task.id, TaskStatus.pushed, f"pushed {sha}")
        self._finish_task(source.id, TaskStatus.pushed, f"pushed {sha}")
        return True

    def _update_feature_issues_after_push(
        self,
        task: TaskRecord,
        source: TaskRecord,
        sha: str,
        transcript: "IntegrationTranscript",
    ) -> None:
        issues = _selected_feature_issues(source)
        if not issues:
            return
        if len(issues) > 1:
            message = "multiple selected feature issues; skipping automatic close"
            transcript.write("issue_update_skipped", message)
            self.store.add_event(
                source.id,
                "github.issue_update_skipped",
                message,
                {
                    "integration_task_id": task.id,
                    "issue_count": len(issues),
                },
            )
            return
        issue = issues[0]
        number = issue.get("issue_number")
        if not isinstance(number, int):
            return
        body = (
            f"Implemented by Steward in {sha} and pushed to "
            f"`{self.config.main_branch}`.\n\n"
            f"Source task: {source.id}"
        )
        comment = run_command(
            [
                "gh",
                "issue",
                "comment",
                str(number),
                "-R",
                self.config.github_repository,
                "--body",
                body,
            ],
            cwd=self.config.repo_root,
            timeout=30,
        )
        if not comment.ok:
            self._record_feature_issue_update_failure(
                task, source, number, "comment", comment.stderr, transcript
            )
            return
        close = run_command(
            [
                "gh",
                "issue",
                "close",
                str(number),
                "-R",
                self.config.github_repository,
                "--reason",
                "completed",
            ],
            cwd=self.config.repo_root,
            timeout=30,
        )
        if not close.ok:
            self._record_feature_issue_update_failure(
                task, source, number, "close", close.stderr, transcript
            )
            return
        transcript.write("issue_closed", f"#{number}")
        self.store.add_event(
            source.id,
            "github.issue_closed",
            str(number),
            {"integration_task_id": task.id, "issue_number": number},
        )

    def _record_feature_issue_update_failure(
        self,
        task: TaskRecord,
        source: TaskRecord,
        number: int,
        step: str,
        error: str,
        transcript: "IntegrationTranscript",
    ) -> None:
        message = error[-2000:] or f"{step} failed"
        transcript.write("issue_update_failed", f"#{number} {step}: {message}")
        self.store.add_event(
            source.id,
            "github.issue_update_failed",
            message,
            {
                "integration_task_id": task.id,
                "issue_number": number,
                "step": step,
            },
        )

    def _commit_message_for_integration(
        self,
        task: TaskRecord,
        source: TaskRecord,
        patch_text: str,
        validations: list[ValidationResult],
        transcript: "IntegrationTranscript",
    ) -> tuple[str, str]:
        changed_files = _patch_paths(patch_text)
        prompt = render_commit_message_prompt(
            source, patch_text, changed_files, validations
        )
        if task.worktree_path is None:
            raise CommitMessageGenerationError(
                "integration worktree missing",
                {
                    "integration_task_id": task.id,
                    "reason": "integration worktree missing",
                },
            )
        result = self._run_with_heartbeat(
            task.id,
            lambda: self.runner.run(
                task,
                prompt,
                task.worktree_path,
                name="commit-message",
                output_schema=commit_message_schema_path(self.config),
                stage=CodexStage.commit_message,
                sandbox="read-only",
            ),
        )
        data = parse_commit_message(result.final_message)
        event_data = {
            "integration_task_id": task.id,
            "diagnostics": result.diagnostics,
            "prompt_path": str(result.prompt_path) if result.prompt_path else None,
            "transcript_path": str(result.transcript_path),
            "last_message_path": str(result.last_message_path),
        }
        if result.completed and data is not None:
            subject = _limit_commit_subject(str(data["subject"]))
            body = str(data["body"]).strip()
            transcript.write("commit_message", f"generated: {subject}")
            self.store.add_event(
                source.id,
                "integration.commit_message_generated",
                subject,
                {**event_data, "subject": subject},
            )
            return subject, body

        reason = (
            f"invalid output: {result.final_message[-500:]}"
            if result.completed
            else result.final_message[-500:] or f"exit {result.exit_code}"
        )
        raise CommitMessageGenerationError(reason, {**event_data, "reason": reason})


class CommitMessageGenerationError(RuntimeError):
    def __init__(self, reason: str, data: dict[str, object]):
        super().__init__(reason)
        self.data = data


def default_worker_for_kind(kind: str) -> WorkerKind:
    mapping = {
        "code-quality": WorkerKind.code_quality_janitor,
        "feature": WorkerKind.feature_implementer,
        "integration": WorkerKind.integration_manager,
        "interop": WorkerKind.interop_doctor,
        "ci": WorkerKind.ci_doctor,
        "rfc-audit": WorkerKind.rfc_auditor,
        "health": WorkerKind.ci_doctor,
    }
    return mapping.get(kind, WorkerKind.custom)


class IntegrationTranscript:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def write(self, stage: str, message: str) -> None:
        from ..core.models import utc_now

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{utc_now().isoformat()}] {stage}: {message}\n")


def _reviewer_name(attempt: int, review_run: int) -> str:
    if review_run == 0:
        return f"reviewer-{attempt}"
    return f"reviewer-{attempt}-retry-{review_run}"


def _iteration_log_label(iteration: int) -> str:
    return f"iteration-{iteration}"


def _next_revision(store: TaskStore, task_id: str) -> int:
    iterations = store.iterations(task_id)
    if not iterations:
        return 1
    return max(item.iteration for item in iterations) + 1


def render_integration_revision_prompt(
    task: TaskRecord, conflict: str, failed_patch: str
) -> str:
    return "\n".join(
        [
            "A Steward integration run could not apply your approved patch on latest main.",
            "",
            "Your current worktree has been reset to latest main.",
            "Port the intended source changes from the failed patch onto this current worktree.",
            "Resolve the conflict by editing source files directly; do not commit, push, change scanner configuration, or modify unrelated files.",
            "After editing, run the relevant local validation commands and leave the revised patch in the worktree.",
            "",
            f"Task: {task.id} - {task.spec.title}",
            "",
            "Integration apply failure:",
            conflict.strip(),
            "",
            "Failed patch:",
            failed_patch.strip(),
        ]
    )


def commit_message_schema_path(config: StewardConfig) -> Path:
    path = config.state_dir / "schemas" / "commit-message.schema.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(COMMIT_MESSAGE_OUTPUT_SCHEMA, indent=2), encoding="utf-8")
    return path


def render_commit_message_prompt(
    source: TaskRecord,
    patch_text: str,
    changed_files: list[str],
    validations: list[ValidationResult],
) -> str:
    return "\n".join(
        [
            "You are CoQUIC Steward's integration commit-message writer.",
            "",
            "Your only job is to write a Conventional Commit message for the reviewed patch that has already applied cleanly to latest main and passed the integration gates.",
            "You do not run tools, edit files, decide whether to commit, or add extra claims.",
            "",
            "Return JSON only:",
            '{"subject":"string","body":"string"}',
            "",
            "Subject rules:",
            "- Format: <type>(<scope>): <imperative summary>.",
            "- Omit scope if no clear single scope exists.",
            "- Max 72 characters.",
            "- Use lowercase type.",
            "- Prefer these types:",
            "  - fix: bug, code-quality, scanner, dependency, runtime, or correctness fixes",
            "  - docs: documentation-only changes",
            "  - test: test-only changes",
            "  - ci: workflow or CI changes",
            "  - chore: maintenance that is not user-facing",
            "- Summary must describe the actual patch, not the task title.",
            "- Avoid generic summaries like \"fix code quality task\" or \"update files\".",
            "",
            "Body rules:",
            "- First paragraph: 1-3 sentences explaining what changed and why.",
            "- Then include \"Changed files:\" with up to 12 changed paths.",
            "- Then include \"Validation:\" with the provided validation commands and outcomes.",
            f"- End with \"Source task: {source.id}\".",
            "- Do not mention internal agents, prompts, transcripts, or automation details.",
            "- Do not invent validation, issue links, or affected files.",
            "- For selected GitHub feature issues, describe the implementation but do not write closing language; Steward comments on and closes those issues only after a successful push.",
            "",
            "Context:",
            "<source_task>",
            json.dumps(_commit_source_task_context(source), indent=2, sort_keys=True),
            "</source_task>",
            "",
            "<selected_signal_items>",
            json.dumps(_selected_signal_items_context(source), indent=2, sort_keys=True),
            "</selected_signal_items>",
            "",
            "<validation_results>",
            json.dumps(
                [_validation_context(item) for item in validations],
                indent=2,
                sort_keys=True,
            ),
            "</validation_results>",
            "",
            "<changed_files>",
            json.dumps(changed_files, indent=2),
            "</changed_files>",
            "",
            "<patch>",
            patch_text.strip(),
            "</patch>",
        ]
    )


def parse_commit_message(message: str) -> dict[str, str] | None:
    try:
        parsed = json.loads(message)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    subject = parsed.get("subject")
    body = parsed.get("body")
    if not isinstance(subject, str) or not isinstance(body, str):
        return None
    subject = _normalize_commit_subject(subject)
    body = body.strip()
    if not subject or not body:
        return None
    if len(subject) > 72:
        return None
    if "\n" in subject:
        return None
    if not re.match(r"^[a-z]+(?:\([A-Za-z0-9._/-]+\))?: .+", subject):
        return None
    return {"subject": subject, "body": body}


def _append_steward_task_trailer(
    config: StewardConfig, body: str, source_task_id: str
) -> str:
    trailer = f"Steward-Task: {_public_task_url(config, source_task_id)}"
    body = body.strip()
    if trailer in body.splitlines():
        return body
    if not body:
        return trailer
    return f"{body}\n\n{trailer}"


def _public_task_url(config: StewardConfig, task_id: str) -> str:
    host = config.public_mirror.remote_host.strip().rstrip("/")
    if host.startswith(("http://", "https://")):
        base_url = host
    else:
        scheme = "http" if host.startswith(("localhost", "127.0.0.1")) else "https"
        base_url = f"{scheme}://{host}"
    return f"{base_url}/steward/tasks/{task_id}"


COMMIT_MESSAGE_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "required": ["subject", "body"],
}


def _is_integration_task(task) -> bool:
    return (
        TaskKind(task.spec.kind) == TaskKind.integration
        or WorkerKind(task.spec.worker) == WorkerKind.integration_manager
    )


def _is_steward_owned_worktree(config: StewardConfig, path: Path) -> bool:
    try:
        resolved = path.resolve()
        root = config.worktrees_dir.resolve()
    except OSError:
        return False
    return root in resolved.parents


def _commit_source_task_context(source: TaskRecord) -> dict[str, object]:
    return {
        "id": source.id,
        "kind": source.spec.kind,
        "worker": source.spec.worker,
        "title": source.spec.title,
        "prompt": source.spec.prompt,
        "priority": source.spec.priority,
        "risk": source.spec.risk,
        "evidence": source.spec.metadata.get("evidence", []),
    }


def _selected_signal_items_context(source: TaskRecord) -> list[object]:
    context = source.spec.metadata.get("source_context")
    if not isinstance(context, dict):
        return []
    selected = context.get("selected_signal_items")
    return selected if isinstance(selected, list) else []


def _selected_feature_issues(source: TaskRecord) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    for item in _selected_signal_items_context(source):
        if not isinstance(item, dict):
            continue
        if item.get("kind") != "github-issues.feature-request":
            continue
        payload = item.get("payload")
        if isinstance(payload, dict):
            issues.append(payload)
    return issues


def _validation_context(validation: ValidationResult) -> dict[str, object]:
    return {
        "command": validation.command,
        "cwd": str(validation.cwd),
        "passed": validation.passed,
        "exit_code": validation.exit_code,
        "summary": validation.summary,
        "output_path": str(validation.output_path),
    }


def _stable_validation_diagnostics(validation: ValidationResult) -> str:
    text = validation.output_path.read_text(encoding="utf-8", errors="replace")
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _NIX_BUSY_WARNING_RE.sub("", text)
    text = _GTEST_DURATION_RE.sub(r"\1(<duration>)", text)
    text = _ZIG_CACHE_OBJECT_RE.sub(".zig-cache/o/<digest>", text)
    text = _ZIG_SEED_RE.sub("--seed <seed>", text)
    text = _ZIG_BUILD_NONCE_RE.sub("-Z<nonce>", text)

    if validation.command[-3:] != ["zig", "build", "test"]:
        return text

    signatures = {
        match.group(0).strip() for match in _GTEST_FAILURE_BLOCK_RE.finditer(text)
    }
    signatures.update(
        match.group(0).strip() for match in _GTEST_FAILED_TEST_RE.finditer(text)
    )
    return "\n\n".join(sorted(signatures)) if signatures else text


def _worker_was_interrupted(result: WorkerResult) -> bool:
    return str(result.diagnostics.get("status", "")) in {
        InvocationStatus.interrupted.value,
        InvocationStatus.forced.value,
    }


def _replace_path_reference(value: str, source: str, target: str) -> str:
    """Replace mounted path references without matching sibling path prefixes."""

    offset = 0
    while True:
        index = value.find(source, offset)
        if index < 0:
            return value
        end = index + len(source)
        if end == len(value) or value[end] in "/#?":
            value = value[:index] + target + value[end:]
            offset = index + len(target)
        else:
            offset = end


def _rewrite_path_references(
    value: str,
    source: Path,
    *,
    target_path: str,
    target_uri: str,
) -> str:
    source = source.resolve()
    value = _replace_path_reference(value, source.as_uri(), target_uri)
    return _replace_path_reference(value, str(source), target_path)


def _rewrite_mounted_argument(value: str, source: Path, target: str) -> str:
    return _rewrite_path_references(
        value,
        source,
        target_path=target,
        target_uri=Path(target).as_uri(),
    )


def _validation_no_progress_fingerprint(
    output_identity: str | None,
    validations: list[ValidationResult],
) -> str:
    failures = []
    for validation in validations:
        if validation.passed:
            continue
        diagnostics = _rewrite_path_references(
            _stable_validation_diagnostics(validation),
            validation.cwd,
            target_path="<worktree>",
            target_uri="file://<worktree>",
        )
        command = [
            _rewrite_path_references(
                item,
                validation.cwd,
                target_path="<worktree>",
                target_uri="file://<worktree>",
            )
            for item in validation.command
        ]
        failures.append(
            {
                "command": command,
                "exit_code": validation.exit_code,
                "diagnostics": sha256(
                    diagnostics.encode("utf-8", errors="replace")
                ).hexdigest(),
            }
        )
    failures.sort(key=lambda item: json.dumps(item, sort_keys=True))
    return bounded_fingerprint("validation", output_identity, failures)


def _review_no_progress_fingerprint(
    output_identity: str | None,
    raw_review: dict[str, Any],
    dispositions: Any,
) -> str:
    findings = raw_review.get("findings", [])
    blocking_findings = []
    for item in dispositions:
        disposition = getattr(item.disposition, "value", str(item.disposition))
        if disposition not in {"required", "revert"}:
            continue
        blocking_findings.append(
            {
                "source_index": item.source_index,
                "disposition": disposition,
                "finding": findings[item.source_index],
            }
        )
    blocking_findings.sort(key=lambda item: item["source_index"])
    return bounded_fingerprint("review", output_identity, blocking_findings)


def _integration_no_progress_fingerprint(
    trigger: PipelineTrigger,
    latest_main: str,
    patch_identity: str,
    applied: bool,
) -> str:
    return bounded_fingerprint(
        "integration",
        trigger.value,
        latest_main,
        patch_identity,
        applied,
    )


def _is_transient_push_failure(message: str) -> bool:
    lowered = message.lower()
    return any(pattern in lowered for pattern in _TRANSIENT_PUSH_PATTERNS) or bool(
        _TRANSIENT_PUSH_HTTP_STATUS_RE.search(message)
    )


def _is_non_fast_forward_push_failure(message: str) -> bool:
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in (
            "non-fast-forward",
            "fetch first",
            "tip of your current branch is behind",
            "remote contains work that you do not have locally",
        )
    )


def _stable_push_failure(message: str) -> str:
    return " ".join(_ANSI_ESCAPE_RE.sub("", message).lower().split())[-2_000:]


def _write_integration_command_log(
    config: StewardConfig, task_id: str, filename: str, text: str
) -> Path:
    path = config.logs_dir / task_id / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _command_result_text(result) -> str:
    return "\n".join(
        [
            f"$ {' '.join(result.args)}",
            f"cwd: {result.cwd}",
            f"exit: {result.returncode}",
            "",
            "stdout:",
            result.stdout.rstrip(),
            "",
            "stderr:",
            result.stderr.rstrip(),
            "",
        ]
    )


def _patch_paths(patch_text: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for line in patch_text.splitlines():
        match = re.match(r"^diff --git a/(.+?) b/(.+)$", line)
        if not match:
            continue
        for path in (match.group(1), match.group(2)):
            if path == "/dev/null" or path in seen:
                continue
            paths.append(path)
            seen.add(path)
    return paths


def frozen_patch_paths(
    config: StewardConfig, task: TaskRecord, patch_text: str
) -> list[str]:
    patterns = config.path_policy.frozen_for_kind(task.spec.kind)
    if not patterns:
        return []
    return [
        path
        for path in _patch_paths(patch_text)
        if any(_path_matches_policy(path, pattern) for pattern in patterns)
    ]


def _path_matches_policy(path: str, pattern: str) -> bool:
    normalized_path = path.strip().replace("\\", "/")
    normalized_pattern = pattern.strip().replace("\\", "/").rstrip("/")
    if not normalized_path or not normalized_pattern:
        return False
    if any(char in normalized_pattern for char in "*?["):
        return fnmatch.fnmatchcase(normalized_path, normalized_pattern)
    return (
        normalized_path == normalized_pattern
        or normalized_path.startswith(normalized_pattern + "/")
    )


def _limit_commit_subject(subject: str) -> str:
    subject = _normalize_commit_subject(subject)
    if len(subject) <= 72:
        return subject
    return subject[:69].rstrip(" .") + "..."


def _normalize_commit_subject(subject: str) -> str:
    return re.sub(r"\s+", " ", subject).strip()


def _safe_filename(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value))
    return text.strip("-.")[:96] or "action"


def _summarize_validations(validations: list[ValidationResult]) -> str:
    failed = [validation for validation in validations if not validation.passed]
    if not failed:
        return "validation passed"
    first = failed[0]
    command = " ".join(first.command)
    summary = first.summary.strip().splitlines()[-1:] or [""]
    suffix = f": {summary[0]}" if summary[0] else ""
    more = f" (+{len(failed) - 1} more)" if len(failed) > 1 else ""
    return f"{command} exited {first.exit_code}{suffix}{more}"


@contextmanager
def _integration_lock(state_dir: Path):
    path = state_dir / "integration.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

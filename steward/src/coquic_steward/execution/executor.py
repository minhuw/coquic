from __future__ import annotations

import fcntl
import fnmatch
import json
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

from ..agents import (
    CodexRunner,
    render_implementation_plan_prompt,
    render_worker_prompt,
)
from ..core.config import StewardConfig
from ..core.models import (
    IntegrationMode,
    CodexStage,
    TaskRecord,
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskWorkflow,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    utc_now,
)
from ..core.subprocesses import run_command
from ..storage import TaskStore
from .review import (
    parse_review,
    render_review_prompt,
    render_review_revision_prompt,
    review_approved,
    review_schema_path,
    summarize_review,
)
from .implementation_plan import (
    MAX_PLAN_RUN_ATTEMPTS,
    implementation_plan_schema_path,
    parse_implementation_plan,
    save_implementation_plan,
)
from .validation import render_validation_revision_prompt, run_gates
from .worktree import Worktrees

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


class PatchPreparationResult(StrEnum):
    ready = "ready"
    no_changes = "no_changes"
    validation_failed = "validation_failed"
    terminal_failure = "terminal_failure"


class StewardExecutor:
    def __init__(self, config: StewardConfig, store: TaskStore):
        self.config = config
        self.store = store
        self.runner = CodexRunner(config)
        self.worktrees = Worktrees(config)
        self._latest_failed_validations: dict[str, list[ValidationResult]] = {}

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
        if result.thread_id:
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
        self.worktrees.save_patch(task.worktree_path, patch_path)
        self.store.record_iteration_patch(task.id, iteration, patch_path)
        self.store.start_validation(task.id, f"validation running: {label}")
        validations = self._run_gates_for_iteration(
            task.id, task.worktree_path, iteration
        )
        task = self.store.get(task.id)
        if self._block_task_for_frozen_paths(task, task.worktree_path):
            return PatchPreparationResult.terminal_failure
        if any(not validation.passed for validation in validations):
            self.worktrees.save_patch(task.worktree_path, patch_path)
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
        self.worktrees.save_patch(task.worktree_path, patch_path)
        task = self.store.get(task.id)
        task.patch_path = patch_path
        self.store.save(task)
        self.store.record_iteration_patch(task.id, iteration, patch_path)
        self.store.add_event(task.id, "patch.saved", str(patch_path), {"label": label})
        return PatchPreparationResult.ready

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
                resume_session=_worker_thread_id(task),
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
                resume_session=_worker_thread_id(task),
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
                resume_session=_worker_thread_id(task),
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
        self, task_id: str, worktree: Path, iteration: int
    ) -> list[ValidationResult]:
        label = _iteration_log_label(iteration)

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
            return [
                validation.model_copy(update={"iteration": iteration})
                for validation in run_gates(
                    self.config,
                    task_id,
                    worktree,
                    label=label,
                    on_gate_start=on_gate_start,
                    on_gate_result=on_gate_result,
                )
            ]
        except TypeError as exc:
            if "label" not in str(exc) and "on_gate" not in str(exc):
                raise
            try:
                validations = run_gates(
                    self.config, task_id, worktree, label=label
                )
            except TypeError as label_exc:
                if "label" not in str(label_exc):
                    raise
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


def _worker_thread_id(task) -> str | None:
    value = task.spec.metadata.get("worker_thread_id")
    return value if isinstance(value, str) and value else None


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


def _is_transient_push_failure(message: str) -> bool:
    lowered = message.lower()
    return any(pattern in lowered for pattern in _TRANSIENT_PUSH_PATTERNS) or bool(
        _TRANSIENT_PUSH_HTTP_STATUS_RE.search(message)
    )


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

from __future__ import annotations

import fcntl
import json
import re
import threading
from collections.abc import Callable
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..agents import CodexRunner, render_worker_prompt
from ..core.config import StewardConfig
from ..core.models import (
    IntegrationMode,
    TaskRecord,
    TaskKind,
    TaskSpec,
    TaskStatus,
    ValidationResult,
    WorkerKind,
    WorkerResult,
)
from ..storage import TaskStore
from .review import (
    parse_review,
    render_review_prompt,
    render_review_revision_prompt,
    review_approved,
    review_schema_path,
    summarize_review,
)
from .validation import render_validation_revision_prompt, run_gates
from .worktree import Worktrees

MAX_TASK_REVISIONS = 100
MAX_REVIEW_RUN_ATTEMPTS = 2
WORKER_HEARTBEAT_SECONDS = 30


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
                task, render_worker_prompt(task, self.config), worktree
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
            self.worktrees.remove(task.worktree_path)
            self.store.add_event(
                task.id,
                "worktree.cleaned",
                str(task.worktree_path),
                {"status": str(task.status)},
            )
            return True
        return False

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

        self.store.start_validation(task.id, f"validation running: {label}")
        validations = _run_gates_for_iteration(
            self.config, task.id, task.worktree_path, iteration
        )
        validations = [
            validation.model_copy(update={"iteration": iteration})
            for validation in validations
        ]
        self.store.record_iteration_validations(task.id, iteration, validations)
        task = self.store.get(task.id)
        if any(not validation.passed for validation in validations):
            patch_path = self.config.patches_dir / task.id / f"{_iteration_log_label(iteration)}.patch"
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
        patch_path = self.config.patches_dir / task.id / f"{_iteration_log_label(iteration)}.patch"
        self.worktrees.save_patch(task.worktree_path, patch_path)
        task = self.store.get(task.id)
        task.patch_path = patch_path
        self.store.save(task)
        self.store.record_iteration_patch(task.id, iteration, patch_path)
        self.store.add_event(task.id, "patch.saved", str(patch_path), {"label": label})
        return PatchPreparationResult.ready

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

        while revisions < MAX_TASK_REVISIONS:
            revisions += 1
            failed = self._latest_failed_validations.get(task_id, [])
            if not self._revise_from_validation(task_id, failed, revisions):
                return False, revisions
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
        self._finish_task(
            task_id,
            TaskStatus.blocked,
            f"revision budget exhausted after {MAX_TASK_REVISIONS} revision(s)",
        )
        return False, revisions

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
                render_review_revision_prompt(task, review),
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
                render_validation_revision_prompt(task, validations),
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
        self.worktrees.reset_to_main(task.worktree_path)
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
            no_changes_status=TaskStatus.failed,
        )
        if not prepared:
            return False
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
            return run()
        finally:
            stop.set()
            thread.join(timeout=1)

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
        if (
            self.store.count_events("main.pushed")
            >= self.config.limits.max_main_pushes_per_day
        ):
            transcript.write("blocked", "main push budget reached")
            self._finish_task(
                task.id, TaskStatus.blocked, "main push budget reached"
            )
            self._finish_task(
                source.id, TaskStatus.blocked, "main push budget reached"
            )
            return False
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
        try:
            patch_text = source.patch_path.read_text(encoding="utf-8")
            transcript.write("reset", f"resetting worktree to {self.config.git_remote}/{self.config.main_branch}")
            self.worktrees.reset_to_main(worktree)
            transcript.write("apply", "applying reviewed patch")
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
            transcript.write("repair", "requesting source worker integration conflict repair")
            return self._repair_integration_conflict(
                source.id, conflict, patch_text, task.id
            )
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
        if any(not validation.passed for validation in validations):
            transcript.write("error", "validation failed after rebase")
            rebased_patch = self.worktrees.diff(worktree)
            self._finish_task(
                task.id, TaskStatus.blocked, "validation failed after rebase"
            )
            failed_validations = [
                validation for validation in validations if not validation.passed
            ]
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
        try:
            commit_subject, commit_body = self._commit_message_for_integration(
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
            return False
        transcript.write("commit", f"creating commit: {commit_subject}")
        try:
            sha = self.worktrees.commit_all(
                worktree,
                commit_subject,
                commit_body,
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
            return False
        if sha is None:
            transcript.write("no_changes", "patch already present on main")
            self._finish_task(
                task.id, TaskStatus.no_changes, "patch already present on main"
            )
            self._finish_task(
                source.id, TaskStatus.no_changes, "patch already present on main"
            )
            return True
        transcript.write("commit", f"created {sha}")
        if self.config.local_only:
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
        self.store.start_integration(task.id, "pushing to main")
        transcript.write("push", f"pushing {sha} to {self.config.git_remote}/{self.config.main_branch}")
        try:
            push_result = self.worktrees.push_head_to_main(worktree)
        except RuntimeError as exc:
            message = str(exc)[-2000:]
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
                },
            )
            return False
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
        self._finish_task(task.id, TaskStatus.pushed, f"pushed {sha}")
        self._finish_task(source.id, TaskStatus.pushed, f"pushed {sha}")
        return True

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
            lambda: self.runner.run_review(
                task,
                prompt,
                task.worktree_path,
                name="commit-message",
                output_schema=commit_message_schema_path(self.config),
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


COMMIT_MESSAGE_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "required": ["subject", "body"],
}


def _run_gates_for_iteration(
    config: StewardConfig, task_id: str, worktree: Path, iteration: int
) -> list[ValidationResult]:
    try:
        return run_gates(
            config, task_id, worktree, label=_iteration_log_label(iteration)
        )
    except TypeError as exc:
        if "label" not in str(exc):
            raise
        return run_gates(config, task_id, worktree)


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


def _validation_context(validation: ValidationResult) -> dict[str, object]:
    return {
        "command": validation.command,
        "cwd": str(validation.cwd),
        "passed": validation.passed,
        "exit_code": validation.exit_code,
        "summary": validation.summary,
        "output_path": str(validation.output_path),
    }


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
        path = match.group(2)
        if path == "/dev/null":
            path = match.group(1)
        if path in seen:
            continue
        paths.append(path)
        seen.add(path)
    return paths


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

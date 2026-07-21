from __future__ import annotations

import json
import os
import re
import selectors
import signal
# subprocess is required to stream Codex stdio; launches use explicit argv and shell=False.
import subprocess  # nosec B404
import time
from pathlib import Path

from ..core.config import StewardConfig
from ..core.models import CodexStage, TaskRecord, WorkerResult
from .diagnostics import diagnostics_for_result
from .tool_changes import ToolChangeCapture


CODEX_RETRY_DELAYS_SECONDS = (5.0, 20.0)
_CODEX_RETRY_PROMPT = (
    "Continue the interrupted turn. Complete the original task and return the "
    "required final response."
)
_TRANSIENT_CODEX_PATTERNS = (
    "selected model is at capacity",
    "stream disconnected before completion",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "too many requests",
    "rate limit exceeded",
    "error sending request for url",
    "could not resolve host",
    "temporary failure in name resolution",
    "connection reset by peer",
)
_TRANSIENT_HTTP_STATUS_RE = re.compile(
    r"\b(?:http(?: status)?|status(?: code)?|unexpected status)\s*[:=]?\s*(?:429|5\d\d)\b",
    re.IGNORECASE,
)


class CodexRunner:
    def __init__(self, config: StewardConfig):
        self.config = config

    def paths(self, task: TaskRecord, *, name: str = "worker") -> tuple[Path, Path]:
        run_dir = self.config.transcripts_dir / task.id / name
        return run_dir / "codex.jsonl", run_dir / "last-message.md"

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
    ) -> WorkerResult:
        transcript_path, last_message_path = self.paths(task, name=name)
        run_dir = transcript_path.parent
        run_dir.mkdir(parents=True, exist_ok=True)
        prompt_path = self.config.prompts_dir / task.id / f"{name}.md"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")
        settings = self.config.codex_settings(stage)
        return self._run_with_retries(
            cwd=cwd,
            prompt=prompt,
            prompt_path=prompt_path,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            output_schema=output_schema,
            resume_session=resume_session,
            stage=stage,
            sandbox=sandbox,
            timeout_seconds=(
                self.config.limits.plan_timeout_minutes
                if stage == CodexStage.implementation_plan
                else self.config.limits.worker_timeout_minutes
            )
            * 60,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
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
        transcript_path, last_message_path = self.paths(task, name=name)
        run_dir = transcript_path.parent
        run_dir.mkdir(parents=True, exist_ok=True)
        prompt_path = self.config.prompts_dir / task.id / f"{name}.md"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")
        settings = self.config.codex_settings(CodexStage.review)
        return self._run_with_retries(
            cwd=cwd,
            prompt=prompt,
            prompt_path=prompt_path,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            output_schema=output_schema,
            resume_session=None,
            stage=CodexStage.review,
            sandbox=None,
            timeout_seconds=self.config.limits.review_timeout_minutes * 60,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
        )

    def _run_with_retries(
        self,
        *,
        cwd: Path,
        prompt: str,
        prompt_path: Path,
        transcript_path: Path,
        last_message_path: Path,
        output_schema: Path | None,
        resume_session: str | None,
        stage: CodexStage,
        sandbox: str | None,
        timeout_seconds: int,
        model: str | None,
        reasoning_effort: str | None,
    ) -> WorkerResult:
        retries: list[dict[str, object]] = []
        active_resume_session = resume_session
        attempt_prompt = prompt
        for attempt in range(len(CODEX_RETRY_DELAYS_SECONDS) + 1):
            args = self._args(
                cwd,
                last_message_path,
                output_schema=output_schema,
                resume_session=active_resume_session,
                stage=stage,
                sandbox=sandbox,
            )
            try:
                result = self._run_process(
                    args,
                    cwd,
                    attempt_prompt,
                    prompt_path,
                    transcript_path,
                    last_message_path,
                    timeout_seconds=timeout_seconds,
                    stage=stage,
                    model=model,
                    reasoning_effort=reasoning_effort,
                )
            except FileNotFoundError as exc:
                result = self._missing_executable_result(
                    args=args,
                    cwd=cwd,
                    prompt_path=prompt_path,
                    transcript_path=transcript_path,
                    last_message_path=last_message_path,
                    stage=stage,
                    model=model,
                    reasoning_effort=reasoning_effort,
                    exc=exc,
                )

            reason = _transient_codex_failure_reason(result)
            if result.completed or reason is None or attempt >= len(CODEX_RETRY_DELAYS_SECONDS):
                return _with_retry_diagnostics(
                    result,
                    retries,
                    fallback_thread_id=active_resume_session,
                )

            delay = CODEX_RETRY_DELAYS_SECONDS[attempt]
            archived = _archive_retry_artifacts(result, attempt + 1)
            next_resume_session = result.thread_id or active_resume_session
            retries.append(
                {
                    "attempt": attempt + 1,
                    "next_attempt": attempt + 2,
                    "delay_seconds": delay,
                    "reason": reason[-2000:],
                    "resume_session": next_resume_session,
                    **archived,
                }
            )
            time.sleep(delay)
            active_resume_session = next_resume_session
            attempt_prompt = _CODEX_RETRY_PROMPT if active_resume_session else prompt
        raise AssertionError("unreachable Codex retry loop")

    def _missing_executable_result(
        self,
        *,
        args: list[str],
        cwd: Path,
        prompt_path: Path,
        transcript_path: Path,
        last_message_path: Path,
        stage: CodexStage,
        model: str | None,
        reasoning_effort: str | None,
        exc: FileNotFoundError,
    ) -> WorkerResult:
        message = (
            f"unable to start Codex executable {self.config.codex_bin!r}: "
            f"{exc.strerror or exc}"
        )
        _write_transcript(transcript_path, "", message)
        diagnostics = diagnostics_for_result(
            completed=False,
            exit_code=127,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            final_message=message,
        )
        diagnostics_json = diagnostics.model_dump(mode="json")
        if stage == CodexStage.code:
            capture_summary = transcript_path.parent / "tool-changes" / "summary.json"
            try:
                if capture_summary.exists():
                    value = json.loads(capture_summary.read_text(encoding="utf-8"))
                    if isinstance(value, dict):
                        diagnostics_json["tool_change_capture"] = _bounded_capture_diagnostics(value)
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                diagnostics_json["tool_change_capture"] = {
                    "schema_version": 1,
                    "state": "unavailable",
                    "reasons": ["context_unavailable"],
                }
        return WorkerResult(
            completed=False,
            command=args,
            cwd=cwd,
            exit_code=127,
            prompt_path=prompt_path,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            final_message=message,
            stage=stage,
            model=model,
            reasoning_effort=reasoning_effort,
            diagnostics=diagnostics_json,
        )

    def _args(
        self,
        cwd: Path,
        last_message_path: Path,
        *,
        output_schema: Path | None,
        resume_session: str | None,
        stage: CodexStage = CodexStage.code,
        sandbox: str | None = None,
    ) -> list[str]:
        settings = self.config.codex_settings(stage)
        args = [self.config.codex_bin, "exec"]
        if resume_session:
            args.append("resume")
        args.extend(["--json"])
        if settings.model:
            args.extend(["--model", settings.model])
        if settings.reasoning_effort:
            args.extend(
                [
                    "--config",
                    "model_reasoning_effort="
                    + json.dumps(settings.reasoning_effort),
                ]
            )
        if self.config.codex_profile:
            args.extend(["--profile", self.config.codex_profile])
        if not resume_session:
            args.extend(
                ["--sandbox", sandbox or self.config.codex_sandbox, "--cd", str(cwd)]
            )
        args.extend(["--output-last-message", str(last_message_path)])
        if output_schema is not None:
            args.extend(["--output-schema", str(output_schema)])
        if resume_session:
            args.append(resume_session)
        args.append("-")
        return args

    def _run_process(
        self,
        args: list[str],
        cwd: Path,
        prompt: str,
        prompt_path: Path,
        transcript_path: Path,
        last_message_path: Path,
        timeout_seconds: int,
        stage: CodexStage,
        model: str | None,
        reasoning_effort: str | None,
    ) -> WorkerResult:
        capture: ToolChangeCapture | None = None
        if stage == CodexStage.code:
            try:
                capture = ToolChangeCapture.start(
                    cwd, transcript_path.parent / "tool-changes"
                )
            except Exception:
                # Capture is observational and must never prevent Codex from
                # starting.  The runner still reports unavailable evidence.
                capture = ToolChangeCapture.unavailable(
                    cwd, transcript_path.parent / "tool-changes"
                )
        child_env = None
        if capture is not None:
            child_env = os.environ.copy()
            child_env["COQUIC_STEWARD_HOOK_CONTEXT"] = str(capture.context_path)
        elif stage != CodexStage.code and "COQUIC_STEWARD_HOOK_CONTEXT" in os.environ:
            # A caller's ambient value must not accidentally enable capture for
            # planning, review, signal, or commit-message processes.
            child_env = os.environ.copy()
            child_env.pop("COQUIC_STEWARD_HOOK_CONTEXT", None)
        # CodexRunner builds args as an argv list and never enables a shell.
        try:
            proc = subprocess.Popen(  # nosec B603
                args,
                cwd=cwd,
                env=child_env,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except OSError:
            if capture is not None:
                capture.finalize()
            raise
        try:
            stdout = _communicate_streaming(
                proc,
                prompt,
                transcript_path,
                timeout_seconds=timeout_seconds,
            )
        finally:
            capture_diagnostics = (
                capture.finalize().diagnostics_dict() if capture is not None else None
            )
        final_message = (
            last_message_path.read_text(encoding="utf-8")
            if last_message_path.exists()
            else ""
        )
        if not final_message:
            final_message = _last_agent_message(stdout)
        if not final_message:
            final_message = _stderr_summary(transcript_path)
        thread_id = _thread_id(stdout)
        diagnostics = diagnostics_for_result(
            completed=proc.returncode == 0,
            exit_code=proc.returncode,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            final_message=final_message,
            thread_id=thread_id,
        )
        diagnostics_json = diagnostics.model_dump(mode="json")
        diagnostics_json.update(
            {
                "stage": stage.value,
                "model": model,
                "reasoning_effort": reasoning_effort,
            }
        )
        if capture_diagnostics is not None:
            diagnostics_json["tool_change_capture"] = capture_diagnostics
        return WorkerResult(
            completed=proc.returncode == 0,
            command=args,
            cwd=cwd,
            exit_code=proc.returncode,
            prompt_path=prompt_path,
            transcript_path=transcript_path,
            last_message_path=last_message_path,
            final_message=final_message,
            thread_id=thread_id,
            stage=stage,
            model=model,
            reasoning_effort=reasoning_effort,
            diagnostics=diagnostics_json,
        )


def _bounded_capture_diagnostics(value: dict[str, object]) -> dict[str, object]:
    allowed = {
        "schema_version",
        "state",
        "completeness",
        "discovered",
        "captured",
        "empty",
        "failed",
        "incomplete",
        "gaps",
        "overlaps",
        "omitted",
        "reasons",
        "reason_categories",
    }
    return {key: value[key] for key in allowed if key in value}


def _transient_codex_failure_reason(result: WorkerResult) -> str | None:
    diagnostics = result.diagnostics
    candidates = [
        result.final_message,
        str(diagnostics.get("last_error") or ""),
        str(diagnostics.get("last_output") or ""),
    ]
    for candidate in candidates:
        if _is_transient_codex_message(candidate):
            return candidate.strip()
    return None


def _is_transient_codex_message(message: str) -> bool:
    lowered = message.lower()
    return any(pattern in lowered for pattern in _TRANSIENT_CODEX_PATTERNS) or bool(
        _TRANSIENT_HTTP_STATUS_RE.search(message)
    )


def _archive_retry_artifacts(
    result: WorkerResult, retry_number: int
) -> dict[str, object]:
    archived: dict[str, object] = {}
    if result.transcript_path.exists():
        transcript_path = _retry_artifact_path(result.transcript_path, retry_number)
        result.transcript_path.replace(transcript_path)
        archived["transcript_path"] = str(transcript_path)
    if result.last_message_path.exists():
        last_message_path = _retry_artifact_path(result.last_message_path, retry_number)
        result.last_message_path.replace(last_message_path)
        archived["last_message_path"] = str(last_message_path)
    tool_changes = result.transcript_path.with_name("tool-changes")
    if tool_changes.exists():
        archived_tool_changes = _retry_directory_path(tool_changes, retry_number)
        try:
            tool_changes.replace(archived_tool_changes)
        except OSError:
            pass
    return archived


def _retry_artifact_path(path: Path, retry_number: int) -> Path:
    return path.with_name(f"{path.stem}.retry-{retry_number}{path.suffix}")


def _retry_directory_path(path: Path, retry_number: int) -> Path:
    return path.with_name(f"{path.name}.retry-{retry_number}")


def _with_retry_diagnostics(
    result: WorkerResult,
    retries: list[dict[str, object]],
    *,
    fallback_thread_id: str | None,
) -> WorkerResult:
    update: dict[str, object] = {}
    if retries:
        diagnostics = dict(result.diagnostics)
        diagnostics["retry_count"] = len(retries)
        diagnostics["retries"] = retries
        update["diagnostics"] = diagnostics
    if result.thread_id is None and fallback_thread_id is not None:
        update["thread_id"] = fallback_thread_id
    return result.model_copy(update=update) if update else result


def _write_transcript(path: Path, stdout: str, stderr: str) -> None:
    path.write_text(stdout, encoding="utf-8")
    if stderr:
        with path.open("a", encoding="utf-8") as handle:
            for line in stderr.splitlines():
                handle.write(json.dumps({"type": "stderr", "text": line}) + "\n")


def _communicate_streaming(
    proc: subprocess.Popen[str],
    input_text: str,
    transcript_path: Path,
    *,
    timeout_seconds: int,
) -> str:
    if proc.stdin is None or proc.stdout is None or proc.stderr is None:
        raise RuntimeError("codex process pipes were not initialized")
    proc.stdin.write(input_text)
    proc.stdin.close()

    deadline = time.monotonic() + timeout_seconds
    stdout_parts: list[str] = []
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    transcript_path.write_text("", encoding="utf-8")
    with transcript_path.open("a", encoding="utf-8") as transcript:
        while selector.get_map():
            if time.monotonic() > deadline:
                _terminate_process_tree(proc)
                timeout_message = (
                    f"codex process timed out after {timeout_seconds // 60} minute(s)"
                )
                transcript.write(
                    json.dumps({"type": "stderr", "text": timeout_message}) + "\n"
                )
                proc.wait()
                proc.returncode = 124
                break
            for key, _ in selector.select(timeout=0.2):
                line = key.fileobj.readline()
                if line == "":
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    stdout_parts.append(line)
                    transcript.write(line)
                else:
                    transcript.write(
                        json.dumps({"type": "stderr", "text": line.rstrip("\n")}) + "\n"
                    )
                transcript.flush()
        if proc.returncode is None:
            proc.wait()
    return "".join(stdout_parts)


def _text(value: str | bytes | None) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _last_agent_message(stdout: str) -> str:
    message = ""
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        candidate = event.get("message") or event.get("text")
        if isinstance(candidate, str) and candidate.strip():
            message = candidate
    return message


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        proc.kill()


def _stderr_summary(transcript_path: Path) -> str:
    message = ""
    if not transcript_path.exists():
        return message
    for line in transcript_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("type") != "stderr":
            continue
        text = event.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        if text.startswith("error:"):
            return text
        message = text
    return message


def _thread_id(stdout: str) -> str | None:
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and isinstance(event.get("thread_id"), str):
            return event["thread_id"]
    return None

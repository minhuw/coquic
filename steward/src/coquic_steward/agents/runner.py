from __future__ import annotations

import json
import os
import selectors
import signal
# subprocess is required to stream Codex stdio; launches use explicit argv and shell=False.
import subprocess  # nosec B404
import time
from pathlib import Path

from ..core.config import StewardConfig
from ..core.models import TaskRecord, WorkerResult
from .diagnostics import diagnostics_for_result


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
    ) -> WorkerResult:
        transcript_path, last_message_path = self.paths(task, name=name)
        run_dir = transcript_path.parent
        run_dir.mkdir(parents=True, exist_ok=True)
        prompt_path = self.config.prompts_dir / task.id / f"{name}.md"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")
        args = self._args(
            cwd,
            last_message_path,
            output_schema=output_schema,
            resume_session=resume_session,
        )
        try:
            return self._run_process(
                args,
                cwd,
                prompt,
                prompt_path,
                transcript_path,
                last_message_path,
                timeout_seconds=self.config.limits.worker_timeout_minutes * 60,
            )
        except FileNotFoundError as exc:
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
            return WorkerResult(
                completed=False,
                command=args,
                cwd=cwd,
                exit_code=127,
                prompt_path=prompt_path,
                transcript_path=transcript_path,
                last_message_path=last_message_path,
                final_message=message,
                diagnostics=diagnostics.model_dump(mode="json"),
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
        args = self._args(
            cwd,
            last_message_path,
            output_schema=output_schema,
            resume_session=None,
        )
        try:
            return self._run_process(
                args,
                cwd,
                prompt,
                prompt_path,
                transcript_path,
                last_message_path,
                timeout_seconds=self.config.limits.review_timeout_minutes * 60,
            )
        except FileNotFoundError as exc:
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
            return WorkerResult(
                completed=False,
                command=args,
                cwd=cwd,
                exit_code=127,
                prompt_path=prompt_path,
                transcript_path=transcript_path,
                last_message_path=last_message_path,
                final_message=message,
                diagnostics=diagnostics.model_dump(mode="json"),
            )

    def _args(
        self,
        cwd: Path,
        last_message_path: Path,
        *,
        output_schema: Path | None,
        resume_session: str | None,
    ) -> list[str]:
        args = [self.config.codex_bin, "exec"]
        if resume_session:
            args.append("resume")
        args.extend(["--json"])
        if self.config.codex_model:
            args.extend(["--model", self.config.codex_model])
        if self.config.codex_profile:
            args.extend(["--profile", self.config.codex_profile])
        if not resume_session:
            args.extend(["--sandbox", self.config.codex_sandbox, "--cd", str(cwd)])
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
    ) -> WorkerResult:
        # CodexRunner builds args as an argv list and never enables a shell.
        proc = subprocess.Popen(  # nosec B603
            args,
            cwd=cwd,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        stdout = _communicate_streaming(
            proc,
            prompt,
            transcript_path,
            timeout_seconds=timeout_seconds,
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
            diagnostics=diagnostics.model_dump(mode="json"),
        )


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

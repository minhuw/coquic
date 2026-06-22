from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict


class CodexRunDiagnostics(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    status: str
    summary: str
    exit_code: int | None = None
    transcript_path: Path | None = None
    last_message_path: Path | None = None
    last_message_present: bool = False
    event_count: int = 0
    error_count: int = 0
    last_event_type: str = ""
    last_item_type: str = ""
    last_item_status: str = ""
    last_error: str = ""
    last_output: str = ""
    thread_id: str | None = None
    timed_out: bool = False


def diagnostics_for_result(
    *,
    completed: bool,
    exit_code: int | None,
    transcript_path: Path,
    last_message_path: Path,
    final_message: str = "",
    thread_id: str | None = None,
) -> CodexRunDiagnostics:
    diagnostics = diagnostics_for_paths(
        transcript_path=transcript_path,
        last_message_path=last_message_path,
        exit_code=exit_code,
        thread_id=thread_id,
    )
    if completed and diagnostics.status == "ok":
        return diagnostics
    if final_message and not diagnostics.last_error:
        diagnostics.last_error = final_message.strip()
    diagnostics.status = _status_for_failure(diagnostics, completed=completed)
    diagnostics.summary = _summary_for(diagnostics)
    return diagnostics


def diagnostics_for_paths(
    *,
    transcript_path: Path | None,
    last_message_path: Path | None,
    exit_code: int | None = None,
    completed: bool | None = None,
    thread_id: str | None = None,
) -> CodexRunDiagnostics:
    last_message_present = bool(
        last_message_path and last_message_path.exists() and last_message_path.stat().st_size
    )
    facts = _transcript_facts(transcript_path)
    timed_out = "timed out" in facts["last_error"].lower()
    status = "ok"
    if exit_code not in (None, 0):
        status = "failed"
    elif timed_out:
        status = "timed_out"
    elif completed is False:
        status = "abandoned"
    elif transcript_path and transcript_path.exists() and not last_message_present:
        status = "missing_last_message"
    diagnostics = CodexRunDiagnostics(
        status=status,
        summary="",
        exit_code=exit_code,
        transcript_path=transcript_path,
        last_message_path=last_message_path,
        last_message_present=last_message_present,
        event_count=facts["event_count"],
        error_count=facts["error_count"],
        last_event_type=facts["last_event_type"],
        last_item_type=facts["last_item_type"],
        last_item_status=facts["last_item_status"],
        last_error=facts["last_error"],
        last_output=facts["last_output"],
        thread_id=thread_id or facts["thread_id"],
        timed_out=timed_out,
    )
    diagnostics.summary = _summary_for(diagnostics)
    return diagnostics


def _transcript_facts(path: Path | None) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "event_count": 0,
        "error_count": 0,
        "last_event_type": "",
        "last_item_type": "",
        "last_item_status": "",
        "last_error": "",
        "last_output": "",
        "thread_id": None,
    }
    if path is None or not path.exists():
        return facts
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        facts["last_error"] = str(exc)
        return facts
    for line in lines:
        if not line.strip():
            continue
        facts["event_count"] += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            facts["last_output"] = line[-2000:]
            continue
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "")
        if event_type:
            facts["last_event_type"] = event_type
        if isinstance(event.get("thread_id"), str):
            facts["thread_id"] = event["thread_id"]
        if event_type == "stderr":
            text = str(event.get("text") or event.get("message") or "").strip()
            if text:
                facts["error_count"] += 1
                facts["last_error"] = text[-2000:]
            continue
        item = event.get("item")
        if isinstance(item, dict):
            item_type = str(item.get("type") or "")
            item_status = str(item.get("status") or "")
            if item_type:
                facts["last_item_type"] = item_type
            if item_status:
                facts["last_item_status"] = item_status
            if item_type == "error":
                message = str(item.get("message") or item.get("text") or "").strip()
                if message:
                    facts["error_count"] += 1
                    facts["last_error"] = message[-2000:]
            output = str(
                item.get("aggregated_output")
                or item.get("output")
                or item.get("text")
                or item.get("message")
                or ""
            ).strip()
            if output:
                facts["last_output"] = output[-2000:]
    return facts


def _status_for_failure(
    diagnostics: CodexRunDiagnostics, *, completed: bool
) -> str:
    if diagnostics.timed_out:
        return "timed_out"
    if diagnostics.exit_code not in (None, 0):
        return "failed"
    if not diagnostics.last_message_present:
        return "missing_last_message"
    return "ok" if completed else "abandoned"


def _summary_for(diagnostics: CodexRunDiagnostics) -> str:
    if diagnostics.timed_out:
        return "Codex session timed out."
    if diagnostics.exit_code not in (None, 0):
        if diagnostics.last_error:
            return f"Codex exited {diagnostics.exit_code}: {diagnostics.last_error}"
        return f"Codex exited with code {diagnostics.exit_code}."
    if diagnostics.status == "missing_last_message":
        tail = _tail_description(diagnostics)
        return f"Codex transcript exists but no structured last message was written{tail}."
    if diagnostics.status == "abandoned":
        tail = _tail_description(diagnostics)
        return f"Codex session did not complete{tail}."
    if diagnostics.last_error:
        return diagnostics.last_error
    return "Codex session completed."


def _tail_description(diagnostics: CodexRunDiagnostics) -> str:
    if diagnostics.last_item_type:
        status = (
            f" ({diagnostics.last_item_status})" if diagnostics.last_item_status else ""
        )
        return f"; last item was {diagnostics.last_item_type}{status}"
    if diagnostics.last_event_type:
        return f"; last event was {diagnostics.last_event_type}"
    return ""

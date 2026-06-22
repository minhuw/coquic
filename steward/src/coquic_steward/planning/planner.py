from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..agents import CodexRunner
from ..core.config import StewardConfig
from ..core.models import (
    IntegrationMode,
    ProjectSignals,
    TaskRecord,
    TaskSpec,
    new_task_id,
)
from .verifier import ActiveTaskSummary, PlanVerifier, summarize_active_tasks

PLANNER_SYSTEM_PROMPT = """\
You are CoQUIC Steward's planning brain.

Your job is to decide which maintenance tasks should exist from Steward inbox
messages. You only plan work; you do not fix code, run tools, commit, push,
dismiss scanner alerts, or mutate the repository.

Review active_tasks before proposing anything. If queued, running, reviewing, or
integrating work already covers a signal or kind of work, do not create another
task for it.

Create only necessary tasks backed by provided signal items. Do not speculate from
missing data. Prefer no task over a vague task.

Mark an inbox item as consumed only when your output has either created the
needed task, or intentionally decided no work is needed for that item. Leave
items unconsumed when concurrent active work already covers them or when you
need to wait for capacity.

Every task must:
- cite at least one allowed evidence ID;
- use a stable dedupe_key derived from that evidence;
- use only allowed kind, worker, priority, and risk values;
- include a clear title and a worker-ready prompt;
- select one concrete, bounded source context from the provided signal items;
- keep scope narrow enough for one Codex execution session.
- use a title that names the selected source context, such as the affected file,
  rule, workflow, or run id.

When remote integration is enabled, plan tasks as patch-producing work and leave
commit/push to Steward's integration manager.

The worker receives only the task prompt and the selected source context. Do not
ask workers to fetch an unknown issue list to decide scope. They may only use
remote APIs to verify that the provided signal items are still current or to
collect extra details for the same selected items.

Return only JSON matching the requested schema. Do not include markdown,
commentary, code fences, or prose outside the JSON object.
"""


@dataclass(frozen=True)
class PlannedTask:
    task: TaskSpec
    dedupe_key: str


@dataclass(frozen=True)
class PlannerRun:
    planned: list[tuple[TaskSpec, str]]
    accepted_count: int
    proposed_count: int
    completed: bool
    exit_code: int
    prompt_path: Path | None
    transcript_path: Path
    thread_id: str | None
    consumed_item_ids: list[str] = field(default_factory=list)
    run_id: str | None = None
    diagnostics: dict[str, object] = field(default_factory=dict)


class CodexPlanner:
    def __init__(self, config: StewardConfig, verifier: PlanVerifier | None = None):
        self.config = config
        self.runner = CodexRunner(config)
        self.verifier = verifier or PlanVerifier()

    def plan(
        self, signals: ProjectSignals, active_tasks: list[TaskRecord]
    ) -> list[tuple[TaskSpec, str]]:
        return self.run(signals, active_tasks).planned

    def run(self, signals: ProjectSignals, active_tasks: list[TaskRecord]) -> PlannerRun:
        active = summarize_active_tasks(active_tasks)
        planner_task = _planner_task()
        result = self.runner.run(
            planner_task,
            render_planner_prompt(signals, active, self.config),
            self.config.repo_root,
            name="planner",
            output_schema=planner_schema_path(self.config),
            resume_session=planner_thread_id(self.config),
        )
        if result.thread_id:
            planner_thread_path(self.config).write_text(
                result.thread_id, encoding="utf-8"
            )
        if not result.completed:
            return PlannerRun(
                planned=[],
                accepted_count=0,
                proposed_count=0,
                completed=False,
                exit_code=result.exit_code,
                prompt_path=result.prompt_path,
                transcript_path=result.transcript_path,
                thread_id=result.thread_id,
                run_id=planner_task.id,
                diagnostics=result.diagnostics,
            )
        raw_json = _extract_json(result.final_message)
        verified = self.verifier.verify_plan(
            raw_json,
            signals,
            active,
        )
        return PlannerRun(
            planned=verified.planned,
            accepted_count=len(verified.planned),
            proposed_count=_proposed_count(raw_json),
            completed=True,
            exit_code=result.exit_code,
            prompt_path=result.prompt_path,
            transcript_path=result.transcript_path,
            thread_id=result.thread_id,
            consumed_item_ids=verified.consumed_item_ids,
            run_id=planner_task.id,
            diagnostics=result.diagnostics,
        )


def plan_tasks(
    config: StewardConfig, signals: ProjectSignals, active_tasks: list[TaskRecord]
) -> list[tuple[TaskSpec, str]]:
    return CodexPlanner(config).plan(signals, active_tasks)


def run_planner(
    config: StewardConfig, signals: ProjectSignals, active_tasks: list[TaskRecord]
) -> PlannerRun:
    return CodexPlanner(config).run(signals, active_tasks)


def render_planner_prompt(
    signals: ProjectSignals,
    active_tasks: list[ActiveTaskSummary],
    config: StewardConfig,
) -> str:
    payload = {
        "repository": config.github_repository,
        "enabled_signals": list(config.enabled_signals),
        "signals": signals.model_dump(mode="json"),
        "signal_items": [item.model_dump(mode="json") for item in signals.items],
        "signal_fetches": [fetch.model_dump(mode="json") for fetch in signals.fetches],
        "active_tasks": [task.model_dump(mode="json") for task in active_tasks],
        "allowed_kinds": [
            "code-quality",
            "interop",
            "ci",
            "rfc-audit",
            "health",
            "custom",
        ],
        "allowed_workers": [
            "interop-doctor",
            "code-quality-janitor",
            "ci-doctor",
            "rfc-auditor",
            "issue-implementer",
            "work-item-creator",
            "custom",
        ],
        "allowed_priorities": ["low", "medium", "high", "urgent"],
        "allowed_risks": ["low", "medium", "high"],
        "remote_integration_enabled": (
            config.integration_mode == IntegrationMode.push_main.value
        ),
    }
    return "\n".join(
        [
            PLANNER_SYSTEM_PROMPT.strip(),
            "",
            "Output schema:",
            '{"consumed_item_ids":["wi-..."],"tasks":[{"dedupe_key":"string","kind":"code-quality","worker":"code-quality-janitor","title":"string","prompt":"string","priority":"high","risk":"medium","evidence":["wi-..."],"metadata":{"selected_signal_item_ids":["wi-..."]}}]}',
            "",
            "Evidence IDs you may cite:",
            "- any signal item id from signal_items",
            "",
            "For metadata:",
            "- selected_signal_item_ids must list the selected signal item ids.",
            "",
            "Planning input JSON:",
            json.dumps(payload, sort_keys=True),
        ]
    )


def planner_schema_path(config: StewardConfig) -> Path:
    path = config.state_dir / "schemas" / "planner.schema.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(PLANNER_OUTPUT_SCHEMA, indent=2), encoding="utf-8")
    return path


def planner_thread_path(config: StewardConfig) -> Path:
    path = config.state_dir / "planner-thread.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def planner_thread_id(config: StewardConfig) -> str | None:
    path = planner_thread_path(config)
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


PLANNER_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "consumed_item_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
        "tasks": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "dedupe_key": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "enum": [
                            "code-quality",
                            "interop",
                            "ci",
                            "rfc-audit",
                            "health",
                            "custom",
                        ],
                    },
                    "worker": {
                        "type": "string",
                        "enum": [
                            "interop-doctor",
                            "code-quality-janitor",
                            "ci-doctor",
                            "rfc-auditor",
                            "issue-implementer",
                            "work-item-creator",
                            "custom",
                        ],
                    },
                    "title": {"type": "string"},
                    "prompt": {"type": "string"},
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "urgent"],
                    },
                    "risk": {"type": "string", "enum": ["low", "medium", "high"]},
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "metadata": {
                        "type": "object",
                        "properties": {
                            "selected_signal_item_ids": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                        "required": ["selected_signal_item_ids"],
                        "additionalProperties": False,
                    },
                },
                "required": [
                    "dedupe_key",
                    "kind",
                    "worker",
                    "title",
                    "prompt",
                    "priority",
                    "risk",
                    "evidence",
                    "metadata",
                ],
            },
        }
    },
    "required": ["consumed_item_ids", "tasks"],
}


def _planner_task() -> TaskRecord:
    from ..core.models import TaskKind, TaskSpec, WorkerKind

    return TaskRecord(
        spec=TaskSpec(
            id=f"planner-{new_task_id()}",
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="Plan Steward tasks",
            prompt="Plan Steward tasks from current signals.",
            source="planner",
        )
    )


def _extract_json(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return stripped
    return stripped[start : end + 1]


def _proposed_count(raw_json: str) -> int:
    try:
        decoded = json.loads(raw_json)
    except json.JSONDecodeError:
        return 0
    tasks = decoded.get("tasks") if isinstance(decoded, dict) else None
    return len(tasks) if isinstance(tasks, list) else 0

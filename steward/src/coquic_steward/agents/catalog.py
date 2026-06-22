from __future__ import annotations

import json
from dataclasses import dataclass

from ..core.config import StewardConfig
from ..core.models import IntegrationMode, TaskRecord, TaskKind, WorkerKind


@dataclass(frozen=True)
class StewardAgent:
    worker: WorkerKind
    name: str
    purpose: str
    skills: tuple[str, ...] = ()
    read_only: bool = False
    remote_writes: bool = False


AGENTS: dict[WorkerKind, StewardAgent] = {
    WorkerKind.integration_manager: StewardAgent(
        WorkerKind.integration_manager,
        "Integration Manager",
        "Serialize reviewed patches onto latest main, validate, commit, and push.",
        remote_writes=True,
    ),
    WorkerKind.interop_doctor: StewardAgent(
        WorkerKind.interop_doctor,
        "Interop Doctor",
        "Debug failed Interop workflow runs and fix locally reproducible CoQUIC bugs.",
        ("debug-interop-run", "quic-rag"),
    ),
    WorkerKind.code_quality_janitor: StewardAgent(
        WorkerKind.code_quality_janitor,
        "Code Quality Janitor",
        "Repair real CodeQL and Codacy findings without weakening scanners.",
        ("fix-code-quality-issues", "quic-rag"),
    ),
    WorkerKind.ci_doctor: StewardAgent(
        WorkerKind.ci_doctor,
        "CI Doctor",
        "Investigate failed workflows, reproduce locally, and make focused fixes.",
        ("quic-rag",),
    ),
    WorkerKind.rfc_auditor: StewardAgent(
        WorkerKind.rfc_auditor,
        "RFC Auditor",
        "Audit QUIC behavior and Duvet annotations against grounded RFC context.",
        ("quic-rag",),
    ),
    WorkerKind.issue_implementer: StewardAgent(
        WorkerKind.issue_implementer,
        "Issue Implementer",
        "Implement a scoped CoQUIC GitHub issue locally and report proposed issue updates.",
        ("gh-issue-implementation", "quic-rag"),
    ),
    WorkerKind.work_item_creator: StewardAgent(
        WorkerKind.work_item_creator,
        "Work Item Creator",
        "Create or update GitHub tracking issues.",
        ("gh-work-item",),
        remote_writes=True,
    ),
    WorkerKind.reviewer: StewardAgent(
        WorkerKind.reviewer,
        "Reviewer",
        "Review a Steward-produced diff for correctness, generated state, validation gaps, and protocol errors.",
        ("quic-rag",),
        read_only=True,
    ),
    WorkerKind.custom: StewardAgent(
        WorkerKind.custom, "Custom", "Run the provided task prompt."
    ),
}


COMMON_RULES = """\
You are running under CoQUIC Steward.

Preserve unrelated user work. Work only in the required worktree. Do not commit,
push, merge, rebase, change GitHub issues, change workflow settings, or weaken
CodeQL/Codacy/CI configuration unless the prompt explicitly says this worker is
allowed to perform that remote-write task.

Produce a concise final report with root cause, changed files, validation
performed, remaining risk, and any generated state avoided.
"""


def agent_for_worker(worker: WorkerKind | str) -> StewardAgent:
    return AGENTS.get(WorkerKind(worker), AGENTS[WorkerKind.custom])


def render_worker_prompt(task: TaskRecord, config: StewardConfig) -> str:
    agent = agent_for_worker(task.spec.worker)
    sections = [
        COMMON_RULES,
        f"Worker: {agent.name}",
        f"Task ID: {task.id}",
        f"Task: {task.spec.title}",
        f"Required worktree: {task.worktree_path}",
        f"GitHub repository: {config.github_repository}",
        f"Enabled signals: {', '.join(config.enabled_signals) or 'none'}",
        "",
        "Worker purpose:",
        agent.purpose,
        "",
        "Task prompt:",
        task.spec.prompt,
    ]
    source_context = _render_source_context(task)
    if source_context:
        sections.extend(
            [
                "",
                "Authoritative source context:",
                source_context,
                "",
                "Scope rule:",
                (
                    "Treat the source context above as the single source of truth for "
                    "this task's scope. Do not fetch a broad or unknown issue list to "
                    "choose different work. Remote APIs may only be used to verify that "
                    "these selected items are still current or to gather extra detail "
                    "for the same selected items."
                ),
            ]
        )
    skill_text = _render_skills(config, agent.skills)
    if skill_text:
        sections.extend(["", "Embedded repo skills:", skill_text])
    if task.spec.metadata:
        metadata = "\n".join(
            f"- {key}: {value}" for key, value in sorted(task.spec.metadata.items())
        )
        sections.extend(["", "Metadata:", metadata])
    boundary = _render_execution_boundary(task, config)
    if boundary:
        sections.extend(["", "Execution boundary:", boundary])
    return "\n".join(sections).strip()


def _render_source_context(task: TaskRecord) -> str:
    context = task.spec.metadata.get("source_context")
    if not isinstance(context, dict):
        return ""
    return json.dumps(context, indent=2, sort_keys=True)


def _render_skills(config: StewardConfig, skill_names: tuple[str, ...]) -> str:
    blocks: list[str] = []
    for name in skill_names:
        path = config.repo_root / ".agents" / "skills" / name / "SKILL.md"
        if path.exists():
            blocks.append(f"## {name}\n\n{path.read_text(encoding='utf-8').strip()}")
        else:
            blocks.append(f"## {name}\n\nMissing skill at {path}.")
    return "\n\n".join(blocks)


def _render_execution_boundary(task: TaskRecord, config: StewardConfig) -> str:
    if TaskKind(task.spec.kind) != TaskKind.code_quality:
        return ""
    if config.integration_mode == IntegrationMode.push_main.value:
        return (
            "Steward owns final integration. You may use remote scanner APIs only to "
            "re-check the selected source-context findings, but do not commit or push "
            "manually. Produce source changes in the "
            "worktree and let Steward review, validate, commit, push, and re-check."
        )
    return (
        "Stop at a validated local patch. Do not commit, push, trigger GitHub workflows, "
        "dismiss scanner alerts, or change scanner configuration. Fix only the selected "
        "source-context findings in the worktree, run local validation, and report what "
        "remote re-check remains."
    )

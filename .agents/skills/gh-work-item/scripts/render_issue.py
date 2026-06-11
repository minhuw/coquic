#!/usr/bin/env python3
"""Render a structured GitHub issue body for coquic work items."""

from __future__ import annotations

import argparse
from pathlib import Path


DEFAULT_CREATOR = "Codex"
DEFAULT_MODEL = "GPT-5"

LOCAL_ONLY_SOURCE_TOKENS = (
    "todo-may.md",
    ".remote-ci/",
    ".rag/",
    ".duvet/",
    ".worktrees/",
)


def lines_from_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(";") if item.strip()]


def checkbox_lines(items: list[str]) -> str:
    return "\n".join(f"- [ ] {item}" for item in items)


def bullet_lines(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def generated_footer(creator: str, model: str) -> str:
    creator = creator.strip()
    model = model.strip()
    if model:
        return f"Created by {creator} ({model})."
    return f"Created by {creator}."


def render_issue(args: argparse.Namespace) -> str:
    source = args.source.strip()
    for token in LOCAL_ONLY_SOURCE_TOKENS:
        if token in source:
            raise ValueError(
                f"source must be self-contained and durable; replace local-only reference {token!r}"
            )

    scope = lines_from_csv(args.scope)
    acceptance = lines_from_csv(args.acceptance)
    validation = lines_from_csv(args.validation)

    body = [
        "## Summary",
        "",
        args.summary.strip(),
        "",
        "## Background",
        "",
        args.background.strip(),
        "",
        "## Current Behavior",
        "",
        args.current.strip(),
        "",
        "## Desired Outcome",
        "",
        args.desired.strip(),
        "",
        "## Scope",
        "",
        bullet_lines(scope) if scope else "- Define the implementation scope before starting.",
        "",
        "## Acceptance Criteria",
        "",
        checkbox_lines(acceptance) if acceptance else "- [ ] Acceptance criteria are defined.",
        "",
        "## Validation",
        "",
        checkbox_lines(validation)
        if validation
        else "\n".join(
            [
                "- [ ] `nix develop -c zig build test`",
                "- [ ] `nix develop -c ./scripts/compliance`",
            ]
        ),
        "",
        "## Tracking",
        "",
        f"- Source: {source}",
        f"- Related: {args.related.strip()}",
        "",
        "---",
        "",
        generated_footer(args.creator, args.model),
    ]

    if args.spec:
        body[7:7] = ["", "## RFC / Spec Reference", "", args.spec.strip()]
    if args.risks:
        body[-3:-3] = ["", "## Risks", "", args.risks.strip()]
    if args.out_of_scope:
        body[-3:-3] = ["", "## Out of Scope", "", args.out_of_scope.strip()]

    return "\n".join(body).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--background", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--desired", required=True)
    parser.add_argument("--scope", default="")
    parser.add_argument("--acceptance", default="")
    parser.add_argument("--validation", default="")
    parser.add_argument("--source", default="user request")
    parser.add_argument("--related", default="none known")
    parser.add_argument("--creator", default=DEFAULT_CREATOR)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--spec", default="")
    parser.add_argument("--risks", default="")
    parser.add_argument("--out-of-scope", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        rendered = render_issue(args)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

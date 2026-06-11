---
name: gh-work-item
description: Create consistent GitHub issues for tracking implementation work, bug fixes, design tasks, technical debt, protocol gaps, test gaps, performance work, documentation work, CI failures, interop follow-ups, and investigations in the coquic repository. Use when asked to draft, create, batch-create, organize, or update GitHub issues for things that should be fixed, implemented, reviewed later, or tracked as project work.
---

# GitHub Work Item

Use this skill to turn a decision, gap, bug, feature idea, CI failure, review finding, or follow-up into a clear GitHub issue for `minhuw/coquic`.

## Workflow

1. Classify the work item:
   `bug`, `feature`, `enhancement`, `tech-debt`, `test-gap`, `docs`, `investigation`, `compliance`, `ci`, `perf`, or `interop`.
2. Identify the source:
   user request, failing test or CI run, code review finding, Duvet/RFC/spec gap, benchmark or interop result, or local code inspection.
3. Check for duplicates before creating:
   use `gh issue list --state all --search "<keywords>"` with likely titles, modules, error text, RFC sections, or source IDs.
4. Draft the issue:
   use `references/work-item-template.md`; keep one issue per independent work item; split unrelated work.
   Make the issue body self-contained. Do not use uncommitted/local-only tracking files, generated state, or downloaded logs as the issue's authoritative source. Translate those into durable context such as an RFC section, GitHub Actions run URL, failing command, commit/PR/issue URL, or a short local-code-inspection summary.
   Include the footer `Created by Codex (<model name>).` so generated issues are distinguishable from human-created issues. Use the current model name; this skill currently defaults to `GPT-5`.
5. Confirm before creating unless the user explicitly asked to create issues now.
6. Create the issue:
   use `gh issue create`; use existing labels only; do not create labels unless explicitly asked.
7. Update source tracking when applicable:
   add issue number/URL, decision, scope, and status to the originating TODO or tracking file.

## Resources

- Read `references/work-item-template.md` for the body template and title/label rules.
- Read `references/classification.md` when the issue type or labels are unclear.
- Use `scripts/render_issue.py` to render a deterministic issue body from command-line fields.
- The renderer adds the Codex/model footer by default. Pass `--model <name>` only when the current model differs from the default.

## Validation

For implementation issues, include `nix develop -c zig build test` and `nix develop -c ./scripts/compliance` unless clearly irrelevant.

Add targeted validation for the touched area:

- migration, routing, or address validation: relevant endpoint and migration tests
- recovery, ACK, congestion, or ECN: recovery and ACK tests
- streams or flow control: stream and flow-control tests
- API/FFI: public API and FFI tests
- CI or automation: affected workflow command or `gh workflow run` follow-up

## Tracking Files

When the issue came from a local tracking file such as `todo-may.md`, update that local file with the issue number/URL, decision, scope, and status. Do not put the local tracking file path in the GitHub issue body unless the file is committed and intended to remain as durable project documentation. Preserve the existing item text and do not reorder unrelated items.

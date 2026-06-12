---
name: gh-issue-implementation
description: Implement CoQUIC GitHub issues end to end. Use when the user gives a GitHub issue URL/number or asks to fetch, implement, test, add Duvet/RFC annotations, update issue TODO checkboxes, comment on, or close an implementation issue in the minhuw/coquic repository.
---

# GitHub Issue Implementation

Use this workflow to turn a CoQUIC GitHub issue into a local implementation with tests, Duvet annotations, issue updates, and a closing comment.

## Workflow

1. Fetch the issue with `gh issue view <number-or-url> --repo minhuw/coquic --json number,title,state,body,comments,labels,assignees,author,url`.
2. Read the issue body and comments for acceptance criteria, task checkboxes, validation commands, and any linked context. If protocol behavior is involved, use `$quic-rag` and cite/query the relevant RFC section before editing.
3. Inspect the working tree before edits with `git status --short --branch`. Preserve unrelated user changes. Do not switch branches, reset, or remove worktrees unless the user explicitly asks.
4. Implement the issue using existing repo patterns. Keep changes focused but update every affected public surface: C++ APIs, C FFI, language bindings, docs, tests, diagnostics, and ABI/version constants when applicable.
5. Add Duvet annotations next to the source behavior or tests that satisfy RFC requirements. Use the local style:

```cpp
//= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
// # Endpoints MUST be able to deliver stream data to an application as an
// # ordered byte stream.
```

6. Add tests that directly cover each acceptance criterion, including negative/error paths and default behavior. For QUIC protocol changes, include regression tests for duplicates, overlaps, final-size conflicts, reset/terminal states, flow-control accounting, and both configured and default modes as relevant.
7. Format touched source files with the repo’s existing formatters (`clang-format`, `gofmt`, `cargo fmt`, etc.).
8. Validate with the issue-requested commands first. Prefer:

```bash
nix develop -c zig build test
nix develop -c ./scripts/compliance
```

If Nix/Zig/Duvet is unavailable, run the strongest available substitutes, such as syntax checks, binding compile checks, and `git diff --check`. Clearly record exact blockers and exact commands attempted.

9. Update GitHub issue task checkboxes only after the matching local work is actually done. Preserve the rest of the issue body exactly; edit only checkbox markers such as `- [ ]` to `- [x]`. Use `gh issue edit <number> --repo minhuw/coquic --body-file <file>` or `gh api` rather than leaving stale TODOs.
10. Close the issue only after implementation and available validation are complete, unless validation is externally blocked. Add a closing comment with real Markdown newlines, not escaped `\n` sequences. Prefer a temp file or ANSI-C quoted shell string:

```bash
cat > /tmp/coquic-issue-comment.md <<'EOF'
Implemented ...

Validation:
- `nix develop -c zig build test`: passed
- `nix develop -c ./scripts/compliance`: passed
EOF
gh issue close <number> --repo minhuw/coquic --comment-file /tmp/coquic-issue-comment.md
```

If using `gh api` for comments, verify the rendered body with `gh issue view <number> --json comments`.

## Issue Comments

Write comments for humans scanning GitHub:

- State what was implemented in one short paragraph.
- List meaningful test coverage and validation results.
- Mention blocked validations with exact root cause and command.
- Include no local-only paths unless they help reproduce a validation failure.
- Avoid escaped newline text; verify comments with `gh issue view`.

## Final Local Report

Before responding to the user:

- Run `git status --short --branch`.
- Confirm the issue state with `gh issue view <number> --json state,url,title`.
- Mention whether issue checkboxes were updated, whether the issue was closed, and which validations passed or were blocked.
- Do not claim full validation if required commands could not run.

# Work Item Template

## Title Format

Use the most specific form:

- Bug: `<area>: fix <broken behavior>`
- Feature: `<area>: implement <capability>`
- Enhancement: `<area>: improve <behavior>`
- Test gap: `<area>: add coverage for <case>`
- Investigation: `<area>: investigate <question>`
- Compliance: `RFC <number> §<section>: <requirement summary>`
- CI: `ci: <workflow/task>`
- Perf: `perf: <benchmark or bottleneck>`
- Interop: `interop: <peer/case/problem>`

## Labels

Prefer existing labels matching the classification. Common candidates:

- `bug`
- `feature`
- `enhancement`
- `documentation`
- `test`
- `ci`
- `performance`
- `interop`
- `protocol`
- `compliance`
- `needs-design`
- `needs-investigation`

If a label does not exist, omit it and mention that it was unavailable.

## Required Body

```markdown
## Summary

<One short paragraph describing the work item.>

## Background

<Why this exists. Include user request, CI failure, RFC/spec reference, review finding, or code inspection summary when relevant. Do not rely on local-only tracking files.>

## Current Behavior

<What the repository does today.>

## Desired Outcome

<What should be true when the issue is done.>

## Scope

- <Specific change area 1>
- <Specific change area 2>
- <Specific change area 3>

## Acceptance Criteria

- [ ] <Observable completion condition 1>
- [ ] <Observable completion condition 2>
- [ ] <Observable completion condition 3>

## Validation

- [ ] `nix develop -c zig build test`
- [ ] `nix develop -c ./scripts/compliance`

## Tracking

- Source: <durable source such as RFC section, GitHub Actions URL, issue/PR/commit URL, failing command, user request, or code inspection summary>
- Related: <issue/PR links, or "none known">

---

Created by Codex (GPT-5).
```

The issue must be useful without access to uncommitted local files. If the work was discovered from a local TODO, generated Duvet state, `.remote-ci/` logs, `.rag/` state, or another private/local artifact, summarize that context in the issue and record the GitHub issue URL back into the local tracker separately.

Use this footer for Codex-created issues and update the model name if the active model is different.

## Optional Sections

Use only when useful:

- `## Reproduction`
- `## RFC / Spec Reference`
- `## Design Notes`
- `## Risks`
- `## Out of Scope`
- `## Related Issues`

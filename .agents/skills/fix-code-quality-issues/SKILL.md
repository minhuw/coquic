---
name: fix-code-quality-issues
description: Fetch and fix current CodeQL and Codacy issues for the minhuw/coquic repository. Use when asked to inspect GitHub Security code scanning alerts at https://github.com/minhuw/coquic/security, Codacy current issues at https://app.codacy.com/gh/minhuw/coquic/issues/current, or to automatically repair static-analysis/security findings without weakening scanner configuration.
---

# Fix Code Quality Issues

Use this workflow to fetch, triage, fix, validate, commit, push, and re-check current CodeQL and
Codacy findings for `minhuw/coquic`.

## Ground Rules

- Fix source, tests, scripts, or documentation; do not hide findings.
- Do not weaken CodeQL or Codacy scanning configuration to make findings disappear.
- Do not remove CodeQL jobs, languages, schedules, pull request coverage, `workflow_dispatch`,
  `security-events: write`, `queries: +security-extended,security-and-quality`, or existing
  CodeQL path coverage.
- Do not add or broaden `paths-ignore`, Codacy `exclude_paths`, engine disables, rule disables,
  baseline files, ignore pragmas, generated-file markers, or alert dismissals unless the user
  explicitly approves the exact false positive and the final response calls it out.
- Do not change `.github/workflows/codeql.yml`, `.codacy.yml`, or scanner settings unless the
  issue is genuinely caused by broken scanner setup and the user explicitly asked for that config
  repair.
- Before editing, inspect the dirty tree and preserve unrelated user changes.
- Store downloaded/fetched scanner snapshots under `.remote-ci/code-quality/`. Do not commit them.
- Use `nix develop -c ...` for build, test, format, lint, CodeQL CLI, or scanner commands that need
  the reproducible toolchain.
- When a finding is in QUIC protocol behavior, use the repo's QUIC RAG skill/query flow before
  making protocol claims.
- Validate with focused tests when available, then `nix develop -c zig build test` and
  `git diff --check` unless a clear constraint blocks them.
- Commit with Conventional Commits, push to `origin`, then trigger/re-check the relevant remote
  scanners.

## 1. Capture Current Findings

Prepare a local snapshot directory:

```bash
mkdir -p .remote-ci/code-quality
git status --short
```

Fetch open CodeQL alerts from GitHub code scanning:

```bash
gh api -X GET 'repos/minhuw/coquic/code-scanning/alerts?state=open&per_page=100' \
  > .remote-ci/code-quality/codeql-alerts.json
```

For each alert that needs dataflow or duplicate-location context, fetch instances:

```bash
gh api -X GET 'repos/minhuw/coquic/code-scanning/alerts/<alert-number>/instances?per_page=100' \
  > .remote-ci/code-quality/codeql-alert-<alert-number>-instances.json
```

Fetch Codacy issues from the API when a `CODACY_API_TOKEN` is available:

```bash
curl -fsS -X POST \
  -H "api-token: ${CODACY_API_TOKEN}" \
  -H "Content-Type: application/json" \
  'https://app.codacy.com/api/v3/analysis/organizations/gh/minhuw/repositories/coquic/issues/search?limit=100' \
  -d '{}' \
  > .remote-ci/code-quality/codacy-issues.json
```

If the response has a `pagination.cursor`, repeat the request with `&cursor=<cursor>` and append
each page to the snapshot set. If the Codacy API shape has changed, check Codacy's official API docs
for `searchRepositoryIssues` and adapt the URL. If no Codacy token is available, use the
authenticated browser/UI only if available; otherwise report that Codacy fetching is blocked and
continue with CodeQL.

## 2. Summarize And Prioritize

Use `jq` to create a concise worklist:

```bash
jq -r '.[] | [.number, .rule.severity, .rule.id, .most_recent_instance.location.path,
  .most_recent_instance.location.start_line, .most_recent_instance.message.text] | @tsv' \
  .remote-ci/code-quality/codeql-alerts.json
```

For Codacy, normalize the issue fields present in the fetched JSON and group by:

- file path
- line or line range
- tool/pattern/rule ID
- severity or category
- issue message

Prioritize:

1. Security and correctness findings.
2. Findings that affect shared library/runtime behavior.
3. Simple dead-code, unused-value, documentation, duplication, and style findings.
4. Larger maintainability changes only after understanding the affected module.

When CodeQL and Codacy report the same underlying problem, fix it once and mention both tools in
the notes.

## 3. Diagnose

For each finding:

- Read the flagged file and surrounding call sites with `rg`, `sed`, or `nl`.
- Confirm whether the finding is real, stale, duplicate, or a false positive.
- Prefer semantic fixes: remove dead code, tighten lifetimes, check errors, validate bounds,
  simplify control flow, split overly complex functions, add useful comments, or add tests.
- Avoid superficial no-op rewrites that only perturb the scanner result.
- If a finding points to generated or vendored code, verify whether the file is tracked source and
  whether fixing the generator/source is possible before considering a narrow approved exclusion.

## 4. Fix And Validate

For each batch of related findings:

1. Add or update focused tests when practical, especially for security/correctness findings.
2. Make the smallest source change that addresses the root cause.
3. Run the focused test or local reproduction command.
4. Re-run local static checks if available for that language/tool.

Then run broader validation:

```bash
nix develop -c zig build test
git diff --check
```

If changing `rag/`, also run:

```bash
uv run --project rag pytest rag/tests
```

If changing frontend code under `site/next`, run that package's relevant lint/test/build command
from inside `site/next` when available.

## 5. Commit, Push, And Re-check

Before committing:

```bash
git status --short
git diff --stat
git diff -- .github/workflows/codeql.yml .codacy.yml
```

If the scanner config diff is non-empty and the user did not explicitly approve that exact config
change, stop and revert only the scanner-config edits you made.

Stage only source/test/docs changes that should be tracked. Do not stage `.remote-ci/`, `.rag/`,
`.zig-cache/`, `.interop-logs/`, or build outputs.

Commit and push:

```bash
git commit -m 'fix: resolve code quality findings'
git push origin HEAD
```

Trigger a fresh CodeQL run:

```bash
gh workflow run .github/workflows/codeql.yml --ref main
gh run list --workflow .github/workflows/codeql.yml --branch main --limit 5 \
  --json databaseId,displayTitle,event,headSha,status,conclusion,url,createdAt
```

Codacy usually analyzes pushed commits automatically. If a Codacy re-analysis API endpoint or UI
action is available, use it; otherwise wait for the pushed commit to appear in Codacy and refetch
current issues.

Re-check CodeQL alerts after the run completes:

```bash
gh api -X GET 'repos/minhuw/coquic/code-scanning/alerts?state=open&per_page=100' \
  > .remote-ci/code-quality/codeql-alerts-after.json
```

Re-check Codacy issues with the same fetch method used in step 1 and save the result as
`.remote-ci/code-quality/codacy-issues-after.json`.

## 6. Report

Final notes must include:

- CodeQL alert numbers, rule IDs, files, and whether each was fixed, still open, stale, or blocked.
- Codacy issue identifiers/rules/files, and whether each was fixed, still open, stale, or blocked.
- The root cause and source changes made.
- Validation commands and outcomes.
- Commit SHA and pushed branch.
- Fresh CodeQL run ID/URL/head SHA, if triggered.
- Codacy re-check status and any token/UI constraints.
- A statement that scanner settings were not weakened, or the exact user-approved scanner-config
  change if one was necessary.

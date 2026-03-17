# Codecov Badge Design

## Status

Approved on 2026-03-17.

## Context

`coquic` already generates LLVM coverage reports in CI as `coverage/lcov.info`
and uploads the raw report artifacts. The repository does not yet publish those
reports to Codecov, so there is no hosted coverage history, no PR coverage view,
and no README coverage badge.

## Goal

Upload the existing LCOV report to Codecov from GitHub Actions using OIDC, and
add a README badge that reflects the default-branch coverage for the repository.

## Decisions

### Authentication

- Use `codecov/codecov-action@v5`.
- Authenticate with `use_oidc: true` instead of a `CODECOV_TOKEN` secret.
- Keep `id-token: write` in the workflow permissions, which is required for
  OIDC uploads.

### Workflow Integration

- Keep the current four CI checks visible:
  - `Format Check`
  - `Lint`
  - `Build`
  - `Test`
- Reuse the existing `coverage/lcov.info` produced by `zig build coverage`.
- Add a dedicated `Upload coverage to Codecov` step after the test run.
- Keep `fail_ci_if_error: true` so upload failures surface immediately once the
  repository is enabled in Codecov.

### Git History For Uploads

- Set the checkout step to `fetch-depth: 0`.
- This satisfies Codecov's GitHub Actions guidance for correctly identifying the
  commit SHA, especially for merge commits.

### README Badge

- Add a Codecov badge near the top of `README.md`.
- Point the image to the GitHub-provider badge URL for `minhuw/coquic` on
  branch `main`.
- Link the badge to the repository's page in the Codecov app.

## Operational Note

The first upload still requires the repository to be enabled in Codecov. Until
that is done, the new CI upload step may fail even though the local coverage
generation remains healthy.

## Verification

The completed change should be checked with:

```bash
nix develop -c zig build coverage
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix shell nixpkgs#actionlint -c actionlint .github/workflows/ci.yml
```

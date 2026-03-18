# README Header Refresh Design

## Status

Approved on 2026-03-18.

## Context

`README.md` should stay human-facing and minimal while still presenting the
project with a little more polish. The current README is functional, but its
header is sparse and no longer includes the Codecov badge that documents
coverage reporting in CI.

The refreshed README should focus the header on the QUIC implementation itself.
The existing QUIC RFC knowledge base and RAG setup notes still belong in the
README, but they should live under a `Development` section instead of sharing
the top of the page with the project pitch.

The repository also does not yet include a root `LICENSE` file. Adding the
standard MIT license enables a license badge in the header and clarifies reuse
terms for the project.

## Goal

Refresh the README header so it looks more intentional and informative while
keeping the document minimal:

- restore the Codecov badge;
- add a CI badge based on the existing GitHub Actions workflow;
- add an MIT license badge linked to a new root `LICENSE` file;
- replace the current one-line description with a more polished,
  implementation-focused project pitch; and
- move setup details into a `## Development` section.

## Non-Goals

- Expanding the README into full project documentation
- Describing the RFC knowledge base in the header pitch
- Changing build, test, or RAG commands
- Introducing additional vanity badges

## Decisions

### Header Structure

Use a standard Markdown header with:

1. the project title;
2. a compact badge row for `CI`, `Codecov`, and `MIT`; and
3. one polished sentence describing the repository as an experimental effort to
   build a full-featured QUIC implementation with Codex using GPT-5.4 and later
   models.

This keeps the top of the README attractive without making it feel heavy or
marketing-driven.

### Development Section

Keep all operational content under `## Development`. The section should start
with the reproducible development shell and common build/test commands, then
retain the QUIC RFC knowledge base quick-start block and the note about the
shared local Qdrant backend.

### License

Add a root `LICENSE` file containing the standard MIT license text, attributed
to `minhuw` for 2026. The README badge should link directly to `LICENSE`.

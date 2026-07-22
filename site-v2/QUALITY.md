# Cross-Cutting Quality Contract

## Accessibility

- Target WCAG 2.2 AA. Automated critical/serious violations MUST be zero on every
  primary route and representative state; automation does not replace manual review.
- Keyboard users MUST reach and operate every command, link, tab, disclosure,
  locally scrollable region, matrix cell, chart datum, and dialog.
- Focus MUST be visible, logically ordered, never trapped outside a modal, and
  restored after temporary surfaces close.
- Dynamic loading, completion, errors, result counts, and copy actions MUST be
  announced with appropriately polite or assertive live regions.
- Color MUST NOT be the only carrier of status. Forced-colors mode MUST retain
  state distinctions and focus.
- Reduced-motion preference MUST remove nonessential animation.
- Touch targets SHOULD be at least 44 by 44 CSS pixels on coarse pointers.
- Charts MUST have an equivalent semantic table or list.

## Responsive behavior

- Required widths: 320, 375, 414, 768, 1024, 1440, and 1920 CSS pixels, plus
  844x390 landscape.
- Required zoom probe: 200% browser text/page scaling at a 1280px viewport.
- The document MUST NOT horizontally overflow. Wide code, tables, matrices,
  graphs, traces, and packet data MAY scroll inside clearly named regions.
- Content and commands MUST remain reachable without hover.

## Resilience and state integrity

- Never equate absent, malformed, delayed, partial, empty, and numeric zero.
- Retain last valid evidence when a secondary request fails.
- Abort stale search/detail requests and ignore late responses after navigation.
- Retry MUST be idempotent from the user's perspective and MUST not duplicate
  listeners, streams, timers, or records.
- Client-only enhancements MUST have a deterministic loading/unavailable state.
- External payloads MUST be schema-validated before rendering.

## Security and privacy

- Render Markdown and transcript content through an allowlist; never execute
  embedded script or event-handler content.
- Validate dynamic slugs, task IDs, session IDs, filenames, artifact paths, and
  proxy paths against explicit allowlists or safe patterns.
- Dataset files are read-only and served with safe content disposition/type.
- The RAG proxy forwards only documented headers and has a bounded timeout.
- Steward publications are read-only and sanitized at the producer boundary.
- External links opened in a new context use appropriate opener isolation.
- Do not expose filesystem paths, credentials, private prompts, or raw internal
  Steward state beyond fields declared in the public schema.

The future raw Steward archive is a separate, deliberate disclosure channel. Its
metadata and every durable non-hidden artifact below the task root are public by
placement, while daemon credentials, auth homes, SQLite/WAL files, worktrees,
runtime caches, sockets, and other private global state are excluded by
placement. Raw prompts and transcripts are preserved byte-for-byte; the importer
does not sanitize, redact, scan, quarantine, or infer credential safety from
content. Safe relative paths reject absolute paths, `.`, `..`, backslashes, NUL,
hidden temporary components, symlinks, and non-regular files.

Archive consumers retain a last-valid JSON cache, import only complete JSONL
lines, detect replacement/truncation/prefix changes, and retry recoverable
eventual-consistency gaps. A watcher is paired with periodic reconciliation after
missed events or restart. Terminal manifest verification checks exact bytes and
marks later mutation as corruption. Raw downloads serve bytes without
normalization; incomplete live tails are never returned as parsed records.

## Performance budgets

- Server-render meaningful route identity and loading state without JavaScript.
- Route JavaScript SHOULD stay below 250 KiB compressed; exceptions for the
  Workbench WASM loader and large visualization libraries require measurement.
- Shared initial JavaScript SHOULD stay below 100 KiB compressed.
- Largest Contentful Paint SHOULD be under 2.5s and Interaction to Next Paint
  under 200ms at the 75th percentile on an agreed preview profile.
- Long tables/lists SHOULD paginate or virtualize without breaking findability,
  browser history, or accessibility.
- Images, frames, and charts MUST reserve stable dimensions to avoid layout shift.

## Compatibility and observability

- Support current stable Chromium, Firefox, and WebKit, with progressive
  enhancement for unsupported APIs.
- Every fetch failure SHOULD log resource, status/category, request correlation
  ID, and schema version without logging sensitive content.
- Visible provenance MUST include generation time and commit/run identity where
  the producer supplies it.
- Contract tests MUST cover happy, empty, partial, missing, malformed, delayed,
  keyboard, compact, dark, reduced-motion, and 200%-zoom states.

Raw archive contract tests MUST additionally cover live metadata-before-artifact
and artifact-before-metadata convergence, last-valid JSON retention, complete-
line JSONL parsing, append and duplicate replay, replacement and truncation,
missed-event periodic reconciliation, manifest-before-content delivery, exact
terminal sizes/hashes, unsafe path rejection, and post-verification mutation.
Freshness, import lag, terminal status, and archive verification remain separate
observable states.

Cross-task quality gates MUST prove that dashboard, history, aggregate usage and
revision requests perform SQLite-only reads. Detail and artifact gates MUST
prove containment to exactly one indexed task root, accepted-prefix cursor
binding, safe download headers, and no absolute path disclosure. Unit and
browser gates MUST cover the 50-row opaque cursor, missing-versus-zero coverage,
`Load more` transcript pagination, one refresh per revision, hidden-tab pause,
bounded retry backoff, and timer/listener cleanup.

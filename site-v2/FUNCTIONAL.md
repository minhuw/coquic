# Functional Contract

Every route MUST implement `loading`, `ready`, `empty`, `partial`, `unavailable`,
and `malformed` where those states are meaningful. State transitions MUST be
announced without replacing retained valid evidence with an error message.

## Home `/`

- Identify the product as experimental open-source QUIC and HTTP/3 work.
- Explain the relationship between implementation, evidence, tools, dataset,
  documentation, and repository automation without making maturity claims.
- Provide direct destinations to all areas in `PRODUCT.md`.
- Make Steward and current engineering evidence easy to discover.
- Lead with the latest complete UTC Steward daily summary: model tokens,
  requests, sessions, tool calls, commits, changed lines, resolved issues, and
  validation pass rate. Pair each daily value with its defined current horizon:
  trailing-window model activity, active sessions, today-to-date repository and
  issue activity, or running validations. Label both horizons and their UTC
  boundary, retain stale snapshots with a stale label, and distinguish genuine
  zero from unavailable data.
- Let users compare the previous complete day, seven complete days, thirty
  complete days, and all recorded history without changing the live companion
  values. The dashboard header exposes only the selected range's exact
  boundaries; source-specific coverage remains available in the growth
  publication and detailed evidence surface. Aggregate validation pass rate from
  passed/completed totals; count unique agent sessions within each period rather
  than summing daily counts.
- All destinations MUST work with keyboard activation and browser-native links.

## Documentation `/docs/**`

- Resolve pages from a catalog rather than arbitrary filesystem paths.
- Render headings, paragraphs, lists, links, images, tables, inline code, fenced
  code, block quotes, and authored HTML/MDX components allowed by policy.
- Rewrite relative Markdown document links to their V2 routes while preserving
  fragments, absolute URLs, and non-Markdown assets.
- Provide document navigation grouped by section, current-page indication, and
  previous/next access where applicable.
- On narrow viewports, document content MUST remain reachable before or without
  opening navigation. Closing navigation MUST restore trigger focus.
- Heading permalinks and copy-code actions MUST be keyboard accessible and
  provide success/failure announcements.
- Wide code and tables MUST scroll locally and retain semantic code/table roles.
- Unknown or unsafe slugs MUST return HTTP 404.

## Blog `/blog` and `/blog/[slug]`

- List all valid posts newest first. Each listing exposes date, reading time,
  author attribution, description, tags, and a stable article URL.
- Render Markdown and MDX with the same content safety and overflow behavior as
  documentation.
- Preserve internal article links and authored image alternative text.
- A bilingual article MUST default to English, expose English and Chinese as an
  accessible tab set, hide inactive content from assistive technology, and
  support arrow-key tab movement.
- Unknown or unsafe slugs MUST return HTTP 404.

## Specification QA `/qa`

- Accept a trimmed QUIC specification question. Empty submission MUST be rejected
  inline and associated with the input.
- Submit by an explicit command or `Ctrl+Enter`; disable duplicate submissions
  while a request is active; allow cancellation if the transport supports it.
- Fetch a random suggested question without submitting it automatically.
- Stream two independent channels: a direct model answer and a retrieval-grounded
  answer. Partial text MUST remain visible if the stream later fails.
- Final evidence includes models, token usage, retrieval confidence, citations,
  source title/section, similarity score, RFC URL, and expandable source excerpt.
- Render answer Markdown, code, and tables safely. Allow copying each completed or
  retained partial answer with an announcement.
- Persist a generated anonymous session ID locally and send it as `X-Session-ID`.
  The implementation MUST work when `crypto.randomUUID()` is unavailable.
- Expose a concise privacy statement explaining the submitted question and
  anonymous session identifier.
- Treat HTTP 429, offline transport, interrupted stream, out-of-scope,
  low-confidence retrieval, and generation failure as distinct recovery states.
- A retry repeats the last question without creating multiple concurrent streams.
- Narrow layouts MUST provide an accessible comparison control for both channels.

## Transcript Dataset `/transcript`

- Show manifest generation time, archive identity/size, transcript and message
  totals, token/tool-call totals, source attribution, and available date range.
- Search title, working directory, filename, public session ID, source, model,
  and preview text. Debounce text input and cancel stale requests.
- Filter by inclusive calendar date range and paginate server-side, 25 sessions
  per page by default.
- Own URL parameters `q`, `from`, `to`, `page`, and `session`. Preserve unrelated
  parameters. Filter replacement MUST not create one history entry per keystroke;
  deliberate pagination and selection MUST support browser back/forward.
- List sessions newest first with stable tie-breaking and expose title, start
  time, working directory, size, messages, tools, tokens, source, and model.
- Selecting a session loads records in original line order. Long sessions MUST
  support cursor-based continuation without duplicating or reordering records.
- Preserve list scroll position when entering and leaving detail on compact
  layouts. A missing deep-linked session MUST be factual and removable.
- Render message roles, event records, tool calls, timestamps, truncation state,
  and code/JSON/text payloads without executing transcript content.
- Provide raw session JSONL download. Provide session/archive ZIP actions only
  when published and the complete dataset download when available.
- Distinguish zero matches, unavailable database, failed session read, missing
  session, scan limit, and unavailable archive.

## Protocol Workbench `/workbench`

- Run a deterministic client/server QUIC simulation in the browser using the
  project WASM engine. If WASM cannot load, controls remain visible but commands
  that require execution are disabled and the failure is explicit.
- Provide a validated scenario catalog. Initial IDs: `handshake`,
  `handshakeloss`, `transfer`, `keyupdate`, `transferloss`,
  `handshakecorruption`, `transfercorruption`, `blackhole`, `chacha20`,
  `longrtt`, `multiplexing`, `retry`, `resumption`, `zerortt`, `v2`, and
  `connectionmigration`.
- Configure loss ratio (0-0.4), bandwidth (500,000-100,000,000 bits/s), and
  one-way delay (50-2500 ms). Display values may be scaled but canonical state
  uses these units.
- Support start, pause, resume, and exactly one protocol action per step command.
- Expose elapsed simulated time, module state, endpoint state, connection,
  wakeup, QUIC version, sent/received packets and bytes, events, and active streams.
- Visualize both packet directions and preserve packet ordering.
- Expose client/server packet spaces, flow/stream limits, streams, trace log, and
  captured packet list.
- Packet detail includes direction, time, packet/header type, packet number,
  protected payload, decoded frames when available, and raw bytes.
- Provide a valid PCAP download of captured traffic.
- Compact layouts MUST make Client, Server, Trace, and Packets independently
  reachable without losing simulation state.

## Performance `/performance`

- Load current snapshot and retained history independently. Current rankings MAY
  become ready while history is still loading or unavailable.
- Modes: bulk throughput, stream request/response, persistent request/response,
  and connection request/response.
- Rank every successful result matching the selected mode and filters. "All"
  MUST mean every matching result. Any featured subset requires a separate,
  explicit user-controlled mode and a visible explanation.
- Filter by language and vendor; display active filter count and allow reset.
- Identify snapshot generation time, event, commit, environment, source
  availability, and completeness.
- Each result exposes implementation/version, congestion control when relevant,
  primary metric, duration, latency percentiles, client/server CPU and memory,
  and artifact availability.
- Retained history supports implementation comparison, keyboard-accessible data
  points, exact values, and a complete semantic data table. Any visual series
  reduction MUST NOT reduce the table and MUST be visibly disclosed.
- Detail inspection and flamegraph inspection use dismissible dialogs that
  restore focus. Raw profile logs and SVG artifacts remain directly accessible.
- Missing or malformed current data MUST not render fallback implementations.
  Missing history MUST not remove a valid current ranking.

## Interop `/interop`

- Show snapshot provenance and aggregate counts for `pass`, `unsupported`,
  `peer_failure`, `known_peer_issue`, `fail`, and `not_reported`.
- Include only lanes where CoQUIC is client or server. Preserve direction and
  published testcase order.
- Present every lane/testcase result in a semantic matrix with sticky context or
  an equally usable compact alternative. Large matrices scroll locally.
- Each cell exposes participant roles, testcase, normalized result, raw producer
  result, details, and known-peer evidence where available.
- Cell detail works by focus, click/tap, and hover where hover exists. Escape or
  outside dismissal closes it and focus returns to the cell.
- The aggregate conclusion MUST distinguish CoQUIC failures from acceptable or
  annotated peer limitations. Unavailable data permits no success conclusion.

## Coverage `/coverage`

- Show snapshot provenance and exact covered/total counts for functions, lines,
  and branches. Percentages are derived, never canonical input.
- Show component metrics and least-covered files in producer order.
- Long source paths wrap or scroll locally without widening the page.
- Provide the generated LLVM HTML report and canonical JSON download.
- Distinguish loading, valid populated, valid empty, valid zero, unavailable, and
  malformed states. A retry performs a new no-cache request.

## Duvet `/duvet`

- Explain that Duvet maps extracted RFC requirements to source/test annotations.
- Probe and embed the same-origin generated HTML report without allowing embedded
  width to create parent-page overflow.
- Provide direct HTML, JSON, and plain-text snapshot downloads at stable URLs.
- States: probing, ready, delayed after 15 seconds, unavailable, and frame error.
  A late frame load after delayed state transitions to ready.
- Retry creates one new attempt, clears the prior timer, and retains download
  actions even when embedding fails.

## Steward `/steward`

- This surface is a read-only sanitized publication; it MUST NOT expose mutation
  controls or secrets.
- Lead with the public control loop `Signals → Planning → Tasks → Integration`.
  The control loop is an instrument and navigation device, not an aggregate
  health score.
- Views are exactly Signals, Planning, and Tasks. Tasks is the default because
  execution evidence is the primary public value.
- At wide desktop widths, Tasks uses parallel queue, selected execution, and
  current-evidence panes; Signals uses provider, pending, and scheduled panes;
  Planning uses wakeup, selected-run, and diagnostics panes. These panes return
  to source order as one readable column on compact screens.
- Signals separate pending evidence from scheduled evidence. Every signal keeps
  source/provider, severity, timestamps, external links, contextual facts, and
  related planner/task IDs. Provider fetch errors, due state, and truncation are
  explicit.
- Planning shows pending wakeups and planner runs with input signals, parsed
  task proposals, accepted results, diagnostics, transcript completeness, and
  links to resulting tasks. Mismatches between output proposals and canonical
  counters are shown as incomplete producer state.
- Tasks separate active, queued, attention, and retained counts. Every row shows
  the five-stage pipeline and links to detail only when detail is published.
- Archive inventory and aggregate outcomes may remain supporting evidence, but
  they do not displace the three control-loop domains.
- Daemon and operator configuration MUST NOT be published or rendered.
- Stale, incompatible, missing, and malformed publications are distinct.

## Steward planning `/steward?view=planning`

- Show retained planner runs newest first with an explicit published-window
  count and truncation state.
- Expose run ID, status, start/completion, accepted/proposed counts, consumed
  signal IDs, output proposals, diagnostics, transcript, and final-message
  artifact.
- Declare whether the published window is complete or truncated.
- Distinguish loading, empty, unavailable, running, succeeded, failed, and invalid.

## Steward task `/steward/tasks/[taskId]`

- Validate task IDs before reading public artifacts; invalid/unknown IDs return 404.
- Show title, state, current conclusion, source, priority/risk, creation/update,
  structured implementation plan, attempts, ordered pipeline, and event timeline.
- Show implementation-planning runs before attempts, including retry order,
  status, duration, model settings, exit state, transcript completeness, model
  usage and cadence when available, and the accepted structured plan result.
- Pipeline stages: Plan, Implementation, Validation, Review, and Integration,
  including feedback loops and a text equivalent.
- Each attempt is selectable and exposes shareable Transcript, Patch,
  Validation, and Review URL views with native keyboard navigation.
- At wide desktop widths, implementation plan, selected attempt evidence, and
  ordered timeline remain visible as three parallel panes. Compact screens keep
  the same evidence in plan, attempt, timeline order.
- Transcript records distinguish task/user messages, agent messages, reasoning,
  tool or command calls, outputs, exit codes, and truncation.
- Validation exposes exact commands, result, exit code, duration, summary, and
  log artifact state. Review exposes verdict, structured findings, validation
  gaps, required changes, and remaining risk.
- Patch supports unified and side-by-side diff; large code/timelines scroll
  locally; closing expanded diff restores focus.
- Artifact states distinguish available, not produced, unavailable, redacted,
  and truncated.

## Raw Steward archive (independent from `/steward`)

- Preserve the sanitized `/steward` channel and its disclosure boundary. The raw
  archive is an explicitly separate research surface and is never silently
  substituted for sanitized task detail.
- Task lists and detail show exact running or terminal execution status beside a
  distinct archive verification state. A terminal task status is not presented
  as a verified archive until every terminal manifest descriptor exists and its
  byte size and SHA-256 match.
- Detail groups evidence by ordered pipeline, then shows each run's role,
  session, interrupted/resumed relationship, retry/parent relationship, raw and
  effective review, validation output, patches, integration evidence, and
  artifact availability. Open role strings remain visible rather than being
  collapsed into a fixed role list.
- Usage and cost cards distinguish available, partial, and unavailable values;
  they show reasons and pricing/model provenance and never render unavailable
  evidence as zero.
- Freshness shows last successful sync/import time, watcher versus periodic
  reconciliation state, accepted JSONL prefix, retry category, and recoverable
  import lag. It distinguishes a manifest observed from an archive verified.
- Newly imported real Codex and observation records MAY appear progressively in
  source order. A minute-sized watcher batch MAY be paced visually, but the UI
  MUST NOT fabricate records, role output, completion, token usage, cost, or
  realtime transport claims. Incomplete live tails are not rendered as parsed
  records.
- Raw artifact download returns synchronized bytes without normalization. Safe
  task, pipeline, run, and artifact paths are validated before lookup. Aggregate
  requests use SQLite only and never scan multiple raw task directories; one
  detail request may read the selected indexed task root.
- The in-process importer starts once from `instrumentation.ts`, returns without
  awaiting a scan, watches as a latency hint, and reconciles every 60 seconds.
  It exposes `indexing`, `ready`, `degraded`, `unavailable`, `incompatible`, and
  `archive-corrupt` states with no path or exception leakage.
- Task history is newest-first with an opaque stable cursor and 50 rows per
  page. Active work has an independent bounded opaque cursor so every indexed
  active task remains reachable without displacing terminal history. Transcript
  chunks start at a complete-line cursor and explicit `Load
  more` controls continue until every accepted record is visible; a changed
  prefix returns a stale-cursor response.
- Every transcript-bearing run owned by a pipeline has an accessible selector;
  the validated pipeline/run selection is shareable through URL state.
- Signals and Planning remain visible route choices but production renders an
  explicit not-connected state; no checked-in fixture records are used there.

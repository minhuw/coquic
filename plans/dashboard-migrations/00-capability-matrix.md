# 00 - Steward Dashboard Capability Matrix

Status: Complete
Inventory date: 2026-07-13
Scope: current repository state before the dashboard migration

This is the baseline for subplans 01, 08, 10, and 11. It records the local
FastAPI and Next.js surfaces, the CLI control surface, the current public
mirror contract, and the site views that consume that contract. It does not
authorize a site control channel: the target site remains read-only.

## Disposition vocabulary

- `retain on site`: publish a sanitized read view and implement the equivalent
  site view. Any control associated with that read view remains a CLI concern.
- `retain in CLI`: keep the operator action or local diagnostic in the CLI.
  The public site may show its resulting state, but it must not invoke it.
- `remove`: delete the local web/API capability after its required successor
  is available. A replacement is recorded in the notes and owner column.

When a current feature has separate read and control halves, the matrix has
separate rows so each half has one unambiguous disposition.

## Source anchors

The inventory was read from these implementation and test surfaces:

| Surface | Primary sources |
| --- | --- |
| Local UI | `steward/web-ui/app/page.tsx`, `api.ts`, `task-detail.tsx`, `timeline.tsx`, `transcript.tsx`, `types.ts`, `layout.tsx` |
| FastAPI | `steward/src/coquic_steward/web/app.py`, `web/runtime.py` |
| CLI | `steward/src/coquic_steward/cli.py` |
| Public producer | `steward/src/coquic_steward/public_mirror.py`, `orchestration/daemon.py` |
| Internal data | `core/models.py`, `core/config.py`, `storage/schema.py`, `storage/mappers.py`, `storage/sqlite.py` |
| Public site | `site/next/app/steward/page.tsx`, `site/next/app/steward/tasks/[taskId]/page.tsx`, `site/next/src/components/steward-public.tsx`, `site/next/app/steward/data/tasks/**/route.ts` |
| Tests | `steward/tests/test_clean_steward.py`, `steward/tests/test_workflows.py` |

Line references below are source anchors at inventory time; the completeness
checks at the end are the authoritative search-based verification.

## FastAPI route matrix

All `/api/*` routes and the `/` redirect call `_require_loopback` and are
therefore local-only. `/healthz` is intentionally unauthenticated and returns
only `ok`. The routes are registered in `create_app()` in
`steward/src/coquic_steward/web/app.py:48-65`.

| Method and route | Current capability, data, limits, and boundary | Disposition | Owner subplans |
| --- | --- | --- | --- |
| `GET /api/state` | Full local snapshot from `_state_payload`: up to 200 tasks, 200 signal items, and 80 fetch runs; includes raw task specs, local config paths, scheduler state, integration data, audit findings, and signal inbox. | `remove` | 01, 08, 09, 17 |
| `GET /api/stream` | Loopback Server-Sent Events stream. Rebuilds the full state payload, compares sorted JSON, and polls the store every 1 second (`STREAM_POLL_SECONDS`). | `remove` | 04, 06, 17 |
| `POST /api/actions/tick` | Loopback scheduler wakeup. Body fields `plan`, `dispatch`, and positive `max_dispatch` are stored as `scheduler.manual`; response returns the wakeup and scheduler state, not the full state. | `remove` | 10, 12, 17 |
| `POST /api/actions/fetch-signals` | Loopback signal-fetch wakeup. Providers default to every enabled provider; a non-list or unknown provider is HTTP 400. | `remove` | 12, 17 |
| `POST /api/tasks` | Loopback task creation from title, prompt, kind, optional workflow, and worker. Requires non-empty title and prompt; source is `web`; dedupe uses the first 80 prompt characters. | `remove` | 12, 17; CLI successor documented by 12 |
| `POST /api/tasks/{task_id}/run` | Loopback synchronous direct execution under the daemon lock; returns 409 when the daemon owns the lock and returns the updated task. | `remove` | 11, 16, 17; CLI successor is `run` |
| `GET /api/tasks/{task_id}` | Loopback task detail: task record, all stored events, path-valued files, derived attempt stack, plan runs, and remote commit. Missing task is 404. | `remove` | 01, 08, 09, 17 |
| `GET /api/integrations/{integration_id}` | Loopback integration detail: integration run, source task, all integration/source events, validations, remote commit, commit-message artifact, and push log. Only integration tasks are accepted. | `remove` | 08, 09, 17 |
| `GET /api/tasks/{task_id}/files/{name}` | Loopback text tail for `transcript`, `integration-transcript`, `patch`, `last-message`, or latest `review-transcript`; state-root containment is checked; line-aligned tail is capped at 256 KiB. | `remove` | 08, 09, 17 |
| `GET /api/tasks/{task_id}/iterations/{iteration}/patch` | Loopback iteration patch text, state-root checked and line-aligned to a 256 KiB tail. | `remove` | 08, 09, 17 |
| `GET /api/tasks/{task_id}/runs/{run_name}/transcript` | Loopback run transcript. Run names must match known worker/reviewer forms. Default is a 256 KiB line-aligned tail; `?window=1` returns a bounded 256 KiB window with offsets; `?full=1` reads the complete file with no explicit byte cap. | `remove` | 08, 09, 17 |
| `GET /api/tasks/{task_id}/validations/{index}` | Loopback validation output tail, limited to 256 KiB and contained under `logs_dir`. | `remove` | 08, 09, 17 |
| `GET /api/tasks/{task_id}/assets?path=...` | Loopback image-only `FileResponse`. Relative paths are rooted in the task worktree; absolute paths may resolve under the state directory or worktree; traversal and non-image files are rejected. No explicit byte cap. | `remove` | 08, 09, 17 |
| `GET /healthz` | Plain-text process liveness response `ok`; no loopback check and no state detail. | `remove` | 16, 17 |
| `GET /api/runtime` | Loopback compatibility probe containing API name, absolute `state_dir`, and feature markers `line-tail`, `signal-inbox`, `signal-items-v2`, and `scheduler-v1`. | `remove` | 02, 16, 17 |
| `GET /api/planner/runs` | Loopback standalone planner-run index from prompt/transcript files. Default `limit=40`, clamped to 1..200; `offset` is clamped to 0..10,000. Index exposes run IDs, local paths, byte sizes, timestamps, and diagnostics but not prompt/transcript text. | `remove` | 01, 07, 09, 17 |
| `GET /api/planner/runs/{run_id}` | Loopback lazy planner artifact. IDs must match `planner-task-<14 digits>-<8 hex>`; prompt and transcript are tail-read at 256 KiB and diagnostics omit no local prompt content. | `remove` | 07, 09, 17 |
| `GET /` | Loopback 307 redirect to `http://127.0.0.1:3000`, coupling the API to the local Next.js UI. | `remove` | 16, 17, 18 |

### FastAPI security notes

- `_require_loopback` accepts `127.0.0.1`, `::1`, `localhost`, and the
  Starlette `testclient` host. It is not an authentication mechanism.
- File routes resolve paths and check containment in `state_dir`, `logs_dir`,
  or the task worktree. The image route additionally checks MIME type.
- The local API intentionally exposes raw prompts, raw paths, raw event data,
  and raw transcripts to the loopback caller. Those values are not eligible
  for direct public publication.
- The full-transcript flag is currently uncapped. This is a local diagnostic
  behavior, not a public artifact contract.

## Local UI navigation and capability matrix

The local dashboard navigation is `ViewKey` in
`steward/web-ui/app/page.tsx:59` and `SectionNav` at lines 404-436. The
task-detail page is linked from task rows but is a separate route.

| Local section or view | Current capability and local data path | Disposition | Owner subplans |
| --- | --- | --- | --- |
| Global shell and project selector | Sidebar shows `CoQUIC Steward`, one active project from `state.projects`, task/signal counts, stream status, project info, refresh, and create-task buttons. The only current project is active; other project buttons are disabled. | `remove` | 08, 18 |
| `Control Loop` navigation section | Default view. Shows active/queued/terminal/integration metrics, scheduler lanes, provider schedule, pending/recent wakeups, and standalone planner iterations. | `retain on site` | 01, 06, 07, 08, 14 |
| Control-loop `Wake` action | Posts `/api/actions/tick` with planning and dispatch enabled, then refreshes local state. | `retain in CLI` | 10, 12, 17 |
| Control-loop `Fetch All` and provider fetch actions | Posts `/api/actions/fetch-signals`; provider rows can request one provider, while the scheduler can request all enabled providers. | `retain in CLI` | 12, 17 |
| `Tasks` navigation section | Task graph and task queue table for non-integration tasks; lanes are queued, in progress, needs attention, and completed. Task list pagination is 10 items per page. | `retain on site` | 01, 05, 08, 14 |
| Task row and task graph links | Shows status, kind, priority, risk, agent/source, timestamps, and safe-looking GitHub commit links; links to `/tasks/{taskId}`. | `retain on site` | 08, 09, 14 |
| `Integration` navigation section | Metrics for mode, queued patches, active sessions, and pushed commits; recent integration runs and pushed commits with 10-item pagination. | `retain on site` | 01, 05, 08, 14 |
| Integration run detail | Lazy no-store fetch of integration detail plus transcript and patch. Tabs are `Patch`, `Validation`, `Commit`, and `Push`; also shows commit-message transcript, push log, filtered transcript, validations, and timeline. Integration events are limited to the last 12 in the summary and fetched in full for detail. | `retain on site` | 08, 09, 14 |
| `Signals` navigation section | Metrics, provider schedule, pending signals, consumed signals, fetch history, 10-item pagination for signal lists, 16 displayed fetch records, and a signal-detail modal. | `retain on site` | 01, 05, 08, 09, 14 |
| Signal detail modal | Shows provider, kind, severity, location, fingerprint, source fetch, planner ID, related tasks, and the complete local signal payload as JSON. | `retain on site` | 08, 09, 14 |
| `Configuration` navigation section | Shows Codex executable and availability, model/reasoning/profile/sandbox, repository/branch/remote/integration mode, all local state paths, scheduler limits, and provider cadence. | `remove` | 08, 09, 18, 19 |
| Create-task modal | Form for title, kind, worker, and prompt; enqueues through `POST /api/tasks` and refreshes the dashboard. | `retain in CLI` | 12, 17, 18 |
| `/tasks/[taskId]` task-detail view | Overview, status, task facts, optional `Run Task`, current-iteration pipeline, feature implementation-plan runs, attempt stack, timeline, refresh, and local SSE-driven reload. | `retain on site` | 01, 05, 08, 11, 14 |
| Task-detail implementation plan | Feature tasks show plan run number/name, model, reasoning effort, structured plan JSON, planner transcript, diagnostics, and earlier-transcript loading. | `retain on site` | 01, 05, 07, 08 |
| Task-detail attempt tabs | For each worker iteration: `Transcript`, `Patch`, `Validation`, and `Review`; includes worker/reviewer diagnostics, transcript windows, diff view, validation logs, review findings, validation gaps, remaining risk, and loop counts. | `retain on site` | 01, 05, 08, 09, 14 |
| Local task-detail `Run Task` action | Available for queued tasks and posts `/api/tasks/{task_id}/run`; direct execution is synchronous and lock-aware. | `retain in CLI` | 11, 12, 17, 18 |
| Local planner pagination/lazy transcript | Planner list uses page size 10, server page limit/offset, and loads the first/open planner artifact only when expanded. | `retain on site` | 01, 07, 08, 14 |
| Local refresh/error behavior | Initial `/api/state` fetch uses `cache: "no-store"`; `EventSource("/api/stream")` is the normal update path, with a manual refresh/retry path and reconnect state. | `remove` | 04, 06, 17, 18 |

The local `Configuration` view is deliberately not copied field-for-field:
paths, executable resolution, and execution settings remain local operator
information. The site successor is a sanitized configuration summary from the
public mirror, while the complete configuration remains available through the
CLI/config file.

## CLI command matrix

The Typer root and nested `enqueue` group are defined in
`steward/src/coquic_steward/cli.py:37-40`. The command list below includes all
root commands and all nested commands currently registered in that file.

| Command | Current behavior, limits, and control boundary | Disposition | Owner subplans |
| --- | --- | --- | --- |
| `coquic-steward agents` | Lists every catalog worker, read-only/write-capable mode, skills, and purpose. | `retain in CLI` | 12 |
| `coquic-steward status [--limit]` | Lists task ID, status, workflow, kind, and title. Default display limit is 20; the integer is passed to storage without a command-level maximum. | `retain in CLI` | 12 |
| `coquic-steward run TASK_ID` | Directly executes one task and reports `ran`/`failed`; exits nonzero for non-blocked failure. Must use the daemon lock after subplan 11. | `retain in CLI` | 11, 12 |
| `coquic-steward daemon` | Runs the scheduler forever or one tick. Current options are `--once`, `--web/--no-web` (default web enabled), `--no-plan`, `--no-dispatch`, and `--max-dispatch`; daemon lock and preflight apply. | `retain in CLI` | 02, 03, 10, 11, 12, 16 |
| `coquic-steward plan [--enqueue]` | Fetches/persists signals, revalidates pending items, runs the planner, optionally enqueues planned tasks, and marks consumed items. | `retain in CLI` | 07, 12, 16 |
| `coquic-steward timeline TASK_ID [--limit]` | Prints stored event timestamps, kinds, and messages. Default limit is 100; event messages can contain local/private data and are for local operators only. | `retain in CLI` | 08, 12 |
| `coquic-steward fetch-signals [--provider/-p]` | Requests a scheduler signal-fetch wakeup. Repeated providers are deduplicated; omitted providers means all enabled providers; unknown providers are rejected. | `retain in CLI` | 12, 16 |
| `coquic-steward publish-public-state [--publish] [--output/-o]` | Writes the public mirror, or force-publishes it over configured SSH/rsync. An explicit output path can redirect the local snapshot. | `retain in CLI` | 03, 09, 12, 16 |
| `coquic-steward audit-invariants` | Prints `ok` or every storage invariant finding and exits nonzero when findings exist. | `retain in CLI` | 08, 12 |
| `coquic-steward web [--host] [--port]` | Starts Uvicorn/FastAPI directly; defaults to `127.0.0.1:8765`. | `remove` | 17, 19 |
| `coquic-steward enqueue` group | Typer namespace for manual task creation commands. | `retain in CLI` | 12 |
| `coquic-steward enqueue code-quality` | Enqueues the fixed CodeQL/Codacy maintenance task with the code-quality janitor, high priority, and medium risk. | `retain in CLI` | 12 |
| `coquic-steward enqueue interop RUN_ID` | Enqueues an interop doctor task for the GitHub Actions run ID, high priority, and high risk. | `retain in CLI` | 12 |
| `coquic-steward enqueue custom TITLE [--prompt-file/--prompt] [--kind] [--worker] [--workflow]` | Enqueues a custom/manual task. Requires at least one prompt source; `--prompt-file` takes precedence when both are supplied. Derives worker/workflow defaults. | `retain in CLI` | 12 |

`StewardWebRuntime` is not a user command by itself, but is an implementation
dependency of the current `daemon` default path. It starts Uvicorn on port
8765 and the local Next dev server on port 3000, checks loopback/runtime
compatibility, clears `.next`, and stops both child processes. It is removed
with the local web runtime by subplans 16, 17, 18, and 19; the daemon remains
headless and outbound-only.

## Public site view matrix

The current public entry points are `/steward` and
`/steward/tasks/[taskId]`. They are read-only and use the types and loaders in
`site/next/src/components/steward-public.tsx`.

| Site view/component | Current capability and source fields | Disposition | Owner subplans |
| --- | --- | --- | --- |
| `StewardSnapshotCardLive` / `StewardSnapshotCard` | Reusable summary card with public state badge, active/queued/pending/completed counts, current task title/kind/worker, relative snapshot age, and link to `/steward`. The live wrapper is currently not imported by a site page. | `retain on site` | 06, 08, 14 |
| `/steward` shell | `DemoNav`, public mirror brand/repository/branch, relative `generated_at`, pending count, and three tab sections. Null state currently renders a first-snapshot unavailable card. | `retain on site` | 04, 05, 06, 14 |
| `/steward` State tab | Scheduler source/integration lanes, pending/recent wakeup counts, integration commit list or integration task fallback, statuses, commit links, and relative update times. | `retain on site` | 01, 05, 08, 14 |
| `/steward` Tasks tab | Non-integration task graph with four lanes and task table with status, kind, priority, risk, update time, remote commit, 10-item pagination, and links to task detail. | `retain on site` | 01, 05, 08, 14 |
| `/steward` Signals tab | Provider tabs, poll cadence/health, provider status, up to 12 signal items for the selected provider, and up to 8 recent fetches. It is read-only and has no fetch button. | `retain on site` | 01, 05, 08, 09, 14 |
| `/steward/tasks/[taskId]` shell | Lowercase task-ID validation, back link, public snapshot age, missing/unavailable detail state, and 30-second detail refresh. | `retain on site` | 04, 05, 06, 14 |
| Public task Overview | Task title/status/summary, ID, kind, workflow, worker, updated time, attempt/validation counts, and safe remote commit link. | `retain on site` | 01, 05, 08, 14 |
| Public task Current Iteration graph | Read-only Plan/Code Generation/Validation/Review/Integration pipeline with active, complete, pending, blocked states and feedback loop counts derived from public events. | `retain on site` | 01, 05, 08, 14 |
| Public task Implementation Plan | Feature workflow plan runs with model, reasoning, completion status, structured plan JSON, and planner transcript/last-message artifact. | `retain on site` | 01, 05, 07, 08, 14 |
| Public task Attempt stack | Newest-first attempt cards. Tabs are `Transcript`, `Patch`, `Validation`, and `Review`; renders bounded artifact text, validation status/log, reviewer transcript, structured review, findings, gaps, and risk. | `retain on site` | 01, 05, 08, 09, 14 |
| Public task Timeline | Reversed public event list with sanitized messages, primitive chips, bounded path fields, status/review/integration rendering, findings, validation gaps, and remaining risk. | `retain on site` | 01, 05, 08, 09, 14 |
| `StewardFreshness` | Exported freshness indicator marks a snapshot stale after 15 minutes. It is not currently mounted by the Steward pages. | `retain on site` | 02, 04, 06, 14 |
| `StewardUnavailableNotice` | Exported unavailable notice says the daemon will publish after its next state change. It is not currently mounted by the Steward pages; the dashboard has a separate null-state message. | `retain on site` | 02, 04, 06, 14 |
| Standalone Planner view | No public standalone planner tab or route exists. Planner runs are currently visible only inside feature task detail; local `/api/planner/runs` is not mirrored. | `retain on site` | 01, 05, 07, 08, 14 |
| Public Integration detail view | The public type carries integration runs, commit-message artifacts, and push logs, but the public task component does not render a dedicated Integration tab or the full local integration run view. | `retain on site` | 01, 05, 08, 09, 14 |
| Public audit/configuration views | `audit` and sanitized `configuration` are present in the snapshot type/producer, but the current site tabs do not render either collection in a dedicated view. | `retain on site` | 01, 05, 08, 09, 14 |

No public row has a create, run, tick, fetch, publish, or audit button. Those
actions stay in the CLI.

## Published status fields

The current producer is schema version 2, not the schema version 3 proposed by
subplan 01. The status payload is built by
`steward/src/coquic_steward/public_mirror.py:75-115`; task details use version 2
at lines 205-266. Field groups below are exhaustive for the current producer,
with fields grouped only where the enclosing object is explicit in code.

| Published class/object | Current fields and behavior | Boundary, limit, or unsupported field | Disposition | Owner subplans |
| --- | --- | --- | --- | --- |
| Status envelope | `schema_version`, `generated_at`, `repository`, `main_branch`, `state`, `counts`, `audit`, `configuration`, `tasks`, `signals`, `scheduler`, `integration`. | `schema_version=2`; `generated_at` is producer time but is removed from the digest, so it does not independently trigger publication. No runtime heartbeat, daemon instance, or publication-health object exists. | `retain on site` | 01, 02, 03, 05, 06, 09, 13, 14 |
| Status `state` | One of `working`, `queued`, `attention`, or `idle`, derived from task statuses. | It describes task state only; an idle/stopped daemon is indistinguishable without a newer heartbeat. | `retain on site` | 01, 02, 06 |
| Status `counts` | `tasks`, `active`, `queued`, `attention`, `completed`, `signals`, `pending_signals`. | Counts use the producer task/signal windows, not necessarily total SQLite history. | `retain on site` | 01, 05, 08 |
| Status `audit` | Array of invariant findings passed through public text normalization. | No finding-specific structure; raw local paths are normalized. Site currently does not render it. | `retain on site` | 01, 08, 09 |
| Status `configuration` | `repository`, `main_branch`, `integration_mode`, `local_only`, `enabled_signals`, `scheduler_wait_interval_sec`; `limits`; `signal_providers`. | Deliberately excludes Codex executable/model/profile/sandbox, all local paths, SSH user/host/key/known-hosts, and publisher credentials. | `retain on site` | 01, 05, 08, 09 |
| Configuration `limits` | `max_active_tasks`, `max_main_pushes_per_day`, `plan_timeout_minutes`, `worker_timeout_minutes`, `review_timeout_minutes`, `validation_timeout_minutes`, `stale_task_minutes`. | Values are configuration, not enforcement metadata for each published task. | `retain on site` | 01, 05, 08 |
| Configuration provider entry | Per provider: `poll_interval_minutes`, `error_retry_minutes`, `idle_poll_interval_minutes`, `suppression_hours`, `max_items`. | Provider names are enabled signal names. Current defaults are listed in the limits section. | `retain on site` | 01, 05, 08 |
| Task summary | `id`, `title`, `kind`, `workflow`, `worker`, `priority`, `risk`, `status`, `summary`, `source`, `created_at`, `updated_at`, and `validations`. Each summary includes only the last five validations, each with `passed`, `exit_code`, `summary`, `iteration`, `started_at`, and `completed_at`. | Title/summary/validation summary pass `_public_text`; no prompt, path, metadata, branch, or artifact content. | `retain on site` | 01, 05, 08, 09 |
| Task summary links | `detail_url` and `detail_json`. | URLs are generated from task IDs; they are read links only. | `retain on site` | 01, 04, 05, 08 |
| Signal item | `id`, `provider`, `kind`, `title`, `summary`, `severity`, `status`, `created_at`, `updated_at`, `planned_at`, `planned_task_id`, and `links`. | Signal `location`, `payload`, `fingerprint`, `planner_run_id`, and `source_fetch_id` are unsupported in the public item even though the local model has them. Links are retained only when their URL starts with `https://github.com/`. | `retain on site` | 01, 05, 08, 09 |
| Signal fetch | `id`, `provider`, `status`, `started_at`, `completed_at`, `item_count`, `new_item_count`, `has_more`, `summary`, and `error`. | Provider errors collapse to `request timed out` or `provider error`; raw exception text is not published. Current fetch window is 40. | `retain on site` | 01, 03, 05, 08, 09 |
| Scheduler envelope | `source_active`, `source_capacity`, `source_queued`, `integration_active`, `integration_queued`, `pending_wakeups`, `recent_wakeups`, and `providers`. | Pending/recent wakeups are storage views capped at 20 each. | `retain on site` | 01, 05, 08 |
| Scheduler wakeup | `id`, `reason`, `status`, `created_at`, `consumed_at`, and sanitized `data`. | Wakeup data recursively removes private-looking keys and caps lists at 20; it is observational, not a public control API. | `retain on site` | 01, 05, 08, 09 |
| Scheduler provider state | Model fields `provider`, `poll_interval_minutes`, `error_retry_minutes`, `idle_poll_interval_minutes`, `suppression_hours`, `max_items`, `last_fetch_at`, `last_status`, `last_error`, `next_due_at`, `idle_next_due_at`, `due`, and `idle_due`. | `last_error` is collapsed to a category. Due timestamps are removed from the digest to avoid repeatedly publishing time-only changes; no publisher health is present. | `retain on site` | 01, 02, 03, 05, 06, 09 |
| Integration summary | `active` and `queue` contain task summaries; `commits` contains `task_id`, `title`, `status`, `summary`, `commit`, `commit_url`, and `updated_at`. | Commit list is capped at 20. Commit URLs are constructed for the configured GitHub repository from a validated hex SHA. | `retain on site` | 01, 05, 08, 09 |

## Published task-detail fields

| Published class/object | Current fields and artifact classes | Boundary, limit, or unsupported field | Disposition | Owner subplans |
| --- | --- | --- | --- | --- |
| Task-detail envelope | `schema_version`, `generated_at`, `repository`, `main_branch`, `task`, `source_task`, `events`, `source_events`, `attempts`, `plan_runs`, `validations`, `artifacts`, `integration`, and `remote`. | `schema_version=2`; source events are limited by kind to `integration.*` and `main.pushed`. | `retain on site` | 01, 05, 08, 09, 14 |
| Task-detail task record | Task summary fields plus `branch_name`, `spec`, `has_patch`, `has_transcript`, and `has_last_message`. | Paths are not emitted. `branch_name` and all text are normalized. | `retain on site` | 01, 05, 08, 09 |
| Task-detail `spec` | `id`, `kind`, `workflow`, `worker`, `title`, `prompt`, `priority`, `risk`, `source`, `allow_main_write`, and filtered `metadata`. | `prompt` is empty unless `transcript_mode="raw"`. Metadata is restricted to `source_task_id`, `main_commit`, `selected_signal_item_ids`, `evidence`, `workflow_file`, `workflow_name`, `run_id`, and `dedupe_key`, then recursively filtered. | `retain on site` | 01, 05, 08, 09 |
| Event | `task_id`, `kind`, `message`, `created_at`, and recursive `data`. | Event messages and data pass public text/key filtering. Current detail event lists are not explicitly capped, so large histories remain a contract risk. | `retain on site` | 01, 05, 08, 09, 13 |
| Attempt | `attempt`, `label`, `started_at`, `updated_at`, `worker`, `reviewer`, `review`, `patch`, and `validations`. Legacy records produce an initial attempt; iteration records are first-class. | Worker/reviewer prompt paths, transcript paths, thread IDs, and local paths are removed. | `retain on site` | 01, 05, 08, 09 |
| Plan run | `run`, `name`, `model`, `reasoning_effort`, `exit_code`, `completed`, `started_at`, `updated_at`, `plan`, and `planner`. | Structured plan is recursively filtered; planner artifacts use the common artifact limits. All stored plan runs are emitted in a task detail. | `retain on site` | 01, 05, 07, 08, 09 |
| Validation detail | `index`, `command`, `passed`, `exit_code`, `summary`, `iteration`, `started_at`, `completed_at`, and `log`. | Each command part is text-normalized; `cwd` and `output_path` are never emitted. Unlike summary validations, detail validations are currently all emitted. | `retain on site` | 01, 05, 08, 09 |
| Remote commit | `commit` and `commit_url`, or both null. | SHA must be 7..64 hexadecimal characters; URL is restricted to the configured GitHub repository. | `retain on site` | 01, 05, 08, 09 |
| Integration detail | `is_integration_task`, `source_task_id`, and up to eight related `runs`. Each run has `task`, `remote`, `commit_message`, and `push_log`. | Related-run search reads up to 400 local tasks; output is capped at eight. `source_task_id` is an allowed relationship identifier, not a control link. | `retain on site` | 01, 05, 08, 09 |

## Published artifact classes

The common redacted artifact envelope is `{text, size, truncated,
tail_bytes}`. Raw transcript envelopes instead use `{text: "", size,
truncated: false, tail_bytes: 0, mode: "raw", url, sha256}`. Artifact paths
must resolve to existing files under the configured state root, except push
logs which must resolve under the log root.

| Artifact class | Producer and current behavior | Current limit and redaction boundary | Disposition | Owner subplans |
| --- | --- | --- | --- | --- |
| Task patch | `artifacts.patch`, attempt `patch`, and integration patch views. | 128 KiB tail, line-aligned, `_public_text` path normalization; `truncated` and original `size` are retained. | `retain on site` | 01, 05, 08, 09 |
| Task/worker/reviewer/planner transcript | Common `transcript` field in `artifacts`, attempts, and plan runs. | `none` omits it; `redacted` renders JSONL into text, removes `thread.started`, `turn.started`, and `turn.completed`, then takes a 64 KiB tail; `truncated` records the original size. | `retain on site` | 01, 05, 07, 08, 09 |
| Last message | Common `last_message` field in task/run artifacts. | 24 KiB tail, text-normalized. | `retain on site` | 01, 05, 08, 09 |
| Validation log | `validations[].log`. | 64 KiB line-aligned tail, state-root containment, text-normalized. | `retain on site` | 01, 05, 08, 09 |
| Integration commit-message artifact | `integration.runs[].commit_message` with `transcript` and `last_message`. | Transcript follows transcript mode/64 KiB cap; last message is 24 KiB. No prompt file is copied. | `retain on site` | 01, 05, 08, 09 |
| Integration push log | `integration.runs[].push_log`. | 64 KiB line-aligned tail and log-root containment. | `retain on site` | 01, 03, 05, 08, 09 |
| Raw transcript file | When `transcript_mode="raw"`, copied under `/steward/data/tasks/{task}/runs/{run}/codex.jsonl`; artifact contains URL and SHA-256, while the JSON detail contains no raw text. | Copy is not byte-capped. The original JSONL, including thread IDs and private paths, is publicly downloadable. Task `spec.prompt` is also published in raw mode. This mode is unsafe for the public target and is explicitly owned by hardening subplan 09. | `remove` | 09, 17, 19 |
| Task detail index | `data/tasks/index.json` with `schema_version`, `generated_at`, and task entries `{id,title,status,updated_at,detail_json}`. | Uses the same 80-task mirror window; stale task JSON/raw directories are removed. | `retain on site` | 01, 04, 05, 08, 09 |

### Public redaction and security boundary

- `transcript_mode` currently accepts `none`, `redacted`, and `raw`; the
  default is `redacted`. Public mode must reject `raw` before rollout (09).
- `_public_json` removes any object key containing one of `path`, `prompt`,
  `transcript`, `worktree`, `payload`, `secret`, `thread`, `token`, or `key`,
  and limits arrays/tuples to 40 entries. Scheduler data uses the same key
  test and a 20-entry list limit.
- `_public_text` replaces configured repo, CoQUIC home, Steward home, and
  state paths; normalizes `.remote-ci`, coverage, and `.rag` paths; and masks
  absolute paths rooted under `/home`, `/media`, `/tmp`, `/var`, or `/opt`.
- Public metadata is allowlisted before recursive filtering. Signal payloads,
  locations, and fingerprints are not emitted. Public links are allowlisted
  to `https://github.com/`.
- Public file artifacts require real existing files contained by the state or
  log root. Public task IDs and raw run segments are sanitized to
  alphanumeric/period/underscore/hyphen segments.
- The remote publisher uses strict host-key checking, batch SSH, configured
  known-host/key paths, a per-target staging directory, `umask 077`, remote
  stage mode 700, a publish lock, and atomic/delayed rsync behavior. These
  publisher credentials and paths never enter the public configuration.
- The local Web API is only loopback-protected, not authenticated. Its raw
  prompt/path/transcript behavior must not be treated as the public contract.

## Limits, polling, publication, and cache behavior

| Area | Current behavior | Migration implication and owner |
| --- | --- | --- |
| Local state snapshot | FastAPI state reads 200 tasks, 200 signal items, and 80 fetch runs. Public mirror defaults are 80 tasks, 80 signal items, and 40 fetch runs. | Define schema-v3 window/truncation semantics before parity (01, 05, 09). |
| Local state updates | Local browser fetches `/api/state` with `cache: "no-store"`, then receives changed snapshots through SSE. SSE rebuilds state every 1 second. | Remove SSE with the local UI; site polling and freshness use the public snapshot (04, 06, 17, 18). |
| Local task detail updates | Task detail uses no-store fetches and refreshes on every SSE `state` event. It loads run transcript windows and iteration patches concurrently. | Site detail polls the published detail every 30 seconds and must preserve stale/last-valid state (04, 06, 14). |
| Local planner list | API default 40/max 200, offset max 10,000; local UI page size 10 and lazy artifact fetch on expansion. | Publish bounded standalone planner history and artifact availability (01, 07, 08). |
| Local artifact reads | Most tails are 256 KiB; transcript `window` is capped at 256 KiB; `full=1` is uncapped; image assets have no explicit byte cap. | Public artifact classes must be bounded and explicit; full/raw behavior is local-only (09). |
| Public producer trigger | Enabled store changes call the mirror updater. Foreground writes are digest-gated. Background publishing waits 1 second after dirty state (`PUBLIC_MIRROR_DEBOUNCE_SECONDS`), retries failed remote publish every 30 seconds, and flushes on shutdown. | The current best-case local publication latency is about 1 second plus serialization/SSH/rsync; remote outage can leave the site stale indefinitely until retry/recovery. Publisher health is missing (02, 03, 15). |
| Public digest | Digest omits generated timestamps and provider due flags/timestamps. Identical normalized state is not rewritten/published. | Heartbeat changes cannot currently force publication; add runtime heartbeat/publication contract (02, 03). |
| Signal provider polling | Defaults: `github-actions:ci`, `test`, and `deploy-demo` 30 minutes; `duvet`, `nightly-ci`, `interop`, and `perf` 1440 minutes; `github-issues:features`, `code-scanning`, and `codacy` 360 minutes. Error retry default is 30 minutes; idle interval is provider default or 30 minutes; suppression is 24 hours; max items is 12. A stable hash adds 0..16 minutes of provider jitter. | Public site displays cadence/last fetch/due state but cannot initiate fetch. Preserve CLI/daemon scheduling (10, 12) and publish health (03). |
| Daemon scheduler wait | `scheduler_wait_interval_sec` defaults to 1.0 seconds; the wait loop sleeps no less than 0.1 seconds and coalesces idle fetches within the wait interval. | Remains daemon-local; only sanitized cadence/health is site data (02, 08). |
| Public browser status polling | `usePublicStewardState()` fetches `/steward/status.json` immediately and every 30 seconds with `cache: "no-store"`. | Meets the 60-second target only when publishing succeeds; stale/offline/incompatible state needs explicit runtime/publication fields (02, 06). |
| Public browser task polling | `usePublicStewardTaskDetail()` fetches the detail URL immediately and every 30 seconds with `cache: "no-store"`; artifact URLs are fetched with `cache: "no-store"` when text is not embedded. | Keep detail lazy/bounded and preserve last valid snapshot on transient failure (04, 06, 07, 08). |
| Current Next route cache | Static task and raw transcript routes are `dynamic='force-dynamic'`, Node runtime, and return `cache-control: public, max-age=0`, not `no-store`. The status loader reads the raw static `/steward/status.json` path directly. | Add the cache-safe status route and point the loader at it; retain path-constrained task/raw routes (04). |
| Public UI display windows | Site task/signal pagination is 10 items; signal items show up to 12 for the active provider; fetch history shows up to 8; State integration shows up to 5 commits or 8 integration tasks. | Contract must carry total/truncated/availability information where a UI window hides records (01, 05, 08, 14). |
| Remote publication | SSH connect timeout defaults to 10 seconds; rsync/SSH command timeout is at least 300 seconds or 30 times the connect timeout. Staging is per remote target and uses checksum/delayed deletion. | Publisher failures must be locally observable without stopping daemon work (03, 15). |

## Unsupported or unsafe current fields

These are deliberate inventory findings, not implied public guarantees:

| Current field/capability | Current state | Follow-up owner |
| --- | --- | --- |
| Daemon identity and heartbeat | No daemon instance ID, process start, heartbeat, cycle start/completion, or last-cycle summary is published. | 02 |
| Publisher health | No last attempt/success/failure/retry/accepted-digest status is published or shown locally in a structured way. | 03 |
| Raw transcript mode | `raw` is accepted and tested; it exposes original JSONL and raw task prompt through a static public path. | 09 |
| Public signal payload | Local UI shows full payload/location/fingerprint; public mirror omits them. There is no reviewed public replacement for diagnostic payload detail. | 01, 08, 09 |
| Public planner history | Local standalone planner files are not in the status payload; task plan runs are separate and only available for feature task detail. | 01, 07 |
| Public audit/configuration rendering | Producer and TypeScript types carry the fields, but current site tabs do not render them. | 08 |
| Public integration parity | Producer carries integration detail, but the site has no local UI-equivalent Patch/Validation/Commit/Push integration view. | 08 |
| Event and attempt growth | Public task detail emits all events, attempts, plan runs, and detail validations without a producer-side count/byte window. | 01, 05, 09 |
| Multi-project support | Local `projects` payload currently contains one active project and disabled alternatives; site uses one repository/branch identity. | 08, 12 |
| Runtime compatibility markers | `/api/runtime` feature markers are local boot checks, not a versioned public compatibility contract. | 01, 04, 05, 17 |

## Completeness verification

The inventory was verified by repository searches over tracked source (excluding
generated `node_modules`, `.next`, Python caches, and build output):

```text
rg -n '^\s*@app\.(get|post)' steward/src/coquic_steward/web/app.py
  -> 18 route decorators: state, stream, tick, fetch-signals, tasks, run,
     task detail, integration detail, files, iteration patch, run transcript,
     validation, assets, healthz, runtime, planner list, planner detail, root

rg -n 'type ViewKey|projectItems|function DashboardView' steward/web-ui/app/page.tsx
  -> five local navigation keys: control, tasks, integration, signals,
     configuration; task detail is the separate linked route

rg -n '^def |@enqueue_app\.command|@app\.command' steward/src/coquic_steward/cli.py
  -> 10 root commands plus the enqueue group and 3 nested commands:
     agents, status, run, daemon, plan, timeline, fetch-signals,
     publish-public-state, audit-invariants, web, code-quality, interop,
     custom

rg -n 'type StewardMirrorTab|MirrorNavItem|StewardTaskDetail|StewardFreshness|StewardUnavailableNotice' site/next/src/components/steward-public.tsx
  -> three public dashboard tabs (overview/state, tasks, signals), the public
     task-detail view, and the two exported but currently unused freshness /
     unavailable components

rg -n 'PUBLIC_MIRROR_SCHEMA_VERSION|PUBLIC_TASK_DETAIL_SCHEMA_VERSION|^def _public_|MIRROR_.*BYTES' steward/src/coquic_steward/public_mirror.py
  -> status/detail schema versions, all status/detail field projectors,
     artifact classes, redaction helpers, file guards, and byte caps

rg -n '^def test_(web_|cli_|public_|daemon_.*mirror|write_public_mirror|test_web)' steward/tests/test_clean_steward.py
  -> route, CLI, redaction, raw-mode, artifact, publisher, digest, retry,
     shutdown-flush, and public-mirror state-change coverage
```

The route search and command search are intentionally counted explicitly so a
future subplan can rerun them and fail the inventory if a new surface appears.
No runtime source, local UI source, site source, tests, or
`plans/dashboard-migrations/README.md` is changed by subplan 00.

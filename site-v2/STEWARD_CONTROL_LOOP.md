# Steward Global Control-Loop Boundary

This document supersedes the former raw control-loop archive contract. The
initial cloud publication contains task-local events in each visible task
graph. It does not publish a global signal ledger, planner archive, or revision
domain. Producer details belong to the [Steward cloud
contracts](../contracts/steward-cloud/README.md); Site reader behavior belongs
to [DATA.md](DATA.md), [API.md](API.md), and [FUNCTIONAL.md](FUNCTIONAL.md).

## Published task boundary

Task events are rows in the visible D1 publication for their owning task. They
carry the task identity, positive sequence, event type, occurrence time, and
bounded summary. Site validates task ownership, expected event count, and
contiguous sequence before returning task detail. Events are evidence attached
to one task; they are not a cross-task event stream and do not establish a
global revision or snapshot.

A completed planning run attached to a task is task evidence. It is the same
complete sanitized trajectory described by the task publication and is not a
global scheduler-planner run. Site does not infer signal, planner, proposal,
or revision relationships from task events, timestamps, labels, or payloads.

## Unpublished global domains

Signals, Planning, and revision remain discoverable navigation destinations,
but the initial cloud contract has no public rows or objects for those global
domains. Their routes return a terminal no-store `410` problem response:

- `/api/steward/revision`
- `/api/steward/signals/{signalId}/events`
- `/api/steward/planner-runs/{plannerRunId}/transcript`
- `/api/steward/planner-runs/{plannerRunId}/artifacts/{artifact}`

Each response uses `schemaVersion: "3.0"`, `code: "UNAVAILABLE"`,
`status: 410`, and `retryable: false`. It never reflects route parameters,
query strings, credentials, private values, or a filesystem path. An empty task
publication is valid; it does not make a global domain available.

The unavailable response is intentional ownership, not a transport failure.
The reader never reads a legacy archive, local fixture, private original, or
partial task evidence to populate these destinations. It never polls,
retries, synthesizes global state, or converts task-local events into global
signals or planner history.

## Ownership and future activation

The task publication producer owns event creation, validation, and exposure.
The cloud contract in [`contracts/steward-cloud/`](../contracts/steward-cloud/)
owns D1/R2 publication rules. Site owns read-only acquisition, normalization,
validation, and rendering. This document owns only the global availability and
ownership boundary; it does not add a transfer process, deployment operation,
database, or control-plane mutation.

A future global domain requires its own producer contract, schema, fixtures,
public-safe publication, API response, and reader tests. Until that contract
exists, global Signals, Planning, and revision remain explicit `410`
unavailable states. Task-local planning evidence remains available only through
the published task graph.

## Superseded raw design

The former control-loop tree, append-only files, prefix cursors, watcher and
importer behavior, local cache, raw transcript/artifact reads, and filesystem
placement disclosure are non-normative historical context. None is a Site V2
input, fallback, or compatibility obligation. Raw JSONL tails, private
credentials, authenticated object storage, and historical migration are outside
the cloud reader boundary.

### Historical context (non-normative)

Steward previously recorded global observations and planner runs beside task
archives for local recovery and research. That archive may explain old names in
operator material, but it is no longer read or written by the Site cloud
reader. Removing those assets does not change this availability contract.

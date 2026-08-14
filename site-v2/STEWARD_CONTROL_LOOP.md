# Steward Global Control-Loop Boundary

The initial Site V2 publication contains task-local events in each visible D1
publication. It does not publish a global signal ledger, planner archive, or
revision domain. Producer details belong to the [Steward cloud
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
global scheduler-planner run. Site does not infer signal, planner, proposal, or
revision relationships from task events, timestamps, labels, or payloads.

## Unavailable product domains

Signals, Planning, and revision remain discoverable navigation destinations, but
the initial cloud publication has no public rows or objects for those global
domains. They are product states, not API endpoints or alternate data sources.
The UI keeps Signals and Planning discoverable and renders their explicit
unavailable state without synthesizing a payload. An empty task publication is
valid; it does not make a global domain available.

The unavailable state is intentional product ownership, not a transport failure.
The reader never polls, retries automatically, derives global state from task
records, or uses a local fixture to populate these destinations. Task-local
planning evidence remains available only through the published task graph.

## Ownership and future activation

The task publication producer owns event creation, validation, and exposure. The
cloud contract in [`contracts/steward-cloud/`](../contracts/steward-cloud/)
owns D1/R2 publication rules. Site owns read-only acquisition, validation, and
rendering. This document owns only the global availability and ownership
boundary; it does not add a transfer process, deployment operation, database, or
control-plane mutation.

A future global domain requires its own producer contract, schema, fixtures,
public-safe publication, API response, and reader tests. Until that contract
exists, global Signals, Planning, and revision remain explicit unavailable
product states. Task-local planning evidence remains available only through the
published task graph.

## Reader input boundary

The Site reader consumes only visible D1 task publications and immutable
sanitized R2 objects addressed by validated artifact identity. It has no
filesystem archive, JSONL tail, local cache, importer, control-plane mutation,
or alternate publication input. Credentials, private paths, authenticated
object locations, and raw internal control-loop records remain outside the
public contract.

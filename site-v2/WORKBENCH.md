# Workbench Engine Boundary

The V2 Workbench presentation communicates with a browser-side engine adapter.
The adapter MAY wrap WASM directly, a Web Worker, or a test simulator. The UI
MUST depend only on the commands and events in `schemas/workbench.schema.json`.

## Lifecycle

1. The adapter emits `engine.state: loading` while acquiring WASM.
2. It emits `engine.state: ready` or `engine.state: unavailable` with an error.
3. The UI sends `scenario.load` with a catalog ID and canonical network values.
4. The adapter emits a complete `simulation.snapshot` with sequence `0`.
5. `simulation.run`, `simulation.pause`, `simulation.step`, and
   `simulation.reset` control execution.
6. Every state-changing event has a monotonically increasing sequence number.
7. `simulation.complete` terminates the current run but does not discard packets,
   trace records, or endpoint state until reset/load.

Only one scenario is active. Commands include a `runId`; adapters MUST ignore
commands for an obsolete run. The UI MUST ignore events from an obsolete run or
events whose sequence is not newer than the last applied sequence.

## Commands

- `scenario.load`: select scenario and initialize client/server/network.
- `network.update`: update loss, bandwidth, or delay before or while paused.
- `simulation.run`: start or resume continuous execution.
- `simulation.pause`: stop automatic advancement at the next safe boundary.
- `simulation.step`: execute one protocol action while paused or ready.
- `simulation.reset`: discard current run state and return to initial snapshot.
- `capture.export`: request a PCAP artifact for the current captured packets.

Commands that cannot run in the current state produce `engine.error` with
`recoverable: true`; they do not corrupt or reset the current snapshot.

## Events

- `engine.state`: adapter loading/readiness/failure.
- `simulation.snapshot`: complete replaceable state after load/reset.
- `clock.updated`: simulated elapsed milliseconds.
- `endpoint.updated`: complete client or server diagnostic snapshot.
- `packet.captured`: one immutable packet in capture order.
- `trace.appended`: one immutable diagnostic entry in trace order.
- `simulation.state`: ready/running/paused/completed/failed.
- `capture.ready`: downloadable PCAP artifact.
- `engine.error`: stable code, message, recoverability, and affected command.

Packet payloads are display-safe data. Raw bytes use lower-case hexadecimal with
no separators. Decoded frames preserve order and use typed scalar fields. The UI
MUST NOT infer protocol correctness from presentation animation; engine events
are the source of truth.

## Determinism and testing

Given the same engine version, scenario, network configuration, and random seed,
the emitted semantic sequence SHOULD be deterministic. The adapter MUST allow a
test seed. Time visible to the UI is simulated time, not animation wall time.

PCAP export MUST include captured packets in event order and declare
`application/vnd.tcpdump.pcap` or `application/x-pcap` consistently.

# Linux-First ECN Interop Design

## Summary

Add Linux-first Explicit Congestion Notification support to `coquic` so the
stack can pass the official `ecn` interop testcase and behave coherently with
RFC-style ECN validation and congestion response. The implementation should:

- send ECN-capable packets on Linux for the ECN testcase
- read inbound IP ECN codepoints on Linux and report ACK-ECN counters
- validate ECN per path, including new paths created by migration
- disable ECN on a path when validation fails instead of failing the
  connection
- treat validated ECN-CE increases as congestion signals
- add `ecn` to the checked-in official interop workflow immediately

This design is grounded in:

- RFC 9000 Section 13.4.1 for ACK-ECN reporting
- RFC 9000 Section 13.4.2 for per-path ECN validation
- RFC 9002 Section 8.3 for handling ECN misreporting and CE-driven congestion

## Goals

- Pass the official `ecn` testcase in the pinned
  `quic-interop-runner` revision already used by this repo.
- Support Linux UDP send and receive plumbing for `Not-ECT`, `ECT(0)`,
  `ECT(1)`, and `CE`.
- Include ACK-ECN counts in ACK frames whenever the runtime has access to
  inbound ECN metadata.
- Validate ECN state per path, not globally per connection.
- Revalidate ECN when a connection moves to a new path, including preferred
  address migration and active migration.
- Feed validated ECN-CE increases into the existing congestion controller using
  the same reduction path already used for loss events.
- Keep non-Linux or runtime-unavailable ECN support as graceful fallback, not
  as a hard connection failure.

## Non-Goals

- Non-Linux socket support in this milestone.
- New congestion-control algorithms, L4S behavior, or any semantics beyond
  loss-equivalent CE response in the existing NewReno controller.
- Changing the pinned `quic-interop-runner` revision.
- Reworking qlog in this slice.
- Adding a public CLI flag specifically for `ECT(1)` selection. The core should
  support `ECT(1)`, but the interop runtime can continue to use its testcase
  profile as the public entrypoint for now.

## Current State

- `src/quic/frame.{h,cpp}` already supports serializing and parsing ACK frames
  with optional ACK-ECN counts.
- `src/quic/recovery.{h,cpp}` already builds ACK frames per packet number
  space, but it does not track ECN counts.
- `src/quic/http09_runtime.cpp` uses `sendto()` and `recvfrom()` only. It does
  not send or receive IP ECN metadata.
- `src/quic/http09.h`, `src/quic/http09.cpp`, and
  `interop/entrypoint.sh` do not expose an `ecn` testcase today.
- `src/quic/connection.{h,cpp}` and `src/quic/core.{h,cpp}` do not carry ECN
  metadata through inbound or outbound datagram paths and do not maintain
  per-path ECN validation state.

The pinned runner testcase confirms only a minimum bar:

- each endpoint sends at least some ECT-marked packets
- traces do not show CE-marked outbound packets
- each endpoint emits at least one ACK frame that contains ACK-ECN fields

The repo should implement more than that minimum. Passing the runner is a
compatibility target, not the entire design.

## Architecture

The design splits ECN into three layers.

### 1. Linux Runtime Socket Layer

`http09_runtime` becomes responsible for Linux UDP ECN socket plumbing.

- Outbound packets use `sendmsg()` with per-datagram control messages so the
  runtime can request `ECT(0)` or `ECT(1)` on a specific send.
- Inbound packets use `recvmsg()` and ancillary data parsing so the runtime can
  recover the received ECN codepoint from IPv4 or IPv6 packets.
- The send-side control message should be chosen from the actual peer address
  family, not just the socket family, so dual-stack IPv6 sockets that send to
  IPv4-mapped peers still behave correctly.
- Runtime socket setup should request the Linux receive metadata needed to read
  inbound ECN information for both IPv4 and IPv6 where relevant.
- If Linux ECN metadata cannot be enabled or read, the runtime should mark ECN
  as unavailable and continue with `Not-ECT`.

This layer knows only about socket metadata and Linux kernel behavior. It does
not own QUIC validation or congestion rules.

### 2. Core and Path State Layer

`QuicCore` and `QuicConnection` own QUIC ECN semantics.

- Inbound datagrams need to carry the received ECN codepoint into the core.
- Outbound send effects need to carry the ECN codepoint that the runtime should
  apply to the outgoing datagram.
- ECN validation state lives under `PathState`, not globally under
  `QuicConnection`, because RFC 9000 Section 13.4.2 requires validation per
  path.
- Path changes created by preferred address or active migration must start a
  fresh validation cycle for the new path.

This layer owns all state transitions:

- unavailable
- testing
- capable
- failed

It also owns the sent/acked accounting needed to decide when ECN remains valid
and when it must be disabled.

### 3. Recovery and Congestion Layer

`ReceivedPacketHistory`, `PacketSpaceRecovery`, and the NewReno controller own
ACK-ECN accounting and CE response.

- ACK generation must include ECN counts per packet number space, as required
  by RFC 9000 Section 13.4.1 and Section 19.3.2.
- ACK processing validates peer-reported counts against sent packet metadata
  for the path and marking codepoint in use.
- When a validated ACK reports a new CE increase, the connection should feed
  that into the same congestion reduction path already used for loss, rather
  than inventing a second controller for this milestone.

## Core Types and State

### IP ECN Codepoint

Add a shared enum for the IP ECN field, used by runtime, core, recovery, and
tests:

- `not_ect`
- `ect0`
- `ect1`
- `ce`

This is a protocol-facing type, not a Linux-only runtime type.

### Transport Configuration

Extend `QuicTransportConfig` with an ECN marking policy:

- `disabled`
- `ect0`
- `ect1`

The default should remain `disabled` so existing non-ECN traffic does not
change behavior accidentally. The interop `ecn` testcase will opt into
`ect0`. Internal tests and future callers can opt into `ect1` through the same
mechanism.

### Core Input and Output

Extend the datagram-bearing core types:

- `QuicCoreInboundDatagram` gains the received ECN codepoint
- `QuicCoreSendDatagram` gains the desired outbound ECN codepoint

This keeps runtime-to-core data flow explicit and avoids hidden side channels.

### Sent Packet Metadata

Extend `SentPacketRecord` with:

- the path id the packet was sent on
- the ECN codepoint used for the send

That metadata is needed for path-local ECN validation and for CE-driven
congestion response.

### Per-Path ECN State

Extend `PathState` with an ECN sub-state containing:

- validation status: `unavailable`, `testing`, `capable`, `failed`
- configured marking policy for this path
- total packets sent with `ECT(0)` on this path
- total packets sent with `ECT(1)` on this path
- largest accepted peer-reported `ECT(0)`, `ECT(1)`, and `CE` totals for this
  path and packet number space
- a bounded validation probe budget so the connection can detect the “all ECT
  packets were lost” failure mode from RFC 9000 Section 13.4.2
- the last accepted CE total that has already been consumed for congestion
  response

The path state is authoritative for whether outbound datagrams should be marked
and which codepoint they should use.

## Data Flow

### Outbound

1. `QuicConnection` decides which path to use for the datagram.
2. That path’s ECN state determines the outbound ECN codepoint:
   - `disabled`, `failed`, or `unavailable` => `Not-ECT`
   - `testing` or `capable` => configured `ECT(0)` or `ECT(1)`
3. `drain_outbound_datagram()` returns a send effect carrying both the bytes and
   the desired ECN codepoint.
4. `http09_runtime` converts that codepoint into Linux `sendmsg()` control
   metadata and sends the datagram.
5. The sent packet record stores the path id and outbound codepoint so ACK
   validation can reason about it later.

### Inbound

1. `http09_runtime` receives a UDP datagram using `recvmsg()`.
2. It extracts the ECN field from ancillary data and maps it to the shared ECN
   enum.
3. It forwards that value in `QuicCoreInboundDatagram`.
4. `QuicConnection::process_inbound_datagram()` processes each QUIC packet in
   the datagram.
5. For each successfully processed QUIC packet, the matching packet number
   space increments its `ECT(0)`, `ECT(1)`, or `CE` counter once.

This matches RFC 9000 Section 13.4.1, including the rule that coalesced QUIC
packets share the same IP ECN field and increment separate packet number spaces
once each.

### ACK Generation

`ReceivedPacketHistory::build_ack_frame()` grows cumulative ECN counts into the
generated `AckFrame` whenever ECN metadata is available.

- Counts remain per packet number space.
- Duplicate packets must not increment those counts.
- If the runtime cannot provide ECN metadata, ACK frames remain valid plain ACK
  frames without ECN counts.

## Validation Rules

The validation algorithm should be intentionally narrow and deterministic.

### Validation Start

When a path first becomes active:

- if transport ECN policy is `disabled`, mark the path `unavailable`
- if runtime ECN metadata is unavailable, mark the path `unavailable`
- otherwise mark the path `testing`

When the connection migrates to a new path or switches to a preferred address,
the new path starts in `testing` again even if an earlier path was already
`capable`.

### Validation Probe Window

Use a small bounded probe budget for path validation, aligned with the example
algorithm in RFC 9000 Appendix A.4.

- The path tracks the first ten ack-eliciting packets sent with a non-zero ECN
  codepoint while in `testing`.
- If all packets in that validation budget are eventually declared lost before
  any valid ACK-ECN evidence arrives, ECN validation fails for that path.

This keeps the failure mode concrete without requiring a more complicated PTO
time-window heuristic in this slice.

### ACK-ECN Validation

When an ACK acknowledges packets sent with `ECT(0)` or `ECT(1)` on a path:

- If ACK-ECN counts are missing, validation fails for that path.
- If reported totals regress relative to the largest accepted totals for that
  packet number space, the ACK is ignored for ECN validation instead of causing
  a hard failure. This avoids false failure from reordered ACK frames, per RFC
  9000 Section 13.4.2.1.
- If `delta(ECTx) + delta(CE)` is less than the number of newly acknowledged
  packets that were sent with that codepoint, validation fails.
- If peer-reported totals exceed the total number of packets sent with the
  corresponding codepoint, validation fails.
- Otherwise validation succeeds for that observation, the path moves to
  `capable`, and the accepted ACK-ECN totals advance.

The validation rules must work symmetrically for both `ECT(0)` and `ECT(1)`.
No code path should hardcode `ECT(0)` semantics.

### Validation Failure

If validation fails:

- stop marking future packets on that path
- mark the path `failed`
- keep the connection alive
- keep reporting inbound ECN counts in ACKs when available

Validation failure is path-local, not connection-fatal.

## CE-Driven Congestion Handling

Once a path is `capable`, a new `CE` increase in an accepted ACK-ECN report is
treated as a congestion signal.

For this milestone:

- CE handling reuses the existing NewReno loss-reduction path
- the connection should reduce congestion once per newly accepted CE increase
- the same recovery guard already used by `on_loss_event()` should prevent
  repeated reductions for the same recovery epoch

This matches the RFC 9002 Section 8.3 guidance that CE can be treated
equivalently to loss in a classic controller for this slice.

The design does not add a new ECN-specific controller or L4S behavior.

## Runtime and Interop Surface

### HTTP/0.9 Runtime

Add `ecn` as a first-class official testcase alias in:

- `src/quic/http09.h`
- `src/quic/http09.cpp`
- `src/quic/http09_runtime.cpp`
- `interop/entrypoint.sh`

Runtime behavior for `ecn`:

- use the same transport and TLS profile as `transfer`
- opt into transport ECN policy `ect0`
- otherwise preserve existing transfer behavior

The core transport config still supports `ect1`; the runtime testcase uses
`ect0` because that is the conservative interop default.

### Official Interop Workflow

Add `ecn` to the requested testcase list in the checked-in GitHub interop
workflow immediately:

- `interop-quicgo`
- `interop-picoquic`
- `interop-self`

That keeps the checked-in workflow aligned with the newly supported interop
surface instead of waiting for a follow-up milestone.

The workflow contract tests must also be updated so they assert the presence of
`ecn` in the shared testcase string.

## File-Level Impact

Expected design impact is concentrated in these areas:

- `src/quic/http09.h`
- `src/quic/http09.cpp`
- `src/quic/http09_runtime.h`
- `src/quic/http09_runtime.cpp`
- `src/quic/http09_runtime_test_hooks.h`
- `src/quic/core.h`
- `src/quic/core.cpp`
- `src/quic/connection.h`
- `src/quic/connection.cpp`
- `src/quic/recovery.h`
- `src/quic/recovery.cpp`
- `src/quic/congestion.h`
- `src/quic/congestion.cpp`
- `interop/entrypoint.sh`
- `.github/workflows/interop.yml`
- targeted tests under `tests/`

No new standalone subsystem is needed. This is a focused extension of existing
runtime, core, recovery, and CI code.

## Testing Strategy

### Unit and Core Tests

Add focused tests for:

- parsing and serializing the new ECN-related config and datagram metadata
- ACK-ECN count accumulation per packet number space
- no counter inflation for duplicate inbound packets
- validation success for `ECT(0)`
- validation success for `ECT(1)`
- validation failure when ACK-ECN counts are absent
- validation failure when counts regress or under-report newly acknowledged
  ECT-marked packets
- CE increases triggering congestion-window reduction
- new-path revalidation after preferred-address and active migration

### Runtime Tests

Extend the runtime test hooks so Linux ECN metadata can be simulated under test
without requiring the real kernel behavior for every case.

Add tests for:

- runtime argument parsing accepting `ecn`
- Linux send-side ECN marking selection for IPv4 and IPv6 paths
- Linux receive-side ECN metadata extraction
- graceful fallback when ECN socket features cannot be enabled

### Interop and Workflow Tests

Add or update tests so they assert:

- `interop/entrypoint.sh` accepts `TESTCASE=ecn`
- the checked-in workflow testcase list includes `ecn`
- the repo-local workflow contract tests stay exact after the testcase list
  changes

### Verification Bar

Before claiming this milestone complete, the implementation should show fresh
evidence for:

- targeted ECN tests
- `zig build test`
- workflow contract tests
- `actionlint`
- local official-runner `ecn` success against at least one external peer
- local official-runner `ecn` success in self-interop

## Risks and Tradeoffs

- Linux-first ECN socket support is the right scope for interop and CI, but it
  leaves other platforms in graceful-fallback mode for now.
- The official runner only checks for any ECT marks and any ACK-ECN frames. The
  internal test suite must carry the stricter validation and CE-behavior burden.
- Path-local ECN state increases connection complexity, but global ECN state
  would be incorrect once migration is involved.
- Reusing NewReno loss behavior for CE is intentionally conservative. It is the
  correct tradeoff for this milestone because it keeps the controller simple and
  standards-aligned.

## Success Criteria

The milestone is complete when all of the following are true:

- `coquic` accepts and advertises the official `ecn` testcase
- Linux runtime code can send and receive ECN metadata
- ACK frames report ECN counts when ECN metadata is accessible
- ECN validation is implemented per path for both `ECT(0)` and `ECT(1)`
- CE increases on validated paths reduce congestion via the existing controller
- ECN validation failure disables ECN marking on that path without killing the
  connection
- the checked-in official interop workflow requests `ecn`
- the pinned official `ecn` testcase passes locally against an external peer
- the pinned official `ecn` testcase passes locally in self-interop

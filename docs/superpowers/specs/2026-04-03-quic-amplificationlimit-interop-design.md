# QUIC Amplification Limit Interop Design

## Status

Approved in conversation on 2026-04-03.

## Goal

Enable the official `amplificationlimit` interop testcase and make `coquic`
enforce the server-side anti-amplification limit required before client address
validation.

The desired outcome is:

- the interop entrypoint accepts `TESTCASE=amplificationlimit`
- the runtime parser accepts `--testcase amplificationlimit`
- server-side QUIC sending is limited to three times the bytes received until
  the peer address is validated
- the official runner can exercise `amplificationlimit` without a repo-local
  testcase fork

## Protocol Grounding

This design is grounded in:

- RFC 9000 Section 8: a server that has not validated the peer address MUST
  limit bytes sent to three times bytes received
- RFC 9000 Section 21.1.1.1: the anti-amplification limit applies only when
  responding to an unvalidated address
- RFC 9002 Section 6.2.2.1: PTO behavior is also constrained by the same limit
  before address validation

## Context

The current repo already has partial pieces of the required behavior:

- the interop runtime has server-side Retry token support in
  `src/quic/http09_runtime.cpp`
- the official wrapper can run arbitrary testcase names via
  `INTEROP_TESTCASES`
- the HTTP/0.9 runtime already treats `retry` as a testcase alias that maps to
  the normal handshake path plus extra transport behavior

However, the missing pieces are material:

- `interop/entrypoint.sh` currently rejects `TESTCASE=amplificationlimit`
- `src/quic/http09_runtime.cpp` does not parse `amplificationlimit`
- `src/quic/connection.cpp` does not clearly account for pre-validation
  amplification budget

One important upstream detail affects the design: in the pinned
`quic-interop-runner` ref used by this repo, the testcase class named
`amplificationlimit` presents `TESTCASE=transfer` to the endpoint container.
That means entrypoint support for the literal testcase name is useful for local
consistency and direct runs, but official interop success depends on general
core transport behavior rather than a testcase-specific runtime branch.

## Scope

This design covers:

- `interop/entrypoint.sh`
- `src/quic/http09_runtime.cpp`
- `src/quic/connection.h`
- `src/quic/connection.cpp`
- `tests/quic_http09_runtime_test.cpp`
- `tests/quic_core_test.cpp`

## Non-Goals

- full path-validation accounting for migration-era paths
- introducing path state objects for every transport address
- changing official runner pins
- adding unrelated missing interop cases such as `ecn` or `connectionmigration`
- implementing a runtime-only amplification guard outside the QUIC core

## Decisions

### 1. Accept `amplificationlimit` Everywhere Local Testcase Names Are Parsed

Add `amplificationlimit` to:

- `interop/entrypoint.sh`
- `parse_testcase(...)` in `src/quic/http09_runtime.cpp`

It will map to the existing `transfer`-style HTTP/0.9 behavior rather than a
new application mode.

Rationale:

- local direct runs should not reject a valid official testcase name
- the official runner already reuses transfer semantics for this testcase
- no extra HTTP/0.9 application logic is needed

### 2. Implement Anti-Amplification In `QuicConnection`, Not In The Runtime Shell

The send budget will live in `QuicConnection`, not in `send_datagram()` and not
in `http09_runtime`.

Rationale:

- the limit is a transport rule, not an HTTP/0.9 runner quirk
- `QuicCore` users besides the interop runtime should inherit the same safety
- the core already decides which datagrams to emit and when PTO/probes are sent

### 3. Track Budget As Payload Bytes Received And Sent Before Validation

For a server connection:

- accumulate inbound UDP payload bytes from the peer until validation completes
- accumulate outbound UDP payload bytes sent to that peer until validation
  completes
- define available budget as `3 * received - sent`, clamped at zero

This follows RFC 9000 Section 8 wording that counts bytes received in datagrams
and limits bytes sent toward the unvalidated address.

### 4. Treat Retry Acceptance As Validation For The Current Connection

When the server accepts a valid Retry token and creates the connection with
retry context, the path is considered validated for anti-amplification purposes.

Rationale:

- Retry exists specifically to provide address validation before the handshake
  completes
- this keeps the existing runtime Retry machinery aligned with the core budget
  model

### 5. Stop Emitting Ack-Eliciting Datagrams When Budget Is Exhausted

If the next server datagram would exceed remaining anti-amplification budget:

- do not emit the datagram
- leave retransmission/probe/application work pending so a future inbound client
  datagram can increase budget and unblock sending

Ack-only behavior remains constrained by normal transport correctness, but this
feature is focused on ack-eliciting datagrams because those are what the core
currently emits in handshake and data flows relevant to the official testcase.

### 6. Keep The Initial Implementation Single-Path

The first slice will model only the original peer path used during connection
establishment. It will not introduce a general per-path accounting framework for
connection migration.

Rationale:

- the official `amplificationlimit` testcase exercises initial address
  validation
- broad path-accounting work would significantly expand scope

## Architecture

### Testcase Parsing Layer

`interop/entrypoint.sh` and `src/quic/http09_runtime.cpp` will accept
`amplificationlimit` as a supported testcase name and map it to the existing
transfer-style runtime behavior.

No new endpoint mode, request handling, or document-root behavior is required.

### QUIC Connection Layer

`QuicConnection` will gain a small server-side pre-validation accounting state:

- whether anti-amplification applies
- bytes received on the unvalidated path
- bytes sent on the unvalidated path

Inbound datagram processing will update received-byte credit before the server
attempts to produce more outbound handshake work.

Outbound datagram construction will consult the budget before committing a
datagram for transmission and packet tracking.

### Validation Transition

The server stops applying the limit once address validation is complete. The
initial implementation will consider the peer validated when:

- the connection is server-side, and
- either Retry context already proved the address, or
- the server reaches the existing handshake/address-validation point already
  represented by the current connection state machine

If additional explicit validation state is required during implementation, it
should be added narrowly and only for the initial path.

## Error Handling

The implementation should avoid new external error surfaces.

When blocked by anti-amplification:

- the connection should simply emit no datagram
- pending retransmission or handshake work must remain queued
- later inbound client datagrams should increase budget and allow progress

Local testcase parsing should continue to reject genuinely unsupported testcase
names with exit code `127`.

## Testing

### Core Tests

Add unit tests in `tests/quic_core_test.cpp` for:

- server send blocked when the next datagram exceeds `3x` budget
- extra client bytes increasing budget and unblocking the server
- Retry-validated server connections bypassing the limit
- server-side budget accounting not applying to client connections

### Runtime Tests

Add runtime tests in `tests/quic_http09_runtime_test.cpp` for:

- `TESTCASE=amplificationlimit` parsing successfully
- entrypoint/runtime mapping using the same HTTP/0.9 transfer semantics as
  `transfer`

### Interop Verification

After the code lands:

- run a focused local official-runner attempt with
  `INTEROP_TESTCASES=amplificationlimit`
- verify whether the pinned peer image and current implementation actually pass

## Risks

### 1. Validation Boundary Could Be Too Early Or Too Late

If the implementation marks the address validated too early, the testcase will
still fail semantically. If it marks validation too late, legitimate handshake
progress might stall.

Mitigation:

- anchor the transition to existing Retry context and established server
  handshake state
- add white-box tests for both pre-validation and post-validation behavior

### 2. Budget Checks Could Accidentally Drop Necessary Pending Work

If blocked sends also clear pending retransmission or crypto state, the server
could deadlock permanently.

Mitigation:

- gate only datagram emission, not the underlying pending frame state
- add unblock-after-more-credit tests

### 3. Runtime Alias Could Drift From Official Runner Behavior

If the pinned official runner changes testcase presentation later, local
assumptions could drift.

Mitigation:

- keep the alias narrow and behavior-preserving
- verify against the actual pinned official runner path after implementation

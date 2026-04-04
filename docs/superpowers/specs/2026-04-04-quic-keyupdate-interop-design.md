# QUIC Key Update Interop Design

## Status

Approved in conversation on 2026-04-04.

## Goal

Enable the official `keyupdate` interop testcase and make `coquic` actively
cause a QUIC 1-RTT key update when it runs in the client role for that
testcase.

The desired outcome is:

- the interop workflow includes `keyupdate`
- local testcase parsing accepts `keyupdate`
- the HTTP/0.9 runtime treats `keyupdate` as transfer-style application traffic
- the QUIC transport can explicitly initiate one local 1-RTT key update after
  handshake confirmation and after an acknowledgment for the current key phase
- locally initiated key updates do not immediately break receipt of reordered
  packets protected with the previous read keys

## Protocol Grounding

This design is grounded in:

- RFC 9001 Section 6: once the handshake is confirmed, an endpoint MAY
  initiate a key update by toggling the Key Phase bit, and QUIC replaces the
  TLS `KeyUpdate` message mechanism
- RFC 9001 Section 6.1: an endpoint MUST NOT initiate a key update before
  handshake confirmation and MUST NOT initiate another one until a packet in
  the current key phase has been acknowledged
- RFC 9001 Section 6.2: when a peer key update is detected, the endpoint MUST
  update send keys before sending an acknowledgment for the triggering packet
- RFC 9001 Section 6.5: old read keys can need to be retained temporarily to
  tolerate reordered packets during a key update

## Runner Grounding

The pinned official runner ref used by this repo is
`97319f8c0be2bc0be67b025522a64c9231018d37`.

At that ref:

- `quic.md` documents `keyupdate` as a client-only testcase
- the client is expected to ensure that a key update happens early in the
  connection, during the first megabyte transferred
- it does not matter which peer actually initiates the update
- `testcases_quic.py` maps the server perspective of `keyupdate` to
  `transfer`

This means the first slice only needs special local initiation behavior when
`coquic` is the client. When `coquic` runs as the server for the official
`keyupdate` testcase, the runner still presents `TESTCASE=transfer`.

## Context

The repo already has partial key update support:

- protected packet parsing and serialization already carry the 1-RTT key phase
  bit
- `QuicConnection` already reacts to a peer-initiated key update by retrying
  decryption with derived next read keys and promoting application secrets
- unit tests already cover several peer-driven key update paths in
  `tests/quic_core_test.cpp`

However, important pieces are missing:

- `.github/workflows/interop.yml` does not run `keyupdate`
- `interop/entrypoint.sh` rejects `TESTCASE=keyupdate`
- `src/quic/http09_runtime.cpp` does not parse `keyupdate`
- `QuicCore` has no public input for “initiate a local key update now”
- `QuicConnection` does not retain previous read keys after a locally
  initiated update, so a local initiator would immediately lose tolerance for
  reordered old-key packets

## Scope

This design covers:

- `.github/workflows/interop.yml`
- `interop/entrypoint.sh`
- `src/quic/http09.h`
- `src/quic/http09_runtime.h`
- `src/quic/http09_runtime.cpp`
- `src/quic/http09_client.h`
- `src/quic/http09_client.cpp`
- `src/quic/core.h`
- `src/quic/core.cpp`
- `src/quic/connection.h`
- `src/quic/connection.cpp`
- `src/quic/recovery.h`
- `tests/quic_http09_runtime_test.cpp`
- `tests/quic_core_test.cpp`

## Non-Goals

- packet-number-limit driven mandatory key rotation
- repeated local key updates on the same connection
- full three-key-phase packet selection logic for arbitrary consecutive updates
- broad HTTP/0.9 behavior changes unrelated to the official testcase
- changing the pinned official runner ref

## Approaches Considered

### 1. Alias `keyupdate` to `transfer` Only

Accept the testcase name everywhere local parsing happens, but rely entirely on
the peer to initiate the actual key update.

Pros:

- smallest code change
- no public transport API change

Cons:

- `coquic` as client would not guarantee that an early key update happens
- official runner success would depend on peer behavior rather than on our own
  implementation

### 2. Hide Local Key Update Behind Runtime-Only Config

Add a testcase-specific automatic key update flag in `QuicCoreConfig` or
`QuicConnection`, with no explicit public input.

Pros:

- avoids expanding `QuicCoreInput`

Cons:

- mixes one testcase policy into the transport configuration surface
- makes future transport callers less clear about how key updates are
  requested
- harder to unit-test as a transport action independent of the HTTP/0.9 runtime

### 3. Add An Explicit Core Input For Local Key Update

Add a new `QuicCoreInput` variant that requests one local key update. The
HTTP/0.9 client endpoint uses it only for the `keyupdate` testcase.

Pros:

- transport action is explicit and reusable
- runtime policy stays in the runtime layer
- transport legality checks stay in the transport layer
- easiest to unit-test with TDD at both core and runtime layers

Cons:

- slightly larger public API change than a hidden config flag

## Decision

Use approach 3.

`keyupdate` will become an explicit testcase name in the interop/runtime layer,
and the runtime will request a local key update through a new `QuicCoreInput`
variant. `QuicConnection` will decide when that request is actually legal to
execute.

## Decisions

### 1. Add `keyupdate` To Local Testcase Parsing And Workflow Lists

Add `keyupdate` to:

- `.github/workflows/interop.yml`
- `interop/entrypoint.sh`
- `QuicHttp09Testcase`
- `parse_testcase(...)` in `src/quic/http09_runtime.cpp`

The runtime will keep the same HTTP/0.9 request/response behavior as
`transfer`.

Rationale:

- the application behavior is still a normal file transfer
- the testcase difference is transport behavior, not HTTP/0.9 semantics
- local direct runs should accept the official testcase name

### 2. Expose Local Key Update As An Explicit `QuicCoreInput`

Add a new input variant, `QuicCoreRequestKeyUpdate`, to `QuicCoreInput`.

`QuicCore::advance(...)` forwards this request to `QuicConnection`, which
records it as pending transport work instead of forcing the runtime to know the
protocol legality rules.

Rationale:

- QUIC key update is transport behavior
- the runtime should request policy, not implement protocol timing rules
- an explicit input is cleaner than a testcase-specific hidden config flag

### 3. Initiate At Most One Local Key Update Per Connection In This Slice

The first slice supports one locally initiated key update per connection.

This is enough for the pinned official runner, which only requires that a key
update happen early in the connection. It avoids the extra complexity of
supporting repeated local updates across wrapped key phase values in the first
implementation.

Rationale:

- keeps the transport changes focused on the official testcase
- avoids needing general previous/current/next packet-number disambiguation for
  multiple consecutive updates

### 4. Only The HTTP/0.9 Client Endpoint Requests A Local Key Update

For the pinned runner semantics:

- `coquic` in client mode for `keyupdate` requests one local key update
- `coquic` in server mode behaves the same as `transfer`

The server path still needs to continue handling peer-initiated key updates
correctly, but it does not need testcase-specific local initiation behavior in
this slice.

Rationale:

- this matches the pinned official runner contract exactly
- it keeps unnecessary server-side runtime branching out of scope

### 5. Runtime Requests The Update Early, Transport Executes It When Legal

The HTTP/0.9 client endpoint will request the update once transfer traffic is
underway, specifically after the first request stream has been activated.

`QuicConnection` will defer actual initiation until all of these are true:

- handshake is confirmed
- application read and write secrets are available
- no local key update has already been initiated on this connection
- a packet from the current write key phase has been acknowledged

Rationale:

- requesting early satisfies the runner’s “during the first MB transferred”
  requirement
- deferring execution in the transport keeps RFC 9001 Section 6.1 compliance in
  one place

### 6. Retain Previous Read Keys After Local Initiation Until The Peer Responds

When `coquic` locally initiates a key update:

- derive the next write secret and next read secret
- toggle the current application key phase
- retain the previous application read secret and phase temporarily

Inbound short-header processing will:

- first try the current read secret and current key phase
- if that fails, and a retained previous read secret exists, retry with the
  previous read secret when the packet key phase matches the previous phase
- discard the retained previous read secret once a packet protected with the
  new current key phase is successfully processed

Rationale:

- this preserves tolerance for reordered packets sent before the peer has
  responded to the update
- it is the narrowest correct slice for one locally initiated update

### 7. Clear Any Pending Local Request If A Peer Update Already Advances The Phase

If a local key update request is pending but the peer initiates the update
first, the request is considered satisfied and will be cleared without
initiating a second update.

Rationale:

- the official testcase only requires that a key update happen
- immediately initiating another update after a peer update would add
  unnecessary risk and could violate the “wait for acknowledgment in the
  current phase” rule

## Architecture

### Testcase Name Layer

`keyupdate` becomes a first-class `QuicHttp09Testcase` value.

At the HTTP/0.9 layer:

- transport profile remains aligned with `transfer`
- cipher suite selection remains unchanged from normal transfer
- only the client endpoint gains additional runtime behavior

### Core API Layer

`QuicCoreInput` gains a new explicit request type for local key update.

`QuicCore::advance(...)` will forward that input to `QuicConnection` similarly
to stream-send and timer inputs, then continue draining outbound datagrams and
effects normally.

### Connection Layer

`QuicConnection` gains small, focused key-update state:

- whether a local key update has been requested
- whether a local key update has already been initiated on this connection
- the lowest application packet number sent in the current write key phase
- the retained previous application read secret and its phase, if any

Local initiation will happen in the connection’s normal outbound path so that:

- the write key phase used for serialization changes atomically with the
  updated write secret
- the first packet sent in the new phase is tracked immediately

ACK processing in the application packet space will be used to determine when a
packet from the current write phase has been acknowledged and therefore when a
pending local request may proceed.

### Runtime Layer

`QuicHttp09ClientEndpoint` will gain a small testcase-specific flag and one-bit
state such as:

- `request_key_update`
- `key_update_requested`

Once the first request stream is activated for the `keyupdate` testcase, the
client endpoint queues `QuicCoreRequestKeyUpdate` exactly once.

No special server endpoint behavior is required for the pinned official runner.

## Error Handling

Unsupported local testcase names should still fail exactly as today.

For local key update requests:

- requesting before handshake confirmation is not a transport error; the
  connection simply keeps the request pending
- requesting after a peer update has already advanced the phase clears the
  request without failing
- if deriving the next local read or write secret fails, the connection fails
  in the same style as existing secret-derivation failures

The first slice will not add a general `KEY_UPDATE_ERROR` enforcement matrix for
multiple consecutive updates. Existing behavior outside the official testcase
scope remains unchanged unless needed to support the one-update path above.

## Testing

### Core Tests

Add unit tests in `tests/quic_core_test.cpp` for:

- a local key update request does not initiate before handshake confirmation
- a local key update request stays pending until a current-phase application
  packet is acknowledged
- once permitted, the next outbound application packet uses the new key phase
- a locally initiated update retains previous read keys long enough to accept a
  reordered old-phase packet
- the retained previous read keys are discarded after a packet from the new
  phase is successfully processed
- a pending local request is cleared if the peer initiates the update first

### Runtime Tests

Add tests in `tests/quic_http09_runtime_test.cpp` for:

- `TESTCASE=keyupdate` parsing successfully
- `--testcase keyupdate` parsing successfully
- the runtime treats `keyupdate` as a valid client testcase without changing
  the transfer-style HTTP/0.9 behavior

Add client endpoint focused tests for:

- queuing exactly one `QuicCoreRequestKeyUpdate` after the first request stream
  activates in the `keyupdate` testcase
- not queuing that request for normal `transfer`

### Interop Verification

After implementation:

- add `keyupdate` to the appropriate official-runner workflow lists
- run local official-runner interop against at least `quic-go`
- if feasible, run the `keyupdate` matrix in both client and server directions
  against `picoquic` as well

## Risks

The main transport risk is local initiation without temporary previous read-key
retention. That would likely work on an ideal path but fail as soon as reordered
old-key packets arrive after local initiation.

The main scoping risk is overbuilding for repeated updates. The pinned official
runner only requires one early update, so the first slice should stay focused on
that requirement.

## Acceptance Criteria

This work is complete when:

- local parsing and interop workflow lists include `keyupdate`
- `coquic` as client can request and complete one early local key update during
  transfer
- locally initiated key updates do not break receipt of reordered old-phase
  packets in the supported one-update model
- the official runner’s pinned `keyupdate` testcase can be exercised locally
  with `coquic` in the client role

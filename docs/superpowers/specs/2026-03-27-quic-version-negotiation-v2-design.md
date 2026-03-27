# QUIC Version Negotiation And V2 Design

## Status

Approved in conversation on 2026-03-27.

## Context

`coquic` currently has:

- QUIC v1 packet parsing and protection logic
- stateless Version Negotiation packet codec support
- a stateless server runtime path that sends a Version Negotiation packet for
  unsupported-version probes
- a connection and handshake stack that hard-codes QUIC v1

That is not sufficient for RFC 9368 and RFC 9369 support.

Current gaps:

- the live handshake path only derives Initial keys with the QUIC v1 salt
- connection packet peeking and runtime routing reject all long-header versions
  other than v1
- there is no `version_information` transport parameter support
- clients do not react to Version Negotiation packets by starting a new first
  flight
- servers cannot perform compatible negotiation between QUIC v1 and QUIC v2
- there is no authenticated validation of negotiated version state

Relevant protocol requirements:

- RFC 9000 Section 6 and Section 17.2.1 define the Version Negotiation packet
  and the baseline stateless response behavior
- RFC 9368 Section 2.1 defines incompatible version negotiation
- RFC 9368 Section 2.3 defines compatible version negotiation
- RFC 9368 Section 8 requires implementations that negotiate versions other than
  QUIC v1 to implement the authenticated version negotiation mechanism
- RFC 9369 Section 3.1 defines the QUIC v2 version field `0x6b3343cf`
- RFC 9369 Section 4 requires endpoints that support QUIC v2 to send, process,
  and validate the `version_information` transport parameter
- RFC 9369 Section 4.1 defines the v1<->v2 compatible negotiation behavior

The user wants the full RFC 9368/9369 path, not only a narrow QUIC v2 enablement
slice.

## Goal

Implement RFC 9368 and RFC 9369 support so that:

- `coquic` supports native QUIC v1 and QUIC v2 handshakes
- clients and servers exchange authenticated `version_information`
- clients handle incompatible Version Negotiation and restart with a mutually
  supported version
- servers can perform compatible negotiation between QUIC v1 and QUIC v2
- handshake packet processing, Initial protection, and transport-parameter
  validation follow the negotiated version rules
- the local RFC RAG source set includes refreshed RFC 9368 and RFC 9369 texts

## Non-Goals

- Retry support in this slice
- additional future QUIC versions beyond v1 and v2
- 0-RTT support across negotiated-version transitions
- version greasing or reserved-version advertisement beyond what is required to
  pass current local and interop validation
- a generic pluggable multi-version framework for arbitrary future versions

## Decisions

### 1. Treat Version As First-Class Connection State

Introduce explicit version state rather than continuing to treat version as a
packet-local detail.

Connection state must track:

- original version
- chosen client version for the current first flight
- negotiated version, once known
- locally supported versions

This state is needed because RFC 9369 Section 4.1 requires endpoints to use the
original version for some Initial packets before the negotiated version is fully
learned, then transition Handshake and 1-RTT packets to the negotiated version.

### 2. Support Exactly Two Real Versions In This Slice

This design adds:

- QUIC v1: `0x00000001`
- QUIC v2: `0x6b3343cf`

The implementation should use helpers and enums rather than open-coded numeric
checks, but it should not introduce speculative support for versions beyond
these two.

### 3. Make Initial Packet Protection Version-Aware

Initial protection derivation must select the correct Initial salt by version.

This affects:

- Initial packet serialization
- Initial packet decryption
- packet-length peeking and datagram processing that depend on long-header
  version checks

Handshake and 1-RTT protection remain TLS-driven, but packet version on the
wire still needs to follow RFC 9369 Section 4.1 after negotiation.

### 4. Implement Authenticated Version Information Transport Parameters

Add `version_information` transport-parameter encode/decode/validation support
for both peers.

The parameter must carry:

- the chosen version
- the available versions list

Validation rules:

- endpoints that support QUIC v2 must send the parameter
- the authenticated values must be consistent with the Version Negotiation or
  compatible-negotiation path that occurred
- invalid or contradictory values fail the connection with version-negotiation
  error semantics

For pure QUIC v1 peers that never negotiate beyond v1, RFC 9368 Section 8
special handling still applies.

### 5. Separate Incompatible And Compatible Negotiation Paths

The implementation should model two explicit negotiation paths.

#### Incompatible Negotiation

Server behavior:

- when the first flight uses an unsupported version and the datagram is large
  enough, send one stateless Version Negotiation packet containing the offered
  versions

Client behavior:

- ignore invalid Version Negotiation packets
- ignore packets that echo the client-selected version
- if a mutually supported version exists, start a new first flight with that
  version
- authenticate the negotiation outcome during the subsequent handshake using
  `version_information`

#### Compatible Negotiation

Server behavior:

- when parsing the client first flight succeeds and both v1 and v2 are locally
  supported, select either the client version or the compatible peer-preferred
  version according to local policy
- emit Version Information that authenticates the negotiated result
- use the original version for pre-negotiation Initial responses when required
- switch Handshake and 1-RTT packets to the negotiated version per RFC 9369
  Section 4.1

Client behavior:

- learn the negotiated version from the first long-header Version field that
  differs from the original version
- continue processing original-version Initial packets until the negotiated
  version is learned
- send subsequent Handshake and 1-RTT packets only in the negotiated version
- reject inconsistent authenticated Version Information

### 6. Keep Runtime Version Negotiation Stateless At The Routing Boundary

The socket runtime should continue to make the unsupported-version response
decision before a connection object exists.

However, the runtime must advertise all supported offered versions, not only
QUIC v1, and it must allow supported v2 Initial packets to route into the same
connection establishment flow as v1.

### 7. Prefer V2 For Compatible Negotiation When Both Sides Support It

When the server can parse the client first flight and both peers support v1 and
v2, the default policy is:

- accept the client version if it is v2
- upgrade a v1 first flight to v2 when compatible negotiation is allowed

This exercises the RFC 9369 path instead of leaving the feature dormant behind
dual-version support.

If later interop results require a different preference policy, that can be a
follow-up change.

## Architecture

### Version Types And Helpers

Introduce a focused version helper layer that centralizes:

- numeric codepoints
- supported-version lists
- Initial salt selection
- predicates such as `is_supported_quic_version(...)`

This avoids duplicating version checks in:

- `connection.cpp`
- `http09_runtime.cpp`
- protected codec and packet crypto code
- tests

### Transport Parameters

Extend transport-parameter structures with a `version_information` model.

That model should be a concrete typed field instead of an unstructured byte
blob, because both serialization and validation need semantic access to:

- chosen version
- available versions

Validation context must also be extended so the connection can check:

- original version
- locally supported versions
- whether incompatible or compatible negotiation occurred
- expected negotiated version, when known

### Connection State Machine

The connection needs explicit negotiation state that survives across Initial,
Handshake, and transport-parameter processing.

That state must drive:

- outbound packet version selection
- inbound packet acceptance and drop rules
- client restart after Version Negotiation
- transition from original-version Initial traffic to negotiated-version
  Handshake traffic

The implementation should avoid a second unrelated handshake engine. The
existing `QuicConnection` remains the handshake owner; negotiation extends its
state rather than wrapping it in a parallel transport abstraction.

### Runtime Integration

`Http09Runtime` needs two changes:

- stateless unsupported-version responses must advertise all offered versions
- runtime/client startup must allow selecting the initial client version list,
  then let the transport react to Version Negotiation and compatible
  negotiation

Interop-oriented defaults should use dual support for v1 and v2 so the feature
is exercised in local tests.

## Testing Strategy

Implementation is test-first and split into small, evidence-producing slices.

### Unit Tests

- packet and plaintext codec tests for Version Negotiation packet offered-version
  lists
- packet crypto tests for QUIC v2 Initial salt/key derivation
- transport-parameter tests for `version_information` encode/decode and
  validation

### Connection Tests

- client restarts with a mutually supported version after receiving a valid
  Version Negotiation packet
- client ignores malformed or invalid Version Negotiation packets
- server accepts QUIC v2 Initial packets
- v1 client and v2-capable server complete compatible negotiation to v2
- peers reject inconsistent authenticated Version Information

### Runtime Tests

- unsupported-version probes receive Version Negotiation listing v1 and v2
- local HTTP/0.9 transfer succeeds over native QUIC v2
- local HTTP/0.9 transfer succeeds after incompatible negotiation
- local HTTP/0.9 transfer succeeds after compatible v1-to-v2 negotiation

## Implementation Sequence

1. Refresh `docs/rfc/rfc9368.txt` and `docs/rfc/rfc9369.txt`, then rebuild the
   local RAG index
2. Add version constants and version-aware Initial secret derivation
3. Add `version_information` transport-parameter support and tests
4. Extend connection version state and client/server negotiation logic
5. Update runtime routing and stateless Version Negotiation advertisement
6. Add end-to-end runtime coverage for native v2, incompatible negotiation, and
   compatible negotiation

## Risks

- compatible negotiation crosses packet-number spaces and packet versions in the
  same handshake, which is easy to implement incorrectly
- missing one remaining hard-coded v1 assumption in packet peeking or protection
  could create non-obvious decryption failures
- QUIC v1 fallback rules from RFC 9368 Section 8 need to remain correct for
  pure-v1 peers while still enforcing authenticated negotiation for v2-capable
  peers

## Acceptance Criteria

This design is complete when:

- the repo contains refreshed RFC 9368 and RFC 9369 source texts and a rebuilt
  local RAG index
- unit and runtime tests cover QUIC v1, QUIC v2, incompatible negotiation, and
  compatible v1<->v2 negotiation
- a dual-version client and server can complete a local HTTP/0.9 transfer after
  negotiating versions
- invalid version negotiation state is detected and rejected

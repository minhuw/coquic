# QUIC Handshake Core Design

## Status

Approved on 2026-03-18.

## Context

`coquic` already has a plaintext QUIC packet/frame codec and a protected QUIC
datagram codec under `src/quic/`. Those layers can serialize, protect,
deserialize, and unprotect `Initial`, `Handshake`, and `1-RTT` packets, but the
repo does not yet have any connection-level handshake state, CRYPTO stream
reassembly, transport parameter handling, or TLS integration.

The next slice is not general QUIC transport. It is a narrow handshake engine
that can drive a real QUIC + TLS 1.3 handshake between two in-process peers.
The requested public shape is a tiny facade with a byte-in, byte-out API so an
integration test can wire two peers together directly.

This design is grounded in:

- RFC 9001 Section 4, which carries TLS handshake bytes in QUIC `CRYPTO` frames
  and binds them to encryption levels and packet number spaces
- RFC 9000 Section 7.3, which authenticates handshake connection IDs through
  transport parameters
- RFC 9000 Section 18.2, which defines the transport parameters exchanged
  during the handshake

## Goal

Add a connection-scoped QUIC handshake engine that:

- exposes a small public `QuicCore` API centered on `receive(...)`
- uses the existing QUIC packet protection and codec layers
- drives a real TLS 1.3 handshake over QUIC `CRYPTO` frames
- exchanges and validates QUIC transport parameters
- installs Initial, Handshake, and 1-RTT secrets in the correct order
- completes a client/server handshake in an in-process integration test without
  introducing timers, retransmission, streams, or application data

## Non-Goals

- General transport behavior such as loss recovery, PTO, congestion control, or
  timers
- Stream state outside the TLS handshake CRYPTO stream
- 0-RTT support
- Retry support
- Connection migration, preferred address handling, or stateless reset
- Production socket I/O or event-loop integration
- A public abstract connection interface or multiple connection
  implementations
- Interoperability with external QUIC stacks in this first slice
- Requiring `HANDSHAKE_DONE` or handshake confirmation semantics before
  reporting local handshake completion

## Decisions

### Public API

- Add a new public `QuicCore` facade as the top-level handshake entry point.
- `QuicCore` exposes:
  - construction from a small config object
  - `std::vector<std::byte> receive(std::vector<std::byte> bytes)`
  - `bool is_handshake_complete() const`
- `receive(...)` accepts one inbound UDP payload image and returns one outbound
  UDP payload image.
- For client bootstrap, calling `receive({})` on a newly constructed client
  starts the handshake and returns the first client Initial datagram.
- The server does not emit bytes spontaneously; it only emits bytes in response
  to a received datagram.

### Connection Boundary

- `QuicCore` is a thin public wrapper around one concrete internal
  `QuicConnection`.
- Do not introduce `IConnection`, virtual dispatch, or multiple connection
  implementations in this slice.
- `QuicConnection` owns all protocol state needed for the handshake:
  - local and peer connection IDs
  - send and receive packet numbers for Initial, Handshake, and Application
    packet number spaces
  - installed read/write secrets by encryption level
  - CRYPTO send buffers and CRYPTO reassembly state by encryption level
  - local and peer transport parameters
  - handshake status and terminal failure state
- This gives the repo a real connection-level abstraction now, without
  over-designing the external surface.

### Internal Layering

- Keep the existing codec layers unchanged as reusable lower layers:
  - `src/quic/plaintext_codec.*`
  - `src/quic/protected_codec.*`
- Build the handshake layer above them with focused internal units:
  - `QuicCore`: public facade
  - `QuicConnection`: connection-scoped handshake state machine
  - packet-space state helpers for Initial, Handshake, and 1-RTT
  - CRYPTO send/reassembly helpers per encryption level
  - transport-parameter encode/parse/validate helpers
  - `TlsAdapter`: a narrow TLS integration seam
- `QuicConnection` owns handshake orchestration; helper modules remain small and
  single-purpose.

### TLS Integration

- Use the real TLS path, not a mock handshake.
- Keep TLS behind a dedicated `TlsAdapter` boundary so connection logic does not
  depend directly on a specific library's callback shape.
- `TlsAdapter` is responsible for:
  - accepting inbound TLS handshake bytes at a given encryption level
  - producing outbound TLS handshake bytes at a given encryption level
  - surfacing newly available write/read traffic secrets
  - surfacing transport parameter extension bytes
  - reporting handshake completion or fatal TLS failure
- `QuicConnection` remains responsible for QUIC packetization, packet
  protection, connection IDs, and transport-parameter validation.
- The current repo environment uses OpenSSL 3.4.3. During design review, the
  available public headers clearly exposed generic TLS hooks, key logging, and
  custom extensions, but did not clearly expose the older raw QUIC callback
  surface for custom server-side QUIC packetization. Therefore the TLS adapter
  seam is a hard requirement, not an optional convenience.

### Handshake Flow

- Client startup flow:
  - choose client source and initial destination connection IDs
  - build local transport parameters including
    `initial_source_connection_id`
  - ask TLS for the initial outbound handshake bytes
  - package those bytes into `CRYPTO` frames in protected Initial packets
- Server receive flow:
  - decode and decrypt Initial packets
  - reassemble Initial-level CRYPTO bytes
  - feed those bytes into TLS
  - once TLS yields response bytes and handshake secrets, emit a coalesced
    datagram containing server Initial and Handshake packets as available
- Client continuation flow:
  - process server Initial and Handshake packets
  - reassemble CRYPTO bytes by encryption level
  - install newly available secrets
  - validate peer transport parameters against observed connection ID values
  - emit follow-up handshake traffic, coalescing packet types when useful
- Completion flow:
  - mark local handshake completion once TLS reports handshake success, peer
    transport parameters have been authenticated and validated, and usable 1-RTT
    keys are installed
  - do not require `HANDSHAKE_DONE` reception or transport-level confirmation
    in this milestone

### CRYPTO Stream Handling

- Maintain separate CRYPTO send state and receive reassembly state for:
  - Initial
  - Handshake
  - 1-RTT
- Reassembly must track offsets so out-of-order `CRYPTO` frames can be accepted
  within a packet number space, even if the first integration test only drives
  in-order delivery.
- Outbound TLS bytes are packetized into one or more `CRYPTO` frames, with
  packet boundaries chosen by the handshake layer.
- Because RFC 9001 Section 4 binds handshake bytes to the encryption level that
  produced them, each encryption level keeps its own CRYPTO bookkeeping.

### Packet Generation

- Use the existing protected codec to serialize protected QUIC datagrams rather
  than constructing encrypted packet bytes by hand in the handshake layer.
- `QuicConnection` decides:
  - which packet types to emit
  - packet number values and packet number lengths
  - which frames go into each packet
  - when to coalesce multiple packets into one datagram
- The first handshake slice only needs these frame families on the wire:
  - `CRYPTO`
  - `PADDING`
  - possibly `ACK` only if a minimal self-handshake shim is proven necessary for
    in-process progress
- General ACK strategy, retransmission, and loss accounting stay out of scope.

### Transport Parameters

- Add focused transport-parameter helpers instead of folding parameter logic
  directly into the TLS adapter.
- Local transport parameters for the first slice include the required handshake
  identity fields plus a minimal set of valid QUIC parameters.
- Validate peer transport parameters according to the handshake rules from
  RFC 9000 Sections 7.3 and 18.2, especially:
  - `initial_source_connection_id`
  - `original_destination_connection_id` on the server side of the exchange
  - server-only parameter presence rules
  - minimum validity requirements such as
    `active_connection_id_limit >= 2`
- Retry-related transport parameter rules remain out of scope because Retry is
  out of scope.

### Error Handling

- Distinguish local handshake-engine failure from lower codec failure:
  - codec errors remain codec errors from existing layers
  - TLS failures become handshake-engine failures with captured detail
  - transport-parameter validation failures become handshake-engine failures
- `QuicCore` does not attempt recovery after a terminal handshake failure in
  this slice.
- The integration test can fail fast when either peer enters a terminal error
  state.

### Testing

- Add one integration-style handshake test that constructs:
  - one client `QuicCore`
  - one server `QuicCore`
- The test drives the handshake by alternately passing datagram outputs from one
  peer into `receive(...)` on the other peer until:
  - both peers report `is_handshake_complete()`, or
  - a fixed iteration budget is exhausted, or
  - either side enters a terminal error
- Add narrower unit tests for:
  - CRYPTO stream reassembly
  - transport-parameter encoding and parsing
  - connection ID validation against peer transport parameters
  - secret installation transitions from Initial to Handshake to 1-RTT
  - coalesced Initial plus Handshake packet handling
- The first milestone is successful when two in-process peers complete the
  handshake deterministically without timers or retransmission.

### Implementation Risk Management

- The highest-risk item is TLS integration, not QUIC packetization.
- Therefore the implementation plan must begin with a TLS adapter spike that
  proves:
  - client and server handshake bytes can be exchanged under application control
  - QUIC transport parameters can be injected and read back
  - traffic secrets needed by the protected codec can be surfaced at the right
    points
- If the spike shows that the current OpenSSL path is not suitable for the
  desired control model, the TLS backend can change without invalidating the
  `QuicCore` / `QuicConnection` / codec layering in this design.

## Verification

The completed implementation must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```

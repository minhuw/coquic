# RFC 9000 Implementation Audit

Date: 2026-05-13

Scope: RFC 9000, "QUIC: A UDP-Based Multiplexed and Secure Transport", as
indexed from `references/rfc/rfc9000.txt`. This is a source inspection audit and
implementation tracker, not a formal conformance certification.

Method: I read RFC 9000 in document order using the repo-local QUIC RAG index
and cross-checked the implementation under `src/quic`, `src/io`, and the
focused tests under `tests/core`, `tests/http09`, `tests/http3`, and
`tests/tls`. The RAG doctor reported `indexed_sections: 1119/1119`.

Verification after this update:

- `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
  passed.
- `nix develop -c zig build test` passed.

## Current Summary

The repository now implements the major RFC 9000 transport-core pieces that the
first audit called out as missing:

- top-level `stateless_reset_token` transport parameter;
- duplicate transport-parameter rejection;
- supported Initial datagram minimum-size discard on server endpoints;
- idle timeout deadline and silent close;
- closing/draining state retention and close timers;
- transport CONNECTION_CLOSE generation for protocol/codec errors where close
  keys are available;
- stateless reset token tables, detection, draining, unknown-CID reset
  generation for tokens retained by the endpoint, and stable reset-token
  derivation when a deployment configures a persistent reset secret;
- NEW_TOKEN issuance, client retention, future Initial reuse, single-use server
  validation, expiry, route/identity binding, restart-stable sealed tokens, and
  token-key rotation;
- restart-stable sealed Retry tokens with route/identity/CID/version binding;
- randomized in-memory Retry and NEW_TOKEN values;
- secret-derived connection IDs, stateless reset tokens, and PATH_CHALLENGE
  data;
- CID retirement tracking for locally retired peer CIDs and in-flight
  RETIRE_CONNECTION_ID frames;
- no-viable-path handling when PMTU falls below 1200 bytes;
- path-validation deadlines, recovery reset on path switch, and validation
  timers based on the QUIC core timeline;
- 0-RTT remembered transport-parameter reduction checks;
- IPv6 flow-label assignment in the Linux socket send path;
- reserved-version greasing for Version Negotiation;
- optional latency spin-bit behavior with admin disablement and random
  connection-level disablement;
- optional file-backed address-validation replay tracking;
- socket-backend address-validation identities derived from peer IP/port;
- request-forgery policy hooks for loopback, link-local, private-use,
  address-space downgrade, and blocked UDP ports.

No known RFC 9000 packet, frame, or endpoint-state mechanism from the original
gap list remains unimplemented in the transport core. The remaining work is
production hardening: continuing to make transport error codes more specific
when useful, adding operational policy around shared PMTU/replay caches in
multi-process deployments, and broadening interop coverage.

## Coverage Map

| RFC 9000 area | Current status |
| --- | --- |
| Sections 2-4, Streams and flow control | Mostly implemented. Stream state, buffers, final-size checks, flow-control windows, BLOCKED frames, stream-limit frames, and structured flow/stream error metadata exist. Residual hardening is any edge-case semantic error mapping still hidden behind packet-shape codec failures. |
| Section 5, Connections and connection IDs | Mostly implemented. Destination-CID routing, CID issuance, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, retirement tracking, active limits, randomized/secret-derived CIDs, reset tokens, bounded post-close reset-token retention, configured stable reset-token derivation, and migration CID privacy lifecycle exist. |
| Section 6, Version Negotiation | Implemented, including optional reserved-version greasing. Version Negotiation generation and client handling are tested. |
| Section 7, Handshake and transport parameters | Mostly implemented. TLS integration, transport-parameter serialization/validation, duplicate rejection, top-level `stateless_reset_token`, original/initial/retry CID authentication, and 0-RTT remembered-parameter checks exist. |
| Section 8, Address validation | Implemented for transport-core scope. Retry and NEW_TOKEN are random, route-bound, expiring, single-use, and can use a sealed HMAC-protected token format with deployment-provided address-validation identity, restart-stable validation, previous-secret rotation, and optional file-backed replay tracking. Socket runtimes populate IP/port identities. |
| Section 9, Connection migration | Mostly implemented. Path state, PATH_CHALLENGE/PATH_RESPONSE, preferred-address events, probing-only validation sends, validation deadlines, recovery reset on path switch, NEW_TOKEN issuance per validated route, local migration CID privacy, a generic address-change allow/deny switch, and fine-grained request-forgery policy hooks exist. |
| Section 10, Connection termination | Mostly implemented. Idle timeout, immediate close, closing/draining, close retention timers, close packet retransmission rate limiting, remote close handling, stateless reset receive draining, bounded local reset-token retention, and configured restart-stable reset-token derivation exist. |
| Section 11, Error handling | Mostly implemented. The code has an RFC transport error enum, queues CONNECTION_CLOSE for protocol/codec failures, and preserves structured transport error/frame metadata in stream, flow-control, CID, and frame-forbidden validators. Packet-shape codec failures still intentionally map coarsely where exact semantic context is not available. |
| Sections 12-13, Packets, frames, ACK, reliability | Mostly implemented. Packet/frame formats, coalescing, packet number spaces, ACK history, retransmission metadata, ECN feedback validation, and loss/recovery integration exist. Residual work is broader interop hardening rather than an identified RFC 9000 packet/ACK mechanism gap. |
| Section 14, Datagram size and PMTU | Mostly implemented. Initial padding, server-side undersized Initial discard, PMTUD/DPLPMTUD scaffolding, Linux PMTU socket options, route-scoped PMTU updates, and no-viable-path handling exist. Shared or persisted PMTU cache policy remains an optional IO/deployment concern. |
| Sections 15-17, Versions, varints, packet formats, spin bit | Mostly implemented. Versions, varints, packet formats, and optional latency spin-bit endpoint behavior are implemented. |
| Sections 18-20, transport parameters, frames, errors | Mostly implemented. The QUIC v1 transport parameters and frame codecs exist, including `stateless_reset_token`, plus structured transport error metadata for the main semantic validators. |
| Section 21, Security considerations | Mostly implemented for transport-core scope. TLS packet protection, anti-amplification, random/secret-derived identifiers, unpredictable path challenges, token replay limits including optional file-backed replay persistence, stateless reset loop-size limits, configured stateless reset derivation after state loss, sealed address-validation tokens, IPv6 flow labels, request-forgery policy hooks, ECN hardening, optional spin-bit privacy disablement, and optional optimistic-ACK mitigation exist. |

## Implemented Items From The Original Gap List

### `stateless_reset_token` Transport Parameter

Status: Implemented

Evidence:

- `TransportParameters::stateless_reset_token` in
  `src/quic/transport_parameters.h`
- parameter ID `0x02`, 16-byte encode/decode, and server-only validation in
  `src/quic/transport_parameters.cpp`
- handshake coverage in `tests/core/connection/handshake_test.cpp`
- packet codec coverage in `tests/core/packets/transport_parameters_test.cpp`

### Stateless Reset Detection And Draining

Status: Implemented

The endpoint tracks peer reset tokens, detects any datagram ending in a known
16-byte token using constant-time comparison, and moves the matching connection
to draining without sending a response. Unknown-CID reset generation exists for
retained endpoint token state with RFC size constraints. Closed connections can
retire routing state while retaining local reset tokens until a configurable
expiry. A deployment can also configure a persistent
`QuicStatelessResetSecret`; for endpoint-generated server CIDs, the endpoint can
derive the same token after restart or live route loss and send a reset without
volatile connection state.

Evidence:

- token tables and route refresh in `src/quic/core.{h,cpp}`
- `QuicCore::retire_endpoint_connection_routes`
- `QuicCore::purge_expired_local_stateless_reset_tokens`
- `QuicCoreEndpointConfig::stateless_reset_secret`
- `QuicCoreConfig::stateless_reset_secret`
- `QuicConnection::enter_stateless_reset_draining` in
  `src/quic/connection.{h,cpp}`
- tests in `tests/core/endpoint/internal_test.cpp`

### Duplicate Transport Parameter Handling

Status: Implemented

The transport-parameter decoder tracks seen parameter IDs and rejects
duplicates, including duplicate unknown/reserved IDs where appropriate.

Evidence:

- decode loop in `src/quic/transport_parameters.cpp`
- tests in `tests/core/packets/transport_parameters_test.cpp`

### NEW_TOKEN Issuance, Storage, And Reuse

Status: Implemented

Servers issue NEW_TOKEN after handshake and address validation, store expiring
single-use server-side token contexts, and issue per validated route. Clients
store received tokens and attach the most recent unused matching token to
future Initial packets. Servers still reject inbound NEW_TOKEN frames, as
required. When a deployment configures `address_validation_token_secret`, the
server issues sealed HMAC-protected NEW_TOKEN values that carry token kind,
QUIC version, expiry, route handle, deployment-provided address-validation
identity, and a random nonce. Those tokens can be validated after process
restart, can be accepted with configured previous secrets for key rotation, and
are still replay-limited by the endpoint's consumed-token table.

Evidence:

- `QuicAddressValidationTokenSecret`
- `QuicCoreInboundDatagram::address_validation_identity`
- `QuicCore::maybe_queue_server_new_token`
- `QuicCore::make_endpoint_new_token`
- `QuicCore::take_new_token_context`
- `QuicCore::remember_client_new_tokens`
- `QuicCore::take_client_new_token_for_open`
- `QuicConnection::queue_new_token`
- tests in `tests/core/endpoint/internal_test.cpp`

Additional hardening:

- The optional replay-store path is intentionally a simple local file. A
  production multi-process deployment might still want a shared database,
  stronger locking, or centralized garbage collection.

### Retry Token Security And Address Binding

Status: Implemented

Retry tokens are random 128-bit values, expire quickly, are stored server-side,
and are bound to route handle, Retry SCID, original DCID, and version. Retry
packet integrity remains separate and is still validated. When
`address_validation_token_secret` is configured, Retry tokens use the same
sealed HMAC-protected token envelope as NEW_TOKEN, with token kind, version,
expiry, route handle, deployment-provided address-validation identity, original
DCID, Retry SCID, and random nonce. A restarted endpoint can validate such a
Retry token without retaining the original in-memory token table.

Evidence:

- `QuicAddressValidationTokenSecret`
- `QuicCore::make_endpoint_retry_token`
- `QuicCore::take_retry_context`
- tests in `tests/core/endpoint/internal_test.cpp`

### Supported Initial Datagram Size Enforcement

Status: Implemented

Server endpoints discard supported Initial UDP datagrams below 1200 bytes
before Retry processing or connection creation.

Evidence:

- supported Initial size gate in `src/quic/core.cpp`
- `ServerDiscardsSupportedInitialDatagramSmallerThan1200Bytes` in
  `tests/core/endpoint/internal_test.cpp`

### Idle Timeout

Status: Implemented

Connections track peer activity and first ack-eliciting send after the idle
base, compute the effective idle timeout from local and peer transport
parameters, expose the deadline through `next_wakeup()`, and silently close on
timeout.

Evidence:

- `QuicConnection::idle_timeout_deadline`
- `QuicConnection::note_idle_peer_activity`
- `QuicConnection::note_idle_ack_eliciting_send`
- timeout path in `QuicConnection::on_timeout`
- tests in `tests/core/connection/handshake_test.cpp` and
  `tests/core/endpoint/multiplex_test.cpp`

### Closing And Draining States

Status: Implemented

The connection now has explicit closing/draining modes, retains state for a
three-PTO close period, suppresses sends while draining, emits a close packet
when possible, and rate-limits close retransmission by requiring a progressively
larger number of inbound packets before each subsequent close response.

Evidence:

- `QuicConnectionCloseMode` in `src/quic/connection.h`
- close/drain helpers in `src/quic/connection.cpp`
- close-state retention in `src/quic/core.cpp`
- tests in `tests/core/connection/handshake_test.cpp` and
  `tests/core/connection/retry_version_test.cpp`

### RFC Transport Error Signaling

Status: Mostly implemented

The code now has a `QuicTransportErrorCode` enum and queues transport
CONNECTION_CLOSE frames for many protocol/codec failures at Initial, Handshake,
or 1-RTT levels depending on available write keys. Stream, flow-control,
connection-ID, and forbidden-frame validators now attach transport error codes
and frame types to their codec error carrier.

Evidence:

- `QuicTransportErrorCode` in `src/quic/connection.h`
- transport codec error helpers in `src/quic/connection.cpp`
- `queue_transport_close_for_error` in `src/quic/connection.cpp`
- close-generation tests in `tests/core/connection/handshake_test.cpp`
- semantic validator coverage in `tests/core/connection/ack_test.cpp`,
  `tests/core/connection/stream_test.cpp`, and
  `tests/core/connection/connection_id_test.cpp`

Additional hardening:

- Continue replacing any newly discovered coarse packet-shape codec failures
  when the caller has enough context to preserve a more exact semantic transport
  error.

### Active Migration And Path State

Status: Mostly implemented

Path validation uses unpredictable challenge data, validation deadlines, and
the QUIC core timeline. Matching PATH_RESPONSE validates the challenged path,
switches the send path when appropriate, resets recovery state, and allows
server NEW_TOKEN issuance on the validated route. Preferred-address validation
sends are probing-only before validation succeeds.

Evidence:

- `start_path_validation`
- `path_validation_timeout_period`
- `reset_recovery_for_new_path`
- `QuicCoreEndpointConfig::allow_peer_address_change`
- `QuicRequestForgeryPolicyConfig`
- `QuicCoreInboundDatagram::address_validation_identity`
- application send gating around `validation_only_send`
- tests in `tests/core/connection/path_validation_test.cpp` and
  `tests/core/connection/migration_test.cpp`
- endpoint migration policy coverage in `tests/core/endpoint/multiplex_test.cpp`
- request-forgery policy coverage in `tests/core/endpoint/internal_test.cpp`

### PATH_CHALLENGE Data Predictability

Status: Implemented

PATH_CHALLENGE data is derived from a secret-keyed PRF with randomized fallback
instead of deterministic public state.

Evidence:

- `make_path_challenge_data` in `src/quic/connection.cpp`
- freshness test in `tests/core/connection/path_validation_test.cpp`

### Connection ID Lifecycle And Reset Token Generation

Status: Implemented

Endpoint-generated CIDs and reset tokens are now random or secret-derived, CID
retirement is tracked, retired peer CIDs are not used for new paths,
RETIRE_CONNECTION_ID frames are tracked while in flight, and spin state resets
when a path changes peer CID sequence. When a persistent reset secret is
configured, stateless reset tokens for endpoint-generated server CIDs are
restart-stable and can be regenerated after volatile connection state is lost.
Local active migration/probing now requires an unused peer connection ID before
sending on the new path, and a successfully validated local migration retires
the peer CID that was tied to the prior path.

Evidence:

- `PeerConnectionIdRecord::locally_retired`
- `PeerConnectionIdRecord::retire_frame_in_flight`
- `make_issued_connection_id`
- `make_stateless_reset_token`
- `QuicConnection::set_path_peer_connection_id_sequence`
- `QuicConnection::select_peer_connection_id_sequence_for_path`
- `QuicConnection::retire_peer_connection_id_for_inactive_path`
- tests in `tests/core/connection/connection_id_test.cpp`
- migration privacy coverage in `tests/core/connection/migration_test.cpp`
- spin-bit reset coverage in `tests/core/connection/ack_test.cpp`

### PMTU/DPLPMTUD No-Viable-Path Handling

Status: Implemented in core

PMTU updates below 1200 bytes mark a path non-viable, stop normal sends on that
path, optionally fall back to the previous validated path, and queue
NO_VIABLE_PATH close when the current path cannot support QUIC.

Evidence:

- `PathMtuState::viable`
- `QuicConnection::apply_path_mtu_update`
- tests in `tests/core/connection/path_validation_test.cpp`

Additional hardening:

- RFC 9000 recommends maximum datagram size tracking per local/remote IP address
  pair when PMTU discovery is used. The core already applies PMTU updates to the
  route/path selected by the IO layer, and Linux socket backends report PMTU
  updates through route handles. A shared or persisted PMTU cache across process
  restarts remains deployment policy rather than a missing transport mechanic.

### 0-RTT Transport Parameter Reduction Checks

Status: Implemented

When 0-RTT is accepted, the client rejects live peer transport parameters that
reduce remembered flow-control, stream-limit, or active-CID limits. Tests cover
every RFC 9000 Section 7.4.1 MUST-NOT-reduce parameter and also verify that
non-remembered or optional parameters such as `ack_delay_exponent`,
`max_ack_delay`, and `max_udp_payload_size` are not incorrectly added to that
mandatory rejection set.

Evidence:

- `zero_rtt_transport_limits_not_reduced`
- `AcceptedZeroRttRejectsReducedServerTransportLimits` in
  `tests/core/connection/zero_rtt_test.cpp`
- `AcceptedZeroRttAllowsNonRememberedAndOptionalParameterReduction` in
  `tests/core/connection/zero_rtt_test.cpp`

## Residual Hardening

### Exact Transport Error Code Mapping

Status: Mostly implemented

Many protocol violations now result in CONNECTION_CLOSE with structured
transport error metadata. The remaining risk is packet-shape or codec failures
where exact semantic context is unavailable at the point of failure; those still
map through the generic codec-to-transport error table.

### Persistent Address-Validation Tokens

Status: Implemented with optional file-backed replay store

The endpoint supports both the original in-memory token table and a configured
sealed token format. With `QuicCoreEndpointConfig::address_validation_token_secret`,
Retry and NEW_TOKEN values carry authenticated metadata, an expiry timestamp,
a random nonce, route binding, and a deployment-provided address-validation
identity. NEW_TOKEN validation also supports configured previous secrets for
key rotation. Accepted tokens are tracked in a consumed-token table so replay is
limited within the endpoint process; when
`QuicCoreEndpointConfig::address_validation_replay_store_path` is set, consumed
tokens are also loaded from and persisted to a local file so replay rejection can
survive endpoint restart.

Evidence:

- `QuicCore::load_consumed_address_validation_tokens`
- `QuicCore::persist_consumed_address_validation_tokens`
- `QuicCore::mark_address_validation_token_consumed`
- `AddressValidationReplayStoreSurvivesEndpointRestart` in
  `tests/core/endpoint/internal_test.cpp`

Additional hardening:

- Multi-process deployments should use an externally synchronized replay store
  if several endpoint processes can validate the same token concurrently.

### Durable Stateless Reset After Total State Loss

Status: Implemented with configured secret

Reset detection for received tokens is implemented. Unknown-CID reset
generation exists for retained endpoint token state, and local reset tokens can
be retained for a bounded period after connection removal. Deployments that set
`QuicCoreEndpointConfig::stateless_reset_secret` derive reset tokens from the
incoming endpoint-generated server CID, so a restarted endpoint with no live
connection table can still generate the token previously issued for that CID.
Deployments that leave the secret unset keep the safer process-local behavior
and can only reset unknown CIDs while retained token state is still available.

### ECN Validation

Status: Implemented in core

The core has path-scoped ECN state, outgoing ECT marking, peer ECN count
handling, disable-on-failure behavior, and congestion response for CE feedback.
Tests cover omitted ACK_ECN counts, count decreases, impossible ECT feedback,
CE marking, ECT1 handling, and probe-loss behavior.

Evidence:

- `QuicConnection::process_inbound_ack_cursor`
- `QuicConnection::disable_ecn_on_path`
- `QuicConnection::outbound_ecn_codepoint_for_path`
- ECN coverage in `tests/core/connection/ack_test.cpp`
- IO ECN metadata coverage in `tests/http09/runtime/socket_io_backend_test.cpp`
  and `tests/http09/runtime/io_uring_backend_test.cpp`

### IPv6 Flow Label

Status: Implemented

RFC 9000 Section 9.7 says IPv6 senders should apply a flow label when the local
API allows it. The Linux socket backends now derive a nonzero flow label for
native IPv6 peers and apply it before sendmsg/sendmmsg/io_uring sends.

Evidence:

- `should_apply_ipv6_flow_label` and `peer_with_ipv6_flow_label` in
  `src/io/poll_io_engine.cpp`
- IO helper declarations in `src/io/socket_io_backend_internal.h`
- io_uring send-path integration in `src/io/io_uring_io_engine.cpp`
- `AppliesIpv6FlowLabelOnOutboundDatagrams` in
  `tests/http09/runtime/socket_io_backend_test.cpp`

### Preferred-Address And Request-Forgery Policy Hooks

Status: Implemented

The transport core avoids non-probing frames on unvalidated preferred-address
paths and exposes both a generic `allow_peer_address_change` endpoint switch and
fine-grained request-forgery policy hooks. `QuicRequestForgeryPolicyConfig` can
reject loopback, link-local, private-use/unique-local addresses, public-to-local
address-space downgrades, and configured UDP ports. Socket IO translates peer
IPv4/IPv6 address and UDP port into `address_validation_identity`, and the
runtime paths pass those identities into client opens, server Initials, existing
inbound routes, and explicit migration requests.

Evidence:

- `QuicRequestForgeryPolicyConfig` in `src/quic/core.h`
- address classification and policy checks in `src/quic/core.cpp`
- `address_validation_identity_from_peer` in
  `src/io/shared_udp_backend_core.cpp`
- identity propagation in `src/http09/http09_runtime.cpp`,
  `src/http3/http3_runtime.cpp`, and `src/perf`
- `RequestForgeryPolicyRejectsUnsafeInitialRoutes`,
  `RequestForgeryPolicyRejectsUnsafeServerInitialRoutes`, and
  `RequestForgeryPolicyRejectsUnsafeNewRoutes` in
  `tests/core/endpoint/internal_test.cpp`

### Latency Spin Bit

Status: Implemented optional feature

The packet/protected-codec layers parse and serialize the spin-bit field.
Endpoint behavior is off by default, can be enabled per connection, maintains
per-path spin state, ignores stale packet numbers, resets spin state when the
path changes peer CID sequence, and randomly disables about one in every 16
connections when the feature is administratively enabled.

Evidence:

- `QuicTransportConfig::enable_latency_spin_bit`
- `QuicConnection::update_spin_bit_on_receive`
- `QuicConnection::outbound_spin_bit_for_path`
- `QuicConnection::set_path_peer_connection_id_sequence`
- spin-bit behavior tests in `tests/core/connection/ack_test.cpp`

### Optimistic ACK Mitigation

Status: Implemented optional feature

RFC 9000 Section 21.4 says endpoints may skip packet numbers to detect
optimistic ACKing and close with PROTOCOL_VIOLATION if a peer acknowledges a
packet it has not received. `QuicTransportConfig::enable_optimistic_ack_mitigation`
now enables skipped packet-number probes, and ACK processing closes the
connection if an ACK range covers one of those unsent packet numbers.

Evidence:

- `QuicTransportConfig::enable_optimistic_ack_mitigation`
- `QuicConnection::reserve_packet_number`
- `QuicConnection::reject_optimistic_ack_if_detected`
- `OptimisticAckMitigationSkipsPacketNumbersAndRejectsAcksForThem` in
  `tests/core/connection/ack_test.cpp`

### Reserved Version Greasing

Status: Implemented optional feature

Version negotiation works for supported versions and can include a reserved
version when `grease_reserved_versions` is enabled.

Evidence:

- `QuicTransportConfig::grease_reserved_versions`
- `QuicCore::make_version_negotiation_packet_bytes`
- `VersionNegotiationCanGreaseReservedVersion` in
  `tests/core/endpoint/internal_test.cpp`

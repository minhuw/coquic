# QUIC Core QLOG Design

## Status

Approved in conversation on 2026-04-04.

## Goal

Add real qlog emission for the core QUIC transport, producing one streamed
`.sqlog` file per `QuicConnection` with the seven Core QUIC qlog events that
are most useful for connection establishment, packet flow, and recovery.

The desired outcome is:

- qlog is available through the core QUIC API, not through environment
  variables or the HTTP/0.9 harness
- each connection can emit one sequential qlog file without requiring real
  network I/O hooks outside the existing core send and receive paths
- qlog failures never fail the QUIC connection
- the first slice logs these seven Core QUIC events only:
  `quic:version_information`
  `quic:alpn_information`
  `quic:parameters_set`
  `quic:packet_sent`
  `quic:packet_received`
  `quic:recovery_metrics_updated`
  `quic:packet_lost`

## Protocol Grounding

This design is grounded in the local qlog drafts under `docs/rfc/`:

- `draft-ietf-quic-qlog-main-schema-13` Section 5 and Section 5.1:
  `QLogFileSeq` is the sequential streaming file format intended for
  append-only logging
- `draft-ietf-quic-qlog-main-schema-13` Section 7.1:
  qlog event `time` values are durations, typically represented as float64
  milliseconds, and can be relative to a reference time
- `draft-ietf-quic-qlog-main-schema-13` Section 7.5:
  `common_fields` should hold repeated trace metadata such as `group_id`,
  `time_format`, and `reference_time`
- `draft-ietf-quic-qlog-main-schema-13` Section 8.1:
  event schema URIs identify the concrete event schema in use
- `draft-ietf-quic-qlog-quic-events-12` Section 1.1:
  when `group_id` is used, qlog recommends using QUIC's Original Destination
  Connection ID and also recommends using ODCID in the qlog filename, suffixed
  by vantage point type
- `draft-ietf-quic-qlog-quic-events-12` Section 2.1:
  because the QUIC qlog event schema is still an Internet-Draft,
  implementations should identify draft traces with
  `urn:ietf:params:qlog:events:quic-12` instead of the final RFC URI
- `draft-ietf-quic-qlog-quic-events-12` Section 5.1, Section 5.2, Section
  5.3, Section 5.5, Section 5.6, Section 7.2, and Section 7.4:
  the seven event definitions and their intended usage

## Context

The repo currently has no real qlog implementation.

Existing observability is limited to ad hoc traces:

- `COQUIC_PACKET_TRACE` in `src/quic/connection.cpp`
- `COQUIC_RUNTIME_TRACE` in `src/quic/http09_runtime.cpp`

Those traces are useful for local debugging, but they are not qlog:

- they do not emit qlog file metadata
- they are not structured as qlog events
- they are not designed for downstream qlog tooling
- they are not connection-local `.sqlog` artifacts

The core transport already has most of the runtime data needed for a first qlog
slice:

- `QuicConnection` owns handshake, packet processing, send, loss, and recovery
  state
- protected packet parsing already yields packet headers and parsed frame lists
- protected packet serialization already occurs in one place before datagrams
  are emitted
- recovery state already tracks RTT, congestion window, bytes in flight, PTO,
  and declared packet loss

The main missing pieces are:

- a structured qlog event model and serializer
- a per-connection qlog file sink
- exact hook points in `QuicConnection`
- draft-correct qlog metadata and schema identifiers
- a small TLS telemetry surface for ALPN visibility
- a way to preserve packet snapshots for later `packet_lost` emission

## Scope

This design covers:

- `src/quic/core.h`
- `src/quic/connection.h`
- `src/quic/connection.cpp`
- `src/quic/protected_codec.h`
- `src/quic/protected_codec.cpp`
- `src/quic/tls_adapter.h`
- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/tls_adapter_boringssl.cpp`
- a new `src/quic/qlog/` module
- `build.zig`
- `tests/quic_core_test.cpp`
- a new `tests/quic_qlog_test.cpp`

## Non-Goals

- HTTP/3 qlog events
- HTTP/0.9 runtime or harness integration in the first slice
- the other 30 QUIC qlog events outside the chosen seven Core events
- `packet_dropped`, UDP datagram events, connection state events, or stream
  events
- raw packet payload logging via `raw.data`
- adding a general JSON dependency just for qlog
- changing the existing ad hoc trace environment variables

## Approaches Considered

### 1. Emit QLOG Only At The `QuicCore` Effect Layer

Observe `QuicCore::advance(...)` inputs and outputs and reconstruct qlog from
those higher-level effects.

Pros:

- minimizes changes to `QuicConnection`
- keeps logging close to the public core API

Cons:

- `QuicCoreEffect` is too high-level for faithful packet, loss, and recovery
  events
- cannot reliably produce parsed packet headers and frames
- cannot correctly attribute recovery updates or `packet_lost` causes

### 2. Extend The Existing Ad Hoc Packet Trace Into A “QLOG-Like” File

Reuse the `COQUIC_PACKET_TRACE` style and append more structured text to a
connection-local file.

Pros:

- smallest short-term code change
- low conceptual overhead

Cons:

- still not real qlog
- poor interoperability with qlog tooling
- would create a second observability format to maintain

### 3. Add A Real Per-Connection QLOG Session Inside `QuicConnection`

Create a focused qlog module, let `QuicConnection` own an optional session, and
emit draft-shaped qlog events directly at the packet, handshake, and recovery
hook points.

Pros:

- maps naturally to the connection-local qlog model
- has direct access to truthful packet and recovery state
- supports draft-correct metadata and file streaming
- isolates qlog formatting from transport logic

Cons:

- larger transport-side change than a pure shell around `QuicCore`
- requires a small TLS telemetry addition for ALPN

## Decision

Use approach 3.

Qlog will be implemented as a core-transport feature owned by `QuicConnection`,
backed by a narrow `src/quic/qlog/` module and an append-only sequential file
sink.

## Decisions

### 1. QLOG Is Opt-In Through `QuicCoreConfig`

Add a new optional qlog configuration to `src/quic/core.h`:

- `struct QuicQlogConfig { std::filesystem::path directory; }`
- `std::optional<QuicQlogConfig> qlog` on `QuicCoreConfig`

No environment variable, CLI flag, or HTTP/0.9 runtime-specific config is part
of this slice.

Rationale:

- qlog belongs to the core transport API
- the first slice should be usable by any caller of `QuicCore`
- avoiding env vars keeps feature enablement explicit and testable

### 2. Emit One `.sqlog` File Per `QuicConnection`

Each enabled connection emits one sequential qlog file:

- client: open when `start_client_if_needed()` begins the connection
- server: open lazily in `start_server_if_needed()` when the first accepted
  Initial determines the ODCID

The filename is:

- `<odcid>_client.sqlog`
- `<odcid>_server.sqlog`

Rationale:

- this follows the qlog draft recommendation to use ODCID for `group_id` and
  filename basis
- client and server traces remain separate while still being easy to pair

### 3. Use `QLogFileSeq` And Stream Events Incrementally

The output format is:

- `file_schema = "urn:ietf:params:qlog:file:sequential"`
- `serialization_format = "application/qlog+json-seq"`
- qlog preamble first
- RFC 7464 record-separated event lines afterward

Because the event schema is still a draft, the trace should advertise:

- `event_schemas = ["urn:ietf:params:qlog:events:quic-12"]`

not the final RFC URI.

Rationale:

- `QLogFileSeq` matches append-only connection-local logging
- the draft-specific event schema URI is the standards-correct choice until
  the RFC is published

### 4. Keep Trace Metadata Minimal And Truthful

The qlog preamble will contain:

- `common_fields.group_id = <odcid hex>`
- `common_fields.time_format = "relative_to_epoch"`
- `common_fields.reference_time = { "clock_type": "monotonic", "epoch": "unknown" }`
- `vantage_point.type = "client"` or `"server"`
- no `vantage_point.name` in the first slice

Event `time` values are float milliseconds relative to qlog session start.

Rationale:

- `QuicCore` uses a steady clock, not a wall clock
- using a monotonic reference avoids inventing timestamps the transport does
  not actually know
- omitting optional metadata keeps the first slice small

### 5. Implement Only The Seven Chosen Core Events

The first slice logs:

- `quic:version_information`
- `quic:alpn_information`
- `quic:parameters_set`
- `quic:packet_sent`
- `quic:packet_received`
- `quic:recovery_metrics_updated`
- `quic:packet_lost`

All other QUIC qlog events remain out of scope.

Rationale:

- this is the smallest slice that still produces “real qlog”
- these events cover handshake identity, transport parameters, packet flow,
  and recovery behavior

### 6. Split `parameters_set` By Initiator

`quic:parameters_set` will be emitted as separate local and remote events:

- local event with `initiator: "local"`
- remote event with `initiator: "remote"`

The first slice includes only transport parameters actually modeled by the core
today:

- `original_destination_connection_id`
- `initial_source_connection_id`
- `retry_source_connection_id`
- `max_idle_timeout`
- `max_udp_payload_size`
- `ack_delay_exponent`
- `max_ack_delay`
- `active_connection_id_limit`
- `initial_max_data`
- `initial_max_stream_data_bidi_local`
- `initial_max_stream_data_bidi_remote`
- `initial_max_stream_data_uni`
- `initial_max_streams_bidi`
- `initial_max_streams_uni`

The first slice omits:

- `tls_cipher`
- `preferred_address`
- `unknown_parameters`
- `max_datagram_frame_size`
- `grease_quic_bit`
- `resumption_allowed`
- `early_data_enabled`

Rationale:

- qlog requires the `initiator` field to be correct for the settings in a
  single event
- omitting unsupported fields is better than logging guessed values

### 7. Emit ALPN Information From Real TLS Telemetry

ALPN logging requires a small `TlsAdapter` telemetry addition:

- server side captures the client-offered ALPN list in the ALPN selection
  callback
- both TLS backends expose the negotiated ALPN once it is known

The public adapter surface for the first slice should be explicit:

- `const std::vector<std::vector<std::byte>> &peer_offered_application_protocols() const`
- `const std::optional<std::vector<std::byte>> &selected_application_protocol() const`

Because the current core config holds only one local ALPN string, local ALPN
offer and support lists are single-element arrays in the first slice.

ALPN values are logged with:

- `byte_value` always
- `string_value` only when the bytes are valid UTF-8

Rationale:

- the current transport does not otherwise expose enough information to emit
  truthful `alpn_information`
- using byte values avoids lossy assumptions about string encoding

### 8. Emit `packet_received` After Successful Decryption And Parse

`quic:packet_received` is emitted after a packet has been successfully parsed
from `deserialize_protected_datagram(...)`, but before
`process_inbound_packet(...)` mutates connection state.

All packets parsed from the same inbound UDP datagram share one inbound
`datagram_id`.

If a packet had been buffered earlier because keys were unavailable, the later
replayed `packet_received` event also carries:

- `trigger: "keys_available"`

To support this, deferred packets will store:

- packet bytes
- original inbound `datagram_id`

Malformed or undecryptable packets are not logged in the first slice because
`packet_dropped` is out of scope.

Rationale:

- successful parse gives the cleanest truthful packet view
- logging before state mutation avoids losing the event when later processing
  fails

### 9. Emit `packet_sent` Only After Successful Datagram Serialization

`quic:packet_sent` is emitted in `finalize_datagram()` after protected packet
serialization succeeds.

All packets inside one coalesced outbound datagram share one outbound
`datagram_id`.

This hook is chosen instead of `track_sent_packet()` so qlog also records:

- ACK-only packets
- other non-recovery-tracked sends

The first slice fills:

- `header`
- `frames`
- `raw.length`
- `datagram_id`

and omits:

- `raw.data`
- `raw.payload_length`

Rationale:

- qlog should reflect what was actually emitted on the wire
- recovery tracking is a subset of send activity, not the full send surface

### 10. Preserve A QLOG Packet Snapshot For Loss Reporting

For recovery-tracked sent packets, store a qlog snapshot alongside the existing
`SentPacketRecord`.

The snapshot contains:

- qlog packet header view
- qlog frame list
- `raw.length`
- `datagram_id`
- send-side qlog trigger, if any

`quic:packet_lost` reuses this stored snapshot instead of reconstructing data
later from `SentPacketRecord`.

Rationale:

- the current `SentPacketRecord` is not rich enough to rebuild truthful qlog
  packet details
- packet loss should point back to the real sent packet shape

### 11. Add A Protected Codec Helper That Returns Per-Packet Serialization Metadata

Protected packet serialization needs an explicit helper that returns:

- final datagram bytes
- per-packet protected length
- packet ordering within the datagram

The first slice does not rely on a second independent encoder or on ad hoc
length guesses after the fact.

Rationale:

- qlog `raw.length` must reflect the final protected packet length
- per-packet lengths are also needed to keep `packet_sent` truthful in coalesced
  datagrams

### 12. Keep Packet Header And Frame Scope Conservative

`packet_sent`, `packet_received`, and `packet_lost` use qlog-shaped packet
headers populated only with fields the transport can actually prove:

- `packet_type`
- `packet_number_length`
- `packet_number`
- long-header `version`
- long-header `scid`
- long-header `dcid`
- long-header `token`
- long-header `length`
- 1-RTT `spin_bit`
- 1-RTT `key_phase`
- 1-RTT `dcid` when available

Packet events log parsed frame arrays from the existing `Frame` model.

The first slice does not add qlog support for unknown frames or for raw frame
payload dumps.

Rationale:

- the transport already has these fields
- qlog consumers benefit more from correct partial packet data than from broad
  but guessed coverage

### 13. Restrict Recovery Metrics To A Safe, Already-Observable Subset

`quic:recovery_metrics_updated` emits only fields that are directly observable
from the current recovery and congestion controller state:

- `min_rtt`
- `smoothed_rtt`
- `latest_rtt`
- `rtt_variance`
- `pto_count`
- `congestion_window`
- `bytes_in_flight`

The first slice omits:

- `ssthresh`
- `packets_in_flight`
- `pacing_rate`

Metrics are emitted only when one or more values actually change.

Rationale:

- the current congestion controller surface does not expose every optional qlog
  field cleanly
- keeping the event diff-based avoids noisy logs

### 14. Keep Trigger Reporting Conservative

For `quic:packet_lost`, the first slice emits:

- `reordering_threshold` when ACK processing declares packet-threshold loss
- `time_threshold` when timer or ACK processing declares time-threshold loss

The first slice omits `pto_expired` unless explicit state is added that proves
the loss declaration came from that cause.

For `quic:packet_sent`, the first slice emits `trigger: "pto_probe"` only when
the send originates from an active PTO probe path. Other send-side qlog triggers
remain omitted until the transport preserves their cause explicitly.

Rationale:

- qlog triggers are useful only when they are accurate
- the current stack preserves enough state for some triggers but not all of
  them

## Architecture

### Public Core Configuration

`src/quic/core.h` gains a small qlog configuration:

- `struct QuicQlogConfig { std::filesystem::path directory; }`
- `std::optional<QuicQlogConfig> qlog`

The first slice keeps this intentionally narrow: an output directory is enough
to enable qlog for all connections created through the core API.

### New `src/quic/qlog/` Module

Add a focused qlog module with clear boundaries:

- `qlog_types`: internal DTOs for qlog events, packet headers, ALPN identifiers,
  and metrics snapshots
- `qlog_json`: manual JSON escaping and serialization helpers
- `qlog_sink`: append-only sequential file output
- `qlog_session`: per-connection session state, one-shot flags, timestamping,
  and high-level emit helpers

`QuicConnection` will call qlog helper methods but will not build JSON strings
inline.

### `QuicConnection` Ownership

`QuicConnection` owns an optional qlog session and keeps qlog-specific state:

- qlog session start time
- inbound and outbound `datagram_id` counters
- one-shot event flags
- last emitted recovery metrics snapshot
- deferred packet metadata with `datagram_id`

Recovery-tracked sent packets also gain an attached qlog packet snapshot for
later loss reporting.

### TLS Telemetry Boundary

`TlsAdapter` gains a small read-only telemetry surface for qlog:

- local or peer ALPN offer visibility as needed by role
- negotiated ALPN visibility once known

Both TLS backends implement this consistently. `QuicConnection` observes it
from `sync_tls_state()` and emits qlog when the relevant information becomes
available.

### Protected Codec Boundary

Protected packet serialization gains a helper that returns both:

- final datagram bytes
- per-packet protected lengths or spans

This keeps qlog `raw.length` aligned with the actual emitted packet bytes,
including coalesced datagrams and final protection overhead.

## Data Flow

### Session Creation

- client session opens in `start_client_if_needed()`
- server session opens in `start_server_if_needed()`
- preamble is written immediately when the sink opens successfully

Right after session creation, the connection emits:

- local `quic:version_information`
- local `quic:alpn_information`
- local `quic:parameters_set`

### Receive Path

Inbound datagram processing:

1. assign one inbound `datagram_id`
2. successfully parse one or more protected packets
3. emit `quic:packet_received` for each parsed packet
4. continue normal packet processing

Deferred packets preserve their original `datagram_id`. When replay succeeds,
their `packet_received` event includes `trigger: "keys_available"`.

### Parameter And ALPN Events

- remote `quic:parameters_set` is emitted once after
  `validate_peer_transport_parameters_if_ready()` succeeds
- missing `quic:alpn_information` fields are emitted from `sync_tls_state()`
  once TLS telemetry makes them available

### Send Path

Outbound datagram construction:

1. build candidate protected packets
2. serialize the final datagram and per-packet metadata
3. emit `quic:packet_sent` for each packet in that datagram
4. record qlog packet snapshots for recovery-tracked packets
5. return the datagram to the normal core send path

### Loss And Recovery

`quic:packet_lost` is emitted from both loss paths:

- ACK-driven loss in `process_inbound_ack()`
- timer-driven loss in `detect_lost_packets()`

`quic:recovery_metrics_updated` is emitted through one helper that snapshots the
current metrics, diffs them against the previously emitted snapshot, and writes
one grouped event when values changed.

The intended call sites are:

- end of `track_sent_packet()`
- end of `process_inbound_ack()`
- end of `detect_lost_packets()`
- end of `arm_pto_probe()`

## Error Handling

Qlog is strictly observational.

The following failures disable qlog for the current connection without failing
the connection itself:

- output directory creation failure
- file open failure
- preamble write failure
- later append failure

After disablement:

- qlog becomes a no-op for the connection
- no retries are attempted
- no `QuicCore` error is surfaced
- the transport continues unchanged

The first slice does not buffer qlog events waiting for a file to become
available later.

## Testing

### Unit Tests

Add `tests/quic_qlog_test.cpp` for qlog module tests covering:

- `QLogFileSeq` preamble shape
- JSON string escaping
- RFC 7464 record-separator framing
- omission of absent optional fields
- monotonic relative timestamp encoding
- draft event schema URI selection
- sink open and append failure disablement
- one-shot event suppression
- recovery metrics diff behavior

### Connection-Level Integration Tests

Add focused integration coverage in `tests/quic_core_test.cpp` for:

- client startup emitting local `version_information`, local `alpn_information`,
  and local `parameters_set`
- validated peer transport parameters emitting remote `parameters_set`
- successful send path emitting `packet_sent`
- successful receive path emitting `packet_received`
- deferred receive replay preserving `datagram_id` and logging
  `trigger: "keys_available"`
- ACK-driven or timer-driven loss emitting `packet_lost`
- PTO probe sends emitting `packet_sent` with `trigger: "pto_probe"`
- a short client and server handshake producing one `.sqlog` file per side
  named from ODCID plus vantage suffix

### Test Utilities

Tests should avoid adding a general JSON parser. The qlog files can be read as
record-separated lines and validated with small helpers that extract stable
fields such as:

- event `name`
- `group_id`
- `vantage_point.type`
- `event_schemas`

### Build Integration

Update `build.zig` to compile:

- the new qlog source files
- the new qlog test file or files

## Implementation Notes

This slice intentionally keeps the qlog surface narrow:

- no HTTP/0.9 harness wiring
- no HTTP/3 qlog events
- no broader QUIC qlog event coverage yet

If later slices add more qlog events, they should reuse the same connection
session, sink, and serializer rather than add a second observability path.

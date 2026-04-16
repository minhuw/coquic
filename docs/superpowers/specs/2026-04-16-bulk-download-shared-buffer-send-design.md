# Bulk Download Shared-Buffer Send Design

## Goal

Improve the `coquic-perf` bulk download case used by [perf.yml](/home/minhu/projects/coquic/.github/workflows/perf.yml) by removing avoidable payload allocation and copy work from the server send path, without changing QUIC wire behavior or recovery semantics.

## Current State

The current local bulk-download benchmark for the CI-aligned case:

- server: `./zig-out/bin/coquic-perf server --io-backend socket`
- client: `./zig-out/bin/coquic-perf client --mode bulk --direction download --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --warmup 0ms --duration 5s`

measured:

- baseline throughput: `57.464 MiB/s`
- sampled throughput during `perf record`: `58.641 MiB/s`

The server-side `perf` sample shows:

- `_aesni_ctr32_ghash_6x`: `39.11%`
- `memmove`: `5.08%`
- `append_protected_one_rtt_packet_to_datagram`: `4.14%`
- `malloc`: `1.97%`
- `append_bytes`: `1.95%`
- `append_stream_frame_payload_into`: `1.83%`

The dominant non-crypto cost is payload churn around the bulk response path:

1. [perf_server.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/perf/perf_server.cpp) builds a fresh `std::vector<std::byte>` for each response.
2. [connection.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/connection.cpp) queues that response through the normal stream-send API.
3. [crypto_stream.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/crypto_stream.cpp) copies the span again into a new shared storage vector inside `ReliableSendBuffer::append`.
4. [protected_codec.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/protected_codec.cpp) still copies payload bytes into the final datagram, which is expected for now.

The first two copies are avoidable for this workload.

## Non-Goals

- No change to QUIC packet formats, ACK behavior, loss recovery, or congestion control.
- No attempt to eliminate the final copy from stream payload into the protected datagram buffer.
- No generic kernel zero-copy send work.
- No broad redesign of all application send APIs in one step.
- No change to upload, `rr`, or `crr` behavior beyond sharing internal plumbing where needed.

## Design Summary

Add a shared-buffer stream-send path to the QUIC core so callers with already-owned shared storage can queue stream data without cloning payload bytes into a second heap allocation. Use that new path in `coquic-perf` bulk-download server responses by caching and reusing the fixed response payload buffer.

## Detailed Design

### 1. Add a shared-buffer send command alongside the existing owned-bytes command

Keep the existing `QuicCoreSendStreamData` path unchanged for current callers. Add a parallel connection input type for shared payloads rather than changing the meaning of the existing public struct.

This keeps the blast radius low:

- existing tests and application code that pass `std::vector<std::byte>` stay unchanged
- the new fast path is opt-in
- protocol behavior remains identical after data enters the send buffer

At the core/connection boundary:

- introduce a new send input carrying `SharedBytes`
- thread that new input through `QuicCoreConnectionInput` and `QuicCoreConnectionCommand`
- add a `QuicConnection::queue_stream_send_shared(...)` helper that validates the stream exactly like `queue_stream_send(...)`

Validation, FIN handling, stream-open rules, and zero-RTT bookkeeping must match the existing owned-bytes path.

### 2. Teach `ReliableSendBuffer` to adopt shared storage directly

`ReliableSendBuffer` already tracks byte ranges as slices into shared storage. The current inefficiency is that `append(std::span<const std::byte>)` always allocates a new vector before creating the segment.

Add an overload that accepts `SharedBytes` and stores that storage/slice directly in the appended segment.

Requirements:

- preserve current append ordering and offsets
- ignore empty non-FIN appends exactly as today
- keep segment splitting, loss marking, acknowledgment, and resend behavior unchanged
- keep storage lifetime tied to the existing `shared_ptr`

The existing span-based append remains in place for all current callers and can internally continue to allocate shared storage as it does today.

### 3. Cache the perf bulk-download response payload

For the `coquic-perf` server bulk-download mode with fixed `response_bytes`, create one cached payload buffer and reuse it for each response stream instead of allocating a new vector every time.

Scope:

- apply to the server-side bulk-download response path first
- use the shared-buffer send command for that path
- keep the finite-total-bytes download case on the existing owned-bytes path for now because the per-stream payload size varies
- keep upload, `rr`, and `crr` on the existing path for now

The cached payload should be built once per `QuicPerfServer` instance, since the perf server configuration is fixed for the life of the process.

### 4. Keep serializer behavior unchanged in this pass

The protected codec still serializes stream payload into the datagram buffer. That copy remains because it is part of assembling a contiguous protected packet buffer and is not the target of this pass.

This means the expected gain is:

- lower `memmove`
- lower allocator pressure (`malloc`, `operator new`)
- lower payload append overhead before AEAD protection

Crypto should remain the largest bucket after the change. That is acceptable.

## Correctness Constraints

- Shared payload storage must remain valid until all queued fragments that reference it are acknowledged or retired.
- Retransmission and loss recovery must continue to operate on the same logical byte ranges.
- `FIN` semantics must stay identical for owned and shared send paths.
- No caller may mutate a shared payload buffer after queuing it for send.

This design relies on immutable shared storage. The new API should document that callers hand off read-only payload ownership to the transport.

## Testing Strategy

### Unit and focused regression coverage

Add coverage for:

- `ReliableSendBuffer` appending from shared storage without cloning payload bytes
- loss/ack/split behavior still working for directly adopted shared storage
- the new QUIC core shared-send command producing the same wire-visible stream behavior as the owned-bytes command
- perf bulk-download server behavior still completing correctly when responses are sent through the shared-buffer path

### End-to-end verification

Run:

- focused QUIC/perf tests covering the new send path
- `nix develop -c zig build -Doptimize=ReleaseFast`
- the same local bulk-download harness used for profiling
- a fresh `perf` sample on the server side after the change

Success criteria:

- tests stay green
- throughput improves materially versus the fresh `57.464 MiB/s` baseline
- `memmove` and allocator share drop relative to the current profile

## Risks

### Lifetime bugs

If the shared payload buffer is released too early, retransmissions could read invalid memory. This is mitigated by routing all queued data through `ReliableSendBuffer`, which already owns payload lifetime via shared storage.

### API duplication

Adding a second send command can create drift if validation logic diverges. This is mitigated by centralizing both owned and shared paths behind the same connection-level validation/helper flow.

### Limited upside

The final datagram copy and AEAD work remain. This change should therefore be treated as a targeted reduction of pre-encryption overhead, not a full zero-copy solution.

## Decision

Proceed with the shared-buffer send path and cached bulk-download server payload. This is the lowest-risk change that directly attacks the largest fixable hotspot cluster from the current profile.

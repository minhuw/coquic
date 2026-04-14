# One-RTT Direct-Write Serializer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the allocator-heavy 1-RTT `stream_frame_views` serializer path with direct writes into the destination datagram buffer.

**Architecture:** Keep the existing non-stream-view serializer path unchanged, but rewrite the stream-view branch in `append_protected_one_rtt_packet_to_datagram_impl` so it serializes header and payload contiguously into `datagram`, then seals that plaintext with `seal_payload_into`. Preserve existing validation, offsets, rollback semantics, and wire output.

**Tech Stack:** C++, GoogleTest, Zig build/test, OpenSSL/BoringSSL packet protection backends

---

### Task 1: Add the regression test

**Files:**
- Modify: `tests/core/packets/protected_codec_test.cpp`
- Test: `tests/core/packets/protected_codec_test.cpp`

- [ ] **Step 1: Write the failing test**

Add a packet test that builds a 1-RTT packet using `stream_frame_views`,
injects `PacketCryptoFaultPoint::seal_payload_update` on occurrence `2`, and
expects append/serialize to succeed because the direct-write path should seal a
single contiguous plaintext span.

- [ ] **Step 2: Run test to verify it fails**

Run: `zig build test --filter ProtectedCodecTest.StreamViewPathUsesSinglePayloadSealUpdate`
Expected: FAIL because the current chunked path consumes multiple payload
update calls and returns `packet_protection_failed`.

- [ ] **Step 3: Write minimal implementation**

Replace the chunked `stream_frame_views` branch in
`src/quic/protected_codec.cpp` with direct serialization into the final
`datagram` buffer, then call `seal_payload_into` over the contiguous plaintext
span.

- [ ] **Step 4: Run test to verify it passes**

Run: `zig build test --filter ProtectedCodecTest.StreamViewPathUsesSinglePayloadSealUpdate`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/core/packets/protected_codec_test.cpp src/quic/protected_codec.cpp   docs/superpowers/specs/2026-04-13-one-rtt-direct-write-serializer-design.md   docs/superpowers/plans/2026-04-13-one-rtt-direct-write-serializer.md
git commit -m "perf: write one-rtt stream views directly into datagrams"
```

### Task 2: Preserve packet semantics

**Files:**
- Modify: `src/quic/protected_codec.cpp`
- Test: `tests/core/packets/protected_codec_test.cpp`

- [ ] **Step 1: Write the failing test**

Keep or extend the existing `AppendOneRttPacket...` stream-view tests if needed
to verify rollback and validation behavior still match the old path.

- [ ] **Step 2: Run test to verify it fails**

Run: `zig build test --filter ProtectedCodecTest.AppendOneRttPacket`
Expected: Any new regression test fails before the implementation is complete.

- [ ] **Step 3: Write minimal implementation**

Retain the current frame ordering and error propagation:
- reject lengthless `StreamFrame` entries before stream views
- propagate `serialize_frame` and varint failures with the same indices
- resize `datagram` back to its starting size on all failure paths

- [ ] **Step 4: Run test to verify it passes**

Run: `zig build test --filter ProtectedCodecTest.AppendOneRttPacket`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/quic/protected_codec.cpp tests/core/packets/protected_codec_test.cpp
git commit -m "test: keep one-rtt stream-view append semantics stable"
```

### Task 3: Verify and benchmark

**Files:**
- Modify: `src/quic/protected_codec.cpp` (only if follow-up fixes are needed)
- Test: `tests/core/packets/protected_codec_test.cpp`

- [ ] **Step 1: Run focused verification**

Run:
`zig build test --filter ProtectedCodecTest.OneRttPacketSerializesSharedStreamFrameViews`
`zig build test --filter ProtectedCodecTest.AppendOneRttPacket`

- [ ] **Step 2: Run build verification**

Run: `zig build -Doptimize=ReleaseFast`
Expected: exit code `0`

- [ ] **Step 3: Run the real bulk benchmark**

Run server:
`taskset -c 2 ./zig-out/bin/coquic-perf server --host 127.0.0.1 --port 9443 --certificate-chain tests/fixtures/quic-server-cert.pem --private-key tests/fixtures/quic-server-key.pem --io-backend socket`

Run client:
`taskset -c 3 ./zig-out/bin/coquic-perf client --host 127.0.0.1 --port 9443 --mode bulk --direction download --io-backend socket --request-bytes 0 --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --warmup 5s --duration 20s --json-out /tmp/coquic-bulk-after-direct-write.json`

- [ ] **Step 4: Record results**

Compare the new bulk throughput with the cache-only baseline and inspect `perf`
again if packet construction remains the dominant hotspot.

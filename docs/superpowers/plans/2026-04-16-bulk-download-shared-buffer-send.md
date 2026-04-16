# Bulk Download Shared-Buffer Send Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce avoidable allocation and copy overhead in the `coquic-perf` bulk download server path by adopting shared payload storage inside QUIC stream send buffers and reusing cached response payload storage for fixed-size downloads.

**Architecture:** Add a new shared-buffer append path to `ReliableSendBuffer`, then plumb an opt-in shared stream-send command through `QuicConnection` and `QuicCore` without changing the existing owned-bytes API. Finally, teach `QuicPerfServer` to cache fixed-size bulk download payloads by response size and send them through the new shared-buffer path, then verify the exact local benchmark and `perf` profile improve relative to the fresh baseline.

**Tech Stack:** C++20, GoogleTest, Zig build, Linux `perf`, OpenSSL/AES-GCM QUIC packet protection

---

### Task 1: Let `ReliableSendBuffer` Adopt Shared Storage Without Cloning

**Files:**
- Modify: `src/quic/crypto_stream.h`
- Modify: `src/quic/crypto_stream.cpp`
- Test: `tests/core/streams/crypto_stream_test.cpp`

- [ ] **Step 1: Write the failing tests for shared-buffer append semantics**

Add these tests to `tests/core/streams/crypto_stream_test.cpp`:

```cpp
TEST(QuicCryptoStreamTest, SharedAppendReusesCallerStorageWithoutCloning) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));
    const SharedBytes shared(storage, 1, 5);

    buffer.append(shared);

    ASSERT_EQ(buffer.segments_.size(), 1u);
    const auto &segment = buffer.segments_.begin()->second;
    EXPECT_EQ(buffer.segments_.begin()->first, 0u);
    EXPECT_EQ(segment.storage, storage);
    EXPECT_EQ(segment.begin, 1u);
    EXPECT_EQ(segment.end, 5u);

    const auto ranges = buffer.take_ranges(4);
    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(ranges[0].offset, 0u);
    EXPECT_EQ(ranges[0].bytes, bytes_from_string("bcde"));
    EXPECT_EQ(ranges[0].bytes.storage().get(), storage.get());
    EXPECT_EQ(ranges[0].bytes.begin_offset(), 1u);
    EXPECT_EQ(ranges[0].bytes.end_offset(), 5u);
}

TEST(QuicCryptoStreamTest, SharedAppendPreservesAckAndLossBookkeeping) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));

    buffer.append(SharedBytes(storage, 0, 6));

    const auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].bytes.storage().get(), storage.get());

    buffer.acknowledge(1, 2);
    buffer.mark_lost(0, 4);

    const auto retransmit = buffer.take_ranges(2);
    ASSERT_EQ(retransmit.size(), 2u);
    EXPECT_EQ(retransmit[0].offset, 0u);
    EXPECT_EQ(retransmit[0].bytes, bytes_from_string("a"));
    EXPECT_EQ(retransmit[0].bytes.storage().get(), storage.get());
    EXPECT_EQ(retransmit[1].offset, 3u);
    EXPECT_EQ(retransmit[1].bytes, bytes_from_string("d"));
    EXPECT_EQ(retransmit[1].bytes.storage().get(), storage.get());
}
```

- [ ] **Step 2: Run the focused stream-buffer tests to confirm the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCryptoStreamTest.SharedAppendReusesCallerStorageWithoutCloning:QuicCryptoStreamTest.SharedAppendPreservesAckAndLossBookkeeping'
```

Expected: build/test fails because `ReliableSendBuffer` does not yet have an `append(SharedBytes)` overload.

- [ ] **Step 3: Implement the shared-storage append overload**

Update `src/quic/crypto_stream.h` so `ReliableSendBuffer` exposes both append paths:

```cpp
class ReliableSendBuffer {
  public:
    void append(std::span<const std::byte> bytes);
    void append(SharedBytes bytes);
    std::vector<ByteRange> take_ranges(std::size_t max_bytes);
    std::vector<ByteRange> take_lost_ranges(std::size_t max_bytes,
                                            std::optional<std::uint64_t> max_offset = std::nullopt);
    std::vector<ByteRange>
    take_unsent_ranges(std::size_t max_bytes,
                       std::optional<std::uint64_t> max_offset = std::nullopt);
```

Update `src/quic/crypto_stream.cpp` so the span-based path allocates once and forwards into the new shared path:

```cpp
void ReliableSendBuffer::append(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    auto storage = std::make_shared<std::vector<std::byte>>(bytes.begin(), bytes.end());
    append(SharedBytes{std::move(storage), 0, bytes.size()});
}

void ReliableSendBuffer::append(SharedBytes bytes) {
    if (bytes.empty()) {
        return;
    }

    segments_.emplace(next_append_offset_, Segment{
                                               .state = SegmentState::unsent,
                                               .storage = bytes.storage(),
                                               .begin = bytes.begin_offset(),
                                               .end = bytes.end_offset(),
                                           });
    next_append_offset_ += static_cast<std::uint64_t>(bytes.size());
    merge_adjacent_segments();
}
```

- [ ] **Step 4: Re-run focused tests plus the existing send-buffer regression slice**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCryptoStreamTest.SharedAppendReusesCallerStorageWithoutCloning:QuicCryptoStreamTest.SharedAppendPreservesAckAndLossBookkeeping:QuicCryptoStreamTest.TakeRangesReusesUnderlyingSegmentStorage:QuicCryptoStreamTest.PartialAcksRetireOnlyAcknowledgedSubrange'
```

Expected: PASS with all four tests green.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add src/quic/crypto_stream.h src/quic/crypto_stream.cpp tests/core/streams/crypto_stream_test.cpp
SKIP=coquic-clang-tidy git commit -m "fix: adopt shared send buffer storage"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 2: Plumb Shared Stream Sends Through `QuicConnection` And `QuicCore`

**Files:**
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Test: `tests/core/endpoint/open_test.cpp`
- Test: `tests/core/endpoint/multiplex_test.cpp`

- [ ] **Step 1: Add failing endpoint tests for the new shared send command**

Add this test to `tests/core/endpoint/open_test.cpp`:

```cpp
TEST(QuicCoreEndpointTest, SharedSendCommandUsesConnectionHandleWithoutLegacyFallback) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendSharedStreamData{
                    .stream_id = 0,
                    .bytes = coquic::quic::SharedBytes(
                        coquic::quic::test::bytes_from_string("hello")),
                    .fin = false,
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(result.local_error.has_value());
    EXPECT_EQ(result.local_error->connection,
              std::optional<coquic::quic::QuicConnectionHandle>{1u});
    EXPECT_EQ(result.local_error->code, coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id);
}
```

Add this test to `tests/core/endpoint/multiplex_test.cpp`:

```cpp
TEST(QuicCoreEndpointTest, SharedSendCommandProducesSameDatagramAsOwnedSendCommand) {
    const auto make_ready_core = [] {
        coquic::quic::QuicCore core(make_client_endpoint_config());
        static_cast<void>(core.advance_endpoint(
            coquic::quic::QuicCoreOpenConnection{
                .connection = make_client_open_config(1),
                .initial_route_handle = 11,
            },
            coquic::quic::test::test_time(0)));

        *core.connections_.at(1).connection = make_connected_client_connection();
        core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
        core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
        return core;
    };

    auto owned_core = make_ready_core();
    auto shared_core = make_ready_core();

    const auto owned = owned_core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_ints({0x68, 0x69, 0x21}),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(1));
    const auto shared = shared_core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendSharedStreamData{
                    .stream_id = 0,
                    .bytes = coquic::quic::SharedBytes(bytes_from_ints({0x68, 0x69, 0x21})),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(1));

    const auto owned_sends = send_effects_from(owned);
    const auto shared_sends = send_effects_from(shared);
    ASSERT_EQ(owned_sends.size(), shared_sends.size());
    ASSERT_FALSE(owned_sends.empty());
    EXPECT_EQ(shared_sends.front().route_handle, owned_sends.front().route_handle);
    EXPECT_EQ(shared_sends.front().bytes, owned_sends.front().bytes);
}
```

- [ ] **Step 2: Run the focused endpoint slice to confirm the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.SharedSendCommandUsesConnectionHandleWithoutLegacyFallback:QuicCoreEndpointTest.SharedSendCommandProducesSameDatagramAsOwnedSendCommand'
```

Expected: build/test fails because `QuicCoreSendSharedStreamData` and the shared send plumbing do not exist yet.

- [ ] **Step 3: Add the shared send input type and route it through connection/core**

Update `src/quic/core.h`:

```cpp
#include "src/quic/crypto_stream.h"

struct QuicCoreSendStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCoreSendSharedStreamData {
    std::uint64_t stream_id = 0;
    SharedBytes bytes;
    bool fin = false;
};

using QuicCoreConnectionInput =
    std::variant<QuicCoreSendStreamData, QuicCoreSendSharedStreamData, QuicCoreResetStream,
                 QuicCoreStopSending, QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                 QuicCoreRequestConnectionMigration>;

using QuicCoreInput =
    std::variant<QuicCoreStart, QuicCoreInboundDatagram, QuicCoreSendStreamData,
                 QuicCoreSendSharedStreamData, QuicCoreResetStream, QuicCoreStopSending,
                 QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                 QuicCoreRequestConnectionMigration, QuicCoreTimerExpired>;
```

Update `src/quic/connection.h`:

```cpp
    StreamStateResult<bool> queue_stream_send(std::uint64_t stream_id,
                                              std::span<const std::byte> bytes, bool fin);
    StreamStateResult<bool> queue_stream_send_shared(std::uint64_t stream_id, SharedBytes bytes,
                                                     bool fin);
  private:
    StreamStateResult<bool>
    queue_stream_send_impl(std::uint64_t stream_id, std::span<const std::byte> owned_bytes,
                           std::optional<SharedBytes> shared_bytes, bool fin);
```

Update `src/quic/connection.cpp` by centralizing the validation and append logic in a private member:

```cpp
StreamStateResult<bool>
QuicConnection::queue_stream_send_impl(std::uint64_t stream_id,
                                       std::span<const std::byte> owned_bytes,
                                       std::optional<SharedBytes> shared_bytes, bool fin) {
    if (status_ == HandshakeStatus::failed ||
        (owned_bytes.empty() && (!shared_bytes.has_value() || shared_bytes->empty()) && !fin)) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_send(fin);
    if (!validated.has_value()) {
        return validated;
    }

    if (shared_bytes.has_value() && !shared_bytes->empty()) {
        stream->send_buffer.append(*shared_bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(shared_bytes->size());
    } else if (!owned_bytes.empty()) {
        stream->send_buffer.append(owned_bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(owned_bytes.size());
    }

    if (fin) {
        stream->send_final_size = stream->send_flow_control_committed;
        stream->send_fin_state = StreamSendFinState::pending;
    }

    const bool should_emit_zero_rtt_attempt =
        (config_.role == EndpointRole::client) & config_.zero_rtt.attempt &
        decoded_resumption_state_.has_value() & zero_rtt_space_.write_secret.has_value() &
        (status_ != HandshakeStatus::connected) & !zero_rtt_attempted_event_emitted_;
    if (should_emit_zero_rtt_attempt) {
        pending_zero_rtt_status_event_ =
            QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::attempted};
        zero_rtt_attempted_event_emitted_ = true;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stream_send(std::uint64_t stream_id,
                                                          std::span<const std::byte> bytes,
                                                          bool fin) {
    return queue_stream_send_impl(stream_id, bytes, std::nullopt, fin);
}

StreamStateResult<bool> QuicConnection::queue_stream_send_shared(std::uint64_t stream_id,
                                                                 SharedBytes bytes, bool fin) {
    return queue_stream_send_impl(stream_id, {}, std::move(bytes), fin);
}
```

Update both `std::visit` call sites in `src/quic/core.cpp` to handle the new variant:

```cpp
                [&](const QuicCoreSendSharedStreamData &in) {
                    const auto queued =
                        entry.connection->queue_stream_send_shared(in.stream_id, in.bytes, in.fin);
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
```

and:

```cpp
            [&](const QuicCoreSendSharedStreamData &in) {
                const auto queued =
                    connection->queue_stream_send_shared(in.stream_id, in.bytes, in.fin);
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
```

- [ ] **Step 4: Run the focused endpoint tests plus existing connection-command coverage**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.SharedSendCommandUsesConnectionHandleWithoutLegacyFallback:QuicCoreEndpointTest.SharedSendCommandProducesSameDatagramAsOwnedSendCommand:QuicCoreEndpointTest.ConnectionCommandsOnlyAdvanceTheSelectedHandle'
```

Expected: PASS with all three endpoint tests green.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add src/quic/core.h src/quic/core.cpp src/quic/connection.h src/quic/connection.cpp tests/core/endpoint/open_test.cpp tests/core/endpoint/multiplex_test.cpp
SKIP=coquic-clang-tidy git commit -m "fix: plumb shared stream sends through quic core"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 3: Cache Fixed-Size Perf Download Payloads And Re-Measure

**Files:**
- Modify: `src/perf/perf_server.h`
- Modify: `src/perf/perf_server.cpp`
- Test: `tests/perf/server_test.cpp`
- Test: `tests/perf/bulk_test.cpp`

- [ ] **Step 1: Add a failing cache-focused perf server test**

Add this test to `tests/perf/server_test.cpp`:

```cpp
TEST(QuicPerfServerTest, FixedDownloadPayloadCacheReusesSharedStorageBySize) {
    const QuicPerfConfig config{
        .role = QuicPerfRole::server,
        .host = "127.0.0.1",
        .port = 9443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    QuicPerfServer server(config, std::unique_ptr<coquic::io::QuicIoBackend>{});

    const auto first = server.cached_download_payload(4096);
    const auto second = server.cached_download_payload(4096);
    const auto other = server.cached_download_payload(2048);

    ASSERT_NE(first.storage(), nullptr);
    ASSERT_NE(second.storage(), nullptr);
    ASSERT_NE(other.storage(), nullptr);
    EXPECT_EQ(first.storage().get(), second.storage().get());
    EXPECT_NE(first.storage().get(), other.storage().get());
    EXPECT_EQ(first.size(), 4096u);
    EXPECT_EQ(other.size(), 2048u);
}
```

- [ ] **Step 2: Run the focused perf tests to confirm the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicPerfServerTest.FixedDownloadPayloadCacheReusesSharedStorageBySize:QuicPerfBulkTest.TimedDownloadUsesMeasurementWindow:QuicPerfBulkTest.TimedDownloadCountsBytesFromStreamsThatSpanWarmupBoundary'
```

Expected: build/test fails because `QuicPerfServer` does not yet expose a fixed-download payload cache helper.

- [ ] **Step 3: Implement the per-size shared payload cache and switch the fixed download path to it**

Update `src/perf/perf_server.h`:

```cpp
#include "src/quic/crypto_stream.h"

class QuicPerfServer {
  public:
    QuicPerfServer(const QuicPerfConfig &config, std::unique_ptr<io::QuicIoBackend> backend);
    int run();

  private:
    struct Session {
        quic::QuicConnectionHandle connection = 0;
        std::vector<std::byte> control_bytes;
        std::optional<QuicPerfSessionStart> start;
        bool ready_sent = false;
        std::uint64_t bytes_sent = 0;
        std::uint64_t bytes_received = 0;
        std::uint64_t requests_completed = 0;
    };

    quic::SharedBytes cached_download_payload(std::size_t bytes);
    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now);
    bool handle_stream_data(Session &session, const quic::QuicCoreReceiveStreamData &received,
                            quic::QuicCoreTimePoint now);
    bool send_control(Session &session, const QuicPerfControlMessage &message);

    QuicPerfConfig config_;
    quic::QuicCore core_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    std::unordered_map<quic::QuicConnectionHandle, Session> sessions_;
    std::unordered_map<std::size_t, quic::SharedBytes> download_payload_cache_;
};
```

Update `src/perf/perf_server.cpp`:

```cpp
quic::SharedBytes QuicPerfServer::cached_download_payload(std::size_t bytes) {
    if (bytes == 0) {
        return {};
    }

    const auto [it, inserted] = download_payload_cache_.try_emplace(bytes);
    if (inserted) {
        it->second = quic::SharedBytes(std::vector<std::byte>(bytes, std::byte{0x5a}));
    }
    return it->second;
}
```

Replace the fixed-size bulk download response send in `handle_stream_data`:

```cpp
        if (session.start->mode == QuicPerfMode::bulk &&
            session.start->direction == QuicPerfDirection::download &&
            !session.start->total_bytes.has_value() && received.fin) {
            const auto response_bytes = static_cast<std::size_t>(session.start->response_bytes);
            const auto send_result = core_.advance_endpoint(
                quic::QuicCoreConnectionCommand{
                    .connection = session.connection,
                    .input =
                        quic::QuicCoreSendSharedStreamData{
                            .stream_id = received.stream_id,
                            .bytes = cached_download_payload(response_bytes),
                            .fin = true,
                        },
                },
                now);
            if (send_result.local_error.has_value() || !flush_send_effects(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += response_bytes;
            return true;
        }
```

- [ ] **Step 4: Run focused perf regressions, rebuild the release binary, and re-measure the exact benchmark**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicPerfServerTest.FixedDownloadPayloadCacheReusesSharedStorageBySize:QuicPerfBulkTest.TimedDownloadUsesMeasurementWindow:QuicPerfBulkTest.TimedDownloadCountsBytesFromStreamsThatSpanWarmupBoundary'
```

Expected: PASS with all three tests green.

Run:

```bash
nix develop -c zig build -Doptimize=ReleaseFast
```

Expected: PASS with exit code `0`.

Run the exact local bulk-download harness:

```bash
bash -lc 'set -euo pipefail
port=9571
server_log=$(mktemp)
json_out=$(mktemp)
cleanup() {
  if [ -n "${server_pid:-}" ]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
taskset -c 2 ./zig-out/bin/coquic-perf server --host 127.0.0.1 --port "$port" --certificate-chain tests/fixtures/quic-server-cert.pem --private-key tests/fixtures/quic-server-key.pem --io-backend socket >"$server_log" 2>&1 &
server_pid=$!
sleep 1
taskset -c 3 ./zig-out/bin/coquic-perf client --host 127.0.0.1 --port "$port" --mode bulk --io-backend socket --request-bytes 0 --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --direction download --warmup 0ms --duration 5s --json-out "$json_out"
cat "$json_out"'
```

Expected: PASS with valid JSON output. Prefer a throughput above the fresh `57.464 MiB/s` baseline; if the first rerun lands within `1 MiB/s` of that baseline in either direction, rerun once before treating it as a miss.

Run a fresh server-side `perf` sample on the same case:

```bash
bash -lc 'set -euo pipefail
port=9572
server_log=$(mktemp)
perf_log=$(mktemp)
perf_data=/tmp/coquic-bulk-shared-send.perf.data
json_out=$(mktemp)
cleanup() {
  if [ -n "${perf_pid:-}" ]; then
    wait "$perf_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "${server_pid:-}" ]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
rm -f "$perf_data"
taskset -c 2 ./zig-out/bin/coquic-perf server --host 127.0.0.1 --port "$port" --certificate-chain tests/fixtures/quic-server-cert.pem --private-key tests/fixtures/quic-server-key.pem --io-backend socket >"$server_log" 2>&1 &
server_pid=$!
sleep 1
sudo perf record -F 799 -g --call-graph dwarf,16384 -p "$server_pid" -o "$perf_data" -- sleep 8 >"$perf_log" 2>&1 &
perf_pid=$!
sleep 1
taskset -c 3 ./zig-out/bin/coquic-perf client --host 127.0.0.1 --port "$port" --mode bulk --io-backend socket --request-bytes 0 --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --direction download --warmup 0ms --duration 5s --json-out "$json_out"
wait "$perf_pid"
sudo perf report -f --stdio --no-inline --no-children --percent-limit 0.5 -i "$perf_data" --sort overhead,comm,dso,symbol | sed -n "1,80p"'
```

Expected: PASS with the bulk run completing, and `memmove`/allocator overhead lower than the current `5.08%` `memmove` + `1.97%` `malloc` baseline profile.

- [ ] **Step 5: Commit Task 3**

Run:

```bash
git add src/perf/perf_server.h src/perf/perf_server.cpp tests/perf/server_test.cpp
SKIP=coquic-clang-tidy git commit -m "fix: reuse perf bulk download payload storage"
```

Expected: commit succeeds and `git status --short` is clean.

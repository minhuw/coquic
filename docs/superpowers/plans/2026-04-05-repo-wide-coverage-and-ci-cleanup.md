# Repo-Wide Coverage And CI Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise the current CI target to literal repo-wide `100%` line, branch, and region coverage while preserving behavior and keeping the existing CI lint path clean.

**Architecture:** Close the remaining gaps where they already belong: qlog helper coverage in `tests/quic_qlog_test.cpp`, connection edge coverage in `tests/quic_core_test.cpp`, and TLS ALPN edge coverage in `tests/quic_tls_adapter_contract_test.cpp`. Add one narrow qlog session seam so tests can deterministically force the preamble-write failure path without weakening the production `Session::try_open(...)` API.

**Tech Stack:** C++20, GoogleTest, Zig build, Nix dev shell, LLVM source-based coverage, pre-commit `clang-format`, pre-commit `clang-tidy`

---

### Task 1: Close QLOG Coverage With A Minimal Session Test Seam

**Files:**
- Modify: `src/quic/qlog/session.h`
- Modify: `src/quic/qlog/session.cpp`
- Modify: `tests/quic_qlog_test.cpp`

- [ ] **Step 1: Write the failing qlog tests**

Add these tests to `tests/quic_qlog_test.cpp` and keep them in the existing `QuicQlogTest` suite.

```cpp
#include <array>
#include <optional>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/qlog/session.h"
#include "tests/quic_test_utils.h"

namespace {

std::vector<std::byte> qlog_bytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

TEST(QuicQlogTest, SessionInjectedSinkCoversPreambleFailureAndIdempotentFlags) {
    using coquic::quic::EndpointRole;
    using coquic::quic::qlog::Session;

    auto failing_sink = std::make_unique<QlogFileSeqSink>(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(failing_sink->open());
    EXPECT_EQ(Session::try_open_with_sink_for_test(
                  std::move(failing_sink), EndpointRole::client,
                  qlog_bytes({0x83, 0x94, 0xc8, 0xf0}), coquic::quic::test::test_time(0)),
              nullptr);

    coquic::quic::test::ScopedTempDir dir;
    auto healthy_sink = std::make_unique<QlogFileSeqSink>(dir.path() / "session.sqlog");
    ASSERT_TRUE(healthy_sink->open());
    auto session = Session::try_open_with_sink_for_test(
        std::move(healthy_sink), EndpointRole::server, qlog_bytes({0x01, 0x02, 0x03, 0x04}),
        coquic::quic::test::test_time(10));
    ASSERT_NE(session, nullptr);

    EXPECT_TRUE(session->mark_local_version_information_emitted());
    EXPECT_FALSE(session->mark_local_version_information_emitted());
    EXPECT_TRUE(session->mark_local_alpn_information_emitted());
    EXPECT_FALSE(session->mark_local_alpn_information_emitted());
    EXPECT_TRUE(session->mark_local_parameters_set_emitted());
    EXPECT_FALSE(session->mark_local_parameters_set_emitted());
    EXPECT_TRUE(session->mark_remote_parameters_set_emitted());
    EXPECT_FALSE(session->mark_remote_parameters_set_emitted());
}

TEST(QuicQlogTest, SerializersCoverRemainingFramesAndOptionalFields) {
    using coquic::quic::AckFrame;
    using coquic::quic::ApplicationConnectionCloseFrame;
    using coquic::quic::ConnectionId;
    using coquic::quic::CryptoFrame;
    using coquic::quic::DataBlockedFrame;
    using coquic::quic::EndpointRole;
    using coquic::quic::Frame;
    using coquic::quic::HandshakeDoneFrame;
    using coquic::quic::MaxDataFrame;
    using coquic::quic::MaxStreamDataFrame;
    using coquic::quic::MaxStreamsFrame;
    using coquic::quic::NewConnectionIdFrame;
    using coquic::quic::NewTokenFrame;
    using coquic::quic::PathChallengeFrame;
    using coquic::quic::PathResponseFrame;
    using coquic::quic::ResetStreamFrame;
    using coquic::quic::RetireConnectionIdFrame;
    using coquic::quic::StopSendingFrame;
    using coquic::quic::StreamDataBlockedFrame;
    using coquic::quic::StreamLimitType;
    using coquic::quic::StreamsBlockedFrame;
    using coquic::quic::TransportConnectionCloseFrame;
    using coquic::quic::qlog::PacketHeader;
    using coquic::quic::qlog::PacketSnapshot;
    using coquic::quic::qlog::RecoveryMetricsSnapshot;

    const auto snapshot = PacketSnapshot{
        .header =
            PacketHeader{
                .packet_type = "1RTT",
                .packet_number_length = 2,
                .packet_number = 7,
                .version = 1,
                .length = 42,
                .spin_bit = true,
                .key_phase = 1,
                .scid = ConnectionId(qlog_bytes({0x01, 0x02})),
                .dcid = ConnectionId(qlog_bytes({0x03, 0x04})),
                .token = qlog_bytes({0xaa, 0xbb}),
            },
        .frames =
            std::vector<Frame>{
                ResetStreamFrame{.stream_id = 1, .application_protocol_error_code = 2, .final_size = 3},
                StopSendingFrame{.stream_id = 4, .application_protocol_error_code = 5},
                CryptoFrame{.offset = 6, .crypto_data = qlog_bytes({0xcc, 0xdd})},
                NewTokenFrame{.token = qlog_bytes({0xee})},
                MaxDataFrame{.maximum_data = 7},
                MaxStreamDataFrame{.stream_id = 8, .maximum_stream_data = 9},
                MaxStreamsFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 10},
                DataBlockedFrame{.maximum_data = 11},
                StreamDataBlockedFrame{.stream_id = 12, .maximum_stream_data = 13},
                StreamsBlockedFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 14},
                NewConnectionIdFrame{
                    .sequence_number = 15,
                    .retire_prior_to = 1,
                    .connection_id = qlog_bytes({0xab, 0xcd}),
                    .stateless_reset_token = {},
                },
                RetireConnectionIdFrame{.sequence_number = 16},
                PathChallengeFrame{.data = {std::byte{0}, std::byte{1}, std::byte{2}, std::byte{3},
                                            std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}}},
                PathResponseFrame{.data = {std::byte{7}, std::byte{6}, std::byte{5}, std::byte{4},
                                           std::byte{3}, std::byte{2}, std::byte{1}, std::byte{0}}},
                TransportConnectionCloseFrame{.error_code = 17, .frame_type = 18},
                ApplicationConnectionCloseFrame{.error_code = 19},
                HandshakeDoneFrame{},
                AckFrame{.largest_acknowledged = 20, .ack_delay = 21},
            },
        .raw_length = 1200,
        .datagram_id = 77,
        .trigger = std::string("pto_probe"),
    };
    const auto snapshot_json = coquic::quic::qlog::serialize_packet_snapshot(snapshot);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"reset_stream\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"stop_sending\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"crypto\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"new_token\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"max_data\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"max_stream_data\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"max_streams\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"data_blocked\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"stream_data_blocked\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"streams_blocked\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"new_connection_id\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"retire_connection_id\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"path_challenge\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"path_response\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"connection_close_transport\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"connection_close_application\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"handshake_done\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"spin_bit\":true"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"key_phase\":1"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"scid\":\"0102\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"dcid\":\"0304\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"token\":\"aabb\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"datagram_id\":77"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"trigger\":\"pto_probe\""), std::string::npos);

    const auto binary_alpn = std::vector<std::byte>{std::byte{0x00}, std::byte{0xff}};
    const auto printable_alpn = qlog_bytes({0x63, 0x6f, 0x71, 0x75, 0x69, 0x63});
    const std::array local_alpns{binary_alpn};
    const std::array peer_alpns{printable_alpn};
    const auto binary_only_alpn_json = coquic::quic::qlog::serialize_alpn_information(
        std::span(local_alpns), std::nullopt, std::span(binary_alpn), EndpointRole::client);
    EXPECT_EQ(binary_only_alpn_json.find("\"string_value\""), std::string::npos);

    const auto alpn_json = coquic::quic::qlog::serialize_alpn_information(
        std::span(local_alpns), std::span(peer_alpns), std::span(binary_alpn), EndpointRole::client);
    EXPECT_NE(alpn_json.find("\"client_alpns\""), std::string::npos);
    EXPECT_NE(alpn_json.find("\"server_alpns\""), std::string::npos);
    EXPECT_NE(alpn_json.find("\"chosen_alpn\""), std::string::npos);

    EXPECT_EQ(coquic::quic::qlog::escape_json_string("a\r\t"), "a\\r\\t");
    const std::array<std::uint32_t, 2> versions{1, 2};
    EXPECT_EQ(coquic::quic::qlog::serialize_version_information(
                  EndpointRole::server, versions, std::nullopt),
              "{\"server_versions\":[1,2]}");

    EXPECT_EQ(coquic::quic::qlog::serialize_recovery_metrics(RecoveryMetricsSnapshot{}), "{}");
    const auto metrics_json = coquic::quic::qlog::serialize_recovery_metrics(RecoveryMetricsSnapshot{
        .min_rtt_ms = 1.5,
        .smoothed_rtt_ms = 2.5,
        .latest_rtt_ms = 3.5,
        .rtt_variance_ms = 4.5,
        .pto_count = 2,
        .congestion_window = 4096,
        .bytes_in_flight = 512,
    });
    EXPECT_NE(metrics_json.find("\"min_rtt\":1.500000"), std::string::npos);
    EXPECT_NE(metrics_json.find("\"bytes_in_flight\":512"), std::string::npos);
}

TEST(QuicQlogTest, SinkPathAndDisabledWritesRemainObservable) {
    coquic::quic::test::ScopedTempDir dir;
    QlogFileSeqSink sink(dir.path() / "trace.sqlog");
    ASSERT_TRUE(sink.open());
    EXPECT_EQ(sink.path(), dir.path() / "trace.sqlog");
    EXPECT_TRUE(sink.write_record("\x1e{\"time\":0}\n"));

    QlogFileSeqSink full_sink(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(full_sink.open());
    EXPECT_FALSE(full_sink.write_record("\x1e{\"time\":1}\n"));
    EXPECT_FALSE(full_sink.write_record("\x1e{\"time\":2}\n"));
}

} // namespace
```

- [ ] **Step 2: Run the focused qlog suite and verify the red phase**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicQlogTest.*
```

Expected: FAIL to compile because `Session::try_open_with_sink_for_test(...)` does not exist yet.

- [ ] **Step 3: Add the minimal qlog session seam**

Update `src/quic/qlog/session.h`:

```cpp
class Session {
  public:
    static std::unique_ptr<Session> try_open(const QuicQlogConfig &config, EndpointRole role,
                                             const ConnectionId &odcid,
                                             QuicCoreTimePoint start_time);
    static std::unique_ptr<Session> try_open_with_sink_for_test(
        std::unique_ptr<QlogFileSeqSink> sink, EndpointRole role, const ConnectionId &odcid,
        QuicCoreTimePoint start_time);
```

Update `src/quic/qlog/session.cpp`:

```cpp
namespace {

std::unique_ptr<Session> try_open_with_sink(std::unique_ptr<QlogFileSeqSink> sink,
                                            EndpointRole role, const ConnectionId &odcid,
                                            QuicCoreTimePoint start_time) {
    const auto suffix = role == EndpointRole::client ? "client" : "server";
    const auto odcid_hex = format_connection_id_hex(odcid);
    if (sink == nullptr || !sink->healthy()) {
        return nullptr;
    }

    const auto preamble = serialize_file_seq_preamble(FilePreamble{
        .title = "coquic qlog",
        .description = "core QUIC trace",
        .group_id = odcid_hex,
        .vantage_point_type = suffix,
        .event_schemas = {"urn:ietf:params:qlog:events:quic-12"},
    });
    if (!sink->write_record(make_json_seq_record(preamble))) {
        return nullptr;
    }

    return std::unique_ptr<Session>(new Session(start_time, std::move(sink)));
}

} // namespace

std::unique_ptr<Session> Session::try_open(const QuicQlogConfig &config, EndpointRole role,
                                           const ConnectionId &odcid,
                                           QuicCoreTimePoint start_time) {
    const auto suffix = role == EndpointRole::client ? "client" : "server";
    const auto odcid_hex = format_connection_id_hex(odcid);
    auto sink =
        std::make_unique<QlogFileSeqSink>(config.directory / (odcid_hex + "_" + suffix + ".sqlog"));
    if (!sink->open()) {
        return nullptr;
    }
    return try_open_with_sink(std::move(sink), role, odcid, start_time);
}

std::unique_ptr<Session> Session::try_open_with_sink_for_test(
    std::unique_ptr<QlogFileSeqSink> sink, EndpointRole role, const ConnectionId &odcid,
    QuicCoreTimePoint start_time) {
    return try_open_with_sink(std::move(sink), role, odcid, start_time);
}
```

- [ ] **Step 4: Re-run the focused qlog suite and verify green**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicQlogTest.*
```

Expected:

```text
Note: Google Test filter = QuicQlogTest.*
[==========] Running 6 tests from 1 test suite.
[  PASSED  ] 6 tests.
```

- [ ] **Step 5: Commit the qlog coverage changes**

Run:

```bash
git add src/quic/qlog/session.h src/quic/qlog/session.cpp tests/quic_qlog_test.cpp
git commit -m "test: close qlog coverage gaps"
```

### Task 2: Close Remaining Connection Coverage

**Files:**
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Add the remaining connection coverage tests**

Append these tests near the existing move and flow-control coverage in `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, ConnectionMoveConstructionPreservesConnectionStartBehavior) {
    coquic::quic::QuicConnection source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicConnection moved(std::move(source));

    moved.start(coquic::quic::test::test_time(1));
    const auto datagram = moved.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionMoveAssignmentPreservesConnectionStartBehavior) {
    coquic::quic::QuicConnection source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicConnection destination(coquic::quic::test::make_client_core_config());
    destination = std::move(source);

    destination.start(coquic::quic::test::test_time(1));
    const auto datagram = destination.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionRemoteQlogParametersAreEmittedAtMostOnce) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.config_.initial_destination_connection_id, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.qlog_session_ != nullptr);

    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(1));
    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(2));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 1u);
}

TEST(QuicCoreTest, ConnectionDeferredProtectedPacketEqualityDependsOnDatagramId) {
    const auto bytes = bytes_from_ints({0xaa, 0xbb, 0xcc});

    EXPECT_TRUE(coquic::quic::DeferredProtectedPacket(bytes) == bytes);
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 7) == bytes);
}
```

- [ ] **Step 2: Run the focused connection suite**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.ConnectionMoveConstructionPreservesConnectionStartBehavior:QuicCoreTest.ConnectionMoveAssignmentPreservesConnectionStartBehavior:QuicCoreTest.ConnectionRemoteQlogParametersAreEmittedAtMostOnce:QuicCoreTest.ConnectionDeferredProtectedPacketEqualityDependsOnDatagramId
```

Expected:

```text
Note: Google Test filter = QuicCoreTest.ConnectionMoveConstructionPreservesConnectionStartBehavior:QuicCoreTest.ConnectionMoveAssignmentPreservesConnectionStartBehavior:QuicCoreTest.ConnectionRemoteQlogParametersAreEmittedAtMostOnce:QuicCoreTest.ConnectionDeferredProtectedPacketEqualityDependsOnDatagramId
[==========] Running 4 tests from 1 test suite.
[  PASSED  ] 4 tests.
```

- [ ] **Step 3: Commit the connection coverage changes**

Run:

```bash
git add tests/quic_core_test.cpp
git commit -m "test: cover connection edge branches"
```

### Task 3: Close The Remaining TLS ALPN Decode Branch

**Files:**
- Modify: `tests/quic_tls_adapter_contract_test.cpp`

- [ ] **Step 1: Add the malformed server ALPN list test**

Extend the existing ALPN helper section in `tests/quic_tls_adapter_contract_test.cpp` with:

```cpp
TEST(QuicTlsAdapterContractTest, SelectApplicationProtocolRejectsMalformedOfferedList) {
    TlsAdapter server(make_server_config());
    const auto malformed = std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i'});
    const uint8_t *selected = nullptr;
    uint8_t selected_length = 0;

    EXPECT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  &server, &selected, &selected_length, malformed),
              SSL_TLSEXT_ERR_ALERT_FATAL);
}
```

- [ ] **Step 2: Run the focused TLS helper suite**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterContractTest.ApplicationProtocolHelpersEncodeAndValidateLists:QuicTlsAdapterContractTest.SelectApplicationProtocolRejectsMalformedOfferedList
```

Expected:

```text
Note: Google Test filter = QuicTlsAdapterContractTest.ApplicationProtocolHelpersEncodeAndValidateLists:QuicTlsAdapterContractTest.SelectApplicationProtocolRejectsMalformedOfferedList
[==========] Running 2 tests from 1 test suite.
[  PASSED  ] 2 tests.
```

- [ ] **Step 3: Commit the TLS coverage change**

Run:

```bash
git add tests/quic_tls_adapter_contract_test.cpp
git commit -m "test: cover tls alpn decode branch"
```

### Task 4: Verify CI And Assert 100% Coverage

**Files:**
- Modify: none

- [ ] **Step 1: Run the exact CI commands locally**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build coverage
```

Expected:

```text
Passed
Passed
[  PASSED  ] 1088 tests.
```

- [ ] **Step 2: Assert the LLVM totals are 100.00%**

Run:

```bash
python - <<'PY'
from html.parser import HTMLParser
from pathlib import Path

html = Path("coverage/html/index.html").read_text()

class TotalsParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_tr = False
        self.in_pre = False
        self.rows = []
        self.cur = []

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.in_tr = True
            self.cur = []
        elif self.in_tr and tag == "pre":
            self.in_pre = True

    def handle_endtag(self, tag):
        if tag == "pre":
            self.in_pre = False
        elif tag == "tr" and self.in_tr:
            row = [cell.strip() for cell in self.cur if cell.strip()]
            if row:
                self.rows.append(row)
            self.in_tr = False

    def handle_data(self, data):
        if self.in_tr and self.in_pre:
            self.cur.append(data)

parser = TotalsParser()
parser.feed(html)
totals = next(row for row in parser.rows if row[0] == "Totals")
assert totals[2].startswith("100.00%"), totals
assert totals[3].startswith("100.00%"), totals
assert totals[4].startswith("100.00%"), totals
print("\n".join(totals))
PY
```

Expected:

The printed `Totals` row shows `100.00%` for line, region, and branch coverage.

- [ ] **Step 3: Confirm the worktree is clean except for generated coverage artifacts**

Run:

```bash
git status --short
```

Expected:

```text
```

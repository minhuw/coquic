# QUIC Core QLOG Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement real core-transport qlog emission for `coquic`, writing one `.sqlog` file per `QuicConnection` and covering the seven approved Core QUIC qlog events.

**Architecture:** Add a focused `src/quic/qlog/` module for qlog DTOs, JSON serialization, file output, and per-connection session state. Keep event emission inside `QuicConnection`, use `QLogFileSeq` with the draft QUIC event schema URI, and make qlog strictly observational so file failures disable logging without affecting transport behavior.

**Tech Stack:** Zig build system, C++20, GoogleTest, `std::filesystem`, `std::ofstream`, OpenSSL-based QUIC TLS backends, local qlog draft corpus in `docs/rfc/`

---

## File Map

- `build.zig`: compile the new qlog sources and add the qlog-specific test file to the default suite.
- `src/quic/core.h`: add `QuicQlogConfig` and the optional qlog field on `QuicCoreConfig`.
- `src/quic/core.cpp`: pass `now` into connection startup so qlog sessions have a real reference time from the core clock.
- `src/quic/recovery.h`: attach an optional qlog packet snapshot pointer to `SentPacketRecord`.
- `src/quic/connection.h`: add qlog session ownership, deferred packet metadata with `datagram_id`, and narrow qlog helper declarations.
- `src/quic/connection.cpp`: open qlog sessions, emit all seven qlog events, preserve packet snapshots for loss, and keep qlog failures non-fatal.
- `src/quic/protected_codec.h`: add the protected-datagram metadata result type and public serializer declaration.
- `src/quic/protected_codec.cpp`: expose per-packet protected lengths and offsets without changing existing serialization behavior.
- `src/quic/tls_adapter.h`: expose peer-offered ALPNs and selected ALPN bytes for qlog.
- `src/quic/tls_adapter_quictls.cpp`: capture ALPN telemetry in the quictls backend.
- `src/quic/tls_adapter_boringssl.cpp`: capture ALPN telemetry in the boringssl backend.
- `src/quic/qlog/fwd.h`: forward declarations for qlog session and packet snapshot types used from transport headers.
- `src/quic/qlog/types.h`: qlog DTOs for packet headers, packet snapshots, ALPN values, and recovery metrics snapshots.
- `src/quic/qlog/json.h`: declarations for JSON escaping and qlog record serialization helpers.
- `src/quic/qlog/json.cpp`: manual JSON escaping plus qlog preamble, event, packet, frame, and recovery-metrics serializers.
- `src/quic/qlog/sink.h`: append-only sequential sink API.
- `src/quic/qlog/sink.cpp`: filesystem-backed `.sqlog` sink implementation.
- `src/quic/qlog/session.h`: per-connection qlog session API and state.
- `src/quic/qlog/session.cpp`: session lifecycle, timestamping, one-shot flags, and event write helpers.
- `tests/quic_qlog_test.cpp`: serializer and sink unit tests.
- `tests/quic_protected_codec_test.cpp`: protected-datagram metadata tests.
- `tests/quic_tls_adapter_contract_test.cpp`: ALPN telemetry tests on the TLS adapters.
- `tests/quic_core_test.cpp`: transport integration tests for qlog lifecycle and event emission.
- `tests/quic_test_utils.h`: temp-directory and `.sqlog` record-reading helpers shared by qlog tests.

### Task 1: Add qlog JSON and sink scaffolding

**Files:**
- Create: `src/quic/qlog/fwd.h`
- Create: `src/quic/qlog/types.h`
- Create: `src/quic/qlog/json.h`
- Create: `src/quic/qlog/json.cpp`
- Create: `src/quic/qlog/sink.h`
- Create: `src/quic/qlog/sink.cpp`
- Create: `tests/quic_qlog_test.cpp`
- Modify: `build.zig`
- Test: `tests/quic_qlog_test.cpp`

- [ ] **Step 1: Write the failing qlog utility tests**

Create `tests/quic_qlog_test.cpp` with these tests:

```cpp
#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "src/quic/qlog/json.h"
#include "src/quic/qlog/sink.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::qlog::FilePreamble;
using coquic::quic::qlog::QlogFileSeqSink;

TEST(QuicQlogTest, SerializesSequentialPreambleWithDraftQuicSchema) {
    const auto preamble = coquic::quic::qlog::serialize_file_seq_preamble(FilePreamble{
        .title = "coquic qlog",
        .description = "client trace",
        .group_id = "8394c8f03e515708",
        .vantage_point_type = "client",
        .event_schemas = {"urn:ietf:params:qlog:events:quic-12"},
    });

    EXPECT_NE(preamble.find("\"file_schema\":\"urn:ietf:params:qlog:file:sequential\""),
              std::string::npos);
    EXPECT_NE(preamble.find("\"serialization_format\":\"application/qlog+json-seq\""),
              std::string::npos);
    EXPECT_NE(preamble.find("\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-12\"]"),
              std::string::npos);
    EXPECT_NE(preamble.find("\"group_id\":\"8394c8f03e515708\""), std::string::npos);
    EXPECT_NE(preamble.find("\"type\":\"client\""), std::string::npos);
}

TEST(QuicQlogTest, EscapesJsonStringsAndFramesJsonSeqRecords) {
    EXPECT_EQ(coquic::quic::qlog::escape_json_string("a\"b\\c\n"),
              "a\\\"b\\\\c\\n");

    const auto record = coquic::quic::qlog::make_json_seq_record("{\"time\":1}");
    ASSERT_FALSE(record.empty());
    EXPECT_EQ(record.front(), '\x1e');
    EXPECT_EQ(record.back(), '\n');
    EXPECT_NE(record.find("{\"time\":1}"), std::string::npos);
}

TEST(QuicQlogTest, SinkDisablesAfterAppendFailure) {
    QlogFileSeqSink sink(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(sink.open());
    EXPECT_FALSE(sink.write_record("\x1e{\"time\":0}\n"));
    EXPECT_FALSE(sink.healthy());
}

} // namespace
```

- [ ] **Step 2: Run the qlog utility tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicQlogTest.*'
```

Expected: FAIL to compile because the new qlog headers, sink, and test target wiring do not exist yet.

- [ ] **Step 3: Add the minimal qlog DTO, JSON, sink, and build wiring**

Create `src/quic/qlog/fwd.h`:

```cpp
#pragma once

namespace coquic::quic::qlog {

struct PacketSnapshot;
struct RecoveryMetricsSnapshot;
class Session;

} // namespace coquic::quic::qlog
```

Create `src/quic/qlog/types.h`:

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace coquic::quic::qlog {

struct FilePreamble {
    std::string title;
    std::string description;
    std::string group_id;
    std::string vantage_point_type;
    std::vector<std::string> event_schemas;
};

} // namespace coquic::quic::qlog
```

Create `src/quic/qlog/json.h`:

```cpp
#pragma once

#include <string>
#include <string_view>

#include "src/quic/qlog/types.h"

namespace coquic::quic::qlog {

std::string escape_json_string(std::string_view value);
std::string serialize_file_seq_preamble(const FilePreamble &preamble);
std::string make_json_seq_record(std::string_view json_object);

} // namespace coquic::quic::qlog
```

Create `src/quic/qlog/json.cpp`:

```cpp
#include "src/quic/qlog/json.h"

namespace coquic::quic::qlog {

std::string escape_json_string(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const auto ch : value) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    return out;
}

std::string serialize_file_seq_preamble(const FilePreamble &preamble) {
    return std::string("{") +
           "\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," +
           "\"serialization_format\":\"application/qlog+json-seq\"," +
           "\"title\":\"" + escape_json_string(preamble.title) + "\"," +
           "\"description\":\"" + escape_json_string(preamble.description) + "\"," +
           "\"trace\":{" +
           "\"common_fields\":{" +
           "\"group_id\":\"" + escape_json_string(preamble.group_id) + "\"," +
           "\"time_format\":\"relative_to_epoch\"," +
           "\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}" +
           "}," +
           "\"vantage_point\":{\"type\":\"" + escape_json_string(preamble.vantage_point_type) + "\"}," +
           "\"event_schemas\":[\"" + escape_json_string(preamble.event_schemas.front()) + "\"]" +
           "}" +
           "}";
}

std::string make_json_seq_record(std::string_view json_object) {
    std::string out;
    out.reserve(json_object.size() + 2);
    out.push_back('\x1e');
    out.append(json_object);
    out.push_back('\n');
    return out;
}

} // namespace coquic::quic::qlog
```

Create `src/quic/qlog/sink.h`:

```cpp
#pragma once

#include <filesystem>
#include <fstream>
#include <string_view>

namespace coquic::quic::qlog {

class QlogFileSeqSink {
  public:
    explicit QlogFileSeqSink(std::filesystem::path path);

    bool open();
    bool write_record(std::string_view record);
    bool healthy() const;
    const std::filesystem::path &path() const;

  private:
    std::filesystem::path path_;
    std::ofstream output_;
    bool healthy_ = true;
};

} // namespace coquic::quic::qlog
```

Create `src/quic/qlog/sink.cpp`:

```cpp
#include "src/quic/qlog/sink.h"

namespace coquic::quic::qlog {

QlogFileSeqSink::QlogFileSeqSink(std::filesystem::path path) : path_(std::move(path)) {}

bool QlogFileSeqSink::open() {
    std::error_code error;
    std::filesystem::create_directories(path_.parent_path(), error);
    if (error) {
        healthy_ = false;
        return false;
    }

    output_.open(path_, std::ios::binary | std::ios::out | std::ios::trunc);
    healthy_ = output_.is_open();
    return healthy_;
}

bool QlogFileSeqSink::write_record(std::string_view record) {
    if (!healthy_) {
        return false;
    }

    output_.write(record.data(), static_cast<std::streamsize>(record.size()));
    output_.flush();
    healthy_ = output_.good();
    return healthy_;
}

bool QlogFileSeqSink::healthy() const {
    return healthy_;
}

const std::filesystem::path &QlogFileSeqSink::path() const {
    return path_;
}

} // namespace coquic::quic::qlog
```

Update `build.zig`:

```zig
files.appendSlice(&.{
    "src/coquic.cpp",
    "src/quic/buffer.cpp",
    "src/quic/congestion.cpp",
    "src/quic/connection.cpp",
    "src/quic/core.cpp",
    "src/quic/crypto_stream.cpp",
    "src/quic/frame.cpp",
    "src/quic/http09.cpp",
    "src/quic/http09_client.cpp",
    "src/quic/http09_runtime.cpp",
    "src/quic/http09_server.cpp",
    "src/quic/packet.cpp",
    "src/quic/packet_number.cpp",
    "src/quic/plaintext_codec.cpp",
    "src/quic/qlog/json.cpp",
    "src/quic/qlog/sink.cpp",
    "src/quic/recovery.cpp",
    "src/quic/protected_codec.cpp",
    "src/quic/streams.cpp",
    "src/quic/transport_parameters.cpp",
    "src/quic/varint.cpp",
}) catch @panic("oom");
```

```zig
const default_test_files = &.{
    "tests/smoke.cpp",
    "tests/quic_core_test.cpp",
    "tests/quic_congestion_test.cpp",
    "tests/quic_frame_test.cpp",
    "tests/quic_crypto_stream_test.cpp",
    "tests/quic_packet_test.cpp",
    "tests/quic_packet_number_test.cpp",
    "tests/quic_packet_crypto_test.cpp",
    "tests/quic_plaintext_codec_test.cpp",
    "tests/quic_http09_test.cpp",
    "tests/quic_http09_server_test.cpp",
    "tests/quic_http09_client_test.cpp",
    "tests/quic_http09_runtime_test.cpp",
    "tests/quic_qlog_test.cpp",
    "tests/quic_recovery_test.cpp",
    "tests/quic_streams_test.cpp",
    "tests/quic_protected_codec_test.cpp",
    "tests/quic_tls_adapter_contract_test.cpp",
    "tests/quic_transport_parameters_test.cpp",
    "tests/quic_varint_test.cpp",
};
```

- [ ] **Step 4: Re-run the qlog utility tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicQlogTest.*'
```

Expected: PASS.

- [ ] **Step 5: Commit the qlog utility scaffold**

Run:

```bash
git add build.zig src/quic/qlog/fwd.h src/quic/qlog/types.h src/quic/qlog/json.h \
        src/quic/qlog/json.cpp src/quic/qlog/sink.h src/quic/qlog/sink.cpp \
        tests/quic_qlog_test.cpp
git commit -m "feat: add qlog json and sink utilities"
```

Expected: one commit containing only the new qlog utility layer and its tests.

### Task 2: Add qlog config and per-connection session lifecycle

**Files:**
- Create: `src/quic/qlog/session.h`
- Create: `src/quic/qlog/session.cpp`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_test_utils.h`
- Modify: `tests/quic_core_test.cpp`
- Modify: `build.zig`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing core tests for qlog session creation and non-fatal open failure**

Add these helpers to `tests/quic_test_utils.h`:

```cpp
inline std::string read_text_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

inline std::vector<std::filesystem::path> sqlog_files_in(const std::filesystem::path &dir) {
    std::vector<std::filesystem::path> out;
    if (!std::filesystem::exists(dir)) {
        return out;
    }

    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".sqlog") {
            out.push_back(entry.path());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

inline std::filesystem::path only_sqlog_file_in(const std::filesystem::path &dir) {
    const auto files = sqlog_files_in(dir);
    EXPECT_EQ(files.size(), 1u);
    return files.empty() ? std::filesystem::path{} : files.front();
}

inline std::vector<std::string> qlog_seq_records_from_file(const std::filesystem::path &path) {
    const auto text = read_text_file(path);
    std::vector<std::string> out;
    std::string current;
    for (const char ch : text) {
        if (ch == '\x1e') {
            if (!current.empty()) {
                out.push_back(current);
                current.clear();
            }
            continue;
        }
        if (ch != '\n') {
            current.push_back(ch);
        }
    }
    if (!current.empty()) {
        out.push_back(current);
    }
    return out;
}
```

Add these tests to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, ClientQlogStartWritesSequentialPreamble) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto config = coquic::quic::test::make_client_core_config();
    config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    coquic::quic::QuicCore core(std::move(config));

    const auto result = core.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    static_cast<void>(result);

    const auto qlog_path = coquic::quic::test::only_sqlog_file_in(qlog_dir.path());
    const auto records = coquic::quic::test::qlog_seq_records_from_file(qlog_path);

    ASSERT_FALSE(records.empty());
    EXPECT_NE(records.front().find("\"file_schema\":\"urn:ietf:params:qlog:file:sequential\""),
              std::string::npos);
    EXPECT_NE(records.front().find("\"type\":\"client\""), std::string::npos);
    EXPECT_FALSE(core.has_failed());
}

TEST(QuicCoreTest, ServerQlogFilenameUsesOriginalDestinationConnectionId) {
    coquic::quic::test::ScopedTempDir qlog_root;
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "client"};
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "server"};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    const auto client_start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto datagrams = coquic::quic::test::send_datagrams_from(client_start);
    ASSERT_EQ(datagrams.size(), 1u);

    static_cast<void>(server.advance(
        coquic::quic::QuicCoreInboundDatagram{datagrams.front()},
        coquic::quic::test::test_time(1)));

    const auto server_qlog = coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "server");
    EXPECT_EQ(server_qlog.filename(),
              std::filesystem::path("8394c8f03e515708_server.sqlog"));
}

TEST(QuicCoreTest, QlogOpenFailureDoesNotFailConnection) {
    auto config = coquic::quic::test::make_client_core_config();
    config.qlog = coquic::quic::QuicQlogConfig{
        .directory = std::filesystem::path("/dev/null/coquic-qlog"),
    };
    coquic::quic::QuicCore core(std::move(config));

    const auto result = core.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());

    EXPECT_FALSE(core.has_failed());
    EXPECT_FALSE(result.local_error.has_value());
}
```

- [ ] **Step 2: Run the targeted core tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog*'
```

Expected: FAIL to compile because `QuicQlogConfig`, the qlog session class, and the startup hook changes do not exist yet.

- [ ] **Step 3: Add the core qlog config, session class, startup timing, and file lifecycle**

Update `src/quic/core.h`:

```cpp
#include <filesystem>
```

```cpp
struct QuicQlogConfig {
    std::filesystem::path directory;
};

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    std::optional<ConnectionId> original_destination_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
    std::vector<std::byte> retry_token;
    std::uint32_t original_version = kQuicVersion1;
    std::uint32_t initial_version = kQuicVersion1;
    std::vector<std::uint32_t> supported_versions = {kQuicVersion1};
    bool reacted_to_version_negotiation = false;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    std::optional<QuicResumptionState> resumption_state;
    QuicZeroRttConfig zero_rtt;
    std::optional<QuicQlogConfig> qlog;
};
```

Create `src/quic/qlog/session.h`:

```cpp
#pragma once

#include <memory>
#include <optional>
#include <string>

#include "src/quic/core.h"
#include "src/quic/packet.h"
#include "src/quic/protected_codec.h"
#include "src/quic/qlog/sink.h"

namespace coquic::quic::qlog {

class Session {
  public:
    static std::unique_ptr<Session> try_open(const QuicQlogConfig &config, EndpointRole role,
                                             const ConnectionId &odcid,
                                             QuicCoreTimePoint start_time);

    bool healthy() const;
    std::uint32_t next_inbound_datagram_id();
    std::uint32_t next_outbound_datagram_id();
    double relative_time_ms(QuicCoreTimePoint now) const;
    bool write_event(QuicCoreTimePoint now, std::string_view name, std::string_view data_json);

  private:
    Session(QuicCoreTimePoint start_time, std::unique_ptr<QlogFileSeqSink> sink);

    std::unique_ptr<QlogFileSeqSink> sink_;
    QuicCoreTimePoint start_time_{};
    std::uint32_t next_inbound_datagram_id_ = 0;
    std::uint32_t next_outbound_datagram_id_ = 0;
};

} // namespace coquic::quic::qlog
```

Create `src/quic/qlog/session.cpp`:

```cpp
#include "src/quic/qlog/session.h"

#include <chrono>

#include "src/quic/qlog/json.h"

namespace coquic::quic::qlog {
namespace {

std::string format_connection_id_hex(const ConnectionId &connection_id) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(connection_id.size() * 2);
    for (const auto byte : connection_id) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        hex.push_back(digits[value >> 4]);
        hex.push_back(digits[value & 0x0f]);
    }
    return hex;
}

} // namespace

Session::Session(QuicCoreTimePoint start_time, std::unique_ptr<QlogFileSeqSink> sink)
    : sink_(std::move(sink)), start_time_(start_time) {}

std::unique_ptr<Session> Session::try_open(const QuicQlogConfig &config, EndpointRole role,
                                           const ConnectionId &odcid,
                                           QuicCoreTimePoint start_time) {
    const auto suffix = role == EndpointRole::client ? "client" : "server";
    const auto odcid_hex = format_connection_id_hex(odcid);
    auto sink = std::make_unique<QlogFileSeqSink>(config.directory /
                                                  (odcid_hex + "_" + suffix + ".sqlog"));
    if (!sink->open()) {
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

bool Session::healthy() const {
    return sink_ != nullptr && sink_->healthy();
}

std::uint32_t Session::next_inbound_datagram_id() {
    return next_inbound_datagram_id_++;
}

std::uint32_t Session::next_outbound_datagram_id() {
    return next_outbound_datagram_id_++;
}

double Session::relative_time_ms(QuicCoreTimePoint now) const {
    return std::chrono::duration<double, std::milli>(now - start_time_).count();
}

bool Session::write_event(QuicCoreTimePoint now, std::string_view name, std::string_view data_json) {
    if (!healthy()) {
        return false;
    }

    const std::string event = std::string("{") +
                              "\"time\":" + std::to_string(relative_time_ms(now)) + "," +
                              "\"name\":\"" + escape_json_string(name) + "\"," +
                              "\"data\":" + std::string(data_json) +
                              "}";
    return sink_->write_record(make_json_seq_record(event));
}

} // namespace coquic::quic::qlog
```

Update `src/quic/connection.h`:

```cpp
#include <memory>

#include "src/quic/qlog/fwd.h"
```

```cpp
class QuicConnection {
  public:
    explicit QuicConnection(QuicCoreConfig config);

    void start(QuicCoreTimePoint now);
```

```cpp
  private:
    void start_client_if_needed(QuicCoreTimePoint now);
    void start_server_if_needed(const ConnectionId &client_initial_destination_connection_id,
                                QuicCoreTimePoint now,
                                std::uint32_t client_initial_version = kQuicVersion1);
    void maybe_open_qlog_session(QuicCoreTimePoint now, const ConnectionId &odcid);
```

```cpp
    std::unique_ptr<qlog::Session> qlog_session_;
```

Update `src/quic/connection.cpp`:

```cpp
void QuicConnection::maybe_open_qlog_session(QuicCoreTimePoint now, const ConnectionId &odcid) {
    if (qlog_session_ != nullptr || !config_.qlog.has_value()) {
        return;
    }

    qlog_session_ = qlog::Session::try_open(*config_.qlog, config_.role, odcid, now);
}
```

```cpp
void QuicConnection::start(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    start_client_if_needed(now);
}
```

```cpp
void QuicConnection::start_client_if_needed(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::client || started_) {
        return;
    }

    maybe_open_qlog_session(now, client_initial_destination_connection_id());
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    ...
}
```

```cpp
void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id,
    QuicCoreTimePoint now, std::uint32_t client_initial_version) {
    if (started_) {
        return;
    }

    maybe_open_qlog_session(now, client_initial_destination_connection_id);
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    ...
}
```

```cpp
if (!started_) {
    ...
    start_server_if_needed(initial_destination_connection_id.value(), now,
                           read_u32_be(bytes.subspan(1, 4)));
}
```

Update `src/quic/core.cpp`:

```cpp
[&](const QuicCoreStart &) { connection_->start(now); },
```

```cpp
connection_ = std::make_unique<QuicConnection>(config_);
connection_->start(now);
```

Update `build.zig` to add `src/quic/qlog/session.cpp` to the library source list.

- [ ] **Step 4: Re-run the targeted core qlog lifecycle tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog*'
```

Expected: PASS for the three new qlog lifecycle tests.

- [ ] **Step 5: Commit the qlog config and session lifecycle changes**

Run:

```bash
git add build.zig src/quic/core.h src/quic/core.cpp src/quic/connection.h \
        src/quic/connection.cpp src/quic/qlog/session.h src/quic/qlog/session.cpp \
        tests/quic_test_utils.h tests/quic_core_test.cpp
git commit -m "feat: open per-connection qlog sessions"
```

Expected: one commit containing the qlog config surface, session startup wiring, and lifecycle tests.

### Task 3: Expose protected packet serialization metadata

**Files:**
- Modify: `src/quic/protected_codec.h`
- Modify: `src/quic/protected_codec.cpp`
- Modify: `tests/quic_protected_codec_test.cpp`
- Test: `tests/quic_protected_codec_test.cpp`

- [ ] **Step 1: Write failing protected-codec tests for packet metadata**

Add these tests to `tests/quic_protected_codec_test.cpp` near the existing protected-datagram coverage:

```cpp
TEST(QuicProtectedCodecTest, SerializeProtectedDatagramWithMetadataTracksPacketOffsets) {
    const auto context = make_handshake_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    const std::array<coquic::quic::ProtectedPacket, 2> packets = {
        make_minimal_handshake_packet(),
        coquic::quic::ProtectedPacket{make_minimal_handshake_packet()},
    };

    const auto encoded =
        coquic::quic::serialize_protected_datagram_with_metadata(packets, context);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_EQ(encoded.value().packet_metadata.size(), 2u);
    EXPECT_EQ(encoded.value().packet_metadata[0].offset, 0u);
    EXPECT_EQ(encoded.value().packet_metadata[1].offset,
              encoded.value().packet_metadata[0].length);
    EXPECT_EQ(encoded.value().packet_metadata[0].length +
                  encoded.value().packet_metadata[1].length,
              encoded.value().bytes.size());
}

TEST(QuicProtectedCodecTest, LegacySerializeProtectedDatagramStillReturnsOnlyBytes) {
    const auto context = make_handshake_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    const std::array<coquic::quic::ProtectedPacket, 1> packets = {
        make_minimal_handshake_packet(),
    };

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, context);
    const auto encoded_with_metadata =
        coquic::quic::serialize_protected_datagram_with_metadata(packets, context);

    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(encoded_with_metadata.has_value());
    EXPECT_EQ(encoded.value(), encoded_with_metadata.value().bytes);
}
```

- [ ] **Step 2: Run the targeted protected-codec tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicProtectedCodecTest.*Metadata*'
```

Expected: FAIL to compile because the metadata result type and serializer do not exist.

- [ ] **Step 3: Add the metadata result type and refactor serialization to fill it**

Update `src/quic/protected_codec.h`:

```cpp
struct SerializedProtectedPacketMetadata {
    std::size_t offset = 0;
    std::size_t length = 0;
};

struct SerializedProtectedDatagram {
    std::vector<std::byte> bytes;
    std::vector<SerializedProtectedPacketMetadata> packet_metadata;
};

CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const SerializeProtectionContext &context);

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context);
```

Update `src/quic/protected_codec.cpp`:

```cpp
CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const SerializeProtectionContext &context) {
    SerializedProtectedDatagram out;
    for (std::size_t index = 0; index < packets.size(); ++index) {
        const auto offset = out.bytes.size();
        const auto encoded = std::visit(
            [&](const auto &packet) -> CodecResult<std::vector<std::byte>> {
                using PacketType = std::decay_t<decltype(packet)>;
                if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                    return serialize_protected_initial_packet(packet, context);
                } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                    return serialize_protected_handshake_packet(packet, context);
                } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                    return serialize_protected_zero_rtt_packet(packet, context);
                } else {
                    const auto before = out.bytes.size();
                    const auto appended =
                        append_protected_one_rtt_packet_to_datagram_impl(out.bytes, packet, context);
                    if (!appended.has_value()) {
                        return CodecResult<std::vector<std::byte>>::failure(
                            appended.error().code, appended.error().offset);
                    }
                    out.packet_metadata.push_back(SerializedProtectedPacketMetadata{
                        .offset = before,
                        .length = appended.value(),
                    });
                    return CodecResult<std::vector<std::byte>>::success({});
                }
            },
            packets[index]);
        if (!encoded.has_value()) {
            return CodecResult<SerializedProtectedDatagram>::failure(encoded.error().code,
                                                                     encoded.error().offset);
        }
        if (!encoded.value().empty()) {
            out.bytes.insert(out.bytes.end(), encoded.value().begin(), encoded.value().end());
            out.packet_metadata.push_back(SerializedProtectedPacketMetadata{
                .offset = offset,
                .length = encoded.value().size(),
            });
        }
    }
    return CodecResult<SerializedProtectedDatagram>::success(std::move(out));
}

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context) {
    const auto encoded = serialize_protected_datagram_with_metadata(packets, context);
    if (!encoded.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                            encoded.error().offset);
    }
    return CodecResult<std::vector<std::byte>>::success(std::move(encoded.value().bytes));
}
```

- [ ] **Step 4: Re-run the targeted protected-codec tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicProtectedCodecTest.*Metadata*'
```

Expected: PASS.

- [ ] **Step 5: Commit the protected packet metadata helper**

Run:

```bash
git add src/quic/protected_codec.h src/quic/protected_codec.cpp \
        tests/quic_protected_codec_test.cpp
git commit -m "feat: expose protected datagram metadata for qlog"
```

Expected: one commit containing the metadata helper and its tests.

### Task 4: Expose ALPN telemetry from both TLS adapters

**Files:**
- Modify: `src/quic/tls_adapter.h`
- Modify: `src/quic/tls_adapter_quictls.cpp`
- Modify: `src/quic/tls_adapter_boringssl.cpp`
- Modify: `tests/quic_tls_adapter_contract_test.cpp`
- Test: `tests/quic_tls_adapter_contract_test.cpp`

- [ ] **Step 1: Write failing TLS contract tests for ALPN telemetry**

Add these tests to `tests/quic_tls_adapter_contract_test.cpp` near the existing ALPN callback tests:

```cpp
TEST(QuicTlsAdapterContractTest, QlogTelemetryCapturesServerOfferedAndSelectedApplicationProtocol) {
    TlsAdapter server(make_server_config());
    const auto offered = std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c'});
    const uint8_t *selected = nullptr;
    uint8_t selected_length = 0;

    ASSERT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  &server, &selected, &selected_length, offered),
              SSL_TLSEXT_ERR_OK);

    const auto expected = std::vector<std::byte>{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'},
        std::byte{'u'}, std::byte{'i'}, std::byte{'c'},
    };

    ASSERT_EQ(server.peer_offered_application_protocols().size(), 1u);
    EXPECT_EQ(server.peer_offered_application_protocols().front(), expected);
    ASSERT_TRUE(server.selected_application_protocol().has_value());
    EXPECT_EQ(*server.selected_application_protocol(), expected);
}

TEST(QuicTlsAdapterContractTest, QlogTelemetryPublishesSelectedApplicationProtocolAfterHandshake) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    drive_tls_handshake(client, server);

    const auto expected = std::vector<std::byte>{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'},
        std::byte{'u'}, std::byte{'i'}, std::byte{'c'},
    };

    ASSERT_TRUE(client.selected_application_protocol().has_value());
    ASSERT_TRUE(server.selected_application_protocol().has_value());
    EXPECT_EQ(*client.selected_application_protocol(), expected);
    EXPECT_EQ(*server.selected_application_protocol(), expected);
}
```

- [ ] **Step 2: Run the targeted TLS contract tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicTlsAdapterContractTest.*QlogTelemetry*'
```

Expected: FAIL to compile because the ALPN telemetry getters do not exist.

- [ ] **Step 3: Add ALPN telemetry getters and backend capture**

Update `src/quic/tls_adapter.h`:

```cpp
class TlsAdapter {
  public:
    ...
    const std::vector<std::vector<std::byte>> &peer_offered_application_protocols() const;
    const std::optional<std::vector<std::byte>> &selected_application_protocol() const;
```

Add shared state and getter plumbing in both backend implementations:

```cpp
std::vector<std::vector<std::byte>> peer_offered_application_protocols_;
std::optional<std::vector<std::byte>> selected_application_protocol_;

const std::vector<std::vector<std::byte>> &peer_offered_application_protocols() const {
    return peer_offered_application_protocols_;
}

const std::optional<std::vector<std::byte>> &selected_application_protocol() const {
    return selected_application_protocol_;
}
```

Add a backend-local parser helper in both `src/quic/tls_adapter_quictls.cpp` and
`src/quic/tls_adapter_boringssl.cpp`:

```cpp
std::vector<std::vector<std::byte>>
decode_application_protocol_list(std::span<const uint8_t> offered) {
    std::vector<std::vector<std::byte>> values;
    std::size_t offset = 0;
    while (offset < offered.size()) {
        const auto length = static_cast<std::size_t>(offered[offset++]);
        if (offset + length > offered.size()) {
            return {};
        }
        values.emplace_back(reinterpret_cast<const std::byte *>(offered.data() + offset),
                            reinterpret_cast<const std::byte *>(offered.data() + offset + length));
        offset += length;
    }
    return values;
}
```

Capture the server-side offered list and selected ALPN in the selection callback:

```cpp
static int select_application_protocol(SSL *, const uint8_t **out, uint8_t *out_len,
                                       const uint8_t *in, unsigned in_len, void *arg) {
    auto *impl = static_cast<Impl *>(arg);
    if (impl == nullptr || out == nullptr || out_len == nullptr) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    impl->peer_offered_application_protocols_ =
        decode_application_protocol_list(std::span(in, in_len));
    if (!application_protocol_valid(impl->config_.application_protocol) ||
        !client_offered_application_protocol(std::span(in, in_len),
                                             impl->config_.application_protocol)) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *out = reinterpret_cast<const uint8_t *>(impl->config_.application_protocol.data());
    *out_len = static_cast<uint8_t>(impl->config_.application_protocol.size());
    impl->selected_application_protocol_ = std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(*out),
        reinterpret_cast<const std::byte *>(*out + *out_len));
    return SSL_TLSEXT_ERR_OK;
}
```

Capture the negotiated ALPN after handshake progress:

```cpp
void update_runtime_status() {
    if (ssl_ == nullptr) {
        return;
    }

    const uint8_t *selected = nullptr;
    unsigned selected_len = 0;
    SSL_get0_alpn_selected(ssl_.get(), &selected, &selected_len);
    if (selected != nullptr && selected_len != 0) {
        selected_application_protocol_ = std::vector<std::byte>(
            reinterpret_cast<const std::byte *>(selected),
            reinterpret_cast<const std::byte *>(selected + selected_len));
    }
    ...
}
```

Add the public getter forwarding methods at the bottom of the wrapper class implementation:

```cpp
const std::vector<std::vector<std::byte>> &TlsAdapter::peer_offered_application_protocols() const {
    return impl_->peer_offered_application_protocols();
}

const std::optional<std::vector<std::byte>> &TlsAdapter::selected_application_protocol() const {
    return impl_->selected_application_protocol();
}
```

- [ ] **Step 4: Re-run the targeted TLS contract tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicTlsAdapterContractTest.*QlogTelemetry*'
```

Expected: PASS.

- [ ] **Step 5: Commit the TLS ALPN telemetry surface**

Run:

```bash
git add src/quic/tls_adapter.h src/quic/tls_adapter_quictls.cpp \
        src/quic/tls_adapter_boringssl.cpp tests/quic_tls_adapter_contract_test.cpp
git commit -m "feat: expose ALPN telemetry from tls adapters"
```

Expected: one commit containing only the telemetry additions and their contract tests.

### Task 5: Emit startup configuration qlog events

**Files:**
- Modify: `src/quic/qlog/types.h`
- Modify: `src/quic/qlog/json.h`
- Modify: `src/quic/qlog/json.cpp`
- Modify: `src/quic/qlog/session.h`
- Modify: `src/quic/qlog/session.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_test_utils.h`
- Modify: `tests/quic_core_test.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing core tests for local startup events, remote parameters, and chosen ALPN**

Add these helpers to `tests/quic_test_utils.h`:

```cpp
inline bool qlog_any_record_contains(std::span<const std::string> records, std::string_view needle) {
    return std::any_of(records.begin(), records.end(), [&](const std::string &record) {
        return record.find(needle) != std::string::npos;
    });
}

inline std::size_t qlog_event_count(std::span<const std::string> records, std::string_view name) {
    const auto needle = std::string("\"name\":\"") + std::string(name) + "\"";
    return static_cast<std::size_t>(std::count_if(records.begin(), records.end(),
                                                  [&](const std::string &record) {
                                                      return record.find(needle) != std::string::npos;
                                                  }));
}
```

Add these tests to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, QlogClientStartEmitsLocalVersionAlpnAndParametersEvents) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto config = coquic::quic::test::make_client_core_config();
    config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    coquic::quic::QuicCore client(std::move(config));

    static_cast<void>(client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time()));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:version_information"), 1u);
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:alpn_information"), 1u);
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 1u);
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"initiator\":\"local\""));
}

TEST(QuicCoreTest, QlogHandshakeEmitsRemoteParametersAndChosenAlpn) {
    coquic::quic::test::ScopedTempDir qlog_root;
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "client"};
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "server"};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto client_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "client"));
    const auto server_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "server"));

    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        client_records, "\"name\":\"quic:parameters_set\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        client_records, "\"initiator\":\"remote\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        client_records, "\"chosen_alpn\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        server_records, "\"client_alpns\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        server_records, "\"server_alpns\""));
}
```

- [ ] **Step 2: Run the targeted core qlog configuration tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog.*(Version|Alpn|Parameters).*'
```

Expected: FAIL because the session does not yet serialize or emit the configuration events.

- [ ] **Step 3: Add qlog event serializers and emit the four setup-time events**

Extend `src/quic/qlog/types.h`:

```cpp
struct AlpnValue {
    std::vector<std::byte> bytes;
};

struct RecoveryMetricsSnapshot {
    std::optional<double> min_rtt_ms;
    std::optional<double> smoothed_rtt_ms;
    std::optional<double> latest_rtt_ms;
    std::optional<double> rtt_variance_ms;
    std::optional<std::uint16_t> pto_count;
    std::optional<std::uint64_t> congestion_window;
    std::optional<std::uint64_t> bytes_in_flight;

    bool operator==(const RecoveryMetricsSnapshot &) const = default;
};
```

Extend `src/quic/qlog/json.h`:

```cpp
std::string serialize_version_information(EndpointRole role,
                                          std::span<const std::uint32_t> supported_versions,
                                          std::optional<std::uint32_t> chosen_version);
std::string serialize_alpn_information(
    std::optional<std::span<const std::vector<std::byte>>> local_alpns,
    std::optional<std::span<const std::vector<std::byte>>> peer_alpns,
    std::optional<std::span<const std::byte>> chosen_alpn,
    EndpointRole role);
std::string serialize_parameters_set(std::string_view initiator,
                                     const TransportParameters &parameters);
```

Implement the three serializers in `src/quic/qlog/json.cpp`:

```cpp
std::string serialize_version_information(EndpointRole role,
                                          std::span<const std::uint32_t> supported_versions,
                                          std::optional<std::uint32_t> chosen_version) {
    std::string json = "{";
    const auto versions_key =
        role == EndpointRole::client ? "\"client_versions\":[" : "\"server_versions\":[";
    json += versions_key;
    for (std::size_t index = 0; index < supported_versions.size(); ++index) {
        if (index != 0) {
            json.push_back(',');
        }
        json += std::to_string(supported_versions[index]);
    }
    json += "]";
    if (chosen_version.has_value()) {
        json += ",\"chosen_version\":" + std::to_string(*chosen_version);
    }
    json += "}";
    return json;
}

std::string serialize_alpn_identifier(std::span<const std::byte> value) {
    std::string json = "{\"byte_value\":\"";
    static constexpr char digits[] = "0123456789abcdef";
    for (const auto byte : value) {
        const auto raw = std::to_integer<std::uint8_t>(byte);
        json.push_back(digits[raw >> 4]);
        json.push_back(digits[raw & 0x0f]);
    }
    json += "\"";
    const auto as_text = std::string(reinterpret_cast<const char *>(value.data()), value.size());
    const auto printable = std::all_of(as_text.begin(), as_text.end(), [](unsigned char ch) {
        return ch >= 0x20 && ch <= 0x7e;
    });
    if (printable) {
        json += ",\"string_value\":\"" + escape_json_string(as_text) + "\"";
    }
    json += "}";
    return json;
}

std::string serialize_alpn_information(
    std::optional<std::span<const std::vector<std::byte>>> local_alpns,
    std::optional<std::span<const std::vector<std::byte>>> peer_alpns,
    std::optional<std::span<const std::byte>> chosen_alpn,
    EndpointRole role) {
    std::string json = "{";
    bool needs_comma = false;
    const auto append_list = [&](std::string_view key,
                                 std::span<const std::vector<std::byte>> values) {
        if (needs_comma) {
            json.push_back(',');
        }
        json += "\"";
        json += key;
        json += "\":[";
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (index != 0) {
                json.push_back(',');
            }
            json += serialize_alpn_identifier(values[index]);
        }
        json += "]";
        needs_comma = true;
    };

    if (local_alpns.has_value()) {
        append_list(role == EndpointRole::client ? "client_alpns" : "server_alpns",
                    *local_alpns);
    }
    if (peer_alpns.has_value()) {
        append_list(role == EndpointRole::client ? "server_alpns" : "client_alpns",
                    *peer_alpns);
    }
    if (chosen_alpn.has_value()) {
        if (needs_comma) {
            json.push_back(',');
        }
        json += "\"chosen_alpn\":";
        json += serialize_alpn_identifier(*chosen_alpn);
    }
    json += "}";
    return json;
}

std::string serialize_parameters_set(std::string_view initiator,
                                     const TransportParameters &parameters) {
    std::string json = "{\"initiator\":\"" + escape_json_string(initiator) + "\"";
    const auto append_u64 = [&](std::string_view key, std::uint64_t value) {
        json += ",\"" + std::string(key) + "\":" + std::to_string(value);
    };
    const auto append_connection_id = [&](std::string_view key,
                                          const std::optional<ConnectionId> &value) {
        if (!value.has_value()) {
            return;
        }
        static constexpr char digits[] = "0123456789abcdef";
        std::string hex;
        for (const auto byte : *value) {
            const auto raw = std::to_integer<std::uint8_t>(byte);
            hex.push_back(digits[raw >> 4]);
            hex.push_back(digits[raw & 0x0f]);
        }
        json += ",\"" + std::string(key) + "\":\"" + hex + "\"";
    };

    append_connection_id("original_destination_connection_id",
                         parameters.original_destination_connection_id);
    append_connection_id("initial_source_connection_id", parameters.initial_source_connection_id);
    append_connection_id("retry_source_connection_id", parameters.retry_source_connection_id);
    append_u64("max_idle_timeout", parameters.max_idle_timeout);
    append_u64("max_udp_payload_size", parameters.max_udp_payload_size);
    append_u64("ack_delay_exponent", parameters.ack_delay_exponent);
    append_u64("max_ack_delay", parameters.max_ack_delay);
    append_u64("active_connection_id_limit", parameters.active_connection_id_limit);
    append_u64("initial_max_data", parameters.initial_max_data);
    append_u64("initial_max_stream_data_bidi_local",
               parameters.initial_max_stream_data_bidi_local);
    append_u64("initial_max_stream_data_bidi_remote",
               parameters.initial_max_stream_data_bidi_remote);
    append_u64("initial_max_stream_data_uni", parameters.initial_max_stream_data_uni);
    append_u64("initial_max_streams_bidi", parameters.initial_max_streams_bidi);
    append_u64("initial_max_streams_uni", parameters.initial_max_streams_uni);
    json += "}";
    return json;
}
```

Extend `src/quic/qlog/session.h` with one-shot flags:

```cpp
    bool emitted_local_version_information() const;
    bool mark_local_version_information_emitted();
    bool emitted_local_alpn_information() const;
    bool mark_local_alpn_information_emitted();
    bool emitted_local_parameters_set() const;
    bool mark_local_parameters_set_emitted();
    bool emitted_remote_parameters_set() const;
    bool mark_remote_parameters_set_emitted();
    bool emitted_server_alpn_selection() const;
    bool mark_server_alpn_selection_emitted();
    bool emitted_client_chosen_alpn() const;
    bool mark_client_chosen_alpn_emitted();
```

Add the backing booleans in `src/quic/qlog/session.cpp` and simple `if (flag) return false; flag = true; return true;` methods.

Add these helpers to `src/quic/connection.h`:

```cpp
    void emit_local_qlog_startup_events(QuicCoreTimePoint now);
    void maybe_emit_remote_qlog_parameters(QuicCoreTimePoint now);
    void maybe_emit_qlog_alpn_information(QuicCoreTimePoint now);
```

Implement the connection hooks in `src/quic/connection.cpp`:

```cpp
void QuicConnection::emit_local_qlog_startup_events(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    if (qlog_session_->mark_local_version_information_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:version_information",
            qlog::serialize_version_information(config_.role, config_.supported_versions,
                                                current_version_)));
    }
    if (qlog_session_->mark_local_alpn_information_emitted()) {
        const std::vector<std::vector<std::byte>> alpns = {
            std::vector<std::byte>(reinterpret_cast<const std::byte *>(config_.application_protocol.data()),
                                   reinterpret_cast<const std::byte *>(config_.application_protocol.data() +
                                                                       config_.application_protocol.size())),
        };
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(alpns, std::nullopt, std::nullopt, config_.role)));
    }
    if (qlog_session_->mark_local_parameters_set_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:parameters_set",
            qlog::serialize_parameters_set("local", local_transport_parameters_)));
    }
}
```

Call that helper from the end of both `start_client_if_needed(now)` and
`start_server_if_needed(..., now)` after local transport parameters are set.

After peer transport parameters validate in `validate_peer_transport_parameters_if_ready()`:

```cpp
if (peer_transport_parameters_validated_) {
    maybe_emit_remote_qlog_parameters(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
}
```

Implement `maybe_emit_remote_qlog_parameters(...)`:

```cpp
void QuicConnection::maybe_emit_remote_qlog_parameters(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !peer_transport_parameters_.has_value()) {
        return;
    }
    if (!qlog_session_->mark_remote_parameters_set_emitted()) {
        return;
    }
    static_cast<void>(qlog_session_->write_event(
        now, "quic:parameters_set",
        qlog::serialize_parameters_set("remote", *peer_transport_parameters_)));
}
```

Implement `maybe_emit_qlog_alpn_information(...)` in `sync_tls_state()`:

```cpp
void QuicConnection::maybe_emit_qlog_alpn_information(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !tls_.has_value()) {
        return;
    }
    const auto &selected = tls_->selected_application_protocol();
    if (!selected.has_value()) {
        return;
    }

    if (config_.role == EndpointRole::server) {
        const auto &client_alpns = tls_->peer_offered_application_protocols();
        if (!client_alpns.empty() && qlog_session_->mark_server_alpn_selection_emitted()) {
            const std::vector<std::vector<std::byte>> server_alpns = {
                std::vector<std::byte>(
                    reinterpret_cast<const std::byte *>(config_.application_protocol.data()),
                    reinterpret_cast<const std::byte *>(config_.application_protocol.data() +
                                                        config_.application_protocol.size())),
            };
            static_cast<void>(qlog_session_->write_event(
                now, "quic:alpn_information",
                qlog::serialize_alpn_information(server_alpns, client_alpns, *selected,
                                                 EndpointRole::server)));
        }
        return;
    }

    if (qlog_session_->mark_client_chosen_alpn_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::nullopt, std::nullopt, *selected,
                                             EndpointRole::client)));
    }
}
```

Call `maybe_emit_qlog_alpn_information(now);` from the end of `sync_tls_state()`.

- [ ] **Step 4: Re-run the targeted configuration-event tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog.*(Version|Alpn|Parameters).*'
```

Expected: PASS.

- [ ] **Step 5: Commit the configuration-event emission**

Run:

```bash
git add src/quic/qlog/types.h src/quic/qlog/json.h src/quic/qlog/json.cpp \
        src/quic/qlog/session.h src/quic/qlog/session.cpp src/quic/connection.h \
        src/quic/connection.cpp tests/quic_test_utils.h tests/quic_core_test.cpp
git commit -m "feat: emit qlog connection setup events"
```

Expected: one commit containing startup metadata and peer-parameter/ALPN event emission.

### Task 6: Emit `packet_sent` and `packet_received` with datagram IDs and packet snapshots

**Files:**
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/qlog/types.h`
- Modify: `src/quic/qlog/json.h`
- Modify: `src/quic/qlog/json.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing tests for send/receive packet qlog and deferred replay**

Add these tests to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, QlogHandshakeAndStreamTrafficEmitPacketSentAndPacketReceived) {
    coquic::quic::test::ScopedTempDir qlog_root;
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "client"};
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "server"};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto send_result = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = {std::byte{'h'}, std::byte{'i'}},
            .fin = true,
        },
        coquic::quic::test::test_time(10));
    static_cast<void>(coquic::quic::test::relay_send_datagrams_to_peer(
        send_result, server, coquic::quic::test::test_time(11)));

    const auto client_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "client"));
    const auto server_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "server"));

    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        client_records, "\"name\":\"quic:packet_sent\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        server_records, "\"name\":\"quic:packet_received\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(client_records, "\"datagram_id\":"));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(client_records, "\"raw\":{\"length\":"));
}

TEST(QuicCoreTest, QlogDeferredReplayPreservesDatagramIdAndAddsKeysAvailableTrigger) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(),
        coquic::quic::test::test_time());

    const auto packet = coquic::quic::ProtectedOneRttPacket{
        .spin_bit = false,
        .key_phase = false,
        .destination_connection_id = connection.config_.source_connection_id,
        .packet_number_length = 1,
        .packet_number = 1,
        .frames = {coquic::quic::PingFrame{}},
    };
    const auto bytes = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{packet},
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::opposite_role(connection.config_.role),
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = *connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(bytes.has_value());

    connection.deferred_protected_packets_.push_back(
        coquic::quic::DeferredProtectedPacket{.bytes = bytes.value(), .datagram_id = 77});
    connection.replay_deferred_protected_packets(coquic::quic::test::test_time(5));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"name\":\"quic:packet_received\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"datagram_id\":77"));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"trigger\":\"keys_available\""));
}
```

- [ ] **Step 2: Run the targeted packet-event tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog.*(Packet|Deferred).*'
```

Expected: FAIL because no packet event serialization or deferred `datagram_id` tracking exists yet.

- [ ] **Step 3: Add packet snapshot types, frame serialization, send/receive hooks, and deferred datagram IDs**

Update `src/quic/recovery.h`:

```cpp
#include <memory>

#include "src/quic/qlog/fwd.h"
```

```cpp
    std::shared_ptr<coquic::quic::qlog::PacketSnapshot> qlog_packet_snapshot;
    bool qlog_pto_probe = false;
```

Extend `src/quic/qlog/types.h`:

```cpp
struct PacketHeader {
    std::string packet_type;
    std::optional<std::uint8_t> packet_number_length;
    std::optional<std::uint64_t> packet_number;
    std::optional<std::uint32_t> version;
    std::optional<std::uint16_t> length;
    std::optional<bool> spin_bit;
    std::optional<std::uint64_t> key_phase;
    std::optional<ConnectionId> scid;
    std::optional<ConnectionId> dcid;
    std::optional<std::vector<std::byte>> token;
};

struct PacketSnapshot {
    PacketHeader header;
    std::vector<Frame> frames;
    std::uint64_t raw_length = 0;
    std::optional<std::uint32_t> datagram_id;
    std::optional<std::string> trigger;
};
```

Extend `src/quic/qlog/json.h`:

```cpp
std::string serialize_packet_snapshot(const PacketSnapshot &snapshot);
```

Implement packet and frame serializers in `src/quic/qlog/json.cpp`:

```cpp
std::string connection_id_hex(const ConnectionId &value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    for (const auto byte : value) {
        const auto raw = std::to_integer<std::uint8_t>(byte);
        hex.push_back(digits[raw >> 4]);
        hex.push_back(digits[raw & 0x0f]);
    }
    return hex;
}

std::string bytes_hex(std::span<const std::byte> value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    for (const auto byte : value) {
        const auto raw = std::to_integer<std::uint8_t>(byte);
        hex.push_back(digits[raw >> 4]);
        hex.push_back(digits[raw & 0x0f]);
    }
    return hex;
}

std::string serialize_frame_json(const Frame &frame) {
    return std::visit(
        [&](const auto &value) -> std::string {
            using FrameType = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<FrameType, PaddingFrame>) {
                return "{\"frame_type\":\"padding\",\"length\":" + std::to_string(value.length) + "}";
            } else if constexpr (std::is_same_v<FrameType, PingFrame>) {
                return "{\"frame_type\":\"ping\"}";
            } else if constexpr (std::is_same_v<FrameType, AckFrame>) {
                return "{\"frame_type\":\"ack\",\"largest_acknowledged\":" +
                       std::to_string(value.largest_acknowledged) +
                       ",\"ack_delay\":" + std::to_string(value.ack_delay) + "}";
            } else if constexpr (std::is_same_v<FrameType, ResetStreamFrame>) {
                return "{\"frame_type\":\"reset_stream\",\"stream_id\":" +
                       std::to_string(value.stream_id) + ",\"error_code\":" +
                       std::to_string(value.application_protocol_error_code) +
                       ",\"final_size\":" + std::to_string(value.final_size) + "}";
            } else if constexpr (std::is_same_v<FrameType, StopSendingFrame>) {
                return "{\"frame_type\":\"stop_sending\",\"stream_id\":" +
                       std::to_string(value.stream_id) + ",\"error_code\":" +
                       std::to_string(value.application_protocol_error_code) + "}";
            } else if constexpr (std::is_same_v<FrameType, CryptoFrame>) {
                return "{\"frame_type\":\"crypto\",\"offset\":" +
                       std::to_string(value.offset) + ",\"length\":" +
                       std::to_string(value.crypto_data.size()) + "}";
            } else if constexpr (std::is_same_v<FrameType, NewTokenFrame>) {
                return "{\"frame_type\":\"new_token\",\"token\":\"" +
                       bytes_hex(value.token) + "\"}";
            } else if constexpr (std::is_same_v<FrameType, StreamFrame>) {
                return "{\"frame_type\":\"stream\",\"stream_id\":" +
                       std::to_string(value.stream_id) + ",\"offset\":" +
                       std::to_string(value.offset.value_or(0)) + ",\"length\":" +
                       std::to_string(value.stream_data.size()) + ",\"fin\":" +
                       std::string(value.fin ? "true" : "false") + "}";
            } else if constexpr (std::is_same_v<FrameType, MaxDataFrame>) {
                return "{\"frame_type\":\"max_data\",\"maximum\":" +
                       std::to_string(value.maximum_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, MaxStreamDataFrame>) {
                return "{\"frame_type\":\"max_stream_data\",\"stream_id\":" +
                       std::to_string(value.stream_id) + ",\"maximum\":" +
                       std::to_string(value.maximum_stream_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, MaxStreamsFrame>) {
                return "{\"frame_type\":\"max_streams\",\"stream_type\":\"" +
                       std::string(value.stream_type == StreamLimitType::bidirectional
                                       ? "bidirectional"
                                       : "unidirectional") +
                       "\",\"maximum\":" + std::to_string(value.maximum_streams) + "}";
            } else if constexpr (std::is_same_v<FrameType, DataBlockedFrame>) {
                return "{\"frame_type\":\"data_blocked\",\"maximum\":" +
                       std::to_string(value.maximum_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, StreamDataBlockedFrame>) {
                return "{\"frame_type\":\"stream_data_blocked\",\"stream_id\":" +
                       std::to_string(value.stream_id) + ",\"maximum\":" +
                       std::to_string(value.maximum_stream_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, StreamsBlockedFrame>) {
                return "{\"frame_type\":\"streams_blocked\",\"stream_type\":\"" +
                       std::string(value.stream_type == StreamLimitType::bidirectional
                                       ? "bidirectional"
                                       : "unidirectional") +
                       "\",\"maximum\":" + std::to_string(value.maximum_streams) + "}";
            } else if constexpr (std::is_same_v<FrameType, NewConnectionIdFrame>) {
                return "{\"frame_type\":\"new_connection_id\",\"sequence_number\":" +
                       std::to_string(value.sequence_number) + ",\"retire_prior_to\":" +
                       std::to_string(value.retire_prior_to) + ",\"connection_id\":\"" +
                       bytes_hex(value.connection_id) + "\"}";
            } else if constexpr (std::is_same_v<FrameType, RetireConnectionIdFrame>) {
                return "{\"frame_type\":\"retire_connection_id\",\"sequence_number\":" +
                       std::to_string(value.sequence_number) + "}";
            } else if constexpr (std::is_same_v<FrameType, PathChallengeFrame>) {
                return "{\"frame_type\":\"path_challenge\",\"data\":\"" +
                       bytes_hex(value.data) + "\"}";
            } else if constexpr (std::is_same_v<FrameType, PathResponseFrame>) {
                return "{\"frame_type\":\"path_response\",\"data\":\"" +
                       bytes_hex(value.data) + "\"}";
            } else if constexpr (std::is_same_v<FrameType, TransportConnectionCloseFrame>) {
                return "{\"frame_type\":\"connection_close_transport\",\"error_code\":" +
                       std::to_string(value.error_code) + ",\"frame_type_value\":" +
                       std::to_string(value.frame_type) + "}";
            } else if constexpr (std::is_same_v<FrameType, ApplicationConnectionCloseFrame>) {
                return "{\"frame_type\":\"connection_close_application\",\"error_code\":" +
                       std::to_string(value.error_code) + "}";
            } else {
                return std::string{"{\"frame_type\":\"handshake_done\"}"};
            }
        },
        frame);
}

std::string serialize_packet_snapshot(const PacketSnapshot &snapshot) {
    std::string json = "{\"header\":{";
    json += "\"packet_type\":\"" + escape_json_string(snapshot.header.packet_type) + "\"";
    if (snapshot.header.packet_number_length.has_value()) {
        json += ",\"packet_number_length\":" +
                std::to_string(*snapshot.header.packet_number_length);
    }
    if (snapshot.header.packet_number.has_value()) {
        json += ",\"packet_number\":" + std::to_string(*snapshot.header.packet_number);
    }
    if (snapshot.header.version.has_value()) {
        json += ",\"version\":" + std::to_string(*snapshot.header.version);
    }
    if (snapshot.header.length.has_value()) {
        json += ",\"length\":" + std::to_string(*snapshot.header.length);
    }
    if (snapshot.header.spin_bit.has_value()) {
        json += ",\"spin_bit\":" + std::string(*snapshot.header.spin_bit ? "true" : "false");
    }
    if (snapshot.header.key_phase.has_value()) {
        json += ",\"key_phase\":" + std::to_string(*snapshot.header.key_phase);
    }
    if (snapshot.header.scid.has_value()) {
        json += ",\"scid\":\"" + connection_id_hex(*snapshot.header.scid) + "\"";
    }
    if (snapshot.header.dcid.has_value()) {
        json += ",\"dcid\":\"" + connection_id_hex(*snapshot.header.dcid) + "\"";
    }
    if (snapshot.header.token.has_value()) {
        json += ",\"token\":\"" + bytes_hex(*snapshot.header.token) + "\"";
    }
    json += "},\"frames\":[";
    for (std::size_t index = 0; index < snapshot.frames.size(); ++index) {
        if (index != 0) {
            json.push_back(',');
        }
        json += serialize_frame_json(snapshot.frames[index]);
    }
    json += "],\"raw\":{\"length\":" + std::to_string(snapshot.raw_length) + "}";
    if (snapshot.datagram_id.has_value()) {
        json += ",\"datagram_id\":" + std::to_string(*snapshot.datagram_id);
    }
    if (snapshot.trigger.has_value()) {
        json += ",\"trigger\":\"" + escape_json_string(*snapshot.trigger) + "\"";
    }
    json += "}";
    return json;
}
```

Update `src/quic/connection.h`:

```cpp
struct DeferredProtectedPacket {
    std::vector<std::byte> bytes;
    std::uint32_t datagram_id = 0;
};
```

```cpp
    qlog::PacketSnapshot make_qlog_packet_snapshot(const ProtectedPacket &packet,
                                                   std::size_t raw_length,
                                                   std::uint32_t datagram_id,
                                                   std::optional<std::string> trigger = std::nullopt) const;
```

```cpp
    std::vector<DeferredProtectedPacket> deferred_protected_packets_;
```

Update the send path in `src/quic/connection.cpp` to use the metadata helper and emit packet events:

```cpp
qlog::PacketSnapshot QuicConnection::make_qlog_packet_snapshot(
    const ProtectedPacket &packet, std::size_t raw_length, std::uint32_t datagram_id,
    std::optional<std::string> trigger) const {
    return std::visit(
        [&](const auto &protected_packet) -> qlog::PacketSnapshot {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            qlog::PacketSnapshot snapshot;
            snapshot.raw_length = raw_length;
            snapshot.datagram_id = datagram_id;
            snapshot.trigger = std::move(trigger);
            snapshot.frames = protected_packet.frames;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                snapshot.header.packet_type = "initial";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.token = protected_packet.token;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                snapshot.header.packet_type = "handshake";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                snapshot.header.packet_type = "0RTT";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else {
                snapshot.header.packet_type = "1RTT";
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.spin_bit = protected_packet.spin_bit;
                snapshot.header.key_phase = protected_packet.key_phase ? 1u : 0u;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            }
            return snapshot;
        },
        packet);
}
```

Inside `process_inbound_datagram(...)`, assign one inbound `datagram_id` and preserve it for deferred packets:

```cpp
const auto inbound_datagram_id =
    qlog_session_ != nullptr ? std::optional<std::uint32_t>(qlog_session_->next_inbound_datagram_id())
                             : std::nullopt;
```

```cpp
const auto defer_packet = [&](std::span<const std::byte> packet_bytes, std::uint32_t datagram_id) {
    const auto deferred = std::vector<std::byte>(packet_bytes.begin(), packet_bytes.end());
    if (std::find_if(deferred_protected_packets_.begin(), deferred_protected_packets_.end(),
                     [&](const DeferredProtectedPacket &candidate) {
                         return candidate.bytes == deferred;
                     }) != deferred_protected_packets_.end()) {
        return;
    }
    if (deferred_protected_packets_.size() >= kMaximumDeferredProtectedPackets) {
        deferred_protected_packets_.erase(deferred_protected_packets_.begin());
    }
    deferred_protected_packets_.push_back(DeferredProtectedPacket{
        .bytes = deferred,
        .datagram_id = datagram_id,
    });
};
```

Emit receive events before state mutation:

```cpp
for (const auto &packet : packets.value()) {
    if (qlog_session_ != nullptr && inbound_datagram_id.has_value()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:packet_received",
            qlog::serialize_packet_snapshot(
                make_qlog_packet_snapshot(packet, packet_bytes.size(), *inbound_datagram_id,
                                          replay_trigger ? std::optional<std::string>("keys_available")
                                                         : std::nullopt))));
    }
    const auto processed = process_inbound_packet(packet, now);
    ...
}
```

In `flush_outbound_datagram(...)`, change `finalize_datagram` to use the metadata helper and emit send events:

```cpp
const auto finalize_datagram = [&](const std::vector<ProtectedPacket> &datagram_packets) {
    const auto encoded = serialize_protected_datagram_with_metadata(
        datagram_packets,
        SerializeProtectionContext{
            .local_role = config_.role,
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.write_secret,
            .zero_rtt_secret = zero_rtt_space_.write_secret,
            .one_rtt_secret = application_space_.write_secret,
            .one_rtt_key_phase = application_write_key_phase_,
        });
    if (!encoded.has_value()) {
        mark_failed();
        return std::vector<std::byte>{};
    }

    const auto outbound_datagram_id =
        qlog_session_ != nullptr ? std::optional<std::uint32_t>(qlog_session_->next_outbound_datagram_id())
                                 : std::nullopt;
    for (std::size_t index = 0; index < datagram_packets.size(); ++index) {
        const auto snapshot = make_qlog_packet_snapshot(
            datagram_packets[index], encoded.value().packet_metadata[index].length,
            outbound_datagram_id.value_or(0), std::nullopt);
        if (qlog_session_ != nullptr && outbound_datagram_id.has_value()) {
            static_cast<void>(qlog_session_->write_event(
                now, "quic:packet_sent", qlog::serialize_packet_snapshot(snapshot)));
        }

        const auto packet_number = std::visit(
            [](const auto &packet_value) { return packet_value.packet_number; }, datagram_packets[index]);
        for (auto *packet_space : {&initial_space_, &handshake_space_, &application_space_}) {
            const auto sent = packet_space->sent_packets.find(packet_number);
            if (sent != packet_space->sent_packets.end()) {
                sent->second.qlog_packet_snapshot =
                    std::make_shared<qlog::PacketSnapshot>(snapshot);
                sent->second.qlog_pto_probe = pto_probe_burst_active;
            }
        }
    }

    note_outbound_datagram_bytes(encoded.value().bytes.size());
    return encoded.value().bytes;
};
```

- [ ] **Step 4: Re-run the targeted packet-event tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog.*(Packet|Deferred).*'
```

Expected: PASS.

- [ ] **Step 5: Commit the packet send/receive event wiring**

Run:

```bash
git add src/quic/recovery.h src/quic/qlog/types.h src/quic/qlog/json.h \
        src/quic/qlog/json.cpp src/quic/connection.h src/quic/connection.cpp \
        tests/quic_core_test.cpp
git commit -m "feat: emit qlog packet flow events"
```

Expected: one commit containing packet send/receive qlog and deferred replay coverage.

### Task 7: Emit recovery metrics and packet-loss qlog, then verify the full slice

**Files:**
- Modify: `src/quic/qlog/session.h`
- Modify: `src/quic/qlog/session.cpp`
- Modify: `src/quic/qlog/json.h`
- Modify: `src/quic/qlog/json.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing tests for recovery metrics, loss triggers, and PTO probe send trigger**

Add these tests to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, QlogPacketLostUsesReorderingAndTimeThresholdTriggers) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(),
        coquic::quic::test::test_time());

    auto first = coquic::quic::SentPacketRecord{
        .packet_number = 1,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = true,
        .bytes_in_flight = 1200,
        .qlog_packet_snapshot = std::make_shared<coquic::quic::qlog::PacketSnapshot>(
            connection.make_qlog_packet_snapshot(
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 1,
                    .packet_number = 1,
                    .frames = {coquic::quic::PingFrame{}},
                },
                27, 1)),
    };
    auto second = first;
    second.packet_number = 2;
    second.sent_time = coquic::quic::test::test_time(-1000);
    second.qlog_packet_snapshot = std::make_shared<coquic::quic::qlog::PacketSnapshot>(
        connection.make_qlog_packet_snapshot(
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 2,
                .frames = {coquic::quic::PingFrame{}},
            },
            27, 1));

    connection.application_space_.sent_packets.emplace(first.packet_number, first);
    connection.application_space_.sent_packets.emplace(second.packet_number, second);
    connection.application_space_.recovery.on_packet_sent(first);
    connection.application_space_.recovery.on_packet_sent(second);
    connection.application_space_.recovery.on_packet_sent(
        coquic::quic::SentPacketRecord{
            .packet_number = 5,
            .sent_time = coquic::quic::test::test_time(10),
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
        });

    ASSERT_TRUE(connection.process_inbound_ack(
                    connection.application_space_,
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 5,
                        .first_ack_range = 0,
                    },
                    coquic::quic::test::test_time(20), 3, 25, false)
                    .has_value());
    connection.detect_lost_packets(coquic::quic::test::test_time(2000));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        records, "\"trigger\":\"reordering_threshold\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        records, "\"trigger\":\"time_threshold\""));
}

TEST(QuicCoreTest, QlogRecoveryMetricsUpdatedAndPtoProbeTriggerAreEmitted) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(),
        coquic::quic::test::test_time());

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.remaining_pto_probe_datagrams_ = 1;

    static_cast<void>(connection.drain_outbound_datagram(coquic::quic::test::test_time(50)));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        records, "\"name\":\"quic:recovery_metrics_updated\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        records, "\"trigger\":\"pto_probe\""));
}
```

- [ ] **Step 2: Run the targeted recovery/loss qlog tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Qlog.*(Lost|Recovery|Pto).*'
```

Expected: FAIL because neither `packet_lost` nor `recovery_metrics_updated` are emitted yet.

- [ ] **Step 3: Add recovery-metrics snapshots, loss-trigger emission, and PTO send triggers**

Extend `src/quic/qlog/json.h`:

```cpp
std::string serialize_recovery_metrics(const RecoveryMetricsSnapshot &metrics);
```

Implement `serialize_recovery_metrics(...)` in `src/quic/qlog/json.cpp`:

```cpp
std::string serialize_recovery_metrics(const RecoveryMetricsSnapshot &metrics) {
    std::string json = "{";
    bool needs_comma = false;
    const auto append_number = [&](std::string_view key, auto value) {
        if (needs_comma) {
            json.push_back(',');
        }
        json += "\"";
        json += key;
        json += "\":";
        json += std::to_string(value);
        needs_comma = true;
    };
    if (metrics.min_rtt_ms.has_value()) {
        append_number("min_rtt", *metrics.min_rtt_ms);
    }
    if (metrics.smoothed_rtt_ms.has_value()) {
        append_number("smoothed_rtt", *metrics.smoothed_rtt_ms);
    }
    if (metrics.latest_rtt_ms.has_value()) {
        append_number("latest_rtt", *metrics.latest_rtt_ms);
    }
    if (metrics.rtt_variance_ms.has_value()) {
        append_number("rtt_variance", *metrics.rtt_variance_ms);
    }
    if (metrics.pto_count.has_value()) {
        append_number("pto_count", *metrics.pto_count);
    }
    if (metrics.congestion_window.has_value()) {
        append_number("congestion_window", *metrics.congestion_window);
    }
    if (metrics.bytes_in_flight.has_value()) {
        append_number("bytes_in_flight", *metrics.bytes_in_flight);
    }
    json += "}";
    return json;
}
```

Extend `src/quic/qlog/session.h` and `src/quic/qlog/session.cpp`:

```cpp
    bool maybe_write_recovery_metrics(QuicCoreTimePoint now,
                                      const RecoveryMetricsSnapshot &metrics);
```

```cpp
    std::optional<RecoveryMetricsSnapshot> last_recovery_metrics_;
```

```cpp
bool Session::maybe_write_recovery_metrics(QuicCoreTimePoint now,
                                           const RecoveryMetricsSnapshot &metrics) {
    if (last_recovery_metrics_.has_value() && last_recovery_metrics_.value() == metrics) {
        return true;
    }
    last_recovery_metrics_ = metrics;
    return write_event(now, "quic:recovery_metrics_updated",
                       serialize_recovery_metrics(metrics));
}
```

Add these helpers to `src/quic/connection.h`:

```cpp
    qlog::RecoveryMetricsSnapshot current_qlog_recovery_metrics() const;
    void maybe_emit_qlog_recovery_metrics(QuicCoreTimePoint now);
    void emit_qlog_packet_lost(const SentPacketRecord &packet, std::string_view trigger,
                               QuicCoreTimePoint now);
```

Implement them in `src/quic/connection.cpp`:

```cpp
qlog::RecoveryMetricsSnapshot QuicConnection::current_qlog_recovery_metrics() const {
    const auto &rtt = shared_recovery_rtt_state();
    return qlog::RecoveryMetricsSnapshot{
        .min_rtt_ms = rtt.min_rtt.has_value()
                          ? std::optional<double>(static_cast<double>(rtt.min_rtt->count()))
                          : std::nullopt,
        .smoothed_rtt_ms = static_cast<double>(rtt.smoothed_rtt.count()),
        .latest_rtt_ms = rtt.latest_rtt.has_value()
                             ? std::optional<double>(static_cast<double>(rtt.latest_rtt->count()))
                             : std::nullopt,
        .rtt_variance_ms = static_cast<double>(rtt.rttvar.count()),
        .pto_count = static_cast<std::uint16_t>(pto_count_),
        .congestion_window = static_cast<std::uint64_t>(congestion_controller_.congestion_window()),
        .bytes_in_flight = static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight()),
    };
}

void QuicConnection::maybe_emit_qlog_recovery_metrics(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }
    static_cast<void>(qlog_session_->maybe_write_recovery_metrics(now, current_qlog_recovery_metrics()));
}

void QuicConnection::emit_qlog_packet_lost(const SentPacketRecord &packet, std::string_view trigger,
                                           QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || packet.qlog_packet_snapshot == nullptr) {
        return;
    }
    auto snapshot = *packet.qlog_packet_snapshot;
    snapshot.trigger = std::string(trigger);
    static_cast<void>(qlog_session_->write_event(
        now, "quic:packet_lost", qlog::serialize_packet_snapshot(snapshot)));
}
```

Hook recovery metrics into the four update sites:

```cpp
void QuicConnection::track_sent_packet(PacketSpaceState &packet_space,
                                       const SentPacketRecord &packet) {
    packet_space.sent_packets[packet.packet_number] = packet;
    packet_space.recovery.on_packet_sent(packet);
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    }
    maybe_emit_qlog_recovery_metrics(packet.sent_time);
}
```

```cpp
    maybe_emit_qlog_recovery_metrics(now);
    return CodecResult<bool>::success(true);
```

```cpp
    rebuild_recovery(packet_space);
    maybe_emit_qlog_recovery_metrics(now);
}
```

```cpp
    if (armed_pto_probe) {
        remaining_pto_probe_datagrams_ = 2;
    }
    maybe_emit_qlog_recovery_metrics(now);
}
```

Emit packet loss with explicit triggers:

```cpp
for (const auto &packet : ack_result.lost_packets) {
    const auto trigger = is_packet_threshold_lost(packet.packet_number,
                                                  ack.largest_acknowledged)
                             ? "reordering_threshold"
                             : "time_threshold";
    emit_qlog_packet_lost(packet, trigger, now);
    mark_lost_packet(packet_space, packet);
}
```

```cpp
for (const auto &packet : lost_packets) {
    emit_qlog_packet_lost(packet, "time_threshold", now);
    mark_lost_packet(packet_space, packet);
}
```

Stamp PTO probe sends when building sent-packet records in `flush_outbound_datagram(...)`:

```cpp
SentPacketRecord sent_packet{
    .packet_number = *packet_number,
    .sent_time = now,
    .ack_eliciting = true,
    .in_flight = true,
    .declared_lost = false,
    .has_handshake_done = probe_packet.has_handshake_done,
    .crypto_ranges = probe_crypto_ranges,
    .reset_stream_frames = probe_packet.reset_stream_frames,
    .stop_sending_frames = probe_packet.stop_sending_frames,
    .max_data_frame = probe_packet.max_data_frame,
    .max_stream_data_frames = probe_packet.max_stream_data_frames,
    .max_streams_frames = probe_packet.max_streams_frames,
    .data_blocked_frame = probe_packet.data_blocked_frame,
    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
    .stream_fragments = probe_stream_fragments,
    .has_ping = include_ping,
    .bytes_in_flight = datagram.value().size(),
    .qlog_pto_probe = true,
};
```

And pass the send trigger into packet snapshots:

```cpp
const auto trigger =
    sent->second.qlog_pto_probe ? std::optional<std::string>("pto_probe") : std::nullopt;
const auto snapshot = make_qlog_packet_snapshot(
    datagram_packets[index], encoded.value().packet_metadata[index].length,
    outbound_datagram_id.value_or(0), trigger);
```

- [ ] **Step 4: Run the targeted qlog suites and then the full suite**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicQlogTest.*:QuicProtectedCodecTest.*Metadata*:QuicTlsAdapterContractTest.*QlogTelemetry*:QuicCoreTest.*Qlog*'
```

Expected: PASS for all focused qlog-related tests.

Run:

```bash
nix develop -c zig build test
```

Expected: PASS for the full GoogleTest suite.

- [ ] **Step 5: Commit the recovery and loss event wiring**

Run:

```bash
git add src/quic/qlog/session.h src/quic/qlog/session.cpp src/quic/qlog/json.h \
        src/quic/qlog/json.cpp src/quic/connection.h src/quic/connection.cpp \
        tests/quic_core_test.cpp
git commit -m "feat: emit qlog recovery and loss events"
```

Expected: one final feature commit for the seven-event qlog slice.

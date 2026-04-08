# Multi-Connection QUIC Core Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `QuicCore` into the endpoint-scoped, multi-connection, I/O-agnostic QUIC transport manager; move QUIC routing/prerouting out of the HTTP/0.9 runtime; and make HTTP/0.9 consume handle-tagged transport events above the new core.

**Architecture:** Add a new endpoint-scoped `QuicCore` API first, but keep a temporary single-connection shim long enough to keep the tree buildable while the runtime migrates. Then move multi-connection dispatch, CID routing, Retry/version-negotiation prerouting, timer aggregation, and per-connection route-to-path bookkeeping into `src/quic/core.*`. After transport semantics are correct, add small HTTP/0.9 app-manager classes above `QuicCore`, slim the runtime down to CLI plus route-handle plus socket work, and only then move files into `src/apps/http09/` and `src/runtime/`.

**Tech Stack:** C++20, Zig build graph, GoogleTest, QUIC packet/parsing code already in `src/quic/`, POSIX UDP sockets in the runtime layer, Nix dev shell, pre-commit `clang-format` and `clang-tidy`

---

## File Map

- Create: `tests/support/core/endpoint_test_fixtures.h`
- Create: `tests/core/endpoint/open_test.cpp`
- Create: `tests/core/endpoint/multiplex_test.cpp`
- Create: `tests/core/endpoint/server_routing_test.cpp`
- Create: `tests/core/endpoint/client_restart_test.cpp`
- Modify: `build.zig`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/resumption.h`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/http09.h`
- Modify: `src/quic/http09_client.h`
- Modify: `src/quic/http09_server.h`
- Create: `src/quic/http09_client_app.h`
- Create: `src/quic/http09_client_app.cpp`
- Create: `src/quic/http09_server_app.h`
- Create: `src/quic/http09_server_app.cpp`
- Modify: `src/quic/http09.h`
- Modify: `src/quic/http09_client.h`
- Modify: `src/quic/http09_server.h`
- Modify: `src/quic/http09_runtime.h`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/http09_runtime_test_hooks.h`
- Modify: `tests/support/http09/runtime_test_fixtures.h`
- Modify: `tests/http09/runtime/routing_test.cpp`
- Modify: `tests/http09/runtime/retry_zero_rtt_test.cpp`
- Modify: `tests/http09/runtime/preferred_address_test.cpp`
- Modify: `tests/http09/runtime/migration_test.cpp`
- Modify: `tests/http09/runtime/io_test.cpp`
- Create: `src/runtime/udp_io.h`
- Create: `src/runtime/udp_io.cpp`
- Move: `src/quic/http09.h` -> `src/apps/http09/protocol.h`
- Move: `src/quic/http09.cpp` -> `src/apps/http09/protocol.cpp`
- Move: `src/quic/http09_client.h` -> `src/apps/http09/client_endpoint.h`
- Move: `src/quic/http09_client.cpp` -> `src/apps/http09/client_endpoint.cpp`
- Move: `src/quic/http09_server.h` -> `src/apps/http09/server_endpoint.h`
- Move: `src/quic/http09_server.cpp` -> `src/apps/http09/server_endpoint.cpp`
- Move: `src/quic/http09_client_app.h` -> `src/apps/http09/client_app.h`
- Move: `src/quic/http09_client_app.cpp` -> `src/apps/http09/client_app.cpp`
- Move: `src/quic/http09_server_app.h` -> `src/apps/http09/server_app.h`
- Move: `src/quic/http09_server_app.cpp` -> `src/apps/http09/server_app.cpp`
- Move: `src/quic/http09_runtime.h` -> `src/runtime/http09_runtime.h`
- Move: `src/quic/http09_runtime.cpp` -> `src/runtime/http09_runtime.cpp`
- Move: `src/quic/http09_runtime_test_hooks.h` -> `src/runtime/http09_runtime_test_hooks.h`
- Modify: `src/main.cpp`

### Task 1: Add The Endpoint-Scoped `QuicCore` API Shell And First Endpoint Tests

**Files:**
- Create: `tests/support/core/endpoint_test_fixtures.h`
- Create: `tests/core/endpoint/open_test.cpp`
- Modify: `build.zig`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/resumption.h`

- [ ] **Step 1: Create the endpoint test fixture header**

Create `tests/support/core/endpoint_test_fixtures.h` with exactly:

```cpp
#pragma once

#include <gtest/gtest.h>

#define private public
#include "src/quic/core.h"
#undef private
#include "tests/support/core/connection_test_fixtures.h"

namespace coquic::quic::test_support {

inline QuicCoreEndpointConfig make_client_endpoint_config() {
    return QuicCoreEndpointConfig{
        .role = EndpointRole::client,
        .verify_peer = false,
        .application_protocol = "coquic",
        .supported_versions = {kQuicVersion1},
    };
}

inline QuicCoreEndpointConfig make_server_endpoint_config() {
    return QuicCoreEndpointConfig{
        .role = EndpointRole::server,
        .verify_peer = false,
        .application_protocol = "hq-interop",
        .supported_versions = {kQuicVersion1},
        .identity = TlsIdentity{
            .certificate_pem = test::read_text_file("tests/fixtures/quic-server-cert.pem"),
            .private_key_pem = test::read_text_file("tests/fixtures/quic-server-key.pem"),
        },
    };
}

inline QuicCoreClientConnectionConfig make_client_open_config(std::uint64_t index = 1) {
    return QuicCoreClientConnectionConfig{
        .source_connection_id = ConnectionId{
            std::byte{0xc1},
            std::byte{static_cast<std::uint8_t>(index)},
        },
        .initial_destination_connection_id = ConnectionId{
            std::byte{0x83},
            std::byte{static_cast<std::uint8_t>(0x40u + index)},
        },
        .server_name = "localhost",
    };
}

inline std::vector<QuicCoreConnectionLifecycleEvent>
lifecycle_events_from(const QuicCoreResult &result) {
    std::vector<QuicCoreConnectionLifecycleEvent> out;
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect)) {
            out.push_back(*event);
        }
    }
    return out;
}

inline std::vector<QuicCoreSendDatagram> send_effects_from(const QuicCoreResult &result) {
    std::vector<QuicCoreSendDatagram> out;
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            out.push_back(*send);
        }
    }
    return out;
}

} // namespace coquic::quic::test_support
```

Expected: the new fixture compiles once `QuicCoreEndpointConfig`, `QuicCoreClientConnectionConfig`, and `QuicCoreConnectionLifecycleEvent` exist.

- [ ] **Step 2: Write the first failing endpoint test against the new API**

Create `tests/core/endpoint/open_test.cpp` with exactly:

```cpp
#include <gtest/gtest.h>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicCoreEndpointTest, ClientOpenCreatesStableHandleAndTagsInitialSendRoute) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));

    const auto lifecycle = lifecycle_events_from(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().connection, 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::created);

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    EXPECT_EQ(sends.front().connection, 1u);
    ASSERT_TRUE(sends.front().route_handle.has_value());
    EXPECT_EQ(*sends.front().route_handle, 17u);

    ASSERT_TRUE(core.next_wakeup().has_value());
    EXPECT_EQ(core.connection_count(), 1u);
}
} // namespace
```

Expected: this test will not compile yet because the endpoint-scoped types and methods do not exist.

- [ ] **Step 3: Add the new endpoint test file to `build.zig` and run the targeted test to confirm the failure**

In `build.zig`, append the new path to `core_test_files`:

```zig
        "tests/core/connection/key_update_test.cpp",
        "tests/core/endpoint/open_test.cpp",
    };
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.ClientOpenCreatesStableHandleAndTagsInitialSendRoute'
```

Expected: FAIL at compile time with missing symbols such as `QuicCoreEndpointConfig`, `QuicCoreClientConnectionConfig`, `QuicCoreOpenConnection`, `QuicCore::advance_endpoint`, `QuicCore::next_wakeup`, or `QuicCore::connection_count`.

- [ ] **Step 4: Add the endpoint-scoped public types to `src/quic/core.h` while keeping the existing single-connection API alive**

In `src/quic/core.h`, add the new public types immediately after `using QuicPathId = std::uint64_t;`:

```cpp
using QuicConnectionHandle = std::uint64_t;
using QuicRouteHandle = std::uint64_t;

struct QuicCoreEndpointConfig {
    EndpointRole role = EndpointRole::client;
    std::vector<std::uint32_t> supported_versions = {kQuicVersion1};
    bool verify_peer = false;
    bool retry_enabled = false;
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    std::optional<QuicQlogConfig> qlog;
    std::optional<std::filesystem::path> tls_keylog_path;
};

struct QuicCoreClientConnectionConfig {
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    std::optional<ConnectionId> original_destination_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
    std::vector<std::byte> retry_token;
    std::uint32_t original_version = kQuicVersion1;
    std::uint32_t initial_version = kQuicVersion1;
    bool reacted_to_version_negotiation = false;
    std::string server_name = "localhost";
    std::optional<QuicResumptionState> resumption_state;
    QuicZeroRttConfig zero_rtt;
};
```

Replace the existing `QuicCoreLocalError` definition with:

```cpp
struct QuicCoreLocalError {
    std::optional<QuicConnectionHandle> connection;
    QuicCoreLocalErrorCode code;
    std::optional<std::uint64_t> stream_id;
};
```

Replace the temporary inbound-datagram and migration-command structs with:

```cpp
struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
    QuicPathId path_id = 0;
    std::optional<QuicRouteHandle> route_handle;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

struct QuicCoreRequestConnectionMigration {
    QuicPathId path_id = 0;
    std::optional<QuicRouteHandle> route_handle;
    QuicMigrationRequestReason reason = QuicMigrationRequestReason::active;
};
```

Add the new endpoint input types:

```cpp
struct QuicCoreOpenConnection {
    QuicCoreClientConnectionConfig connection;
    QuicRouteHandle initial_route_handle = 0;
};

using QuicCoreConnectionInput =
    std::variant<QuicCoreSendStreamData, QuicCoreResetStream, QuicCoreStopSending,
                 QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                 QuicCoreRequestConnectionMigration>;

struct QuicCoreConnectionCommand {
    QuicConnectionHandle connection = 0;
    QuicCoreConnectionInput input;
};

using QuicCoreEndpointInput =
    std::variant<QuicCoreOpenConnection, QuicCoreInboundDatagram, QuicCoreConnectionCommand,
                 QuicCoreTimerExpired>;
```

Add handle-tagged effect fields without removing the temporary single-connection fields yet:

```cpp
struct QuicCoreSendDatagram {
    QuicConnectionHandle connection = 0;
    std::optional<QuicPathId> path_id;
    std::optional<QuicRouteHandle> route_handle;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};

struct QuicCoreReceiveStreamData {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCorePeerResetStream {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
    std::uint64_t final_size = 0;
};

struct QuicCorePeerStopSending {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStateEvent {
    QuicConnectionHandle connection = 0;
    QuicCoreStateChange change;
};

enum class QuicCoreConnectionLifecycle : std::uint8_t {
    created,
    accepted,
    closed,
};

struct QuicCoreConnectionLifecycleEvent {
    QuicConnectionHandle connection = 0;
    QuicCoreConnectionLifecycle event = QuicCoreConnectionLifecycle::created;
};

struct QuicCorePeerPreferredAddressAvailable {
    QuicConnectionHandle connection = 0;
    PreferredAddress preferred_address;
};
```

Update the class declaration to add the endpoint constructor and endpoint entrypoint, but keep the old constructor and `advance` method for now:

```cpp
class QuicCore {
  public:
    explicit QuicCore(QuicCoreEndpointConfig config);
    explicit QuicCore(QuicCoreConfig config);
    ~QuicCore();

    QuicCore(const QuicCore &) = delete;
    QuicCore &operator=(const QuicCore &) = delete;
    QuicCore(QuicCore &&) noexcept;
    QuicCore &operator=(QuicCore &&) noexcept;

    QuicCoreResult advance_endpoint(QuicCoreEndpointInput input, QuicCoreTimePoint now);
    QuicCoreResult advance(QuicCoreInput input, QuicCoreTimePoint now);
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    std::size_t connection_count() const;

    std::vector<ConnectionId> active_local_connection_ids() const;
    bool is_handshake_complete() const;
    bool has_failed() const;

  private:
    struct ConnectionEntry;
```

Expected: the header compiles once `QuicCoreResult` and the remaining private members are updated in the next step.

- [ ] **Step 5: Move the resumption and 0-RTT effect wrappers into `src/quic/core.h` and keep `src/quic/resumption.h` transport-neutral**

In `src/quic/resumption.h`, delete the two `QuicCore*` effect structs and leave only the transport-neutral state and status types:

```cpp
struct QuicResumptionState {
    std::vector<std::byte> serialized;
};

struct QuicZeroRttConfig {
    bool attempt = false;
    bool allow = false;
    std::vector<std::byte> application_context;
};

enum class QuicZeroRttStatus : std::uint8_t {
    unavailable,
    not_attempted,
    attempted,
    accepted,
    rejected,
};
```

Then add the handle-tagged wrappers in `src/quic/core.h` right after `QuicCorePeerPreferredAddressAvailable`:

```cpp
struct QuicCoreResumptionStateAvailable {
    QuicConnectionHandle connection = 0;
    QuicResumptionState state;
};

struct QuicCoreZeroRttStatusEvent {
    QuicConnectionHandle connection = 0;
    QuicZeroRttStatus status = QuicZeroRttStatus::not_attempted;
};
```

Expected: `QuicCoreEffect` can keep using the same variant name, but every effect type is now handle-tagged.

- [ ] **Step 6: Implement the minimal endpoint scaffold in `src/quic/core.cpp`**

At the top of `src/quic/core.cpp`, add the new private entry struct and the new endpoint-aware members:

```cpp
struct QuicCore::ConnectionEntry {
    QuicConnectionHandle handle = 0;
    std::optional<QuicRouteHandle> default_route_handle;
    std::unique_ptr<QuicConnection> connection;
};
```

Add the new constructors and accessors:

```cpp
QuicCore::QuicCore(QuicCoreEndpointConfig config) : endpoint_config_(std::move(config)) {
}

QuicCore::QuicCore(QuicCoreConfig config)
    : endpoint_config_(QuicCoreEndpointConfig{
          .role = config.role,
          .supported_versions = config.supported_versions,
          .verify_peer = config.verify_peer,
          .application_protocol = config.application_protocol,
          .identity = config.identity,
          .transport = config.transport,
          .allowed_tls_cipher_suites = config.allowed_tls_cipher_suites,
          .qlog = config.qlog,
          .tls_keylog_path = config.tls_keylog_path,
      }),
      legacy_config_(std::move(config)) {
}

std::optional<QuicCoreTimePoint> QuicCore::next_wakeup() const {
    std::optional<QuicCoreTimePoint> earliest;
    for (const auto &[handle, entry] : connections_) {
        (void)handle;
        const auto candidate = entry.connection->next_wakeup();
        if (!candidate.has_value()) {
            continue;
        }
        earliest = std::min(earliest.value_or(*candidate), *candidate);
    }
    return earliest;
}

std::size_t QuicCore::connection_count() const {
    return connections_.size();
}
```

Add the endpoint entrypoint branch for client opens:

```cpp
QuicCoreResult QuicCore::advance_endpoint(QuicCoreEndpointInput input, QuicCoreTimePoint now) {
    if (const auto *open = std::get_if<QuicCoreOpenConnection>(&input)) {
        QuicCoreConfig config{
            .role = endpoint_config_.role,
            .source_connection_id = open->connection.source_connection_id,
            .initial_destination_connection_id =
                open->connection.initial_destination_connection_id,
            .original_destination_connection_id =
                open->connection.original_destination_connection_id,
            .retry_source_connection_id = open->connection.retry_source_connection_id,
            .retry_token = open->connection.retry_token,
            .original_version = open->connection.original_version,
            .initial_version = open->connection.initial_version,
            .supported_versions = endpoint_config_.supported_versions,
            .reacted_to_version_negotiation =
                open->connection.reacted_to_version_negotiation,
            .verify_peer = endpoint_config_.verify_peer,
            .server_name = open->connection.server_name,
            .application_protocol = endpoint_config_.application_protocol,
            .identity = endpoint_config_.identity,
            .transport = endpoint_config_.transport,
            .allowed_tls_cipher_suites = endpoint_config_.allowed_tls_cipher_suites,
            .resumption_state = open->connection.resumption_state,
            .zero_rtt = open->connection.zero_rtt,
            .qlog = endpoint_config_.qlog,
            .tls_keylog_path = endpoint_config_.tls_keylog_path,
        };

        auto entry = ConnectionEntry{
            .handle = next_connection_handle_++,
            .default_route_handle = open->initial_route_handle,
            .connection = std::make_unique<QuicConnection>(std::move(config)),
        };
        entry.connection->start(now);

        QuicCoreResult result;
        const auto handle = entry.handle;
        while (true) {
            auto datagram = entry.connection->drain_outbound_datagram(now);
            if (datagram.empty()) {
                break;
            }
            result.effects.emplace_back(QuicCoreSendDatagram{
                .connection = handle,
                .path_id = entry.connection->last_drained_path_id(),
                .route_handle = entry.default_route_handle,
                .bytes = std::move(datagram),
                .ecn = entry.connection->last_drained_ecn_codepoint(),
            });
        }
        result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = handle,
            .event = QuicCoreConnectionLifecycle::created,
        });
        connections_.emplace(handle, std::move(entry));
        result.next_wakeup = next_wakeup();
        return result;
    }

    return {};
}
```

Keep the old `advance(QuicCoreInput, now)` body in place for now, but have it lazily create one legacy entry so the old runtime still compiles while Tasks 2 through 5 migrate:

```cpp
if (connections_.empty() && legacy_config_.has_value()) {
    auto entry = ConnectionEntry{
        .handle = next_connection_handle_++,
        .connection = std::make_unique<QuicConnection>(*legacy_config_),
    };
    connections_.emplace(entry.handle, std::move(entry));
}
```

Expected: the new endpoint test compiles and passes, and existing runtime callers still build because the old constructor and `advance` method still exist.

- [ ] **Step 7: Run the new endpoint test and one legacy transport test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.ClientOpenCreatesStableHandleAndTagsInitialSendRoute:QuicCoreTest.ProcessInboundDatagramIgnoresInitialPacketsAfterDiscardingInitialSpace'
```

Expected: PASS for both tests.

- [ ] **Step 8: Commit the API shell**

Run:

```bash
git add build.zig \
  src/quic/core.h \
  src/quic/core.cpp \
  src/quic/resumption.h \
  tests/support/core/endpoint_test_fixtures.h \
  tests/core/endpoint/open_test.cpp
git commit -m "refactor: add endpoint-scoped quic core shell"
```

### Task 2: Implement Multi-Connection Dispatch, Tagged Effect Draining, And Wakeup Aggregation

**Files:**
- Create: `tests/core/endpoint/multiplex_test.cpp`
- Modify: `build.zig`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/support/core/endpoint_test_fixtures.h`

- [ ] **Step 1: Add a failing endpoint test for per-handle command dispatch**

Create `tests/core/endpoint/multiplex_test.cpp` with exactly:

```cpp
#include <gtest/gtest.h>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicCoreEndpointTest, ConnectionCommandsOnlyAdvanceTheSelectedHandle) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(1)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    *core.connections_.at(2).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
    core.connections_.at(2).route_handle_by_path_id.emplace(0, 22);
    core.connections_.at(2).path_id_by_route_handle.emplace(22, 0);

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 2,
            .input = coquic::quic::QuicCoreSendStreamData{
                .stream_id = 0,
                .bytes = bytes_from_ints({0x68, 0x69}),
                .fin = true,
            },
        },
        coquic::quic::test::test_time(2));

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    for (const auto &send : sends) {
        EXPECT_EQ(send.connection, 2u);
        ASSERT_TRUE(send.route_handle.has_value());
        EXPECT_EQ(*send.route_handle, 22u);
    }
    EXPECT_EQ(core.connection_count(), 2u);
}

TEST(QuicCoreEndpointTest, EndpointTimerExpiredWalksAllDueConnections) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(0)));

    ASSERT_TRUE(core.next_wakeup().has_value());
    const auto wakeup = *core.next_wakeup();
    const auto result =
        core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{}, wakeup);

    EXPECT_EQ(core.connection_count(), 2u);
    EXPECT_EQ(result.next_wakeup, core.next_wakeup());
}
} // namespace
```

Expected: this test will not compile yet because `connections_`, `route_handle_by_path_id`, and `path_id_by_route_handle` are not defined.

- [ ] **Step 2: Add the new multiplex test to `build.zig` and confirm the compile failure**

Append the new source path in `build.zig`:

```zig
        "tests/core/endpoint/open_test.cpp",
        "tests/core/endpoint/multiplex_test.cpp",
    };
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.ConnectionCommandsOnlyAdvanceTheSelectedHandle'
```

Expected: FAIL at compile time because the `ConnectionEntry` route maps and endpoint command dispatch do not exist yet.

- [ ] **Step 3: Expand `QuicCore::ConnectionEntry` to hold per-connection route bookkeeping**

Replace the private entry struct in `src/quic/core.h` with:

```cpp
    struct ConnectionEntry {
        QuicConnectionHandle handle = 0;
        std::optional<QuicRouteHandle> default_route_handle;
        std::unique_ptr<QuicConnection> connection;
        std::unordered_map<QuicRouteHandle, QuicPathId> path_id_by_route_handle;
        std::unordered_map<QuicPathId, QuicRouteHandle> route_handle_by_path_id;
    };
```

Also add the missing top-level include at the top of `src/quic/core.h`:

```cpp
#include <unordered_map>
```

Add the storage members immediately after it:

```cpp
    QuicCoreEndpointConfig endpoint_config_;
    std::optional<QuicCoreConfig> legacy_config_;
    std::unordered_map<QuicConnectionHandle, ConnectionEntry> connections_;
    QuicConnectionHandle next_connection_handle_ = 1;
```

Expected: tests can use `#define private public` to seed route mappings without exposing a new public test API.

- [ ] **Step 4: Implement handle-targeted command dispatch and shared effect draining**

In `src/quic/core.cpp`, add these helpers above `QuicCore::advance_endpoint`:

```cpp
QuicCoreResult drain_connection_effects(QuicCore::ConnectionEntry &entry, QuicCoreTimePoint now) {
    QuicCoreResult result;

    while (true) {
        auto datagram = entry.connection->drain_outbound_datagram(now);
        if (datagram.empty()) {
            break;
        }

        const auto path_id = entry.connection->last_drained_path_id();
        const auto route_it =
            path_id.has_value() ? entry.route_handle_by_path_id.find(*path_id)
                                : entry.route_handle_by_path_id.end();
        result.effects.emplace_back(QuicCoreSendDatagram{
            .connection = entry.handle,
            .path_id = path_id,
            .route_handle = route_it != entry.route_handle_by_path_id.end()
                                ? std::optional<QuicRouteHandle>(route_it->second)
                                : entry.default_route_handle,
            .bytes = std::move(datagram),
            .ecn = entry.connection->last_drained_ecn_codepoint(),
        });
    }

    while (const auto received = entry.connection->take_received_stream_data()) {
        result.effects.emplace_back(QuicCoreReceiveStreamData{
            .connection = entry.handle,
            .stream_id = received->stream_id,
            .bytes = std::move(received->bytes),
            .fin = received->fin,
        });
    }
    while (const auto reset = entry.connection->take_peer_reset_stream()) {
        result.effects.emplace_back(QuicCorePeerResetStream{
            .connection = entry.handle,
            .stream_id = reset->stream_id,
            .application_error_code = reset->application_error_code,
            .final_size = reset->final_size,
        });
    }
    while (const auto stop = entry.connection->take_peer_stop_sending()) {
        result.effects.emplace_back(QuicCorePeerStopSending{
            .connection = entry.handle,
            .stream_id = stop->stream_id,
            .application_error_code = stop->application_error_code,
        });
    }
    while (const auto event = entry.connection->take_state_change()) {
        result.effects.emplace_back(QuicCoreStateEvent{
            .connection = entry.handle,
            .change = *event,
        });
    }
    while (const auto preferred = entry.connection->take_peer_preferred_address_available()) {
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .connection = entry.handle,
            .preferred_address = preferred->preferred_address,
        });
    }
    while (const auto state = entry.connection->take_resumption_state_available()) {
        result.effects.emplace_back(QuicCoreResumptionStateAvailable{
            .connection = entry.handle,
            .state = state->state,
        });
    }
    while (const auto status = entry.connection->take_zero_rtt_status_event()) {
        result.effects.emplace_back(QuicCoreZeroRttStatusEvent{
            .connection = entry.handle,
            .status = status->status,
        });
    }
    if (const auto terminal = entry.connection->take_terminal_state()) {
        if (*terminal == QuicConnectionTerminalState::closed) {
            result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
                .connection = entry.handle,
                .event = QuicCoreConnectionLifecycle::closed,
            });
        }
    }

    result.next_wakeup = entry.connection->next_wakeup();
    return result;
}
```

Back this with a minimal terminal-state hook in `src/quic/connection.h`:

```cpp
enum class QuicConnectionTerminalState : std::uint8_t {
    closed,
    failed,
};

std::optional<QuicConnectionTerminalState> take_terminal_state();
```

Add the backing member in `src/quic/connection.h` next to the other pending effect queues:

```cpp
    std::optional<QuicConnectionTerminalState> pending_terminal_state_;
```

And in `src/quic/connection.cpp`, set the pending terminal state at the two existing terminal
boundaries:

```cpp
std::optional<QuicConnectionTerminalState> QuicConnection::take_terminal_state() {
    if (!pending_terminal_state_.has_value()) {
        return std::nullopt;
    }
    const auto out = pending_terminal_state_;
    pending_terminal_state_.reset();
    return out;
}
```

Set `pending_terminal_state_ = QuicConnectionTerminalState::failed;` in the existing hard-failure
path that currently flips `status_ = HandshakeStatus::failed;`, and set
`pending_terminal_state_ = QuicConnectionTerminalState::closed;` immediately after a locally queued
or peer-observed `CONNECTION_CLOSE` reaches its terminal state.

Then add the command branch inside `QuicCore::advance_endpoint`:

```cpp
    if (const auto *command = std::get_if<QuicCoreConnectionCommand>(&input)) {
        auto entry_it = connections_.find(command->connection);
        if (entry_it == connections_.end()) {
            return QuicCoreResult{
                .local_error = QuicCoreLocalError{
                    .connection = command->connection,
                    .code = QuicCoreLocalErrorCode::unsupported_operation,
                },
            };
        }

        auto &entry = entry_it->second;
        QuicCoreResult result;
        std::visit(
            overloaded{
                [&](const QuicCoreSendStreamData &in) {
                    const auto queued =
                        entry.connection->queue_stream_send(in.stream_id, in.bytes, in.fin);
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreResetStream &in) {
                    const auto queued = entry.connection->queue_stream_reset(LocalResetCommand{
                        .stream_id = in.stream_id,
                        .application_error_code = in.application_error_code,
                    });
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreStopSending &in) {
                    const auto queued = entry.connection->queue_stop_sending(LocalStopSendingCommand{
                        .stream_id = in.stream_id,
                        .application_error_code = in.application_error_code,
                    });
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreCloseConnection &in) {
                    static_cast<void>(
                        entry.connection->queue_application_close(LocalApplicationCloseCommand{
                            .application_error_code = in.application_error_code,
                            .reason_phrase = in.reason_phrase,
                        }));
                },
                [&](const QuicCoreRequestKeyUpdate &) { entry.connection->request_key_update(); },
                [&](const QuicCoreRequestConnectionMigration &in) {
                    const auto path_id =
                        in.route_handle.has_value()
                            ? entry.path_id_by_route_handle.contains(*in.route_handle)
                                  ? entry.path_id_by_route_handle.at(*in.route_handle)
                                  : in.path_id
                            : in.path_id;
                    const auto requested =
                        entry.connection->request_connection_migration(path_id, in.reason);
                    if (!requested.has_value()) {
                        result.local_error = QuicCoreLocalError{
                            .connection = entry.handle,
                            .code = QuicCoreLocalErrorCode::unsupported_operation,
                        };
                    }
                },
                [&](const auto &) {},
            },
            command->input);

        auto drained = drain_connection_effects(entry, now);
        result.effects.insert(result.effects.end(),
                              std::make_move_iterator(drained.effects.begin()),
                              std::make_move_iterator(drained.effects.end()));
        if (entry.connection->has_failed()) {
            connections_.erase(entry_it);
        }
        result.next_wakeup = next_wakeup();
        return result;
    }

    if (std::holds_alternative<QuicCoreTimerExpired>(input)) {
        QuicCoreResult result;
        std::vector<QuicConnectionHandle> erase_after;
        for (auto &[handle, entry] : connections_) {
            (void)handle;
            const auto wakeup = entry.connection->next_wakeup();
            if (!wakeup.has_value() || *wakeup > now) {
                continue;
            }
            entry.connection->on_timeout(now);
            auto drained = drain_connection_effects(entry, now);
            result.effects.insert(result.effects.end(),
                                  std::make_move_iterator(drained.effects.begin()),
                                  std::make_move_iterator(drained.effects.end()));
            if (entry.connection->has_failed()) {
                erase_after.push_back(entry.handle);
            }
        }
        for (const auto handle : erase_after) {
            connections_.erase(handle);
        }
        result.next_wakeup = next_wakeup();
        return result;
    }
```

If a connection emits `QuicCoreConnectionLifecycle::closed`, erase that handle in the same
post-drain cleanup path so `connection_count()` reflects only live entries.

Expected: the endpoint command test now passes, and `QuicCoreResult.local_error.connection` points at the failing handle.

- [ ] **Step 5: Run the new multiplex test and the full core test binary**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.ConnectionCommandsOnlyAdvanceTheSelectedHandle'
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.*'
```

Expected: PASS for the new endpoint tests.

- [ ] **Step 6: Commit the multiplexing support**

Run:

```bash
git add build.zig \
  src/quic/connection.h \
  src/quic/connection.cpp \
  src/quic/core.h \
  src/quic/core.cpp \
  tests/support/core/endpoint_test_fixtures.h \
  tests/core/endpoint/multiplex_test.cpp
git commit -m "refactor: add multiconnection core dispatch"
```

### Task 3: Move Server CID Routing, Version Negotiation, And Retry Prerouting Into `QuicCore`

**Files:**
- Create: `tests/core/endpoint/server_routing_test.cpp`
- Modify: `build.zig`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/http09_runtime_test_hooks.h`
- Modify: `tests/http09/runtime/routing_test.cpp`
- Modify: `tests/http09/runtime/retry_zero_rtt_test.cpp`

- [ ] **Step 1: Write a failing core endpoint test for server-side accept, version negotiation, and retry**

Create `tests/core/endpoint/server_routing_test.cpp` with exactly:

```cpp
#include <gtest/gtest.h>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

std::vector<std::byte> captured_picoquic_client_initial_datagram() {
    return bytes_from_hex(
        "ce00000001085398e92f19c3659808825ff16a7a5d8b9f0041409c471d3fbfe46c43389ad82ab17702dc"
        "9686e7157b4dcceaeecc13f61aef037f58b15e94c06417a351f30d50cf1152098bb49ce2b69c3ba80bd5"
        "cb9e1086f9a7f6d2f854b5b5638b23486d23ad1651202d87997ba51cb9f7a14d20bb430b4e6b5e25b940"
        "16b0d7ad981ae8e883a49a461444a531929c5d24044b6964cfeb5b2132e0053a434ecdd0ea2ae8adb8ca"
        "274e2ee7e6d680ea6d4756e4c37268970177613d2f31b6db1cb0799bb2f506830c96de55b72228253a6c"
        "f4d0f3512e5d93b7d8cb262a471ca0ec44eba3ceadd500870849b5cf00782bbb38188c49c95b776c97ae"
        "0fecd918f499525b6b9a61d900fb43844de41cc805abbef8c99b5727003a094b22955c2e582a45057521"
        "9cac4d4b3c51be3a436bae6e032b619c5773547abebf9f63ad9ab519f19c6813411b76e9b040d48c9d94"
        "ef16dd17aaca9bf3cd862e27007aec392281967ec218de253c37c2bc45aec40570b5c1aad297b56e3fcf"
        "aaea35a0bc7c53de7e3d5fe4a7786a02a205421d5aa9a40a4dfcc7df3415d42a96256ed422dfdeda4322"
        "8c84f714b0f312521fd34edb356fd1fc12a5c49e6b77e16cf6198a29e196a0d7afe26a8fb46ecd1215f1"
        "7125619b579e9b13e0a982faaa42605f50f992140560e3011a64248df0a6a7ac87a4b500c70206618c8c"
        "1df51145aebd76773470ca88b8cb2fb2f47bfbeb92736837d9d94dfcc7df3415d42ab2fb517033e41d7e"
        "49f54b4fddd99742ea55c6f02aea1cd3e8e4327f860d7c18c6c455b78b0f5245e98165442b45d00b4272"
        "ca77bae3d14f7e3b68f2a426ef3429eca95eb24cd1ba7c55c7ff46bae3f2614ede6e8b679bde2d52f465"
        "ab4ee9d6a72efd6b9974c9a8cad66100d27e107a7bc695cfb229120dcd21c583eae090e5164faff7db96"
        "1e139012e71c657a89b5b9770e24bbcce8b5f7f9c2a9c0146cbf1512d156bbd182301c01a7eb252a0133"
        "83bcd866859e51ff2e4322839f64f0d0357213b2d610f696fe1bc3b48fa3ad8fd349e1426c6d6c6fec01"
        "acd9304cba80bcfd4bde751f4c76cabd262fee0c15bbfbfccd0c7a547857cd813a4977f6befab20399e8"
        "62e65c0eb81f95e27387f233ef0c82823c62f61da922b268caa09bc585ee26a645b56f735231bf8ca7fe"
        "3f65387fa669c229e7f4ac0115d6da7a5ab3c84c9633a67d8b00bcae2898b8203d9d7d7e04664bc2a782"
        "672ac79f3f8de8bd3cd89730557b0a94ae103b715f221a4713cf04b42b0dd948e9089cedaf267bbbcb40"
        "e06180aa90932ede76825f3e6d6badc2542cc8746986368ce3038a36782c60cf8da7279859cbd92033d6"
        "294238f2fa3a780f5141350c9994ac0ce4814653a4d8acad56eeeeb857cf6e97a5e4542f5e3e56f9f06b"
        "0b351a0cc6bb2a7ed3af43fd69e576e20bf4fb578b83bebb79c984c3f167bb065c745cb0d6e1e83cb620"
        "e9427e6352d431fe3c0fe6a8507155c6c6117cdea8048b6637546140320447dc4b4ce533bde22778023a"
        "6e94413981afd021b3d3d6e34cc91786e95414083731cf1e8efb8e6497734a67021d7e3174391d616388"
        "da325bd70449c0f3f823f1da82c67add7701068e673ef0dba9d912082ffde7aefba917324ace49e22202"
        "fe73854a4d994a2c60696815a474a2510bca2bdec845fe96333be55b5d59e068223510494d812491b7ff"
        "cbb9abb1db0b1dbec9b72a644bf39ef778a68cec4d70120c56d9b3fa7eea849e980f");
}

TEST(QuicCoreEndpointTest, SupportedInitialIsAcceptedInsideCore) {
    coquic::quic::QuicCore core(make_server_endpoint_config());

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = captured_picoquic_client_initial_datagram(),
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1));

    const auto lifecycle = lifecycle_events_from(result);
    ASSERT_FALSE(lifecycle.empty());
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::accepted);

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    EXPECT_EQ(sends.front().connection, lifecycle.front().connection);
    ASSERT_TRUE(sends.front().route_handle.has_value());
    EXPECT_EQ(*sends.front().route_handle, 31u);
}

TEST(QuicCoreEndpointTest, RepeatedSupportedInitialReusesAcceptedHandle) {
    coquic::quic::QuicCore core(make_server_endpoint_config());

    const auto datagram = captured_picoquic_client_initial_datagram();
    const auto first = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagram,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1));
    const auto accepted = lifecycle_events_from(first);
    ASSERT_EQ(accepted.size(), 1u);

    const auto second = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagram,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(2));

    EXPECT_EQ(core.connection_count(), 1u);
    const auto lifecycle = lifecycle_events_from(second);
    EXPECT_TRUE(lifecycle.empty());
}
} // namespace
```

Expected: this test will fail because server-side accept still lives in `http09_runtime.cpp`.

- [ ] **Step 2: Register the new server endpoint test and confirm the failure**

Append the new test file in `build.zig`:

```zig
        "tests/core/endpoint/multiplex_test.cpp",
        "tests/core/endpoint/server_routing_test.cpp",
    };
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.SupportedInitialIsAcceptedInsideCore'
```

Expected: FAIL because `advance_endpoint` returns no accepted lifecycle event and no server flight.

- [ ] **Step 3: Move server prerouting helpers from `http09_runtime.cpp` into `src/quic/core.cpp`**

Cut these types and helpers out of `src/quic/http09_runtime.cpp` and place them in the
private section of `src/quic/core.h` plus the anonymous namespace in `src/quic/core.cpp`:

```cpp
struct ParsedEndpointDatagram {
    enum class Kind : std::uint8_t {
        short_header,
        supported_initial,
        supported_long_header,
        unsupported_version_long_header,
    };

    Kind kind = Kind::short_header;
    ConnectionId destination_connection_id;
    std::optional<ConnectionId> source_connection_id;
    std::uint32_t version = kQuicVersion1;
    std::vector<std::byte> token;
};

struct PendingRetryToken {
    ConnectionId original_destination_connection_id;
    ConnectionId retry_source_connection_id;
    std::uint32_t original_version = kQuicVersion1;
    std::vector<std::byte> token;
    QuicRouteHandle route_handle = 0;
};

    using RetryTokenStore = std::unordered_map<std::string, PendingRetryToken>;
    RetryTokenStore retry_tokens_;
```

Move the parser and response builders, but switch the send surface from real sockets to datagram effects:

```cpp
std::string connection_id_key(std::span<const std::byte> connection_id);
std::optional<ParsedEndpointDatagram> parse_endpoint_datagram(std::span<const std::byte> bytes);
std::vector<std::byte> make_endpoint_retry_token(std::uint64_t sequence);
std::optional<PendingRetryToken>
take_retry_context(const ParsedEndpointDatagram &parsed, RetryTokenStore &retry_tokens);
std::vector<std::byte>
make_version_negotiation_packet_bytes(const ParsedEndpointDatagram &parsed,
                                      std::span<const std::uint32_t> supported_versions);
std::vector<std::byte> make_retry_packet_bytes(const ParsedEndpointDatagram &parsed,
                                               const PendingRetryToken &pending);
```

Expected: transport prerouting logic stops depending on socket FDs, peers, or `sendto`.

- [ ] **Step 4: Teach `QuicCore::advance_endpoint` to accept new server connections and emit Retry or version-negotiation itself**

Insert this server-datagram branch near the top of `QuicCore::advance_endpoint`, before the connection-command handling:

```cpp
    if (const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&input);
        inbound != nullptr && endpoint_config_.role == EndpointRole::server) {
        const auto parsed = parse_endpoint_datagram(inbound->bytes);
        if (!parsed.has_value()) {
            return {};
        }

        if (parsed->kind == ParsedEndpointDatagram::Kind::unsupported_version_long_header) {
            return QuicCoreResult{
                .effects =
                    {
                        QuicCoreSendDatagram{
                            .connection = 0,
                            .route_handle = inbound->route_handle,
                            .bytes = make_version_negotiation_packet_bytes(
                                *parsed, endpoint_config_.supported_versions),
                        },
                    },
            };
        }

        const auto retry_context =
            parsed->kind == ParsedEndpointDatagram::Kind::supported_initial
                ? take_retry_context(*parsed, retry_tokens_)
                : std::nullopt;

        if (parsed->kind == ParsedEndpointDatagram::Kind::supported_initial &&
            endpoint_config_.retry_enabled && !retry_context.has_value()) {
            const auto sequence = next_connection_handle_;
            const auto token = make_endpoint_retry_token(sequence);
            const auto retry_source_connection_id =
                ConnectionId{std::byte{0x53}, std::byte{static_cast<std::uint8_t>(sequence)}};
            retry_tokens_.emplace(
                connection_id_key(token),
                PendingRetryToken{
                    .original_destination_connection_id = parsed->destination_connection_id,
                    .retry_source_connection_id = retry_source_connection_id,
                    .original_version = parsed->version,
                    .token = token,
                    .route_handle = inbound->route_handle.value_or(0),
                });
            return QuicCoreResult{
                .effects =
                    {
                        QuicCoreSendDatagram{
                            .connection = 0,
                            .route_handle = inbound->route_handle,
                            .bytes = make_retry_packet_bytes(
                                *parsed,
                                PendingRetryToken{
                                    .original_destination_connection_id =
                                        parsed->destination_connection_id,
                                    .retry_source_connection_id = retry_source_connection_id,
                                    .original_version = parsed->version,
                                    .token = token,
                                    .route_handle = inbound->route_handle.value_or(0),
                                }),
                        },
                    },
            };
        }

        if (parsed->kind == ParsedEndpointDatagram::Kind::supported_initial) {
            QuicCoreConfig config{
                .role = EndpointRole::server,
                .source_connection_id = ConnectionId{
                    std::byte{0x53},
                    std::byte{static_cast<std::uint8_t>(next_connection_handle_)},
                },
                .supported_versions = endpoint_config_.supported_versions,
                .verify_peer = endpoint_config_.verify_peer,
                .application_protocol = endpoint_config_.application_protocol,
                .identity = endpoint_config_.identity,
                .transport = endpoint_config_.transport,
                .allowed_tls_cipher_suites = endpoint_config_.allowed_tls_cipher_suites,
                .qlog = endpoint_config_.qlog,
                .tls_keylog_path = endpoint_config_.tls_keylog_path,
            };
            if (retry_context.has_value()) {
                config.initial_destination_connection_id =
                    retry_context->retry_source_connection_id;
                config.original_destination_connection_id =
                    retry_context->original_destination_connection_id;
                config.retry_source_connection_id =
                    retry_context->retry_source_connection_id;
                config.original_version = retry_context->original_version;
                config.initial_version = retry_context->original_version;
            }

            auto entry = ConnectionEntry{
                .handle = next_connection_handle_++,
                .default_route_handle = inbound->route_handle,
                .connection = std::make_unique<QuicConnection>(std::move(config)),
            };
            const auto path_id = 0u;
            entry.path_id_by_route_handle.emplace(inbound->route_handle.value_or(0), path_id);
            entry.route_handle_by_path_id.emplace(path_id, inbound->route_handle.value_or(0));
            entry.connection->process_inbound_datagram(inbound->bytes, now, path_id, inbound->ecn);

            auto result = drain_connection_effects(entry, now);
            result.effects.insert(result.effects.begin(), QuicCoreConnectionLifecycleEvent{
                                                           .connection = entry.handle,
                                                           .event = QuicCoreConnectionLifecycle::
                                                               accepted,
                                                       });
            connections_.emplace(entry.handle, std::move(entry));
            result.next_wakeup = next_wakeup();
            return result;
        }
    }
```

Expected: server-side new connection acceptance, Retry, and version negotiation no longer depend on `http09_runtime.cpp`.

- [ ] **Step 5: Delete the transport-routing test hooks from the HTTP/0.9 runtime and move those assertions into the new endpoint tests**

Delete these declarations from `src/quic/http09_runtime_test_hooks.h`:

```cpp
bool supported_long_header_routes_via_initial_destination_for_tests();
bool retry_context_lookup_for_tests();
bool invalid_retry_token_server_datagram_path_for_tests();
bool retry_trace_paths_for_tests();
bool send_retry_for_initial_failures_for_tests();
std::optional<ParsedServerDatagramForTests>
parse_server_datagram_for_routing_for_tests(std::span<const std::byte> bytes);
```

Replace the transport-only assertions in `tests/http09/runtime/routing_test.cpp` and
`tests/http09/runtime/retry_zero_rtt_test.cpp` with comments-free deletions, keeping only
HTTP/0.9/runtime behavior there. The transport coverage for parsing, accept, Retry, and version
negotiation now belongs in `tests/core/endpoint/server_routing_test.cpp`.

Expected: `tests/http09/runtime/*` stop depending on QUIC endpoint-routing internals.

- [ ] **Step 6: Run the new server endpoint tests and the remaining HTTP/0.9 runtime tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.SupportedInitialIsAcceptedInsideCore:QuicHttp09RuntimeTest.*'
```

Expected: PASS for the new endpoint test and the still-runtime-focused HTTP/0.9 tests.

- [ ] **Step 7: Commit the server prerouting move**

Run:

```bash
git add build.zig \
  src/quic/core.h \
  src/quic/core.cpp \
  src/quic/http09_runtime.cpp \
  src/quic/http09_runtime_test_hooks.h \
  tests/core/endpoint/server_routing_test.cpp \
  tests/http09/runtime/routing_test.cpp \
  tests/http09/runtime/retry_zero_rtt_test.cpp
git commit -m "refactor: move server prerouting into quic core"
```

### Task 4: Move Client Retry Or Version-Negotiation Restart And Route-Handle Bookkeeping Into `QuicCore`

**Files:**
- Create: `tests/core/endpoint/client_restart_test.cpp`
- Modify: `build.zig`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `tests/support/core/endpoint_test_fixtures.h`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/http09_runtime_test_hooks.h`
- Modify: `tests/http09/runtime/preferred_address_test.cpp`
- Modify: `tests/http09/runtime/migration_test.cpp`

- [ ] **Step 1: Add a failing endpoint test for client-side restart preserving handle and route**

Create `tests/core/endpoint/client_restart_test.cpp` with exactly:

```cpp
#include <gtest/gtest.h>

#include "src/quic/packet_crypto.h"
#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicCoreEndpointTest, RetryRestartPreservesConnectionHandleAndRouteHandle) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 44,
        },
        coquic::quic::test::test_time(0)));

    coquic::quic::RetryPacket retry_packet{
        .version = coquic::quic::kQuicVersion1,
        .destination_connection_id = ConnectionId{std::byte{0xc1}, std::byte{0x01}},
        .source_connection_id = ConnectionId{std::byte{0x99}, std::byte{0x01}},
        .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x41}},
        .retry_token = std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}},
        .integrity_tag = {},
    };
    retry_packet.integrity_tag = optional_value_or_terminate(
        coquic::quic::compute_retry_integrity_tag(
            retry_packet, retry_packet.original_destination_connection_id));

    const auto retry_bytes = optional_value_or_terminate(coquic::quic::serialize_packet(retry_packet));
    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = retry_bytes,
            .route_handle = 44,
        },
        coquic::quic::test::test_time(1));

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    EXPECT_EQ(sends.front().connection, 1u);
    ASSERT_TRUE(sends.front().route_handle.has_value());
    EXPECT_EQ(*sends.front().route_handle, 44u);
    EXPECT_EQ(core.connection_count(), 1u);
}
} // namespace
```

Expected: this test will fail because the client restart logic still mutates a single raw `connection_` pointer instead of a stable endpoint entry.

- [ ] **Step 2: Register the test and confirm the failure**

Append the new file in `build.zig`:

```zig
        "tests/core/endpoint/server_routing_test.cpp",
        "tests/core/endpoint/client_restart_test.cpp",
    };
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.RetryRestartPreservesConnectionHandleAndRouteHandle'
```

Expected: FAIL because Retry restarts still replace the single `connection_` directly and lose the endpoint entry state.

- [ ] **Step 3: Change the endpoint-side route bookkeeping from `path_id` compatibility to real route handles**

In `src/quic/core.cpp`, add these helper functions above `advance_endpoint`:

```cpp
QuicPathId ensure_path_for_route(QuicCore::ConnectionEntry &entry, QuicRouteHandle route_handle) {
    if (const auto existing = entry.path_id_by_route_handle.find(route_handle);
        existing != entry.path_id_by_route_handle.end()) {
        return existing->second;
    }

    const auto next_path_id = static_cast<QuicPathId>(entry.path_id_by_route_handle.size());
    entry.path_id_by_route_handle.emplace(route_handle, next_path_id);
    entry.route_handle_by_path_id.emplace(next_path_id, route_handle);
    return next_path_id;
}

QuicRouteHandle selected_route_handle(const QuicCore::ConnectionEntry &entry,
                                      std::optional<QuicPathId> path_id) {
    if (path_id.has_value()) {
        const auto it = entry.route_handle_by_path_id.find(*path_id);
        if (it != entry.route_handle_by_path_id.end()) {
            return it->second;
        }
    }
    return entry.default_route_handle.value_or(0);
}
```

Update the send-effect tagging in `drain_connection_effects`:

```cpp
        result.effects.emplace_back(QuicCoreSendDatagram{
            .connection = entry.handle,
            .path_id = path_id,
            .route_handle = selected_route_handle(entry, path_id),
            .bytes = std::move(datagram),
            .ecn = entry.connection->last_drained_ecn_codepoint(),
        });
```

Update inbound-datagram handling so endpoint routing uses route handles first and only falls back to the old `path_id` field during the migration window:

```cpp
        const auto route_handle =
            inbound->route_handle.value_or(static_cast<QuicRouteHandle>(inbound->path_id));
        const auto path_id = ensure_path_for_route(entry, route_handle);
        entry.connection->process_inbound_datagram(inbound->bytes, now, path_id, inbound->ecn);
```

Update the migration-command branch in `QuicCore::advance_endpoint` to use the same helper:

```cpp
                [&](const QuicCoreRequestConnectionMigration &in) {
                    const auto path_id =
                        in.route_handle.has_value()
                            ? ensure_path_for_route(entry, *in.route_handle)
                            : in.path_id;
                    const auto requested =
                        entry.connection->request_connection_migration(path_id, in.reason);
                    if (!requested.has_value()) {
                        result.local_error = QuicCoreLocalError{
                            .connection = entry.handle,
                            .code = QuicCoreLocalErrorCode::unsupported_operation,
                        };
                    }
                },
```

Expected: the route-handle surface becomes the truth, and `path_id` only remains as a temporary compatibility field for the old runtime code.

- [ ] **Step 4: Rework client-side Retry and version-negotiation restart to rebuild a stable endpoint entry instead of replacing a global `connection_`**

Replace the old single-pointer restart logic in `src/quic/core.cpp` with an entry-local helper:

```cpp
void restart_client_entry(QuicCore::ConnectionEntry &entry, const QuicCoreConfig &config,
                          QuicCoreTimePoint now, QuicRouteHandle route_handle) {
    auto restarted = std::make_unique<QuicConnection>(config);
    const auto path_id = ensure_path_for_route(entry, route_handle);
    restarted->last_inbound_path_id_ = path_id;
    restarted->current_send_path_id_ = path_id;
    restarted->ensure_path_state(path_id).is_current_send_path = true;
    restarted->start(now);
    entry.default_route_handle = route_handle;
    entry.connection = std::move(restarted);
}
```

Use it in the client inbound branch:

```cpp
        if (endpoint_config_.role == EndpointRole::client &&
            !entry.connection->is_handshake_complete()) {
            const auto version_negotiation =
                parse_version_negotiation_packet(inbound->bytes);
            if (version_negotiation.has_value()) {
                QuicCoreConfig restarted = entry.connection->config_;
                for (const auto supported_version : endpoint_config_.supported_versions) {
                    if (!contains_version(version_negotiation->supported_versions,
                                          supported_version)) {
                        continue;
                    }
                    restarted.initial_version = supported_version;
                    break;
                }
                restarted.reacted_to_version_negotiation = true;
                restart_client_entry(entry, restarted, now,
                                     inbound->route_handle.value_or(entry.default_route_handle.value_or(0)));
                return drain_connection_effects(entry, now);
            }

            const auto retry = parse_retry_packet(inbound->bytes);
            if (retry.has_value()) {
                QuicCoreConfig restarted = entry.connection->config_;
                restarted.original_destination_connection_id =
                    restarted.original_destination_connection_id.value_or(
                        restarted.initial_destination_connection_id);
                restarted.retry_source_connection_id = retry->source_connection_id;
                restarted.retry_token = retry->retry_token;
                restarted.initial_destination_connection_id = retry->source_connection_id;
                restart_client_entry(entry, restarted, now,
                                     inbound->route_handle.value_or(entry.default_route_handle.value_or(0)));
                return drain_connection_effects(entry, now);
            }
        }
```

Expected: client-side restarts preserve the external connection handle and route-handle-selected send path.

- [ ] **Step 5: Remove the transport-path bookkeeping hooks from the HTTP/0.9 runtime**

Delete these declarations from `src/quic/http09_runtime_test_hooks.h`:

```cpp
bool runtime_assigns_stable_path_ids_for_tests();
bool drive_endpoint_uses_transport_selected_path_for_tests();
bool core_version_negotiation_restart_preserves_inbound_path_ids_for_tests();
bool core_retry_restart_preserves_inbound_path_ids_for_tests();
bool drive_endpoint_rejects_unknown_transport_selected_path_for_tests();
```

Delete the corresponding transport-only assertions from `tests/http09/runtime/preferred_address_test.cpp`
and `tests/http09/runtime/migration_test.cpp`. Recreate the essential coverage as public `QuicCore`
endpoint tests in `tests/core/endpoint/client_restart_test.cpp`.

Expected: runtime tests stop asserting transport path bookkeeping that now belongs entirely to `QuicCore`.

- [ ] **Step 6: Run the client restart endpoint tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreEndpointTest.RetryRestartPreservesConnectionHandleAndRouteHandle'
```

Expected: PASS.

- [ ] **Step 7: Commit the client restart and route-bookkeeping move**

Run:

```bash
git add build.zig \
  src/quic/core.h \
  src/quic/core.cpp \
  src/quic/http09_runtime.cpp \
  src/quic/http09_runtime_test_hooks.h \
  tests/core/endpoint/client_restart_test.cpp \
  tests/http09/runtime/preferred_address_test.cpp \
  tests/http09/runtime/migration_test.cpp
git commit -m "refactor: move client restart and routing into quic core"
```

### Task 5: Rewrite HTTP/0.9 To Sit Above Handle-Tagged `QuicCore` Effects

**Files:**
- Create: `src/quic/http09_client_app.h`
- Create: `src/quic/http09_client_app.cpp`
- Create: `src/quic/http09_server_app.h`
- Create: `src/quic/http09_server_app.cpp`
- Modify: `src/quic/http09_runtime.h`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `tests/support/http09/runtime_test_fixtures.h`
- Modify: `tests/http09/runtime/io_test.cpp`
- Modify: `tests/http09/runtime/preferred_address_test.cpp`
- Modify: `tests/http09/runtime/migration_test.cpp`

- [ ] **Step 1: Write a failing test for handle-keyed HTTP/0.9 app dispatch**

In `tests/support/http09/runtime_test_fixtures.h`, extend the existing private-visibility block so
tests can inspect the new app-manager maps:

```cpp
#define private public
#include "src/quic/http09_runtime.h"
#include "src/quic/http09_client_app.h"
#include "src/quic/http09_server_app.h"
#include "src/quic/connection.h"
#undef private
```

In `tests/http09/runtime/io_test.cpp`, add this test near the existing helper-hook tests:

```cpp
TEST(QuicHttp09RuntimeTest, ServerAppCreatesEndpointPerAcceptedConnectionHandle) {
    coquic::quic::QuicHttp09ServerApp app(
        coquic::quic::QuicHttp09ServerConfig{.document_root = std::filesystem::path("/www")});

    coquic::quic::QuicCoreResult result;
    result.effects.emplace_back(coquic::quic::QuicCoreConnectionLifecycleEvent{
        .connection = 9,
        .event = coquic::quic::QuicCoreConnectionLifecycle::accepted,
    });

    static_cast<void>(app.on_core_result(result, runtime_now()));

    EXPECT_TRUE(app.endpoints_.contains(9));
}
```

Expected: compile failure because `QuicHttp09ServerApp` does not exist yet.

- [ ] **Step 2: Run the focused HTTP/0.9 runtime test and confirm the failure**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.ServerAppCreatesEndpointPerAcceptedConnectionHandle'
```

Expected: FAIL at compile time because the app-manager class has not been added.

- [ ] **Step 3: Add small app-manager classes that wrap the existing per-connection endpoints**

First, narrow the HTTP/0.9 endpoint-facing command type so the app managers can wrap it directly.
In `src/quic/http09.h`, replace the endpoint update definition with:

```cpp
struct QuicHttp09EndpointUpdate {
    std::vector<QuicCoreConnectionInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};
```

In `src/quic/http09_client.h` and `src/quic/http09_server.h`, replace the pending-input queues with:

```cpp
    std::deque<QuicCoreConnectionInput> pending_core_inputs_;
```

Create `src/quic/http09_server_app.h` with exactly:

```cpp
#pragma once

#include <deque>
#include <unordered_map>

#include "src/quic/http09_server.h"

namespace coquic::quic {

struct QuicHttp09AppUpdate {
    std::vector<QuicCoreEndpointInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class QuicHttp09ServerApp {
  public:
    explicit QuicHttp09ServerApp(QuicHttp09ServerConfig config);

    QuicHttp09AppUpdate on_core_result(const QuicCoreResult &result, QuicCoreTimePoint now);
    QuicHttp09AppUpdate poll(QuicCoreTimePoint now);

  private:
    QuicCoreResult filter_result_for(QuicConnectionHandle connection,
                                     const QuicCoreResult &result) const;
    void append_connection_inputs(QuicConnectionHandle connection,
                                  const QuicHttp09EndpointUpdate &endpoint_update,
                                  QuicHttp09AppUpdate &out);

    QuicHttp09ServerConfig config_;
    std::unordered_map<QuicConnectionHandle, QuicHttp09ServerEndpoint> endpoints_;
};

} // namespace coquic::quic
```

Create `src/quic/http09_server_app.cpp` with this implementation skeleton:

```cpp
#include "src/quic/http09_server_app.h"

namespace coquic::quic {

QuicHttp09ServerApp::QuicHttp09ServerApp(QuicHttp09ServerConfig config)
    : config_(std::move(config)) {
}

QuicCoreResult QuicHttp09ServerApp::filter_result_for(QuicConnectionHandle connection,
                                                      const QuicCoreResult &result) const {
    QuicCoreResult filtered;
    if (result.local_error.has_value() && result.local_error->connection == connection) {
        filtered.local_error = result.local_error;
    }
    for (const auto &effect : result.effects) {
        std::visit(
            [&](const auto &typed_effect) {
                if constexpr (requires { typed_effect.connection; }) {
                    if (typed_effect.connection == connection) {
                        filtered.effects.emplace_back(typed_effect);
                    }
                }
            },
            effect);
    }
    return filtered;
}

void QuicHttp09ServerApp::append_connection_inputs(QuicConnectionHandle connection,
                                                   const QuicHttp09EndpointUpdate &endpoint_update,
                                                   QuicHttp09AppUpdate &out) {
    for (const auto &input : endpoint_update.core_inputs) {
        out.core_inputs.emplace_back(QuicCoreConnectionCommand{
            .connection = connection,
            .input = input,
        });
    }
    out.has_pending_work = out.has_pending_work || endpoint_update.has_pending_work;
    out.terminal_failure = out.terminal_failure || endpoint_update.terminal_failure;
    out.handled_local_error = out.handled_local_error || endpoint_update.handled_local_error;
}

QuicHttp09AppUpdate QuicHttp09ServerApp::on_core_result(const QuicCoreResult &result,
                                                        QuicCoreTimePoint now) {
    QuicHttp09AppUpdate update;
    for (const auto &effect : result.effects) {
        if (const auto *lifecycle = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
            lifecycle != nullptr &&
            lifecycle->event == QuicCoreConnectionLifecycle::accepted &&
            !endpoints_.contains(lifecycle->connection)) {
            endpoints_.emplace(lifecycle->connection,
                               QuicHttp09ServerEndpoint(config_));
        }
        if (const auto *lifecycle = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
            lifecycle != nullptr &&
            lifecycle->event == QuicCoreConnectionLifecycle::closed) {
            endpoints_.erase(lifecycle->connection);
        }
        if (const auto *state = std::get_if<QuicCoreStateEvent>(&effect);
            state != nullptr && state->change == QuicCoreStateChange::failed) {
            endpoints_.erase(state->connection);
        }
    }

    for (auto &[connection, endpoint] : endpoints_) {
        append_connection_inputs(connection,
                                 endpoint.on_core_result(filter_result_for(connection, result), now),
                                 update);
    }
    return update;
}

QuicHttp09AppUpdate QuicHttp09ServerApp::poll(QuicCoreTimePoint now) {
    QuicHttp09AppUpdate update;
    for (auto &[connection, endpoint] : endpoints_) {
        append_connection_inputs(connection, endpoint.poll(now), update);
    }
    return update;
}

} // namespace coquic::quic
```

Create `src/quic/http09_client_app.h` with exactly:

```cpp
#pragma once

#include <optional>

#include "src/quic/http09_client.h"
#include "src/quic/http09_server_app.h"

namespace coquic::quic {

class QuicHttp09ClientApp {
  public:
    explicit QuicHttp09ClientApp(QuicHttp09ClientConfig config);

    void bind_connection(QuicConnectionHandle connection);
    QuicHttp09AppUpdate on_core_result(const QuicCoreResult &result, QuicCoreTimePoint now);
    QuicHttp09AppUpdate poll(QuicCoreTimePoint now);

  private:
    QuicCoreResult filter_result_for_current_connection(const QuicCoreResult &result) const;

    QuicHttp09ClientEndpoint endpoint_;
    std::optional<QuicConnectionHandle> current_connection_;
};

} // namespace coquic::quic
```

Create `src/quic/http09_client_app.cpp` with exactly:

```cpp
#include "src/quic/http09_client_app.h"

namespace coquic::quic {

QuicHttp09ClientApp::QuicHttp09ClientApp(QuicHttp09ClientConfig config)
    : endpoint_(std::move(config)) {
}

void QuicHttp09ClientApp::bind_connection(QuicConnectionHandle connection) {
    current_connection_ = connection;
}

QuicCoreResult QuicHttp09ClientApp::filter_result_for_current_connection(
    const QuicCoreResult &result) const {
    QuicCoreResult filtered;
    if (!current_connection_.has_value()) {
        return filtered;
    }
    if (result.local_error.has_value() && result.local_error->connection == *current_connection_) {
        filtered.local_error = result.local_error;
    }
    for (const auto &effect : result.effects) {
        std::visit(
            [&](const auto &typed_effect) {
                if constexpr (requires { typed_effect.connection; }) {
                    if (typed_effect.connection == *current_connection_) {
                        filtered.effects.emplace_back(typed_effect);
                    }
                }
            },
            effect);
    }
    return filtered;
}

QuicHttp09AppUpdate QuicHttp09ClientApp::on_core_result(const QuicCoreResult &result,
                                                        QuicCoreTimePoint now) {
    QuicHttp09AppUpdate update;
    if (!current_connection_.has_value()) {
        return update;
    }
    const auto endpoint_update =
        endpoint_.on_core_result(filter_result_for_current_connection(result), now);
    for (const auto &input : endpoint_update.core_inputs) {
        update.core_inputs.emplace_back(QuicCoreConnectionCommand{
            .connection = *current_connection_,
            .input = input,
        });
    }
    update.has_pending_work = endpoint_update.has_pending_work;
    update.terminal_success = endpoint_update.terminal_success;
    update.terminal_failure = endpoint_update.terminal_failure;
    update.handled_local_error = endpoint_update.handled_local_error;
    return update;
}

QuicHttp09AppUpdate QuicHttp09ClientApp::poll(QuicCoreTimePoint now) {
    QuicHttp09AppUpdate update;
    if (!current_connection_.has_value()) {
        return update;
    }
    const auto endpoint_update = endpoint_.poll(now);
    for (const auto &input : endpoint_update.core_inputs) {
        update.core_inputs.emplace_back(QuicCoreConnectionCommand{
            .connection = *current_connection_,
            .input = input,
        });
    }
    update.has_pending_work = endpoint_update.has_pending_work;
    update.terminal_success = endpoint_update.terminal_success;
    update.terminal_failure = endpoint_update.terminal_failure;
    update.handled_local_error = endpoint_update.handled_local_error;
    return update;
}

} // namespace coquic::quic
```

Expected: HTTP/0.9 app state is now explicitly keyed by `QuicConnectionHandle`, above `QuicCore`.

- [ ] **Step 4: Rewrite `src/quic/http09_runtime.cpp` to use one endpoint-scoped `QuicCore` plus the new app managers**

In `src/quic/http09_runtime.h`, replace the old server-core factory declaration with:

```cpp
QuicCoreEndpointConfig make_http09_server_endpoint_core_config(
    const Http09RuntimeConfig &config);
```

Implement it in `src/quic/http09_runtime.cpp` by lifting the existing server-side defaults out of
the old per-connection factory:

```cpp
QuicCoreEndpointConfig make_http09_server_endpoint_core_config(const Http09RuntimeConfig &config) {
    return QuicCoreEndpointConfig{
        .role = EndpointRole::server,
        .supported_versions = {kQuicVersion1},
        .verify_peer = config.verify_peer,
        .retry_enabled = config.retry_enabled,
        .application_protocol = config.application_protocol,
        .identity =
            TlsIdentity{
                .certificate_pem = read_text_file(config.certificate_chain_path),
                .private_key_pem = read_text_file(config.private_key_path),
            },
        .transport = http09_server_transport_for_testcase(config.testcase),
        .allowed_tls_cipher_suites = http09_tls_cipher_suites_for_testcase(config.testcase),
        .qlog = config.qlog_directory.has_value()
                    ? std::optional<QuicQlogConfig>(QuicQlogConfig{
                          .directory = *config.qlog_directory,
                      })
                    : std::nullopt,
        .tls_keylog_path = config.tls_keylog_path,
    };
}
```

At the top of `src/quic/http09_runtime.cpp`, replace the old path bookkeeping helpers with an
I/O-only route registry:

```cpp
struct RuntimeRouteRegistry {
    std::unordered_map<std::string, QuicRouteHandle> handle_by_peer;
    std::unordered_map<QuicRouteHandle, RuntimeSendRoute> route_by_handle;
    QuicRouteHandle next_handle = 1;

    QuicRouteHandle remember(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len) {
        const auto key = runtime_peer_tuple_key(socket_fd, peer, peer_len);
        if (const auto existing = handle_by_peer.find(key); existing != handle_by_peer.end()) {
            route_by_handle[existing->second] = RuntimeSendRoute{
                .socket_fd = socket_fd,
                .peer = peer,
                .peer_len = peer_len,
            };
            return existing->second;
        }

        const auto handle = next_handle++;
        handle_by_peer.emplace(key, handle);
        route_by_handle.emplace(handle,
                                RuntimeSendRoute{
                                    .socket_fd = socket_fd,
                                    .peer = peer,
                                    .peer_len = peer_len,
                                });
        return handle;
    }

    const RuntimeSendRoute *find(QuicRouteHandle handle) const {
        const auto it = route_by_handle.find(handle);
        return it == route_by_handle.end() ? nullptr : &it->second;
    }
};
```

Update `handle_core_effects` so it resolves outbound sends by `route_handle` instead of transport
path ID:

```cpp
bool handle_core_effects(const RuntimeRouteRegistry &routes, const QuicCoreResult &result,
                         std::string_view role_name) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        if (!send->route_handle.has_value()) {
            std::cerr << "http09-" << role_name
                      << " failed: missing route_handle for outbound datagram\n";
            return false;
        }
        const auto *route = routes.find(*send->route_handle);
        if (route == nullptr) {
            std::cerr << "http09-" << role_name
                      << " failed: unknown route_handle for outbound datagram\n";
            return false;
        }
        if (!send_datagram(route->socket_fd, send->bytes, route->peer, route->peer_len, role_name,
                           send->ecn)) {
            return false;
        }
    }
    return true;
}
```

Replace the old server-session state in `src/quic/http09_runtime.cpp`:

```cpp
    ServerSessionMap sessions;
    ServerConnectionIdRouteMap connection_id_routes;
    std::unordered_map<std::string, std::string> initial_destination_routes;
    RetryTokenStore retry_tokens;
    std::uint64_t next_connection_index = 1;
```

With the endpoint-scoped transport plus the app manager:

```cpp
    QuicCore core(make_http09_server_endpoint_core_config(config));
    QuicHttp09ServerApp app(QuicHttp09ServerConfig{
        .document_root = config.document_root,
    });
    RuntimeRouteRegistry routes;
```

Update the server datagram handling path from:

```cpp
        auto session_it = find_server_session_for_datagram(sessions, connection_id_routes,
                                                           initial_destination_routes, *parsed);
```

To:

```cpp
        const auto route_handle =
            routes.remember(step.socket_fd, step.source, step.source_len);
        auto result = core.advance_endpoint(
            QuicCoreInboundDatagram{
                .bytes = inbound.bytes,
                .route_handle = route_handle,
                .ecn = inbound.ecn,
            },
            step.input_time);
        if (!handle_core_effects(routes, result, "server")) {
            return false;
        }
        auto update = app.on_core_result(result, step.input_time);
        if (result.local_error.has_value() && !update.handled_local_error) {
            return false;
        }
        while (!update.core_inputs.empty()) {
            auto next = core.advance_endpoint(std::move(update.core_inputs.front()), now());
            update.core_inputs.erase(update.core_inputs.begin());
            if (!handle_core_effects(routes, next, "server")) {
                return false;
            }
            const auto follow_up = app.on_core_result(next, now());
            if (next.local_error.has_value() && !follow_up.handled_local_error) {
                return false;
            }
            update.core_inputs.insert(update.core_inputs.end(), follow_up.core_inputs.begin(),
                                      follow_up.core_inputs.end());
        }
```

On the client path, replace the old single-connection bootstrap with:

```cpp
    QuicCore core(QuicCoreEndpointConfig{
        .role = EndpointRole::client,
        .supported_versions = {kQuicVersion1},
        .verify_peer = config.verify_peer,
        .application_protocol = config.application_protocol,
        .transport = http09_client_transport_for_testcase(config.testcase),
        .allowed_tls_cipher_suites = http09_tls_cipher_suites_for_testcase(config.testcase),
        .tls_keylog_path = config.tls_keylog_path,
    });
    RuntimeRouteRegistry routes;
    const auto route_handle = routes.remember(client_sockets.primary.fd, peer, peer_len);
    auto open_result = core.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_runtime_client_core_config(config, connection_index),
            .initial_route_handle = route_handle,
        },
        now());
    QuicHttp09ClientApp app(make_http09_client_endpoint_config(
        config, requests, attempt_zero_rtt_requests, open_result));
    std::optional<QuicConnectionHandle> opened_connection;
    for (const auto &effect : open_result.effects) {
        if (const auto *lifecycle =
                std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
            lifecycle != nullptr &&
            lifecycle->event == QuicCoreConnectionLifecycle::created) {
            opened_connection = lifecycle->connection;
            break;
        }
    }
    if (!opened_connection.has_value()) {
        return 1;
    }
    app.bind_connection(*opened_connection);
    if (!handle_core_effects(routes, open_result, "client")) {
        return 1;
    }
    auto update = app.on_core_result(open_result, now());
```

After that, the client loop uses the same `QuicCoreInboundDatagram{ .route_handle = ... }` and
`QuicCoreConnectionCommand` flow that the server loop uses; the runtime owns only route-handle to
socket or peer mappings, `QuicCore` owns CID routing, Retry, version negotiation, timer aggregation,
and path selection, and `QuicHttp09ClientApp` plus `QuicHttp09ServerApp` own per-handle application
state only.

Expected: `http09_runtime.cpp` stops being a second transport endpoint implementation.

- [ ] **Step 5: Update runtime fixtures and tests to target route handles instead of transport path IDs**

In `tests/support/http09/runtime_test_fixtures.h`, replace references to
`drive_endpoint_uses_transport_selected_path_for_tests` and route-by-path assertions with route-handle
assertions only:

```cpp
struct RuntimeRecordedSendForTests {
    int socket_fd = -1;
    std::uint16_t peer_port = 0;
    std::optional<QuicRouteHandle> route_handle;
};
```

In `tests/http09/runtime/preferred_address_test.cpp` and `tests/http09/runtime/migration_test.cpp`,
update the expected migration command construction from path IDs to route handles:

```cpp
EXPECT_EQ(command.route_handle, expected_preferred_route_handle);
EXPECT_EQ(command.reason, coquic::quic::QuicMigrationRequestReason::preferred_address);
```

Expected: runtime tests now validate route-handle plus socket integration and app policy, not transport path bookkeeping.

- [ ] **Step 6: Run the HTTP/0.9 tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*'
```

Expected: PASS.

- [ ] **Step 7: Commit the handle-keyed HTTP/0.9 layer**

Run:

```bash
git add \
  src/quic/http09.h \
  src/quic/http09_client.h \
  src/quic/http09_server.h \
  src/quic/http09_client_app.h \
  src/quic/http09_client_app.cpp \
  src/quic/http09_server_app.h \
  src/quic/http09_server_app.cpp \
  src/quic/http09_runtime.h \
  src/quic/http09_runtime.cpp \
  tests/support/http09/runtime_test_fixtures.h \
  tests/http09/runtime/io_test.cpp \
  tests/http09/runtime/preferred_address_test.cpp \
  tests/http09/runtime/migration_test.cpp
git commit -m "refactor: lift http09 above handle-tagged quic core"
```

### Task 6: Split The Source Tree, Extract Runtime I/O, And Remove The Temporary Legacy Shim

**Files:**
- Create: `src/runtime/udp_io.h`
- Create: `src/runtime/udp_io.cpp`
- Move: `src/quic/http09.h` -> `src/apps/http09/protocol.h`
- Move: `src/quic/http09.cpp` -> `src/apps/http09/protocol.cpp`
- Move: `src/quic/http09_client.h` -> `src/apps/http09/client_endpoint.h`
- Move: `src/quic/http09_client.cpp` -> `src/apps/http09/client_endpoint.cpp`
- Move: `src/quic/http09_server.h` -> `src/apps/http09/server_endpoint.h`
- Move: `src/quic/http09_server.cpp` -> `src/apps/http09/server_endpoint.cpp`
- Move: `src/quic/http09_client_app.h` -> `src/apps/http09/client_app.h`
- Move: `src/quic/http09_client_app.cpp` -> `src/apps/http09/client_app.cpp`
- Move: `src/quic/http09_server_app.h` -> `src/apps/http09/server_app.h`
- Move: `src/quic/http09_server_app.cpp` -> `src/apps/http09/server_app.cpp`
- Move: `src/quic/http09_runtime.h` -> `src/runtime/http09_runtime.h`
- Move: `src/quic/http09_runtime.cpp` -> `src/runtime/http09_runtime.cpp`
- Move: `src/quic/http09_runtime_test_hooks.h` -> `src/runtime/http09_runtime_test_hooks.h`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `build.zig`
- Modify: `src/main.cpp`

- [ ] **Step 1: Extract the POSIX UDP helpers into `src/runtime/udp_io.*`**

Create `src/runtime/udp_io.h` with exactly:

```cpp
#pragma once

#include <netinet/in.h>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "src/quic/core.h"

namespace coquic::runtime {

struct RuntimeSendRoute {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

struct RuntimeRouteRegistry {
    std::unordered_map<std::string, quic::QuicRouteHandle> handle_by_peer;
    std::unordered_map<quic::QuicRouteHandle, RuntimeSendRoute> route_by_handle;
    quic::QuicRouteHandle next_handle = 1;

    quic::QuicRouteHandle remember(int socket_fd, const sockaddr_storage &peer,
                                   socklen_t peer_len);
    const RuntimeSendRoute *find(quic::QuicRouteHandle route_handle) const;
};

bool send_runtime_datagram(const RuntimeRouteRegistry &routes,
                           quic::QuicRouteHandle route_handle,
                           std::span<const std::byte> bytes,
                           quic::QuicEcnCodepoint ecn, std::string_view role_name);

} // namespace coquic::runtime
```

Move the socket, address-resolution, sendmsg, recvmsg, and ECN helpers out of the runtime file into
`src/runtime/udp_io.cpp` unchanged except for namespace and include-path updates.

Expected: `http09_runtime.cpp` becomes orchestration glue instead of a 6,700-line mix of transport plus app plus socket code.

- [ ] **Step 2: Move the HTTP/0.9 protocol and app files into `src/apps/http09/` and the runtime files into `src/runtime/`**

Run:

```bash
mkdir -p src/apps/http09 src/runtime
git mv src/quic/http09.h src/apps/http09/protocol.h
git mv src/quic/http09.cpp src/apps/http09/protocol.cpp
git mv src/quic/http09_client.h src/apps/http09/client_endpoint.h
git mv src/quic/http09_client.cpp src/apps/http09/client_endpoint.cpp
git mv src/quic/http09_server.h src/apps/http09/server_endpoint.h
git mv src/quic/http09_server.cpp src/apps/http09/server_endpoint.cpp
git mv src/quic/http09_client_app.h src/apps/http09/client_app.h
git mv src/quic/http09_client_app.cpp src/apps/http09/client_app.cpp
git mv src/quic/http09_server_app.h src/apps/http09/server_app.h
git mv src/quic/http09_server_app.cpp src/apps/http09/server_app.cpp
git mv src/quic/http09_runtime.h src/runtime/http09_runtime.h
git mv src/quic/http09_runtime.cpp src/runtime/http09_runtime.cpp
git mv src/quic/http09_runtime_test_hooks.h src/runtime/http09_runtime_test_hooks.h
```

Expected: `git status --short` shows only renames plus the new `src/runtime/udp_io.*` files.

- [ ] **Step 3: Update include paths and `build.zig` to the new layout**

In `build.zig`, replace the old source paths:

```zig
        "src/quic/http09.cpp",
        "src/quic/http09_client.cpp",
        "src/quic/http09_runtime.cpp",
        "src/quic/http09_server.cpp",
```

With:

```zig
        "src/apps/http09/protocol.cpp",
        "src/apps/http09/client_endpoint.cpp",
        "src/apps/http09/client_app.cpp",
        "src/apps/http09/server_endpoint.cpp",
        "src/apps/http09/server_app.cpp",
        "src/runtime/udp_io.cpp",
        "src/runtime/http09_runtime.cpp",
```

Update `src/main.cpp` to include the moved header:

```cpp
#include "src/runtime/http09_runtime.h"
```

Expected: the build graph matches the new transport versus app versus runtime boundaries from the approved spec.

- [ ] **Step 4: Remove the temporary single-connection shim and the temporary `path_id` compatibility fields from `QuicCore`**

Delete the legacy constructor and old `advance` declaration from `src/quic/core.h`:

```cpp
    explicit QuicCore(QuicCoreConfig config);
    QuicCoreResult advance(QuicCoreInput input, QuicCoreTimePoint now);
```

Delete the compatibility storage from the private members:

```cpp
    std::optional<QuicCoreConfig> legacy_config_;
```

Delete the temporary compatibility fields from the endpoint input and effect structs:

```cpp
    QuicPathId path_id = 0;
```

And:

```cpp
    std::optional<QuicPathId> path_id;
```

Update every remaining runtime caller to use only `route_handle`.

Expected: there is now one public transport manager surface, and it is the endpoint-scoped one.

- [ ] **Step 5: Run full verification**

Run:

```bash
nix develop -c zig build
nix develop -c zig build test
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: all four commands pass.

- [ ] **Step 6: Commit the final layout and shim removal**

Run:

```bash
git add build.zig \
  src/quic/core.h \
  src/quic/core.cpp \
  src/runtime/udp_io.h \
  src/runtime/udp_io.cpp \
  src/runtime/http09_runtime.h \
  src/runtime/http09_runtime.cpp \
  src/runtime/http09_runtime_test_hooks.h \
  src/apps/http09/protocol.h \
  src/apps/http09/protocol.cpp \
  src/apps/http09/client_endpoint.h \
  src/apps/http09/client_endpoint.cpp \
  src/apps/http09/client_app.h \
  src/apps/http09/client_app.cpp \
  src/apps/http09/server_endpoint.h \
  src/apps/http09/server_endpoint.cpp \
  src/apps/http09/server_app.h \
  src/apps/http09/server_app.cpp \
  src/main.cpp
git commit -m "refactor: split quic core app and runtime boundaries"
```

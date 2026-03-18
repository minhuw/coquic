# QUIC Handshake Core Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a connection-scoped QUIC handshake engine with a tiny `QuicCore` byte-in, byte-out API that lets one in-process client and one in-process server complete a real TLS-backed handshake.

**Architecture:** Keep the existing packet and protection codecs as the wire-format foundation. Add a concrete internal `QuicConnection` that owns connection IDs, packet-number spaces, CRYPTO buffers, transport parameters, and handshake state, plus a narrow `TlsAdapter` seam that surfaces handshake bytes and traffic secrets without leaking backend details into `QuicCore`.

**Tech Stack:** C++20, OpenSSL 3.4.3 in the current Nix shell, Zig build, GoogleTest, QUIC packet/crypto codecs already in `src/quic/`, RFC 9000 transport parameters and RFC 9001 CRYPTO-by-encryption-level rules

---

## File Map

- Modify: `build.zig`
  - Compile the new handshake sources and add the new test files to the main test binary.
- Modify: `src/coquic.h`
  - Export the new public `QuicCore` API.
- Create: `src/quic/core.h`
  - Declare `QuicCore`, `QuicCoreConfig`, and the small TLS identity/config types used by tests and callers.
- Create: `src/quic/core.cpp`
  - Implement the public wrapper that delegates to the internal connection object.
- Create: `src/quic/connection.h`
  - Declare `QuicConnection`, handshake status, and the per-space state it owns.
- Create: `src/quic/connection.cpp`
  - Implement datagram ingest, protected packet parsing, TLS handoff, transport-parameter validation, packet emission, and client bootstrap.
- Create: `src/quic/crypto_stream.h`
  - Declare CRYPTO send-buffer and receive-reassembly helpers.
- Create: `src/quic/crypto_stream.cpp`
  - Implement CRYPTO stream chunking and contiguous reassembly.
- Create: `src/quic/transport_parameters.h`
  - Declare minimal transport-parameter types, serializer/deserializer, and handshake validation helpers.
- Create: `src/quic/transport_parameters.cpp`
  - Implement varint-encoded transport-parameter parsing, encoding, and validation.
- Create: `src/quic/tls_adapter.h`
  - Declare the TLS adapter seam that accepts QUIC transport parameters, yields handshake bytes by encryption level, and surfaces traffic secrets.
- Create: `src/quic/tls_adapter.cpp`
  - Implement the current backend probe and TLS-backed adapter.
- Create: `tests/quic_tls_adapter_test.cpp`
  - Prove the TLS adapter can exchange handshake bytes and surface secrets/transport parameters under application control.
- Create: `tests/quic_transport_parameters_test.cpp`
  - Lock down transport-parameter encoding, decoding, and handshake validation.
- Create: `tests/quic_crypto_stream_test.cpp`
  - Lock down CRYPTO frame chunking and receive-side reassembly.
- Create: `tests/quic_core_test.cpp`
  - Cover client bootstrap, server response, and the two-peer handshake integration loop.
- Create: `tests/quic_test_utils.h`
  - Share fixture loading and deterministic config builders across handshake tests.
- Create: `tests/fixtures/quic-server-cert.pem`
  - Self-signed server certificate committed for test-only use.
- Create: `tests/fixtures/quic-server-key.pem`
  - Matching private key committed for test-only use.

## Execution Notes

- Follow `@superpowers:test-driven-development` on every task: write the failing test first, run it and watch it fail, then implement the minimum code to pass.
- Before any success claim or commit, use `@superpowers:verification-before-completion`.
- Ground protocol choices in `docs/superpowers/specs/2026-03-18-quic-handshake-design.md`, `RFC 9001 Section 4`, `RFC 9000 Section 7.3`, and `RFC 9000 Section 18.2`.
- Keep the public surface intentionally tiny. Do not add ACK strategy, timers, stream state, Retry, or 0-RTT in this plan.

### Task 1: Add TLS Adapter Probe Tests And Scaffolding

**Files:**
- Modify: `build.zig`
- Create: `src/quic/tls_adapter.h`
- Create: `tests/quic_tls_adapter_test.cpp`
- Create: `tests/quic_test_utils.h`
- Create: `tests/fixtures/quic-server-cert.pem`
- Create: `tests/fixtures/quic-server-key.pem`

- [ ] **Step 1: Generate and commit deterministic test credentials**

Run:

```bash
nix develop -c bash -lc 'mkdir -p tests/fixtures && \
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=localhost" \
    -keyout tests/fixtures/quic-server-key.pem \
    -out tests/fixtures/quic-server-cert.pem'
```

Expected: the two PEM files appear under `tests/fixtures/`.

- [ ] **Step 2: Add shared test helpers**

Create `tests/quic_test_utils.h` with file-loading helpers and deterministic
transport-parameter bytes for the TLS adapter tests:

```cpp
#pragma once

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "src/quic/packet.h"

namespace coquic::quic::test {

inline std::string read_text_file(const char *path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

inline std::vector<std::byte> sample_transport_parameters() {
    return {
        std::byte{0x0f}, std::byte{0x04},
        std::byte{0x03}, std::byte{0x02}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x0e}, std::byte{0x01}, std::byte{0x02},
    };
}

} // namespace coquic::quic::test
```

- [ ] **Step 3: Write the failing TLS adapter probe tests**

Create `tests/quic_tls_adapter_test.cpp` with a real client/server loop that
proves the adapter can exchange handshake bytes by encryption level, surface the
peer transport parameters, and publish traffic secrets:

```cpp
#include <gtest/gtest.h>

#include "src/quic/tls_adapter.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::EndpointRole;
using coquic::quic::EncryptionLevel;
using coquic::quic::TlsAdapter;
using coquic::quic::TlsAdapterConfig;
using coquic::quic::TlsIdentity;

TlsAdapterConfig make_client_config() {
    return TlsAdapterConfig{
        .role = EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    };
}

TlsAdapterConfig make_server_config() {
    return TlsAdapterConfig{
        .role = EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .identity = TlsIdentity{
            .certificate_pem =
                coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"),
            .private_key_pem =
                coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"),
        },
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    };
}

TEST(QuicTlsAdapterTest, ClientAndServerExchangeHandshakeBytesAndSecrets) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    ASSERT_TRUE(client.start().has_value());

    for (int i = 0; i < 32 && !(client.handshake_complete() && server.handshake_complete()); ++i) {
        const auto client_initial = client.take_pending(EncryptionLevel::initial);
        if (!client_initial.empty()) {
            ASSERT_TRUE(server.provide(EncryptionLevel::initial, client_initial).has_value());
        }

        const auto server_initial = server.take_pending(EncryptionLevel::initial);
        if (!server_initial.empty()) {
            ASSERT_TRUE(client.provide(EncryptionLevel::initial, server_initial).has_value());
        }

        const auto server_handshake = server.take_pending(EncryptionLevel::handshake);
        if (!server_handshake.empty()) {
            ASSERT_TRUE(client.provide(EncryptionLevel::handshake, server_handshake).has_value());
        }

        const auto client_handshake = client.take_pending(EncryptionLevel::handshake);
        if (!client_handshake.empty()) {
            ASSERT_TRUE(server.provide(EncryptionLevel::handshake, client_handshake).has_value());
        }

        client.poll();
        server.poll();
    }

    EXPECT_TRUE(client.handshake_complete());
    EXPECT_TRUE(server.handshake_complete());
    EXPECT_TRUE(client.peer_transport_parameters().has_value());
    EXPECT_TRUE(server.peer_transport_parameters().has_value());
    EXPECT_FALSE(client.take_available_secrets().empty());
    EXPECT_FALSE(server.take_available_secrets().empty());
}

} // namespace
```

- [ ] **Step 4: Declare the adapter seam**

Create `src/quic/tls_adapter.h` with the exact API the later connection code
will depend on:

```cpp
#pragma once

#include <optional>
#include <span>
#include <string>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic {

enum class EncryptionLevel : std::uint8_t {
    initial,
    handshake,
    application,
};

struct TlsIdentity {
    std::string certificate_pem;
    std::string private_key_pem;
};

struct AvailableTrafficSecret {
    EncryptionLevel level = EncryptionLevel::initial;
    EndpointRole sender = EndpointRole::client;
    TrafficSecret secret;
};

struct TlsAdapterConfig {
    EndpointRole role = EndpointRole::client;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::optional<TlsIdentity> identity;
    std::vector<std::byte> local_transport_parameters;
};

class TlsAdapter {
  public:
    explicit TlsAdapter(TlsAdapterConfig config);

    CodecResult<bool> start();
    CodecResult<bool> provide(EncryptionLevel level, std::span<const std::byte> bytes);
    void poll();
    std::vector<std::byte> take_pending(EncryptionLevel level);
    std::vector<AvailableTrafficSecret> take_available_secrets();
    const std::optional<std::vector<std::byte>> &peer_transport_parameters() const;
    bool handshake_complete() const;
};

} // namespace coquic::quic
```

- [ ] **Step 5: Wire the new test into the build**

Update `build.zig` so the test binary compiles `tests/quic_tls_adapter_test.cpp`.
Do not add `src/quic/tls_adapter.cpp` yet.

- [ ] **Step 6: Run the test to verify it fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterTest.*
```

Expected: FAIL at link time because `TlsAdapter` is declared but not defined.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/quic/tls_adapter.h tests/quic_tls_adapter_test.cpp \
    tests/quic_test_utils.h tests/fixtures/quic-server-cert.pem \
    tests/fixtures/quic-server-key.pem
git commit -m "test: add QUIC TLS adapter probe"
```

### Task 2: Implement The TLS Adapter Backend Probe

**Files:**
- Modify: `build.zig`
- Modify: `src/quic/tls_adapter.h`
- Create: `src/quic/tls_adapter.cpp`
- Modify: `tests/quic_tls_adapter_test.cpp`

- [ ] **Step 1: Tighten the probe with one more failing assertion**

Extend `tests/quic_tls_adapter_test.cpp` so the adapter must also surface both
client and server handshake secrets:

```cpp
const auto client_secrets = client.take_available_secrets();
const auto server_secrets = server.take_available_secrets();

EXPECT_TRUE(std::any_of(client_secrets.begin(), client_secrets.end(), [](const auto &secret) {
    return secret.level == EncryptionLevel::handshake;
}));
EXPECT_TRUE(std::any_of(server_secrets.begin(), server_secrets.end(), [](const auto &secret) {
    return secret.level == EncryptionLevel::handshake;
}));
```

- [ ] **Step 2: Run the filtered test and confirm it still fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterTest.ClientAndServerExchangeHandshakeBytesAndSecrets
```

Expected: FAIL because the adapter backend is still missing.

- [ ] **Step 3: Implement the smallest backend that satisfies the seam**

Create `src/quic/tls_adapter.cpp` and implement:

```cpp
SSL_CTX_add_custom_ext(
    ctx_.get(),
    TLSEXT_TYPE_quic_transport_parameters,
    SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
    &TlsAdapter::add_transport_parameters,
    &TlsAdapter::free_transport_parameters,
    this,
    &TlsAdapter::parse_transport_parameters,
    this);
SSL_CTX_set_keylog_callback(ctx_.get(), &TlsAdapter::on_keylog_line);

if (config_.role == EndpointRole::client) {
    SSL_set_connect_state(ssl_.get());
} else {
    SSL_set_accept_state(ssl_.get());
}
```

Use the backend implementation to:

- accept local QUIC transport-parameter bytes from `TlsAdapterConfig`
- parse peer QUIC transport-parameter bytes from the extension callback
- map keylog labels such as
  `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
  `SERVER_HANDSHAKE_TRAFFIC_SECRET`,
  `CLIENT_TRAFFIC_SECRET_0`, and
  `SERVER_TRAFFIC_SECRET_0`
  into `TrafficSecret` values
- keep handshake bytes separate by `EncryptionLevel`
- make `start()` emit the first client handshake bytes without requiring input

- [ ] **Step 4: Add the implementation source to the library build**

Update `build.zig` so the project library compiles `src/quic/tls_adapter.cpp`.

- [ ] **Step 5: Re-run the filtered probe**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterTest.*
```

Expected: PASS.

If this cannot be made to pass with the current OpenSSL 3.4.3 headers after one
focused implementation attempt, stop execution here, keep
`src/quic/tls_adapter.h` stable, and write a short design delta before touching
`QuicConnection`. Do not continue with the connection tasks until the TLS seam
can actually exchange handshake bytes under application control.

- [ ] **Step 6: Commit**

```bash
git add build.zig src/quic/tls_adapter.h src/quic/tls_adapter.cpp \
    tests/quic_tls_adapter_test.cpp
git commit -m "feat: add QUIC TLS adapter probe"
```

### Task 3: Add Transport-Parameter Encoding, Parsing, And Validation

**Files:**
- Modify: `build.zig`
- Create: `src/quic/transport_parameters.h`
- Create: `src/quic/transport_parameters.cpp`
- Create: `tests/quic_transport_parameters_test.cpp`

- [ ] **Step 1: Write the failing transport-parameter tests**

Create `tests/quic_transport_parameters_test.cpp` with the minimal handshake
parameter set this milestone needs:

```cpp
#include <gtest/gtest.h>

#include "src/quic/transport_parameters.h"

namespace {

using coquic::quic::EndpointRole;
using coquic::quic::TransportParameters;
using coquic::quic::TransportParametersValidationContext;

TEST(QuicTransportParametersTest, RoundTripsMinimalClientParameters) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().initial_source_connection_id,
              (coquic::quic::ConnectionId{std::byte{0xc1}, std::byte{0x01}}));
    EXPECT_EQ(decoded.value().active_connection_id_limit, 2u);
}

TEST(QuicTransportParametersTest, RejectsActiveConnectionIdLimitBelowTwo) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 1,
        .initial_source_connection_id = {std::byte{0xaa}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        coquic::quic::deserialize_transport_parameters(encoded.value()).value(),
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = {std::byte{0xaa}},
        });
    ASSERT_FALSE(validation.has_value());
}

TEST(QuicTransportParametersTest, ValidatesServerConnectionIdsAgainstHandshakeContext) {
    const TransportParameters parameters{
        .original_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = {std::byte{0x53}, std::byte{0x01}},
    };

    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        parameters,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = {std::byte{0x53}, std::byte{0x01}},
            .expected_original_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
        });
    ASSERT_TRUE(validation.has_value());
}

} // namespace
```

- [ ] **Step 2: Run the new tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTransportParametersTest.*
```

Expected: FAIL because the transport-parameter helpers do not exist yet.

- [ ] **Step 3: Declare the transport-parameter API**

Create `src/quic/transport_parameters.h` with the exact types the connection
layer will call:

```cpp
#pragma once

#include <optional>
#include <span>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

struct TransportParameters {
    std::optional<ConnectionId> original_destination_connection_id;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t active_connection_id_limit = 2;
    ConnectionId initial_source_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
};

struct TransportParametersValidationContext {
    ConnectionId expected_initial_source_connection_id;
    std::optional<ConnectionId> expected_original_destination_connection_id;
    std::optional<ConnectionId> expected_retry_source_connection_id;
};

struct TransportParametersValidationOk {};

CodecResult<std::vector<std::byte>>
serialize_transport_parameters(const TransportParameters &parameters);

CodecResult<TransportParameters>
deserialize_transport_parameters(std::span<const std::byte> bytes);

CodecResult<TransportParametersValidationOk> validate_peer_transport_parameters(
    EndpointRole peer_role,
    const TransportParameters &parameters,
    const TransportParametersValidationContext &context);

} // namespace coquic::quic
```

- [ ] **Step 4: Implement the serializer, parser, and validator**

Create `src/quic/transport_parameters.cpp` and implement:

- varint-encoded parameter IDs and lengths
- `max_udp_payload_size >= 1200`
- `active_connection_id_limit >= 2`
- server-only handling for `original_destination_connection_id` and
  `retry_source_connection_id`
- connection-ID matching against the context from RFC 9000 Section 7.3

Keep the first cut intentionally small. Support only the transport parameters
the milestone needs instead of building a generic QUIC transport-parameter
framework.

- [ ] **Step 5: Add the source and test to `build.zig`**

Update `build.zig` so the library compiles `src/quic/transport_parameters.cpp`
and the test binary compiles `tests/quic_transport_parameters_test.cpp`.

- [ ] **Step 6: Re-run the filtered test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTransportParametersTest.*
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/quic/transport_parameters.h src/quic/transport_parameters.cpp \
    tests/quic_transport_parameters_test.cpp
git commit -m "feat: add QUIC transport parameter helpers"
```

### Task 4: Add CRYPTO Stream Chunking And Reassembly Helpers

**Files:**
- Modify: `build.zig`
- Create: `src/quic/crypto_stream.h`
- Create: `src/quic/crypto_stream.cpp`
- Create: `tests/quic_crypto_stream_test.cpp`

- [ ] **Step 1: Write the failing CRYPTO stream tests**

Create `tests/quic_crypto_stream_test.cpp`:

```cpp
#include <gtest/gtest.h>

#include "src/quic/crypto_stream.h"

namespace {

using coquic::quic::CryptoReceiveBuffer;
using coquic::quic::CryptoSendBuffer;

TEST(QuicCryptoStreamTest, SendBufferProducesIncreasingOffsets) {
    CryptoSendBuffer buffer;
    buffer.append({std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}});

    const auto frames = buffer.take_frames(3);
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].offset, 0u);
    EXPECT_EQ(frames[1].offset, 3u);
}

TEST(QuicCryptoStreamTest, ReceiveBufferReleasesOnlyContiguousBytes) {
    CryptoReceiveBuffer buffer;

    const auto first = buffer.push(2, {std::byte{0xcc}, std::byte{0xdd}});
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(first.value().empty());

    const auto second = buffer.push(0, {std::byte{0xaa}, std::byte{0xbb}});
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value(),
              (std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb},
                                      std::byte{0xcc}, std::byte{0xdd}}));
}

} // namespace
```

- [ ] **Step 2: Run the filtered tests and watch them fail**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCryptoStreamTest.*
```

Expected: FAIL because the helper classes are not defined.

- [ ] **Step 3: Declare the helper types**

Create `src/quic/crypto_stream.h`:

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/varint.h"

namespace coquic::quic {

class CryptoSendBuffer {
  public:
    void append(std::span<const std::byte> bytes);
    std::vector<CryptoFrame> take_frames(std::size_t max_frame_payload_size);
    bool empty() const;

  private:
    std::vector<std::byte> pending_;
    std::uint64_t next_offset_ = 0;
  };

class CryptoReceiveBuffer {
  public:
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset,
                                             std::span<const std::byte> bytes);

  private:
    std::uint64_t next_contiguous_offset_ = 0;
    std::map<std::uint64_t, std::vector<std::byte>> segments_;
  };

} // namespace coquic::quic
```

- [ ] **Step 4: Implement the minimal send and receive behavior**

Create `src/quic/crypto_stream.cpp` so that:

- `append(...)` queues raw TLS bytes
- `take_frames(max_frame_payload_size)` emits one or more `CryptoFrame`s with
  monotonically increasing offsets
- `push(offset, bytes)` stores out-of-order data, merges overlapping segments
  conservatively, and returns only the newly contiguous bytes starting at
  `next_contiguous_offset_`

- [ ] **Step 5: Add the source and test to the build**

Update `build.zig` so the library compiles `src/quic/crypto_stream.cpp` and the
test binary compiles `tests/quic_crypto_stream_test.cpp`.

- [ ] **Step 6: Re-run the filtered tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCryptoStreamTest.*
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/quic/crypto_stream.h src/quic/crypto_stream.cpp \
    tests/quic_crypto_stream_test.cpp
git commit -m "feat: add QUIC CRYPTO stream buffers"
```

### Task 5: Add The Public QuicCore Surface And Client Bootstrap

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Create: `src/quic/core.h`
- Create: `src/quic/core.cpp`
- Create: `src/quic/connection.h`
- Create: `src/quic/connection.cpp`
- Modify: `tests/quic_test_utils.h`
- Create: `tests/quic_core_test.cpp`

- [ ] **Step 1: Extend the shared test helpers with deterministic configs**

Add to `tests/quic_test_utils.h`:

```cpp
#include "src/quic/core.h"

namespace coquic::quic::test {

inline QuicCoreConfig make_client_core_config() {
    return QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id =
            {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
             std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08}},
        .verify_peer = false,
        .server_name = "localhost",
    };
}

inline QuicCoreConfig make_server_core_config() {
    return QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .verify_peer = false,
        .server_name = "localhost",
        .identity = TlsIdentity{
            .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
            .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
        },
    };
}

} // namespace coquic::quic::test
```

- [ ] **Step 2: Write the failing QuicCore bootstrap tests**

Create `tests/quic_core_test.cpp`:

```cpp
#include <gtest/gtest.h>

#include "src/coquic.h"
#include "src/quic/protected_codec.h"
#include "tests/quic_test_utils.h"

namespace {

TEST(QuicCoreTest, ClientStartsHandshakeFromEmptyInput) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());

    const auto datagram = client.receive({});
    ASSERT_GE(datagram.size(), 1200u);
    EXPECT_FALSE(client.is_handshake_complete());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagram,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                coquic::quic::test::make_client_core_config().initial_destination_connection_id,
        });
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]), nullptr);
}

TEST(QuicCoreTest, ServerDoesNotEmitUntilItReceivesBytes) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    EXPECT_TRUE(server.receive({}).empty());
    EXPECT_FALSE(server.is_handshake_complete());
}

} // namespace
```

- [ ] **Step 3: Run the filtered tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.ClientStartsHandshakeFromEmptyInput:QuicCoreTest.ServerDoesNotEmitUntilItReceivesBytes
```

Expected: FAIL because `QuicCore` and `QuicConnection` do not exist yet.

- [ ] **Step 4: Declare the public and internal connection APIs**

Create `src/quic/core.h`:

```cpp
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::optional<TlsIdentity> identity;
};

class QuicConnection;

class QuicCore {
  public:
    explicit QuicCore(QuicCoreConfig config);
    ~QuicCore();

    std::vector<std::byte> receive(std::vector<std::byte> bytes);
    bool is_handshake_complete() const;

  private:
    std::unique_ptr<QuicConnection> connection_;
};

} // namespace coquic::quic
```

Create `src/quic/connection.h` with a concrete internal state holder:

```cpp
#pragma once

#include <optional>

#include "src/quic/crypto_stream.h"
#include "src/quic/tls_adapter.h"
#include "src/quic/transport_parameters.h"

namespace coquic::quic {

enum class HandshakeStatus : std::uint8_t {
    idle,
    in_progress,
    connected,
    failed,
};

struct PacketSpaceState {
    std::uint64_t next_send_packet_number = 0;
    std::optional<std::uint64_t> largest_authenticated_packet_number;
    std::optional<TrafficSecret> read_secret;
    std::optional<TrafficSecret> write_secret;
    CryptoSendBuffer send_crypto;
    CryptoReceiveBuffer receive_crypto;
};

class QuicConnection {
  public:
    explicit QuicConnection(QuicCoreConfig config);

    std::vector<std::byte> receive(std::span<const std::byte> bytes);
    bool is_handshake_complete() const;

  private:
    void start_client_if_needed();
};

} // namespace coquic::quic
```

- [ ] **Step 5: Export the new public API**

Update `src/coquic.h` to include:

```cpp
#include "src/quic/core.h"
```

- [ ] **Step 6: Implement the wrapper and the smallest client bootstrap**

In `src/quic/core.cpp`, make `QuicCore` forward directly to `QuicConnection`.

In `src/quic/connection.cpp`, implement the first client turn:

```cpp
void QuicConnection::start_client_if_needed() {
    if (config_.role != EndpointRole::client || started_) {
        return;
    }

    started_ = true;
    status_ = HandshakeStatus::in_progress;

    local_transport_parameters_ = TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = config_.source_connection_id,
    };
    tls_ = TlsAdapter(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .identity = config_.identity,
        .local_transport_parameters =
            serialize_transport_parameters(local_transport_parameters_).value(),
    });
    tls_.start().value();
    initial_space_.send_crypto.append(tls_.take_pending(EncryptionLevel::initial));
}
```

Then packetize that CRYPTO data into a single `ProtectedInitialPacket` and pad
the resulting datagram to 1200 bytes:

```cpp
std::vector<ProtectedPacket> packets{
    ProtectedInitialPacket{
        .version = 1,
        .destination_connection_id = config_.initial_destination_connection_id,
        .source_connection_id = config_.source_connection_id,
        .token = {},
        .packet_number_length = 2,
        .packet_number = initial_space_.next_send_packet_number++,
        .frames = initial_frames,
    },
};
```

- [ ] **Step 7: Add the sources and test to the build**

Update `build.zig` so the library compiles `src/quic/core.cpp` and
`src/quic/connection.cpp`, and the test binary compiles
`tests/quic_core_test.cpp`.

- [ ] **Step 8: Re-run the filtered bootstrap tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.ClientStartsHandshakeFromEmptyInput:QuicCoreTest.ServerDoesNotEmitUntilItReceivesBytes
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add build.zig src/coquic.h src/quic/core.h src/quic/core.cpp \
    src/quic/connection.h src/quic/connection.cpp tests/quic_test_utils.h \
    tests/quic_core_test.cpp
git commit -m "feat: add QUIC core bootstrap"
```

### Task 6: Process Client Initials On The Server And Emit The First Server Flight

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write the failing server-flight test**

Add to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, ServerProcessesClientInitialAndEmitsHandshakeFlight) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto client_initial = client.receive({});
    const auto server_flight = server.receive(client_initial);

    EXPECT_FALSE(server_flight.empty());
    EXPECT_FALSE(server.is_handshake_complete());
}
```

- [ ] **Step 2: Run the filtered test and confirm it fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.ServerProcessesClientInitialAndEmitsHandshakeFlight
```

Expected: FAIL because the server path does not yet parse and answer client
Initial packets.

- [ ] **Step 3: Add the server-side helpers to `QuicConnection`**

Extend `src/quic/connection.h` with:

```cpp
private:
    CodecResult<ConnectionId> peek_client_initial_destination_connection_id(
        std::span<const std::byte> bytes) const;
    void process_inbound_packet(const ProtectedPacket &packet);
    std::vector<std::byte> flush_outbound_datagram();
```

- [ ] **Step 4: Implement the server receive path**

In `src/quic/connection.cpp`:

- peek the client-chosen Initial destination connection ID from the incoming
  long header before calling `deserialize_protected_datagram(...)`
- build `DeserializeProtectionContext` with:

```cpp
DeserializeProtectionContext context{
    .peer_role = peer_role_,
    .client_initial_destination_connection_id = client_initial_destination_connection_id_,
    .handshake_secret = handshake_space_.read_secret,
    .one_rtt_secret = application_space_.read_secret,
    .largest_authenticated_initial_packet_number =
        initial_space_.largest_authenticated_packet_number,
    .largest_authenticated_handshake_packet_number =
        handshake_space_.largest_authenticated_packet_number,
    .largest_authenticated_application_packet_number =
        application_space_.largest_authenticated_packet_number,
    .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
};
```

- accept inbound `CRYPTO` frames, ignore `PADDING`, and feed newly contiguous
  TLS bytes into `TlsAdapter::provide(...)`
- capture the first server local transport parameters:

```cpp
local_transport_parameters_ = TransportParameters{
    .original_destination_connection_id = client_initial_destination_connection_id_,
    .max_udp_payload_size = 1200,
    .active_connection_id_limit = 2,
    .initial_source_connection_id = config_.source_connection_id,
};
```

- once TLS yields Handshake secrets and outbound bytes, emit a coalesced
  datagram containing:
  - one `ProtectedInitialPacket` carrying any pending Initial-level CRYPTO data
  - one `ProtectedHandshakePacket` carrying any pending Handshake-level CRYPTO
    data

- [ ] **Step 5: Re-run the filtered test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.ServerProcessesClientInitialAndEmitsHandshakeFlight
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/connection.h src/quic/connection.cpp tests/quic_core_test.cpp
git commit -m "feat: add QUIC server handshake flight"
```

### Task 7: Complete The Two-Peer Handshake And Validate Peer Transport Parameters

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write the failing end-to-end handshake test**

Add this integration test to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, TwoPeersCompleteHandshake) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    auto to_server = client.receive({});
    auto to_client = std::vector<std::byte>{};

    for (int i = 0; i < 16 && !(client.is_handshake_complete() && server.is_handshake_complete());
         ++i) {
        if (!to_server.empty()) {
            to_client = server.receive(to_server);
        }
        if (client.is_handshake_complete() && server.is_handshake_complete()) {
            break;
        }
        to_server = client.receive(to_client);
    }

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
}
```

- [ ] **Step 2: Run the filtered integration test and confirm it fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.TwoPeersCompleteHandshake
```

Expected: FAIL because the client continuation path and completion checks are
not implemented yet.

- [ ] **Step 3: Implement client continuation, secret installation, and transport-parameter validation**

In `src/quic/connection.cpp`:

- when inbound packets are decrypted successfully, update the largest
  authenticated packet number in the matching packet space
- when `TlsAdapter::take_available_secrets()` yields new secrets, install them
  into the matching `PacketSpaceState`
- when `peer_transport_parameters()` becomes available, parse and validate them
  with `validate_peer_transport_parameters(...)`
- drain outbound TLS bytes from Initial and Handshake levels into the matching
  `CryptoSendBuffer`s
- mark the handshake complete only when:
  - TLS reports handshake completion
  - peer transport parameters validated successfully
  - both read and write 1-RTT secrets are installed

Use a single dispatch point for inbound protected packets:

```cpp
std::visit([&](const auto &packet) {
    using PacketType = std::decay_t<decltype(packet)>;
    if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
        process_crypto_frames(EncryptionLevel::initial, packet.frames);
    } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
        process_crypto_frames(EncryptionLevel::handshake, packet.frames);
    } else {
        process_crypto_frames(EncryptionLevel::application, packet.frames);
    }
}, protected_packet);
```

- [ ] **Step 4: Re-run the filtered end-to-end test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicCoreTest.TwoPeersCompleteHandshake
```

Expected: PASS.

- [ ] **Step 5: Run the full handshake-focused test set**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterTest.*:QuicTransportParametersTest.*:QuicCryptoStreamTest.*:QuicCoreTest.*
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/connection.h src/quic/connection.cpp tests/quic_core_test.cpp
git commit -m "feat: complete QUIC handshake core"
```

### Task 8: Run Full Verification And Final Cleanup

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/crypto_stream.h`
- Modify: `src/quic/crypto_stream.cpp`
- Modify: `src/quic/transport_parameters.h`
- Modify: `src/quic/transport_parameters.cpp`
- Modify: `src/quic/tls_adapter.h`
- Modify: `src/quic/tls_adapter.cpp`
- Modify: `tests/quic_tls_adapter_test.cpp`
- Modify: `tests/quic_transport_parameters_test.cpp`
- Modify: `tests/quic_crypto_stream_test.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_test_utils.h`

- [ ] **Step 1: Run formatting verification**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
```

Expected: PASS with no diff.

- [ ] **Step 2: Run clang-tidy verification**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: PASS with no diagnostics.

- [ ] **Step 3: Run a full build**

Run:

```bash
nix develop -c zig build
```

Expected: PASS.

- [ ] **Step 4: Run the full test suite**

Run:

```bash
nix develop -c zig build test
```

Expected: PASS.

- [ ] **Step 5: Run coverage**

Run:

```bash
nix develop -c zig build coverage
```

Expected: PASS and refreshed coverage output under `coverage/`.

- [ ] **Step 6: Commit the final verified implementation**

```bash
git add build.zig src/coquic.h src/quic/core.h src/quic/core.cpp \
    src/quic/connection.h src/quic/connection.cpp src/quic/crypto_stream.h \
    src/quic/crypto_stream.cpp src/quic/transport_parameters.h \
    src/quic/transport_parameters.cpp src/quic/tls_adapter.h \
    src/quic/tls_adapter.cpp tests/quic_tls_adapter_test.cpp \
    tests/quic_transport_parameters_test.cpp tests/quic_crypto_stream_test.cpp \
    tests/quic_core_test.cpp tests/quic_test_utils.h \
    tests/fixtures/quic-server-cert.pem tests/fixtures/quic-server-key.pem
git commit -m "feat: add QUIC handshake core"
```

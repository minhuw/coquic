# QUIC Key Update Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable the official `keyupdate` interop testcase locally and in CI, and implement one locally initiated 1-RTT key update for client-side transfer traffic.

**Architecture:** Make `keyupdate` a first-class runtime testcase that keeps normal transfer-style HTTP/0.9 behavior. Have the HTTP/0.9 client endpoint queue one explicit `QuicCoreRequestKeyUpdate` after the first request stream is actually accepted, then let `QuicConnection` defer local initiation until handshake confirmation and acknowledgement of a packet sent in the current write phase. When the local update happens, retain the previous read secret temporarily so reordered old-phase packets still decrypt until the peer responds in the new phase.

**Tech Stack:** Zig build system, C++20, GoogleTest, Bash, Nix, official `quic-interop-runner`

---

## File Map

- `.github/workflows/interop.yml`: add `keyupdate` to the official-runner testcase lists only after local runner verification is green.
- `interop/entrypoint.sh`: accept `TESTCASE=keyupdate` for local official-runner containers.
- `src/quic/http09.h`: add `QuicHttp09Testcase::keyupdate`.
- `src/quic/http09_runtime.cpp`: expose `keyupdate` in usage text and testcase parsing, and pass a `request_key_update` policy flag into the HTTP/0.9 client endpoint.
- `src/quic/http09_client.h`: add one-bit client policy state for `request_key_update` and `key_update_requested`.
- `src/quic/http09_client.cpp`: emit one `QuicCoreRequestKeyUpdate` after the first request stream is activated for the `keyupdate` testcase.
- `src/quic/core.h`: add the explicit `QuicCoreRequestKeyUpdate` input type and extend `QuicCoreInput`.
- `src/quic/core.cpp`: add a minimal no-op `QuicCoreRequestKeyUpdate` visit arm in Task 2 for compilation safety, then replace that no-op with real forwarding in Task 4.
- `src/quic/connection.h`: add narrow connection state for pending local key updates, single-update gating, current-phase acknowledgement tracking, and temporary previous read-key retention.
- `src/quic/connection.cpp`: defer local initiation until RFC-legal, flip application secrets and key phases locally, clear pending local requests if the peer updates first, and accept reordered old-phase packets with retained previous read keys.
- `tests/quic_http09_runtime_test.cpp`: cover env and CLI parsing for `keyupdate`.
- `tests/quic_http09_client_test.cpp`: cover one-shot `QuicCoreRequestKeyUpdate` emission and the absence of that emission for `transfer`.
- `tests/quic_core_test.cpp`: cover request deferral, local phase flip after acknowledgement, reordered old-phase receipt, previous-key retirement, and peer-first satisfaction.
- Leave `src/quic/http09_runtime.h` unchanged: the runtime config already carries `testcase`, so this slice does not need new public runtime fields.
- Leave `src/quic/recovery.h` unchanged: use a connection-level `current_write_phase_first_packet_number_` threshold instead of tagging `SentPacketRecord` with extra key-phase metadata.

### Task 1: Accept `keyupdate` in local testcase parsing and entrypoint surfaces

**Files:**
- Modify: `interop/entrypoint.sh`
- Modify: `src/quic/http09.h`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write failing runtime parsing tests for `keyupdate`**

Add these tests to `tests/quic_http09_runtime_test.cpp`:

```cpp
TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialKeyUpdateTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "keyupdate");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::keyupdate);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsKeyUpdateCliFlag) {
    const char *argv[] = {"coquic", "interop-client", "--testcase", "keyupdate",
                          "--requests", "https://localhost/hello.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::keyupdate);
}

TEST(QuicHttp09RuntimeTest, KeyUpdateUsesTransferTransportProfile) {
    const auto keyupdate = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::keyupdate,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost/hello.txt",
    };

    const auto keyupdate_core = coquic::quic::make_http09_client_core_config(keyupdate);
    const auto transfer_core = coquic::quic::make_http09_client_core_config(transfer);

    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_bidi,
              transfer_core.transport.initial_max_streams_bidi);
    EXPECT_EQ(keyupdate_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(coquic::quic::test::client_receive_timeout_ms_for_tests(keyupdate),
              coquic::quic::test::client_receive_timeout_ms_for_tests(transfer));
}
```

- [ ] **Step 2: Run the targeted runtime tests and verify the new case fails first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*KeyUpdate*'
```

Expected: FAIL because `keyupdate` is not parsed yet in the runtime surface.

- [ ] **Step 3: Add the testcase name to the runtime enum, parser, usage text, and entrypoint**

Make these minimal changes:

```cpp
enum class QuicHttp09Testcase : std::uint8_t {
    handshake,
    transfer,
    keyupdate,
    multiconnect,
    chacha20,
    resumption,
    zerortt,
    v2,
};
```

```cpp
if (value == "keyupdate") {
    return QuicHttp09Testcase::keyupdate;
}
```

```bash
handshake | transfer | keyupdate | amplificationlimit | multiconnect | chacha20 | retry | resumption | zerortt | v2)
```

Also add `keyupdate` to the usage string in `src/quic/http09_runtime.cpp`.

- [ ] **Step 4: Re-run the targeted runtime tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*KeyUpdate*'
```

Expected: PASS.

- [ ] **Step 5: Commit the runtime testcase-surface changes**

Run:

```bash
git add interop/entrypoint.sh src/quic/http09.h src/quic/http09_runtime.cpp \
        tests/quic_http09_runtime_test.cpp
git commit -m "feat: accept keyupdate testcase locally"
```

Expected: one clean commit containing only the parser and entrypoint enablement.

### Task 2: Queue one explicit local key-update request from the HTTP/0.9 client endpoint

**Files:**
- Modify: `src/quic/http09_client.h`
- Modify: `src/quic/http09_client.cpp`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/core.h` (minimal input type declaration only)
- Modify: `src/quic/core.cpp` (minimal explicit no-op visit arm only)
- Test: `tests/quic_http09_client_test.cpp`

- [ ] **Step 1: Write failing client-endpoint tests for one-shot request emission**

Add these tests to `tests/quic_http09_client_test.cpp`:

```cpp
TEST(QuicHttp09ClientTest, KeyUpdateCaseQueuesSingleRequestAfterFirstRequestActivation) {
    const auto now = coquic::quic::test::test_time();
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/alpha.txt")},
        .download_root = std::filesystem::path("/downloads"),
        .request_key_update = true,
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);
    const auto accepted =
        endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(1));

    ASSERT_EQ(accepted.core_inputs.size(), 1u);
    EXPECT_TRUE(std::holds_alternative<coquic::quic::QuicCoreRequestKeyUpdate>(
        accepted.core_inputs.front()));
}

TEST(QuicHttp09ClientTest, TransferCaseDoesNotQueueLocalKeyUpdateRequest) {
    const auto now = coquic::quic::test::test_time();
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/alpha.txt")},
        .download_root = std::filesystem::path("/downloads"),
        .request_key_update = false,
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);
    const auto accepted =
        endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(1));

    EXPECT_TRUE(accepted.core_inputs.empty());
}
```

- [ ] **Step 2: Run the targeted client tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09ClientTest.*KeyUpdate*'
```

Expected: FAIL to compile or run because the client config and core input do not expose local key-update requests yet.

- [ ] **Step 3: Add the one-shot endpoint policy and wire it from the runtime**

Implement the client policy exactly once per connection:

```cpp
struct QuicHttp09ClientConfig {
    std::vector<QuicHttp09Request> requests;
    std::filesystem::path download_root;
    bool allow_requests_before_handshake_ready = false;
    bool request_key_update = false;
};
```

```cpp
if (config_.request_key_update && !key_update_requested_ && request_index == 0) {
    pending_core_inputs_.emplace_back(QuicCoreRequestKeyUpdate{});
    key_update_requested_ = true;
}
```

```cpp
QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
    .requests = requests,
    .download_root = config.download_root,
    .allow_requests_before_handshake_ready =
        allow_requests_before_handshake_ready(attempt_zero_rtt_requests, start_result),
    .request_key_update = config.testcase == QuicHttp09Testcase::keyupdate,
});
```

Queue the request from `activate_pending_request()` so it only happens after the first HTTP request stream has been accepted by the transport.

Because `QuicCoreInput` gains a new variant in this task, add the smallest compile-safe core slice now:

```cpp
struct QuicCoreRequestKeyUpdate {};
```

```cpp
[&](const QuicCoreRequestKeyUpdate &) {},
```

This no-op arm is Task 2 scaffolding only; real forwarding and transport behavior starts in Task 4.

- [ ] **Step 4: Re-run the targeted client tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09ClientTest.*KeyUpdate*'
```

Expected: PASS.

- [ ] **Step 5: Commit the client-endpoint policy slice**

Run:

```bash
git add src/quic/http09_client.h src/quic/http09_client.cpp src/quic/http09_runtime.cpp \
        src/quic/core.h src/quic/core.cpp tests/quic_http09_client_test.cpp
git commit -m "feat: queue local keyupdate requests from http09 client"
```

Expected: one clean commit containing the HTTP/0.9 policy changes plus the minimal explicit core no-op surface required to compile.

### Task 3: Add failing transport tests for the local key-update state machine

**Files:**
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Add focused failing tests that lock down the transport behavior**

Add these transport tests to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, LocalKeyUpdateWaitsForHandshakeConfirmationAndAckedCurrentPhasePacket) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.request_key_update();

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
}

TEST(QuicCoreTest, LocalKeyUpdateUsesNewKeyPhaseAfterCurrentPhasePacketIsAcknowledged) {
    auto connection = make_connected_client_connection();
    connection.request_key_update();

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto current_phase_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(current_phase_datagram.empty());

    connection.process_inbound_ack(connection.application_space_,
                                   coquic::quic::AckFrame{
                                       .largest_acknowledged = 0,
                                       .first_ack_range = 0,
                                   },
                                   coquic::quic::test::test_time(2),
                                   connection.config_.transport.ack_delay_exponent,
                                   connection.config_.transport.max_ack_delay,
                                   false);

    ASSERT_TRUE(connection.queue_stream_send(4, bytes_from_ints({0x62}), false).has_value());
    const auto updated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(updated_datagram.empty());
}
```

Also add two more tests with concrete names and assertions:

- `QuicCoreTest.LocalKeyUpdateRetainsPreviousReadKeysUntilPeerRespondsInNewPhase`
- `QuicCoreTest.PendingLocalKeyUpdateClearsWhenPeerUpdatesFirst`

Use the same protected-packet helpers already exercised by:

- `ProcessInboundDatagramPromotesApplicationKeysOnPeerKeyUpdate`
- `KeyUpdatedAckOnlyPacketRetiresAckedApplicationFragment`

The retained-key test must:

- locally initiate the update
- inject one reordered old-phase 1-RTT packet using the pre-update read secret and old key phase
- verify the packet is accepted
- then inject one new-phase packet using the post-update read secret and current key phase
- verify `previous_application_read_secret_` is cleared afterward

- [ ] **Step 2: Run the focused core tests and verify they fail first**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*KeyUpdate*'
```

Expected: FAIL because there is no explicit local key-update request type and no transport support for locally initiated phase changes.

### Task 4: Replace the Task 2 no-op with real core forwarding and implement the one-update transport state machine

**Files:**
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Replace the Task 2 no-op core arm with connection forwarding and add the connection request hook**

The public core input surface already exists from Task 2:

```cpp
struct QuicCoreRequestKeyUpdate {};

using QuicCoreInput =
    std::variant<QuicCoreStart, QuicCoreInboundDatagram, QuicCoreSendStreamData,
                 QuicCoreResetStream, QuicCoreStopSending, QuicCoreRequestKeyUpdate,
                 QuicCoreTimerExpired>;
```

Forward it in `QuicCore::advance`:

```cpp
[&](const QuicCoreRequestKeyUpdate &) { connection_->request_key_update(); },
```

Add a narrow connection hook in `src/quic/connection.h`:

```cpp
void request_key_update();
```

- [ ] **Step 2: Add the local key-update state and initiate only when RFC 9001 Section 6.1 allows it**

Add only the state required for one locally initiated update:

```cpp
bool local_key_update_requested_ = false;
bool local_key_update_initiated_ = false;
std::optional<std::uint64_t> current_write_phase_first_packet_number_;
std::optional<TrafficSecret> previous_application_read_secret_;
bool previous_application_read_key_phase_ = false;
```

Implement these rules in `src/quic/connection.cpp`:

- `request_key_update()` only records intent; it does not fail for early calls.
- The connection may initiate only when all are true:
  - `handshake_confirmed_`
  - `application_space_.read_secret.has_value()`
  - `application_space_.write_secret.has_value()`
  - `!local_key_update_initiated_`
  - `current_write_phase_first_packet_number_.has_value()`
  - an ACK has newly acknowledged an application packet number greater than or equal to `*current_write_phase_first_packet_number_`
- Perform the initiation in the outbound application send path immediately before serializing the next 1-RTT packet so the new write secret and new key phase become active atomically for that packet.

- [ ] **Step 3: Retain the previous read secret, accept reordered old-phase packets, and clear pending requests when the peer updates first**

Update short-header receive handling in `process_inbound_datagram`:

```cpp
if (!packets.has_value() && short_header_packet && previous_application_read_secret_.has_value()) {
    auto previous_packets = deserialize_protected_datagram(
        packet_bytes,
        make_deserialize_context(previous_application_read_secret_,
                                 previous_application_read_key_phase_));
    if (previous_packets.has_value()) {
        packets = std::move(previous_packets);
    }
}
```

Keep these behaviors together:

- when the local endpoint initiates:
  - save the old read secret into `previous_application_read_secret_`
  - save the old phase into `previous_application_read_key_phase_`
  - derive and install next read and write secrets
  - toggle `application_read_key_phase_` and `application_write_key_phase_`
  - set `local_key_update_initiated_ = true`
  - set `current_write_phase_first_packet_number_` to the first packet number sent in the new phase
- when a peer-driven key update succeeds before local initiation:
  - clear `local_key_update_requested_`
  - do not immediately initiate another update
- when any packet protected with the current post-update read phase is successfully processed:
  - clear `previous_application_read_secret_`

- [ ] **Step 4: Re-run the focused key-update tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*KeyUpdate*'
```

Expected: PASS, including the retained-old-keys and peer-first cases.

- [ ] **Step 5: Commit the transport key-update implementation**

Run:

```bash
git add src/quic/core.h src/quic/core.cpp src/quic/connection.h src/quic/connection.cpp \
        tests/quic_core_test.cpp
git commit -m "feat: add local quic keyupdate support"
```

Expected: one clean commit containing only the explicit core input and transport state machine.

### Task 5: Verify locally, then enable `keyupdate` in the interop workflow

**Files:**
- Modify: `.github/workflows/interop.yml`
- Use: `interop/run-official.sh`

- [ ] **Step 1: Run the focused GoogleTest coverage for runtime, client, and core slices**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*KeyUpdate*:QuicHttp09ClientTest.*KeyUpdate*:QuicCoreTest.*KeyUpdate*'
```

Expected: PASS.

- [ ] **Step 2: Run the full local test suite before touching CI selection**

Run:

```bash
nix develop -c zig build test
```

Expected: PASS.

- [ ] **Step 3: Run the local official-runner `keyupdate` testcase against the pinned `quic-go` peer**

Run:

```bash
INTEROP_TESTCASES=keyupdate \
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
nix develop -c bash interop/run-official.sh
```

Expected: the runner completes and reports a passing `keyupdate` result for the pinned `quic-go` peer.

- [ ] **Step 4: Run the same local official-runner testcase against the pinned `picoquic` peer**

Run:

```bash
INTEROP_TESTCASES=keyupdate \
INTEROP_PEER_IMPL=picoquic \
INTEROP_PEER_IMAGE=privateoctopus/picoquic@sha256:7e4110e3260cd9d4f815ad63ca1d93e020e94d3a8d3cb6cb9cc5c59d97999b05 \
nix develop -c bash interop/run-official.sh
```

Expected: the runner completes and reports whether the current implementation also passes `keyupdate` against the pinned `picoquic` peer.

- [ ] **Step 5: After the local runner is green, add `keyupdate` to both workflow matrices and commit**

Update both `INTEROP_TESTCASES` lines in `.github/workflows/interop.yml` so they include `keyupdate`.

Run:

```bash
git add .github/workflows/interop.yml
git commit -m "ci: enable keyupdate interop coverage"
```

Expected: one final CI-only commit after local verification is already complete.

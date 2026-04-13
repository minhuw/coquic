# HTTP/3 Client Cancellation Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagate peer request rejection and cancellation on client request streams through `Http3Connection` and `Http3ClientEndpoint` so repo-native HTTP/3 clients do not retain stale active-request state when a peer resets a request stream.

**Architecture:** Keep QUIC-side reset handling inside `Http3Connection`, but surface a protocol event when a peer resets a client request stream. Extend `Http3ClientEndpoint` with a small per-request error event so callers can distinguish completed responses from peer-reset requests without turning a single-stream cancellation into a connection-wide failure.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/http3_connection.*`, existing `src/http3/http3_client.*`, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### Task 1: Add RED tests for peer-reset propagation on client request streams

**Files:**
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/client_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRolePeerReset*:QuicHttp3ClientTest.PeerReset*'`

- [ ] **Step 1: Add a failing connection test for peer reset events**

Add this test near the other client-role connection tests in `tests/http3/connection_test.cpp`:

```cpp
TEST(QuicHttp3ConnectionTest, ClientRolePeerResetEmitsResponseResetEvent) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const auto update = connection.on_core_result(
        reset_result(0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected)),
        coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(update.events.size(), 1u);
    const auto *reset =
        std::get_if<coquic::http3::Http3PeerResponseResetEvent>(&update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected));
}
```

- [ ] **Step 2: Run the new connection test and verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRolePeerResetEmitsResponseResetEvent'`

Expected: FAIL because `Http3PeerResponseResetEvent` does not exist yet and peer resets do not emit a client-side endpoint event.

- [ ] **Step 3: Add failing client-endpoint tests for rejected and cancelled requests**

Add these tests near the existing client endpoint tests in `tests/http3/client_test.cpp`:

```cpp
TEST(QuicHttp3ClientTest, PeerResetRejectedRequestEmitsRequestErrorEvent) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/reject",
            },
    });
    ASSERT_TRUE(submitted.has_value());

    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const auto update = endpoint.on_core_result(
        reset_result(0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected)),
        coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(update.terminal_failure);
    ASSERT_TRUE(update.events.empty());
    ASSERT_EQ(update.request_error_events.size(), 1u);
    EXPECT_EQ(update.request_error_events[0].stream_id, 0u);
    EXPECT_EQ(update.request_error_events[0].request.head.path, "/reject");
    EXPECT_EQ(update.request_error_events[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected));
}
```

```cpp
TEST(QuicHttp3ClientTest, PeerResetAfterCompletedResponseIsIgnored) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "GET",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/complete",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
    };
    const auto response_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, response_headers), true),
                                coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(response_update.events.size(), 1u);
    ASSERT_TRUE(response_update.request_error_events.empty());

    const auto reset_update = endpoint.on_core_result(
        reset_result(0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(reset_update.terminal_failure);
    EXPECT_TRUE(reset_update.events.empty());
    EXPECT_TRUE(reset_update.request_error_events.empty());
}
```

- [ ] **Step 4: Run the focused client tests and verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ClientTest.PeerReset*'`

Expected: FAIL because `Http3ClientEndpointUpdate` has no request-error event collection and the endpoint currently leaks active-request state on peer reset.

### Task 2: Extend shared HTTP/3 types for peer response resets and client request-error events

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_client.h`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRolePeerReset*:QuicHttp3ClientTest.PeerReset*'`

- [ ] **Step 1: Add a connection-level peer response reset event**

In `src/http3/http3.h`, add:

```cpp
struct Http3PeerResponseResetEvent {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};
```

Then extend `Http3EndpointEvent`:

```cpp
using Http3EndpointEvent = std::variant<
    Http3PeerRequestHeadEvent, Http3PeerRequestBodyEvent, Http3PeerRequestTrailersEvent,
    Http3PeerRequestCompleteEvent, Http3PeerInformationalResponseEvent, Http3PeerResponseHeadEvent,
    Http3PeerResponseBodyEvent, Http3PeerResponseTrailersEvent, Http3PeerResponseCompleteEvent,
    Http3PeerResponseResetEvent>;
```

- [ ] **Step 2: Add a client-side per-request error event**

In `src/http3/http3_client.h`, add:

```cpp
struct Http3ClientRequestErrorEvent {
    std::uint64_t stream_id = 0;
    Http3Request request;
    std::uint64_t application_error_code = 0;
};
```

Extend `Http3ClientEndpointUpdate`:

```cpp
struct Http3ClientEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3ClientResponseEvent> events;
    std::vector<Http3ClientRequestErrorEvent> request_error_events;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};
```

- [ ] **Step 3: Re-run the focused tests to move the failure into implementation**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRolePeerReset*:QuicHttp3ClientTest.PeerReset*'`

Expected: FAIL because the new types compile, but `Http3Connection` still drops peer resets silently and `Http3ClientEndpoint` still does not translate them into request-error events.

### Task 3: Implement peer-reset propagation in the shared connection engine and client endpoint

**Files:**
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3_client.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/client_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRolePeerReset*:QuicHttp3ClientTest.PeerReset*'`

- [ ] **Step 1: Emit a response-reset event when a peer resets a client request stream**

In `src/http3/http3_connection.cpp`, update `handle_peer_reset_stream(...)` so local client request streams emit a protocol event before the state is erased:

```cpp
    const auto local_request = local_request_streams_.find(reset.stream_id);
    if (local_request != local_request_streams_.end()) {
        if (local_request->second.blocked_field_section.has_value()) {
            const auto cancelled = cancel_http3_qpack_stream(decoder_, reset.stream_id);
            if (!cancelled.has_value()) {
                queue_connection_close(cancelled.error().code, cancelled.error().detail);
                return;
            }
            flush_qpack_decoder_instructions();
            if (closed_) {
                return;
            }
        }

        pending_events_.push_back(Http3PeerResponseResetEvent{
            .stream_id = reset.stream_id,
            .application_error_code = reset.application_error_code,
        });
        local_request_streams_.erase(local_request);
    }
```

Keep the existing critical-stream and peer-request-stream logic intact.

- [ ] **Step 2: Translate response-reset events into client request-error events**

In `src/http3/http3_client.cpp`, extend `handle_connection_events(...)`:

```cpp
        if (const auto *reset = std::get_if<Http3PeerResponseResetEvent>(&event)) {
            const auto request_it = active_requests_.find(reset->stream_id);
            if (request_it == active_requests_.end()) {
                pending_responses_.erase(reset->stream_id);
                continue;
            }

            pending_responses_.erase(reset->stream_id);
            update.request_error_events.push_back(Http3ClientRequestErrorEvent{
                .stream_id = reset->stream_id,
                .request = std::move(request_it->second),
                .application_error_code = reset->application_error_code,
            });
            active_requests_.erase(request_it);
            continue;
        }
```

This keeps a peer-reset request local to the stream instead of converting it into endpoint failure.

- [ ] **Step 3: Run the focused tests and keep them green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRolePeerReset*:QuicHttp3ClientTest.PeerReset*'`

Expected: PASS.

### Task 4: Run wider HTTP/3 verification and commit the slice

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3_client.h`
- Modify: `src/http3/http3_client.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/client_test.cpp`

- [ ] **Step 1: Run the wider HTTP/3 test slice**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.*:QuicHttp3Qpack*:QuicHttp3ConnectionTest*:QuicHttp3ServerTest*:QuicHttp3ClientTest.*'`

Expected: PASS.

- [ ] **Step 2: Format and lint the touched files**

Run: `nix develop -c pre-commit run clang-format --files src/http3/http3.h src/http3/http3_connection.cpp src/http3/http3_client.h src/http3/http3_client.cpp tests/http3/connection_test.cpp tests/http3/client_test.cpp`

Expected: PASS.

Run: `nix develop -c pre-commit run coquic-clang-tidy --files src/http3/http3.h src/http3/http3_connection.cpp src/http3/http3_client.h src/http3/http3_client.cpp tests/http3/connection_test.cpp tests/http3/client_test.cpp`

Expected: PASS.

- [ ] **Step 3: Run the repo verification bar**

Run: `nix develop -c zig build test`

Expected: PASS.

- [ ] **Step 4: Commit the slice**

```bash
git add docs/superpowers/plans/2026-04-12-http3-client-cancellation.md \
  src/http3/http3.h src/http3/http3_connection.cpp \
  src/http3/http3_client.h src/http3/http3_client.cpp \
  tests/http3/connection_test.cpp tests/http3/client_test.cpp
git commit -m "feat: propagate http3 client request cancellation"
```

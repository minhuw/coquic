# HTTP/3 Server Cancellation Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagate request-stream resets and response-stream `STOP_SENDING` into the shared HTTP/3 server path so the server endpoint can observe cancelled in-flight requests and the connection stops sending abandoned responses.

**Architecture:** Extend `Http3Connection` with a server-side peer-request reset event and explicit handling of peer `STOP_SENDING` on local response streams. Keep the protocol mechanics in the shared connection engine, and let `Http3ServerEndpoint` translate request-reset events into non-terminal server cancellation events without turning stream-level cancellation into endpoint failure.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/http3_connection.*`, existing `src/http3/http3_server.*`, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### Task 1: Add RED tests for server-side cancellation behavior

**Files:**
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRolePeer*:QuicHttp3ServerTest.PeerReset*'`

- [ ] **Step 1: Add a helper to synthesize peer STOP_SENDING**

In `tests/http3/connection_test.cpp`, add near `reset_result(...)`:

```cpp
coquic::quic::QuicCoreResult stop_sending_result(std::uint64_t stream_id,
                                                 std::uint64_t error_code = 0) {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCorePeerStopSending{
            .stream_id = stream_id,
            .application_error_code = error_code,
        },
    });
    return result;
}
```

- [ ] **Step 2: Add a failing connection test for request reset propagation**

Add this test near the other server-role request-stream tests in `tests/http3/connection_test.cpp`:

```cpp
TEST(QuicHttp3ConnectionTest, ServerRolePeerResetEmitsRequestResetEvent) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(reset_update.events.size(), 1u);
    const auto *reset =
        std::get_if<coquic::http3::Http3PeerRequestResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}
```

- [ ] **Step 3: Add a failing connection test for response stop-sending**

Add this test in `tests/http3/connection_test.cpp`:

```cpp
TEST(QuicHttp3ConnectionTest, ServerRolePeerStopSendingResetsLocalResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/hello"},
    };

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                                   .status = 200,
                                               })
                    .has_value());

    const auto stop_update = connection.on_core_result(
        stop_sending_result(
            0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    const auto resets = reset_stream_inputs_from(stop_update);

    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
    EXPECT_FALSE(connection
                     .submit_response_body(0, bytes_from_text("late body"), true)
                     .has_value());
}
```

- [ ] **Step 4: Add a failing server-endpoint test for partial request cancellation**

In `tests/http3/server_test.cpp`, add:

```cpp
TEST(QuicHttp3ServerTest, PeerResetDropsBufferedRequestAndEmitsCancellationEvent) {
    bool handler_called = false;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_handler =
            [&](const coquic::http3::Http3Request &) {
                handler_called = true;
                return coquic::http3::Http3Response{
                    .head = {.status = 204},
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto headers_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(headers_update.terminal_failure);

    const auto body_update = endpoint.on_core_result(receive_result(0, data_frame_bytes("ping")),
                                                     coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(body_update.terminal_failure);

    const auto cancel_update = endpoint.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(cancel_update.terminal_failure);
    EXPECT_FALSE(handler_called);
    ASSERT_EQ(cancel_update.request_cancelled_events.size(), 1u);
    EXPECT_EQ(cancel_update.request_cancelled_events[0].stream_id, 0u);
    ASSERT_TRUE(cancel_update.request_cancelled_events[0].head.has_value());
    EXPECT_EQ(cancel_update.request_cancelled_events[0].head->path, "/upload");
    EXPECT_EQ(cancel_update.request_cancelled_events[0].body, bytes_from_text("ping"));
    EXPECT_EQ(cancel_update.request_cancelled_events[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}
```

- [ ] **Step 5: Run the focused tests and verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRolePeer*:QuicHttp3ServerTest.PeerReset*'`

Expected: FAIL because the shared connection engine does not emit server-side request reset events, `STOP_SENDING` on response streams is ignored, and `Http3ServerEndpointUpdate` has no cancellation-event surface.

### Task 2: Extend shared and server endpoint types for cancellation events

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_server.h`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRolePeer*:QuicHttp3ServerTest.PeerReset*'`

- [ ] **Step 1: Add a shared peer request reset event**

In `src/http3/http3.h`, add:

```cpp
struct Http3PeerRequestResetEvent {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};
```

Extend `Http3EndpointEvent`:

```cpp
using Http3EndpointEvent = std::variant<
    Http3PeerRequestHeadEvent, Http3PeerRequestBodyEvent, Http3PeerRequestTrailersEvent,
    Http3PeerRequestCompleteEvent, Http3PeerRequestResetEvent,
    Http3PeerInformationalResponseEvent, Http3PeerResponseHeadEvent,
    Http3PeerResponseBodyEvent, Http3PeerResponseTrailersEvent,
    Http3PeerResponseCompleteEvent, Http3PeerResponseResetEvent>;
```

- [ ] **Step 2: Add a server-side cancellation event surface**

In `src/http3/http3_server.h`, add:

```cpp
struct Http3ServerRequestCancelledEvent {
    std::uint64_t stream_id = 0;
    std::optional<Http3RequestHead> head;
    std::vector<std::byte> body;
    Http3Headers trailers;
    std::uint64_t application_error_code = 0;
};
```

Extend `Http3ServerEndpointUpdate`:

```cpp
struct Http3ServerEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3ServerRequestCancelledEvent> request_cancelled_events;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};
```

- [ ] **Step 3: Re-run the focused tests to move the failure into implementation**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRolePeer*:QuicHttp3ServerTest.PeerReset*'`

Expected: FAIL because the new types exist, but `Http3Connection` still does not emit the new event or act on response-stream `STOP_SENDING`, and the server endpoint still ignores cancelled streams.

### Task 3: Implement server-side cancellation in the shared connection engine and server wrapper

**Files:**
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3_server.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRolePeer*:QuicHttp3ServerTest.PeerReset*'`

- [ ] **Step 1: Emit a request-reset event when a peer resets an in-flight server request stream**

In `src/http3/http3_connection.cpp`, update `handle_peer_reset_stream(...)` for `peer_request_streams_`:

```cpp
    const auto request = peer_request_streams_.find(reset.stream_id);
    if (request == peer_request_streams_.end()) {
        return;
    }

    if (request->second.blocked_field_section.has_value()) {
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
    pending_events_.push_back(Http3PeerRequestResetEvent{
        .stream_id = reset.stream_id,
        .application_error_code = reset.application_error_code,
    });
    peer_request_streams_.erase(request);
```

- [ ] **Step 2: Reset abandoned local response streams on peer `STOP_SENDING`**

In `src/http3/http3_connection.cpp`, extend `handle_peer_stop_sending(...)`:

```cpp
    const auto response = local_response_streams_.find(stop.stream_id);
    if (response == local_response_streams_.end()) {
        return;
    }

    pending_core_inputs_.push_back(quic::QuicCoreResetStream{
        .stream_id = stop.stream_id,
        .application_error_code = stop.application_error_code,
    });
    local_response_streams_.erase(response);
```

Keep the existing critical-stream guard at the top of the function.

- [ ] **Step 3: Translate request-reset events into non-terminal server cancellation updates**

In `src/http3/http3_server.cpp`, extend the event loop in `on_core_result(...)`:

```cpp
        if (const auto *reset = std::get_if<Http3PeerRequestResetEvent>(&event)) {
            const auto pending_it = pending_requests_.find(reset->stream_id);
            if (pending_it == pending_requests_.end()) {
                continue;
            }

            update.request_cancelled_events.push_back(Http3ServerRequestCancelledEvent{
                .stream_id = reset->stream_id,
                .head = std::move(pending_it->second.head),
                .body = std::move(pending_it->second.body),
                .trailers = std::move(pending_it->second.trailers),
                .application_error_code = reset->application_error_code,
            });
            pending_requests_.erase(pending_it);
            continue;
        }
```

This must not mark the endpoint failed and must not call the request handler.

- [ ] **Step 4: Run the focused tests and keep them green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRolePeer*:QuicHttp3ServerTest.PeerReset*'`

Expected: PASS.

### Task 4: Run wider verification and commit the slice

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3_server.h`
- Modify: `src/http3/http3_server.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/server_test.cpp`

- [ ] **Step 1: Run the wider HTTP/3 test slice**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.*:QuicHttp3Qpack*:QuicHttp3ConnectionTest*:QuicHttp3ServerTest*:QuicHttp3ClientTest.*'`

Expected: PASS.

- [ ] **Step 2: Format and lint the touched files**

Run: `nix develop -c pre-commit run clang-format --files src/http3/http3.h src/http3/http3_connection.cpp src/http3/http3_server.h src/http3/http3_server.cpp tests/http3/connection_test.cpp tests/http3/server_test.cpp`

Expected: PASS.

Run: `nix develop -c pre-commit run coquic-clang-tidy --files src/http3/http3.h src/http3/http3_connection.cpp src/http3/http3_server.h src/http3/http3_server.cpp tests/http3/connection_test.cpp tests/http3/server_test.cpp`

Expected: PASS.

- [ ] **Step 3: Run the repo verification bar**

Run: `nix develop -c zig build test`

Expected: PASS.

- [ ] **Step 4: Commit the slice**

```bash
git add docs/superpowers/plans/2026-04-12-http3-server-cancellation.md \
  src/http3/http3.h src/http3/http3_connection.cpp \
  src/http3/http3_server.h src/http3/http3_server.cpp \
  tests/http3/connection_test.cpp tests/http3/server_test.cpp
git commit -m "feat: propagate http3 server request cancellation"
```

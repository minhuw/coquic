# HTTP/3 Server Early Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the HTTP/3 server emit a complete final response as soon as request headers are available, then terminate further request-body upload cleanly with `H3_NO_ERROR`, while preserving the existing buffered full-request handler path.

**Architecture:** Keep the response framing logic in `Http3Connection`, add one small shared-connection API for aborting further reads on a peer request stream, and extend `Http3ServerEndpoint` with an optional head-phase callback that can either return an early final response or fall back to the existing completion-buffered handler. Use RFC 9114 Section 4.1 and RFC 9000 Section 3.5 semantics: the server sends the full HTTP response, issues `STOP_SENDING` with `H3_NO_ERROR` only when the request stream is still open, and ignores any later request-body delivery for that stream.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/http3_connection.*`, existing `src/http3/http3_server.*`, local RFC corpus in `docs/rfc/`, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### File Map

**Files:**
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3_server.h`
- Modify: `src/http3/http3_server.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/server_test.cpp`
- Reference: `docs/superpowers/specs/2026-04-11-full-http3-core-design.md`
- Reference: `docs/rfc/rfc9114.txt`
- Reference: `docs/rfc/rfc9000.txt`

- [ ] **Step 1: Reconfirm the RFC rule before coding**

Run:

```bash
tools/rag/scripts/query-rag get-section --doc rfc9114 --section-id 4.1
tools/rag/scripts/query-rag get-section --doc rfc9000 --section-id 3.5
```

Expected: RFC 9114 Section 4.1 says a server that no longer needs the remainder of the request `MAY abort reading the request stream` and `H3_NO_ERROR SHOULD be used` when asking the client to stop sending. RFC 9000 Section 3.5 says aborting reads maps to `STOP_SENDING`, and later STREAM data can be discarded on receipt.

### Task 1: Add RED tests for early-response semantics

**Files:**
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames:QuicHttp3ServerTest.Early*:QuicHttp3ServerTest.HeadRequestSuppressesResponseBodyButKeepsHeaders'`

- [ ] **Step 1: Add a failing connection test for server-side request abort**

Add this test near the existing server-role request-stream tests in `tests/http3/connection_test.cpp`:

```cpp
TEST(QuicHttp3ConnectionTest,
     ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/too-large"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    const auto abort_update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto stops = stop_sending_inputs_from(abort_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));

    const auto late_update = connection.on_core_result(
        receive_result(0, data_frame_bytes("ignored"), true), coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(late_update).has_value());
    EXPECT_TRUE(late_update.events.empty());
    EXPECT_TRUE(reset_stream_inputs_from(late_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(late_update).empty());
}
```

- [ ] **Step 2: Add a failing server-endpoint test for early final response on request headers**

Add this test in `tests/http3/server_test.cpp`:

```cpp
TEST(QuicHttp3ServerTest, EarlyRequestHandlerSendsFinalResponseAndStopsRequestBody) {
    std::optional<coquic::http3::Http3RequestHead> captured_head;
    bool buffered_handler_called = false;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_head_handler =
            [&](const coquic::http3::Http3RequestHead &head)
            -> std::optional<coquic::http3::Http3Response> {
                captured_head = head;
                return coquic::http3::Http3Response{
                    .head =
                        {
                            .status = 413,
                            .content_length = 0,
                            .headers = {{"x-early", "1"}},
                        },
                };
            },
        .request_handler =
            [&](const coquic::http3::Http3Request &) {
                buffered_handler_called = true;
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
        coquic::http3::Http3Field{":path", "/too-large"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto early_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(early_update);
    const auto stops = stop_sending_inputs_from(early_update);

    ASSERT_TRUE(captured_head.has_value());
    EXPECT_EQ(captured_head->path, "/too-large");
    EXPECT_FALSE(buffered_handler_called);

    const auto expected_headers = headers_frame_bytes(
        0, response_fields(413, std::array{coquic::http3::Http3Field{"x-early", "1"}}, 0u));
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);

    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));

    const auto late_update = endpoint.on_core_result(
        receive_result(0, data_frame_bytes("ignored"), true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(late_update.terminal_failure);
    EXPECT_FALSE(buffered_handler_called);
    EXPECT_TRUE(send_stream_inputs_from(late_update).empty());
    EXPECT_TRUE(late_update.request_cancelled_events.empty());
}
```

- [ ] **Step 3: Add a failing server-endpoint test for HEAD early-response body suppression**

Add this test in `tests/http3/server_test.cpp`:

```cpp
TEST(QuicHttp3ServerTest, EarlyHeadResponseSuppressesBodyButKeepsContentLength) {
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_head_handler =
            [](const coquic::http3::Http3RequestHead &head)
            -> std::optional<coquic::http3::Http3Response> {
                EXPECT_EQ(head.method, "HEAD");
                return coquic::http3::Http3Response{
                    .head =
                        {
                            .status = 200,
                            .content_length = 4,
                            .headers = {{"content-type", "text/plain"}},
                        },
                    .body = bytes_from_text("pong"),
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "HEAD"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/head"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto stops = stop_sending_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, 4u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
    EXPECT_TRUE(stops.empty());
}
```

- [ ] **Step 4: Run the focused tests and verify RED**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames:QuicHttp3ServerTest.Early*:QuicHttp3ServerTest.HeadRequestSuppressesResponseBodyButKeepsHeaders'
```

Expected: FAIL because `Http3Connection` has no public request-body abort API, `Http3ServerConfig` has no head-phase callback, and `Http3ServerEndpoint` still waits for `Http3PeerRequestCompleteEvent` before dispatching any response.

### Task 2: Extend the public connection and server endpoint interfaces

**Files:**
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_server.h`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames:QuicHttp3ServerTest.Early*'`

- [ ] **Step 1: Add a public connection API for aborting further request-body reads**

In `src/http3/http3_connection.h`, add:

```cpp
    Http3Result<bool> abort_request_body(std::uint64_t stream_id,
                                         std::uint64_t application_error_code =
                                             static_cast<std::uint64_t>(Http3ErrorCode::no_error));
```

Place it with the other public request/response submission methods.

- [ ] **Step 2: Add an optional request-head callback to the server config**

In `src/http3/http3_server.h`, update `Http3ServerConfig`:

```cpp
struct Http3ServerConfig {
    Http3SettingsSnapshot local_settings;
    std::function<std::optional<Http3Response>(const Http3RequestHead &)> request_head_handler;
    std::function<Http3Response(const Http3Request &)> request_handler;
};
```

Also extend `PendingRequest` with a bit that marks requests that already committed an early response:

```cpp
    struct PendingRequest {
        std::optional<Http3RequestHead> head;
        std::vector<std::byte> body;
        Http3Headers trailers;
        bool early_response_committed = false;
    };
```

- [ ] **Step 3: Re-run the focused tests to move the failure into implementation**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames:QuicHttp3ServerTest.Early*'
```

Expected: FAIL because the new declarations exist, but `Http3Connection` does not yet queue `STOP_SENDING` and ignore later request bytes, and `Http3ServerEndpoint` does not yet consume `request_head_handler`.

### Task 3: Implement request-body abort in the shared connection engine

**Files:**
- Modify: `src/http3/http3_connection.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames'`

- [ ] **Step 1: Implement the new public method**

In `src/http3/http3_connection.cpp`, add:

```cpp
Http3Result<bool> Http3Connection::abort_request_body(
    std::uint64_t stream_id, std::uint64_t application_error_code) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request abort requires server role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto request_it = peer_request_streams_.find(stream_id);
    if (request_it == peer_request_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream is not available", stream_id);
    }

    if (request_it->second.blocked_field_section.has_value()) {
        const auto cancelled = cancel_http3_qpack_stream(decoder_, stream_id);
        if (!cancelled.has_value()) {
            return Http3Result<bool>::failure(cancelled.error());
        }
        flush_qpack_decoder_instructions();
        if (closed_) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "connection closed while aborting request",
                                             stream_id);
        }
    }

    peer_request_streams_.erase(request_it);
    terminated_peer_request_streams_.insert(stream_id);
    pending_core_inputs_.push_back(quic::QuicCoreStopSending{
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    });
    return Http3Result<bool>::success(true);
}
```

- [ ] **Step 2: Keep later peer request bytes discardable instead of surfacing HTTP events**

Do not add new event emission in `handle_peer_bidi_stream(...)`. Rely on the existing guard:

```cpp
    if (terminated_peer_request_streams_.contains(stream_id)) {
        return;
    }
```

The new method must populate `terminated_peer_request_streams_` so later body bytes are ignored without connection failure.

- [ ] **Step 3: Run the focused connection test and verify GREEN**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames'
```

Expected: PASS.

### Task 4: Implement head-phase server dispatch for early final responses

**Files:**
- Modify: `src/http3/http3_server.cpp`
- Modify: `src/http3/http3_server.h`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.Early*:QuicHttp3ServerTest.HeadRequestSuppressesResponseBodyButKeepsHeaders:QuicHttp3ServerTest.BuffersRequestUntilCompleteThenDispatchesCustomHandler'`

- [ ] **Step 1: Extract response submission into a helper that works for both buffered and early paths**

In `src/http3/http3_server.cpp`, introduce a helper with the existing response-send logic:

```cpp
Http3Result<bool> submit_response(Http3Connection &connection, std::uint64_t stream_id,
                                  const Http3RequestHead &request_head,
                                  const Http3Response &response) {
    for (const auto &interim : response.interim_heads) {
        const auto submitted = connection.submit_response_head(stream_id, interim);
        if (!submitted.has_value()) {
            return submitted;
        }
    }

    auto final_head = response.head;
    const bool head_request = request_head.method == "HEAD";
    if (head_request && !final_head.content_length.has_value()) {
        final_head.content_length = static_cast<std::uint64_t>(response.body.size());
    }

    const auto head_submit = connection.submit_response_head(stream_id, final_head);
    if (!head_submit.has_value()) {
        return head_submit;
    }

    if (head_request) {
        return connection.finish_response(stream_id, /*enforce_content_length=*/false);
    }
    if (!response.body.empty()) {
        const auto body_submit =
            connection.submit_response_body(stream_id, response.body, response.trailers.empty());
        if (!body_submit.has_value()) {
            return body_submit;
        }
    }
    if (!response.trailers.empty()) {
        return connection.submit_response_trailers(stream_id, response.trailers);
    }
    if (response.body.empty()) {
        return connection.finish_response(stream_id);
    }
    return Http3Result<bool>::success(true);
}
```

- [ ] **Step 2: Invoke the optional head-phase callback as soon as request headers arrive**

Inside the `Http3PeerRequestHeadEvent` branch in `Http3ServerEndpoint::on_core_result(...)`, add:

```cpp
            auto &pending = pending_requests_[head->stream_id];
            pending.head = head->head;

            if (!config_.request_head_handler) {
                continue;
            }

            const auto response = config_.request_head_handler(head->head);
            if (!response.has_value()) {
                continue;
            }

            const auto submitted =
                submit_response(connection_, head->stream_id, head->head, *response);
            if (!submitted.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }

            pending.early_response_committed = true;
            dispatched_response = true;
```

- [ ] **Step 3: Skip the buffered path for requests that already committed an early response**

In the body, trailers, reset, and complete branches in `src/http3/http3_server.cpp`, guard on the new bit:

```cpp
            if (pending_it != pending_requests_.end() && pending_it->second.early_response_committed) {
                continue;
            }
```

In the complete branch, after finding `pending_it`, short-circuit:

```cpp
        if (pending_it != pending_requests_.end() && pending_it->second.early_response_committed) {
            pending_requests_.erase(pending_it);
            continue;
        }
```

This keeps the old buffered handler untouched for all streams that do not take the early path.

- [ ] **Step 4: Abort the remaining request body only when the request stream is still open**

Before iterating the events, pre-scan the batch:

```cpp
    std::unordered_set<std::uint64_t> completed_request_streams;
    for (const auto &event : connection_update.events) {
        if (const auto *complete = std::get_if<Http3PeerRequestCompleteEvent>(&event)) {
            completed_request_streams.insert(complete->stream_id);
        }
    }
```

Then, right after an early response is submitted:

```cpp
            if (!completed_request_streams.contains(head->stream_id)) {
                const auto aborted = connection_.abort_request_body(
                    head->stream_id,
                    static_cast<std::uint64_t>(Http3ErrorCode::no_error));
                if (!aborted.has_value()) {
                    failed_ = true;
                    pending_requests_.clear();
                    return make_failure_update();
                }
            }
```

That keeps `HEAD` or already-finished requests from sending an unnecessary `STOP_SENDING`.

- [ ] **Step 5: Run the focused server tests and verify GREEN**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.Early*:QuicHttp3ServerTest.HeadRequestSuppressesResponseBodyButKeepsHeaders:QuicHttp3ServerTest.BuffersRequestUntilCompleteThenDispatchesCustomHandler'
```

Expected: PASS.

### Task 5: Full verification and commit

**Files:**
- Modify: `docs/superpowers/plans/2026-04-12-http3-server-early-response.md`
- Test: `nix develop -c zig build test`
- Test: `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
- Test: `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`

- [ ] **Step 1: Run the full test suite**

Run:

```bash
nix develop -c zig build test
```

Expected: PASS.

- [ ] **Step 2: Run formatting**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
```

Expected: PASS.

- [ ] **Step 3: Run clang-tidy**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: PASS.

- [ ] **Step 4: Commit the slice**

Run:

```bash
git add docs/superpowers/plans/2026-04-12-http3-server-early-response.md \
        src/http3/http3_connection.h src/http3/http3_connection.cpp \
        src/http3/http3_server.h src/http3/http3_server.cpp \
        tests/http3/connection_test.cpp tests/http3/server_test.cpp
git commit -m "feat: add http3 server early responses"
```

Expected: commit created on `feature/full-http3-core`.

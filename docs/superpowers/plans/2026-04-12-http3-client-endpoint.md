# HTTP/3 Client Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first protocol-level `http3_client.*` endpoint that issues HTTP/3 requests above `Http3Connection`, uploads optional bodies and trailers, aggregates complete responses, and respects peer `GOAWAY` boundaries.

**Architecture:** Extend `Http3Connection` so the shared engine handles both halves of client request streams: local request framing on client-initiated bidirectional streams and peer response parsing on those same streams. Build `Http3ClientEndpoint` as a thin wrapper that assigns client request stream IDs, queues request submission, aggregates response events into complete `Http3Response` values, and blocks new submissions once peer `GOAWAY` closes the stream-id window.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/http3_connection.*`, `src/http3/http3_protocol.*`, `src/http3/http3_qpack.*`, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### Task 1: Add failing client-path tests and register the new files

**Files:**
- Modify: `build.zig`
- Modify: `tests/http3/connection_test.cpp`
- Create: `tests/http3/client_test.cpp`
- Create: `src/http3/http3_client.h`
- Create: `src/http3/http3_client.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRole*:QuicHttp3ClientTest.*'`

- [ ] **Step 1: Add the new production and test files to the build**

In `build.zig`, add the new source file to `addProjectLibrary(...)` and the new test file to `http3_test_files`:

```zig
        "src/http3/http3_client.cpp",
```

```zig
        "tests/http3/client_test.cpp",
```

- [ ] **Step 2: Add RED connection tests for client-side request submission and response parsing**

In `tests/http3/connection_test.cpp`, add these tests near the existing server response tests:

```cpp
void prime_client_transport(coquic::http3::Http3Connection &connection) {
    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(startup).has_value());
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);
}
```

```cpp
TEST(QuicHttp3ConnectionTest, ClientRoleQueuesRequestHeadersBodyAndTrailersWithFin) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_headers{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    const std::array request_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, peer_settings);

    ASSERT_TRUE(connection.submit_request_head(
                    0, coquic::http3::Http3RequestHead{
                           .method = "POST",
                           .scheme = "https",
                           .authority = "example.test",
                           .path = "/upload",
                           .content_length = 4,
                       })
                    .has_value());
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("ping")).has_value());
    ASSERT_TRUE(connection.submit_request_trailers(0, request_trailers).has_value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 4u); // encoder instructions + HEADERS + DATA + trailers
}
```

```cpp
TEST(QuicHttp3ConnectionTest, ClientRoleEmitsInterimFinalBodyTrailersAndCompleteResponseEvents) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection.submit_request_head(
                    0, coquic::http3::Http3RequestHead{
                           .method = "GET",
                           .scheme = "https",
                           .authority = "example.test",
                           .path = "/resource",
                       })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_TRUE(connection.poll(coquic::quic::QuicCoreTimePoint{}).events.empty());

    // Feed one 103 HEADERS frame, one final 200 HEADERS frame, DATA, trailers, then FIN.
    // Expect interim, final, body, trailers, and complete events in that order.
}
```

```cpp
TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataBeforeHeaders) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection.submit_request_head(
                    0, coquic::http3::Http3RequestHead{
                           .method = "GET",
                           .scheme = "https",
                           .authority = "example.test",
                           .path = "/resource",
                       })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_TRUE(connection.poll(coquic::quic::QuicCoreTimePoint{}).core_inputs.size() >= 1u);

    const auto update = connection.on_core_result(
        receive_result(0, data_frame_bytes("oops"), false), coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(close_input_from(update).has_value());
    EXPECT_EQ(close_application_error_code(close_input_from(update)),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}
```

- [ ] **Step 3: Add RED endpoint tests for request submission, response aggregation, and GOAWAY gating**

Create `tests/http3/client_test.cpp` with helpers copied from the server tests plus these cases:

```cpp
void prime_client_transport(coquic::http3::Http3ClientEndpoint &endpoint) {
    const auto update =
        endpoint.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_EQ(send_stream_inputs_from(update).size(), 3u);
}
```

```cpp
TEST(QuicHttp3ClientTest, SubmitRequestEmitsCompletedResponseAfterFinalFin) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);
    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "POST",
                .scheme = "https",
                .authority = "example.test",
                .path = "/_coquic/echo",
                .content_length = 4,
            },
        .body = bytes_from_text("ping"),
        .trailers = {{"etag", "done"}},
    });
    ASSERT_TRUE(submitted.has_value());

    const auto request_update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(send_stream_inputs_from(request_update).empty());

    // Feed final HEADERS + DATA + trailers + FIN for stream 0 and expect one completed response event.
}
```

```cpp
TEST(QuicHttp3ClientTest, HeadRequestCollectsHeadersOnlyFinalResponse) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);
    ASSERT_TRUE(endpoint.submit_request(coquic::http3::Http3Request{
                    .head =
                        {
                            .method = "HEAD",
                            .scheme = "https",
                            .authority = "example.test",
                            .path = "/head",
                        },
                })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    // Feed a final HEADERS frame with content-length: 4 and FIN; expect a completed response event
    // whose body is empty but whose head.content_length is 4.
}
```

```cpp
TEST(QuicHttp3ClientTest, RejectsSubmissionAtOrAbovePeerGoawayBoundary) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);
    EXPECT_TRUE(endpoint.submit_request(coquic::http3::Http3Request{
                    .head =
                        {
                            .method = "GET",
                            .scheme = "https",
                            .authority = "example.test",
                            .path = "/first",
                        },
                })
                    .has_value()); // stream 0
    EXPECT_FALSE(endpoint.poll(coquic::quic::QuicCoreTimePoint{}).core_inputs.empty());

    // Feed peer GOAWAY carrying stream 4, then verify stream 4 submission fails locally.
}
```

- [ ] **Step 4: Run the focused client-path suite and verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRole*:QuicHttp3ClientTest.*'`

Expected: FAIL because the new client files and client-side connection APIs do not exist yet, and then later because the client-side behavior is not implemented yet.

### Task 2: Extend shared HTTP/3 types and `Http3Connection` for client request streams

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRole*'`

- [ ] **Step 1: Add response-side endpoint event types**

In `src/http3/http3.h`, add explicit response events and extend `Http3EndpointEvent`:

```cpp
struct Http3PeerInformationalResponseEvent {
    std::uint64_t stream_id = 0;
    Http3ResponseHead head;
};

struct Http3PeerResponseHeadEvent {
    std::uint64_t stream_id = 0;
    Http3ResponseHead head;
};

struct Http3PeerResponseBodyEvent {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> body;
};

struct Http3PeerResponseTrailersEvent {
    std::uint64_t stream_id = 0;
    Http3Headers trailers;
};

struct Http3PeerResponseCompleteEvent {
    std::uint64_t stream_id = 0;
};
```

```cpp
using Http3EndpointEvent =
    std::variant<Http3PeerRequestHeadEvent, Http3PeerRequestBodyEvent,
                 Http3PeerRequestTrailersEvent, Http3PeerRequestCompleteEvent,
                 Http3PeerInformationalResponseEvent, Http3PeerResponseHeadEvent,
                 Http3PeerResponseBodyEvent, Http3PeerResponseTrailersEvent,
                 Http3PeerResponseCompleteEvent>;
```

- [ ] **Step 2: Add client-side request submission APIs and state**

In `src/http3/http3_connection.h`, add the client-side send surface and role-specific stream state:

```cpp
Http3Result<bool> submit_request_head(std::uint64_t stream_id, const Http3RequestHead &head);
Http3Result<bool> submit_request_body(std::uint64_t stream_id, std::span<const std::byte> body,
                                      bool fin = false);
Http3Result<bool> submit_request_trailers(std::uint64_t stream_id,
                                          std::span<const Http3Field> trailers,
                                          bool fin = true);
Http3Result<bool> finish_request(std::uint64_t stream_id);
```

```cpp
enum class ResponseFieldSectionKind : std::uint8_t {
    informational_or_final_headers,
    trailers,
};

struct LocalRequestStreamState {
    std::vector<std::byte> buffer;
    bool final_request_headers_sent = false;
    bool request_trailers_sent = false;
    bool request_finished = false;
    bool final_response_received = false;
    bool response_trailers_received = false;
    bool response_fin_received = false;
    std::optional<ResponseFieldSectionKind> blocked_field_section;
    std::optional<std::uint64_t> expected_request_content_length;
    std::optional<std::uint64_t> expected_response_content_length;
    std::uint64_t request_body_bytes_sent = 0;
    std::uint64_t response_body_bytes_received = 0;
};
```

Also add the new connection member:

```cpp
std::unordered_map<std::uint64_t, LocalRequestStreamState> local_request_streams_;
```

- [ ] **Step 3: Implement client-side request serialization and response parsing in `Http3Connection`**

In `src/http3/http3_connection.cpp`, mirror the existing server response helpers for client requests:

```cpp
Http3Result<bool> Http3Connection::submit_request_head(std::uint64_t stream_id,
                                                       const Http3RequestHead &head) {
    if (config_.role != Http3ConnectionRole::client) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request sending requires client role", stream_id);
    }
    // Validate that stream_id is a local-initiated bidirectional stream for this endpoint role.
    // Encode the field section, queue encoder instructions if present, queue the HEADERS frame,
    // and initialize local_request_streams_[stream_id].
}
```

```cpp
void Http3Connection::handle_receive_stream_data(const quic::QuicCoreReceiveStreamData &received) {
    const auto info = classify_stream_id(received.stream_id, endpoint_role(config_.role));
    if (info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::unidirectional) {
        handle_peer_uni_stream_data(received.stream_id, received.bytes, received.fin);
        return;
    }
    if (config_.role == Http3ConnectionRole::server && info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::bidirectional) {
        handle_peer_bidi_stream(received.stream_id, received.bytes, received.fin);
        return;
    }
    if (config_.role == Http3ConnectionRole::client && info.initiator == StreamInitiator::local &&
        info.direction == StreamDirection::bidirectional) {
        handle_peer_bidi_stream(received.stream_id, received.bytes, received.fin);
    }
}
```

Add client-role branches to the bidirectional-stream processing path:

```cpp
void Http3Connection::handle_peer_bidi_stream(std::uint64_t stream_id,
                                              std::span<const std::byte> bytes, bool fin) {
    if (config_.role == Http3ConnectionRole::server) {
        auto &stream = peer_request_streams_[stream_id];
        stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());
        stream.fin_received = stream.fin_received || fin;
        process_request_stream(stream_id);
        return;
    }

    auto &stream = local_request_streams_[stream_id];
    stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());
    stream.response_fin_received = stream.response_fin_received || fin;
    process_response_stream(stream_id);
}
```

Implement `process_response_stream(...)`, `handle_response_frame(...)`,
`handle_response_headers_frame(...)`, `handle_response_data_frame(...)`,
`apply_response_field_section(...)`, and `finalize_response_stream(...)` so they:

- accept zero or more informational response `HEADERS` sections before the final response
- validate the final response with `validate_http3_response_headers(...)`
- validate trailers with `validate_http3_trailers(...)`
- emit `Http3PeerInformationalResponseEvent`, `Http3PeerResponseHeadEvent`,
  `Http3PeerResponseBodyEvent`, `Http3PeerResponseTrailersEvent`, and
  `Http3PeerResponseCompleteEvent`
- enforce content-length accounting for the response body
- close the connection with `H3_FRAME_UNEXPECTED` on `DATA` before final response headers

- [ ] **Step 4: Re-run the client-role connection tests and keep them green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ClientRole*'`

Expected: PASS.

### Task 3: Add the `Http3ClientEndpoint` wrapper above `Http3Connection`

**Files:**
- Create: `src/http3/http3_client.h`
- Create: `src/http3/http3_client.cpp`
- Modify: `tests/http3/client_test.cpp`
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ClientTest.*'`

- [ ] **Step 1: Define the client endpoint surface**

Create `src/http3/http3_client.h`:

```cpp
#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>
#include <vector>

#include "src/http3/http3_connection.h"

namespace coquic::http3 {

struct Http3ClientConfig {
    Http3SettingsSnapshot local_settings;
};

struct Http3ClientResponseEvent {
    std::uint64_t stream_id = 0;
    Http3Request request;
    Http3Response response;
};

struct Http3ClientEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3ClientResponseEvent> events;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class Http3ClientEndpoint {
  public:
    explicit Http3ClientEndpoint(Http3ClientConfig config = {});

    Http3Result<std::uint64_t> submit_request(Http3Request request);
    Http3ClientEndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                             quic::QuicCoreTimePoint now);
    Http3ClientEndpointUpdate poll(quic::QuicCoreTimePoint now);

    bool has_failed() const;

  private:
    struct PendingRequest {
        std::uint64_t stream_id = 0;
        Http3Request request;
    };

    struct PendingResponse {
        std::vector<Http3ResponseHead> interim_heads;
        std::optional<Http3ResponseHead> head;
        std::vector<std::byte> body;
        Http3Headers trailers;
    };

    Http3ClientConfig config_;
    Http3Connection connection_;
    bool failed_ = false;
    std::uint64_t next_request_stream_id_ = 0;
    std::deque<PendingRequest> pending_requests_;
    std::unordered_map<std::uint64_t, Http3Request> active_requests_;
    std::unordered_map<std::uint64_t, PendingResponse> pending_responses_;
};

} // namespace coquic::http3
```

- [ ] **Step 2: Implement request submission, GOAWAY gating, and response aggregation**

In `src/http3/http3_client.cpp`, implement the wrapper logic:

```cpp
Http3Result<std::uint64_t> Http3ClientEndpoint::submit_request(Http3Request request) {
    if (failed_) {
        return Http3Result<std::uint64_t>::failure(Http3Error{
            .code = Http3ErrorCode::general_protocol_error,
            .detail = "client endpoint has failed",
        });
    }

    const auto stream_id = next_request_stream_id_;
    if (connection_.state().goaway_id.has_value() && stream_id >= *connection_.state().goaway_id) {
        return Http3Result<std::uint64_t>::failure(Http3Error{
            .code = Http3ErrorCode::request_rejected,
            .detail = "peer goaway prevents issuing a new request",
            .stream_id = stream_id,
        });
    }

    next_request_stream_id_ += 4u;
    pending_requests_.push_back(PendingRequest{
        .stream_id = stream_id,
        .request = std::move(request),
    });
    return Http3Result<std::uint64_t>::success(stream_id);
}
```

```cpp
// During poll()/on_core_result(), when the local control stream exists, drain pending_requests_:
// 1. submit_request_head(stream_id, request.head)
// 2. submit_request_body(...) if body is non-empty
// 3. submit_request_trailers(...) if trailers are non-empty
// 4. otherwise finish_request(stream_id)
// Move the request into active_requests_ only after all submit_* calls succeed.
```

```cpp
// Aggregate response events until complete:
if (const auto *interim = std::get_if<Http3PeerInformationalResponseEvent>(&event)) {
    pending_responses_[interim->stream_id].interim_heads.push_back(interim->head);
} else if (const auto *head = std::get_if<Http3PeerResponseHeadEvent>(&event)) {
    pending_responses_[head->stream_id].head = head->head;
} else if (const auto *body = std::get_if<Http3PeerResponseBodyEvent>(&event)) {
    auto &pending = pending_responses_[body->stream_id];
    pending.body.insert(pending.body.end(), body->body.begin(), body->body.end());
} else if (const auto *trailers = std::get_if<Http3PeerResponseTrailersEvent>(&event)) {
    pending_responses_[trailers->stream_id].trailers = trailers->trailers;
} else if (const auto *complete = std::get_if<Http3PeerResponseCompleteEvent>(&event)) {
    // Emit Http3ClientResponseEvent and erase active/pending state.
}
```

- [ ] **Step 3: Handle endpoint failure and core update merging consistently**

Match the server-wrapper pattern:

- if `result.local_error` is set, mark the endpoint failed and return
  `handled_local_error=true`
- merge the wrapped `Http3Connection` `core_inputs` into the client update
- if the wrapped connection reports `terminal_failure`, fail the endpoint
- set `has_pending_work` while queued requests remain unsent

Use the same small helper style as `src/http3/http3_server.cpp` so the two role wrappers stay structurally aligned.

- [ ] **Step 4: Re-run the focused client-endpoint suite and keep it green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ClientTest.*'`

Expected: PASS.

### Task 4: Run wider HTTP/3 verification, format/lint, and commit the slice

**Files:**
- Modify: `build.zig`
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Create: `src/http3/http3_client.h`
- Create: `src/http3/http3_client.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Create: `tests/http3/client_test.cpp`
- Create: `docs/superpowers/plans/2026-04-12-http3-client-endpoint.md`

- [ ] **Step 1: Run the wider HTTP/3 suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.*:QuicHttp3Qpack*:QuicHttp3ConnectionTest*:QuicHttp3ServerTest*:QuicHttp3ClientTest.*'`

Expected: PASS.

- [ ] **Step 2: Format the touched files**

Run:

```bash
nix develop -c pre-commit run clang-format --files \
  build.zig \
  src/http3/http3.h \
  src/http3/http3_connection.h \
  src/http3/http3_connection.cpp \
  src/http3/http3_client.h \
  src/http3/http3_client.cpp \
  tests/http3/connection_test.cpp \
  tests/http3/client_test.cpp
```

Expected: PASS.

- [ ] **Step 3: Run clang-tidy on the touched HTTP/3 files**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --files \
  src/http3/http3.h \
  src/http3/http3_connection.h \
  src/http3/http3_connection.cpp \
  src/http3/http3_client.h \
  src/http3/http3_client.cpp \
  tests/http3/connection_test.cpp \
  tests/http3/client_test.cpp
```

Expected: PASS.

- [ ] **Step 4: Commit the slice**

```bash
git add build.zig docs/superpowers/plans/2026-04-12-http3-client-endpoint.md \
  src/http3/http3.h src/http3/http3_connection.h src/http3/http3_connection.cpp \
  src/http3/http3_client.h src/http3/http3_client.cpp \
  tests/http3/connection_test.cpp tests/http3/client_test.cpp
git commit -m "feat: add http3 client endpoint"
```

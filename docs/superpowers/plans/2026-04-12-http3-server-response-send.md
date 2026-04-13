# HTTP/3 Server Response Send Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add standards-conformant outbound server response sending on existing HTTP/3 request streams inside `src/http3/http3_connection.*`, including interim responses, final response headers, body data, trailers, FIN handling, and outbound `content-length` enforcement.

**Architecture:** Keep the shared connection engine as the first implementation point. Extend shared HTTP/3 types and protocol validation for response-side `content-length`, then add a server-only response send API plus per-request local response state in `Http3Connection`. Use the existing `poll()`-driven `QuicCoreInput` queue, and emit QPACK encoder-stream instructions before request-stream HEADERS when dynamic-table references are used.

**Tech Stack:** C++20, GoogleTest, existing HTTP/3 frame/protocol helpers, existing QPACK encoder/decoder contexts, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### Task 1: Add failing protocol tests for response `content-length`

**Files:**
- Modify: `tests/http3/protocol_test.cpp`
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_protocol.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.ResponseContentLength*'`

- [ ] **Step 1: Add a passing-shape response parse test that should fail until `Http3ResponseHead` grows `content_length`**

```cpp
TEST(QuicHttp3ProtocolTest, ResponseContentLengthParsesIntoResponseHead) {
    const std::array fields{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"server", "coquic"},
    };

    const auto response = coquic::http3::validate_http3_response_headers(fields);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response.value().status, 200);
    EXPECT_EQ(response.value().content_length, std::optional<std::uint64_t>(4u));
}
```

- [ ] **Step 2: Add a malformed duplicate/mismatched response `content-length` test**

```cpp
TEST(QuicHttp3ProtocolTest, ResponseContentLengthRejectsMismatchedDuplicateValues) {
    const std::array fields{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"content-length", "5"},
    };

    const auto response = coquic::http3::validate_http3_response_headers(fields);
    ASSERT_FALSE(response.has_value());
    EXPECT_EQ(response.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(response.error().detail, "invalid content-length header");
}
```

- [ ] **Step 3: Run the focused protocol tests to verify they fail**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.ResponseContentLength*'`
Expected: FAIL because `Http3ResponseHead` has no `content_length` member and/or response validation does not parse the header yet.

### Task 2: Add failing connection tests for outbound server response sequencing

**Files:**
- Modify: `tests/http3/connection_test.cpp`
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerQueues*:QuicHttp3ConnectionTest.Sending*Response*:QuicHttp3ConnectionTest.DynamicTableResponse*'`

- [ ] **Step 1: Add a headers-only final response send test**

```cpp
TEST(QuicHttp3ConnectionTest, ServerQueuesHeadersOnlyFinalResponseWithFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto result = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{.status = 204, .headers = {{"server", "coquic"}}});
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(send_stream_inputs_from(update).size(), 1u);
    EXPECT_TRUE(send_stream_inputs_from(update)[0].fin);
}
```

- [ ] **Step 2: Add body/trailer ordering and invalid-local-state tests**

```cpp
TEST(QuicHttp3ConnectionTest, ServerQueuesFinalHeadersThenBodyWithFin) {}

TEST(QuicHttp3ConnectionTest, ServerQueuesTrailersWithFinAfterResponseBody) {}

TEST(QuicHttp3ConnectionTest, ServerAllowsInterimResponseBeforeFinalResponse) {}

TEST(QuicHttp3ConnectionTest, SendingResponseBodyBeforeFinalHeadersFailsLocally) {}

TEST(QuicHttp3ConnectionTest, SendingResponseTrailersBeforeFinalHeadersFailsLocally) {}

TEST(QuicHttp3ConnectionTest, SendingSecondFinalResponseFailsLocally) {}

TEST(QuicHttp3ConnectionTest, SendingResponseBodyPastDeclaredContentLengthFailsLocally) {}

TEST(QuicHttp3ConnectionTest, DynamicTableResponseHeadersQueueEncoderInstructionsBeforeHeaders) {}
```

- [ ] **Step 3: Run the focused connection tests to verify they fail**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerQueues*:QuicHttp3ConnectionTest.Sending*Response*:QuicHttp3ConnectionTest.DynamicTableResponse*'`
Expected: FAIL because `Http3Connection` does not expose a response send API or local response stream state yet.

### Task 3: Implement shared types and protocol validation

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_protocol.cpp`
- Modify: `tests/http3/protocol_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.ResponseContentLength*'`

- [ ] **Step 1: Extend `Http3ResponseHead` with send-side `content_length`**

```cpp
struct Http3ResponseHead {
    std::uint16_t status = 200;
    std::optional<std::uint64_t> content_length;
    Http3Headers headers;
};
```

- [ ] **Step 2: Parse and validate response `content-length` using the existing helper used for requests**

```cpp
if (field.name == "content-length") {
    const auto content_length = parse_content_length_value(field.value);
    if (!content_length.has_value()) {
        return http3_failure<Http3ResponseHead>(content_length.error().code,
                                                content_length.error().detail);
    }
    if (head.content_length.has_value() && *head.content_length != content_length.value()) {
        return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
    }
    head.content_length = content_length.value();
    continue;
}
```

- [ ] **Step 3: Re-run the focused protocol tests and keep them green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.ResponseContentLength*'`
Expected: PASS.

### Task 4: Implement outbound server response sending in `Http3Connection`

**Files:**
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3.h`
- Modify: `tests/http3/connection_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerQueues*:QuicHttp3ConnectionTest.Sending*Response*:QuicHttp3ConnectionTest.DynamicTableResponse*'`

- [ ] **Step 1: Add a server-only public send surface and local response stream state**

```cpp
Http3Result<bool> submit_response_head(std::uint64_t stream_id, const Http3ResponseHead &head);
Http3Result<bool> submit_response_body(std::uint64_t stream_id, std::span<const std::byte> body,
                                       bool fin = false);
Http3Result<bool> submit_response_trailers(std::uint64_t stream_id,
                                           std::span<const Http3Field> trailers,
                                           bool fin = true);
Http3Result<bool> finish_response(std::uint64_t stream_id);
```

```cpp
struct LocalResponseStreamState {
    bool final_response_sent = false;
    bool trailers_sent = false;
    bool finished = false;
    std::optional<std::uint64_t> expected_content_length;
    std::uint64_t body_bytes_sent = 0;
};
```

- [ ] **Step 2: Encode HEADERS with QPACK and queue encoder-stream instructions before request-stream bytes**

```cpp
const auto encoded = encode_http3_field_section(encoder_, stream_id, fields);
if (!encoded.has_value()) {
    return Http3Result<bool>::failure(encoded.error());
}
if (!encoded.value().encoder_instructions.empty()) {
    queue_send(*state_.local_qpack_encoder_stream_id, encoded.value().encoder_instructions);
}
queue_send(stream_id, serialized_headers, fin);
```

- [ ] **Step 3: Enforce local ordering and `content-length` accounting**

```cpp
if (!response.final_response_sent) {
    return Http3Result<bool>::failure(Http3Error{
        .code = Http3ErrorCode::frame_unexpected,
        .detail = "response body before final response headers",
        .stream_id = stream_id,
    });
}
if (response.expected_content_length.has_value() &&
    response.body_bytes_sent + body.size() > *response.expected_content_length) {
    return Http3Result<bool>::failure(Http3Error{
        .code = Http3ErrorCode::message_error,
        .detail = "response body exceeds content-length",
        .stream_id = stream_id,
    });
}
```

- [ ] **Step 4: Add FIN-capable send queuing and stream completion handling**

```cpp
void queue_send(std::uint64_t stream_id, std::span<const std::byte> bytes, bool fin = false);
```

- [ ] **Step 5: Re-run the focused connection tests and keep them green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ConnectionTest.ServerQueues*:QuicHttp3ConnectionTest.Sending*Response*:QuicHttp3ConnectionTest.DynamicTableResponse*'`
Expected: PASS.

### Task 5: Run slice verification and commit

**Files:**
- Modify: `src/http3/http3.h`
- Modify: `src/http3/http3_connection.h`
- Modify: `src/http3/http3_connection.cpp`
- Modify: `src/http3/http3_protocol.cpp`
- Modify: `tests/http3/connection_test.cpp`
- Modify: `tests/http3/protocol_test.cpp`
- Create: `docs/superpowers/plans/2026-04-12-http3-server-response-send.md`

- [ ] **Step 1: Run focused HTTP/3 verification**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.*:QuicHttp3Qpack*:QuicHttp3ConnectionTest*'`
Expected: PASS for the HTTP/3 protocol, QPACK, and connection suites.

- [ ] **Step 2: Format and lint touched files**

Run: `nix develop -c pre-commit run clang-format --files src/http3/http3.h src/http3/http3_connection.h src/http3/http3_connection.cpp src/http3/http3_protocol.cpp tests/http3/connection_test.cpp tests/http3/protocol_test.cpp docs/superpowers/plans/2026-04-12-http3-server-response-send.md`
Expected: PASS.

Run: `nix develop -c pre-commit run coquic-clang-tidy --files src/http3/http3.h src/http3/http3_connection.h src/http3/http3_connection.cpp src/http3/http3_protocol.cpp tests/http3/connection_test.cpp tests/http3/protocol_test.cpp`
Expected: PASS.

- [ ] **Step 3: Commit the slice**

```bash
git add docs/superpowers/plans/2026-04-12-http3-server-response-send.md \
  src/http3/http3.h src/http3/http3_connection.h src/http3/http3_connection.cpp \
  src/http3/http3_protocol.cpp tests/http3/connection_test.cpp tests/http3/protocol_test.cpp
git commit -m "feat: send outbound http3 server responses"
```

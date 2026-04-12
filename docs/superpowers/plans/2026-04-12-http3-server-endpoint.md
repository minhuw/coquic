# HTTP/3 Server Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first protocol-level `http3_server.*` endpoint that buffers complete HTTP/3 requests above `Http3Connection`, dispatches them through a small handler surface, and emits final HTTP/3 responses for deterministic reserved routes and custom handlers.

**Architecture:** Keep request parsing and frame/QPACK sequencing inside `Http3Connection`, and build `Http3ServerEndpoint` as a thin wrapper that aggregates request events into complete messages. The endpoint exposes `on_core_result()` and `poll()` like the existing HTTP/0.9 server, invokes either a caller-supplied handler or built-in reserved-route logic, then uses the already-tested `submit_response_*` connection API to send headers, body, trailers, and FIN in the correct order.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/http3_connection.*`, existing QPACK helpers, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### Task 1: Add failing HTTP/3 server endpoint tests and register the new test binary input

**Files:**
- Modify: `build.zig`
- Create: `tests/http3/server_test.cpp`
- Create: `src/http3/http3_server.h`
- Create: `src/http3/http3_server.cpp`
- Modify: `src/http3/http3.h`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*'`

- [ ] **Step 1: Add the new test file to the HTTP/3 test list**

```zig
const http3_test_files = &.{
    "tests/http3/connection_test.cpp",
    "tests/http3/protocol_test.cpp",
    "tests/http3/qpack_test.cpp",
    "tests/http3/qpack_dynamic_test.cpp",
    "tests/http3/server_test.cpp",
};
```

- [ ] **Step 2: Write a failing custom-handler aggregation test**

```cpp
TEST(QuicHttp3ServerTest, BuffersRequestUntilCompleteThenDispatchesCustomHandler) {
    std::optional<coquic::http3::Http3Request> captured_request;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_handler =
            [&](const coquic::http3::Http3Request &request) {
                captured_request = request;
                return coquic::http3::Http3Response{
                    .head = {.status = 200},
                };
            },
    });

    // Feed request HEADERS first, then DATA+FIN. Verify the handler runs only after completion.
}
```

- [ ] **Step 3: Write failing reserved-route tests**

```cpp
TEST(QuicHttp3ServerTest, DefaultEchoRouteReturnsRequestBody) {}

TEST(QuicHttp3ServerTest, DefaultInspectRouteReturnsDeterministicJson) {}

TEST(QuicHttp3ServerTest, UnknownRouteReturns404) {}

TEST(QuicHttp3ServerTest, HeadRequestSuppressesResponseBodyButKeepsHeaders) {}
```

- [ ] **Step 4: Run the focused test to verify it fails**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*'`
Expected: FAIL with missing `http3_server.*` files, missing shared request/response message types, and missing endpoint API.

### Task 2: Add shared request/response message models and the server endpoint surface

**Files:**
- Modify: `src/http3/http3.h`
- Create: `src/http3/http3_server.h`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*'`

- [ ] **Step 1: Extend shared HTTP/3 types with complete request/response message models**

```cpp
struct Http3Request {
    Http3RequestHead head;
    std::vector<std::byte> body;
    Http3Headers trailers;
};

struct Http3Response {
    std::vector<Http3ResponseHead> interim_heads;
    Http3ResponseHead head;
    std::vector<std::byte> body;
    Http3Headers trailers;
};
```

- [ ] **Step 2: Define the server endpoint config and update surface**

```cpp
using Http3ServerHandler = std::function<Http3Response(const Http3Request &)>;

struct Http3ServerConfig {
    Http3SettingsSnapshot local_settings;
    Http3ServerHandler request_handler;
};

struct Http3ServerEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};
```

- [ ] **Step 3: Define the endpoint class and minimal internal state**

```cpp
class Http3ServerEndpoint {
  public:
    explicit Http3ServerEndpoint(Http3ServerConfig config = {});

    Http3ServerEndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                             quic::QuicCoreTimePoint now);
    Http3ServerEndpointUpdate poll(quic::QuicCoreTimePoint now);
    bool has_failed() const;

  private:
    struct PendingRequest {
        std::optional<Http3RequestHead> head;
        std::vector<std::byte> body;
        Http3Headers trailers;
    };

    Http3ServerConfig config_;
    Http3Connection connection_;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, PendingRequest> pending_requests_;
};
```

- [ ] **Step 4: Re-run the focused test to move the failure into implementation**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*'`
Expected: FAIL because the endpoint methods are declared but do not yet buffer requests or send responses.

### Task 3: Implement request aggregation and handler dispatch

**Files:**
- Create: `src/http3/http3_server.cpp`
- Modify: `src/http3/http3_server.h`
- Modify: `src/http3/http3.h`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*'`

- [ ] **Step 1: Aggregate `Http3Connection` events into complete requests**

```cpp
if (const auto *head = std::get_if<Http3PeerRequestHeadEvent>(&event)) {
    auto &pending = pending_requests_[head->stream_id];
    pending.head = head->head;
} else if (const auto *body = std::get_if<Http3PeerRequestBodyEvent>(&event)) {
    pending_requests_[body->stream_id].body.insert(
        pending_requests_[body->stream_id].body.end(), body->body.begin(), body->body.end());
} else if (const auto *trailers = std::get_if<Http3PeerRequestTrailersEvent>(&event)) {
    pending_requests_[trailers->stream_id].trailers = trailers->trailers;
} else if (const auto *complete = std::get_if<Http3PeerRequestCompleteEvent>(&event)) {
    // Build Http3Request and dispatch it.
}
```

- [ ] **Step 2: Implement the built-in reserved-route handler**

```cpp
if (request.head.method == "POST" && request.head.path == "/_coquic/echo") {
    return Http3Response{
        .head = {
            .status = 200,
            .content_length = static_cast<std::uint64_t>(request.body.size()),
            .headers = {{"content-type", "application/octet-stream"}},
        },
        .body = request.body,
    };
}
```

```cpp
if (request.head.method == "POST" && request.head.path == "/_coquic/inspect") {
    return Http3Response{
        .head = {
            .status = 200,
            .content_length = static_cast<std::uint64_t>(json.size()),
            .headers = {{"content-type", "application/json"}},
        },
        .body = std::move(json_bytes),
    };
}
```

- [ ] **Step 3: Submit the handler response through `Http3Connection` in the correct order**

```cpp
for (const auto &interim : response.interim_heads) {
    const auto submitted = connection_.submit_response_head(stream_id, interim);
    if (!submitted.has_value()) {
        failed_ = true;
        return make_failure_update();
    }
}

auto final_head = response.head;
if (request.head.method == "HEAD") {
    final_head.content_length = final_head.content_length.value_or(response.body.size());
}
```

```cpp
const auto head_result = connection_.submit_response_head(stream_id, final_head);
// For HEAD: finish immediately.
// Otherwise send body, then trailers or finish_response().
```

- [ ] **Step 4: Re-run the focused test and keep it green**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*'`
Expected: PASS.

### Task 4: Integrate the new source file and run wider HTTP/3 verification

**Files:**
- Modify: `build.zig`
- Create: `src/http3/http3_server.cpp`
- Create: `src/http3/http3_server.h`
- Create: `tests/http3/server_test.cpp`
- Modify: `src/http3/http3.h`

- [ ] **Step 1: Add the new production source to the main library build**

```zig
"src/http3/http3_server.cpp",
```

- [ ] **Step 2: Run the wider HTTP/3 suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ProtocolTest.*:QuicHttp3Qpack*:QuicHttp3ConnectionTest*:QuicHttp3ServerTest*'`
Expected: PASS.

- [ ] **Step 3: Format and lint the touched files**

Run: `nix develop -c pre-commit run clang-format --files build.zig src/http3/http3.h src/http3/http3_server.h src/http3/http3_server.cpp tests/http3/server_test.cpp`
Expected: PASS.

Run: `nix develop -c pre-commit run coquic-clang-tidy --files src/http3/http3.h src/http3/http3_server.h src/http3/http3_server.cpp tests/http3/server_test.cpp`
Expected: PASS.

- [ ] **Step 4: Commit the slice**

```bash
git add build.zig docs/superpowers/plans/2026-04-12-http3-server-endpoint.md \
  src/http3/http3.h src/http3/http3_server.h src/http3/http3_server.cpp \
  tests/http3/server_test.cpp
git commit -m "feat: add http3 server endpoint"
```

# HTTP/3 Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-class `coquic h3-server` and `coquic h3-client` runtime modes that drive the existing HTTP/3 endpoints over real QUIC sockets.

**Architecture:** Keep protocol semantics in the existing `Http3Connection`, `Http3ClientEndpoint`, and `Http3ServerEndpoint` types. Add a thin `http3_runtime.*` layer that parses CLI arguments, builds QUIC endpoint configs with ALPN `h3`, runs endpoint-scoped QUIC event loops on top of `QuicCore::advance_endpoint(...)`, and supplies a runtime-owned static-file handler plus the existing reserved POST routes.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/*`, existing `src/io/*` backends, `zig build test`, loopback runtime tests with fixture certs.

---

### Task 1: Add RED runtime tests and register the new files

**Files:**
- Modify: `build.zig`
- Create: `src/http3/http3_runtime.h`
- Create: `src/http3/http3_runtime.cpp`
- Create: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.*'`

- [ ] **Step 1: Register the runtime source and tests**

Add these entries:

```zig
        "src/http3/http3_runtime.cpp",
```

```zig
        "tests/http3/runtime_test.cpp",
```

- [ ] **Step 2: Add RED parser and config-builder tests**

Write tests that cover:

```cpp
TEST(QuicHttp3RuntimeTest, ParsesServerInvocation) {}

TEST(QuicHttp3RuntimeTest, ParsesClientInvocation) {}

TEST(QuicHttp3RuntimeTest, CoreEndpointConfigsUseH3Alpn) {}
```

The assertions should verify:
- `h3-server` parses `--host`, `--port`, `--document-root`, `--certificate-chain`, `--private-key`
- `h3-client` parses URL, `--method`, repeated `--header`, `--data`, `--output`, `--server-name`
- both endpoint config builders force ALPN `h3`
- the server config builder loads the configured certificate and key files

- [ ] **Step 3: Add one RED loopback runtime test**

Write one real runtime test that:
- starts `run_http3_runtime(server)` in a child process
- serves a temporary `hello.txt` from the configured document root
- runs `run_http3_runtime(client)` against `https://localhost:<port>/hello.txt`
- asserts the response body is written to the output file

- [ ] **Step 4: Run the focused suite and verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.*'`

Expected: FAIL because the runtime files and APIs do not exist yet.

### Task 2: Define runtime config, parsing, and QUIC config builders

**Files:**
- Create: `src/http3/http3_runtime.h`
- Create: `src/http3/http3_runtime.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.Parses*:QuicHttp3RuntimeTest.CoreEndpointConfigsUseH3Alpn'`

- [ ] **Step 1: Define the runtime config surface**

Add focused types:

```cpp
enum class Http3RuntimeMode : std::uint8_t { server, client };

struct Http3RuntimeHeader {
    std::string name;
    std::string value;
};

struct Http3RuntimeConfig {
    Http3RuntimeMode mode = Http3RuntimeMode::server;
    io::QuicIoBackendKind io_backend = io::QuicIoBackendKind::socket;
    std::string host = "127.0.0.1";
    std::uint16_t port = 4433;
    std::filesystem::path document_root = ".";
    std::filesystem::path certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    std::filesystem::path private_key_path = "tests/fixtures/quic-server-key.pem";
    std::string url;
    std::string method;
    std::vector<Http3RuntimeHeader> headers;
    std::optional<std::string> body_text;
    std::optional<std::filesystem::path> body_file_path;
    std::optional<std::filesystem::path> output_path;
    std::string server_name;
    bool verify_peer = false;
};
```

- [ ] **Step 2: Implement argument parsing for `h3-server` and `h3-client`**

Support:
- `h3-server --host --port --io-backend --document-root --certificate-chain --private-key`
- `h3-client URL [--method GET|HEAD|POST] [--header NAME:VALUE] [--data TEXT] [--body-file PATH] [--output PATH] [--server-name NAME] [--verify-peer] [--io-backend socket|io_uring]`

Reject:
- missing subcommand
- unknown flags
- invalid port
- both `--data` and `--body-file`
- client requests without a URL

- [ ] **Step 3: Implement QUIC endpoint config builders**

Expose helpers:

```cpp
quic::QuicCoreEndpointConfig make_http3_client_endpoint_config(const Http3RuntimeConfig &config);
std::optional<quic::QuicCoreEndpointConfig>
make_http3_server_endpoint_config(const Http3RuntimeConfig &config);
```

The builders should:
- set `role`
- force `application_protocol = "h3"`
- propagate `verify_peer`
- load server TLS identity from the configured PEM files

- [ ] **Step 4: Re-run the focused parser/config suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.Parses*:QuicHttp3RuntimeTest.CoreEndpointConfigsUseH3Alpn'`

Expected: PASS.

### Task 3: Implement the endpoint-driven HTTP/3 server runtime

**Files:**
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.ServesStaticFileOverLoopback'`

- [ ] **Step 1: Add a runtime-owned static file handler**

Implement a small handler that:
- resolves request paths under `document_root`
- serves regular files for `GET` and `HEAD`
- uses `index.html` for `/`
- returns `404` when the file is absent
- keeps reserved `POST /_coquic/echo` and `POST /_coquic/inspect` on the endpoint’s built-in path

- [ ] **Step 2: Add a server event loop on top of `QuicCore::advance_endpoint(...)`**

Follow the perf runtime pattern:
- bootstrap the UDP backend
- create `QuicCore` with endpoint config
- track `QuicConnectionHandle -> Http3ServerEndpoint`
- filter per-connection core results into each endpoint
- turn endpoint `core_inputs` into `QuicCoreConnectionCommand`
- keep the server alive across bad peer traffic; drop only the failed connection endpoint

- [ ] **Step 3: Keep draining endpoint work until quiescent**

When an endpoint returns `has_pending_work`, call `poll(now)` and feed its commands back into the core until:
- no more pending work remains, or
- the connection closes/fails

- [ ] **Step 4: Re-run the loopback static-file test**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.ServesStaticFileOverLoopback'`

Expected: PASS.

### Task 4: Implement the endpoint-driven HTTP/3 client runtime and CLI dispatch

**Files:**
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `src/main.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.*'`

- [ ] **Step 1: Build the client request from the parsed config**

Create a helper that:
- parses the absolute `https://` URL
- derives `authority`, request `path`, remote host, remote port, and default `server_name`
- assembles `Http3Request` with headers and optional body
- sets `content_length` when a request body is present

- [ ] **Step 2: Add a client event loop on top of `QuicCore::advance_endpoint(...)`**

The client loop should:
- bootstrap the client backend
- open one endpoint connection
- submit one HTTP/3 request through `Http3ClientEndpoint`
- feed connection commands and poll-driven work back into `QuicCore`
- write the final response body to stdout or `--output`
- return non-zero on transport/runtime failure or request reset

- [ ] **Step 3: Dispatch the new runtime from `src/main.cpp`**

Update `main` to:
- run `parse_http3_runtime_args(...)` + `run_http3_runtime(...)` for `h3-server` and `h3-client`
- continue routing all other invocations through the existing HTTP/0.9 runtime

- [ ] **Step 4: Re-run the focused runtime suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.*'`

Expected: PASS.

### Task 5: Run wider HTTP/3 verification

**Files:**
- Modify: `build.zig`
- Modify: `src/main.cpp`
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `tests/http3/runtime_test.cpp`

- [ ] **Step 1: Run the full HTTP/3 suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3*'`

Expected: PASS.

- [ ] **Step 2: Run formatting on touched files**

Run: `nix develop -c pre-commit run clang-format --files build.zig src/main.cpp src/http3/http3_runtime.h src/http3/http3_runtime.cpp tests/http3/runtime_test.cpp`

Expected: PASS.

- [ ] **Step 3: Run clang-tidy on touched files**

Run: `nix develop -c pre-commit run coquic-clang-tidy --files src/main.cpp src/http3/http3_runtime.h src/http3/http3_runtime.cpp tests/http3/runtime_test.cpp`

Expected: PASS.

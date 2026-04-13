# HTTP/3 Browser Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal HTTPS bootstrap origin to `coquic h3-server` so browsers can discover the existing UDP HTTP/3 endpoint through `Alt-Svc`.

**Architecture:** Introduce a dedicated runtime-only `http3_bootstrap.*` module for TCP/TLS + HTTP/1.1 bootstrap behavior, keep QUIC/H3 logic in the existing runtime, and extend `Http3RuntimeConfig` so one `h3-server` invocation can launch both listeners with shared certificate and content settings. Verify the slice with focused HTTPS loopback tests and keep the broader HTTP/3 suite green.

**Tech Stack:** C++20, GoogleTest, existing HTTP/3 runtime, OpenSSL-compatible TLS APIs from the repo’s linked TLS backend, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

### Task 1: Add RED bootstrap tests and register the new files

**Files:**
- Modify: `build.zig`
- Create: `src/http3/http3_bootstrap.h`
- Create: `src/http3/http3_bootstrap.cpp`
- Create: `tests/http3/bootstrap_test.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3BootstrapTest.*:QuicHttp3RuntimeTest.ParsesServerInvocation'`

- [ ] **Step 1: Register the bootstrap source and test files**

Add:

```zig
        "src/http3/http3_bootstrap.cpp",
```

```zig
        "tests/http3/bootstrap_test.cpp",
```

- [ ] **Step 2: Extend the server runtime parse test for bootstrap config**

In `tests/http3/runtime_test.cpp`, extend `ParsesServerInvocation` so the argv contains:

```cpp
        "--bootstrap-port",
        "9443",
        "--alt-svc-max-age",
        "120",
```

and assert:

```cpp
    EXPECT_EQ(parsed.bootstrap_port, 9443);
    EXPECT_EQ(parsed.alt_svc_max_age, 120u);
```

- [ ] **Step 3: Add RED bootstrap tests**

Create `tests/http3/bootstrap_test.cpp` with:

```cpp
TEST(QuicHttp3BootstrapTest, FormatsAltSvcValueFromBootstrapConfig) {}

TEST(QuicHttp3BootstrapTest, HttpsGetServesStaticFileAndAdvertisesAltSvc) {}

TEST(QuicHttp3BootstrapTest, HttpsHeadSuppressesBodyButAdvertisesAltSvc) {}
```

These tests should verify:
- `make_http3_alt_svc_value(...)` returns `h3=":4433"; ma=60`
- a loopback HTTPS `GET` receives `200`, `Alt-Svc`, and the expected file body
- a loopback HTTPS `HEAD` receives `200`, `Alt-Svc`, `Content-Length`, and no body

- [ ] **Step 4: Run the focused suite and verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3BootstrapTest.*:QuicHttp3RuntimeTest.ParsesServerInvocation'`

Expected: FAIL because the bootstrap module and new runtime config fields do not exist yet.

### Task 2: Define bootstrap config and parser/runtime surface

**Files:**
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_runtime.cpp`
- Create: `src/http3/http3_bootstrap.h`
- Create: `src/http3/http3_bootstrap.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Modify: `tests/http3/bootstrap_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3BootstrapTest.FormatsAltSvcValueFromBootstrapConfig:QuicHttp3RuntimeTest.ParsesServerInvocation'`

- [ ] **Step 1: Extend `Http3RuntimeConfig`**

Add:

```cpp
    std::uint16_t bootstrap_port = 0;
    std::uint64_t alt_svc_max_age = 60;
```

and finalize defaults so `bootstrap_port == 0` resolves to `port`.

- [ ] **Step 2: Parse `--bootstrap-port` and `--alt-svc-max-age`**

In `parse_http3_runtime_args(...)`, support:

```cpp
        if (arg == "--bootstrap-port") { ... }
        if (arg == "--alt-svc-max-age") { ... }
```

Reject invalid ports and non-numeric max-age values.

- [ ] **Step 3: Define a focused bootstrap module surface**

Add to `src/http3/http3_bootstrap.h`:

```cpp
struct Http3BootstrapConfig {
    std::string host = "127.0.0.1";
    std::uint16_t port = 4433;
    std::uint16_t h3_port = 4433;
    std::uint64_t alt_svc_max_age = 60;
    std::filesystem::path document_root = ".";
    std::filesystem::path certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    std::filesystem::path private_key_path = "tests/fixtures/quic-server-key.pem";
};

std::string make_http3_alt_svc_value(const Http3BootstrapConfig &config);
```

- [ ] **Step 4: Re-run the focused parser/value tests**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3BootstrapTest.FormatsAltSvcValueFromBootstrapConfig:QuicHttp3RuntimeTest.ParsesServerInvocation'`

Expected: PASS.

### Task 3: Implement the HTTPS bootstrap origin

**Files:**
- Create: `src/http3/http3_bootstrap.cpp`
- Modify: `src/http3/http3_bootstrap.h`
- Modify: `tests/http3/bootstrap_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3BootstrapTest.*'`

- [ ] **Step 1: Add the minimal TLS HTTP server**

Implement a small synchronous server that:
- opens a TCP listener on `config.host:config.port`
- loads the configured certificate and key into an OpenSSL-compatible `SSL_CTX`
- accepts one connection at a time
- reads one HTTP/1.1 request
- writes one response
- closes the connection

- [ ] **Step 2: Implement request parsing and static response generation**

Support only:

```cpp
GET /path HTTP/1.1
HEAD /path HTTP/1.1
```

Return:
- `200` for regular files under `document_root`
- `404` for missing or invalid paths
- `405` with `Allow: GET, HEAD` otherwise

Always emit:

```cpp
Alt-Svc: h3=":<h3_port>"; ma=<max_age>
Connection: close
Content-Length: ...
```

- [ ] **Step 3: Add a blocking bootstrap server entry point for tests**

Expose a small callable entry point such as:

```cpp
int run_http3_bootstrap_server(const Http3BootstrapConfig &config,
                               const std::atomic<bool> *stop_requested = nullptr);
```

so the tests can launch it in a child process or helper thread.

- [ ] **Step 4: Run the focused bootstrap suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3BootstrapTest.*'`

Expected: PASS.

### Task 4: Wire bootstrap startup into `h3-server`

**Files:**
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_bootstrap.h`
- Modify: `src/http3/http3_bootstrap.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.*:QuicHttp3BootstrapTest.*'`

- [ ] **Step 1: Derive bootstrap config from the runtime config**

Add a helper like:

```cpp
Http3BootstrapConfig make_http3_bootstrap_config(const Http3RuntimeConfig &config);
```

that maps:
- `host`
- `bootstrap_port`
- `port` -> `h3_port`
- `alt_svc_max_age`
- `document_root`
- certificate paths

- [ ] **Step 2: Start the bootstrap listener from `run_http3_runtime(server)`**

Before entering the UDP server loop:
- construct the bootstrap config
- start the bootstrap server in a dedicated thread
- ensure the bootstrap thread is stopped and joined if the UDP runtime exits early

- [ ] **Step 3: Add or adjust runtime loopback coverage**

Extend `tests/http3/runtime_test.cpp` so one server child can serve:
- H3 static content to `h3-client`
- HTTPS bootstrap content to a TLS test client

without changing the existing green H3 runtime behavior.

- [ ] **Step 4: Re-run the focused runtime + bootstrap suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.*:QuicHttp3BootstrapTest.*'`

Expected: PASS.

### Task 5: Add manual browser-setup documentation and run wider verification

**Files:**
- Create: `docs/http3-browser-discovery.md`
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `src/http3/http3_bootstrap.h`
- Modify: `src/http3/http3_bootstrap.cpp`
- Modify: `tests/http3/bootstrap_test.cpp`
- Modify: `tests/http3/runtime_test.cpp`

- [ ] **Step 1: Add the browser discovery doc**

Create `docs/http3-browser-discovery.md` covering:
- trusted local certificate setup
- starting `coquic h3-server`
- visiting the HTTPS bootstrap URL first
- checking the `Alt-Svc` response header
- confirming the browser upgrades to HTTP/3 on subsequent requests

- [ ] **Step 2: Run the wider HTTP/3 suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3*'`

Expected: PASS.

- [ ] **Step 3: Format and lint the touched files**

Run: `nix develop -c pre-commit run clang-format --files src/http3/http3_runtime.h src/http3/http3_runtime.cpp src/http3/http3_bootstrap.h src/http3/http3_bootstrap.cpp tests/http3/runtime_test.cpp tests/http3/bootstrap_test.cpp`

Expected: PASS.

Run: `nix develop -c pre-commit run coquic-clang-tidy --files src/http3/http3_runtime.h src/http3/http3_runtime.cpp src/http3/http3_bootstrap.h src/http3/http3_bootstrap.cpp tests/http3/runtime_test.cpp tests/http3/bootstrap_test.cpp`

Expected: PASS.

# QUIC Runner Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a runner-compatible HTTP/0.9 layer above `QuicCore` for both client and server roles, pass the official `handshake` and ideal-case `transfer` slices, migrate the local runtime to that layer, and remove `QuicDemoChannel`.

**Architecture:** Keep `QuicCore` transport-only. Add shared HTTP/0.9 parsing and path-resolution helpers, then separate client and server endpoint objects that consume `QuicCore` effects and emit `QuicCore` inputs. Put the UDP loop and runner env / CLI adaptation in a thin runtime layer, then delete the old demo path once the new endpoint path and tests cover the same ground.

**Tech Stack:** C++20, Zig build wiring, GoogleTest, `QuicCore`, POSIX UDP sockets, filesystem-backed integration tests, `quictls` / `boringssl`

---

## Spec Reference

- `docs/superpowers/specs/2026-03-20-quic-runner-interop-design.md`

## File Map

- Modify: `build.zig`
  - Add new HTTP/0.9 source and test files during migration, then remove `demo_channel` build entries at the end.
- Modify: `src/coquic.h`
  - Export the new public HTTP/0.9 endpoint headers during migration and drop `demo_channel.h` once the demo path is removed.
- Create: `src/quic/http09.h`
  - Shared HTTP/0.9 enums, configs, endpoint update types, parser declarations, path-resolution helpers, and testcase-specific transport-profile helpers.
- Create: `src/quic/http09.cpp`
  - `REQUESTS` parsing, request-line parsing, path normalization, download-path mapping, and testcase-specific transport-profile selection.
- Create: `src/quic/http09_client.h`
  - Client endpoint public type and config surface.
- Create: `src/quic/http09_client.cpp`
  - Client request scheduling, per-stream transfer tracking, response-body file writes, and completion logic.
- Create: `src/quic/http09_server.h`
  - Server endpoint public type and config surface.
- Create: `src/quic/http09_server.cpp`
  - Per-stream request parsing, file lookup, response streaming, and deterministic failure handling.
- Create: `src/quic/http09_runtime.h`
  - Runtime config structs and reusable UDP-loop helpers for client / server endpoint execution.
- Create: `src/quic/http09_runtime.cpp`
  - Env / CLI parsing, UDP socket loop, peer-address tracking, and endpoint-to-core drive logic.
- Modify: `src/main.cpp`
  - Replace the demo-specific main program with a thin entrypoint that delegates to the HTTP/0.9 runtime.
- Modify: `tests/quic_test_utils.h`
  - Add reusable helpers for HTTP/0.9 endpoint tests: temp file fixtures, byte conversions, and core-relay helpers that don’t depend on `QuicDemoChannel`.
- Create: `tests/quic_http09_test.cpp`
  - Shared parser, path-resolution, and testcase-profile tests.
- Create: `tests/quic_http09_server_test.cpp`
  - In-process server endpoint tests over relayed QUIC datagrams.
- Create: `tests/quic_http09_client_test.cpp`
  - In-process client endpoint tests over relayed QUIC datagrams.
- Create: `tests/quic_http09_runtime_test.cpp`
  - Socket-backed localhost smoke tests for the new runtime and endpoint pair.
- Create: `scripts/run_endpoint.sh`
  - Official-runner entrypoint wrapper translating `ROLE`, `TESTCASE`, and mounted paths into binary invocations.
- Create: `Dockerfile`
  - Build a runner-usable image for the current repo layout.
- Create: `docs/quic-interop-runner.md`
  - Human documentation for local manual runs and official runner / simulator use.
- Delete: `src/quic/demo_channel.h`
  - Remove the obsolete one-stream demo wrapper after migration.
- Delete: `src/quic/demo_channel.cpp`
  - Remove the obsolete one-stream demo wrapper after migration.
- Delete: `tests/quic_demo_channel_test.cpp`
  - Remove tests that only justify the old demo wrapper.

## Execution Notes

- Follow `@superpowers:test-driven-development` for every behavior change.
- Keep each task independently green before moving on.
- Prefer `nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='...'` for red / green cycles, then run the full suite after the final cleanup task.
- Keep `QuicCore` free of HTTP or runner-specific behavior. If a step seems to require new protocol semantics inside `QuicCore`, stop and verify that the endpoint layer can own it instead.
- The worktree already has unrelated user edits in `tests/quic_core_test.cpp`, `tests/quic_streams_test.cpp`, and `tests/quic_transport_parameters_test.cpp`. Do not revert or overwrite them while following this plan.
- The server endpoint is intentionally long-lived. Do not force a synthetic “success exit” into server-only endpoint logic; termination belongs in the runtime / test harness.

### Task 1: Add Shared HTTP/0.9 Utilities And Build Wiring

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Create: `src/quic/http09.h`
- Create: `src/quic/http09.cpp`
- Create: `tests/quic_http09_test.cpp`

- [ ] **Step 1: Write the failing shared-utility tests**

Create `tests/quic_http09_test.cpp` with focused tests for:

```cpp
TEST(QuicHttp09Test, ParsesRequestsEnvAsSpaceSeparatedAbsoluteUrls) {
    const auto parsed = coquic::quic::parse_http09_requests_env(
        "https://example.test/a https://example.test/b/c");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->size(), 2u);
    EXPECT_EQ((*parsed)[0].request_target, "/a");
    EXPECT_EQ((*parsed)[1].request_target, "/b/c");
}

TEST(QuicHttp09Test, RejectsMixedAuthoritiesInSingleClientRun) {
    const auto parsed = coquic::quic::parse_http09_requests_env(
        "https://a.test/x https://b.test/y");
    EXPECT_FALSE(parsed.has_value());
}

TEST(QuicHttp09Test, UsesSmallTransferFlowControlProfileForTransferCase) {
    const auto config =
        coquic::quic::http09_client_transport_for_testcase(
            coquic::quic::QuicHttp09Testcase::transfer);
    EXPECT_EQ(config.initial_max_data, 64u * 1024u);
    EXPECT_EQ(config.initial_max_stream_data_bidi_local, 16u * 1024u);
}

TEST(QuicHttp09Test, ResolvesRequestTargetUnderRootWithoutDiscardingRoot) {
    const auto resolved = coquic::quic::resolve_http09_path_under_root(
        "/tmp/downloads", "/a/b.bin");
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, std::filesystem::path("/tmp/downloads/a/b.bin"));
}

TEST(QuicHttp09Test, RejectsTraversalQueriesAndFragmentsWhenResolvingPath) {
    EXPECT_FALSE(coquic::quic::resolve_http09_path_under_root(
                     "/tmp/downloads", "/../secret")
                     .has_value());
    EXPECT_FALSE(coquic::quic::resolve_http09_path_under_root(
                     "/tmp/downloads", "/a?b")
                     .has_value());
    EXPECT_FALSE(coquic::quic::resolve_http09_path_under_root(
                     "/tmp/downloads", "/a#b")
                     .has_value());
}
```

- [ ] **Step 2: Wire the new test file into `build.zig` and confirm a clean red**

Add `tests/quic_http09_test.cpp` to the default test list, then run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09Test.*'
```

Expected: FAIL because `src/quic/http09.h` and its symbols do not exist yet.

- [ ] **Step 3: Add the shared public header and source skeleton**

Create `src/quic/http09.h` and `src/quic/http09.cpp` with the common surface:

```cpp
enum class QuicHttp09Testcase : std::uint8_t {
    handshake,
    transfer,
};

struct QuicHttp09Request {
    std::string url;
    std::string authority;
    std::string request_target;
    std::filesystem::path relative_output_path;
};

struct QuicHttp09EndpointUpdate {
    std::vector<QuicCoreInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
};

CodecResult<std::vector<QuicHttp09Request>>
parse_http09_requests_env(std::string_view requests_env);

CodecResult<std::string> parse_http09_request_target(std::span<const std::byte> bytes);

CodecResult<std::filesystem::path>
resolve_http09_path_under_root(const std::filesystem::path &root, std::string_view request_target);

QuicTransportConfig http09_client_transport_for_testcase(QuicHttp09Testcase testcase);
```

Also export the new header from `src/coquic.h`.

- [ ] **Step 4: Implement the minimal shared behavior to satisfy the tests**

Implement only the logic needed for the red tests:

```cpp
CodecResult<std::vector<QuicHttp09Request>>
parse_http09_requests_env(std::string_view requests_env) {
    // split on ASCII spaces, require absolute https:// URLs, and require one authority
}

QuicTransportConfig http09_client_transport_for_testcase(QuicHttp09Testcase testcase) {
    auto config = QuicTransportConfig{};
    if (testcase == QuicHttp09Testcase::transfer) {
        config.initial_max_data = 64u * 1024u;
        config.initial_max_stream_data_bidi_local = 16u * 1024u;
    }
    return config;
}
```

`resolve_http09_path_under_root(...)` must:

- reject query strings and fragments
- strip the leading `/` before joining
- join only via a relative path segment so `root / "/x"` never discards `root`
- reject any normalized path that escapes the requested root

- [ ] **Step 5: Re-run the shared utility tests**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09Test.*'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add build.zig src/coquic.h src/quic/http09.h src/quic/http09.cpp tests/quic_http09_test.cpp
git commit -m "feat: add QUIC HTTP/0.9 shared utilities"
```

### Task 2: Implement The HTTP/0.9 Server Endpoint

**Files:**
- Modify: `build.zig`
- Create: `src/quic/http09_server.h`
- Create: `src/quic/http09_server.cpp`
- Modify: `tests/quic_test_utils.h`
- Create: `tests/quic_http09_server_test.cpp`

- [ ] **Step 1: Write failing in-process server endpoint tests**

Create `tests/quic_http09_server_test.cpp` using two `QuicCore` instances and relayed datagrams:

```cpp
TEST(QuicHttp09ServerTest, ServesFileBodyOnRequestedBidirectionalStream) {
    // temp root contains /hello.txt with "hello"
    // client sends "GET /hello.txt\r\n" on stream 0
    // server emits QuicCoreSendStreamData on stream 0 and eventually FIN
}

TEST(QuicHttp09ServerTest, RejectsPathTraversalRequest) {
    // request "../secret" or "/../../secret"
    // server enters deterministic failure state
}
```

Use `tests/quic_test_utils.h` helpers instead of copying the current `QuicDemoChannel` test harness.

- [ ] **Step 2: Add the new server files to `build.zig` and run the server suite to confirm red**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09ServerTest.*'
```

Expected: FAIL because the server endpoint types do not exist yet, not because the new test file is missing from the build.

- [ ] **Step 3: Add the server endpoint public shape**

Create `src/quic/http09_server.h` with a focused API:

```cpp
struct QuicHttp09ServerConfig {
    std::filesystem::path document_root;
};

class QuicHttp09ServerEndpoint {
  public:
    explicit QuicHttp09ServerEndpoint(QuicHttp09ServerConfig config);

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &result,
                                            QuicCoreTimePoint now);
    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint now);

    bool has_failed() const;
};
```

- [ ] **Step 4: Implement minimal request parsing, file lookup, and response streaming**

In `src/quic/http09_server.cpp`, implement:

```cpp
QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::on_core_result(
    const QuicCoreResult &result, QuicCoreTimePoint now) {
    // inspect QuicCoreReceiveStreamData events
    // buffer by stream id until a request line is complete
    // resolve request target only through resolve_http09_path_under_root(document_root, ...)
    // enqueue QuicCoreSendStreamData{.stream_id = ..., .bytes = chunk, .fin = true/false}
}
```

Keep failures deterministic:

- reject non-`GET` requests
- reject relative or escaping paths
- reject application data on server-initiated streams

- [ ] **Step 5: Re-run the server suite**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09ServerTest.*'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add build.zig src/quic/http09_server.h src/quic/http09_server.cpp tests/quic_test_utils.h tests/quic_http09_server_test.cpp
git commit -m "feat: add QUIC HTTP/0.9 server endpoint"
```

### Task 3: Implement The HTTP/0.9 Client Endpoint

**Files:**
- Modify: `build.zig`
- Create: `src/quic/http09_client.h`
- Create: `src/quic/http09_client.cpp`
- Create: `tests/quic_http09_client_test.cpp`

- [ ] **Step 1: Write failing in-process client endpoint tests**

Create tests for both `handshake` and `transfer` behavior:

```cpp
TEST(QuicHttp09ClientTest, OpensOneBidirectionalStreamPerRequestAfterHandshake) {
    // one connection, two request URLs
    // after handshake_ready, endpoint emits GET requests on stream 0 and stream 4
}

TEST(QuicHttp09ClientTest, WritesDownloadedResponseBodiesToFilesystem) {
    // server responds with bytes on stream 0 and FIN
    // client writes /downloads/hello.txt exactly
}

TEST(QuicHttp09ClientTest, ReportsSuccessOnlyAfterAllStreamsFinishWithFin) {
    // bytes without FIN are not enough for terminal success
}
```

- [ ] **Step 2: Add the new client files to `build.zig` and run the client suite to confirm red**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09ClientTest.*'
```

Expected: FAIL because the client endpoint types do not exist yet, not because the new test file is missing from the build.

- [ ] **Step 3: Add the client endpoint public shape**

Create `src/quic/http09_client.h`:

```cpp
struct QuicHttp09ClientConfig {
    std::vector<QuicHttp09Request> requests;
    std::filesystem::path download_root;
};

class QuicHttp09ClientEndpoint {
  public:
    explicit QuicHttp09ClientEndpoint(QuicHttp09ClientConfig config);

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &result,
                                            QuicCoreTimePoint now);
    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint now);

    bool is_complete() const;
    bool has_failed() const;
};
```

- [ ] **Step 4: Implement request issuance, stream tracking, and file writes**

In `src/quic/http09_client.cpp`, implement the minimal transport-facing behavior:

```cpp
QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::poll(QuicCoreTimePoint now) {
    // once handshake_ready is observed:
    //   assign stream ids 0, 4, 8, ...
    //   emit "GET <target>\\r\\n" with fin=true on each request stream
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::on_core_result(
    const QuicCoreResult &result, QuicCoreTimePoint now) {
    // resolve request_target only through resolve_http09_path_under_root(download_root, ...)
    // append received bytes to the resolved path under download_root
    // mark each stream complete only on fin=true
    // set terminal_success only when all requests complete
}
```

Do not add a second scheduler beyond `QuicCore`; issue all `transfer` requests as soon as the handshake completes.

- [ ] **Step 5: Re-run the client suite**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09ClientTest.*'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add build.zig src/quic/http09_client.h src/quic/http09_client.cpp tests/quic_http09_client_test.cpp
git commit -m "feat: add QUIC HTTP/0.9 client endpoint"
```

### Task 4: Rework The Local Runtime Around The New Endpoints

**Files:**
- Modify: `build.zig`
- Create: `src/quic/http09_runtime.h`
- Create: `src/quic/http09_runtime.cpp`
- Modify: `src/main.cpp`
- Create: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write failing socket-backed runtime tests**

Create `tests/quic_http09_runtime_test.cpp` with localhost UDP smoke tests:

```cpp
TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileOverUdpSockets) {
    // start runtime server in one thread with temp /www
    // start runtime client in another thread with temp /downloads
    // expect downloaded file bytes to match exactly
}

TEST(QuicHttp09RuntimeTest, TransferCaseUsesSingleConnectionAndMultipleStreams) {
    // two requested files, one connection, multiple request streams
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsCoreConfigWithInteropAlpnAndRunnerDefaults) {
    // assert application_protocol == "hq-interop"
    // assert document_root == "/www", download_root == "/downloads"
    // assert server cert/key paths default to /certs/cert.pem and /certs/priv.key
    // assert TESTCASE=transfer applies the transfer flow-control profile in QuicCoreConfig
}

TEST(QuicHttp09RuntimeTest, HandshakeCaseNeverEmitsRetryPackets) {
    // capture the server's early outbound datagrams in handshake mode
    // decode them and assert no Retry packet type appears
}
```

- [ ] **Step 2: Add the runtime files to `build.zig` and run the runtime suite to confirm red**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09RuntimeTest.*'
```

Expected: FAIL because the runtime layer does not exist yet, not because the new test file is missing from the build.

- [ ] **Step 3: Add the runtime layer with reusable UDP-loop helpers**

Create `src/quic/http09_runtime.h/.cpp` with:

```cpp
enum class Http09RuntimeMode : std::uint8_t { health_check, client, server };

struct Http09RuntimeConfig {
    Http09RuntimeMode mode = Http09RuntimeMode::health_check;
    std::string host = "127.0.0.1";
    std::uint16_t port = 443;
    QuicHttp09Testcase testcase = QuicHttp09Testcase::handshake;
    std::filesystem::path document_root = "/www";
    std::filesystem::path download_root = "/downloads";
    std::filesystem::path certificate_chain_path = "/certs/cert.pem";
    std::filesystem::path private_key_path = "/certs/priv.key";
    bool verify_peer = false;
    std::string application_protocol = "hq-interop";
    std::string server_name = "localhost";
    std::string requests_env;
};

std::optional<Http09RuntimeConfig> parse_http09_runtime_args(int argc, char **argv);
QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config);
QuicCoreConfig make_http09_server_core_config(const Http09RuntimeConfig &config);
int run_http09_runtime(const Http09RuntimeConfig &config);
```

Move the reusable socket polling, datagram send / receive, and timer-handling logic out of `src/main.cpp` into this runtime. `make_http09_*_core_config(...)` must be the single place that overrides `QuicCoreConfig::application_protocol` to `"hq-interop"` and applies the `transfer` testcase flow-control profile.
`parse_http09_runtime_args(...)` must read `ROLE`, `TESTCASE`, `REQUESTS`, and the mounted runner paths from the environment by default, with CLI flags allowed to override them for local manual runs.

- [ ] **Step 4: Replace the demo-specific `main.cpp` with a thin runtime entrypoint**

Shrink `src/main.cpp` to:

```cpp
int main(int argc, char **argv) {
    const auto config = coquic::quic::parse_http09_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::quic::run_http09_runtime(*config);
}
```

`parse_http09_runtime_args(...)` must accept literal `interop-server` and `interop-client` subcommands so the runner wrapper in Task 5 has a stable CLI target. Keep a health-check mode, but remove the old `demo-server` / `demo-client <message>` behavior from the main path.

- [ ] **Step 5: Re-run the runtime suite**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09RuntimeTest.*'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add build.zig src/quic/http09_runtime.h src/quic/http09_runtime.cpp src/main.cpp tests/quic_http09_runtime_test.cpp
git commit -m "feat: move local runtime to QUIC HTTP/0.9 endpoints"
```

### Task 5: Add Official Runner Packaging And Operator Docs

**Files:**
- Create: `scripts/run_endpoint.sh`
- Create: `Dockerfile`
- Create: `docs/quic-interop-runner.md`

- [ ] **Step 1: Write the failing runner-smoke contract as documentation-driven tests**

Before adding packaging, pin the intended commands in `docs/quic-interop-runner.md`:

```markdown
ROLE=server TESTCASE=handshake ./scripts/run_endpoint.sh
ROLE=client TESTCASE=transfer REQUESTS="https://server/file1 https://server/file2" ./scripts/run_endpoint.sh
```

Treat this step as the red requirement: the commands are documented but the script and image do not exist yet.

- [ ] **Step 2: Create `scripts/run_endpoint.sh` mirroring the official runner contract**

Implement a thin wrapper:

```bash
#!/usr/bin/env bash
set -euo pipefail

if [ "${ROLE:-}" = "server" ]; then
  exec /usr/local/bin/coquic interop-server
fi

if [ "${ROLE:-}" = "client" ]; then
  exec /usr/local/bin/coquic interop-client
fi

echo "unsupported ROLE=${ROLE:-}" >&2
exit 1
```

Pass through `TESTCASE`, `REQUESTS`, `/www`, `/downloads`, and `/certs` via environment variables instead of re-implementing application logic in shell.

- [ ] **Step 3: Create a runner-usable `Dockerfile`**

Build the project into an image that exposes:

- `/usr/local/bin/coquic`
- `/entrypoint.sh` or `scripts/run_endpoint.sh`
- certificate and mounted-path expectations compatible with the runner

The image does not need extra behavior beyond the official runner contract.

- [ ] **Step 4: Document local and official interop usage**

In `docs/quic-interop-runner.md`, document:

- how to build the image
- how to run `interop-server` and `interop-client` manually
- how to point `quic-interop-runner` and `quic-network-simulator` at the image
- that only `handshake` and ideal `transfer` are targeted in this slice

- [ ] **Step 5: Commit**

```bash
git add scripts/run_endpoint.sh Dockerfile docs/quic-interop-runner.md
git commit -m "feat: add QUIC interop runner packaging"
```

### Task 6: Remove `QuicDemoChannel` And Run Full Verification

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Modify: `tests/quic_test_utils.h`
- Delete: `src/quic/demo_channel.h`
- Delete: `src/quic/demo_channel.cpp`
- Delete: `tests/quic_demo_channel_test.cpp`

- [ ] **Step 1: Write the migration-finish assertion by removing all remaining `QuicDemoChannel` references**

Use:

```bash
rg -n "QuicDemoChannel|demo-server|demo-client" src tests build.zig
```

Expected before cleanup: matches in the old demo files and any stale test helpers.

- [ ] **Step 2: Remove the demo wrapper and stale test helpers**

Delete:

- `src/quic/demo_channel.h`
- `src/quic/demo_channel.cpp`
- `tests/quic_demo_channel_test.cpp`

Update:

- `build.zig` to stop compiling the deleted files
- `src/coquic.h` to stop exporting `demo_channel.h`
- `tests/quic_test_utils.h` to drop obsolete `QuicDemoChannel` relay helpers

- [ ] **Step 3: Run the targeted HTTP/0.9 suites**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls -- --gtest_filter='QuicHttp09*'
```

Expected: PASS.

- [ ] **Step 4: Run the full verification suite**

Run:

```bash
nix develop -c zig build test -Dtls_backend=quictls
nix develop -c zig build -Dtls_backend=quictls
pre-commit run clang-format --all-files --show-diff-on-failure
pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: PASS on all commands.

- [ ] **Step 5: Commit**

```bash
git add build.zig src/coquic.h tests/quic_test_utils.h
git rm src/quic/demo_channel.h src/quic/demo_channel.cpp tests/quic_demo_channel_test.cpp
git commit -m "refactor: replace demo channel with HTTP/0.9 interop path"
```

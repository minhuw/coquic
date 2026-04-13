# HTTP/3 Interop Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated official-runner-facing HTTP/3 harness that supports the runner's `http3` testcase in both directions while leaving the current HTTP/0.9 interop path unchanged.

**Architecture:** Add new `h3-interop-server` and `h3-interop-client` subcommands in the existing `coquic` binary, implemented in a focused `src/http3/http3_interop.*` layer. Reuse the current HTTP/3 runtime and endpoint logic, extract only the minimum shared client-transfer helper needed for one-connection multi-file downloads, and update `interop/entrypoint.sh` to dispatch `TESTCASE=http3` to the new H3 surface while preserving the existing HTTP/0.9 flow for all other testcases.

**Tech Stack:** C++20, GoogleTest, Bash, Zig build system, existing `src/http3/` runtime and endpoint code, official `quic-interop-runner` contract, `zig build test`, `pre-commit` clang-format, `pre-commit` clang-tidy.

---

## File Map

- Create: `src/http3/http3_interop.h`
  - runner-facing HTTP/3 config structs and public entrypoints for `h3-interop-server` and `h3-interop-client`
- Create: `src/http3/http3_interop.cpp`
  - env / CLI parsing, testcase gating, H3 interop server runtime mapping, H3 interop client orchestration
- Modify: `src/http3/http3_runtime.h`
  - add the minimal runtime surface needed to disable bootstrap in interop mode and run multiple HTTP/3 client transfers over one connection
- Modify: `src/http3/http3_runtime.cpp`
  - extract reusable multi-request client transfer loop, keep `h3-client` behavior unchanged, honor a bootstrap-disable flag for runner-facing server mode
- Modify: `src/main.cpp`
  - dispatch `h3-interop-server` and `h3-interop-client`
- Modify: `build.zig`
  - compile the new HTTP/3 interop module and test file
- Create: `tests/http3/interop_test.cpp`
  - H3 interop env parsing, unsupported testcase exit behavior, loopback multi-file H3 transfer coverage
- Modify: `tests/http3/runtime_test.cpp`
  - add focused runtime coverage for disabling the bootstrap listener in runner-facing H3 server mode
- Create: `tests/nix/http3_interop_entrypoint_test.sh`
  - shell-level dispatch checks for `interop/entrypoint.sh`
- Modify: `interop/entrypoint.sh`
  - route `TESTCASE=http3` to the new H3 runner subcommands and keep existing HTTP/0.9 behavior unchanged otherwise
- Modify: `interop/README.md`
  - document the split HTTP/0.9 vs HTTP/3 runner surfaces and the local `http3` runner invocation

### Task 1: Add RED HTTP/3 Interop Tests And Build Wiring

**Files:**
- Modify: `build.zig`
- Create: `tests/http3/interop_test.cpp`
- Create: `tests/nix/http3_interop_entrypoint_test.sh`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.*:QuicHttp3RuntimeTest.ServerModeCanDisableBootstrapListener'`
- Test: `bash tests/nix/http3_interop_entrypoint_test.sh`

- [ ] **Step 1: Register the new HTTP/3 interop source and test files**

Add the new source and test registration in `build.zig`:

```zig
        "src/http3/http3_interop.cpp",
```

and:

```zig
        "tests/http3/interop_test.cpp",
```

- [ ] **Step 2: Add failing H3 interop config and loopback tests**

Create `tests/http3/interop_test.cpp` with focused RED tests that assume the new H3 interop surface exists:

```cpp
#include <gtest/gtest.h>

#include "src/http3/http3_interop.h"
#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using coquic::http09::test_support::ScopedEnvVar;
using coquic::http09::test_support::optional_ref_or_terminate;

TEST(QuicHttp3InteropTest, ParsesServerInvocationFromEnvironment) {
    const char *argv[] = {"coquic", "h3-interop-server"};
    ScopedEnvVar testcase("TESTCASE", "http3");
    ScopedEnvVar host("HOST", "0.0.0.0");
    ScopedEnvVar port("PORT", "443");
    ScopedEnvVar document_root("DOCUMENT_ROOT", "/www");
    ScopedEnvVar certificate_chain("CERTIFICATE_CHAIN_PATH", "/certs/cert.pem");
    ScopedEnvVar private_key("PRIVATE_KEY_PATH", "/certs/priv.key");

    const auto parsed =
        coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));

    ASSERT_TRUE(parsed.has_value());
    const auto &config = optional_ref_or_terminate(parsed);
    EXPECT_EQ(config.mode, coquic::http3::Http3InteropMode::server);
    EXPECT_EQ(config.testcase, "http3");
    EXPECT_EQ(config.host, "0.0.0.0");
    EXPECT_EQ(config.port, 443);
    EXPECT_EQ(config.document_root, std::filesystem::path("/www"));
}

TEST(QuicHttp3InteropTest, UnsupportedTestcaseReturnsRunnerSkipExitCode) {
    const auto config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::server,
        .testcase = "transfer",
    };

    EXPECT_EQ(coquic::http3::run_http3_interop(config), 127);
}

TEST(QuicHttp3InteropTest, ClientDownloadsMultipleFilesOverLoopback) {
    // This test will launch one H3 server and require the interop client to
    // fetch two URLs over one runner-oriented HTTP/3 invocation.
}
} // namespace
```

- [ ] **Step 3: Add a failing runtime test for bootstrap-disable support**

Extend `tests/http3/runtime_test.cpp` with a test that assumes the server runtime can skip the HTTPS bootstrap listener:

```cpp
TEST(QuicHttp3RuntimeTest, ServerModeCanDisableBootstrapListener) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto h3_port = allocate_udp_loopback_port();
    ASSERT_NE(h3_port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = h3_port,
        .enable_bootstrap = false,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(h3_port) + "/hello.txt",
    };

    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}
```

- [ ] **Step 4: Add a failing wrapper-dispatch shell test**

Create `tests/nix/http3_interop_entrypoint_test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

cat > "${tmpdir}/fake-coquic" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${TEST_OUTPUT}"
EOF
chmod +x "${tmpdir}/fake-coquic"

TEST_OUTPUT="${tmpdir}/server-http3.txt" \
COQUIC_BIN="${tmpdir}/fake-coquic" \
COQUIC_SKIP_SETUP=1 \
ROLE=server \
TESTCASE=http3 \
bash interop/entrypoint.sh
grep -qx 'h3-interop-server' "${tmpdir}/server-http3.txt"

TEST_OUTPUT="${tmpdir}/client-http3.txt" \
COQUIC_BIN="${tmpdir}/fake-coquic" \
COQUIC_SKIP_SETUP=1 \
COQUIC_SKIP_WAIT=1 \
ROLE=client \
TESTCASE=http3 \
REQUESTS="https://server/a.txt https://server/b.txt" \
bash interop/entrypoint.sh
grep -qx 'h3-interop-client' "${tmpdir}/client-http3.txt"

TEST_OUTPUT="${tmpdir}/client-transfer.txt" \
COQUIC_BIN="${tmpdir}/fake-coquic" \
COQUIC_SKIP_SETUP=1 \
COQUIC_SKIP_WAIT=1 \
ROLE=client \
TESTCASE=transfer \
REQUESTS="https://server/a.txt" \
bash interop/entrypoint.sh
grep -qx 'interop-client' "${tmpdir}/client-transfer.txt"

echo "http3 interop entrypoint dispatch looks correct"
```

- [ ] **Step 5: Run the focused RED suite**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.*:QuicHttp3RuntimeTest.ServerModeCanDisableBootstrapListener'
bash tests/nix/http3_interop_entrypoint_test.sh
```

Expected:

- the C++ test build fails because `src/http3/http3_interop.*` does not exist and `enable_bootstrap` is not defined yet
- the shell test fails because `interop/entrypoint.sh` still dispatches `TESTCASE=http3` to the HTTP/0.9 surface

- [ ] **Step 6: Commit the red test scaffolding**

```bash
git add build.zig tests/http3/interop_test.cpp tests/http3/runtime_test.cpp tests/nix/http3_interop_entrypoint_test.sh
git commit -m "test: add HTTP/3 interop harness coverage"
```

### Task 2: Implement The H3 Interop Config Surface And Server Wrapper

**Files:**
- Create: `src/http3/http3_interop.h`
- Create: `src/http3/http3_interop.cpp`
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `src/main.cpp`
- Modify: `tests/http3/interop_test.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.ParsesServerInvocationFromEnvironment:QuicHttp3InteropTest.UnsupportedTestcaseReturnsRunnerSkipExitCode:QuicHttp3RuntimeTest.ServerModeCanDisableBootstrapListener'`

- [ ] **Step 1: Define the runner-facing H3 interop API**

Add `src/http3/http3_interop.h`:

```cpp
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace coquic::http3 {

enum class Http3InteropMode : std::uint8_t { server, client };

struct Http3InteropConfig {
    Http3InteropMode mode = Http3InteropMode::server;
    std::string testcase = "http3";
    std::string host = "::";
    std::uint16_t port = 443;
    std::filesystem::path document_root = "/www";
    std::filesystem::path download_root = "/downloads";
    std::filesystem::path certificate_chain_path = "/certs/cert.pem";
    std::filesystem::path private_key_path = "/certs/priv.key";
    std::string server_name;
    std::vector<std::string> requests;
};

std::optional<Http3InteropConfig> parse_http3_interop_args(int argc, char **argv);
int run_http3_interop(const Http3InteropConfig &config);

} // namespace coquic::http3
```

- [ ] **Step 2: Add the minimal runtime switch to disable the bootstrap HTTPS listener**

Extend `src/http3/http3_runtime.h`:

```cpp
struct Http3RuntimeConfig {
    Http3RuntimeMode mode = Http3RuntimeMode::server;
    io::QuicIoBackendKind io_backend = io::QuicIoBackendKind::socket;
    std::string host = "127.0.0.1";
    std::uint16_t port = 4433;
    std::uint16_t bootstrap_port = 0;
    std::uint64_t alt_svc_max_age = 60;
    bool enable_bootstrap = true;
    std::filesystem::path document_root = ".";
    // ...
};
```

and gate the bootstrap thread startup in `src/http3/http3_runtime.cpp`:

```cpp
if (config.mode == Http3RuntimeMode::server) {
    const auto endpoint = make_http3_server_endpoint_config(config);
    if (!endpoint.has_value()) {
        return 1;
    }

    auto bootstrap = io::bootstrap_server_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "h3-server",
                    .idle_timeout_ms = 1000,
                },
        },
        config.host, std::span<const std::uint16_t>(&config.port, 1));
    if (!bootstrap.has_value()) {
        return 1;
    }

    std::optional<std::thread> bootstrap_thread;
    std::optional<std::future<int>> bootstrap_result;
    std::atomic<bool> bootstrap_stop_requested = false;
    if (config.enable_bootstrap) {
        const auto bootstrap_config = make_http3_bootstrap_config(config);
        std::packaged_task<int()> bootstrap_task(std::bind(
            run_http3_bootstrap_server_guarded, bootstrap_config, &bootstrap_stop_requested));
        bootstrap_result = bootstrap_task.get_future();
        bootstrap_thread.emplace(std::move(bootstrap_task));
    }

    Http3ServerRuntime runtime(config, *endpoint, std::move(bootstrap->backend));
    const int runtime_exit_code = runtime.run();
    bootstrap_stop_requested.store(true, std::memory_order_relaxed);
    if (bootstrap_thread.has_value()) {
        bootstrap_thread->join();
    }
    // ...
}
```

- [ ] **Step 3: Implement env parsing and server-side runner mapping**

Add the server-facing `parse_http3_interop_args(...)` and `run_http3_interop(...)` logic in `src/http3/http3_interop.cpp`:

```cpp
#include "src/http3/http3_interop.h"

#include "src/http3/http3_runtime.h"

#include <charconv>
#include <cstdlib>

namespace coquic::http3 {
namespace {

std::optional<std::string> env_copy(const char *name) {
    const char *value = std::getenv(name);
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
}

std::optional<std::uint16_t> parse_port(std::string_view value) {
    std::uint32_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed > 65535u) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

} // namespace

std::optional<Http3InteropConfig> parse_http3_interop_args(int argc, char **argv) {
    if (argc < 2) {
        return std::nullopt;
    }

    Http3InteropConfig config;
    const std::string_view subcommand = argv[1];
    if (subcommand == "h3-interop-server") {
        config.mode = Http3InteropMode::server;
        config.host = env_copy("HOST").value_or("::");
        config.port = parse_port(env_copy("PORT").value_or("443")).value_or(0);
        config.document_root = env_copy("DOCUMENT_ROOT").value_or("/www");
        config.certificate_chain_path =
            env_copy("CERTIFICATE_CHAIN_PATH").value_or("/certs/cert.pem");
        config.private_key_path =
            env_copy("PRIVATE_KEY_PATH").value_or("/certs/priv.key");
    } else if (subcommand == "h3-interop-client") {
        config.mode = Http3InteropMode::client;
        config.port = parse_port(env_copy("PORT").value_or("443")).value_or(0);
        config.download_root = env_copy("DOWNLOAD_ROOT").value_or("/downloads");
        config.server_name = env_copy("SERVER_NAME").value_or("");
        // request parsing lands in Task 3
    } else {
        return std::nullopt;
    }

    config.testcase = env_copy("TESTCASE").value_or("http3");
    if (config.port == 0) {
        return std::nullopt;
    }
    return config;
}

int run_http3_interop(const Http3InteropConfig &config) {
    if (config.testcase != "http3") {
        return 127;
    }

    if (config.mode == Http3InteropMode::server) {
        return run_http3_runtime(Http3RuntimeConfig{
            .mode = Http3RuntimeMode::server,
            .host = config.host,
            .port = config.port,
            .enable_bootstrap = false,
            .document_root = config.document_root,
            .certificate_chain_path = config.certificate_chain_path,
            .private_key_path = config.private_key_path,
        });
    }

    return 1;
}

} // namespace coquic::http3
```

- [ ] **Step 4: Wire the new subcommands in `src/main.cpp`**

Update `src/main.cpp`:

```cpp
#include "src/http3/http3_interop.h"
#include "src/http3/http3_runtime.h"
#include "src/http09/http09_runtime.h"

#include <string_view>

int main(int argc, char **argv) {
    if (argc >= 2) {
        const auto subcommand = std::string_view(argv[1]);
        if (subcommand == "h3-server" || subcommand == "h3-client") {
            const auto config = coquic::http3::parse_http3_runtime_args(argc, argv);
            if (!config.has_value()) {
                return 1;
            }
            return coquic::http3::run_http3_runtime(*config);
        }
        if (subcommand == "h3-interop-server" || subcommand == "h3-interop-client") {
            const auto config = coquic::http3::parse_http3_interop_args(argc, argv);
            if (!config.has_value()) {
                return 1;
            }
            return coquic::http3::run_http3_interop(*config);
        }
    }

    const auto config = coquic::http09::parse_http09_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::http09::run_http09_runtime(*config);
}
```

- [ ] **Step 5: Run the focused parser and server wrapper tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.ParsesServerInvocationFromEnvironment:QuicHttp3InteropTest.UnsupportedTestcaseReturnsRunnerSkipExitCode:QuicHttp3RuntimeTest.ServerModeCanDisableBootstrapListener'
```

Expected:

- all three tests pass
- failures move to the still-unimplemented H3 interop client path

- [ ] **Step 6: Commit the H3 interop server surface**

```bash
git add src/http3/http3_interop.h src/http3/http3_interop.cpp src/http3/http3_runtime.h src/http3/http3_runtime.cpp src/main.cpp tests/http3/interop_test.cpp tests/http3/runtime_test.cpp
git commit -m "feat: add HTTP/3 interop server surface"
```

### Task 3: Extract Reusable Multi-Request H3 Client Transfer Support

**Files:**
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `tests/http3/interop_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.ClientDownloadsMultipleFilesOverLoopback'`

- [ ] **Step 1: Expand the failing loopback test to pin the multi-request contract**

Fill in `ClientDownloadsMultipleFilesOverLoopback` in `tests/http3/interop_test.cpp`:

```cpp
TEST(QuicHttp3InteropTest, ClientDownloadsMultipleFilesOverLoopback) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("a.txt", "alpha");
    document_root.write_file("b.txt", "bravo");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .enable_bootstrap = false,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    ScopedHttp3Process server_process(server);

    const auto config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::client,
        .testcase = "http3",
        .download_root = download_root.path(),
        .requests = {
            "https://localhost:" + std::to_string(port) + "/a.txt",
            "https://localhost:" + std::to_string(port) + "/b.txt",
        },
    };

    EXPECT_EQ(coquic::http3::run_http3_interop(config), 0);
    EXPECT_EQ(coquic::quic::test::read_text_file(download_root.path() / "a.txt"), "alpha");
    EXPECT_EQ(coquic::quic::test::read_text_file(download_root.path() / "b.txt"), "bravo");
}
```

- [ ] **Step 2: Add a reusable multi-request transfer type and entrypoint**

Extend `src/http3/http3_runtime.h`:

```cpp
struct Http3RuntimeTransferJob {
    std::string url;
    std::filesystem::path output_path;
};

int run_http3_client_transfers(const Http3RuntimeConfig &config,
                               std::span<const Http3RuntimeTransferJob> jobs);
```

- [ ] **Step 3: Extract the current single-request client loop into a multi-request helper**

Refactor `src/http3/http3_runtime.cpp` so the old `Http3ClientRuntime` path becomes a reusable multi-request loop:

```cpp
class Http3TransferClientRuntime {
  public:
    Http3TransferClientRuntime(const Http3RuntimeConfig &config,
                               std::vector<Http3ClientExecutionPlan> plans,
                               quic::QuicRouteHandle primary_route_handle,
                               std::unique_ptr<io::QuicIoBackend> backend)
        : config_(config), plans_(std::move(plans)),
          core_(make_http3_client_endpoint_config(config)), backend_(std::move(backend)),
          primary_route_handle_(primary_route_handle) {
    }

    int run() {
        for (auto &plan : plans_) {
            const auto submitted = endpoint_.submit_request(plan.request);
            if (!submitted.has_value()) {
                return 1;
            }
            pending_outputs_.insert_or_assign(submitted.value(), plan.output_path);
        }

        const auto start = quic::QuicCoreClock::now();
        if (!handle_result(core_.advance_endpoint(
                               quic::QuicCoreOpenConnection{
                                   .connection = make_client_open_config(plans_.front()),
                                   .initial_route_handle = primary_route_handle_,
                               },
                               start),
                           start)) {
            return 1;
        }

        while (completed_outputs_ < pending_outputs_.size()) {
            // existing wait / advance loop from Http3ClientRuntime, but collect
            // every response event and write each body to its mapped output path
        }
        return 0;
    }
};

int run_http3_client_transfers(const Http3RuntimeConfig &config,
                               std::span<const Http3RuntimeTransferJob> jobs) {
    if (jobs.empty()) {
        return 1;
    }

    std::vector<Http3ClientExecutionPlan> plans;
    plans.reserve(jobs.size());
    for (const auto &job : jobs) {
        Http3RuntimeConfig request_config = config;
        request_config.mode = Http3RuntimeMode::client;
        request_config.url = job.url;
        request_config.output_path = job.output_path;
        const auto plan = make_client_execution_plan(request_config);
        if (!plan.has_value()) {
            return 1;
        }
        plans.push_back(*plan);
    }

    const auto first = plans.front();
    for (const auto &plan : plans) {
        if (plan.host != first.host || plan.port != first.port || plan.server_name != first.server_name) {
            return 1;
        }
    }

    auto bootstrap = io::bootstrap_client_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "h3-client",
                    .idle_timeout_ms = 1000,
                },
        },
        first.host, first.port);
    if (!bootstrap.has_value()) {
        return 1;
    }

    Http3TransferClientRuntime runtime(config, std::move(plans), bootstrap->primary_route_handle,
                                       std::move(bootstrap->backend));
    return runtime.run();
}
```

- [ ] **Step 4: Keep the existing `h3-client` behavior as a one-job wrapper**

Update the client branch in `run_http3_runtime(...)`:

```cpp
const auto plan = make_client_execution_plan(config);
if (!plan.has_value() || !config.output_path.has_value()) {
    return 1;
}

return run_http3_client_transfers(
    config, std::array<Http3RuntimeTransferJob, 1>{
                Http3RuntimeTransferJob{
                    .url = config.url,
                    .output_path = *config.output_path,
                },
            });
```

- [ ] **Step 5: Run the focused multi-request loopback test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.ClientDownloadsMultipleFilesOverLoopback'
```

Expected:

- one loopback H3 server serves both files
- one H3 interop client invocation downloads both files successfully

- [ ] **Step 6: Commit the shared multi-request transfer helper**

```bash
git add src/http3/http3_runtime.h src/http3/http3_runtime.cpp tests/http3/interop_test.cpp
git commit -m "feat: add reusable HTTP/3 multi-transfer client runtime"
```

### Task 4: Implement The H3 Interop Client, Wrapper Dispatch, And Docs

**Files:**
- Modify: `src/http3/http3_interop.cpp`
- Modify: `interop/entrypoint.sh`
- Modify: `interop/README.md`
- Create: `tests/nix/http3_interop_entrypoint_test.sh`
- Modify: `tests/http3/interop_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.*'`
- Test: `bash tests/nix/http3_interop_entrypoint_test.sh`

- [ ] **Step 1: Implement request-list parsing and output-path derivation in the H3 interop layer**

Extend `src/http3/http3_interop.cpp`:

```cpp
namespace {

std::vector<std::string> split_requests(std::string_view value) {
    std::vector<std::string> requests;
    std::size_t offset = 0;
    while (offset < value.size()) {
        while (offset < value.size() && std::isspace(static_cast<unsigned char>(value[offset])) != 0) {
            ++offset;
        }
        const auto next = value.find(' ', offset);
        const auto token = value.substr(offset, next == std::string_view::npos ? value.size() - offset
                                                                                : next - offset);
        if (!token.empty()) {
            requests.emplace_back(token);
        }
        if (next == std::string_view::npos) {
            break;
        }
        offset = next + 1;
    }
    return requests;
}

std::optional<std::filesystem::path> output_path_for_request(
    const std::filesystem::path &download_root, std::string_view url) {
    const auto parsed = parse_https_url(url);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    const auto filename = std::filesystem::path(parsed->path).filename();
    if (filename.empty() || filename == "/") {
        return std::nullopt;
    }
    return download_root / filename;
}

} // namespace
```

- [ ] **Step 2: Implement the H3 interop client on top of the shared multi-transfer runtime**

Finish `run_http3_interop(...)`:

```cpp
if (config.mode == Http3InteropMode::client) {
    if (config.requests.empty()) {
        return 1;
    }

    std::vector<Http3RuntimeTransferJob> jobs;
    jobs.reserve(config.requests.size());
    for (const auto &request_url : config.requests) {
        const auto output_path = output_path_for_request(config.download_root, request_url);
        if (!output_path.has_value()) {
            return 1;
        }
        jobs.push_back(Http3RuntimeTransferJob{
            .url = request_url,
            .output_path = *output_path,
        });
    }

    return run_http3_client_transfers(
        Http3RuntimeConfig{
            .mode = Http3RuntimeMode::client,
            .server_name = config.server_name,
        },
        jobs);
}
```

and fill the client parser branch:

```cpp
if (subcommand == "h3-interop-client") {
    config.mode = Http3InteropMode::client;
    config.port = parse_port(env_copy("PORT").value_or("443")).value_or(0);
    config.download_root = env_copy("DOWNLOAD_ROOT").value_or("/downloads");
    config.server_name = env_copy("SERVER_NAME").value_or("");
    const auto requests = env_copy("REQUESTS");
    if (!requests.has_value()) {
        return std::nullopt;
    }
    config.requests = split_requests(*requests);
    if (config.requests.empty()) {
        return std::nullopt;
    }
}
```

- [ ] **Step 3: Dispatch `TESTCASE=http3` in the interop wrapper**

Update `interop/entrypoint.sh`:

```bash
supports_testcase() {
  case "$1" in
    handshake | transfer | keyupdate | amplificationlimit | rebind-port | rebind-addr | connectionmigration | ecn | multiconnect | chacha20 | retry | resumption | zerortt | v2 | http3)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

case "${role}" in
server)
  run_setup
  export HOST="${HOST:-::}"
  export PORT="${PORT:-443}"
  export DOCUMENT_ROOT="${DOCUMENT_ROOT:-/www}"
  cert_root="${CERTS:-/certs}"
  export CERTIFICATE_CHAIN_PATH="${CERTIFICATE_CHAIN_PATH:-${cert_root}/cert.pem}"
  export PRIVATE_KEY_PATH="${PRIVATE_KEY_PATH:-${cert_root}/priv.key}"
  if [ "${testcase}" = "http3" ]; then
    exec "${binary}" h3-interop-server
  fi
  exec "${binary}" interop-server
  ;;
client)
  run_setup
  wait_for_sim
  export HOST="${HOST:-}"
  export PORT="${PORT:-443}"
  export SERVER_NAME="${SERVER_NAME:-}"
  export DOWNLOAD_ROOT="${DOWNLOAD_ROOT:-/downloads}"
  if [ "${testcase}" = "http3" ]; then
    exec "${binary}" h3-interop-client
  fi
  exec "${binary}" interop-client
  ;;
esac
```

- [ ] **Step 4: Update the interop README for the protocol split**

Add a dedicated HTTP/3 section in `interop/README.md`:

```md
## HTTP/3 Runner Surface

The existing `interop-server` / `interop-client` commands remain the QUIC
HTTP/0.9 interop surface for the current transport matrix.

The official QUIC testcase `http3` now dispatches to a separate HTTP/3 surface:

- `h3-interop-server`
- `h3-interop-client`

That split is handled inside `interop/entrypoint.sh`. Non-`http3` testcases keep
the current HTTP/0.9 behavior.

Run the local official HTTP/3 lane with:

```bash
INTEROP_TESTCASES=http3 \
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
INTEROP_DIRECTIONS=both \
nix develop -c bash interop/run-official.sh
```
```

- [ ] **Step 5: Run the focused H3 interop and shell dispatch suite**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.*'
bash tests/nix/http3_interop_entrypoint_test.sh
```

Expected:

- the H3 interop parser and loopback client tests pass
- the wrapper dispatch shell test prints `http3 interop entrypoint dispatch looks correct`

- [ ] **Step 6: Commit the H3 interop client and wrapper dispatch**

```bash
git add src/http3/http3_interop.cpp interop/entrypoint.sh interop/README.md tests/http3/interop_test.cpp tests/nix/http3_interop_entrypoint_test.sh
git commit -m "feat: add HTTP/3 interop runner dispatch"
```

### Task 5: Run Full Verification And Official Runner HTTP/3 Validation

**Files:**
- Modify: `src/http3/http3_interop.h`
- Modify: `src/http3/http3_interop.cpp`
- Modify: `src/http3/http3_runtime.h`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `src/main.cpp`
- Modify: `interop/entrypoint.sh`
- Modify: `interop/README.md`
- Modify: `tests/http3/interop_test.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Create: `tests/nix/http3_interop_entrypoint_test.sh`

- [ ] **Step 1: Run the focused C++ and shell suites**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3InteropTest.*:QuicHttp3RuntimeTest.ServerModeCanDisableBootstrapListener'
bash tests/nix/http3_interop_entrypoint_test.sh
```

Expected: PASS.

- [ ] **Step 2: Run the broader HTTP/3 suite**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3*'
```

Expected: PASS for the existing HTTP/3 protocol, QPACK, runtime, bootstrap, and new interop tests.

- [ ] **Step 3: Run a full build**

Run:

```bash
nix develop -c zig build
```

Expected: PASS.

- [ ] **Step 4: Run formatting and static analysis on the touched files**

Run:

```bash
nix develop -c pre-commit run clang-format --files src/http3/http3_interop.h src/http3/http3_interop.cpp src/http3/http3_runtime.h src/http3/http3_runtime.cpp src/main.cpp tests/http3/interop_test.cpp tests/http3/runtime_test.cpp
nix develop -c pre-commit run coquic-clang-tidy --files src/http3/http3_interop.h src/http3/http3_interop.cpp src/http3/http3_runtime.h src/http3/http3_runtime.cpp src/main.cpp tests/http3/interop_test.cpp tests/http3/runtime_test.cpp
```

Expected: PASS.

- [ ] **Step 5: Run the local official-runner HTTP/3 lane**

Run:

```bash
INTEROP_TESTCASES=http3 \
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
INTEROP_DIRECTIONS=both \
nix develop -c bash interop/run-official.sh
```

Expected:

- the official runner executes the `http3` testcase in both directions
- the results JSON includes successful `http3` results for the selected matrix cell(s)
- the wrapper prints `Pinned official interop runner cases passed.`

- [ ] **Step 6: Commit the verified HTTP/3 interop harness slice**

```bash
git add src/http3/http3_interop.h src/http3/http3_interop.cpp src/http3/http3_runtime.h src/http3/http3_runtime.cpp src/main.cpp interop/entrypoint.sh interop/README.md tests/http3/interop_test.cpp tests/http3/runtime_test.cpp tests/nix/http3_interop_entrypoint_test.sh build.zig
git commit -m "feat: add HTTP/3 interop harness"
```

# Interop QLOG Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable `coquic` to emit core-QUIC `.sqlog` files during official interop runs by honoring the standard `QLOGDIR` runtime environment variable.

**Architecture:** Keep the change at the HTTP/0.9 runtime boundary. Add an optional qlog directory field to `Http09RuntimeConfig`, parse `QLOGDIR` from the environment, and forward it into `QuicCoreConfig.qlog` for both client and server runtime factories. Leave the workflow and wrapper logic unchanged because the pinned official runner already injects `QLOGDIR` and copies `/logs` into the uploaded artifact tree.

**Tech Stack:** C++20, Zig build/test flow, GoogleTest, `std::filesystem`, official `quic-interop-runner`

---

## File Map

- `src/quic/http09_runtime.h`: add the runtime-owned optional qlog directory field.
- `src/quic/http09_runtime.cpp`: parse `QLOGDIR` from the environment and wire it into client/server `QuicCoreConfig` construction.
- `tests/quic_http09_runtime_test.cpp`: add parser and factory tests for the runtime qlog path.
- `.github/workflows/interop.yml`: reference only, no modification planned because the existing artifact upload path already preserves runner logs.
- `interop/run-official.sh`: reference only, no modification planned because the pinned runner already exports `QLOGDIR`.

### Task 1: Add failing runtime parser tests for `QLOGDIR`

**Files:**
- Modify: `tests/quic_http09_runtime_test.cpp`
- Modify: `src/quic/http09_runtime.h`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write the failing parser tests**

Add these tests to `tests/quic_http09_runtime_test.cpp` near the existing
environment parsing coverage:

```cpp
TEST(QuicHttp09RuntimeTest, RuntimeLeavesQlogDisabledWhenQlogdirUnsetOrEmpty) {
    const char *argv[] = {"coquic"};

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", std::nullopt);

        const auto parsed = coquic::quic::parse_http09_runtime_args(
            1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_FALSE(parsed->qlog_directory.has_value());
    }

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", "");

        const auto parsed = coquic::quic::parse_http09_runtime_args(
            1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_FALSE(parsed->qlog_directory.has_value());
    }
}

TEST(QuicHttp09RuntimeTest, RuntimeReadsQlogDirectoryFromEnvironment) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
    ScopedEnvVar qlogdir("QLOGDIR", "/logs/qlog");

    const auto parsed =
        coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(parsed->qlog_directory.has_value());
    EXPECT_EQ(*parsed->qlog_directory, std::filesystem::path("/logs/qlog"));
}
```

- [ ] **Step 2: Run the parser tests to verify they fail**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.RuntimeLeavesQlogDisabledWhenQlogdirUnsetOrEmpty:QuicHttp09RuntimeTest.RuntimeReadsQlogDirectoryFromEnvironment'
```

Expected: FAIL to compile because `Http09RuntimeConfig` does not yet expose a
`qlog_directory` field.

- [ ] **Step 3: Add the minimal runtime config field and env parsing**

Modify `src/quic/http09_runtime.h` to add the new field at the end of
`Http09RuntimeConfig` so existing designated initializers keep working:

```cpp
struct Http09RuntimeConfig {
    Http09RuntimeMode mode = Http09RuntimeMode::health_check;
    std::string host = "127.0.0.1";
    std::uint16_t port = 443;
    QuicHttp09Testcase testcase = QuicHttp09Testcase::handshake;
    bool retry_enabled = false;
    std::filesystem::path document_root = "/www";
    std::filesystem::path download_root = "/downloads";
    std::filesystem::path certificate_chain_path = "/certs/cert.pem";
    std::filesystem::path private_key_path = "/certs/priv.key";
    bool verify_peer = false;
    std::string application_protocol = "hq-interop";
    std::string server_name = "localhost";
    std::string requests_env;
    std::optional<std::filesystem::path> qlog_directory;
};
```

Modify `src/quic/http09_runtime.cpp` inside `parse_http09_runtime_args()` to
read `QLOGDIR` after the other path-like environment variables:

```cpp
    if (const auto path = getenv_string("PRIVATE_KEY_PATH"); path.has_value()) {
        config.private_key_path = *path;
    }
    if (const auto qlogdir = getenv_string("QLOGDIR");
        qlogdir.has_value() && !qlogdir->empty()) {
        config.qlog_directory = std::filesystem::path(*qlogdir);
    }
    if (const auto server_name = getenv_string("SERVER_NAME"); server_name.has_value()) {
        config.server_name = *server_name;
        server_name_specified = true;
    }
```

- [ ] **Step 4: Re-run the parser tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.RuntimeLeavesQlogDisabledWhenQlogdirUnsetOrEmpty:QuicHttp09RuntimeTest.RuntimeReadsQlogDirectoryFromEnvironment'
```

Expected: PASS.

- [ ] **Step 5: Commit the parser slice**

Run:

```bash
git add tests/quic_http09_runtime_test.cpp src/quic/http09_runtime.h src/quic/http09_runtime.cpp
git commit -m "feat: parse qlogdir in http09 runtime"
```

Expected: a commit containing only the new runtime qlog config field, env
parsing, and parser tests.

### Task 2: Add failing client/server factory tests and wire `QuicCoreConfig.qlog`

**Files:**
- Modify: `tests/quic_http09_runtime_test.cpp`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write the failing factory propagation test**

Add this test to `tests/quic_http09_runtime_test.cpp` near the existing
`make_http09_client_core_config()` and `make_http09_server_core_config()`
coverage:

```cpp
TEST(QuicHttp09RuntimeTest, RuntimePropagatesQlogDirectoryIntoClientAndServerCoreConfigs) {
    const auto qlog_path = std::filesystem::path("/logs/qlog");

    const auto client_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .requests_env = "https://localhost/a.txt",
        .qlog_directory = qlog_path,
    };
    const auto client_core = coquic::quic::make_http09_client_core_config(client_runtime);
    ASSERT_TRUE(client_core.qlog.has_value());
    EXPECT_EQ(client_core.qlog->directory, qlog_path);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
        .qlog_directory = qlog_path,
    };
    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    ASSERT_TRUE(server_core.qlog.has_value());
    EXPECT_EQ(server_core.qlog->directory, qlog_path);
}
```

- [ ] **Step 2: Run the propagation test to verify it fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.RuntimePropagatesQlogDirectoryIntoClientAndServerCoreConfigs'
```

Expected: FAIL at runtime because the HTTP/0.9 client and server core factory
functions do not yet populate `QuicCoreConfig.qlog`.

- [ ] **Step 3: Wire the runtime qlog directory into both core factories**

Modify `src/quic/http09_runtime.cpp` in
`make_http09_client_core_config(const Http09RuntimeConfig &config)`:

```cpp
QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config) {
    const auto original_version = runtime_original_quic_version_for_testcase(config.testcase);
    const auto transfer_like_testcase = transfer_semantics_testcase(config.testcase);
    auto core = QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .original_version = original_version,
        .initial_version = original_version,
        .supported_versions = runtime_supported_quic_versions_for_testcase(config.testcase),
        .verify_peer = config.verify_peer,
        .server_name = config.server_name.empty() ? "localhost" : config.server_name,
        .application_protocol = std::string(kInteropApplicationProtocol),
        .transport = http09_client_transport_for_testcase(transfer_like_testcase),
        .allowed_tls_cipher_suites = http09_tls_cipher_suites_for_testcase(transfer_like_testcase),
    };
    if (config.qlog_directory.has_value()) {
        core.qlog = QuicQlogConfig{.directory = *config.qlog_directory};
    }
    return core;
}
```

Modify `make_http09_server_core_config_with_identity(...)` the same way:

```cpp
QuicCoreConfig make_http09_server_core_config_with_identity(const Http09RuntimeConfig &config,
                                                            TlsIdentity identity) {
    const auto original_version = runtime_original_quic_version_for_testcase(config.testcase);
    const auto transfer_like_testcase = transfer_semantics_testcase(config.testcase);
    auto core = QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .original_version = original_version,
        .initial_version = original_version,
        .supported_versions = runtime_supported_quic_versions_for_testcase(config.testcase),
        .verify_peer = config.verify_peer,
        .server_name = config.server_name,
        .application_protocol = std::string(kInteropApplicationProtocol),
        .identity = std::move(identity),
        .transport = http09_server_transport_for_testcase(transfer_like_testcase),
        .allowed_tls_cipher_suites = http09_tls_cipher_suites_for_testcase(transfer_like_testcase),
        .zero_rtt =
            QuicZeroRttConfig{
                .allow = config.testcase == QuicHttp09Testcase::zerortt,
            },
    };
    if (config.qlog_directory.has_value()) {
        core.qlog = QuicQlogConfig{.directory = *config.qlog_directory};
    }
    return core;
}
```

- [ ] **Step 4: Re-run the propagation test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.RuntimePropagatesQlogDirectoryIntoClientAndServerCoreConfigs'
```

Expected: PASS.

- [ ] **Step 5: Commit the factory wiring**

Run:

```bash
git add tests/quic_http09_runtime_test.cpp src/quic/http09_runtime.cpp
git commit -m "feat: wire runtime qlog into http09 core config"
```

Expected: a commit containing only the qlog propagation test and the client and
server factory wiring.

### Task 3: Verify the complete runtime and interop qlog contract

**Files:**
- Modify: none
- Test: `tests/quic_http09_runtime_test.cpp`
- Verify: `interop/run-official.sh`

- [ ] **Step 1: Run the full HTTP/0.9 runtime test group**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*'
```

Expected: PASS.

- [ ] **Step 2: Run the full repository test suite**

Run:

```bash
nix develop -c zig build test
```

Expected: PASS.

- [ ] **Step 3: Run a minimal official-runner interop smoke case**

Run:

```bash
INTEROP_TESTCASES=handshake \
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
nix develop -c bash interop/run-official.sh
```

Expected: the script finishes successfully and prints `Pinned official interop
runner cases passed.`

- [ ] **Step 4: Verify that the interop artifacts now contain `.sqlog` files**

Run:

```bash
find .interop-logs/official -type f -name '*.sqlog' -print | sed -n '1,10p'
```

Expected: one or more `.sqlog` paths under the copied client or server log
trees, typically beneath a `qlog/` directory inside the testcase artifacts.

- [ ] **Step 5: Confirm the working tree state after verification**

Run:

```bash
git status --short
```

Expected: no unexpected changes from verification commands; only the intended
runtime/test edits should remain.

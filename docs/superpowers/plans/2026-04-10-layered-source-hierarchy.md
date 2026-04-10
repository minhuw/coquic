# Layered Source Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the production tree into `src/quic`, `src/io`, `src/http09`, and `src/http3`, with matching namespaces and hard layering rules, while preserving the existing behavior and build entry points.

**Architecture:** Execute the move from the bottom of the dependency graph upward: first create an isolated worktree and record a clean baseline, then move HTTP/3, I/O, HTTP/0.9 protocol, and HTTP/0.9 runtime in separate phases. Each phase updates file locations, namespaces, includes, tests, and `build.zig` together so the tree stays buildable after every commit. Finish with a repository-wide old-path cleanup, boundary scans, and full verification.

**Tech Stack:** Zig build graph, C++20, GoogleTest, Bash, ripgrep, git worktrees, Nix dev shell, pre-commit, LLVM coverage

---

## File Map

- Move: `src/quic/io_backend.h` -> `src/io/io_backend.h`
- Move: `src/quic/io_backend_test_hooks.h` -> `src/io/io_backend_test_hooks.h`
- Move: `src/quic/socket_io_backend.cpp` -> `src/io/socket_io_backend.cpp`
- Move: `src/quic/socket_io_backend.h` -> `src/io/socket_io_backend.h`
- Move: `src/quic/http09.cpp` -> `src/http09/http09.cpp`
- Move: `src/quic/http09.h` -> `src/http09/http09.h`
- Move: `src/quic/http09_client.cpp` -> `src/http09/http09_client.cpp`
- Move: `src/quic/http09_client.h` -> `src/http09/http09_client.h`
- Move: `src/quic/http09_server.cpp` -> `src/http09/http09_server.cpp`
- Move: `src/quic/http09_server.h` -> `src/http09/http09_server.h`
- Move: `src/quic/http09_runtime.cpp` -> `src/http09/http09_runtime.cpp`
- Move: `src/quic/http09_runtime.h` -> `src/http09/http09_runtime.h`
- Move: `src/quic/http09_runtime_test_hooks.h` -> `src/http09/http09_runtime_test_hooks.h`
- Move: `src/quic/http3.h` -> `src/http3/http3.h`
- Move: `src/quic/http3_protocol.cpp` -> `src/http3/http3_protocol.cpp`
- Move: `src/quic/http3_protocol.h` -> `src/http3/http3_protocol.h`
- Move: `src/quic/http3_qpack.cpp` -> `src/http3/http3_qpack.cpp`
- Move: `src/quic/http3_qpack.h` -> `src/http3/http3_qpack.h`
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Modify: `src/main.cpp`
- Modify: `tests/support/http09/runtime_test_fixtures.h`
- Modify: `tests/http3/protocol_test.cpp`
- Modify: `tests/http3/qpack_test.cpp`
- Modify: `tests/http09/protocol/http09_test.cpp`
- Modify: `tests/http09/protocol/client_test.cpp`
- Modify: `tests/http09/protocol/server_test.cpp`
- Modify: `tests/http09/runtime/config_test.cpp`
- Modify: `tests/http09/runtime/interop_alias_test.cpp`
- Modify: `tests/http09/runtime/io_test.cpp`
- Modify: `tests/http09/runtime/linux_ecn_test.cpp`
- Modify: `tests/http09/runtime/migration_test.cpp`
- Modify: `tests/http09/runtime/preferred_address_test.cpp`
- Modify: `tests/http09/runtime/retry_zero_rtt_test.cpp`
- Modify: `tests/http09/runtime/routing_test.cpp`
- Modify: `tests/http09/runtime/socket_io_backend_test.cpp`
- Modify: `tests/http09/runtime/startup_test.cpp`
- Modify: `tests/http09/runtime/transfer_test.cpp`
- Modify: `tests/core/connection/ack_test.cpp`
- Modify: `tests/core/connection/connection_id_test.cpp`
- Modify: `tests/core/connection/flow_control_test.cpp`
- Modify: `tests/core/connection/handshake_test.cpp`
- Modify: `tests/core/connection/key_update_test.cpp`
- Modify: `tests/core/connection/migration_test.cpp`
- Modify: `tests/core/connection/path_validation_test.cpp`
- Modify: `tests/core/connection/retry_version_test.cpp`
- Modify: `tests/core/connection/stream_test.cpp`
- Modify: `tests/core/connection/zero_rtt_test.cpp`

### Task 1: Create An Isolated Worktree And Capture The Baseline

**Files:**
- Create: `.worktrees/layered-source-hierarchy/`
- Modify: none

- [ ] **Step 1: Create the dedicated worktree and branch**

Run:

```bash
git worktree add .worktrees/layered-source-hierarchy \
  -b refactor/layered-source-hierarchy HEAD
cd .worktrees/layered-source-hierarchy
```

Expected: `git branch --show-current` prints `refactor/layered-source-hierarchy`.

- [ ] **Step 2: Record the pre-refactor baseline**

Run:

```bash
nix develop -c zig build test
nix develop -c zig build coverage
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: all four commands pass before any moves start.

- [ ] **Step 3: Create the target top-level directories**

Run:

```bash
mkdir -p src/io src/http09 src/http3
test -d src/io
test -d src/http09
test -d src/http3
```

Expected: all three `test -d` commands succeed.

### Task 2: Move The HTTP/3 Layer

**Files:**
- Move: `src/quic/http3.h` -> `src/http3/http3.h`
- Move: `src/quic/http3_protocol.cpp` -> `src/http3/http3_protocol.cpp`
- Move: `src/quic/http3_protocol.h` -> `src/http3/http3_protocol.h`
- Move: `src/quic/http3_qpack.cpp` -> `src/http3/http3_qpack.cpp`
- Move: `src/quic/http3_qpack.h` -> `src/http3/http3_qpack.h`
- Modify: `build.zig`
- Modify: `tests/http3/protocol_test.cpp`
- Modify: `tests/http3/qpack_test.cpp`
- Modify: `tests/core/connection/ack_test.cpp`
- Modify: `tests/core/connection/connection_id_test.cpp`
- Modify: `tests/core/connection/flow_control_test.cpp`
- Modify: `tests/core/connection/handshake_test.cpp`
- Modify: `tests/core/connection/key_update_test.cpp`
- Modify: `tests/core/connection/migration_test.cpp`
- Modify: `tests/core/connection/path_validation_test.cpp`
- Modify: `tests/core/connection/retry_version_test.cpp`
- Modify: `tests/core/connection/stream_test.cpp`
- Modify: `tests/core/connection/zero_rtt_test.cpp`

- [ ] **Step 1: Update the HTTP/3 test and core-test includes before moving the files**

Apply these replacements:

```cpp
// tests/http3/protocol_test.cpp
#include "src/http3/http3_protocol.h"

// tests/http3/qpack_test.cpp
#include "src/http3/http3_qpack.h"

// tests/core/connection/*.cpp that currently include src/quic/http3.h
#include "src/http3/http3.h"
```

And update HTTP/3 qualifications to the new namespace form:

```cpp
static_assert(std::is_same_v<decltype(coquic::http3::kHttp3ApplicationProtocol),
                             const std::string_view>);

const auto failed = coquic::http3::Http3Result<bool>::failure(coquic::http3::Http3Error{
    .code = coquic::http3::Http3ErrorCode::missing_settings,
    .detail = "missing settings",
    .stream_id = 7,
});
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3*'
```

Expected: FAIL with a missing-header error for `src/http3/http3_protocol.h`, `src/http3/http3_qpack.h`, or `src/http3/http3.h`.

- [ ] **Step 2: Move the HTTP/3 files into the new directory**

Run:

```bash
git mv src/quic/http3.h src/http3/http3.h
git mv src/quic/http3_protocol.cpp src/http3/http3_protocol.cpp
git mv src/quic/http3_protocol.h src/http3/http3_protocol.h
git mv src/quic/http3_qpack.cpp src/http3/http3_qpack.cpp
git mv src/quic/http3_qpack.h src/http3/http3_qpack.h
```

Expected: `git status --short` shows five renames under `src/http3/`.

- [ ] **Step 3: Rewrite the moved HTTP/3 files to the new namespace and internal include paths**

Apply these header/source forms:

```cpp
// src/http3/http3_protocol.h
#include "src/http3/http3.h"
#include "src/quic/varint.h"

namespace coquic::http3 {
```

```cpp
// src/http3/http3_qpack.h
#include "src/http3/http3.h"
#include "src/quic/varint.h"

namespace coquic::http3 {
```

```cpp
// src/http3/http3_protocol.cpp and src/http3/http3_qpack.cpp
#include "src/http3/http3_protocol.h"
// or
#include "src/http3/http3_qpack.h"

namespace coquic::http3 {
```

Expected: no moved HTTP/3 file still includes `src/quic/http3` or opens `namespace coquic::quic`.

- [ ] **Step 4: Update `build.zig` to compile the moved HTTP/3 sources**

In the `files.appendSlice(&.{ ... })` block inside `addProjectLibrary`, replace the two HTTP/3 entries with:

```zig
        "src/http3/http3_protocol.cpp",
        "src/http3/http3_qpack.cpp",
```

Expected: `rg -n 'src/quic/http3_(protocol|qpack)|src/quic/http3\\.h' build.zig src tests` no longer reports old HTTP/3 paths.

- [ ] **Step 5: Verify the HTTP/3 move**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp3*'
```

Expected: PASS. The HTTP/3 tests run, and the core connection tests still compile with the new `src/http3/http3.h` include.

- [ ] **Step 6: Commit the HTTP/3 layer move**

Run:

```bash
git add build.zig src/http3 tests/http3 \
  tests/core/connection/ack_test.cpp \
  tests/core/connection/connection_id_test.cpp \
  tests/core/connection/flow_control_test.cpp \
  tests/core/connection/handshake_test.cpp \
  tests/core/connection/key_update_test.cpp \
  tests/core/connection/migration_test.cpp \
  tests/core/connection/path_validation_test.cpp \
  tests/core/connection/retry_version_test.cpp \
  tests/core/connection/stream_test.cpp \
  tests/core/connection/zero_rtt_test.cpp
git commit -m "refactor: move http3 sources into layered namespace"
```

### Task 3: Move The I/O Layer

**Files:**
- Move: `src/quic/io_backend.h` -> `src/io/io_backend.h`
- Move: `src/quic/io_backend_test_hooks.h` -> `src/io/io_backend_test_hooks.h`
- Move: `src/quic/socket_io_backend.cpp` -> `src/io/socket_io_backend.cpp`
- Move: `src/quic/socket_io_backend.h` -> `src/io/socket_io_backend.h`
- Modify: `build.zig`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/http09_runtime_test_hooks.h`
- Modify: `tests/http09/runtime/socket_io_backend_test.cpp`

- [ ] **Step 1: Point the socket-backend test at the future I/O paths**

Apply these include and namespace updates:

```cpp
// tests/http09/runtime/socket_io_backend_test.cpp
#include "src/io/io_backend_test_hooks.h"
#include "src/io/socket_io_backend.h"

using namespace coquic::io;

auto backend = coquic::io::make_socket_io_backend(coquic::io::SocketIoBackendConfig{
    .role_name = "client",
    .idle_timeout_ms = 5,
});
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='SocketIoBackendTest.*'
```

Expected: FAIL with a missing-header error for `src/io/socket_io_backend.h` or `src/io/io_backend_test_hooks.h`.

- [ ] **Step 2: Move the I/O files into `src/io/`**

Run:

```bash
git mv src/quic/io_backend.h src/io/io_backend.h
git mv src/quic/io_backend_test_hooks.h src/io/io_backend_test_hooks.h
git mv src/quic/socket_io_backend.cpp src/io/socket_io_backend.cpp
git mv src/quic/socket_io_backend.h src/io/socket_io_backend.h
```

Expected: `git status --short` shows four renames under `src/io/`.

- [ ] **Step 3: Rewrite the moved I/O files to `coquic::io` and update the runtime consumers**

Use these forms:

```cpp
// src/io/io_backend.h
#include "src/quic/core.h"

namespace coquic::io {
```

```cpp
// src/io/socket_io_backend.h
#include "src/io/io_backend.h"

namespace coquic::io {
```

```cpp
// src/io/socket_io_backend.cpp
#include "src/io/socket_io_backend.h"
#include "src/io/io_backend_test_hooks.h"

namespace coquic::io {
```

And update the runtime-side includes in the still-unmoved runtime files:

```cpp
// src/quic/http09_runtime.cpp
#include "src/io/socket_io_backend.h"

namespace test {
using Http09RuntimeOpsOverride = coquic::io::test::SocketIoBackendOpsOverride;
using ScopedHttp09RuntimeOpsOverride = coquic::io::test::ScopedSocketIoBackendOpsOverride;
}
```

```cpp
// src/quic/http09_runtime_test_hooks.h
#include "src/io/io_backend_test_hooks.h"
```

Expected: `rg -n 'src/quic/(io_backend|socket_io_backend)' src tests` reports no remaining uses.

- [ ] **Step 4: Update `build.zig` to compile the moved socket backend**

In the `files.appendSlice(&.{ ... })` block, replace the old socket backend entry with:

```zig
        "src/io/socket_io_backend.cpp",
```

Expected: `rg -n 'src/quic/socket_io_backend\\.cpp|src/quic/io_backend' build.zig src tests` reports no matches.

- [ ] **Step 5: Verify the I/O layer move**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='SocketIoBackendTest.*:QuicHttp09RuntimeTest.RuntimeHelperHooksDriveClientConnectionBackendLoopCases:QuicHttp09RuntimeTest.RuntimeHelperHooksDriveServerBackendLoopCases:QuicHttp09RuntimeTest.RuntimeLowLevelHooksExerciseSocketAndEcnFallbacks'
```

Expected: PASS. The socket backend tests and the backend-oriented runtime hook coverage all compile and run against `coquic::io`.

- [ ] **Step 6: Commit the I/O layer move**

Run:

```bash
git add build.zig src/io \
  src/quic/http09_runtime.cpp \
  src/quic/http09_runtime_test_hooks.h \
  tests/http09/runtime/socket_io_backend_test.cpp
git commit -m "refactor: move io backend into layered namespace"
```

### Task 4: Move The HTTP/0.9 Protocol Layer

**Files:**
- Move: `src/quic/http09.cpp` -> `src/http09/http09.cpp`
- Move: `src/quic/http09.h` -> `src/http09/http09.h`
- Move: `src/quic/http09_client.cpp` -> `src/http09/http09_client.cpp`
- Move: `src/quic/http09_client.h` -> `src/http09/http09_client.h`
- Move: `src/quic/http09_server.cpp` -> `src/http09/http09_server.cpp`
- Move: `src/quic/http09_server.h` -> `src/http09/http09_server.h`
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Modify: `src/quic/http09_runtime.h`
- Modify: `tests/http09/protocol/http09_test.cpp`
- Modify: `tests/http09/protocol/client_test.cpp`
- Modify: `tests/http09/protocol/server_test.cpp`

- [ ] **Step 1: Update the HTTP/0.9 protocol tests and public umbrella header before moving files**

Apply these include and namespace updates:

```cpp
// src/coquic.h
#include "src/http09/http09.h"
```

```cpp
// tests/http09/protocol/http09_test.cpp
#include "src/http09/http09.h"

const auto parsed =
    coquic::http09::parse_http09_requests_env("https://example.test/a https://example.test/b/c");
```

```cpp
// tests/http09/protocol/client_test.cpp
#include "src/http09/http09_client.h"
```

```cpp
// tests/http09/protocol/server_test.cpp
#include "src/http09/http09_server.h"
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09Test.*:QuicHttp09ClientTest.*:QuicHttp09ServerTest.*'
```

Expected: FAIL with a missing-header error for one of the new `src/http09/*` paths.

- [ ] **Step 2: Move the HTTP/0.9 protocol files**

Run:

```bash
git mv src/quic/http09.cpp src/http09/http09.cpp
git mv src/quic/http09.h src/http09/http09.h
git mv src/quic/http09_client.cpp src/http09/http09_client.cpp
git mv src/quic/http09_client.h src/http09/http09_client.h
git mv src/quic/http09_server.cpp src/http09/http09_server.cpp
git mv src/quic/http09_server.h src/http09/http09_server.h
```

Expected: `git status --short` shows six renames under `src/http09/`.

- [ ] **Step 3: Rewrite the moved HTTP/0.9 protocol files to `coquic::http09`**

Use these forms:

```cpp
// src/http09/http09.h
#include "src/quic/core.h"
#include "src/quic/varint.h"

namespace coquic::http09 {
```

```cpp
// src/http09/http09_client.h
#include "src/http09/http09.h"

namespace coquic::http09 {
```

```cpp
// src/http09/http09_server.h
#include "src/http09/http09.h"

namespace coquic::http09 {
```

```cpp
// src/http09/http09.cpp, src/http09/http09_client.cpp, src/http09/http09_server.cpp
#include "src/http09/http09.h"
// or the corresponding client/server header

namespace coquic::http09 {
```

Also update the still-unmoved runtime header to include the new protocol headers:

```cpp
// src/quic/http09_runtime.h
#include "src/http09/http09_client.h"
#include "src/http09/http09_server.h"
```

Expected: `rg -n 'src/quic/http09(_client|_server)?\\.h|src/quic/http09\\.h' src tests` reports no matches.

- [ ] **Step 4: Update `build.zig` to compile the moved HTTP/0.9 protocol sources**

In the `files.appendSlice(&.{ ... })` block, replace the three protocol entries with:

```zig
        "src/http09/http09.cpp",
        "src/http09/http09_client.cpp",
        "src/http09/http09_server.cpp",
```

Expected: the only remaining `src/quic/http09_runtime.cpp` reference in `build.zig` is the runtime source, which moves in the next task.

- [ ] **Step 5: Verify the HTTP/0.9 protocol move**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09Test.*:QuicHttp09ClientTest.*:QuicHttp09ServerTest.*'
```

Expected: PASS. The protocol tests compile and run from `coquic::http09`.

- [ ] **Step 6: Commit the HTTP/0.9 protocol move**

Run:

```bash
git add build.zig src/coquic.h src/http09 \
  src/quic/http09_runtime.h \
  tests/http09/protocol/http09_test.cpp \
  tests/http09/protocol/client_test.cpp \
  tests/http09/protocol/server_test.cpp
git commit -m "refactor: move http09 protocol into layered namespace"
```

### Task 5: Move The HTTP/0.9 Runtime Layer

**Files:**
- Move: `src/quic/http09_runtime.cpp` -> `src/http09/http09_runtime.cpp`
- Move: `src/quic/http09_runtime.h` -> `src/http09/http09_runtime.h`
- Move: `src/quic/http09_runtime_test_hooks.h` -> `src/http09/http09_runtime_test_hooks.h`
- Modify: `build.zig`
- Modify: `src/main.cpp`
- Modify: `tests/support/http09/runtime_test_fixtures.h`
- Modify: `tests/http09/runtime/config_test.cpp`
- Modify: `tests/http09/runtime/interop_alias_test.cpp`
- Modify: `tests/http09/runtime/io_test.cpp`
- Modify: `tests/http09/runtime/linux_ecn_test.cpp`
- Modify: `tests/http09/runtime/migration_test.cpp`
- Modify: `tests/http09/runtime/preferred_address_test.cpp`
- Modify: `tests/http09/runtime/retry_zero_rtt_test.cpp`
- Modify: `tests/http09/runtime/routing_test.cpp`
- Modify: `tests/http09/runtime/socket_io_backend_test.cpp`
- Modify: `tests/http09/runtime/startup_test.cpp`
- Modify: `tests/http09/runtime/transfer_test.cpp`

- [ ] **Step 1: Update `src/main.cpp`, test fixtures, and runtime tests to the future runtime path**

Apply these forms:

```cpp
// src/main.cpp
#include "src/http09/http09_runtime.h"

int main(int argc, char **argv) {
    const auto config = coquic::http09::parse_http09_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::http09::run_http09_runtime(*config);
}
```

```cpp
// tests/support/http09/runtime_test_fixtures.h
#include "src/http09/http09_runtime.h"
#include "src/http09/http09_runtime_test_hooks.h"

namespace coquic::http09::test_support {
```

```cpp
// every tests/http09/runtime/*.cpp file
#include "src/http09/http09_runtime.h"
```

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*'
```

Expected: FAIL with a missing-header error for `src/http09/http09_runtime.h` or `src/http09/http09_runtime_test_hooks.h`.

- [ ] **Step 2: Move the runtime files into `src/http09/`**

Run:

```bash
git mv src/quic/http09_runtime.cpp src/http09/http09_runtime.cpp
git mv src/quic/http09_runtime.h src/http09/http09_runtime.h
git mv src/quic/http09_runtime_test_hooks.h src/http09/http09_runtime_test_hooks.h
```

Expected: `git status --short` shows three renames under `src/http09/`.

- [ ] **Step 3: Rewrite the moved runtime files to `coquic::http09` and the new include graph**

Use these forms:

```cpp
// src/http09/http09_runtime.h
#include "src/http09/http09_client.h"
#include "src/http09/http09_server.h"

namespace coquic::http09 {
```

```cpp
// src/http09/http09_runtime_test_hooks.h
#include "src/http09/http09_runtime.h"
#include "src/io/io_backend_test_hooks.h"
#include "src/quic/packet.h"

namespace coquic::http09::test {
```

```cpp
// src/http09/http09_runtime.cpp
#include "src/http09/http09_runtime.h"
#include "src/http09/http09_runtime_test_hooks.h"
#include "src/io/socket_io_backend.h"
#include "src/quic/buffer.h"
#include "src/quic/packet.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/version.h"

namespace coquic::http09 {
```

Also update all runtime-test code to use the new namespace, for example:

```cpp
const auto config = coquic::http09::parse_http09_runtime_args(argc, argv);
EXPECT_TRUE(coquic::http09::test::runtime_low_level_socket_and_ecn_coverage_for_tests());
```

Expected: `rg -n 'src/quic/http09_runtime|coquic::quic::parse_http09_runtime_args|coquic::quic::run_http09_runtime' src tests` reports no matches.

- [ ] **Step 4: Update `build.zig` to compile the moved runtime source**

In the `files.appendSlice(&.{ ... })` block, replace the remaining runtime entry with:

```zig
        "src/http09/http09_runtime.cpp",
```

Expected: the source list now references `src/http09/*`, `src/http3/*`, and `src/io/*` for the moved layers.

- [ ] **Step 5: Verify the runtime move**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicHttp09RuntimeTest.*'
```

Expected: PASS. The full HTTP/0.9 runtime test binary compiles and runs against `coquic::http09` and `coquic::io`.

- [ ] **Step 6: Commit the runtime move**

Run:

```bash
git add build.zig src/main.cpp src/http09 \
  tests/support/http09/runtime_test_fixtures.h \
  tests/http09/runtime/config_test.cpp \
  tests/http09/runtime/interop_alias_test.cpp \
  tests/http09/runtime/io_test.cpp \
  tests/http09/runtime/linux_ecn_test.cpp \
  tests/http09/runtime/migration_test.cpp \
  tests/http09/runtime/preferred_address_test.cpp \
  tests/http09/runtime/retry_zero_rtt_test.cpp \
  tests/http09/runtime/routing_test.cpp \
  tests/http09/runtime/socket_io_backend_test.cpp \
  tests/http09/runtime/startup_test.cpp \
  tests/http09/runtime/transfer_test.cpp
git commit -m "refactor: move http09 runtime into layered namespace"
```

### Task 6: Sweep Remaining Old Paths And Finalize Root Composition

**Files:**
- Modify: `src/coquic.h`
- Modify: `src/main.cpp`
- Modify: `build.zig`
- Modify: any file still reported by the repository-wide old-path scan

- [ ] **Step 1: Scan for old moved-path includes and old moved-layer namespaces**

Run:

```bash
rg -n 'src/quic/(http09|http3|io_backend|socket_io_backend|http09_runtime)' src tests build.zig
rg -n 'coquic::quic::(parse_http09|run_http09|QuicHttp09|Http3|SocketIoBackend|QuicIo|kHttp3ApplicationProtocol)' src tests
```

Expected: both commands print no matches. If either command prints a file, edit that file immediately in this task.

- [ ] **Step 2: Normalize the root composition headers**

`src/coquic.h` should have exactly these moved-layer includes:

```cpp
#include "src/quic/core.h"
#include "src/http09/http09.h"
#include "src/quic/plaintext_codec.h"
#include "src/quic/protected_codec.h"
```

`src/main.cpp` should still include only:

```cpp
#include "src/http09/http09_runtime.h"
```

Expected: `src/coquic.h` and `src/main.cpp` are the only root files that include top-layer headers directly.

- [ ] **Step 3: Rebuild the compile database after the include sweep**

Run:

```bash
nix develop -c zig build compdb
```

Expected: PASS. The full project and all test binaries compile in the new layered layout.

- [ ] **Step 4: Commit the old-path cleanup**

Run:

```bash
git add build.zig src/coquic.h src/main.cpp src tests
git commit -m "refactor: finalize layered source hierarchy wiring"
```

### Task 7: Enforce The Layering Rules And Run Final Verification

**Files:**
- Modify: none unless a boundary scan finds a violation

- [ ] **Step 1: Run explicit dependency-boundary scans**

Run:

```bash
! rg -n '#include "src/(io|http09|http3)/' src/quic
! rg -n '#include "src/(http09|http3)/' src/io
! rg -n 'namespace coquic::(io|http09|http3)|coquic::(io|http09|http3)::' src/quic
! rg -n 'namespace coquic::(http09|http3)|coquic::(http09|http3)::' src/io
```

Expected: all four commands exit successfully with no matches.

- [ ] **Step 2: Run the full verification suite**

Run:

```bash
nix develop -c zig build test
nix develop -c zig build coverage
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: all four commands pass from the layered tree.

- [ ] **Step 3: Commit the verified refactor**

Run:

```bash
git add build.zig src tests
git commit -m "refactor: enforce layered source hierarchy"
```

- [ ] **Step 4: Prepare the branch for review**

Run:

```bash
git status --short
git log --oneline --max-count=5
```

Expected: `git status --short` prints nothing, and the recent commit list shows the HTTP/3, I/O, HTTP/0.9 protocol, runtime, and final verification commits in order.

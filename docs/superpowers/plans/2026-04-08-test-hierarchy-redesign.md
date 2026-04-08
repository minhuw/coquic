# Repo-Wide Test Hierarchy Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize `tests/` into a domain-oriented hierarchy with smaller translation units and six area-specific GoogleTest executables, while preserving behavior, coverage, and the existing `zig build test` and `zig build coverage` entry points.

**Architecture:** First create the target directory skeleton, move shared support behind a temporary compatibility shim, and relocate the already-small standalone test files without changing behavior. Then extract shared fixtures from `tests/quic_core_test.cpp` and `tests/quic_http09_runtime_test.cpp`, split those oversized translation units into behavior-oriented files, and finally rewire `build.zig`, `zig build compdb`, and `scripts/run-coverage.sh` around six area binaries. Finish by deleting the shim, refreshing `compile_commands.json`, and comparing all-files `clang-tidy` wall time before and after the reorg.

**Tech Stack:** Zig build graph, C++20, GoogleTest, Bash, Nix dev shell, pre-commit `clang-tidy`, LLVM coverage tools

---

## File Map

- Move: `tests/quic_test_utils.h` -> `tests/support/quic_test_utils.h`
- Create: `tests/quic_test_utils.h` temporary compatibility shim during the migration
- Create: `tests/support/core/connection_test_fixtures.h`
- Create: `tests/support/http09/runtime_test_fixtures.h`
- Move: `tests/smoke.cpp` -> `tests/smoke/smoke_test.cpp`
- Move: `tests/quic_congestion_test.cpp` -> `tests/core/recovery/congestion_test.cpp`
- Move: `tests/quic_recovery_test.cpp` -> `tests/core/recovery/recovery_test.cpp`
- Move: `tests/quic_frame_test.cpp` -> `tests/core/packets/frame_test.cpp`
- Move: `tests/quic_packet_test.cpp` -> `tests/core/packets/packet_test.cpp`
- Move: `tests/quic_packet_number_test.cpp` -> `tests/core/packets/packet_number_test.cpp`
- Move: `tests/quic_plaintext_codec_test.cpp` -> `tests/core/packets/plaintext_codec_test.cpp`
- Move: `tests/quic_protected_codec_test.cpp` -> `tests/core/packets/protected_codec_test.cpp`
- Move: `tests/quic_transport_parameters_test.cpp` -> `tests/core/packets/transport_parameters_test.cpp`
- Move: `tests/quic_varint_test.cpp` -> `tests/core/packets/varint_test.cpp`
- Move: `tests/quic_streams_test.cpp` -> `tests/core/streams/streams_test.cpp`
- Move: `tests/quic_crypto_stream_test.cpp` -> `tests/core/streams/crypto_stream_test.cpp`
- Move: `tests/quic_packet_crypto_test.cpp` -> `tests/tls/packet_crypto_test.cpp`
- Move: `tests/quic_tls_adapter_contract_test.cpp` -> `tests/tls/tls_adapter_contract_test.cpp`
- Move: `tests/quic_http09_test.cpp` -> `tests/http09/protocol/http09_test.cpp`
- Move: `tests/quic_http09_server_test.cpp` -> `tests/http09/protocol/server_test.cpp`
- Move: `tests/quic_http09_client_test.cpp` -> `tests/http09/protocol/client_test.cpp`
- Move: `tests/quic_http3_protocol_test.cpp` -> `tests/http3/protocol_test.cpp`
- Move: `tests/quic_http3_qpack_test.cpp` -> `tests/http3/qpack_test.cpp`
- Move: `tests/quic_qlog_test.cpp` -> `tests/qlog/qlog_test.cpp`
- Create: `tests/qlog/core_integration_test.cpp`
- Split: `tests/quic_core_test.cpp` into
  - `tests/core/connection/handshake_test.cpp`
  - `tests/core/connection/zero_rtt_test.cpp`
  - `tests/core/connection/connection_id_test.cpp`
  - `tests/core/connection/stream_test.cpp`
  - `tests/core/connection/flow_control_test.cpp`
  - `tests/core/connection/ack_test.cpp`
  - `tests/core/connection/migration_test.cpp`
  - `tests/core/connection/path_validation_test.cpp`
  - `tests/core/connection/retry_version_test.cpp`
  - `tests/core/connection/key_update_test.cpp`
- Split: `tests/quic_http09_runtime_test.cpp` into
  - `tests/http09/runtime/transfer_test.cpp`
  - `tests/http09/runtime/startup_test.cpp`
  - `tests/http09/runtime/config_test.cpp`
  - `tests/http09/runtime/io_test.cpp`
  - `tests/http09/runtime/routing_test.cpp`
  - `tests/http09/runtime/migration_test.cpp`
  - `tests/http09/runtime/preferred_address_test.cpp`
  - `tests/http09/runtime/retry_zero_rtt_test.cpp`
  - `tests/http09/runtime/interop_alias_test.cpp`
  - `tests/http09/runtime/linux_ecn_test.cpp`
- Modify: `build.zig`
- Modify: `scripts/run-coverage.sh`
- Delete: `tests/quic_core_test.cpp`
- Delete: `tests/quic_http09_runtime_test.cpp`
- Delete: `tests/quic_test_utils.h` after all includes are updated

### Task 1: Capture Baseline And Create The Target Skeleton

**Files:**
- Move: `tests/quic_test_utils.h` -> `tests/support/quic_test_utils.h`
- Create: `tests/quic_test_utils.h`
- Move: `tests/smoke.cpp` -> `tests/smoke/smoke_test.cpp`
- Modify: `build.zig`

- [ ] **Step 1: Record the current baseline before any moves**

Run:

```bash
/usr/bin/time -f 'REFRESH_ELAPSED=%e' \
  nix develop -c ./scripts/refresh-compile-commands.sh
/usr/bin/time -f 'LINT_ELAPSED=%e' \
  nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
/usr/bin/time -f 'TEST_ELAPSED=%e' \
  nix develop -c zig build test
```

Expected: all three commands pass. Save the three reported numbers in task notes because the final report compares against them.

- [ ] **Step 2: Create the directory hierarchy and move the smoke test plus shared utility header**

Run:

```bash
mkdir -p \
  tests/support/core \
  tests/support/http09 \
  tests/smoke \
  tests/core/connection \
  tests/core/recovery \
  tests/core/packets \
  tests/core/streams \
  tests/http09/protocol \
  tests/http09/runtime \
  tests/http3 \
  tests/qlog \
  tests/tls

git mv tests/smoke.cpp tests/smoke/smoke_test.cpp
git mv tests/quic_test_utils.h tests/support/quic_test_utils.h
```

Expected: `git status --short` shows the two moves, and `test -d tests/core/connection && test -d tests/http09/runtime` succeeds.

- [ ] **Step 3: Add the temporary compatibility shim at the old utility-header path**

Create `tests/quic_test_utils.h` with exactly:

```cpp
#pragma once

#include "tests/support/quic_test_utils.h"
```

Expected: every existing source that still includes `tests/quic_test_utils.h` keeps compiling unchanged.

- [ ] **Step 4: Point `build.zig` at the moved smoke file without changing the rest of the source list yet**

In `build.zig`, replace the first entry in the current flat test source list:

```zig
    const default_test_files = &.{
        "tests/smoke/smoke_test.cpp",
        "tests/quic_core_test.cpp",
        "tests/quic_congestion_test.cpp",
        "tests/quic_frame_test.cpp",
        "tests/quic_crypto_stream_test.cpp",
        "tests/quic_packet_test.cpp",
        "tests/quic_packet_number_test.cpp",
        "tests/quic_packet_crypto_test.cpp",
        "tests/quic_plaintext_codec_test.cpp",
        "tests/quic_http09_test.cpp",
        "tests/quic_http09_server_test.cpp",
        "tests/quic_http09_client_test.cpp",
        "tests/quic_http09_runtime_test.cpp",
        "tests/quic_http3_protocol_test.cpp",
        "tests/quic_http3_qpack_test.cpp",
        "tests/quic_qlog_test.cpp",
        "tests/quic_recovery_test.cpp",
        "tests/quic_streams_test.cpp",
        "tests/quic_protected_codec_test.cpp",
        "tests/quic_tls_adapter_contract_test.cpp",
        "tests/quic_transport_parameters_test.cpp",
        "tests/quic_varint_test.cpp",
    };
```

Expected: only the smoke path changes in this step.

- [ ] **Step 5: Verify the scaffold builds with the shim in place**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='*Smoke*'
```

Expected: the smoke-focused run passes.

- [ ] **Step 6: Commit the scaffolding change**

Run:

```bash
git add build.zig tests/smoke/smoke_test.cpp tests/support/quic_test_utils.h tests/quic_test_utils.h
git commit -m "refactor: scaffold hierarchical test tree"
```

### Task 2: Move The Small Standalone Test Files Into The New Tree

**Files:**
- Move: `tests/quic_congestion_test.cpp` -> `tests/core/recovery/congestion_test.cpp`
- Move: `tests/quic_recovery_test.cpp` -> `tests/core/recovery/recovery_test.cpp`
- Move: `tests/quic_frame_test.cpp` -> `tests/core/packets/frame_test.cpp`
- Move: `tests/quic_packet_test.cpp` -> `tests/core/packets/packet_test.cpp`
- Move: `tests/quic_packet_number_test.cpp` -> `tests/core/packets/packet_number_test.cpp`
- Move: `tests/quic_plaintext_codec_test.cpp` -> `tests/core/packets/plaintext_codec_test.cpp`
- Move: `tests/quic_protected_codec_test.cpp` -> `tests/core/packets/protected_codec_test.cpp`
- Move: `tests/quic_transport_parameters_test.cpp` -> `tests/core/packets/transport_parameters_test.cpp`
- Move: `tests/quic_varint_test.cpp` -> `tests/core/packets/varint_test.cpp`
- Move: `tests/quic_streams_test.cpp` -> `tests/core/streams/streams_test.cpp`
- Move: `tests/quic_crypto_stream_test.cpp` -> `tests/core/streams/crypto_stream_test.cpp`
- Move: `tests/quic_packet_crypto_test.cpp` -> `tests/tls/packet_crypto_test.cpp`
- Move: `tests/quic_tls_adapter_contract_test.cpp` -> `tests/tls/tls_adapter_contract_test.cpp`
- Move: `tests/quic_http09_test.cpp` -> `tests/http09/protocol/http09_test.cpp`
- Move: `tests/quic_http09_server_test.cpp` -> `tests/http09/protocol/server_test.cpp`
- Move: `tests/quic_http09_client_test.cpp` -> `tests/http09/protocol/client_test.cpp`
- Move: `tests/quic_http3_protocol_test.cpp` -> `tests/http3/protocol_test.cpp`
- Move: `tests/quic_http3_qpack_test.cpp` -> `tests/http3/qpack_test.cpp`
- Move: `tests/quic_qlog_test.cpp` -> `tests/qlog/qlog_test.cpp`
- Modify: `build.zig`

- [ ] **Step 1: Move every already-small test file into its target directory**

Run:

```bash
git mv tests/quic_congestion_test.cpp tests/core/recovery/congestion_test.cpp
git mv tests/quic_recovery_test.cpp tests/core/recovery/recovery_test.cpp
git mv tests/quic_frame_test.cpp tests/core/packets/frame_test.cpp
git mv tests/quic_packet_test.cpp tests/core/packets/packet_test.cpp
git mv tests/quic_packet_number_test.cpp tests/core/packets/packet_number_test.cpp
git mv tests/quic_plaintext_codec_test.cpp tests/core/packets/plaintext_codec_test.cpp
git mv tests/quic_protected_codec_test.cpp tests/core/packets/protected_codec_test.cpp
git mv tests/quic_transport_parameters_test.cpp tests/core/packets/transport_parameters_test.cpp
git mv tests/quic_varint_test.cpp tests/core/packets/varint_test.cpp
git mv tests/quic_streams_test.cpp tests/core/streams/streams_test.cpp
git mv tests/quic_crypto_stream_test.cpp tests/core/streams/crypto_stream_test.cpp
git mv tests/quic_packet_crypto_test.cpp tests/tls/packet_crypto_test.cpp
git mv tests/quic_tls_adapter_contract_test.cpp tests/tls/tls_adapter_contract_test.cpp
git mv tests/quic_http09_test.cpp tests/http09/protocol/http09_test.cpp
git mv tests/quic_http09_server_test.cpp tests/http09/protocol/server_test.cpp
git mv tests/quic_http09_client_test.cpp tests/http09/protocol/client_test.cpp
git mv tests/quic_http3_protocol_test.cpp tests/http3/protocol_test.cpp
git mv tests/quic_http3_qpack_test.cpp tests/http3/qpack_test.cpp
git mv tests/quic_qlog_test.cpp tests/qlog/qlog_test.cpp
```

Expected: `git status --short` shows only renames for these files.

- [ ] **Step 2: Rewrite the flat paths in `build.zig` to the new leaf locations**

Update the flat list in `build.zig` to exactly:

```zig
    const default_test_files = &.{
        "tests/smoke/smoke_test.cpp",
        "tests/quic_core_test.cpp",
        "tests/core/recovery/congestion_test.cpp",
        "tests/core/packets/frame_test.cpp",
        "tests/core/streams/crypto_stream_test.cpp",
        "tests/core/packets/packet_test.cpp",
        "tests/core/packets/packet_number_test.cpp",
        "tests/tls/packet_crypto_test.cpp",
        "tests/core/packets/plaintext_codec_test.cpp",
        "tests/http09/protocol/http09_test.cpp",
        "tests/http09/protocol/server_test.cpp",
        "tests/http09/protocol/client_test.cpp",
        "tests/quic_http09_runtime_test.cpp",
        "tests/http3/protocol_test.cpp",
        "tests/http3/qpack_test.cpp",
        "tests/qlog/qlog_test.cpp",
        "tests/core/recovery/recovery_test.cpp",
        "tests/core/streams/streams_test.cpp",
        "tests/core/packets/protected_codec_test.cpp",
        "tests/tls/tls_adapter_contract_test.cpp",
        "tests/core/packets/transport_parameters_test.cpp",
        "tests/core/packets/varint_test.cpp",
    };
```

Expected: `tests/quic_core_test.cpp` and `tests/quic_http09_runtime_test.cpp` stay in place for now.

- [ ] **Step 3: Verify representative moved suites still run from the new locations**

Run:

```bash
nix develop -c zig build test -- \
  --gtest_filter='QuicFrameTest.*:QuicPacketTest.*:QuicHttp3ProtocolTest.*:QuicQlogTest.*:QuicHttp09ClientTest.*'
```

Expected: the selected suites pass.

- [ ] **Step 4: Run `clang-tidy` on a representative subset of the moved files**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --files \
  tests/core/recovery/congestion_test.cpp \
  tests/core/packets/frame_test.cpp \
  tests/http09/protocol/client_test.cpp \
  tests/http3/qpack_test.cpp \
  tests/qlog/qlog_test.cpp
```

Expected: `Passed`.

- [ ] **Step 5: Commit the leaf-file moves**

Run:

```bash
git add build.zig tests/core tests/http09 tests/http3 tests/qlog tests/tls
git commit -m "refactor: move leaf tests into hierarchy"
```

### Task 3: Extract Shared Core Fixtures And Move QLOG Integration Out Of `tests/quic_core_test.cpp`

**Files:**
- Create: `tests/support/core/connection_test_fixtures.h`
- Create: `tests/qlog/core_integration_test.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `build.zig`

- [ ] **Step 1: Move the shared core helper block into `tests/support/core/connection_test_fixtures.h`**

Create `tests/support/core/connection_test_fixtures.h` and move the file-local helper block that currently appears before the first `TEST(...)` in `tests/quic_core_test.cpp`. Because this header will be included by many `.cpp` files, mark every moved non-template free function as `inline` so the split test files do not introduce multiple-definition link failures. The header must expose these exact helpers under `namespace coquic::quic::test_support`:

```cpp
std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values);
std::uint32_t read_u32_be_at(std::span<const std::byte> bytes, std::size_t offset);
std::uint8_t hex_nibble_or_terminate(char value);
std::vector<std::byte> bytes_from_hex(std::string_view hex);

template <typename T> T optional_value_or_terminate(const std::optional<T> &value);
template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value);
template <typename T> T &optional_ref_or_terminate(std::optional<T> &value);

class ScopedEnvVar;

coquic::quic::CipherSuite invalid_cipher_suite();
coquic::quic::TrafficSecret make_test_traffic_secret(
    coquic::quic::CipherSuite cipher_suite =
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
    std::byte fill = std::byte{0x11});
coquic::quic::PreferredAddress make_test_preferred_address();
coquic::quic::QuicConnection make_connected_client_connection();
coquic::quic::QuicConnection make_connected_server_connection();
coquic::quic::QuicConnection make_connected_server_connection_with_preferred_address();

std::vector<coquic::quic::ProtectedPacket>
decode_sender_datagram(const coquic::quic::QuicConnection &connection,
                       std::span<const std::byte> datagram);
std::optional<std::vector<coquic::quic::ConnectionId>>
protected_datagram_destination_connection_ids(
    std::span<const std::byte> datagram,
    std::size_t one_rtt_destination_connection_id_length);
std::optional<std::size_t> protected_next_packet_length(std::span<const std::byte> bytes);

enum class ProtectedPacketKind : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

std::optional<std::vector<ProtectedPacketKind>>
protected_datagram_packet_kinds(std::span<const std::byte> datagram);
bool ack_frame_acks_packet_number_for_tests(const coquic::quic::AckFrame &ack,
                                            std::uint64_t packet_number);
std::vector<std::uint64_t>
application_stream_ids_from_datagram(const coquic::quic::QuicConnection &connection,
                                     std::span<const std::byte> datagram);
bool datagram_has_application_ack(const coquic::quic::QuicConnection &connection,
                                  std::span<const std::byte> datagram);
bool datagram_has_application_stream(const coquic::quic::QuicConnection &connection,
                                     std::span<const std::byte> datagram);
std::optional<std::size_t> find_application_probe_payload_size_that_drops_ack();
std::optional<std::size_t> find_application_send_payload_size_that_drops_ack();
void expect_local_error(const coquic::quic::QuicCoreResult &result,
                        coquic::quic::QuicCoreLocalErrorCode code,
                        std::uint64_t stream_id);
```

Move the existing bodies from `tests/quic_core_test.cpp`, adding `inline` to the moved non-template free functions.

- [ ] **Step 2: Replace the helper block in `tests/quic_core_test.cpp` with the shared fixture include**

At the top of `tests/quic_core_test.cpp`, keep the existing protocol includes, add:

```cpp
#include "tests/support/core/connection_test_fixtures.h"
```

Then replace the old anonymous-namespace helper block with:

```cpp
using coquic::quic::test_support::ProtectedPacketKind;
using coquic::quic::test_support::ScopedEnvVar;
using coquic::quic::test_support::ack_frame_acks_packet_number_for_tests;
using coquic::quic::test_support::application_stream_ids_from_datagram;
using coquic::quic::test_support::bytes_from_hex;
using coquic::quic::test_support::bytes_from_ints;
using coquic::quic::test_support::datagram_has_application_ack;
using coquic::quic::test_support::datagram_has_application_stream;
using coquic::quic::test_support::decode_sender_datagram;
using coquic::quic::test_support::expect_local_error;
using coquic::quic::test_support::find_application_probe_payload_size_that_drops_ack;
using coquic::quic::test_support::find_application_send_payload_size_that_drops_ack;
using coquic::quic::test_support::invalid_cipher_suite;
using coquic::quic::test_support::make_connected_client_connection;
using coquic::quic::test_support::make_connected_server_connection;
using coquic::quic::test_support::make_connected_server_connection_with_preferred_address;
using coquic::quic::test_support::make_test_preferred_address;
using coquic::quic::test_support::make_test_traffic_secret;
using coquic::quic::test_support::optional_ref_or_terminate;
using coquic::quic::test_support::optional_value_or_terminate;
using coquic::quic::test_support::protected_datagram_destination_connection_ids;
using coquic::quic::test_support::protected_datagram_packet_kinds;
using coquic::quic::test_support::protected_next_packet_length;
using coquic::quic::test_support::read_u32_be_at;
```

Expected: `tests/quic_core_test.cpp` now starts quickly with includes plus `using` declarations instead of thousands of lines of fixtures.

- [ ] **Step 3: Move the QLOG integration tests into `tests/qlog/core_integration_test.cpp`**

Create `tests/qlog/core_integration_test.cpp` with this preamble:

```cpp
#include <gtest/gtest.h>

#include "tests/support/core/connection_test_fixtures.h"
```

Move these exact tests out of `tests/quic_core_test.cpp` into the new file, leaving every `TEST(QuicCoreTest, ...)` name unchanged:

```text
ClientQlogStartWritesSequentialPreamble
ServerQlogFilenameUsesOriginalDestinationConnectionId
QlogOpenFailureDoesNotFailConnection
QlogClientStartEmitsLocalVersionAlpnAndParametersEvents
QlogHandshakeEmitsRemoteParametersAndChosenAlpn
QlogHandshakeAndStreamTrafficEmitPacketSentAndPacketReceived
QlogDeferredReplayPreservesDatagramIdAndAddsKeysAvailableTrigger
QlogPacketLostUsesReorderingAndTimeThresholdTriggers
QlogRecoveryMetricsUpdatedAndPtoProbeTriggerAreEmitted
ConnectionQlogSessionOpenGuardsRespectConfigAndExistingSession
ConnectionQlogLocalStartupEventsAreIdempotent
ConnectionQlogRemoteParametersReturnWhenPeerParametersMissing
ConnectionQlogServerAlpnSelectionEmissionIsIdempotent
ConnectionQlogServerAlpnSelectionSkipsMalformedPeerAlpnList
ConnectionQlogPacketLostReturnsWhenSessionOrSnapshotMissing
```

Expected: the qlog-specific integration coverage leaves the monolithic core file and lands in the future qlog test binary, but the GoogleTest names stay stable.

- [ ] **Step 4: Add the new qlog integration file to the current flat build list and verify it**

Append the new file to the current flat source list in `build.zig`:

```zig
        "tests/qlog/core_integration_test.cpp",
```

Run:

```bash
nix develop -c zig build test -- \
  --gtest_filter='QuicCoreTest.ClientQlogStartWritesSequentialPreamble:QuicCoreTest.QlogRecoveryMetricsUpdatedAndPtoProbeTriggerAreEmitted:QuicCoreTest.ConnectionQlogServerAlpnSelectionEmissionIsIdempotent'
```

Expected: the moved qlog integration tests pass from the new file.

- [ ] **Step 5: Commit the fixture extraction and qlog split**

Run:

```bash
git add build.zig tests/support/core/connection_test_fixtures.h tests/qlog/core_integration_test.cpp tests/quic_core_test.cpp
git commit -m "refactor: extract core fixtures and qlog integration tests"
```

### Task 4: Split `tests/quic_core_test.cpp` Into Domain-Focused Core Files

**Files:**
- Create: `tests/core/connection/handshake_test.cpp`
- Create: `tests/core/connection/zero_rtt_test.cpp`
- Create: `tests/core/connection/connection_id_test.cpp`
- Create: `tests/core/connection/stream_test.cpp`
- Create: `tests/core/connection/flow_control_test.cpp`
- Create: `tests/core/connection/ack_test.cpp`
- Create: `tests/core/connection/migration_test.cpp`
- Create: `tests/core/connection/path_validation_test.cpp`
- Create: `tests/core/connection/retry_version_test.cpp`
- Create: `tests/core/connection/key_update_test.cpp`
- Delete: `tests/quic_core_test.cpp`
- Modify: `build.zig`

- [ ] **Step 1: Create the new core split files with a shared preamble and stable test suite names**

Each new file must start with:

```cpp
#include <gtest/gtest.h>

#include "tests/support/core/connection_test_fixtures.h"
```

Keep every moved test named `TEST(QuicCoreTest, ...)` so existing filters, failure logs, and grep patterns keep working after the split.

- [ ] **Step 2: Move the remaining tests into the new files by behavior cluster**

Use this exact mapping:

```text
tests/core/connection/handshake_test.cpp
  PublicConfigAcceptsOpaqueResumptionStateAndZeroRttConfig
  TestUtilsExtractResumptionAndZeroRttEffects
  CompletedHandshakeEmitsResumptionStateEffect
  EmptySourceCidClientCompletesHandshakeAndEmitsResumptionState
  ClientStartProducesSendEffect
  TwoPeersEmitHandshakeReadyExactlyOnce
  ClientHandshakeReadyEmitsBeforeHandshakeConfirmation
  HandshakeExportsConfiguredTransportParametersToPeer
  MoveConstructionPreservesStartBehavior
  MoveAssignmentPreservesStartBehavior
  HandshakeRecoversWhenInitialFlightIsDropped
  ServerEmitsHandshakeCryptoAfterOutOfOrderClientInitialRecovery
  ApplicationDataIsRetransmittedAfterLoss
  ServerHandshakeCompletionQueuesHandshakeDoneFrame
  InboundHandshakeDoneQueuesApplicationAck
  ApplicationLevelHandshakeDoneFrameConfirmsHandshakeInCryptoPath
  ClientHandshakePacketUpdatesCurrentVersionWhenPeerNegotiatesSupportedVersion
  InboundOneRttPacketAcceptsMixedCryptoAndPostHandshakeControlFrames
  HandshakePacketAcceptsTransportConnectionCloseFrame
  OneRttPacketTerminatesOnConnectionCloseFrames
  ConnectionCloseFramesDoNotEmitInternalFailureDebugLog
  any remaining startup, shutdown, namespace-helper, equality, or utility tests that do not match a later bucket

tests/core/connection/zero_rtt_test.cpp
  every test whose name contains `ZeroRtt`
  every test whose name contains `Resumed`
  every test whose name contains `Resumption`
  every test whose name starts with `EmptySourceCid`

tests/core/connection/connection_id_test.cpp
  every test whose name contains `ConnectionId`
  every test whose name contains `NewConnectionId`
  every test whose name contains `RetireConnectionId`
  PreferredAddressCountsTowardIssuedConnectionIdLimit
  PreferredAddressReservesSequenceOneInLocalConnectionIdInventory
  PreferredAddressStartsIssuedConnectionIdsAtSequenceTwo
  PreferredAddressSequenceOneCanBeRetired

tests/core/connection/stream_test.cpp
  every test whose name contains `Stream`
  every test whose name contains `ResetStream`
  every test whose name contains `StopSending`
  LocalApplicationCloseQueuesApplicationConnectionCloseFrame
  PeerStopSendingQueuesAutomaticReset
  InboundStopSendingFailsForReceiveOnlyStream
  InboundResetStreamFailsForSendOnlyStream
  InboundStreamDataIsIgnoredAfterPeerResetStream
  TakePeerEffectsReturnNulloptWhenEmptyOrFailed
  ProcessInboundDatagramIgnoresEmptyAndFailedInputs

tests/core/connection/flow_control_test.cpp
  every test whose name contains `FlowControl`
  every test whose name contains `MaxData`
  every test whose name contains `MaxStreamData`
  every test whose name contains `DataBlocked`
  every test whose name contains `StreamsBlocked`
  every test whose name contains `ReceiveCredit`
  ApplicationSendQueuesConnectionDataBlockedFrameWhenCreditIsExhausted

tests/core/connection/ack_test.cpp
  every test whose name starts with `Ack`
  every test whose name contains `Pto`
  every test whose name contains `Keepalive`
  every test whose name contains `Ecn`
  every test whose name contains `Lost`
  every test whose name contains `Probe`
  every test whose name contains `Deadline`
  ReceivingAckElicitingPacketsSchedulesAckResponse
  ReorderedApplicationPacketsAreDeliveredOnceContiguous
  InboundApplicationAckRetiresOwnedSendRanges
  AckOnlyApplicationResponsesAreNotRetainedAsOutstandingPackets
  LargeAckOnlyHistoryEmitsTrimmedAckDatagram
  ConnectionNamespaceHelpersCoverEdgeCases
  any remaining loss-detection, retransmission, send-path-budget, or probe-selection tests that do not match a later bucket

tests/core/connection/migration_test.cpp
  every test whose name contains `Migration`
  every test whose name contains `Rebind`
  ConnectionInternalCoverageHooksExerciseRemainingMigrationBranches

tests/core/connection/path_validation_test.cpp
  every test whose name contains `PathChallenge`
  every test whose name contains `PathResponse`
  every test whose name contains `UnvalidatedPath`
  every test whose name contains `AckOnlyFallbackCarriesPathValidationFrames`
  every test whose name contains `AckOnlyFallbackCarriesCurrentPathValidationFrames`
  PreconnectedPathResponseWithoutApplicationKeysIsRejectedWhilePaddingIsIgnored
  PreconnectedPathResponseIsAcceptedWhenApplicationKeysExist

tests/core/connection/retry_version_test.cpp
  every test whose name contains `Retry`
  every test whose name contains `VersionNegotiation`
  every test whose name contains `CompatibleNegotiation`
  every test whose name contains `SupportedVersion`
  every test whose name contains `CurrentVersion`

tests/core/connection/key_update_test.cpp
  every test whose name contains `KeyUpdate`
  every test whose name contains `KeyUpdated`
  every test whose name contains `Key phase`
  every test whose name contains `key phase`
```

After the move, run:

```bash
rg -n '^TEST\\(QuicCoreTest' tests/quic_core_test.cpp
```

Expected: no output. Do not change assertions while moving tests. The only intended change in this task is file placement.

- [ ] **Step 3: Replace the old monolith in the current flat source list**

In `build.zig`, remove `"tests/quic_core_test.cpp"` and add these exact files in its place:

```zig
        "tests/core/connection/handshake_test.cpp",
        "tests/core/connection/zero_rtt_test.cpp",
        "tests/core/connection/connection_id_test.cpp",
        "tests/core/connection/stream_test.cpp",
        "tests/core/connection/flow_control_test.cpp",
        "tests/core/connection/ack_test.cpp",
        "tests/core/connection/migration_test.cpp",
        "tests/core/connection/path_validation_test.cpp",
        "tests/core/connection/retry_version_test.cpp",
        "tests/core/connection/key_update_test.cpp",
```

Then delete `tests/quic_core_test.cpp`.

- [ ] **Step 4: Verify representative core cases after the split**

Run:

```bash
nix develop -c zig build test -- \
  --gtest_filter='QuicCoreTest.ServerProcessesOneRttPathChallengeBeforeHandshakeCompletesWhenApplicationKeysExist:QuicCoreTest.PreconnectedPathResponseIsAcceptedWhenApplicationKeysExist:QuicCoreTest.ClientTimerAfterLargePartialResponseFlowRetainsPathChallengeAcrossPtoBurst:QuicCoreTest.LocalKeyUpdateUsesNewKeyPhaseAfterCurrentPhasePacketIsAcknowledged:QuicCoreTest.ClientRestartsHandshakeAfterValidRetry'
```

Expected: all selected tests pass from the new files.

- [ ] **Step 5: Commit the core split**

Run:

```bash
git add build.zig tests/core/connection tests/quic_core_test.cpp
git commit -m "refactor: split core connection tests by behavior"
```

### Task 5: Split `tests/quic_http09_runtime_test.cpp` By Runtime Concern

**Files:**
- Create: `tests/support/http09/runtime_test_fixtures.h`
- Create: `tests/http09/runtime/transfer_test.cpp`
- Create: `tests/http09/runtime/startup_test.cpp`
- Create: `tests/http09/runtime/config_test.cpp`
- Create: `tests/http09/runtime/io_test.cpp`
- Create: `tests/http09/runtime/routing_test.cpp`
- Create: `tests/http09/runtime/migration_test.cpp`
- Create: `tests/http09/runtime/preferred_address_test.cpp`
- Create: `tests/http09/runtime/retry_zero_rtt_test.cpp`
- Create: `tests/http09/runtime/interop_alias_test.cpp`
- Create: `tests/http09/runtime/linux_ecn_test.cpp`
- Delete: `tests/quic_http09_runtime_test.cpp`
- Modify: `build.zig`

- [ ] **Step 1: Extract the reusable runtime helper block into `tests/support/http09/runtime_test_fixtures.h`**

Create `tests/support/http09/runtime_test_fixtures.h` and move the reusable helper block that currently appears before the first `TEST(...)` in `tests/quic_http09_runtime_test.cpp`. Because this header will be included by many `.cpp` files, mark every moved non-template free function as `inline`, mark ordinary moved globals as `inline`, mark moved thread-local globals as `inline thread_local`, and keep the current behavior unchanged. Expose the shared pieces under `namespace coquic::quic::test_support`. The header must include the helpers that multiple runtime split files need:

```text
ScopedEnvVar
ScopedFd
optional_value_or_terminate
optional_ref_or_terminate
invalid_runtime_mode
ScopedRuntimeServerStopFlag
stoppable_poll
wake_runtime_server
run_http09_runtime_child_process
ScopedChildProcess
the socket, poll, getaddrinfo, sendto, and recvfrom override helpers
the address-family trace and reset helpers
the in-memory transfer harness helpers
the observing-server helpers
the runtime time and connection-id formatting helpers
```

Do not invent new helpers in this task. Move the existing ones from the top of `tests/quic_http09_runtime_test.cpp`, adjusting linkage only where the new header form requires `inline`.

- [ ] **Step 2: Create the new runtime files with a shared preamble and keep the existing suite name**

Each new file must start with:

```cpp
#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"
```

Keep every moved test named `TEST(QuicHttp09RuntimeTest, ...)`.

- [ ] **Step 3: Move the runtime tests by stable concern**

Use this exact mapping:

```text
tests/http09/runtime/transfer_test.cpp
  ClientAndServerTransferSingleFileOverUdpSockets
  ClientAndServerTransferSingleFileAfterConnectionMigration
  InMemoryClientAndServerTransferLargeFile
  InMemoryClientAndServerTransferMediumFile
  InMemoryClientAndServerTransferManyFilesAcrossRefreshedStreamLimits
  ClientAndServerTransferLargeFileOverUdpSockets
  TransferCaseUsesSingleConnectionAndMultipleStreams
  MulticonnectCaseUsesSeparateConnectionPerRequest
  MulticonnectCaseSupportsThreeRequestsWithoutRoutingCollisions
  ClientAndServerTransferSingleFileWithResumptionTestcase
  ClientAndRuntimeServerTransferLargeFileOverUdpSockets
  ClientAndRuntimeServerMulticonnectThreeFilesOverUdpSockets
  every remaining transfer, multiconnect, in-memory transfer, or warmup/final data-plane test

tests/http09/runtime/startup_test.cpp
  ServerDoesNotExitAfterMalformedTraffic
  ServerFailsFastWhenTlsFilesMissing
  ServerFailsFastWhenPrivateKeyFileMissing
  ServerFailsWhenSocketCreationFails
  ServerFailsWhenSocketBindFails
  ServerFailsWhenConfiguredHostIsNotIpv4
  ServerUsesIpv6SocketFamilyForIpv6Host
  ServerResolutionPassesNullNodeForWildcardHost
  ClientFailsWhenPeerResolutionFails
  ClientFailsWhenResolutionSucceedsWithoutAnyAddrinfoResults
  RuntimeHealthCheckSucceedsWhenDependenciesAreAvailable
  RuntimeReturnsFailureForUnknownMode
  ServerRespondsToUnsupportedVersionProbeAndStillTransfersFile
  ServerIgnoresUnsupportedVersionProbeBelowMinimumInitialSize
  ServerIgnoresSupportedLongHeaderWithoutSession
  ServerFailsWhenVersionNegotiationSendFails
  TraceEnabledServerDropsMalformedSupportedInitialAndStillTransfersFile
  every remaining startup, shutdown, resolver bootstrap, or server bring-up failure test

tests/http09/runtime/config_test.cpp
  ClientDerivesPeerAddressAndServerNameFromRequests
  RuntimeBuildsCoreConfigWithInteropAlpnAndRunnerDefaults
  RuntimeLeavesQlogDisabledWhenQlogdirUnsetOrEmpty
  RuntimeReadsQlogDirectoryFromEnvironment
  RuntimeLeavesTlsKeylogDisabledWhenSslkeylogfileUnsetOrEmpty
  RuntimeReadsTlsKeylogPathFromEnvironment
  RuntimePropagatesQlogDirectoryIntoClientAndServerCoreConfigs
  RuntimePropagatesTlsKeylogPathIntoClientAndServerCoreConfigs
  RuntimeRejectsInvalidAndEmptyPortStringsFromEnvironment
  RuntimeRejectsUnknownTestcaseNamesFromEnvironmentAndCli
  RuntimeRejectsInvalidRoleAndUsageDispatchFailures
  RuntimeRejectsClientStartupWithoutRequests
  RejectsMalformedBracketedAuthority
  RejectsEmptyAndColonOnlyAuthorities
  ParsesBracketedAuthoritiesWithAndWithoutPort
  RejectsBracketedAuthoritiesWithEmptyHostOrInvalidSuffix
  RejectsMalformedHostPortAuthority
  ParsesHostnamePortAndIpv6LiteralAuthorities
  DerivesHostPortAndServerNameFromRequestWhenUnset
  DerivesOnlyServerNameWhenHostAlreadySpecified
  DerivesOnlyHostWhenServerNameAlreadySpecified
  DerivationReturnsConfiguredRemoteWithoutRequestsWhenComplete
  DerivationFailsForEmptyRequestListWhenFallbackRequired
  DerivationFailsForInvalidRequestAuthority
  MigrationCasesUseTransferTransportProfile
  KeyUpdateUsesTransferTransportProfile
  KeyUpdateRuntimeEnablesClientKeyUpdatePolicy
  KeyUpdateUsesTransferTransportProfileOnServerPath
  RuntimeReadsServerEnvironmentOverrides
  RuntimeParsesInteropServerSubcommandFlags
  RuntimeParsesRetryFlagFromEnvironmentAndCli
  RuntimeTreatsRetryTestcaseAliasAsHandshakeWithRetryEnabled
  RuntimeCliFlagsOverrideEnvironmentAndKeepExplicitClientRemote
  RuntimeRejectsInvalidCliPortString
  RuntimeAcceptsOfficialChacha20TestcaseAndConstrainsCipherSuites
  RuntimeBuildsV2CoreConfigsWithCompatibleVersionSupport
  RuntimeBuildsServerCoreConfigWithExtendedIdleTimeoutForMulticonnect
  RuntimeHelperHooksExposeTraceAndConnectionIdFormatting
  ClientFailsWhenRequestsEnvIsInvalidAtRuntime
  ClientConnectionWithoutRequestsCompletesAfterHandshake
  every remaining environment, authority-parsing, profile-selection, or config-construction test

tests/http09/runtime/io_test.cpp
  ClientFailsWhenSocketCreationFailsAfterRemoteDerivation
  ClientConnectionFreesResolverResultsWhenResolutionFails
  ClientFailsWhenInitialSendFails
  ClientFailsWhenPollErrors
  ClientFailsWhenSocketBecomesUnreadable
  ClientFailsWhenRecvfromFailsAfterReadablePoll
  ServerContinuesAfterIdlePollTimeoutThenFailsOnPollError
  RuntimeHelperExtendsClientReceiveTimeoutForMulticonnect
  RuntimeWaitHelperReturnsIdleTimeoutWithoutWakeup
  RuntimeWaitHelperReturnsTimerInputWhenWakeupIsDue
  RuntimeHelperHooksSelectEarliestWakeupAcrossEntries
  RuntimeConfiguresLinuxSocketsForReceivingEcnMetadata
  RuntimeUsesSendmsgToApplyOutboundEcnMarkings
  RuntimeUsesIpTosForIpv4MappedIpv6OutboundEcnMarkings
  RuntimeMapsRecvmsgEcnMetadataIntoCoreInputs
  RuntimeHelperHooksDriveEndpointUntilBlockedFailureCases
  RuntimeHelperHooksDriveEndpointUntilBlockedSuccessCase
  RuntimeHelperHooksDriveClientConnectionLoopCases
  RuntimeHelperHooksCoverServerFailureCleanupAndLoopCases
  RuntimeWaitHelperFailsWhenReadableSocketRecvfromFails
  RuntimeWaitHelperRetriesPollAfterEintrBeforeIdleTimeout
  RuntimeWaitHelperReceivesInboundDatagram
  RuntimeTraceHooksCoverIdleTimeoutAndServerFailureBranches
  RuntimeLowLevelHooksExerciseSocketAndEcnFallbacks
  every remaining socket, poll, recvfrom, sendto, sendmsg, recvmsg, or wait-helper test

tests/http09/runtime/routing_test.cpp
  RuntimeAssignsStablePathIdsPerPeerTuple
  DriveEndpointUsesTransportSelectedPathAndSocket
  DeferredReplayPreservesIndividualBufferedPathIds
  DeferredReplayKeepsDistinctPathsForIdenticalPayloads
  CoreVersionNegotiationRestartPreservesInboundPathIds
  CoreRetryRestartPreservesInboundPathIds
  DriveEndpointRejectsUnknownTransportSelectedPath
  RuntimeProcessesPolicyInputsBeforeTerminalSuccess
  RuntimeRegistersAllServerCoreConnectionIdsForRouting
  RuntimeMiscInternalCoverageHooksExerciseFallbackPaths
  RuntimeInternalCoverageHooksExerciseRemainingBranches
  RuntimeRestartFailureHooksExerciseRestartFailures
  ExistingServerSessionRouteHelperErasesFailedSession
  every remaining path-id, deferred-replay, or route-registration test

tests/http09/runtime/migration_test.cpp
  ConnectionMigrationServerBindsPreferredSocketAndPollsBothSockets
  ConnectionMigrationServerConfigAdvertisesPreferredAddress
  ConnectionMigrationServerConfigIncludesPreferredAddressResetToken
  ConnectionMigrationServerConfigUsesConcreteAddressForWildcardHost
  RuntimeConnectionMigrationFailureHooksExerciseFalseBranches
  ExistingServerSessionRoutesLiveLikeMigrationRetransmitOnNewPath
  ExistingServerSessionRoutesSecondRebindToLatestIpv6Peer
  ExistingServerSessionRoutesSecondRebindToLatestV4MappedPeer
  ExistingServerSessionRoutesSecondRebindAddrToLatestV4MappedPeer
  every remaining migration or rebind test

tests/http09/runtime/preferred_address_test.cpp
  PreferredAddressCidRoutesToExistingServerSession
  RuntimeQueuesPreferredAddressMigrationRequestAfterHandshakeConfirmed
  CrossFamilyPreferredAddressUsesCompatibleSocket
  ClientLoopUsesAllActiveSocketsForPreferredAddress
  RegularTransferDoesNotQueuePreferredAddressMigration
  every remaining preferred-address behavior test

tests/http09/runtime/retry_zero_rtt_test.cpp
  ZeroRttRuntimeTransfersWarmupAndFinalRequestsAcrossResumedConnection
  RuntimeHelperHooksCoverRetryAndZeroRttBranches
  HandshakeCaseNeverEmitsRetryPackets
  RetryEnabledServerSendsRetryBeforeCreatingSession
  RetryEnabledServerCompletesHandshakeAfterRetriedInitial
  V2CaseStartsInQuicV1AndNegotiatesQuicV2LongHeaders
  every remaining retry, resumption, zero-rtt, or v2 negotiation test

tests/http09/runtime/interop_alias_test.cpp
  RuntimeAcceptsOfficialRunnerAliasesViaCliFlags
  RuntimeAcceptsOfficialMulticonnectTestcase
  RuntimeAcceptsOfficialV2Testcase
  RuntimeAcceptsOfficialEcnTestcase
  RuntimeTreatsAmplificationLimitEnvironmentAliasAsTransfer
  RuntimeTreatsAmplificationLimitCliAliasAsTransfer
  RuntimeAcceptsOfficialResumptionAndZeroRttTestcases
  RuntimeAcceptsOfficialKeyUpdateTestcase
  RuntimeAcceptsKeyUpdateCliFlag
  RuntimeAcceptsOfficialRebindPortTestcase
  RuntimeAcceptsRebindAddrCliFlag
  RuntimeAcceptsOfficialConnectionMigrationTestcase
  every remaining official-runner alias acceptance test

tests/http09/runtime/linux_ecn_test.cpp
  ClientPrefersIpv4AddrinfoWhenHostnameIsNonNumeric
  ClientConnectionUsesIpv6ResolutionAndSocketFamilyForIpv6Remote
  ClientFallsBackToEarlierValidAddrinfoWhenPreferredResultIsInvalid
  ClientFailsWhenAllResolvedAddrinfoEntriesAreInvalid
  ClientFailsWhenAddrinfoFamilyIsUnsupported
  ClientUsesRealIpv6SocketSetupBeforeInitialSend
  every remaining address-family-selection test that is not a startup or bring-up failure case
```

After the move, run:

```bash
rg -n '^TEST\\(QuicHttp09RuntimeTest' tests/quic_http09_runtime_test.cpp
```

Expected: no output.

- [ ] **Step 4: Replace the old runtime file in the current flat list and verify representative cases**

In `build.zig`, remove `"tests/quic_http09_runtime_test.cpp"` and add:

```zig
        "tests/http09/runtime/transfer_test.cpp",
        "tests/http09/runtime/startup_test.cpp",
        "tests/http09/runtime/config_test.cpp",
        "tests/http09/runtime/io_test.cpp",
        "tests/http09/runtime/routing_test.cpp",
        "tests/http09/runtime/migration_test.cpp",
        "tests/http09/runtime/preferred_address_test.cpp",
        "tests/http09/runtime/retry_zero_rtt_test.cpp",
        "tests/http09/runtime/interop_alias_test.cpp",
        "tests/http09/runtime/linux_ecn_test.cpp",
```

Then run:

```bash
nix develop -c zig build test -- \
  --gtest_filter='QuicHttp09RuntimeTest.PreferredAddressCidRoutesToExistingServerSession:QuicHttp09RuntimeTest.CrossFamilyPreferredAddressUsesCompatibleSocket:QuicHttp09RuntimeTest.ClientLoopUsesAllActiveSocketsForPreferredAddress:QuicHttp09RuntimeTest.ExistingServerSessionRoutesLiveLikeMigrationRetransmitOnNewPath:QuicHttp09RuntimeTest.RuntimeConfiguresLinuxSocketsForReceivingEcnMetadata'
```

Expected: the selected runtime cases pass from the new files.

- [ ] **Step 5: Commit the runtime split**

Run:

```bash
git add build.zig tests/http09/runtime tests/support/http09/runtime_test_fixtures.h tests/quic_http09_runtime_test.cpp
git commit -m "refactor: split http09 runtime tests by concern"
```

### Task 6: Replace The Monolithic Test Binary With Six Area Binaries And Multi-Binary Coverage

**Files:**
- Modify: `build.zig`
- Modify: `scripts/run-coverage.sh`

- [ ] **Step 1: Replace the flat source list with six area-specific arrays**

In `build.zig`, replace `default_test_files` with these exact arrays:

```zig
    const smoke_test_files = &.{
        "tests/smoke/smoke_test.cpp",
    };
    const core_test_files = &.{
        "tests/core/recovery/congestion_test.cpp",
        "tests/core/recovery/recovery_test.cpp",
        "tests/core/packets/frame_test.cpp",
        "tests/core/packets/packet_test.cpp",
        "tests/core/packets/packet_number_test.cpp",
        "tests/core/packets/plaintext_codec_test.cpp",
        "tests/core/packets/protected_codec_test.cpp",
        "tests/core/packets/transport_parameters_test.cpp",
        "tests/core/packets/varint_test.cpp",
        "tests/core/streams/streams_test.cpp",
        "tests/core/streams/crypto_stream_test.cpp",
        "tests/core/connection/handshake_test.cpp",
        "tests/core/connection/zero_rtt_test.cpp",
        "tests/core/connection/connection_id_test.cpp",
        "tests/core/connection/stream_test.cpp",
        "tests/core/connection/flow_control_test.cpp",
        "tests/core/connection/ack_test.cpp",
        "tests/core/connection/migration_test.cpp",
        "tests/core/connection/path_validation_test.cpp",
        "tests/core/connection/retry_version_test.cpp",
        "tests/core/connection/key_update_test.cpp",
    };
    const http09_test_files = &.{
        "tests/http09/protocol/http09_test.cpp",
        "tests/http09/protocol/server_test.cpp",
        "tests/http09/protocol/client_test.cpp",
        "tests/http09/runtime/transfer_test.cpp",
        "tests/http09/runtime/startup_test.cpp",
        "tests/http09/runtime/config_test.cpp",
        "tests/http09/runtime/io_test.cpp",
        "tests/http09/runtime/routing_test.cpp",
        "tests/http09/runtime/migration_test.cpp",
        "tests/http09/runtime/preferred_address_test.cpp",
        "tests/http09/runtime/retry_zero_rtt_test.cpp",
        "tests/http09/runtime/interop_alias_test.cpp",
        "tests/http09/runtime/linux_ecn_test.cpp",
    };
    const http3_test_files = &.{
        "tests/http3/protocol_test.cpp",
        "tests/http3/qpack_test.cpp",
    };
    const qlog_test_files = &.{
        "tests/qlog/qlog_test.cpp",
        "tests/qlog/core_integration_test.cpp",
    };
    const tls_test_files = &.{
        "tests/tls/packet_crypto_test.cpp",
        "tests/tls/tls_adapter_contract_test.cpp",
    };
```

Expected: the file lists now reflect the approved directory hierarchy and executable split.

- [ ] **Step 2: Replace the single `coquic-tests` binary with six area binaries**

In `build.zig`, create these executables with `addTestBinary(...)` and wire each run artifact into `test_step`:

```zig
    const smoke_tests =
        addTestBinary(b, "coquic-tests-smoke", target, optimize, cpp_flags, project_lib, gtest_root, smoke_test_files);
    const core_tests =
        addTestBinary(b, "coquic-tests-core", target, optimize, cpp_flags, project_lib, gtest_root, core_test_files);
    const http09_tests =
        addTestBinary(b, "coquic-tests-http09", target, optimize, cpp_flags, project_lib, gtest_root, http09_test_files);
    const http3_tests =
        addTestBinary(b, "coquic-tests-http3", target, optimize, cpp_flags, project_lib, gtest_root, http3_test_files);
    const qlog_tests =
        addTestBinary(b, "coquic-tests-qlog", target, optimize, cpp_flags, project_lib, gtest_root, qlog_test_files);
    const tls_tests =
        addTestBinary(b, "coquic-tests-tls", target, optimize, cpp_flags, project_lib, gtest_root, tls_test_files);
```

For each binary:

```zig
    linkTlsBackend(b, <binary>, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(<binary>);
    const <binary>_run = b.addRunArtifact(<binary>);
    if (b.args) |args| {
        <binary>_run.addArgs(args);
    }
    test_step.dependOn(&<binary>_run.step);
```

Remove the old single `coquic-tests` binary and its run artifact.

- [ ] **Step 3: Update the `compdb` step so `compile_commands.json` still covers every test source**

In `build.zig`, keep the existing `compdb` step name but make it depend on all six area binaries instead of the old single test binary:

```zig
    compdb_step.dependOn(&exe.step);
    compdb_step.dependOn(&smoke_tests.step);
    compdb_step.dependOn(&core_tests.step);
    compdb_step.dependOn(&http09_tests.step);
    compdb_step.dependOn(&http3_tests.step);
    compdb_step.dependOn(&qlog_tests.step);
    compdb_step.dependOn(&tls_tests.step);
```

Expected: `./scripts/refresh-compile-commands.sh` still works and now emits entries for every moved test source.

- [ ] **Step 4: Create coverage binaries per area and update `scripts/run-coverage.sh` to accept multiple binaries**

Create coverage executables that mirror the six area lists:

```zig
    const smoke_coverage_tests =
        addTestBinary(b, "coquic-coverage-tests-smoke", target, optimize, coverage_cpp_flags, coverage_lib, gtest_root, smoke_test_files);
    const core_coverage_tests =
        addTestBinary(b, "coquic-coverage-tests-core", target, optimize, coverage_cpp_flags, coverage_lib, gtest_root, core_test_files);
    const http09_coverage_tests =
        addTestBinary(b, "coquic-coverage-tests-http09", target, optimize, coverage_cpp_flags, coverage_lib, gtest_root, http09_test_files);
    const http3_coverage_tests =
        addTestBinary(b, "coquic-coverage-tests-http3", target, optimize, coverage_cpp_flags, coverage_lib, gtest_root, http3_test_files);
    const qlog_coverage_tests =
        addTestBinary(b, "coquic-coverage-tests-qlog", target, optimize, coverage_cpp_flags, coverage_lib, gtest_root, qlog_test_files);
    const tls_coverage_tests =
        addTestBinary(b, "coquic-coverage-tests-tls", target, optimize, coverage_cpp_flags, coverage_lib, gtest_root, tls_test_files);
```

Apply the same TLS, spdlog, and profile-runtime wiring to each coverage binary, then change the coverage command wiring to:

```zig
    coverage_cmd.addFileArg(b.path("scripts/run-coverage.sh"));
    coverage_cmd.addArtifactArg(smoke_coverage_tests);
    coverage_cmd.addArtifactArg(core_coverage_tests);
    coverage_cmd.addArtifactArg(http09_coverage_tests);
    coverage_cmd.addArtifactArg(http3_coverage_tests);
    coverage_cmd.addArtifactArg(qlog_coverage_tests);
    coverage_cmd.addArtifactArg(tls_coverage_tests);
```

Replace `scripts/run-coverage.sh` with:

```bash
#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <test-binary> [<test-binary> ...]" >&2
    exit 1
fi

if [ -z "${LLVM_COV:-}" ] || [ -z "${LLVM_PROFDATA:-}" ]; then
    echo "LLVM_COV and LLVM_PROFDATA must be set; run inside nix develop" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
coverage_dir="${repo_root}/coverage"
profile_data="${coverage_dir}/coquic.profdata"
html_dir="${coverage_dir}/html"
lcov_report="${coverage_dir}/lcov.info"
ignore_pattern='(^/nix/store/|/tests/|/\.zig-cache/)'

rm -rf "${coverage_dir}"
mkdir -p "${html_dir}"

profraws=()
index=0
for test_binary in "$@"; do
    profile_raw="${coverage_dir}/coquic-${index}.profraw"
    LLVM_PROFILE_FILE="${profile_raw}" "${test_binary}"
    profraws+=("${profile_raw}")
    index=$((index + 1))
done

"${LLVM_PROFDATA}" merge -sparse "${profraws[@]}" -o "${profile_data}"

binary_args=()
for test_binary in "$@"; do
    binary_args+=("-object" "${test_binary}")
done

"${LLVM_COV}" export \
    --format=lcov \
    --instr-profile="${profile_data}" \
    --ignore-filename-regex="${ignore_pattern}" \
    "${binary_args[@]}" > "${lcov_report}"

"${LLVM_COV}" show \
    --instr-profile="${profile_data}" \
    --format=html \
    --output-dir="${html_dir}" \
    --ignore-filename-regex="${ignore_pattern}" \
    "${binary_args[@]}"
```

- [ ] **Step 5: Verify the new build graph, compdb refresh, aggregate tests, and coverage**

Run:

```bash
nix develop -c ./scripts/refresh-compile-commands.sh
nix develop -c zig build -l
nix develop -c zig build test
nix develop -c zig build coverage
```

Expected:

```text
zig build -l includes test, coverage, and compdb
compile_commands.json is refreshed successfully
coverage/lcov.info exists
coverage/html exists
```

- [ ] **Step 6: Commit the build-graph and coverage rewrite**

Run:

```bash
git add build.zig scripts/run-coverage.sh
git commit -m "build: split tests into area executables"
```

### Task 7: Remove The Compatibility Shim And Run Final Verification

**Files:**
- Delete: `tests/quic_test_utils.h`
- Modify: moved test files that still include `tests/quic_test_utils.h`

- [ ] **Step 1: Rewrite the remaining test includes to the final support path**

Run:

```bash
rg -l '#include "tests/quic_test_utils.h"' tests src | \
  xargs -r sed -i 's#"tests/quic_test_utils.h"#"tests/support/quic_test_utils.h"#'
```

Expected: the remaining include sites now point directly at `tests/support/quic_test_utils.h`.

- [ ] **Step 2: Delete the shim and verify that no stale include remains**

Run:

```bash
rm tests/quic_test_utils.h
rg -n 'tests/quic_test_utils.h' tests src build.zig
```

Expected: the `rg` command prints no output.

- [ ] **Step 3: Commit the final include cleanup**

Run:

```bash
git add tests src
git commit -m "refactor: finalize shared test support includes"
```

- [ ] **Step 4: Run the exact final verification slice before full lint**

Run:

```bash
nix develop -c zig build test -- \
  --gtest_filter='QuicCoreTest.ServerProcessesOneRttPathChallengeBeforeHandshakeCompletesWhenApplicationKeysExist:QuicCoreTest.PreconnectedPathResponseIsAcceptedWhenApplicationKeysExist:QuicHttp09RuntimeTest.PreferredAddressCidRoutesToExistingServerSession:QuicHttp09RuntimeTest.CrossFamilyPreferredAddressUsesCompatibleSocket:QuicHttp09RuntimeTest.ClientLoopUsesAllActiveSocketsForPreferredAddress:QuicQlogTest.*'
```

Expected: the focused regression slice passes.

- [ ] **Step 5: Run the full repo verification and capture the post-reorg lint time**

Run:

```bash
/usr/bin/time -f 'REFRESH_ELAPSED=%e' \
  nix develop -c ./scripts/refresh-compile-commands.sh
nix develop -c zig build test
nix develop -c zig build coverage
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
/usr/bin/time -f 'LINT_ELAPSED=%e' \
  nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: all commands pass, and you record the final `LINT_ELAPSED`.

- [ ] **Step 6: Compare the baseline and final lint measurements**

Run:

```bash
python - <<'PY'
before = float(input().strip())
after = float(input().strip())
print({
    "before_seconds": before,
    "after_seconds": after,
    "delta_seconds": after - before,
    "delta_percent": ((after - before) / before) * 100.0,
})
PY
```

Feed the baseline `LINT_ELAPSED` from Task 1 on the first line and the final `LINT_ELAPSED` from Step 5 on the second line.

Expected: a before/after summary suitable for the final report.

- [ ] **Step 7: Run the targeted interop regression**

Run:

```bash
INTEROP_TESTCASES=handshakecorruption \
INTEROP_PEER_IMPL=coquic \
INTEROP_PEER_IMAGE=coquic-interop:quictls-musl \
INTEROP_DIRECTIONS=coquic-server \
nix develop -c bash interop/run-official.sh
```

Expected: `TestResult.SUCCEEDED` for `handshakecorruption`.

- [ ] **Step 8: Confirm the final branch state**

Run:

```bash
git status --short
git log --oneline -n 10
```

Expected: `git status --short` is empty, and the log shows the plan's staged refactor commits in order.

# QUIC ECN Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Linux-first QUIC ECN support with RFC-style ACK ECN reporting, sender-side validation, CE-driven congestion handling, ECT(1)-aware accounting, and checked-in official interop workflow coverage for the `ecn` testcase.

**Architecture:** Keep receive-side ECN accounting inside per-packet-number-space `ReceivedPacketHistory`, because ACK ECN counts are maintained per packet number space. Keep sender-side ECN probing, validation, and disablement in `PathState`, with sent-packet metadata extended so ACK processing can validate newly acknowledged ECT(0)/ECT(1) packets and trigger congestion response on CE increases. Extend the Linux HTTP/0.9 runtime transport shim to surface IP ECN metadata through `QuicCoreInboundDatagram` and `QuicCoreSendDatagram`, while preserving existing call sites with defaults.

**Tech Stack:** C++20, GoogleTest, Linux UDP socket ancillary data (`recvmsg`, `sendmsg`, `setsockopt`), GitHub Actions, QUIC RFC 9000/9002.

---

### Task 1: Add failing connection/recovery ECN tests

**Files:**
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_recovery_test.cpp`
- Modify: `src/quic/core.h`
- Test: `zig build test -- tests/quic_core_test.cpp tests/quic_recovery_test.cpp`

- [ ] **Step 1: Write failing ACK generation tests**

```cpp
TEST(QuicCoreTest, AckFramesIncludeApplicationEcnCountsWhenInboundEcnIsAvailable) {
    auto connection = make_connected_server_connection();

    connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 9,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    // Update once ECN metadata plumbs through packet processing.
    // Expect ACK type 0x03 with ECT(0)/ECT(1)/CE counters.
}
```

- [ ] **Step 2: Write failing ACK validation and CE-response tests**

```cpp
TEST(QuicCoreTest, AckProcessingDisablesEcnWhenAckOmitsCountsForNewlyAckedEctPackets) {}

TEST(QuicCoreTest, AckProcessingTreatsCeCounterGrowthAsSingleCongestionEvent) {}

TEST(QuicCoreTest, AckProcessingValidatesEct1CountsIndependently) {}
```

- [ ] **Step 3: Write failing recovery-history tests**

```cpp
TEST(QuicRecoveryTest, ReceivedPacketHistoryBuildsAckFrameWithZeroEcnCountsWhenAccessible) {}

TEST(QuicRecoveryTest, ReceivedPacketHistoryDoesNotDoubleCountDuplicatePacketsForEcn) {}
```

- [ ] **Step 4: Run the focused tests to verify they fail**

Run: `nix develop -c zig build test -- tests/quic_core_test.cpp tests/quic_recovery_test.cpp`
Expected: FAIL with missing ECN metadata/state members or wrong ACK/validation behavior.

- [ ] **Step 5: Commit the red tests**

```bash
git add tests/quic_core_test.cpp tests/quic_recovery_test.cpp
git commit -m "test: add failing QUIC ECN coverage"
```

### Task 2: Add failing Linux runtime ECN I/O and interop contract tests

**Files:**
- Modify: `tests/quic_http09_runtime_test.cpp`
- Modify: `src/quic/http09_runtime_test_hooks.h`
- Modify: `tests/nix/github_interop_workflow_test.sh`
- Modify: `interop/entrypoint.sh`
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/http09.h`
- Test: `nix develop -c zig build test -- tests/quic_http09_runtime_test.cpp`
- Test: `nix develop -c bash tests/nix/github_interop_workflow_test.sh`

- [ ] **Step 1: Add failing runtime send/receive metadata tests**

```cpp
TEST(QuicHttp09RuntimeTest, RuntimeConfiguresLinuxSocketsForReceivingEcnMetadata) {}

TEST(QuicHttp09RuntimeTest, RuntimeSendsEctMarkedDatagramsViaSendmsg) {}

TEST(QuicHttp09RuntimeTest, RuntimeMapsReceivedIpEcnBitsIntoCoreInputs) {}
```

- [ ] **Step 2: Add failing workflow and wrapper testcase tests**

```bash
# Update the expected interop-self block to include ecn.
# Add entrypoint allowlist coverage for TESTCASE=ecn.
```

- [ ] **Step 3: Run the targeted tests to verify they fail**

Run: `nix develop -c zig build test -- tests/quic_http09_runtime_test.cpp`
Expected: FAIL because runtime ops do not expose `sendmsg`/`recvmsg` or ECN metadata yet.

Run: `nix develop -c bash tests/nix/github_interop_workflow_test.sh`
Expected: FAIL until workflow testcase lists include `ecn`.

- [ ] **Step 4: Commit the red tests**

```bash
git add tests/quic_http09_runtime_test.cpp src/quic/http09_runtime_test_hooks.h \
  tests/nix/github_interop_workflow_test.sh interop/entrypoint.sh src/quic/http09_runtime.cpp \
  src/quic/http09.h
git commit -m "test: add failing ECN runtime and workflow coverage"
```

### Task 3: Implement protocol-side ECN accounting and validation

**Files:**
- Modify: `src/quic/core.h`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `src/quic/frame.h`
- Test: `tests/quic_core_test.cpp`
- Test: `tests/quic_recovery_test.cpp`

- [ ] **Step 1: Add shared ECN types and metadata carriers**

```cpp
enum class QuicEcnCodepoint : std::uint8_t {
    unavailable,
    not_ect,
    ect0,
    ect1,
    ce,
};

struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

struct QuicCoreSendDatagram {
    std::optional<QuicPathId> path_id;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};
```

- [ ] **Step 2: Extend receive history and sent-packet records**

```cpp
struct SentPacketRecord {
    // existing fields...
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};

class ReceivedPacketHistory {
    // add ECN feedback availability flag and cumulative counts
};
```

- [ ] **Step 3: Implement ACK ECN count generation**

```cpp
void ReceivedPacketHistory::record_received(std::uint64_t packet_number, bool ack_eliciting,
                                            QuicCoreTimePoint received_time,
                                            QuicEcnCodepoint ecn);
```

- [ ] **Step 4: Implement sender-side path ECN state and validation**

```cpp
enum class QuicPathEcnState : std::uint8_t { probing, capable, failed };

struct PathEcnState {
    QuicPathEcnState state = QuicPathEcnState::probing;
    QuicEcnCodepoint transmit_mark = QuicEcnCodepoint::ect0;
    std::array<AckEcnCounts, 3> last_peer_counts{};
    std::array<bool, 3> has_last_peer_counts{};
    std::uint64_t probing_packets_sent = 0;
    std::uint64_t probing_packets_acked = 0;
    std::uint64_t probing_packets_lost = 0;
};
```

- [ ] **Step 5: Wire ACK processing to validate ECN and react to CE**

```cpp
// In process_inbound_ack:
// 1. collect newly acked/late acked marked packets
// 2. validate ACK ECN deltas per RFC 9000 Section 13.4.2.1
// 3. disable ECN on validation failure or all-probes-lost failure
// 4. call congestion_controller_.on_loss_event(sent_time) when CE counter grows
```

- [ ] **Step 6: Run focused tests to verify green**

Run: `nix develop -c zig build test -- tests/quic_core_test.cpp tests/quic_recovery_test.cpp`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/quic/core.h src/quic/connection.h src/quic/connection.cpp \
  src/quic/recovery.h src/quic/recovery.cpp src/quic/frame.h \
  tests/quic_core_test.cpp tests/quic_recovery_test.cpp
git commit -m "feat: add QUIC ECN protocol support"
```

### Task 4: Implement Linux runtime ECN socket plumbing

**Files:**
- Modify: `src/quic/http09_runtime.cpp`
- Modify: `src/quic/http09_runtime_test_hooks.h`
- Modify: `tests/quic_http09_runtime_test.cpp`
- Modify: `src/quic/core.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Extend runtime ops for Linux socket ECN hooks**

```cpp
int (*setsockopt_fn)(int, int, int, const void *, socklen_t) = nullptr;
ssize_t (*sendmsg_fn)(int, const msghdr *, int) = nullptr;
ssize_t (*recvmsg_fn)(int, msghdr *, int) = nullptr;
```

- [ ] **Step 2: Configure sockets to receive ECN metadata on Linux**

```cpp
// IPv4: IP_RECVTOS
// IPv6: IPV6_RECVTCLASS
```

- [ ] **Step 3: Send marked datagrams with ancillary data**

```cpp
// IPv4: IP_TOS with ECT(0)/ECT(1)
// IPv6: IPV6_TCLASS with ECT(0)/ECT(1)
```

- [ ] **Step 4: Parse incoming ancillary data into QuicCoreInboundDatagram.ecn**

```cpp
// Map IP ECN low bits to QuicEcnCodepoint, defaulting to unavailable when absent.
```

- [ ] **Step 5: Run focused runtime tests**

Run: `nix develop -c zig build test -- tests/quic_http09_runtime_test.cpp`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/quic/http09_runtime.cpp src/quic/http09_runtime_test_hooks.h \
  tests/quic_http09_runtime_test.cpp src/quic/core.cpp
git commit -m "feat: add Linux runtime ECN plumbing"
```

### Task 5: Expose the official `ecn` testcase in checked-in interop coverage

**Files:**
- Modify: `.github/workflows/interop.yml`
- Modify: `tests/nix/github_interop_workflow_test.sh`
- Modify: `interop/entrypoint.sh`
- Modify: `src/quic/http09.h`
- Modify: `src/quic/http09.cpp`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `nix develop -c bash tests/nix/github_interop_workflow_test.sh`

- [ ] **Step 1: Add `ecn` testcase parsing/allowlist support**

```cpp
enum class QuicHttp09Testcase : std::uint8_t {
    // existing cases...
    ecn,
};
```

- [ ] **Step 2: Treat `ecn` as transfer-semantics in the HTTP/0.9 runtime**

```cpp
// parse_testcase("ecn") -> QuicHttp09Testcase::ecn
// transfer_profile_testcase(ecn) -> transfer
```

- [ ] **Step 3: Add `ecn` to the checked-in official workflow testcase lists**

```yaml
INTEROP_TESTCASES: ...,connectionmigration,ecn
```

- [ ] **Step 4: Run workflow contract coverage**

Run: `nix develop -c bash tests/nix/github_interop_workflow_test.sh`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/interop.yml tests/nix/github_interop_workflow_test.sh \
  interop/entrypoint.sh src/quic/http09.h src/quic/http09.cpp src/quic/http09_runtime.cpp
git commit -m "ci: add ECN interop coverage"
```

### Task 6: Full verification for the ECN milestone

**Files:**
- Verify only

- [ ] **Step 1: Run focused unit coverage**

Run: `nix develop -c zig build test -- tests/quic_core_test.cpp tests/quic_recovery_test.cpp tests/quic_http09_runtime_test.cpp`
Expected: PASS

- [ ] **Step 2: Run the workflow contract test**

Run: `nix develop -c bash tests/nix/github_interop_workflow_test.sh`
Expected: `interop-self workflow contract looks correct`

- [ ] **Step 3: Run the full main suite**

Run: `nix develop -c zig build test`
Expected: PASS

- [ ] **Step 4: Capture the exact verification evidence before any completion claim**

```bash
git status --short
```


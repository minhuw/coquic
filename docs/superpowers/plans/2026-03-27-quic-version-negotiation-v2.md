# QUIC Version Negotiation And V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 9368 and RFC 9369 support so `coquic` can negotiate QUIC versions, complete native QUIC v2 handshakes, and authenticate version negotiation with `version_information`.

**Architecture:** Refresh the local RFC corpus first, then make QUIC version a first-class transport concept shared by packet crypto, packet parsing, runtime routing, and transport-parameter validation. Build the feature in test-first slices: v2 wire/crypto support, `version_information` transport parameters, incompatible Version Negotiation restart, and compatible v1<->v2 negotiation.

**Tech Stack:** Zig build system, C++20, GoogleTest, quictls/BoringSSL backends, local QUIC RFC RAG tooling

---

### Task 1: Refresh RFC 9368/9369 sources and rebuild the local RAG index

**Files:**
- Modify: `docs/rfc/rfc9368.txt`
- Modify: `docs/rfc/rfc9369.txt`
- Regenerate local state: `.rag/` (must remain uncommitted)

- [ ] **Step 1: Download the current RFC 9368 and RFC 9369 texts into the repo RFC corpus**

Run:
```bash
curl -fsSL https://www.rfc-editor.org/rfc/rfc9368.txt -o docs/rfc/rfc9368.txt
curl -fsSL https://www.rfc-editor.org/rfc/rfc9369.txt -o docs/rfc/rfc9369.txt
```
Expected: both files update successfully with the canonical RFC Editor text.

- [ ] **Step 2: Rebuild the local QUIC RAG index against the refreshed corpus**

Run:
```bash
tools/rag/scripts/build-index --source docs/rfc --state-dir .rag
tools/rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag
```
Expected: index rebuild completes and `ready: yes` is reported by `doctor`.

- [ ] **Step 3: Verify the refreshed corpus contains the required negotiation sections**

Run:
```bash
tools/rag/scripts/query-rag get-section --rfc 9368 --section-id 2.1
tools/rag/scripts/query-rag get-section --rfc 9368 --section-id 2.3
tools/rag/scripts/query-rag get-section --rfc 9369 --section-id 4.1
```
Expected: the command output shows the incompatible negotiation, compatible negotiation, and v1<->v2 transition requirements used by the implementation.

### Task 2: Add explicit QUIC version helpers and native QUIC v2 Initial support

**Files:**
- Create: `src/quic/version.h`
- Modify: `src/quic/packet_crypto.h`
- Modify: `src/quic/packet_crypto_internal.h`
- Modify: `src/quic/packet_crypto_quictls.cpp`
- Modify: `src/quic/packet_crypto_boringssl.cpp`
- Modify: `src/quic/protected_codec.cpp`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_packet_crypto_test.cpp`
- Test: `tests/quic_protected_codec_test.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing tests for QUIC v2 Initial protection and version-aware packet acceptance**

Add targeted tests that:
- derive different Initial packet keys for v1 and v2 using the same destination connection ID
- round-trip a protected QUIC v2 Initial packet through the protected codec
- verify `QuicConnection` peeking helpers accept QUIC v2 long headers instead of rejecting every non-v1 version

Sketch:
```cpp
TEST(QuicPacketCryptoTest, DeriveDifferentInitialKeysForQuicV2) { ... }
TEST(QuicProtectedCodecTest, RoundTripsQuicV2InitialPacket) { ... }
TEST(QuicCoreTest, ConnectionPeekAcceptsQuicV2InitialPacket) { ... }
```

- [ ] **Step 2: Run the focused tests and verify they fail for the right reason**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicPacketCryptoTest.*V2*:QuicProtectedCodecTest.*V2*:QuicCoreTest.*QuicV2*'
```
Expected: FAIL because QUIC v2 salts and version checks are still hard-coded to v1.

- [ ] **Step 3: Implement minimal version helpers and v2 Initial plumbing**

Introduce a small helper layer such as:
```cpp
constexpr std::uint32_t kQuicVersion1 = 0x00000001u;
constexpr std::uint32_t kQuicVersion2 = 0x6b3343cfu;

constexpr bool is_supported_quic_version(std::uint32_t version) {
    return version == kQuicVersion1 || version == kQuicVersion2;
}

std::span<const std::byte> initial_salt_for_version(std::uint32_t version);
```

Then thread `std::uint32_t version` through `derive_initial_packet_keys(...)` and update the protected codec, connection peeking helpers, and runtime routing to use supported-version checks rather than `version == 1`.

- [ ] **Step 4: Re-run the focused tests and confirm they pass**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicPacketCryptoTest.*V2*:QuicProtectedCodecTest.*V2*:QuicCoreTest.*QuicV2*'
```
Expected: PASS.

### Task 3: Implement the `version_information` transport parameter with validation

**Files:**
- Modify: `src/quic/transport_parameters.h`
- Modify: `src/quic/transport_parameters.cpp`
- Modify: `src/quic/connection.cpp`
- Test: `tests/quic_transport_parameters_test.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing transport-parameter tests for `version_information`**

Add tests that:
- round-trip a `version_information` value containing chosen and available versions
- reject malformed encodings
- reject missing `version_information` for QUIC v2-capable peers
- accept the RFC 9368 Section 8 QUIC v1 special case where appropriate

Sketch:
```cpp
TEST(QuicTransportParametersTest, RoundTripsVersionInformation) { ... }
TEST(QuicTransportParametersTest, RejectsMalformedVersionInformation) { ... }
TEST(QuicCoreTest, PeerTransportParametersRequireVersionInformationForQuicV2) { ... }
```

- [ ] **Step 2: Run the focused transport-parameter tests and verify they fail correctly**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicTransportParametersTest.*VersionInformation*:QuicCoreTest.*VersionInformation*'
```
Expected: FAIL because the transport-parameter model and validation context do not yet contain version negotiation state.

- [ ] **Step 3: Add typed `version_information` support and negotiation-aware validation**

Extend the transport-parameter types with a concrete model such as:
```cpp
struct VersionInformation {
    std::uint32_t chosen_version = 0;
    std::vector<std::uint32_t> available_versions;
};
```

Extend `TransportParameters` and `TransportParametersValidationContext` to carry:
- optional `version_information`
- original version
- negotiated version when known
- locally supported versions
- whether incompatible negotiation occurred

Implement serialization, deserialization, and validation in `transport_parameters.cpp`, then feed the new validation context from `connection.cpp`.

- [ ] **Step 4: Re-run the focused transport-parameter tests and confirm they pass**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicTransportParametersTest.*VersionInformation*:QuicCoreTest.*VersionInformation*'
```
Expected: PASS.

### Task 4: Implement incompatible Version Negotiation and client restart

**Files:**
- Modify: `src/quic/core.h`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_core_test.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write failing tests for client restart after Version Negotiation**

Add tests that:
- verify server stateless Version Negotiation packets advertise both v1 and v2
- verify a client that receives a valid Version Negotiation packet starts a new first flight with a mutually supported version
- verify the client ignores Version Negotiation packets that echo the originally chosen version or contain wrong connection IDs

Sketch:
```cpp
TEST(QuicCoreTest, ClientRestartsHandshakeAfterValidVersionNegotiation) { ... }
TEST(QuicCoreTest, ClientIgnoresInvalidVersionNegotiationPacket) { ... }
TEST(QuicHttp09RuntimeTest, ServerAdvertisesV1AndV2InVersionNegotiation) { ... }
```

- [ ] **Step 2: Run the focused negotiation tests and verify they fail correctly**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*VersionNegotiation*:QuicHttp09RuntimeTest.*VersionNegotiation*'
```
Expected: FAIL because the client currently has no Version Negotiation state machine and the runtime only advertises v1.

- [ ] **Step 3: Implement incompatible negotiation state and restart logic**

Add connection/core state for:
```cpp
struct VersionNegotiationState {
    std::uint32_t original_version = kQuicVersion1;
    std::uint32_t current_version = kQuicVersion1;
    std::optional<std::uint32_t> negotiated_version;
    std::vector<std::uint32_t> supported_versions;
    bool incompatible_negotiation_attempted = false;
};
```

Then:
- parse inbound plaintext Version Negotiation packets before normal protected-packet processing on the client path
- select a mutually supported version
- reset handshake startup state for a fresh first flight
- update the runtime stateless response path to advertise all locally offered versions

- [ ] **Step 4: Re-run the focused negotiation tests and confirm they pass**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*VersionNegotiation*:QuicHttp09RuntimeTest.*VersionNegotiation*'
```
Expected: PASS.

### Task 5: Implement compatible v1<->v2 negotiation and end-to-end verification

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/core.h`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_core_test.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write failing tests for compatible negotiation and negotiated-version packet transitions**

Add tests that:
- verify a dual-version server upgrades a v1 first flight to v2
- verify the client learns the negotiated version from the first differing long-header version
- verify Handshake and 1-RTT packets use the negotiated version after the transition
- verify inconsistent authenticated Version Information fails the connection
- verify local HTTP/0.9 transfer succeeds over native v2 and after compatible negotiation

Sketch:
```cpp
TEST(QuicCoreTest, CompatibleNegotiationUpgradesV1HandshakeToV2) { ... }
TEST(QuicCoreTest, RejectsInconsistentAuthenticatedVersionInformation) { ... }
TEST(QuicHttp09RuntimeTest, TransferSucceedsAfterCompatibleVersionNegotiation) { ... }
TEST(QuicHttp09RuntimeTest, TransferSucceedsOverNativeQuicV2) { ... }
```

- [ ] **Step 2: Run the focused compatible-negotiation tests and verify they fail correctly**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Compatible*:QuicHttp09RuntimeTest.*QuicV2*:QuicHttp09RuntimeTest.*Compatible*'
```
Expected: FAIL because the handshake state machine still emits and accepts only v1 packet versions.

- [ ] **Step 3: Implement compatible negotiation state transitions in `QuicConnection`**

Update the connection to:
- preserve the original version for pre-negotiation Initial traffic
- choose the negotiated version when both sides support v1 and v2
- learn the negotiated version from inbound long-header packets
- emit Handshake and 1-RTT packets with the negotiated version
- drop packets that use the wrong version after the negotiated-version transition

Keep the change minimal by extending the existing handshake state rather than adding a second handshake engine.

- [ ] **Step 4: Re-run the focused compatible-negotiation tests and confirm they pass**

Run:
```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.*Compatible*:QuicHttp09RuntimeTest.*QuicV2*:QuicHttp09RuntimeTest.*Compatible*'
```
Expected: PASS.

### Task 6: Run the full verification set

**Files:**
- Modify: any files touched by Tasks 1-5

- [ ] **Step 1: Run the full unit and runtime test suite**

Run:
```bash
nix develop -c zig build test
```
Expected: PASS.

- [ ] **Step 2: Run the full source-coverage pipeline to catch untested negotiation branches**

Run:
```bash
nix develop -c zig build coverage
```
Expected: PASS and regenerate `coverage/html/index.html`.

- [ ] **Step 3: Spot-check the refreshed RAG and record the final state**

Run:
```bash
tools/rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag
git status --short
```
Expected: `ready: yes` from the RAG doctor, a clean tree except for intended source/test/doc changes, and no committed `.rag/` state.

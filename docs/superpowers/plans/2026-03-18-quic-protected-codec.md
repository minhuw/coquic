# QUIC Protected Codec Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a stateless QUIC protected datagram codec for `Initial`, `Handshake`, and `1-RTT` packets on top of the existing plaintext codec, with caller-supplied secrets and packet-number context.

**Architecture:** Keep the current plaintext packet/frame codec intact and layer a new `protected_codec` above it. `packet_number` owns truncation and recovery, `packet_crypto` owns Initial key derivation plus AEAD and header protection, and `protected_codec` converts between protected packet structs and plaintext packet images while patching long-header lengths before encryption and after decryption.

**Tech Stack:** C++20, OpenSSL EVP/HKDF primitives, Zig build, GoogleTest, RFC 9000/RFC 9001 packet format and crypto rules

---

## File Map

- Modify: `build.zig`
  - Compile new QUIC crypto sources and add dedicated protected-codec tests.
- Modify: `src/coquic.h`
  - Export the new protected codec API next to the plaintext codec API.
- Modify: `src/quic/varint.h`
  - Extend `CodecErrorCode` with crypto/protection failures.
- Create: `src/quic/packet_number.h`
  - Declare packet-number truncation and recovery helpers.
- Create: `src/quic/packet_number.cpp`
  - Implement RFC 9000 Appendix A.3 recovery and sender-side truncation validation.
- Create: `src/quic/packet_crypto.h`
  - Declare cipher-suite-aware key expansion, nonce, AEAD, and header-protection helpers.
- Create: `src/quic/packet_crypto.cpp`
  - Implement Initial secret derivation, traffic-secret expansion, AEAD seal/open, and AES/ChaCha20 header protection.
- Create: `src/quic/protected_codec.h`
  - Define `CipherSuite`, `EndpointRole`, `TrafficSecret`, protected packet structs, protected contexts, and top-level APIs.
- Create: `src/quic/protected_codec.cpp`
  - Implement protected packet serialization/deserialization and datagram coalescing.
- Create: `tests/quic_packet_number_test.cpp`
  - Lock down packet-number truncation and recovery behavior, including the empty-space bootstrap case.
- Create: `tests/quic_packet_crypto_test.cpp`
  - Lock down Initial key derivation, HKDF label expansion, AEAD, and header protection with RFC-backed vectors.
- Create: `tests/quic_protected_codec_test.cpp`
  - Cover end-to-end protected `Initial`, `Handshake`, and `1-RTT` round trips plus error paths.

### Task 1: Add The Public Surface And Failing API Tests

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.h`
- Modify: `src/quic/varint.h`
- Create: `src/quic/protected_codec.h`
- Create: `tests/quic_protected_codec_test.cpp`

- [ ] **Step 1: Extend codec errors for protection failures**

Add these enum members to `src/quic/varint.h` after the existing plaintext-only
errors:

```cpp
missing_crypto_context,
unsupported_cipher_suite,
packet_number_recovery_failed,
header_protection_sample_too_short,
header_protection_failed,
packet_decryption_failed,
invalid_packet_protection_state,
```

- [ ] **Step 2: Declare the protected codec types**

Create `src/quic/protected_codec.h` with the public API skeleton:

```cpp
enum class CipherSuite : std::uint8_t {
    tls_aes_128_gcm_sha256,
    tls_aes_256_gcm_sha384,
    tls_chacha20_poly1305_sha256,
};

enum class EndpointRole : std::uint8_t {
    client,
    server,
};

struct TrafficSecret {
    CipherSuite cipher_suite;
    std::vector<std::byte> secret;
};

struct ProtectedInitialPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
};
```

Also add `ProtectedHandshakePacket`, `ProtectedOneRttPacket`,
`SerializeProtectionContext`, `DeserializeProtectionContext`,
`using ProtectedPacket = std::variant<...>`, and declarations for:

```cpp
CodecResult<std::vector<std::byte>> serialize_protected_datagram(
    std::span<const ProtectedPacket> packets,
    const SerializeProtectionContext& context
);

CodecResult<std::vector<ProtectedPacket>> deserialize_protected_datagram(
    std::span<const std::byte> bytes,
    const DeserializeProtectionContext& context
);
```

- [ ] **Step 3: Export the new API**

Update `src/coquic.h` to include:

```cpp
#include "src/quic/protected_codec.h"
```

alongside the plaintext include.

- [ ] **Step 4: Add failing end-to-end API tests**

Create `tests/quic_protected_codec_test.cpp` with compile-time coverage of the
public API and one runtime expectation that will fail until the implementation
exists:

```cpp
TEST(QuicProtectedCodecTest, DeclaresInitialRoundTripApi) {
    const std::vector<coquic::quic::ProtectedPacket> packets{
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .source_connection_id = {},
            .token = {},
            .packet_number_length = 4,
            .packet_number = 2,
            .frames = {coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
            }},
        },
    };

    const coquic::quic::SerializeProtectionContext serialize_context{
        .local_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id = {
            std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
            std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
        },
    };

    const auto encoded =
        coquic::quic::serialize_protected_datagram(packets, serialize_context);
    EXPECT_TRUE(encoded.has_value());
}
```

- [ ] **Step 5: Wire the new test into the build**

Update `build.zig` so the test binary compiles `tests/quic_protected_codec_test.cpp`.
Do not add `src/quic/protected_codec.cpp` yet.

- [ ] **Step 6: Run the test to verify it fails before implementation**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*`
Expected: FAIL at link time because `serialize_protected_datagram(...)` and
`deserialize_protected_datagram(...)` are declared but not defined yet.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/coquic.h src/quic/varint.h src/quic/protected_codec.h \
    tests/quic_protected_codec_test.cpp
git commit -m "test: add QUIC protected codec API surface"
```

### Task 2: Add Packet Number Helpers With RFC Vectors

**Files:**
- Modify: `build.zig`
- Create: `src/quic/packet_number.h`
- Create: `src/quic/packet_number.cpp`
- Create: `tests/quic_packet_number_test.cpp`

- [ ] **Step 1: Write the failing packet-number tests**

Create `tests/quic_packet_number_test.cpp` with these cases:

```cpp
TEST(QuicPacketNumberTest, RecoversPacketNumberFromRfc9000AppendixA3Example) {
    const auto recovered = coquic::quic::recover_packet_number(
        0xa82f30eaULL,
        0x9b32U,
        2
    );
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered.value(), 0xa82f9b32ULL);
}

TEST(QuicPacketNumberTest, RecoversFirstPacketWhenLargestAuthenticatedIsMissing) {
    const auto recovered = coquic::quic::recover_packet_number(std::nullopt, 0U, 1);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered.value(), 0ULL);
}

TEST(QuicPacketNumberTest, RejectsInvalidPacketNumberLength) {
    const auto recovered = coquic::quic::recover_packet_number(7ULL, 1U, 0);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}
```

Add a truncation test too:

```cpp
EXPECT_EQ(coquic::quic::truncate_packet_number(0x12345678ULL, 2).value(), 0x5678U);
```

- [ ] **Step 2: Run the new tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicPacketNumberTest.*`
Expected: FAIL because the helper declarations and implementation do not exist.

- [ ] **Step 3: Declare the helper API**

Create `src/quic/packet_number.h` with:

```cpp
CodecResult<std::uint32_t> truncate_packet_number(std::uint64_t packet_number,
                                                  std::uint8_t packet_number_length);

CodecResult<std::uint64_t> recover_packet_number(
    std::optional<std::uint64_t> largest_authenticated_packet_number,
    std::uint32_t truncated_packet_number,
    std::uint8_t packet_number_length
);
```

- [ ] **Step 4: Implement RFC 9000 Appendix A.3 recovery**

Implement `src/quic/packet_number.cpp` exactly around the RFC algorithm:

```cpp
const auto expected_packet_number =
    largest_authenticated_packet_number.has_value()
        ? (largest_authenticated_packet_number.value() + 1)
        : 0;
```

then compute the candidate packet number, half-window adjustment, and overflow
guards from RFC 9000 Appendix A.3.

- [ ] **Step 5: Add the helper source to the library build**

Update `build.zig` so the project library compiles `src/quic/packet_number.cpp`
and the test binary compiles `tests/quic_packet_number_test.cpp`.

- [ ] **Step 6: Re-run the filtered tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicPacketNumberTest.*`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/quic/packet_number.h src/quic/packet_number.cpp \
    tests/quic_packet_number_test.cpp
git commit -m "feat: add QUIC packet number helpers"
```

### Task 3: Add Initial Secret Derivation And Key Expansion Helpers

**Files:**
- Modify: `build.zig`
- Create: `src/quic/packet_crypto.h`
- Create: `src/quic/packet_crypto.cpp`
- Create: `tests/quic_packet_crypto_test.cpp`

- [ ] **Step 1: Write failing RFC-backed key-derivation tests**

Create `tests/quic_packet_crypto_test.cpp` with the RFC 9001 Appendix A.1
vectors for client DCID `0x8394c8f03e515708`:

```cpp
TEST(QuicPacketCryptoTest, DerivesClientInitialKeysFromRfc9001AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::client,
        true,
        hex_bytes("8394c8f03e515708")
    );
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "1f369613dd76d5467730efcbe3b1a22d");
    EXPECT_EQ(to_hex(keys.value().iv), "fa044b2f42a3fd3b46fb255c");
    EXPECT_EQ(to_hex(keys.value().hp_key), "9f50449e04a0e810283a1e9933adedd2");
}

TEST(QuicPacketCryptoTest, DerivesServerInitialKeysFromRfc9001AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::server,
        true,
        hex_bytes("8394c8f03e515708")
    );
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "cf3a5331653c364c88f0f379b6067e37");
    EXPECT_EQ(to_hex(keys.value().iv), "0ac1493ca1905853b0bba03e");
    EXPECT_EQ(to_hex(keys.value().hp_key), "c206b8d9b9f0f37644430b490eeaa314");
}
```

Add one traffic-secret expansion test too:

```cpp
TEST(QuicPacketCryptoTest, ExpandsChaChaTrafficSecretFromRfc9001AppendixA5) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        .secret = hex_bytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"),
    };

    const auto keys = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key),
              "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
    EXPECT_EQ(to_hex(keys.value().iv), "e0459b3474bdd0e44a41c144");
    EXPECT_EQ(to_hex(keys.value().hp_key),
              "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicPacketCryptoTest.Derives*`
Expected: FAIL because `packet_crypto` does not exist yet.

- [ ] **Step 3: Declare the crypto helper API**

Create `src/quic/packet_crypto.h` with:

```cpp
struct PacketProtectionKeys {
    std::vector<std::byte> key;
    std::vector<std::byte> iv;
    std::vector<std::byte> hp_key;
};

CodecResult<PacketProtectionKeys> derive_initial_packet_keys(
    EndpointRole local_role,
    bool for_local_send,
    const ConnectionId& client_initial_destination_connection_id
);

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret& secret);
```

- [ ] **Step 4: Implement HKDF-Extract and HKDF-Expand-Label helpers**

In `src/quic/packet_crypto.cpp`, use OpenSSL HKDF primitives to implement:

- QUIC v1 Initial salt extraction with SHA-256
- TLS 1.3 `HKDF-Expand-Label` for `"client in"`, `"server in"`, `"quic key"`,
  `"quic iv"`, and `"quic hp"`
- hash selection by `CipherSuite`

Keep the `HKDF-Expand-Label` wire label construction explicit:

```cpp
// "tls13 " + label, zero-length context
```

- [ ] **Step 5: Add the source and tests to `build.zig`**

Compile `src/quic/packet_crypto.cpp` into the library and
`tests/quic_packet_crypto_test.cpp` into the test binary.

- [ ] **Step 6: Re-run the filtered tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicPacketCryptoTest.Derives*`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/quic/packet_crypto.h src/quic/packet_crypto.cpp \
    tests/quic_packet_crypto_test.cpp
git commit -m "feat: add QUIC packet key derivation"
```

### Task 4: Add AEAD And Header-Protection Primitives

**Files:**
- Modify: `src/quic/packet_crypto.h`
- Modify: `src/quic/packet_crypto.cpp`
- Modify: `tests/quic_packet_crypto_test.cpp`

- [ ] **Step 1: Extend the crypto tests with deterministic vectors**

Add an AES header-protection test from RFC 9001 Appendix A.2:

```cpp
TEST(QuicPacketCryptoTest, BuildsAesHeaderProtectionMaskFromRfc9001AppendixA2) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
        hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b")
    );
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "437b9aec36");
}
```

Add a ChaCha20 header-protection test from RFC 9001 Appendix A.5:

```cpp
TEST(QuicPacketCryptoTest, BuildsChaChaHeaderProtectionMaskFromRfc9001AppendixA5) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
        hex_bytes("5e5cd55c41f69080575d7999c25a5bfb")
    );
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "aefefe7d03");
}
```

Add one nonce and AEAD round-trip test:

```cpp
TEST(QuicPacketCryptoTest, SealsAndOpensPayloadWithAssociatedData) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"),
        654360564ULL
    );
    ASSERT_TRUE(nonce.has_value());
    EXPECT_EQ(to_hex(nonce.value()), "e0459b3474bdd0e46d417eb0");
}
```

- [ ] **Step 2: Run the crypto tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicPacketCryptoTest.*`
Expected: FAIL because mask and AEAD helpers are still missing.

- [ ] **Step 3: Add the remaining declarations**

Extend `src/quic/packet_crypto.h` with:

```cpp
CodecResult<std::vector<std::byte>> make_packet_protection_nonce(
    std::span<const std::byte> iv,
    std::uint64_t packet_number
);

CodecResult<std::vector<std::byte>> seal_payload(
    CipherSuite cipher_suite,
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> associated_data,
    std::span<const std::byte> plaintext
);

CodecResult<std::vector<std::byte>> open_payload(
    CipherSuite cipher_suite,
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> associated_data,
    std::span<const std::byte> ciphertext
);

CodecResult<std::vector<std::byte>> make_header_protection_mask(
    CipherSuite cipher_suite,
    std::span<const std::byte> hp_key,
    std::span<const std::byte> sample
);
```

- [ ] **Step 4: Implement nonce, AEAD, and header protection**

In `src/quic/packet_crypto.cpp`:

- XOR the packet number into the IV to form the nonce.
- Use the correct OpenSSL AEAD for each `CipherSuite`.
- Return `packet_decryption_failed` on authentication failure.
- Use AES-ECB for the AES suites and raw ChaCha20 for the ChaCha suite to
  produce the 5-byte header-protection mask.
- Validate sample length is exactly 16 bytes and return
  `header_protection_sample_too_short` when too short.

- [ ] **Step 5: Re-run the crypto tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicPacketCryptoTest.*`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/packet_crypto.h src/quic/packet_crypto.cpp \
    tests/quic_packet_crypto_test.cpp
git commit -m "feat: add QUIC packet protection primitives"
```

### Task 5: Implement Protected Initial Packets End To End

**Files:**
- Modify: `build.zig`
- Modify: `src/quic/protected_codec.h`
- Create: `src/quic/protected_codec.cpp`
- Modify: `tests/quic_protected_codec_test.cpp`

- [ ] **Step 1: Add failing Initial packet vector tests**

Extend `tests/quic_protected_codec_test.cpp` with the RFC 9001 Appendix A.2
client Initial packet vector:

```cpp
TEST(QuicProtectedCodecTest, SerializesClientInitialFromRfc9001AppendixA2) {
    const auto packet = make_rfc9001_client_initial_packet();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_rfc9001_client_initial_serialize_context()
    );
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(to_hex(encoded.value()), kRfc9001ClientInitialPacketHex);
}

TEST(QuicProtectedCodecTest, DeserializesClientInitialFromRfc9001AppendixA2) {
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        hex_bytes(kRfc9001ClientInitialPacketHex),
        make_rfc9001_client_initial_deserialize_context()
    );
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    const auto* initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->packet_number, 2ULL);
}
```

Also add:

```cpp
TEST(QuicProtectedCodecTest, RejectsInitialWithoutClientInitialDestinationConnectionId) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        {}
    );
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}
```

- [ ] **Step 2: Run the Initial tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*Initial*`
Expected: FAIL because the protected codec implementation does not exist yet.

- [ ] **Step 3: Implement plaintext-image conversion helpers**

In `src/quic/protected_codec.cpp`, add helpers that:

- convert `ProtectedInitialPacket` to plaintext `InitialPacket` by truncating the
  full packet number with `truncate_packet_number(...)`;
- call `serialize_packet(...)` to build the plaintext image;
- locate and patch the long-header `Length` field so it reflects
  `packet_number_length + ciphertext_size` instead of plaintext payload size.

Keep the patching logic in a small helper that only touches the encoded
`Length` varint bytes.

- [ ] **Step 4: Implement Initial encryption and decryption**

Add long-header protected flow that:

- derives Initial send or receive keys from the client Initial DCID;
- builds the nonce from the full packet number;
- uses the unprotected header as AEAD associated data;
- applies header protection after encryption;
- removes header protection before packet-number recovery and decryption; and
- reconstructs a plaintext image after decryption, patches the long-header
  `Length` back to plaintext size, then calls `deserialize_packet(...)`.

- [ ] **Step 5: Add `src/quic/protected_codec.cpp` to the build**

Update `build.zig` so the library now compiles `src/quic/protected_codec.cpp`.

- [ ] **Step 6: Re-run the Initial tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*Initial*`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add build.zig src/quic/protected_codec.h src/quic/protected_codec.cpp \
    tests/quic_protected_codec_test.cpp
git commit -m "feat: add QUIC Initial protected codec"
```

### Task 6: Implement Protected Handshake Packets For All Three Cipher Suites

**Files:**
- Modify: `src/quic/protected_codec.cpp`
- Modify: `tests/quic_protected_codec_test.cpp`

- [ ] **Step 1: Add failing Handshake tests**

Add a parameterized Handshake round-trip test that runs for:

- `CipherSuite::tls_aes_128_gcm_sha256` with a 32-byte secret
- `CipherSuite::tls_aes_256_gcm_sha384` with a 48-byte secret
- `CipherSuite::tls_chacha20_poly1305_sha256` with a 32-byte secret

Use concrete secrets in the test fixture so results are deterministic, for
example:

```cpp
std::vector<std::byte> make_secret(std::size_t size) {
    std::vector<std::byte> secret(size);
    for (std::size_t i = 0; i < size; ++i) {
        secret[i] = static_cast<std::byte>(i);
    }
    return secret;
}
```

Add one negative test too:

```cpp
TEST(QuicProtectedCodecTest, RejectsHandshakePacketWithoutHandshakeSecret) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_context_without_handshake_secret()
    );
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}
```

- [ ] **Step 2: Run the Handshake tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*Handshake*`
Expected: FAIL.

- [ ] **Step 3: Implement Handshake secret expansion in the codec**

Extend the long-header path in `src/quic/protected_codec.cpp` so Handshake
packets:

- require `context.handshake_secret`;
- derive packet protection keys from `expand_traffic_secret(...)`;
- reuse the same long-header encrypt/decrypt path as Initial packets, but with
  caller-supplied traffic secrets instead of Initial derivation.

- [ ] **Step 4: Add one wrong-secret decryption failure test**

Extend `tests/quic_protected_codec_test.cpp` with:

```cpp
TEST(QuicProtectedCodecTest, RejectsHandshakePacketWhenSecretDoesNotMatch) {
    const auto encoded = serialize_with_known_handshake_secret();
    const auto decoded = deserialize_with_different_handshake_secret(encoded.value());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}
```

- [ ] **Step 5: Re-run the Handshake tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*Handshake*`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/protected_codec.cpp tests/quic_protected_codec_test.cpp
git commit -m "feat: add QUIC Handshake protected codec"
```

### Task 7: Implement Protected 1-RTT Packets For All Three Cipher Suites

**Files:**
- Modify: `src/quic/protected_codec.cpp`
- Modify: `tests/quic_protected_codec_test.cpp`

- [ ] **Step 1: Add failing 1-RTT tests**

Add parameterized `1-RTT` round-trip tests that cover:

- all three cipher suites;
- short-header destination connection ID length from
  `DeserializeProtectionContext::one_rtt_destination_connection_id_length`;
- packet-number recovery with a nontrivial largest-authenticated application
  packet number; and
- single active key-phase validation.

Use the RFC 9000 Appendix A.3 recovery example in the setup:

```cpp
const auto largest_authenticated = 0xa82f30eaULL;
const auto full_packet_number = 0xa82f9b32ULL;
const std::uint8_t packet_number_length = 2;
```

Add two negative tests:

```cpp
TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenKeyPhaseDoesNotMatchContext);
TEST(QuicProtectedCodecTest, RejectsOneRttPacketWithoutDestinationConnectionIdLength);
```

- [ ] **Step 2: Run the 1-RTT tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*OneRtt*`
Expected: FAIL.

- [ ] **Step 3: Implement the short-header path**

In `src/quic/protected_codec.cpp`:

- convert `ProtectedOneRttPacket` to plaintext `OneRttPacket` with a truncated
  packet number;
- call `serialize_packet(...)` to get the plaintext short-header image;
- compute `pn_offset = 1 + destination_connection_id.size()`;
- encrypt the payload and apply header protection;
- on receive, remove header protection before reading the encoded packet number
  length, recover the full packet number, decrypt, then rebuild the plaintext
  image and call `deserialize_packet(...)` with:

```cpp
DeserializeOptions{
    .one_rtt_destination_connection_id_length =
        context.one_rtt_destination_connection_id_length,
};
```

- [ ] **Step 4: Enforce single-key-phase behavior**

During outbound serialization and inbound deserialization, reject packets when:

- `ProtectedOneRttPacket::key_phase != context.one_rtt_key_phase`; or
- the unprotected short header reveals a key phase different from the active
  context.

Return `CodecErrorCode::invalid_packet_protection_state`.

- [ ] **Step 5: Re-run the 1-RTT tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*OneRtt*`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/protected_codec.cpp tests/quic_protected_codec_test.cpp
git commit -m "feat: add QUIC 1-RTT protected codec"
```

### Task 8: Finish Datagram Coalescing And Negative Coverage

**Files:**
- Modify: `src/quic/protected_codec.cpp`
- Modify: `tests/quic_protected_codec_test.cpp`

- [ ] **Step 1: Add failing coalesced-datagram and error-offset tests**

Extend `tests/quic_protected_codec_test.cpp` with:

```cpp
TEST(QuicProtectedCodecTest, RoundTripsCoalescedInitialAndHandshakeDatagram);
TEST(QuicProtectedCodecTest, RejectsEmptyProtectedDatagram);
TEST(QuicProtectedCodecTest, ReportsOffsetOfSecondPacketFailureInDatagram);
TEST(QuicProtectedCodecTest, RejectsUnsupportedProtectedPacketTypes);
TEST(QuicProtectedCodecTest, RejectsPacketsTooShortForHeaderProtectionSample);
```

Make the second-packet-offset test build a valid Initial followed by a truncated
Handshake so the expected offset is the byte length of the first packet.

- [ ] **Step 2: Run the datagram tests and confirm they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*Datagram*`
Expected: FAIL.

- [ ] **Step 3: Implement top-level datagram loops and offset propagation**

In `src/quic/protected_codec.cpp`:

- make `serialize_protected_datagram(...)` serialize each protected packet in
  order and concatenate the resulting bytes;
- make `deserialize_protected_datagram(...)` parse packets until all bytes are
  consumed;
- when a packet fails, add the packet start offset to the packet-local error;
- reject unsupported protected packet variants or unsupported long-header types
  with `unsupported_packet_type`.

- [ ] **Step 4: Re-run the focused datagram tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*Datagram*`
Expected: PASS.

- [ ] **Step 5: Re-run the full protected codec test file**

Run: `nix develop -c zig build test -- --gtest_filter=QuicProtectedCodecTest.*`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/protected_codec.cpp tests/quic_protected_codec_test.cpp
git commit -m "feat: finish QUIC protected datagram codec"
```

### Task 9: Run Full Verification And Coverage

**Files:**
- Modify: none

- [ ] **Step 1: Run formatting**

Run: `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
Expected: PASS.

- [ ] **Step 2: Run lint**

Run: `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
Expected: PASS.

- [ ] **Step 3: Run the full build**

Run: `nix develop -c zig build`
Expected: PASS.

- [ ] **Step 4: Run the full test suite**

Run: `nix develop -c zig build test`
Expected: PASS.

- [ ] **Step 5: Run coverage**

Run: `nix develop -c zig build coverage`
Expected: PASS with 100% line coverage.

- [ ] **Step 6: Confirm the tree is clean**

Run: `git status --short`
Expected: clean working tree after the task commits.

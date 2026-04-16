#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"

namespace coquic::quic {
CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret);
// Test-local adapters preserve the existing test call sites while the public
// API uses request structs to satisfy clang-tidy in production code.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
CodecResult<std::vector<std::byte>> make_packet_protection_nonce(std::span<const std::byte> iv,
                                                                 std::uint64_t packet_number) {
    return make_packet_protection_nonce(PacketProtectionNonceInput{
        .iv = iv,
        .packet_number = packet_number,
    });
}

CodecResult<std::size_t> make_packet_protection_nonce_into(std::span<const std::byte> iv,
                                                           std::uint64_t packet_number,
                                                           std::span<std::byte> nonce) {
    return make_packet_protection_nonce_into(
        PacketProtectionNonceInput{
            .iv = iv,
            .packet_number = packet_number,
        },
        nonce);
}

CodecResult<std::size_t> seal_payload_into(CipherSuite cipher_suite, std::span<const std::byte> key,
                                           std::span<const std::byte> nonce,
                                           std::span<const std::byte> associated_data,
                                           std::span<const std::byte> plaintext,
                                           std::span<std::byte> ciphertext) {
    return seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = key,
        .nonce = nonce,
        .associated_data = associated_data,
        .plaintext = plaintext,
        .ciphertext = ciphertext,
    });
}

CodecResult<std::size_t> seal_payload_chunks_into(CipherSuite cipher_suite,
                                                  std::span<const std::byte> key,
                                                  std::span<const std::byte> nonce,
                                                  std::span<const std::byte> associated_data,
                                                  std::span<const PlaintextChunk> plaintext_chunks,
                                                  std::span<std::byte> ciphertext) {
    return seal_payload_chunks_into(SealPayloadChunksIntoInput{
        .cipher_suite = cipher_suite,
        .key = key,
        .nonce = nonce,
        .associated_data = associated_data,
        .plaintext_chunks = plaintext_chunks,
        .ciphertext = ciphertext,
    });
}

CodecResult<std::vector<std::byte>> seal_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> plaintext) {
    return seal_payload(SealPayloadInput{
        .cipher_suite = cipher_suite,
        .key = key,
        .nonce = nonce,
        .associated_data = associated_data,
        .plaintext = plaintext,
    });
}

CodecResult<std::vector<std::byte>> open_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> ciphertext) {
    return open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = key,
        .nonce = nonce,
        .associated_data = associated_data,
        .ciphertext = ciphertext,
    });
}
// NOLINTEND(bugprone-easily-swappable-parameters)
} // namespace coquic::quic

namespace {

template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return *value;
}

std::vector<std::byte> hex_bytes(const char *hex) {
    std::vector<std::byte> bytes;
    const std::string_view text{hex};
    if ((text.size() % 2) != 0) {
        ADD_FAILURE() << "hex string must contain an even number of characters: " << text;
        return bytes;
    }

    bytes.reserve(text.size() / 2);

    const auto hex_value = [](char ch) -> std::optional<std::uint8_t> {
        if (ch >= '0' && ch <= '9') {
            return static_cast<std::uint8_t>(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f') {
            return static_cast<std::uint8_t>(10 + (ch - 'a'));
        }
        if (ch >= 'A' && ch <= 'F') {
            return static_cast<std::uint8_t>(10 + (ch - 'A'));
        }
        return std::nullopt;
    };

    for (std::size_t index = 0; index < text.size(); index += 2) {
        const auto high = hex_value(text[index]);
        const auto low = hex_value(text[index + 1]);
        if (!high.has_value() || !low.has_value()) {
            ADD_FAILURE() << "hex string contains a non-hex character: " << text;
            return {};
        }
        bytes.push_back(static_cast<std::byte>((high.value() << 4) | low.value()));
    }

    return bytes;
}

std::string to_hex(const std::vector<std::byte> &bytes) {
    static constexpr char digits[] = "0123456789abcdef";

    std::string text;
    text.reserve(bytes.size() * 2);

    for (const auto byte : bytes) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        text.push_back(digits[value >> 4]);
        text.push_back(digits[value & 0x0f]);
    }

    return text;
}

std::vector<std::byte> make_secret(std::size_t size) {
    std::vector<std::byte> secret(size);
    for (std::size_t index = 0; index < size; ++index) {
        secret[index] = static_cast<std::byte>(index);
    }
    return secret;
}

std::array<std::byte, 16> hex_array16(const char *hex) {
    const auto bytes = hex_bytes(hex);
    std::array<std::byte, 16> output{};
    if (bytes.size() != output.size()) {
        ADD_FAILURE() << "hex string must decode to exactly 16 bytes";
        return output;
    }

    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = bytes[index];
    }

    return output;
}

class ReservedSpan {
  public:
    explicit ReservedSpan(std::size_t size) : size_(size) {
        bytes_ = static_cast<std::byte *>(
            mmap(nullptr, size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    }

    ~ReservedSpan() {
        if (bytes_ != MAP_FAILED) {
            munmap(bytes_, size_);
        }
    }

    ReservedSpan(const ReservedSpan &) = delete;
    ReservedSpan &operator=(const ReservedSpan &) = delete;

    bool ok() const {
        return bytes_ != MAP_FAILED;
    }
    std::span<const std::byte> bytes() const {
        return {bytes_, size_};
    }

  private:
    std::byte *bytes_ = static_cast<std::byte *>(MAP_FAILED);
    std::size_t size_ = 0;
};

coquic::quic::CipherSuite invalid_cipher_suite() {
    const auto raw = static_cast<std::underlying_type_t<coquic::quic::CipherSuite>>(0xff);
    coquic::quic::CipherSuite cipher_suite{};
    std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
    return cipher_suite;
}

struct PacketCryptoFaultCase {
    const char *name;
    coquic::quic::test::PacketCryptoFaultPoint fault_point;
    std::size_t occurrence;
    coquic::quic::CodecErrorCode error_code;
};

struct PacketCryptoHeaderProtectionFaultCase {
    const char *name;
    coquic::quic::CipherSuite cipher_suite;
    std::vector<std::byte> hp_key;
    std::vector<std::byte> sample;
    coquic::quic::test::PacketCryptoFaultPoint fault_point;
};

class QuicPacketCryptoInitialKeyFaultTest : public testing::TestWithParam<PacketCryptoFaultCase> {};

class QuicPacketCryptoTrafficSecretFaultTest
    : public testing::TestWithParam<PacketCryptoFaultCase> {};

class QuicPacketCryptoSealFaultTest : public testing::TestWithParam<PacketCryptoFaultCase> {};

class QuicPacketCryptoOpenFaultTest : public testing::TestWithParam<PacketCryptoFaultCase> {};

class QuicPacketCryptoHeaderProtectionFaultTest
    : public testing::TestWithParam<PacketCryptoHeaderProtectionFaultCase> {};

TEST_P(QuicPacketCryptoInitialKeyFaultTest, RejectsInitialKeyDerivationWhenFaultInjected) {
    const auto params = GetParam();
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(params.fault_point,
                                                                       params.occurrence);

    const auto keys = coquic::quic::derive_initial_packet_keys(coquic::quic::EndpointRole::client,
                                                               true, hex_bytes("8394c8f03e515708"));
    ASSERT_FALSE(keys.has_value());
    EXPECT_EQ(keys.error().code, params.error_code);
}

TEST_P(QuicPacketCryptoTrafficSecretFaultTest, RejectsTrafficSecretExpansionWhenFaultInjected) {
    const auto params = GetParam();
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(params.fault_point,
                                                                       params.occurrence);

    const auto keys = coquic::quic::expand_traffic_secret(secret);
    ASSERT_FALSE(keys.has_value());
    EXPECT_EQ(keys.error().code, params.error_code);
}

TEST(QuicPacketCryptoTest, DerivesNextTrafficSecretFromRfc9001AppendixA5) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        .secret = hex_bytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"),
    };

    const auto next_secret = coquic::quic::derive_next_traffic_secret(secret);
    ASSERT_TRUE(next_secret.has_value());
    EXPECT_EQ(to_hex(next_secret.value().secret),
              "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");

    const auto expanded = coquic::quic::expand_traffic_secret(next_secret.value());
    ASSERT_TRUE(expanded.has_value());
    EXPECT_EQ(to_hex(expanded.value().hp_key),
              "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
}

TEST(QuicPacketCryptoTest, DeriveNextTrafficSecretRejectsUnsupportedCipherSuite) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x00}},
    };

    const auto next_secret = coquic::quic::derive_next_traffic_secret(secret);
    ASSERT_FALSE(next_secret.has_value());
    EXPECT_EQ(next_secret.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicPacketCryptoTest, DeriveNextTrafficSecretPropagatesExpandFailure) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, 1);

    const auto next_secret = coquic::quic::derive_next_traffic_secret(secret);
    ASSERT_FALSE(next_secret.has_value());
    EXPECT_EQ(next_secret.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, DeriveNextTrafficSecretPropagatesHeaderProtectionKeyFailure) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, 2);

    const auto next_secret = coquic::quic::derive_next_traffic_secret(secret);
    ASSERT_FALSE(next_secret.has_value());
    EXPECT_EQ(next_secret.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, ExpandTrafficSecretPropagatesDerivedHeaderProtectionKeyFailure) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, 4);

    const auto expanded = coquic::quic::expand_traffic_secret(secret);
    ASSERT_FALSE(expanded.has_value());
    EXPECT_EQ(expanded.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, ExpandTrafficSecretRejectsUnsupportedQuicVersion) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
        .quic_version = 0,
    };

    const auto expanded = coquic::quic::expand_traffic_secret(secret);
    ASSERT_FALSE(expanded.has_value());
    EXPECT_EQ(expanded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
}

TEST(QuicPacketCryptoTest, DeriveNextTrafficSecretReusesProvidedHeaderProtectionKey) {
    const auto header_protection_key = hex_bytes("00112233445566778899aabbccddeeff");
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
        .header_protection_key = header_protection_key,
    };

    const auto next_secret = coquic::quic::derive_next_traffic_secret(secret);
    ASSERT_TRUE(next_secret.has_value());
    const auto &next_secret_value = next_secret.value();
    ASSERT_TRUE(next_secret_value.header_protection_key.has_value());
    const auto &next_header_protection_key =
        optional_ref_or_terminate(next_secret_value.header_protection_key);
    EXPECT_EQ(next_header_protection_key, header_protection_key);
}

TEST(QuicPacketCryptoTest, ExpandTrafficSecretReusesCachedKeysAcrossCalls) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };

    const auto first = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(first.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_context_new, 1);

    const auto second = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value().key, first.value().key);
    EXPECT_EQ(second.value().iv, first.value().iv);
    EXPECT_EQ(second.value().hp_key, first.value().hp_key);
}

TEST(QuicPacketCryptoTest, ExpandTrafficSecretRefreshesCacheWhenHeaderProtectionKeyChanges) {
    coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };

    const auto first = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(first.has_value());

    secret.header_protection_key = hex_bytes("00112233445566778899aabbccddeeff");

    const auto second = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(secret.header_protection_key.has_value());
    EXPECT_EQ(second.value().hp_key, secret.header_protection_key.value());
    EXPECT_NE(second.value().hp_key, first.value().hp_key);
}

TEST(QuicPacketCryptoTest, ExpandTrafficSecretRefreshesCacheWhenSecretChanges) {
    coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
    };

    const auto first = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(first.has_value());

    secret.secret.front() ^= std::byte{0x5a};

    const auto second = coquic::quic::expand_traffic_secret(secret);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(second.value().key, first.value().key);
    EXPECT_NE(second.value().iv, first.value().iv);
}

TEST(QuicPacketCryptoTest, DeriveNextTrafficSecretRejectsUnsupportedQuicVersion) {
    const coquic::quic::TrafficSecret secret{
        .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        .secret = make_secret(32),
        .quic_version = 0,
    };

    const auto next_secret = coquic::quic::derive_next_traffic_secret(secret);
    ASSERT_FALSE(next_secret.has_value());
    EXPECT_EQ(next_secret.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
}

TEST_P(QuicPacketCryptoSealFaultTest, RejectsSealingWhenFaultInjected) {
    const auto params = GetParam();
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(params.fault_point,
                                                                       params.occurrence);

    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), hex_bytes("01"));
    ASSERT_FALSE(ciphertext.has_value());
    EXPECT_EQ(ciphertext.error().code, params.error_code);
}

TEST_P(QuicPacketCryptoOpenFaultTest, RejectsOpeningWhenFaultInjected) {
    const auto params = GetParam();
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), hex_bytes("01"));
    ASSERT_TRUE(ciphertext.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(params.fault_point,
                                                                       params.occurrence);
    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), ciphertext.value());
    ASSERT_FALSE(plaintext.has_value());
    EXPECT_EQ(plaintext.error().code, params.error_code);
}

TEST_P(QuicPacketCryptoHeaderProtectionFaultTest, RejectsHeaderProtectionWhenFaultInjected) {
    const auto &params = GetParam();
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(params.fault_point);

    const auto mask = coquic::quic::make_header_protection_mask(
        params.cipher_suite, coquic::quic::HeaderProtectionMaskInput{
                                 .hp_key = params.hp_key,
                                 .sample = params.sample,
                             });
    ASSERT_FALSE(mask.has_value());
    EXPECT_EQ(mask.error().code, coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicPacketCryptoTest, DerivesClientInitialKeysFromRfc9001AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(coquic::quic::EndpointRole::client,
                                                               true, hex_bytes("8394c8f03e515708"));
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "1f369613dd76d5467730efcbe3b1a22d");
    EXPECT_EQ(to_hex(keys.value().iv), "fa044b2f42a3fd3b46fb255c");
    EXPECT_EQ(to_hex(keys.value().hp_key), "9f50449e04a0e810283a1e9933adedd2");
}

TEST(QuicPacketCryptoTest, DerivesServerInitialKeysFromRfc9001AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(coquic::quic::EndpointRole::server,
                                                               true, hex_bytes("8394c8f03e515708"));
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "cf3a5331653c364c88f0f379b6067e37");
    EXPECT_EQ(to_hex(keys.value().iv), "0ac1493ca1905853b0bba03e");
    EXPECT_EQ(to_hex(keys.value().hp_key), "c206b8d9b9f0f37644430b490eeaa314");
}

TEST(QuicPacketCryptoTest, DerivesServerInitialKeysForClientReceiveFromRfc9001AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::client, false, hex_bytes("8394c8f03e515708"));
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "cf3a5331653c364c88f0f379b6067e37");
    EXPECT_EQ(to_hex(keys.value().iv), "0ac1493ca1905853b0bba03e");
    EXPECT_EQ(to_hex(keys.value().hp_key), "c206b8d9b9f0f37644430b490eeaa314");
}

TEST(QuicPacketCryptoTest, DerivesClientInitialKeysForServerReceiveFromRfc9001AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::server, false, hex_bytes("8394c8f03e515708"));
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "1f369613dd76d5467730efcbe3b1a22d");
    EXPECT_EQ(to_hex(keys.value().iv), "fa044b2f42a3fd3b46fb255c");
    EXPECT_EQ(to_hex(keys.value().hp_key), "9f50449e04a0e810283a1e9933adedd2");
}

TEST(QuicPacketCryptoTest, DerivesClientInitialKeysFromRfc9369AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::client, true, hex_bytes("8394c8f03e515708"), 0x6b3343cfu);
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "8b1a0bc121284290a29e0971b5cd045d");
    EXPECT_EQ(to_hex(keys.value().iv), "91f73e2351d8fa91660e909f");
    EXPECT_EQ(to_hex(keys.value().hp_key), "45b95e15235d6f45a6b19cbcb0294ba9");
}

TEST(QuicPacketCryptoTest, DerivesServerInitialKeysFromRfc9369AppendixA1) {
    const auto keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::server, true, hex_bytes("8394c8f03e515708"), 0x6b3343cfu);
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(to_hex(keys.value().key), "82db637861d55e1d011f19ea71d5d2a7");
    EXPECT_EQ(to_hex(keys.value().iv), "dd13c276499c0249d3310652");
    EXPECT_EQ(to_hex(keys.value().hp_key), "edf6d05c83121201b436e16877593c3a");
}

TEST(QuicPacketCryptoTest, DerivesDifferentInitialKeysForQuicV2) {
    const auto v1_keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::client, true, hex_bytes("8394c8f03e515708"), 0x00000001u);
    ASSERT_TRUE(v1_keys.has_value());

    const auto v2_keys = coquic::quic::derive_initial_packet_keys(
        coquic::quic::EndpointRole::client, true, hex_bytes("8394c8f03e515708"), 0x6b3343cfu);
    ASSERT_TRUE(v2_keys.has_value());

    EXPECT_NE(to_hex(v1_keys.value().key), to_hex(v2_keys.value().key));
    EXPECT_NE(to_hex(v1_keys.value().iv), to_hex(v2_keys.value().iv));
    EXPECT_NE(to_hex(v1_keys.value().hp_key), to_hex(v2_keys.value().hp_key));
}

TEST(QuicPacketCryptoTest, ComputesAndValidatesRetryIntegrityTagForQuicV1) {
    const auto original_destination_connection_id = hex_bytes("8394c8f03e515708");
    const auto retry_packet_bytes =
        hex_bytes("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    const auto expected_retry_integrity_tag = hex_array16("04a265ba2eff4d829058fb3f0f2496ba");

    const auto decoded_retry_packet =
        coquic::quic::deserialize_packet(retry_packet_bytes, coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);
    EXPECT_EQ(retry_packet->retry_unused_bits, 0x0fu);

    const auto computed_retry_integrity_tag = coquic::quic::compute_retry_integrity_tag(
        *retry_packet, original_destination_connection_id);
    ASSERT_TRUE(computed_retry_integrity_tag.has_value());
    EXPECT_EQ(to_hex(std::vector<std::byte>(computed_retry_integrity_tag.value().begin(),
                                            computed_retry_integrity_tag.value().end())),
              "04a265ba2eff4d829058fb3f0f2496ba");

    const auto valid = coquic::quic::validate_retry_integrity_tag(
        *retry_packet, original_destination_connection_id);
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(retry_packet->retry_integrity_tag, expected_retry_integrity_tag);
    EXPECT_TRUE(valid.value());
}

TEST(QuicPacketCryptoTest, ComputesAndValidatesRetryIntegrityTagForQuicV1RejectsMismatches) {
    const auto original_destination_connection_id = hex_bytes("8394c8f03e515708");
    const auto retry_packet_bytes =
        hex_bytes("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");

    const auto decoded_retry_packet =
        coquic::quic::deserialize_packet(retry_packet_bytes, coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);

    const auto baseline_valid = coquic::quic::validate_retry_integrity_tag(
        *retry_packet, original_destination_connection_id);
    ASSERT_TRUE(baseline_valid.has_value());
    EXPECT_TRUE(baseline_valid.value());

    auto modified_tag_packet = *retry_packet;
    modified_tag_packet.retry_integrity_tag[0] ^= std::byte{0x01};
    const auto modified_tag_valid = coquic::quic::validate_retry_integrity_tag(
        modified_tag_packet, original_destination_connection_id);
    ASSERT_TRUE(modified_tag_valid.has_value());
    EXPECT_FALSE(modified_tag_valid.value());

    auto modified_unused_bits_packet = *retry_packet;
    modified_unused_bits_packet.retry_unused_bits ^= 0x01u;
    const auto modified_unused_bits_valid = coquic::quic::validate_retry_integrity_tag(
        modified_unused_bits_packet, original_destination_connection_id);
    ASSERT_TRUE(modified_unused_bits_valid.has_value());
    EXPECT_FALSE(modified_unused_bits_valid.value());

    auto wrong_original_destination_connection_id = original_destination_connection_id;
    wrong_original_destination_connection_id[0] ^= std::byte{0x01};
    const auto wrong_odcid_valid = coquic::quic::validate_retry_integrity_tag(
        *retry_packet, wrong_original_destination_connection_id);
    ASSERT_TRUE(wrong_odcid_valid.has_value());
    EXPECT_FALSE(wrong_odcid_valid.value());
}

TEST(QuicPacketCryptoTest, ComputesAndValidatesRetryIntegrityTagForQuicV2) {
    const auto original_destination_connection_id = hex_bytes("8394c8f03e515708");
    const auto retry_packet_bytes =
        hex_bytes("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
    const auto expected_retry_integrity_tag = hex_array16("c8646ce8bfe33952d955543665dcc7b6");

    const auto decoded_retry_packet =
        coquic::quic::deserialize_packet(retry_packet_bytes, coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);
    EXPECT_EQ(retry_packet->retry_unused_bits, 0x0fu);

    const auto computed_retry_integrity_tag = coquic::quic::compute_retry_integrity_tag(
        *retry_packet, original_destination_connection_id);
    ASSERT_TRUE(computed_retry_integrity_tag.has_value());
    EXPECT_EQ(to_hex(std::vector<std::byte>(computed_retry_integrity_tag.value().begin(),
                                            computed_retry_integrity_tag.value().end())),
              "c8646ce8bfe33952d955543665dcc7b6");

    const auto valid = coquic::quic::validate_retry_integrity_tag(
        *retry_packet, original_destination_connection_id);
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(retry_packet->retry_integrity_tag, expected_retry_integrity_tag);
    EXPECT_TRUE(valid.value());
}

TEST(QuicPacketCryptoTest, ComputesAndValidatesRetryIntegrityTagForQuicV2RejectsMismatches) {
    const auto original_destination_connection_id = hex_bytes("8394c8f03e515708");
    const auto retry_packet_bytes =
        hex_bytes("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");

    const auto decoded_retry_packet =
        coquic::quic::deserialize_packet(retry_packet_bytes, coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);

    const auto baseline_valid = coquic::quic::validate_retry_integrity_tag(
        *retry_packet, original_destination_connection_id);
    ASSERT_TRUE(baseline_valid.has_value());
    EXPECT_TRUE(baseline_valid.value());

    auto modified_tag_packet = *retry_packet;
    modified_tag_packet.retry_integrity_tag[0] ^= std::byte{0x01};
    const auto modified_tag_valid = coquic::quic::validate_retry_integrity_tag(
        modified_tag_packet, original_destination_connection_id);
    ASSERT_TRUE(modified_tag_valid.has_value());
    EXPECT_FALSE(modified_tag_valid.value());

    auto modified_unused_bits_packet = *retry_packet;
    modified_unused_bits_packet.retry_unused_bits ^= 0x01u;
    const auto modified_unused_bits_valid = coquic::quic::validate_retry_integrity_tag(
        modified_unused_bits_packet, original_destination_connection_id);
    ASSERT_TRUE(modified_unused_bits_valid.has_value());
    EXPECT_FALSE(modified_unused_bits_valid.value());

    auto wrong_original_destination_connection_id = original_destination_connection_id;
    wrong_original_destination_connection_id[0] ^= std::byte{0x01};
    const auto wrong_odcid_valid = coquic::quic::validate_retry_integrity_tag(
        *retry_packet, wrong_original_destination_connection_id);
    ASSERT_TRUE(wrong_odcid_valid.has_value());
    EXPECT_FALSE(wrong_odcid_valid.value());
}

TEST(QuicPacketCryptoTest,
     ComputeRetryIntegrityTagRejectsOversizedOriginalDestinationConnectionId) {
    const auto decoded_retry_packet = coquic::quic::deserialize_packet(
        hex_bytes("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"),
        coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);

    const std::vector<std::byte> oversized_original_destination_connection_id(256, std::byte{0x42});
    const auto retry_integrity_tag = coquic::quic::compute_retry_integrity_tag(
        *retry_packet, oversized_original_destination_connection_id);
    ASSERT_FALSE(retry_integrity_tag.has_value());
    EXPECT_EQ(retry_integrity_tag.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicPacketCryptoTest, ComputeRetryIntegrityTagRejectsInvalidRetryPacketEncoding) {
    const auto decoded_retry_packet = coquic::quic::deserialize_packet(
        hex_bytes("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"),
        coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);

    auto invalid_retry_packet = *retry_packet;
    invalid_retry_packet.retry_unused_bits = 0x10u;
    const auto retry_integrity_tag = coquic::quic::compute_retry_integrity_tag(
        invalid_retry_packet, hex_bytes("8394c8f03e515708"));
    ASSERT_FALSE(retry_integrity_tag.has_value());
    EXPECT_EQ(retry_integrity_tag.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicPacketCryptoTest, ComputeRetryIntegrityTagPropagatesSealFailure) {
    const auto decoded_retry_packet = coquic::quic::deserialize_packet(
        hex_bytes("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"),
        coquic::quic::DeserializeOptions{});
    ASSERT_TRUE(decoded_retry_packet.has_value());
    const auto *retry_packet =
        std::get_if<coquic::quic::RetryPacket>(&decoded_retry_packet.value().packet);
    ASSERT_NE(retry_packet, nullptr);

    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);
    const auto retry_integrity_tag =
        coquic::quic::compute_retry_integrity_tag(*retry_packet, hex_bytes("8394c8f03e515708"));
    ASSERT_FALSE(retry_integrity_tag.has_value());
    EXPECT_EQ(retry_integrity_tag.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, DerivesInitialKeysForEmptyDestinationConnectionId) {
    const auto client_keys =
        coquic::quic::derive_initial_packet_keys(coquic::quic::EndpointRole::client, true, {});
    ASSERT_TRUE(client_keys.has_value());
    EXPECT_EQ(to_hex(client_keys.value().key), "77946e94d6f58bf7e8140b50b1ad28d2");
    EXPECT_EQ(to_hex(client_keys.value().iv), "1533d930a17b66f492940f71");
    EXPECT_EQ(to_hex(client_keys.value().hp_key), "f5d64bf060bebe4e086d31f48efe3610");

    const auto server_keys =
        coquic::quic::derive_initial_packet_keys(coquic::quic::EndpointRole::server, true, {});
    ASSERT_TRUE(server_keys.has_value());
    EXPECT_EQ(to_hex(server_keys.value().key), "1e737190106f6dcfd3e5f005c1567466");
    EXPECT_EQ(to_hex(server_keys.value().iv), "c78324064e7b5bafb8ed27d7");
    EXPECT_EQ(to_hex(server_keys.value().hp_key), "b175abd708d3c7b157293412365e8007");
}

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

TEST(QuicPacketCryptoTest, BuildsAesHeaderProtectionMaskFromRfc9001AppendixA2) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
        });
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "437b9aec36");
}

TEST(QuicPacketCryptoTest, BuildsHeaderProtectionMaskFromFirstSixteenSampleBytes) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9bfeedface"),
        });
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "437b9aec36");
}

TEST(QuicPacketCryptoTest, BuildsChaChaHeaderProtectionMaskFromRfc9001AppendixA5) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            .sample = hex_bytes("5e5cd55c41f69080575d7999c25a5bfb"),
        });
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "aefefe7d03");
}

TEST(QuicPacketCryptoTest, BuildsPacketProtectionNonceIntoCallerOwnedBuffer) {
    std::array<std::byte, 12> nonce{};

    const auto written = coquic::quic::make_packet_protection_nonce_into(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL, nonce);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), nonce.size());
    EXPECT_EQ(to_hex(std::vector<std::byte>(nonce.begin(), nonce.end())),
              "e0459b3474bdd0e46d417eb0");
}

TEST(QuicPacketCryptoTest, BuildsHeaderProtectionMaskIntoCallerOwnedBuffer) {
    std::array<std::byte, 5> mask{};

    const auto written = coquic::quic::make_header_protection_mask_into(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
        },
        mask);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), mask.size());
    EXPECT_EQ(to_hex(std::vector<std::byte>(mask.begin(), mask.end())), "437b9aec36");
}

TEST(QuicPacketCryptoTest, SealsAndOpensPayloadWithAssociatedData) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());
    EXPECT_EQ(to_hex(nonce.value()), "e0459b3474bdd0e46d417eb0");

    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), hex_bytes("01"));
    ASSERT_TRUE(ciphertext.has_value());
    EXPECT_EQ(to_hex(ciphertext.value()), "655e5cd55c41f69080575d7999c25a5bfb");

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), ciphertext.value());
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(to_hex(plaintext.value()), "01");
}

TEST(QuicPacketCryptoTest, SealsPayloadDirectlyIntoCallerOwnedBuffer) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    std::vector<std::byte> ciphertext(1u + 16u);
    const auto written = coquic::quic::seal_payload_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), hex_bytes("01"), ciphertext);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), ciphertext.size());
    EXPECT_EQ(to_hex(ciphertext), "655e5cd55c41f69080575d7999c25a5bfb");

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), ciphertext);
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(to_hex(plaintext.value()), "01");
}

TEST(QuicPacketCryptoTest, SealsPayloadInPlaceInsideCallerOwnedBuffer) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    std::vector<std::byte> buffer = hex_bytes("0100000000000000000000000000000000");
    ASSERT_EQ(buffer.size(), 17u);

    const auto written = coquic::quic::seal_payload_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), std::span<const std::byte>(buffer).first(1),
        std::span<std::byte>(buffer));
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), buffer.size());
    EXPECT_EQ(to_hex(buffer), "655e5cd55c41f69080575d7999c25a5bfb");
}

TEST(QuicPacketCryptoTest, SealPayloadIntoReusesContextAcrossCalls) {
    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();

    const auto key = hex_bytes("000102030405060708090a0b0c0d0e0f");
    const auto aad = hex_bytes("a0a1a2a3a4");
    const auto plaintext = hex_bytes("112233445566778899");
    std::vector<std::byte> first_ciphertext(plaintext.size() + 16u);
    std::vector<std::byte> second_ciphertext(plaintext.size() + 16u);

    const auto first_written = coquic::quic::seal_payload_into(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, key,
        hex_bytes("101112131415161718191a1b"), aad, plaintext, first_ciphertext);
    ASSERT_TRUE(first_written.has_value());

    const auto second_written = coquic::quic::seal_payload_into(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, key,
        hex_bytes("202122232425262728292a2b"), aad, plaintext, second_ciphertext);
    ASSERT_TRUE(second_written.has_value());

    const auto stats = coquic::quic::test::packet_crypto_runtime_cache_stats_for_tests();
    EXPECT_EQ(stats.seal_context_new_calls, 1u);
    EXPECT_EQ(stats.seal_key_setup_calls, 1u);
}

TEST(QuicPacketCryptoTest, OpenPayloadReusesKeySetupAcrossCalls) {
    const auto key = hex_bytes("000102030405060708090a0b0c0d0e0f");
    const auto aad = hex_bytes("a0a1a2a3a4");
    const auto plaintext = hex_bytes("112233445566778899");

    const auto first_ciphertext =
        coquic::quic::seal_payload(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, key,
                                   hex_bytes("101112131415161718191a1b"), aad, plaintext);
    ASSERT_TRUE(first_ciphertext.has_value());

    const auto second_ciphertext =
        coquic::quic::seal_payload(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, key,
                                   hex_bytes("202122232425262728292a2b"), aad, plaintext);
    ASSERT_TRUE(second_ciphertext.has_value());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();

    const auto first_plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, key,
        hex_bytes("101112131415161718191a1b"), aad, first_ciphertext.value());
    ASSERT_TRUE(first_plaintext.has_value());
    EXPECT_EQ(first_plaintext.value(), plaintext);

    const auto second_plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, key,
        hex_bytes("202122232425262728292a2b"), aad, second_ciphertext.value());
    ASSERT_TRUE(second_plaintext.has_value());
    EXPECT_EQ(second_plaintext.value(), plaintext);

    const auto stats = coquic::quic::test::packet_crypto_runtime_cache_stats_for_tests();
    EXPECT_EQ(stats.open_context_new_calls, 1u);
    EXPECT_EQ(stats.open_key_setup_calls, 1u);
}

TEST(QuicPacketCryptoTest, HeaderProtectionReusesContextAcrossCalls) {
    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();

    const auto first_mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
        });
    ASSERT_TRUE(first_mask.has_value());

    const auto second_mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("00112233445566778899aabbccddeeff"),
        });
    ASSERT_TRUE(second_mask.has_value());

    const auto stats = coquic::quic::test::packet_crypto_runtime_cache_stats_for_tests();
    EXPECT_EQ(stats.header_protection_context_new_calls, 1u);
}

TEST(QuicPacketCryptoTest, SealPayloadIntoRejectsUnsupportedCipherSuite) {
    std::array<std::byte, 16> ciphertext{};

    const auto written =
        coquic::quic::seal_payload_into(invalid_cipher_suite(), {}, {}, {}, {}, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicPacketCryptoTest, SealsChunkedPayloadDirectlyIntoCallerOwnedBuffer) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const auto plaintext = hex_bytes("0102030405");
    const auto expected = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), plaintext);
    ASSERT_TRUE(expected.has_value());

    const auto plaintext_span = std::span<const std::byte>(plaintext);
    const auto first = plaintext_span.first<1>();
    const auto second = plaintext_span.subspan(1, 2);
    const auto third = plaintext_span.subspan(3);
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = first},
        coquic::quic::PlaintextChunk{.bytes = second},
        coquic::quic::PlaintextChunk{.bytes = third},
    };

    std::vector<std::byte> ciphertext(expected.value().size());
    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), chunks, ciphertext);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), expected.value().size());
    EXPECT_EQ(ciphertext, expected.value());

    const auto opened = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), ciphertext);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(opened.value(), plaintext);
}

TEST(QuicPacketCryptoTest, SealsChunkedPayloadWithoutAssociatedData) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const auto plaintext = hex_bytes("0102030405");
    const auto expected = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), {}, plaintext);
    ASSERT_TRUE(expected.has_value());

    const auto plaintext_span = std::span<const std::byte>(plaintext);
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = plaintext_span.first<2>()},
        coquic::quic::PlaintextChunk{.bytes = plaintext_span.last<3>()},
    };

    std::vector<std::byte> ciphertext(expected.value().size());
    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), {}, chunks, ciphertext);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), expected.value().size());
    EXPECT_EQ(ciphertext, expected.value());

    const auto opened = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), {}, ciphertext);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(opened.value(), plaintext);
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoRejectsUnsupportedCipherSuite) {
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = std::span<const std::byte>{}},
    };
    std::array<std::byte, 16> ciphertext{};

    const auto written = coquic::quic::seal_payload_chunks_into(invalid_cipher_suite(), {}, {}, {},
                                                                chunks, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoRejectsInvalidKeyMaterialSizes) {
    const auto plaintext = hex_bytes("01");
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = std::span<const std::byte>(plaintext)},
    };
    std::array<std::byte, 17> ciphertext{};

    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0"), chunks, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoRejectsInvalidNonceLength) {
    const auto plaintext = hex_bytes("01");
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = std::span<const std::byte>(plaintext)},
    };
    std::array<std::byte, 17> ciphertext{};

    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a"),
        hex_bytes("a0"), chunks, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoRejectsTooSmallCallerBuffer) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const auto plaintext = hex_bytes("01");
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = std::span<const std::byte>(plaintext)},
    };
    std::array<std::byte, 16> ciphertext{};

    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), chunks, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoSkipsEmptyChunks) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const auto plaintext = hex_bytes("0102030405");
    const auto expected = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), plaintext);
    ASSERT_TRUE(expected.has_value());

    const auto plaintext_span = std::span<const std::byte>(plaintext);
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = plaintext_span.first<2>()},
        coquic::quic::PlaintextChunk{.bytes = std::span<const std::byte>{}},
        coquic::quic::PlaintextChunk{.bytes = plaintext_span.last<3>()},
    };
    std::vector<std::byte> ciphertext(expected.value().size());

    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), chunks, ciphertext);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), expected.value().size());
    EXPECT_EQ(ciphertext, expected.value());
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoRejectsChunkLargerThanOpenSslInt) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const std::size_t huge_size = static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1u;
    const ReservedSpan huge_chunk(huge_size);
    ASSERT_TRUE(huge_chunk.ok());

    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = huge_chunk.bytes()},
    };
    std::array<std::byte, 16> ciphertext{};

    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), chunks, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, SealPayloadChunksIntoRejectsTotalLengthLargerThanOpenSslInt) {
    const auto nonce = coquic::quic::make_packet_protection_nonce(
        hex_bytes("e0459b3474bdd0e44a41c144"), 654360564ULL);
    ASSERT_TRUE(nonce.has_value());

    const std::size_t chunk_size =
        static_cast<std::size_t>(std::numeric_limits<int>::max() / 2) + 1u;
    const std::size_t total_size = chunk_size * 2u;
    const ReservedSpan huge_chunks(total_size);
    ASSERT_TRUE(huge_chunks.ok());

    const auto bytes = huge_chunks.bytes();
    const std::array chunks{
        coquic::quic::PlaintextChunk{.bytes = bytes.first(chunk_size)},
        coquic::quic::PlaintextChunk{.bytes = bytes.last(chunk_size)},
    };
    std::array<std::byte, 16> ciphertext{};

    const auto written = coquic::quic::seal_payload_chunks_into(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        nonce.value(), hex_bytes("4200bff4"), chunks, ciphertext);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, SealsAndOpensPayloadWithoutAssociatedData) {
    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"), {},
        hex_bytes("11223344"));
    ASSERT_TRUE(ciphertext.has_value());

    const auto plaintext =
        coquic::quic::open_payload(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                   hex_bytes("000102030405060708090a0b0c0d0e0f"),
                                   hex_bytes("101112131415161718191a1b"), {}, ciphertext.value());
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(to_hex(plaintext.value()), "11223344");
}

TEST(QuicPacketCryptoTest, XorsPacketNumberIntoShortIvTail) {
    const auto nonce =
        coquic::quic::make_packet_protection_nonce(hex_bytes("00112233"), 0x4455667788ULL);
    ASSERT_TRUE(nonce.has_value());
    EXPECT_EQ(to_hex(nonce.value()), "557755bb");
}

TEST(QuicPacketCryptoTest, BuildsPacketProtectionNonceFromEmptyIv) {
    const auto nonce = coquic::quic::make_packet_protection_nonce({}, 0x4455667788ULL);
    ASSERT_TRUE(nonce.has_value());
    EXPECT_TRUE(nonce.value().empty());
}

TEST(QuicPacketCryptoTest, SealsAndOpensAes128PayloadWithAssociatedData) {
    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a4"), hex_bytes("112233445566778899"));
    ASSERT_TRUE(ciphertext.has_value());
    EXPECT_EQ(ciphertext.value().size(), 25U);

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a4"), ciphertext.value());
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(to_hex(plaintext.value()), "112233445566778899");
}

TEST(QuicPacketCryptoTest, RejectsAes128PayloadWhenAssociatedDataChanges) {
    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a4"), hex_bytes("112233445566778899"));
    ASSERT_TRUE(ciphertext.has_value());

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a5"), ciphertext.value());
    ASSERT_FALSE(plaintext.has_value());
    EXPECT_EQ(plaintext.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}

TEST(QuicPacketCryptoTest, SealsAndOpensAes256PayloadWithAssociatedData) {
    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_256_gcm_sha384,
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        hex_bytes("202122232425262728292a2b"), hex_bytes("b0b1b2b3b4b5"),
        hex_bytes("aabbccddeeff0011223344"));
    ASSERT_TRUE(ciphertext.has_value());
    EXPECT_EQ(ciphertext.value().size(), 27U);

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_256_gcm_sha384,
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        hex_bytes("202122232425262728292a2b"), hex_bytes("b0b1b2b3b4b5"), ciphertext.value());
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(to_hex(plaintext.value()), "aabbccddeeff0011223344");
}

TEST(QuicPacketCryptoTest, RejectsAes256PayloadWhenAssociatedDataChanges) {
    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_256_gcm_sha384,
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        hex_bytes("202122232425262728292a2b"), hex_bytes("b0b1b2b3b4b5"),
        hex_bytes("aabbccddeeff0011223344"));
    ASSERT_TRUE(ciphertext.has_value());

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_256_gcm_sha384,
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        hex_bytes("202122232425262728292a2b"), hex_bytes("b0b1b2b3b4b6"), ciphertext.value());
    ASSERT_FALSE(plaintext.has_value());
    EXPECT_EQ(plaintext.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}

TEST(QuicPacketCryptoTest, RejectsPayloadWhenAuthenticationFails) {
    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        hex_bytes("e0459b3474bdd0e46d417eb0"), hex_bytes("4200bff5"),
        hex_bytes("655e5cd55c41f69080575d7999c25a5bfb"));
    ASSERT_FALSE(plaintext.has_value());
    EXPECT_EQ(plaintext.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}

TEST(QuicPacketCryptoTest, RejectsShortHeaderProtectionSample) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8"),
        });
    ASSERT_FALSE(mask.has_value());
    EXPECT_EQ(mask.error().code, coquic::quic::CodecErrorCode::header_protection_sample_too_short);
}

TEST(QuicPacketCryptoTest, RejectsUnsupportedCipherSuites) {
    const coquic::quic::TrafficSecret invalid_secret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x00}},
    };

    const auto expanded = coquic::quic::expand_traffic_secret(invalid_secret);
    ASSERT_FALSE(expanded.has_value());
    EXPECT_EQ(expanded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);

    const auto sealed = coquic::quic::seal_payload(invalid_cipher_suite(), {}, {}, {}, {});
    ASSERT_FALSE(sealed.has_value());
    EXPECT_EQ(sealed.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);

    const auto opened = coquic::quic::open_payload(invalid_cipher_suite(), {}, {}, {}, {});
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);

    const auto mask = coquic::quic::make_header_protection_mask(
        invalid_cipher_suite(), coquic::quic::HeaderProtectionMaskInput{});
    ASSERT_FALSE(mask.has_value());
    EXPECT_EQ(mask.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicPacketCryptoTest, RejectsPayloadProtectionWhenKeyMaterialSizesDoNotMatchCipherSuite) {
    const auto sealed_with_short_key = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0"), hex_bytes("01"));
    ASSERT_FALSE(sealed_with_short_key.has_value());
    EXPECT_EQ(sealed_with_short_key.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    const auto sealed_with_short_nonce = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a"),
        hex_bytes("a0"), hex_bytes("01"));
    ASSERT_FALSE(sealed_with_short_nonce.has_value());
    EXPECT_EQ(sealed_with_short_nonce.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    const auto opened_with_short_key = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0"), hex_bytes("00112233445566778899aabbccddeeff"));
    ASSERT_FALSE(opened_with_short_key.has_value());
    EXPECT_EQ(opened_with_short_key.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    const auto opened_with_short_nonce = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a"),
        hex_bytes("a0"), hex_bytes("00112233445566778899aabbccddeeff"));
    ASSERT_FALSE(opened_with_short_nonce.has_value());
    EXPECT_EQ(opened_with_short_nonce.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, RejectsCiphertextsShorterThanAuthenticationTag) {
    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0"), hex_bytes("00112233445566778899aabbccddee"));
    ASSERT_FALSE(plaintext.has_value());
    EXPECT_EQ(plaintext.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}

TEST(QuicPacketCryptoTest, RejectsSealPayloadWhenLengthGuardFaultIsInjected) {
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector{
        coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard};

    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a4"), hex_bytes("112233445566778899"));
    ASSERT_FALSE(ciphertext.has_value());
    EXPECT_EQ(ciphertext.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, RejectsOpenPayloadWhenLengthGuardFaultIsInjected) {
    const auto ciphertext = coquic::quic::seal_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a4"), hex_bytes("112233445566778899"));
    ASSERT_TRUE(ciphertext.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector{
        coquic::quic::test::PacketCryptoFaultPoint::open_length_guard};

    const auto plaintext = coquic::quic::open_payload(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("000102030405060708090a0b0c0d0e0f"), hex_bytes("101112131415161718191a1b"),
        hex_bytes("a0a1a2a3a4"), ciphertext.value());
    ASSERT_FALSE(plaintext.has_value());
    EXPECT_EQ(plaintext.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicPacketCryptoTest, RejectsHeaderProtectionWhenKeyLengthDoesNotMatchCipherSuite) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        coquic::quic::HeaderProtectionMaskInput{
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933aded"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
        });
    ASSERT_FALSE(mask.has_value());
    EXPECT_EQ(mask.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

INSTANTIATE_TEST_SUITE_P(
    FaultInjection, QuicPacketCryptoInitialKeyFaultTest,
    testing::Values(
        PacketCryptoFaultCase{
            .name = "HkdfExtractContextNew",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_extract_context_new,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "HkdfExtractSetup",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_extract_setup,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "HkdfExpandContextNew",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_context_new,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "HkdfExpandSetup",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        }),
    [](const testing::TestParamInfo<PacketCryptoFaultCase> &info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(
    FaultInjection, QuicPacketCryptoTrafficSecretFaultTest,
    testing::Values(
        PacketCryptoFaultCase{
            .name = "ExpandKey",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "ExpandIv",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
            .occurrence = 2,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "ExpandHp",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
            .occurrence = 3,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        }),
    [](const testing::TestParamInfo<PacketCryptoFaultCase> &info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(
    FaultInjection, QuicPacketCryptoSealFaultTest,
    testing::Values(
        PacketCryptoFaultCase{
            .name = "ContextNew",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_context_new,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "Init",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_init,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "AadUpdate",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_aad_update,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "PayloadUpdate",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "NativeSeal",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_native_seal,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "Final",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_final,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "GetTag",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::seal_get_tag,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        }),
    [](const testing::TestParamInfo<PacketCryptoFaultCase> &info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(
    FaultInjection, QuicPacketCryptoOpenFaultTest,
    testing::Values(
        PacketCryptoFaultCase{
            .name = "ContextNew",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::open_context_new,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "Init",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::open_init,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "AadUpdate",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::open_aad_update,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "PayloadUpdate",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::open_payload_update,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        },
        PacketCryptoFaultCase{
            .name = "SetTag",
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::open_set_tag,
            .occurrence = 1,
            .error_code = coquic::quic::CodecErrorCode::invalid_packet_protection_state,
        }),
    [](const testing::TestParamInfo<PacketCryptoFaultCase> &info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(
    FaultInjection, QuicPacketCryptoHeaderProtectionFaultTest,
    testing::Values(
        PacketCryptoHeaderProtectionFaultCase{
            .name = "ContextNew",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "AesInit",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_init,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "AesContextNew",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_context_new,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "AesSetPadding",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_set_padding,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "AesUpdate",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_update,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "AesFinal",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point = coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_final,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "AesBadLength",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .hp_key = hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
            .sample = hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_bad_length,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "ChaChaInit",
            .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
            .hp_key = hex_bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            .sample = hex_bytes("5e5cd55c41f69080575d7999c25a5bfb"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_chacha_init,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "ChaChaFinal",
            .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
            .hp_key = hex_bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            .sample = hex_bytes("5e5cd55c41f69080575d7999c25a5bfb"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_chacha_final,
        },
        PacketCryptoHeaderProtectionFaultCase{
            .name = "ChaChaBadLength",
            .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
            .hp_key = hex_bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            .sample = hex_bytes("5e5cd55c41f69080575d7999c25a5bfb"),
            .fault_point =
                coquic::quic::test::PacketCryptoFaultPoint::header_protection_chacha_bad_length,
        }),
    [](const testing::TestParamInfo<PacketCryptoHeaderProtectionFaultCase> &info) {
        return info.param.name;
    });

} // namespace

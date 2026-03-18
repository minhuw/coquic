#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"

namespace {

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
    const auto params = GetParam();
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(params.fault_point);

    const auto mask = coquic::quic::make_header_protection_mask(params.cipher_suite, params.hp_key,
                                                                params.sample);
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
    const auto mask =
        coquic::quic::make_header_protection_mask(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                                  hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
                                                  hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"));
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "437b9aec36");
}

TEST(QuicPacketCryptoTest, BuildsHeaderProtectionMaskFromFirstSixteenSampleBytes) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
        hex_bytes("9f50449e04a0e810283a1e9933adedd2"),
        hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9bfeedface"));
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "437b9aec36");
}

TEST(QuicPacketCryptoTest, BuildsChaChaHeaderProtectionMaskFromRfc9001AppendixA5) {
    const auto mask = coquic::quic::make_header_protection_mask(
        coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
        hex_bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
        hex_bytes("5e5cd55c41f69080575d7999c25a5bfb"));
    ASSERT_TRUE(mask.has_value());
    EXPECT_EQ(to_hex(mask.value()), "aefefe7d03");
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
        hex_bytes("9f50449e04a0e810283a1e9933adedd2"), hex_bytes("d1b1c98dd7689fb8"));
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

    const auto mask = coquic::quic::make_header_protection_mask(invalid_cipher_suite(), {}, {});
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
        hex_bytes("9f50449e04a0e810283a1e9933aded"), hex_bytes("d1b1c98dd7689fb8ec11d242b123dc9b"));
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

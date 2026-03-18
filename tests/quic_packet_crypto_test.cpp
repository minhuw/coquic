#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/packet_crypto.h"

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

} // namespace

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/packet_crypto.h"

namespace {

std::vector<std::byte> hex_bytes(const char *hex) {
    std::vector<std::byte> bytes;
    const std::string_view text{hex};
    bytes.reserve(text.size() / 2);

    const auto hex_value = [](char ch) -> std::uint8_t {
        if (ch >= '0' && ch <= '9') {
            return static_cast<std::uint8_t>(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f') {
            return static_cast<std::uint8_t>(10 + (ch - 'a'));
        }
        if (ch >= 'A' && ch <= 'F') {
            return static_cast<std::uint8_t>(10 + (ch - 'A'));
        }
        return 0;
    };

    for (std::size_t index = 0; index < text.size(); index += 2) {
        const auto high = hex_value(text[index]);
        const auto low = hex_value(text[index + 1]);
        bytes.push_back(static_cast<std::byte>((high << 4) | low));
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

} // namespace

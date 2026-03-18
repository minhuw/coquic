#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "src/coquic.h"

namespace {

constexpr std::string_view kRfc9001ClientHelloHex =
    "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c"
    "00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a"
    "00080006001d0017001800100007000504616c706e000500050100000000003300260024001d"
    "00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003"
    "020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900"
    "320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f0883"
    "94c8f03e51570806048000ffff";

constexpr std::string_view kRfc9001ClientInitialPacketHex =
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8"
    "bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb3"
    "5a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7a"
    "ce01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347"
    "b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25"
    "ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4"
    "e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eb"
    "a0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998c"
    "cabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5"
    "f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565"
    "636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f349"
    "1de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec"
    "281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c"
    "5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5"
    "bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302"
    "f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2"
    "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857"
    "fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b06108534"
    "9d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb6"
    "05cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365"
    "565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e"
    "6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3"
    "986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440"
    "591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db"
    "82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca88"
    "85c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078c"
    "dfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85"
    "194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9"
    "ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a0798"
    "31aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c"
    "8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";

constexpr std::size_t kRfc9001ClientInitialPayloadLength = 1162;

std::vector<std::byte> hex_bytes(std::string_view hex) {
    std::vector<std::byte> bytes;
    if ((hex.size() % 2) != 0) {
        ADD_FAILURE() << "hex string must contain an even number of characters: " << hex;
        return bytes;
    }

    bytes.reserve(hex.size() / 2);

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

    for (std::size_t index = 0; index < hex.size(); index += 2) {
        const auto high = hex_value(hex[index]);
        const auto low = hex_value(hex[index + 1]);
        if (!high.has_value() || !low.has_value()) {
            ADD_FAILURE() << "hex string contains a non-hex character: " << hex;
            return {};
        }

        bytes.push_back(static_cast<std::byte>((high.value() << 4) | low.value()));
    }

    return bytes;
}

std::string to_hex(const std::vector<std::byte> &bytes) {
    static constexpr char digits[] = "0123456789abcdef";

    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (const auto byte : bytes) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        hex.push_back(digits[value >> 4]);
        hex.push_back(digits[value & 0x0f]);
    }

    return hex;
}

coquic::quic::ProtectedInitialPacket make_rfc9001_client_initial_packet() {
    auto crypto_data = hex_bytes(kRfc9001ClientHelloHex);
    const auto encoded_crypto = coquic::quic::serialize_frame(coquic::quic::CryptoFrame{
        .offset = 0,
        .crypto_data = crypto_data,
    });
    if (!encoded_crypto.has_value()) {
        ADD_FAILURE() << "failed to encode RFC 9001 CRYPTO frame fixture";
        return {};
    }

    std::vector<coquic::quic::Frame> frames;
    frames.emplace_back(coquic::quic::CryptoFrame{
        .offset = 0,
        .crypto_data = std::move(crypto_data),
    });
    frames.emplace_back(coquic::quic::PaddingFrame{
        .length = kRfc9001ClientInitialPayloadLength - encoded_crypto.value().size(),
    });

    return coquic::quic::ProtectedInitialPacket{
        .version = 1,
        .destination_connection_id = hex_bytes("8394c8f03e515708"),
        .source_connection_id = {},
        .token = {},
        .packet_number_length = 4,
        .packet_number = 2,
        .frames = std::move(frames),
    };
}

coquic::quic::SerializeProtectionContext make_rfc9001_client_initial_serialize_context() {
    return coquic::quic::SerializeProtectionContext{
        .local_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id = hex_bytes("8394c8f03e515708"),
    };
}

coquic::quic::DeserializeProtectionContext make_rfc9001_client_initial_deserialize_context() {
    return coquic::quic::DeserializeProtectionContext{
        .peer_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id = hex_bytes("8394c8f03e515708"),
    };
}

coquic::quic::ProtectedInitialPacket make_minimal_initial_packet() {
    return coquic::quic::ProtectedInitialPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {},
        .token = {},
        .packet_number_length = 1,
        .packet_number = 0,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = {std::byte{0x01}},
                },
            },
    };
}

TEST(QuicProtectedCodecTest, SerializesClientInitialFromRfc9001AppendixA2) {
    const auto packet = make_rfc9001_client_initial_packet();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(to_hex(encoded.value()), kRfc9001ClientInitialPacketHex);
}

TEST(QuicProtectedCodecTest, DeserializesClientInitialFromRfc9001AppendixA2) {
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        hex_bytes(kRfc9001ClientInitialPacketHex),
        make_rfc9001_client_initial_deserialize_context());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->packet_number, 2ULL);
}

TEST(QuicProtectedCodecTest, RejectsInitialWithoutClientInitialDestinationConnectionId) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(packets, {});
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

} // namespace

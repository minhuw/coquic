#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/core.h"
#include "src/quic/protected_codec.h"
#include "src/quic/protected_codec_test_hooks.h"

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

struct HandshakeCipherSuiteCase {
    const char *name;
    coquic::quic::CipherSuite cipher_suite;
    std::size_t secret_size;
};

struct OneRttCipherSuiteCase {
    const char *name;
    coquic::quic::CipherSuite cipher_suite;
    std::size_t secret_size;
};

constexpr std::uint64_t kOneRttLargestAuthenticatedPacketNumber = 0xa82f30eaULL;
constexpr std::uint64_t kOneRttPacketNumber = 0xa82f9b32ULL;
constexpr std::uint8_t kOneRttPacketNumberLength = 2;
constexpr std::size_t kOneRttDestinationConnectionIdLength = 4;

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

std::vector<std::byte> make_secret(std::size_t size) {
    std::vector<std::byte> secret(size);
    for (std::size_t i = 0; i < size; ++i) {
        secret[i] = static_cast<std::byte>(i);
    }
    return secret;
}

coquic::quic::CipherSuite invalid_cipher_suite() {
    const auto raw = static_cast<std::underlying_type_t<coquic::quic::CipherSuite>>(0xff);
    coquic::quic::CipherSuite cipher_suite{};
    std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
    return cipher_suite;
}

coquic::quic::ProtectedHandshakePacket make_minimal_handshake_packet() {
    return coquic::quic::ProtectedHandshakePacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
        .source_connection_id = {std::byte{0xcc}},
        .packet_number_length = 2,
        .packet_number = 0x1234,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
                },
            },
    };
}

coquic::quic::ProtectedZeroRttPacket make_minimal_zero_rtt_packet() {
    return coquic::quic::ProtectedZeroRttPacket{
        .version = coquic::quic::kQuicVersion1,
        .destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .packet_number_length = 2,
        .packet_number = 7,
        .frames = {coquic::quic::PingFrame{}},
    };
}

coquic::quic::TrafficSecret make_zero_rtt_secret(
    coquic::quic::CipherSuite cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
    std::size_t secret_size = 32) {
    return coquic::quic::TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, std::byte{0x11}),
    };
}

coquic::quic::SerializeProtectionContext
make_handshake_serialize_context(coquic::quic::CipherSuite cipher_suite, std::size_t secret_size) {
    return coquic::quic::SerializeProtectionContext{
        .local_role = coquic::quic::EndpointRole::client,
        .handshake_secret =
            coquic::quic::TrafficSecret{
                .cipher_suite = cipher_suite,
                .secret = make_secret(secret_size),
            },
    };
}

coquic::quic::DeserializeProtectionContext
make_handshake_deserialize_context(coquic::quic::CipherSuite cipher_suite,
                                   std::size_t secret_size) {
    return coquic::quic::DeserializeProtectionContext{
        .peer_role = coquic::quic::EndpointRole::client,
        .handshake_secret =
            coquic::quic::TrafficSecret{
                .cipher_suite = cipher_suite,
                .secret = make_secret(secret_size),
            },
    };
}

class QuicProtectedCodecHandshakeTest : public testing::TestWithParam<HandshakeCipherSuiteCase> {};

coquic::quic::ProtectedOneRttPacket make_minimal_one_rtt_packet(bool key_phase = false) {
    return coquic::quic::ProtectedOneRttPacket{
        .spin_bit = true,
        .key_phase = key_phase,
        .destination_connection_id =
            {
                std::byte{0xde},
                std::byte{0xad},
                std::byte{0xbe},
                std::byte{0xef},
            },
        .packet_number_length = kOneRttPacketNumberLength,
        .packet_number = kOneRttPacketNumber,
        .frames =
            {
                coquic::quic::PingFrame{},
                coquic::quic::PingFrame{},
            },
    };
}

coquic::quic::SerializeProtectionContext
make_one_rtt_serialize_context(coquic::quic::CipherSuite cipher_suite, std::size_t secret_size,
                               bool key_phase = false) {
    return coquic::quic::SerializeProtectionContext{
        .local_role = coquic::quic::EndpointRole::client,
        .one_rtt_secret =
            coquic::quic::TrafficSecret{
                .cipher_suite = cipher_suite,
                .secret = make_secret(secret_size),
            },
        .one_rtt_key_phase = key_phase,
    };
}

coquic::quic::DeserializeProtectionContext make_one_rtt_deserialize_context(
    coquic::quic::CipherSuite cipher_suite, std::size_t secret_size, bool key_phase = false,
    std::size_t destination_connection_id_length = kOneRttDestinationConnectionIdLength) {
    return coquic::quic::DeserializeProtectionContext{
        .peer_role = coquic::quic::EndpointRole::client,
        .one_rtt_secret =
            coquic::quic::TrafficSecret{
                .cipher_suite = cipher_suite,
                .secret = make_secret(secret_size),
            },
        .one_rtt_key_phase = key_phase,
        .largest_authenticated_application_packet_number = kOneRttLargestAuthenticatedPacketNumber,
        .one_rtt_destination_connection_id_length = destination_connection_id_length,
    };
}

class QuicProtectedCodecOneRttTest : public testing::TestWithParam<OneRttCipherSuiteCase> {};

TEST(QuicProtectedCodecTest, OneRttPacketSerializesSharedStreamFrameViews) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    auto shared_payload = std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
        std::byte{0xdd},
    });
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = true,
            .stream_id = 9,
            .offset = 4,
            .storage = shared_payload,
            .begin = 1,
            .end = 3,
        },
    };

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::vector<coquic::quic::ProtectedPacket>{packet},
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                       /*secret_size=*/16));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                         /*secret_size=*/16));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);

    const auto *one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.value().front());
    ASSERT_NE(one_rtt, nullptr);
    ASSERT_EQ(one_rtt->frames.size(), 1u);

    const auto *stream = std::get_if<coquic::quic::StreamFrame>(&one_rtt->frames.front());
    ASSERT_NE(stream, nullptr);
    EXPECT_TRUE(stream->fin);
    EXPECT_EQ(stream->stream_id, 9u);
    EXPECT_EQ(stream->offset, std::optional<std::uint64_t>{4u});
    EXPECT_EQ(stream->stream_data, (std::vector<std::byte>{std::byte{0xbb}, std::byte{0xcc}}));
}

TEST(QuicProtectedCodecTest, AppendsOneRttPacketIntoExistingDatagramBuffer) {
    const auto packet = make_minimal_one_rtt_packet();
    const auto context = make_one_rtt_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/16);

    const std::vector<std::byte> prefix{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };
    auto datagram = prefix;

    const auto appended =
        coquic::quic::test::append_protected_one_rtt_packet_to_datagram(datagram, packet, context);
    ASSERT_TRUE(appended.has_value());
    EXPECT_EQ(datagram.size(), prefix.size() + appended.value());
    EXPECT_EQ(std::vector<std::byte>(datagram.begin(),
                                     datagram.begin() + static_cast<std::ptrdiff_t>(prefix.size())),
              prefix);

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::vector<coquic::quic::ProtectedPacket>{packet}, context);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(std::vector<std::byte>(datagram.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
                                     datagram.end()),
              encoded.value());
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsInvalidStreamViewBounds) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage = std::make_shared<std::vector<std::byte>>(
                std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}}),
            .begin = 2,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsStreamViewOffsetOverflow) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 4611686018427387903ull,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsMissingStreamViewStorage) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage = nullptr,
            .begin = 0,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsStreamViewPastStorageEnd) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 2,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsStreamViewStreamIdAboveVarintLimit) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = UINT64_MAX,
            .offset = 0,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsInvalidPacketNumberLengthOnStreamViewPath) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.packet_number_length = 5;
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsEmptyPayloadOnStreamViewPath) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views.clear();

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::empty_packet_payload);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsLengthlessFrameBeforeStreamView) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames = {
        coquic::quic::StreamFrame{
            .fin = false,
            .has_offset = false,
            .has_length = false,
            .stream_id = 0,
            .offset = std::nullopt,
            .stream_data = {std::byte{0x01}},
        },
    };
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRejectsInvalidSerializedFrameBeforeStreamView) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames = {
        coquic::quic::StreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = UINT64_MAX,
            .offset = 0,
            .stream_data = {std::byte{0x01}},
        },
    };
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 1,
        },
    };

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketPropagatesHeaderProtectionFaultOnStreamViewPath) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    packet.stream_frame_views = {
        coquic::quic::StreamFrameView{
            .fin = false,
            .stream_id = 0,
            .offset = 0,
            .storage =
                std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{std::byte{0xaa}}),
            .begin = 0,
            .end = 1,
        },
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_aes_context_new);

    std::vector<std::byte> datagram;
    const auto appended = coquic::quic::test::append_protected_one_rtt_packet_to_datagram(
        datagram, packet,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16));
    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(appended.error().code, coquic::quic::CodecErrorCode::header_protection_failed);
}

coquic::quic::SerializeProtectionContext
make_initial_and_handshake_serialize_context(coquic::quic::CipherSuite cipher_suite,
                                             std::size_t secret_size) {
    return coquic::quic::SerializeProtectionContext{
        .local_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id = hex_bytes("8394c8f03e515708"),
        .handshake_secret =
            coquic::quic::TrafficSecret{
                .cipher_suite = cipher_suite,
                .secret = make_secret(secret_size),
            },
    };
}

coquic::quic::DeserializeProtectionContext
make_initial_and_handshake_deserialize_context(coquic::quic::CipherSuite cipher_suite,
                                               std::size_t secret_size) {
    return coquic::quic::DeserializeProtectionContext{
        .peer_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id = hex_bytes("8394c8f03e515708"),
        .handshake_secret =
            coquic::quic::TrafficSecret{
                .cipher_suite = cipher_suite,
                .secret = make_secret(secret_size),
            },
    };
}

void expect_protected_serialize_fault(const coquic::quic::ProtectedPacket &packet,
                                      const coquic::quic::SerializeProtectionContext &context,
                                      coquic::quic::test::PacketCryptoFaultPoint fault_point,
                                      coquic::quic::CodecErrorCode expected_error) {
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(fault_point);

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, context);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, expected_error);
}

void expect_protected_deserialize_fault(const std::vector<std::byte> &bytes,
                                        const coquic::quic::DeserializeProtectionContext &context,
                                        coquic::quic::test::PacketCryptoFaultPoint fault_point,
                                        coquic::quic::CodecErrorCode expected_error) {
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(fault_point);

    const auto decoded = coquic::quic::deserialize_protected_datagram(bytes, context);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, expected_error);
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

TEST(QuicProtectedCodecTest, SerializeProtectedDatagramWithMetadataTracksPacketOffsets) {
    const auto context =
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    const std::array<coquic::quic::ProtectedPacket, 2> packets = {
        make_minimal_handshake_packet(),
        coquic::quic::ProtectedPacket{make_minimal_handshake_packet()},
    };

    const auto encoded = coquic::quic::serialize_protected_datagram_with_metadata(packets, context);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_EQ(encoded.value().packet_metadata.size(), 2u);
    EXPECT_EQ(encoded.value().packet_metadata[0].offset, 0u);
    EXPECT_EQ(encoded.value().packet_metadata[1].offset, encoded.value().packet_metadata[0].length);
    EXPECT_EQ(encoded.value().packet_metadata[0].length + encoded.value().packet_metadata[1].length,
              encoded.value().bytes.size());
}

TEST(QuicProtectedCodecTest, LegacySerializeProtectedDatagramStillReturnsOnlyBytes) {
    const auto context =
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    const std::array<coquic::quic::ProtectedPacket, 1> packets = {
        make_minimal_handshake_packet(),
    };

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, context);
    const auto encoded_with_metadata =
        coquic::quic::serialize_protected_datagram_with_metadata(packets, context);

    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(encoded_with_metadata.has_value());
    EXPECT_EQ(encoded.value(), encoded_with_metadata.value().bytes);
}

TEST(QuicProtectedCodecTest, RoundTripsQuicV2InitialPacket) {
    auto packet = make_minimal_initial_packet();
    packet.version = 0x6b3343cfu;
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(std::to_integer<std::uint8_t>(encoded.value().front()) & 0xf0u, 0xd0u);

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_rfc9001_client_initial_deserialize_context());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->version, 0x6b3343cfu);
    EXPECT_EQ(initial->packet_number, 0u);
}

TEST(QuicProtectedCodecTest, RoundTripsQuicV2HandshakePacket) {
    auto packet = make_minimal_handshake_packet();
    packet.version = coquic::quic::kQuicVersion2;
    const auto context = make_handshake_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/32);
    const auto decode_context = make_handshake_deserialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/32);
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, context);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(std::to_integer<std::uint8_t>(encoded.value().front()) & 0xf0u, 0xf0u);

    const auto decoded =
        coquic::quic::deserialize_protected_datagram(encoded.value(), decode_context);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    const auto *handshake =
        std::get_if<coquic::quic::ProtectedHandshakePacket>(&decoded.value()[0]);
    ASSERT_NE(handshake, nullptr);
    EXPECT_EQ(handshake->version, coquic::quic::kQuicVersion2);
    EXPECT_EQ(handshake->packet_number, 0x1234u);
}

TEST(QuicProtectedCodecTest, RoundTripsProtectedZeroRttPacket) {
    const auto packet = make_minimal_zero_rtt_packet();
    const auto secret = make_zero_rtt_secret();

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{packet},
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        });
    ASSERT_TRUE(decoded.has_value());
    EXPECT_NE(std::get_if<coquic::quic::ProtectedZeroRttPacket>(&decoded.value().front()), nullptr);
}

TEST(QuicProtectedCodecTest, ReconstructsZeroRttPacketNumbersInApplicationDataSpace) {
    auto packet = make_minimal_zero_rtt_packet();
    packet.packet_number_length = 1;
    packet.packet_number = 257;
    const auto secret = make_zero_rtt_secret();

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{packet},
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
            .largest_authenticated_application_packet_number = 256,
        });
    ASSERT_TRUE(decoded.has_value());
    const auto *zero_rtt =
        std::get_if<coquic::quic::ProtectedZeroRttPacket>(&decoded.value().front());
    ASSERT_NE(zero_rtt, nullptr);
    EXPECT_EQ(zero_rtt->packet_number, 257u);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWithoutZeroRttSecret) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWhenCipherSuiteIsUnsupported) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret =
                         coquic::quic::TrafficSecret{
                             .cipher_suite = invalid_cipher_suite(),
                             .secret = make_secret(32),
                         },
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWithUnsupportedVersion) {
    auto packet = make_minimal_zero_rtt_packet();
    packet.version = 2;
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWithInvalidPacketNumberLength) {
    auto packet = make_minimal_zero_rtt_packet();
    packet.packet_number_length = 5;
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWithFrameForbiddenInZeroRttSpace) {
    auto packet = make_minimal_zero_rtt_packet();
    packet.frames = {
        coquic::quic::CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        },
    };
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicProtectedCodecTest, PropagatesZeroRttSealFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_minimal_zero_rtt_packet()},
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = make_zero_rtt_secret(),
        },
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWithoutReceiveZeroRttSecret) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsMalformedZeroRttPacketWhenLongHeaderLayoutIsTruncated) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());
    encoded.value().resize(5);

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWhenReceiveCipherSuiteIsUnsupported) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret =
                coquic::quic::TrafficSecret{
                    .cipher_suite = invalid_cipher_suite(),
                    .secret = make_secret(32),
                },
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicProtectedCodecTest, RejectsZeroRttPacketWhenPacketNumberRecoveryContextOverflows) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());

    auto context = coquic::quic::DeserializeProtectionContext{
        .peer_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
        .zero_rtt_secret = secret,
    };
    context.largest_authenticated_application_packet_number = (1ULL << 62) - 1;
    const auto decoded = coquic::quic::deserialize_protected_datagram(encoded.value(), context);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_number_recovery_failed);
}

TEST(QuicProtectedCodecTest, PropagatesZeroRttDeserializeHeaderProtectionFaultsFromPacketCrypto) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        },
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesZeroRttDeserializePayloadFaultsFromPacketCrypto) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        },
        coquic::quic::test::PacketCryptoFaultPoint::open_set_tag,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, PropagatesZeroRttDeserializePlaintextPacketFaultsFromProtectedCodec) {
    const auto secret = make_zero_rtt_secret();
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_zero_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
                     .zero_rtt_secret = secret,
                 });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector(
        coquic::quic::test::ProtectedCodecFaultPoint::deserialize_plaintext_packet);
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .zero_rtt_secret = secret,
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RoundTripsPaddedQuicV2InitialAndHandshakeDatagramWithCryptoFrames) {
    coquic::quic::ProtectedInitialPacket initial{
        .version = coquic::quic::kQuicVersion2,
        .destination_connection_id = hex_bytes("8394c8f03e515708"),
        .source_connection_id = hex_bytes("c101"),
        .packet_number_length = 2,
        .packet_number = 0,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = hex_bytes("0102030405060708"),
                },
            },
    };
    coquic::quic::ProtectedHandshakePacket handshake{
        .version = coquic::quic::kQuicVersion2,
        .destination_connection_id = hex_bytes("8394c8f03e515708"),
        .source_connection_id = hex_bytes("c101"),
        .packet_number_length = 2,
        .packet_number = 0x1234u,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = hex_bytes("1112131415161718"),
                },
            },
    };
    auto packets = std::vector<coquic::quic::ProtectedPacket>{
        initial,
        handshake,
    };
    const auto context = make_initial_and_handshake_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/32);
    const auto decode_context = make_initial_and_handshake_deserialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/32);

    auto encoded = coquic::quic::serialize_protected_datagram(packets, context);
    ASSERT_TRUE(encoded.has_value());
    if (encoded.value().size() < 1200u) {
        auto *initial_packet = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
        ASSERT_NE(initial_packet, nullptr);
        initial_packet->frames.emplace_back(coquic::quic::PaddingFrame{
            .length = 1200u - encoded.value().size(),
        });
        encoded = coquic::quic::serialize_protected_datagram(packets, context);
        ASSERT_TRUE(encoded.has_value());
    }

    const auto decoded =
        coquic::quic::deserialize_protected_datagram(encoded.value(), decode_context);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 2u);

    const auto *decoded_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]);
    ASSERT_NE(decoded_initial, nullptr);
    ASSERT_FALSE(decoded_initial->frames.empty());
    EXPECT_TRUE(std::holds_alternative<coquic::quic::CryptoFrame>(decoded_initial->frames.front()));
    if (const auto *crypto =
            std::get_if<coquic::quic::CryptoFrame>(&decoded_initial->frames.front())) {
        EXPECT_EQ(crypto->crypto_data, hex_bytes("0102030405060708"));
    }

    const auto *decoded_handshake =
        std::get_if<coquic::quic::ProtectedHandshakePacket>(&decoded.value()[1]);
    ASSERT_NE(decoded_handshake, nullptr);
    ASSERT_FALSE(decoded_handshake->frames.empty());
    EXPECT_TRUE(
        std::holds_alternative<coquic::quic::CryptoFrame>(decoded_handshake->frames.front()));
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWithUnsupportedVersion) {
    auto packet = make_minimal_initial_packet();
    packet.version = 2;
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWithInvalidPacketNumberLength) {
    auto packet = make_minimal_initial_packet();
    packet.packet_number_length = 5;
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWithEmptyPayload) {
    auto packet = make_minimal_initial_packet();
    packet.frames.clear();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::empty_packet_payload);
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWithFrameForbiddenInInitialSpace) {
    auto packet = make_minimal_initial_packet();
    packet.frames = {
        coquic::quic::NewTokenFrame{
            .token = {std::byte{0x01}},
        },
    };
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWithoutReceiveInitialContext) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), coquic::quic::DeserializeProtectionContext{
                             .peer_role = coquic::quic::EndpointRole::client,
                         });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWhenPacketNumberRecoveryContextOverflows) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    auto context = make_rfc9001_client_initial_deserialize_context();
    context.largest_authenticated_initial_packet_number = (1ULL << 62) - 1;
    const auto decoded = coquic::quic::deserialize_protected_datagram(encoded.value(), context);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_number_recovery_failed);
}

TEST(QuicProtectedCodecTest, PropagatesInitialSealFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_rfc9001_client_initial_packet()},
        make_rfc9001_client_initial_serialize_context(),
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, PropagatesInitialHeaderProtectionFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_rfc9001_client_initial_packet()},
        make_rfc9001_client_initial_serialize_context(),
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesInitialDeserializeHeaderProtectionFaultsFromPacketCrypto) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(), make_rfc9001_client_initial_deserialize_context(),
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesInitialDeserializePayloadFaultsFromPacketCrypto) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(), make_rfc9001_client_initial_deserialize_context(),
        coquic::quic::test::PacketCryptoFaultPoint::open_set_tag,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST_P(QuicProtectedCodecHandshakeTest, RoundTripsHandshakePacketForCipherSuite) {
    const auto params = GetParam();
    const auto expected_packet = make_minimal_handshake_packet();
    const std::vector<coquic::quic::ProtectedPacket> packets{expected_packet};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_handshake_serialize_context(params.cipher_suite, params.secret_size));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        make_handshake_deserialize_context(params.cipher_suite, params.secret_size));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    const auto *handshake =
        std::get_if<coquic::quic::ProtectedHandshakePacket>(&decoded.value().front());
    ASSERT_NE(handshake, nullptr);
    EXPECT_EQ(handshake->packet_number, 0x1234ULL);
    EXPECT_EQ(handshake->destination_connection_id, expected_packet.destination_connection_id);
    EXPECT_EQ(handshake->source_connection_id, expected_packet.source_connection_id);
    ASSERT_EQ(handshake->frames.size(), 1u);
    const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&handshake->frames.front());
    ASSERT_NE(crypto, nullptr);
    EXPECT_EQ(crypto->offset, 0ULL);
    EXPECT_EQ(crypto->crypto_data,
              std::vector<std::byte>({std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}));
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWithoutHandshakeSecret) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWithEmptyPayload) {
    auto packet = make_minimal_handshake_packet();
    packet.frames.clear();
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::empty_packet_payload);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWithUnsupportedVersion) {
    auto packet = make_minimal_handshake_packet();
    packet.version = 2;
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWithInvalidPacketNumberLength) {
    auto packet = make_minimal_handshake_packet();
    packet.packet_number_length = 5;
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWhenCipherSuiteIsUnsupported) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .handshake_secret =
                         coquic::quic::TrafficSecret{
                             .cipher_suite = invalid_cipher_suite(),
                             .secret = make_secret(32),
                         },
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWhenSecretDoesNotMatch) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    auto wrong_secret = make_secret(32);
    wrong_secret.back() ^= std::byte{0xff};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .handshake_secret =
                coquic::quic::TrafficSecret{
                    .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                    .secret = std::move(wrong_secret),
                },
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWithoutReceiveHandshakeSecret) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), coquic::quic::DeserializeProtectionContext{
                             .peer_role = coquic::quic::EndpointRole::client,
                         });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWhenReceiveCipherSuiteIsUnsupported) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), coquic::quic::DeserializeProtectionContext{
                             .peer_role = coquic::quic::EndpointRole::client,
                             .handshake_secret =
                                 coquic::quic::TrafficSecret{
                                     .cipher_suite = invalid_cipher_suite(),
                                     .secret = make_secret(32),
                                 },
                         });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicProtectedCodecTest, RejectsHandshakePacketWhenPacketNumberRecoveryContextOverflows) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    auto context =
        make_handshake_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    context.largest_authenticated_handshake_packet_number = (1ULL << 62) - 1;
    const auto decoded = coquic::quic::deserialize_protected_datagram(encoded.value(), context);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_number_recovery_failed);
}

TEST(QuicProtectedCodecTest, PropagatesHandshakeSealFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_minimal_handshake_packet()},
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, PropagatesHandshakeHeaderProtectionFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_minimal_handshake_packet()},
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesHandshakeDeserializeHeaderProtectionFaultsFromPacketCrypto) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(),
        make_handshake_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesHandshakeDeserializePayloadFaultsFromPacketCrypto) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(),
        make_handshake_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::open_set_tag,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST_P(QuicProtectedCodecOneRttTest, RoundTripsOneRttPacketForCipherSuite) {
    const auto params = GetParam();
    const auto expected_packet = make_minimal_one_rtt_packet();
    const std::vector<coquic::quic::ProtectedPacket> packets{expected_packet};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_one_rtt_serialize_context(params.cipher_suite, params.secret_size));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_one_rtt_deserialize_context(params.cipher_suite, params.secret_size));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    const auto *one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.value().front());
    ASSERT_NE(one_rtt, nullptr);
    EXPECT_TRUE(one_rtt->spin_bit);
    EXPECT_FALSE(one_rtt->key_phase);
    EXPECT_EQ(one_rtt->destination_connection_id, expected_packet.destination_connection_id);
    EXPECT_EQ(one_rtt->packet_number_length, kOneRttPacketNumberLength);
    EXPECT_EQ(one_rtt->packet_number, kOneRttPacketNumber);
    ASSERT_EQ(one_rtt->frames.size(), 2u);
    EXPECT_TRUE(std::holds_alternative<coquic::quic::PingFrame>(one_rtt->frames[0]));
    EXPECT_TRUE(std::holds_alternative<coquic::quic::PingFrame>(one_rtt->frames[1]));
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenKeyPhaseDoesNotMatchContext) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet(false)};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_one_rtt_deserialize_context(
                             coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32, true));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWithoutOneRttSecret) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenSerializeKeyPhaseDoesNotMatchContext) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet(true)};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                                32, false));
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest,
     RejectsOneRttPacketWhenConfiguredDestinationConnectionIdLengthIsWrong) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_one_rtt_deserialize_context(
                             coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32, false, 0));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWithInvalidPacketNumberLength) {
    auto packet = make_minimal_one_rtt_packet();
    packet.packet_number_length = 5;
    const std::vector<coquic::quic::ProtectedPacket> packets{packet};

    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWithUnsupportedCipherSuite) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, coquic::quic::SerializeProtectionContext{
                     .local_role = coquic::quic::EndpointRole::client,
                     .one_rtt_secret =
                         coquic::quic::TrafficSecret{
                             .cipher_suite = invalid_cipher_suite(),
                             .secret = make_secret(32),
                         },
                 });
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWithNonTerminalStreamFrameWithoutLength) {
    const std::vector<coquic::quic::ProtectedPacket> packets{
        coquic::quic::ProtectedOneRttPacket{
            .spin_bit = false,
            .key_phase = false,
            .destination_connection_id =
                {
                    std::byte{0xde},
                    std::byte{0xad},
                    std::byte{0xbe},
                    std::byte{0xef},
                },
            .packet_number_length = kOneRttPacketNumberLength,
            .packet_number = kOneRttPacketNumber,
            .frames =
                {
                    coquic::quic::StreamFrame{
                        .fin = false,
                        .has_offset = false,
                        .has_length = false,
                        .stream_id = 0,
                        .offset = std::nullopt,
                        .stream_data = {std::byte{0x01}},
                    },
                    coquic::quic::PingFrame{},
                },
        },
    };
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWithoutReceiveOneRttSecret) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .one_rtt_destination_connection_id_length = kOneRttDestinationConnectionIdLength,
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::missing_crypto_context);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenReceiveCipherSuiteIsUnsupported) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .one_rtt_secret =
                coquic::quic::TrafficSecret{
                    .cipher_suite = invalid_cipher_suite(),
                    .secret = make_secret(32),
                },
            .largest_authenticated_application_packet_number =
                kOneRttLargestAuthenticatedPacketNumber,
            .one_rtt_destination_connection_id_length = kOneRttDestinationConnectionIdLength,
        });
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::unsupported_cipher_suite);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenDestinationConnectionIdLengthExceedsBytes) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    auto context =
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    context.one_rtt_destination_connection_id_length = encoded.value().size();
    const auto decoded = coquic::quic::deserialize_protected_datagram(encoded.value(), context);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::malformed_short_header_context);
    EXPECT_EQ(decoded.error().offset, 1u);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenPacketNumberRecoveryContextOverflows) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    auto context =
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    context.largest_authenticated_application_packet_number = (1ULL << 62) - 1;
    const auto decoded = coquic::quic::deserialize_protected_datagram(encoded.value(), context);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_number_recovery_failed);
}

TEST(QuicProtectedCodecTest, PropagatesOneRttSealFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_minimal_one_rtt_packet()},
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, PropagatesOneRttHeaderProtectionFaultsFromPacketCrypto) {
    expect_protected_serialize_fault(
        coquic::quic::ProtectedPacket{make_minimal_one_rtt_packet()},
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesOneRttDeserializeHeaderProtectionFaultsFromPacketCrypto) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(),
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new,
        coquic::quic::CodecErrorCode::header_protection_failed);
}

TEST(QuicProtectedCodecTest, PropagatesOneRttDeserializePayloadFaultsFromPacketCrypto) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    expect_protected_deserialize_fault(
        encoded.value(),
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32),
        coquic::quic::test::PacketCryptoFaultPoint::open_set_tag,
        coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicProtectedCodecTest, RoundTripsCoalescedInitialAndHandshakeDatagram) {
    const std::vector<coquic::quic::ProtectedPacket> packets{
        make_rfc9001_client_initial_packet(),
        make_minimal_handshake_packet(),
    };
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_initial_and_handshake_serialize_context(
                     coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_initial_and_handshake_deserialize_context(
                             coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 2u);
    EXPECT_TRUE(std::holds_alternative<coquic::quic::ProtectedInitialPacket>(decoded.value()[0]));
    EXPECT_TRUE(std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(decoded.value()[1]));
}

TEST(QuicProtectedCodecTest, RejectsEmptyProtectedDatagram) {
    const auto decoded = coquic::quic::deserialize_protected_datagram({}, {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, ReportsOffsetOfSecondPacketFailureInDatagram) {
    const std::vector<coquic::quic::ProtectedPacket> initial_packets{
        make_rfc9001_client_initial_packet()};
    const auto initial = coquic::quic::serialize_protected_datagram(
        initial_packets, make_initial_and_handshake_serialize_context(
                             coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(initial.has_value());

    const std::vector<coquic::quic::ProtectedPacket> handshake_packets{
        make_minimal_handshake_packet()};
    const auto handshake = coquic::quic::serialize_protected_datagram(
        handshake_packets, make_initial_and_handshake_serialize_context(
                               coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(handshake.has_value());

    std::vector<std::byte> datagram = initial.value();
    datagram.insert(datagram.end(), handshake.value().begin(), handshake.value().end());
    datagram.back() ^= std::byte{0xff};

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagram, make_initial_and_handshake_deserialize_context(
                      coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_decryption_failed);
    EXPECT_EQ(decoded.error().offset, initial.value().size());
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithoutDestinationConnectionIdLength) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTruncatedDestinationConnectionId) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithoutSourceConnectionIdLength) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x01}, std::byte{0xaa},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTruncatedSourceConnectionId) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTruncatedTokenLengthVarint) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x40},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTruncatedPayloadLengthVarint) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x40},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsUnsupportedProtectedPacketTypes) {
    const std::vector<std::byte> bytes{
        std::byte{0xf0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(bytes, {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
    EXPECT_EQ(decoded.error().offset, 0u);
}

TEST(QuicProtectedCodecTest, RejectsUnsupportedLongHeaderTypeAfterParsingHeaderTypeField) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x6b}, std::byte{0x33}, std::byte{0x43}, std::byte{0xcf},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(bytes, {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
    EXPECT_EQ(decoded.error().offset, 0u);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithoutFixedBit) {
    const std::vector<std::byte> bytes{
        std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(bytes, {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);
    EXPECT_EQ(decoded.error().offset, 0u);
}

TEST(QuicProtectedCodecTest, RejectsTruncatedLongHeaderVersionField) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0},
        std::byte{0x00},
        std::byte{0x00},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithUnsupportedVersion) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTooLongDestinationConnectionId) {
    const std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x15},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTooLongSourceConnectionId) {
    std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x01}, std::byte{0xaa}, std::byte{0x15},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithTokenLengthLongerThanRemainingBytes) {
    std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x01}, std::byte{0xaa}, std::byte{0x00}, std::byte{0x40}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicProtectedCodecTest, RejectsLongHeaderPacketsWithPayloadLengthLongerThanRemainingBytes) {
    std::vector<std::byte> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicProtectedCodecTest, RejectsTruncatedHandshakeLongHeaderAfterVersion) {
    const std::vector<std::byte> bytes{
        std::byte{0xe0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        bytes,
        make_handshake_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketsTooShortToRemoveHeaderProtection) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GT(encoded.value().size(), 17u);

    auto truncated = encoded.value();
    truncated[16] = std::byte{0x01};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        truncated, make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code,
              coquic::quic::CodecErrorCode::header_protection_sample_too_short);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketsTooShortToRemoveHeaderProtection) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GT(encoded.value().size(), 8u);

    const std::vector<std::byte> truncated(encoded.value().begin(), encoded.value().begin() + 8);
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        truncated,
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code,
              coquic::quic::CodecErrorCode::header_protection_sample_too_short);
}

TEST(QuicProtectedCodecTest, PadsPacketsTooShortForHeaderProtectionSample) {
    const std::vector<coquic::quic::ProtectedPacket> packets{
        coquic::quic::ProtectedOneRttPacket{
            .spin_bit = false,
            .key_phase = false,
            .destination_connection_id =
                {
                    std::byte{0xde},
                    std::byte{0xad},
                    std::byte{0xbe},
                    std::byte{0xef},
                },
            .packet_number_length = 1,
            .packet_number = 1,
            .frames =
                {
                    coquic::quic::PingFrame{},
                },
        },
    };
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .one_rtt_secret =
                coquic::quic::TrafficSecret{
                    .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                    .secret = make_secret(32),
                },
            .largest_authenticated_application_packet_number = 0,
            .one_rtt_destination_connection_id_length = 4,
        });
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);

    const auto *one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.value().front());
    ASSERT_NE(one_rtt, nullptr);
    ASSERT_GE(one_rtt->frames.size(), 2u);
    EXPECT_TRUE(std::holds_alternative<coquic::quic::PingFrame>(one_rtt->frames[0]));
    EXPECT_TRUE(std::holds_alternative<coquic::quic::PaddingFrame>(one_rtt->frames[1]));
}

TEST(QuicProtectedCodecTest, RejectsInitialPacketWhenHeaderProtectionRevealsTooLongPacketNumber) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector{
        coquic::quic::test::ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicProtectedCodecTest, RejectsOneRttPacketWhenHeaderProtectionRevealsTooLongPacketNumber) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector{
        coquic::quic::test::ProtectedCodecFaultPoint::remove_short_header_packet_length_mismatch};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicProtectedCodecTest, PropagatesInitialPlaintextDecodeFaultFromProtectedCodecSeam) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector{
        coquic::quic::test::ProtectedCodecFaultPoint::deserialize_plaintext_packet};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_rfc9001_client_initial_deserialize_context());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, PropagatesHandshakePlaintextDecodeFaultFromProtectedCodecSeam) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_handshake_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_handshake_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector{
        coquic::quic::test::ProtectedCodecFaultPoint::deserialize_plaintext_packet};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        make_handshake_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, PropagatesOneRttPlaintextDecodeFaultFromProtectedCodecSeam) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_minimal_one_rtt_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets,
        make_one_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector{
        coquic::quic::test::ProtectedCodecFaultPoint::deserialize_plaintext_packet};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(),
        make_one_rtt_deserialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicProtectedCodecTest, IgnoresProtectedCodecFaultUntilConfiguredOccurrence) {
    const std::vector<coquic::quic::ProtectedPacket> packets{make_rfc9001_client_initial_packet()};
    const auto encoded = coquic::quic::serialize_protected_datagram(
        packets, make_rfc9001_client_initial_serialize_context());
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector injector{
        coquic::quic::test::ProtectedCodecFaultPoint::deserialize_plaintext_packet, 2};
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        encoded.value(), make_rfc9001_client_initial_deserialize_context());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]), nullptr);
}

INSTANTIATE_TEST_SUITE_P(
    AllCipherSuites, QuicProtectedCodecHandshakeTest,
    testing::Values(
        HandshakeCipherSuiteCase{
            .name = "Aes128GcmSha256",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret_size = 32,
        },
        HandshakeCipherSuiteCase{
            .name = "Aes256GcmSha384",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_256_gcm_sha384,
            .secret_size = 48,
        },
        HandshakeCipherSuiteCase{
            .name = "ChaCha20Poly1305Sha256",
            .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
            .secret_size = 32,
        }),
    [](const testing::TestParamInfo<HandshakeCipherSuiteCase> &info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(
    AllCipherSuites, QuicProtectedCodecOneRttTest,
    testing::Values(
        OneRttCipherSuiteCase{
            .name = "Aes128GcmSha256",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret_size = 32,
        },
        OneRttCipherSuiteCase{
            .name = "Aes256GcmSha384",
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_256_gcm_sha384,
            .secret_size = 48,
        },
        OneRttCipherSuiteCase{
            .name = "ChaCha20Poly1305Sha256",
            .cipher_suite = coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
            .secret_size = 32,
        }),
    [](const testing::TestParamInfo<OneRttCipherSuiteCase> &info) { return info.param.name; });

} // namespace

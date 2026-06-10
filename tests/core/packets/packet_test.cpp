#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/codec/packet.h"
#include "src/quic/transport/recovery.h"
#include "tests/support/quic_test_utils.h"

namespace {

using coquic::quic::AckFrame;
using coquic::quic::ApplicationConnectionCloseFrame;
using coquic::quic::CodecErrorCode;
using coquic::quic::CryptoFrame;
using coquic::quic::DatagramFrame;
using coquic::quic::HandshakeDoneFrame;
using coquic::quic::HandshakePacket;
using coquic::quic::InitialPacket;
using coquic::quic::NewTokenFrame;
using coquic::quic::OneRttPacket;
using coquic::quic::Packet;
using coquic::quic::PaddingFrame;
using coquic::quic::PathChallengeFrame;
using coquic::quic::PathResponseFrame;
using coquic::quic::PingFrame;
using coquic::quic::RetireConnectionIdFrame;
using coquic::quic::RetryPacket;
using coquic::quic::StreamFrame;
using coquic::quic::TransportConnectionCloseFrame;
using coquic::quic::VersionNegotiationPacket;
using coquic::quic::ZeroRttPacket;

constexpr std::uint64_t kInvalidQuicVarInt = 4611686018427387904ull;

template <std::size_t N> std::span<const std::byte> as_span(const std::array<std::byte, N> &bytes) {
    return std::span<const std::byte>(bytes.data(), bytes.size());
}

void expect_packet_decode_error(std::span<const std::byte> bytes,
                                const coquic::quic::DeserializeOptions &options,
                                CodecErrorCode code) {
    const auto decoded = coquic::quic::deserialize_packet(bytes, options);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, code);
}

void expect_packet_decode_error(const std::vector<std::byte> &bytes,
                                const coquic::quic::DeserializeOptions &options,
                                CodecErrorCode code) {
    expect_packet_decode_error(std::span<const std::byte>(bytes.data(), bytes.size()), options,
                               code);
}

void expect_packet_decode_error_at(std::span<const std::byte> bytes,
                                   const coquic::quic::DeserializeOptions &options,
                                   CodecErrorCode code, std::size_t offset) {
    const auto decoded = coquic::quic::deserialize_packet(bytes, options);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, code);
    EXPECT_EQ(decoded.error().offset, offset);
    EXPECT_LE(decoded.error().offset, bytes.size());
}

void expect_packet_serialize_error(const Packet &packet, CodecErrorCode code) {
    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, code);
}

TEST(QuicPacketTest, SerializesInitialPacketHeaderAndPayloadLength) {
    InitialPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
        .source_connection_id = {std::byte{0xcc}},
        .token = {},
        .packet_number_length = 2,
        .truncated_packet_number = 0x1234,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # The value included prior to protection MUST be set to 0.
    EXPECT_EQ(std::to_integer<std::uint8_t>(encoded.value().front()) & 0x0cu, 0u);

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<InitialPacket>(decoded.value().packet));
}

TEST(QuicPacketTest, RoundTripsVersionNegotiationPacket) {
    VersionNegotiationPacket packet{
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .supported_versions = {1u, 0x6b3343cfu},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GE(encoded.value().size(), 5u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # Where QUIC might be multiplexed with other protocols (see [RFC7983]),
    // # servers SHOULD set the most significant bit of this field (0x40) to 1
    // # so that Version Negotiation packets appear to have the Fixed Bit field.
    EXPECT_EQ(std::to_integer<std::uint8_t>(encoded.value()[0]) & 0x40u, 0x40u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # The Version field of a Version Negotiation packet MUST be set to
    // # 0x00000000.
    EXPECT_EQ(encoded.value()[1], std::byte{0x00});
    EXPECT_EQ(encoded.value()[2], std::byte{0x00});
    EXPECT_EQ(encoded.value()[3], std::byte{0x00});
    EXPECT_EQ(encoded.value()[4], std::byte{0x00});

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    const auto *version_negotiation =
        std::get_if<VersionNegotiationPacket>(&decoded.value().packet);
    ASSERT_NE(version_negotiation, nullptr);
    ASSERT_EQ(version_negotiation->supported_versions.size(), 2u);
    EXPECT_EQ(version_negotiation->supported_versions[1], 0x6b3343cfu);

    encoded.value()[0] = std::byte{0xff};
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # The value in the Unused field is set to an arbitrary value by the
    // # server.  Clients MUST ignore the value of this field.
    EXPECT_TRUE(coquic::quic::deserialize_packet(encoded.value(), {}).has_value());
}

TEST(QuicPacketTest, RoundTripsRetryPacket) {
    RetryPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
        .source_connection_id = {std::byte{0xcc}},
        .retry_token = {std::byte{0x10}, std::byte{0x11}},
        .retry_integrity_tag = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                                std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
                                std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
                                std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    const auto *retry = std::get_if<RetryPacket>(&decoded.value().packet);
    ASSERT_NE(retry, nullptr);
    EXPECT_EQ(retry->retry_token.size(), 2u);
    EXPECT_EQ(retry->retry_integrity_tag[15], std::byte{0x0f});
}

TEST(QuicPacketTest, RoundTripsRetryPacketWithNonZeroUnusedBits) {
    RetryPacket packet{
        .version = 1,
        .retry_unused_bits = 0x0bu,
        .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
        .source_connection_id = {std::byte{0xcc}},
        .retry_token = {std::byte{0x10}, std::byte{0x11}},
        .retry_integrity_tag = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                                std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
                                std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
                                std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_FALSE(encoded.value().empty());
    EXPECT_EQ(std::to_integer<std::uint8_t>(encoded.value()[0]) & 0x0fu, 0x0bu);

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    const auto *retry = std::get_if<RetryPacket>(&decoded.value().packet);
    ASSERT_NE(retry, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5
    // # The value in the Unused field is set to an arbitrary value by the
    // # server; a client MUST ignore these bits.
    EXPECT_EQ(retry->retry_unused_bits, 0x0bu);
}

TEST(QuicPacketTest, SerializesQuicV2LongHeaderTypeBitsPerRfc9369) {
    const auto initial = coquic::quic::serialize_packet(InitialPacket{
        .version = 0x6b3343cfu,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    });
    ASSERT_TRUE(initial.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9369#section-3
    // # Except for a few differences, QUIC version 2 endpoints MUST implement
    // # the QUIC version 1 specification as described in [QUIC], [QUIC-TLS],
    // # and [QUIC-RECOVERY].
    EXPECT_EQ(std::to_integer<std::uint8_t>(initial.value().front()) & 0xf0u, 0xd0u);

    const auto zero_rtt = coquic::quic::serialize_packet(ZeroRttPacket{
        .version = 0x6b3343cfu,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 2,
        .frames = {PingFrame{}},
    });
    ASSERT_TRUE(zero_rtt.has_value());
    EXPECT_EQ(std::to_integer<std::uint8_t>(zero_rtt.value().front()) & 0xf0u, 0xe0u);

    const auto handshake = coquic::quic::serialize_packet(HandshakePacket{
        .version = 0x6b3343cfu,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 3,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x02}},
        }},
    });
    ASSERT_TRUE(handshake.has_value());
    EXPECT_EQ(std::to_integer<std::uint8_t>(handshake.value().front()) & 0xf0u, 0xf0u);

    const auto retry = coquic::quic::serialize_packet(RetryPacket{
        .version = 0x6b3343cfu,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .retry_token = {std::byte{0x10}},
        .retry_integrity_tag = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                                std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
                                std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
                                std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}},
    });
    ASSERT_TRUE(retry.has_value());
    EXPECT_EQ(std::to_integer<std::uint8_t>(retry.value().front()) & 0xf0u, 0xc0u);
}

TEST(QuicPacketTest, RejectsAckFrameInZeroRttPacket) {
    ZeroRttPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames = {AckFrame{}},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicPacketTest, RejectsApplicationConnectionCloseInNonApplicationPacket) {
    InitialPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames = {ApplicationConnectionCloseFrame{
            .error_code = 0x100,
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.5
    // # CONNECTION_CLOSE frames signaling application errors (type 0x1d)
    // # MUST only appear in the application data packet number space.
    EXPECT_EQ(encoded.error().code, CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicPacketTest, RejectsOtherForbiddenFramesInZeroRttPacket) {
    expect_packet_serialize_error(
        ZeroRttPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);
    expect_packet_serialize_error(
        ZeroRttPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 2,
            .frames = {HandshakeDoneFrame{}},
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);
    expect_packet_serialize_error(
        ZeroRttPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 3,
            .frames = {NewTokenFrame{
                .token = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);
    expect_packet_serialize_error(
        ZeroRttPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 4,
            .frames = {PathResponseFrame{
                .data = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                         std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}},
            }},
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);
    expect_packet_serialize_error(
        ZeroRttPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 5,
            .frames = {RetireConnectionIdFrame{
                .sequence_number = 1,
            }},
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicPacketTest, AllowsHandshakeSafeFrameSubsetInHandshakePackets) {
    HandshakePacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames =
            {
                PingFrame{},
                CryptoFrame{
                    .offset = 0,
                    .crypto_data = {std::byte{0x01}},
                },
                AckFrame{},
                TransportConnectionCloseFrame{},
            },
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<HandshakePacket>(decoded.value().packet));
}

TEST(QuicPacketTest, AllowsPaddingInInitialPacketsAndStreamFramesWithoutLengthAtPacketEnd) {
    const auto initial_encoded = coquic::quic::serialize_packet(InitialPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 9,
        .frames = {PaddingFrame{
            .length = 2,
        }},
    });
    ASSERT_TRUE(initial_encoded.has_value());

    const auto initial_decoded = coquic::quic::deserialize_packet(initial_encoded.value(), {});
    ASSERT_TRUE(initial_decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<InitialPacket>(initial_decoded.value().packet));

    const auto one_rtt_encoded = coquic::quic::serialize_packet(OneRttPacket{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames = {StreamFrame{
            .stream_id = 0,
            .stream_data = {std::byte{0x10}, std::byte{0x11}},
        }},
    });
    ASSERT_TRUE(one_rtt_encoded.has_value());

    const auto one_rtt_decoded = coquic::quic::deserialize_packet(
        one_rtt_encoded.value(), coquic::quic::DeserializeOptions{
                                     .one_rtt_destination_connection_id_length = 1,
                                 });
    if (!one_rtt_decoded.has_value()) {
        FAIL() << "1-RTT packet did not decode";
    }
    const auto *one_rtt = std::get_if<OneRttPacket>(&one_rtt_decoded.value().packet);
    if (one_rtt == nullptr) {
        FAIL() << "expected 1-RTT packet";
    }
    if (one_rtt->frames.size() != 1u) {
        FAIL() << "unexpected 1-RTT frame count";
    }
    const auto *stream = std::get_if<StreamFrame>(&one_rtt->frames.front());
    ASSERT_NE(stream, nullptr);
    EXPECT_FALSE(stream->has_length);
    EXPECT_EQ(stream->stream_data, (std::vector<std::byte>{std::byte{0x10}, std::byte{0x11}}));
}

TEST(QuicPacketTest, AllowsLengthEncodedStreamFrameAtPacketEndAndNonV1LongConnectionIds) {
    const auto one_rtt_encoded = coquic::quic::serialize_packet(OneRttPacket{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 8,
        .frames = {StreamFrame{
            .has_length = true,
            .stream_id = 1,
            .stream_data = {std::byte{0x20}, std::byte{0x21}},
        }},
    });
    ASSERT_TRUE(one_rtt_encoded.has_value());

    const auto one_rtt_decoded = coquic::quic::deserialize_packet(
        one_rtt_encoded.value(), coquic::quic::DeserializeOptions{
                                     .one_rtt_destination_connection_id_length = 1,
                                 });
    ASSERT_TRUE(one_rtt_decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<OneRttPacket>(one_rtt_decoded.value().packet));

    const auto initial_encoded = coquic::quic::serialize_packet(InitialPacket{
        .version = 2,
        .destination_connection_id = std::vector<std::byte>(21, std::byte{0xaa}),
        .source_connection_id = std::vector<std::byte>(21, std::byte{0xbb}),
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    });
    ASSERT_TRUE(initial_encoded.has_value());

    const auto initial_decoded = coquic::quic::deserialize_packet(initial_encoded.value(), {});
    if (!initial_decoded.has_value()) {
        FAIL() << "Initial packet did not decode";
    }
    const auto *initial = std::get_if<InitialPacket>(&initial_decoded.value().packet);
    if (initial == nullptr) {
        FAIL() << "expected Initial packet";
    }
    EXPECT_EQ(initial->version, 2u);
    EXPECT_EQ(initial->destination_connection_id.size(), 21u);
    EXPECT_EQ(initial->source_connection_id.size(), 21u);
}

TEST(QuicPacketTest, ParsesOneRttPacketWithContextLength) {
    coquic::quic::OneRttPacket packet{
        .spin_bit = true,
        .key_phase = true,
        .destination_connection_id = {std::byte{0xde}, std::byte{0xad}},
        .packet_number_length = 1,
        .truncated_packet_number = 9,
        .frames = {PathChallengeFrame{
            .data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}},
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    // # The value included prior to protection MUST be set to 0.
    EXPECT_EQ(std::to_integer<std::uint8_t>(encoded.value().front()) & 0x18u, 0u);

    auto decoded = coquic::quic::deserialize_packet(
        encoded.value(), coquic::quic::DeserializeOptions{
                             .one_rtt_destination_connection_id_length = 2,
                         });
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<coquic::quic::OneRttPacket>(decoded.value().packet));
}

TEST(QuicPacketTest, RejectsReservedBitsInPlaintextPacketImage) {
    std::vector<std::byte> bytes{
        std::byte{0xcd}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x01}, std::byte{0xaa}, std::byte{0x01}, std::byte{0xbb}, std::byte{0x00},
        std::byte{0x02}, std::byte{0x01}, std::byte{0x01},
    };

    auto decoded = coquic::quic::deserialize_packet(bytes, {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_reserved_bits);
}

TEST(QuicPacketTest, ReportsLongHeaderFrameDecodeErrorAtPayloadOffset) {
    const std::array<std::byte, 17> bytes{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x02}, std::byte{0xaa}, std::byte{0xbb}, std::byte{0x01}, std::byte{0xcc},
        std::byte{0x00}, std::byte{0x05}, std::byte{0x01}, std::byte{0xd6}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x42},
    };

    expect_packet_decode_error_at(as_span(bytes), {}, CodecErrorCode::truncated_input,
                                  std::size_t{14});
}

TEST(QuicPacketTest, ReportsShortHeaderFrameDecodeErrorAtPayloadOffset) {
    const std::array<std::byte, 7> bytes{
        std::byte{0x40}, std::byte{0xaa}, std::byte{0x01}, std::byte{0xd6},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x42},
    };

    expect_packet_decode_error_at(as_span(bytes),
                                  coquic::quic::DeserializeOptions{
                                      .one_rtt_destination_connection_id_length = 1,
                                  },
                                  CodecErrorCode::truncated_input, std::size_t{4});
}

TEST(QuicPacketTest, RejectsLongHeaderConnectionIdOverLimit) {
    InitialPacket packet{
        .version = 1,
        .destination_connection_id = std::vector<std::byte>(21, std::byte{0xaa}),
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # In QUIC version 1, this value MUST NOT exceed
    // # 20 bytes.
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicPacketTest, RejectsPacketNumberLengthsAboveFourBytes) {
    expect_packet_serialize_error(
        HandshakePacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 5,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
}

TEST(QuicPacketTest, RoundTripsZeroRttPacketWithAllowedFrames) {
    ZeroRttPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 4,
        .truncated_packet_number = 0x12345678,
        .frames =
            {
                PingFrame{},
            },
    };

    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());

    const auto *zero_rtt = std::get_if<ZeroRttPacket>(&decoded.value().packet);
    ASSERT_NE(zero_rtt, nullptr);
    EXPECT_EQ(zero_rtt->packet_number_length, 4u);
    EXPECT_EQ(zero_rtt->truncated_packet_number, 0x12345678u);
}

TEST(QuicPacketTest, AllowsNonTerminalStreamFramesWhenTheyCarryExplicitLengths) {
    OneRttPacket packet{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames =
            {
                StreamFrame{
                    .has_length = true,
                    .stream_id = 0,
                    .stream_data = {std::byte{0x01}},
                },
                PingFrame{},
            },
    };

    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());
}

TEST(QuicPacketTest, AllowsTerminalStreamFramesWithoutLength) {
    OneRttPacket packet{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames =
            {
                StreamFrame{
                    .has_length = false,
                    .stream_id = 0,
                    .stream_data = {std::byte{0x01}},
                },
            },
    };

    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_packet(
        encoded.value(), coquic::quic::DeserializeOptions{
                             .one_rtt_destination_connection_id_length = 1,
                         });
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<OneRttPacket>(decoded.value().packet));
}

TEST(QuicPacketTest, RejectsDatagramFrameInInitialAndHandshakePackets) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.5
    // # * All other frame types MUST only be sent in the application data
    // # packet number space.
    expect_packet_serialize_error(
        InitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    DatagramFrame{
                        .has_length = true,
                        .data = {std::byte{0x01}},
                    },
                },
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);

    expect_packet_serialize_error(
        HandshakePacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    DatagramFrame{
                        .has_length = true,
                        .data = {std::byte{0x01}},
                    },
                },
        },
        CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicPacketTest, AllowsDatagramFramesInZeroRttAndOneRttPackets) {
    const auto zero_rtt_encoded = coquic::quic::serialize_packet(ZeroRttPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames =
            {
                DatagramFrame{
                    .has_length = true,
                    .data = {std::byte{0x01}, std::byte{0x02}},
                },
            },
    });
    ASSERT_TRUE(zero_rtt_encoded.has_value());

    const auto zero_rtt_decoded = coquic::quic::deserialize_packet(zero_rtt_encoded.value(), {});
    ASSERT_TRUE(zero_rtt_decoded.has_value());
    const auto *zero_rtt = std::get_if<ZeroRttPacket>(&zero_rtt_decoded.value().packet);
    ASSERT_NE(zero_rtt, nullptr);
    ASSERT_EQ(zero_rtt->frames.size(), 1u);
    EXPECT_TRUE(std::holds_alternative<DatagramFrame>(zero_rtt->frames.front()));

    const auto one_rtt_encoded = coquic::quic::serialize_packet(OneRttPacket{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 2,
        .frames =
            {
                DatagramFrame{
                    .has_length = false,
                    .data = {std::byte{0x03}, std::byte{0x04}},
                },
            },
    });
    ASSERT_TRUE(one_rtt_encoded.has_value());

    const auto one_rtt_decoded = coquic::quic::deserialize_packet(
        one_rtt_encoded.value(), coquic::quic::DeserializeOptions{
                                     .one_rtt_destination_connection_id_length = 1,
                                 });
    if (!one_rtt_decoded.has_value()) {
        FAIL() << "1-RTT packet did not decode";
    }
    const auto *one_rtt = std::get_if<OneRttPacket>(&one_rtt_decoded.value().packet);
    if (one_rtt == nullptr) {
        FAIL() << "expected 1-RTT packet";
    }
    if (one_rtt->frames.size() != 1u) {
        FAIL() << "unexpected 1-RTT frame count";
    }
    const auto *datagram = std::get_if<DatagramFrame>(&one_rtt->frames.front());
    ASSERT_NE(datagram, nullptr);
    EXPECT_FALSE(datagram->has_length);
    EXPECT_EQ(datagram->data, (std::vector<std::byte>{std::byte{0x03}, std::byte{0x04}}));
}

TEST(QuicPacketTest, RejectsInvalidPacketSerializationInputs) {
    expect_packet_serialize_error(
        VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .supported_versions = {},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        VersionNegotiationPacket{
            .destination_connection_id = std::vector<std::byte>(256, std::byte{0xaa}),
            .source_connection_id = {std::byte{0xbb}},
            .supported_versions = {1u},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = std::vector<std::byte>(256, std::byte{0xbb}),
            .supported_versions = {1u},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        RetryPacket{
            .version = 0,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        RetryPacket{
            .version = 1,
            .destination_connection_id = std::vector<std::byte>(21, std::byte{0xaa}),
            .source_connection_id = {std::byte{0xbb}},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        RetryPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = std::vector<std::byte>(21, std::byte{0xbb}),
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 0,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::unsupported_packet_type);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 5,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = std::vector<std::byte>(21, std::byte{0xbb}),
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 0,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {},
        },
        CodecErrorCode::empty_packet_payload);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
    // # The payload of a packet that contains frames MUST contain at least
    // # one frame, and MAY contain multiple frames and multiple frame types.
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    StreamFrame{
                        .has_length = false,
                        .stream_id = 0,
                        .stream_data = {std::byte{0x01}},
                    },
                    PingFrame{},
                },
        },
        CodecErrorCode::packet_length_mismatch);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    DatagramFrame{
                        .has_length = false,
                        .data = {std::byte{0x01}},
                    },
                    PingFrame{},
                },
        },
        CodecErrorCode::packet_length_mismatch);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    PaddingFrame{
                        .length = 0,
                    },
                },
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 0x100,
            .frames =
                {
                    PingFrame{},
                },
        },
        CodecErrorCode::invalid_varint);
}

TEST(QuicPacketTest, RejectsMalformedVersionNegotiationPackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}}),
        {}, CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 8>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::packet_length_mismatch);
}

TEST(QuicPacketTest, RejectsMalformedInitialPackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x15}}),
        {}, CodecErrorCode::invalid_varint);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # Endpoints that receive a version 1 long header with a
    // # value larger than 20 MUST drop the packet.
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 8>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x02}}),
        {}, CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 8>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 9>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 10>{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}}),
        {}, CodecErrorCode::empty_packet_payload);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
    // # An endpoint MUST treat receipt of a packet containing no frames as a
    // # connection error of type PROTOCOL_VIOLATION.
}

TEST(QuicPacketTest, RejectsMalformedZeroRttAndHandshakePackets) {
    auto zero_rtt = coquic::quic::serialize_packet(ZeroRttPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PingFrame{}},
    });
    ASSERT_TRUE(zero_rtt.has_value());
    zero_rtt.value()[9] = std::byte{0x03};
    expect_packet_decode_error(zero_rtt.value(), {}, CodecErrorCode::packet_length_mismatch);

    auto serialized_handshake = coquic::quic::serialize_packet(HandshakePacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PingFrame{}},
    });
    ASSERT_TRUE(serialized_handshake.has_value());
    serialized_handshake.value()[9] = std::byte{0x03};
    expect_packet_decode_error(serialized_handshake.value(), {},
                               CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xd0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xe0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
}

TEST(QuicPacketTest, RejectsForbiddenFramesAndFrameDecodeErrorsInLongHeaders) {
    const auto forbidden_payload = coquic::quic::serialize_frame(NewTokenFrame{
        .token = {std::byte{0x01}},
    });
    ASSERT_TRUE(forbidden_payload.has_value());

    std::vector<std::byte> initial_with_forbidden_frame{
        std::byte{0xc0},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        static_cast<std::byte>(1 + forbidden_payload.value().size()),
        std::byte{0x00},
    };
    initial_with_forbidden_frame.insert(initial_with_forbidden_frame.end(),
                                        forbidden_payload.value().begin(),
                                        forbidden_payload.value().end());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.5
    // # * All other frame types MUST only be sent in the application data
    // # packet number space.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
    // # An endpoint MUST treat
    // # receipt of a frame in a packet type that is not permitted as a
    // # connection error of type PROTOCOL_VIOLATION.
    expect_packet_decode_error(initial_with_forbidden_frame, {},
                               CodecErrorCode::frame_not_allowed_in_packet_type);

    std::vector<std::byte> handshake_with_forbidden_frame{
        std::byte{0xe0}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, static_cast<std::byte>(1 + forbidden_payload.value().size()),
        std::byte{0x00},
    };
    handshake_with_forbidden_frame.insert(handshake_with_forbidden_frame.end(),
                                          forbidden_payload.value().begin(),
                                          forbidden_payload.value().end());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.4
    // # Endpoints MUST treat receipt of Handshake packets with other frames
    // # as a connection error of type PROTOCOL_VIOLATION.
    expect_packet_decode_error(handshake_with_forbidden_frame, {},
                               CodecErrorCode::frame_not_allowed_in_packet_type);

    expect_packet_decode_error(
        std::vector<std::byte>{
            std::byte{0xc0},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x01},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x02},
            std::byte{0x00},
            std::byte{0x1f},
        },
        {}, CodecErrorCode::unknown_frame_type);
}

TEST(QuicPacketTest, RejectsOutboundAckFrameInZeroRttPacket) {
    coquic::quic::ReceivedPacketHistory history;
    history.record_received(5, true, coquic::quic::test::test_time(1));
    const auto header = history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                                          coquic::quic::test::test_time(2));
    ASSERT_TRUE(header.has_value());
    if (!header.has_value()) {
        return;
    }
    const auto &ack_header = header.value();

    const auto encoded = coquic::quic::serialize_packet(coquic::quic::ZeroRttPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames =
            {
                coquic::quic::Frame{coquic::quic::OutboundAckFrame{
                    .history = &history,
                    .header = ack_header,
                }},
            },
    });

    ASSERT_FALSE(encoded.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
    // # An endpoint MUST treat
    // # receipt of a frame in a packet type that is not permitted as a
    // # connection error of type PROTOCOL_VIOLATION.
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicPacketTest, RejectsMalformedRetryAndShortHeaderPackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xf0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xf0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xf0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}}),
        {}, CodecErrorCode::packet_length_mismatch);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    // # Packets
    // # containing a zero value for this bit are not valid packets in this
    // # version and MUST be discarded.
    expect_packet_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x00}}), {},
                               CodecErrorCode::invalid_fixed_bit);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    // # An endpoint MUST treat receipt of a
    // # packet that has a non-zero value for these bits, after removing
    // # both packet and header protection, as a connection error of type
    // # PROTOCOL_VIOLATION.
    expect_packet_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x58}}), {},
                               CodecErrorCode::invalid_reserved_bits);
    expect_packet_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x40}, std::byte{0xaa}}),
                               coquic::quic::DeserializeOptions{
                                   .one_rtt_destination_connection_id_length = 2,
                               },
                               CodecErrorCode::malformed_short_header_context);
    expect_packet_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x40}, std::byte{0xaa}}),
                               coquic::quic::DeserializeOptions{
                                   .one_rtt_destination_connection_id_length = 1,
                               },
                               CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x40}, std::byte{0xaa}, std::byte{0x01}}),
        coquic::quic::DeserializeOptions{
            .one_rtt_destination_connection_id_length = 1,
        },
        CodecErrorCode::empty_packet_payload);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
    // # An endpoint MUST treat receipt of a packet containing no frames as a
    // # connection error of type PROTOCOL_VIOLATION.
    expect_packet_decode_error(as_span(std::array<std::byte, 4>{std::byte{0x40}, std::byte{0xaa},
                                                                std::byte{0x01}, std::byte{0x1f}}),
                               coquic::quic::DeserializeOptions{
                                   .one_rtt_destination_connection_id_length = 1,
                               },
                               CodecErrorCode::unknown_frame_type);
}

TEST(QuicPacketTest, RejectsMalformedGenericPacketHeaders) {
    expect_packet_decode_error(as_span(std::array<std::byte, 0>{}), {},
                               CodecErrorCode::truncated_input);
    expect_packet_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x80}}), {},
                               CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::invalid_fixed_bit);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # An endpoint MUST
    // # treat receipt of a packet that has a non-zero value for these bits
    // # after removing both packet and header protection as a connection
    // # error of type PROTOCOL_VIOLATION.
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xcc}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::invalid_reserved_bits);
}

TEST(QuicPacketTest, AcceptsGreasedQuicBitWhenEnabled) {
    const auto initial_encoded = coquic::quic::serialize_packet(InitialPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {CryptoFrame{.offset = 0, .crypto_data = {std::byte{0x01}}}},
    });
    ASSERT_TRUE(initial_encoded.has_value());

    auto greased_initial = initial_encoded.value();
    greased_initial.front() &= std::byte{0xbfu};
    const auto strict_initial = coquic::quic::deserialize_packet(greased_initial, {});
    ASSERT_FALSE(strict_initial.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # Packets containing a zero
    // # value for this bit are not valid packets in this version and MUST
    // # be discarded.
    EXPECT_EQ(strict_initial.error().code, CodecErrorCode::invalid_fixed_bit);

    const auto decoded_initial = coquic::quic::deserialize_packet(
        greased_initial, coquic::quic::DeserializeOptions{.accept_greased_quic_bit = true});
    ASSERT_TRUE(decoded_initial.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3
    // # An endpoint that advertises the grease_quic_bit transport parameter
    // # MUST accept packets with the QUIC Bit set to a value of 0.
    EXPECT_NE(std::get_if<InitialPacket>(&decoded_initial.value().packet), nullptr);

    const auto one_rtt_encoded = coquic::quic::serialize_packet(OneRttPacket{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PingFrame{}},
    });
    ASSERT_TRUE(one_rtt_encoded.has_value());

    auto greased_one_rtt = one_rtt_encoded.value();
    greased_one_rtt.front() &= std::byte{0xbfu};
    const auto strict_one_rtt = coquic::quic::deserialize_packet(
        greased_one_rtt, coquic::quic::DeserializeOptions{
                             .one_rtt_destination_connection_id_length = 1,
                         });
    if (strict_one_rtt.has_value()) {
        FAIL() << "strict GREASE QUIC bit decode succeeded";
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    // # Packets
    // # containing a zero value for this bit are not valid packets in this
    // # version and MUST be discarded.
    EXPECT_EQ(strict_one_rtt.error().code, CodecErrorCode::invalid_fixed_bit);

    const auto decoded_one_rtt = coquic::quic::deserialize_packet(
        greased_one_rtt, coquic::quic::DeserializeOptions{
                             .one_rtt_destination_connection_id_length = 1,
                             .accept_greased_quic_bit = true,
                         });
    if (!decoded_one_rtt.has_value()) {
        FAIL() << "GREASE QUIC bit 1-RTT packet did not decode";
    }
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3
    // # An endpoint that advertises the grease_quic_bit transport parameter
    // # MUST accept packets with the QUIC Bit set to a value of 0.
    EXPECT_NE(std::get_if<OneRttPacket>(&decoded_one_rtt.value().packet), nullptr);
}

} // namespace

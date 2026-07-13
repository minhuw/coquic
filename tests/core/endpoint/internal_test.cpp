#if defined(__clang_analyzer__) && !__has_builtin(__builtin_ctzg)
// Zig 0.16's libc++ references Clang 19 builtins while the lint shell still
// runs clang-tidy 18.
// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define __builtin_ctzg(value, fallback)                                                            \
    ((value) == 0 ? (fallback) : __builtin_ctzll(static_cast<unsigned long long>(value)))
// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define __builtin_clzg(value, fallback)                                                            \
    ((value) == 0 ? (fallback)                                                                     \
                  : (__builtin_clzll(static_cast<unsigned long long>(value)) -                     \
                     (static_cast<int>(sizeof(unsigned long long) * __CHAR_BIT__) -                \
                      static_cast<int>(sizeof(value) * __CHAR_BIT__))))
// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define __builtin_popcountg(value) __builtin_popcountll(static_cast<unsigned long long>(value))
// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define __is_nothrow_convertible(from_type, to_type) __is_convertible(from_type, to_type)
#endif

#include <gtest/gtest.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic;
using namespace coquic::quic::test_support;
using coquic::quic::test::bytes_from_string;

std::vector<std::byte> make_client_initial_datagram() {
    auto client_config = make_client_endpoint_config();
    client_config.application_protocol = "coquic";

    QuicCore client(std::move(client_config));
    auto open = make_client_open_config();
    open.initial_destination_connection_id =
        bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(open),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));
    auto sends = send_effects_from(opened);
    EXPECT_FALSE(sends.empty());
    if (sends.empty()) {
        return {};
    }
    return sends.front().bytes;
}

std::vector<std::byte> make_plaintext_initial_datagram_with_token(std::vector<std::byte> token) {
    auto encoded = serialize_packet(InitialPacket{
        .version = kQuicVersion1,
        .destination_connection_id =
            bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .token = std::move(token),
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PaddingFrame{}},
    });
    EXPECT_TRUE(encoded.has_value());
    auto bytes = encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
    if (bytes.size() < 1200) {
        bytes.resize(1200, std::byte{0x00});
    }
    return bytes;
}

std::vector<std::byte>
make_plaintext_initial_datagram(std::uint32_t version,
                                std::vector<std::byte> destination_connection_id,
                                std::vector<std::byte> source_connection_id,
                                std::vector<std::byte> token, std::size_t minimum_size = 1200) {
    auto encoded = serialize_packet(InitialPacket{
        .version = version,
        .destination_connection_id = std::move(destination_connection_id),
        .source_connection_id = std::move(source_connection_id),
        .token = std::move(token),
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PaddingFrame{}},
    });
    EXPECT_TRUE(encoded.has_value());
    auto bytes = encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
    if (bytes.size() < minimum_size) {
        bytes.resize(minimum_size, std::byte{0x00});
    }
    return bytes;
}

std::vector<std::byte> make_supported_long_header_datagram(
    std::uint32_t version, std::vector<std::byte> destination_connection_id,
    std::vector<std::byte> source_connection_id, std::size_t minimum_size = 1200) {
    std::vector<std::byte> bytes;
    bytes.reserve(minimum_size);
    bytes.push_back(std::byte{0xe0});
    bytes.push_back(static_cast<std::byte>((version >> 24) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 16) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 8) & 0xffu));
    bytes.push_back(static_cast<std::byte>(version & 0xffu));
    bytes.push_back(static_cast<std::byte>(destination_connection_id.size()));
    bytes.insert(bytes.end(), destination_connection_id.begin(), destination_connection_id.end());
    bytes.push_back(static_cast<std::byte>(source_connection_id.size()));
    bytes.insert(bytes.end(), source_connection_id.begin(), source_connection_id.end());
    if (bytes.size() < minimum_size) {
        bytes.resize(minimum_size, std::byte{0x00});
    }
    return bytes;
}

std::vector<std::byte>
make_supported_initial_datagram(std::uint32_t version,
                                std::vector<std::byte> destination_connection_id,
                                std::vector<std::byte> source_connection_id,
                                std::vector<std::byte> token, std::size_t minimum_size = 1200) {
    std::vector<std::byte> bytes;
    bytes.reserve(minimum_size);
    bytes.push_back(std::byte{0xc0});
    bytes.push_back(static_cast<std::byte>((version >> 24) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 16) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 8) & 0xffu));
    bytes.push_back(static_cast<std::byte>(version & 0xffu));
    bytes.push_back(static_cast<std::byte>(destination_connection_id.size()));
    bytes.insert(bytes.end(), destination_connection_id.begin(), destination_connection_id.end());
    bytes.push_back(static_cast<std::byte>(source_connection_id.size()));
    bytes.insert(bytes.end(), source_connection_id.begin(), source_connection_id.end());
    EXPECT_LT(token.size(), 64u);
    bytes.push_back(static_cast<std::byte>(token.size()));
    bytes.insert(bytes.end(), token.begin(), token.end());
    if (bytes.size() < minimum_size) {
        bytes.resize(minimum_size, std::byte{0x00});
    }
    return bytes;
}

QuicAddressValidationTokenSecret make_address_validation_secret(std::uint8_t seed) {
    QuicAddressValidationTokenSecret secret{};
    for (std::size_t index = 0; index < secret.size(); ++index) {
        secret[index] = static_cast<std::byte>(seed + index);
    }
    return secret;
}

std::vector<std::byte> make_ipv4_identity(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                                          std::uint8_t d, std::uint16_t port) {
    return bytes_from_ints({0x04, a, b, c, d, static_cast<std::uint8_t>((port >> 8) & 0xffu),
                            static_cast<std::uint8_t>(port & 0xffu)});
}

std::vector<std::byte> make_ipv6_identity(std::initializer_list<std::uint8_t> address,
                                          std::uint16_t port) {
    std::vector<std::byte> bytes;
    bytes.reserve(19);
    bytes.push_back(std::byte{0x06});
    for (auto value : address) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    while (bytes.size() < 17) {
        bytes.push_back(std::byte{0x00});
    }
    bytes.push_back(static_cast<std::byte>((port >> 8) & 0xffu));
    bytes.push_back(static_cast<std::byte>(port & 0xffu));
    return bytes;
}

std::filesystem::path make_replay_store_path_for_test(std::string_view name) {
    static std::uint64_t sequence = 0;
    auto path = std::filesystem::temp_directory_path() / "coquic-rfc9000";
    path /= std::string(name) + "-" + std::to_string(++sequence) + ".tokens";
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::create_directories(path.parent_path(), ignored);
    return path;
}

bool seed_legacy_route_handle_path_for_test(QuicCore &core, QuicRouteHandle route_handle,
                                            QuicPathId path_id) {
    auto *entry = core.ensure_legacy_entry();
    if (entry == nullptr) {
        return false;
    }

    if (!entry->default_route_handle.has_value()) {
        entry->default_route_handle = route_handle;
    }

    const auto existing_by_handle = entry->path_id_by_route_handle.find(route_handle);
    if (existing_by_handle != entry->path_id_by_route_handle.end() &&
        existing_by_handle->second == path_id) {
        return true;
    }

    if (path_id == std::numeric_limits<QuicPathId>::max()) {
        return false;
    }

    if (existing_by_handle != entry->path_id_by_route_handle.end()) {
        entry->route_handle_by_path_id.erase(existing_by_handle->second);
    }

    const auto existing_by_path = entry->route_handle_by_path_id.find(path_id);
    if (existing_by_path != entry->route_handle_by_path_id.end() &&
        existing_by_path->second != route_handle) {
        const auto displaced_route_handle = existing_by_path->second;
        entry->path_id_by_route_handle.erase(displaced_route_handle);
        if (entry->default_route_handle == displaced_route_handle) {
            entry->default_route_handle = route_handle;
        }
    }

    entry->path_id_by_route_handle[route_handle] = path_id;
    entry->route_handle_by_path_id[path_id] = route_handle;
    entry->next_path_id = std::max(entry->next_path_id, static_cast<QuicPathId>(path_id + 1));
    return true;
}

// NOLINTBEGIN(clang-analyzer-cplusplus.NewDeleteLeaks)
QuicCore::ConnectionEntry make_server_connection_entry(
    QuicConnectionHandle handle,
    std::optional<std::string> initial_destination_connection_id_key = std::nullopt) {
    return QuicCore::ConnectionEntry{
        .handle = handle,
        .connection =
            std::make_unique<QuicConnection>(coquic::quic::test::make_server_core_config()),
        .initial_destination_connection_id_key = std::move(initial_destination_connection_id_key),
    };
}
// NOLINTEND(clang-analyzer-cplusplus.NewDeleteLeaks)

std::vector<ProtectedPacket> decode_endpoint_initial_datagram(std::span<const std::byte> datagram,
                                                              const ConnectionId &client_dcid) {
    auto decoded = deserialize_protected_datagram(
        datagram, DeserializeProtectionContext{
                      .peer_role = EndpointRole::server,
                      .client_initial_destination_connection_id = client_dcid,
                  });
    EXPECT_TRUE(decoded.has_value());
    if (!decoded.has_value()) {
        return {};
    }
    return decoded.value();
}

TEST(QuicCoreEndpointInternalTest, LegacyViewAndLegacyEntryHelpersHandleNullAndMissingCases) {
    QuicCore::LegacyConnectionView detached;
    EXPECT_EQ(detached.get(), nullptr);
    EXPECT_FALSE(static_cast<bool>(detached));
    EXPECT_TRUE(detached == nullptr);
    EXPECT_FALSE(detached != nullptr);

    QuicCore endpoint_core(make_client_endpoint_config());
    EXPECT_EQ(endpoint_core.ensure_legacy_entry(), nullptr);
    endpoint_core.set_legacy_connection(nullptr);
    ASSERT_TRUE(endpoint_core.legacy_connection_handle_.has_value());
    EXPECT_TRUE(endpoint_core.connections_.empty());

    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    if (!legacy_core.legacy_connection_handle_.has_value()) {
        FAIL() << "expected legacy connection handle";
        return;
    }
    auto legacy_handle = *legacy_core.legacy_connection_handle_;
    legacy_core.connections_.erase(legacy_handle);

    const QuicCore &const_core = legacy_core;
    EXPECT_EQ(legacy_core.legacy_entry(), nullptr);
    EXPECT_EQ(const_core.legacy_entry(), nullptr);
    EXPECT_EQ(legacy_core.connection_.get(), nullptr);
    EXPECT_FALSE(static_cast<bool>(legacy_core.connection_));
    EXPECT_TRUE(legacy_core.connection_ == nullptr);
    EXPECT_FALSE(legacy_core.connection_ != nullptr);
}

TEST(QuicCoreEndpointInternalTest, ReceiveStreamDataPayloadPrefersSharedBytes) {
    QuicCoreReceiveStreamData owned{
        .bytes = bytes_from_ints({0x01, 0x02}),
    };
    EXPECT_EQ(owned.byte_count(), 2u);
    EXPECT_EQ(std::vector<std::byte>(owned.payload().begin(), owned.payload().end()),
              bytes_from_ints({0x01, 0x02}));

    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_ints({0xaa, 0xbb, 0xcc}));
    QuicCoreReceiveStreamData shared{
        .bytes = bytes_from_ints({0x01}),
        .shared_bytes = SharedBytes(storage, 1, 3),
    };
    EXPECT_EQ(shared.byte_count(), 2u);
    EXPECT_EQ(shared.payload().data(), storage->data() + 1);
    EXPECT_EQ(std::vector<std::byte>(shared.payload().begin(), shared.payload().end()),
              bytes_from_ints({0xbb, 0xcc}));
}

TEST(QuicCoreEndpointInternalTest, InboundDatagramMaterializeClampsSharedPayload) {
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_ints({0xaa, 0xbb, 0xcc}));
    QuicCoreInboundDatagram shared{
        .bytes = bytes_from_ints({0x01}),
        .shared_bytes = storage,
        .begin = 1,
        .end = 99,
    };
    EXPECT_EQ(shared.materialize(), bytes_from_ints({0xbb, 0xcc}));

    shared.shared_bytes.reset();
    EXPECT_EQ(shared.materialize(), bytes_from_ints({0x01}));
}

TEST(QuicCoreEndpointInternalTest, ParseEndpointDatagramRejectsMalformedInputs) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # Endpoints MUST discard packets that are too small to be valid QUIC
    // # packets.
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(std::span<const std::byte>{}).has_value());

    auto invalid_short_header = bytes_from_ints({0x00});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(invalid_short_header).has_value());

    auto too_short_short_header = bytes_from_ints({0x40, 0, 1, 2});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # Endpoints MUST discard packets that are too small to be valid QUIC
    // # packets.
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(too_short_short_header).has_value());

    auto version_negotiation = bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x00});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.1
    // # An endpoint MUST NOT send a Version Negotiation packet
    // # in response to receiving a Version Negotiation packet.
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(version_negotiation).has_value());

    auto truncated_destination_connection_id = bytes_from_ints(
        {0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10});
    EXPECT_FALSE(
        QuicCore::parse_endpoint_datagram(truncated_destination_connection_id).has_value());

    auto truncated_source_connection_id =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x08, 0xbb});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(truncated_source_connection_id).has_value());

    auto truncated_initial_token_varint =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x01, 0xbb, 0x40});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(truncated_initial_token_varint).has_value());

    auto initial_token_length_exceeds_remaining =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x01, 0xbb, 0x05});
    EXPECT_FALSE(
        QuicCore::parse_endpoint_datagram(initial_token_length_exceeds_remaining).has_value());
}

TEST(QuicCoreEndpointInternalTest, ParseEndpointDatagramAcceptsGreasedQuicBitWhenEnabled) {
    auto greased_short_header =
        bytes_from_ints({0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(greased_short_header).has_value());
    auto short_header =
        QuicCore::parse_endpoint_datagram(greased_short_header, /*accept_greased_quic_bit=*/true);
    ASSERT_TRUE(short_header.has_value());
    auto &short_header_value = optional_ref_or_terminate(short_header);
    EXPECT_EQ(short_header_value.kind, QuicCore::ParsedEndpointDatagram::Kind::short_header);

    auto greased_initial =
        bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x01, 0xbb, 0x00});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(greased_initial).has_value());
    auto initial =
        QuicCore::parse_endpoint_datagram(greased_initial, /*accept_greased_quic_bit=*/true);
    ASSERT_TRUE(initial.has_value());
    auto &initial_value = optional_ref_or_terminate(initial);
    EXPECT_EQ(initial_value.kind, QuicCore::ParsedEndpointDatagram::Kind::supported_initial);
    EXPECT_EQ(initial_value.destination_connection_id, bytes_from_ints({0xaa}));
    ASSERT_TRUE(initial_value.source_connection_id.has_value());
    EXPECT_EQ(optional_ref_or_terminate(initial_value.source_connection_id),
              bytes_from_ints({0xbb}));
}

TEST(QuicCoreEndpointInternalTest, RetryContextAndPacketBuildersRejectMissingOrMismatchedInputs) {
    QuicCore core(make_server_endpoint_config());

    QuicCore::PendingRetryToken pending{
        .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x44}},
        .retry_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        .original_version = kQuicVersion1,
        .token = bytes_from_ints({0x72, 0x74, 0x72, 0x79}),
        .route_handle = 7,
    };
    core.retry_tokens_.insert_or_assign(QuicCore::connection_id_key(pending.token), pending);

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = pending.retry_source_connection_id,
        .source_connection_id = ConnectionId{std::byte{0xc1}, std::byte{0x01}},
        .version = pending.original_version,
        .token = pending.token,
    };

    EXPECT_FALSE(core.take_retry_context(parsed, 9, coquic::quic::test::test_time(0),
                                         std::span<const std::byte>{})
                     .has_value());
    EXPECT_TRUE(core.retry_tokens_.contains(QuicCore::connection_id_key(pending.token)));

    auto no_source = parsed;
    no_source.source_connection_id.reset();
    constexpr std::array<std::uint32_t, 1> supported_versions = {kQuicVersion1};
    EXPECT_TRUE(
        QuicCore::make_version_negotiation_packet_bytes(no_source, supported_versions).empty());
    EXPECT_TRUE(QuicCore::make_retry_packet_bytes(no_source, pending).empty());

    constexpr std::array<std::uint32_t, 0> no_supported_versions = {};
    EXPECT_TRUE(
        QuicCore::make_version_negotiation_packet_bytes(parsed, no_supported_versions).empty());

    auto unsupported_retry = parsed;
    unsupported_retry.version = kVersionNegotiationVersion;
    EXPECT_TRUE(QuicCore::make_retry_packet_bytes(unsupported_retry, pending).empty());

    auto same_retry_source = pending;
    same_retry_source.retry_source_connection_id = parsed.destination_connection_id;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    // # This value MUST NOT be equal to the Destination
    // # Connection ID field of the packet sent by the client.
    EXPECT_TRUE(QuicCore::make_retry_packet_bytes(parsed, same_retry_source).empty());
}

TEST(QuicCoreEndpointInternalTest, VersionNegotiationCanGreaseReservedVersion) {
    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::unsupported_version_long_header,
        .destination_connection_id = bytes_from_ints({0x83, 0x44}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion2,
    };
    constexpr std::array<std::uint32_t, 1> supported_versions = {kQuicVersion1};

    auto bytes = QuicCore::make_version_negotiation_packet_bytes(parsed, supported_versions, true);
    ASSERT_FALSE(bytes.empty());

    auto decoded = deserialize_packet(bytes, {});
    ASSERT_TRUE(decoded.has_value());
    auto *version_negotiation = std::get_if<VersionNegotiationPacket>(&decoded.value().packet);
    ASSERT_NE(version_negotiation, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # The server MUST include the value from the Source Connection ID field
    // # of the packet it receives in the Destination Connection ID field.
    EXPECT_EQ(version_negotiation->destination_connection_id, parsed.source_connection_id);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # The value for Source Connection ID MUST be copied from the
    // # Destination Connection ID of the received packet, which is initially
    // # randomly selected by a client.
    EXPECT_EQ(version_negotiation->source_connection_id, parsed.destination_connection_id);
    EXPECT_EQ(version_negotiation->supported_versions,
              (std::vector<std::uint32_t>{kQuicVersion1, 0x0a0a0a0a}));

    constexpr std::array<std::uint32_t, 2> already_greased = {kQuicVersion1, 0x1a2a3a4a};
    auto already_greased_bytes =
        QuicCore::make_version_negotiation_packet_bytes(parsed, already_greased, true);
    ASSERT_FALSE(already_greased_bytes.empty());
    auto already_greased_decoded = deserialize_packet(already_greased_bytes, {});
    ASSERT_TRUE(already_greased_decoded.has_value());
    auto *already_greased_vn =
        std::get_if<VersionNegotiationPacket>(&already_greased_decoded.value().packet);
    ASSERT_NE(already_greased_vn, nullptr);
    EXPECT_EQ(already_greased_vn->supported_versions,
              (std::vector<std::uint32_t>{kQuicVersion1, 0x1a2a3a4a}));
}

TEST(QuicCoreEndpointInternalTest, ReservedVersionProbePacketUsesReservedVersionPattern) {
    auto open = make_client_open_config();

    auto bytes = QuicCore::make_reserved_version_probe_packet_bytes(open);

    ASSERT_EQ(bytes.size(), 7u + open.initial_destination_connection_id.size() +
                                open.source_connection_id.size());
    EXPECT_EQ(bytes[0], std::byte{0xc0});
    EXPECT_EQ(bytes[1], std::byte{0x0a});
    EXPECT_EQ(bytes[2], std::byte{0x0a});
    EXPECT_EQ(bytes[3], std::byte{0x0a});
    EXPECT_EQ(bytes[4], std::byte{0x0a});
    EXPECT_EQ(bytes[5], static_cast<std::byte>(open.initial_destination_connection_id.size()));
    EXPECT_TRUE(std::equal(open.initial_destination_connection_id.begin(),
                           open.initial_destination_connection_id.end(), bytes.begin() + 6));
    const auto source_length_offset = 6 + open.initial_destination_connection_id.size();
    EXPECT_EQ(bytes[source_length_offset],
              static_cast<std::byte>(open.source_connection_id.size()));
    EXPECT_TRUE(std::equal(open.source_connection_id.begin(), open.source_connection_id.end(),
                           bytes.begin() + static_cast<std::ptrdiff_t>(source_length_offset + 1)));
    EXPECT_LT(bytes.size(), 1200u);
}

TEST(QuicCoreEndpointInternalTest, ReservedVersionProbeIsDisabledByDefaultOnClientOpen) {
    QuicCore client(make_client_endpoint_config());

    auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));

    const auto sends = send_effects_from(opened);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends.front().connection, 1u);
    auto diagnostics = client.connection_diagnostics();
    ASSERT_EQ(diagnostics.size(), 1u);
    EXPECT_EQ(diagnostics.front().initial_space.next_send_packet_number, 1u);
    EXPECT_GT(diagnostics.front().initial_space.outstanding_packets, 0u);
    EXPECT_GT(diagnostics.front().recovery.bytes_in_flight, 0u);
}

TEST(QuicCoreEndpointInternalTest, ReservedVersionProbeOptInSendsUntrackedStartupDatagram) {
    auto config = make_client_endpoint_config();
    config.enable_reserved_version_probe = true;
    QuicCore client(std::move(config));
    auto open = make_client_open_config();
    auto expected_probe = QuicCore::make_reserved_version_probe_packet_bytes(open);

    auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = open,
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));

    const auto sends = send_effects_from(opened);
    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends.front().connection, 1u);
    EXPECT_EQ(sends.back().connection, 0u);
    EXPECT_EQ(sends.back().route_handle, std::optional<QuicRouteHandle>{17});
    EXPECT_EQ(sends.back().ecn, QuicEcnCodepoint::not_ect);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.3
    // # Endpoints MAY send packets with a reserved version to test that a
    // # peer correctly discards the packet.
    EXPECT_EQ(sends.back().bytes.to_vector(), expected_probe);

    auto diagnostics = client.connection_diagnostics();
    ASSERT_EQ(diagnostics.size(), 1u);
    EXPECT_EQ(diagnostics.front().initial_space.next_send_packet_number, 1u);
    EXPECT_GT(diagnostics.front().initial_space.outstanding_packets, 0u);
    EXPECT_GT(diagnostics.front().recovery.bytes_in_flight, 0u);
}

TEST(QuicCoreEndpointInternalTest, ServerDropsSmallReservedVersionProbeWithoutNegotiation) {
    QuicCore server(make_server_endpoint_config());
    auto probe = QuicCore::make_reserved_version_probe_packet_bytes(make_client_open_config());

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = std::move(probe),
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # Servers MUST drop smaller packets that specify unsupported versions.
    EXPECT_TRUE(result.effects.empty());
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, ClientEndpointRestartsHandshakeAfterValidVersionNegotiation) {
    auto endpoint_config = make_client_endpoint_config();
    endpoint_config.supported_versions = {kQuicVersion2, kQuicVersion1};
    QuicCore client(std::move(endpoint_config));

    auto open_config = make_client_open_config();
    open_config.original_version = kQuicVersion1;
    open_config.initial_version = kQuicVersion1;
    auto start = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = open_config,
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));
    ASSERT_FALSE(send_effects_from(start).empty());

    const auto version_negotiation = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = open_config.source_connection_id,
        .source_connection_id = open_config.initial_destination_connection_id,
        .supported_versions = {kQuicVersion2},
    });
    ASSERT_TRUE(version_negotiation.has_value());

    auto after_version_negotiation = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = version_negotiation.value(),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(1));

    const auto restart_sends = send_effects_from(after_version_negotiation);
    ASSERT_FALSE(restart_sends.empty());
    //= https://www.rfc-editor.org/rfc/rfc9368#section-2.1
    // # Otherwise, it SHALL select a mutually supported version and send a
    // # new first flight with that version -- this version is now the
    // # Negotiated Version.
    EXPECT_EQ(read_u32_be_at(restart_sends.front().bytes, 1), kQuicVersion2);
    ASSERT_EQ(client.connections_.size(), 1u);
    const auto &entry = client.connections_.begin()->second;
    ASSERT_NE(entry.connection, nullptr);
    EXPECT_EQ(entry.connection->config_.initial_version, kQuicVersion2);
    EXPECT_TRUE(entry.connection->config_.reacted_to_version_negotiation);
    EXPECT_EQ(entry.default_route_handle, std::optional<QuicRouteHandle>{17});
    EXPECT_EQ(entry.route_handle_by_path_id.at(0), 17u);
}

TEST(QuicCoreEndpointInternalTest, ClientEndpointIgnoresInvalidOrRepeatedVersionNegotiation) {
    auto endpoint_config = make_client_endpoint_config();
    endpoint_config.supported_versions = {kQuicVersion2, kQuicVersion1};
    QuicCore client(std::move(endpoint_config));

    auto open_config = make_client_open_config();
    open_config.original_version = kQuicVersion1;
    open_config.initial_version = kQuicVersion1;
    auto start = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = open_config,
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));
    ASSERT_FALSE(send_effects_from(start).empty());

    const auto echoes_original = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = open_config.source_connection_id,
        .source_connection_id = open_config.initial_destination_connection_id,
        .supported_versions = {kQuicVersion1, kQuicVersion2},
    });
    ASSERT_TRUE(echoes_original.has_value());
    auto ignored = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = echoes_original.value(),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(1));
    //= https://www.rfc-editor.org/rfc/rfc9368#section-4
    // # Clients MUST ignore any received Version Negotiation packets that
    // # contain the Original Version.
    EXPECT_TRUE(send_effects_from(ignored).empty());

    const auto valid = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = open_config.source_connection_id,
        .source_connection_id = open_config.initial_destination_connection_id,
        .supported_versions = {kQuicVersion2},
    });
    ASSERT_TRUE(valid.has_value());
    auto restarted = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = valid.value(),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(2));
    ASSERT_FALSE(send_effects_from(restarted).empty());

    const auto repeated = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = open_config.source_connection_id,
        .source_connection_id = open_config.initial_destination_connection_id,
        .supported_versions = {kQuicVersion1},
    });
    ASSERT_TRUE(repeated.has_value());
    auto second = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = repeated.value(),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(3));
    //= https://www.rfc-editor.org/rfc/rfc9368#section-4
    // # A client that makes a connection
    // # attempt based on information received from a Version Negotiation
    // # packet MUST ignore any Version Negotiation packets it receives in
    // # response to that connection attempt.
    EXPECT_TRUE(send_effects_from(second).empty());

    ASSERT_EQ(client.connections_.size(), 1u);
    const auto &entry = client.connections_.begin()->second;
    ASSERT_NE(entry.connection, nullptr);
    EXPECT_EQ(entry.connection->config_.initial_version, kQuicVersion2);
    EXPECT_TRUE(entry.connection->config_.reacted_to_version_negotiation);
}

TEST(QuicCoreEndpointInternalTest, ClientEndpointIgnoresVersionNegotiationAfterPeerPacket) {
    auto endpoint_config = make_client_endpoint_config();
    endpoint_config.supported_versions = {kQuicVersion2, kQuicVersion1};
    QuicCore client(std::move(endpoint_config));

    auto open_config = make_client_open_config();
    open_config.original_version = kQuicVersion1;
    open_config.initial_version = kQuicVersion1;
    auto start = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = open_config,
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));
    ASSERT_FALSE(send_effects_from(start).empty());
    ASSERT_EQ(client.connections_.size(), 1u);
    auto &entry = client.connections_.begin()->second;
    ASSERT_NE(entry.connection, nullptr);
    entry.connection->processed_peer_packet_ = true;

    const auto version_negotiation = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = open_config.source_connection_id,
        .source_connection_id = open_config.initial_destination_connection_id,
        .supported_versions = {kQuicVersion2},
    });
    ASSERT_TRUE(version_negotiation.has_value());

    auto after_version_negotiation = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = version_negotiation.value(),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
    // # A client MUST discard any Version Negotiation packet if it has
    // # received and successfully processed any other packet, including an
    // # earlier Version Negotiation packet.
    EXPECT_TRUE(send_effects_from(after_version_negotiation).empty());
    ASSERT_EQ(client.connections_.size(), 1u);
    EXPECT_EQ(entry.connection->config_.initial_version, kQuicVersion1);
    EXPECT_FALSE(entry.connection->config_.reacted_to_version_negotiation);
}

TEST(QuicCoreEndpointInternalTest, RouteRefreshRememberPathAndLegacySeedingCoverCollisionPaths) {
    QuicCore server_core(make_server_endpoint_config());

    auto route_entry = make_server_connection_entry(9);
    route_entry.connection->local_connection_ids_.clear();
    route_entry.connection->local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                                                 .sequence_number = 0,
                                                                 .connection_id = {},
                                                                 .retired = false,
                                                             });
    route_entry.connection->local_connection_ids_.emplace(
        1, LocalConnectionIdRecord{
               .sequence_number = 1,
               .connection_id = ConnectionId{std::byte{0x44}},
               .retired = false,
           });
    route_entry.active_connection_id_keys = {"stale"};
    server_core.connection_id_routes_.emplace("stale", route_entry.handle);
    route_entry.initial_destination_connection_id_key = "old";
    server_core.initial_destination_routes_.emplace("old", route_entry.handle);
    route_entry.connection->client_initial_destination_connection_id_.reset();

    server_core.refresh_server_connection_routes(route_entry);
    route_entry.connection.reset();

    auto live_key = QuicCore::connection_id_key(ConnectionId{std::byte{0x44}});
    EXPECT_FALSE(server_core.connection_id_routes_.contains("stale"));
    EXPECT_EQ(server_core.connection_id_routes_.at(live_key), route_entry.handle);
    EXPECT_EQ(route_entry.active_connection_id_keys.size(), 1u);
    EXPECT_EQ(route_entry.active_connection_id_keys.front(), live_key);
    EXPECT_FALSE(route_entry.initial_destination_connection_id_key.has_value());
    EXPECT_FALSE(server_core.initial_destination_routes_.contains("old"));

    QuicCore::ConnectionEntry path_entry{};
    path_entry.route_handle_by_path_id.emplace(0, 11);
    path_entry.path_id_by_route_handle.emplace(11, 0);
    path_entry.route_handle_by_path_id.emplace(1, 12);
    path_entry.path_id_by_route_handle.emplace(12, 1);
    path_entry.next_path_id = 1;
    EXPECT_EQ(server_core.remember_inbound_path(path_entry, 13, std::span<const std::byte>{}), 2u);

    QuicCore endpoint_core(make_client_endpoint_config());
    EXPECT_FALSE(seed_legacy_route_handle_path_for_test(endpoint_core, 7, 0));

    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    EXPECT_FALSE(seed_legacy_route_handle_path_for_test(legacy_core, 1,
                                                        std::numeric_limits<QuicPathId>::max()));
    ASSERT_TRUE(seed_legacy_route_handle_path_for_test(legacy_core, 11, 1));
    ASSERT_TRUE(seed_legacy_route_handle_path_for_test(legacy_core, 22, 2));

    auto *legacy_entry = legacy_core.ensure_legacy_entry();
    ASSERT_NE(legacy_entry, nullptr);
    legacy_entry->default_route_handle = 22;
    ASSERT_TRUE(seed_legacy_route_handle_path_for_test(legacy_core, 11, 2));
    EXPECT_FALSE(legacy_entry->path_id_by_route_handle.contains(22));
    EXPECT_FALSE(legacy_entry->route_handle_by_path_id.contains(1));
    EXPECT_EQ(legacy_entry->default_route_handle, std::optional<QuicRouteHandle>{11u});
    EXPECT_EQ(legacy_entry->path_id_by_route_handle.at(11), 2u);
    EXPECT_EQ(legacy_entry->route_handle_by_path_id.at(2), 11u);
}

TEST(QuicCoreEndpointInternalTest, ClientEndpointRoutesShortHeaderByFullLocalConnectionId) {
    QuicCore endpoint(make_client_endpoint_config());
    auto open_config = make_client_open_config();
    open_config.source_connection_id =
        bytes_from_ints({0xc1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});

    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = open_config,
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    ASSERT_EQ(endpoint.connection_count(), 1u);
    auto parsed = QuicCore::parse_endpoint_datagram(
        bytes_from_ints({0x40, 0xc1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff}));
    if (!parsed.has_value()) {
        FAIL() << "expected short-header endpoint datagram to parse";
        return;
    }
    EXPECT_EQ(endpoint.find_endpoint_connection_for_datagram(parsed.value()),
              std::optional<QuicConnectionHandle>{1u});

    auto routed_malformed = endpoint.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0xc1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff}),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(1));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11
    // # A stateless reset MUST NOT be used by an endpoint that has the state
    // # necessary to send a frame on the connection.
    EXPECT_TRUE(send_effects_from(routed_malformed).empty());
}

TEST(QuicCoreEndpointInternalTest, RetryAcceptedServerRoutesOriginalDestinationCidAlias) {
    QuicCore endpoint(make_server_endpoint_config());

    auto config = coquic::quic::test::make_server_core_config();
    config.source_connection_id = bytes_from_ints({0x53, 0x28, 0xab, 0x16, 0x7a, 0x22, 0xb1, 0xc2});
    config.initial_destination_connection_id = config.source_connection_id;
    config.original_destination_connection_id =
        bytes_from_ints({0xe1, 0xbb, 0x00, 0x5c, 0x56, 0xd0, 0x0c, 0x3f});
    config.retry_source_connection_id = config.source_connection_id;

    auto entry = QuicCore::ConnectionEntry{
        .handle = 7,
        .connection = std::make_unique<QuicConnection>(std::move(config)),
    };
    endpoint.refresh_server_connection_routes(entry);
    endpoint.connections_.emplace(entry.handle, std::move(entry));

    auto original_destination_short_header = QuicCore::parse_endpoint_datagram(
        bytes_from_ints({0x40, 0xe1, 0xbb, 0x00, 0x5c, 0x56, 0xd0, 0x0c, 0x3f, 0xff}));
    ASSERT_TRUE(original_destination_short_header.has_value());
    EXPECT_EQ(endpoint.find_endpoint_connection_for_datagram(
                  optional_ref_or_terminate(original_destination_short_header)),
              std::optional<QuicConnectionHandle>{7u});

    auto retry_source_short_header = QuicCore::parse_endpoint_datagram(
        bytes_from_ints({0x40, 0x53, 0x28, 0xab, 0x16, 0x7a, 0x22, 0xb1, 0xc2, 0xff}));
    ASSERT_TRUE(retry_source_short_header.has_value());
    EXPECT_EQ(endpoint.find_endpoint_connection_for_datagram(
                  optional_ref_or_terminate(retry_source_short_header)),
              std::optional<QuicConnectionHandle>{7u});
}

TEST(QuicCoreEndpointInternalTest, ConnectionCommandDrainsPendingEndpointEffects) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
        .stream_id = 9,
        .application_error_code = 21,
        .final_size = 34,
    });
    entry.connection->pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
        .stream_id = 11,
        .application_error_code = 22,
    });
    entry.connection->pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
        .preferred_address = make_test_preferred_address(),
    };
    entry.connection->pending_zero_rtt_status_event_ = QuicCoreZeroRttStatusEvent{
        .status = QuicZeroRttStatus::accepted,
    };

    auto result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input = QuicCoreRequestKeyUpdate{},
        },
        coquic::quic::test::test_time(1));

    bool saw_reset = false;
    bool saw_stop = false;
    bool saw_preferred = false;
    bool saw_zero_rtt = false;
    for (auto &effect : result.effects) {
        if (auto *reset_stream = std::get_if<QuicCorePeerResetStream>(&effect)) {
            saw_reset = true;
            EXPECT_EQ(reset_stream->connection, 1u);
            EXPECT_EQ(reset_stream->stream_id, 9u);
            EXPECT_EQ(reset_stream->application_error_code, 21u);
            EXPECT_EQ(reset_stream->final_size, 34u);
            continue;
        }
        if (auto *stop = std::get_if<QuicCorePeerStopSending>(&effect)) {
            saw_stop = true;
            EXPECT_EQ(stop->connection, 1u);
            EXPECT_EQ(stop->stream_id, 11u);
            EXPECT_EQ(stop->application_error_code, 22u);
            continue;
        }
        if (auto *preferred = std::get_if<QuicCorePeerPreferredAddressAvailable>(&effect)) {
            saw_preferred = true;
            EXPECT_EQ(preferred->connection, 1u);
            EXPECT_EQ(preferred->preferred_address.connection_id,
                      make_test_preferred_address().connection_id);
            continue;
        }
        if (auto *status = std::get_if<QuicCoreZeroRttStatusEvent>(&effect)) {
            saw_zero_rtt = true;
            EXPECT_EQ(status->connection, 1u);
            EXPECT_EQ(status->status, QuicZeroRttStatus::accepted);
        }
    }

    EXPECT_TRUE(saw_reset);
    EXPECT_TRUE(saw_stop);
    EXPECT_TRUE(saw_preferred);
    EXPECT_TRUE(saw_zero_rtt);
}

TEST(QuicCoreEndpointInternalTest, InboundDatagramCanDeferSendDrainUntilReceiveEffects) {
    auto config = make_client_endpoint_config();
    config.defer_inbound_application_send_drain = true;
    QuicCore endpoint(std::move(config));
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    const ConnectionId endpoint_cid = bytes_from_ints({0xc1, 0x01, 0, 0, 0, 0, 0, 0x01});
    entry.connection->config_.source_connection_id = endpoint_cid;
    entry.connection->local_connection_ids_[0].connection_id = endpoint_cid;
    entry.connection->note_endpoint_route_state_changed();
    entry.default_route_handle = 17;
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    endpoint.refresh_server_connection_routes(entry);

    const auto peer_datagram = serialize_protected_datagram(
        std::array<ProtectedPacket, 1>{
            ProtectedOneRttPacket{
                .destination_connection_id = entry.connection->config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 1,
                .frames =
                    {
                        StreamFrame{
                            .fin = true,
                            .has_offset = false,
                            .has_length = true,
                            .stream_id = 1,
                            .stream_data = bytes_from_ints({0x6f, 0x6b}),
                        },
                    },
            },
        },
        SerializeProtectionContext{
            .local_role = EndpointRole::server,
            .client_initial_destination_connection_id =
                entry.connection->client_initial_destination_connection_id(),
            .one_rtt_secret = entry.connection->application_space_.read_secret,
            .one_rtt_key_phase = entry.connection->application_read_key_phase_,
        });
    ASSERT_TRUE(peer_datagram.has_value());

    auto inbound = endpoint.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = peer_datagram.value(),
            .route_handle = 17,
            .ecn = QuicEcnCodepoint::ce,
        },
        coquic::quic::test::test_time(2));

    EXPECT_TRUE(send_effects_from(inbound).empty());
    auto received = received_stream_data_from(inbound);
    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received.front().connection, 1u);
    EXPECT_EQ(received.front().stream_id, 1u);
    EXPECT_EQ(received.front().bytes, bytes_from_ints({0x6f, 0x6b}));

    auto response = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = 1,
                    .bytes = bytes_from_ints({0x72}),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(2));
    EXPECT_FALSE(send_effects_from(response).empty());
}

TEST(QuicCoreEndpointInternalTest, RecentAddressCacheReusesValidatedServerPathOnMigration) {
    QuicCore endpoint(make_server_endpoint_config());
    QuicCore::ConnectionEntry entry{.handle = 1, .default_route_handle = 17};
    entry.connection = std::make_unique<QuicConnection>(make_connected_server_connection());
    const ConnectionId endpoint_cid = bytes_from_ints({0x53, 0x01, 0, 0, 0, 0, 0, 1});
    entry.connection->config_.source_connection_id = endpoint_cid;
    entry.connection->local_connection_ids_[0].connection_id = endpoint_cid;
    entry.connection->note_endpoint_route_state_changed();
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    entry.address_validation_identity_by_path_id.emplace(0, bytes_from_string("addr-a"));
    entry.connection->peer_connection_ids_[0] = PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa}),
    };
    entry.connection->peer_connection_ids_[1] = PeerConnectionIdRecord{
        .sequence_number = 1,
        .connection_id = bytes_from_ints({0xab}),
    };
    entry.connection->ensure_path_state(0).peer_connection_id_sequence = 0;
    auto [entry_it, inserted] = endpoint.connections_.emplace(1, std::move(entry));
    ASSERT_TRUE(inserted);
    endpoint.refresh_server_connection_routes(entry_it->second);
    const auto client_initial_destination_connection_id =
        entry_it->second.connection->client_initial_destination_connection_id();
    const auto one_rtt_secret = entry_it->second.connection->application_space_.read_secret;
    const auto one_rtt_key_phase = entry_it->second.connection->application_read_key_phase_;

    const auto make_inbound = [&](std::uint64_t packet_number) {
        return serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedOneRttPacket{
                    .destination_connection_id = endpoint_cid,
                    .packet_number_length = 1,
                    .packet_number = packet_number,
                    .frames =
                        {
                            StreamFrame{
                                .fin = false,
                                .has_offset = true,
                                .has_length = true,
                                .stream_id = 0,
                                .offset = packet_number - 1,
                                .stream_data = bytes_from_ints(
                                    {static_cast<std::uint8_t>(0x60u + packet_number)}),
                            },
                        },
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::client,
                .client_initial_destination_connection_id =
                    client_initial_destination_connection_id,
                .one_rtt_secret = one_rtt_secret,
                .one_rtt_key_phase = one_rtt_key_phase,
            });
    };

    auto first = make_inbound(1);
    ASSERT_TRUE(first.has_value());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = std::move(first.value()),
            .route_handle = 17,
            .address_validation_identity = bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(1)));
    EXPECT_EQ(endpoint.connections_.at(1).recent_validated_peer_addresses.size(), 1u);

    auto migrated = make_inbound(2);
    ASSERT_TRUE(migrated.has_value());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = std::move(migrated.value()),
            .route_handle = 18,
            .address_validation_identity = bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(2)));

    const auto &connection = *endpoint.connections_.at(1).connection;
    ASSERT_EQ(connection.current_send_path_id_, 1u);
    ASSERT_TRUE(connection.paths_.at(1).validated);
    EXPECT_EQ(connection.paths_.at(1).peer_connection_id_sequence, 1u);
    EXPECT_TRUE(connection.paths_.at(0).outstanding_challenge.has_value());
    EXPECT_FALSE(connection.anti_amplification_applies(1));
    EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::nullopt);
}

TEST(QuicCoreEndpointInternalTest, EndpointDiagnosticsSkipNullEntriesAndTrackContinuations) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    endpoint.connections_.emplace(404,
                                  QuicCore::ConnectionEntry{
                                      .handle = 404,
                                      .send_continuation_wakeup = coquic::quic::test::test_time(3),
                                  });

    EXPECT_FALSE(endpoint.has_send_continuation_pending());

    entry.send_continuation_wakeup = coquic::quic::test::test_time(2);
    EXPECT_TRUE(endpoint.has_send_continuation_pending());
    auto next_wakeup = endpoint.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    EXPECT_EQ(optional_value_or_terminate(next_wakeup), coquic::quic::test::test_time(2));

    auto diagnostics = endpoint.connection_diagnostics();
    ASSERT_EQ(diagnostics.size(), 1u);
    EXPECT_EQ(diagnostics.front().handle, 1u);
    EXPECT_TRUE(diagnostics.front().started);
}

TEST(QuicCoreEndpointInternalTest, EndpointPacketInspectionEffectsCarryConnectionHandle) {
    auto config = make_client_endpoint_config();
    config.enable_packet_inspection = true;
    QuicCore endpoint(std::move(config));
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->config_.enable_packet_inspection = true;

    auto result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_ints({0x68, 0x69}),
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(send_effects_from(result).empty());
    bool saw_inspection = false;
    for (auto &effect : result.effects) {
        auto *inspection = std::get_if<QuicCorePacketInspection>(&effect);
        if (inspection == nullptr) {
            continue;
        }
        saw_inspection = true;
        EXPECT_EQ(inspection->connection, 1u);
        EXPECT_EQ(inspection->direction, QuicCorePacketInspectionDirection::outbound);
        EXPECT_EQ(inspection->packet_type, QuicCorePacketInspectionPacketType::one_rtt);
        EXPECT_FALSE(inspection->encrypted_packet.empty());
        EXPECT_FALSE(inspection->frames.empty());
    }
    EXPECT_TRUE(saw_inspection);
}

TEST(QuicCoreEndpointInternalTest, EndpointDrainMarksContinuationAfterBatchCap) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->config_.max_outbound_datagram_size = 1200;
    entry.connection->congestion_controller_.congestion_window_ = 1u << 30u;
    entry.connection->congestion_controller_.bytes_in_flight_ = 0;
    entry.connection->connection_flow_control_.peer_max_data = 1u << 30u;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(entry.connection->peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = 1u << 30u;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = 1u << 30u;
    entry.connection->initialize_peer_flow_control_from_transport_parameters();

    auto result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = std::vector<std::byte>(400000, std::byte{0x51}),
                },
        },
        coquic::quic::test::test_time(1));

    EXPECT_FALSE(result.send_continuation_pending);
    ASSERT_TRUE(result.next_wakeup.has_value());
    EXPECT_GT(optional_value_or_terminate(result.next_wakeup), coquic::quic::test::test_time(1));
    EXPECT_EQ(send_effects_from(result).size(), 10u);
}

TEST(QuicCoreEndpointInternalTest, EndpointFlushesUnderfilledPacketAtCoalescingWakeup) {
    class SendSink final : public QuicCoreSendDatagramSink {
      public:
        bool on_send_datagram(QuicCoreSendDatagram datagram) override {
            datagrams.push_back(std::move(datagram));
            return true;
        }

        std::vector<QuicCoreSendDatagram> datagrams;
    } sink;
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->config_.transport.underfilled_packet_coalescing_delay =
        std::chrono::milliseconds{5};

    const auto first = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_string("ping"),
                },
        },
        coquic::quic::test::test_time(1), sink);

    EXPECT_TRUE(send_effects_from(first).empty());
    EXPECT_EQ(sink.datagrams.size(), 1u);

    const auto delayed = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_string("pong"),
                },
        },
        coquic::quic::test::test_time(2), sink);

    EXPECT_TRUE(send_effects_from(delayed).empty());
    EXPECT_EQ(sink.datagrams.size(), 1u);
    EXPECT_FALSE(delayed.send_continuation_pending);
    EXPECT_FALSE(endpoint.has_send_continuation_pending());
    ASSERT_TRUE(delayed.next_wakeup.has_value());
    EXPECT_EQ(optional_value_or_terminate(delayed.next_wakeup), coquic::quic::test::test_time(7));

    const auto flushed =
        endpoint.advance_endpoint(QuicCoreTimerExpired{}, coquic::quic::test::test_time(7), sink);
    EXPECT_TRUE(send_effects_from(flushed).empty());
    EXPECT_EQ(sink.datagrams.size(), 2u);
    EXPECT_EQ(flushed.next_wakeup, endpoint.next_wakeup());
}

TEST(QuicCoreEndpointInternalTest, EndpointSendContinuationResumesPacedBurst) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->config_.transport.pmtud_enabled = false;
    entry.connection->config_.max_outbound_datagram_size = 1200;
    entry.connection->congestion_controller_ = QuicCongestionController(
        QuicCongestionControlAlgorithm::bbr, entry.connection->config_.max_outbound_datagram_size);
    auto &bbr_controller =
        std::get<BbrCongestionController>(entry.connection->congestion_controller_.storage_);
    bbr_controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    bbr_controller.max_bandwidth_bytes_per_second_ = 120000000.0;
    bbr_controller.bandwidth_bytes_per_second_ = 120000000.0;
    bbr_controller.pacing_rate_bytes_per_second_ = 120000000.0;
    bbr_controller.min_rtt_ = std::chrono::milliseconds{1};
    bbr_controller.send_quantum_ = 400000;
    entry.connection->congestion_controller_.congestion_window_ = 1u << 30u;
    entry.connection->congestion_controller_.bytes_in_flight_ = 0;
    entry.connection->connection_flow_control_.peer_max_data = 1u << 30u;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(entry.connection->peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = 1u << 30u;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = 1u << 30u;
    entry.connection->initialize_peer_flow_control_from_transport_parameters();

    auto send_time = coquic::quic::test::test_time(1);
    auto first = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = std::vector<std::byte>(700000, std::byte{0x51}),
                },
        },
        send_time);

    EXPECT_TRUE(first.send_continuation_pending);
    EXPECT_TRUE(endpoint.has_send_continuation_pending());
    EXPECT_EQ(send_effects_from(first).size(), 256u);
    ASSERT_TRUE(first.next_wakeup.has_value());
    EXPECT_EQ(optional_value_or_terminate(first.next_wakeup), send_time);

    auto continued = endpoint.advance_endpoint(QuicCoreTimerExpired{}, send_time);

    EXPECT_FALSE(continued.local_error.has_value());
    EXPECT_FALSE(send_effects_from(continued).empty());
    EXPECT_TRUE(datagram_has_application_stream(*entry.connection,
                                                send_effects_from(continued).front().bytes));
}

TEST(QuicCoreEndpointInternalTest, LegacyDrainMarksContinuationAndCarriesPacketInspection) {
    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    *legacy_core.connection_ = make_connected_client_connection();
    legacy_core.connection_->config_.max_outbound_datagram_size = 1200;
    legacy_core.connection_->congestion_controller_.congestion_window_ = 1u << 30u;
    legacy_core.connection_->congestion_controller_.bytes_in_flight_ = 0;
    legacy_core.connection_->connection_flow_control_.peer_max_data = 1u << 30u;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(legacy_core.connection_->peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = 1u << 30u;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = 1u << 30u;
    legacy_core.connection_->initialize_peer_flow_control_from_transport_parameters();
    legacy_core.connection_->pending_packet_inspections_.push_back(QuicCorePacketInspection{
        .direction = QuicCorePacketInspectionDirection::outbound,
        .packet_type = QuicCorePacketInspectionPacketType::one_rtt,
        .datagram_id = 77,
        .packet_number = 9,
    });

    auto result = legacy_core.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = std::vector<std::byte>(400000, std::byte{0x52}),
        },
        coquic::quic::test::test_time(2));

    EXPECT_FALSE(result.send_continuation_pending);
    ASSERT_TRUE(result.next_wakeup.has_value());
    EXPECT_GT(optional_value_or_terminate(result.next_wakeup), coquic::quic::test::test_time(2));
    EXPECT_EQ(send_effects_from(result).size(), 10u);

    bool saw_inspection = false;
    for (auto &effect : result.effects) {
        auto *inspection = std::get_if<QuicCorePacketInspection>(&effect);
        if (inspection == nullptr) {
            continue;
        }
        saw_inspection = true;
        EXPECT_EQ(inspection->connection, 1u);
        EXPECT_EQ(inspection->direction, QuicCorePacketInspectionDirection::outbound);
        EXPECT_EQ(inspection->packet_type, QuicCorePacketInspectionPacketType::one_rtt);
        EXPECT_EQ(inspection->datagram_id, 77u);
        EXPECT_EQ(inspection->packet_number, 9u);
    }
    EXPECT_TRUE(saw_inspection);
}

TEST(QuicCoreEndpointInternalTest, EndpointPathMtuUpdateAppliesToMatchedRouteOnly) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 29,
        },
        coquic::quic::test::test_time(1)));

    auto &first = endpoint.connections_.at(1);
    auto &second = endpoint.connections_.at(2);
    *first.connection = make_connected_client_connection();
    *second.connection = make_connected_client_connection();
    const auto first_source_connection_id = bytes_from_ints({0xc1, 0x01});
    first.connection->config_.source_connection_id = first_source_connection_id;
    first.connection->local_connection_ids_.clear();
    first.connection->local_connection_ids_.emplace(0,
                                                    LocalConnectionIdRecord{
                                                        .sequence_number = 0,
                                                        .connection_id = first_source_connection_id,
                                                    });
    const auto second_source_connection_id = bytes_from_ints({0xc2, 0x02});
    second.connection->config_.source_connection_id = second_source_connection_id;
    second.connection->local_connection_ids_.clear();
    second.connection->local_connection_ids_.emplace(
        0, LocalConnectionIdRecord{
               .sequence_number = 0,
               .connection_id = second_source_connection_id,
           });
    first.endpoint_route_generation = 0;
    second.endpoint_route_generation = 0;
    endpoint.refresh_server_connection_routes(first);
    endpoint.refresh_server_connection_routes(second);
    first.connection->config_.max_outbound_datagram_size = 4096;
    second.connection->config_.max_outbound_datagram_size = 4096;
    first.path_id_by_route_handle.emplace(17, 0);
    first.route_handle_by_path_id.emplace(0, 17);
    second.path_id_by_route_handle.emplace(29, 0);
    second.route_handle_by_path_id.emplace(0, 29);

    first.connection->paths_.at(0).mtu.validated_datagram_size = 1500;
    first.connection->paths_.at(0).mtu.probe_ceiling = 4096;
    first.connection->paths_.at(0).mtu.search_low = 1500;
    first.connection->paths_.at(0).mtu.outstanding_probe_size = 1800;
    first.connection->paths_.at(0).mtu.outstanding_probe_packet_number = 7;
    first.connection->paths_.at(0).mtu.failed_probe_sizes = {1600, 2500};
    second.connection->paths_.at(0).mtu.validated_datagram_size = 1500;
    second.connection->paths_.at(0).mtu.probe_ceiling = 4096;

    auto ignored = endpoint.advance_endpoint(
        QuicCorePathMtuUpdate{
            .route_handle = 99,
            .max_udp_payload_size = 1300,
            .quoted_packet = make_supported_long_header_datagram(
                kQuicVersion1, first.connection->config_.source_connection_id,
                first.connection->config_.initial_destination_connection_id),
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(ignored.effects.empty());
    EXPECT_EQ(first.connection->paths_.at(0).mtu.validated_datagram_size, 1500u);

    auto mismatched_quote = endpoint.advance_endpoint(
        QuicCorePathMtuUpdate{
            .route_handle = 17,
            .max_udp_payload_size = 1300,
            .quoted_packet = make_supported_long_header_datagram(
                kQuicVersion1, second.connection->config_.source_connection_id,
                second.connection->config_.initial_destination_connection_id),
        },
        coquic::quic::test::test_time(3));
    EXPECT_TRUE(mismatched_quote.effects.empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2.1
    // # The endpoint SHOULD ignore all ICMP messages that fail validation.
    EXPECT_EQ(first.connection->paths_.at(0).mtu.validated_datagram_size, 1500u);

    auto updated = endpoint.advance_endpoint(
        QuicCorePathMtuUpdate{
            .route_handle = 17,
            .max_udp_payload_size = 1400,
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2.1
            // # This validation SHOULD use the quoted packet supplied in the
            // # payload of an ICMP message to associate the message with a
            // # corresponding transport connection (see Section 4.6.1 of
            // # [DPLPMTUD]).
            .quoted_packet = make_supported_long_header_datagram(
                kQuicVersion1, first.connection->config_.source_connection_id,
                first.connection->config_.initial_destination_connection_id),
        },
        coquic::quic::test::test_time(4));

    EXPECT_FALSE(updated.local_error.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
    // # QUIC implementations that implement any kind of PMTU discovery
    // # therefore SHOULD maintain a maximum datagram size for each combination
    // # of local and remote IP addresses.
    EXPECT_EQ(first.connection->paths_.at(0).mtu.probe_ceiling, 1400u);
    EXPECT_EQ(first.connection->paths_.at(0).mtu.validated_datagram_size, 1400u);
    EXPECT_FALSE(first.connection->paths_.at(0).mtu.outstanding_probe_size.has_value());
    EXPECT_EQ(first.connection->paths_.at(0).mtu.failed_probe_sizes, std::vector<std::size_t>{});
    EXPECT_EQ(second.connection->paths_.at(0).mtu.validated_datagram_size, 1500u);
}

TEST(QuicCoreEndpointInternalTest, LegacyPathMtuUpdateHonorsRouteMapping) {
    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    *legacy_core.connection_ = make_connected_client_connection();
    legacy_core.connection_->config_.max_outbound_datagram_size = 4096;
    ASSERT_TRUE(seed_legacy_route_handle_path_for_test(legacy_core, 17, 0));
    auto *entry = legacy_core.ensure_legacy_entry();
    ASSERT_NE(entry, nullptr);
    auto &path = entry->connection->paths_.at(0);
    path.mtu.validated_datagram_size = 1500;
    path.mtu.probe_ceiling = 4096;
    path.mtu.search_low = 1500;

    static_cast<void>(legacy_core.advance(
        QuicCorePathMtuUpdate{
            .route_handle = std::nullopt,
            .max_udp_payload_size = 1300,
        },
        coquic::quic::test::test_time(1)));
    EXPECT_EQ(path.mtu.validated_datagram_size, 1500u);

    static_cast<void>(legacy_core.advance(
        QuicCorePathMtuUpdate{
            .route_handle = 404,
            .max_udp_payload_size = 1300,
        },
        coquic::quic::test::test_time(2)));
    EXPECT_EQ(path.mtu.validated_datagram_size, 1500u);

    static_cast<void>(legacy_core.advance(
        QuicCorePathMtuUpdate{
            .route_handle = 17,
            .max_udp_payload_size = 1300,
        },
        coquic::quic::test::test_time(3)));
    EXPECT_EQ(path.mtu.probe_ceiling, 1300u);
    EXPECT_EQ(path.mtu.validated_datagram_size, 1300u);
}

TEST(QuicCoreEndpointInternalTest, LegacyClientBindsFirstInboundRouteAsDefaultPath) {
    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    auto *entry = legacy_core.ensure_legacy_entry();
    ASSERT_NE(entry, nullptr);
    ASSERT_NE(entry->connection, nullptr);
    ASSERT_EQ(legacy_core.connection_count(), 1u);
    ASSERT_FALSE(entry->default_route_handle.has_value());
    ASSERT_TRUE(entry->path_id_by_route_handle.empty());
    ASSERT_TRUE(entry->route_handle_by_path_id.empty());

    const auto identity = make_ipv4_identity(198, 51, 100, 7, 4433);
    auto route_probe = legacy_core.advance(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40}),
            .route_handle = 17,
            .address_validation_identity = identity,
        },
        coquic::quic::test::test_time(1));

    EXPECT_FALSE(route_probe.local_error.has_value());
    entry = legacy_core.ensure_legacy_entry();
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->default_route_handle, std::optional<QuicRouteHandle>{17u});
    ASSERT_TRUE(entry->path_id_by_route_handle.contains(17));
    EXPECT_EQ(entry->path_id_by_route_handle.at(17), 0u);
    ASSERT_TRUE(entry->route_handle_by_path_id.contains(0));
    EXPECT_EQ(entry->route_handle_by_path_id.at(0), 17u);
    ASSERT_TRUE(entry->address_validation_identity_by_path_id.contains(0));
    EXPECT_EQ(entry->address_validation_identity_by_path_id.at(0), identity);
}

TEST(QuicCoreEndpointInternalTest,
     ExistingInboundDatagramUsesDefaultRouteAndErasesClosedConnection) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));
    auto initial = make_client_initial_datagram();

    auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1));
    ASSERT_EQ(server.connection_count(), 1u);
    ASSERT_EQ(lifecycle_events_from(accepted).size(), 1u);

    auto &entry = server.connections_.begin()->second;
    ASSERT_EQ(entry.default_route_handle, std::optional<QuicRouteHandle>{31u});
    entry.connection->pending_terminal_state_ = QuicConnectionTerminalState::closed;

    auto closed = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
        },
        coquic::quic::test::test_time(2));

    EXPECT_EQ(server.connection_count(), 0u);
    auto lifecycle = lifecycle_events_from(closed);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::closed);
    auto sends = send_effects_from(closed);
    if (!sends.empty()) {
        EXPECT_EQ(sends.front().route_handle, std::optional<QuicRouteHandle>{31u});
    }
}

TEST(QuicCoreEndpointInternalTest, SelfMoveAssignmentLeavesLegacyCoreUsable) {
    QuicCore core(coquic::quic::test::make_client_core_config());

    auto &self = core;
    auto original_handle = core.legacy_connection_handle_;
    auto original_count = core.connection_count();
    core = std::move(self);

    EXPECT_EQ(core.legacy_connection_handle_, original_handle);
    EXPECT_EQ(core.connection_count(), original_count);
    EXPECT_EQ(core.connection_.owner, &core);
}

TEST(QuicCoreEndpointInternalTest, InboundEndpointBranchesCoverAcceptRetryAndUnknownToken) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));

    auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
        },
        coquic::quic::test::test_time(1));

    auto lifecycle = lifecycle_events_from(accepted);
    ASSERT_FALSE(lifecycle.empty());
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    auto accepted_sends = send_effects_from(accepted);
    ASSERT_FALSE(accepted_sends.empty());
    EXPECT_EQ(accepted_sends.front().route_handle, std::nullopt);

    QuicCore client(make_client_endpoint_config());
    auto ignored = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(ignored.effects.empty());
    EXPECT_FALSE(ignored.local_error.has_value());

    auto retry_config = make_server_endpoint_config();
    retry_config.retry_enabled = true;
    QuicCore retry_server(std::move(retry_config));
    auto retried_unknown_token = retry_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_plaintext_initial_datagram_with_token(bytes_from_ints({0xaa})),
            .route_handle = 55,
        },
        coquic::quic::test::test_time(3));
    auto unknown_token_sends = send_effects_from(retried_unknown_token);
    ASSERT_EQ(unknown_token_sends.size(), 1u);
    auto unknown_token_retry = deserialize_packet(unknown_token_sends.front().bytes.span(), {});
    ASSERT_TRUE(unknown_token_retry.has_value());
    EXPECT_NE(std::get_if<RetryPacket>(&unknown_token_retry.value().packet), nullptr);
    EXPECT_EQ(retry_server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, RetryHandshakeValidationCapturesPreRetryCryptoOnlyWhenEnabled) {
    auto enabled_config = make_server_endpoint_config();
    enabled_config.retry_enabled = true;
    enabled_config.retry_handshake_validation_policy = QuicRetryHandshakeValidationPolicy::discard;
    QuicCore enabled_server(std::move(enabled_config));
    auto enabled_result = enabled_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
        },
        coquic::quic::test::test_time(1));
    ASSERT_EQ(send_effects_from(enabled_result).size(), 1u);
    ASSERT_EQ(enabled_server.retry_tokens_.size(), 1u);
    EXPECT_TRUE(
        enabled_server.retry_tokens_.begin()->second.retry_handshake_crypto_digest.has_value());

    auto disabled_config = make_server_endpoint_config();
    disabled_config.retry_enabled = true;
    QuicCore disabled_server(std::move(disabled_config));
    auto disabled_result = disabled_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
        },
        coquic::quic::test::test_time(1));
    ASSERT_EQ(send_effects_from(disabled_result).size(), 1u);
    ASSERT_EQ(disabled_server.retry_tokens_.size(), 1u);
    EXPECT_FALSE(
        disabled_server.retry_tokens_.begin()->second.retry_handshake_crypto_digest.has_value());
}

TEST(QuicCoreEndpointInternalTest, RetryHandshakeValidationCaptureFailureStillRequiresRetry) {
    auto config = make_server_endpoint_config();
    config.retry_enabled = true;
    config.retry_handshake_validation_policy = QuicRetryHandshakeValidationPolicy::discard;
    QuicCore server(std::move(config));

    const auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_plaintext_initial_datagram(
                kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
                bytes_from_ints({0xc1, 0x01}), {}),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(1));

    const auto sends = send_effects_from(result);
    ASSERT_EQ(sends.size(), 1u);
    const auto decoded_retry = deserialize_packet(sends.front().bytes.span(), {});
    ASSERT_TRUE(decoded_retry.has_value());
    const auto &retry_datagram = decoded_retry.value();
    EXPECT_NE(std::get_if<RetryPacket>(&retry_datagram.packet), nullptr);
    EXPECT_TRUE(lifecycle_events_from(result).empty());
    EXPECT_EQ(server.connection_count(), 0u);
    ASSERT_EQ(server.retry_tokens_.size(), 1u);
    const auto &pending = server.retry_tokens_.begin()->second;
    EXPECT_FALSE(pending.retry_handshake_crypto_digest.has_value());
    EXPECT_TRUE(pending.retry_handshake_validation_state_unavailable);
}

TEST(QuicCoreEndpointInternalTest, RetryHandshakeValidationBudgetExhaustionStillRequiresRetry) {
    auto config = make_server_endpoint_config();
    config.retry_enabled = true;
    config.retry_handshake_validation_policy = QuicRetryHandshakeValidationPolicy::discard;
    QuicCore server(std::move(config));

    const auto digest = make_retry_handshake_crypto_digest({QuicRetryHandshakeCryptoRange{
        .offset = 0,
        .bytes = bytes_from_ints({0x01, 0x00, 0x00, 0x00}),
    }});
    ASSERT_TRUE(digest.has_value());
    for (std::size_t index = 0;
         index < 300 && server.retry_handshake_validation_state_budget_available(); ++index) {
        const auto token = bytes_from_ints({
            static_cast<std::uint8_t>((index >> 24) & 0xffu),
            static_cast<std::uint8_t>((index >> 16) & 0xffu),
            static_cast<std::uint8_t>((index >> 8) & 0xffu),
            static_cast<std::uint8_t>(index & 0xffu),
        });
        server.retry_tokens_.emplace(server.connection_id_key(token),
                                     QuicCore::PendingRetryToken{
                                         .token = token,
                                         .retry_handshake_crypto_digest = digest,
                                         .expires_at = coquic::quic::test::test_time(100),
                                     });
    }
    ASSERT_FALSE(server.retry_handshake_validation_state_budget_available());

    const auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{.bytes = make_client_initial_datagram(), .route_handle = 17},
        coquic::quic::test::test_time(1));
    EXPECT_EQ(send_effects_from(result).size(), 1u);
    EXPECT_TRUE(lifecycle_events_from(result).empty());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(std::any_of(server.retry_tokens_.begin(), server.retry_tokens_.end(),
                            [](const auto &entry) {
                                return entry.second.retry_handshake_validation_state_unavailable;
                            }));
}

TEST(QuicCoreEndpointInternalTest,
     RetryHandshakeValidationRejectsBeforeEndpointAcceptanceAndAllowsRetransmission) {
    const auto client_dcid = bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    const auto initial = make_client_initial_datagram();
    auto decoded_initial = deserialize_protected_datagram(
        initial, DeserializeProtectionContext{
                     .peer_role = EndpointRole::client,
                     .client_initial_destination_connection_id = client_dcid,
                 });
    ASSERT_TRUE(decoded_initial.has_value());
    const auto &initial_packets = decoded_initial.value();
    ASSERT_FALSE(initial_packets.empty());
    const auto *initial_packet = std::get_if<ProtectedInitialPacket>(&initial_packets.front());
    ASSERT_NE(initial_packet, nullptr);
    const auto initial_crypto_it =
        std::find_if(initial_packet->frames.begin(), initial_packet->frames.end(),
                     [](const auto &frame) { return std::get_if<CryptoFrame>(&frame) != nullptr; });
    ASSERT_NE(initial_crypto_it, initial_packet->frames.end());
    const auto *initial_crypto = std::get_if<CryptoFrame>(&*initial_crypto_it);
    ASSERT_NE(initial_crypto, nullptr);
    ASSERT_GE(initial_crypto->crypto_data.size(), 4u);
    const auto client_hello_length =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(initial_crypto->crypto_data[1]))
         << 16) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(initial_crypto->crypto_data[2]))
         << 8) |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(initial_crypto->crypto_data[3]));
    ASSERT_GT(client_hello_length, 0u);
    const auto client_hello_last_byte = std::size_t{4} + client_hello_length - 1;
    ASSERT_LT(client_hello_last_byte, initial_crypto->crypto_data.size());

    const auto make_retried_initial = [&](const RetryPacket &retry, bool mismatch) {
        auto retried = *initial_packet;
        retried.destination_connection_id = retry.source_connection_id;
        retried.token = retry.retry_token;
        if (mismatch) {
            for (auto &frame : retried.frames) {
                auto *crypto = std::get_if<CryptoFrame>(&frame);
                if (crypto != nullptr && !crypto->crypto_data.empty()) {
                    crypto->crypto_data[client_hello_last_byte] ^= std::byte{0x01};
                    break;
                }
            }
        }
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{std::move(retried)},
            SerializeProtectionContext{
                .local_role = EndpointRole::client,
                .client_initial_destination_connection_id = retry.source_connection_id,
            });
        EXPECT_TRUE(encoded.has_value());
        return encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
    };

    const auto make_retried_initial_fragment = [&](const RetryPacket &retry,
                                                   std::vector<std::byte> crypto_data) {
        auto retried = *initial_packet;
        retried.destination_connection_id = retry.source_connection_id;
        retried.token = retry.retry_token;
        for (auto &frame : retried.frames) {
            auto *crypto = std::get_if<CryptoFrame>(&frame);
            if (crypto != nullptr) {
                crypto->offset = 0;
                crypto->crypto_data = std::move(crypto_data);
                break;
            }
        }
        for (std::size_t index = 0; index < 512; ++index) {
            retried.frames.emplace_back(PaddingFrame{});
        }
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{std::move(retried)},
            SerializeProtectionContext{
                .local_role = EndpointRole::client,
                .client_initial_destination_connection_id = retry.source_connection_id,
            });
        EXPECT_TRUE(encoded.has_value());
        return encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
    };

    const auto make_pre_retry_initial_fragment = [&](std::vector<std::byte> crypto_data) {
        auto fragmented = *initial_packet;
        fragmented.token.clear();
        for (auto &frame : fragmented.frames) {
            auto *crypto = std::get_if<CryptoFrame>(&frame);
            if (crypto != nullptr) {
                crypto->offset = 0;
                crypto->crypto_data = std::move(crypto_data);
                break;
            }
        }
        for (std::size_t index = 0; index < 512; ++index) {
            fragmented.frames.emplace_back(PaddingFrame{});
        }
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{std::move(fragmented)},
            SerializeProtectionContext{
                .local_role = EndpointRole::client,
                .client_initial_destination_connection_id = client_dcid,
            });
        EXPECT_TRUE(encoded.has_value());
        return encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
    };

    const auto send_mismatch_and_get_retry = [&](QuicCore &server,
                                                 bool fragmented) -> std::optional<RetryPacket> {
        const auto retry_result =
            server.advance_endpoint(QuicCoreInboundDatagram{.bytes = initial, .route_handle = 17},
                                    coquic::quic::test::test_time(1));
        const auto retry_sends = send_effects_from(retry_result);
        EXPECT_EQ(retry_sends.size(), 1u);
        if (retry_sends.empty()) {
            return std::nullopt;
        }
        const auto retry_decoded = deserialize_packet(retry_sends.front().bytes.span(), {});
        if (!retry_decoded.has_value()) {
            ADD_FAILURE() << "Retry packet did not decode";
            return std::nullopt;
        }
        const auto *retry = std::get_if<RetryPacket>(&retry_decoded.value().packet);
        if (retry == nullptr) {
            ADD_FAILURE() << "Retry response was not a Retry packet";
            return std::nullopt;
        }
        if (server.retry_tokens_.size() != 1u) {
            ADD_FAILURE() << "Retry token state was not retained";
            return std::nullopt;
        }

        auto mismatch_bytes = make_retried_initial(*retry, true);
        if (fragmented) {
            auto wrong_prefix = std::vector<std::byte>{initial_crypto->crypto_data.front()};
            wrong_prefix.front() ^= std::byte{0x01};
            mismatch_bytes = make_retried_initial_fragment(*retry, std::move(wrong_prefix));
        }
        const auto parsed_mismatch = server.parse_endpoint_datagram(mismatch_bytes);
        if (!parsed_mismatch.has_value() ||
            parsed_mismatch->token.size() != retry->retry_token.size()) {
            ADD_FAILURE() << "Retransmitted Initial did not preserve its Retry token";
            return std::nullopt;
        }
        const auto mismatch_result = server.advance_endpoint(
            QuicCoreInboundDatagram{
                .bytes = std::move(mismatch_bytes),
                .route_handle = 17,
            },
            coquic::quic::test::test_time(2));
        const auto mismatch_lifecycle = lifecycle_events_from(mismatch_result);
        if (server.endpoint_config_.retry_handshake_validation_policy ==
            QuicRetryHandshakeValidationPolicy::connection_error) {
            EXPECT_TRUE(std::none_of(
                mismatch_lifecycle.begin(), mismatch_lifecycle.end(), [](const auto &event) {
                    return event.event == QuicCoreConnectionLifecycle::accepted;
                }));
            EXPECT_EQ(server.connection_count(), 0u);
        } else {
            EXPECT_TRUE(mismatch_lifecycle.empty());
        }
        return *retry;
    };

    auto discard_config = make_server_endpoint_config();
    discard_config.retry_enabled = true;
    discard_config.application_protocol = "coquic";
    discard_config.retry_handshake_validation_policy = QuicRetryHandshakeValidationPolicy::discard;
    QuicCore discard_server(std::move(discard_config));
    const auto discard_retry = send_mismatch_and_get_retry(discard_server, true);
    ASSERT_TRUE(discard_retry.has_value());
    if (!discard_retry.has_value()) {
        return;
    }
    ASSERT_EQ(discard_server.connection_count(), 1u);
    ASSERT_FALSE(discard_server.connections_.begin()->second.connection->has_failed());
    const auto &discard_retry_packet = optional_ref_or_terminate(discard_retry);
    const auto discard_suffix = discard_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_retried_initial(discard_retry_packet, true),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(3));
    EXPECT_TRUE(lifecycle_events_from(discard_suffix).empty());
    EXPECT_EQ(discard_server.connection_count(), 1u);
    auto correct_overlap = std::vector<std::byte>(initial_crypto->crypto_data.begin(),
                                                  initial_crypto->crypto_data.begin() + 2);
    const auto discard_overlap = discard_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes =
                make_retried_initial_fragment(discard_retry_packet, std::move(correct_overlap)),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(3));
    EXPECT_TRUE(lifecycle_events_from(discard_overlap).empty());
    EXPECT_EQ(discard_server.connection_count(), 1u);
    const auto discard_retransmission = discard_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_retried_initial(discard_retry_packet, false),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(4));
    const auto discard_lifecycle = lifecycle_events_from(discard_retransmission);
    ASSERT_EQ(discard_lifecycle.size(), 1u);
    EXPECT_EQ(discard_lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    EXPECT_EQ(discard_server.connection_count(), 1u);

    discard_server.connections_.begin()->second.connection->pending_terminal_state_ =
        QuicConnectionTerminalState::closed;
    const auto discard_teardown = discard_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_retried_initial(discard_retry_packet, false),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(5));
    const auto teardown_lifecycle = lifecycle_events_from(discard_teardown);
    ASSERT_EQ(teardown_lifecycle.size(), 1u);
    EXPECT_EQ(teardown_lifecycle.front().event, QuicCoreConnectionLifecycle::closed);
    EXPECT_EQ(discard_server.connection_count(), 0u);

    const auto replay = discard_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_retried_initial(discard_retry_packet, false),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(6));
    EXPECT_TRUE(lifecycle_events_from(replay).empty());
    EXPECT_EQ(discard_server.connection_count(), 0u);
    EXPECT_FALSE(send_effects_from(replay).empty());

    auto error_config = make_server_endpoint_config();
    error_config.retry_enabled = true;
    error_config.application_protocol = "coquic";
    error_config.retry_handshake_validation_policy =
        QuicRetryHandshakeValidationPolicy::connection_error;
    QuicCore error_server(std::move(error_config));
    const auto error_retry = send_mismatch_and_get_retry(error_server, false);
    ASSERT_TRUE(error_retry.has_value());
    if (!error_retry.has_value()) {
        return;
    }
    EXPECT_EQ(error_server.connection_count(), 0u);

    auto fragmented_config = make_server_endpoint_config();
    fragmented_config.retry_enabled = true;
    fragmented_config.application_protocol = "coquic";
    fragmented_config.retry_handshake_validation_policy =
        QuicRetryHandshakeValidationPolicy::discard;
    QuicCore fragmented_server(std::move(fragmented_config));
    const auto prefix =
        std::vector<std::byte>{initial_crypto->crypto_data[0], initial_crypto->crypto_data[1]};
    const auto fragmented_retry_result = fragmented_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_pre_retry_initial_fragment(prefix),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(7));
    const auto fragmented_retry_sends = send_effects_from(fragmented_retry_result);
    ASSERT_EQ(fragmented_retry_sends.size(), 1u);
    const auto fragmented_retry_decoded =
        deserialize_packet(fragmented_retry_sends.front().bytes.span(), {});
    ASSERT_TRUE(fragmented_retry_decoded.has_value());
    const auto &fragmented_retry_datagram = fragmented_retry_decoded.value();
    const auto *fragmented_retry = std::get_if<RetryPacket>(&fragmented_retry_datagram.packet);
    ASSERT_NE(fragmented_retry, nullptr);
    ASSERT_EQ(fragmented_server.retry_tokens_.size(), 1u);
    EXPECT_TRUE(fragmented_server.retry_tokens_.begin()
                    ->second.retry_handshake_validation_state_incomplete);
    EXPECT_FALSE(fragmented_server.retry_tokens_.begin()
                     ->second.retry_handshake_validation_state_unavailable);
    const auto fragmented_post_retry = fragmented_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_retried_initial_fragment(
                *fragmented_retry, std::vector<std::byte>(initial_crypto->crypto_data.begin(),
                                                          initial_crypto->crypto_data.end())),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(8));
    const auto fragmented_lifecycle = lifecycle_events_from(fragmented_post_retry);
    ASSERT_EQ(fragmented_lifecycle.size(), 1u);
    EXPECT_EQ(fragmented_lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    EXPECT_FALSE(send_effects_from(fragmented_post_retry).empty());
    EXPECT_EQ(fragmented_server.connection_count(), 1u);
}

TEST(QuicCoreEndpointInternalTest, InitialServerCloseUsesMinimalRetention) {
    auto config = make_server_endpoint_config();
    config.application_protocol = "coquic";
    config.enable_minimal_closing_state_retention = true;
    config.identity = TlsIdentity{
        .certificate_pem = "invalid certificate",
        .private_key_pem = "invalid key",
    };
    QuicCore server(std::move(config));

    static_cast<void>(server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 61,
        },
        coquic::quic::test::test_time(1)));

    ASSERT_EQ(server.connection_count(), 1u);
    const auto &entry = server.connections_.begin()->second;
    EXPECT_EQ(entry.connection, nullptr);
    EXPECT_TRUE(entry.minimal_closing_state.has_value());
    ASSERT_FALSE(entry.active_connection_id_keys.empty());
    EXPECT_EQ(server.connection_id_routes_.at(entry.active_connection_id_keys.front()),
              entry.handle);
}

TEST(QuicCoreEndpointInternalTest, ServerClosesInvalidRetryTokenWithInvalidToken) {
    auto config = make_server_endpoint_config();
    config.retry_enabled = true;
    config.address_validation_token_secret = make_address_validation_secret(0x8a);
    QuicCore server(std::move(config));

    auto client_dcid = bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    auto client_scid = bytes_from_ints({0xc1, 0x01});
    auto initial = make_supported_initial_datagram(kQuicVersion1, client_dcid, client_scid, {});

    auto retry = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 56,
        },
        coquic::quic::test::test_time(1));
    auto retry_sends = send_effects_from(retry);
    ASSERT_EQ(retry_sends.size(), 1u);
    auto decoded_retry = deserialize_packet(retry_sends.front().bytes.span(), {});
    ASSERT_TRUE(decoded_retry.has_value());
    auto *retry_packet = std::get_if<RetryPacket>(&decoded_retry.value().packet);
    ASSERT_NE(retry_packet, nullptr);

    auto tampered_token = retry_packet->retry_token;
    tampered_token.back() =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered_token.back()) ^ 0x01u);
    auto retried_initial = make_plaintext_initial_datagram(
        kQuicVersion1, retry_packet->source_connection_id, client_scid, tampered_token);
    auto rejected = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = retried_initial,
            .route_handle = 56,
        },
        coquic::quic::test::test_time(2));

    auto close_sends = send_effects_from(rejected);
    ASSERT_EQ(close_sends.size(), 1u);
    auto close_packets = decode_endpoint_initial_datagram(close_sends.front().bytes, client_dcid);
    ASSERT_EQ(close_packets.size(), 1u);
    auto *initial_close = std::get_if<ProtectedInitialPacket>(&close_packets.front());
    ASSERT_NE(initial_close, nullptr);
    ASSERT_EQ(initial_close->frames.size(), 1u);
    auto *close_frame = std::get_if<TransportConnectionCloseFrame>(&initial_close->frames.front());
    ASSERT_NE(close_frame, nullptr);
    EXPECT_EQ(close_frame->error_code,
              static_cast<std::uint64_t>(QuicTransportErrorCode::invalid_token));
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, ServerRefusesNewConnectionAtAdmissionLimit) {
    auto config = make_server_endpoint_config();
    config.application_protocol = "coquic";
    config.max_server_connections = 1;
    QuicCore server(std::move(config));

    auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 56,
        },
        coquic::quic::test::test_time(1));
    auto lifecycle = lifecycle_events_from(accepted);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    ASSERT_EQ(server.connection_count(), 1u);

    auto refused_client_dcid = bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09});
    auto refused_client_scid = bytes_from_ints({0xc1, 0x02});
    auto refused_initial = make_supported_initial_datagram(kQuicVersion1, refused_client_dcid,
                                                           refused_client_scid, {});
    auto refused = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = refused_initial,
            .route_handle = 57,
        },
        coquic::quic::test::test_time(2));

    auto close_sends = send_effects_from(refused);
    ASSERT_EQ(close_sends.size(), 1u);
    EXPECT_EQ(close_sends.front().route_handle, std::optional<QuicRouteHandle>{57u});
    auto close_packets =
        decode_endpoint_initial_datagram(close_sends.front().bytes, refused_client_dcid);
    ASSERT_EQ(close_packets.size(), 1u);
    auto *initial_close = std::get_if<ProtectedInitialPacket>(&close_packets.front());
    ASSERT_NE(initial_close, nullptr);
    ASSERT_EQ(initial_close->frames.size(), 1u);
    auto *close_frame = std::get_if<TransportConnectionCloseFrame>(&initial_close->frames.front());
    ASSERT_NE(close_frame, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # If a server refuses to accept a new connection, it SHOULD send an
    // # Initial packet containing a CONNECTION_CLOSE frame with error code
    // # CONNECTION_REFUSED.
    EXPECT_EQ(close_frame->error_code,
              static_cast<std::uint64_t>(QuicTransportErrorCode::connection_refused));
    EXPECT_EQ(server.connection_count(), 1u);
}

TEST(QuicCoreEndpointInternalTest, ServerRetriesInvalidNewTokenAsUnvalidatedAddress) {
    auto issuer_config = make_server_endpoint_config();
    issuer_config.address_validation_token_secret = make_address_validation_secret(0x8b);
    QuicCore issuer(std::move(issuer_config));
    auto identity = make_ipv4_identity(198, 51, 100, 7, 4433);
    auto token = issuer.make_endpoint_new_token(1, kQuicVersion1, 57, identity,
                                                coquic::quic::test::test_time(1));
    ASSERT_FALSE(token.empty());
    token.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(token.back()) ^ 0x01u);

    auto server_config = make_server_endpoint_config();
    server_config.retry_enabled = true;
    server_config.address_validation_token_secret = make_address_validation_secret(0x8b);
    QuicCore server(std::move(server_config));

    auto client_config = make_client_endpoint_config();
    client_config.application_protocol = "coquic";
    QuicCore client(std::move(client_config));
    auto open = make_client_open_config(12);
    open.initial_destination_connection_id =
        bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    open.retry_token = token;
    auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(open),
            .initial_route_handle = 57,
        },
        coquic::quic::test::test_time(2));
    auto initial_sends = send_effects_from(opened);
    ASSERT_FALSE(initial_sends.empty());

    auto response = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial_sends.front().bytes,
            .route_handle = 57,
            .address_validation_identity = identity,
        },
        coquic::quic::test::test_time(3));
    auto response_sends = send_effects_from(response);
    ASSERT_EQ(response_sends.size(), 1u);
    auto decoded_retry = deserialize_packet(response_sends.front().bytes.span(), {});
    ASSERT_TRUE(decoded_retry.has_value());
    EXPECT_NE(std::get_if<RetryPacket>(&decoded_retry.value().packet), nullptr);
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, StrictServerDiscardsTokenlessInitialBeforeRetry) {
    auto config = make_server_endpoint_config();
    config.retry_enabled = true;
    config.require_address_validation_token = true;
    config.address_validation_token_secret = make_address_validation_secret(0x90);
    QuicCore server(std::move(config));

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 55,
            .address_validation_identity = make_ipv4_identity(198, 51, 100, 7, 4433),
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # Servers MAY discard any Initial packet that does not carry the
    // # expected token.
    EXPECT_TRUE(result.effects.empty());
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(server.retry_tokens_.empty());
}

TEST(QuicCoreEndpointInternalTest, RetryFallbackForTokenlessInitialRemainsDefault) {
    auto config = make_server_endpoint_config();
    config.retry_enabled = true;
    config.address_validation_token_secret = make_address_validation_secret(0x91);
    QuicCore server(std::move(config));

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 56,
            .address_validation_identity = make_ipv4_identity(198, 51, 100, 8, 4433),
        },
        coquic::quic::test::test_time(1));

    auto sends = send_effects_from(result);
    ASSERT_EQ(sends.size(), 1u);
    auto decoded_retry = deserialize_packet(sends.front().bytes.span(), {});
    ASSERT_TRUE(decoded_retry.has_value());
    EXPECT_NE(std::get_if<RetryPacket>(&decoded_retry.value().packet), nullptr);
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_EQ(server.retry_tokens_.size(), 1u);
}

TEST(QuicCoreEndpointInternalTest, StrictServerDiscardsTokenlessInitialAtAdmissionLimit) {
    auto config = make_server_endpoint_config();
    config.application_protocol = "coquic";
    config.max_server_connections = 1;
    QuicCore server(std::move(config));

    auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));
    ASSERT_EQ(lifecycle_events_from(accepted).size(), 1u);
    ASSERT_EQ(server.connection_count(), 1u);
    server.endpoint_config_.require_address_validation_token = true;

    auto refused_client_dcid = bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09});
    auto refused_client_scid = bytes_from_ints({0xc1, 0x02});
    auto refused_initial = make_supported_initial_datagram(kQuicVersion1, refused_client_dcid,
                                                           refused_client_scid, {});
    auto refused = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = refused_initial,
            .route_handle = 56,
        },
        coquic::quic::test::test_time(2));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # Servers MAY discard any Initial packet that does not carry the
    // # expected token.
    EXPECT_TRUE(refused.effects.empty());
    EXPECT_FALSE(refused.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 1u);
}

TEST(QuicCoreEndpointInternalTest, StrictServerAcceptsValidNewTokenAndValidatesAddress) {
    auto issuer_config = make_server_endpoint_config();
    issuer_config.address_validation_token_secret = make_address_validation_secret(0x92);
    QuicCore issuer(std::move(issuer_config));

    const auto identity = make_ipv4_identity(198, 51, 100, 9, 4433);
    auto token = issuer.make_endpoint_new_token(1, kQuicVersion1, 57, identity,
                                                coquic::quic::test::test_time(1));
    ASSERT_FALSE(token.empty());

    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    server_config.require_address_validation_token = true;
    server_config.address_validation_token_secret = make_address_validation_secret(0x92);
    QuicCore server(std::move(server_config));

    auto open = make_client_open_config(6);
    open.retry_token = token;
    QuicCore client(make_client_endpoint_config());
    auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(open),
            .initial_route_handle = 57,
        },
        coquic::quic::test::test_time(2));
    auto initial_sends = send_effects_from(opened);
    ASSERT_FALSE(initial_sends.empty());

    auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial_sends.front().bytes,
            .route_handle = 57,
            .address_validation_identity = identity,
        },
        coquic::quic::test::test_time(3));

    auto lifecycle = lifecycle_events_from(accepted);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    ASSERT_EQ(server.connection_count(), 1u);
    auto &connection = *server.connections_.at(lifecycle.front().connection).connection;
    EXPECT_TRUE(connection.peer_address_validated_);
    EXPECT_FALSE(connection.anti_amplification_applies());
}

TEST(QuicCoreEndpointInternalTest, StrictServerKeepsInvalidNewTokenUnvalidated) {
    auto issuer_config = make_server_endpoint_config();
    issuer_config.address_validation_token_secret = make_address_validation_secret(0x93);
    QuicCore issuer(std::move(issuer_config));

    const auto identity = make_ipv4_identity(198, 51, 100, 10, 4433);
    auto token = issuer.make_endpoint_new_token(1, kQuicVersion1, 58, identity,
                                                coquic::quic::test::test_time(1));
    ASSERT_FALSE(token.empty());
    token.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(token.back()) ^ 0x01u);

    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    server_config.require_address_validation_token = true;
    server_config.address_validation_token_secret = make_address_validation_secret(0x93);
    QuicCore server(std::move(server_config));

    auto open = make_client_open_config(7);
    open.retry_token = token;
    QuicCore client(make_client_endpoint_config());
    auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(open),
            .initial_route_handle = 58,
        },
        coquic::quic::test::test_time(2));
    auto initial_sends = send_effects_from(opened);
    ASSERT_FALSE(initial_sends.empty());

    auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial_sends.front().bytes,
            .route_handle = 58,
            .address_validation_identity = identity,
        },
        coquic::quic::test::test_time(3));

    auto lifecycle = lifecycle_events_from(accepted);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    ASSERT_EQ(server.connection_count(), 1u);
    auto &connection = *server.connections_.at(lifecycle.front().connection).connection;
    EXPECT_FALSE(connection.peer_address_validated_);
    EXPECT_TRUE(connection.anti_amplification_applies());
    EXPECT_EQ(connection.anti_amplification_send_budget(),
              connection.anti_amplification_received_bytes_ * 3u);
}

TEST(QuicCoreEndpointInternalTest, EndpointAndLegacyCommandsCoverErrorAndCleanupBranches) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    if (!entry.connection->peer_transport_parameters_.has_value()) {
        FAIL() << "expected peer transport parameters";
        return;
    }
    auto &peer_transport_parameters = *entry.connection->peer_transport_parameters_;
    peer_transport_parameters.disable_active_migration = true;

    auto reset_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreResetStream{
                    .stream_id = 3,
                    .application_error_code = 11,
                },
        },
        coquic::quic::test::test_time(1));
    if (!reset_result.local_error.has_value()) {
        FAIL() << "expected reset local error";
        return;
    }
    auto &reset_error = *reset_result.local_error;
    EXPECT_EQ(reset_error.connection, std::optional<QuicConnectionHandle>{1u});
    EXPECT_EQ(reset_error.code, QuicCoreLocalErrorCode::invalid_stream_direction);

    auto stop_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreStopSending{
                    .stream_id = 2,
                    .application_error_code = 12,
                },
        },
        coquic::quic::test::test_time(2));
    if (!stop_result.local_error.has_value()) {
        FAIL() << "expected stop local error";
        return;
    }
    auto &stop_error = *stop_result.local_error;
    EXPECT_EQ(stop_error.connection, std::optional<QuicConnectionHandle>{1u});
    EXPECT_EQ(stop_error.code, QuicCoreLocalErrorCode::invalid_stream_direction);

    auto migration_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = QuicMigrationRequestReason::active,
                },
        },
        coquic::quic::test::test_time(3));
    if (!migration_result.local_error.has_value()) {
        FAIL() << "expected migration local error";
        return;
    }
    auto &migration_error = *migration_result.local_error;
    EXPECT_EQ(migration_error.connection, std::optional<QuicConnectionHandle>{1u});
    EXPECT_EQ(migration_error.code, QuicCoreLocalErrorCode::unsupported_operation);

    QuicCore timer_core(make_client_endpoint_config());
    static_cast<void>(timer_core.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    auto &timer_entry = timer_core.connections_.at(1);
    *timer_entry.connection = make_connected_client_connection();
    timer_entry.connection->application_space_.pending_ack_deadline =
        coquic::quic::test::test_time(5);
    timer_entry.connection->pending_terminal_state_ = QuicConnectionTerminalState::closed;

    auto timeout_result =
        timer_core.advance_endpoint(QuicCoreTimerExpired{}, coquic::quic::test::test_time(5));
    EXPECT_EQ(timer_core.connection_count(), 0u);
    auto timeout_lifecycle = lifecycle_events_from(timeout_result);
    ASSERT_EQ(timeout_lifecycle.size(), 1u);
    EXPECT_EQ(timeout_lifecycle.front().event, QuicCoreConnectionLifecycle::closed);

    QuicCore draining_core(make_client_endpoint_config());
    auto draining_entry = QuicCore::ConnectionEntry{
        .handle = 1,
        .connection = std::make_unique<QuicConnection>(make_connected_client_connection()),
    };
    draining_entry.connection->recovery_rtt_state_.latest_rtt = std::chrono::milliseconds(10);
    draining_entry.connection->recovery_rtt_state_.smoothed_rtt = std::chrono::milliseconds(10);
    draining_entry.connection->recovery_rtt_state_.rttvar = std::chrono::milliseconds(1);
    draining_entry.connection->enter_draining_state(coquic::quic::test::test_time(100));
    draining_core.connections_.emplace(draining_entry.handle, std::move(draining_entry));
    ASSERT_EQ(draining_core.next_wakeup(), coquic::quic::test::test_time(142));

    auto draining_expired =
        draining_core.advance_endpoint(QuicCoreTimerExpired{}, coquic::quic::test::test_time(142));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
    // # Once its closing or draining state ends, an endpoint SHOULD discard
    // # all connection state.
    EXPECT_EQ(draining_core.connection_count(), 0u);
    auto draining_lifecycle = lifecycle_events_from(draining_expired);
    ASSERT_EQ(draining_lifecycle.size(), 1u);
    EXPECT_EQ(draining_lifecycle.front().event, QuicCoreConnectionLifecycle::closed);

    QuicCore missing_legacy(coquic::quic::test::make_client_core_config());
    auto *missing_legacy_entry = missing_legacy.ensure_legacy_entry();
    ASSERT_NE(missing_legacy_entry, nullptr);
    missing_legacy_entry->connection.reset();
    auto missing_legacy_result =
        missing_legacy.advance(QuicCoreStart{}, coquic::quic::test::test_time(6));
    EXPECT_TRUE(missing_legacy_result.effects.empty());
    EXPECT_FALSE(missing_legacy_result.local_error.has_value());

    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    auto shared_send_result = legacy_core.advance(
        QuicCoreSendSharedStreamData{
            .stream_id = 0,
            .bytes = SharedBytes(bytes_from_ints({0x68, 0x69})),
            .fin = false,
        },
        coquic::quic::test::test_time(7));
    if (!shared_send_result.local_error.has_value()) {
        FAIL() << "expected shared-send local error";
        return;
    }
    auto &shared_send_error = *shared_send_result.local_error;
    EXPECT_EQ(shared_send_error.connection, std::nullopt);
    EXPECT_EQ(shared_send_error.code, QuicCoreLocalErrorCode::invalid_stream_id);
}

TEST(QuicCoreEndpointInternalTest, RouteMaintenanceSkipsForeignOwnersAndMissingInitialKeys) {
    QuicCore server_core(make_server_endpoint_config());

    QuicCore::ConnectionEntry erase_entry{
        .handle = 9,
    };
    erase_entry.active_connection_id_keys = {"owned", "foreign", "missing"};
    erase_entry.local_stateless_reset_connection_id_keys = {"owned-reset-cid", "foreign-reset-cid",
                                                            "missing-reset-cid"};
    erase_entry.peer_stateless_reset_token_keys = {"owned-peer-token", "foreign-peer-token",
                                                   "missing-peer-token"};
    erase_entry.initial_destination_connection_id_key = "foreign-initial";
    server_core.connection_id_routes_.emplace("owned", erase_entry.handle);
    server_core.connection_id_routes_.emplace("foreign", 77);
    server_core.initial_destination_routes_.emplace("foreign-initial", 77);
    server_core.local_stateless_reset_tokens_by_cid_.emplace(
        "owned-reset-cid", QuicCore::LocalStatelessResetTokenRoute{
                               .owner = erase_entry.handle,
                           });
    server_core.local_stateless_reset_tokens_by_cid_.emplace(
        "foreign-reset-cid", QuicCore::LocalStatelessResetTokenRoute{
                                 .owner = 77,
                             });
    server_core.peer_stateless_reset_tokens_.emplace("owned-peer-token",
                                                     QuicCore::PeerStatelessResetTokenRoute{
                                                         .owner = erase_entry.handle,
                                                     });
    server_core.peer_stateless_reset_tokens_.emplace("foreign-peer-token",
                                                     QuicCore::PeerStatelessResetTokenRoute{
                                                         .owner = 77,
                                                     });

    server_core.erase_endpoint_connection_routes(erase_entry);
    EXPECT_FALSE(server_core.connection_id_routes_.contains("owned"));
    EXPECT_EQ(server_core.connection_id_routes_.at("foreign"), 77u);
    EXPECT_EQ(server_core.initial_destination_routes_.at("foreign-initial"), 77u);
    EXPECT_FALSE(server_core.local_stateless_reset_tokens_by_cid_.contains("owned-reset-cid"));
    EXPECT_EQ(server_core.local_stateless_reset_tokens_by_cid_.at("foreign-reset-cid").owner, 77u);
    EXPECT_FALSE(server_core.peer_stateless_reset_tokens_.contains("owned-peer-token"));
    EXPECT_EQ(server_core.peer_stateless_reset_tokens_.at("foreign-peer-token").owner, 77u);

    QuicCore::ConnectionEntry no_initial_entry{
        .handle = 10,
    };
    no_initial_entry.active_connection_id_keys = {"owned-no-initial"};
    server_core.connection_id_routes_.emplace("owned-no-initial", no_initial_entry.handle);

    server_core.erase_endpoint_connection_routes(no_initial_entry);
    EXPECT_FALSE(server_core.connection_id_routes_.contains("owned-no-initial"));

    QuicCore::ConnectionEntry missing_initial_entry{
        .handle = 10,
        .initial_destination_connection_id_key = std::string("missing-initial"),
    };
    server_core.erase_endpoint_connection_routes(missing_initial_entry);

    auto refresh_entry = make_server_connection_entry(11, std::string("foreign-refresh-initial"));
    refresh_entry.connection->local_connection_ids_.clear();
    refresh_entry.connection->local_connection_ids_.emplace(
        0, LocalConnectionIdRecord{
               .sequence_number = 0,
               .connection_id = ConnectionId{std::byte{0x44}},
               .retired = false,
           });
    refresh_entry.connection->client_initial_destination_connection_id_ =
        ConnectionId{std::byte{0x83}};
    refresh_entry.active_connection_id_keys = {"owned-refresh", "foreign-refresh",
                                               "missing-refresh"};
    server_core.connection_id_routes_.emplace("owned-refresh", refresh_entry.handle);
    server_core.connection_id_routes_.emplace("foreign-refresh", 88);
    server_core.initial_destination_routes_.emplace("foreign-refresh-initial", 88);

    server_core.refresh_server_connection_routes(refresh_entry);
    refresh_entry.connection.reset();
    EXPECT_FALSE(server_core.connection_id_routes_.contains("owned-refresh"));
    EXPECT_EQ(server_core.connection_id_routes_.at("foreign-refresh"), 88u);
    EXPECT_EQ(server_core.initial_destination_routes_.at("foreign-refresh-initial"), 88u);
    auto has_refreshed_initial = refresh_entry.initial_destination_connection_id_key.has_value();
    EXPECT_TRUE(has_refreshed_initial);
    if (has_refreshed_initial) {
        EXPECT_NE(refresh_entry.initial_destination_connection_id_key.value(),
                  "foreign-refresh-initial");
    }

    auto refresh_missing_initial =
        make_server_connection_entry(12, std::string("missing-refresh-initial"));
    refresh_missing_initial.connection->local_connection_ids_.clear();
    refresh_missing_initial.connection->local_connection_ids_.emplace(
        0, LocalConnectionIdRecord{
               .sequence_number = 0,
               .connection_id = ConnectionId{std::byte{0x45}},
               .retired = false,
           });
    refresh_missing_initial.connection->client_initial_destination_connection_id_ =
        ConnectionId{std::byte{0x84}};
    refresh_missing_initial.active_connection_id_keys = {"missing-refresh-only"};
    server_core.refresh_server_connection_routes(refresh_missing_initial);
    refresh_missing_initial.connection.reset();
}

TEST(QuicCoreEndpointInternalTest, RetiringRoutesSkipsForeignResetsAndErasesPeerTokens) {
    auto config = make_server_endpoint_config();
    config.retain_stateless_reset_tokens_after_connection_close = false;
    QuicCore server_core(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 9,
    };
    entry.local_stateless_reset_connection_id_keys = {"missing-local-reset", "foreign-local-reset",
                                                      "owned-local-reset"};
    entry.peer_stateless_reset_token_keys = {"missing-peer-reset", "foreign-peer-reset",
                                             "owned-peer-reset"};

    server_core.local_stateless_reset_tokens_by_cid_.emplace(
        "foreign-local-reset", QuicCore::LocalStatelessResetTokenRoute{
                                   .owner = 77,
                               });
    server_core.local_stateless_reset_tokens_by_cid_.emplace(
        "owned-local-reset", QuicCore::LocalStatelessResetTokenRoute{
                                 .owner = entry.handle,
                             });
    server_core.peer_stateless_reset_tokens_.emplace("foreign-peer-reset",
                                                     QuicCore::PeerStatelessResetTokenRoute{
                                                         .owner = 77,
                                                     });
    server_core.peer_stateless_reset_tokens_.emplace("owned-peer-reset",
                                                     QuicCore::PeerStatelessResetTokenRoute{
                                                         .owner = entry.handle,
                                                     });

    server_core.retire_endpoint_connection_routes(entry, coquic::quic::test::test_time(10));

    EXPECT_EQ(server_core.local_stateless_reset_tokens_by_cid_.at("foreign-local-reset").owner,
              77u);
    EXPECT_FALSE(server_core.local_stateless_reset_tokens_by_cid_.contains("owned-local-reset"));
    EXPECT_EQ(server_core.peer_stateless_reset_tokens_.at("foreign-peer-reset").owner, 77u);
    EXPECT_FALSE(server_core.peer_stateless_reset_tokens_.contains("owned-peer-reset"));
}

TEST(QuicCoreEndpointInternalTest,
     SupportedLongHeaderAndRetryGuardsCoverEmptyVersionNegotiationAndRetryReplies) {
    auto empty_versions = make_server_endpoint_config();
    empty_versions.supported_versions.clear();
    QuicCore version_negotiation_server(std::move(empty_versions));

    auto supported_long_header = make_supported_long_header_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        bytes_from_ints({0xc1, 0x01}));
    auto version_negotiation_result = version_negotiation_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = supported_long_header,
            .route_handle = 41,
        },
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(version_negotiation_result.effects.empty());
    EXPECT_FALSE(version_negotiation_result.local_error.has_value());
    EXPECT_EQ(version_negotiation_server.connection_count(), 0u);

    QuicCore short_header_server(make_server_endpoint_config());
    auto short_header_result = short_header_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
            .route_handle = 42,
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(short_header_result.effects.empty());
    EXPECT_FALSE(short_header_result.local_error.has_value());
    EXPECT_EQ(short_header_server.connection_count(), 0u);

    auto retry_config = make_server_endpoint_config();
    retry_config.retry_enabled = true;
    QuicCore retry_server(std::move(retry_config));

    auto oversized_source_connection_id =
        bytes_from_ints({0xc1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                         0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14});
    auto retry_initial = make_supported_initial_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        oversized_source_connection_id, {});
    auto retry_result = retry_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = retry_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(retry_result.effects.empty());
    EXPECT_FALSE(retry_result.local_error.has_value());
    EXPECT_EQ(retry_server.connection_count(), 0u);
    EXPECT_EQ(retry_server.retry_tokens_.size(), 1u);
}

TEST(QuicCoreEndpointInternalTest, ServerIgnoresSupportedHandshakeBeforeClientInitial) {
    QuicCore server(make_server_endpoint_config());
    auto supported_handshake = make_supported_long_header_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        bytes_from_ints({0xc1, 0x01}));

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = supported_handshake,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # Clients are not able to send Handshake packets prior to receiving a
    // # server response, so servers SHOULD ignore any such packets.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # Servers MUST drop incoming packets under all other circumstances.
    EXPECT_TRUE(result.effects.empty());
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, ServerDiscardsSupportedInitialDatagramSmallerThan1200Bytes) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    server_config.retry_enabled = true;
    QuicCore server(std::move(server_config));

    auto undersized_initial = make_supported_initial_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        bytes_from_ints({0xc1, 0x01}), {}, 1199);

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = undersized_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
    // # A server MUST discard an Initial packet that is carried in a UDP
    // # datagram with a payload that is smaller than the smallest allowed
    // # maximum datagram size of 1200 bytes.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # Servers MUST drop smaller packets that specify unsupported versions.
    EXPECT_TRUE(result.effects.empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14
    // # Therefore, an endpoint MUST NOT close a connection when it receives a
    // # datagram that does not meet size constraints; the endpoint MAY discard
    // # such datagrams.
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(server.retry_tokens_.empty());
}

TEST(QuicCoreEndpointInternalTest, ServerCanCloseUndersizedSupportedInitialWithProtocolViolation) {
    auto config = make_server_endpoint_config();
    config.close_on_undersized_initial = true;
    config.retry_enabled = true;
    QuicCore server(std::move(config));

    const auto client_dcid = bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    auto undersized_initial = make_supported_initial_datagram(
        kQuicVersion1, client_dcid, bytes_from_ints({0xc1, 0x01}), {}, 1199);
    const auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = undersized_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    const auto sends = send_effects_from(result);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends.front().route_handle, std::optional<QuicRouteHandle>{55u});
    EXPECT_LE(sends.front().bytes.size(), undersized_initial.size() * 3);
    const auto close_packets = decode_endpoint_initial_datagram(sends.front().bytes, client_dcid);
    ASSERT_EQ(close_packets.size(), 1u);
    const auto *initial_close = std::get_if<ProtectedInitialPacket>(&close_packets.front());
    ASSERT_NE(initial_close, nullptr);
    ASSERT_EQ(initial_close->frames.size(), 1u);
    const auto *close_frame =
        std::get_if<TransportConnectionCloseFrame>(&initial_close->frames.front());
    ASSERT_NE(close_frame, nullptr);
    EXPECT_EQ(close_frame->error_code,
              static_cast<std::uint64_t>(QuicTransportErrorCode::protocol_violation));
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(server.retry_tokens_.empty());
}

TEST(QuicCoreEndpointInternalTest, StrictUndersizedInitialPolicyDropsIneligibleDatagrams) {
    auto config = make_server_endpoint_config();
    config.close_on_undersized_initial = true;
    QuicCore server(std::move(config));

    const auto destination_connection_id =
        bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    const auto source_connection_id = bytes_from_ints({0xc1, 0x01});
    const auto unsupported_initial = make_supported_long_header_datagram(
        0x0a0a0a0a, destination_connection_id, source_connection_id, 1199);
    const auto non_initial = make_supported_long_header_datagram(
        kQuicVersion1, destination_connection_id, source_connection_id, 1199);

    for (const auto &datagram : {unsupported_initial, non_initial}) {
        const auto result =
            server.advance_endpoint(QuicCoreInboundDatagram{.bytes = datagram, .route_handle = 55},
                                    coquic::quic::test::test_time(1));
        EXPECT_TRUE(result.effects.empty());
        EXPECT_FALSE(result.local_error.has_value());
    }
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, StrictUndersizedInitialPolicyAccepts1200ByteInitial) {
    auto config = make_server_endpoint_config();
    config.application_protocol = "coquic";
    config.close_on_undersized_initial = true;
    QuicCore server(std::move(config));

    const auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    const auto lifecycle = lifecycle_events_from(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    EXPECT_EQ(server.connection_count(), 1u);
}

TEST(QuicCoreEndpointInternalTest, ServerDiscardsInitialWithShortDestinationConnectionId) {
    auto server_config = make_server_endpoint_config();
    server_config.retry_enabled = true;
    QuicCore server(std::move(server_config));
    auto initial = make_supported_initial_datagram(kQuicVersion1, bytes_from_ints({0x83, 0x01}),
                                                   bytes_from_ints({0xc1, 0x01}), {});

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 41,
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    // # This Destination Connection ID MUST be at least 8 bytes in length.
    EXPECT_TRUE(result.effects.empty());
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(server.retry_tokens_.empty());
}

TEST(QuicCoreEndpointInternalTest, ServerSendsVersionNegotiationForLargeUnsupportedVersion) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));

    auto unsupported_initial = make_supported_long_header_datagram(
        0x0a0a0a0a, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0}), bytes_from_ints({0xc1, 0x01}), 1200);

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = unsupported_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    const auto sends = send_effects_from(result);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # If a server receives a packet that indicates an unsupported version
    // # and if the packet is large enough to initiate a new connection for
    // # any supported version, the server SHOULD send a Version Negotiation
    // # packet as described in Section 6.1.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # Servers SHOULD respond with a Version
    // # Negotiation packet, provided that the datagram is sufficiently long.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # A server MUST NOT send more than one Version Negotiation packet in
    // # response to a single UDP datagram.
    ASSERT_EQ(sends.size(), 1u);
    auto decoded = deserialize_packet(sends.front().bytes, {});
    ASSERT_TRUE(decoded.has_value());
    auto *version_negotiation = std::get_if<VersionNegotiationPacket>(&decoded.value().packet);
    ASSERT_NE(version_negotiation, nullptr);
    EXPECT_EQ(sends.front().route_handle, std::optional<QuicRouteHandle>{55u});
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest,
     ServerSendsVersionNegotiationForUnsupportedVersionWithLongConnectionIds) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));
    const auto destination_connection_id = std::vector<std::byte>(21, std::byte{0x83});
    const auto source_connection_id = std::vector<std::byte>(21, std::byte{0xc1});

    auto unsupported_initial = make_supported_long_header_datagram(
        0x0a0a0a0a, destination_connection_id, source_connection_id, 1200);

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = unsupported_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1));

    const auto sends = send_effects_from(result);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # Version-specific rules for the connection ID therefore MUST NOT
    // # influence a decision about whether to send a Version Negotiation
    // # packet.
    ASSERT_EQ(sends.size(), 1u);
    auto decoded = deserialize_packet(sends.front().bytes, {});
    ASSERT_TRUE(decoded.has_value());
    auto *version_negotiation = std::get_if<VersionNegotiationPacket>(&decoded.value().packet);
    ASSERT_NE(version_negotiation, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # In order to properly form a Version Negotiation packet, servers
    // # SHOULD be able to read longer connection IDs from other QUIC versions.
    EXPECT_EQ(version_negotiation->destination_connection_id, source_connection_id);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # In order to properly form a Version Negotiation packet, servers
    // # SHOULD be able to read longer connection IDs from other QUIC versions.
    EXPECT_EQ(version_negotiation->source_connection_id, destination_connection_id);
    EXPECT_EQ(sends.front().route_handle, std::optional<QuicRouteHandle>{55u});
    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, RetryTokensUseUnpredictablePerIssueBytes) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    server_config.retry_enabled = true;
    QuicCore server(std::move(server_config));

    auto first_initial = make_supported_initial_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        bytes_from_ints({0xc1, 0x01}), {});
    static_cast<void>(server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = first_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(1)));

    auto second_initial = make_supported_initial_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09}),
        bytes_from_ints({0xc1, 0x02}), {});
    static_cast<void>(server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = second_initial,
            .route_handle = 56,
        },
        coquic::quic::test::test_time(2)));

    ASSERT_EQ(server.retry_tokens_.size(), 2u);
    std::vector<std::vector<std::byte>> tokens;
    for (auto &[key, pending] : server.retry_tokens_) {
        static_cast<void>(key);
        tokens.push_back(pending.token);
    }
    ASSERT_EQ(tokens.size(), 2u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # An address validation token MUST be difficult to guess.
    EXPECT_NE(tokens[0], tokens[1]);
    for (auto &token : tokens) {
        EXPECT_EQ(token.size(), 16u);
        ASSERT_GE(token.size(), 4u);
        EXPECT_NE(std::vector<std::byte>(token.begin(), token.begin() + 4),
                  bytes_from_ints({0x72, 0x74, 0x72, 0x79}));
    }
}

TEST(QuicCoreEndpointInternalTest, NewTokenContextValidatesRouteVersionAndExpiry) {
    QuicCore server(make_server_endpoint_config());
    auto token = server.make_endpoint_new_token(7);
    ASSERT_FALSE(token.empty());

    server.new_tokens_.insert_or_assign(QuicCore::connection_id_key(token),
                                        QuicCore::StoredEndpointNewToken{
                                            .token = token,
                                            .route_handle = 55,
                                            .version = kQuicVersion1,
                                            .expires_at = coquic::quic::test::test_time(1000),
                                            .used = false,
                                        });

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = bytes_from_ints({0x83, 0x01}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion1,
        .token = token,
    };

    EXPECT_FALSE(server
                     .take_new_token_context(parsed, 56, coquic::quic::test::test_time(1),
                                             std::span<const std::byte>{})
                     .has_value());
    EXPECT_EQ(server.new_tokens_.size(), 1u);

    auto wrong_version = parsed;
    wrong_version.version = kQuicVersion2;
    EXPECT_FALSE(server
                     .take_new_token_context(wrong_version, 55, coquic::quic::test::test_time(1),
                                             std::span<const std::byte>{})
                     .has_value());
    EXPECT_EQ(server.new_tokens_.size(), 1u);

    auto validated = server.take_new_token_context(parsed, 55, coquic::quic::test::test_time(1),
                                                   std::span<const std::byte>{});
    auto validated_context = optional_value_or_terminate(validated);
    EXPECT_EQ(validated_context.token, token);
    EXPECT_TRUE(server.new_tokens_.empty());

    auto truncated = parsed;
    truncated.token = bytes_from_ints({0x01, 0x02});
    EXPECT_FALSE(server
                     .take_new_token_context(truncated, 55, coquic::quic::test::test_time(1),
                                             std::span<const std::byte>{})
                     .has_value());
}

TEST(QuicCoreEndpointInternalTest, SealedRetryTokenSurvivesRestartAndBindsRouteIdentityAndCids) {
    auto config = make_server_endpoint_config();
    config.retry_enabled = true;
    config.address_validation_token_secret = make_address_validation_secret(0x30);
    QuicCore original(std::move(config));

    auto destination_connection_id =
        bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
    auto source_connection_id = bytes_from_ints({0xc1, 0x01});
    auto identity = bytes_from_ints({0x7f, 0x00, 0x00, 0x01});
    auto initial = make_supported_initial_datagram(kQuicVersion1, destination_connection_id,
                                                   source_connection_id, {});

    auto retry_result = original.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 55,
            .address_validation_identity = identity,
        },
        coquic::quic::test::test_time(1));
    auto retry_sends = send_effects_from(retry_result);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    // # A server MUST NOT send more than one Retry
    // # packet in response to a single UDP datagram.
    ASSERT_EQ(retry_sends.size(), 1u);
    auto decoded_retry = deserialize_packet(retry_sends.front().bytes.span(), {});
    ASSERT_TRUE(decoded_retry.has_value());
    ASSERT_EQ(decoded_retry.value().bytes_consumed, retry_sends.front().bytes.size());
    auto *retry_packet = std::get_if<RetryPacket>(&decoded_retry.value().packet);
    ASSERT_NE(retry_packet, nullptr);
    EXPECT_GT(retry_packet->retry_token.size(), 48u);
    EXPECT_EQ(original.retry_tokens_.size(), 1u);

    auto restarted_config = make_server_endpoint_config();
    restarted_config.retry_enabled = true;
    restarted_config.address_validation_token_secret = make_address_validation_secret(0x30);
    QuicCore restarted(std::move(restarted_config));
    ASSERT_TRUE(restarted.retry_tokens_.empty());

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = retry_packet->source_connection_id,
        .source_connection_id = source_connection_id,
        .version = kQuicVersion1,
        .token = retry_packet->retry_token,
    };

    EXPECT_FALSE(
        restarted.take_new_token_context(parsed, 55, coquic::quic::test::test_time(2), identity)
            .has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.1
    // # A token sent in a NEW_TOKEN frame or a Retry packet MUST be
    // # constructed in a way that allows the server to identify how it was
    // # provided to a client.
    EXPECT_FALSE(
        restarted.take_retry_context(parsed, 56, coquic::quic::test::test_time(2), identity)
            .has_value());
    EXPECT_FALSE(restarted
                     .take_retry_context(parsed, 55, coquic::quic::test::test_time(2),
                                         bytes_from_ints({0x7f, 0x00, 0x00, 0x02}))
                     .has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # Tokens sent in Retry packets SHOULD include information that allows
    // # the server to verify that the source IP address and port in client
    // # packets remain constant.
    auto wrong_destination = parsed;
    wrong_destination.destination_connection_id = bytes_from_ints({0x53, 0xaa});
    EXPECT_FALSE(
        restarted
            .take_retry_context(wrong_destination, 55, coquic::quic::test::test_time(2), identity)
            .has_value());

    auto accepted =
        restarted.take_retry_context(parsed, 55, coquic::quic::test::test_time(2), identity);
    auto accepted_retry = optional_value_or_terminate(accepted);
    EXPECT_EQ(accepted_retry.original_destination_connection_id, destination_connection_id);
    EXPECT_EQ(accepted_retry.retry_source_connection_id, retry_packet->source_connection_id);
    EXPECT_EQ(accepted_retry.address_validation_identity, identity);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # To protect against such attacks, servers MUST ensure that replay of
    // # tokens is prevented or limited.
    EXPECT_FALSE(
        restarted.take_retry_context(parsed, 55, coquic::quic::test::test_time(3), identity)
            .has_value());

    auto expired_restarted_config = make_server_endpoint_config();
    expired_restarted_config.retry_enabled = true;
    expired_restarted_config.address_validation_token_secret = make_address_validation_secret(0x30);
    QuicCore expired_restarted(std::move(expired_restarted_config));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
    // # Servers SHOULD provide mitigations for this attack by limiting the
    // # usage and lifetime of address validation tokens; see Section 8.1.3.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # Servers SHOULD ensure that tokens sent in Retry packets are only
    // # accepted for a short time, as they are returned immediately by clients.
    EXPECT_FALSE(
        expired_restarted
            .take_retry_context(parsed, 55, coquic::quic::test::test_time(12'001), identity)
            .has_value());
}

TEST(QuicCoreEndpointInternalTest, SealedNewTokenSurvivesRestartAndIsSingleUse) {
    auto config = make_server_endpoint_config();
    config.address_validation_token_secret = make_address_validation_secret(0x40);
    QuicCore original(std::move(config));
    auto identity = bytes_from_ints({0x20, 0x01, 0x0d, 0xb8});
    auto token = original.make_endpoint_new_token(9, kQuicVersion1, 77, identity,
                                                  coquic::quic::test::test_time(100));
    ASSERT_GT(token.size(), 48u);
    ASSERT_TRUE(original.new_tokens_.empty());

    auto restarted_config = make_server_endpoint_config();
    restarted_config.address_validation_token_secret = make_address_validation_secret(0x40);
    QuicCore restarted(std::move(restarted_config));
    ASSERT_TRUE(restarted.new_tokens_.empty());

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = bytes_from_ints({0x83, 0x01}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion1,
        .token = token,
    };

    EXPECT_FALSE(
        restarted.take_new_token_context(parsed, 78, coquic::quic::test::test_time(101), identity)
            .has_value());
    EXPECT_FALSE(restarted
                     .take_new_token_context(parsed, 77, coquic::quic::test::test_time(101),
                                             bytes_from_ints({0x20, 0x01, 0x0d, 0xb9}))
                     .has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # Tokens sent in NEW_TOKEN frames MUST include information that allows
    // # the server to verify that the client IP address has not changed from
    // # when the token was issued.

    auto wrong_version = parsed;
    wrong_version.version = kQuicVersion2;
    EXPECT_FALSE(
        restarted
            .take_new_token_context(wrong_version, 77, coquic::quic::test::test_time(101), identity)
            .has_value());

    auto expired_config = make_server_endpoint_config();
    expired_config.address_validation_token_secret = make_address_validation_secret(0x40);
    QuicCore expired(std::move(expired_config));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
    // # Servers SHOULD provide mitigations for this attack by limiting the
    // # usage and lifetime of address validation tokens; see Section 8.1.3.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # Thus, a token SHOULD have an expiration time, which could be either an
    // # explicit expiration time or an issued timestamp that can be used to
    // # dynamically calculate the expiration time.
    EXPECT_FALSE(
        expired
            .take_new_token_context(
                parsed, 77, coquic::quic::test::test_time(24 * 60 * 60 * 1000 + 101), identity)
            .has_value());

    auto accepted =
        restarted.take_new_token_context(parsed, 77, coquic::quic::test::test_time(101), identity);
    auto accepted_token = optional_value_or_terminate(accepted);
    EXPECT_EQ(accepted_token.route_handle, std::optional<QuicRouteHandle>{77u});
    EXPECT_EQ(accepted_token.address_validation_identity, identity);
    EXPECT_TRUE(accepted_token.used);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
    // # Servers SHOULD provide mitigations for this attack by limiting the
    // # usage and lifetime of address validation tokens; see Section 8.1.3.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # Tokens that are provided in NEW_TOKEN frames (Section 19.7) need to be
    // # valid for longer but SHOULD NOT be accepted multiple times.
    EXPECT_FALSE(
        restarted.take_new_token_context(parsed, 77, coquic::quic::test::test_time(102), identity)
            .has_value());

    auto tampered_config = make_server_endpoint_config();
    tampered_config.address_validation_token_secret = make_address_validation_secret(0x40);
    QuicCore tampered_server(std::move(tampered_config));
    auto tampered = parsed;
    tampered.token.back() =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered.token.back()) ^ 0x01u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # For this design to work, the token MUST be covered by integrity
    // # protection against modification or falsification by clients.
    EXPECT_FALSE(
        tampered_server
            .take_new_token_context(tampered, 77, coquic::quic::test::test_time(101), identity)
            .has_value());

    auto truncated = parsed;
    truncated.token.resize(20);
    EXPECT_FALSE(
        tampered_server
            .take_new_token_context(truncated, 77, coquic::quic::test::test_time(101), identity)
            .has_value());

    auto accept_server_config = make_server_endpoint_config();
    accept_server_config.address_validation_token_secret = make_address_validation_secret(0x40);
    QuicCore accept_server(std::move(accept_server_config));
    auto accept_open = make_client_open_config(4);
    accept_open.retry_token = original.make_endpoint_new_token(10, kQuicVersion1, 91, identity,
                                                               coquic::quic::test::test_time(100));
    QuicCore accept_client(make_client_endpoint_config());
    auto client_initial = accept_client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(accept_open),
            .initial_route_handle = 91,
        },
        coquic::quic::test::test_time(101));
    auto initial_sends = send_effects_from(client_initial);
    ASSERT_FALSE(initial_sends.empty());
    auto accepted_initial = accept_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial_sends.front().bytes,
            .route_handle = 91,
            .address_validation_identity = identity,
        },
        coquic::quic::test::test_time(102));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # When a server receives an Initial packet with an address validation
    // # token, it MUST attempt to validate the token, unless it has already
    // # completed address validation.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # If the validation succeeds, the server SHOULD then allow the handshake
    // # to proceed.
    auto accept_lifecycle = lifecycle_events_from(accepted_initial);
    ASSERT_FALSE(accept_lifecycle.empty());
    EXPECT_EQ(accept_lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);

    auto changed_address_server_config = make_server_endpoint_config();
    changed_address_server_config.application_protocol = "coquic";
    changed_address_server_config.address_validation_token_secret =
        make_address_validation_secret(0x40);
    QuicCore changed_address_server(std::move(changed_address_server_config));
    auto changed_address_open = make_client_open_config(5);
    changed_address_open.retry_token = original.make_endpoint_new_token(
        11, kQuicVersion1, 92, identity, coquic::quic::test::test_time(100));
    QuicCore changed_address_client(make_client_endpoint_config());
    auto changed_address_initial = changed_address_client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(changed_address_open),
            .initial_route_handle = 92,
        },
        coquic::quic::test::test_time(101));
    auto changed_address_sends = send_effects_from(changed_address_initial);
    ASSERT_FALSE(changed_address_sends.empty());
    auto changed_address_result = changed_address_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = changed_address_sends.front().bytes,
            .route_handle = 92,
            .address_validation_identity = bytes_from_ints({0x20, 0x01, 0x0d, 0xba}),
        },
        coquic::quic::test::test_time(102));
    auto changed_address_lifecycle = lifecycle_events_from(changed_address_result);
    ASSERT_FALSE(changed_address_lifecycle.empty());
    ASSERT_EQ(changed_address_server.connection_count(), 1u);
    const auto changed_handle = changed_address_lifecycle.front().connection;
    auto &changed_connection = *changed_address_server.connections_.at(changed_handle).connection;
    EXPECT_FALSE(changed_connection.peer_address_validated_);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # If the client IP address has changed, the server MUST adhere to the
    // # anti-amplification limit; see Section 8.
    EXPECT_TRUE(changed_connection.anti_amplification_applies());
    EXPECT_EQ(changed_connection.anti_amplification_send_budget(),
              changed_connection.anti_amplification_received_bytes_ * 3u);
}

TEST(QuicCoreEndpointInternalTest, SealedNewTokenCanValidateWithPreviousSecret) {
    auto issuer_config = make_server_endpoint_config();
    issuer_config.address_validation_token_secret = make_address_validation_secret(0x50);
    QuicCore issuer(std::move(issuer_config));
    auto identity = bytes_from_ints({0x0a, 0x00, 0x00, 0x01});
    auto token = issuer.make_endpoint_new_token(5, kQuicVersion1, 9, identity,
                                                coquic::quic::test::test_time(20));
    ASSERT_FALSE(token.empty());

    auto rotated_config = make_server_endpoint_config();
    rotated_config.address_validation_token_secret = make_address_validation_secret(0x60);
    rotated_config.previous_address_validation_token_secrets.push_back(
        make_address_validation_secret(0x50));
    QuicCore rotated(std::move(rotated_config));

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = bytes_from_ints({0x83, 0x01}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion1,
        .token = token,
    };
    EXPECT_TRUE(
        rotated.take_new_token_context(parsed, 9, coquic::quic::test::test_time(21), identity)
            .has_value());

    auto unbound_token = issuer.make_endpoint_new_token(6, kQuicVersion1, std::nullopt, identity,
                                                        coquic::quic::test::test_time(20));
    ASSERT_FALSE(unbound_token.empty());
    auto unbound_parsed = parsed;
    unbound_parsed.token = unbound_token;
    EXPECT_TRUE(
        rotated
            .take_new_token_context(unbound_parsed, 10, coquic::quic::test::test_time(21), identity)
            .has_value());
}

TEST(QuicCoreEndpointInternalTest, AddressValidationReplayStoreSurvivesEndpointRestart) {
    auto replay_store = make_replay_store_path_for_test("address-validation-replay");
    auto issuer_config = make_server_endpoint_config();
    issuer_config.address_validation_token_secret = make_address_validation_secret(0x70);
    issuer_config.address_validation_replay_store_path = replay_store;

    auto identity = bytes_from_ints({0xc0, 0xa8, 0x00, 0x01});
    auto token = [&] {
        QuicCore issuer(issuer_config);
        return issuer.make_endpoint_new_token(11, kQuicVersion1, 42, identity,
                                              coquic::quic::test::test_time(30));
    }();
    ASSERT_FALSE(token.empty());

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = bytes_from_ints({0x83, 0x01}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion1,
        .token = token,
    };

    auto first_config = make_server_endpoint_config();
    first_config.address_validation_token_secret = make_address_validation_secret(0x70);
    first_config.address_validation_replay_store_path = replay_store;
    QuicCore first(std::move(first_config));
    EXPECT_TRUE(
        first.take_new_token_context(parsed, 42, coquic::quic::test::test_time(31), identity)
            .has_value());
    ASSERT_TRUE(std::filesystem::exists(replay_store));

    auto restarted_config = make_server_endpoint_config();
    restarted_config.address_validation_token_secret = make_address_validation_secret(0x70);
    restarted_config.address_validation_replay_store_path = replay_store;
    QuicCore restarted(std::move(restarted_config));
    EXPECT_FALSE(
        restarted.take_new_token_context(parsed, 42, coquic::quic::test::test_time(32), identity)
            .has_value());

    auto after_expiry_config = make_server_endpoint_config();
    after_expiry_config.address_validation_token_secret = make_address_validation_secret(0x70);
    after_expiry_config.address_validation_replay_store_path = replay_store;
    QuicCore after_expiry(std::move(after_expiry_config));
    EXPECT_FALSE(
        after_expiry
            .take_new_token_context(
                parsed, 42, coquic::quic::test::test_time(24 * 60 * 60 * 1000 + 32), identity)
            .has_value());
    EXPECT_TRUE(after_expiry.consumed_address_validation_tokens_.empty());

    std::error_code ignored;
    std::filesystem::remove(replay_store, ignored);
}

TEST(QuicCoreEndpointInternalTest, AddressValidationReplayStoreIgnoresMalformedLines) {
    auto replay_store = make_replay_store_path_for_test("address-validation-replay-malformed");
    {
        std::ofstream output(replay_store, std::ios::trunc);
        ASSERT_TRUE(output.is_open());
        output << "missing-separator\n";
        output << "zz 123\n";
        output << "616263 not-a-number\n";
        output << " 456\n";
        output << "616263 789\n";
    }

    auto config = make_server_endpoint_config();
    config.address_validation_replay_store_path = replay_store;
    QuicCore server(std::move(config));

    ASSERT_EQ(server.consumed_address_validation_tokens_.size(), 1u);
    EXPECT_TRUE(server.consumed_address_validation_tokens_.contains("abc"));
    EXPECT_EQ(server.consumed_address_validation_tokens_.at("abc"),
              QuicCoreTimePoint{} + QuicCoreDuration(789));

    std::error_code ignored;
    std::filesystem::remove(replay_store, ignored);
}

TEST(QuicCoreEndpointInternalTest, StoredRetryAndNewTokensRejectAlreadyConsumedReplay) {
    QuicCore server(make_server_endpoint_config());
    auto identity = bytes_from_ints({0xc0, 0xa8, 0x00, 0x01});

    QuicCore::PendingRetryToken pending_retry{
        .original_destination_connection_id = bytes_from_ints({0x83, 0x01}),
        .retry_source_connection_id = bytes_from_ints({0x53, 0x01}),
        .original_version = kQuicVersion1,
        .token = bytes_from_ints({0xaa, 0xbb, 0xcc}),
        .route_handle = 55,
        .address_validation_identity = identity,
        .expires_at = coquic::quic::test::test_time(100),
    };
    server.retry_tokens_.insert_or_assign(QuicCore::connection_id_key(pending_retry.token),
                                          pending_retry);
    server.mark_address_validation_token_consumed(pending_retry.token,
                                                  coquic::quic::test::test_time(100));

    QuicCore::ParsedEndpointDatagram retry_parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = pending_retry.retry_source_connection_id,
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion1,
        .token = pending_retry.token,
    };
    EXPECT_FALSE(
        server.take_retry_context(retry_parsed, 55, coquic::quic::test::test_time(1), identity)
            .has_value());
    EXPECT_TRUE(server.retry_tokens_.contains(QuicCore::connection_id_key(pending_retry.token)));

    auto new_token = bytes_from_ints({0x4e, 0x11, 0x22});
    server.new_tokens_.insert_or_assign(QuicCore::connection_id_key(new_token),
                                        QuicCore::StoredEndpointNewToken{
                                            .token = new_token,
                                            .route_handle = 55,
                                            .address_validation_identity = identity,
                                            .version = kQuicVersion1,
                                            .expires_at = coquic::quic::test::test_time(100),
                                            .used = false,
                                        });
    server.mark_address_validation_token_consumed(new_token, coquic::quic::test::test_time(100));

    auto new_token_parsed = retry_parsed;
    new_token_parsed.destination_connection_id = bytes_from_ints({0x83, 0x02});
    new_token_parsed.token = new_token;
    EXPECT_FALSE(server
                     .take_new_token_context(new_token_parsed, 55, coquic::quic::test::test_time(1),
                                             identity)
                     .has_value());
    EXPECT_TRUE(server.new_tokens_.contains(QuicCore::connection_id_key(new_token)));
}

TEST(QuicCoreEndpointInternalTest, NewTokensUseIndependentPerIssueBytes) {
    QuicCore stateful_server(make_server_endpoint_config());
    auto first_stateful = stateful_server.make_endpoint_new_token(
        1, kQuicVersion1, 55, std::span<const std::byte>{}, coquic::quic::test::test_time(1));
    auto second_stateful = stateful_server.make_endpoint_new_token(
        2, kQuicVersion1, 55, std::span<const std::byte>{}, coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_stateful.empty());
    ASSERT_FALSE(second_stateful.empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A server MUST ensure that every NEW_TOKEN frame it sends is unique
    // # across all clients, with the exception of those sent to repair losses
    // # of previously sent NEW_TOKEN frames.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A token issued with NEW_TOKEN MUST NOT include information that would
    // # allow values to be linked by an observer to the connection on which it
    // # was issued.
    EXPECT_NE(first_stateful, second_stateful);

    auto sealed_config = make_server_endpoint_config();
    sealed_config.address_validation_token_secret = make_address_validation_secret(0x4e);
    QuicCore sealed_server(std::move(sealed_config));
    auto identity = make_ipv4_identity(198, 51, 100, 9, 4433);
    auto first_sealed = sealed_server.make_endpoint_new_token(3, kQuicVersion1, 56, identity,
                                                              coquic::quic::test::test_time(1));
    auto second_sealed = sealed_server.make_endpoint_new_token(4, kQuicVersion1, 56, identity,
                                                               coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_sealed.empty());
    ASSERT_FALSE(second_sealed.empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A server MUST ensure that every NEW_TOKEN frame it sends is unique
    // # across all clients, with the exception of those sent to repair losses
    // # of previously sent NEW_TOKEN frames.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A token issued with NEW_TOKEN MUST NOT include information that would
    // # allow values to be linked by an observer to the connection on which it
    // # was issued.
    EXPECT_NE(first_sealed, second_sealed);
}

TEST(QuicCoreEndpointInternalTest, RouteIdentityHelpersReuseStoredIdentityAndRejectDowngrade) {
    auto config = make_client_endpoint_config();
    config.allow_peer_address_change = true;
    config.request_forgery_policy.reject_address_space_downgrade = true;
    QuicCore client(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 7,
    };
    entry.connection =
        std::make_unique<QuicConnection>(coquic::quic::test::make_client_core_config());
    entry.connection->current_send_path_id_ = 0;
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    auto public_identity = make_ipv4_identity(198, 51, 100, 7, 4433);
    entry.address_validation_identity_by_path_id.emplace(0, public_identity);

    EXPECT_EQ(client.effective_address_validation_identity_for_route(entry, 17,
                                                                     std::span<const std::byte>{}),
              public_identity);
    EXPECT_TRUE(client
                    .effective_address_validation_identity_for_route(entry, 18,
                                                                     std::span<const std::byte>{})
                    .empty());
    auto proposed_identity = make_ipv4_identity(203, 0, 113, 8, 4433);
    EXPECT_EQ(client.effective_address_validation_identity_for_route(entry, 18, proposed_identity),
              proposed_identity);

    entry.connection->current_send_path_id_.reset();
    EXPECT_TRUE(client.current_address_validation_identity(entry).empty());
    entry.connection->current_send_path_id_ = 9;
    EXPECT_TRUE(client.current_address_validation_identity(entry).empty());
    entry.connection->current_send_path_id_ = 0;

    auto rejected_private =
        client.path_id_for_inbound_route(entry, 29, make_ipv4_identity(192, 168, 0, 10, 4433));
    EXPECT_FALSE(rejected_private.has_value());
    EXPECT_FALSE(entry.path_id_by_route_handle.contains(29));
}

TEST(QuicCoreEndpointInternalTest, PortOnlyRebindingSelectsRecoveryRetentionPolicy) {
    auto config = make_server_endpoint_config();
    config.allow_peer_address_change = true;
    QuicCore server(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 7,
    };
    entry.connection = std::make_unique<QuicConnection>(make_connected_server_connection());
    entry.default_route_handle = 17;
    entry.connection->current_send_path_id_ = 0;
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    entry.address_validation_identity_by_path_id.emplace(0,
                                                         make_ipv4_identity(198, 51, 100, 7, 4433));

    EXPECT_EQ(server.recovery_reset_policy_for_peer_address_change(
                  entry, make_ipv4_identity(198, 51, 100, 7, 9443)),
              QuicPathRecoveryResetPolicy::retain_congestion_and_rtt);
    EXPECT_EQ(server.recovery_reset_policy_for_peer_address_change(
                  entry, make_ipv4_identity(198, 51, 100, 8, 9443)),
              QuicPathRecoveryResetPolicy::reset);
    EXPECT_EQ(
        server.recovery_reset_policy_for_peer_address_change(entry, std::span<const std::byte>{}),
        QuicPathRecoveryResetPolicy::reset);
}

TEST(QuicCoreEndpointInternalTest, NewPortOnlyInboundRouteStoresRecoveryRetentionPolicy) {
    auto config = make_server_endpoint_config();
    config.allow_peer_address_change = true;
    QuicCore server(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 7,
    };
    entry.connection = std::make_unique<QuicConnection>(make_connected_server_connection());
    entry.default_route_handle = 17;
    entry.connection->current_send_path_id_ = 0;
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    entry.address_validation_identity_by_path_id.emplace(0,
                                                         make_ipv4_identity(198, 51, 100, 7, 4433));

    const auto port_only_path =
        server.path_id_for_inbound_route(entry, 18, make_ipv4_identity(198, 51, 100, 7, 9443));

    ASSERT_TRUE(port_only_path.has_value());
    const auto path_id = optional_value_or_terminate(port_only_path);
    EXPECT_EQ(entry.connection->paths_.at(path_id).recovery_reset_policy,
              QuicPathRecoveryResetPolicy::retain_congestion_and_rtt);
    EXPECT_EQ(entry.connection->paths_.at(path_id).recovery_reset_policy_source_path_id, 0u);

    const auto ip_change_path =
        server.path_id_for_inbound_route(entry, 19, make_ipv4_identity(198, 51, 100, 8, 9443));

    ASSERT_TRUE(ip_change_path.has_value());
    EXPECT_EQ(entry.connection->paths_.at(optional_value_or_terminate(ip_change_path))
                  .recovery_reset_policy,
              QuicPathRecoveryResetPolicy::reset);
}

TEST(QuicCoreEndpointInternalTest, PortOnlyInboundValidationRetainsRecoveryPolicy) {
    auto config = make_server_endpoint_config();
    config.allow_peer_address_change = true;
    QuicCore server(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 7,
    };
    entry.connection = std::make_unique<QuicConnection>(make_connected_server_connection());
    entry.default_route_handle = 17;
    entry.connection->current_send_path_id_ = 0;
    entry.connection->ensure_path_state(0).validated = true;
    entry.connection->ensure_path_state(0).is_current_send_path = true;
    entry.connection->congestion_controller_.congestion_window_ = 48000;
    entry.connection->congestion_controller_.bytes_in_flight_ = 4800;
    entry.connection->recovery_rtt_state_.latest_rtt = std::chrono::milliseconds(42);
    entry.connection->recovery_rtt_state_.min_rtt = std::chrono::milliseconds(30);
    entry.connection->recovery_rtt_state_.smoothed_rtt = std::chrono::milliseconds(36);
    entry.connection->recovery_rtt_state_.rttvar = std::chrono::milliseconds(6);
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    entry.address_validation_identity_by_path_id.emplace(0,
                                                         make_ipv4_identity(198, 51, 100, 7, 4433));

    const auto port_only_path =
        server.path_id_for_inbound_route(entry, 18, make_ipv4_identity(198, 51, 100, 7, 9443));
    ASSERT_TRUE(port_only_path.has_value());
    const auto path_id = optional_value_or_terminate(port_only_path);

    auto first_packet = entry.connection->process_inbound_application(
        std::array<Frame, 1>{PingFrame{}}, coquic::quic::test::test_time(1),
        /*allow_preconnected_frames=*/false, path_id);
    ASSERT_TRUE(first_packet.has_value());

    ASSERT_TRUE(entry.connection->paths_.contains(path_id));
    ASSERT_TRUE(entry.connection->paths_.at(path_id).outstanding_challenge.has_value());
    const auto challenge =
        optional_value_or_terminate(entry.connection->paths_.at(path_id).outstanding_challenge);
    EXPECT_EQ(entry.connection->paths_.at(path_id).recovery_reset_policy,
              QuicPathRecoveryResetPolicy::retain_congestion_and_rtt);
    EXPECT_EQ(entry.connection->current_send_path_id_, path_id);
    EXPECT_EQ(entry.connection->congestion_controller_.congestion_window(), 48000u);
    EXPECT_EQ(entry.connection->congestion_controller_.bytes_in_flight(), 4800u);
    EXPECT_EQ(entry.connection->recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(42));
    EXPECT_EQ(entry.connection->recovery_rtt_state_.min_rtt, std::chrono::milliseconds(30));
    EXPECT_EQ(entry.connection->recovery_rtt_state_.smoothed_rtt, std::chrono::milliseconds(36));
    EXPECT_EQ(entry.connection->recovery_rtt_state_.rttvar, std::chrono::milliseconds(6));

    auto validated = entry.connection->process_inbound_application(
        std::array<Frame, 1>{PathResponseFrame{.data = challenge}},
        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false, path_id);
    ASSERT_TRUE(validated.has_value());

    EXPECT_TRUE(entry.connection->paths_.at(path_id).validated);
    EXPECT_EQ(entry.connection->congestion_controller_.congestion_window(), 48000u);
    EXPECT_EQ(entry.connection->congestion_controller_.bytes_in_flight(), 4800u);
    EXPECT_EQ(entry.connection->recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(42));
    EXPECT_EQ(entry.connection->recovery_rtt_state_.min_rtt, std::chrono::milliseconds(30));
    EXPECT_EQ(entry.connection->recovery_rtt_state_.smoothed_rtt, std::chrono::milliseconds(36));
}

TEST(QuicCoreEndpointInternalTest, IpChangeInboundValidationResetsRecoveryPolicy) {
    auto config = make_server_endpoint_config();
    config.allow_peer_address_change = true;
    QuicCore server(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 7,
    };
    entry.connection = std::make_unique<QuicConnection>(make_connected_server_connection());
    entry.default_route_handle = 17;
    entry.connection->current_send_path_id_ = 0;
    entry.connection->ensure_path_state(0).validated = true;
    entry.connection->ensure_path_state(0).is_current_send_path = true;
    entry.connection->congestion_controller_.bytes_in_flight_ = 4800;
    entry.connection->recovery_rtt_state_.latest_rtt = std::chrono::milliseconds(42);
    entry.connection->recovery_rtt_state_.min_rtt = std::chrono::milliseconds(30);
    entry.connection->recovery_rtt_state_.smoothed_rtt = std::chrono::milliseconds(36);
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);
    entry.address_validation_identity_by_path_id.emplace(0,
                                                         make_ipv4_identity(198, 51, 100, 7, 4433));

    const auto ip_change_path =
        server.path_id_for_inbound_route(entry, 18, make_ipv4_identity(198, 51, 100, 8, 9443));
    ASSERT_TRUE(ip_change_path.has_value());
    const auto path_id = optional_value_or_terminate(ip_change_path);

    auto first_packet = entry.connection->process_inbound_application(
        std::array<Frame, 1>{PingFrame{}}, coquic::quic::test::test_time(1),
        /*allow_preconnected_frames=*/false, path_id);
    ASSERT_TRUE(first_packet.has_value());

    ASSERT_TRUE(entry.connection->paths_.contains(path_id));
    ASSERT_TRUE(entry.connection->paths_.at(path_id).outstanding_challenge.has_value());
    const auto challenge =
        optional_value_or_terminate(entry.connection->paths_.at(path_id).outstanding_challenge);
    EXPECT_EQ(entry.connection->paths_.at(path_id).recovery_reset_policy,
              QuicPathRecoveryResetPolicy::reset);

    auto validated = entry.connection->process_inbound_application(
        std::array<Frame, 1>{PathResponseFrame{.data = challenge}},
        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false, path_id);
    ASSERT_TRUE(validated.has_value());

    EXPECT_TRUE(entry.connection->paths_.at(path_id).validated);
    EXPECT_EQ(entry.connection->congestion_controller_.bytes_in_flight(), 0u);
    EXPECT_EQ(entry.connection->recovery_rtt_state_.latest_rtt, std::nullopt);
    EXPECT_EQ(entry.connection->recovery_rtt_state_.min_rtt, std::nullopt);
    EXPECT_EQ(entry.connection->recovery_rtt_state_.smoothed_rtt, std::chrono::milliseconds(333));
}

TEST(QuicCoreEndpointInternalTest, ClientRejectsUnknownInboundServerRoute) {
    auto config = make_client_endpoint_config();
    config.allow_peer_address_change = true;
    QuicCore client(std::move(config));

    QuicCore::ConnectionEntry entry{
        .handle = 7,
    };
    entry.connection = std::make_unique<QuicConnection>(make_connected_client_connection());
    entry.default_route_handle = 17;
    entry.path_id_by_route_handle.emplace(17, 0);
    entry.route_handle_by_path_id.emplace(0, 17);

    const auto unknown_path =
        client.path_id_for_inbound_route(entry, 18, make_ipv4_identity(198, 51, 100, 8, 4433));
    EXPECT_FALSE(unknown_path.has_value());
    EXPECT_FALSE(entry.path_id_by_route_handle.contains(18));

    entry.path_id_by_route_handle.emplace(19, 1);
    entry.route_handle_by_path_id.emplace(1, 19);
    const auto client_initiated_path =
        client.path_id_for_inbound_route(entry, 19, make_ipv4_identity(198, 51, 100, 9, 4433));
    ASSERT_TRUE(client_initiated_path.has_value());
    EXPECT_EQ(optional_value_or_terminate(client_initiated_path), 1u);
}

TEST(QuicCoreEndpointInternalTest, RequestForgeryPolicyRejectsUnsafeInitialRoutes) {
    auto config = make_client_endpoint_config();
    config.request_forgery_policy.reject_loopback_addresses = true;
    config.request_forgery_policy.blocked_udp_ports = {53};
    QuicCore client(std::move(config));

    auto loopback = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 7,
            .address_validation_identity = make_ipv4_identity(127, 0, 0, 1, 4433),
        },
        coquic::quic::test::test_time(1));
    auto loopback_error = optional_value_or_terminate(loopback.local_error);
    EXPECT_EQ(loopback_error.code, QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_EQ(client.connection_count(), 0u);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.5.6
    // # Endpoints SHOULD NOT refuse to use an address unless they have specific
    // # knowledge about the network indicating that sending datagrams to
    // # unvalidated addresses in a given range is not safe.
    auto blocked_port = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 8,
            .address_validation_identity = make_ipv4_identity(198, 51, 100, 7, 53),
        },
        coquic::quic::test::test_time(2));
    auto blocked_port_error = optional_value_or_terminate(blocked_port.local_error);
    EXPECT_EQ(blocked_port_error.code, QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_EQ(client.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, RequestForgeryPolicyRejectsUnsafeServerInitialRoutes) {
    auto config = make_server_endpoint_config();
    config.application_protocol = "coquic";
    config.retry_enabled = true;
    config.request_forgery_policy.reject_private_use_addresses = true;
    config.request_forgery_policy.blocked_udp_ports = {53};
    QuicCore server(std::move(config));

    auto private_initial = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 41,
            .address_validation_identity = make_ipv4_identity(192, 168, 0, 10, 4433),
        },
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(private_initial.effects.empty());
    EXPECT_FALSE(private_initial.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(server.retry_tokens_.empty());

    auto blocked_port_initial = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
            .route_handle = 42,
            .address_validation_identity = make_ipv4_identity(198, 51, 100, 10, 53),
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(blocked_port_initial.effects.empty());
    EXPECT_FALSE(blocked_port_initial.local_error.has_value());
    EXPECT_EQ(server.connection_count(), 0u);
    EXPECT_TRUE(server.retry_tokens_.empty());
}

TEST(QuicCoreEndpointInternalTest, RequestForgeryPolicyRejectsUnsafeNewRoutes) {
    auto config = make_client_endpoint_config();
    config.request_forgery_policy.reject_address_space_downgrade = true;
    config.request_forgery_policy.reject_link_local_addresses = true;
    QuicCore client(std::move(config));

    static_cast<void>(client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
            .address_validation_identity = make_ipv4_identity(198, 51, 100, 1, 4433),
        },
        coquic::quic::test::test_time(1)));
    ASSERT_TRUE(client.connections_.contains(1));
    auto &entry = client.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->current_send_path_id_ = 0;

    auto private_migration = client.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = QuicMigrationRequestReason::active,
                    .address_validation_identity = make_ipv4_identity(192, 168, 0, 5, 4433),
                },
        },
        coquic::quic::test::test_time(2));
    auto private_migration_error = optional_value_or_terminate(private_migration.local_error);
    EXPECT_EQ(private_migration_error.code, QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_FALSE(entry.path_id_by_route_handle.contains(29));

    auto loopback_migration = client.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreRequestConnectionMigration{
                    .route_handle = 30,
                    .reason = QuicMigrationRequestReason::active,
                    .address_validation_identity = make_ipv4_identity(127, 0, 0, 1, 4433),
                },
        },
        coquic::quic::test::test_time(3));
    auto loopback_migration_error = optional_value_or_terminate(loopback_migration.local_error);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.5.6
    // # Endpoints SHOULD NOT allow connections or migration to a
    // # loopback address if the same service was previously available
    // # at a different interface or if the address was provided by a
    // # service at a non-loopback address.
    EXPECT_EQ(loopback_migration_error.code, QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_FALSE(entry.path_id_by_route_handle.contains(30));

    auto link_local_inbound = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0xa1, 0xb2, 0x00, 0x00}),
            .route_handle = 31,
            .address_validation_identity =
                make_ipv6_identity({0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
                                   4433),
        },
        coquic::quic::test::test_time(4));
    EXPECT_TRUE(link_local_inbound.effects.empty());
    EXPECT_FALSE(entry.path_id_by_route_handle.contains(31));
}

TEST(QuicCoreEndpointInternalTest,
     PreferredAddressMigrationRejectsRouteFamilyWithoutAdvertisedPreferredAddress) {
    auto config = make_client_endpoint_config();
    config.allow_peer_address_change = true;
    QuicCore client(std::move(config));

    static_cast<void>(client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
            .address_validation_identity = make_ipv4_identity(198, 51, 100, 1, 4433),
        },
        coquic::quic::test::test_time(1)));
    ASSERT_TRUE(client.connections_.contains(1));
    auto &entry = client.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->current_send_path_id_ = 0;
    auto &peer_parameters = optional_ref_or_terminate(entry.connection->peer_transport_parameters_);
    peer_parameters.active_connection_id_limit = 8;
    peer_parameters.preferred_address = PreferredAddress{
        .ipv4_address = {std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2}},
        .ipv4_port = 4433,
        .connection_id = bytes_from_ints({0x41, 0x42}),
    };

    auto ipv6_migration = client.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = QuicMigrationRequestReason::preferred_address,
                    .address_validation_identity =
                        make_ipv6_identity({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
                                           4433),
                },
        },
        coquic::quic::test::test_time(2));

    auto ipv6_migration_error = optional_value_or_terminate(ipv6_migration.local_error);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.3
    // # A client that migrates to a new address SHOULD use a preferred
    // # address from the same address family for the server.
    EXPECT_EQ(ipv6_migration_error.code, QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_FALSE(entry.path_id_by_route_handle.contains(29));

    auto ipv4_migration = client.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreRequestConnectionMigration{
                    .route_handle = 30,
                    .reason = QuicMigrationRequestReason::preferred_address,
                    .address_validation_identity = make_ipv4_identity(198, 51, 100, 2, 4433),
                },
        },
        coquic::quic::test::test_time(3));

    EXPECT_FALSE(ipv4_migration.local_error.has_value());
    EXPECT_TRUE(entry.path_id_by_route_handle.contains(30));
}

TEST(QuicCoreEndpointInternalTest, ExpiredRetryAndNewTokensAreRemoved) {
    QuicCore server(make_server_endpoint_config());
    QuicCore::PendingRetryToken pending_retry{
        .original_destination_connection_id = bytes_from_ints({0x83, 0x01}),
        .retry_source_connection_id = bytes_from_ints({0x53, 0x01}),
        .original_version = kQuicVersion1,
        .token = bytes_from_ints({0xaa, 0xbb}),
        .route_handle = 55,
        .expires_at = coquic::quic::test::test_time(10),
    };
    server.retry_tokens_.insert_or_assign(QuicCore::connection_id_key(pending_retry.token),
                                          pending_retry);

    QuicCore::ParsedEndpointDatagram retry_parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = pending_retry.retry_source_connection_id,
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .version = kQuicVersion1,
        .token = pending_retry.token,
    };
    EXPECT_FALSE(server
                     .take_retry_context(retry_parsed, 55, coquic::quic::test::test_time(11),
                                         std::span<const std::byte>{})
                     .has_value());
    EXPECT_TRUE(server.retry_tokens_.empty());

    auto new_token = bytes_from_ints({0x4e, 0x01, 0x02});
    server.new_tokens_.insert_or_assign(QuicCore::connection_id_key(new_token),
                                        QuicCore::StoredEndpointNewToken{
                                            .token = new_token,
                                            .route_handle = 55,
                                            .version = kQuicVersion1,
                                            .expires_at = coquic::quic::test::test_time(20),
                                            .used = false,
                                        });
    auto new_token_parsed = retry_parsed;
    new_token_parsed.destination_connection_id = bytes_from_ints({0x83, 0x02});
    new_token_parsed.token = new_token;

    EXPECT_FALSE(server
                     .take_new_token_context(new_token_parsed, 55,
                                             coquic::quic::test::test_time(21),
                                             std::span<const std::byte>{})
                     .has_value());
    EXPECT_TRUE(server.new_tokens_.empty());
}

TEST(QuicCoreEndpointInternalTest, ServerQueuesNewTokenForValidatedMigratedClientRoute) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));

    auto entry = make_server_connection_entry(1);
    entry.connection = std::make_unique<QuicConnection>(make_connected_server_connection());
    auto &connection = *entry.connection;
    connection.current_send_path_id_ = 7;
    connection.last_validated_path_id_ = 7;
    auto &migrated_path = connection.ensure_path_state(7);
    migrated_path.validated = true;
    migrated_path.is_current_send_path = true;
    entry.default_route_handle = 11;
    entry.route_handle_by_path_id.emplace(7, 55);
    entry.path_id_by_route_handle.emplace(55, 7);

    server.maybe_queue_server_new_token(entry, coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.pending_new_token_frames_.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3
    // # After verifying a new client address, the server SHOULD send new
    // # address validation tokens (Section 8) to the client.
    EXPECT_FALSE(connection.pending_new_token_frames_.front().token.empty());
    ASSERT_EQ(entry.new_token_issued_routes.size(), 1u);
    EXPECT_EQ(entry.new_token_issued_routes.front(), 55u);

    server.maybe_queue_server_new_token(entry, coquic::quic::test::test_time(2));
    EXPECT_EQ(connection.pending_new_token_frames_.size(), 1u);
}

// NOLINTBEGIN(clang-analyzer-cplusplus.NewDeleteLeaks)
TEST(QuicCoreEndpointInternalTest, ClientStoresMostRecentUnusedNewTokenForOpen) {
    QuicCore client(make_client_endpoint_config());
    auto entry = QuicCore::ConnectionEntry{
        .handle = 3,
        .connection =
            std::make_unique<QuicConnection>(coquic::quic::test::make_client_core_config()),
    };
    entry.connection->current_version_ = kQuicVersion1;
    entry.connection->config_.server_name = "localhost";

    QuicCoreResult first;
    first.effects.emplace_back(QuicCoreNewTokenAvailable{
        .connection = 3,
        .token = bytes_from_ints({0x01}),
    });
    QuicCoreResult second;
    second.effects.emplace_back(QuicCoreNewTokenAvailable{
        .connection = 3,
        .token = bytes_from_ints({0x02}),
    });

    client.remember_client_new_tokens(entry, first);
    client.remember_client_new_tokens(entry, second);
    ASSERT_EQ(client.client_new_tokens_.size(), 2u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A client MAY use a token from any previous connection to that server.
    EXPECT_EQ(client.client_new_tokens_.front().token, bytes_from_ints({0x01}));

    auto open = make_client_open_config();
    auto selected = client.take_client_new_token_for_open(open);
    auto selected_token = optional_value_or_terminate(selected);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # When connecting to a server for which the client retains an
    // # applicable and unused token, it SHOULD include that token
    // # in the Token field of its Initial packet.
    EXPECT_EQ(selected_token, bytes_from_ints({0x02}));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A client SHOULD NOT reuse a token from a NEW_TOKEN frame for
    // # different connection attempts.
    EXPECT_TRUE(client.client_new_tokens_.back().used);

    auto selected_again = client.take_client_new_token_for_open(open);
    auto selected_again_token = optional_value_or_terminate(selected_again);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A client SHOULD NOT reuse a token from a NEW_TOKEN frame for
    // # different connection attempts.
    EXPECT_EQ(selected_again_token, bytes_from_ints({0x01}));
    EXPECT_TRUE(client.take_client_new_token_for_open(open) == std::nullopt);

    entry.connection.reset();

    QuicCore opening_client(make_client_endpoint_config());
    opening_client.client_new_tokens_.push_back(QuicCore::ClientStoredNewToken{
        .server_name = "localhost",
        .version = kQuicVersion1,
        .token = bytes_from_ints({0x03}),
        .used = false,
    });
    opening_client.client_new_tokens_.push_back(QuicCore::ClientStoredNewToken{
        .server_name = "other.example",
        .version = kQuicVersion1,
        .token = bytes_from_ints({0x04}),
        .used = false,
    });
    auto opened = opening_client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(1));
    auto sends = send_effects_from(opened);
    ASSERT_FALSE(sends.empty());
    auto initial_token = coquic::quic::test::client_initial_datagram_token(sends.front().bytes);
    ASSERT_TRUE(initial_token.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # When connecting to a server for which the client retains an
    // # applicable and unused token, it SHOULD include that token
    // # in the Token field of its Initial packet.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # The client MUST include the token in all Initial packets it sends,
    // # unless a Retry replaces the token with a newer one.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A client MUST NOT include a token that is not applicable to the server
    // # that it is connecting to, unless the client has the knowledge that the
    // # server that issued the token and the server the client is connecting to
    // # are jointly managing the tokens.
    EXPECT_EQ(optional_ref_or_terminate(initial_token), bytes_from_ints({0x03}));
}

TEST(QuicCoreEndpointInternalTest, ClientDoesNotStoreRetryTokenForFutureOpen) {
    QuicCore client(make_client_endpoint_config());
    auto retry_open = make_client_open_config();
    retry_open.retry_token = bytes_from_ints({0x72, 0x74, 0x72, 0x79});
    auto retried = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(retry_open),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(1));
    auto retry_sends = send_effects_from(retried);
    ASSERT_FALSE(retry_sends.empty());
    auto retry_initial_token =
        coquic::quic::test::client_initial_datagram_token(retry_sends.front().bytes);
    ASSERT_TRUE(retry_initial_token.has_value());
    EXPECT_EQ(optional_ref_or_terminate(retry_initial_token),
              bytes_from_ints({0x72, 0x74, 0x72, 0x79}));
    ASSERT_TRUE(client.client_new_tokens_.empty());

    auto future = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 18,
        },
        coquic::quic::test::test_time(2));
    auto future_sends = send_effects_from(future);
    ASSERT_FALSE(future_sends.empty());
    auto future_initial_token =
        coquic::quic::test::client_initial_datagram_token(future_sends.front().bytes);
    ASSERT_TRUE(future_initial_token.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # The client MUST NOT use the token provided in a Retry for future
    // # connections.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # In comparison, a token obtained in a Retry packet MUST be used
    // # immediately during the connection attempt and cannot be used in
    // # subsequent connection attempts.
    EXPECT_TRUE(optional_ref_or_terminate(future_initial_token).empty());
}
// NOLINTEND(clang-analyzer-cplusplus.NewDeleteLeaks)

TEST(QuicCoreEndpointInternalTest, StatelessResetHelpersGenerateAndDetectResets) {
    QuicCore server(make_server_endpoint_config());
    auto server_entry = make_server_connection_entry(9);
    server_entry.connection->local_connection_ids_.clear();
    auto connection_id = bytes_from_ints({0x53, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33});
    auto token = std::array<std::byte, 16>{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
        std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
        std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
        std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f},
    };
    server_entry.connection->local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                                                  .sequence_number = 0,
                                                                  .connection_id = connection_id,
                                                                  .stateless_reset_token = token,
                                                                  .retired = false,
                                                              });
    server.refresh_server_connection_routes(server_entry);

    std::vector<std::byte> unknown_short_header(43, std::byte{0xaa});
    unknown_short_header.front() = std::byte{0x40};
    std::copy(connection_id.begin(), connection_id.end(), unknown_short_header.begin() + 1);
    auto parsed = QuicCore::parse_endpoint_datagram(unknown_short_header);
    auto parsed_datagram = optional_value_or_terminate(parsed);

    auto stateless_reset = server.make_stateless_reset_for_unknown_cid(
        parsed_datagram, unknown_short_header, 55, coquic::quic::test::test_time(0));
    auto reset_datagram = optional_value_or_terminate(stateless_reset);
    EXPECT_EQ(reset_datagram.connection, 9u);
    EXPECT_EQ(reset_datagram.route_handle, std::optional<QuicRouteHandle>{55u});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint that sends a Stateless Reset in response to a packet that
    // # is 43 bytes or shorter SHOULD send a Stateless Reset that is one byte
    // # shorter than the packet it responds to.
    EXPECT_EQ(reset_datagram.bytes.size(), 42u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
    // # An endpoint MUST ensure that every Stateless Reset that it sends is
    // # smaller than the packet that triggered it, unless it maintains state
    // # sufficient to prevent looping.
    EXPECT_LT(reset_datagram.bytes.size(), unknown_short_header.size());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # Endpoints MUST send Stateless Resets formatted as a packet with a
    // # short header.
    EXPECT_EQ(std::to_integer<std::uint8_t>(reset_datagram.bytes.span().front()) & 0xc0u, 0x40u);
    ASSERT_GE(reset_datagram.bytes.size(), 21u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint MUST NOT send a Stateless Reset that is three times or
    // # more larger than the packet it receives to avoid being used for
    // # amplification.
    EXPECT_LT(reset_datagram.bytes.size(), unknown_short_header.size() * 3u);
    EXPECT_TRUE(std::equal(token.begin(), token.end(),
                           reset_datagram.bytes.end() - static_cast<std::ptrdiff_t>(token.size())));

    auto second_stateless_reset = server.make_stateless_reset_for_unknown_cid(
        parsed_datagram, unknown_short_header, 55, coquic::quic::test::test_time(0));
    auto second_reset_datagram = optional_value_or_terminate(second_stateless_reset);
    auto first_random_prefix = reset_datagram.bytes.to_vector();
    first_random_prefix.resize(first_random_prefix.size() - token.size());
    auto second_random_prefix = second_reset_datagram.bytes.to_vector();
    second_random_prefix.resize(second_random_prefix.size() - token.size());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # The remainder of the first byte and an arbitrary number of bytes
    // # following it are set to values that SHOULD be indistinguishable from
    // # random.
    EXPECT_NE(first_random_prefix, second_random_prefix);

    std::vector<std::byte> minimum_reset_unknown_short_header(21, std::byte{0xaa});
    minimum_reset_unknown_short_header.front() = std::byte{0x40};
    std::copy(connection_id.begin(), connection_id.end(),
              minimum_reset_unknown_short_header.begin() + 1);
    auto minimum_reset_parsed =
        QuicCore::parse_endpoint_datagram(minimum_reset_unknown_short_header);
    auto minimum_reset_parsed_datagram = optional_value_or_terminate(minimum_reset_parsed);
    auto minimum_reset_stateless_reset = server.make_stateless_reset_for_unknown_cid(
        minimum_reset_parsed_datagram, minimum_reset_unknown_short_header, 55,
        coquic::quic::test::test_time(0));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
    // # An endpoint MUST ensure that every Stateless Reset that it sends is
    // # smaller than the packet that triggered it, unless it maintains state
    // # sufficient to prevent looping.
    EXPECT_FALSE(minimum_reset_stateless_reset.has_value());

    std::vector<std::byte> small_unknown_short_header(22, std::byte{0xaa});
    small_unknown_short_header.front() = std::byte{0x40};
    std::copy(connection_id.begin(), connection_id.end(), small_unknown_short_header.begin() + 1);
    auto small_parsed = QuicCore::parse_endpoint_datagram(small_unknown_short_header);
    auto small_parsed_datagram = optional_value_or_terminate(small_parsed);
    auto small_stateless_reset = server.make_stateless_reset_for_unknown_cid(
        small_parsed_datagram, small_unknown_short_header, 55, coquic::quic::test::test_time(0));
    auto small_reset_datagram = optional_value_or_terminate(small_stateless_reset);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint MUST NOT send a Stateless Reset that is three times or
    // # more larger than the packet it receives to avoid being used for
    // # amplification.
    EXPECT_LT(small_reset_datagram.bytes.size(), small_unknown_short_header.size() * 3u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
    // # An endpoint MUST ensure that every Stateless Reset that it sends is
    // # smaller than the packet that triggered it, unless it maintains state
    // # sufficient to prevent looping.
    EXPECT_LT(small_reset_datagram.bytes.size(), small_unknown_short_header.size());

    std::vector<std::byte> medium_unknown_short_header(64, std::byte{0xaa});
    medium_unknown_short_header.front() = std::byte{0x40};
    std::copy(connection_id.begin(), connection_id.end(), medium_unknown_short_header.begin() + 1);
    auto medium_parsed = QuicCore::parse_endpoint_datagram(medium_unknown_short_header);
    auto medium_parsed_datagram = optional_value_or_terminate(medium_parsed);
    auto medium_stateless_reset = server.make_stateless_reset_for_unknown_cid(
        medium_parsed_datagram, medium_unknown_short_header, 55, coquic::quic::test::test_time(0));
    auto medium_reset_datagram = optional_value_or_terminate(medium_stateless_reset);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
    // # An endpoint MUST ensure that every Stateless Reset that it sends is
    // # smaller than the packet that triggered it, unless it maintains state
    // # sufficient to prevent looping.
    EXPECT_LT(medium_reset_datagram.bytes.size(), medium_unknown_short_header.size());

    QuicCore client(make_client_endpoint_config());
    client.peer_stateless_reset_tokens_.insert_or_assign(QuicCore::stateless_reset_token_key(token),
                                                         QuicCore::PeerStatelessResetTokenRoute{
                                                             .owner = 4,
                                                         });
    client.peer_stateless_reset_tokens_.insert_or_assign("short",
                                                         QuicCore::PeerStatelessResetTokenRoute{
                                                             .owner = 99,
                                                         });
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # However, endpoints MUST treat any packet ending in a valid stateless
    // # reset token as a Stateless Reset, as other QUIC versions might allow
    // # the use of a long header.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
    // # When comparing a datagram to stateless reset token values, endpoints
    // # MUST perform the comparison without leaking information about the value
    // # of the token.
    EXPECT_EQ(client.detect_stateless_reset(reset_datagram.bytes.span()),
              std::optional<QuicConnectionHandle>{4u});

    auto corrupted = reset_datagram.bytes.to_vector();
    corrupted.back() =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(corrupted.back()) ^ 0x80u);
    EXPECT_FALSE(client.detect_stateless_reset(corrupted).has_value());
}

TEST(QuicCoreEndpointInternalTest, LongHeaderStatelessResetIsOptInAndHandshakeOnly) {
    const auto connection_id = bytes_from_ints({0x53, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33});
    const auto source_connection_id = bytes_from_ints({0xc1, 0x01});
    const auto token = std::array<std::byte, 16>{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
        std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
        std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
        std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f},
    };
    const auto handshake =
        make_supported_long_header_datagram(kQuicVersion1, connection_id, source_connection_id, 64);
    const auto parsed_handshake =
        optional_value_or_terminate(QuicCore::parse_endpoint_datagram(handshake));
    ASSERT_EQ(parsed_handshake.kind, QuicCore::ParsedEndpointDatagram::Kind::supported_long_header);

    QuicCore disabled(make_server_endpoint_config());
    disabled.local_stateless_reset_tokens_by_cid_.emplace(
        QuicCore::connection_id_key(connection_id),
        QuicCore::LocalStatelessResetTokenRoute{.owner = 9, .stateless_reset_token = token});
    EXPECT_FALSE(disabled
                     .make_stateless_reset_for_unknown_cid(parsed_handshake, handshake, 55,
                                                           coquic::quic::test::test_time(0))
                     .has_value());

    auto enabled_config = make_server_endpoint_config();
    enabled_config.enable_long_header_stateless_reset = true;
    QuicCore enabled(std::move(enabled_config));
    enabled.local_stateless_reset_tokens_by_cid_.emplace(
        QuicCore::connection_id_key(connection_id),
        QuicCore::LocalStatelessResetTokenRoute{.owner = 9, .stateless_reset_token = token});
    const auto endpoint_result =
        enabled.advance_endpoint(QuicCoreInboundDatagram{.bytes = handshake, .route_handle = 55},
                                 coquic::quic::test::test_time(0));
    const auto sends = send_effects_from(endpoint_result);
    ASSERT_EQ(sends.size(), 1u);
    const auto &reset = sends.front();
    EXPECT_EQ(reset.connection, 9u);
    EXPECT_EQ(reset.route_handle, std::optional<QuicRouteHandle>{55u});
    EXPECT_LT(reset.bytes.size(), handshake.size());
    EXPECT_EQ(std::to_integer<std::uint8_t>(reset.bytes.span().front()) & 0xc0u, 0x40u);
    EXPECT_TRUE(std::equal(token.begin(), token.end(),
                           reset.bytes.end() - static_cast<std::ptrdiff_t>(token.size())));

    const auto initial =
        make_supported_initial_datagram(kQuicVersion1, connection_id, source_connection_id, {}, 64);
    const auto parsed_initial =
        optional_value_or_terminate(QuicCore::parse_endpoint_datagram(initial));
    EXPECT_FALSE(enabled
                     .make_stateless_reset_for_unknown_cid(parsed_initial, initial, 55,
                                                           coquic::quic::test::test_time(0))
                     .has_value());

    auto zero_rtt = handshake;
    zero_rtt.front() = std::byte{0xd0};
    const auto parsed_zero_rtt =
        optional_value_or_terminate(QuicCore::parse_endpoint_datagram(zero_rtt));
    ASSERT_EQ(parsed_zero_rtt.kind, QuicCore::ParsedEndpointDatagram::Kind::supported_zero_rtt);
    EXPECT_FALSE(enabled
                     .make_stateless_reset_for_unknown_cid(parsed_zero_rtt, zero_rtt, 55,
                                                           coquic::quic::test::test_time(0))
                     .has_value());

    auto retry = handshake;
    retry.front() = std::byte{0xf0};
    const auto parsed_retry = optional_value_or_terminate(QuicCore::parse_endpoint_datagram(retry));
    ASSERT_EQ(parsed_retry.kind, QuicCore::ParsedEndpointDatagram::Kind::supported_retry);
    EXPECT_FALSE(enabled
                     .make_stateless_reset_for_unknown_cid(parsed_retry, retry, 55,
                                                           coquic::quic::test::test_time(0))
                     .has_value());

    auto no_token_config = make_server_endpoint_config();
    no_token_config.enable_long_header_stateless_reset = true;
    QuicCore no_token(std::move(no_token_config));
    EXPECT_FALSE(no_token
                     .make_stateless_reset_for_unknown_cid(parsed_handshake, handshake, 55,
                                                           coquic::quic::test::test_time(0))
                     .has_value());
}

TEST(QuicCoreEndpointInternalTest, ClosedConnectionResetTokensAreRetainedUntilExpiry) {
    auto server_config = make_server_endpoint_config();
    server_config.stateless_reset_token_retention = std::chrono::milliseconds(50);
    QuicCore server(std::move(server_config));

    auto server_entry = make_server_connection_entry(9);
    server_entry.connection->local_connection_ids_.clear();
    auto connection_id = bytes_from_ints({0x53, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70});
    auto token = std::array<std::byte, 16>{
        std::byte{0x20}, std::byte{0x21}, std::byte{0x22}, std::byte{0x23},
        std::byte{0x24}, std::byte{0x25}, std::byte{0x26}, std::byte{0x27},
        std::byte{0x28}, std::byte{0x29}, std::byte{0x2a}, std::byte{0x2b},
        std::byte{0x2c}, std::byte{0x2d}, std::byte{0x2e}, std::byte{0x2f},
    };
    server_entry.connection->local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                                                  .sequence_number = 0,
                                                                  .connection_id = connection_id,
                                                                  .stateless_reset_token = token,
                                                                  .retired = false,
                                                              });
    server.refresh_server_connection_routes(server_entry);
    server.retire_endpoint_connection_routes(server_entry, coquic::quic::test::test_time(10));

    std::vector<std::byte> unknown_short_header(43, std::byte{0xaa});
    unknown_short_header.front() = std::byte{0x40};
    std::copy(connection_id.begin(), connection_id.end(), unknown_short_header.begin() + 1);
    auto parsed = QuicCore::parse_endpoint_datagram(unknown_short_header);
    auto parsed_datagram = optional_value_or_terminate(parsed);

    auto retained = server.make_stateless_reset_for_unknown_cid(
        parsed_datagram, unknown_short_header, 55, coquic::quic::test::test_time(59));
    auto retained_reset = optional_value_or_terminate(retained);
    EXPECT_TRUE(std::equal(token.begin(), token.end(),
                           retained_reset.bytes.end() - static_cast<std::ptrdiff_t>(token.size())));

    auto expired = server.make_stateless_reset_for_unknown_cid(
        parsed_datagram, unknown_short_header, 55, coquic::quic::test::test_time(60));
    EXPECT_FALSE(expired.has_value());

    auto disabled_config = make_server_endpoint_config();
    disabled_config.retain_stateless_reset_tokens_after_connection_close = false;
    QuicCore disabled(std::move(disabled_config));
    auto disabled_entry = make_server_connection_entry(10);
    disabled_entry.connection->local_connection_ids_.clear();
    disabled_entry.connection->local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                                                    .sequence_number = 0,
                                                                    .connection_id = connection_id,
                                                                    .stateless_reset_token = token,
                                                                    .retired = false,
                                                                });
    disabled.refresh_server_connection_routes(disabled_entry);
    disabled.retire_endpoint_connection_routes(disabled_entry, coquic::quic::test::test_time(10));
    EXPECT_FALSE(disabled
                     .make_stateless_reset_for_unknown_cid(parsed_datagram, unknown_short_header,
                                                           55, coquic::quic::test::test_time(11))
                     .has_value());
}

TEST(QuicCoreEndpointInternalTest, ConfiguredResetSecretSupportsUnknownCidAfterStateLoss) {
    QuicStatelessResetSecret reset_secret{};
    for (std::size_t index = 0; index < reset_secret.size(); ++index) {
        reset_secret[index] = static_cast<std::byte>(0xa0u + index);
    }

    auto original_config = make_server_endpoint_config();
    original_config.stateless_reset_secret = reset_secret;
    QuicCore original(std::move(original_config));

    auto original_entry = make_server_connection_entry(9);
    original_entry.connection->config_.stateless_reset_secret = reset_secret;
    original_entry.connection->config_.source_connection_id =
        bytes_from_ints({0x53, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70});
    original_entry.connection->local_connection_ids_.clear();
    auto token_source_config = coquic::quic::test::make_server_core_config();
    token_source_config.source_connection_id =
        original_entry.connection->config_.source_connection_id;
    token_source_config.stateless_reset_secret = reset_secret;
    const QuicConnection token_source(std::move(token_source_config));
    auto expected_token = token_source.local_connection_ids_.at(0).stateless_reset_token;
    auto different_secret = reset_secret;
    different_secret.front() =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(different_secret.front()) ^ 0x55u);
    auto different_secret_token_source_config = coquic::quic::test::make_server_core_config();
    different_secret_token_source_config.source_connection_id =
        original_entry.connection->config_.source_connection_id;
    different_secret_token_source_config.stateless_reset_secret = different_secret;
    const QuicConnection different_secret_token_source(
        std::move(different_secret_token_source_config));
    auto different_cid_token_source_config = coquic::quic::test::make_server_core_config();
    different_cid_token_source_config.source_connection_id =
        original_entry.connection->config_.source_connection_id;
    different_cid_token_source_config.source_connection_id.back() =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(
                                   different_cid_token_source_config.source_connection_id.back()) ^
                               0x11u);
    different_cid_token_source_config.stateless_reset_secret = reset_secret;
    const QuicConnection different_cid_token_source(std::move(different_cid_token_source_config));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
    // # The stateless reset token MUST be difficult to guess.
    EXPECT_NE(different_secret_token_source.local_connection_ids_.at(0).stateless_reset_token,
              expected_token);
    EXPECT_NE(different_cid_token_source.local_connection_ids_.at(0).stateless_reset_token,
              expected_token);
    original_entry.connection->local_connection_ids_.emplace(
        0, LocalConnectionIdRecord{
               .sequence_number = 0,
               .connection_id = original_entry.connection->config_.source_connection_id,
               .stateless_reset_token = expected_token,
               .retired = false,
           });
    original.refresh_server_connection_routes(original_entry);

    auto connection_id = original_entry.connection->config_.source_connection_id;
    EXPECT_EQ(
        original.local_stateless_reset_tokens_by_cid_.at(QuicCore::connection_id_key(connection_id))
            .stateless_reset_token,
        expected_token);

    std::vector<std::byte> unknown_short_header(64, std::byte{0xaa});
    unknown_short_header.front() = std::byte{0x40};
    std::copy(connection_id.begin(), connection_id.end(), unknown_short_header.begin() + 1);
    auto parsed = QuicCore::parse_endpoint_datagram(unknown_short_header);
    auto parsed_datagram = optional_value_or_terminate(parsed);

    auto restarted_config = make_server_endpoint_config();
    restarted_config.stateless_reset_secret = reset_secret;
    QuicCore restarted(std::move(restarted_config));
    ASSERT_TRUE(restarted.local_stateless_reset_tokens_by_cid_.empty());

    auto stateless_reset = restarted.make_stateless_reset_for_unknown_cid(
        parsed_datagram, unknown_short_header, 55, coquic::quic::test::test_time(10));
    auto reset_datagram = optional_value_or_terminate(stateless_reset);
    EXPECT_EQ(reset_datagram.connection, 0u);
    EXPECT_EQ(reset_datagram.route_handle, std::optional<QuicRouteHandle>{55u});
    EXPECT_TRUE(std::equal(expected_token.begin(), expected_token.end(),
                           reset_datagram.bytes.end() -
                               static_cast<std::ptrdiff_t>(expected_token.size())));

    auto wrong_length_connection_id = connection_id;
    wrong_length_connection_id.push_back(std::byte{0x80});
    std::vector<std::byte> wrong_length_unknown_initial{
        std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, static_cast<std::byte>(wrong_length_connection_id.size()),
    };
    wrong_length_unknown_initial.insert(wrong_length_unknown_initial.end(),
                                        wrong_length_connection_id.begin(),
                                        wrong_length_connection_id.end());
    wrong_length_unknown_initial.push_back(std::byte{0x01});
    wrong_length_unknown_initial.push_back(std::byte{0x11});
    wrong_length_unknown_initial.push_back(std::byte{0x00});
    wrong_length_unknown_initial.resize(64, std::byte{0xaa});
    auto wrong_length_parsed = QuicCore::parse_endpoint_datagram(wrong_length_unknown_initial);
    auto wrong_length_parsed_datagram = optional_value_or_terminate(wrong_length_parsed);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
    // # An endpoint that uses this design MUST either use the same connection
    // # ID length for all connections or encode the length of the connection
    // # ID such that it can be recovered without state.
    EXPECT_FALSE(restarted
                     .make_stateless_reset_for_unknown_cid(wrong_length_parsed_datagram,
                                                           wrong_length_unknown_initial, 55,
                                                           coquic::quic::test::test_time(10))
                     .has_value());

    auto no_secret_config = make_server_endpoint_config();
    QuicCore no_secret(std::move(no_secret_config));
    EXPECT_FALSE(no_secret
                     .make_stateless_reset_for_unknown_cid(parsed_datagram, unknown_short_header,
                                                           55, coquic::quic::test::test_time(10))
                     .has_value());
}

TEST(QuicCoreEndpointInternalTest, StatelessResetDatagramEntersDrainingWithoutResponse) {
    QuicCore client(make_client_endpoint_config());
    auto entry = make_server_connection_entry(4);
    entry.connection =
        std::make_unique<QuicConnection>(coquic::quic::test::make_client_core_config());
    entry.connection->started_ = true;
    entry.connection->status_ = HandshakeStatus::connected;
    entry.connection->application_space_.write_secret = make_test_traffic_secret();
    entry.connection->peer_transport_parameters_ = TransportParameters{
        .stateless_reset_token =
            std::array<std::byte, 16>{
                std::byte{0x10},
                std::byte{0x11},
                std::byte{0x12},
                std::byte{0x13},
                std::byte{0x14},
                std::byte{0x15},
                std::byte{0x16},
                std::byte{0x17},
                std::byte{0x18},
                std::byte{0x19},
                std::byte{0x1a},
                std::byte{0x1b},
                std::byte{0x1c},
                std::byte{0x1d},
                std::byte{0x1e},
                std::byte{0x1f},
            },
        .max_udp_payload_size = entry.connection->config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
    };
    entry.connection->peer_transport_parameters_validated_ = true;
    entry.connection->current_send_path_id_ = 0;
    entry.connection->ensure_path_state(0).validated = true;
    auto handle = entry.handle;
    client.refresh_server_connection_routes(entry);
    client.connections_.emplace(handle, std::move(entry));

    std::vector<std::byte> datagram(43, std::byte{0x55});
    datagram.front() = std::byte{0x40};
    auto &peer_transport_parameters =
        client.connections_.at(handle).connection->peer_transport_parameters_;
    auto &parameters = optional_ref_or_terminate(peer_transport_parameters);
    auto token = optional_value_or_terminate(parameters.stateless_reset_token);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
    // # However, the comparison MUST be performed when the first packet in an
    // # incoming datagram either cannot be associated with a connection or
    // # cannot be decrypted.
    std::copy(token.begin(), token.end(),
              datagram.end() - static_cast<std::ptrdiff_t>(token.size()));

    auto result = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = std::move(datagram),
            .route_handle = 17,
        },
        coquic::quic::test::test_time(123));

    EXPECT_TRUE(send_effects_from(result).empty());
    ASSERT_TRUE(client.connections_.contains(handle));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
    // # If the last 16 bytes of the datagram are identical in value to a
    // # stateless reset token, the endpoint MUST enter the draining period and
    // # not send any further packets on this connection.
    EXPECT_TRUE(client.connections_.at(handle).connection->close_state_active());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
    // # An endpoint MUST NOT send further packets.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
    // # While otherwise identical to the closing state, an
    // # endpoint in the draining state MUST NOT send any packets.
    EXPECT_FALSE(client.connections_.at(handle).connection->has_sendable_datagram(
        coquic::quic::test::test_time(123)));
    EXPECT_TRUE(result.next_wakeup.has_value());
}

TEST(QuicCoreEndpointInternalTest, ParseableButInvalidInitialSkipsAcceptedConnectionInsertion) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));

    auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_plaintext_initial_datagram_with_token({}),
            .route_handle = 61,
        },
        coquic::quic::test::test_time(1));

    EXPECT_EQ(server.connection_count(), 0u);
    auto lifecycle = lifecycle_events_from(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
}

TEST(QuicCoreEndpointInternalTest, EndpointCommandsAndTimersCoverSuccessAndCleanupBranches) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();

    auto reset_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreResetStream{
                    .stream_id = 0,
                    .application_error_code = 13,
                },
        },
        coquic::quic::test::test_time(1));
    EXPECT_FALSE(reset_result.local_error.has_value());
    EXPECT_FALSE(send_effects_from(reset_result).empty());

    auto &stop_entry = endpoint.connections_.at(1);
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        *stop_entry.connection,
        {coquic::quic::test::make_inbound_application_stream_frame("a", 0, 3)}));
    auto stop_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreStopSending{
                    .stream_id = 3,
                    .application_error_code = 14,
                },
        },
        coquic::quic::test::test_time(2));
    EXPECT_FALSE(stop_result.local_error.has_value());
    EXPECT_FALSE(send_effects_from(stop_result).empty());

    QuicCore cleanup_endpoint(make_client_endpoint_config());
    static_cast<void>(cleanup_endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    auto &cleanup_entry = cleanup_endpoint.connections_.at(1);
    *cleanup_entry.connection = make_connected_client_connection();
    cleanup_entry.connection->pending_terminal_state_ = QuicConnectionTerminalState::closed;

    auto cleanup_result = cleanup_endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input = QuicCoreRequestKeyUpdate{},
        },
        coquic::quic::test::test_time(3));
    EXPECT_EQ(cleanup_endpoint.connection_count(), 0u);
    auto cleanup_lifecycle = lifecycle_events_from(cleanup_result);
    ASSERT_EQ(cleanup_lifecycle.size(), 1u);
    EXPECT_EQ(cleanup_lifecycle.front().event, QuicCoreConnectionLifecycle::closed);

    QuicCore timer_core(make_client_endpoint_config());
    static_cast<void>(timer_core.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    auto &timer_entry = timer_core.connections_.at(1);
    *timer_entry.connection = make_connected_client_connection();
    timer_entry.connection->application_space_.pending_ack_deadline =
        coquic::quic::test::test_time(5);

    auto timer_result =
        timer_core.advance_endpoint(QuicCoreTimerExpired{}, coquic::quic::test::test_time(5));
    EXPECT_EQ(timer_core.connection_count(), 1u);
    EXPECT_FALSE(timer_result.local_error.has_value());
    EXPECT_TRUE(lifecycle_events_from(timer_result).empty());
}

TEST(QuicCoreEndpointInternalTest, LegacyAdvanceSuccessfulSharedSendQueuesDatagrams) {
    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    *legacy_core.connection_ = make_connected_client_connection();

    auto shared_send_result = legacy_core.advance(
        QuicCoreSendSharedStreamData{
            .stream_id = 0,
            .bytes = SharedBytes(bytes_from_ints({0x68, 0x69})),
            .fin = false,
        },
        coquic::quic::test::test_time(7));
    EXPECT_FALSE(shared_send_result.local_error.has_value());
    EXPECT_FALSE(send_effects_from(shared_send_result).empty());
}

} // namespace

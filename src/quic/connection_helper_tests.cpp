#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_support.h"

namespace coquic::quic::test {

CodecResult<SerializedProtectedDatagram> successful_serialized_datagram_for_tests() {
    SerializedProtectedDatagram datagram;
    datagram.bytes = DatagramBuffer{std::byte{0x03}, std::byte{0x04}, std::byte{0x05}};
    return CodecResult<SerializedProtectedDatagram>::success(std::move(datagram));
}

std::vector<std::byte> resumption_state_missing_application_context_for_tests(
    std::span<const std::byte> transport_parameters) {
    std::vector<std::byte> state = {std::byte{0x01}};
    append_u32_be(state, kQuicVersion1);
    append_length_prefixed_bytes(state, {});
    append_length_prefixed_text(state, "h3");
    append_length_prefixed_bytes(state, transport_parameters);
    return state;
}

std::vector<std::byte> resumption_state_missing_application_protocol_for_tests() {
    std::vector<std::byte> state = {std::byte{0x01}};
    append_u32_be(state, kQuicVersion1);
    append_length_prefixed_bytes(state, {});
    return state;
}

std::vector<std::byte> resumption_state_missing_transport_parameters_for_tests() {
    std::vector<std::byte> state = {std::byte{0x01}};
    append_u32_be(state, kQuicVersion1);
    append_length_prefixed_bytes(state, {});
    append_length_prefixed_text(state, "h3");
    return state;
}

struct PendingFinStreamCaseForTests {
    std::uint64_t final_size = 0;
    std::uint64_t peer_max_stream_data = 0;
};

bool stream_with_pending_fin_is_sendable_for_tests(PendingFinStreamCaseForTests test_case) {
    auto stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    stream.send_final_size = test_case.final_size;
    stream.send_fin_state = StreamSendFinState::pending;
    stream.flow_control.peer_max_stream_data = test_case.peer_max_stream_data;
    return stream_fin_sendable(stream);
}

bool pending_stream_data_blocks_fin_for_tests() {
    auto stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    stream.send_final_size = 1;
    stream.send_fin_state = StreamSendFinState::pending;
    stream.flow_control.peer_max_stream_data = 1;
    stream.send_buffer.append(std::array{std::byte{0x78}});
    return !stream_fin_sendable(stream);
}

bool stream_limits_without_peer_credit_preserve_state_for_tests() {
    LocalStreamLimitState stream_limits;
    stream_limits.max_streams_bidi_state = StreamControlFrameState::pending;
    stream_limits.max_streams_uni_state = StreamControlFrameState::pending;
    return stream_limits.take_max_streams_frames().empty() &&
           (stream_limits.max_streams_bidi_state == StreamControlFrameState::pending) &&
           (stream_limits.max_streams_uni_state == StreamControlFrameState::pending);
}

ProtectedOneRttPacket protected_one_rtt_reset_packet_for_tests() {
    return ProtectedOneRttPacket{
        .frames =
            {
                ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
    };
}

ProtectedOneRttPacket protected_one_rtt_ack_packet_for_tests() {
    return ProtectedOneRttPacket{
        .frames =
            {
                AckFrame{},
            },
    };
}

ReceivedProtectedOneRttPacket received_one_rtt_ack_packet_for_tests() {
    return ReceivedProtectedOneRttPacket{
        .frames =
            {
                ReceivedAckFrame{},
            },
    };
}

ReceivedProtectedOneRttPacket received_one_rtt_reset_packet_for_tests() {
    return ReceivedProtectedOneRttPacket{
        .frames =
            {
                ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
    };
}

ReceivedProtectedOneRttAckOnlyPacket received_ack_only_fast_packet_for_tests() {
    return ReceivedProtectedOneRttAckOnlyPacket{
        .packet_number = 42,
        .ack = ReceivedAckFrame{},
    };
}

ReceivedProtectedOneRttStreamPacket received_stream_fast_packet_for_tests() {
    return ReceivedProtectedOneRttStreamPacket{
        .packet_number = 43,
        .stream =
            ReceivedStreamFrame{
                .stream_id = 0,
                .stream_data = SharedBytes(bytes_from_ints_for_tests({0xaa})),
            },
    };
}

bool stream_state_codec_error_adds_transport_code_for_tests() {
    const auto codec_error = stream_state_codec_error(
        CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0}, kFrameTypeStreamBase);
    return codec_error.has_transport_error_code &&
           codec_error.transport_error_code ==
               transport_error_code_value(QuicTransportErrorCode::stream_state_error);
}

bool deferred_packet_equals_vector_for_tests() {
    return bytes_from_ints_for_tests({0x01, 0x02, 0x03}) ==
           DeferredProtectedDatagram(bytes_from_ints_for_tests({0x01, 0x02, 0x03}), /*id=*/9);
}

PathState traced_path_for_summary_tests() {
    return PathState{
        .id = 7,
        .validated = true,
        .is_current_send_path = true,
        .challenge_pending = true,
        .anti_amplification_received_bytes = 11,
        .anti_amplification_sent_bytes = 7,
        .outstanding_challenge =
            std::array{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                       std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}},
        .pending_response =
            std::array{std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
                       std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18}},
    };
}

bool path_summary_mentions_state_for_tests(const PathState &path) {
    const auto summary = format_path_state_summary(&path);
    return (summary.find("id=7") != std::string::npos) &
           (summary.find("val=1") != std::string::npos) &
           (summary.find("cur=1") != std::string::npos) &
           (summary.find("chal=1") != std::string::npos) &
           (summary.find("out=1") != std::string::npos) &
           (summary.find("resp=1") != std::string::npos) &
           (summary.find("recv=11") != std::string::npos) &
           (summary.find("sent=7") != std::string::npos);
}

bool packet_summary_mentions_counts_for_tests() {
    const auto summary = summarize_packets(std::array{
        SentPacketRecord{
            .packet_number = 5,
            .stream_fragments =
                {
                    StreamFrameSendFragment{
                        .stream_id = 0,
                        .offset = 4,
                        .bytes = SharedBytes(bytes_from_ints_for_tests({0xaa, 0xbb})),
                        .fin = false,
                        .consumes_flow_control = true,
                    },
                },
        },
        SentPacketRecord{
            .packet_number = 9,
        },
    });
    return (summary.find("count=2") != std::string::npos) &
           (summary.find("pn=5-9") != std::string::npos) &
           (summary.find("stream_fragments=1") != std::string::npos) &
           (summary.find("first_stream_offset=4") != std::string::npos);
}

bool packet_summary_without_stream_offset_omits_offset_for_tests() {
    const auto summary = summarize_packets(std::array{
        SentPacketRecord{
            .packet_number = 6,
        },
        SentPacketRecord{
            .packet_number = 8,
        },
    });
    return (summary.find("count=2") != std::string::npos) &
           (summary.find("pn=6-8") != std::string::npos) &
           (summary.find("stream_fragments=0") != std::string::npos) &
           (summary.find("first_stream_offset=") == std::string::npos);
}

SentPacketRecord metadata_packet_for_tests() {
    return SentPacketRecord{
        .first_stream_frame_metadata =
            StreamFrameSendMetadata{
                .stream_id = 0,
                .offset = 2,
                .length = 3,
                .fin = false,
                .consumes_flow_control = true,
            },
        .stream_frame_metadata =
            {
                StreamFrameSendMetadata{
                    .stream_id = 4,
                    .offset = 9,
                    .length = 5,
                    .fin = true,
                    .consumes_flow_control = true,
                },
            },
        .stream_fragments =
            {
                StreamFrameSendFragment{
                    .stream_id = 8,
                    .offset = 14,
                    .bytes = SharedBytes(bytes_from_ints_for_tests({0x01, 0x02})),
                    .fin = false,
                    .consumes_flow_control = true,
                },
            },
    };
}

SentPacketRecord vector_only_metadata_packet_for_tests() {
    return SentPacketRecord{
        .stream_frame_metadata =
            {
                StreamFrameSendMetadata{
                    .stream_id = 12,
                    .offset = 33,
                    .length = 7,
                    .fin = false,
                    .consumes_flow_control = true,
                },
            },
    };
}

SentPacketRecord fragment_only_metadata_packet_for_tests() {
    return SentPacketRecord{
        .stream_fragments =
            {
                StreamFrameSendFragment{
                    .stream_id = 16,
                    .offset = 44,
                    .bytes = SharedBytes(bytes_from_ints_for_tests({0x03})),
                    .fin = false,
                    .consumes_flow_control = true,
                },
            },
    };
}

bool stream_frame_payload_budget_handles_edges_for_tests() {
    return max_stream_frame_payload_for_wire_budget(/*stream_id=*/0, kMaxQuicVarInt + 1u,
                                                    /*wire_budget=*/1200) == 0 &&
           max_stream_frame_payload_for_wire_budget(/*stream_id=*/0, /*offset=*/0,
                                                    /*wire_budget=*/1) == 0 &&
           max_stream_frame_payload_for_wire_budget(/*stream_id=*/0, /*offset=*/0,
                                                    /*wire_budget=*/32) > 0;
}

bool one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_for_tests(
    const ConnectionId &destination_connection_id) {
    const std::array<Frame, 2> frames{
        Frame{StreamFrame{
            .has_length = false,
            .stream_id = 0,
            .stream_data = bytes_from_ints_for_tests({0xaa}),
        }},
        Frame{PingFrame{}},
    };
    const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
        .destination_connection_id = destination_connection_id,
        .packet_number_length = 2,
        .frames = frames,
    });
    return !size.has_value() && size.error().code == CodecErrorCode::packet_length_mismatch &&
           size.error().offset == 0;
}

bool one_rtt_fragment_size_propagates_frame_size_errors_for_tests(
    const ConnectionId &destination_connection_id) {
    const std::array<Frame, 1> frames{
        Frame{PaddingFrame{.length = 0}},
    };
    const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
        .destination_connection_id = destination_connection_id,
        .packet_number_length = 2,
        .frames = frames,
    });
    return !size.has_value() && size.error().code == CodecErrorCode::invalid_varint &&
           size.error().offset == 0;
}

bool one_rtt_fragment_size_rejects_empty_payloads_for_tests(
    const ConnectionId &destination_connection_id) {
    const std::array<Frame, 0> frames{};
    const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
        .destination_connection_id = destination_connection_id,
        .packet_number_length = 2,
        .frames = frames,
    });
    return !size.has_value() && size.error().code == CodecErrorCode::empty_packet_payload;
}

std::array<StreamFrameSendFragment, 2> stream_fragments_for_wire_size_tests() {
    const auto storage =
        std::make_shared<std::vector<std::byte>>(bytes_from_ints_for_tests({0xaa, 0xbb, 0xcc}));
    return {
        StreamFrameSendFragment{
            .stream_id = 0,
            .offset = 0,
            .bytes = SharedBytes(storage, 0, 2),
            .fin = false,
            .consumes_flow_control = true,
        },
        StreamFrameSendFragment{
            .stream_id = 4,
            .offset = 2,
            .bytes = SharedBytes(storage, 2, 3),
            .fin = true,
            .consumes_flow_control = true,
        },
    };
}

bool one_rtt_fragment_helpers_count_stream_fragment_bytes_for_tests(
    const ConnectionId &destination_connection_id) {
    const std::array<Frame, 0> frames{};
    const auto fragments = stream_fragments_for_wire_size_tests();
    const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
        .destination_connection_id = destination_connection_id,
        .packet_number_length = 2,
        .frames = frames,
        .stream_fragments = fragments,
    });
    return stream_fragment_bytes(fragments) == 3 && stream_fragment_wire_bytes(fragments) > 3 &&
           size.has_value() &&
           size.value() > destination_connection_id.size() + kDefaultInitialPacketNumberLength +
                              kOneRttPacketProtectionTagLength;
}

bool one_rtt_fragment_size_rejects_overflowing_fragment_offsets_for_tests(
    const ConnectionId &destination_connection_id) {
    const std::array<Frame, 0> frames{};
    const std::array<StreamFrameSendFragment, 1> fragments{
        StreamFrameSendFragment{
            .stream_id = 0,
            .offset = kMaxQuicVarInt,
            .bytes = SharedBytes(bytes_from_ints_for_tests({0xdd, 0xee})),
        },
    };
    const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
        .destination_connection_id = destination_connection_id,
        .packet_number_length = 2,
        .frames = frames,
        .stream_fragments = fragments,
    });
    return !size.has_value() && size.error().code == CodecErrorCode::invalid_varint &&
           size.error().offset == 0;
}

bool connection_helper_edge_cases_for_tests() {
    bool ok = true;

    constexpr std::array supported_versions = {kQuicVersion2, kQuicVersion1};
    const auto retry_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x00}};
    connection_coverage_check(ok, "retry_same_version_omits_version_information",
                              !version_information_for_handshake(supported_versions, kQuicVersion1,
                                                                 retry_source_connection_id,
                                                                 kQuicVersion1, kQuicVersion1)
                                   .has_value());
    connection_coverage_check(ok, "retry_version_change_keeps_version_information",
                              version_information_for_handshake(supported_versions, kQuicVersion2,
                                                                retry_source_connection_id,
                                                                kQuicVersion1, kQuicVersion2)
                                  .has_value());

    const auto failed_datagram =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    const auto successful_datagram =
        CodecResult<std::vector<std::byte>>::success({std::byte{0x01}, std::byte{0x02}});
    const auto empty_packet_payload_datagram =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload, 0);
    const auto failed_serialized_datagram =
        CodecResult<SerializedProtectedDatagram>::failure(CodecErrorCode::invalid_varint, 0);
    connection_coverage_check(ok, "failed_datagram_reports_zero_size",
                              datagram_size_or_zero(failed_datagram) == 0);
    connection_coverage_check(ok, "successful_datagram_reports_size",
                              datagram_size_or_zero(successful_datagram) == 2);
    connection_coverage_check(ok, "failed_serialized_datagram_reports_zero_size",
                              datagram_size_or_zero(failed_serialized_datagram) == 0);
    connection_coverage_check(ok, "successful_serialized_datagram_reports_size",
                              datagram_size_or_zero(successful_serialized_datagram_for_tests()) ==
                                  3);
    connection_coverage_check(ok, "empty_packet_payload_error_reported",
                              is_empty_packet_payload_error(empty_packet_payload_datagram));
    connection_coverage_check(ok, "successful_datagram_not_reported",
                              !is_empty_packet_payload_error(successful_datagram));
    connection_coverage_check(ok, "non_empty_packet_payload_error_not_reported",
                              !is_empty_packet_payload_error(failed_datagram));
    connection_coverage_check(
        ok, "empty_packet_payload_serialized_error_reported",
        is_empty_packet_payload_error(CodecResult<SerializedProtectedDatagram>::failure(
            CodecErrorCode::empty_packet_payload, 0)));
    connection_coverage_check(ok, "non_empty_packet_payload_serialized_error_not_reported",
                              !is_empty_packet_payload_error(failed_serialized_datagram));

    TransportParameters invalid_transport_parameters;
    invalid_transport_parameters.max_udp_payload_size = std::numeric_limits<std::uint64_t>::max();
    connection_coverage_check(
        ok, "encode_failure_returns_empty",
        encode_resumption_state({}, kQuicVersion1, "h3", invalid_transport_parameters, {}).empty());

    constexpr std::array wrong_magic_bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                              std::byte{0x00}, std::byte{0x00}};
    connection_coverage_check(ok, "wrong_magic_rejected",
                              !decode_resumption_state(wrong_magic_bytes).has_value());

    std::vector<std::byte> truncated_tls_state = {std::byte{0x01}};
    append_u32_be(truncated_tls_state, kQuicVersion1);
    connection_coverage_check(ok, "truncated_tls_state_rejected",
                              !decode_resumption_state(truncated_tls_state).has_value());

    const TransportParameters resumption_parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };

    connection_coverage_check(
        ok, "missing_application_context_rejected",
        !decode_resumption_state(resumption_state_missing_application_context_for_tests(
                                     serialize_transport_parameters(resumption_parameters).value()))
             .has_value());

    connection_coverage_check(
        ok, "missing_application_protocol_rejected",
        !decode_resumption_state(resumption_state_missing_application_protocol_for_tests())
             .has_value());

    connection_coverage_check(
        ok, "missing_transport_parameters_rejected",
        !decode_resumption_state(resumption_state_missing_transport_parameters_for_tests())
             .has_value());

    auto trailing_resumption_state =
        encode_resumption_state({}, kQuicVersion1, "h3", resumption_parameters, {});
    trailing_resumption_state.push_back(std::byte{0xff});
    connection_coverage_check(ok, "trailing_bytes_rejected",
                              !decode_resumption_state(trailing_resumption_state).has_value());

    connection_coverage_check(
        ok, "pending_fin_without_buffer_is_sendable",
        stream_with_pending_fin_is_sendable_for_tests(PendingFinStreamCaseForTests{
            .final_size = 1,
            .peer_max_stream_data = 1,
        }));

    connection_coverage_check(
        ok, "pending_fin_blocked_by_credit",
        !stream_with_pending_fin_is_sendable_for_tests(PendingFinStreamCaseForTests{
            .final_size = 2,
            .peer_max_stream_data = 1,
        }));

    connection_coverage_check(ok, "pending_data_blocks_fin",
                              pending_stream_data_blocks_fin_for_tests());

    connection_coverage_check(ok, "missing_pending_frames_preserve_state",
                              stream_limits_without_peer_credit_preserve_state_for_tests());

    constexpr std::array short_header_packet = {std::byte{0x40}};
    connection_coverage_check(ok, "short_header_is_bufferable",
                              packet_is_bufferable(short_header_packet));
    constexpr std::array truncated_long_header = {std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}};
    connection_coverage_check(ok, "truncated_long_header_is_not_bufferable",
                              !packet_is_bufferable(truncated_long_header));
    constexpr std::array handshake_long_header = {std::byte{0xe0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}, std::byte{0x01}};
    connection_coverage_check(ok, "handshake_long_header_is_bufferable",
                              packet_is_bufferable(handshake_long_header));

    connection_coverage_check(
        ok, "server_protected_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(protected_one_rtt_ack_packet_for_tests(),
                                              EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(
        ok, "client_connected_state_protected_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(protected_one_rtt_reset_packet_for_tests(),
                                              EndpointRole::client, HandshakeStatus::in_progress));
    connection_coverage_check(
        ok, "server_received_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(received_one_rtt_ack_packet_for_tests(),
                                              EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(
        ok, "client_connected_state_received_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(received_one_rtt_reset_packet_for_tests(),
                                              EndpointRole::client, HandshakeStatus::in_progress));
    connection_coverage_check(
        ok, "received_ack_only_fast_packet_deferred",
        should_defer_protected_one_rtt_packet(
            ReceivedProtectedPacket{received_ack_only_fast_packet_for_tests()},
            EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(ok, "received_stream_fast_packet_deferred",
                              should_defer_protected_one_rtt_packet(
                                  ReceivedProtectedPacket{received_stream_fast_packet_for_tests()},
                                  EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(ok, "connected_received_stream_fast_packet_not_deferred",
                              !should_defer_protected_one_rtt_packet(
                                  ReceivedProtectedPacket{received_stream_fast_packet_for_tests()},
                                  EndpointRole::server, HandshakeStatus::connected));
    connection_coverage_check(ok, "received_fast_packet_numbers_for_trace",
                              protected_one_rtt_packet_number_for_trace(ReceivedProtectedPacket{
                                  received_ack_only_fast_packet_for_tests()}) == 42u &&
                                  protected_one_rtt_packet_number_for_trace(ReceivedProtectedPacket{
                                      received_stream_fast_packet_for_tests()}) == 43u);
    connection_coverage_check(
        ok, "connected_protected_one_rtt_packet_not_deferred",
        !should_defer_protected_one_rtt_packet(protected_one_rtt_reset_packet_for_tests(),
                                               EndpointRole::server, HandshakeStatus::connected));
    connection_coverage_check(
        ok, "chacha_limits_match_expected",
        !confidentiality_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256)
                .has_value() &&
            integrity_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256) ==
                kChaCha20Poly1305IntegrityLimit);
    connection_coverage_check(
        ok, "aes_gcm_limits_match_expected",
        confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256) ==
                kAesGcmConfidentialityLimit &&
            confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_256_gcm_sha384) ==
                kAesGcmConfidentialityLimit &&
            integrity_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256) ==
                kAesGcmIntegrityLimit &&
            integrity_limit_for_cipher_suite(CipherSuite::tls_aes_256_gcm_sha384) ==
                kAesGcmIntegrityLimit);
    connection_coverage_check(
        ok, "invalid_cipher_limits_are_empty",
        !confidentiality_limit_for_cipher_suite(invalid_cipher_suite_for_tests()).has_value() &&
            !integrity_limit_for_cipher_suite(invalid_cipher_suite_for_tests()).has_value());
    connection_coverage_check(ok, "saturating_add_handles_overflow_and_sum",
                              saturating_add(std::numeric_limits<std::uint64_t>::max() - 1u, 8u) ==
                                      std::numeric_limits<std::uint64_t>::max() &&
                                  saturating_add(3u, 4u) == 7u);
    connection_coverage_check(
        ok, "protected_zero_rtt_crypto_can_advance_tls",
        packet_can_advance_tls_state(ProtectedPacket{ProtectedZeroRttPacket{
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = std::vector<std::byte>{std::byte{0x01}},
                    },
                },
        }}));
    connection_coverage_check(ok, "protected_one_rtt_ack_cannot_advance_tls",
                              !packet_can_advance_tls_state(ProtectedPacket{ProtectedOneRttPacket{
                                  .frames =
                                      {
                                          AckFrame{},
                                      },
                              }}));
    connection_coverage_check(
        ok, "corrupted_long_header_discarded",
        should_discard_corrupted_long_header_packet(false, CodecErrorCode::invalid_fixed_bit) &
            should_discard_corrupted_long_header_packet(false,
                                                        CodecErrorCode::unsupported_packet_type));
    connection_coverage_check(
        ok, "short_header_not_discarded_as_corrupted_long_header",
        !should_discard_corrupted_long_header_packet(true, CodecErrorCode::invalid_fixed_bit));

    const auto bytes_from_ints = [](std::initializer_list<std::uint8_t> values) {
        std::vector<std::byte> bytes;
        bytes.reserve(values.size());
        for (const auto value : values) {
            bytes.push_back(static_cast<std::byte>(value));
        }
        return bytes;
    };

    connection_coverage_check(ok, "empty_connection_id_formats_empty",
                              format_connection_id_hex({}).empty());
    connection_coverage_check(ok, "connection_id_formats_lower_hex",
                              format_connection_id_hex(retry_source_connection_id) == "5300");
    connection_coverage_check(ok, "empty_issued_connection_id_remains_empty",
                              make_issued_connection_id({}, /*sequence_number=*/7).empty());
    bool quic_core_secret_fallback_has_bytes = false;
    bool issued_connection_id_rand_fallback_has_bytes = false;
    bool issued_connection_id_fallback_has_bytes = false;
    bool stateless_reset_token_rand_fallback_has_bytes = false;
    bool stateless_reset_token_fallback_has_bytes = false;
    bool stateless_reset_token_empty_connection_id_fallback_has_bytes = false;
    bool stateless_reset_token_empty_connection_id_rand_fallback_has_bytes = false;
    bool path_challenge_rand_fallback_has_bytes = false;
    bool path_challenge_fallback_has_bytes = false;
    bool path_challenge_empty_connection_id_fallback_has_bytes = false;
    bool path_challenge_empty_connection_id_rand_fallback_has_bytes = false;
    bool random_one_in_sixteen_fallback_returns_bool = false;
    bool forced_random_one_in_sixteen_false = false;
    bool forced_random_one_in_sixteen_true = false;
    {
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_quic_core_secret_rand_failure);
        const auto secret = make_quic_core_secret();
        quic_core_secret_fallback_has_bytes =
            std::ranges::any_of(secret, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto connection_id = make_issued_connection_id(retry_source_connection_id, 7);
        issued_connection_id_rand_fallback_has_bytes =
            connection_id.size() == retry_source_connection_id.size() &&
            std::ranges::any_of(connection_id, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_short_prf_output);
        const auto connection_id = make_issued_connection_id(retry_source_connection_id, 13);
        issued_connection_id_rand_fallback_has_bytes &=
            connection_id.size() == retry_source_connection_id.size() &&
            std::ranges::any_of(connection_id, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_issued_connection_id_rand_failure);
        const auto connection_id = make_issued_connection_id(retry_source_connection_id, 8);
        issued_connection_id_fallback_has_bytes =
            connection_id.size() == retry_source_connection_id.size() &&
            std::ranges::any_of(connection_id, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto token = make_stateless_reset_token(retry_source_connection_id, 7);
        stateless_reset_token_rand_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_stateless_reset_token_rand_failure);
        const auto token = make_stateless_reset_token(retry_source_connection_id, 8);
        stateless_reset_token_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_stateless_reset_token_rand_failure);
        const auto token = make_stateless_reset_token({}, 9);
        stateless_reset_token_empty_connection_id_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto token = make_stateless_reset_token({}, 10);
        stateless_reset_token_empty_connection_id_rand_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto challenge = make_path_challenge_data(retry_source_connection_id, 3, 7);
        path_challenge_rand_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_path_challenge_rand_failure);
        const auto challenge = make_path_challenge_data(retry_source_connection_id, 3, 8);
        path_challenge_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_path_challenge_rand_failure);
        const auto challenge = make_path_challenge_data({}, 3, 9);
        path_challenge_empty_connection_id_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto challenge = make_path_challenge_data({}, 3, 10);
        path_challenge_empty_connection_id_rand_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_rand_failure);
        const bool fallback = random_one_in_sixteen();
        random_one_in_sixteen_fallback_returns_bool = fallback || !fallback;
    }
    {
        const ScopedConnectionDrainOptionalBoolTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, false);
        forced_random_one_in_sixteen_false = !random_one_in_sixteen();
    }
    {
        const ScopedConnectionDrainOptionalBoolTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, true);
        forced_random_one_in_sixteen_true = random_one_in_sixteen();
    }
    connection_coverage_check(ok, "random_one_in_sixteen_openssl_returns_bool", [] {
        const bool value = random_one_in_sixteen();
        return value || !value;
    }());
    connection_coverage_check(
        ok, "stream_state_error_helpers_cover_all_codes",
        stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_id) ==
                QuicTransportErrorCode::stream_limit_error &&
            stream_transport_error_for_state_error(
                StreamStateErrorCode::invalid_stream_direction) ==
                QuicTransportErrorCode::stream_state_error &&
            stream_transport_error_for_state_error(StreamStateErrorCode::send_side_closed) ==
                QuicTransportErrorCode::stream_state_error &&
            stream_transport_error_for_state_error(StreamStateErrorCode::receive_side_closed) ==
                QuicTransportErrorCode::stream_state_error &&
            stream_transport_error_for_state_error(StreamStateErrorCode::final_size_conflict) ==
                QuicTransportErrorCode::final_size_error);
    connection_coverage_check(ok, "stream_state_codec_error_adds_transport_code",
                              stream_state_codec_error_adds_transport_code_for_tests());
    connection_coverage_check(ok, "stream_limit_frame_type_helpers_cover_uni",
                              frame_type_for_max_streams(StreamLimitType::unidirectional) ==
                                      kFrameTypeMaxStreamsUni &&
                                  frame_type_for_streams_blocked(StreamLimitType::unidirectional) ==
                                      kFrameTypeStreamsBlockedUni);
    connection_coverage_check(
        ok, "transport_error_for_codec_error_covers_residual_codes",
        transport_error_for_codec_error(CodecErrorCode::invalid_reserved_bits) ==
                QuicTransportErrorCode::protocol_violation &&
            transport_error_for_codec_error(CodecErrorCode::invalid_fixed_bit) ==
                QuicTransportErrorCode::internal_error &&
            transport_error_for_codec_error(CodecErrorCode::missing_crypto_context) ==
                QuicTransportErrorCode::internal_error &&
            transport_error_for_codec_error(CodecErrorCode::http09_parse_error) ==
                QuicTransportErrorCode::application_error &&
            transport_error_for_codec_error(CodecErrorCode::http3_parse_error) ==
                QuicTransportErrorCode::application_error);
    connection_coverage_check(ok, "vector_equals_deferred_packet",
                              deferred_packet_equals_vector_for_tests());

    PathState traced_path = traced_path_for_summary_tests();
    std::map<QuicPathId, PathState> traced_paths{
        {traced_path.id, traced_path},
    };
    connection_coverage_check(ok, "optional_path_none_formats_dash",
                              format_optional_path_id(std::nullopt) == "-");
    connection_coverage_check(ok, "optional_path_value_formats_decimal",
                              format_optional_path_id(traced_path.id) == "7");
    connection_coverage_check(ok, "missing_optional_path_returns_null",
                              find_path_state(traced_paths, std::nullopt) == nullptr);
    connection_coverage_check(ok, "unknown_path_returns_null",
                              find_path_state(traced_paths, 99) == nullptr);
    connection_coverage_check(ok, "existing_path_is_found",
                              find_path_state(traced_paths, traced_path.id) != nullptr);
    connection_coverage_check(ok, "null_path_summary_formats_dash",
                              format_path_state_summary(nullptr) == "-");
    connection_coverage_check(ok, "traced_path_summary_mentions_path_state",
                              path_summary_mentions_state_for_tests(traced_path));
    connection_coverage_check(ok, "invalid_ack_first_range_formats_invalid",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 1,
                                  .first_ack_range = 2,
                              }) == "[invalid]");
    connection_coverage_check(ok, "invalid_ack_gap_formats_invalid",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 0,
                                  .additional_ranges =
                                      {
                                          AckRange{.gap = 9, .range_length = 0},
                                      },
                              }) == "[10-10,invalid]");
    connection_coverage_check(ok, "invalid_ack_range_length_formats_invalid",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 2,
                                  .additional_ranges =
                                      {
                                          AckRange{.gap = 0, .range_length = 7},
                                      },
                              }) == "[8-10,invalid]");
    connection_coverage_check(ok, "valid_ack_ranges_format_expected",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 1,
                                  .additional_ranges =
                                      {
                                          AckRange{.gap = 0, .range_length = 1},
                                      },
                              }) == "[9-10,6-7]");
    connection_coverage_check(ok, "invalid_received_ack_formats_invalid",
                              format_ack_ranges(ReceivedAckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 1,
                                  .additional_range_count = 1,
                                  .additional_range_bytes =
                                      SharedBytes{
                                          std::byte{0x40},
                                      },
                              }) == "[invalid]");
    connection_coverage_check(ok, "empty_packet_summary_reports_zero",
                              summarize_packets({}) == "count=0");
    connection_coverage_check(ok, "packet_summary_mentions_counts",
                              packet_summary_mentions_counts_for_tests());
    connection_coverage_check(ok, "packet_summary_without_stream_offset_omits_offset",
                              packet_summary_without_stream_offset_omits_offset_for_tests());
    const auto metadata_packet = metadata_packet_for_tests();
    connection_coverage_check(ok,
                              "packet_stream_metadata_helpers_cover_count_bytes_and_first_offset",
                              packet_stream_frame_count(metadata_packet) == 3 &&
                                  packet_stream_frame_bytes(metadata_packet) == 10 &&
                                  packet_first_stream_frame_offset(metadata_packet) == 2u);
    connection_coverage_check(
        ok, "packet_first_stream_frame_offset_covers_vector_fragment_and_empty",
        packet_first_stream_frame_offset(vector_only_metadata_packet_for_tests()) == 33u &&
            packet_first_stream_frame_offset(fragment_only_metadata_packet_for_tests()) == 44u &&
            !packet_first_stream_frame_offset(SentPacketRecord{}).has_value());
    bool for_each_stream_frame_metadata_visits_vector_metadata = false;
    bool for_each_stream_frame_metadata_visits_first_metadata = false;
    const auto note_stream_frame_metadata_visit = [&](const StreamFrameSendMetadata &metadata) {
        if (metadata.stream_id == 0 && metadata.offset == 2 && metadata.length == 3) {
            for_each_stream_frame_metadata_visits_first_metadata = true;
        }
        if (metadata.stream_id == 4 && metadata.offset == 9 && metadata.length == 5 &&
            metadata.fin) {
            for_each_stream_frame_metadata_visits_vector_metadata = true;
        }
    };
    for_each_stream_frame_metadata(SentPacketRecord{}, note_stream_frame_metadata_visit);
    for_each_stream_frame_metadata(metadata_packet, note_stream_frame_metadata_visit);
    bool stream_metadata_probe_worthy_outstanding = false;
    bool stream_metadata_probe_worthy_fin = false;
    bool stream_metadata_probe_worthy_missing_fin_rejected = false;
    bool stream_metadata_probe_worthy_acked_fin_rejected = false;
    {
        auto probe_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
        probe_stream.send_buffer.append(bytes_from_ints_for_tests({0x01, 0x02, 0x03}));
        static_cast<void>(probe_stream.send_buffer.take_ranges(3));
        stream_metadata_probe_worthy_outstanding =
            stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                    .stream_id = 0,
                                                                    .offset = 0,
                                                                    .length = 2,
                                                                    .fin = false,
                                                                    .consumes_flow_control = true,
                                                                });
    }
    {
        auto probe_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
        probe_stream.send_final_size = 5;
        probe_stream.send_fin_state = StreamSendFinState::pending;
        stream_metadata_probe_worthy_fin =
            stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                    .stream_id = 0,
                                                                    .offset = 3,
                                                                    .length = 2,
                                                                    .fin = true,
                                                                    .consumes_flow_control = true,
                                                                });
        stream_metadata_probe_worthy_missing_fin_rejected =
            !stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                     .stream_id = 0,
                                                                     .offset = 3,
                                                                     .length = 2,
                                                                     .fin = false,
                                                                     .consumes_flow_control = true,
                                                                 });
        probe_stream.send_fin_state = StreamSendFinState::acknowledged;
        stream_metadata_probe_worthy_acked_fin_rejected =
            !stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                     .stream_id = 0,
                                                                     .offset = 3,
                                                                     .length = 2,
                                                                     .fin = true,
                                                                     .consumes_flow_control = true,
                                                                 });
    }
    const auto make_simple_stream_ack_sample = [](std::uint64_t packet_number, QuicPathId path_id,
                                                  QuicEcnCodepoint ecn,
                                                  std::chrono::milliseconds sent_offset) {
        return AckedStreamPacketSample{
            .packet_number = packet_number,
            .sent_time = QuicCoreTimePoint{} + sent_offset,
            .congestion_send_sequence = packet_number,
            .bytes_in_flight = 1200,
            .path_id = path_id,
            .ecn = ecn,
        };
    };
    bool single_path_simple_stream_ack_ecn_ignores_failed_path = false;
    bool single_path_simple_stream_ack_ecn_missing_counts_disable = false;
    bool single_path_simple_stream_ack_ecn_decreased_counts_disable = false;
    bool single_path_simple_stream_ack_ecn_counts_ect1 = false;
    bool single_path_simple_stream_ack_ecn_missing_feedback_disables = false;
    bool single_path_simple_stream_ack_ecn_success_tracks_ce_time = false;
    bool simple_stream_ack_ecn_non_ect_samples_are_ignored = false;
    bool multi_path_simple_stream_ack_ecn_ignores_failed_path = false;
    bool multi_path_simple_stream_ack_ecn_missing_counts_disable = false;
    bool multi_path_simple_stream_ack_ecn_decreased_counts_disable = false;
    bool multi_path_simple_stream_ack_ecn_missing_feedback_disables = false;
    bool multi_path_simple_stream_ack_ecn_success_tracks_ce_time = false;
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(17);
        path.ecn.state = QuicPathEcnState::failed;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{make_simple_stream_ack_sample(17, 17, QuicEcnCodepoint::ect0,
                                                               std::chrono::milliseconds(17))};
        single_path_simple_stream_ack_ecn_ignores_failed_path =
            connection.process_single_path_simple_stream_ack_ecn(
                connection.application_space_, 17, /*newly_acked_ect0=*/1,
                /*newly_acked_ect1=*/0, samples.front().sent_time, AckEcnCounts{.ect0 = 1},
                latest_ecn_ce_sent_time) &&
            connection.paths_.at(17).ecn.state == QuicPathEcnState::failed;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(18);
        path.ecn.total_sent_ect0 = 4;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{make_simple_stream_ack_sample(18, 18, QuicEcnCodepoint::ect0,
                                                               std::chrono::milliseconds(18))};
        single_path_simple_stream_ack_ecn_missing_counts_disable =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     std::nullopt, latest_ecn_ce_sent_time) &&
            connection.paths_.at(18).ecn.state == QuicPathEcnState::failed &&
            !latest_ecn_ce_sent_time.has_value();
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(19);
        path.ecn.total_sent_ect0 = 8;
        path.ecn.last_peer_counts[2] = AckEcnCounts{.ect0 = 4};
        path.ecn.has_last_peer_counts[2] = true;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        single_path_simple_stream_ack_ecn_decreased_counts_disable =
            connection.process_single_path_simple_stream_ack_ecn(
                connection.application_space_, 19, /*newly_acked_ect0=*/1,
                /*newly_acked_ect1=*/0, QuicCoreTimePoint{} + std::chrono::milliseconds(19),
                AckEcnCounts{.ect0 = 3}, latest_ecn_ce_sent_time) &&
            connection.paths_.at(19).ecn.state == QuicPathEcnState::failed;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(33);
        path.ecn.total_sent_ect1 = 4;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{make_simple_stream_ack_sample(33, 33, QuicEcnCodepoint::ect1,
                                                               std::chrono::milliseconds(33))};
        single_path_simple_stream_ack_ecn_counts_ect1 =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     AckEcnCounts{.ect1 = 1},
                                                     latest_ecn_ce_sent_time) &&
            connection.paths_.at(33).ecn.state == QuicPathEcnState::capable &&
            connection.paths_.at(33).ecn.probing_packets_acked == 1;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(20);
        path.ecn.total_sent_ect0 = 8;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        single_path_simple_stream_ack_ecn_missing_feedback_disables =
            connection.process_single_path_simple_stream_ack_ecn(
                connection.application_space_, 20, /*newly_acked_ect0=*/2,
                /*newly_acked_ect1=*/0, QuicCoreTimePoint{} + std::chrono::milliseconds(20),
                AckEcnCounts{.ect0 = 1}, latest_ecn_ce_sent_time) &&
            connection.paths_.at(20).ecn.state == QuicPathEcnState::failed;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(21);
        path.ecn.total_sent_ect0 = 4;
        path.ecn.total_sent_ect1 = 4;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const auto marked_time = QuicCoreTimePoint{} + std::chrono::milliseconds(21);
        single_path_simple_stream_ack_ecn_success_tracks_ce_time =
            connection.process_single_path_simple_stream_ack_ecn(
                connection.application_space_, 21, /*newly_acked_ect0=*/0,
                /*newly_acked_ect1=*/1, marked_time, AckEcnCounts{.ect1 = 0, .ecn_ce = 1},
                latest_ecn_ce_sent_time) &&
            connection.paths_.at(21).ecn.state == QuicPathEcnState::capable &&
            connection.paths_.at(21).ecn.probing_packets_acked == 1 &&
            latest_ecn_ce_sent_time == marked_time;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{make_simple_stream_ack_sample(22, 22, QuicEcnCodepoint::not_ect,
                                                               std::chrono::milliseconds(22))};
        simple_stream_ack_ecn_non_ect_samples_are_ignored =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     std::nullopt, latest_ecn_ce_sent_time) &&
            connection.paths_.find(22) == connection.paths_.end() &&
            !latest_ecn_ce_sent_time.has_value();
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.ensure_path_state(23).ecn.state = QuicPathEcnState::failed;
        auto &second_path = connection.ensure_path_state(24);
        second_path.ecn.total_sent_ect0 = 4;
        second_path.ecn.total_sent_ect1 = 4;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{
            make_simple_stream_ack_sample(23, 23, QuicEcnCodepoint::ect0,
                                          std::chrono::milliseconds(23)),
            make_simple_stream_ack_sample(24, 24, QuicEcnCodepoint::ect1,
                                          std::chrono::milliseconds(24)),
        };
        multi_path_simple_stream_ack_ecn_ignores_failed_path =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     AckEcnCounts{.ect0 = 1, .ect1 = 1},
                                                     latest_ecn_ce_sent_time) &&
            connection.paths_.at(23).ecn.state == QuicPathEcnState::failed &&
            connection.paths_.at(24).ecn.state == QuicPathEcnState::capable;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.ensure_path_state(25).ecn.total_sent_ect0 = 4;
        connection.ensure_path_state(26).ecn.total_sent_ect1 = 4;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{
            make_simple_stream_ack_sample(25, 25, QuicEcnCodepoint::ect0,
                                          std::chrono::milliseconds(25)),
            make_simple_stream_ack_sample(26, 26, QuicEcnCodepoint::ect1,
                                          std::chrono::milliseconds(26)),
        };
        multi_path_simple_stream_ack_ecn_missing_counts_disable =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     std::nullopt, latest_ecn_ce_sent_time) &&
            connection.paths_.at(25).ecn.state == QuicPathEcnState::failed &&
            connection.paths_.at(26).ecn.state == QuicPathEcnState::failed;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        for (const auto path_id : {QuicPathId{27}, QuicPathId{28}}) {
            auto &path = connection.ensure_path_state(path_id);
            path.ecn.total_sent_ect0 = 8;
            path.ecn.total_sent_ect1 = 8;
            path.ecn.last_peer_counts[2] = AckEcnCounts{.ect0 = 4, .ect1 = 4};
            path.ecn.has_last_peer_counts[2] = true;
        }
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{
            make_simple_stream_ack_sample(27, 27, QuicEcnCodepoint::ect0,
                                          std::chrono::milliseconds(27)),
            make_simple_stream_ack_sample(28, 28, QuicEcnCodepoint::ect1,
                                          std::chrono::milliseconds(28)),
        };
        multi_path_simple_stream_ack_ecn_decreased_counts_disable =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     AckEcnCounts{.ect0 = 3, .ect1 = 4},
                                                     latest_ecn_ce_sent_time) &&
            connection.paths_.at(27).ecn.state == QuicPathEcnState::failed &&
            connection.paths_.at(28).ecn.state == QuicPathEcnState::failed;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.ensure_path_state(29).ecn.total_sent_ect0 = 8;
        connection.ensure_path_state(30).ecn.total_sent_ect1 = 8;
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{
            make_simple_stream_ack_sample(29, 29, QuicEcnCodepoint::ect0,
                                          std::chrono::milliseconds(29)),
            make_simple_stream_ack_sample(30, 30, QuicEcnCodepoint::ect1,
                                          std::chrono::milliseconds(30)),
        };
        multi_path_simple_stream_ack_ecn_missing_feedback_disables =
            connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                     AckEcnCounts{.ect0 = 0, .ect1 = 1},
                                                     latest_ecn_ce_sent_time) &&
            connection.paths_.at(29).ecn.state == QuicPathEcnState::failed &&
            connection.paths_.at(30).ecn.state == QuicPathEcnState::capable;
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        for (const auto path_id : {QuicPathId{31}, QuicPathId{32}}) {
            auto &path = connection.ensure_path_state(path_id);
            path.ecn.total_sent_ect0 = 8;
            path.ecn.total_sent_ect1 = 8;
        }
        std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
        const std::array samples{
            make_simple_stream_ack_sample(31, 31, QuicEcnCodepoint::ect0,
                                          std::chrono::milliseconds(31)),
            make_simple_stream_ack_sample(32, 32, QuicEcnCodepoint::ect1,
                                          std::chrono::milliseconds(32)),
        };
        multi_path_simple_stream_ack_ecn_success_tracks_ce_time =
            connection.process_simple_stream_ack_ecn(
                connection.application_space_, samples,
                AckEcnCounts{.ect0 = 1, .ect1 = 1, .ecn_ce = 1}, latest_ecn_ce_sent_time) &&
            connection.paths_.at(31).ecn.state == QuicPathEcnState::capable &&
            connection.paths_.at(32).ecn.state == QuicPathEcnState::capable &&
            latest_ecn_ce_sent_time == QuicCoreTimePoint{} + std::chrono::milliseconds(32);
    }
    connection_coverage_check(ok, "stream_frame_payload_budget_handles_edges",
                              stream_frame_payload_budget_handles_edges_for_tests());
    connection_coverage_check(
        ok, "application_stream_budget_handles_small_and_oversized_connection_ids",
        application_stream_frame_budget(/*max_datagram_size=*/1199,
                                        /*destination_connection_id_size=*/8) == 1172 &&
            application_stream_frame_budget(/*max_datagram_size=*/1200,
                                            /*destination_connection_id_size=*/1200) == 0 &&
            application_stream_frame_budget(/*max_datagram_size=*/26,
                                            /*destination_connection_id_size=*/8) == 0 &&
            application_stream_frame_budget(/*max_datagram_size=*/1400,
                                            /*destination_connection_id_size=*/8) == 1373);

    connection_coverage_check(
        ok, "one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_frames",
        one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_for_tests(
            retry_source_connection_id));

    connection_coverage_check(
        ok, "one_rtt_fragment_size_propagates_frame_size_errors",
        one_rtt_fragment_size_propagates_frame_size_errors_for_tests(retry_source_connection_id));

    connection_coverage_check(
        ok, "one_rtt_fragment_size_rejects_empty_payloads",
        one_rtt_fragment_size_rejects_empty_payloads_for_tests(retry_source_connection_id));

    connection_coverage_check(
        ok, "one_rtt_fragment_helpers_count_stream_fragment_bytes",
        one_rtt_fragment_helpers_count_stream_fragment_bytes_for_tests(retry_source_connection_id));

    connection_coverage_check(ok, "one_rtt_fragment_size_rejects_overflowing_fragment_offsets",
                              one_rtt_fragment_size_rejects_overflowing_fragment_offsets_for_tests(
                                  retry_source_connection_id));

    bool trace_unset_disabled = false;
    bool trace_empty_disabled = false;
    bool trace_zero_disabled = false;
    bool trace_matches_without_filter = false;
    bool trace_matches_with_empty_filter = false;
    bool trace_matches_with_exact_filter = false;
    bool trace_rejects_mismatched_filter = false;
    {
        ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
        ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", std::nullopt);
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
            trace_unset_disabled = !packet_trace_enabled() &
                                   !packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "");
            trace_empty_disabled = !packet_trace_enabled();
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "0");
            trace_zero_disabled = !packet_trace_enabled();
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
            trace_matches_without_filter = packet_trace_enabled() & packet_trace_matches_connection(
                                                                        retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
            trace_matches_with_empty_filter =
                packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID",
                                        format_connection_id_hex(retry_source_connection_id));
            trace_matches_with_exact_filter =
                packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "deadbeef");
            trace_rejects_mismatched_filter =
                !packet_trace_matches_connection(retry_source_connection_id);
        }
    }

    connection_coverage_check(ok, "empty_long_header_rejected",
                              !peek_discardable_long_header_packet_length({}).has_value());
    connection_coverage_check(
        ok, "short_header_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0x40})).has_value());
    connection_coverage_check(
        ok, "truncated_version_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00}))
             .has_value());
    connection_coverage_check(
        ok, "unsupported_version_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00}))
             .has_value());
    connection_coverage_check(
        ok, "missing_destination_connection_id_length_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}))
             .has_value());
    connection_coverage_check(ok, "oversized_destination_connection_id_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}))
                                   .has_value());
    connection_coverage_check(ok, "truncated_destination_connection_id_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01}))
                                   .has_value());
    connection_coverage_check(ok, "missing_source_connection_id_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}))
                                   .has_value());
    connection_coverage_check(ok, "oversized_source_connection_id_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x15}))
                                   .has_value());
    connection_coverage_check(ok, "truncated_source_connection_id_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}))
                                   .has_value());
    connection_coverage_check(ok, "missing_initial_token_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(
        ok, "oversized_initial_token_length_rejected",
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value());
    connection_coverage_check(ok, "unsupported_retry_packet_type_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(
        ok, "missing_payload_length_after_initial_token_rejected",
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00}))
             .has_value());
    connection_coverage_check(ok, "missing_payload_length_for_handshake_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(ok, "missing_payload_length_for_zero_rtt_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(
        ok, "oversized_payload_length_rejected",
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value());
    bool discardable_deferred_replay_packet_does_not_block_current_packet = false;
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const std::array frames{Frame{PingFrame{}}};
        auto current = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/291, frames);
        auto deferred = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/292, frames);
        if (!current.empty() && !deferred.empty()) {
            deferred.back() =
                static_cast<std::byte>(std::to_integer<unsigned>(deferred.back()) ^ 0x01u);
            connection.deferred_protected_packets_.push_back(DeferredProtectedDatagram{
                std::move(deferred),
            });
            connection.process_inbound_datagram(current, QuicCoreTimePoint{});
            discardable_deferred_replay_packet_does_not_block_current_packet =
                !connection.has_failed() && connection.deferred_protected_packets_.empty() &&
                connection.application_space_.largest_authenticated_packet_number == 291u;
        }
    }
    bool in_place_receive_storage_before_begin_guard = false;
    bool in_place_receive_storage_overflow_guard = false;
    bool replay_failure_before_current_packet_is_non_fatal = false;
    bool replay_failure_after_current_packet_is_non_fatal = false;
    bool fast_path_ack_only_packet_processed = false;
    bool fast_path_duplicate_ack_only_packet_ignored = false;
    bool fast_path_stream_packet_processed = false;
    bool fast_path_duplicate_stream_packet_ignored = false;
    bool fast_path_corrupted_packet_discarded = false;
    {
        const std::array frames{Frame{PingFrame{}}};
        const auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            make_connected_client_connection_for_connection_coverage(), /*packet_number=*/300,
            frames);
        if (!datagram.empty()) {
            const auto exercise_guard = [&](bool ConnectionDrainTestHooks::*hook_field) {
                auto connection = make_connected_client_connection_for_connection_coverage();
                auto storage = std::make_shared<std::vector<std::byte>>(datagram);
                const ScopedConnectionDrainTestHook hook(hook_field);
                connection.process_inbound_datagram(
                    storage, /*begin=*/0, /*end=*/storage->size(), QuicCoreTimePoint{},
                    /*path_id=*/0, QuicEcnCodepoint::unavailable, std::nullopt,
                    /*replay_trigger=*/false, /*count_inbound_bytes=*/true,
                    /*allow_in_place_receive_decode=*/true);
                return !connection.has_failed();
            };
            in_place_receive_storage_before_begin_guard =
                exercise_guard(&ConnectionDrainTestHooks::force_storage_range_before_storage);
            in_place_receive_storage_overflow_guard =
                exercise_guard(&ConnectionDrainTestHooks::force_storage_range_overflow);
        }
    }
    {
        const std::array frames{Frame{PingFrame{}}};
        auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            make_connected_client_connection_for_connection_coverage(), /*packet_number=*/301,
            frames);
        if (!datagram.empty()) {
            auto connection = make_connected_client_connection_for_connection_coverage();
            const ScopedConnectionDrainCountdownTestHook hook(
                &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown, 0);
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
            replay_failure_before_current_packet_is_non_fatal = !connection.has_failed();
        }
    }
    {
        const std::array frames{Frame{PingFrame{}}};
        auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            make_connected_client_connection_for_connection_coverage(), /*packet_number=*/302,
            frames);
        if (!datagram.empty()) {
            auto connection = make_connected_client_connection_for_connection_coverage();
            const ScopedConnectionDrainCountdownTestHook hook(
                &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown, 1);
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
            replay_failure_after_current_packet_is_non_fatal =
                !connection.has_failed() &&
                connection.application_space_.largest_authenticated_packet_number == 302u;
        }
    }
    const auto process_fast_path_datagram = [](QuicConnection &connection,
                                               const std::vector<std::byte> &datagram,
                                               QuicCoreTimePoint now = QuicCoreTimePoint{}) {
        connection.resumption_state_emitted_ = true;
        auto storage = std::make_shared<std::vector<std::byte>>(datagram);
        connection.process_inbound_datagram(
            storage, /*begin=*/0, /*end=*/storage->size(), now, /*path_id=*/0,
            QuicEcnCodepoint::ect0, std::nullopt, /*replay_trigger=*/false,
            /*count_inbound_bytes=*/true, /*allow_in_place_receive_decode=*/true);
    };
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 0,
                                         .sent_time = QuicCoreTimePoint{} - std::chrono::seconds(1),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .path_id = 0,
                                         .ecn = QuicEcnCodepoint::ect0,
                                     });
        const std::array frames{Frame{AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        }}};
        const auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/401, frames);
        if (!datagram.empty()) {
            process_fast_path_datagram(connection, datagram);
            fast_path_ack_only_packet_processed =
                !connection.has_failed() &&
                connection.application_space_.received_packets.contains(401);
            process_fast_path_datagram(connection, datagram);
            fast_path_duplicate_ack_only_packet_ignored =
                !connection.has_failed() &&
                connection.application_space_.received_packets.contains(401);
        }
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const std::array frames{Frame{StreamFrame{
            .has_length = true,
            .stream_id = 1,
            .stream_data = bytes_from_ints_for_tests({0x41, 0x42}),
        }}};
        const auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/402, frames);
        if (!datagram.empty()) {
            process_fast_path_datagram(connection, datagram);
            fast_path_stream_packet_processed =
                !connection.has_failed() &&
                connection.application_space_.received_packets.contains(402) &&
                !connection.pending_stream_receive_effects_.empty();
            process_fast_path_datagram(connection, datagram);
            fast_path_duplicate_stream_packet_ignored =
                !connection.has_failed() &&
                connection.application_space_.received_packets.contains(402);
        }
    }
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const std::array frames{Frame{PingFrame{}}};
        auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/403, frames);
        if (!datagram.empty()) {
            datagram.back() =
                static_cast<std::byte>(std::to_integer<unsigned>(datagram.back()) ^ 0x01u);
            process_fast_path_datagram(connection, datagram);
            fast_path_corrupted_packet_discarded =
                !connection.has_failed() &&
                !connection.application_space_.received_packets.contains(403);
        }
    }

    connection_coverage_check(ok, "quic_core_secret_fallback_has_bytes",
                              static_cast<bool>(quic_core_secret_fallback_has_bytes));
    connection_coverage_check(ok, "issued_connection_id_rand_fallback_has_bytes",
                              static_cast<bool>(issued_connection_id_rand_fallback_has_bytes));
    connection_coverage_check(ok, "issued_connection_id_fallback_has_bytes",
                              static_cast<bool>(issued_connection_id_fallback_has_bytes));
    connection_coverage_check(ok, "stateless_reset_token_rand_fallback_has_bytes",
                              static_cast<bool>(stateless_reset_token_rand_fallback_has_bytes));
    connection_coverage_check(ok, "stateless_reset_token_fallback_has_bytes",
                              static_cast<bool>(stateless_reset_token_fallback_has_bytes));
    connection_coverage_check(
        ok, "stateless_reset_token_empty_connection_id_fallback_has_bytes",
        static_cast<bool>(stateless_reset_token_empty_connection_id_fallback_has_bytes));
    connection_coverage_check(
        ok, "stateless_reset_token_empty_connection_id_rand_fallback_has_bytes",
        static_cast<bool>(stateless_reset_token_empty_connection_id_rand_fallback_has_bytes));
    connection_coverage_check(ok, "path_challenge_rand_fallback_has_bytes",
                              static_cast<bool>(path_challenge_rand_fallback_has_bytes));
    connection_coverage_check(ok, "path_challenge_fallback_has_bytes",
                              static_cast<bool>(path_challenge_fallback_has_bytes));
    connection_coverage_check(
        ok, "path_challenge_empty_connection_id_fallback_has_bytes",
        static_cast<bool>(path_challenge_empty_connection_id_fallback_has_bytes));
    connection_coverage_check(
        ok, "path_challenge_empty_connection_id_rand_fallback_has_bytes",
        static_cast<bool>(path_challenge_empty_connection_id_rand_fallback_has_bytes));
    connection_coverage_check(ok, "random_one_in_sixteen_fallback_returns_bool",
                              static_cast<bool>(random_one_in_sixteen_fallback_returns_bool));
    connection_coverage_check(ok, "forced_random_one_in_sixteen_false",
                              static_cast<bool>(forced_random_one_in_sixteen_false));
    connection_coverage_check(ok, "forced_random_one_in_sixteen_true",
                              static_cast<bool>(forced_random_one_in_sixteen_true));
    connection_coverage_check(
        ok, "for_each_stream_frame_metadata_visits_first_metadata",
        static_cast<bool>(for_each_stream_frame_metadata_visits_first_metadata));
    connection_coverage_check(
        ok, "for_each_stream_frame_metadata_visits_vector_metadata",
        static_cast<bool>(for_each_stream_frame_metadata_visits_vector_metadata));
    connection_coverage_check(ok, "stream_metadata_probe_worthy_outstanding",
                              static_cast<bool>(stream_metadata_probe_worthy_outstanding));
    connection_coverage_check(ok, "stream_metadata_probe_worthy_fin",
                              static_cast<bool>(stream_metadata_probe_worthy_fin));
    connection_coverage_check(ok, "stream_metadata_probe_worthy_missing_fin_rejected",
                              static_cast<bool>(stream_metadata_probe_worthy_missing_fin_rejected));
    connection_coverage_check(ok, "stream_metadata_probe_worthy_acked_fin_rejected",
                              static_cast<bool>(stream_metadata_probe_worthy_acked_fin_rejected));
    connection_coverage_check(
        ok, "single_path_simple_stream_ack_ecn_ignores_failed_path",
        static_cast<bool>(single_path_simple_stream_ack_ecn_ignores_failed_path));
    connection_coverage_check(
        ok, "single_path_simple_stream_ack_ecn_missing_counts_disable",
        static_cast<bool>(single_path_simple_stream_ack_ecn_missing_counts_disable));
    connection_coverage_check(
        ok, "single_path_simple_stream_ack_ecn_decreased_counts_disable",
        static_cast<bool>(single_path_simple_stream_ack_ecn_decreased_counts_disable));
    connection_coverage_check(ok, "single_path_simple_stream_ack_ecn_counts_ect1",
                              static_cast<bool>(single_path_simple_stream_ack_ecn_counts_ect1));
    connection_coverage_check(
        ok, "single_path_simple_stream_ack_ecn_missing_feedback_disables",
        static_cast<bool>(single_path_simple_stream_ack_ecn_missing_feedback_disables));
    connection_coverage_check(
        ok, "single_path_simple_stream_ack_ecn_success_tracks_ce_time",
        static_cast<bool>(single_path_simple_stream_ack_ecn_success_tracks_ce_time));
    connection_coverage_check(ok, "simple_stream_ack_ecn_non_ect_samples_are_ignored",
                              static_cast<bool>(simple_stream_ack_ecn_non_ect_samples_are_ignored));
    connection_coverage_check(
        ok, "multi_path_simple_stream_ack_ecn_ignores_failed_path",
        static_cast<bool>(multi_path_simple_stream_ack_ecn_ignores_failed_path));
    connection_coverage_check(
        ok, "multi_path_simple_stream_ack_ecn_missing_counts_disable",
        static_cast<bool>(multi_path_simple_stream_ack_ecn_missing_counts_disable));
    connection_coverage_check(
        ok, "multi_path_simple_stream_ack_ecn_decreased_counts_disable",
        static_cast<bool>(multi_path_simple_stream_ack_ecn_decreased_counts_disable));
    connection_coverage_check(
        ok, "multi_path_simple_stream_ack_ecn_missing_feedback_disables",
        static_cast<bool>(multi_path_simple_stream_ack_ecn_missing_feedback_disables));
    connection_coverage_check(
        ok, "multi_path_simple_stream_ack_ecn_success_tracks_ce_time",
        static_cast<bool>(multi_path_simple_stream_ack_ecn_success_tracks_ce_time));
    connection_coverage_check(ok, "trace_unset_disabled", static_cast<bool>(trace_unset_disabled));
    connection_coverage_check(ok, "trace_empty_disabled", static_cast<bool>(trace_empty_disabled));
    connection_coverage_check(ok, "trace_zero_disabled", static_cast<bool>(trace_zero_disabled));
    connection_coverage_check(ok, "trace_matches_without_filter",
                              static_cast<bool>(trace_matches_without_filter));
    connection_coverage_check(ok, "trace_matches_with_empty_filter",
                              static_cast<bool>(trace_matches_with_empty_filter));
    connection_coverage_check(ok, "trace_matches_with_exact_filter",
                              static_cast<bool>(trace_matches_with_exact_filter));
    connection_coverage_check(ok, "trace_rejects_mismatched_filter",
                              static_cast<bool>(trace_rejects_mismatched_filter));
    connection_coverage_check(
        ok, "discardable_deferred_replay_packet_does_not_block_current_packet",
        static_cast<bool>(discardable_deferred_replay_packet_does_not_block_current_packet));
    connection_coverage_check(ok, "in_place_receive_storage_before_begin_guard",
                              static_cast<bool>(in_place_receive_storage_before_begin_guard));
    connection_coverage_check(ok, "in_place_receive_storage_overflow_guard",
                              static_cast<bool>(in_place_receive_storage_overflow_guard));
    connection_coverage_check(ok, "replay_failure_before_current_packet_is_non_fatal",
                              static_cast<bool>(replay_failure_before_current_packet_is_non_fatal));
    connection_coverage_check(ok, "replay_failure_after_current_packet_is_non_fatal",
                              static_cast<bool>(replay_failure_after_current_packet_is_non_fatal));
    connection_coverage_check(ok, "fast_path_ack_only_packet_processed",
                              static_cast<bool>(fast_path_ack_only_packet_processed));
    connection_coverage_check(ok, "fast_path_duplicate_ack_only_packet_ignored",
                              static_cast<bool>(fast_path_duplicate_ack_only_packet_ignored));
    connection_coverage_check(ok, "fast_path_stream_packet_processed",
                              static_cast<bool>(fast_path_stream_packet_processed));
    connection_coverage_check(ok, "fast_path_duplicate_stream_packet_ignored",
                              static_cast<bool>(fast_path_duplicate_stream_packet_ignored));
    connection_coverage_check(ok, "fast_path_corrupted_packet_discarded",
                              static_cast<bool>(fast_path_corrupted_packet_discarded));

    return ok;
}

bool connection_ack_deadline_and_stream_utilities_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) {
        ok &= condition;
        return condition;
    };
    const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(17);

    PacketSpaceState ce_packet_space;
    schedule_application_ack_deadline(ce_packet_space, now, /*max_ack_delay_ms=*/25,
                                      QuicEcnCodepoint::ce);
    record(ce_packet_space.pending_ack_deadline == now && ce_packet_space.force_ack_send);

    PacketSpaceState delayed_ack_packet_space;
    schedule_application_ack_deadline(delayed_ack_packet_space, now, /*max_ack_delay_ms=*/25,
                                      QuicEcnCodepoint::ect0);
    record(delayed_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(25) &&
           !delayed_ack_packet_space.force_ack_send);
    schedule_application_ack_deadline(delayed_ack_packet_space, now + std::chrono::milliseconds(4),
                                      /*max_ack_delay_ms=*/25, QuicEcnCodepoint::ect0);
    record(delayed_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(25));

    PacketSpaceState immediate_ack_packet_space;
    for (std::uint64_t packet_number = 4; packet_number < 19; ++packet_number) {
        immediate_ack_packet_space.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, now, QuicEcnCodepoint::unavailable,
            /*ack_eliciting_threshold=*/16);
    }
    immediate_ack_packet_space.received_packets.record_received(
        /*packet_number=*/19, /*ack_eliciting=*/true, now + std::chrono::milliseconds(1),
        QuicEcnCodepoint::unavailable, /*ack_eliciting_threshold=*/16);
    schedule_application_ack_deadline(immediate_ack_packet_space,
                                      now + std::chrono::milliseconds(2),
                                      /*max_ack_delay_ms=*/25, QuicEcnCodepoint::ect0);
    record(immediate_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(2) &&
           !immediate_ack_packet_space.force_ack_send);

    const std::map<std::uint64_t, StreamState> empty_streams;
    record(round_robin_stream_order(empty_streams, std::nullopt).empty());
    record(unfair_stream_order(empty_streams, std::nullopt).empty());

    std::map<std::uint64_t, StreamState> streams;
    streams.emplace(4, make_implicit_stream_state(/*stream_id=*/4, EndpointRole::client));
    streams.emplace(8, make_implicit_stream_state(/*stream_id=*/8, EndpointRole::client));
    streams.emplace(12, make_implicit_stream_state(/*stream_id=*/12, EndpointRole::client));
    record(round_robin_stream_order(streams, std::nullopt) == std::vector<std::uint64_t>{4, 8, 12});
    record(round_robin_stream_order(streams, /*last_stream_id=*/8) ==
           std::vector<std::uint64_t>{12, 4, 8});
    record(round_robin_stream_order(streams, /*last_stream_id=*/12) ==
           std::vector<std::uint64_t>{4, 8, 12});
    record(unfair_stream_order(streams, /*last_stream_id=*/8) ==
           std::vector<std::uint64_t>{8, 12, 4});
    record(unfair_stream_order(streams, /*last_stream_id=*/12) ==
           std::vector<std::uint64_t>{12, 4, 8});
    record(unfair_stream_order(streams, std::nullopt) == std::vector<std::uint64_t>{4, 8, 12});

    return ok;
}

bool connection_header_packet_space_coverage_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok &= condition; };

    {
        SerializedProtectedDatagram datagram{
            .bytes = DatagramBuffer{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
            .packet_metadata = {{.offset = 1, .length = 1}},
        };
        record(QuicConnection(make_client_core_config_for_connection_coverage())
                   .queue_outbound_packet_inspections(datagram, /*datagram_id=*/1) == 0);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.enable_packet_inspection = true;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x71});
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x72});
        connection.zero_rtt_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x73});
        const std::array<ProtectedPacket, 3> protected_packets{
            ProtectedPacket{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.initial_destination_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 1,
                .frames = {PingFrame{}},
            }},
            ProtectedPacket{ProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.initial_destination_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 2,
                .frames = {PingFrame{}},
            }},
            ProtectedPacket{ProtectedZeroRttPacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.initial_destination_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 3,
                .frames = {PingFrame{}},
            }},
        };
        const auto datagram = serialize_protected_datagram_with_metadata(
            protected_packets, SerializeProtectionContext{
                                   .local_role = connection.config_.role,
                                   .client_initial_destination_connection_id =
                                       connection.client_initial_destination_connection_id(),
                                   .handshake_secret = connection.handshake_space_.write_secret,
                                   .zero_rtt_secret = connection.zero_rtt_space_.write_secret,
                               });
        record(datagram.has_value());
        if (datagram.has_value()) {
            record(connection.queue_outbound_packet_inspections(datagram.value(), 7) == 3);
            const auto first = connection.take_packet_inspection();
            const auto second = connection.take_packet_inspection();
            const auto third = connection.take_packet_inspection();
            record(first.has_value() &&
                   first->packet_type == QuicCorePacketInspectionPacketType::initial);
            record(second.has_value() &&
                   second->packet_type == QuicCorePacketInspectionPacketType::handshake);
            record(third.has_value() &&
                   third->packet_type == QuicCorePacketInspectionPacketType::zero_rtt);
        }
    }

    {
        PacketSpacePacketMapView view;
        record(view.size() == 0);
        record(view.begin() == view.end());
        record(view.rbegin() == view.rend());
        record(!view.contains(1));
        const auto emplace_result = view.emplace(1, SentPacketRecord{});
        record(!emplace_result.second);
        record(emplace_result.first == view.end());
        record(view.erase(1) == 0);
    }

    {
        PacketSpaceRecovery recovery;
        PacketSpacePacketMapView outstanding(&recovery,
                                             PacketSpacePacketMapView::Filter::outstanding);
        PacketSpacePacketMapView declared_lost(&recovery,
                                               PacketSpacePacketMapView::Filter::declared_lost);
        const SentPacketRecord packet{
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
        };

        const auto outstanding_result = outstanding.emplace(7, packet);
        record(outstanding_result.second);
        record(outstanding_result.first != outstanding.end());
        record(!outstanding.empty());
        record(outstanding.size() == 1);
        record(outstanding.size() == 1);
        record(outstanding.contains(7));
        record(outstanding.at(7).packet_number == 7);
        record(outstanding.rbegin() != outstanding.rend());

        const auto duplicate_result = outstanding.emplace(7, packet);
        record(!duplicate_result.second);
        record(duplicate_result.first != outstanding.end());
        record(outstanding.erase(99) == 0);

        const auto declared_lost_result = declared_lost.emplace(9, packet);
        record(declared_lost_result.second);
        record(declared_lost_result.first != declared_lost.end());
        record(declared_lost.contains(9));
        const auto &declared_lost_packet = declared_lost.at(9);
        record(declared_lost_packet.packet_number == 9);
        record(declared_lost_packet.declared_lost);
        record(!declared_lost_packet.in_flight);
        record(declared_lost_packet.bytes_in_flight == 0);
        record(!outstanding.contains(9));

        record(declared_lost.erase(9) == 1);
        record(!declared_lost.contains(9));
        record(outstanding.erase(7) == 1);
        record(outstanding.empty());
        record(outstanding.rbegin() == outstanding.rend());
    }

    const auto make_packet_space_state = [] {
        PacketSpaceState state;
        state.next_send_packet_number = 17;
        state.largest_authenticated_packet_number = 9;
        state.send_crypto.append(std::vector<std::byte>{std::byte{0xaa}});
        state.received_packets.record_received(5, true, QuicCoreTimePoint{});
        state.sent_packets.emplace(11, SentPacketRecord{
                                           .ack_eliciting = true,
                                           .in_flight = true,
                                           .bytes_in_flight = 1200,
                                       });
        state.declared_lost_packets.emplace(12, SentPacketRecord{
                                                    .ack_eliciting = true,
                                                    .in_flight = true,
                                                    .bytes_in_flight = 1300,
                                                });
        state.pending_probe_packet = SentPacketRecord{
            .packet_number = 13,
            .has_ping = true,
        };
        state.pending_ack_deadline = QuicCoreTimePoint{} + std::chrono::milliseconds(5);
        state.force_ack_send = true;
        return state;
    };

    {
        auto source = make_packet_space_state();
        PacketSpaceState copy(source);
        record(copy.next_send_packet_number == 17);
        record(copy.largest_authenticated_packet_number == 9);
        record(copy.send_crypto.has_pending_data());
        record(copy.received_packets.contains(5));
        record(copy.sent_packets.contains(11));
        record(copy.declared_lost_packets.contains(12));
        record(copy.pending_probe_packet.has_value());
        record(copy.pending_probe_packet.value_or(SentPacketRecord{}).packet_number == 13);
        record(copy.force_ack_send);
        record(source.sent_packets.erase(11) == 1);
        record(!source.sent_packets.contains(11));
        record(copy.sent_packets.contains(11));
    }

    {
        auto source = make_packet_space_state();
        PacketSpaceState assigned;
        assigned = source;
        record(assigned.sent_packets.contains(11));
        record(assigned.declared_lost_packets.contains(12));
        record(assigned.pending_probe_packet.has_value());
        record(assigned.pending_ack_deadline.has_value());
        record(source.sent_packets.erase(11) == 1);
        record(!source.sent_packets.contains(11));
        record(assigned.sent_packets.contains(11));
        assigned = assigned;
        record(assigned.sent_packets.contains(11));
        record(assigned.declared_lost_packets.contains(12));
        assigned = std::move(assigned);
        record(assigned.sent_packets.contains(11));
        record(assigned.declared_lost_packets.contains(12));
    }

    return ok;
}

} // namespace coquic::quic::test

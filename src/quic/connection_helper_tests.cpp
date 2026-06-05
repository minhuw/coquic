#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_support.h"
#include "src/quic/packet_crypto_test_hooks.h"

namespace coquic::quic::test {

bool successful_bool_result_for_coverage(const CodecResult<bool> &result) {
    return std::get<bool>(result.storage);
}

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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "stream_limits_without_peer_credit_emit_no_frames",
                              stream_limits.take_max_streams_frames().empty());
    connection_coverage_check(coverage_ok, "stream_limits_without_peer_credit_preserve_bidi_state",
                              stream_limits.max_streams_bidi_state ==
                                  StreamControlFrameState::pending);
    connection_coverage_check(coverage_ok, "stream_limits_without_peer_credit_preserve_uni_state",
                              stream_limits.max_streams_uni_state ==
                                  StreamControlFrameState::pending);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "stream_state_codec_error_has_transport_code",
                              codec_error.has_transport_error_code);
    connection_coverage_check(
        coverage_ok, "stream_state_codec_error_transport_code",
        codec_error.transport_error_code ==
            transport_error_code_value(QuicTransportErrorCode::stream_state_error));
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "path_summary_mentions_id",
                              summary.find("id=7") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_validated",
                              summary.find("val=1") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_current",
                              summary.find("cur=1") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_challenge",
                              summary.find("chal=1") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_outstanding",
                              summary.find("out=1") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_response",
                              summary.find("resp=1") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_received_bytes",
                              summary.find("recv=11") != std::string::npos);
    connection_coverage_check(coverage_ok, "path_summary_mentions_sent_bytes",
                              summary.find("sent=7") != std::string::npos);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "packet_summary_mentions_count",
                              summary.find("count=2") != std::string::npos);
    connection_coverage_check(coverage_ok, "packet_summary_mentions_packet_range",
                              summary.find("pn=5-9") != std::string::npos);
    connection_coverage_check(coverage_ok, "packet_summary_mentions_stream_fragment_count",
                              summary.find("stream_fragments=1") != std::string::npos);
    connection_coverage_check(coverage_ok, "packet_summary_mentions_first_stream_offset",
                              summary.find("first_stream_offset=4") != std::string::npos);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "packet_summary_without_offset_mentions_count",
                              summary.find("count=2") != std::string::npos);
    connection_coverage_check(coverage_ok, "packet_summary_without_offset_mentions_range",
                              summary.find("pn=6-8") != std::string::npos);
    connection_coverage_check(coverage_ok, "packet_summary_without_offset_mentions_zero_fragments",
                              summary.find("stream_fragments=0") != std::string::npos);
    connection_coverage_check(coverage_ok, "packet_summary_without_offset_omits_offset",
                              summary.find("first_stream_offset=") == std::string::npos);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "stream_frame_payload_budget_rejects_overflowing_offset",
                              max_stream_frame_payload_for_wire_budget(/*stream_id=*/0,
                                                                       kMaxQuicVarInt + 1u,
                                                                       /*wire_budget=*/1200) == 0);
    connection_coverage_check(coverage_ok, "stream_frame_payload_budget_rejects_tiny_wire_budget",
                              max_stream_frame_payload_for_wire_budget(/*stream_id=*/0,
                                                                       /*offset=*/0,
                                                                       /*wire_budget=*/1) == 0);
    connection_coverage_check(coverage_ok, "stream_frame_payload_budget_accepts_payload_budget",
                              max_stream_frame_payload_for_wire_budget(/*stream_id=*/0,
                                                                       /*offset=*/0,
                                                                       /*wire_budget=*/32) > 0);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "non_terminal_lengthless_stream_size_is_error",
                              !size.has_value());
    connection_coverage_check(coverage_ok, "non_terminal_lengthless_stream_size_error_code",
                              size.error().code == CodecErrorCode::packet_length_mismatch);
    connection_coverage_check(coverage_ok, "non_terminal_lengthless_stream_size_error_offset",
                              size.error().offset == 0);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "frame_size_error_is_error", !size.has_value());
    connection_coverage_check(coverage_ok, "frame_size_error_code",
                              size.error().code == CodecErrorCode::invalid_varint);
    connection_coverage_check(coverage_ok, "frame_size_error_offset", size.error().offset == 0);
    return coverage_ok;
}

bool one_rtt_fragment_size_rejects_empty_payloads_for_tests(
    const ConnectionId &destination_connection_id) {
    const std::array<Frame, 0> frames{};
    const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
        .destination_connection_id = destination_connection_id,
        .packet_number_length = 2,
        .frames = frames,
    });
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "empty_payload_size_is_error", !size.has_value());
    connection_coverage_check(coverage_ok, "empty_payload_size_error_code",
                              size.error().code == CodecErrorCode::empty_packet_payload);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "stream_fragment_payload_bytes_counted",
                              stream_fragment_bytes(fragments) == 3);
    connection_coverage_check(coverage_ok, "stream_fragment_wire_bytes_include_overhead",
                              stream_fragment_wire_bytes(fragments) > 3);
    connection_coverage_check(coverage_ok, "stream_fragment_wire_size_has_value", size.has_value());
    connection_coverage_check(coverage_ok, "stream_fragment_wire_size_includes_packet_overhead",
                              size.value() > destination_connection_id.size() +
                                                 kDefaultInitialPacketNumberLength +
                                                 kOneRttPacketProtectionTagLength);
    return coverage_ok;
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
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "overflowing_fragment_offset_size_is_error",
                              !size.has_value());
    connection_coverage_check(coverage_ok, "overflowing_fragment_offset_error_code",
                              size.error().code == CodecErrorCode::invalid_varint);
    connection_coverage_check(coverage_ok, "overflowing_fragment_offset_error_offset",
                              size.error().offset == 0);
    return coverage_ok;
}

template <typename Bytes> bool any_nonzero_byte_for_tests(const Bytes &bytes) {
    return std::ranges::any_of(bytes, [](std::byte byte) { return byte != std::byte{0}; });
}

bool quic_core_secret_fallback_has_bytes_for_tests() {
    const ScopedConnectionDrainTestHook hook(
        &ConnectionDrainTestHooks::force_quic_core_secret_rand_failure);
    return any_nonzero_byte_for_tests(make_quic_core_secret());
}

bool issued_connection_id_rand_fallback_has_bytes_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto connection_id = make_issued_connection_id(test_retry_source_connection_id, 7);
        bool coverage_ok = true;
        connection_coverage_check(coverage_ok, "prf_failure_connection_id_size_matches",
                                  connection_id.size() == test_retry_source_connection_id.size());
        connection_coverage_check(coverage_ok, "prf_failure_connection_id_has_nonzero_byte",
                                  any_nonzero_byte_for_tests(connection_id));
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_short_prf_output);
        const auto connection_id = make_issued_connection_id(test_retry_source_connection_id, 13);
        bool coverage_ok = true;
        connection_coverage_check(coverage_ok, "short_prf_connection_id_size_matches",
                                  connection_id.size() == test_retry_source_connection_id.size());
        connection_coverage_check(coverage_ok, "short_prf_connection_id_has_nonzero_byte",
                                  any_nonzero_byte_for_tests(connection_id));
        return coverage_ok;
    }
}

bool issued_connection_id_fallback_has_bytes_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    const ScopedConnectionDrainDualTestHook hooks(
        &ConnectionDrainTestHooks::force_prf_failure,
        &ConnectionDrainTestHooks::force_issued_connection_id_rand_failure);
    const auto connection_id = make_issued_connection_id(test_retry_source_connection_id, 8);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "issued_connection_id_fallback_size_matches",
                              connection_id.size() == test_retry_source_connection_id.size());
    connection_coverage_check(coverage_ok, "issued_connection_id_fallback_has_nonzero_byte",
                              any_nonzero_byte_for_tests(connection_id));
    return coverage_ok;
}

bool stateless_reset_token_rand_fallback_has_bytes_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
    return any_nonzero_byte_for_tests(
        make_stateless_reset_token(test_retry_source_connection_id, 7));
}

bool stateless_reset_token_fallback_has_bytes_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    const ScopedConnectionDrainDualTestHook hooks(
        &ConnectionDrainTestHooks::force_prf_failure,
        &ConnectionDrainTestHooks::force_stateless_reset_token_rand_failure);
    return any_nonzero_byte_for_tests(
        make_stateless_reset_token(test_retry_source_connection_id, 8));
}

bool stateless_reset_token_empty_connection_id_fallback_has_bytes_for_tests() {
    const ScopedConnectionDrainDualTestHook hooks(
        &ConnectionDrainTestHooks::force_prf_failure,
        &ConnectionDrainTestHooks::force_stateless_reset_token_rand_failure);
    return any_nonzero_byte_for_tests(make_stateless_reset_token({}, 9));
}

bool stateless_reset_token_empty_connection_id_rand_fallback_has_bytes_for_tests() {
    const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
    return any_nonzero_byte_for_tests(make_stateless_reset_token({}, 10));
}

bool path_challenge_rand_fallback_has_bytes_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
    return any_nonzero_byte_for_tests(
        make_path_challenge_data(test_retry_source_connection_id, 3, 7));
}

bool path_challenge_fallback_has_bytes_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    const ScopedConnectionDrainDualTestHook hooks(
        &ConnectionDrainTestHooks::force_prf_failure,
        &ConnectionDrainTestHooks::force_path_challenge_rand_failure);
    return any_nonzero_byte_for_tests(
        make_path_challenge_data(test_retry_source_connection_id, 3, 8));
}

bool path_challenge_empty_connection_id_fallback_has_bytes_for_tests() {
    const ScopedConnectionDrainDualTestHook hooks(
        &ConnectionDrainTestHooks::force_prf_failure,
        &ConnectionDrainTestHooks::force_path_challenge_rand_failure);
    return any_nonzero_byte_for_tests(make_path_challenge_data({}, 3, 9));
}

bool path_challenge_empty_connection_id_rand_fallback_has_bytes_for_tests() {
    const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
    return any_nonzero_byte_for_tests(make_path_challenge_data({}, 3, 10));
}

bool random_one_in_sixteen_fallback_returns_bool_for_tests() {
    const ScopedConnectionDrainTestHook hook(
        &ConnectionDrainTestHooks::force_random_one_in_sixteen_rand_failure);
    const bool fallback = random_one_in_sixteen();
    static_cast<void>(fallback);
    return true;
}

bool forced_random_one_in_sixteen_false_for_tests() {
    const ScopedConnectionDrainOptionalBoolTestHook hook(
        &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, false);
    return !random_one_in_sixteen();
}

bool forced_random_one_in_sixteen_true_for_tests() {
    const ScopedConnectionDrainOptionalBoolTestHook hook(
        &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, true);
    return random_one_in_sixteen();
}

bool packet_stream_metadata_helpers_cover_count_bytes_and_first_offset_for_tests() {
    const auto packet = metadata_packet_for_tests();
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "packet_stream_metadata_count",
                              packet_stream_frame_count(packet) == 3);
    connection_coverage_check(coverage_ok, "packet_stream_metadata_bytes",
                              packet_stream_frame_bytes(packet) == 10);
    connection_coverage_check(coverage_ok, "packet_stream_metadata_first_offset",
                              packet_first_stream_frame_offset(packet) == 2u);
    return coverage_ok;
}

struct StreamMetadataVisitResultsForTests {
    bool visits_vector_metadata = false;
    bool visits_first_metadata = false;
};

StreamMetadataVisitResultsForTests stream_metadata_visit_results_for_tests() {
    StreamMetadataVisitResultsForTests results;
    const auto note_visit = [&results](const StreamFrameSendMetadata &metadata) {
        const bool first_stream_id_matches = metadata.stream_id == 0;
        const bool first_offset_matches = metadata.offset == 2;
        const bool first_length_matches = metadata.length == 3;
        bool is_first_metadata = first_stream_id_matches;
        is_first_metadata = is_first_metadata ? first_offset_matches : false;
        is_first_metadata = is_first_metadata ? first_length_matches : false;
        if (is_first_metadata) {
            results.visits_first_metadata = true;
        }
        const bool vector_stream_id_matches = metadata.stream_id == 4;
        const bool vector_offset_matches = metadata.offset == 9;
        const bool vector_length_matches = metadata.length == 5;
        const bool vector_fin_matches = metadata.fin;
        bool is_vector_metadata = vector_stream_id_matches;
        is_vector_metadata = is_vector_metadata ? vector_offset_matches : false;
        is_vector_metadata = is_vector_metadata ? vector_length_matches : false;
        is_vector_metadata = is_vector_metadata ? vector_fin_matches : false;
        if (is_vector_metadata) {
            results.visits_vector_metadata = true;
        }
    };
    for_each_stream_frame_metadata(SentPacketRecord{}, note_visit);
    for_each_stream_frame_metadata(metadata_packet_for_tests(), note_visit);
    return results;
}

bool stream_metadata_probe_worthy_outstanding_for_tests() {
    auto probe_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    probe_stream.send_buffer.append(bytes_from_ints_for_tests({0x01, 0x02, 0x03}));
    static_cast<void>(probe_stream.send_buffer.take_ranges(3));
    return stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                   .stream_id = 0,
                                                                   .offset = 0,
                                                                   .length = 2,
                                                                   .fin = false,
                                                                   .consumes_flow_control = true,
                                                               });
}

bool stream_metadata_probe_worthy_fin_for_tests() {
    auto probe_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    probe_stream.send_final_size = 5;
    probe_stream.send_fin_state = StreamSendFinState::pending;
    return stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                   .stream_id = 0,
                                                                   .offset = 3,
                                                                   .length = 2,
                                                                   .fin = true,
                                                                   .consumes_flow_control = true,
                                                               });
}

bool stream_metadata_probe_worthy_missing_fin_rejected_for_tests() {
    auto probe_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    probe_stream.send_final_size = 5;
    probe_stream.send_fin_state = StreamSendFinState::pending;
    return !stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                    .stream_id = 0,
                                                                    .offset = 3,
                                                                    .length = 2,
                                                                    .fin = false,
                                                                    .consumes_flow_control = true,
                                                                });
}

bool stream_metadata_probe_worthy_acked_fin_rejected_for_tests() {
    auto probe_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    probe_stream.send_final_size = 5;
    probe_stream.send_fin_state = StreamSendFinState::acknowledged;
    return !stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                    .stream_id = 0,
                                                                    .offset = 3,
                                                                    .length = 2,
                                                                    .fin = true,
                                                                    .consumes_flow_control = true,
                                                                });
}

struct SimpleStreamAckSampleCaseForTests {
    std::uint64_t packet_number = 0;
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    std::chrono::milliseconds sent_offset{};
};

AckedStreamPacketSample
make_simple_stream_ack_sample_for_tests(SimpleStreamAckSampleCaseForTests test_case) {
    return AckedStreamPacketSample{
        .packet_number = test_case.packet_number,
        .sent_time = QuicCoreTimePoint{} + test_case.sent_offset,
        .congestion_send_sequence = test_case.packet_number,
        .bytes_in_flight = 1200,
        .path_id = test_case.path_id,
        .ecn = test_case.ecn,
    };
}

bool single_path_simple_stream_ack_ecn_ignores_failed_path_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 17);
    path.ecn.state = QuicPathEcnState::failed;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{make_simple_stream_ack_sample_for_tests({
        .packet_number = 17,
        .path_id = 17,
        .ecn = QuicEcnCodepoint::ect0,
        .sent_offset = std::chrono::milliseconds(17),
    })};
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "single_path_failed_path_processes_ack",
                              ConnectionCoverageTestPeer::process_single_path_simple_stream_ack_ecn(
                                  test_connection, 17, /*newly_acked_ect0=*/1,
                                  /*newly_acked_ect1=*/0, samples.front().sent_time,
                                  AckEcnCounts{.ect0 = 1}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "single_path_failed_path_remains_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(17).ecn.state ==
                                  QuicPathEcnState::failed);
    return coverage_ok;
}

bool single_path_simple_stream_ack_ecn_missing_counts_disable_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 18);
    path.ecn.total_sent_ect0 = 4;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{make_simple_stream_ack_sample_for_tests({
        .packet_number = 18,
        .path_id = 18,
        .ecn = QuicEcnCodepoint::ect0,
        .sent_offset = std::chrono::milliseconds(18),
    })};
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "single_path_missing_counts_processes_ack",
                              ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
                                  test_connection, samples, std::nullopt, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "single_path_missing_counts_disables_path",
                              ConnectionCoverageTestPeer::paths(test_connection).at(18).ecn.state ==
                                  QuicPathEcnState::failed);
    connection_coverage_check(coverage_ok, "single_path_missing_counts_has_no_ce_time",
                              !latest_ecn_ce_sent_time.has_value());
    return coverage_ok;
}

bool single_path_simple_stream_ack_ecn_decreased_counts_disable_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 19);
    path.ecn.total_sent_ect0 = 8;
    path.ecn.last_peer_counts[2] = AckEcnCounts{.ect0 = 4};
    path.ecn.has_last_peer_counts[2] = true;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "single_path_decreased_counts_processes_ack",
                              ConnectionCoverageTestPeer::process_single_path_simple_stream_ack_ecn(
                                  test_connection, 19, /*newly_acked_ect0=*/1,
                                  /*newly_acked_ect1=*/0,
                                  QuicCoreTimePoint{} + std::chrono::milliseconds(19),
                                  AckEcnCounts{.ect0 = 3}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "single_path_decreased_counts_disables_path",
                              ConnectionCoverageTestPeer::paths(test_connection).at(19).ecn.state ==
                                  QuicPathEcnState::failed);
    return coverage_ok;
}

bool single_path_simple_stream_ack_ecn_counts_ect1_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 33);
    path.ecn.total_sent_ect1 = 4;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{make_simple_stream_ack_sample_for_tests({
        .packet_number = 33,
        .path_id = 33,
        .ecn = QuicEcnCodepoint::ect1,
        .sent_offset = std::chrono::milliseconds(33),
    })};
    bool coverage_ok = true;
    connection_coverage_check(
        coverage_ok, "single_path_ect1_processes_ack",
        ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
            test_connection, samples, AckEcnCounts{.ect1 = 1}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "single_path_ect1_marks_path_capable",
                              ConnectionCoverageTestPeer::paths(test_connection).at(33).ecn.state ==
                                  QuicPathEcnState::capable);
    connection_coverage_check(
        coverage_ok, "single_path_ect1_counts_probe_ack",
        ConnectionCoverageTestPeer::paths(test_connection).at(33).ecn.probing_packets_acked == 1);
    return coverage_ok;
}

bool single_path_simple_stream_ack_ecn_missing_feedback_disables_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 20);
    path.ecn.total_sent_ect0 = 8;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "single_path_missing_feedback_processes_ack",
                              ConnectionCoverageTestPeer::process_single_path_simple_stream_ack_ecn(
                                  test_connection, 20, /*newly_acked_ect0=*/2,
                                  /*newly_acked_ect1=*/0,
                                  QuicCoreTimePoint{} + std::chrono::milliseconds(20),
                                  AckEcnCounts{.ect0 = 1}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "single_path_missing_feedback_disables_path",
                              ConnectionCoverageTestPeer::paths(test_connection).at(20).ecn.state ==
                                  QuicPathEcnState::failed);
    return coverage_ok;
}

bool single_path_simple_stream_ack_ecn_success_tracks_ce_time_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 21);
    path.ecn.total_sent_ect0 = 4;
    path.ecn.total_sent_ect1 = 4;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const auto marked_time = QuicCoreTimePoint{} + std::chrono::milliseconds(21);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "single_path_success_processes_ack",
                              ConnectionCoverageTestPeer::process_single_path_simple_stream_ack_ecn(
                                  test_connection, 21, /*newly_acked_ect0=*/0,
                                  /*newly_acked_ect1=*/1, marked_time,
                                  AckEcnCounts{.ect1 = 0, .ecn_ce = 1}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "single_path_success_marks_capable",
                              ConnectionCoverageTestPeer::paths(test_connection).at(21).ecn.state ==
                                  QuicPathEcnState::capable);
    connection_coverage_check(
        coverage_ok, "single_path_success_counts_probe_ack",
        ConnectionCoverageTestPeer::paths(test_connection).at(21).ecn.probing_packets_acked == 1);
    connection_coverage_check(coverage_ok, "single_path_success_tracks_ce_time",
                              latest_ecn_ce_sent_time == marked_time);
    return coverage_ok;
}

bool simple_stream_ack_ecn_non_ect_samples_are_ignored_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{make_simple_stream_ack_sample_for_tests({
        .packet_number = 22,
        .path_id = 22,
        .ecn = QuicEcnCodepoint::not_ect,
        .sent_offset = std::chrono::milliseconds(22),
    })};
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "non_ect_samples_process_ack",
                              ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
                                  test_connection, samples, std::nullopt, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "non_ect_samples_do_not_create_path",
                              ConnectionCoverageTestPeer::paths(test_connection).find(22) ==
                                  ConnectionCoverageTestPeer::paths(test_connection).end());
    connection_coverage_check(coverage_ok, "non_ect_samples_have_no_ce_time",
                              !latest_ecn_ce_sent_time.has_value());
    return coverage_ok;
}

bool multi_path_simple_stream_ack_ecn_ignores_failed_path_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    ConnectionCoverageTestPeer::ensure_path_state(test_connection, 23).ecn.state =
        QuicPathEcnState::failed;
    auto &second_path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, 24);
    second_path.ecn.total_sent_ect0 = 4;
    second_path.ecn.total_sent_ect1 = 4;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 23,
            .path_id = 23,
            .ecn = QuicEcnCodepoint::ect0,
            .sent_offset = std::chrono::milliseconds(23),
        }),
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 24,
            .path_id = 24,
            .ecn = QuicEcnCodepoint::ect1,
            .sent_offset = std::chrono::milliseconds(24),
        }),
    };
    bool coverage_ok = true;
    connection_coverage_check(
        coverage_ok, "multi_path_failed_path_processes_ack",
        ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
            test_connection, samples, AckEcnCounts{.ect0 = 1, .ect1 = 1}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "multi_path_failed_path_remains_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(23).ecn.state ==
                                  QuicPathEcnState::failed);
    connection_coverage_check(coverage_ok, "multi_path_second_path_capable",
                              ConnectionCoverageTestPeer::paths(test_connection).at(24).ecn.state ==
                                  QuicPathEcnState::capable);
    return coverage_ok;
}

bool multi_path_simple_stream_ack_ecn_missing_counts_disable_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    ConnectionCoverageTestPeer::ensure_path_state(test_connection, 25).ecn.total_sent_ect0 = 4;
    ConnectionCoverageTestPeer::ensure_path_state(test_connection, 26).ecn.total_sent_ect1 = 4;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 25,
            .path_id = 25,
            .ecn = QuicEcnCodepoint::ect0,
            .sent_offset = std::chrono::milliseconds(25),
        }),
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 26,
            .path_id = 26,
            .ecn = QuicEcnCodepoint::ect1,
            .sent_offset = std::chrono::milliseconds(26),
        }),
    };
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "multi_path_missing_counts_processes_ack",
                              ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
                                  test_connection, samples, std::nullopt, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "multi_path_missing_counts_first_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(25).ecn.state ==
                                  QuicPathEcnState::failed);
    connection_coverage_check(coverage_ok, "multi_path_missing_counts_second_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(26).ecn.state ==
                                  QuicPathEcnState::failed);
    return coverage_ok;
}

bool multi_path_simple_stream_ack_ecn_decreased_counts_disable_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    for (const auto path_id : {QuicPathId{27}, QuicPathId{28}}) {
        auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, path_id);
        path.ecn.total_sent_ect0 = 8;
        path.ecn.total_sent_ect1 = 8;
        path.ecn.last_peer_counts[2] = AckEcnCounts{.ect0 = 4, .ect1 = 4};
        path.ecn.has_last_peer_counts[2] = true;
    }
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 27,
            .path_id = 27,
            .ecn = QuicEcnCodepoint::ect0,
            .sent_offset = std::chrono::milliseconds(27),
        }),
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 28,
            .path_id = 28,
            .ecn = QuicEcnCodepoint::ect1,
            .sent_offset = std::chrono::milliseconds(28),
        }),
    };
    bool coverage_ok = true;
    connection_coverage_check(
        coverage_ok, "multi_path_decreased_counts_processes_ack",
        ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
            test_connection, samples, AckEcnCounts{.ect0 = 3, .ect1 = 4}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "multi_path_decreased_counts_first_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(27).ecn.state ==
                                  QuicPathEcnState::failed);
    connection_coverage_check(coverage_ok, "multi_path_decreased_counts_second_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(28).ecn.state ==
                                  QuicPathEcnState::failed);
    return coverage_ok;
}

bool multi_path_simple_stream_ack_ecn_missing_feedback_disables_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    ConnectionCoverageTestPeer::ensure_path_state(test_connection, 29).ecn.total_sent_ect0 = 8;
    ConnectionCoverageTestPeer::ensure_path_state(test_connection, 30).ecn.total_sent_ect1 = 8;
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 29,
            .path_id = 29,
            .ecn = QuicEcnCodepoint::ect0,
            .sent_offset = std::chrono::milliseconds(29),
        }),
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 30,
            .path_id = 30,
            .ecn = QuicEcnCodepoint::ect1,
            .sent_offset = std::chrono::milliseconds(30),
        }),
    };
    bool coverage_ok = true;
    connection_coverage_check(
        coverage_ok, "multi_path_missing_feedback_processes_ack",
        ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
            test_connection, samples, AckEcnCounts{.ect0 = 0, .ect1 = 1}, latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "multi_path_missing_feedback_first_failed",
                              ConnectionCoverageTestPeer::paths(test_connection).at(29).ecn.state ==
                                  QuicPathEcnState::failed);
    connection_coverage_check(coverage_ok, "multi_path_missing_feedback_second_capable",
                              ConnectionCoverageTestPeer::paths(test_connection).at(30).ecn.state ==
                                  QuicPathEcnState::capable);
    return coverage_ok;
}

bool multi_path_simple_stream_ack_ecn_success_tracks_ce_time_for_tests() {
    auto test_connection = make_connected_client_connection_for_connection_coverage();
    for (const auto path_id : {QuicPathId{31}, QuicPathId{32}}) {
        auto &path = ConnectionCoverageTestPeer::ensure_path_state(test_connection, path_id);
        path.ecn.total_sent_ect0 = 8;
        path.ecn.total_sent_ect1 = 8;
    }
    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    const std::array samples{
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 31,
            .path_id = 31,
            .ecn = QuicEcnCodepoint::ect0,
            .sent_offset = std::chrono::milliseconds(31),
        }),
        make_simple_stream_ack_sample_for_tests({
            .packet_number = 32,
            .path_id = 32,
            .ecn = QuicEcnCodepoint::ect1,
            .sent_offset = std::chrono::milliseconds(32),
        }),
    };
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "multi_path_success_processes_ack",
                              ConnectionCoverageTestPeer::process_simple_stream_ack_ecn(
                                  test_connection, samples,
                                  AckEcnCounts{.ect0 = 1, .ect1 = 1, .ecn_ce = 1},
                                  latest_ecn_ce_sent_time));
    connection_coverage_check(coverage_ok, "multi_path_success_first_capable",
                              ConnectionCoverageTestPeer::paths(test_connection).at(31).ecn.state ==
                                  QuicPathEcnState::capable);
    connection_coverage_check(coverage_ok, "multi_path_success_second_capable",
                              ConnectionCoverageTestPeer::paths(test_connection).at(32).ecn.state ==
                                  QuicPathEcnState::capable);
    connection_coverage_check(coverage_ok, "multi_path_success_tracks_ce_time",
                              latest_ecn_ce_sent_time ==
                                  QuicCoreTimePoint{} + std::chrono::milliseconds(32));
    return coverage_ok;
}

bool trace_unset_disabled_for_tests(const ConnectionId &test_retry_source_connection_id) {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", std::nullopt);
    ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "trace_unset_packet_trace_disabled",
                              !packet_trace_enabled());
    connection_coverage_check(coverage_ok, "trace_unset_filter_does_not_match",
                              !packet_trace_matches_connection(test_retry_source_connection_id));
    return coverage_ok;
}

bool trace_empty_disabled_for_tests() {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "");
    return !packet_trace_enabled();
}

bool trace_zero_disabled_for_tests() {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "0");
    return !packet_trace_enabled();
}

bool trace_matches_without_filter_for_tests(const ConnectionId &test_retry_source_connection_id) {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "trace_without_filter_enabled", packet_trace_enabled());
    connection_coverage_check(coverage_ok, "trace_without_filter_matches",
                              packet_trace_matches_connection(test_retry_source_connection_id));
    return coverage_ok;
}

bool trace_matches_with_empty_filter_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
    return packet_trace_matches_connection(test_retry_source_connection_id);
}

bool trace_matches_with_exact_filter_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID",
                                format_connection_id_hex(test_retry_source_connection_id));
    return packet_trace_matches_connection(test_retry_source_connection_id);
}

bool trace_rejects_mismatched_filter_for_tests(
    const ConnectionId &test_retry_source_connection_id) {
    ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
    ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");
    ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "deadbeef");
    return !packet_trace_matches_connection(test_retry_source_connection_id);
}

void process_fast_path_datagram_for_tests(QuicConnection &connection,
                                          const std::vector<std::byte> &datagram,
                                          QuicCoreTimePoint now = QuicCoreTimePoint{}) {
    ConnectionCoverageTestPeer::mark_resumption_state_emitted(connection);
    auto storage = std::make_shared<std::vector<std::byte>>(datagram);
    ConnectionCoverageTestPeer::process_inbound_datagram(
        connection, storage, /*begin=*/0, /*end=*/storage->size(), now, /*path_id=*/0,
        QuicEcnCodepoint::ect0, std::nullopt, /*replay_trigger=*/false,
        /*count_inbound_bytes=*/true, /*allow_in_place_receive_decode=*/true);
}

bool discardable_deferred_replay_packet_does_not_block_current_packet_for_tests() {
    auto connection = make_connected_client_connection_for_connection_coverage();
    const std::array frames{Frame{PingFrame{}}};
    auto current =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/291, frames);
    auto deferred =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/292, frames);
    const auto current_serialized = !current.empty();
    const auto deferred_serialized = !deferred.empty();
    if (!current_serialized || !deferred_serialized) {
        return false;
    }
    bool coverage_ok = true;
    deferred.back() = static_cast<std::byte>(std::to_integer<unsigned>(deferred.back()) ^ 0x01u);
    ConnectionCoverageTestPeer::push_deferred_protected_datagram(connection,
                                                                 DeferredProtectedDatagram{
                                                                     std::move(deferred),
                                                                 });
    connection.process_inbound_datagram(current, QuicCoreTimePoint{});
    connection_coverage_check(coverage_ok, "discardable_deferred_replay_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "discardable_deferred_replay_queue_empty",
        ConnectionCoverageTestPeer::deferred_protected_packets_empty(connection));
    connection_coverage_check(
        coverage_ok, "discardable_deferred_replay_authenticates_current_packet",
        ConnectionCoverageTestPeer::application_largest_authenticated_packet_number(connection) ==
            291u);
    return coverage_ok;
}

bool in_place_receive_storage_guard_for_tests(bool ConnectionDrainTestHooks::*hook_field) {
    const std::array frames{Frame{PingFrame{}}};
    const auto datagram = serialize_one_rtt_packet_for_connection_coverage(
        make_connected_client_connection_for_connection_coverage(), /*packet_number=*/300, frames);
    if (datagram.empty()) {
        return false;
    }
    auto connection = make_connected_client_connection_for_connection_coverage();
    auto storage = std::make_shared<std::vector<std::byte>>(datagram);
    const ScopedConnectionDrainTestHook hook(hook_field);
    ConnectionCoverageTestPeer::process_inbound_datagram(
        connection, storage, /*begin=*/0, /*end=*/storage->size(), QuicCoreTimePoint{},
        /*path_id=*/0, QuicEcnCodepoint::unavailable, std::nullopt, /*replay_trigger=*/false,
        /*count_inbound_bytes=*/true, /*allow_in_place_receive_decode=*/true);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "in_place_receive_storage_guard_connection_not_failed",
                              !connection.has_failed());
    return coverage_ok;
}

bool replay_failure_before_current_packet_is_non_fatal_for_tests() {
    const std::array frames{Frame{PingFrame{}}};
    auto datagram = serialize_one_rtt_packet_for_connection_coverage(
        make_connected_client_connection_for_connection_coverage(), /*packet_number=*/301, frames);
    if (datagram.empty()) {
        return false;
    }
    auto connection = make_connected_client_connection_for_connection_coverage();
    const ScopedConnectionDrainCountdownTestHook hook(
        &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown, 0);
    connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "replay_failure_before_current_connection_not_failed",
                              !connection.has_failed());
    return coverage_ok;
}

bool replay_failure_after_current_packet_is_non_fatal_for_tests() {
    const std::array frames{Frame{PingFrame{}}};
    auto datagram = serialize_one_rtt_packet_for_connection_coverage(
        make_connected_client_connection_for_connection_coverage(), /*packet_number=*/302, frames);
    if (datagram.empty()) {
        return false;
    }
    auto connection = make_connected_client_connection_for_connection_coverage();
    const ScopedConnectionDrainCountdownTestHook hook(
        &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown, 1);
    connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "replay_failure_after_current_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "replay_failure_after_current_authenticates_current_packet",
        ConnectionCoverageTestPeer::application_largest_authenticated_packet_number(connection) ==
            302u);
    return coverage_ok;
}

bool fast_path_ack_only_packet_processed_for_tests() {
    auto connection = make_connected_client_connection_for_connection_coverage();
    ConnectionCoverageTestPeer::track_application_sent_packet(
        connection, SentPacketRecord{
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
    const auto datagram =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/401, frames);
    if (datagram.empty()) {
        return false;
    }
    process_fast_path_datagram_for_tests(connection, datagram);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "fast_path_ack_only_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "fast_path_ack_only_packet_received",
        ConnectionCoverageTestPeer::application_received_packets_contains(connection, 401));
    return coverage_ok;
}

bool fast_path_duplicate_ack_only_packet_ignored_for_tests() {
    auto connection = make_connected_client_connection_for_connection_coverage();
    ConnectionCoverageTestPeer::track_application_sent_packet(
        connection, SentPacketRecord{
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
    const auto datagram =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/401, frames);
    if (datagram.empty()) {
        return false;
    }
    process_fast_path_datagram_for_tests(connection, datagram);
    process_fast_path_datagram_for_tests(connection, datagram);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "fast_path_duplicate_ack_only_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "fast_path_duplicate_ack_only_original_packet_received",
        ConnectionCoverageTestPeer::application_received_packets_contains(connection, 401));
    return coverage_ok;
}

bool fast_path_stream_packet_processed_for_tests() {
    auto connection = make_connected_client_connection_for_connection_coverage();
    const std::array frames{Frame{StreamFrame{
        .has_length = true,
        .stream_id = 1,
        .stream_data = bytes_from_ints_for_tests({0x41, 0x42}),
    }}};
    const auto datagram =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/402, frames);
    if (datagram.empty()) {
        return false;
    }
    process_fast_path_datagram_for_tests(connection, datagram);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "fast_path_stream_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "fast_path_stream_packet_received",
        ConnectionCoverageTestPeer::application_received_packets_contains(connection, 402));
    connection_coverage_check(
        coverage_ok, "fast_path_stream_receive_effect_emitted",
        !ConnectionCoverageTestPeer::pending_stream_receive_effects_empty(connection));
    return coverage_ok;
}

bool fast_path_duplicate_stream_packet_ignored_for_tests() {
    auto connection = make_connected_client_connection_for_connection_coverage();
    const std::array frames{Frame{StreamFrame{
        .has_length = true,
        .stream_id = 1,
        .stream_data = bytes_from_ints_for_tests({0x41, 0x42}),
    }}};
    const auto datagram =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/402, frames);
    if (datagram.empty()) {
        return false;
    }
    process_fast_path_datagram_for_tests(connection, datagram);
    process_fast_path_datagram_for_tests(connection, datagram);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "fast_path_duplicate_stream_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "fast_path_duplicate_stream_original_packet_received",
        ConnectionCoverageTestPeer::application_received_packets_contains(connection, 402));
    return coverage_ok;
}

bool fast_path_corrupted_packet_discarded_for_tests() {
    auto connection = make_connected_client_connection_for_connection_coverage();
    const std::array frames{Frame{PingFrame{}}};
    auto datagram =
        serialize_one_rtt_packet_for_connection_coverage(connection, /*packet_number=*/403, frames);
    if (datagram.empty()) {
        return false;
    }
    datagram.back() = static_cast<std::byte>(std::to_integer<unsigned>(datagram.back()) ^ 0x01u);
    process_fast_path_datagram_for_tests(connection, datagram);
    bool coverage_ok = true;
    connection_coverage_check(coverage_ok, "fast_path_corrupted_connection_not_failed",
                              !connection.has_failed());
    connection_coverage_check(
        coverage_ok, "fast_path_corrupted_packet_not_received",
        !ConnectionCoverageTestPeer::application_received_packets_contains(connection, 403));
    return coverage_ok;
}

bool retired_peer_application_frames_are_ignored_for_tests() {
    constexpr std::uint64_t stream_id = 1;
    constexpr std::uint64_t final_size = 4;
    const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(19);

    bool coverage_ok = true;

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const std::array frames{
            Frame{StreamFrame{
                .fin = true,
                .has_length = true,
                .stream_id = stream_id,
                .stream_data = bytes_from_ints_for_tests({0x01, 0x02, 0x03, 0x04}),
            }},
            Frame{ResetStreamFrame{
                .stream_id = stream_id,
                .application_protocol_error_code = 0x77,
                .final_size = final_size,
            }},
            Frame{StopSendingFrame{
                .stream_id = stream_id,
                .application_protocol_error_code = 0x78,
            }},
            Frame{MaxStreamDataFrame{
                .stream_id = stream_id,
                .maximum_stream_data = 16,
            }},
            Frame{StreamDataBlockedFrame{
                .stream_id = stream_id,
                .maximum_stream_data = final_size,
            }},
        };
        const auto retired_peer_application_result =
            ConnectionCoverageTestPeer::process_inbound_application(connection, frames, now);
        connection_coverage_check(
            coverage_ok, "retired_peer_application_frames_processed",
            successful_bool_result_for_coverage(retired_peer_application_result));
        connection_coverage_check(coverage_ok, "retired_peer_application_stream_effect_suppressed",
                                  !connection.take_received_stream_data().has_value());
        connection_coverage_check(coverage_ok, "retired_peer_application_reset_effect_suppressed",
                                  !connection.take_peer_reset_stream().has_value());
        connection_coverage_check(coverage_ok, "retired_peer_application_stop_effect_suppressed",
                                  !connection.take_peer_stop_sending().has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const std::array frames{
            ReceivedFrame{ReceivedStreamFrame{
                .fin = true,
                .has_length = true,
                .stream_id = stream_id,
                .stream_data = SharedBytes(bytes_from_ints_for_tests({0x05, 0x06, 0x07, 0x08})),
            }},
            ReceivedFrame{ResetStreamFrame{
                .stream_id = stream_id,
                .application_protocol_error_code = 0x79,
                .final_size = final_size,
            }},
            ReceivedFrame{StopSendingFrame{
                .stream_id = stream_id,
                .application_protocol_error_code = 0x7a,
            }},
            ReceivedFrame{MaxStreamDataFrame{
                .stream_id = stream_id,
                .maximum_stream_data = 32,
            }},
            ReceivedFrame{StreamDataBlockedFrame{
                .stream_id = stream_id,
                .maximum_stream_data = final_size,
            }},
        };
        const auto retired_peer_received_application_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(connection, frames,
                                                                             now);
        connection_coverage_check(
            coverage_ok, "retired_peer_received_application_frames_processed",
            successful_bool_result_for_coverage(retired_peer_received_application_result));
        connection_coverage_check(coverage_ok, "retired_peer_received_stream_effect_suppressed",
                                  !connection.take_received_stream_data().has_value());
        connection_coverage_check(coverage_ok, "retired_peer_received_reset_effect_suppressed",
                                  !connection.take_peer_reset_stream().has_value());
        connection_coverage_check(coverage_ok, "retired_peer_received_stop_effect_suppressed",
                                  !connection.take_peer_stop_sending().has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const auto retired_peer_fast_path_result =
            ConnectionCoverageTestPeer::process_inbound_received_application_stream(
                connection,
                ReceivedStreamFrame{
                    .fin = true,
                    .has_length = true,
                    .stream_id = stream_id,
                    .stream_data = SharedBytes(bytes_from_ints_for_tests({0x09, 0x0a, 0x0b, 0x0c})),
                },
                /*require_connected=*/true);
        connection_coverage_check(
            coverage_ok, "retired_peer_received_stream_fast_path_processed",
            successful_bool_result_for_coverage(retired_peer_fast_path_result));
        connection_coverage_check(coverage_ok,
                                  "retired_peer_received_stream_fast_path_effect_suppressed",
                                  !connection.take_received_stream_data().has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const std::array frames{Frame{StreamFrame{
            .fin = true,
            .has_length = true,
            .stream_id = stream_id,
            .stream_data = bytes_from_ints_for_tests({0x01, 0x02, 0x03}),
        }}};
        const auto retired_peer_stream_conflict_result =
            ConnectionCoverageTestPeer::process_inbound_application(connection, frames, now);
        connection_coverage_check(coverage_ok, "retired_peer_application_stream_conflict_rejected",
                                  !retired_peer_stream_conflict_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const std::array frames{Frame{ResetStreamFrame{
            .stream_id = stream_id,
            .application_protocol_error_code = 0x7b,
            .final_size = final_size + 1,
        }}};
        const auto retired_peer_reset_conflict_result =
            ConnectionCoverageTestPeer::process_inbound_application(connection, frames, now);
        connection_coverage_check(coverage_ok, "retired_peer_application_reset_conflict_rejected",
                                  !retired_peer_reset_conflict_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const std::array frames{ReceivedFrame{ResetStreamFrame{
            .stream_id = stream_id,
            .application_protocol_error_code = 0x7c,
            .final_size = final_size + 1,
        }}};
        const auto retired_peer_received_reset_conflict_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(connection, frames,
                                                                             now);
        connection_coverage_check(coverage_ok, "retired_peer_received_reset_conflict_rejected",
                                  !retired_peer_received_reset_conflict_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        ConnectionCoverageTestPeer::retire_peer_bidi_range(connection, /*first_index=*/0,
                                                           /*last_index=*/0, final_size,
                                                           final_size);
        const auto retired_peer_received_stream_conflict_result =
            ConnectionCoverageTestPeer::process_inbound_received_application_stream(
                connection,
                ReceivedStreamFrame{
                    .fin = true,
                    .has_length = true,
                    .stream_id = stream_id,
                    .stream_data =
                        SharedBytes(bytes_from_ints_for_tests({0x0d, 0x0e, 0x0f, 0x10, 0x11})),
                },
                /*require_connected=*/true);
        connection_coverage_check(coverage_ok,
                                  "retired_peer_received_stream_fast_path_conflict_rejected",
                                  !retired_peer_received_stream_conflict_result.has_value());
    }

    return coverage_ok;
}

bool connection_helper_edge_cases_for_tests() {
    bool coverage_ok = true;

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const std::array owned_datagram_frames{Frame{DatagramFrame{
            .has_length = true,
            .data = bytes_from_ints_for_tests({0x01, 0x02}),
        }}};
        const auto owned_datagram_result = ConnectionCoverageTestPeer::process_inbound_application(
            connection, owned_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok, "owned_datagram_frame_processed",
                                  owned_datagram_result.has_value());
        connection_coverage_check(coverage_ok, "owned_datagram_frame_processing_succeeded",
                                  successful_bool_result_for_coverage(owned_datagram_result));
        const auto received = connection.take_received_datagram_data();
        connection_coverage_check(coverage_ok, "owned_datagram_frame_emits_receive_effect",
                                  received.has_value());
        const auto received_datagram = received.value_or(QuicCoreReceiveDatagramData{});
        connection_coverage_check(coverage_ok, "owned_datagram_frame_payload_size",
                                  received_datagram.byte_count() == 2u);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.status_ = HandshakeStatus::in_progress;
        connection.application_space_.read_secret.reset();
        const std::array disconnected_datagram_frames{Frame{DatagramFrame{
            .has_length = true,
            .data = bytes_from_ints_for_tests({0x03}),
        }}};
        const auto disconnected_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_application(
                connection, disconnected_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok, "owned_datagram_requires_connected_state",
                                  !disconnected_datagram_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.status_ = HandshakeStatus::in_progress;
        const std::array preconnected_datagram_frames{Frame{DatagramFrame{
            .has_length = true,
            .data = bytes_from_ints_for_tests({0x04}),
        }}};
        const auto preconnected_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_application(
                connection, preconnected_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok,
                                  "owned_datagram_allowed_with_preconnected_read_secret",
                                  preconnected_datagram_result.has_value());
        connection_coverage_check(
            coverage_ok, "owned_preconnected_datagram_processing_succeeded",
            successful_bool_result_for_coverage(preconnected_datagram_result));
        connection_coverage_check(coverage_ok, "owned_preconnected_datagram_emits_receive_effect",
                                  connection.take_received_datagram_data().has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.local_transport_parameters_.max_datagram_frame_size = 0;
        const std::array unsupported_datagram_frames{Frame{DatagramFrame{
            .has_length = true,
            .data = bytes_from_ints_for_tests({0x05}),
        }}};
        const auto unsupported_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_application(
                connection, unsupported_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok,
                                  "owned_datagram_rejected_when_local_support_disabled",
                                  !unsupported_datagram_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.local_transport_parameters_.max_datagram_frame_size = 2;
        const std::array oversized_datagram_frames{Frame{DatagramFrame{
            .has_length = true,
            .data = bytes_from_ints_for_tests({0x06, 0x07}),
        }}};
        const auto oversized_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_application(
                connection, oversized_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok,
                                  "owned_datagram_rejected_when_larger_than_local_limit",
                                  !oversized_datagram_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const auto storage =
            std::make_shared<std::vector<std::byte>>(bytes_from_ints_for_tests({0x08, 0x09}));
        const std::array shared_datagram_frames{ReceivedFrame{ReceivedDatagramFrame{
            .has_length = true,
            .data = SharedBytes(storage, 0, storage->size()),
        }}};
        const auto shared_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(
                connection, shared_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok, "shared_datagram_frame_processed",
                                  shared_datagram_result.has_value());
        connection_coverage_check(coverage_ok, "shared_datagram_frame_processing_succeeded",
                                  successful_bool_result_for_coverage(shared_datagram_result));
        const auto received = connection.take_received_datagram_data();
        connection_coverage_check(coverage_ok, "shared_datagram_frame_emits_receive_effect",
                                  received.has_value());
        const auto received_datagram = received.value_or(QuicCoreReceiveDatagramData{});
        connection_coverage_check(coverage_ok, "shared_datagram_frame_preserves_storage",
                                  received_datagram.shared_bytes.storage() == storage);
        connection_coverage_check(coverage_ok, "shared_datagram_frame_payload_size",
                                  received_datagram.byte_count() == 2u);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.status_ = HandshakeStatus::in_progress;
        connection.application_space_.read_secret.reset();
        const auto storage =
            std::make_shared<std::vector<std::byte>>(bytes_from_ints_for_tests({0x0a}));
        const std::array shared_disconnected_datagram_frames{ReceivedFrame{ReceivedDatagramFrame{
            .has_length = true,
            .data = SharedBytes(storage, 0, storage->size()),
        }}};
        const auto shared_disconnected_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(
                connection, shared_disconnected_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok, "shared_datagram_requires_connected_state",
                                  !shared_disconnected_datagram_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.status_ = HandshakeStatus::in_progress;
        const auto storage =
            std::make_shared<std::vector<std::byte>>(bytes_from_ints_for_tests({0x0b}));
        const std::array shared_preconnected_datagram_frames{ReceivedFrame{ReceivedDatagramFrame{
            .has_length = true,
            .data = SharedBytes(storage, 0, storage->size()),
        }}};
        const auto shared_preconnected_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(
                connection, shared_preconnected_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok,
                                  "shared_datagram_allowed_with_preconnected_read_secret",
                                  shared_preconnected_datagram_result.has_value());
        connection_coverage_check(
            coverage_ok, "shared_preconnected_datagram_processing_succeeded",
            successful_bool_result_for_coverage(shared_preconnected_datagram_result));
        connection_coverage_check(coverage_ok, "shared_preconnected_datagram_emits_receive_effect",
                                  connection.take_received_datagram_data().has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.local_transport_parameters_.max_datagram_frame_size = 0;
        const auto storage =
            std::make_shared<std::vector<std::byte>>(bytes_from_ints_for_tests({0x0c}));
        const std::array shared_unsupported_datagram_frames{ReceivedFrame{ReceivedDatagramFrame{
            .has_length = true,
            .data = SharedBytes(storage, 0, storage->size()),
        }}};
        const auto shared_unsupported_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(
                connection, shared_unsupported_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok,
                                  "shared_datagram_rejected_when_local_support_disabled",
                                  !shared_unsupported_datagram_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.local_transport_parameters_.max_datagram_frame_size = 2;
        const auto storage =
            std::make_shared<std::vector<std::byte>>(bytes_from_ints_for_tests({0x0d, 0x0e}));
        const std::array shared_oversized_datagram_frames{ReceivedFrame{ReceivedDatagramFrame{
            .has_length = true,
            .data = SharedBytes(storage, 0, storage->size()),
        }}};
        const auto shared_oversized_datagram_result =
            ConnectionCoverageTestPeer::process_inbound_received_application(
                connection, shared_oversized_datagram_frames, QuicCoreTimePoint{});
        connection_coverage_check(coverage_ok,
                                  "shared_datagram_rejected_when_larger_than_local_limit",
                                  !shared_oversized_datagram_result.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto retired = make_implicit_stream_state(/*stream_id=*/0, connection.config_.role);
        auto [retired_it, inserted] = connection.retired_streams_.emplace(0, std::move(retired));
        connection_coverage_check(coverage_ok, "retired_stream_seed_inserted", inserted);

        const auto local_stream = connection.get_or_open_local_stream(0);
        connection_coverage_check(coverage_ok, "local_stream_lookup_finds_retired_stream",
                                  local_stream.has_value());
        connection_coverage_check(coverage_ok, "local_stream_lookup_returns_retired_stream",
                                  local_stream.value() == &retired_it->second);

        const auto receive_stream = connection.get_existing_receive_stream(0);
        connection_coverage_check(coverage_ok, "receive_stream_lookup_finds_retired_stream",
                                  receive_stream.has_value());
        connection_coverage_check(coverage_ok, "receive_stream_lookup_returns_retired_stream",
                                  receive_stream.value() == &retired_it->second);

        const auto send_stream = connection.get_or_open_send_stream(0);
        connection_coverage_check(coverage_ok, "send_stream_lookup_finds_retired_stream",
                                  send_stream.has_value());
        connection_coverage_check(coverage_ok, "send_stream_lookup_returns_retired_stream",
                                  send_stream.value() == &retired_it->second);
    }

    constexpr std::array supported_versions = {kQuicVersion2, kQuicVersion1};
    const auto test_retry_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x00}};
    connection_coverage_check(coverage_ok, "retry_same_version_omits_version_information",
                              !version_information_for_handshake(supported_versions, kQuicVersion1,
                                                                 test_retry_source_connection_id,
                                                                 kQuicVersion1, kQuicVersion1)
                                   .has_value());
    connection_coverage_check(coverage_ok, "retry_version_change_keeps_version_information",
                              version_information_for_handshake(supported_versions, kQuicVersion2,
                                                                test_retry_source_connection_id,
                                                                kQuicVersion1, kQuicVersion2)
                                  .has_value());

    const auto failed_datagram_result =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    const auto successful_datagram_result =
        CodecResult<std::vector<std::byte>>::success({std::byte{0x01}, std::byte{0x02}});
    const auto empty_packet_payload_datagram_result =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload, 0);
    connection_coverage_check(coverage_ok, "failed_datagram_reports_zero_size",
                              datagram_size_or_zero(failed_datagram_result) == 0);
    connection_coverage_check(coverage_ok, "successful_datagram_reports_size",
                              datagram_size_or_zero(successful_datagram_result) == 2);
    connection_coverage_check(
        coverage_ok, "failed_serialized_datagram_reports_zero_size",
        datagram_size_or_zero(CodecResult<SerializedProtectedDatagram>::failure(
            CodecErrorCode::invalid_varint, 0)) == 0);
    connection_coverage_check(coverage_ok, "successful_serialized_datagram_reports_size",
                              datagram_size_or_zero(successful_serialized_datagram_for_tests()) ==
                                  3);
    connection_coverage_check(coverage_ok, "empty_packet_payload_error_reported",
                              is_empty_packet_payload_error(empty_packet_payload_datagram_result));
    connection_coverage_check(coverage_ok, "successful_datagram_not_reported",
                              !is_empty_packet_payload_error(successful_datagram_result));
    connection_coverage_check(coverage_ok, "non_empty_packet_payload_error_not_reported",
                              !is_empty_packet_payload_error(failed_datagram_result));
    connection_coverage_check(
        coverage_ok, "empty_packet_payload_serialized_error_reported",
        is_empty_packet_payload_error(CodecResult<SerializedProtectedDatagram>::failure(
            CodecErrorCode::empty_packet_payload, 0)));
    connection_coverage_check(
        coverage_ok, "non_empty_packet_payload_serialized_error_not_reported",
        !is_empty_packet_payload_error(
            CodecResult<SerializedProtectedDatagram>::failure(CodecErrorCode::invalid_varint, 0)));

    TransportParameters invalid_transport_parameters;
    invalid_transport_parameters.max_udp_payload_size = std::numeric_limits<std::uint64_t>::max();
    connection_coverage_check(
        coverage_ok, "encode_failure_returns_empty",
        encode_resumption_state({}, kQuicVersion1, "h3", invalid_transport_parameters, {}).empty());

    constexpr std::array wrong_magic_bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                              std::byte{0x00}, std::byte{0x00}};
    connection_coverage_check(coverage_ok, "wrong_magic_rejected",
                              !decode_resumption_state(wrong_magic_bytes).has_value());

    std::vector<std::byte> truncated_tls_state = {std::byte{0x01}};
    append_u32_be(truncated_tls_state, kQuicVersion1);
    connection_coverage_check(coverage_ok, "truncated_tls_state_rejected",
                              !decode_resumption_state(truncated_tls_state).has_value());

    connection_coverage_check(
        coverage_ok, "missing_application_context_rejected",
        !decode_resumption_state(
             resumption_state_missing_application_context_for_tests(
                 serialize_transport_parameters(
                     TransportParameters{
                         .max_udp_payload_size = 1200,
                         .active_connection_id_limit = 8,
                         .initial_source_connection_id = ConnectionId{std::byte{0x01}},
                     })
                     .value()))
             .has_value());

    connection_coverage_check(
        coverage_ok, "missing_application_protocol_rejected",
        !decode_resumption_state(resumption_state_missing_application_protocol_for_tests())
             .has_value());

    connection_coverage_check(
        coverage_ok, "missing_transport_parameters_rejected",
        !decode_resumption_state(resumption_state_missing_transport_parameters_for_tests())
             .has_value());

    auto trailing_resumption_state =
        encode_resumption_state({}, kQuicVersion1, "h3",
                                TransportParameters{
                                    .max_udp_payload_size = 1200,
                                    .active_connection_id_limit = 8,
                                    .initial_source_connection_id = ConnectionId{std::byte{0x01}},
                                },
                                {});
    trailing_resumption_state.push_back(std::byte{0xff});
    connection_coverage_check(coverage_ok, "trailing_bytes_rejected",
                              !decode_resumption_state(trailing_resumption_state).has_value());

    connection_coverage_check(
        coverage_ok, "pending_fin_without_buffer_is_sendable",
        stream_with_pending_fin_is_sendable_for_tests(PendingFinStreamCaseForTests{
            .final_size = 1,
            .peer_max_stream_data = 1,
        }));

    connection_coverage_check(
        coverage_ok, "pending_fin_blocked_by_credit",
        !stream_with_pending_fin_is_sendable_for_tests(PendingFinStreamCaseForTests{
            .final_size = 2,
            .peer_max_stream_data = 1,
        }));

    connection_coverage_check(coverage_ok, "pending_data_blocks_fin",
                              pending_stream_data_blocks_fin_for_tests());

    connection_coverage_check(coverage_ok, "missing_pending_frames_preserve_state",
                              stream_limits_without_peer_credit_preserve_state_for_tests());

    constexpr std::array short_header_packet = {std::byte{0x40}};
    connection_coverage_check(coverage_ok, "short_header_is_bufferable",
                              packet_is_bufferable(short_header_packet));
    constexpr std::array truncated_long_header = {std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}};
    connection_coverage_check(coverage_ok, "truncated_long_header_is_not_bufferable",
                              !packet_is_bufferable(truncated_long_header));
    constexpr std::array handshake_long_header = {std::byte{0xe0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}, std::byte{0x01}};
    connection_coverage_check(coverage_ok, "handshake_long_header_is_bufferable",
                              packet_is_bufferable(handshake_long_header));

    connection_coverage_check(
        coverage_ok, "server_protected_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(protected_one_rtt_ack_packet_for_tests(),
                                              EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(
        coverage_ok, "client_connected_state_protected_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(protected_one_rtt_reset_packet_for_tests(),
                                              EndpointRole::client, HandshakeStatus::in_progress));
    connection_coverage_check(
        coverage_ok, "server_received_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(received_one_rtt_ack_packet_for_tests(),
                                              EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(
        coverage_ok, "client_connected_state_received_one_rtt_packet_deferred",
        should_defer_protected_one_rtt_packet(received_one_rtt_reset_packet_for_tests(),
                                              EndpointRole::client, HandshakeStatus::in_progress));
    connection_coverage_check(
        coverage_ok, "received_ack_only_fast_packet_deferred",
        should_defer_protected_one_rtt_packet(
            ReceivedProtectedPacket{received_ack_only_fast_packet_for_tests()},
            EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(coverage_ok, "received_stream_fast_packet_deferred",
                              should_defer_protected_one_rtt_packet(
                                  ReceivedProtectedPacket{received_stream_fast_packet_for_tests()},
                                  EndpointRole::server, HandshakeStatus::in_progress));
    connection_coverage_check(coverage_ok, "connected_received_stream_fast_packet_not_deferred",
                              !should_defer_protected_one_rtt_packet(
                                  ReceivedProtectedPacket{received_stream_fast_packet_for_tests()},
                                  EndpointRole::server, HandshakeStatus::connected));
    connection_coverage_check(coverage_ok, "received_ack_only_fast_packet_number_for_trace",
                              protected_one_rtt_packet_number_for_trace(ReceivedProtectedPacket{
                                  received_ack_only_fast_packet_for_tests()}) == 42u);
    connection_coverage_check(coverage_ok, "received_stream_fast_packet_number_for_trace",
                              protected_one_rtt_packet_number_for_trace(ReceivedProtectedPacket{
                                  received_stream_fast_packet_for_tests()}) == 43u);
    connection_coverage_check(
        coverage_ok, "connected_protected_one_rtt_packet_not_deferred",
        !should_defer_protected_one_rtt_packet(protected_one_rtt_reset_packet_for_tests(),
                                               EndpointRole::server, HandshakeStatus::connected));
    connection_coverage_check(
        coverage_ok, "chacha_confidentiality_limit_is_empty",
        !confidentiality_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256)
             .has_value());
    connection_coverage_check(
        coverage_ok, "chacha_integrity_limit_matches_expected",
        integrity_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256) ==
            kChaCha20Poly1305IntegrityLimit);
    connection_coverage_check(
        coverage_ok, "aes_128_confidentiality_limit_matches_expected",
        confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256) ==
            kAesGcmConfidentialityLimit);
    connection_coverage_check(
        coverage_ok, "aes_256_confidentiality_limit_matches_expected",
        confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_256_gcm_sha384) ==
            kAesGcmConfidentialityLimit);
    connection_coverage_check(coverage_ok, "aes_128_integrity_limit_matches_expected",
                              integrity_limit_for_cipher_suite(
                                  CipherSuite::tls_aes_128_gcm_sha256) == kAesGcmIntegrityLimit);
    connection_coverage_check(coverage_ok, "aes_256_integrity_limit_matches_expected",
                              integrity_limit_for_cipher_suite(
                                  CipherSuite::tls_aes_256_gcm_sha384) == kAesGcmIntegrityLimit);
    connection_coverage_check(
        coverage_ok, "invalid_cipher_confidentiality_limit_is_empty",
        !confidentiality_limit_for_cipher_suite(invalid_cipher_suite_for_tests()).has_value());
    connection_coverage_check(
        coverage_ok, "invalid_cipher_integrity_limit_is_empty",
        !integrity_limit_for_cipher_suite(invalid_cipher_suite_for_tests()).has_value());
    connection_coverage_check(coverage_ok, "saturating_add_handles_overflow",
                              saturating_add(std::numeric_limits<std::uint64_t>::max() - 1u, 8u) ==
                                  std::numeric_limits<std::uint64_t>::max());
    connection_coverage_check(coverage_ok, "saturating_add_handles_sum",
                              saturating_add(3u, 4u) == 7u);
    connection_coverage_check(
        coverage_ok, "protected_zero_rtt_crypto_can_advance_tls",
        packet_can_advance_tls_state(ProtectedPacket{ProtectedZeroRttPacket{
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = std::vector<std::byte>{std::byte{0x01}},
                    },
                },
        }}));
    connection_coverage_check(coverage_ok, "protected_one_rtt_ack_cannot_advance_tls",
                              !packet_can_advance_tls_state(ProtectedPacket{ProtectedOneRttPacket{
                                  .frames =
                                      {
                                          AckFrame{},
                                      },
                              }}));
    connection_coverage_check(
        coverage_ok, "corrupted_long_header_invalid_fixed_bit_discarded",
        should_discard_corrupted_long_header_packet(false, CodecErrorCode::invalid_fixed_bit));
    connection_coverage_check(coverage_ok,
                              "corrupted_long_header_unsupported_packet_type_discarded",
                              should_discard_corrupted_long_header_packet(
                                  false, CodecErrorCode::unsupported_packet_type));
    connection_coverage_check(
        coverage_ok, "short_header_not_discarded_as_corrupted_long_header",
        !should_discard_corrupted_long_header_packet(true, CodecErrorCode::invalid_fixed_bit));

    const auto bytes_from_ints = [](std::initializer_list<std::uint8_t> values) {
        std::vector<std::byte> bytes;
        bytes.reserve(values.size());
        for (const auto value : values) {
            bytes.push_back(static_cast<std::byte>(value));
        }
        return bytes;
    };

    connection_coverage_check(coverage_ok, "empty_connection_id_formats_empty",
                              format_connection_id_hex({}).empty());
    connection_coverage_check(coverage_ok, "connection_id_formats_lower_hex",
                              format_connection_id_hex(test_retry_source_connection_id) == "5300");
    connection_coverage_check(coverage_ok, "empty_issued_connection_id_remains_empty",
                              make_issued_connection_id({}, /*sequence_number=*/7).empty());
    connection_coverage_check(coverage_ok, "random_one_in_sixteen_openssl_returns_bool", [] {
        bool false_result = true;
        {
            const ScopedConnectionDrainOptionalBoolTestHook force_false(
                &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, false);
            false_result = random_one_in_sixteen();
        }
        ScopedConnectionDrainOptionalBoolTestHook force_true(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, true);
        bool coverage_ok = true;
        connection_coverage_check(coverage_ok, "random_one_in_sixteen_forced_false_result",
                                  !false_result);
        connection_coverage_check(coverage_ok, "random_one_in_sixteen_forced_true_result",
                                  random_one_in_sixteen());
        return coverage_ok;
    }());
    connection_coverage_check(
        coverage_ok, "invalid_stream_id_maps_to_stream_limit_error",
        stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_id) ==
            QuicTransportErrorCode::stream_limit_error);
    connection_coverage_check(
        coverage_ok, "invalid_stream_direction_maps_to_stream_state_error",
        stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_direction) ==
            QuicTransportErrorCode::stream_state_error);
    connection_coverage_check(
        coverage_ok, "send_side_closed_maps_to_stream_state_error",
        stream_transport_error_for_state_error(StreamStateErrorCode::send_side_closed) ==
            QuicTransportErrorCode::stream_state_error);
    connection_coverage_check(
        coverage_ok, "receive_side_closed_maps_to_stream_state_error",
        stream_transport_error_for_state_error(StreamStateErrorCode::receive_side_closed) ==
            QuicTransportErrorCode::stream_state_error);
    connection_coverage_check(
        coverage_ok, "final_size_conflict_maps_to_final_size_error",
        stream_transport_error_for_state_error(StreamStateErrorCode::final_size_conflict) ==
            QuicTransportErrorCode::final_size_error);
    connection_coverage_check(coverage_ok, "stream_state_codec_error_adds_transport_code",
                              stream_state_codec_error_adds_transport_code_for_tests());
    connection_coverage_check(coverage_ok, "max_streams_uni_frame_type",
                              frame_type_for_max_streams(StreamLimitType::unidirectional) ==
                                  kFrameTypeMaxStreamsUni);
    connection_coverage_check(coverage_ok, "streams_blocked_uni_frame_type",
                              frame_type_for_streams_blocked(StreamLimitType::unidirectional) ==
                                  kFrameTypeStreamsBlockedUni);
    connection_coverage_check(
        coverage_ok, "invalid_reserved_bits_maps_to_protocol_violation",
        transport_error_for_codec_error(CodecErrorCode::invalid_reserved_bits) ==
            QuicTransportErrorCode::protocol_violation);
    connection_coverage_check(coverage_ok, "invalid_fixed_bit_maps_to_internal_error",
                              transport_error_for_codec_error(CodecErrorCode::invalid_fixed_bit) ==
                                  QuicTransportErrorCode::internal_error);
    connection_coverage_check(
        coverage_ok, "missing_crypto_context_maps_to_internal_error",
        transport_error_for_codec_error(CodecErrorCode::missing_crypto_context) ==
            QuicTransportErrorCode::internal_error);
    connection_coverage_check(coverage_ok, "http09_parse_error_maps_to_application_error",
                              transport_error_for_codec_error(CodecErrorCode::http09_parse_error) ==
                                  QuicTransportErrorCode::application_error);
    connection_coverage_check(coverage_ok, "http3_parse_error_maps_to_application_error",
                              transport_error_for_codec_error(CodecErrorCode::http3_parse_error) ==
                                  QuicTransportErrorCode::application_error);
    connection_coverage_check(coverage_ok, "vector_equals_deferred_packet",
                              deferred_packet_equals_vector_for_tests());

    PathState traced_path = traced_path_for_summary_tests();
    std::map<QuicPathId, PathState> traced_paths{
        {traced_path.id, traced_path},
    };
    connection_coverage_check(coverage_ok, "optional_path_none_formats_dash",
                              format_optional_path_id(std::nullopt) == "-");
    connection_coverage_check(coverage_ok, "optional_path_value_formats_decimal",
                              format_optional_path_id(traced_path.id) == "7");
    connection_coverage_check(coverage_ok, "missing_optional_path_returns_null",
                              find_path_state(traced_paths, std::nullopt) == nullptr);
    connection_coverage_check(coverage_ok, "unknown_path_returns_null",
                              find_path_state(traced_paths, 99) == nullptr);
    connection_coverage_check(coverage_ok, "existing_path_is_found",
                              find_path_state(traced_paths, traced_path.id) != nullptr);
    connection_coverage_check(coverage_ok, "null_path_summary_formats_dash",
                              format_path_state_summary(nullptr) == "-");
    connection_coverage_check(coverage_ok, "traced_path_summary_mentions_path_state",
                              path_summary_mentions_state_for_tests(traced_path));
    connection_coverage_check(coverage_ok, "invalid_ack_first_range_formats_invalid",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 1,
                                  .first_ack_range = 2,
                              }) == "[invalid]");
    connection_coverage_check(coverage_ok, "invalid_ack_gap_formats_invalid",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 0,
                                  .additional_ranges =
                                      {
                                          AckRange{.gap = 9, .range_length = 0},
                                      },
                              }) == "[10-10,invalid]");
    connection_coverage_check(coverage_ok, "invalid_ack_range_length_formats_invalid",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 2,
                                  .additional_ranges =
                                      {
                                          AckRange{.gap = 0, .range_length = 7},
                                      },
                              }) == "[8-10,invalid]");
    connection_coverage_check(coverage_ok, "valid_ack_ranges_format_expected",
                              format_ack_ranges(AckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 1,
                                  .additional_ranges =
                                      {
                                          AckRange{.gap = 0, .range_length = 1},
                                      },
                              }) == "[9-10,6-7]");
    connection_coverage_check(coverage_ok, "invalid_received_ack_formats_invalid",
                              format_ack_ranges(ReceivedAckFrame{
                                  .largest_acknowledged = 10,
                                  .first_ack_range = 1,
                                  .additional_range_count = 1,
                                  .additional_range_bytes =
                                      SharedBytes{
                                          std::byte{0x40},
                                      },
                              }) == "[invalid]");
    connection_coverage_check(coverage_ok, "empty_packet_summary_reports_zero",
                              summarize_packets({}) == "count=0");
    connection_coverage_check(coverage_ok, "packet_summary_mentions_counts",
                              packet_summary_mentions_counts_for_tests());
    connection_coverage_check(coverage_ok, "packet_summary_without_stream_offset_omits_offset",
                              packet_summary_without_stream_offset_omits_offset_for_tests());
    connection_coverage_check(
        coverage_ok, "packet_stream_metadata_helpers_cover_count_bytes_and_first_offset",
        packet_stream_metadata_helpers_cover_count_bytes_and_first_offset_for_tests());
    connection_coverage_check(
        coverage_ok, "packet_first_stream_frame_offset_covers_vector_metadata",
        packet_first_stream_frame_offset(vector_only_metadata_packet_for_tests()) == 33u);
    connection_coverage_check(
        coverage_ok, "packet_first_stream_frame_offset_covers_fragment_metadata",
        packet_first_stream_frame_offset(fragment_only_metadata_packet_for_tests()) == 44u);
    connection_coverage_check(coverage_ok, "packet_first_stream_frame_offset_covers_empty_packet",
                              !packet_first_stream_frame_offset(SentPacketRecord{}).has_value());
    connection_coverage_check(coverage_ok, "stream_frame_payload_budget_handles_edges",
                              stream_frame_payload_budget_handles_edges_for_tests());
    connection_coverage_check(
        coverage_ok, "application_stream_budget_normal_datagram",
        application_stream_frame_budget(/*max_datagram_size=*/1199,
                                        /*destination_connection_id_size=*/8) == 1172);
    connection_coverage_check(coverage_ok, "application_stream_budget_oversized_connection_id",
                              application_stream_frame_budget(
                                  /*max_datagram_size=*/1200,
                                  /*destination_connection_id_size=*/1200) == 0);
    connection_coverage_check(
        coverage_ok, "application_stream_budget_tiny_datagram",
        application_stream_frame_budget(/*max_datagram_size=*/26,
                                        /*destination_connection_id_size=*/8) == 0);
    connection_coverage_check(
        coverage_ok, "application_stream_budget_large_datagram",
        application_stream_frame_budget(/*max_datagram_size=*/1400,
                                        /*destination_connection_id_size=*/8) == 1373);

    connection_coverage_check(
        coverage_ok, "one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_frames",
        one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_for_tests(
            test_retry_source_connection_id));

    connection_coverage_check(coverage_ok, "one_rtt_fragment_size_propagates_frame_size_errors",
                              one_rtt_fragment_size_propagates_frame_size_errors_for_tests(
                                  test_retry_source_connection_id));

    connection_coverage_check(
        coverage_ok, "one_rtt_fragment_size_rejects_empty_payloads",
        one_rtt_fragment_size_rejects_empty_payloads_for_tests(test_retry_source_connection_id));

    connection_coverage_check(coverage_ok, "one_rtt_fragment_helpers_count_stream_fragment_bytes",
                              one_rtt_fragment_helpers_count_stream_fragment_bytes_for_tests(
                                  test_retry_source_connection_id));

    connection_coverage_check(coverage_ok,
                              "one_rtt_fragment_size_rejects_overflowing_fragment_offsets",
                              one_rtt_fragment_size_rejects_overflowing_fragment_offsets_for_tests(
                                  test_retry_source_connection_id));

    connection_coverage_check(coverage_ok, "empty_long_header_rejected",
                              !peek_discardable_long_header_packet_length({}).has_value());
    connection_coverage_check(
        coverage_ok, "short_header_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0x40})).has_value());
    connection_coverage_check(
        coverage_ok, "truncated_version_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00}))
             .has_value());
    connection_coverage_check(
        coverage_ok, "unsupported_version_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00}))
             .has_value());
    connection_coverage_check(
        coverage_ok, "missing_destination_connection_id_length_rejected",
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}))
             .has_value());
    connection_coverage_check(coverage_ok, "oversized_destination_connection_id_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}))
                                   .has_value());
    connection_coverage_check(coverage_ok, "truncated_destination_connection_id_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01}))
                                   .has_value());
    connection_coverage_check(coverage_ok, "missing_source_connection_id_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}))
                                   .has_value());
    connection_coverage_check(coverage_ok, "oversized_source_connection_id_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x15}))
                                   .has_value());
    connection_coverage_check(coverage_ok, "truncated_source_connection_id_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}))
                                   .has_value());
    connection_coverage_check(coverage_ok, "missing_initial_token_length_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(
        coverage_ok, "oversized_initial_token_length_rejected",
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value());
    connection_coverage_check(coverage_ok, "unsupported_retry_packet_type_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(
        coverage_ok, "missing_payload_length_after_initial_token_rejected",
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00}))
             .has_value());
    connection_coverage_check(coverage_ok, "missing_payload_length_for_handshake_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(coverage_ok, "missing_payload_length_for_zero_rtt_rejected",
                              !peek_discardable_long_header_packet_length(
                                   bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
                                   .has_value());
    connection_coverage_check(
        coverage_ok, "oversized_payload_length_rejected",
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value());
    connection_coverage_check(coverage_ok, "quic_core_secret_fallback_has_bytes",
                              quic_core_secret_fallback_has_bytes_for_tests());
    connection_coverage_check(
        coverage_ok, "issued_connection_id_rand_fallback_has_bytes",
        issued_connection_id_rand_fallback_has_bytes_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "issued_connection_id_fallback_has_bytes",
        issued_connection_id_fallback_has_bytes_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "stateless_reset_token_rand_fallback_has_bytes",
        stateless_reset_token_rand_fallback_has_bytes_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "stateless_reset_token_fallback_has_bytes",
        stateless_reset_token_fallback_has_bytes_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "stateless_reset_token_empty_connection_id_fallback_has_bytes",
        stateless_reset_token_empty_connection_id_fallback_has_bytes_for_tests());
    connection_coverage_check(
        coverage_ok, "stateless_reset_token_empty_connection_id_rand_fallback_has_bytes",
        stateless_reset_token_empty_connection_id_rand_fallback_has_bytes_for_tests());
    connection_coverage_check(
        coverage_ok, "path_challenge_rand_fallback_has_bytes",
        path_challenge_rand_fallback_has_bytes_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "path_challenge_fallback_has_bytes",
        path_challenge_fallback_has_bytes_for_tests(test_retry_source_connection_id));
    connection_coverage_check(coverage_ok, "path_challenge_empty_connection_id_fallback_has_bytes",
                              path_challenge_empty_connection_id_fallback_has_bytes_for_tests());
    connection_coverage_check(
        coverage_ok, "path_challenge_empty_connection_id_rand_fallback_has_bytes",
        path_challenge_empty_connection_id_rand_fallback_has_bytes_for_tests());
    connection_coverage_check(coverage_ok, "random_one_in_sixteen_fallback_returns_bool",
                              random_one_in_sixteen_fallback_returns_bool_for_tests());
    connection_coverage_check(coverage_ok, "forced_random_one_in_sixteen_false",
                              forced_random_one_in_sixteen_false_for_tests());
    connection_coverage_check(coverage_ok, "forced_random_one_in_sixteen_true",
                              forced_random_one_in_sixteen_true_for_tests());
    connection_coverage_check(coverage_ok, "for_each_stream_frame_metadata_visits_first_metadata",
                              stream_metadata_visit_results_for_tests().visits_first_metadata);
    connection_coverage_check(coverage_ok, "for_each_stream_frame_metadata_visits_vector_metadata",
                              stream_metadata_visit_results_for_tests().visits_vector_metadata);
    connection_coverage_check(coverage_ok, "stream_metadata_probe_worthy_outstanding",
                              stream_metadata_probe_worthy_outstanding_for_tests());
    connection_coverage_check(coverage_ok, "stream_metadata_probe_worthy_fin",
                              stream_metadata_probe_worthy_fin_for_tests());
    connection_coverage_check(coverage_ok, "stream_metadata_probe_worthy_missing_fin_rejected",
                              stream_metadata_probe_worthy_missing_fin_rejected_for_tests());
    connection_coverage_check(coverage_ok, "stream_metadata_probe_worthy_acked_fin_rejected",
                              stream_metadata_probe_worthy_acked_fin_rejected_for_tests());
    connection_coverage_check(coverage_ok, "single_path_simple_stream_ack_ecn_ignores_failed_path",
                              single_path_simple_stream_ack_ecn_ignores_failed_path_for_tests());
    connection_coverage_check(coverage_ok,
                              "single_path_simple_stream_ack_ecn_missing_counts_disable",
                              single_path_simple_stream_ack_ecn_missing_counts_disable_for_tests());
    connection_coverage_check(
        coverage_ok, "single_path_simple_stream_ack_ecn_decreased_counts_disable",
        single_path_simple_stream_ack_ecn_decreased_counts_disable_for_tests());
    connection_coverage_check(coverage_ok, "single_path_simple_stream_ack_ecn_counts_ect1",
                              single_path_simple_stream_ack_ecn_counts_ect1_for_tests());
    connection_coverage_check(
        coverage_ok, "single_path_simple_stream_ack_ecn_missing_feedback_disables",
        single_path_simple_stream_ack_ecn_missing_feedback_disables_for_tests());
    connection_coverage_check(coverage_ok,
                              "single_path_simple_stream_ack_ecn_success_tracks_ce_time",
                              single_path_simple_stream_ack_ecn_success_tracks_ce_time_for_tests());
    connection_coverage_check(coverage_ok, "simple_stream_ack_ecn_non_ect_samples_are_ignored",
                              simple_stream_ack_ecn_non_ect_samples_are_ignored_for_tests());
    connection_coverage_check(coverage_ok, "multi_path_simple_stream_ack_ecn_ignores_failed_path",
                              multi_path_simple_stream_ack_ecn_ignores_failed_path_for_tests());
    connection_coverage_check(coverage_ok,
                              "multi_path_simple_stream_ack_ecn_missing_counts_disable",
                              multi_path_simple_stream_ack_ecn_missing_counts_disable_for_tests());
    connection_coverage_check(
        coverage_ok, "multi_path_simple_stream_ack_ecn_decreased_counts_disable",
        multi_path_simple_stream_ack_ecn_decreased_counts_disable_for_tests());
    connection_coverage_check(
        coverage_ok, "multi_path_simple_stream_ack_ecn_missing_feedback_disables",
        multi_path_simple_stream_ack_ecn_missing_feedback_disables_for_tests());
    connection_coverage_check(coverage_ok,
                              "multi_path_simple_stream_ack_ecn_success_tracks_ce_time",
                              multi_path_simple_stream_ack_ecn_success_tracks_ce_time_for_tests());
    connection_coverage_check(coverage_ok, "trace_unset_disabled",
                              trace_unset_disabled_for_tests(test_retry_source_connection_id));
    connection_coverage_check(coverage_ok, "trace_empty_disabled",
                              trace_empty_disabled_for_tests());
    connection_coverage_check(coverage_ok, "trace_zero_disabled", trace_zero_disabled_for_tests());
    connection_coverage_check(
        coverage_ok, "trace_matches_without_filter",
        trace_matches_without_filter_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "trace_matches_with_empty_filter",
        trace_matches_with_empty_filter_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "trace_matches_with_exact_filter",
        trace_matches_with_exact_filter_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "trace_rejects_mismatched_filter",
        trace_rejects_mismatched_filter_for_tests(test_retry_source_connection_id));
    connection_coverage_check(
        coverage_ok, "discardable_deferred_replay_packet_does_not_block_current_packet",
        discardable_deferred_replay_packet_does_not_block_current_packet_for_tests());
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(
            coverage_ok, "discardable_deferred_replay_packet_reports_serialization_failure",
            !discardable_deferred_replay_packet_does_not_block_current_packet_for_tests());
    }
    connection_coverage_check(coverage_ok, "in_place_receive_storage_before_begin_guard",
                              in_place_receive_storage_guard_for_tests(
                                  &ConnectionDrainTestHooks::force_storage_range_before_storage));
    connection_coverage_check(coverage_ok, "in_place_receive_storage_overflow_guard",
                              in_place_receive_storage_guard_for_tests(
                                  &ConnectionDrainTestHooks::force_storage_range_overflow));
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(
            coverage_ok, "in_place_receive_storage_guard_reports_serialization_failure",
            !in_place_receive_storage_guard_for_tests(
                &ConnectionDrainTestHooks::force_storage_range_before_storage));
    }
    connection_coverage_check(coverage_ok, "replay_failure_before_current_packet_is_non_fatal",
                              replay_failure_before_current_packet_is_non_fatal_for_tests());
    connection_coverage_check(coverage_ok, "replay_failure_after_current_packet_is_non_fatal",
                              replay_failure_after_current_packet_is_non_fatal_for_tests());
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(
            coverage_ok, "replay_failure_before_current_packet_reports_serialization_failure",
            !replay_failure_before_current_packet_is_non_fatal_for_tests());
    }
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(
            coverage_ok, "replay_failure_after_current_packet_reports_serialization_failure",
            !replay_failure_after_current_packet_is_non_fatal_for_tests());
    }
    connection_coverage_check(coverage_ok, "fast_path_ack_only_packet_processed",
                              fast_path_ack_only_packet_processed_for_tests());
    connection_coverage_check(coverage_ok, "fast_path_duplicate_ack_only_packet_ignored",
                              fast_path_duplicate_ack_only_packet_ignored_for_tests());
    connection_coverage_check(coverage_ok, "fast_path_stream_packet_processed",
                              fast_path_stream_packet_processed_for_tests());
    connection_coverage_check(coverage_ok, "fast_path_duplicate_stream_packet_ignored",
                              fast_path_duplicate_stream_packet_ignored_for_tests());
    connection_coverage_check(coverage_ok, "fast_path_corrupted_packet_discarded",
                              fast_path_corrupted_packet_discarded_for_tests());
    connection_coverage_check(coverage_ok, "retired_peer_application_frames_are_ignored",
                              retired_peer_application_frames_are_ignored_for_tests());
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(coverage_ok, "fast_path_ack_only_reports_serialization_failure",
                                  !fast_path_ack_only_packet_processed_for_tests());
    }
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(coverage_ok,
                                  "fast_path_duplicate_ack_only_reports_serialization_failure",
                                  !fast_path_duplicate_ack_only_packet_ignored_for_tests());
    }
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(coverage_ok, "fast_path_stream_reports_serialization_failure",
                                  !fast_path_stream_packet_processed_for_tests());
    }
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(coverage_ok,
                                  "fast_path_duplicate_stream_reports_serialization_failure",
                                  !fast_path_duplicate_stream_packet_ignored_for_tests());
    }
    {
        const ScopedPacketCryptoFaultInjector injector(PacketCryptoFaultPoint::seal_context_new);
        connection_coverage_check(coverage_ok, "fast_path_corrupted_reports_serialization_failure",
                                  !fast_path_corrupted_packet_discarded_for_tests());
    }

    return coverage_ok;
}

bool connection_ack_deadline_and_stream_utilities_for_tests() {
    bool coverage_ok = true;
    const auto record = [&](bool condition) {
        coverage_ok &= condition;
        return condition;
    };
    const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(17);

    PacketSpaceState ce_packet_space;
    schedule_application_ack_deadline(ce_packet_space, now, /*max_ack_delay_ms=*/25,
                                      QuicEcnCodepoint::ce);
    record(ce_packet_space.pending_ack_deadline == now);
    record(ce_packet_space.force_ack_send);

    PacketSpaceState delayed_ack_packet_space;
    schedule_application_ack_deadline(delayed_ack_packet_space, now, /*max_ack_delay_ms=*/25,
                                      QuicEcnCodepoint::ect0);
    record(delayed_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(25));
    record(!delayed_ack_packet_space.force_ack_send);
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
    record(immediate_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(2));
    record(!immediate_ack_packet_space.force_ack_send);

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

    return coverage_ok;
}

bool connection_header_packet_space_coverage_for_tests() {
    bool coverage_ok = true;
    const auto record = [&](bool condition) { coverage_ok &= condition; };

    {
        SerializedProtectedDatagram inspection_datagram{
            .bytes = DatagramBuffer{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
            .packet_metadata = {{.offset = 1, .length = 1}},
        };
        record(QuicConnection(make_client_core_config_for_connection_coverage())
                   .queue_outbound_packet_inspections(inspection_datagram, /*datagram_id=*/1) == 0);
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
        const auto protected_inspection_datagram = serialize_protected_datagram_with_metadata(
            std::array<ProtectedPacket, 3>{
                ProtectedPacket{ProtectedInitialPacket{
                    .version = kQuicVersion1,
                    .destination_connection_id =
                        connection.config_.initial_destination_connection_id,
                    .source_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 1,
                    .frames = {PingFrame{}},
                }},
                ProtectedPacket{ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id =
                        connection.config_.initial_destination_connection_id,
                    .source_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 2,
                    .frames = {PingFrame{}},
                }},
                ProtectedPacket{ProtectedZeroRttPacket{
                    .version = kQuicVersion1,
                    .destination_connection_id =
                        connection.config_.initial_destination_connection_id,
                    .source_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 3,
                    .frames = {PingFrame{}},
                }},
            },
            SerializeProtectionContext{
                .local_role = connection.config_.role,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.write_secret,
                .zero_rtt_secret = connection.zero_rtt_space_.write_secret,
            });
        record(protected_inspection_datagram.has_value());
        record(connection.queue_outbound_packet_inspections(protected_inspection_datagram.value(),
                                                            7) == 3);
        const auto initial_inspection = connection.take_packet_inspection();
        const auto handshake_inspection = connection.take_packet_inspection();
        const auto zero_rtt_inspection = connection.take_packet_inspection();
        record(initial_inspection.has_value());
        record(initial_inspection.value_or(QuicCorePacketInspection{}).packet_type ==
               QuicCorePacketInspectionPacketType::initial);
        record(handshake_inspection.has_value());
        record(handshake_inspection.value_or(QuicCorePacketInspection{}).packet_type ==
               QuicCorePacketInspectionPacketType::handshake);
        record(zero_rtt_inspection.has_value());
        record(zero_rtt_inspection.value_or(QuicCorePacketInspection{}).packet_type ==
               QuicCorePacketInspectionPacketType::zero_rtt);
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

        record(declared_lost.emplace(9, packet).second);
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

    return coverage_ok;
}

} // namespace coquic::quic::test

#pragma once

#include "src/quic/frame.h"

namespace coquic::quic::test {

bool frame_internal_coverage_for_tests();
bool frame_fault_helper_branch_coverage_for_tests();
bool frame_length_prefixed_span_fault_coverage_for_tests();
bool frame_single_varint_writer_fault_coverage_for_tests();
bool frame_matches_codec_error_branch_coverage_for_tests();
bool frame_matches_codec_error_success_branch_coverage_for_tests();
bool frame_received_unknown_type_branch_coverage_for_tests();
bool frame_streams_blocked_writer_success_coverage_for_tests(StreamLimitType stream_type);
bool frame_writer_branch_coverage_for_tests();

} // namespace coquic::quic::test

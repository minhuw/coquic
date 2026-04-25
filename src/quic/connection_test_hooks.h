#pragma once

namespace coquic::quic::test {

bool connection_helper_edge_cases_for_tests();
bool connection_ack_deadline_and_stream_utilities_for_tests();
bool connection_header_packet_space_coverage_for_tests();
void connection_set_force_missing_packet_metadata_for_tests(bool enabled);
void connection_set_force_missing_fallback_packet_length_for_tests(bool enabled);

} // namespace coquic::quic::test

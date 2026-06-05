#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_hooks.h"

namespace coquic::quic::test {

void connection_set_force_missing_packet_metadata_for_tests(bool enabled) {
    connection_drain_test_hooks().force_missing_packet_metadata = enabled;
}

void connection_set_force_quic_core_secret_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_quic_core_secret_rand_failure = enabled;
}

void connection_set_force_prf_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_prf_failure = enabled;
}

void connection_set_force_issued_connection_id_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_issued_connection_id_rand_failure = enabled;
}

void connection_set_force_stateless_reset_token_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_stateless_reset_token_rand_failure = enabled;
}

void connection_set_force_path_challenge_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_path_challenge_rand_failure = enabled;
}

void connection_set_force_random_one_in_sixteen_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_random_one_in_sixteen_rand_failure = enabled;
}

void connection_set_force_missing_fallback_packet_length_for_tests(bool enabled) {
    connection_drain_test_hooks().force_missing_fallback_packet_length = enabled;
}

void connection_set_force_appended_fragment_base_datagram_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_appended_fragment_base_datagram_failure = enabled;
}

void connection_set_force_aead_confidentiality_limit_for_tests(bool enabled) {
    connection_drain_test_hooks().force_aead_confidentiality_limit = enabled;
}

void connection_set_force_aead_integrity_limit_for_tests(bool enabled) {
    connection_drain_test_hooks().force_aead_integrity_limit = enabled;
}

void connection_set_force_application_candidate_estimate_failure_countdown_for_tests(int value) {
    connection_drain_test_hooks().force_application_candidate_estimate_failure_countdown = value;
}

void connection_set_force_candidate_datagram_serialization_failure_countdown_for_tests(int value) {
    connection_drain_test_hooks().force_candidate_datagram_serialization_failure_countdown = value;
}

void connection_set_force_application_candidate_datagram_extra_bytes_for_tests(
    ApplicationCandidateDatagramExtraBytesTestHook hook) {
    connection_drain_test_hooks().force_application_candidate_datagram_extra_bytes_countdown =
        hook.countdown;
    connection_drain_test_hooks().force_application_candidate_datagram_extra_bytes = hook.bytes;
}

} // namespace coquic::quic::test

#!/usr/bin/env bash

COQUIC_FUZZ_TARGETS=(
  fuzz_varint
  fuzz_frame
  fuzz_plaintext_packet
  fuzz_long_header_packet
  fuzz_short_header_packet
  fuzz_datagram
  fuzz_transport_parameters
  fuzz_protected_packet
  fuzz_stream_state
  fuzz_recovery_ack
  fuzz_congestion
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "${COQUIC_FUZZ_TARGETS[@]}"
fi

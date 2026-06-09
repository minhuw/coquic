#!/usr/bin/env bash

COQUIC_FUZZ_TARGETS=(
  fuzz_varint
  fuzz_frame
  fuzz_plaintext_packet
  fuzz_long_header_packet
  fuzz_short_header_packet
  fuzz_datagram
  fuzz_transport_parameters
)


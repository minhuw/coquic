from __future__ import annotations

import ctypes as C
import ctypes.util
import os
from pathlib import Path

FFI_ABI_VERSION = 4

COQUIC_STATUS_OK = 0
COQUIC_STATUS_INVALID_ARGUMENT = 1
COQUIC_STATUS_OUT_OF_MEMORY = 2
COQUIC_STATUS_INTERNAL_ERROR = 3

COQUIC_ROLE_CLIENT = 0
COQUIC_ROLE_SERVER = 1

COQUIC_CONGESTION_CONTROL_NEWRENO = 0
COQUIC_CONGESTION_CONTROL_CUBIC = 1
COQUIC_CONGESTION_CONTROL_BBR = 2
COQUIC_CONGESTION_CONTROL_COPA = 3

COQUIC_ECN_UNAVAILABLE = 0
COQUIC_ECN_NOT_ECT = 1
COQUIC_ECN_ECT0 = 2
COQUIC_ECN_ECT1 = 3
COQUIC_ECN_CE = 4

COQUIC_STATE_CHANGE_HANDSHAKE_READY = 0
COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED = 1
COQUIC_STATE_CHANGE_FAILED = 2

COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION = 0
COQUIC_LOCAL_ERROR_INVALID_STREAM_ID = 1
COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION = 2
COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED = 3
COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED = 4
COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT = 5
COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED = 6
COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE = 7

COQUIC_LIFECYCLE_CREATED = 0
COQUIC_LIFECYCLE_ACCEPTED = 1
COQUIC_LIFECYCLE_CLOSED = 2

COQUIC_MIGRATION_REASON_ACTIVE = 0
COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS = 1

COQUIC_ZERO_RTT_UNAVAILABLE = 0
COQUIC_ZERO_RTT_NOT_ATTEMPTED = 1
COQUIC_ZERO_RTT_ATTEMPTED = 2
COQUIC_ZERO_RTT_ACCEPTED = 3
COQUIC_ZERO_RTT_REJECTED = 4

COQUIC_PACKET_INSPECTION_OUTBOUND = 0
COQUIC_PACKET_INSPECTION_INBOUND = 1

COQUIC_PACKET_INSPECTION_INITIAL = 0
COQUIC_PACKET_INSPECTION_ZERO_RTT = 1
COQUIC_PACKET_INSPECTION_HANDSHAKE = 2
COQUIC_PACKET_INSPECTION_ONE_RTT = 3

COQUIC_CONNECTION_INPUT_SEND_STREAM = 0
COQUIC_CONNECTION_INPUT_SEND_DATAGRAM = 1
COQUIC_CONNECTION_INPUT_RESET_STREAM = 2
COQUIC_CONNECTION_INPUT_STOP_SENDING = 3
COQUIC_CONNECTION_INPUT_CLOSE = 4
COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE = 5
COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION = 6

COQUIC_EFFECT_SEND_DATAGRAM = 0
COQUIC_EFFECT_RECEIVE_STREAM_DATA = 1
COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA = 2
COQUIC_EFFECT_PEER_RESET_STREAM = 3
COQUIC_EFFECT_PEER_STOP_SENDING = 4
COQUIC_EFFECT_STATE_EVENT = 5
COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT = 6
COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE = 7
COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE = 8
COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT = 9
COQUIC_EFFECT_PACKET_INSPECTION = 10
COQUIC_EFFECT_NEW_TOKEN_AVAILABLE = 11


class coquic_bytes_view_t(C.Structure):
    _fields_ = [
        ("data", C.POINTER(C.c_uint8)),
        ("length", C.c_size_t),
    ]


class coquic_bytes_t(C.Structure):
    _fields_ = [
        ("data", C.POINTER(C.c_uint8)),
        ("length", C.c_size_t),
    ]


class coquic_optional_route_handle_t(C.Structure):
    _fields_ = [
        ("has_value", C.c_uint8),
        ("value", C.c_uint64),
    ]


class coquic_optional_connection_handle_t(C.Structure):
    _fields_ = [
        ("has_value", C.c_uint8),
        ("value", C.c_uint64),
    ]


class coquic_optional_stream_id_t(C.Structure):
    _fields_ = [
        ("has_value", C.c_uint8),
        ("value", C.c_uint64),
    ]


class coquic_optional_time_us_t(C.Structure):
    _fields_ = [
        ("has_value", C.c_uint8),
        ("value", C.c_uint64),
    ]


class coquic_optional_u64_t(C.Structure):
    _fields_ = [
        ("has_value", C.c_uint8),
        ("value", C.c_uint64),
    ]


class coquic_tls_identity_t(C.Structure):
    _fields_ = [
        ("certificate_pem", C.POINTER(C.c_char)),
        ("certificate_pem_length", C.c_size_t),
        ("private_key_pem", C.POINTER(C.c_char)),
        ("private_key_pem_length", C.c_size_t),
    ]


class coquic_zero_rtt_config_t(C.Structure):
    _fields_ = [
        ("attempt", C.c_uint8),
        ("allow", C.c_uint8),
        ("application_context", coquic_bytes_t),
    ]


class coquic_orphan_zero_rtt_buffer_config_t(C.Structure):
    _fields_ = [
        ("max_packets", C.c_size_t),
        ("max_bytes", C.c_size_t),
        ("max_age_us", C.c_uint64),
    ]


class coquic_transport_config_t(C.Structure):
    _fields_ = [
        ("max_idle_timeout", C.c_uint64),
        ("max_udp_payload_size", C.c_uint64),
        ("pmtud_enabled", C.c_uint8),
        ("pmtud_base_datagram_size", C.c_size_t),
        ("pmtud_max_datagram_size", C.c_size_t),
        ("active_connection_id_limit", C.c_uint64),
        ("disable_active_migration", C.c_uint8),
        ("ack_delay_exponent", C.c_uint64),
        ("max_ack_delay", C.c_uint64),
        ("ack_eliciting_threshold", C.c_uint64),
        ("initial_max_data", C.c_uint64),
        ("initial_max_stream_data_bidi_local", C.c_uint64),
        ("initial_max_stream_data_bidi_remote", C.c_uint64),
        ("initial_max_stream_data_uni", C.c_uint64),
        ("initial_max_streams_bidi", C.c_uint64),
        ("initial_max_streams_uni", C.c_uint64),
        ("max_datagram_frame_size", C.c_uint64),
        ("congestion_control", C.c_uint8),
        ("enable_hystart_plus_plus", C.c_uint8),
        ("send_stream_fairness", C.c_uint8),
        ("enable_latency_spin_bit", C.c_uint8),
        ("grease_reserved_versions", C.c_uint8),
        ("grease_quic_bit", C.c_uint8),
        ("enable_optimistic_ack_mitigation", C.c_uint8),
    ]


class coquic_endpoint_config_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("role", C.c_uint8),
        ("supported_versions", C.POINTER(C.c_uint32)),
        ("supported_versions_count", C.c_size_t),
        ("verify_peer", C.c_uint8),
        ("retry_enabled", C.c_uint8),
        ("application_protocol", C.POINTER(C.c_char)),
        ("application_protocol_length", C.c_size_t),
        ("identity", C.POINTER(coquic_tls_identity_t)),
        ("transport", coquic_transport_config_t),
        ("max_outbound_datagram_size", C.c_size_t),
        ("zero_rtt", coquic_zero_rtt_config_t),
        ("emit_shared_receive_stream_data", C.c_uint8),
        ("enable_packet_inspection", C.c_uint8),
        ("allow_peer_address_change", C.c_uint8),
        ("max_server_connections", C.c_size_t),
        ("enable_out_of_order_receive", C.c_uint8),
        ("orphan_zero_rtt_buffer", coquic_orphan_zero_rtt_buffer_config_t),
    ]


class coquic_resumption_state_t(C.Structure):
    _fields_ = [("serialized", coquic_bytes_t)]


class coquic_client_connection_config_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("source_connection_id", coquic_bytes_t),
        ("initial_destination_connection_id", coquic_bytes_t),
        ("original_destination_connection_id", coquic_bytes_t),
        ("has_original_destination_connection_id", C.c_uint8),
        ("retry_source_connection_id", coquic_bytes_t),
        ("has_retry_source_connection_id", C.c_uint8),
        ("retry_token", coquic_bytes_t),
        ("original_version", C.c_uint32),
        ("initial_version", C.c_uint32),
        ("reacted_to_version_negotiation", C.c_uint8),
        ("server_name", C.POINTER(C.c_char)),
        ("server_name_length", C.c_size_t),
        ("resumption_state", C.POINTER(coquic_resumption_state_t)),
        ("zero_rtt", coquic_zero_rtt_config_t),
    ]


class coquic_open_connection_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("connection", coquic_client_connection_config_t),
        ("initial_route_handle", C.c_uint64),
        ("address_validation_identity", coquic_bytes_t),
    ]


class coquic_inbound_datagram_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("bytes", coquic_bytes_t),
        ("route_handle", coquic_optional_route_handle_t),
        ("address_validation_identity", coquic_bytes_t),
        ("ecn", C.c_uint8),
    ]


class coquic_path_mtu_update_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("route_handle", coquic_optional_route_handle_t),
        ("max_udp_payload_size", C.c_size_t),
    ]


class coquic_send_stream_data_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("stream_id", C.c_uint64),
        ("bytes", coquic_bytes_t),
        ("fin", C.c_uint8),
        ("priority", C.c_int32),
    ]


class coquic_send_datagram_data_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("bytes", coquic_bytes_t),
        ("priority", C.c_int32),
    ]


class coquic_reset_stream_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("stream_id", C.c_uint64),
        ("application_error_code", C.c_uint64),
    ]


class coquic_stop_sending_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("stream_id", C.c_uint64),
        ("application_error_code", C.c_uint64),
    ]


class coquic_close_connection_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("application_error_code", C.c_uint64),
        ("reason_phrase", C.POINTER(C.c_char)),
        ("reason_phrase_length", C.c_size_t),
    ]


class coquic_request_connection_migration_t(C.Structure):
    _fields_ = [
        ("size", C.c_size_t),
        ("route_handle", C.c_uint64),
        ("reason", C.c_uint8),
        ("address_validation_identity", coquic_bytes_t),
    ]


class coquic_connection_input_union_t(C.Union):
    _fields_ = [
        ("send_stream", coquic_send_stream_data_t),
        ("send_datagram", coquic_send_datagram_data_t),
        ("reset_stream", coquic_reset_stream_t),
        ("stop_sending", coquic_stop_sending_t),
        ("close", coquic_close_connection_t),
        ("request_migration", coquic_request_connection_migration_t),
    ]


class coquic_connection_input_t(C.Structure):
    _fields_ = [
        ("kind", C.c_uint8),
        ("as_", coquic_connection_input_union_t),
    ]


class coquic_local_error_t(C.Structure):
    _fields_ = [
        ("connection", coquic_optional_connection_handle_t),
        ("code", C.c_uint8),
        ("stream_id", coquic_optional_stream_id_t),
    ]


class coquic_send_datagram_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("route_handle", coquic_optional_route_handle_t),
        ("bytes", coquic_bytes_view_t),
        ("ecn", C.c_uint8),
        ("is_pmtu_probe", C.c_uint8),
    ]


class coquic_receive_stream_data_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("stream_id", C.c_uint64),
        ("offset", C.c_uint64),
        ("bytes", coquic_bytes_view_t),
        ("fin", C.c_uint8),
        ("final_size", coquic_optional_u64_t),
    ]


class coquic_receive_datagram_data_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("bytes", coquic_bytes_view_t),
    ]


class coquic_peer_reset_stream_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("stream_id", C.c_uint64),
        ("application_error_code", C.c_uint64),
        ("final_size", C.c_uint64),
    ]


class coquic_peer_stop_sending_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("stream_id", C.c_uint64),
        ("application_error_code", C.c_uint64),
    ]


class coquic_state_event_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("change", C.c_uint8),
    ]


class coquic_connection_lifecycle_event_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("event", C.c_uint8),
    ]


class coquic_preferred_address_t(C.Structure):
    _fields_ = [
        ("ipv4_address", C.c_uint8 * 4),
        ("ipv4_port", C.c_uint16),
        ("ipv6_address", C.c_uint8 * 16),
        ("ipv6_port", C.c_uint16),
        ("connection_id", coquic_bytes_view_t),
        ("stateless_reset_token", C.c_uint8 * 16),
    ]


class coquic_peer_preferred_address_available_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("preferred_address", coquic_preferred_address_t),
    ]


class coquic_resumption_state_available_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("serialized", coquic_bytes_view_t),
    ]


class coquic_zero_rtt_status_event_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("status", C.c_uint8),
    ]


class coquic_packet_inspection_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("direction", C.c_uint8),
        ("packet_type", C.c_uint8),
        ("datagram_id", C.c_uint64),
        ("datagram_length", C.c_size_t),
        ("datagram_offset", C.c_size_t),
        ("packet_length", C.c_size_t),
        ("version", C.c_uint32),
        ("destination_connection_id", coquic_bytes_view_t),
        ("source_connection_id", coquic_bytes_view_t),
        ("token", coquic_bytes_view_t),
        ("spin_bit", C.c_uint8),
        ("key_phase", C.c_uint8),
        ("packet_number_length", C.c_uint8),
        ("packet_number", C.c_uint64),
        ("encrypted_packet", coquic_bytes_view_t),
        ("plaintext_payload", coquic_bytes_view_t),
    ]


class coquic_new_token_available_effect_t(C.Structure):
    _fields_ = [
        ("connection", C.c_uint64),
        ("token", coquic_bytes_view_t),
    ]


class coquic_effect_union_t(C.Union):
    _fields_ = [
        ("send_datagram", coquic_send_datagram_effect_t),
        ("receive_stream_data", coquic_receive_stream_data_effect_t),
        ("receive_datagram_data", coquic_receive_datagram_data_effect_t),
        ("peer_reset_stream", coquic_peer_reset_stream_effect_t),
        ("peer_stop_sending", coquic_peer_stop_sending_effect_t),
        ("state_event", coquic_state_event_effect_t),
        ("connection_lifecycle_event", coquic_connection_lifecycle_event_effect_t),
        ("peer_preferred_address_available", coquic_peer_preferred_address_available_effect_t),
        ("resumption_state_available", coquic_resumption_state_available_effect_t),
        ("zero_rtt_status_event", coquic_zero_rtt_status_event_effect_t),
        ("packet_inspection", coquic_packet_inspection_effect_t),
        ("new_token_available", coquic_new_token_available_effect_t),
    ]


class coquic_effect_t(C.Structure):
    _fields_ = [
        ("kind", C.c_uint8),
        ("as_", coquic_effect_union_t),
    ]


_LIB = None


def _platform_library_names(name: str) -> list[str]:
    if name.startswith(("lib", "/")) or name.endswith((".so", ".dylib", ".dll")):
        return [name]
    if os.name == "nt":
        return [f"{name}.dll", f"lib{name}.dll"]
    if os.uname().sysname == "Darwin":
        return [f"lib{name}.dylib", f"{name}.dylib"]
    return [f"lib{name}.so", f"{name}.so"]


def _candidate_paths() -> list[str]:
    paths: list[str] = []
    explicit = os.environ.get("COQUIC_LIB_PATH")
    if explicit:
        paths.append(explicit)

    lib_dir = os.environ.get("COQUIC_LIB_DIR")
    lib_name = os.environ.get("COQUIC_LIB_NAME", "coquic-boringssl")
    if lib_dir:
        for name in _platform_library_names(lib_name):
            paths.append(str(Path(lib_dir) / name))

    repo = Path(__file__).resolve().parents[5]
    for name in ("coquic-boringssl", "coquic-quictls"):
        for platform_name in _platform_library_names(name):
            paths.append(str(repo / "zig-out" / "lib" / platform_name))

    for name in ("coquic-boringssl", "coquic-quictls", "coquic"):
        found = ctypes.util.find_library(name)
        if found:
            paths.append(found)

    return paths


def load_library() -> C.CDLL:
    global _LIB
    if _LIB is not None:
        return _LIB

    errors: list[str] = []
    for path in _candidate_paths():
        try:
            _LIB = C.CDLL(path)
            _configure_library(_LIB)
            return _LIB
        except OSError as error:
            errors.append(f"{path}: {error}")

    detail = "\n".join(errors) if errors else "no candidate libraries"
    raise OSError(f"failed to load CoQUIC shared library:\n{detail}")


def _configure_library(lib: C.CDLL) -> None:
    endpoint = C.c_void_p
    result = C.c_void_p

    lib.coquic_ffi_abi_version.argtypes = []
    lib.coquic_ffi_abi_version.restype = C.c_uint32
    lib.coquic_transport_config_init.argtypes = [C.POINTER(coquic_transport_config_t)]
    lib.coquic_transport_config_init.restype = None
    lib.coquic_endpoint_config_init.argtypes = [C.POINTER(coquic_endpoint_config_t)]
    lib.coquic_endpoint_config_init.restype = None
    lib.coquic_client_connection_config_init.argtypes = [
        C.POINTER(coquic_client_connection_config_t)
    ]
    lib.coquic_client_connection_config_init.restype = None

    lib.coquic_endpoint_create.argtypes = [
        C.POINTER(coquic_endpoint_config_t),
        C.POINTER(endpoint),
    ]
    lib.coquic_endpoint_create.restype = C.c_uint8
    lib.coquic_endpoint_destroy.argtypes = [endpoint]
    lib.coquic_endpoint_destroy.restype = None

    result_out = C.POINTER(result)
    lib.coquic_endpoint_open_connection.argtypes = [
        endpoint,
        C.POINTER(coquic_open_connection_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_endpoint_open_connection.restype = C.c_uint8
    lib.coquic_endpoint_input_datagram.argtypes = [
        endpoint,
        C.POINTER(coquic_inbound_datagram_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_endpoint_input_datagram.restype = C.c_uint8
    lib.coquic_endpoint_update_path_mtu.argtypes = [
        endpoint,
        C.POINTER(coquic_path_mtu_update_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_endpoint_update_path_mtu.restype = C.c_uint8
    lib.coquic_endpoint_timer_expired.argtypes = [endpoint, C.c_uint64, result_out]
    lib.coquic_endpoint_timer_expired.restype = C.c_uint8

    lib.coquic_connection_send_stream.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_send_stream_data_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_send_stream.restype = C.c_uint8
    lib.coquic_connection_send_datagram.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_send_datagram_data_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_send_datagram.restype = C.c_uint8
    lib.coquic_connection_reset_stream.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_reset_stream_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_reset_stream.restype = C.c_uint8
    lib.coquic_connection_stop_sending.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_stop_sending_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_stop_sending.restype = C.c_uint8
    lib.coquic_connection_close.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_close_connection_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_close.restype = C.c_uint8
    lib.coquic_connection_request_key_update.argtypes = [
        endpoint,
        C.c_uint64,
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_request_key_update.restype = C.c_uint8
    lib.coquic_connection_request_migration.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_request_connection_migration_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_request_migration.restype = C.c_uint8
    lib.coquic_connection_advance.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_connection_input_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_connection_advance.restype = C.c_uint8

    lib.coquic_quic_connect.argtypes = [
        endpoint,
        C.POINTER(coquic_open_connection_t),
        C.c_uint64,
        C.POINTER(C.c_uint64),
        result_out,
    ]
    lib.coquic_quic_connect.restype = C.c_uint8
    lib.coquic_quic_receive_datagram.argtypes = [
        endpoint,
        C.POINTER(coquic_inbound_datagram_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_receive_datagram.restype = C.c_uint8
    lib.coquic_quic_update_path_mtu.argtypes = [
        endpoint,
        C.POINTER(coquic_path_mtu_update_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_update_path_mtu.restype = C.c_uint8
    lib.coquic_quic_timer_expired.argtypes = [endpoint, C.c_uint64, result_out]
    lib.coquic_quic_timer_expired.restype = C.c_uint8
    lib.coquic_quic_connection_send_stream.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_send_stream_data_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_send_stream.restype = C.c_uint8
    lib.coquic_quic_connection_send_datagram.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_send_datagram_data_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_send_datagram.restype = C.c_uint8
    lib.coquic_quic_connection_reset_stream.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_reset_stream_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_reset_stream.restype = C.c_uint8
    lib.coquic_quic_connection_stop_sending.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_stop_sending_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_stop_sending.restype = C.c_uint8
    lib.coquic_quic_connection_close.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_close_connection_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_close.restype = C.c_uint8
    lib.coquic_quic_connection_request_key_update.argtypes = [
        endpoint,
        C.c_uint64,
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_request_key_update.restype = C.c_uint8
    lib.coquic_quic_connection_advance.argtypes = [
        endpoint,
        C.c_uint64,
        C.POINTER(coquic_connection_input_t),
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_connection_advance.restype = C.c_uint8
    lib.coquic_quic_stream_send.argtypes = [
        endpoint,
        C.c_uint64,
        C.c_uint64,
        coquic_bytes_t,
        C.c_uint8,
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_stream_send.restype = C.c_uint8
    lib.coquic_quic_stream_finish.argtypes = [
        endpoint,
        C.c_uint64,
        C.c_uint64,
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_stream_finish.restype = C.c_uint8
    lib.coquic_quic_stream_reset.argtypes = [
        endpoint,
        C.c_uint64,
        C.c_uint64,
        C.c_uint64,
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_stream_reset.restype = C.c_uint8
    lib.coquic_quic_stream_stop_sending.argtypes = [
        endpoint,
        C.c_uint64,
        C.c_uint64,
        C.c_uint64,
        C.c_uint64,
        result_out,
    ]
    lib.coquic_quic_stream_stop_sending.restype = C.c_uint8

    lib.coquic_endpoint_connection_count.argtypes = [endpoint]
    lib.coquic_endpoint_connection_count.restype = C.c_size_t
    lib.coquic_endpoint_has_send_continuation_pending.argtypes = [endpoint]
    lib.coquic_endpoint_has_send_continuation_pending.restype = C.c_uint8
    lib.coquic_endpoint_has_pending_stream_send.argtypes = [endpoint]
    lib.coquic_endpoint_has_pending_stream_send.restype = C.c_uint8
    lib.coquic_endpoint_next_wakeup.argtypes = [endpoint]
    lib.coquic_endpoint_next_wakeup.restype = coquic_optional_time_us_t

    lib.coquic_result_destroy.argtypes = [result]
    lib.coquic_result_destroy.restype = None
    lib.coquic_result_effect_count.argtypes = [result]
    lib.coquic_result_effect_count.restype = C.c_size_t
    lib.coquic_result_effect_at.argtypes = [
        result,
        C.c_size_t,
        C.POINTER(coquic_effect_t),
    ]
    lib.coquic_result_effect_at.restype = C.c_uint8
    lib.coquic_result_next_wakeup.argtypes = [result]
    lib.coquic_result_next_wakeup.restype = coquic_optional_time_us_t
    lib.coquic_result_has_local_error.argtypes = [result]
    lib.coquic_result_has_local_error.restype = C.c_uint8
    lib.coquic_result_local_error.argtypes = [result, C.POINTER(coquic_local_error_t)]
    lib.coquic_result_local_error.restype = C.c_uint8
    lib.coquic_result_send_continuation_pending.argtypes = [result]
    lib.coquic_result_send_continuation_pending.restype = C.c_uint8

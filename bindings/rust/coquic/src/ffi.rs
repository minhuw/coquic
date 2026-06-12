#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]

use std::ffi::c_char;

pub const COQUIC_FFI_ABI_VERSION: u32 = 4;

pub enum coquic_endpoint_t {}
pub enum coquic_result_t {}
pub enum coquic_http3_client_t {}
pub enum coquic_http3_server_t {}
pub enum coquic_http3_client_update_t {}
pub enum coquic_http3_server_update_t {}

pub type coquic_connection_handle_t = u64;
pub type coquic_route_handle_t = u64;
pub type coquic_stream_id_t = u64;
pub type coquic_time_us_t = u64;

pub type coquic_status_t = u8;
pub const COQUIC_STATUS_OK: coquic_status_t = 0;
pub const COQUIC_STATUS_INVALID_ARGUMENT: coquic_status_t = 1;
pub const COQUIC_STATUS_OUT_OF_MEMORY: coquic_status_t = 2;
pub const COQUIC_STATUS_INTERNAL_ERROR: coquic_status_t = 3;

pub type coquic_role_t = u8;
pub const COQUIC_ROLE_CLIENT: coquic_role_t = 0;
pub const COQUIC_ROLE_SERVER: coquic_role_t = 1;

pub type coquic_congestion_control_t = u8;
pub const COQUIC_CONGESTION_CONTROL_NEWRENO: coquic_congestion_control_t = 0;
pub const COQUIC_CONGESTION_CONTROL_CUBIC: coquic_congestion_control_t = 1;
pub const COQUIC_CONGESTION_CONTROL_BBR: coquic_congestion_control_t = 2;
pub const COQUIC_CONGESTION_CONTROL_COPA: coquic_congestion_control_t = 3;

pub type coquic_ecn_codepoint_t = u8;
pub const COQUIC_ECN_UNAVAILABLE: coquic_ecn_codepoint_t = 0;
pub const COQUIC_ECN_NOT_ECT: coquic_ecn_codepoint_t = 1;
pub const COQUIC_ECN_ECT0: coquic_ecn_codepoint_t = 2;
pub const COQUIC_ECN_ECT1: coquic_ecn_codepoint_t = 3;
pub const COQUIC_ECN_CE: coquic_ecn_codepoint_t = 4;

pub type coquic_state_change_t = u8;
pub const COQUIC_STATE_CHANGE_HANDSHAKE_READY: coquic_state_change_t = 0;
pub const COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED: coquic_state_change_t = 1;
pub const COQUIC_STATE_CHANGE_FAILED: coquic_state_change_t = 2;

pub type coquic_local_error_code_t = u8;
pub const COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION: coquic_local_error_code_t = 0;
pub const COQUIC_LOCAL_ERROR_INVALID_STREAM_ID: coquic_local_error_code_t = 1;
pub const COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION: coquic_local_error_code_t = 2;
pub const COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED: coquic_local_error_code_t = 3;
pub const COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED: coquic_local_error_code_t = 4;
pub const COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT: coquic_local_error_code_t = 5;
pub const COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED: coquic_local_error_code_t = 6;
pub const COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE: coquic_local_error_code_t = 7;

pub type coquic_lifecycle_t = u8;
pub const COQUIC_LIFECYCLE_CREATED: coquic_lifecycle_t = 0;
pub const COQUIC_LIFECYCLE_ACCEPTED: coquic_lifecycle_t = 1;
pub const COQUIC_LIFECYCLE_CLOSED: coquic_lifecycle_t = 2;

pub type coquic_migration_reason_t = u8;
pub const COQUIC_MIGRATION_REASON_ACTIVE: coquic_migration_reason_t = 0;
pub const COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS: coquic_migration_reason_t = 1;

pub type coquic_zero_rtt_status_t = u8;
pub const COQUIC_ZERO_RTT_UNAVAILABLE: coquic_zero_rtt_status_t = 0;
pub const COQUIC_ZERO_RTT_NOT_ATTEMPTED: coquic_zero_rtt_status_t = 1;
pub const COQUIC_ZERO_RTT_ATTEMPTED: coquic_zero_rtt_status_t = 2;
pub const COQUIC_ZERO_RTT_ACCEPTED: coquic_zero_rtt_status_t = 3;
pub const COQUIC_ZERO_RTT_REJECTED: coquic_zero_rtt_status_t = 4;

pub type coquic_packet_inspection_direction_t = u8;
pub const COQUIC_PACKET_INSPECTION_OUTBOUND: coquic_packet_inspection_direction_t = 0;
pub const COQUIC_PACKET_INSPECTION_INBOUND: coquic_packet_inspection_direction_t = 1;

pub type coquic_packet_inspection_packet_type_t = u8;
pub const COQUIC_PACKET_INSPECTION_INITIAL: coquic_packet_inspection_packet_type_t = 0;
pub const COQUIC_PACKET_INSPECTION_ZERO_RTT: coquic_packet_inspection_packet_type_t = 1;
pub const COQUIC_PACKET_INSPECTION_HANDSHAKE: coquic_packet_inspection_packet_type_t = 2;
pub const COQUIC_PACKET_INSPECTION_ONE_RTT: coquic_packet_inspection_packet_type_t = 3;

pub type coquic_connection_input_kind_t = u8;
pub const COQUIC_CONNECTION_INPUT_SEND_STREAM: coquic_connection_input_kind_t = 0;
pub const COQUIC_CONNECTION_INPUT_SEND_DATAGRAM: coquic_connection_input_kind_t = 1;
pub const COQUIC_CONNECTION_INPUT_RESET_STREAM: coquic_connection_input_kind_t = 2;
pub const COQUIC_CONNECTION_INPUT_STOP_SENDING: coquic_connection_input_kind_t = 3;
pub const COQUIC_CONNECTION_INPUT_CLOSE: coquic_connection_input_kind_t = 4;
pub const COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE: coquic_connection_input_kind_t = 5;
pub const COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION: coquic_connection_input_kind_t = 6;

pub type coquic_effect_kind_t = u8;
pub const COQUIC_EFFECT_SEND_DATAGRAM: coquic_effect_kind_t = 0;
pub const COQUIC_EFFECT_RECEIVE_STREAM_DATA: coquic_effect_kind_t = 1;
pub const COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA: coquic_effect_kind_t = 2;
pub const COQUIC_EFFECT_PEER_RESET_STREAM: coquic_effect_kind_t = 3;
pub const COQUIC_EFFECT_PEER_STOP_SENDING: coquic_effect_kind_t = 4;
pub const COQUIC_EFFECT_STATE_EVENT: coquic_effect_kind_t = 5;
pub const COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT: coquic_effect_kind_t = 6;
pub const COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE: coquic_effect_kind_t = 7;
pub const COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE: coquic_effect_kind_t = 8;
pub const COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT: coquic_effect_kind_t = 9;
pub const COQUIC_EFFECT_PACKET_INSPECTION: coquic_effect_kind_t = 10;
pub const COQUIC_EFFECT_NEW_TOKEN_AVAILABLE: coquic_effect_kind_t = 11;

pub type coquic_http3_error_code_t = u16;
pub const COQUIC_HTTP3_ERROR_NO_ERROR: coquic_http3_error_code_t = 0x0100;
pub const COQUIC_HTTP3_ERROR_GENERAL_PROTOCOL_ERROR: coquic_http3_error_code_t = 0x0101;
pub const COQUIC_HTTP3_ERROR_INTERNAL_ERROR: coquic_http3_error_code_t = 0x0102;
pub const COQUIC_HTTP3_ERROR_STREAM_CREATION_ERROR: coquic_http3_error_code_t = 0x0103;
pub const COQUIC_HTTP3_ERROR_CLOSED_CRITICAL_STREAM: coquic_http3_error_code_t = 0x0104;
pub const COQUIC_HTTP3_ERROR_FRAME_UNEXPECTED: coquic_http3_error_code_t = 0x0105;
pub const COQUIC_HTTP3_ERROR_FRAME_ERROR: coquic_http3_error_code_t = 0x0106;
pub const COQUIC_HTTP3_ERROR_EXCESSIVE_LOAD: coquic_http3_error_code_t = 0x0107;
pub const COQUIC_HTTP3_ERROR_ID_ERROR: coquic_http3_error_code_t = 0x0108;
pub const COQUIC_HTTP3_ERROR_SETTINGS_ERROR: coquic_http3_error_code_t = 0x0109;
pub const COQUIC_HTTP3_ERROR_MISSING_SETTINGS: coquic_http3_error_code_t = 0x010a;
pub const COQUIC_HTTP3_ERROR_REQUEST_REJECTED: coquic_http3_error_code_t = 0x010b;
pub const COQUIC_HTTP3_ERROR_REQUEST_CANCELLED: coquic_http3_error_code_t = 0x010c;
pub const COQUIC_HTTP3_ERROR_REQUEST_INCOMPLETE: coquic_http3_error_code_t = 0x010d;
pub const COQUIC_HTTP3_ERROR_MESSAGE_ERROR: coquic_http3_error_code_t = 0x010e;
pub const COQUIC_HTTP3_ERROR_VERSION_FALLBACK: coquic_http3_error_code_t = 0x0110;
pub const COQUIC_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED: coquic_http3_error_code_t = 0x0200;
pub const COQUIC_HTTP3_ERROR_QPACK_ENCODER_STREAM_ERROR: coquic_http3_error_code_t = 0x0201;
pub const COQUIC_HTTP3_ERROR_QPACK_DECODER_STREAM_ERROR: coquic_http3_error_code_t = 0x0202;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_bytes_view_t {
    pub data: *const u8,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_bytes_t {
    pub data: *const u8,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_optional_route_handle_t {
    pub has_value: u8,
    pub value: coquic_route_handle_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_optional_connection_handle_t {
    pub has_value: u8,
    pub value: coquic_connection_handle_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_optional_stream_id_t {
    pub has_value: u8,
    pub value: coquic_stream_id_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_optional_time_us_t {
    pub has_value: u8,
    pub value: coquic_time_us_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_optional_u64_t {
    pub has_value: u8,
    pub value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_tls_identity_t {
    pub certificate_pem: *const c_char,
    pub certificate_pem_length: usize,
    pub private_key_pem: *const c_char,
    pub private_key_pem_length: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_zero_rtt_config_t {
    pub attempt: u8,
    pub allow: u8,
    pub application_context: coquic_bytes_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_orphan_zero_rtt_buffer_config_t {
    pub max_packets: usize,
    pub max_bytes: usize,
    pub max_age_us: coquic_time_us_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_transport_config_t {
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub pmtud_enabled: u8,
    pub pmtud_base_datagram_size: usize,
    pub pmtud_max_datagram_size: usize,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: u8,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub ack_eliciting_threshold: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_datagram_frame_size: u64,
    pub congestion_control: coquic_congestion_control_t,
    pub enable_hystart_plus_plus: u8,
    pub send_stream_fairness: u8,
    pub enable_latency_spin_bit: u8,
    pub grease_reserved_versions: u8,
    pub grease_quic_bit: u8,
    pub enable_optimistic_ack_mitigation: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_endpoint_config_t {
    pub size: usize,
    pub role: coquic_role_t,
    pub supported_versions: *const u32,
    pub supported_versions_count: usize,
    pub verify_peer: u8,
    pub retry_enabled: u8,
    pub application_protocol: *const c_char,
    pub application_protocol_length: usize,
    pub identity: *const coquic_tls_identity_t,
    pub transport: coquic_transport_config_t,
    pub max_outbound_datagram_size: usize,
    pub zero_rtt: coquic_zero_rtt_config_t,
    pub emit_shared_receive_stream_data: u8,
    pub enable_packet_inspection: u8,
    pub allow_peer_address_change: u8,
    pub max_server_connections: usize,
    pub enable_out_of_order_receive: u8,
    pub orphan_zero_rtt_buffer: coquic_orphan_zero_rtt_buffer_config_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_resumption_state_t {
    pub serialized: coquic_bytes_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_client_connection_config_t {
    pub size: usize,
    pub source_connection_id: coquic_bytes_t,
    pub initial_destination_connection_id: coquic_bytes_t,
    pub original_destination_connection_id: coquic_bytes_t,
    pub has_original_destination_connection_id: u8,
    pub retry_source_connection_id: coquic_bytes_t,
    pub has_retry_source_connection_id: u8,
    pub retry_token: coquic_bytes_t,
    pub original_version: u32,
    pub initial_version: u32,
    pub reacted_to_version_negotiation: u8,
    pub server_name: *const c_char,
    pub server_name_length: usize,
    pub resumption_state: *const coquic_resumption_state_t,
    pub zero_rtt: coquic_zero_rtt_config_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_open_connection_t {
    pub size: usize,
    pub connection: coquic_client_connection_config_t,
    pub initial_route_handle: coquic_route_handle_t,
    pub address_validation_identity: coquic_bytes_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_inbound_datagram_t {
    pub size: usize,
    pub bytes: coquic_bytes_t,
    pub route_handle: coquic_optional_route_handle_t,
    pub address_validation_identity: coquic_bytes_t,
    pub ecn: coquic_ecn_codepoint_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_path_mtu_update_t {
    pub size: usize,
    pub route_handle: coquic_optional_route_handle_t,
    pub max_udp_payload_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_send_stream_data_t {
    pub size: usize,
    pub stream_id: coquic_stream_id_t,
    pub bytes: coquic_bytes_t,
    pub fin: u8,
    pub priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_send_datagram_data_t {
    pub size: usize,
    pub bytes: coquic_bytes_t,
    pub priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_reset_stream_t {
    pub size: usize,
    pub stream_id: coquic_stream_id_t,
    pub application_error_code: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_stop_sending_t {
    pub size: usize,
    pub stream_id: coquic_stream_id_t,
    pub application_error_code: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_close_connection_t {
    pub size: usize,
    pub application_error_code: u64,
    pub reason_phrase: *const c_char,
    pub reason_phrase_length: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_request_connection_migration_t {
    pub size: usize,
    pub route_handle: coquic_route_handle_t,
    pub reason: coquic_migration_reason_t,
    pub address_validation_identity: coquic_bytes_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union coquic_connection_input_union_t {
    pub send_stream: coquic_send_stream_data_t,
    pub send_datagram: coquic_send_datagram_data_t,
    pub reset_stream: coquic_reset_stream_t,
    pub stop_sending: coquic_stop_sending_t,
    pub close: coquic_close_connection_t,
    pub request_migration: coquic_request_connection_migration_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct coquic_connection_input_t {
    pub kind: coquic_connection_input_kind_t,
    pub as_: coquic_connection_input_union_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_local_error_t {
    pub connection: coquic_optional_connection_handle_t,
    pub code: coquic_local_error_code_t,
    pub stream_id: coquic_optional_stream_id_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_send_datagram_effect_t {
    pub connection: coquic_connection_handle_t,
    pub route_handle: coquic_optional_route_handle_t,
    pub bytes: coquic_bytes_view_t,
    pub ecn: coquic_ecn_codepoint_t,
    pub is_pmtu_probe: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_receive_stream_data_effect_t {
    pub connection: coquic_connection_handle_t,
    pub stream_id: coquic_stream_id_t,
    pub offset: u64,
    pub bytes: coquic_bytes_view_t,
    pub fin: u8,
    pub final_size: coquic_optional_u64_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_receive_datagram_data_effect_t {
    pub connection: coquic_connection_handle_t,
    pub bytes: coquic_bytes_view_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_peer_reset_stream_effect_t {
    pub connection: coquic_connection_handle_t,
    pub stream_id: coquic_stream_id_t,
    pub application_error_code: u64,
    pub final_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_peer_stop_sending_effect_t {
    pub connection: coquic_connection_handle_t,
    pub stream_id: coquic_stream_id_t,
    pub application_error_code: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_state_event_effect_t {
    pub connection: coquic_connection_handle_t,
    pub change: coquic_state_change_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_connection_lifecycle_event_effect_t {
    pub connection: coquic_connection_handle_t,
    pub event: coquic_lifecycle_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_preferred_address_t {
    pub ipv4_address: [u8; 4],
    pub ipv4_port: u16,
    pub ipv6_address: [u8; 16],
    pub ipv6_port: u16,
    pub connection_id: coquic_bytes_view_t,
    pub stateless_reset_token: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_peer_preferred_address_available_effect_t {
    pub connection: coquic_connection_handle_t,
    pub preferred_address: coquic_preferred_address_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_resumption_state_available_effect_t {
    pub connection: coquic_connection_handle_t,
    pub serialized: coquic_bytes_view_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_zero_rtt_status_event_effect_t {
    pub connection: coquic_connection_handle_t,
    pub status: coquic_zero_rtt_status_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_packet_inspection_effect_t {
    pub connection: coquic_connection_handle_t,
    pub direction: coquic_packet_inspection_direction_t,
    pub packet_type: coquic_packet_inspection_packet_type_t,
    pub datagram_id: u64,
    pub datagram_length: usize,
    pub datagram_offset: usize,
    pub packet_length: usize,
    pub version: u32,
    pub destination_connection_id: coquic_bytes_view_t,
    pub source_connection_id: coquic_bytes_view_t,
    pub token: coquic_bytes_view_t,
    pub spin_bit: u8,
    pub key_phase: u8,
    pub packet_number_length: u8,
    pub packet_number: u64,
    pub encrypted_packet: coquic_bytes_view_t,
    pub plaintext_payload: coquic_bytes_view_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_new_token_available_effect_t {
    pub connection: coquic_connection_handle_t,
    pub token: coquic_bytes_view_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union coquic_effect_union_t {
    pub send_datagram: coquic_send_datagram_effect_t,
    pub receive_stream_data: coquic_receive_stream_data_effect_t,
    pub receive_datagram_data: coquic_receive_datagram_data_effect_t,
    pub peer_reset_stream: coquic_peer_reset_stream_effect_t,
    pub peer_stop_sending: coquic_peer_stop_sending_effect_t,
    pub state_event: coquic_state_event_effect_t,
    pub connection_lifecycle_event: coquic_connection_lifecycle_event_effect_t,
    pub peer_preferred_address_available: coquic_peer_preferred_address_available_effect_t,
    pub resumption_state_available: coquic_resumption_state_available_effect_t,
    pub zero_rtt_status_event: coquic_zero_rtt_status_event_effect_t,
    pub packet_inspection: coquic_packet_inspection_effect_t,
    pub new_token_available: coquic_new_token_available_effect_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct coquic_effect_t {
    pub kind: coquic_effect_kind_t,
    pub as_: coquic_effect_union_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_optional_u64_t {
    pub has_value: u8,
    pub value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_settings_t {
    pub size: usize,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
    pub max_field_section_size: coquic_http3_optional_u64_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_client_config_t {
    pub size: usize,
    pub local_settings: coquic_http3_settings_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_server_config_t {
    pub size: usize,
    pub local_settings: coquic_http3_settings_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_field_t {
    pub name: *const c_char,
    pub name_length: usize,
    pub value: *const c_char,
    pub value_length: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_field_view_t {
    pub name: coquic_bytes_view_t,
    pub value: coquic_bytes_view_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_request_head_t {
    pub size: usize,
    pub method: *const c_char,
    pub method_length: usize,
    pub scheme: *const c_char,
    pub scheme_length: usize,
    pub authority: *const c_char,
    pub authority_length: usize,
    pub path: *const c_char,
    pub path_length: usize,
    pub content_length: coquic_http3_optional_u64_t,
    pub headers: *const coquic_http3_field_t,
    pub headers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_response_head_t {
    pub size: usize,
    pub status: u16,
    pub content_length: coquic_http3_optional_u64_t,
    pub headers: *const coquic_http3_field_t,
    pub headers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_request_t {
    pub size: usize,
    pub head: coquic_http3_request_head_t,
    pub body: coquic_bytes_t,
    pub trailers: *const coquic_http3_field_t,
    pub trailers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_request_head_view_t {
    pub method: coquic_bytes_view_t,
    pub scheme: coquic_bytes_view_t,
    pub authority: coquic_bytes_view_t,
    pub path: coquic_bytes_view_t,
    pub content_length: coquic_http3_optional_u64_t,
    pub headers: *const coquic_http3_field_view_t,
    pub headers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_response_head_view_t {
    pub status: u16,
    pub content_length: coquic_http3_optional_u64_t,
    pub headers: *const coquic_http3_field_view_t,
    pub headers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_request_view_t {
    pub head: coquic_http3_request_head_view_t,
    pub body: coquic_bytes_view_t,
    pub trailers: *const coquic_http3_field_view_t,
    pub trailers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_response_view_t {
    pub interim_heads: *const coquic_http3_response_head_view_t,
    pub interim_head_count: usize,
    pub head: coquic_http3_response_head_view_t,
    pub body: coquic_bytes_view_t,
    pub trailers: *const coquic_http3_field_view_t,
    pub trailers_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_client_response_event_t {
    pub stream_id: coquic_stream_id_t,
    pub request: coquic_http3_request_view_t,
    pub response: coquic_http3_response_view_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_client_request_error_event_t {
    pub stream_id: coquic_stream_id_t,
    pub request: coquic_http3_request_view_t,
    pub application_error_code: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_server_request_cancelled_event_t {
    pub stream_id: coquic_stream_id_t,
    pub has_head: u8,
    pub head: coquic_http3_request_head_view_t,
    pub body: coquic_bytes_view_t,
    pub trailers: *const coquic_http3_field_view_t,
    pub trailers_count: usize,
    pub application_error_code: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct coquic_http3_error_t {
    pub code: coquic_http3_error_code_t,
    pub stream_id: coquic_optional_stream_id_t,
    pub detail_buffer: *mut c_char,
    pub detail_buffer_capacity: usize,
    pub detail_length: usize,
    pub detail_truncated: u8,
}

extern "C" {
    pub fn coquic_ffi_abi_version() -> u32;
    pub fn coquic_transport_config_init(config: *mut coquic_transport_config_t);
    pub fn coquic_endpoint_config_init(config: *mut coquic_endpoint_config_t);
    pub fn coquic_client_connection_config_init(config: *mut coquic_client_connection_config_t);

    pub fn coquic_endpoint_create(
        config: *const coquic_endpoint_config_t,
        out_endpoint: *mut *mut coquic_endpoint_t,
    ) -> coquic_status_t;
    pub fn coquic_endpoint_destroy(endpoint: *mut coquic_endpoint_t);
    pub fn coquic_endpoint_open_connection(
        endpoint: *mut coquic_endpoint_t,
        input: *const coquic_open_connection_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_endpoint_input_datagram(
        endpoint: *mut coquic_endpoint_t,
        input: *const coquic_inbound_datagram_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_endpoint_update_path_mtu(
        endpoint: *mut coquic_endpoint_t,
        input: *const coquic_path_mtu_update_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_endpoint_timer_expired(
        endpoint: *mut coquic_endpoint_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_send_stream(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_send_stream_data_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_send_datagram(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_send_datagram_data_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_reset_stream(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_reset_stream_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_stop_sending(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_stop_sending_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_close(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_close_connection_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_request_key_update(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_request_migration(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_request_connection_migration_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_connection_advance(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_connection_input_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;

    pub fn coquic_quic_connect(
        endpoint: *mut coquic_endpoint_t,
        input: *const coquic_open_connection_t,
        now: coquic_time_us_t,
        out_connection: *mut coquic_connection_handle_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_receive_datagram(
        endpoint: *mut coquic_endpoint_t,
        input: *const coquic_inbound_datagram_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_update_path_mtu(
        endpoint: *mut coquic_endpoint_t,
        input: *const coquic_path_mtu_update_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_timer_expired(
        endpoint: *mut coquic_endpoint_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_send_stream(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_send_stream_data_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_send_datagram(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_send_datagram_data_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_reset_stream(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_reset_stream_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_stop_sending(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_stop_sending_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_close(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_close_connection_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_request_key_update(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_connection_advance(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        input: *const coquic_connection_input_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_stream_send(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        stream_id: coquic_stream_id_t,
        bytes: coquic_bytes_t,
        fin: u8,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_stream_finish(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        stream_id: coquic_stream_id_t,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_stream_reset(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        stream_id: coquic_stream_id_t,
        application_error_code: u64,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;
    pub fn coquic_quic_stream_stop_sending(
        endpoint: *mut coquic_endpoint_t,
        connection: coquic_connection_handle_t,
        stream_id: coquic_stream_id_t,
        application_error_code: u64,
        now: coquic_time_us_t,
        out_result: *mut *mut coquic_result_t,
    ) -> coquic_status_t;

    pub fn coquic_endpoint_connection_count(endpoint: *const coquic_endpoint_t) -> usize;
    pub fn coquic_endpoint_has_send_continuation_pending(endpoint: *const coquic_endpoint_t) -> u8;
    pub fn coquic_endpoint_has_pending_stream_send(endpoint: *const coquic_endpoint_t) -> u8;
    pub fn coquic_endpoint_next_wakeup(
        endpoint: *const coquic_endpoint_t,
    ) -> coquic_optional_time_us_t;

    pub fn coquic_result_destroy(result: *mut coquic_result_t);
    pub fn coquic_result_effect_count(result: *const coquic_result_t) -> usize;
    pub fn coquic_result_effect_at(
        result: *const coquic_result_t,
        index: usize,
        out_effect: *mut coquic_effect_t,
    ) -> coquic_status_t;
    pub fn coquic_result_next_wakeup(result: *const coquic_result_t) -> coquic_optional_time_us_t;
    pub fn coquic_result_has_local_error(result: *const coquic_result_t) -> u8;
    pub fn coquic_result_local_error(
        result: *const coquic_result_t,
        out_error: *mut coquic_local_error_t,
    ) -> coquic_status_t;
    pub fn coquic_result_send_continuation_pending(result: *const coquic_result_t) -> u8;

    pub fn coquic_http3_settings_init(settings: *mut coquic_http3_settings_t);
    pub fn coquic_http3_client_config_init(config: *mut coquic_http3_client_config_t);
    pub fn coquic_http3_server_config_init(config: *mut coquic_http3_server_config_t);
    pub fn coquic_http3_client_endpoint_config_init(config: *mut coquic_endpoint_config_t);
    pub fn coquic_http3_server_endpoint_config_init(config: *mut coquic_endpoint_config_t);
    pub fn coquic_http3_client_create(
        config: *const coquic_http3_client_config_t,
        out_client: *mut *mut coquic_http3_client_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_destroy(client: *mut coquic_http3_client_t);
    pub fn coquic_http3_client_submit_request(
        client: *mut coquic_http3_client_t,
        request: *const coquic_http3_request_t,
        out_stream_id: *mut coquic_stream_id_t,
        out_error: *mut coquic_http3_error_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_on_quic_result(
        client: *mut coquic_http3_client_t,
        result: *const coquic_result_t,
        now: coquic_time_us_t,
        out_update: *mut *mut coquic_http3_client_update_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_poll(
        client: *mut coquic_http3_client_t,
        now: coquic_time_us_t,
        out_update: *mut *mut coquic_http3_client_update_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_has_failed(client: *const coquic_http3_client_t) -> u8;
    pub fn coquic_http3_client_update_destroy(update: *mut coquic_http3_client_update_t);
    pub fn coquic_http3_client_update_connection_input_count(
        update: *const coquic_http3_client_update_t,
    ) -> usize;
    pub fn coquic_http3_client_update_connection_input_at(
        update: *const coquic_http3_client_update_t,
        index: usize,
        out_input: *mut coquic_connection_input_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_update_response_count(
        update: *const coquic_http3_client_update_t,
    ) -> usize;
    pub fn coquic_http3_client_update_response_at(
        update: *const coquic_http3_client_update_t,
        index: usize,
        out_event: *mut coquic_http3_client_response_event_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_update_request_error_count(
        update: *const coquic_http3_client_update_t,
    ) -> usize;
    pub fn coquic_http3_client_update_request_error_at(
        update: *const coquic_http3_client_update_t,
        index: usize,
        out_event: *mut coquic_http3_client_request_error_event_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_client_update_has_pending_work(
        update: *const coquic_http3_client_update_t,
    ) -> u8;
    pub fn coquic_http3_client_update_terminal_failure(
        update: *const coquic_http3_client_update_t,
    ) -> u8;
    pub fn coquic_http3_client_update_handled_local_error(
        update: *const coquic_http3_client_update_t,
    ) -> u8;

    pub fn coquic_http3_server_create(
        config: *const coquic_http3_server_config_t,
        out_server: *mut *mut coquic_http3_server_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_server_destroy(server: *mut coquic_http3_server_t);
    pub fn coquic_http3_server_on_quic_result(
        server: *mut coquic_http3_server_t,
        result: *const coquic_result_t,
        now: coquic_time_us_t,
        out_update: *mut *mut coquic_http3_server_update_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_server_poll(
        server: *mut coquic_http3_server_t,
        now: coquic_time_us_t,
        out_update: *mut *mut coquic_http3_server_update_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_server_has_failed(server: *const coquic_http3_server_t) -> u8;
    pub fn coquic_http3_server_update_destroy(update: *mut coquic_http3_server_update_t);
    pub fn coquic_http3_server_update_connection_input_count(
        update: *const coquic_http3_server_update_t,
    ) -> usize;
    pub fn coquic_http3_server_update_connection_input_at(
        update: *const coquic_http3_server_update_t,
        index: usize,
        out_input: *mut coquic_connection_input_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_server_update_request_cancelled_count(
        update: *const coquic_http3_server_update_t,
    ) -> usize;
    pub fn coquic_http3_server_update_request_cancelled_at(
        update: *const coquic_http3_server_update_t,
        index: usize,
        out_event: *mut coquic_http3_server_request_cancelled_event_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_server_update_has_pending_work(
        update: *const coquic_http3_server_update_t,
    ) -> u8;
    pub fn coquic_http3_server_update_terminal_failure(
        update: *const coquic_http3_server_update_t,
    ) -> u8;
    pub fn coquic_http3_server_update_handled_local_error(
        update: *const coquic_http3_server_update_t,
    ) -> u8;

    pub fn coquic_http3_request_view_header_at(
        request: *const coquic_http3_request_view_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_request_view_trailer_at(
        request: *const coquic_http3_request_view_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_request_head_view_header_at(
        head: *const coquic_http3_request_head_view_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_response_view_interim_head_at(
        response: *const coquic_http3_response_view_t,
        index: usize,
        out_head: *mut coquic_http3_response_head_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_response_view_header_at(
        response: *const coquic_http3_response_view_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_response_view_trailer_at(
        response: *const coquic_http3_response_view_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_response_head_view_header_at(
        head: *const coquic_http3_response_head_view_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
    pub fn coquic_http3_server_request_cancelled_view_trailer_at(
        event: *const coquic_http3_server_request_cancelled_event_t,
        index: usize,
        out_field: *mut coquic_http3_field_view_t,
    ) -> coquic_status_t;
}

impl coquic_bytes_t {
    pub const fn empty() -> Self {
        Self {
            data: std::ptr::null(),
            length: 0,
        }
    }
}

impl coquic_bytes_view_t {
    pub const fn empty() -> Self {
        Self {
            data: std::ptr::null(),
            length: 0,
        }
    }
}

impl coquic_optional_route_handle_t {
    pub const fn none() -> Self {
        Self {
            has_value: 0,
            value: 0,
        }
    }
}

impl coquic_optional_stream_id_t {
    pub const fn none() -> Self {
        Self {
            has_value: 0,
            value: 0,
        }
    }
}

impl coquic_http3_optional_u64_t {
    pub const fn none() -> Self {
        Self {
            has_value: 0,
            value: 0,
        }
    }
}

impl Default for coquic_http3_error_t {
    fn default() -> Self {
        Self {
            code: COQUIC_HTTP3_ERROR_NO_ERROR,
            stream_id: coquic_optional_stream_id_t::none(),
            detail_buffer: std::ptr::null_mut(),
            detail_buffer_capacity: 0,
            detail_length: 0,
            detail_truncated: 0,
        }
    }
}

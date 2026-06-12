//! Safe Rust wrappers over the CoQUIC C FFI.
//!
//! CoQUIC remains sans-I/O. This crate owns C handles and result/update
//! lifetimes, but callers still drive sockets, timers, routing, and scheduling.

mod ffi;

pub mod http3;

use std::error::Error;
use std::ffi::c_char;
use std::fmt;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

pub use ffi::COQUIC_FFI_ABI_VERSION as FFI_ABI_VERSION;

pub type ConnectionHandle = u64;
pub type RouteHandle = u64;
pub type StreamId = u64;
pub type TimeUs = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok,
    InvalidArgument,
    OutOfMemory,
    InternalError,
    Unknown(u8),
}

impl Status {
    fn from_raw(raw: ffi::coquic_status_t) -> Self {
        match raw {
            ffi::COQUIC_STATUS_OK => Self::Ok,
            ffi::COQUIC_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            ffi::COQUIC_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            ffi::COQUIC_STATUS_INTERNAL_ERROR => Self::InternalError,
            other => Self::Unknown(other),
        }
    }

    fn into_result(raw: ffi::coquic_status_t) -> Result<(), Self> {
        match Self::from_raw(raw) {
            Self::Ok => Ok(()),
            status => Err(status),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::OutOfMemory => f.write_str("out of memory"),
            Self::InternalError => f.write_str("internal error"),
            Self::Unknown(value) => write!(f, "unknown status {value}"),
        }
    }
}

impl Error for Status {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    fn into_raw(self) -> ffi::coquic_role_t {
        match self {
            Self::Client => ffi::COQUIC_ROLE_CLIENT,
            Self::Server => ffi::COQUIC_ROLE_SERVER,
        }
    }

    fn from_raw(raw: ffi::coquic_role_t) -> Self {
        match raw {
            ffi::COQUIC_ROLE_SERVER => Self::Server,
            _ => Self::Client,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionControl {
    NewReno,
    Cubic,
    Bbr,
    Copa,
}

impl CongestionControl {
    fn into_raw(self) -> ffi::coquic_congestion_control_t {
        match self {
            Self::NewReno => ffi::COQUIC_CONGESTION_CONTROL_NEWRENO,
            Self::Cubic => ffi::COQUIC_CONGESTION_CONTROL_CUBIC,
            Self::Bbr => ffi::COQUIC_CONGESTION_CONTROL_BBR,
            Self::Copa => ffi::COQUIC_CONGESTION_CONTROL_COPA,
        }
    }

    fn from_raw(raw: ffi::coquic_congestion_control_t) -> Self {
        match raw {
            ffi::COQUIC_CONGESTION_CONTROL_CUBIC => Self::Cubic,
            ffi::COQUIC_CONGESTION_CONTROL_BBR => Self::Bbr,
            ffi::COQUIC_CONGESTION_CONTROL_COPA => Self::Copa,
            _ => Self::NewReno,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcnCodepoint {
    Unavailable,
    NotEct,
    Ect0,
    Ect1,
    Ce,
}

impl EcnCodepoint {
    fn into_raw(self) -> ffi::coquic_ecn_codepoint_t {
        match self {
            Self::Unavailable => ffi::COQUIC_ECN_UNAVAILABLE,
            Self::NotEct => ffi::COQUIC_ECN_NOT_ECT,
            Self::Ect0 => ffi::COQUIC_ECN_ECT0,
            Self::Ect1 => ffi::COQUIC_ECN_ECT1,
            Self::Ce => ffi::COQUIC_ECN_CE,
        }
    }

    fn from_raw(raw: ffi::coquic_ecn_codepoint_t) -> Self {
        match raw {
            ffi::COQUIC_ECN_NOT_ECT => Self::NotEct,
            ffi::COQUIC_ECN_ECT0 => Self::Ect0,
            ffi::COQUIC_ECN_ECT1 => Self::Ect1,
            ffi::COQUIC_ECN_CE => Self::Ce,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateChange {
    HandshakeReady,
    HandshakeConfirmed,
    Failed,
    Unknown(u8),
}

impl StateChange {
    fn from_raw(raw: ffi::coquic_state_change_t) -> Self {
        match raw {
            ffi::COQUIC_STATE_CHANGE_HANDSHAKE_READY => Self::HandshakeReady,
            ffi::COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED => Self::HandshakeConfirmed,
            ffi::COQUIC_STATE_CHANGE_FAILED => Self::Failed,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErrorCode {
    UnsupportedOperation,
    InvalidStreamId,
    InvalidStreamDirection,
    SendSideClosed,
    ReceiveSideClosed,
    FinalSizeConflict,
    DatagramNotSupported,
    DatagramTooLarge,
    Unknown(u8),
}

impl LocalErrorCode {
    fn from_raw(raw: ffi::coquic_local_error_code_t) -> Self {
        match raw {
            ffi::COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION => Self::UnsupportedOperation,
            ffi::COQUIC_LOCAL_ERROR_INVALID_STREAM_ID => Self::InvalidStreamId,
            ffi::COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION => Self::InvalidStreamDirection,
            ffi::COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED => Self::SendSideClosed,
            ffi::COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED => Self::ReceiveSideClosed,
            ffi::COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT => Self::FinalSizeConflict,
            ffi::COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED => Self::DatagramNotSupported,
            ffi::COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE => Self::DatagramTooLarge,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    Created,
    Accepted,
    Closed,
    Unknown(u8),
}

impl Lifecycle {
    fn from_raw(raw: ffi::coquic_lifecycle_t) -> Self {
        match raw {
            ffi::COQUIC_LIFECYCLE_CREATED => Self::Created,
            ffi::COQUIC_LIFECYCLE_ACCEPTED => Self::Accepted,
            ffi::COQUIC_LIFECYCLE_CLOSED => Self::Closed,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationReason {
    Active,
    PreferredAddress,
}

impl MigrationReason {
    fn into_raw(self) -> ffi::coquic_migration_reason_t {
        match self {
            Self::Active => ffi::COQUIC_MIGRATION_REASON_ACTIVE,
            Self::PreferredAddress => ffi::COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZeroRttStatus {
    Unavailable,
    NotAttempted,
    Attempted,
    Accepted,
    Rejected,
    Unknown(u8),
}

impl ZeroRttStatus {
    fn from_raw(raw: ffi::coquic_zero_rtt_status_t) -> Self {
        match raw {
            ffi::COQUIC_ZERO_RTT_UNAVAILABLE => Self::Unavailable,
            ffi::COQUIC_ZERO_RTT_NOT_ATTEMPTED => Self::NotAttempted,
            ffi::COQUIC_ZERO_RTT_ATTEMPTED => Self::Attempted,
            ffi::COQUIC_ZERO_RTT_ACCEPTED => Self::Accepted,
            ffi::COQUIC_ZERO_RTT_REJECTED => Self::Rejected,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketInspectionDirection {
    Outbound,
    Inbound,
    Unknown(u8),
}

impl PacketInspectionDirection {
    fn from_raw(raw: ffi::coquic_packet_inspection_direction_t) -> Self {
        match raw {
            ffi::COQUIC_PACKET_INSPECTION_OUTBOUND => Self::Outbound,
            ffi::COQUIC_PACKET_INSPECTION_INBOUND => Self::Inbound,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketInspectionPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
    Unknown(u8),
}

impl PacketInspectionPacketType {
    fn from_raw(raw: ffi::coquic_packet_inspection_packet_type_t) -> Self {
        match raw {
            ffi::COQUIC_PACKET_INSPECTION_INITIAL => Self::Initial,
            ffi::COQUIC_PACKET_INSPECTION_ZERO_RTT => Self::ZeroRtt,
            ffi::COQUIC_PACKET_INSPECTION_HANDSHAKE => Self::Handshake,
            ffi::COQUIC_PACKET_INSPECTION_ONE_RTT => Self::OneRtt,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsIdentity {
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZeroRttConfig {
    pub attempt: bool,
    pub allow: bool,
    pub application_context: Vec<u8>,
}

impl ZeroRttConfig {
    fn to_raw(&self) -> ffi::coquic_zero_rtt_config_t {
        ffi::coquic_zero_rtt_config_t {
            attempt: self.attempt as u8,
            allow: self.allow as u8,
            application_context: bytes(self.application_context.as_slice()),
        }
    }
}

impl Default for ZeroRttConfig {
    fn default() -> Self {
        Self {
            attempt: false,
            allow: false,
            application_context: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrphanZeroRttBufferConfig {
    pub max_packets: usize,
    pub max_bytes: usize,
    pub max_age_us: TimeUs,
}

impl OrphanZeroRttBufferConfig {
    fn from_raw(raw: ffi::coquic_orphan_zero_rtt_buffer_config_t) -> Self {
        Self {
            max_packets: raw.max_packets,
            max_bytes: raw.max_bytes,
            max_age_us: raw.max_age_us,
        }
    }

    fn to_raw(self) -> ffi::coquic_orphan_zero_rtt_buffer_config_t {
        ffi::coquic_orphan_zero_rtt_buffer_config_t {
            max_packets: self.max_packets,
            max_bytes: self.max_bytes,
            max_age_us: self.max_age_us,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub pmtud_enabled: bool,
    pub pmtud_base_datagram_size: usize,
    pub pmtud_max_datagram_size: usize,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,
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
    pub congestion_control: CongestionControl,
    pub enable_hystart_plus_plus: bool,
    pub send_stream_fairness: bool,
    pub enable_latency_spin_bit: bool,
    pub grease_reserved_versions: bool,
    pub grease_quic_bit: bool,
    pub enable_optimistic_ack_mitigation: bool,
}

impl TransportConfig {
    fn from_raw(raw: ffi::coquic_transport_config_t) -> Self {
        Self {
            max_idle_timeout: raw.max_idle_timeout,
            max_udp_payload_size: raw.max_udp_payload_size,
            pmtud_enabled: raw.pmtud_enabled != 0,
            pmtud_base_datagram_size: raw.pmtud_base_datagram_size,
            pmtud_max_datagram_size: raw.pmtud_max_datagram_size,
            active_connection_id_limit: raw.active_connection_id_limit,
            disable_active_migration: raw.disable_active_migration != 0,
            ack_delay_exponent: raw.ack_delay_exponent,
            max_ack_delay: raw.max_ack_delay,
            ack_eliciting_threshold: raw.ack_eliciting_threshold,
            initial_max_data: raw.initial_max_data,
            initial_max_stream_data_bidi_local: raw.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: raw.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: raw.initial_max_stream_data_uni,
            initial_max_streams_bidi: raw.initial_max_streams_bidi,
            initial_max_streams_uni: raw.initial_max_streams_uni,
            max_datagram_frame_size: raw.max_datagram_frame_size,
            congestion_control: CongestionControl::from_raw(raw.congestion_control),
            enable_hystart_plus_plus: raw.enable_hystart_plus_plus != 0,
            send_stream_fairness: raw.send_stream_fairness != 0,
            enable_latency_spin_bit: raw.enable_latency_spin_bit != 0,
            grease_reserved_versions: raw.grease_reserved_versions != 0,
            grease_quic_bit: raw.grease_quic_bit != 0,
            enable_optimistic_ack_mitigation: raw.enable_optimistic_ack_mitigation != 0,
        }
    }

    fn to_raw(&self) -> ffi::coquic_transport_config_t {
        ffi::coquic_transport_config_t {
            max_idle_timeout: self.max_idle_timeout,
            max_udp_payload_size: self.max_udp_payload_size,
            pmtud_enabled: self.pmtud_enabled as u8,
            pmtud_base_datagram_size: self.pmtud_base_datagram_size,
            pmtud_max_datagram_size: self.pmtud_max_datagram_size,
            active_connection_id_limit: self.active_connection_id_limit,
            disable_active_migration: self.disable_active_migration as u8,
            ack_delay_exponent: self.ack_delay_exponent,
            max_ack_delay: self.max_ack_delay,
            ack_eliciting_threshold: self.ack_eliciting_threshold,
            initial_max_data: self.initial_max_data,
            initial_max_stream_data_bidi_local: self.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: self.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: self.initial_max_stream_data_uni,
            initial_max_streams_bidi: self.initial_max_streams_bidi,
            initial_max_streams_uni: self.initial_max_streams_uni,
            max_datagram_frame_size: self.max_datagram_frame_size,
            congestion_control: self.congestion_control.into_raw(),
            enable_hystart_plus_plus: self.enable_hystart_plus_plus as u8,
            send_stream_fairness: self.send_stream_fairness as u8,
            enable_latency_spin_bit: self.enable_latency_spin_bit as u8,
            grease_reserved_versions: self.grease_reserved_versions as u8,
            grease_quic_bit: self.grease_quic_bit as u8,
            enable_optimistic_ack_mitigation: self.enable_optimistic_ack_mitigation as u8,
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        let mut raw = MaybeUninit::<ffi::coquic_transport_config_t>::uninit();
        unsafe {
            ffi::coquic_transport_config_init(raw.as_mut_ptr());
            Self::from_raw(raw.assume_init())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointConfig {
    pub role: Role,
    pub supported_versions: Vec<u32>,
    pub verify_peer: bool,
    pub retry_enabled: bool,
    pub application_protocol: Vec<u8>,
    pub identity: Option<TlsIdentity>,
    pub transport: TransportConfig,
    pub max_outbound_datagram_size: usize,
    pub zero_rtt: ZeroRttConfig,
    pub orphan_zero_rtt_buffer: OrphanZeroRttBufferConfig,
    pub emit_shared_receive_stream_data: bool,
    pub enable_out_of_order_receive: bool,
    pub enable_packet_inspection: bool,
    pub allow_peer_address_change: bool,
}

impl EndpointConfig {
    pub fn http3_client() -> Self {
        let mut config = Self::default();
        config.role = Role::Client;
        config.application_protocol = b"h3".to_vec();
        config
    }

    pub fn http3_server() -> Self {
        let mut config = Self::default();
        config.role = Role::Server;
        config.application_protocol = b"h3".to_vec();
        config
    }

    fn materialize(&self) -> MaterializedEndpointConfig<'_> {
        MaterializedEndpointConfig {
            identity: self
                .identity
                .as_ref()
                .map(|identity| ffi::coquic_tls_identity_t {
                    certificate_pem: identity.certificate_pem.as_ptr().cast::<c_char>(),
                    certificate_pem_length: identity.certificate_pem.len(),
                    private_key_pem: identity.private_key_pem.as_ptr().cast::<c_char>(),
                    private_key_pem_length: identity.private_key_pem.len(),
                }),
            config: ffi::coquic_endpoint_config_t {
                size: std::mem::size_of::<ffi::coquic_endpoint_config_t>(),
                role: self.role.into_raw(),
                supported_versions: self.supported_versions.as_ptr(),
                supported_versions_count: self.supported_versions.len(),
                verify_peer: self.verify_peer as u8,
                retry_enabled: self.retry_enabled as u8,
                application_protocol: self.application_protocol.as_ptr().cast::<c_char>(),
                application_protocol_length: self.application_protocol.len(),
                identity: std::ptr::null(),
                transport: self.transport.to_raw(),
                max_outbound_datagram_size: self.max_outbound_datagram_size,
                zero_rtt: self.zero_rtt.to_raw(),
                orphan_zero_rtt_buffer: self.orphan_zero_rtt_buffer.to_raw(),
                emit_shared_receive_stream_data: self.emit_shared_receive_stream_data as u8,
                enable_out_of_order_receive: self.enable_out_of_order_receive as u8,
                enable_packet_inspection: self.enable_packet_inspection as u8,
                allow_peer_address_change: self.allow_peer_address_change as u8,
                max_server_connections: 0,
            },
            _marker: PhantomData,
        }
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        let mut raw = MaybeUninit::<ffi::coquic_endpoint_config_t>::uninit();
        unsafe {
            ffi::coquic_endpoint_config_init(raw.as_mut_ptr());
            let raw = raw.assume_init();
            Self {
                role: Role::from_raw(raw.role),
                supported_versions: Vec::new(),
                verify_peer: raw.verify_peer != 0,
                retry_enabled: raw.retry_enabled != 0,
                application_protocol: view_to_vec(
                    raw.application_protocol.cast::<u8>(),
                    raw.application_protocol_length,
                ),
                identity: None,
                transport: TransportConfig::from_raw(raw.transport),
                max_outbound_datagram_size: raw.max_outbound_datagram_size,
                zero_rtt: ZeroRttConfig::default(),
                orphan_zero_rtt_buffer: OrphanZeroRttBufferConfig::from_raw(
                    raw.orphan_zero_rtt_buffer,
                ),
                emit_shared_receive_stream_data: raw.emit_shared_receive_stream_data != 0,
                enable_out_of_order_receive: raw.enable_out_of_order_receive != 0,
                enable_packet_inspection: raw.enable_packet_inspection != 0,
                allow_peer_address_change: raw.allow_peer_address_change != 0,
            }
        }
    }
}

struct MaterializedEndpointConfig<'a> {
    identity: Option<ffi::coquic_tls_identity_t>,
    config: ffi::coquic_endpoint_config_t,
    _marker: PhantomData<&'a EndpointConfig>,
}

impl MaterializedEndpointConfig<'_> {
    fn as_raw(&mut self) -> *const ffi::coquic_endpoint_config_t {
        self.config.identity = match &self.identity {
            Some(identity) => identity as *const ffi::coquic_tls_identity_t,
            None => std::ptr::null(),
        };
        &self.config
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumptionState {
    pub serialized: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConnectionConfig {
    pub source_connection_id: Vec<u8>,
    pub initial_destination_connection_id: Vec<u8>,
    pub original_destination_connection_id: Option<Vec<u8>>,
    pub retry_source_connection_id: Option<Vec<u8>>,
    pub retry_token: Vec<u8>,
    pub original_version: u32,
    pub initial_version: u32,
    pub reacted_to_version_negotiation: bool,
    pub server_name: Vec<u8>,
    pub resumption_state: Option<ResumptionState>,
    pub zero_rtt: ZeroRttConfig,
}

impl ClientConnectionConfig {
    fn materialize(&self) -> MaterializedClientConnectionConfig<'_> {
        MaterializedClientConnectionConfig {
            resumption_state: self.resumption_state.as_ref().map(|state| {
                ffi::coquic_resumption_state_t {
                    serialized: bytes(state.serialized.as_slice()),
                }
            }),
            config: ffi::coquic_client_connection_config_t {
                size: std::mem::size_of::<ffi::coquic_client_connection_config_t>(),
                source_connection_id: bytes(self.source_connection_id.as_slice()),
                initial_destination_connection_id: bytes(
                    self.initial_destination_connection_id.as_slice(),
                ),
                original_destination_connection_id: bytes(
                    self.original_destination_connection_id
                        .as_deref()
                        .unwrap_or_default(),
                ),
                has_original_destination_connection_id: self
                    .original_destination_connection_id
                    .is_some() as u8,
                retry_source_connection_id: bytes(
                    self.retry_source_connection_id
                        .as_deref()
                        .unwrap_or_default(),
                ),
                has_retry_source_connection_id: self.retry_source_connection_id.is_some() as u8,
                retry_token: bytes(self.retry_token.as_slice()),
                original_version: self.original_version,
                initial_version: self.initial_version,
                reacted_to_version_negotiation: self.reacted_to_version_negotiation as u8,
                server_name: self.server_name.as_ptr().cast::<c_char>(),
                server_name_length: self.server_name.len(),
                resumption_state: std::ptr::null(),
                zero_rtt: self.zero_rtt.to_raw(),
            },
            _marker: PhantomData,
        }
    }
}

impl Default for ClientConnectionConfig {
    fn default() -> Self {
        let mut raw = MaybeUninit::<ffi::coquic_client_connection_config_t>::uninit();
        unsafe {
            ffi::coquic_client_connection_config_init(raw.as_mut_ptr());
            let raw = raw.assume_init();
            Self {
                source_connection_id: Vec::new(),
                initial_destination_connection_id: Vec::new(),
                original_destination_connection_id: None,
                retry_source_connection_id: None,
                retry_token: Vec::new(),
                original_version: raw.original_version,
                initial_version: raw.initial_version,
                reacted_to_version_negotiation: raw.reacted_to_version_negotiation != 0,
                server_name: view_to_vec(raw.server_name.cast::<u8>(), raw.server_name_length),
                resumption_state: None,
                zero_rtt: ZeroRttConfig::default(),
            }
        }
    }
}

struct MaterializedClientConnectionConfig<'a> {
    resumption_state: Option<ffi::coquic_resumption_state_t>,
    config: ffi::coquic_client_connection_config_t,
    _marker: PhantomData<&'a ClientConnectionConfig>,
}

impl MaterializedClientConnectionConfig<'_> {
    fn as_raw(&mut self) -> ffi::coquic_client_connection_config_t {
        self.config.resumption_state = match &self.resumption_state {
            Some(state) => state as *const ffi::coquic_resumption_state_t,
            None => std::ptr::null(),
        };
        self.config
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenConnection {
    pub connection: ClientConnectionConfig,
    pub initial_route_handle: RouteHandle,
    pub address_validation_identity: Vec<u8>,
}

impl OpenConnection {
    fn materialize(&self) -> MaterializedOpenConnection<'_> {
        MaterializedOpenConnection {
            connection: self.connection.materialize(),
            raw: ffi::coquic_open_connection_t {
                size: std::mem::size_of::<ffi::coquic_open_connection_t>(),
                connection: ffi::coquic_client_connection_config_t {
                    size: 0,
                    source_connection_id: ffi::coquic_bytes_t::empty(),
                    initial_destination_connection_id: ffi::coquic_bytes_t::empty(),
                    original_destination_connection_id: ffi::coquic_bytes_t::empty(),
                    has_original_destination_connection_id: 0,
                    retry_source_connection_id: ffi::coquic_bytes_t::empty(),
                    has_retry_source_connection_id: 0,
                    retry_token: ffi::coquic_bytes_t::empty(),
                    original_version: 1,
                    initial_version: 1,
                    reacted_to_version_negotiation: 0,
                    server_name: std::ptr::null(),
                    server_name_length: 0,
                    resumption_state: std::ptr::null(),
                    zero_rtt: ffi::coquic_zero_rtt_config_t {
                        attempt: 0,
                        allow: 0,
                        application_context: ffi::coquic_bytes_t::empty(),
                    },
                },
                initial_route_handle: self.initial_route_handle,
                address_validation_identity: bytes(self.address_validation_identity.as_slice()),
            },
            _marker: PhantomData,
        }
    }
}

impl Default for OpenConnection {
    fn default() -> Self {
        Self {
            connection: ClientConnectionConfig::default(),
            initial_route_handle: 0,
            address_validation_identity: Vec::new(),
        }
    }
}

struct MaterializedOpenConnection<'a> {
    connection: MaterializedClientConnectionConfig<'a>,
    raw: ffi::coquic_open_connection_t,
    _marker: PhantomData<&'a OpenConnection>,
}

impl MaterializedOpenConnection<'_> {
    fn as_raw(&mut self) -> *const ffi::coquic_open_connection_t {
        self.raw.connection = self.connection.as_raw();
        &self.raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundDatagram<'a> {
    pub bytes: &'a [u8],
    pub route_handle: Option<RouteHandle>,
    pub address_validation_identity: &'a [u8],
    pub ecn: EcnCodepoint,
}

impl<'a> InboundDatagram<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            route_handle: None,
            address_validation_identity: &[],
            ecn: EcnCodepoint::Unavailable,
        }
    }

    fn to_raw(&self) -> ffi::coquic_inbound_datagram_t {
        ffi::coquic_inbound_datagram_t {
            size: std::mem::size_of::<ffi::coquic_inbound_datagram_t>(),
            bytes: bytes(self.bytes),
            route_handle: optional_route(self.route_handle),
            address_validation_identity: bytes(self.address_validation_identity),
            ecn: self.ecn.into_raw(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathMtuUpdate {
    pub route_handle: Option<RouteHandle>,
    pub max_udp_payload_size: usize,
}

impl PathMtuUpdate {
    fn to_raw(&self) -> ffi::coquic_path_mtu_update_t {
        ffi::coquic_path_mtu_update_t {
            size: std::mem::size_of::<ffi::coquic_path_mtu_update_t>(),
            route_handle: optional_route(self.route_handle),
            max_udp_payload_size: self.max_udp_payload_size,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendStreamData<'a> {
    pub stream_id: StreamId,
    pub bytes: &'a [u8],
    pub fin: bool,
    pub priority: i32,
}

impl<'a> SendStreamData<'a> {
    fn to_raw(&self) -> ffi::coquic_send_stream_data_t {
        ffi::coquic_send_stream_data_t {
            size: std::mem::size_of::<ffi::coquic_send_stream_data_t>(),
            stream_id: self.stream_id,
            bytes: bytes(self.bytes),
            fin: self.fin as u8,
            priority: self.priority,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendDatagramData<'a> {
    pub bytes: &'a [u8],
    pub priority: i32,
}

impl<'a> SendDatagramData<'a> {
    fn to_raw(&self) -> ffi::coquic_send_datagram_data_t {
        ffi::coquic_send_datagram_data_t {
            size: std::mem::size_of::<ffi::coquic_send_datagram_data_t>(),
            bytes: bytes(self.bytes),
            priority: self.priority,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResetStream {
    pub stream_id: StreamId,
    pub application_error_code: u64,
}

impl ResetStream {
    fn to_raw(&self) -> ffi::coquic_reset_stream_t {
        ffi::coquic_reset_stream_t {
            size: std::mem::size_of::<ffi::coquic_reset_stream_t>(),
            stream_id: self.stream_id,
            application_error_code: self.application_error_code,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopSending {
    pub stream_id: StreamId,
    pub application_error_code: u64,
}

impl StopSending {
    fn to_raw(&self) -> ffi::coquic_stop_sending_t {
        ffi::coquic_stop_sending_t {
            size: std::mem::size_of::<ffi::coquic_stop_sending_t>(),
            stream_id: self.stream_id,
            application_error_code: self.application_error_code,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseConnection<'a> {
    pub application_error_code: u64,
    pub reason_phrase: &'a [u8],
}

impl<'a> CloseConnection<'a> {
    fn to_raw(&self) -> ffi::coquic_close_connection_t {
        ffi::coquic_close_connection_t {
            size: std::mem::size_of::<ffi::coquic_close_connection_t>(),
            application_error_code: self.application_error_code,
            reason_phrase: self.reason_phrase.as_ptr().cast::<c_char>(),
            reason_phrase_length: self.reason_phrase.len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestConnectionMigration<'a> {
    pub route_handle: RouteHandle,
    pub reason: MigrationReason,
    pub address_validation_identity: &'a [u8],
}

impl<'a> RequestConnectionMigration<'a> {
    fn to_raw(&self) -> ffi::coquic_request_connection_migration_t {
        ffi::coquic_request_connection_migration_t {
            size: std::mem::size_of::<ffi::coquic_request_connection_migration_t>(),
            route_handle: self.route_handle,
            reason: self.reason.into_raw(),
            address_validation_identity: bytes(self.address_validation_identity),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionInput<'a> {
    SendStream(SendStreamData<'a>),
    SendDatagram(SendDatagramData<'a>),
    ResetStream(ResetStream),
    StopSending(StopSending),
    Close(CloseConnection<'a>),
    RequestKeyUpdate,
    RequestMigration(RequestConnectionMigration<'a>),
}

impl<'a> ConnectionInput<'a> {
    pub(crate) fn to_raw(&self) -> ffi::coquic_connection_input_t {
        match self {
            Self::SendStream(value) => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_SEND_STREAM,
                as_: ffi::coquic_connection_input_union_t {
                    send_stream: value.to_raw(),
                },
            },
            Self::SendDatagram(value) => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_SEND_DATAGRAM,
                as_: ffi::coquic_connection_input_union_t {
                    send_datagram: value.to_raw(),
                },
            },
            Self::ResetStream(value) => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_RESET_STREAM,
                as_: ffi::coquic_connection_input_union_t {
                    reset_stream: value.to_raw(),
                },
            },
            Self::StopSending(value) => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_STOP_SENDING,
                as_: ffi::coquic_connection_input_union_t {
                    stop_sending: value.to_raw(),
                },
            },
            Self::Close(value) => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_CLOSE,
                as_: ffi::coquic_connection_input_union_t {
                    close: value.to_raw(),
                },
            },
            Self::RequestKeyUpdate => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE,
                as_: ffi::coquic_connection_input_union_t {
                    send_datagram: ffi::coquic_send_datagram_data_t {
                        size: 0,
                        bytes: ffi::coquic_bytes_t::empty(),
                        priority: 0,
                    },
                },
            },
            Self::RequestMigration(value) => ffi::coquic_connection_input_t {
                kind: ffi::COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION,
                as_: ffi::coquic_connection_input_union_t {
                    request_migration: value.to_raw(),
                },
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalError {
    pub connection: Option<ConnectionHandle>,
    pub code: LocalErrorCode,
    pub stream_id: Option<StreamId>,
}

impl LocalError {
    fn from_raw(raw: ffi::coquic_local_error_t) -> Self {
        Self {
            connection: optional_connection_from_raw(raw.connection),
            code: LocalErrorCode::from_raw(raw.code),
            stream_id: optional_stream_from_raw(raw.stream_id),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreferredAddress<'a> {
    pub ipv4_address: [u8; 4],
    pub ipv4_port: u16,
    pub ipv6_address: [u8; 16],
    pub ipv6_port: u16,
    pub connection_id: &'a [u8],
    pub stateless_reset_token: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketInspection<'a> {
    pub connection: ConnectionHandle,
    pub direction: PacketInspectionDirection,
    pub packet_type: PacketInspectionPacketType,
    pub datagram_id: u64,
    pub datagram_length: usize,
    pub datagram_offset: usize,
    pub packet_length: usize,
    pub version: u32,
    pub destination_connection_id: &'a [u8],
    pub source_connection_id: &'a [u8],
    pub token: &'a [u8],
    pub spin_bit: bool,
    pub key_phase: bool,
    pub packet_number_length: u8,
    pub packet_number: u64,
    pub encrypted_packet: &'a [u8],
    pub plaintext_payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect<'a> {
    SendDatagram {
        connection: ConnectionHandle,
        route_handle: Option<RouteHandle>,
        bytes: &'a [u8],
        ecn: EcnCodepoint,
        is_pmtu_probe: bool,
    },
    ReceiveStreamData {
        connection: ConnectionHandle,
        stream_id: StreamId,
        offset: u64,
        bytes: &'a [u8],
        fin: bool,
        final_size: Option<u64>,
    },
    ReceiveDatagramData {
        connection: ConnectionHandle,
        bytes: &'a [u8],
    },
    PeerResetStream {
        connection: ConnectionHandle,
        stream_id: StreamId,
        application_error_code: u64,
        final_size: u64,
    },
    PeerStopSending {
        connection: ConnectionHandle,
        stream_id: StreamId,
        application_error_code: u64,
    },
    StateEvent {
        connection: ConnectionHandle,
        change: StateChange,
    },
    ConnectionLifecycleEvent {
        connection: ConnectionHandle,
        event: Lifecycle,
    },
    PeerPreferredAddressAvailable {
        connection: ConnectionHandle,
        preferred_address: PreferredAddress<'a>,
    },
    ResumptionStateAvailable {
        connection: ConnectionHandle,
        serialized: &'a [u8],
    },
    ZeroRttStatusEvent {
        connection: ConnectionHandle,
        status: ZeroRttStatus,
    },
    PacketInspection(PacketInspection<'a>),
    NewTokenAvailable {
        connection: ConnectionHandle,
        token: &'a [u8],
    },
    Unknown(u8),
}

impl<'a> Effect<'a> {
    unsafe fn from_raw(raw: ffi::coquic_effect_t) -> Self {
        match raw.kind {
            ffi::COQUIC_EFFECT_SEND_DATAGRAM => {
                let value = unsafe { raw.as_.send_datagram };
                Self::SendDatagram {
                    connection: value.connection,
                    route_handle: optional_route_from_raw(value.route_handle),
                    bytes: unsafe { bytes_view(value.bytes) },
                    ecn: EcnCodepoint::from_raw(value.ecn),
                    is_pmtu_probe: value.is_pmtu_probe != 0,
                }
            }
            ffi::COQUIC_EFFECT_RECEIVE_STREAM_DATA => {
                let value = unsafe { raw.as_.receive_stream_data };
                Self::ReceiveStreamData {
                    connection: value.connection,
                    stream_id: value.stream_id,
                    offset: value.offset,
                    bytes: unsafe { bytes_view(value.bytes) },
                    fin: value.fin != 0,
                    final_size: optional_core_u64_from_raw(value.final_size),
                }
            }
            ffi::COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA => {
                let value = unsafe { raw.as_.receive_datagram_data };
                Self::ReceiveDatagramData {
                    connection: value.connection,
                    bytes: unsafe { bytes_view(value.bytes) },
                }
            }
            ffi::COQUIC_EFFECT_PEER_RESET_STREAM => {
                let value = unsafe { raw.as_.peer_reset_stream };
                Self::PeerResetStream {
                    connection: value.connection,
                    stream_id: value.stream_id,
                    application_error_code: value.application_error_code,
                    final_size: value.final_size,
                }
            }
            ffi::COQUIC_EFFECT_PEER_STOP_SENDING => {
                let value = unsafe { raw.as_.peer_stop_sending };
                Self::PeerStopSending {
                    connection: value.connection,
                    stream_id: value.stream_id,
                    application_error_code: value.application_error_code,
                }
            }
            ffi::COQUIC_EFFECT_STATE_EVENT => {
                let value = unsafe { raw.as_.state_event };
                Self::StateEvent {
                    connection: value.connection,
                    change: StateChange::from_raw(value.change),
                }
            }
            ffi::COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT => {
                let value = unsafe { raw.as_.connection_lifecycle_event };
                Self::ConnectionLifecycleEvent {
                    connection: value.connection,
                    event: Lifecycle::from_raw(value.event),
                }
            }
            ffi::COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE => {
                let value = unsafe { raw.as_.peer_preferred_address_available };
                let address = value.preferred_address;
                Self::PeerPreferredAddressAvailable {
                    connection: value.connection,
                    preferred_address: PreferredAddress {
                        ipv4_address: address.ipv4_address,
                        ipv4_port: address.ipv4_port,
                        ipv6_address: address.ipv6_address,
                        ipv6_port: address.ipv6_port,
                        connection_id: unsafe { bytes_view(address.connection_id) },
                        stateless_reset_token: address.stateless_reset_token,
                    },
                }
            }
            ffi::COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE => {
                let value = unsafe { raw.as_.resumption_state_available };
                Self::ResumptionStateAvailable {
                    connection: value.connection,
                    serialized: unsafe { bytes_view(value.serialized) },
                }
            }
            ffi::COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT => {
                let value = unsafe { raw.as_.zero_rtt_status_event };
                Self::ZeroRttStatusEvent {
                    connection: value.connection,
                    status: ZeroRttStatus::from_raw(value.status),
                }
            }
            ffi::COQUIC_EFFECT_PACKET_INSPECTION => {
                let value = unsafe { raw.as_.packet_inspection };
                Self::PacketInspection(PacketInspection {
                    connection: value.connection,
                    direction: PacketInspectionDirection::from_raw(value.direction),
                    packet_type: PacketInspectionPacketType::from_raw(value.packet_type),
                    datagram_id: value.datagram_id,
                    datagram_length: value.datagram_length,
                    datagram_offset: value.datagram_offset,
                    packet_length: value.packet_length,
                    version: value.version,
                    destination_connection_id: unsafe {
                        bytes_view(value.destination_connection_id)
                    },
                    source_connection_id: unsafe { bytes_view(value.source_connection_id) },
                    token: unsafe { bytes_view(value.token) },
                    spin_bit: value.spin_bit != 0,
                    key_phase: value.key_phase != 0,
                    packet_number_length: value.packet_number_length,
                    packet_number: value.packet_number,
                    encrypted_packet: unsafe { bytes_view(value.encrypted_packet) },
                    plaintext_payload: unsafe { bytes_view(value.plaintext_payload) },
                })
            }
            ffi::COQUIC_EFFECT_NEW_TOKEN_AVAILABLE => {
                let value = unsafe { raw.as_.new_token_available };
                Self::NewTokenAvailable {
                    connection: value.connection,
                    token: unsafe { bytes_view(value.token) },
                }
            }
            other => Self::Unknown(other),
        }
    }
}

pub struct Endpoint {
    ptr: NonNull<ffi::coquic_endpoint_t>,
}

impl Endpoint {
    pub fn new(config: &EndpointConfig) -> Result<Self, Status> {
        let mut config = config.materialize();
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_endpoint_create(config.as_raw(), &mut out))?;
        }
        let ptr = NonNull::new(out).ok_or(Status::InternalError)?;
        Ok(Self { ptr })
    }

    pub fn as_raw(&self) -> *mut ffi::coquic_endpoint_t {
        self.ptr.as_ptr()
    }

    pub fn open_connection(
        &mut self,
        input: &OpenConnection,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let mut raw = input.materialize();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_endpoint_open_connection(endpoint, raw.as_raw(), now, out)
        })
    }

    pub fn input_datagram(
        &mut self,
        input: InboundDatagram<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_endpoint_input_datagram(endpoint, &raw, now, out)
        })
    }

    pub fn update_path_mtu(
        &mut self,
        input: &PathMtuUpdate,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_endpoint_update_path_mtu(endpoint, &raw, now, out)
        })
    }

    pub fn timer_expired(&mut self, now: TimeUs) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_endpoint_timer_expired(endpoint, now, out)
        })
    }

    pub fn connection_send_stream(
        &mut self,
        connection: ConnectionHandle,
        input: SendStreamData<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_send_stream(endpoint, connection, &raw, now, out)
        })
    }

    pub fn connection_send_datagram(
        &mut self,
        connection: ConnectionHandle,
        input: SendDatagramData<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_send_datagram(endpoint, connection, &raw, now, out)
        })
    }

    pub fn connection_reset_stream(
        &mut self,
        connection: ConnectionHandle,
        input: &ResetStream,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_reset_stream(endpoint, connection, &raw, now, out)
        })
    }

    pub fn connection_stop_sending(
        &mut self,
        connection: ConnectionHandle,
        input: &StopSending,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_stop_sending(endpoint, connection, &raw, now, out)
        })
    }

    pub fn connection_close(
        &mut self,
        connection: ConnectionHandle,
        input: CloseConnection<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_close(endpoint, connection, &raw, now, out)
        })
    }

    pub fn connection_request_key_update(
        &mut self,
        connection: ConnectionHandle,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_request_key_update(endpoint, connection, now, out)
        })
    }

    pub fn connection_request_migration(
        &mut self,
        connection: ConnectionHandle,
        input: RequestConnectionMigration<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_request_migration(endpoint, connection, &raw, now, out)
        })
    }

    pub fn connection_advance(
        &mut self,
        connection: ConnectionHandle,
        input: ConnectionInput<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_connection_advance(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_connect(
        &mut self,
        input: &OpenConnection,
        now: TimeUs,
    ) -> Result<(ConnectionHandle, QueryResult), Status> {
        let mut raw = input.materialize();
        let mut out_connection = 0;
        let result = self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connect(endpoint, raw.as_raw(), now, &mut out_connection, out)
        })?;
        Ok((out_connection, result))
    }

    pub fn quic_receive_datagram(
        &mut self,
        input: InboundDatagram<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_receive_datagram(endpoint, &raw, now, out)
        })
    }

    pub fn quic_update_path_mtu(
        &mut self,
        input: &PathMtuUpdate,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_update_path_mtu(endpoint, &raw, now, out)
        })
    }

    pub fn quic_timer_expired(&mut self, now: TimeUs) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_timer_expired(endpoint, now, out)
        })
    }

    pub fn quic_connection_send_stream(
        &mut self,
        connection: ConnectionHandle,
        input: SendStreamData<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_send_stream(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_connection_send_datagram(
        &mut self,
        connection: ConnectionHandle,
        input: SendDatagramData<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_send_datagram(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_connection_reset_stream(
        &mut self,
        connection: ConnectionHandle,
        input: &ResetStream,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_reset_stream(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_connection_stop_sending(
        &mut self,
        connection: ConnectionHandle,
        input: &StopSending,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_stop_sending(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_connection_close(
        &mut self,
        connection: ConnectionHandle,
        input: CloseConnection<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_close(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_connection_request_key_update(
        &mut self,
        connection: ConnectionHandle,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_request_key_update(endpoint, connection, now, out)
        })
    }

    pub fn quic_connection_advance(
        &mut self,
        connection: ConnectionHandle,
        input: ConnectionInput<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let raw = input.to_raw();
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_connection_advance(endpoint, connection, &raw, now, out)
        })
    }

    pub fn quic_stream_send(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        let data = bytes(data);
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_stream_send(endpoint, connection, stream_id, data, fin as u8, now, out)
        })
    }

    pub fn quic_stream_finish(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_stream_finish(endpoint, connection, stream_id, now, out)
        })
    }

    pub fn quic_stream_reset(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        application_error_code: u64,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_stream_reset(
                endpoint,
                connection,
                stream_id,
                application_error_code,
                now,
                out,
            )
        })
    }

    pub fn quic_stream_stop_sending(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        application_error_code: u64,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.call_result(|endpoint, out| unsafe {
            ffi::coquic_quic_stream_stop_sending(
                endpoint,
                connection,
                stream_id,
                application_error_code,
                now,
                out,
            )
        })
    }

    pub fn connection_count(&self) -> usize {
        unsafe { ffi::coquic_endpoint_connection_count(self.ptr.as_ptr()) }
    }

    pub fn has_send_continuation_pending(&self) -> bool {
        unsafe { ffi::coquic_endpoint_has_send_continuation_pending(self.ptr.as_ptr()) != 0 }
    }

    pub fn has_pending_stream_send(&self) -> bool {
        unsafe { ffi::coquic_endpoint_has_pending_stream_send(self.ptr.as_ptr()) != 0 }
    }

    pub fn next_wakeup(&self) -> Option<TimeUs> {
        unsafe { optional_time_from_raw(ffi::coquic_endpoint_next_wakeup(self.ptr.as_ptr())) }
    }

    fn call_result(
        &mut self,
        call: impl FnOnce(
            *mut ffi::coquic_endpoint_t,
            *mut *mut ffi::coquic_result_t,
        ) -> ffi::coquic_status_t,
    ) -> Result<QueryResult, Status> {
        let mut out = std::ptr::null_mut();
        Status::into_result(call(self.ptr.as_ptr(), &mut out))?;
        QueryResult::from_raw(out)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        unsafe {
            ffi::coquic_endpoint_destroy(self.ptr.as_ptr());
        }
    }
}

pub struct QueryResult {
    ptr: NonNull<ffi::coquic_result_t>,
}

impl QueryResult {
    fn from_raw(ptr: *mut ffi::coquic_result_t) -> Result<Self, Status> {
        let ptr = NonNull::new(ptr).ok_or(Status::InternalError)?;
        Ok(Self { ptr })
    }

    pub(crate) fn as_raw(&self) -> *const ffi::coquic_result_t {
        self.ptr.as_ptr()
    }

    pub fn effect_count(&self) -> usize {
        unsafe { ffi::coquic_result_effect_count(self.ptr.as_ptr()) }
    }

    pub fn effect(&self, index: usize) -> Result<Effect<'_>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_effect_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_result_effect_at(
                self.ptr.as_ptr(),
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(Effect::from_raw(out.assume_init()))
        }
    }

    pub fn effects(&self) -> Effects<'_> {
        Effects {
            result: self,
            next: 0,
            count: self.effect_count(),
        }
    }

    pub fn next_wakeup(&self) -> Option<TimeUs> {
        unsafe { optional_time_from_raw(ffi::coquic_result_next_wakeup(self.ptr.as_ptr())) }
    }

    pub fn local_error(&self) -> Result<Option<LocalError>, Status> {
        unsafe {
            if ffi::coquic_result_has_local_error(self.ptr.as_ptr()) == 0 {
                return Ok(None);
            }
            let mut out = MaybeUninit::<ffi::coquic_local_error_t>::uninit();
            Status::into_result(ffi::coquic_result_local_error(
                self.ptr.as_ptr(),
                out.as_mut_ptr(),
            ))?;
            Ok(Some(LocalError::from_raw(out.assume_init())))
        }
    }

    pub fn send_continuation_pending(&self) -> bool {
        unsafe { ffi::coquic_result_send_continuation_pending(self.ptr.as_ptr()) != 0 }
    }
}

impl Drop for QueryResult {
    fn drop(&mut self) {
        unsafe {
            ffi::coquic_result_destroy(self.ptr.as_ptr());
        }
    }
}

pub struct Effects<'a> {
    result: &'a QueryResult,
    next: usize,
    count: usize,
}

impl<'a> Iterator for Effects<'a> {
    type Item = Result<Effect<'a>, Status>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(self.result.effect(index))
    }
}

pub fn runtime_ffi_abi_version() -> u32 {
    unsafe { ffi::coquic_ffi_abi_version() }
}

pub fn check_ffi_abi_version() -> Result<(), AbiVersionMismatch> {
    let runtime = runtime_ffi_abi_version();
    if runtime == FFI_ABI_VERSION {
        Ok(())
    } else {
        Err(AbiVersionMismatch {
            compile_time: FFI_ABI_VERSION,
            runtime,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiVersionMismatch {
    pub compile_time: u32,
    pub runtime: u32,
}

impl fmt::Display for AbiVersionMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoQUIC FFI ABI mismatch: wrapper was built for {}, runtime is {}",
            self.compile_time, self.runtime
        )
    }
}

impl Error for AbiVersionMismatch {}

pub(crate) fn bytes(value: &[u8]) -> ffi::coquic_bytes_t {
    if value.is_empty() {
        ffi::coquic_bytes_t::empty()
    } else {
        ffi::coquic_bytes_t {
            data: value.as_ptr(),
            length: value.len(),
        }
    }
}

pub(crate) fn optional_u64(value: Option<u64>) -> ffi::coquic_http3_optional_u64_t {
    match value {
        Some(value) => ffi::coquic_http3_optional_u64_t {
            has_value: 1,
            value,
        },
        None => ffi::coquic_http3_optional_u64_t::none(),
    }
}

fn optional_core_u64_from_raw(raw: ffi::coquic_optional_u64_t) -> Option<u64> {
    (raw.has_value != 0).then_some(raw.value)
}

pub(crate) fn optional_http3_u64_from_raw(raw: ffi::coquic_http3_optional_u64_t) -> Option<u64> {
    (raw.has_value != 0).then_some(raw.value)
}

pub(crate) fn optional_stream_from_raw(raw: ffi::coquic_optional_stream_id_t) -> Option<StreamId> {
    (raw.has_value != 0).then_some(raw.value)
}

fn optional_route(value: Option<RouteHandle>) -> ffi::coquic_optional_route_handle_t {
    match value {
        Some(value) => ffi::coquic_optional_route_handle_t {
            has_value: 1,
            value,
        },
        None => ffi::coquic_optional_route_handle_t::none(),
    }
}

fn optional_route_from_raw(raw: ffi::coquic_optional_route_handle_t) -> Option<RouteHandle> {
    (raw.has_value != 0).then_some(raw.value)
}

fn optional_connection_from_raw(
    raw: ffi::coquic_optional_connection_handle_t,
) -> Option<ConnectionHandle> {
    (raw.has_value != 0).then_some(raw.value)
}

fn optional_time_from_raw(raw: ffi::coquic_optional_time_us_t) -> Option<TimeUs> {
    (raw.has_value != 0).then_some(raw.value)
}

unsafe fn bytes_view<'a>(view: ffi::coquic_bytes_view_t) -> &'a [u8] {
    if view.data.is_null() || view.length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(view.data, view.length) }
    }
}

unsafe fn view_to_vec(data: *const u8, length: usize) -> Vec<u8> {
    if data.is_null() || length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, length).to_vec() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_matches() {
        check_ffi_abi_version().unwrap();
    }

    #[test]
    fn endpoint_create_destroy_smoke() {
        let mut config = EndpointConfig::default();
        assert!(!config.enable_out_of_order_receive);
        config.enable_out_of_order_receive = true;
        let endpoint = Endpoint::new(&config).unwrap();
        assert_eq!(endpoint.connection_count(), 0);
    }

    #[test]
    fn http3_endpoint_config_helpers() {
        let client = EndpointConfig::http3_client();
        assert_eq!(client.role, Role::Client);
        assert_eq!(client.application_protocol, b"h3");

        let server = EndpointConfig::http3_server();
        assert_eq!(server.role, Role::Server);
        assert_eq!(server.application_protocol, b"h3");
    }
}

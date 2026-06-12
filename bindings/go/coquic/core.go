package coquic

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#cgo !boringssl LDFLAGS: -L${SRCDIR}/../../../zig-out/lib -lcoquic-quictls
#cgo boringssl LDFLAGS: -L${SRCDIR}/../../../zig-out/lib -lcoquic-boringssl

#include <stddef.h>
#include <stdint.h>
#include <coquic/ffi/core.h>

static inline coquic_bytes_t coquic_go_bytes(const uint8_t *data, size_t length) {
    coquic_bytes_t bytes = { data, length };
    return bytes;
}

static inline coquic_status_t coquic_go_endpoint_create(
    coquic_role_t role,
    const uint32_t *supported_versions,
    size_t supported_versions_count,
    uint8_t verify_peer,
    uint8_t retry_enabled,
    const char *application_protocol,
    size_t application_protocol_length,
    uint8_t has_identity,
    const char *certificate_pem,
    size_t certificate_pem_length,
    const char *private_key_pem,
    size_t private_key_pem_length,
    coquic_transport_config_t transport,
    size_t max_outbound_datagram_size,
    uint8_t zero_rtt_attempt,
    uint8_t zero_rtt_allow,
    const uint8_t *zero_rtt_context,
    size_t zero_rtt_context_length,
    size_t orphan_zero_rtt_max_packets,
    size_t orphan_zero_rtt_max_bytes,
    coquic_time_us_t orphan_zero_rtt_max_age_us,
    uint8_t emit_shared_receive_stream_data,
    uint8_t enable_out_of_order_receive,
    uint8_t enable_packet_inspection,
    uint8_t allow_peer_address_change,
    coquic_endpoint_t **out_endpoint
) {
    coquic_endpoint_config_t config;
    coquic_tls_identity_t identity;
    coquic_endpoint_config_init(&config);
    config.role = role;
    config.supported_versions = supported_versions;
    config.supported_versions_count = supported_versions_count;
    config.verify_peer = verify_peer;
    config.retry_enabled = retry_enabled;
    config.application_protocol = application_protocol;
    config.application_protocol_length = application_protocol_length;
    if (has_identity) {
        identity.certificate_pem = certificate_pem;
        identity.certificate_pem_length = certificate_pem_length;
        identity.private_key_pem = private_key_pem;
        identity.private_key_pem_length = private_key_pem_length;
        config.identity = &identity;
    } else {
        config.identity = NULL;
    }
    config.transport = transport;
    config.max_outbound_datagram_size = max_outbound_datagram_size;
    config.zero_rtt.attempt = zero_rtt_attempt;
    config.zero_rtt.allow = zero_rtt_allow;
    config.zero_rtt.application_context = coquic_go_bytes(zero_rtt_context, zero_rtt_context_length);
    config.orphan_zero_rtt_buffer.max_packets = orphan_zero_rtt_max_packets;
    config.orphan_zero_rtt_buffer.max_bytes = orphan_zero_rtt_max_bytes;
    config.orphan_zero_rtt_buffer.max_age_us = orphan_zero_rtt_max_age_us;
    config.emit_shared_receive_stream_data = emit_shared_receive_stream_data;
    config.enable_out_of_order_receive = enable_out_of_order_receive;
    config.enable_packet_inspection = enable_packet_inspection;
    config.allow_peer_address_change = allow_peer_address_change;
    return coquic_endpoint_create(&config, out_endpoint);
}

static inline coquic_status_t coquic_go_quic_connect(
    coquic_endpoint_t *endpoint,
    const uint8_t *source_connection_id,
    size_t source_connection_id_length,
    const uint8_t *initial_destination_connection_id,
    size_t initial_destination_connection_id_length,
    const char *server_name,
    size_t server_name_length,
    coquic_route_handle_t initial_route_handle,
    const uint8_t *address_validation_identity,
    size_t address_validation_identity_length,
    coquic_time_us_t now,
    coquic_connection_handle_t *out_connection,
    coquic_result_t **out_result
) {
    coquic_client_connection_config_t connection;
    coquic_open_connection_t open;
    coquic_client_connection_config_init(&connection);
    connection.source_connection_id = coquic_go_bytes(source_connection_id, source_connection_id_length);
    connection.initial_destination_connection_id =
        coquic_go_bytes(initial_destination_connection_id, initial_destination_connection_id_length);
    connection.server_name = server_name;
    connection.server_name_length = server_name_length;

    open.size = sizeof(coquic_open_connection_t);
    open.connection = connection;
    open.initial_route_handle = initial_route_handle;
    open.address_validation_identity =
        coquic_go_bytes(address_validation_identity, address_validation_identity_length);
    return coquic_quic_connect(endpoint, &open, now, out_connection, out_result);
}

static inline coquic_status_t coquic_go_quic_receive_datagram(
    coquic_endpoint_t *endpoint,
    const uint8_t *bytes,
    size_t bytes_length,
    uint8_t has_route_handle,
    coquic_route_handle_t route_handle,
    const uint8_t *address_validation_identity,
    size_t address_validation_identity_length,
    coquic_ecn_codepoint_t ecn,
    coquic_time_us_t now,
    coquic_result_t **out_result
) {
    coquic_inbound_datagram_t input;
    input.size = sizeof(coquic_inbound_datagram_t);
    input.bytes = coquic_go_bytes(bytes, bytes_length);
    input.route_handle.has_value = has_route_handle;
    input.route_handle.value = route_handle;
    input.address_validation_identity =
        coquic_go_bytes(address_validation_identity, address_validation_identity_length);
    input.ecn = ecn;
    return coquic_quic_receive_datagram(endpoint, &input, now, out_result);
}

static inline coquic_status_t coquic_go_quic_stream_send(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_stream_id_t stream_id,
    const uint8_t *bytes,
    size_t bytes_length,
    uint8_t fin,
    int32_t priority,
    coquic_time_us_t now,
    coquic_result_t **out_result
) {
    coquic_send_stream_data_t input;
    input.size = sizeof(coquic_send_stream_data_t);
    input.stream_id = stream_id;
    input.bytes = coquic_go_bytes(bytes, bytes_length);
    input.fin = fin;
    input.priority = priority;
    return coquic_quic_connection_send_stream(endpoint, connection, &input, now, out_result);
}

static inline coquic_status_t coquic_go_quic_connection_close(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    uint64_t application_error_code,
    const char *reason_phrase,
    size_t reason_phrase_length,
    coquic_time_us_t now,
    coquic_result_t **out_result
) {
    coquic_close_connection_t input;
    input.size = sizeof(coquic_close_connection_t);
    input.application_error_code = application_error_code;
    input.reason_phrase = reason_phrase;
    input.reason_phrase_length = reason_phrase_length;
    return coquic_quic_connection_close(endpoint, connection, &input, now, out_result);
}

static inline coquic_send_datagram_effect_t coquic_go_effect_send_datagram(coquic_effect_t effect) {
    return effect.as.send_datagram;
}

static inline coquic_receive_stream_data_effect_t coquic_go_effect_receive_stream_data(coquic_effect_t effect) {
    return effect.as.receive_stream_data;
}

static inline coquic_receive_datagram_data_effect_t coquic_go_effect_receive_datagram_data(coquic_effect_t effect) {
    return effect.as.receive_datagram_data;
}

static inline coquic_peer_reset_stream_effect_t coquic_go_effect_peer_reset_stream(coquic_effect_t effect) {
    return effect.as.peer_reset_stream;
}

static inline coquic_peer_stop_sending_effect_t coquic_go_effect_peer_stop_sending(coquic_effect_t effect) {
    return effect.as.peer_stop_sending;
}

static inline coquic_state_event_effect_t coquic_go_effect_state_event(coquic_effect_t effect) {
    return effect.as.state_event;
}

static inline coquic_connection_lifecycle_event_effect_t coquic_go_effect_connection_lifecycle_event(coquic_effect_t effect) {
    return effect.as.connection_lifecycle_event;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

const FFIABIVersion = uint32(C.COQUIC_FFI_ABI_VERSION)

type ConnectionHandle uint64
type RouteHandle uint64
type StreamID uint64
type TimeUs uint64

type Status uint8

const (
	StatusOK              Status = C.COQUIC_STATUS_OK
	StatusInvalidArgument Status = C.COQUIC_STATUS_INVALID_ARGUMENT
	StatusOutOfMemory     Status = C.COQUIC_STATUS_OUT_OF_MEMORY
	StatusInternalError   Status = C.COQUIC_STATUS_INTERNAL_ERROR
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusInvalidArgument:
		return "invalid argument"
	case StatusOutOfMemory:
		return "out of memory"
	case StatusInternalError:
		return "internal error"
	default:
		return fmt.Sprintf("unknown status %d", uint8(s))
	}
}

type StatusError struct {
	Status Status
}

func (e StatusError) Error() string {
	return e.Status.String()
}

func statusError(raw C.coquic_status_t) error {
	status := Status(raw)
	if status == StatusOK {
		return nil
	}
	return StatusError{Status: status}
}

type Role uint8

const (
	RoleClient Role = C.COQUIC_ROLE_CLIENT
	RoleServer Role = C.COQUIC_ROLE_SERVER
)

type CongestionControl uint8

const (
	CongestionControlNewReno CongestionControl = C.COQUIC_CONGESTION_CONTROL_NEWRENO
	CongestionControlCubic   CongestionControl = C.COQUIC_CONGESTION_CONTROL_CUBIC
	CongestionControlBBR     CongestionControl = C.COQUIC_CONGESTION_CONTROL_BBR
	CongestionControlCopa    CongestionControl = C.COQUIC_CONGESTION_CONTROL_COPA
)

type EcnCodepoint uint8

const (
	EcnUnavailable EcnCodepoint = C.COQUIC_ECN_UNAVAILABLE
	EcnNotECT      EcnCodepoint = C.COQUIC_ECN_NOT_ECT
	EcnECT0        EcnCodepoint = C.COQUIC_ECN_ECT0
	EcnECT1        EcnCodepoint = C.COQUIC_ECN_ECT1
	EcnCE          EcnCodepoint = C.COQUIC_ECN_CE
)

type StateChange uint8

const (
	StateChangeHandshakeReady     StateChange = C.COQUIC_STATE_CHANGE_HANDSHAKE_READY
	StateChangeHandshakeConfirmed StateChange = C.COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED
	StateChangeFailed             StateChange = C.COQUIC_STATE_CHANGE_FAILED
)

type LocalErrorCode uint8

const (
	LocalErrorUnsupportedOperation   LocalErrorCode = C.COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION
	LocalErrorInvalidStreamID        LocalErrorCode = C.COQUIC_LOCAL_ERROR_INVALID_STREAM_ID
	LocalErrorInvalidStreamDirection LocalErrorCode = C.COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION
	LocalErrorSendSideClosed         LocalErrorCode = C.COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED
	LocalErrorReceiveSideClosed      LocalErrorCode = C.COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED
	LocalErrorFinalSizeConflict      LocalErrorCode = C.COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT
	LocalErrorDatagramNotSupported   LocalErrorCode = C.COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED
	LocalErrorDatagramTooLarge       LocalErrorCode = C.COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE
)

type Lifecycle uint8

const (
	LifecycleCreated  Lifecycle = C.COQUIC_LIFECYCLE_CREATED
	LifecycleAccepted Lifecycle = C.COQUIC_LIFECYCLE_ACCEPTED
	LifecycleClosed   Lifecycle = C.COQUIC_LIFECYCLE_CLOSED
)

type TlsIdentity struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

type ZeroRttConfig struct {
	Attempt            bool
	Allow              bool
	ApplicationContext []byte
}

type TransportConfig struct {
	MaxIdleTimeout                 uint64
	MaxUDPPayloadSize              uint64
	PMTUDEnabled                   bool
	PMTUDBaseDatagramSize          int
	PMTUDMaxDatagramSize           int
	ActiveConnectionIDLimit        uint64
	DisableActiveMigration         bool
	AckDelayExponent               uint64
	MaxAckDelay                    uint64
	AckElicitingThreshold          uint64
	InitialMaxData                 uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi          uint64
	InitialMaxStreamsUni           uint64
	MaxDatagramFrameSize           uint64
	CongestionControl              CongestionControl
	EnableHyStartPlusPlus          bool
	SendStreamFairness             bool
	EnableLatencySpinBit           bool
	GreaseReservedVersions         bool
	GreaseQUICBit                  bool
	EnableOptimisticAckMitigation  bool
}

func DefaultTransportConfig() TransportConfig {
	var raw C.coquic_transport_config_t
	C.coquic_transport_config_init(&raw)
	return transportConfigFromRaw(raw)
}

func transportConfigFromRaw(raw C.coquic_transport_config_t) TransportConfig {
	return TransportConfig{
		MaxIdleTimeout:                 uint64(raw.max_idle_timeout),
		MaxUDPPayloadSize:              uint64(raw.max_udp_payload_size),
		PMTUDEnabled:                   raw.pmtud_enabled != 0,
		PMTUDBaseDatagramSize:          int(raw.pmtud_base_datagram_size),
		PMTUDMaxDatagramSize:           int(raw.pmtud_max_datagram_size),
		ActiveConnectionIDLimit:        uint64(raw.active_connection_id_limit),
		DisableActiveMigration:         raw.disable_active_migration != 0,
		AckDelayExponent:               uint64(raw.ack_delay_exponent),
		MaxAckDelay:                    uint64(raw.max_ack_delay),
		AckElicitingThreshold:          uint64(raw.ack_eliciting_threshold),
		InitialMaxData:                 uint64(raw.initial_max_data),
		InitialMaxStreamDataBidiLocal:  uint64(raw.initial_max_stream_data_bidi_local),
		InitialMaxStreamDataBidiRemote: uint64(raw.initial_max_stream_data_bidi_remote),
		InitialMaxStreamDataUni:        uint64(raw.initial_max_stream_data_uni),
		InitialMaxStreamsBidi:          uint64(raw.initial_max_streams_bidi),
		InitialMaxStreamsUni:           uint64(raw.initial_max_streams_uni),
		MaxDatagramFrameSize:           uint64(raw.max_datagram_frame_size),
		CongestionControl:              CongestionControl(raw.congestion_control),
		EnableHyStartPlusPlus:          raw.enable_hystart_plus_plus != 0,
		SendStreamFairness:             raw.send_stream_fairness != 0,
		EnableLatencySpinBit:           raw.enable_latency_spin_bit != 0,
		GreaseReservedVersions:         raw.grease_reserved_versions != 0,
		GreaseQUICBit:                  raw.grease_quic_bit != 0,
		EnableOptimisticAckMitigation:  raw.enable_optimistic_ack_mitigation != 0,
	}
}

func (c TransportConfig) raw() C.coquic_transport_config_t {
	return C.coquic_transport_config_t{
		max_idle_timeout:                    C.uint64_t(c.MaxIdleTimeout),
		max_udp_payload_size:                C.uint64_t(c.MaxUDPPayloadSize),
		pmtud_enabled:                       cBool(c.PMTUDEnabled),
		pmtud_base_datagram_size:            C.size_t(c.PMTUDBaseDatagramSize),
		pmtud_max_datagram_size:             C.size_t(c.PMTUDMaxDatagramSize),
		active_connection_id_limit:          C.uint64_t(c.ActiveConnectionIDLimit),
		disable_active_migration:            cBool(c.DisableActiveMigration),
		ack_delay_exponent:                  C.uint64_t(c.AckDelayExponent),
		max_ack_delay:                       C.uint64_t(c.MaxAckDelay),
		ack_eliciting_threshold:             C.uint64_t(c.AckElicitingThreshold),
		initial_max_data:                    C.uint64_t(c.InitialMaxData),
		initial_max_stream_data_bidi_local:  C.uint64_t(c.InitialMaxStreamDataBidiLocal),
		initial_max_stream_data_bidi_remote: C.uint64_t(c.InitialMaxStreamDataBidiRemote),
		initial_max_stream_data_uni:         C.uint64_t(c.InitialMaxStreamDataUni),
		initial_max_streams_bidi:            C.uint64_t(c.InitialMaxStreamsBidi),
		initial_max_streams_uni:             C.uint64_t(c.InitialMaxStreamsUni),
		max_datagram_frame_size:             C.uint64_t(c.MaxDatagramFrameSize),
		congestion_control:                  C.coquic_congestion_control_t(c.CongestionControl),
		enable_hystart_plus_plus:            cBool(c.EnableHyStartPlusPlus),
		send_stream_fairness:                cBool(c.SendStreamFairness),
		enable_latency_spin_bit:             cBool(c.EnableLatencySpinBit),
		grease_reserved_versions:            cBool(c.GreaseReservedVersions),
		grease_quic_bit:                     cBool(c.GreaseQUICBit),
		enable_optimistic_ack_mitigation:    cBool(c.EnableOptimisticAckMitigation),
	}
}

type EndpointConfig struct {
	Role                        Role
	SupportedVersions           []uint32
	VerifyPeer                  bool
	RetryEnabled                bool
	ApplicationProtocol         []byte
	Identity                    *TlsIdentity
	Transport                   TransportConfig
	MaxOutboundDatagramSize     int
	ZeroRtt                     ZeroRttConfig
	OrphanZeroRttBuffer         OrphanZeroRttBufferConfig
	EmitSharedReceiveStreamData bool
	EnableOutOfOrderReceive     bool
	EnablePacketInspection      bool
	AllowPeerAddressChange      bool
}

type OrphanZeroRttBufferConfig struct {
	MaxPackets int
	MaxBytes   int
	MaxAgeUs   TimeUs
}

func DefaultEndpointConfig() EndpointConfig {
	var raw C.coquic_endpoint_config_t
	C.coquic_endpoint_config_init(&raw)
	return EndpointConfig{
		Role:                    Role(raw.role),
		VerifyPeer:              raw.verify_peer != 0,
		RetryEnabled:            raw.retry_enabled != 0,
		ApplicationProtocol:     copyChar(raw.application_protocol, raw.application_protocol_length),
		Transport:               transportConfigFromRaw(raw.transport),
		MaxOutboundDatagramSize: int(raw.max_outbound_datagram_size),
		OrphanZeroRttBuffer: OrphanZeroRttBufferConfig{
			MaxPackets: int(raw.orphan_zero_rtt_buffer.max_packets),
			MaxBytes:   int(raw.orphan_zero_rtt_buffer.max_bytes),
			MaxAgeUs:   TimeUs(raw.orphan_zero_rtt_buffer.max_age_us),
		},
		EmitSharedReceiveStreamData: raw.emit_shared_receive_stream_data != 0,
		EnableOutOfOrderReceive:     raw.enable_out_of_order_receive != 0,
		EnablePacketInspection:      raw.enable_packet_inspection != 0,
		AllowPeerAddressChange:      raw.allow_peer_address_change != 0,
	}
}

type ClientConfig struct {
	SourceConnectionID             []byte
	InitialDestinationConnectionID []byte
	ServerName                     []byte
	InitialRouteHandle             RouteHandle
	AddressValidationIdentity      []byte
}

func NewClientConfig(sourceConnectionID, initialDestinationConnectionID []byte) ClientConfig {
	return ClientConfig{
		SourceConnectionID:             append([]byte(nil), sourceConnectionID...),
		InitialDestinationConnectionID: append([]byte(nil), initialDestinationConnectionID...),
		ServerName:                     []byte("localhost"),
	}
}

type InboundDatagram struct {
	Bytes                     []byte
	RouteHandle               RouteHandle
	HasRouteHandle            bool
	AddressValidationIdentity []byte
	Ecn                       EcnCodepoint
}

type SendStreamData struct {
	StreamID StreamID
	Bytes    []byte
	Fin      bool
	Priority int32
}

type Endpoint struct {
	ptr *C.coquic_endpoint_t
}

func CheckFFIABIVersion() error {
	actual := uint32(C.coquic_ffi_abi_version())
	if actual != FFIABIVersion {
		return fmt.Errorf("coquic FFI ABI mismatch: expected %d got %d", FFIABIVersion, actual)
	}
	return nil
}

func NewEndpoint(config EndpointConfig) (*Endpoint, error) {
	if err := CheckFFIABIVersion(); err != nil {
		return nil, err
	}

	var out *C.coquic_endpoint_t
	status := C.coquic_go_endpoint_create(
		C.coquic_role_t(config.Role),
		uint32Ptr(config.SupportedVersions),
		C.size_t(len(config.SupportedVersions)),
		cBool(config.VerifyPeer),
		cBool(config.RetryEnabled),
		charPtr(config.ApplicationProtocol),
		C.size_t(len(config.ApplicationProtocol)),
		cBool(config.Identity != nil),
		identityCertPtr(config.Identity),
		identityCertLen(config.Identity),
		identityKeyPtr(config.Identity),
		identityKeyLen(config.Identity),
		config.Transport.raw(),
		C.size_t(config.MaxOutboundDatagramSize),
		cBool(config.ZeroRtt.Attempt),
		cBool(config.ZeroRtt.Allow),
		bytePtr(config.ZeroRtt.ApplicationContext),
		C.size_t(len(config.ZeroRtt.ApplicationContext)),
		C.size_t(config.OrphanZeroRttBuffer.MaxPackets),
		C.size_t(config.OrphanZeroRttBuffer.MaxBytes),
		C.coquic_time_us_t(config.OrphanZeroRttBuffer.MaxAgeUs),
		cBool(config.EmitSharedReceiveStreamData),
		cBool(config.EnableOutOfOrderReceive),
		cBool(config.EnablePacketInspection),
		cBool(config.AllowPeerAddressChange),
		&out,
	)
	if err := statusError(status); err != nil {
		return nil, err
	}
	endpoint := &Endpoint{ptr: out}
	runtime.SetFinalizer(endpoint, (*Endpoint).Destroy)
	return endpoint, nil
}

func (e *Endpoint) Destroy() {
	if e == nil || e.ptr == nil {
		return
	}
	C.coquic_endpoint_destroy(e.ptr)
	e.ptr = nil
}

func (e *Endpoint) Connect(config ClientConfig, now TimeUs) (ConnectionHandle, *QueryResult, error) {
	if e == nil || e.ptr == nil {
		return 0, nil, StatusError{Status: StatusInvalidArgument}
	}
	var handle C.coquic_connection_handle_t
	var out *C.coquic_result_t
	status := C.coquic_go_quic_connect(
		e.ptr,
		bytePtr(config.SourceConnectionID),
		C.size_t(len(config.SourceConnectionID)),
		bytePtr(config.InitialDestinationConnectionID),
		C.size_t(len(config.InitialDestinationConnectionID)),
		charPtr(config.ServerName),
		C.size_t(len(config.ServerName)),
		C.coquic_route_handle_t(config.InitialRouteHandle),
		bytePtr(config.AddressValidationIdentity),
		C.size_t(len(config.AddressValidationIdentity)),
		C.coquic_time_us_t(now),
		&handle,
		&out,
	)
	if err := statusError(status); err != nil {
		return 0, nil, err
	}
	return ConnectionHandle(handle), newQueryResult(out), nil
}

func (e *Endpoint) ReceiveDatagram(datagram InboundDatagram, now TimeUs) (*QueryResult, error) {
	if e == nil || e.ptr == nil {
		return nil, StatusError{Status: StatusInvalidArgument}
	}
	var out *C.coquic_result_t
	status := C.coquic_go_quic_receive_datagram(
		e.ptr,
		bytePtr(datagram.Bytes),
		C.size_t(len(datagram.Bytes)),
		cBool(datagram.HasRouteHandle),
		C.coquic_route_handle_t(datagram.RouteHandle),
		bytePtr(datagram.AddressValidationIdentity),
		C.size_t(len(datagram.AddressValidationIdentity)),
		C.coquic_ecn_codepoint_t(datagram.Ecn),
		C.coquic_time_us_t(now),
		&out,
	)
	if err := statusError(status); err != nil {
		return nil, err
	}
	return newQueryResult(out), nil
}

func (e *Endpoint) TimerExpired(now TimeUs) (*QueryResult, error) {
	if e == nil || e.ptr == nil {
		return nil, StatusError{Status: StatusInvalidArgument}
	}
	var out *C.coquic_result_t
	status := C.coquic_quic_timer_expired(e.ptr, C.coquic_time_us_t(now), &out)
	if err := statusError(status); err != nil {
		return nil, err
	}
	return newQueryResult(out), nil
}

func (e *Endpoint) SendStream(connection ConnectionHandle, streamID StreamID, data []byte, fin bool, now TimeUs) (*QueryResult, error) {
	return e.SendStreamWithPriority(
		connection,
		SendStreamData{
			StreamID: streamID,
			Bytes:    data,
			Fin:      fin,
		},
		now,
	)
}

func (e *Endpoint) SendStreamWithPriority(connection ConnectionHandle, streamData SendStreamData, now TimeUs) (*QueryResult, error) {
	if e == nil || e.ptr == nil {
		return nil, StatusError{Status: StatusInvalidArgument}
	}
	var out *C.coquic_result_t
	status := C.coquic_go_quic_stream_send(
		e.ptr,
		C.coquic_connection_handle_t(connection),
		C.coquic_stream_id_t(streamData.StreamID),
		bytePtr(streamData.Bytes),
		C.size_t(len(streamData.Bytes)),
		cBool(streamData.Fin),
		C.int32_t(streamData.Priority),
		C.coquic_time_us_t(now),
		&out,
	)
	if err := statusError(status); err != nil {
		return nil, err
	}
	return newQueryResult(out), nil
}

func (e *Endpoint) CloseConnection(connection ConnectionHandle, applicationErrorCode uint64, reason []byte, now TimeUs) (*QueryResult, error) {
	if e == nil || e.ptr == nil {
		return nil, StatusError{Status: StatusInvalidArgument}
	}
	var out *C.coquic_result_t
	status := C.coquic_go_quic_connection_close(
		e.ptr,
		C.coquic_connection_handle_t(connection),
		C.uint64_t(applicationErrorCode),
		charPtr(reason),
		C.size_t(len(reason)),
		C.coquic_time_us_t(now),
		&out,
	)
	if err := statusError(status); err != nil {
		return nil, err
	}
	return newQueryResult(out), nil
}

func (e *Endpoint) NextWakeup() (TimeUs, bool) {
	if e == nil || e.ptr == nil {
		return 0, false
	}
	raw := C.coquic_endpoint_next_wakeup(e.ptr)
	if raw.has_value == 0 {
		return 0, false
	}
	return TimeUs(raw.value), true
}

func (e *Endpoint) ConnectionCount() int {
	if e == nil || e.ptr == nil {
		return 0
	}
	return int(C.coquic_endpoint_connection_count(e.ptr))
}

func (e *Endpoint) HasSendContinuationPending() bool {
	if e == nil || e.ptr == nil {
		return false
	}
	return C.coquic_endpoint_has_send_continuation_pending(e.ptr) != 0
}

func (e *Endpoint) HasPendingStreamSend() bool {
	if e == nil || e.ptr == nil {
		return false
	}
	return C.coquic_endpoint_has_pending_stream_send(e.ptr) != 0
}

type QueryResult struct {
	ptr *C.coquic_result_t
}

func newQueryResult(ptr *C.coquic_result_t) *QueryResult {
	result := &QueryResult{ptr: ptr}
	runtime.SetFinalizer(result, (*QueryResult).Destroy)
	return result
}

func (r *QueryResult) Destroy() {
	if r == nil || r.ptr == nil {
		return
	}
	C.coquic_result_destroy(r.ptr)
	r.ptr = nil
}

type LocalError struct {
	Connection    ConnectionHandle
	HasConnection bool
	Code          LocalErrorCode
	StreamID      StreamID
	HasStreamID   bool
}

func (r *QueryResult) LocalError() (*LocalError, error) {
	if r == nil || r.ptr == nil || C.coquic_result_has_local_error(r.ptr) == 0 {
		return nil, nil
	}
	var raw C.coquic_local_error_t
	if err := statusError(C.coquic_result_local_error(r.ptr, &raw)); err != nil {
		return nil, err
	}
	return &LocalError{
		Connection:    ConnectionHandle(raw.connection.value),
		HasConnection: raw.connection.has_value != 0,
		Code:          LocalErrorCode(raw.code),
		StreamID:      StreamID(raw.stream_id.value),
		HasStreamID:   raw.stream_id.has_value != 0,
	}, nil
}

func (r *QueryResult) NextWakeup() (TimeUs, bool) {
	if r == nil || r.ptr == nil {
		return 0, false
	}
	raw := C.coquic_result_next_wakeup(r.ptr)
	if raw.has_value == 0 {
		return 0, false
	}
	return TimeUs(raw.value), true
}

func (r *QueryResult) SendContinuationPending() bool {
	if r == nil || r.ptr == nil {
		return false
	}
	return C.coquic_result_send_continuation_pending(r.ptr) != 0
}

type EffectKind uint8

const (
	EffectSendDatagram             EffectKind = C.COQUIC_EFFECT_SEND_DATAGRAM
	EffectReceiveStreamData        EffectKind = C.COQUIC_EFFECT_RECEIVE_STREAM_DATA
	EffectReceiveDatagramData      EffectKind = C.COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA
	EffectPeerResetStream          EffectKind = C.COQUIC_EFFECT_PEER_RESET_STREAM
	EffectPeerStopSending          EffectKind = C.COQUIC_EFFECT_PEER_STOP_SENDING
	EffectStateEvent               EffectKind = C.COQUIC_EFFECT_STATE_EVENT
	EffectConnectionLifecycleEvent EffectKind = C.COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT
	EffectPeerPreferredAddress     EffectKind = C.COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE
	EffectResumptionStateAvailable EffectKind = C.COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE
	EffectZeroRttStatusEvent       EffectKind = C.COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT
	EffectPacketInspection         EffectKind = C.COQUIC_EFFECT_PACKET_INSPECTION
	EffectNewTokenAvailable        EffectKind = C.COQUIC_EFFECT_NEW_TOKEN_AVAILABLE
)

type Effect struct {
	Kind                 EffectKind
	Connection           ConnectionHandle
	RouteHandle          RouteHandle
	HasRouteHandle       bool
	StreamID             StreamID
	Offset               uint64
	Bytes                []byte
	Ecn                  EcnCodepoint
	IsPMTUProbe          bool
	Fin                  bool
	StateChange          StateChange
	Lifecycle            Lifecycle
	ApplicationErrorCode uint64
	FinalSize            uint64
	HasFinalSize         bool
}

func (r *QueryResult) Effects() ([]Effect, error) {
	if r == nil || r.ptr == nil {
		return nil, errors.New("coquic query result is closed")
	}
	count := int(C.coquic_result_effect_count(r.ptr))
	effects := make([]Effect, 0, count)
	err := r.ForEachEffect(func(effect Effect) error {
		effects = append(effects, effect)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return effects, nil
}

func (r *QueryResult) ForEachEffect(callback func(Effect) error) error {
	if r == nil || r.ptr == nil {
		return errors.New("coquic query result is closed")
	}
	count := int(C.coquic_result_effect_count(r.ptr))
	for index := 0; index < count; index++ {
		var raw C.coquic_effect_t
		if err := statusError(C.coquic_result_effect_at(r.ptr, C.size_t(index), &raw)); err != nil {
			return err
		}
		if err := callback(effectFromRaw(raw)); err != nil {
			return err
		}
	}
	return nil
}

func effectFromRaw(raw C.coquic_effect_t) Effect {
	effect := Effect{Kind: EffectKind(raw.kind)}
	switch effect.Kind {
	case EffectSendDatagram:
		value := C.coquic_go_effect_send_datagram(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.RouteHandle = RouteHandle(value.route_handle.value)
		effect.HasRouteHandle = value.route_handle.has_value != 0
		effect.Bytes = copyBytes(value.bytes)
		effect.Ecn = EcnCodepoint(value.ecn)
		effect.IsPMTUProbe = value.is_pmtu_probe != 0
	case EffectReceiveStreamData:
		value := C.coquic_go_effect_receive_stream_data(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.StreamID = StreamID(value.stream_id)
		effect.Offset = uint64(value.offset)
		effect.Bytes = copyBytes(value.bytes)
		effect.Fin = value.fin != 0
		effect.FinalSize = uint64(value.final_size.value)
		effect.HasFinalSize = value.final_size.has_value != 0
	case EffectReceiveDatagramData:
		value := C.coquic_go_effect_receive_datagram_data(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.Bytes = copyBytes(value.bytes)
	case EffectPeerResetStream:
		value := C.coquic_go_effect_peer_reset_stream(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.StreamID = StreamID(value.stream_id)
		effect.ApplicationErrorCode = uint64(value.application_error_code)
		effect.FinalSize = uint64(value.final_size)
	case EffectPeerStopSending:
		value := C.coquic_go_effect_peer_stop_sending(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.StreamID = StreamID(value.stream_id)
		effect.ApplicationErrorCode = uint64(value.application_error_code)
	case EffectStateEvent:
		value := C.coquic_go_effect_state_event(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.StateChange = StateChange(value.change)
	case EffectConnectionLifecycleEvent:
		value := C.coquic_go_effect_connection_lifecycle_event(raw)
		effect.Connection = ConnectionHandle(value.connection)
		effect.Lifecycle = Lifecycle(value.event)
	}
	return effect
}

func cBool(value bool) C.uint8_t {
	if value {
		return 1
	}
	return 0
}

func bytePtr(bytes []byte) *C.uint8_t {
	if len(bytes) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&bytes[0]))
}

func charPtr(bytes []byte) *C.char {
	return (*C.char)(unsafe.Pointer(bytePtr(bytes)))
}

func uint32Ptr(values []uint32) *C.uint32_t {
	if len(values) == 0 {
		return nil
	}
	return (*C.uint32_t)(unsafe.Pointer(&values[0]))
}

func identityCertPtr(identity *TlsIdentity) *C.char {
	if identity == nil {
		return nil
	}
	return charPtr(identity.CertificatePEM)
}

func identityCertLen(identity *TlsIdentity) C.size_t {
	if identity == nil {
		return 0
	}
	return C.size_t(len(identity.CertificatePEM))
}

func identityKeyPtr(identity *TlsIdentity) *C.char {
	if identity == nil {
		return nil
	}
	return charPtr(identity.PrivateKeyPEM)
}

func identityKeyLen(identity *TlsIdentity) C.size_t {
	if identity == nil {
		return 0
	}
	return C.size_t(len(identity.PrivateKeyPEM))
}

func copyChar(data *C.char, length C.size_t) []byte {
	if data == nil || length == 0 {
		return nil
	}
	source := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))
	return append([]byte(nil), source...)
}

func copyBytes(bytes C.coquic_bytes_view_t) []byte {
	if bytes.data == nil || bytes.length == 0 {
		return nil
	}
	source := unsafe.Slice((*byte)(unsafe.Pointer(bytes.data)), int(bytes.length))
	return append([]byte(nil), source...)
}

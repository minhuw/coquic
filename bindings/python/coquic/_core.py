from __future__ import annotations

import ctypes as C
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Iterable

from . import _ffi as ffi

ConnectionHandle = int
RouteHandle = int
StreamId = int
TimeUs = int


class Status(IntEnum):
    OK = ffi.COQUIC_STATUS_OK
    INVALID_ARGUMENT = ffi.COQUIC_STATUS_INVALID_ARGUMENT
    OUT_OF_MEMORY = ffi.COQUIC_STATUS_OUT_OF_MEMORY
    INTERNAL_ERROR = ffi.COQUIC_STATUS_INTERNAL_ERROR

    @classmethod
    def from_raw(cls, raw: int) -> "Status":
        try:
            return cls(raw)
        except ValueError:
            raise CoquicError(f"unknown status {raw}") from None

    @classmethod
    def check(cls, raw: int) -> None:
        status = cls.from_raw(raw)
        if status != cls.OK:
            raise CoquicStatusError(status)


class CoquicError(Exception):
    __slots__ = ()


class CoquicStatusError(CoquicError):
    def __init__(self, status: Status):
        """Create an exception for a non-OK CoQUIC status."""
        super().__init__(status.name.lower())
        self.status = status


class Role(IntEnum):
    CLIENT = ffi.COQUIC_ROLE_CLIENT
    SERVER = ffi.COQUIC_ROLE_SERVER


class CongestionControl(IntEnum):
    NEWRENO = ffi.COQUIC_CONGESTION_CONTROL_NEWRENO
    CUBIC = ffi.COQUIC_CONGESTION_CONTROL_CUBIC
    BBR = ffi.COQUIC_CONGESTION_CONTROL_BBR
    COPA = ffi.COQUIC_CONGESTION_CONTROL_COPA
    PCC = ffi.COQUIC_CONGESTION_CONTROL_PCC
    PCC_VIVACE = ffi.COQUIC_CONGESTION_CONTROL_PCC_VIVACE


class EcnCodepoint(IntEnum):
    UNAVAILABLE = ffi.COQUIC_ECN_UNAVAILABLE
    NOT_ECT = ffi.COQUIC_ECN_NOT_ECT
    ECT0 = ffi.COQUIC_ECN_ECT0
    ECT1 = ffi.COQUIC_ECN_ECT1
    CE = ffi.COQUIC_ECN_CE


class StateChange(IntEnum):
    HANDSHAKE_READY = ffi.COQUIC_STATE_CHANGE_HANDSHAKE_READY
    HANDSHAKE_CONFIRMED = ffi.COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED
    FAILED = ffi.COQUIC_STATE_CHANGE_FAILED


class LocalErrorCode(IntEnum):
    UNSUPPORTED_OPERATION = ffi.COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION
    INVALID_STREAM_ID = ffi.COQUIC_LOCAL_ERROR_INVALID_STREAM_ID
    INVALID_STREAM_DIRECTION = ffi.COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION
    SEND_SIDE_CLOSED = ffi.COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED
    RECEIVE_SIDE_CLOSED = ffi.COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED
    FINAL_SIZE_CONFLICT = ffi.COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT
    DATAGRAM_NOT_SUPPORTED = ffi.COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED
    DATAGRAM_TOO_LARGE = ffi.COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE


class Lifecycle(IntEnum):
    CREATED = ffi.COQUIC_LIFECYCLE_CREATED
    ACCEPTED = ffi.COQUIC_LIFECYCLE_ACCEPTED
    CLOSED = ffi.COQUIC_LIFECYCLE_CLOSED


class MigrationReason(IntEnum):
    ACTIVE = ffi.COQUIC_MIGRATION_REASON_ACTIVE
    PREFERRED_ADDRESS = ffi.COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS


class ZeroRttStatus(IntEnum):
    UNAVAILABLE = ffi.COQUIC_ZERO_RTT_UNAVAILABLE
    NOT_ATTEMPTED = ffi.COQUIC_ZERO_RTT_NOT_ATTEMPTED
    ATTEMPTED = ffi.COQUIC_ZERO_RTT_ATTEMPTED
    ACCEPTED = ffi.COQUIC_ZERO_RTT_ACCEPTED
    REJECTED = ffi.COQUIC_ZERO_RTT_REJECTED


class PacketInspectionDirection(IntEnum):
    OUTBOUND = ffi.COQUIC_PACKET_INSPECTION_OUTBOUND
    INBOUND = ffi.COQUIC_PACKET_INSPECTION_INBOUND


class PacketInspectionPacketType(IntEnum):
    INITIAL = ffi.COQUIC_PACKET_INSPECTION_INITIAL
    ZERO_RTT = ffi.COQUIC_PACKET_INSPECTION_ZERO_RTT
    HANDSHAKE = ffi.COQUIC_PACKET_INSPECTION_HANDSHAKE
    ONE_RTT = ffi.COQUIC_PACKET_INSPECTION_ONE_RTT


@dataclass(slots=True)
class TlsIdentity:
    certificate_pem: bytes
    private_key_pem: bytes


@dataclass(slots=True)
class ZeroRttConfig:
    attempt: bool = False
    allow: bool = False
    application_context: bytes = b""


@dataclass(slots=True)
class TransportConfig:
    max_idle_timeout: int
    max_udp_payload_size: int
    pmtud_enabled: bool
    pmtud_base_datagram_size: int
    pmtud_max_datagram_size: int
    active_connection_id_limit: int
    disable_active_migration: bool
    ack_delay_exponent: int
    max_ack_delay: int
    ack_eliciting_threshold: int
    initial_max_data: int
    initial_max_stream_data_bidi_local: int
    initial_max_stream_data_bidi_remote: int
    initial_max_stream_data_uni: int
    initial_max_streams_bidi: int
    initial_max_streams_uni: int
    max_datagram_frame_size: int
    congestion_control: CongestionControl
    enable_hystart_plus_plus: bool
    send_stream_fairness: bool
    enable_latency_spin_bit: bool
    grease_reserved_versions: bool
    grease_quic_bit: bool
    enable_optimistic_ack_mitigation: bool

    @classmethod
    def default(cls) -> "TransportConfig":
        raw = ffi.coquic_transport_config_t()
        ffi.load_library().coquic_transport_config_init(C.byref(raw))
        return cls.from_raw(raw)

    @classmethod
    def from_raw(cls, raw: ffi.coquic_transport_config_t) -> "TransportConfig":
        return cls(
            max_idle_timeout=raw.max_idle_timeout,
            max_udp_payload_size=raw.max_udp_payload_size,
            pmtud_enabled=bool(raw.pmtud_enabled),
            pmtud_base_datagram_size=raw.pmtud_base_datagram_size,
            pmtud_max_datagram_size=raw.pmtud_max_datagram_size,
            active_connection_id_limit=raw.active_connection_id_limit,
            disable_active_migration=bool(raw.disable_active_migration),
            ack_delay_exponent=raw.ack_delay_exponent,
            max_ack_delay=raw.max_ack_delay,
            ack_eliciting_threshold=raw.ack_eliciting_threshold,
            initial_max_data=raw.initial_max_data,
            initial_max_stream_data_bidi_local=raw.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote=raw.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni=raw.initial_max_stream_data_uni,
            initial_max_streams_bidi=raw.initial_max_streams_bidi,
            initial_max_streams_uni=raw.initial_max_streams_uni,
            max_datagram_frame_size=raw.max_datagram_frame_size,
            congestion_control=CongestionControl(raw.congestion_control),
            enable_hystart_plus_plus=bool(raw.enable_hystart_plus_plus),
            send_stream_fairness=bool(raw.send_stream_fairness),
            enable_latency_spin_bit=bool(raw.enable_latency_spin_bit),
            grease_reserved_versions=bool(raw.grease_reserved_versions),
            grease_quic_bit=bool(raw.grease_quic_bit),
            enable_optimistic_ack_mitigation=bool(raw.enable_optimistic_ack_mitigation),
        )

    def to_raw(self) -> ffi.coquic_transport_config_t:
        return ffi.coquic_transport_config_t(
            max_idle_timeout=self.max_idle_timeout,
            max_udp_payload_size=self.max_udp_payload_size,
            pmtud_enabled=int(self.pmtud_enabled),
            pmtud_base_datagram_size=self.pmtud_base_datagram_size,
            pmtud_max_datagram_size=self.pmtud_max_datagram_size,
            active_connection_id_limit=self.active_connection_id_limit,
            disable_active_migration=int(self.disable_active_migration),
            ack_delay_exponent=self.ack_delay_exponent,
            max_ack_delay=self.max_ack_delay,
            ack_eliciting_threshold=self.ack_eliciting_threshold,
            initial_max_data=self.initial_max_data,
            initial_max_stream_data_bidi_local=self.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote=self.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni=self.initial_max_stream_data_uni,
            initial_max_streams_bidi=self.initial_max_streams_bidi,
            initial_max_streams_uni=self.initial_max_streams_uni,
            max_datagram_frame_size=self.max_datagram_frame_size,
            congestion_control=int(self.congestion_control),
            enable_hystart_plus_plus=int(self.enable_hystart_plus_plus),
            send_stream_fairness=int(self.send_stream_fairness),
            enable_latency_spin_bit=int(self.enable_latency_spin_bit),
            grease_reserved_versions=int(self.grease_reserved_versions),
            grease_quic_bit=int(self.grease_quic_bit),
            enable_optimistic_ack_mitigation=int(self.enable_optimistic_ack_mitigation),
        )


@dataclass(slots=True)
class EndpointConfig:
    role: Role = Role.CLIENT
    supported_versions: list[int] = field(default_factory=list)
    verify_peer: bool = True
    retry_enabled: bool = False
    application_protocol: bytes = b""
    identity: TlsIdentity | None = None
    transport: TransportConfig = field(default_factory=TransportConfig.default)
    max_outbound_datagram_size: int = 0
    zero_rtt: ZeroRttConfig = field(default_factory=ZeroRttConfig)
    emit_shared_receive_stream_data: bool = False
    enable_packet_inspection: bool = False
    allow_peer_address_change: bool = False

    @classmethod
    def default(cls) -> "EndpointConfig":
        raw = ffi.coquic_endpoint_config_t()
        ffi.load_library().coquic_endpoint_config_init(C.byref(raw))
        return cls(
            role=Role(raw.role),
            supported_versions=[],
            verify_peer=bool(raw.verify_peer),
            retry_enabled=bool(raw.retry_enabled),
            application_protocol=_bytes_view(
                raw.application_protocol, raw.application_protocol_length
            ),
            identity=None,
            transport=TransportConfig.from_raw(raw.transport),
            max_outbound_datagram_size=raw.max_outbound_datagram_size,
            zero_rtt=ZeroRttConfig(),
            emit_shared_receive_stream_data=bool(raw.emit_shared_receive_stream_data),
            enable_packet_inspection=bool(raw.enable_packet_inspection),
            allow_peer_address_change=bool(raw.allow_peer_address_change),
        )

    @classmethod
    def http3_client(cls) -> "EndpointConfig":
        config = cls.default()
        config.role = Role.CLIENT
        config.application_protocol = b"h3"
        return config

    @classmethod
    def http3_server(cls) -> "EndpointConfig":
        config = cls.default()
        config.role = Role.SERVER
        config.application_protocol = b"h3"
        return config

    def materialize(self) -> "_EndpointConfigMaterialization":
        return _EndpointConfigMaterialization(self)


@dataclass(slots=True)
class ResumptionState:
    serialized: bytes


@dataclass(slots=True)
class ClientConnectionConfig:
    source_connection_id: bytes = b""
    initial_destination_connection_id: bytes = b""
    original_destination_connection_id: bytes | None = None
    retry_source_connection_id: bytes | None = None
    retry_token: bytes = b""
    original_version: int = 1
    initial_version: int = 1
    reacted_to_version_negotiation: bool = False
    server_name: bytes = b""
    resumption_state: ResumptionState | None = None
    zero_rtt: ZeroRttConfig = field(default_factory=ZeroRttConfig)

    @classmethod
    def default(cls) -> "ClientConnectionConfig":
        raw = ffi.coquic_client_connection_config_t()
        ffi.load_library().coquic_client_connection_config_init(C.byref(raw))
        return cls(
            original_version=raw.original_version,
            initial_version=raw.initial_version,
            reacted_to_version_negotiation=bool(raw.reacted_to_version_negotiation),
            server_name=_bytes_view(raw.server_name, raw.server_name_length),
        )

    def materialize(self) -> "_ClientConnectionConfigMaterialization":
        return _ClientConnectionConfigMaterialization(self)


@dataclass(slots=True)
class OpenConnection:
    connection: ClientConnectionConfig = field(
        default_factory=ClientConnectionConfig.default
    )
    initial_route_handle: RouteHandle = 0
    address_validation_identity: bytes = b""

    def materialize(self) -> "_OpenConnectionMaterialization":
        return _OpenConnectionMaterialization(self)


@dataclass(slots=True)
class InboundDatagram:
    bytes: bytes
    route_handle: RouteHandle | None = None
    address_validation_identity: bytes = b""
    ecn: EcnCodepoint = EcnCodepoint.UNAVAILABLE

    def to_raw(self, arena: "_CallArena") -> ffi.coquic_inbound_datagram_t:
        return ffi.coquic_inbound_datagram_t(
            size=C.sizeof(ffi.coquic_inbound_datagram_t),
            bytes=arena.bytes(self.bytes),
            route_handle=_optional_route(self.route_handle),
            address_validation_identity=arena.bytes(self.address_validation_identity),
            ecn=int(self.ecn),
        )


@dataclass(slots=True)
class PathMtuUpdate:
    route_handle: RouteHandle | None
    max_udp_payload_size: int

    def to_raw(self) -> ffi.coquic_path_mtu_update_t:
        return ffi.coquic_path_mtu_update_t(
            size=C.sizeof(ffi.coquic_path_mtu_update_t),
            route_handle=_optional_route(self.route_handle),
            max_udp_payload_size=self.max_udp_payload_size,
        )


@dataclass(slots=True)
class SendStreamData:
    stream_id: StreamId
    bytes: bytes
    fin: bool = False
    priority: int = 0

    def to_raw(self, arena: "_CallArena") -> ffi.coquic_send_stream_data_t:
        return ffi.coquic_send_stream_data_t(
            size=C.sizeof(ffi.coquic_send_stream_data_t),
            stream_id=self.stream_id,
            bytes=arena.bytes(self.bytes),
            fin=int(self.fin),
            priority=self.priority,
        )


@dataclass(slots=True)
class SendDatagramData:
    bytes: bytes
    priority: int = 0

    def to_raw(self, arena: "_CallArena") -> ffi.coquic_send_datagram_data_t:
        return ffi.coquic_send_datagram_data_t(
            size=C.sizeof(ffi.coquic_send_datagram_data_t),
            bytes=arena.bytes(self.bytes),
            priority=self.priority,
        )


@dataclass(slots=True)
class ResetStream:
    stream_id: StreamId
    application_error_code: int

    def to_raw(self) -> ffi.coquic_reset_stream_t:
        return ffi.coquic_reset_stream_t(
            size=C.sizeof(ffi.coquic_reset_stream_t),
            stream_id=self.stream_id,
            application_error_code=self.application_error_code,
        )


@dataclass(slots=True)
class StopSending:
    stream_id: StreamId
    application_error_code: int

    def to_raw(self) -> ffi.coquic_stop_sending_t:
        return ffi.coquic_stop_sending_t(
            size=C.sizeof(ffi.coquic_stop_sending_t),
            stream_id=self.stream_id,
            application_error_code=self.application_error_code,
        )


@dataclass(slots=True)
class CloseConnection:
    application_error_code: int
    reason_phrase: bytes = b""

    def to_raw(self, arena: "_CallArena") -> ffi.coquic_close_connection_t:
        return ffi.coquic_close_connection_t(
            size=C.sizeof(ffi.coquic_close_connection_t),
            application_error_code=self.application_error_code,
            reason_phrase=arena.char_pointer(self.reason_phrase),
            reason_phrase_length=len(self.reason_phrase),
        )


@dataclass(slots=True)
class RequestConnectionMigration:
    route_handle: RouteHandle
    reason: MigrationReason = MigrationReason.ACTIVE
    address_validation_identity: bytes = b""

    def to_raw(self, arena: "_CallArena") -> ffi.coquic_request_connection_migration_t:
        return ffi.coquic_request_connection_migration_t(
            size=C.sizeof(ffi.coquic_request_connection_migration_t),
            route_handle=self.route_handle,
            reason=int(self.reason),
            address_validation_identity=arena.bytes(self.address_validation_identity),
        )


@dataclass(slots=True)
class ConnectionInput:
    kind: int
    value: object | None = None

    @classmethod
    def send_stream(cls, value: SendStreamData) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_SEND_STREAM, value)

    @classmethod
    def send_datagram(cls, value: SendDatagramData) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_SEND_DATAGRAM, value)

    @classmethod
    def reset_stream(cls, value: ResetStream) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_RESET_STREAM, value)

    @classmethod
    def stop_sending(cls, value: StopSending) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_STOP_SENDING, value)

    @classmethod
    def close(cls, value: CloseConnection) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_CLOSE, value)

    @classmethod
    def request_key_update(cls) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE)

    @classmethod
    def request_migration(cls, value: RequestConnectionMigration) -> "ConnectionInput":
        return cls(ffi.COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION, value)

    def to_raw(self, arena: "_CallArena") -> ffi.coquic_connection_input_t:
        union = ffi.coquic_connection_input_union_t()
        if self.kind == ffi.COQUIC_CONNECTION_INPUT_SEND_STREAM:
            union.send_stream = self.value.to_raw(arena)  # type: ignore[union-attr]
        elif self.kind == ffi.COQUIC_CONNECTION_INPUT_SEND_DATAGRAM:
            union.send_datagram = self.value.to_raw(arena)  # type: ignore[union-attr]
        elif self.kind == ffi.COQUIC_CONNECTION_INPUT_RESET_STREAM:
            union.reset_stream = self.value.to_raw()  # type: ignore[union-attr]
        elif self.kind == ffi.COQUIC_CONNECTION_INPUT_STOP_SENDING:
            union.stop_sending = self.value.to_raw()  # type: ignore[union-attr]
        elif self.kind == ffi.COQUIC_CONNECTION_INPUT_CLOSE:
            union.close = self.value.to_raw(arena)  # type: ignore[union-attr]
        elif self.kind == ffi.COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION:
            union.request_migration = self.value.to_raw(arena)  # type: ignore[union-attr]
        return ffi.coquic_connection_input_t(kind=self.kind, as_=union)


@dataclass(frozen=True, slots=True)
class LocalError:
    connection: ConnectionHandle | None
    code: LocalErrorCode
    stream_id: StreamId | None


@dataclass(frozen=True, slots=True)
class PreferredAddress:
    ipv4_address: bytes
    ipv4_port: int
    ipv6_address: bytes
    ipv6_port: int
    connection_id: bytes
    stateless_reset_token: bytes


@dataclass(frozen=True, slots=True)
class PacketInspection:
    connection: ConnectionHandle
    direction: PacketInspectionDirection
    packet_type: PacketInspectionPacketType
    datagram_id: int
    datagram_length: int
    datagram_offset: int
    packet_length: int
    version: int
    destination_connection_id: bytes
    source_connection_id: bytes
    token: bytes
    spin_bit: bool
    key_phase: bool
    packet_number_length: int
    packet_number: int
    encrypted_packet: bytes
    plaintext_payload: bytes


@dataclass(frozen=True, slots=True)
class Effect:
    kind: str
    connection: ConnectionHandle | None = None
    route_handle: RouteHandle | None = None
    stream_id: StreamId | None = None
    bytes: bytes = b""
    fin: bool = False
    ecn: EcnCodepoint = EcnCodepoint.UNAVAILABLE
    is_pmtu_probe: bool = False
    application_error_code: int = 0
    final_size: int = 0
    change: StateChange | None = None
    event: Lifecycle | None = None
    preferred_address: PreferredAddress | None = None
    serialized: bytes = b""
    status: ZeroRttStatus | None = None
    packet_inspection: PacketInspection | None = None
    token: bytes = b""
    unknown: int | None = None


@dataclass(frozen=True, slots=True)
class QueryResult:
    effects: tuple[Effect, ...]
    next_wakeup: TimeUs | None
    local_error: LocalError | None
    send_continuation_pending: bool

    @property
    def effect_count(self) -> int:
        return len(self.effects)


class Endpoint:
    def __init__(self, config: EndpointConfig):
        """Create a CoQUIC endpoint from a materialized endpoint config."""
        self._lib = ffi.load_library()
        self._ptr = C.c_void_p()
        materialized = config.materialize()
        Status.check(
            self._lib.coquic_endpoint_create(
                materialized.raw_pointer(), C.byref(self._ptr)
            )
        )
        if not self._ptr.value:
            raise CoquicStatusError(Status.INTERNAL_ERROR)

    def close_handle(self) -> None:
        if getattr(self, "_ptr", None) is not None and self._ptr.value:
            self._lib.coquic_endpoint_destroy(self._ptr)
            self._ptr = C.c_void_p()

    def __del__(self) -> None:
        """Release the native endpoint handle during garbage collection."""
        try:
            self.close_handle()
        except Exception as error:
            # Destructors cannot report cleanup failures safely.
            _ = error

    def open_connection(self, request: OpenConnection, now: TimeUs) -> QueryResult:
        materialized = request.materialize()
        return self._call_result(
            lambda out: self._lib.coquic_endpoint_open_connection(
                self._checked_ptr(), materialized.raw_pointer(), now, out
            )
        )

    def input_datagram(self, datagram: InboundDatagram, now: TimeUs) -> QueryResult:
        arena = _CallArena()
        raw = datagram.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_endpoint_input_datagram(
                self._checked_ptr(), C.byref(raw), now, out
            )
        )

    def update_path_mtu(self, update: PathMtuUpdate, now: TimeUs) -> QueryResult:
        raw = update.to_raw()
        return self._call_result(
            lambda out: self._lib.coquic_endpoint_update_path_mtu(
                self._checked_ptr(), C.byref(raw), now, out
            )
        )

    def timer_expired(self, now: TimeUs) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_endpoint_timer_expired(
                self._checked_ptr(), now, out
            )
        )

    def connection_send_stream(
        self, connection: ConnectionHandle, stream_data: SendStreamData, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = stream_data.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_connection_send_stream(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def connection_send_datagram(
        self, connection: ConnectionHandle, datagram_data: SendDatagramData, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = datagram_data.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_connection_send_datagram(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def connection_reset_stream(
        self, connection: ConnectionHandle, reset: ResetStream, now: TimeUs
    ) -> QueryResult:
        raw = reset.to_raw()
        return self._call_result(
            lambda out: self._lib.coquic_connection_reset_stream(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def connection_stop_sending(
        self, connection: ConnectionHandle, stop: StopSending, now: TimeUs
    ) -> QueryResult:
        raw = stop.to_raw()
        return self._call_result(
            lambda out: self._lib.coquic_connection_stop_sending(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def connection_close(
        self, connection: ConnectionHandle, close: CloseConnection, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = close.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_connection_close(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def connection_request_key_update(
        self, connection: ConnectionHandle, now: TimeUs
    ) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_connection_request_key_update(
                self._checked_ptr(), connection, now, out
            )
        )

    def connection_request_migration(
        self,
        connection: ConnectionHandle,
        migration: RequestConnectionMigration,
        now: TimeUs,
    ) -> QueryResult:
        arena = _CallArena()
        raw = migration.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_connection_request_migration(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def connection_advance(
        self,
        connection: ConnectionHandle,
        connection_input: ConnectionInput,
        now: TimeUs,
    ) -> QueryResult:
        arena = _CallArena()
        raw = connection_input.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_connection_advance(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_connect(
        self, request: OpenConnection, now: TimeUs
    ) -> tuple[ConnectionHandle, QueryResult]:
        materialized = request.materialize()
        out_connection = C.c_uint64()
        out_result = C.c_void_p()
        Status.check(
            self._lib.coquic_quic_connect(
                self._checked_ptr(),
                materialized.raw_pointer(),
                now,
                C.byref(out_connection),
                C.byref(out_result),
            )
        )
        return out_connection.value, self._take_result(out_result)

    def quic_receive_datagram(
        self, datagram: InboundDatagram, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = datagram.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_quic_receive_datagram(
                self._checked_ptr(), C.byref(raw), now, out
            )
        )

    def quic_update_path_mtu(self, update: PathMtuUpdate, now: TimeUs) -> QueryResult:
        raw = update.to_raw()
        return self._call_result(
            lambda out: self._lib.coquic_quic_update_path_mtu(
                self._checked_ptr(), C.byref(raw), now, out
            )
        )

    def quic_timer_expired(self, now: TimeUs) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_quic_timer_expired(
                self._checked_ptr(), now, out
            )
        )

    def quic_connection_send_stream(
        self, connection: ConnectionHandle, stream_data: SendStreamData, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = stream_data.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_send_stream(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_connection_send_datagram(
        self, connection: ConnectionHandle, datagram_data: SendDatagramData, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = datagram_data.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_send_datagram(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_connection_reset_stream(
        self, connection: ConnectionHandle, reset: ResetStream, now: TimeUs
    ) -> QueryResult:
        raw = reset.to_raw()
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_reset_stream(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_connection_stop_sending(
        self, connection: ConnectionHandle, stop: StopSending, now: TimeUs
    ) -> QueryResult:
        raw = stop.to_raw()
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_stop_sending(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_connection_close(
        self, connection: ConnectionHandle, close: CloseConnection, now: TimeUs
    ) -> QueryResult:
        arena = _CallArena()
        raw = close.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_close(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_connection_request_key_update(
        self, connection: ConnectionHandle, now: TimeUs
    ) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_request_key_update(
                self._checked_ptr(), connection, now, out
            )
        )

    def quic_connection_advance(
        self,
        connection: ConnectionHandle,
        connection_input: ConnectionInput,
        now: TimeUs,
    ) -> QueryResult:
        arena = _CallArena()
        raw = connection_input.to_raw(arena)
        return self._call_result(
            lambda out: self._lib.coquic_quic_connection_advance(
                self._checked_ptr(), connection, C.byref(raw), now, out
            )
        )

    def quic_stream_send(
        self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        data: bytes,
        fin: bool,
        now: TimeUs,
    ) -> QueryResult:
        arena = _CallArena()
        raw_bytes = arena.bytes(data)
        return self._call_result(
            lambda out: self._lib.coquic_quic_stream_send(
                self._checked_ptr(),
                connection,
                stream_id,
                raw_bytes,
                int(fin),
                now,
                out,
            )
        )

    def quic_stream_finish(
        self, connection: ConnectionHandle, stream_id: StreamId, now: TimeUs
    ) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_quic_stream_finish(
                self._checked_ptr(), connection, stream_id, now, out
            )
        )

    def quic_stream_reset(
        self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        application_error_code: int,
        now: TimeUs,
    ) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_quic_stream_reset(
                self._checked_ptr(),
                connection,
                stream_id,
                application_error_code,
                now,
                out,
            )
        )

    def quic_stream_stop_sending(
        self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        application_error_code: int,
        now: TimeUs,
    ) -> QueryResult:
        return self._call_result(
            lambda out: self._lib.coquic_quic_stream_stop_sending(
                self._checked_ptr(),
                connection,
                stream_id,
                application_error_code,
                now,
                out,
            )
        )

    def connection_count(self) -> int:
        return int(self._lib.coquic_endpoint_connection_count(self._checked_ptr()))

    def has_send_continuation_pending(self) -> bool:
        return bool(
            self._lib.coquic_endpoint_has_send_continuation_pending(self._checked_ptr())
        )

    def has_pending_stream_send(self) -> bool:
        return bool(self._lib.coquic_endpoint_has_pending_stream_send(self._checked_ptr()))

    def next_wakeup(self) -> TimeUs | None:
        return _optional_time(
            self._lib.coquic_endpoint_next_wakeup(self._checked_ptr())
        )

    def _checked_ptr(self) -> C.c_void_p:
        if not self._ptr.value:
            raise CoquicStatusError(Status.INVALID_ARGUMENT)
        return self._ptr

    def _call_result(self, call: Callable[[C.POINTER(C.c_void_p)], int]) -> QueryResult:
        out_result = C.c_void_p()
        Status.check(call(C.byref(out_result)))
        return self._take_result(out_result)

    def _take_result(self, ptr: C.c_void_p) -> QueryResult:
        if not ptr.value:
            return QueryResult((), None, None, False)

        try:
            effect_count = self._lib.coquic_result_effect_count(ptr)
            effects: list[Effect] = []
            for index in range(effect_count):
                raw = ffi.coquic_effect_t()
                Status.check(
                    self._lib.coquic_result_effect_at(ptr, index, C.byref(raw))
                )
                effects.append(_effect_from_raw(raw))

            next_wakeup = _optional_time(self._lib.coquic_result_next_wakeup(ptr))
            local_error = None
            if self._lib.coquic_result_has_local_error(ptr):
                raw_error = ffi.coquic_local_error_t()
                Status.check(
                    self._lib.coquic_result_local_error(ptr, C.byref(raw_error))
                )
                local_error = LocalError(
                    connection=_optional_connection(raw_error.connection),
                    code=LocalErrorCode(raw_error.code),
                    stream_id=_optional_stream(raw_error.stream_id),
                )
            send_continuation_pending = bool(
                self._lib.coquic_result_send_continuation_pending(ptr)
            )
            return QueryResult(
                tuple(effects), next_wakeup, local_error, send_continuation_pending
            )
        finally:
            self._lib.coquic_result_destroy(ptr)


class _EndpointConfigMaterialization:
    def __init__(self, config: EndpointConfig):
        self._arena = _CallArena()
        self._supported_versions = _u32_array(config.supported_versions)
        self._application_protocol = config.application_protocol
        self._zero_rtt_context = config.zero_rtt.application_context
        self._identity_certificate = (
            config.identity.certificate_pem if config.identity else b""
        )
        self._identity_key = config.identity.private_key_pem if config.identity else b""
        self._identity = (
            ffi.coquic_tls_identity_t(
                certificate_pem=self._arena.char_pointer(self._identity_certificate),
                certificate_pem_length=len(self._identity_certificate),
                private_key_pem=self._arena.char_pointer(self._identity_key),
                private_key_pem_length=len(self._identity_key),
            )
            if config.identity
            else None
        )
        self.raw = ffi.coquic_endpoint_config_t(
            size=C.sizeof(ffi.coquic_endpoint_config_t),
            role=int(config.role),
            supported_versions=self._supported_versions,
            supported_versions_count=len(config.supported_versions),
            verify_peer=int(config.verify_peer),
            retry_enabled=int(config.retry_enabled),
            application_protocol=self._arena.char_pointer(config.application_protocol),
            application_protocol_length=len(config.application_protocol),
            identity=C.pointer(self._identity) if self._identity is not None else None,
            transport=config.transport.to_raw(),
            max_outbound_datagram_size=config.max_outbound_datagram_size,
            zero_rtt=ffi.coquic_zero_rtt_config_t(
                attempt=int(config.zero_rtt.attempt),
                allow=int(config.zero_rtt.allow),
                application_context=self._arena.bytes(
                    config.zero_rtt.application_context
                ),
            ),
            emit_shared_receive_stream_data=int(config.emit_shared_receive_stream_data),
            enable_packet_inspection=int(config.enable_packet_inspection),
            allow_peer_address_change=int(config.allow_peer_address_change),
        )

    def raw_pointer(self) -> C.POINTER(ffi.coquic_endpoint_config_t):
        return C.byref(self.raw)


class _ClientConnectionConfigMaterialization:
    def __init__(self, config: ClientConnectionConfig):
        self._arena = _CallArena()
        self._source_connection_id = config.source_connection_id
        self._initial_destination_connection_id = (
            config.initial_destination_connection_id
        )
        self._original_destination_connection_id = (
            config.original_destination_connection_id or b""
        )
        self._retry_source_connection_id = config.retry_source_connection_id or b""
        self._retry_token = config.retry_token
        self._server_name = config.server_name
        self._resumption_bytes = (
            config.resumption_state.serialized
            if config.resumption_state is not None
            else b""
        )
        self._resumption_state = (
            ffi.coquic_resumption_state_t(
                serialized=self._arena.bytes(self._resumption_bytes)
            )
            if config.resumption_state is not None
            else None
        )
        self.raw = ffi.coquic_client_connection_config_t(
            size=C.sizeof(ffi.coquic_client_connection_config_t),
            source_connection_id=self._arena.bytes(self._source_connection_id),
            initial_destination_connection_id=self._arena.bytes(
                self._initial_destination_connection_id
            ),
            original_destination_connection_id=self._arena.bytes(
                self._original_destination_connection_id
            ),
            has_original_destination_connection_id=int(
                config.original_destination_connection_id is not None
            ),
            retry_source_connection_id=self._arena.bytes(
                self._retry_source_connection_id
            ),
            has_retry_source_connection_id=int(
                config.retry_source_connection_id is not None
            ),
            retry_token=self._arena.bytes(self._retry_token),
            original_version=config.original_version,
            initial_version=config.initial_version,
            reacted_to_version_negotiation=int(config.reacted_to_version_negotiation),
            server_name=self._arena.char_pointer(self._server_name),
            server_name_length=len(self._server_name),
            resumption_state=(
                C.pointer(self._resumption_state)
                if self._resumption_state is not None
                else None
            ),
            zero_rtt=ffi.coquic_zero_rtt_config_t(
                attempt=int(config.zero_rtt.attempt),
                allow=int(config.zero_rtt.allow),
                application_context=self._arena.bytes(
                    config.zero_rtt.application_context
                ),
            ),
        )


class _OpenConnectionMaterialization:
    def __init__(self, open_connection: OpenConnection):
        self._arena = _CallArena()
        self.connection = open_connection.connection.materialize()
        self._address_validation_identity = open_connection.address_validation_identity
        self.raw = ffi.coquic_open_connection_t(
            size=C.sizeof(ffi.coquic_open_connection_t),
            connection=self.connection.raw,
            initial_route_handle=open_connection.initial_route_handle,
            address_validation_identity=self._arena.bytes(
                self._address_validation_identity
            ),
        )

    def raw_pointer(self) -> C.POINTER(ffi.coquic_open_connection_t):
        return C.byref(self.raw)


def _effect_from_raw(raw: ffi.coquic_effect_t) -> Effect:
    if raw.kind == ffi.COQUIC_EFFECT_SEND_DATAGRAM:
        value = raw.as_.send_datagram
        return Effect(
            kind="send_datagram",
            connection=value.connection,
            route_handle=_optional_route_from_raw(value.route_handle),
            bytes=_bytes_view(value.bytes.data, value.bytes.length),
            ecn=EcnCodepoint(value.ecn),
            is_pmtu_probe=bool(value.is_pmtu_probe),
        )
    if raw.kind == ffi.COQUIC_EFFECT_RECEIVE_STREAM_DATA:
        value = raw.as_.receive_stream_data
        return Effect(
            kind="receive_stream_data",
            connection=value.connection,
            stream_id=value.stream_id,
            bytes=_bytes_view(value.bytes.data, value.bytes.length),
            fin=bool(value.fin),
        )
    if raw.kind == ffi.COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA:
        value = raw.as_.receive_datagram_data
        return Effect(
            kind="receive_datagram_data",
            connection=value.connection,
            bytes=_bytes_view(value.bytes.data, value.bytes.length),
        )
    if raw.kind == ffi.COQUIC_EFFECT_PEER_RESET_STREAM:
        value = raw.as_.peer_reset_stream
        return Effect(
            kind="peer_reset_stream",
            connection=value.connection,
            stream_id=value.stream_id,
            application_error_code=value.application_error_code,
            final_size=value.final_size,
        )
    if raw.kind == ffi.COQUIC_EFFECT_PEER_STOP_SENDING:
        value = raw.as_.peer_stop_sending
        return Effect(
            kind="peer_stop_sending",
            connection=value.connection,
            stream_id=value.stream_id,
            application_error_code=value.application_error_code,
        )
    if raw.kind == ffi.COQUIC_EFFECT_STATE_EVENT:
        value = raw.as_.state_event
        return Effect(
            kind="state_event",
            connection=value.connection,
            change=StateChange(value.change),
        )
    if raw.kind == ffi.COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT:
        value = raw.as_.connection_lifecycle_event
        return Effect(
            kind="connection_lifecycle_event",
            connection=value.connection,
            event=Lifecycle(value.event),
        )
    if raw.kind == ffi.COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE:
        value = raw.as_.peer_preferred_address_available
        address = value.preferred_address
        return Effect(
            kind="peer_preferred_address_available",
            connection=value.connection,
            preferred_address=PreferredAddress(
                ipv4_address=bytes(address.ipv4_address),
                ipv4_port=address.ipv4_port,
                ipv6_address=bytes(address.ipv6_address),
                ipv6_port=address.ipv6_port,
                connection_id=_bytes_view(
                    address.connection_id.data, address.connection_id.length
                ),
                stateless_reset_token=bytes(address.stateless_reset_token),
            ),
        )
    if raw.kind == ffi.COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE:
        value = raw.as_.resumption_state_available
        return Effect(
            kind="resumption_state_available",
            connection=value.connection,
            serialized=_bytes_view(value.serialized.data, value.serialized.length),
        )
    if raw.kind == ffi.COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT:
        value = raw.as_.zero_rtt_status_event
        return Effect(
            kind="zero_rtt_status_event",
            connection=value.connection,
            status=ZeroRttStatus(value.status),
        )
    if raw.kind == ffi.COQUIC_EFFECT_PACKET_INSPECTION:
        value = raw.as_.packet_inspection
        return Effect(
            kind="packet_inspection",
            connection=value.connection,
            packet_inspection=PacketInspection(
                connection=value.connection,
                direction=PacketInspectionDirection(value.direction),
                packet_type=PacketInspectionPacketType(value.packet_type),
                datagram_id=value.datagram_id,
                datagram_length=value.datagram_length,
                datagram_offset=value.datagram_offset,
                packet_length=value.packet_length,
                version=value.version,
                destination_connection_id=_bytes_view(
                    value.destination_connection_id.data,
                    value.destination_connection_id.length,
                ),
                source_connection_id=_bytes_view(
                    value.source_connection_id.data,
                    value.source_connection_id.length,
                ),
                token=_bytes_view(value.token.data, value.token.length),
                spin_bit=bool(value.spin_bit),
                key_phase=bool(value.key_phase),
                packet_number_length=value.packet_number_length,
                packet_number=value.packet_number,
                encrypted_packet=_bytes_view(
                    value.encrypted_packet.data,
                    value.encrypted_packet.length,
                ),
                plaintext_payload=_bytes_view(
                    value.plaintext_payload.data,
                    value.plaintext_payload.length,
                ),
            ),
        )
    if raw.kind == ffi.COQUIC_EFFECT_NEW_TOKEN_AVAILABLE:
        value = raw.as_.new_token_available
        return Effect(
            kind="new_token_available",
            connection=value.connection,
            token=_bytes_view(value.token.data, value.token.length),
        )
    return Effect(kind="unknown", unknown=raw.kind)


class _CallArena:
    def __init__(self) -> None:
        self._buffers: list[C.Array[C.c_char]] = []

    def bytes(self, value: bytes | bytearray | memoryview) -> ffi.coquic_bytes_t:
        raw = bytes(value)
        if not raw:
            return ffi.coquic_bytes_t(None, 0)
        buffer = C.create_string_buffer(raw, len(raw))
        self._buffers.append(buffer)
        return ffi.coquic_bytes_t(C.cast(buffer, C.POINTER(C.c_uint8)), len(raw))

    def char_pointer(self, value: bytes | bytearray | memoryview) -> C.POINTER(
        C.c_char
    ):
        raw = bytes(value)
        if not raw:
            return C.POINTER(C.c_char)()
        buffer = C.create_string_buffer(raw, len(raw))
        self._buffers.append(buffer)
        return C.cast(buffer, C.POINTER(C.c_char))


def _u32_array(values: Iterable[int]) -> C.Array[C.c_uint32] | C.POINTER(C.c_uint32):
    values = list(values)
    if not values:
        return C.POINTER(C.c_uint32)()
    array_type = C.c_uint32 * len(values)
    return array_type(*values)


def _optional_route(value: RouteHandle | None) -> ffi.coquic_optional_route_handle_t:
    return ffi.coquic_optional_route_handle_t(
        int(value is not None), 0 if value is None else value
    )


def _optional_route_from_raw(
    raw: ffi.coquic_optional_route_handle_t,
) -> RouteHandle | None:
    return raw.value if raw.has_value else None


def _optional_connection(
    raw: ffi.coquic_optional_connection_handle_t,
) -> ConnectionHandle | None:
    return raw.value if raw.has_value else None


def _optional_stream(raw: ffi.coquic_optional_stream_id_t) -> StreamId | None:
    return raw.value if raw.has_value else None


def _optional_time(raw: ffi.coquic_optional_time_us_t) -> TimeUs | None:
    return raw.value if raw.has_value else None


def _bytes_view(data: object, length: int) -> bytes:
    if not data or length == 0:
        return b""
    return C.string_at(data, length)

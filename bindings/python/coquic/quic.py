from __future__ import annotations

import weakref
from dataclasses import dataclass, field

from ._core import (
    ClientConnectionConfig,
    CloseConnection,
    CoquicStatusError,
    ConnectionHandle,
    ConnectionInput,
    Endpoint as CoreEndpoint,
    EndpointConfig as CoreEndpointConfig,
    InboundDatagram,
    OpenConnection,
    PathMtuUpdate,
    QueryResult,
    RequestConnectionMigration,
    ResetStream,
    SendDatagramData,
    SendStreamData,
    Status,
    StopSending,
    StreamId,
    TimeUs,
)


@dataclass(slots=True)
class EndpointConfig:
    core: CoreEndpointConfig = field(default_factory=CoreEndpointConfig.default)


@dataclass(slots=True)
class ClientConfig:
    core: ClientConnectionConfig = field(default_factory=ClientConnectionConfig.default)
    initial_route_handle: int = 0
    address_validation_identity: bytes = b""

    @classmethod
    def new(
        cls,
        source_connection_id: bytes | bytearray | memoryview,
        initial_destination_connection_id: bytes | bytearray | memoryview,
    ) -> "ClientConfig":
        core = ClientConnectionConfig.default()
        core.source_connection_id = bytes(source_connection_id)
        core.initial_destination_connection_id = bytes(
            initial_destination_connection_id
        )
        return cls(core=core)

    def to_open_connection(self) -> OpenConnection:
        return OpenConnection(
            connection=self.core,
            initial_route_handle=self.initial_route_handle,
            address_validation_identity=self.address_validation_identity,
        )


@dataclass(slots=True)
class ConnectResult:
    connection: "Connection"
    result: QueryResult


class Endpoint:
    def __init__(self, config: EndpointConfig | None = None):
        """Create a high-level QUIC endpoint wrapper."""
        self._core = CoreEndpoint((config or EndpointConfig()).core)

    def connect(self, config: ClientConfig, now: TimeUs) -> ConnectResult:
        handle, result = self._core.quic_connect(config.to_open_connection(), now)
        return ConnectResult(connection=self.connection(handle), result=result)

    def connection(self, handle: ConnectionHandle) -> "Connection":
        return Connection(self, handle)

    def receive_datagram(self, datagram: InboundDatagram, now: TimeUs) -> QueryResult:
        return self._core.quic_receive_datagram(datagram, now)

    def update_path_mtu(self, update: PathMtuUpdate, now: TimeUs) -> QueryResult:
        return self._core.quic_update_path_mtu(update, now)

    def timer_expired(self, now: TimeUs) -> QueryResult:
        return self._core.quic_timer_expired(now)

    def connection_count(self) -> int:
        return self._core.connection_count()

    def next_wakeup(self) -> TimeUs | None:
        return self._core.next_wakeup()

    def has_send_continuation_pending(self) -> bool:
        return self._core.has_send_continuation_pending()

    def has_pending_stream_send(self) -> bool:
        return self._core.has_pending_stream_send()


class Connection:
    def __init__(self, endpoint: Endpoint, handle: ConnectionHandle):
        """Bind a connection handle to its owning endpoint."""
        self._endpoint = weakref.ref(endpoint)
        self._handle = handle

    @property
    def handle(self) -> ConnectionHandle:
        return self._handle

    def is_valid(self) -> bool:
        return self._handle != 0 and self._endpoint() is not None

    def stream(self, stream_id: StreamId) -> "Stream":
        return Stream(self, stream_id)

    def advance(self, connection_input: ConnectionInput, now: TimeUs) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_advance(
                self._handle, connection_input, now
            )
        )

    def send_stream(
        self,
        stream_id: StreamId,
        data: bytes | bytearray | memoryview,
        fin: bool,
        now: TimeUs,
        priority: int = 0,
    ) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_send_stream(
                self._handle, SendStreamData(stream_id, bytes(data), fin, priority), now
            )
        )

    def send_datagram(
        self, data: bytes | bytearray | memoryview, now: TimeUs
    ) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_send_datagram(
                self._handle, SendDatagramData(bytes(data)), now
            )
        )

    def reset_stream(
        self, stream_id: StreamId, application_error_code: int, now: TimeUs
    ) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_reset_stream(
                self._handle, ResetStream(stream_id, application_error_code), now
            )
        )

    def stop_sending(
        self, stream_id: StreamId, application_error_code: int, now: TimeUs
    ) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_stop_sending(
                self._handle, StopSending(stream_id, application_error_code), now
            )
        )

    def close(
        self, application_error_code: int, reason_phrase: bytes, now: TimeUs
    ) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_close(
                self._handle,
                CloseConnection(application_error_code, reason_phrase),
                now,
            )
        )

    def request_key_update(self, now: TimeUs) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.quic_connection_request_key_update(
                self._handle, now
            )
        )

    def request_migration(
        self, migration: RequestConnectionMigration, now: TimeUs
    ) -> QueryResult:
        return self._with_endpoint(
            lambda endpoint: endpoint._core.connection_request_migration(
                self._handle, migration, now
            )
        )

    def _with_endpoint(self, call):
        endpoint = self._endpoint()
        if endpoint is None:
            raise CoquicStatusError(Status.INVALID_ARGUMENT)
        return call(endpoint)


class Stream:
    def __init__(self, connection: Connection, stream_id: StreamId):
        """Bind a stream ID to a high-level connection wrapper."""
        self._connection = connection
        self._stream_id = stream_id

    @property
    def id(self) -> StreamId:
        return self._stream_id

    def is_valid(self) -> bool:
        return self._connection.is_valid()

    def send(
        self,
        data: bytes | bytearray | memoryview,
        fin: bool,
        now: TimeUs,
        priority: int = 0,
    ) -> QueryResult:
        return self._connection.send_stream(self._stream_id, bytes(data), fin, now, priority)

    def finish(self, now: TimeUs, priority: int = 0) -> QueryResult:
        return self._connection.send_stream(self._stream_id, b"", True, now, priority)

    def reset(self, application_error_code: int, now: TimeUs) -> QueryResult:
        return self._connection.reset_stream(
            self._stream_id, application_error_code, now
        )

    def stop_sending(self, application_error_code: int, now: TimeUs) -> QueryResult:
        return self._connection.stop_sending(
            self._stream_id, application_error_code, now
        )

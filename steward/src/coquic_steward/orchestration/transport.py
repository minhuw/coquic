from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from botocore.awsrequest import AWSHTTPConnection, AWSHTTPSConnection
from httpcore import (
    ConnectionPool,
    HTTP11Connection,
    HTTP2Connection,
    HTTPConnection,
    HTTPProxy,
    Origin,
)
from httpcore._sync.http_proxy import ForwardHTTPConnection, TunnelHTTPConnection

from ..publication.d1 import D1PublicationClient
from ..publication.r2 import R2Client
from .contracts import (
    DaemonCancellation,
    DaemonCancellationResult,
    PublicationTransportSetupError,
)


class _PublicationTransportCancelled(RuntimeError):
    """Signal a checkout that lost the cancellation race before handoff."""


class _CallbackDaemonCancellation(DaemonCancellation):
    """Bridge the existing publication cleanup callback to the typed boundary."""

    def __init__(self, callback: Callable[[], None]) -> None:
        self._callback = callback

    def cancel(self, deadline: float | None = None) -> DaemonCancellationResult:
        del deadline
        self._callback()
        return DaemonCancellationResult(quiescent=True)


def _close_r2_provider_client(client: R2Client) -> None:
    """Close the daemon-owned botocore client without discovering fallbacks."""

    try:
        client._client.close()
    except Exception:
        pass


def _close_d1_provider_client(client: D1PublicationClient) -> None:
    """Close the daemon-owned httpx client through its concrete owner."""

    try:
        client.close()
    except Exception:
        pass


class BotocoreR2TransportAdapter(DaemonCancellation):
    """Cancel botocore 1.43.58 through its observed private transport shape."""

    def __init__(self, client: R2Client) -> None:
        self._lock = threading.RLock()
        self._cleanup_lock = threading.RLock()
        self._cancelled = False
        self._cancel_in_progress = False
        self._cancel_complete = threading.Event()
        self._cancel_result: DaemonCancellationResult | None = None
        self._owner_closed = False
        self._connections: dict[int, object] = {}
        self._connection_methods: dict[int, object] = {}
        self._managers: dict[int, object] = {}
        self._pools: dict[int, object] = {}
        try:
            provider_client = client._client
            endpoint = provider_client._endpoint
            session = endpoint.http_session
            get_manager = session._get_connection_manager
            manager = get_manager(endpoint.host)
            connection_from_url = manager.connection_from_url
            pool = connection_from_url(endpoint.host)
            get_connection = pool._get_conn
            put_connection = pool._put_conn
            provider_client.close
            self._provider_client = provider_client
            connection = get_connection(timeout=0.0)
            try:
                self._install_connection(connection)
            finally:
                put_connection(connection)
            self._install_manager(manager)
            self._install_pool(pool)

            def tracked_get_manager(
                url: str, proxy_url: str | None = None
            ) -> object:
                selected_manager = get_manager(url, proxy_url)
                self._install_manager(selected_manager)
                return selected_manager

            session._get_connection_manager = tracked_get_manager
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None

    def _is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def _install_manager(self, manager: object) -> None:
        manager_id = id(manager)
        with self._lock:
            if manager_id in self._managers:
                return
        try:
            connection_from_url = manager.connection_from_url

            def tracked_connection_from_url(
                url: str, pool_kwargs: dict[str, Any] | None = None
            ) -> object:
                pool = connection_from_url(url, pool_kwargs)
                self._install_pool(pool)
                return pool

            manager.connection_from_url = tracked_connection_from_url
        except Exception:
            raise PublicationTransportSetupError() from None
        with self._lock:
            self._managers[manager_id] = manager

    def _install_pool(self, pool: object) -> None:
        pool_id = id(pool)
        with self._lock:
            if pool_id in self._pools:
                return
        try:
            get_connection = pool._get_conn
            put_connection = pool._put_conn

            def tracked_get(timeout: float | None = None) -> object:
                connection = get_connection(timeout=timeout)
                try:
                    self._install_connection(connection)
                    accepted = self._track_connection(connection)
                except PublicationTransportSetupError:
                    try:
                        put_connection(connection)
                    except Exception:
                        pass
                    raise
                if not accepted or self._is_cancelled():
                    self._abort_connection(connection)
                    raise _PublicationTransportCancelled()
                return connection

            def tracked_put(connection: object) -> None:
                try:
                    put_connection(connection)
                finally:
                    self._forget_connection(connection)

            pool._get_conn = tracked_get
            pool._put_conn = tracked_put
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None
        with self._lock:
            self._pools[pool_id] = pool

    def _install_connection(self, connection: object) -> None:
        connection_id = id(connection)
        with self._lock:
            if connection_id in self._connection_methods:
                return
        try:
            if not isinstance(connection, (AWSHTTPConnection, AWSHTTPSConnection)):
                raise PublicationTransportSetupError()
            connect = connection.connect

            def guarded_connect() -> None:
                if self._is_cancelled():
                    self._abort_connection(connection)
                    raise _PublicationTransportCancelled()
                connect()
                if self._is_cancelled():
                    self._abort_connection(connection)
                    raise _PublicationTransportCancelled()

            connection.connect = guarded_connect
        except Exception:
            raise PublicationTransportSetupError() from None
        with self._lock:
            self._connection_methods[connection_id] = connect

    def _track_connection(self, connection: object) -> bool:
        with self._lock:
            if self._cancelled:
                return False
            self._connections[id(connection)] = connection
            return True

    def _forget_connection(self, connection: object) -> None:
        with self._lock:
            self._connections.pop(id(connection), None)

    @staticmethod
    def _abort_connection(connection: object) -> None:
        try:
            raw_socket = connection.sock
        except AttributeError:
            raw_socket = None
        if raw_socket is not None:
            try:
                raw_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                raw_socket.close()
            except Exception:
                pass
        try:
            connection.close()
        except Exception:
            pass

    def cancel(self, deadline: float | None = None) -> DaemonCancellationResult:
        with self._lock:
            if self._cancel_complete.is_set():
                return self._cancel_result or DaemonCancellationResult(quiescent=False)
            if self._cancel_in_progress:
                completion = self._cancel_complete
                connections: tuple[object, ...] = ()
                owner = False
            else:
                self._cancel_in_progress = True
                self._cancelled = True
                completion = self._cancel_complete
                connections = tuple(self._connections.values())
                owner = True

        if not owner:
            if deadline is None:
                completed = completion.wait()
            else:
                remaining = deadline - time.monotonic()
                completed = remaining > 0 and completion.wait(timeout=remaining)
            if not completed:
                return DaemonCancellationResult(quiescent=False)
            with self._lock:
                return self._cancel_result or DaemonCancellationResult(
                    quiescent=False
                )

        result = DaemonCancellationResult(quiescent=False)
        try:
            for connection in connections:
                self._abort_connection(connection)
            result = DaemonCancellationResult(quiescent=True)
        finally:
            with self._lock:
                self._cancel_result = result
                self._cancel_in_progress = False
                self._cancel_complete.set()
        return result

    def close(self) -> None:
        with self._cleanup_lock:
            if self._owner_closed:
                return
            try:
                self.cancel()
            finally:
                try:
                    self._provider_client.close()
                except Exception:
                    pass
                self._owner_closed = True


class _HttpxD1HandoffStream:
    """Keep a connected stream fenced until httpcore finishes handoff."""

    def __init__(
        self,
        adapter: "HttpxD1TransportAdapter",
        connection: object,
        stream: object,
    ) -> None:
        self._adapter = adapter
        self._connection = connection
        self._stream = stream
        self._closed = False
        self._write_started = False
        self._active_operations = 0
        self._operations_complete = threading.Event()
        self._operations_complete.set()

    def _raise_if_cancelled(self) -> None:
        with self._adapter._lock:
            cancelled = self._adapter._cancelled
            write_started = self._write_started
        if cancelled:
            self.close()
            # HTTPConnection can install its protocol connection after this
            # stream was cancelled.  Use the handoff's own request state rather
            # than that mutable private pointer: until the first request write
            # starts, cancellation must terminate the handoff locally.  Once a
            # request has begun, preserve established-socket behavior so
            # httpcore/httpx translates the closed socket into the provider's
            # normal transport error.
            if not write_started:
                raise _PublicationTransportCancelled()
            raise OSError("publication transport cancelled")

    def _begin_operation(self, *, writes: bool = False) -> None:
        with self._adapter._lock:
            cancelled = self._adapter._cancelled
            if not cancelled:
                if self._active_operations == 0:
                    self._operations_complete.clear()
                self._active_operations += 1
                if writes:
                    # Record the handoff's first request write before releasing
                    # the lock.  Cancellation after this point follows the
                    # established socket shutdown path instead of racing the
                    # handoff fence.
                    self._write_started = True
        if cancelled:
            self._raise_if_cancelled()

    def _end_operation(self) -> None:
        with self._adapter._lock:
            self._active_operations = max(0, self._active_operations - 1)
            if self._active_operations == 0:
                self._operations_complete.set()
                if self._closed:
                    self._adapter._handoff_streams.pop(id(self), None)

    def _wait_for_operations(self, deadline: float | None = None) -> bool:
        if deadline is None:
            self._operations_complete.wait()
            return True
        if self._operations_complete.is_set():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        return self._operations_complete.wait(timeout=remaining)

    def close(self) -> None:
        with self._adapter._lock:
            if self._closed:
                return
            self._closed = True
            stream = self._stream
            if self._adapter._pending_streams.get(id(self._connection)) is self:
                self._adapter._pending_streams.pop(id(self._connection), None)
            if self._active_operations == 0:
                self._adapter._handoff_streams.pop(id(self), None)
        self._adapter._close_stream(stream)

    def get_extra_info(self, info: str) -> object:
        self._begin_operation()
        try:
            value = self._stream.get_extra_info(info)
            # Cancellation may close the stream while httpcore is inspecting
            # it, before HTTPConnection has assigned it to its protocol
            # connection.
            self._raise_if_cancelled()
            return value
        finally:
            self._end_operation()

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self._begin_operation()
        try:
            value = self._stream.read(max_bytes, timeout=timeout)
            self._raise_if_cancelled()
            return value
        finally:
            self._end_operation()

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._begin_operation(writes=True)
        try:
            self._stream.write(buffer, timeout=timeout)
            self._raise_if_cancelled()
        finally:
            self._end_operation()

    def start_tls(self, *args: object, **kwargs: object) -> object:
        self._begin_operation()
        try:
            stream = self._stream.start_tls(*args, **kwargs)
            with self._adapter._lock:
                cancelled = self._closed or self._adapter._cancelled
                if not cancelled:
                    self._stream = stream
            if cancelled:
                self._adapter._close_stream(stream)
                self.close()
                self._raise_if_cancelled()
            return self
        finally:
            self._end_operation()

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)


class _HttpxD1NetworkBackend:
    """Fence one HTTPConnection's stream handoff after cancellation."""

    def __init__(
        self,
        adapter: "HttpxD1TransportAdapter",
        connection: HTTPConnection,
        backend: object,
    ) -> None:
        self._adapter = adapter
        self._connection = connection
        self._backend = backend

    def connect_tcp(self, *args: object, **kwargs: object) -> object:
        self._adapter._raise_if_cancelled(self._connection)
        stream = self._backend.connect_tcp(*args, **kwargs)
        return self._adapter._register_stream(self._connection, stream)

    def connect_unix_socket(self, *args: object, **kwargs: object) -> object:
        self._adapter._raise_if_cancelled(self._connection)
        stream = self._backend.connect_unix_socket(*args, **kwargs)
        return self._adapter._register_stream(self._connection, stream)

    def __getattr__(self, name: str) -> object:
        return getattr(self._backend, name)


class HttpxD1TransportAdapter(DaemonCancellation):
    """Cancel the selected httpx 0.28.1/httpcore 1.0.9 route."""

    def __init__(self, client: D1PublicationClient) -> None:
        self._lock = threading.RLock()
        self._cancelled = False
        self._cancellation_failed = False
        self._cancellation_in_progress = False
        self._cancellation_validation_complete = threading.Event()
        self._connections: dict[int, object] = {}
        self._pending_streams: dict[int, _HttpxD1HandoffStream] = {}
        self._handoff_streams: dict[int, _HttpxD1HandoffStream] = {}
        self._connection_methods: dict[int, object] = {}
        self._pool_methods: dict[int, object] = {}
        self._proxy_connections: dict[int, HTTPConnection] = {}
        self._cleanup_lock = threading.Lock()
        self._owner_closed = False
        try:
            http_client = client._client
            if not isinstance(http_client, httpx.Client):
                raise PublicationTransportSetupError()
            endpoint = httpx.URL(client.endpoint)
            try:
                select_transport = http_client._transport_for_url
            except Exception:
                raise PublicationTransportSetupError() from None
            if not isinstance(select_transport, Callable):
                raise PublicationTransportSetupError()
            transport = select_transport(endpoint)
            if type(transport) is not httpx.HTTPTransport:
                raise PublicationTransportSetupError()
            if endpoint.scheme not in ("http", "https"):
                raise PublicationTransportSetupError()
            pool = transport._pool
            if type(pool) not in (ConnectionPool, HTTPProxy):
                raise PublicationTransportSetupError()
            if not isinstance(pool.create_connection, Callable):
                raise PublicationTransportSetupError()
            connections = tuple(pool.connections)
            if not isinstance(client.close, Callable):
                raise PublicationTransportSetupError()

            self._owner = client
            self._endpoint = endpoint
            self._transport = transport
            self._pool = pool
            for connection in connections:
                self._validate_connection_shape(connection)
            for connection in connections:
                self._install_connection(connection)
                self._track_connection(connection)
            self._install_pool(pool)
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None

    @staticmethod
    def _validate_protocol(protocol: object) -> None:
        if type(protocol) not in (HTTP11Connection, HTTP2Connection):
            raise PublicationTransportSetupError()
        try:
            stream = protocol._network_stream
        except Exception:
            raise PublicationTransportSetupError() from None
        if isinstance(stream, _HttpxD1HandoffStream):
            return
        try:
            raw_socket = stream._sock
        except Exception:
            raise PublicationTransportSetupError() from None
        if not isinstance(raw_socket, socket.socket):
            raise PublicationTransportSetupError()

    @classmethod
    def _validate_http_connection(
        cls, connection: object
    ) -> tuple[object, object]:
        if type(connection) is not HTTPConnection:
            raise PublicationTransportSetupError()
        try:
            current = connection._connection
            connect = connection._connect
            backend = connection._network_backend
            uds = connection._uds
        except Exception:
            raise PublicationTransportSetupError() from None
        if current is not None:
            cls._validate_protocol(current)
        if not isinstance(connect, Callable):
            raise PublicationTransportSetupError()
        if not isinstance(getattr(backend, "connect_tcp", None), Callable):
            raise PublicationTransportSetupError()
        if uds is not None and not isinstance(
            getattr(backend, "connect_unix_socket", None), Callable
        ):
            raise PublicationTransportSetupError()
        return connect, backend

    def _validate_forward_connection(
        self, connection: ForwardHTTPConnection
    ) -> HTTPConnection:
        try:
            nested = connection._connection
            close = connection.close
            proxy_origin = connection._proxy_origin
            remote_origin = connection._remote_origin
            nested_origin = nested._origin
            proxy_url_origin = self._pool._proxy_url.origin
            valid_origins = (
                type(nested) is HTTPConnection
                and type(proxy_origin) is Origin
                and type(remote_origin) is Origin
                and type(nested_origin) is Origin
                and type(proxy_url_origin) is Origin
                and remote_origin.scheme == b"http"
                and proxy_origin == proxy_url_origin
                and nested_origin == proxy_origin
            )
        except Exception:
            raise PublicationTransportSetupError() from None
        if not isinstance(close, Callable) or not valid_origins:
            raise PublicationTransportSetupError()
        return nested

    def _validate_connection_shape(self, connection: object) -> HTTPConnection | None:
        if type(self._pool) is ConnectionPool:
            if type(connection) is not HTTPConnection:
                raise PublicationTransportSetupError()
            self._validate_http_connection(connection)
            return connection
        if type(self._pool) is not HTTPProxy:
            raise PublicationTransportSetupError()
        if type(connection) is ForwardHTTPConnection:
            nested = self._validate_forward_connection(connection)
            self._validate_http_connection(nested)
            return nested
        if type(connection) is not TunnelHTTPConnection:
            raise PublicationTransportSetupError()
        try:
            current = connection._connection
            connected = connection._connected
            close = connection.close
        except Exception:
            raise PublicationTransportSetupError() from None
        if not isinstance(connected, bool) or not isinstance(close, Callable):
            raise PublicationTransportSetupError()
        if type(current) is HTTPConnection:
            self._validate_http_connection(current)
            if connected:
                raise PublicationTransportSetupError()
            return current
        if type(current) in (HTTP11Connection, HTTP2Connection):
            self._validate_protocol(current)
            return None
        raise PublicationTransportSetupError()

    def _stream_socket(self, stream: object) -> socket.socket | None:
        allow_missing = isinstance(stream, _HttpxD1HandoffStream)
        if allow_missing:
            with self._lock:
                if stream._adapter is not self:
                    raise PublicationTransportSetupError()
                stream = stream._stream
        try:
            raw_socket = stream._sock
        except AttributeError:
            if allow_missing:
                # Socketless test and handoff streams are still closed through
                # their stream owner.  A pinned SyncStream exposes _sock here.
                return None
            raise PublicationTransportSetupError() from None
        except Exception:
            raise PublicationTransportSetupError() from None
        if not isinstance(raw_socket, socket.socket):
            raise PublicationTransportSetupError()
        return raw_socket

    def _connection_socket(self, connection: object) -> socket.socket | None:
        """Return an established socket, or None for a valid connecting state."""

        if type(connection) is HTTPConnection:
            try:
                http_connection = connection._connection
            except Exception:
                raise PublicationTransportSetupError() from None
            if http_connection is None:
                return None
        elif type(connection) in (HTTP11Connection, HTTP2Connection):
            http_connection = connection
        else:
            raise PublicationTransportSetupError()
        self._validate_protocol(http_connection)
        try:
            stream = http_connection._network_stream
        except Exception:
            raise PublicationTransportSetupError() from None
        return self._stream_socket(stream)

    def _connection_parts(self, connection: object) -> tuple[object, ...]:
        if type(connection) is HTTPConnection:
            if type(self._pool) is ConnectionPool:
                self._validate_http_connection(connection)
                return (connection,)
            if type(self._pool) is not HTTPProxy:
                raise PublicationTransportSetupError()
            with self._lock:
                nested_ids = {
                    id(nested) for nested in self._proxy_connections.values()
                }
            if id(connection) not in nested_ids:
                raise PublicationTransportSetupError()
            self._validate_http_connection(connection)
            return (connection,)
        if type(self._pool) is not HTTPProxy or type(connection) not in (
            ForwardHTTPConnection,
            TunnelHTTPConnection,
        ):
            raise PublicationTransportSetupError()
        with self._lock:
            nested = self._proxy_connections.get(id(connection))
        try:
            current = connection._connection
            connected = connection._connected if type(connection) is TunnelHTTPConnection else None
        except Exception:
            raise PublicationTransportSetupError() from None
        parts: list[object] = []
        if type(connection) is ForwardHTTPConnection:
            if type(current) is not HTTPConnection:
                raise PublicationTransportSetupError()
            validated_nested = self._validate_forward_connection(connection)
            if validated_nested is not current:
                raise PublicationTransportSetupError()
            self._validate_http_connection(current)
            if nested is not None and nested is not current:
                raise PublicationTransportSetupError()
            nested = current
        elif type(current) is HTTPConnection:
            self._validate_http_connection(current)
            if not isinstance(connected, bool) or connected:
                raise PublicationTransportSetupError()
            if nested is not None and nested is not current:
                raise PublicationTransportSetupError()
            nested = current
        elif type(current) in (HTTP11Connection, HTTP2Connection):
            self._validate_protocol(current)
            if not isinstance(connected, bool):
                raise PublicationTransportSetupError()
        else:
            raise PublicationTransportSetupError()
        if nested is not None:
            self._validate_http_connection(nested)
            parts.append(nested)
        if all(id(part) != id(current) for part in parts):
            parts.append(current)
        return tuple(parts)

    def _is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def _raise_if_cancelled(self, connection: HTTPConnection) -> None:
        if self._is_cancelled():
            self._abort_connection(connection)
            raise _PublicationTransportCancelled()

    @staticmethod
    def _close_stream(stream: object) -> None:
        try:
            stream.close()
        except Exception:
            pass

    def _register_stream(
        self,
        connection: object,
        stream: object,
        *,
        write_started: bool = False,
    ) -> _HttpxD1HandoffStream:
        handoff = _HttpxD1HandoffStream(self, connection, stream)
        with self._lock:
            self._handoff_streams[id(handoff)] = handoff
            if self._cancelled:
                rejected = True
            else:
                rejected = False
                handoff._write_started = write_started
                self._pending_streams[id(connection)] = handoff
        if rejected:
            handoff.close()
            raise _PublicationTransportCancelled()
        return handoff

    def _attach_protocol_stream(
        self, protocol: object, connection: object
    ) -> None:
        self._validate_protocol(protocol)
        try:
            stream = protocol._network_stream
        except Exception:
            raise PublicationTransportSetupError() from None
        if isinstance(stream, _HttpxD1HandoffStream):
            if stream._adapter is not self:
                raise PublicationTransportSetupError()
            return
        with self._lock:
            handoff = next(
                (
                    candidate
                    for candidate in self._pending_streams.values()
                    if candidate._stream is stream and not candidate._closed
                ),
                None,
            )
        if handoff is None:
            handoff = self._register_stream(
                connection, stream, write_started=True
            )
        else:
            with self._lock:
                handoff._write_started = True
        protocol._network_stream = handoff

    def _install_pool(self, pool: ConnectionPool) -> None:
        pool_id = id(pool)
        with self._lock:
            if pool_id in self._pool_methods:
                return
        try:
            create_connection = pool.create_connection
            if not isinstance(create_connection, Callable):
                raise PublicationTransportSetupError()

            def tracked_create_connection(origin: object) -> object:
                connection = create_connection(origin)
                try:
                    self._install_connection(connection)
                    accepted = self._track_connection(connection)
                except PublicationTransportSetupError:
                    self._abort_connection(connection)
                    raise
                if not accepted or self._is_cancelled():
                    self._abort_connection(connection)
                    raise _PublicationTransportCancelled()
                return connection

            pool.create_connection = tracked_create_connection
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None
        with self._lock:
            self._pool_methods[pool_id] = create_connection

    def _install_http_connection(self, connection: HTTPConnection) -> None:
        connection_id = id(connection)
        with self._lock:
            if connection_id in self._connection_methods:
                return
        try:
            connect, backend = self._validate_http_connection(connection)
            current = connection._connection
            if current is not None:
                self._attach_protocol_stream(current, connection)
            connection._network_backend = _HttpxD1NetworkBackend(
                self,
                connection,
                backend,
            )

            def guarded_connect(request: object) -> object:
                self._raise_if_cancelled(connection)
                stream = connect(request)
                if not isinstance(stream, _HttpxD1HandoffStream):
                    stream = self._register_stream(connection, stream)
                stream._raise_if_cancelled()
                return stream

            connection._connect = guarded_connect
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None
        with self._lock:
            self._connection_methods[connection_id] = connect

    def _install_connection(self, connection: object) -> None:
        connection_id = id(connection)
        with self._lock:
            if connection_id in self._connection_methods:
                return
        try:
            nested = self._validate_connection_shape(connection)
            if nested is not None:
                self._install_http_connection(nested)
                if type(connection) is not HTTPConnection:
                    with self._lock:
                        self._proxy_connections[connection_id] = nested
            if type(connection) is not HTTPConnection:
                current = connection._connection
                if type(current) in (HTTP11Connection, HTTP2Connection):
                    self._attach_protocol_stream(
                        current, nested if nested is not None else connection
                    )
                close = connection.close
                with self._lock:
                    self._connection_methods[connection_id] = close
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None

    def _track_connection(self, connection: object) -> bool:
        with self._lock:
            if self._cancelled:
                return False
            self._connections[id(connection)] = connection
            return True

    @staticmethod
    def _shutdown_sockets(sockets: list[socket.socket]) -> None:
        # Shutdown must precede stream close: closing a socket from another
        # thread does not reliably interrupt a blocked recv/send.
        for raw_socket in sockets:
            try:
                raw_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    @staticmethod
    def _close_sockets(sockets: list[socket.socket]) -> None:
        for raw_socket in sockets:
            try:
                raw_socket.close()
            except Exception:
                pass

    def _abort_connection(self, connection: object) -> None:
        with self._lock:
            pending_ids = [id(connection)]
            nested = self._proxy_connections.get(id(connection))
            if nested is not None:
                pending_ids.append(id(nested))
            pending_streams = tuple(
                pending
                for connection_id in pending_ids
                if (pending := self._pending_streams.get(connection_id)) is not None
            )

        sockets: list[socket.socket] = []
        try:
            # These streams were installed and tracked by this adapter.  Keep
            # their sockets available even when later validation finds that a
            # mutable wrapper field has become contradictory.
            for stream in pending_streams:
                raw_socket = self._stream_socket(stream)
                if raw_socket is not None and all(
                    id(raw_socket) != id(existing) for existing in sockets
                ):
                    sockets.append(raw_socket)
            parts = self._connection_parts(connection)
            for part in parts:
                raw_socket = self._connection_socket(part)
                if raw_socket is not None and all(
                    id(raw_socket) != id(existing) for existing in sockets
                ):
                    sockets.append(raw_socket)
        except PublicationTransportSetupError:
            self._shutdown_sockets(sockets)
            for pending in pending_streams:
                pending.close()
            self._close_sockets(sockets)
            raise

        self._shutdown_sockets(sockets)
        for pending in pending_streams:
            pending.close()
        self._close_sockets(sockets)
        try:
            connection.close()
        except Exception:
            pass

    def _cancel(self, deadline: float | None = None) -> DaemonCancellationResult:
        with self._lock:
            already_cancelled = self._cancelled
            cancellation_failed = self._cancellation_failed
            cancellation_in_progress = self._cancellation_in_progress
            # Set the state before inspecting any private connection shape.  A
            # stream returned by connect can otherwise become reachable only
            # after cancellation has already started.
            self._cancelled = True
            if not already_cancelled:
                self._cancellation_in_progress = True
            connections = tuple(self._connections.values())
            pending_streams = tuple(self._pending_streams.values())
            handoff_streams = tuple(self._handoff_streams.values())
        if already_cancelled:
            if cancellation_failed:
                return DaemonCancellationResult(quiescent=False)
            if cancellation_in_progress:
                if deadline is None:
                    validated = self._cancellation_validation_complete.wait()
                else:
                    remaining = deadline - time.monotonic()
                    validated = (
                        remaining > 0
                        and self._cancellation_validation_complete.wait(
                            timeout=remaining
                        )
                    )
                if not validated:
                    return DaemonCancellationResult(quiescent=False)
                with self._lock:
                    if self._cancellation_failed:
                        return DaemonCancellationResult(quiescent=False)
                    handoff_streams = tuple(self._handoff_streams.values())
            for stream in handoff_streams:
                if not stream._wait_for_operations(deadline=deadline):
                    return DaemonCancellationResult(quiescent=False)
            return DaemonCancellationResult(quiescent=True)
        pool_error = False
        try:
            pool_connections = tuple(self._pool.connections)
        except Exception:
            pool_connections = ()
            pool_error = True
        connections += pool_connections
        seen: set[int] = set()
        setup_error = pool_error
        try:
            for connection in connections:
                connection_id = id(connection)
                if connection_id in seen:
                    continue
                seen.add(connection_id)
                try:
                    self._abort_connection(connection)
                except PublicationTransportSetupError:
                    setup_error = True
        except BaseException:
            with self._lock:
                self._cancellation_in_progress = False
                self._cancellation_failed = True
                self._cancellation_validation_complete.set()
            raise
        for stream in pending_streams:
            stream.close()
        with self._lock:
            self._cancellation_in_progress = False
            if setup_error:
                self._cancellation_failed = True
            self._cancellation_validation_complete.set()
        # A closed stream may still be inside start_tls or another admitted
        # handoff operation.  Do not let authority revocation follow one of
        # those operations while it can still touch the underlying stream.
        quiescent = True
        for stream in handoff_streams:
            if not stream._wait_for_operations(deadline=deadline):
                quiescent = False
                break
        if setup_error:
            raise PublicationTransportSetupError()
        return DaemonCancellationResult(quiescent=quiescent)

    def cancel(self, deadline: float | None = None) -> DaemonCancellationResult:
        return self._cancel(deadline=deadline)

    def close(self) -> None:
        with self._cleanup_lock:
            if self._owner_closed:
                return
            try:
                self._cancel()
            finally:
                try:
                    self._owner.close()
                except Exception:
                    pass
                self._owner_closed = True


class _PublicationTransportCancellation(DaemonCancellation):
    """Own both provider adapters behind the daemon cancellation boundary."""

    def __init__(self, r2: R2Client, d1: D1PublicationClient) -> None:
        r2_adapter: BotocoreR2TransportAdapter | None = None
        d1_adapter: HttpxD1TransportAdapter | None = None
        try:
            r2_adapter = BotocoreR2TransportAdapter(r2)
            d1_adapter = HttpxD1TransportAdapter(d1)
        except Exception:
            if r2_adapter is not None:
                try:
                    r2_adapter.close()
                except Exception:
                    pass
            else:
                _close_r2_provider_client(r2)
            _close_d1_provider_client(d1)
            raise
        self._r2 = r2_adapter
        self._d1 = d1_adapter

    def cancel(self, deadline: float | None = None) -> DaemonCancellationResult:
        errors: list[BaseException] = []
        results: list[DaemonCancellationResult] = []
        for adapter in (self._r2, self._d1):
            try:
                results.append(adapter.cancel(deadline=deadline))
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]
        return DaemonCancellationResult(
            quiescent=all(result.quiescent for result in results)
        )

    def close(self) -> None:
        self._r2.close()
        self._d1.close()

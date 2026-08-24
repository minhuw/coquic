from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from typing import Any

import httpx
from botocore.awsrequest import AWSHTTPConnection, AWSHTTPSConnection
from httpcore import ConnectionPool, HTTPConnection

from ..publication.d1 import D1PublicationClient
from ..publication.r2 import R2Client
from .contracts import DaemonCancellation, PublicationTransportSetupError


class _PublicationTransportCancelled(RuntimeError):
    """Signal a checkout that lost the cancellation race before handoff."""


class _CallbackDaemonCancellation(DaemonCancellation):
    """Bridge the existing publication cleanup callback to the typed boundary."""

    def __init__(self, callback: Callable[[], None]) -> None:
        self._callback = callback

    def cancel(self) -> None:
        self._callback()


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
        self._cancelled = False
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

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            connections = tuple(self._connections.values())
        for connection in connections:
            self._abort_connection(connection)

    def close(self) -> None:
        self.cancel()
        try:
            self._provider_client.close()
        except Exception:
            pass


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
        if self._adapter._is_cancelled():
            self._adapter._close_stream(stream)
            self._adapter._abort_connection(self._connection)
            raise _PublicationTransportCancelled()
        return stream

    def connect_unix_socket(self, *args: object, **kwargs: object) -> object:
        self._adapter._raise_if_cancelled(self._connection)
        stream = self._backend.connect_unix_socket(*args, **kwargs)
        if self._adapter._is_cancelled():
            self._adapter._close_stream(stream)
            self._adapter._abort_connection(self._connection)
            raise _PublicationTransportCancelled()
        return stream

    def __getattr__(self, name: str) -> object:
        return getattr(self._backend, name)


class HttpxD1TransportAdapter(DaemonCancellation):
    """Cancel httpx 0.28.1/httpcore 1.0.9 through its observed pool shape."""

    def __init__(self, client: D1PublicationClient) -> None:
        self._lock = threading.RLock()
        self._cancelled = False
        self._connections: dict[int, object] = {}
        self._connection_methods: dict[int, object] = {}
        self._pool_methods: dict[int, object] = {}
        try:
            http_client = client._client
            if not isinstance(http_client, httpx.Client):
                raise PublicationTransportSetupError()
            transport = http_client._transport
            if not isinstance(transport, httpx.HTTPTransport):
                raise PublicationTransportSetupError()
            pool = transport._pool
            if not isinstance(pool, ConnectionPool):
                raise PublicationTransportSetupError()
            if not isinstance(pool.create_connection, Callable):
                raise PublicationTransportSetupError()
            connections = tuple(pool.connections)
            client.close
            self._owner = client
            self._pool = pool
            for connection in connections:
                self._install_connection(connection)
                self._track_connection(connection)
            self._install_pool(pool)
        except PublicationTransportSetupError:
            raise
        except Exception:
            raise PublicationTransportSetupError() from None

    @staticmethod
    def _connection_socket(connection: object) -> socket.socket | None:
        """Return an established socket, or None for a valid connecting state."""

        if not isinstance(connection, HTTPConnection):
            raise PublicationTransportSetupError()
        try:
            http_connection = connection._connection
        except Exception:
            raise PublicationTransportSetupError() from None
        if http_connection is None:
            return None
        try:
            raw_socket = http_connection._network_stream._sock
        except Exception:
            raise PublicationTransportSetupError() from None
        if not isinstance(raw_socket, socket.socket):
            raise PublicationTransportSetupError()
        return raw_socket

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

    def _install_pool(self, pool: ConnectionPool) -> None:
        pool_id = id(pool)
        with self._lock:
            if pool_id in self._pool_methods:
                return
        try:
            create_connection = pool.create_connection

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

    def _install_connection(self, connection: object) -> None:
        connection_id = id(connection)
        with self._lock:
            if connection_id in self._connection_methods:
                return
        try:
            if not isinstance(connection, HTTPConnection):
                raise PublicationTransportSetupError()
            self._connection_socket(connection)
            connect = connection._connect
            backend = connection._network_backend
            connect_tcp = getattr(backend, "connect_tcp", None)
            if not isinstance(connect, Callable) or not isinstance(connect_tcp, Callable):
                raise PublicationTransportSetupError()
            if getattr(connection, "_uds", None) is not None and not isinstance(
                getattr(backend, "connect_unix_socket", None), Callable
            ):
                raise PublicationTransportSetupError()
            connection._network_backend = _HttpxD1NetworkBackend(
                self,
                connection,
                backend,
            )

            def guarded_connect(request: object) -> object:
                self._raise_if_cancelled(connection)
                stream = connect(request)
                if self._is_cancelled():
                    self._close_stream(stream)
                    self._abort_connection(connection)
                    raise _PublicationTransportCancelled()
                return stream

            connection._connect = guarded_connect
        except PublicationTransportSetupError:
            raise
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

    @classmethod
    def _abort_connection(cls, connection: object) -> None:
        raw_socket = cls._connection_socket(connection)
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

    def cancel(self) -> None:
        with self._lock:
            if self._cancelled:
                return
            self._cancelled = True
            connections = tuple(self._connections.values())
        try:
            connections += tuple(self._pool.connections)
        except Exception:
            raise PublicationTransportSetupError() from None
        seen: set[int] = set()
        for connection in connections:
            connection_id = id(connection)
            if connection_id in seen:
                continue
            seen.add(connection_id)
            self._abort_connection(connection)

    def close(self) -> None:
        self.cancel()
        try:
            self._owner.close()
        except Exception:
            pass


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

    def cancel(self) -> None:
        self._r2.close()
        self._d1.close()

    def close(self) -> None:
        self._r2.close()
        self._d1.close()

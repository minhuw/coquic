from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass

import coquic

from . import PerfError

MAX_UDP_DATAGRAM_SIZE = 64 * 1024
MAX_BUFFERED_SEND_DATAGRAMS = 4096


@dataclass(slots=True)
class Route:
    peer: tuple[str, int]
    address_validation_identity: bytes


@dataclass(slots=True)
class TxDatagram:
    route_handle: int
    bytes: bytes
    ecn: coquic.EcnCodepoint
    is_pmtu_probe: bool


@dataclass(slots=True)
class RxDatagram:
    bytes: bytes
    route_handle: int
    address_validation_identity: bytes


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        """Create a datagram protocol with an in-memory receive queue."""
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:
        self.queue.put_nowait((bytes(data), addr))


class WaitEvent:
    def __init__(self, kind: str, datagram: RxDatagram | None = None):
        """Create a wait result for received datagrams, timers, or idle timeouts."""
        self.kind = kind
        self.datagram = datagram


class UdpRuntime:
    def __init__(
        self, transport: asyncio.DatagramTransport, protocol: _DatagramProtocol
    ):
        """Wrap an asyncio UDP endpoint with CoQUIC route bookkeeping."""
        self.transport = transport
        self.protocol = protocol
        self.start = time.monotonic()
        self.routes_by_handle: dict[int, Route] = {}
        self.handles_by_peer: dict[tuple[str, int], int] = {}
        self.next_route_handle = 1
        self.send_buffer: list[TxDatagram] = []

    @classmethod
    async def client(cls, host: str, port: int) -> tuple["UdpRuntime", int, bytes]:
        peer = _resolve_remote(host, port)
        bind_addr = _client_bind_address(peer[0])
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            _DatagramProtocol,
            local_addr=(bind_addr, 0),
        )
        runtime = cls(transport, protocol)
        route = runtime.ensure_route(peer)
        identity = runtime.address_validation_identity(route)
        if identity is None:
            raise PerfError("missing client primary route identity")
        return runtime, route, identity

    @classmethod
    async def server(cls, host: str, port: int) -> "UdpRuntime":
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            _DatagramProtocol,
            local_addr=(host, port),
        )
        return cls(transport, protocol)

    def close(self) -> None:
        self.transport.close()

    def now_us(self) -> int:
        return min(int((time.monotonic() - self.start) * 1_000_000), (1 << 64) - 1)

    def ensure_route(self, peer: tuple[str, int]) -> int:
        peer = (peer[0], int(peer[1]))
        if peer in self.handles_by_peer:
            return self.handles_by_peer[peer]
        handle = self.next_route_handle
        self.next_route_handle += 1
        self.handles_by_peer[peer] = handle
        self.routes_by_handle[handle] = Route(peer, address_validation_identity(peer))
        return handle

    def inbound_datagram(self, rx: RxDatagram) -> coquic.InboundDatagram:
        return coquic.InboundDatagram(
            bytes=rx.bytes,
            route_handle=rx.route_handle,
            address_validation_identity=rx.address_validation_identity,
            ecn=coquic.EcnCodepoint.UNAVAILABLE,
        )

    def append_result_sends(self, result: coquic.QueryResult) -> None:
        for effect in result.effects:
            if effect.kind != "send_datagram":
                continue
            if len(self.send_buffer) >= MAX_BUFFERED_SEND_DATAGRAMS:
                raise PerfError(
                    "send buffer exceeded before flush; call flush_sends more often"
                )
            if effect.route_handle is None:
                raise PerfError("send datagram missing route handle")
            self.send_buffer.append(
                TxDatagram(
                    route_handle=effect.route_handle,
                    bytes=effect.bytes,
                    ecn=effect.ecn,
                    is_pmtu_probe=effect.is_pmtu_probe,
                )
            )

    async def flush_sends(self) -> None:
        datagrams = self.send_buffer
        self.send_buffer = []
        for datagram in datagrams:
            route = self.routes_by_handle.get(datagram.route_handle)
            if route is None:
                raise PerfError(f"unknown route handle {datagram.route_handle}")
            self.transport.sendto(datagram.bytes, route.peer)
        await asyncio.sleep(0)

    async def recv(self) -> RxDatagram:
        data, peer = await self.protocol.queue.get()
        if len(data) > MAX_UDP_DATAGRAM_SIZE:
            data = data[:MAX_UDP_DATAGRAM_SIZE]
        route_handle = self.ensure_route(peer)
        identity = self.address_validation_identity(route_handle) or b""
        return RxDatagram(data, route_handle, identity)

    async def wait(self, next_wakeup: int | None, idle_timeout: float) -> WaitEvent:
        timer_timeout: float | None = None
        if next_wakeup is not None:
            now = self.now_us()
            if next_wakeup <= now:
                return WaitEvent("timer")
            timer_timeout = (next_wakeup - now) / 1_000_000.0
        timeout = (
            min(timer_timeout, idle_timeout)
            if timer_timeout is not None
            else idle_timeout
        )
        try:
            datagram = await asyncio.wait_for(self.recv(), timeout)
            return WaitEvent("datagram", datagram)
        except asyncio.TimeoutError:
            if timer_timeout is not None and timer_timeout <= idle_timeout:
                return WaitEvent("timer")
            return WaitEvent("idle")

    def address_validation_identity(self, route_handle: int) -> bytes | None:
        route = self.routes_by_handle.get(route_handle)
        return route.address_validation_identity if route is not None else None


def copy_non_send_effects(result: coquic.QueryResult) -> list[coquic.Effect]:
    out = []
    for effect in result.effects:
        if effect.kind in (
            "receive_stream_data",
            "state_event",
            "connection_lifecycle_event",
            "peer_reset_stream",
            "peer_stop_sending",
        ):
            out.append(effect)
    return out


def address_validation_identity(peer: tuple[str, int]) -> bytes:
    address = ipaddress.ip_address(peer[0])
    port = int(peer[1])
    if isinstance(address, ipaddress.IPv4Address):
        return b"\x04" + address.packed + port.to_bytes(2, "big")
    return b"\x06" + address.packed + port.to_bytes(2, "big")


def _client_bind_address(peer_host: str) -> str:
    address = ipaddress.ip_address(peer_host)
    if address.is_loopback:
        return "127.0.0.1" if isinstance(address, ipaddress.IPv4Address) else "::1"
    return "0.0.0.0" if isinstance(address, ipaddress.IPv4Address) else "::"


def _resolve_remote(host: str, port: int) -> tuple[str, int]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    if not infos:
        raise PerfError("failed to resolve remote address")
    addr = infos[0][4]
    return (addr[0], int(addr[1]))

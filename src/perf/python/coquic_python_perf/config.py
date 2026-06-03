from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import coquic
from coquic import quic

from . import PerfError

APPLICATION_PROTOCOL = b"coquic-perf/1"
PERF_MAX_OUTBOUND_DATAGRAM_SIZE = 60 * 1024
PERF_TRANSFER_CONNECTION_RECEIVE_WINDOW = 32 * 1024 * 1024
PERF_TRANSFER_STREAM_RECEIVE_WINDOW = 16 * 1024 * 1024
PERF_ACK_ELICITING_THRESHOLD = 2
PERF_COPA_BULK_ACK_ELICITING_THRESHOLD = 1
PERF_COPA_INTERACTIVE_ACK_ELICITING_THRESHOLD = 8
PERF_SERVER_INITIAL_MAX_BIDIRECTIONAL_STREAMS = 4096


class Role(Enum):
    SERVER = "server"
    CLIENT = "client"


class Mode(Enum):
    BULK = "bulk"
    RR = "rr"
    CRR = "crr"


class Direction(Enum):
    UPLOAD = "upload"
    DOWNLOAD = "download"


@dataclass(slots=True)
class PerfConfig:
    role: Role = Role.SERVER
    mode: Mode = Mode.BULK
    direction: Direction = Direction.DOWNLOAD
    host: str = "127.0.0.1"
    port: int = 4433
    server_name: str = "localhost"
    verify_peer: bool = False
    certificate_chain_path: Path = Path("tests/fixtures/quic-server-cert.pem")
    private_key_path: Path = Path("tests/fixtures/quic-server-key.pem")
    json_out: Path | None = None
    request_bytes: int = 64
    response_bytes: int = 64
    streams: int = 1
    connections: int = 1
    requests_in_flight: int = 1
    requests: int | None = None
    total_bytes: int | None = None
    warmup: float = 0.0
    duration: float = 5.0
    congestion_control: coquic.CongestionControl = coquic.CongestionControl.NEWRENO


def parse_runtime_args(args: list[str]) -> PerfConfig:
    if not args:
        raise PerfError(usage())

    config = PerfConfig()
    role = args[0]
    if role == "server":
        config.role = Role.SERVER
    elif role == "client":
        config.role = Role.CLIENT
    else:
        raise PerfError(usage())

    saw_direction = False
    index = 1
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--verify-peer":
            config.verify_peer = True
            continue
        if index >= len(args):
            raise PerfError(f"missing value for {arg}\n{usage()}")
        value = args[index]
        index += 1

        if arg == "--host":
            config.host = value
        elif arg == "--port":
            config.port = _parse_size(value)
            if config.port > 65535:
                raise PerfError(usage())
        elif arg == "--io-backend":
            if value != "socket":
                raise PerfError("coquic-python-perf currently supports --io-backend socket")
        elif arg == "--congestion-control":
            config.congestion_control = parse_congestion_control(value)
        elif arg == "--mode":
            config.mode = parse_mode(value)
        elif arg == "--direction":
            saw_direction = True
            config.direction = parse_direction(value)
        elif arg == "--request-bytes":
            config.request_bytes = _parse_size(value)
        elif arg == "--response-bytes":
            config.response_bytes = _parse_size(value)
        elif arg == "--streams":
            config.streams = _parse_size(value)
        elif arg == "--connections":
            config.connections = _parse_size(value)
        elif arg == "--requests-in-flight":
            config.requests_in_flight = _parse_size(value)
        elif arg == "--requests":
            config.requests = _parse_size(value)
        elif arg == "--total-bytes":
            config.total_bytes = _parse_size(value)
        elif arg == "--warmup":
            config.warmup = parse_duration(value)
        elif arg == "--duration":
            config.duration = parse_duration(value)
        elif arg == "--certificate-chain":
            config.certificate_chain_path = Path(value)
        elif arg == "--private-key":
            config.private_key_path = Path(value)
        elif arg == "--server-name":
            config.server_name = value
        elif arg == "--json-out":
            config.json_out = Path(value)
        else:
            raise PerfError(usage())

    if config.mode != Mode.BULK and saw_direction:
        raise PerfError(usage())
    if config.streams == 0 or config.connections == 0 or config.requests_in_flight == 0:
        raise PerfError(usage())
    return config


def client_endpoint_config(config: PerfConfig) -> quic.EndpointConfig:
    endpoint = quic.EndpointConfig()
    endpoint.core.role = coquic.Role.CLIENT
    endpoint.core.verify_peer = config.verify_peer
    endpoint.core.application_protocol = APPLICATION_PROTOCOL
    endpoint.core.max_outbound_datagram_size = PERF_MAX_OUTBOUND_DATAGRAM_SIZE
    endpoint.core.emit_shared_receive_stream_data = True
    apply_transport_defaults(config, endpoint.core.transport)
    return endpoint


def server_endpoint_config(config: PerfConfig) -> quic.EndpointConfig:
    endpoint = quic.EndpointConfig()
    endpoint.core.role = coquic.Role.SERVER
    endpoint.core.verify_peer = config.verify_peer
    endpoint.core.application_protocol = APPLICATION_PROTOCOL
    endpoint.core.identity = coquic.TlsIdentity(
        certificate_pem=_read_file(config.certificate_chain_path),
        private_key_pem=_read_file(config.private_key_path),
    )
    endpoint.core.max_outbound_datagram_size = PERF_MAX_OUTBOUND_DATAGRAM_SIZE
    endpoint.core.emit_shared_receive_stream_data = True
    apply_transport_defaults(config, endpoint.core.transport)
    endpoint.core.transport.initial_max_streams_bidi = max(
        endpoint.core.transport.initial_max_streams_bidi,
        PERF_SERVER_INITIAL_MAX_BIDIRECTIONAL_STREAMS,
    )
    return endpoint


def apply_transport_defaults(config: PerfConfig, transport: coquic.TransportConfig) -> None:
    transport.congestion_control = config.congestion_control
    transport.enable_hystart_plus_plus = perf_enable_hystart_plus_plus(config)
    transport.send_stream_fairness = perf_send_stream_fairness(config)
    transport.ack_eliciting_threshold = perf_ack_eliciting_threshold(config)
    transport.initial_max_data = PERF_TRANSFER_CONNECTION_RECEIVE_WINDOW
    transport.initial_max_stream_data_bidi_local = PERF_TRANSFER_STREAM_RECEIVE_WINDOW
    transport.initial_max_stream_data_bidi_remote = PERF_TRANSFER_STREAM_RECEIVE_WINDOW


def perf_ack_eliciting_threshold(config: PerfConfig) -> int:
    if config.congestion_control == coquic.CongestionControl.COPA:
        if config.mode == Mode.BULK:
            return PERF_COPA_BULK_ACK_ELICITING_THRESHOLD
        return PERF_COPA_INTERACTIVE_ACK_ELICITING_THRESHOLD
    return PERF_ACK_ELICITING_THRESHOLD


def perf_enable_hystart_plus_plus(config: PerfConfig) -> bool:
    if config.mode != Mode.BULK:
        return True
    return config.congestion_control not in (
        coquic.CongestionControl.NEWRENO,
        coquic.CongestionControl.CUBIC,
    )


def perf_send_stream_fairness(config: PerfConfig) -> bool:
    return config.mode != Mode.BULK


def parse_mode(value: str) -> Mode:
    try:
        return Mode(value)
    except ValueError:
        raise PerfError(usage()) from None


def parse_direction(value: str) -> Direction:
    try:
        return Direction(value)
    except ValueError:
        raise PerfError(usage()) from None


def parse_congestion_control(value: str) -> coquic.CongestionControl:
    mapping = {
        "newreno": coquic.CongestionControl.NEWRENO,
        "cubic": coquic.CongestionControl.CUBIC,
        "bbr": coquic.CongestionControl.BBR,
        "copa": coquic.CongestionControl.COPA,
    }
    try:
        return mapping[value]
    except KeyError:
        raise PerfError(usage()) from None


def mode_name(mode: Mode) -> str:
    return mode.value


def direction_name(direction: Direction) -> str:
    return direction.value


def congestion_control_name(congestion_control: coquic.CongestionControl) -> str:
    mapping = {
        coquic.CongestionControl.NEWRENO: "newreno",
        coquic.CongestionControl.CUBIC: "cubic",
        coquic.CongestionControl.BBR: "bbr",
        coquic.CongestionControl.COPA: "copa",
    }
    return mapping[congestion_control]


def parse_duration(value: str) -> float:
    if value.endswith("ms"):
        return int(value[:-2]) / 1000.0
    if value.endswith("s"):
        return float(int(value[:-1]))
    raise PerfError("duration must use ms or s suffix")


def _parse_size(value: str) -> int:
    return int(value)


def _read_file(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise PerfError(f"failed to read {path}: {error}") from error


def usage() -> str:
    return (
        "usage: coquic-python-perf [server|client] [--host HOST] [--port PORT] "
        "[--io-backend socket] [--congestion-control newreno|cubic|bbr|copa] "
        "[--mode bulk|rr|crr] [--direction upload|download] [--request-bytes N] "
        "[--response-bytes N] [--streams N] [--connections N] "
        "[--requests-in-flight N] [--requests N] [--total-bytes N] "
        "[--warmup 250ms|2s] [--duration 250ms|2s] "
        "[--certificate-chain PATH] [--private-key PATH] [--server-name NAME] "
        "[--verify-peer] [--json-out PATH]"
    )

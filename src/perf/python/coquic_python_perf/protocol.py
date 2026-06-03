from __future__ import annotations

from dataclasses import dataclass

from .config import Direction, Mode

PROTOCOL_VERSION_LEGACY = 1
PROTOCOL_VERSION_MILLISECONDS = 2
PROTOCOL_VERSION = 3
CONTROL_STREAM_ID = 0
FIRST_DATA_STREAM_ID = 4

MESSAGE_SESSION_START = 1
MESSAGE_SESSION_READY = 2
MESSAGE_SESSION_ERROR = 3
MESSAGE_SESSION_COMPLETE = 4

OPTIONAL_TOTAL_BYTES_FLAG = 0x01
OPTIONAL_REQUESTS_FLAG = 0x02


@dataclass(slots=True)
class SessionStart:
    protocol_version: int = PROTOCOL_VERSION
    mode: Mode = Mode.BULK
    direction: Direction = Direction.DOWNLOAD
    request_bytes: int = 0
    response_bytes: int = 0
    total_bytes: int | None = None
    requests: int | None = None
    warmup: float = 0.0
    duration: float = 0.0
    streams: int = 1
    connections: int = 1
    requests_in_flight: int = 1


@dataclass(frozen=True, slots=True)
class SessionReady:
    protocol_version: int


@dataclass(frozen=True, slots=True)
class SessionError:
    reason: str


@dataclass(frozen=True, slots=True)
class SessionComplete:
    bytes_sent: int = 0
    bytes_received: int = 0
    requests_completed: int = 0


ControlMessage = SessionStart | SessionReady | SessionError | SessionComplete


def encode_control_message(message: ControlMessage) -> bytes:
    payload = bytearray()
    if isinstance(message, SessionStart):
        message_type = MESSAGE_SESSION_START
        _append_u32(payload, message.protocol_version)
        _append_u8(payload, _mode_to_u8(message.mode))
        _append_u8(payload, _direction_to_u8(message.direction))
        _append_u64(payload, message.request_bytes)
        _append_u64(payload, message.response_bytes)
        if message.protocol_version != PROTOCOL_VERSION_LEGACY:
            _append_u8(payload, _session_start_optional_flags(message))
        _append_u64(payload, message.total_bytes or 0)
        _append_u64(payload, message.requests or 0)
        if message.protocol_version in (PROTOCOL_VERSION_LEGACY, PROTOCOL_VERSION_MILLISECONDS):
            _append_u64(payload, _duration_ms(message.warmup))
            _append_u64(payload, _duration_ms(message.duration))
        else:
            _append_u64(payload, _duration_us(message.warmup))
            _append_u64(payload, _duration_us(message.duration))
        _append_u64(payload, message.streams)
        _append_u64(payload, message.connections)
        _append_u64(payload, message.requests_in_flight)
    elif isinstance(message, SessionReady):
        message_type = MESSAGE_SESSION_READY
        _append_u32(payload, message.protocol_version)
    elif isinstance(message, SessionError):
        message_type = MESSAGE_SESSION_ERROR
        data = message.reason.encode()
        _append_u32(payload, len(data))
        payload.extend(data)
    else:
        message_type = MESSAGE_SESSION_COMPLETE
        _append_u64(payload, message.bytes_sent)
        _append_u64(payload, message.bytes_received)
        _append_u64(payload, message.requests_completed)

    out = bytearray()
    _append_u8(out, message_type)
    _append_u32(out, len(payload))
    out.extend(payload)
    return bytes(out)


def decode_control_message(data: bytes) -> ControlMessage | None:
    if len(data) < 5:
        return None
    message_type = data[0]
    payload_size = int.from_bytes(data[1:5], "big")
    payload = memoryview(data[5:])
    if len(payload) != payload_size:
        return None
    reader = _Reader(payload)

    try:
        if message_type == MESSAGE_SESSION_START:
            return _decode_session_start(reader)
        if message_type == MESSAGE_SESSION_READY:
            protocol_version = reader.take_u32()
            return SessionReady(protocol_version) if reader.empty else None
        if message_type == MESSAGE_SESSION_ERROR:
            reason = reader.take_string()
            return SessionError(reason) if reader.empty else None
        if message_type == MESSAGE_SESSION_COMPLETE:
            bytes_sent = reader.take_u64()
            bytes_received = reader.take_u64()
            requests_completed = reader.take_u64()
            return (
                SessionComplete(bytes_sent, bytes_received, requests_completed)
                if reader.empty
                else None
            )
    except (UnicodeDecodeError, ValueError):
        return None
    return None


def take_control_message(buffer: bytearray) -> ControlMessage | None:
    if len(buffer) < 5:
        return None
    payload_size = int.from_bytes(buffer[1:5], "big")
    frame_size = 5 + payload_size
    if len(buffer) < frame_size:
        return None
    frame = bytes(buffer[:frame_size])
    del buffer[:frame_size]
    return decode_control_message(frame)


def next_client_stream_id(current: int) -> int:
    return FIRST_DATA_STREAM_ID if current == 0 else current + 4


def _decode_session_start(reader: "_Reader") -> SessionStart | None:
    protocol_version = reader.take_u32()
    mode = _parse_mode(reader.take_u8())
    direction = _parse_direction(reader.take_u8())
    if mode is None or direction is None:
        return None
    request_bytes = reader.take_u64()
    response_bytes = reader.take_u64()

    if protocol_version in (PROTOCOL_VERSION, PROTOCOL_VERSION_MILLISECONDS):
        optional_flags = reader.take_u8()
    elif protocol_version == PROTOCOL_VERSION_LEGACY:
        optional_flags = 0
    else:
        return None

    total_bytes_raw = reader.take_u64()
    requests_raw = reader.take_u64()
    warmup_raw = reader.take_u64()
    duration_raw = reader.take_u64()
    streams = reader.take_u64()
    connections = reader.take_u64()
    requests_in_flight = reader.take_u64()
    if not reader.empty:
        return None

    if protocol_version == PROTOCOL_VERSION_LEGACY:
        total_bytes = total_bytes_raw or None
        requests = requests_raw or None
    else:
        total_bytes = total_bytes_raw if optional_flags & OPTIONAL_TOTAL_BYTES_FLAG else None
        requests = requests_raw if optional_flags & OPTIONAL_REQUESTS_FLAG else None

    if protocol_version in (PROTOCOL_VERSION_LEGACY, PROTOCOL_VERSION_MILLISECONDS):
        warmup = warmup_raw / 1000.0
        duration = duration_raw / 1000.0
    else:
        warmup = warmup_raw / 1_000_000.0
        duration = duration_raw / 1_000_000.0

    return SessionStart(
        protocol_version=protocol_version,
        mode=mode,
        direction=direction,
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        total_bytes=total_bytes,
        requests=requests,
        warmup=warmup,
        duration=duration,
        streams=streams,
        connections=connections,
        requests_in_flight=requests_in_flight,
    )


class _Reader:
    def __init__(self, data: memoryview):
        self._data = data
        self._offset = 0

    @property
    def empty(self) -> bool:
        return self._offset == len(self._data)

    def take_u8(self) -> int:
        if self._offset >= len(self._data):
            raise ValueError("short input")
        value = self._data[self._offset]
        self._offset += 1
        return int(value)

    def take_u32(self) -> int:
        return self._take_int(4)

    def take_u64(self) -> int:
        return self._take_int(8)

    def take_string(self) -> str:
        size = self.take_u32()
        if len(self._data) - self._offset < size:
            raise ValueError("short input")
        raw = bytes(self._data[self._offset : self._offset + size])
        self._offset += size
        return raw.decode()

    def _take_int(self, size: int) -> int:
        if len(self._data) - self._offset < size:
            raise ValueError("short input")
        value = int.from_bytes(self._data[self._offset : self._offset + size], "big")
        self._offset += size
        return value


def _append_u8(out: bytearray, value: int) -> None:
    out.append(value & 0xFF)


def _append_u32(out: bytearray, value: int) -> None:
    out.extend(value.to_bytes(4, "big"))


def _append_u64(out: bytearray, value: int) -> None:
    out.extend(value.to_bytes(8, "big"))


def _mode_to_u8(mode: Mode) -> int:
    return {Mode.BULK: 0, Mode.RR: 1, Mode.CRR: 2}[mode]


def _parse_mode(value: int) -> Mode | None:
    return {0: Mode.BULK, 1: Mode.RR, 2: Mode.CRR}.get(value)


def _direction_to_u8(direction: Direction) -> int:
    return {Direction.UPLOAD: 0, Direction.DOWNLOAD: 1}[direction]


def _parse_direction(value: int) -> Direction | None:
    return {0: Direction.UPLOAD, 1: Direction.DOWNLOAD}.get(value)


def _session_start_optional_flags(start: SessionStart) -> int:
    flags = 0
    if start.total_bytes is not None:
        flags |= OPTIONAL_TOTAL_BYTES_FLAG
    if start.requests is not None:
        flags |= OPTIONAL_REQUESTS_FLAG
    return flags


def _duration_us(seconds: float) -> int:
    return min(int(seconds * 1_000_000), (1 << 64) - 1)


def _duration_ms(seconds: float) -> int:
    return min(int(seconds * 1000), (1 << 64) - 1)

from __future__ import annotations

import os
from dataclasses import dataclass, field

import coquic

from . import PerfError
from .config import Direction, Mode, PerfConfig, server_endpoint_config
from .io import UdpRuntime, copy_non_send_effects
from .metrics import new_run_summary
from .protocol import (
    CONTROL_STREAM_ID,
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_LEGACY,
    SessionComplete,
    SessionError,
    SessionReady,
    SessionStart,
    decode_control_message,
    encode_control_message,
)

IDLE_TIMEOUT = 1.0


@dataclass(slots=True)
class Session:
    control_bytes: bytearray = field(default_factory=bytearray)
    start: SessionStart | None = None
    complete_sent: bool = False
    bytes_sent: int = 0
    bytes_received: int = 0
    requests_completed: int = 0


@dataclass(frozen=True, slots=True)
class SendResponseCommand:
    connection: int
    stream_id: int
    bytes: int


@dataclass(frozen=True, slots=True)
class SendControlCommand:
    connection: int
    message: object


ServerCommand = SendResponseCommand | SendControlCommand


async def run_server(config: PerfConfig):
    endpoint = coquic.quic.Endpoint(server_endpoint_config(config))
    io = await UdpRuntime.server(config.host, config.port)
    try:
        server = Server(endpoint, io)
        await server.run()
        return new_run_summary(config)
    finally:
        io.close()


class Server:
    def __init__(self, endpoint: coquic.quic.Endpoint, io: UdpRuntime):
        """Initialize server state for one performance session."""
        self.endpoint = endpoint
        self.io = io
        self.sessions: dict[int, Session] = {}
        self.completed_crr_sessions: set[int] = set()
        self.accepted_session = False
        self.completed_session_seen = False

    async def run(self) -> None:
        while True:
            await self.handle_due_timer()
            if (
                self.should_exit_on_session_complete()
                or self.should_exit_on_idle_empty()
            ):
                return

            event = await self.io.wait(self.endpoint.next_wakeup(), IDLE_TIMEOUT)
            if event.kind == "datagram":
                now = self.io.now_us()
                result = self.endpoint.receive_datagram(
                    self.io.inbound_datagram(event.datagram), now
                )
                await self.handle_result(result, now)
            elif event.kind == "timer":
                now = self.io.now_us()
                result = self.endpoint.timer_expired(now)
                await self.handle_result(result, now)
            else:
                await self.io.flush_sends()
                if (
                    self.should_exit_on_idle_empty()
                    or self.should_exit_on_session_complete()
                ):
                    return

    async def handle_due_timer(self) -> None:
        while True:
            wakeup = self.endpoint.next_wakeup()
            if wakeup is None:
                return
            now = self.io.now_us()
            if wakeup > now:
                return
            result = self.endpoint.timer_expired(now)
            await self.handle_result(result, now)

    async def handle_result(self, result: coquic.QueryResult, now: int) -> None:
        pending = [result]
        while pending:
            current = pending.pop()
            commands = self.collect_result_commands(current, now)
            for command in commands:
                pending.append(self.execute_command(command, now))
        await self.io.flush_sends()

    def collect_result_commands(
        self, result: coquic.QueryResult, now: int
    ) -> list[ServerCommand]:
        if result.local_error is not None:
            raise PerfError(f"server local error: {result.local_error!r}")

        self.io.append_result_sends(result)
        effects = copy_non_send_effects(result)

        commands: list[ServerCommand] = []
        for effect in effects:
            if effect.kind == "connection_lifecycle_event":
                if effect.event == coquic.Lifecycle.ACCEPTED:
                    self.accepted_session = True
                    self.sessions[effect.connection] = Session()
                elif effect.event == coquic.Lifecycle.CLOSED:
                    session = self.sessions.get(effect.connection)
                    if (
                        session is not None
                        and session.start is not None
                        and session.start.mode == Mode.CRR
                        and session.requests_completed > 0
                    ):
                        self.completed_crr_sessions.add(effect.connection)
                    self.sessions.pop(effect.connection, None)
            elif (
                effect.kind == "state_event"
                and effect.change == coquic.StateChange.FAILED
            ):
                if not self._tolerate_failed_state(effect.connection):
                    raise PerfError(
                        f"server core state failed connection={effect.connection}"
                    )
            elif effect.kind == "receive_stream_data":
                commands.extend(
                    self.handle_stream_data(
                        effect.connection,
                        effect.stream_id,
                        effect.bytes,
                        effect.fin,
                    )
                )
        return commands

    def handle_stream_data(
        self, connection: int, stream_id: int, data: bytes, fin: bool
    ) -> list[ServerCommand]:
        if stream_id == CONTROL_STREAM_ID:
            return self.handle_control_stream_data(connection, data, fin)

        session = self.sessions.get(connection)
        if session is None or session.start is None:
            return []

        self.record_stream_data(session, data, fin)
        if not fin:
            return []
        if session.start.mode == Mode.BULK:
            return self.handle_bulk_stream_fin(connection, stream_id, session)
        if session.start.mode in (Mode.RR, Mode.CRR):
            return self.handle_request_response_fin(connection, stream_id, session)
        return []

    def handle_control_stream_data(
        self, connection: int, data: bytes, fin: bool
    ) -> list[ServerCommand]:
        session = self.sessions.get(connection)
        if session is None:
            raise PerfError("control stream for unknown session")
        session.control_bytes.extend(data)
        if not fin:
            return []

        decoded = decode_control_message(bytes(session.control_bytes))
        session.control_bytes.clear()
        if not isinstance(decoded, SessionStart):
            return [
                SendControlCommand(connection, SessionError("expected session_start"))
            ]

        reason = validate_session_start(decoded)
        if reason is not None:
            return [SendControlCommand(connection, SessionError(reason))]

        session.start = decoded
        return [
            SendControlCommand(
                connection, SessionReady(protocol_version=PROTOCOL_VERSION)
            )
        ]

    def record_stream_data(self, session: Session, data: bytes, fin: bool) -> None:
        session.bytes_received += len(data)
        if fin:
            session.requests_completed += 1

    def handle_bulk_stream_fin(
        self, connection: int, stream_id: int, session: Session
    ) -> list[ServerCommand]:
        start = session.start
        if start is None:
            return []
        if start.direction == Direction.DOWNLOAD:
            return self.handle_bulk_download_fin(connection, stream_id, session)
        if session.requests_completed >= start.streams:
            return self.complete_session(connection)
        return []

    def handle_bulk_download_fin(
        self, connection: int, stream_id: int, session: Session
    ) -> list[ServerCommand]:
        start = session.start
        if start is None:
            return []

        target = start.response_bytes
        commands: list[ServerCommand] = []
        if start.total_bytes is not None:
            stream_index = max(session.requests_completed - 1, 0)
            per_stream = start.total_bytes // start.streams
            remainder = start.total_bytes % start.streams
            target = per_stream + (1 if stream_index < remainder else 0)
        commands.append(SendResponseCommand(connection, stream_id, target))
        session.bytes_sent += target
        if (
            start.total_bytes is not None
            and session.requests_completed >= start.streams
        ):
            commands.extend(self.complete_session(connection))
        return commands

    def handle_request_response_fin(
        self, connection: int, stream_id: int, session: Session
    ) -> list[ServerCommand]:
        start = session.start
        if start is None:
            return []
        commands: list[ServerCommand] = [
            SendResponseCommand(connection, stream_id, start.response_bytes)
        ]
        session.bytes_sent += start.response_bytes
        if (
            start.mode == Mode.RR
            and start.requests is not None
            and session.requests_completed >= start.requests
        ):
            commands.extend(self.complete_session(connection))
        return commands

    def complete_session(self, connection: int) -> list[ServerCommand]:
        complete = self.make_complete_command(connection)
        return [complete] if complete is not None else []

    def execute_command(self, command: ServerCommand, now: int) -> coquic.QueryResult:
        if isinstance(command, SendResponseCommand):
            payload = make_payload(command.bytes)
            return (
                self.endpoint.connection(command.connection)
                .stream(command.stream_id)
                .send(payload, True, now)
            )

        fin = isinstance(command.message, (SessionError, SessionComplete))
        payload = encode_control_message(command.message)
        return (
            self.endpoint.connection(command.connection)
            .stream(CONTROL_STREAM_ID)
            .send(payload, fin, now)
        )

    def make_complete_command(self, connection: int) -> SendControlCommand | None:
        session = self.sessions.get(connection)
        if session is None or session.complete_sent:
            return None
        session.complete_sent = True
        self.completed_session_seen = True
        return SendControlCommand(
            connection,
            SessionComplete(
                bytes_sent=session.bytes_sent,
                bytes_received=session.bytes_received,
                requests_completed=session.requests_completed,
            ),
        )

    def should_exit_on_idle_empty(self) -> bool:
        return (
            self.accepted_session
            and not self.sessions
            and env_flag_enabled("COQUIC_PERF_SERVER_EXIT_ON_IDLE_EMPTY")
        )

    def should_exit_on_session_complete(self) -> bool:
        return (
            self.accepted_session
            and self.completed_session_seen
            and env_flag_enabled("COQUIC_PERF_SERVER_EXIT_ON_SESSION_COMPLETE")
            and all(session.complete_sent for session in self.sessions.values())
            and not self.endpoint.has_send_continuation_pending()
        )

    def _tolerate_failed_state(self, connection: int) -> bool:
        session = self.sessions.get(connection)
        return connection in self.completed_crr_sessions or (
            session is not None
            and session.start is not None
            and session.start.mode == Mode.CRR
            and session.requests_completed > 0
        )


def validate_session_start(start: SessionStart) -> str | None:
    if start.protocol_version not in (PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY):
        return "unsupported protocol version"
    if start.streams == 0:
        return "streams must be greater than zero"
    if start.connections == 0:
        return "connections must be greater than zero"
    if start.requests_in_flight == 0:
        return "requests_in_flight must be greater than zero"
    return None


def make_payload(size: int) -> bytes:
    return b"\x5a" * size


def env_flag_enabled(name: str) -> bool:
    value = os.environ.get(name)
    return value is not None and value != "" and value != "0"

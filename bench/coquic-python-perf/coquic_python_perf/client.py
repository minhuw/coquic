from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import coquic

from . import PerfError
from .config import Direction, Mode, PerfConfig, client_endpoint_config
from .io import UdpRuntime, copy_non_send_effects
from .metrics import (
    ServerCounters,
    duration_millis,
    finalize_summary,
    new_run_summary,
    reset_measurement,
)
from .protocol import (
    CONTROL_STREAM_ID,
    FIRST_DATA_STREAM_ID,
    PROTOCOL_VERSION,
    SessionComplete,
    SessionError,
    SessionReady,
    SessionStart,
    encode_control_message,
    next_client_stream_id,
    take_control_message,
)

IDLE_TIMEOUT = 1.0
DRAIN_TIMEOUT = 2.0


class BenchmarkPhase(Enum):
    WARMUP = "warmup"
    MEASURE = "measure"
    DRAIN = "drain"


@dataclass(slots=True)
class OutstandingRequest:
    started_at: int
    counts_toward_measurement: bool


@dataclass(slots=True)
class ConnectionState:
    session_ready: bool = False
    control_complete: bool = False
    close_requested: bool = False
    control_bytes: bytearray = field(default_factory=bytearray)
    outstanding_requests: dict[int, OutstandingRequest] = field(default_factory=dict)
    active_bulk_streams: dict[int, bool] = field(default_factory=dict)
    next_stream_id: int = FIRST_DATA_STREAM_ID
    request_limit: int | None = None
    requests_started: int = 0
    server_complete_counted: bool = False


@dataclass(frozen=True, slots=True)
class OpenConnectionCommand:
    pass


@dataclass(frozen=True, slots=True)
class SendStreamCommand:
    connection: int
    stream_id: int
    bytes: bytes
    fin: bool


@dataclass(frozen=True, slots=True)
class CloseCommand:
    connection: int
    reason: bytes


ClientCommand = OpenConnectionCommand | SendStreamCommand | CloseCommand


async def run_client(config: PerfConfig):
    endpoint = coquic.quic.Endpoint(client_endpoint_config(config))
    io, primary_route, primary_identity = await UdpRuntime.client(
        config.host, config.port
    )
    try:
        client = Client(config, endpoint, io, primary_route, primary_identity)
        return await client.run()
    finally:
        io.close()


class Client:
    def __init__(
        self,
        config: PerfConfig,
        endpoint: coquic.quic.Endpoint,
        io: UdpRuntime,
        primary_route: int,
        primary_identity: bytes,
    ):
        """Initialize client state for a single performance run."""
        self.config = config
        self.endpoint = endpoint
        self.io = io
        self.primary_route = primary_route
        self.primary_identity = primary_identity
        self.connections: dict[int, ConnectionState] = {}
        self.closing_connections: set[int] = set()
        self.requests_started = 0
        self.crr_requests_opened = 0
        self.next_connection_index = 0
        self.phase = BenchmarkPhase.WARMUP
        self.run_started_at = 0
        self.benchmark_started_at: int | None = None
        self.measure_started_at = 0
        self.measure_deadline = 0
        self.drain_deadline: int | None = None
        self.summary = new_run_summary(config)

    async def run(self):
        start = self.io.now_us()
        self.run_started_at = start
        self.measure_started_at = start
        self.phase = BenchmarkPhase.WARMUP
        if not self.timed_mode():
            self.benchmark_started_at = start

        for _ in range(self.initial_connection_target()):
            result = self.execute_command(OpenConnectionCommand(), start)
            await self.handle_result(result, start)

        while True:
            now = self.io.now_us()
            await self.advance_benchmark_phase(now)

            if self.run_complete():
                await self.io.flush_sends()
                if (
                    self.timed_bulk_mode()
                    and self.config.direction == Direction.DOWNLOAD
                    and self.config.response_bytes > 0
                    and self.summary.bytes_received == 0
                ):
                    raise PerfError("timed bulk download measured zero bytes")
                self.summary.status = "ok"
                self.summary.elapsed_ms = duration_millis(
                    self.result_elapsed_seconds(now)
                )
                if self.timed_rr_mode() or self.timed_crr_mode():
                    self.summary.server_counters = ServerCounters(
                        bytes_sent=self.summary.bytes_received,
                        bytes_received=self.summary.bytes_sent,
                        requests_completed=self.summary.requests_completed,
                    )
                finalize_summary(self.summary)
                return self.summary

            await self.handle_due_timer()
            await self.maybe_open_crr_connections()
            await self.io.flush_sends()

            event = await self.io.wait(
                self.next_wait_wakeup(self.endpoint.next_wakeup()),
                IDLE_TIMEOUT,
            )
            if event.kind == "datagram":
                now = self.io.now_us()
                await self.advance_benchmark_phase(now)
                result = self.endpoint.receive_datagram(
                    self.io.inbound_datagram(event.datagram), now
                )
                await self.handle_result(result, now)
            elif event.kind == "timer":
                now = self.io.now_us()
                await self.advance_benchmark_phase(now)
                await self.handle_due_timer()
            else:
                raise PerfError("client timed out waiting for progress")

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
    ) -> list[ClientCommand]:
        self.advance_benchmark_phase_sync(now)
        if result.local_error is not None:
            self.summary.failure_reason = f"client local error: {result.local_error!r}"
            raise PerfError(self.summary.failure_reason)

        self.io.append_result_sends(result)
        effects = copy_non_send_effects(result)

        commands: list[ClientCommand] = []
        for effect in effects:
            if effect.kind == "connection_lifecycle_event":
                if effect.event == coquic.Lifecycle.CREATED:
                    connection_index = len(self.connections)
                    self.connections.setdefault(
                        effect.connection,
                        ConnectionState(
                            request_limit=request_limit_for_connection(
                                self.config, connection_index
                            )
                        ),
                    )
                elif effect.event == coquic.Lifecycle.CLOSED:
                    if self.config.mode == Mode.CRR:
                        self.connections.pop(effect.connection, None)
                    elif effect.connection in self.connections:
                        self.connections[effect.connection].control_complete = True
            elif effect.kind == "state_event":
                if (
                    effect.change == coquic.StateChange.FAILED
                    and effect.connection not in self.closing_connections
                ):
                    raise PerfError(
                        f"client core state failed connection={effect.connection}"
                    )
                if (
                    effect.change == coquic.StateChange.HANDSHAKE_READY
                    and effect.connection in self.connections
                ):
                    commands.append(
                        SendStreamCommand(
                            connection=effect.connection,
                            stream_id=CONTROL_STREAM_ID,
                            bytes=encode_control_message(
                                self.make_session_start(
                                    self.connections[effect.connection].request_limit
                                )
                            ),
                            fin=True,
                        )
                    )
            elif effect.kind == "receive_stream_data":
                commands.extend(
                    self.handle_stream_data(
                        effect.connection,
                        effect.stream_id,
                        effect.bytes,
                        effect.fin,
                        now,
                    )
                )
        return commands

    def handle_stream_data(
        self, connection: int, stream_id: int, data: bytes, fin: bool, now: int
    ) -> list[ClientCommand]:
        if stream_id == CONTROL_STREAM_ID:
            return self.handle_control_stream_data(connection, data, fin, now)

        if self.timed_bulk_mode():
            return self.handle_bulk_data(connection, stream_id, data, fin, now)

        if self.config.mode in (Mode.RR, Mode.CRR):
            return self.handle_request_response_data(
                connection, stream_id, data, fin, now
            )

        self.summary.bytes_received += len(data)
        return []

    def handle_control_stream_data(
        self, connection: int, data: bytes, fin: bool, now: int
    ) -> list[ClientCommand]:
        state = self.connections.get(connection)
        if state is None:
            raise PerfError("control data for unknown connection")
        state.control_bytes.extend(data)
        messages = self.take_control_messages(state)

        commands: list[ClientCommand] = []
        for message in messages:
            commands.extend(
                self.handle_control_message(connection, state, message, now)
            )

        if fin and state.control_bytes:
            raise PerfError("incomplete control frame at FIN")
        return commands

    def take_control_messages(self, state: ConnectionState) -> list[object]:
        messages = []
        while True:
            message = take_control_message(state.control_bytes)
            if message is None:
                return messages
            messages.append(message)

    def handle_control_message(
        self, connection: int, state: ConnectionState, message: object, now: int
    ) -> list[ClientCommand]:
        if isinstance(message, SessionReady):
            state.session_ready = True
            self.maybe_start_timed_benchmark(now)
            return self.start_work_for_connection(connection, now)
        if isinstance(message, SessionError):
            state.control_complete = True
            raise PerfError(message.reason)
        if isinstance(message, SessionComplete):
            if not state.server_complete_counted:
                self.summary.server_counters.bytes_sent += message.bytes_sent
                self.summary.server_counters.bytes_received += message.bytes_received
                self.summary.server_counters.requests_completed += message.requests_completed
                state.server_complete_counted = True
            if self.config.mode == Mode.BULK:
                self.summary.requests_completed = (
                    self.summary.server_counters.requests_completed
                )
            state.control_complete = True
            return []
        raise PerfError("client received unexpected session_start")

    def handle_bulk_data(
        self, connection: int, stream_id: int, data: bytes, fin: bool, now: int
    ) -> list[ClientCommand]:
        commands: list[ClientCommand] = []
        state = self.connections.get(connection)
        counts = (
            state.active_bulk_streams.get(stream_id, False)
            if state is not None
            else False
        )
        within_window = now >= self.measure_started_at and now < self.measure_deadline
        if self.config.direction == Direction.DOWNLOAD and counts and within_window:
            self.summary.bytes_received += len(data)
        if not fin:
            return commands

        if state is not None:
            state.active_bulk_streams.pop(stream_id, None)
        commands.extend(self.maybe_start_bulk_streams(connection, now))
        state = self.connections.get(connection)
        if (
            self.phase == BenchmarkPhase.DRAIN
            and state is not None
            and not state.active_bulk_streams
        ):
            commands.extend(self.maybe_close_bulk_connection(connection))
        return commands

    def handle_request_response_data(
        self, connection: int, stream_id: int, data: bytes, fin: bool, now: int
    ) -> list[ClientCommand]:
        commands: list[ClientCommand] = []
        state = self.connections.get(connection)
        request = (
            state.outstanding_requests.get(stream_id) if state is not None else None
        )
        if request is None:
            return commands
        if request.counts_toward_measurement:
            self.summary.bytes_received += len(data)
        if fin:
            commands.extend(
                self.finish_request_response_stream(
                    connection, stream_id, state, request, now
                )
            )
        return commands

    def finish_request_response_stream(
        self,
        connection: int,
        stream_id: int,
        state: ConnectionState,
        request: OutstandingRequest,
        now: int,
    ) -> list[ClientCommand]:
        if request.counts_toward_measurement:
            self.summary.latency_samples.append((now - request.started_at) / 1_000_000)
            self.summary.requests_completed += 1
        state.outstanding_requests.pop(stream_id, None)
        if self.config.mode == Mode.RR:
            if self.phase == BenchmarkPhase.DRAIN and not state.outstanding_requests:
                return self.maybe_close_rr_connection(connection)
            return self.maybe_issue_rr_requests(connection, now)
        if not state.close_requested:
            return self.close_connection(connection, b"done")
        return []

    def execute_command(self, command: ClientCommand, now: int) -> coquic.QueryResult:
        if isinstance(command, OpenConnectionCommand):
            config = self.make_client_config(self.next_connection_index)
            self.next_connection_index += 1
            config.initial_route_handle = self.primary_route
            config.address_validation_identity = self.primary_identity
            return self.endpoint.connect(config, now).result
        if isinstance(command, SendStreamCommand):
            return (
                self.endpoint.connection(command.connection)
                .stream(command.stream_id)
                .send(command.bytes, command.fin, now)
            )
        self.closing_connections.add(command.connection)
        return self.endpoint.connection(command.connection).close(
            0, command.reason, now
        )

    def start_work_for_connection(
        self, connection: int, now: int
    ) -> list[ClientCommand]:
        commands: list[ClientCommand] = []
        commands.extend(self.maybe_start_bulk_streams(connection, now))
        commands.extend(self.maybe_issue_rr_requests(connection, now))
        commands.extend(self.maybe_issue_crr_request(connection, now))
        return commands

    def maybe_start_bulk_streams(
        self, connection: int, _now: int
    ) -> list[ClientCommand]:
        commands: list[ClientCommand] = []
        if self.config.mode != Mode.BULK:
            return commands
        state = self.connections.get(connection)
        if state is None or not state.session_ready or state.control_complete:
            return commands

        if self.timed_bulk_mode():
            if self.phase == BenchmarkPhase.DRAIN:
                return commands
            while (
                len(state.active_bulk_streams) < self.config.streams
                and self.benchmark_accepts_new_work()
            ):
                commands.extend(
                    self.open_bulk_stream(
                        connection,
                        self.phase == BenchmarkPhase.MEASURE,
                    )
                )
            return commands

        if state.next_stream_id != FIRST_DATA_STREAM_ID:
            return commands

        total_bytes = self.config.total_bytes or 0
        per_stream = total_bytes // self.config.streams
        remainder = total_bytes % self.config.streams
        for index in range(self.config.streams):
            stream_id = self.next_stream_id(connection)
            target_bytes = per_stream + (1 if index < remainder else 0)
            payload = b""
            if self.config.direction == Direction.UPLOAD:
                self.summary.bytes_sent += target_bytes
                payload = make_payload(target_bytes)
            commands.append(SendStreamCommand(connection, stream_id, payload, True))
        return commands

    def open_bulk_stream(
        self, connection: int, counts_toward_measurement: bool
    ) -> list[ClientCommand]:
        stream_id = self.next_stream_id(connection)
        state = self.connections.get(connection)
        if state is None:
            raise PerfError("bulk stream for unknown connection")
        state.active_bulk_streams[stream_id] = counts_toward_measurement
        payload = b""
        if self.config.direction == Direction.UPLOAD:
            payload = make_payload(max(self.config.request_bytes, self.config.response_bytes))
            if counts_toward_measurement:
                self.summary.bytes_sent += len(payload)
        return [SendStreamCommand(connection, stream_id, payload, True)]

    def maybe_issue_rr_requests(self, connection: int, now: int) -> list[ClientCommand]:
        commands: list[ClientCommand] = []
        if self.config.mode != Mode.RR or not self.benchmark_accepts_new_work():
            return commands
        state = self.connections.get(connection)
        if state is None or not state.session_ready or state.control_complete:
            return commands

        while len(state.outstanding_requests) < self.config.requests_in_flight and (
            self.config.requests is None or self.requests_started < self.config.requests
        ) and (
            state.request_limit is None
            or state.requests_started < state.request_limit
        ):
            commands.extend(self.issue_request(connection, now))
            self.requests_started += 1
        return commands

    def maybe_issue_crr_request(self, connection: int, now: int) -> list[ClientCommand]:
        commands: list[ClientCommand] = []
        if self.config.mode != Mode.CRR:
            return commands
        state = self.connections.get(connection)
        can_issue = (
            state is not None
            and state.session_ready
            and not state.control_complete
            and not state.close_requested
            and not state.outstanding_requests
        )
        if not can_issue:
            return commands
        if not self.benchmark_accepts_new_work():
            commands.extend(self.maybe_close_crr_connection(connection))
            return commands
        commands.extend(self.issue_request(connection, now))
        return commands

    def issue_request(self, connection: int, now: int) -> list[ClientCommand]:
        stream_id = self.next_stream_id(connection)
        counts = (
            self.config.requests is not None or self.phase == BenchmarkPhase.MEASURE
        )
        state = self.connections.get(connection)
        if state is None:
            raise PerfError("request for unknown connection")
        state.outstanding_requests[stream_id] = OutstandingRequest(now, counts)
        state.requests_started += 1
        if counts:
            self.summary.bytes_sent += self.config.request_bytes
        return [
            SendStreamCommand(
                connection,
                stream_id,
                make_payload(self.config.request_bytes),
                True,
            )
        ]

    async def maybe_open_crr_connections(self) -> None:
        if self.config.mode != Mode.CRR or not self.benchmark_accepts_new_work():
            return
        while len(self.connections) < self.config.connections and (
            self.config.requests is None
            or self.crr_requests_opened < self.config.requests
        ):
            now = self.io.now_us()
            result = self.execute_command(OpenConnectionCommand(), now)
            self.crr_requests_opened += 1
            await self.handle_result(result, now)

    def maybe_close_rr_connection(self, connection: int) -> list[ClientCommand]:
        force = self.timed_rr_mode() and self.phase == BenchmarkPhase.DRAIN
        state = self.connections.get(connection)
        if (
            state is None
            or state.close_requested
            or (not force and state.outstanding_requests)
        ):
            return []
        return self.close_connection(connection, b"timed rr drain complete")

    def maybe_close_bulk_connection(self, connection: int) -> list[ClientCommand]:
        state = self.connections.get(connection)
        if state is None or state.close_requested or state.active_bulk_streams:
            return []
        return self.close_connection(connection, b"timed bulk drain complete")

    def maybe_close_crr_connection(self, connection: int) -> list[ClientCommand]:
        force = self.timed_crr_mode() and self.phase == BenchmarkPhase.DRAIN
        state = self.connections.get(connection)
        if (
            state is None
            or state.close_requested
            or (not force and state.outstanding_requests)
        ):
            return []
        return self.close_connection(connection, b"timed crr drain complete")

    def close_connection(self, connection: int, reason: bytes) -> list[ClientCommand]:
        state = self.connections.get(connection)
        if state is not None:
            if state.close_requested:
                return []
            state.close_requested = True
        self.closing_connections.add(connection)
        return [CloseCommand(connection, reason)]

    async def advance_benchmark_phase(self, now: int) -> None:
        self.advance_benchmark_phase_sync(now)
        if self.phase == BenchmarkPhase.MEASURE and now >= self.measure_deadline:
            await self.enter_drain_phase(now)
        await self.force_close_timed_bulk_drain(now)

    def advance_benchmark_phase_sync(self, now: int) -> None:
        if self.benchmark_started_at is None or not self.timed_mode():
            return
        if (
            self.phase == BenchmarkPhase.WARMUP
            and now - self.benchmark_started_at >= duration_us(self.config.warmup)
        ):
            self.enter_measure_phase(now)

    async def force_close_timed_bulk_drain(self, now: int) -> None:
        if (
            not self.timed_bulk_mode()
            or self.phase != BenchmarkPhase.DRAIN
            or self.drain_deadline is None
            or now < self.drain_deadline
        ):
            return

        for handle in list(self.connections.keys()):
            state = self.connections.get(handle)
            if state is not None:
                state.active_bulk_streams.clear()
            for command in self.maybe_close_bulk_connection(handle):
                result = self.execute_command(command, now)
                await self.handle_result(result, now)

    def maybe_start_timed_benchmark(self, now: int) -> None:
        if not self.timed_mode() or self.benchmark_started_at is not None:
            return
        self.benchmark_started_at = now
        self.run_started_at = now
        self.measure_started_at = now
        self.phase = BenchmarkPhase.WARMUP
        if self.config.warmup == 0:
            self.enter_measure_phase(now)

    def enter_measure_phase(self, now: int) -> None:
        self.phase = BenchmarkPhase.MEASURE
        self.measure_started_at = now
        self.measure_deadline = now + duration_us(self.config.duration)
        reset_measurement(self.summary)
        for state in self.connections.values():
            for request in state.outstanding_requests.values():
                request.counts_toward_measurement = False
            for stream_id in list(state.active_bulk_streams.keys()):
                state.active_bulk_streams[stream_id] = True

    async def enter_drain_phase(self, now: int) -> None:
        if self.phase == BenchmarkPhase.DRAIN:
            return
        self.phase = BenchmarkPhase.DRAIN
        self.summary.elapsed_ms = duration_millis(self.result_elapsed_seconds(now))
        if self.timed_bulk_mode():
            self.drain_deadline = now + duration_us(
                min(self.config.duration, DRAIN_TIMEOUT)
            )

        for handle in list(self.connections.keys()):
            if self.config.mode == Mode.RR:
                commands = self.maybe_close_rr_connection(handle)
            elif self.config.mode == Mode.CRR:
                commands = self.maybe_close_crr_connection(handle)
            elif self.timed_bulk_mode():
                commands = self.maybe_close_bulk_connection(handle)
            else:
                commands = []
            for command in commands:
                result = self.execute_command(command, now)
                await self.handle_result(result, now)

    def timed_rr_mode(self) -> bool:
        return self.config.mode == Mode.RR and self.config.requests is None

    def timed_crr_mode(self) -> bool:
        return self.config.mode == Mode.CRR and self.config.requests is None

    def timed_bulk_mode(self) -> bool:
        return self.config.mode == Mode.BULK and self.config.total_bytes is None

    def timed_mode(self) -> bool:
        return (
            self.timed_rr_mode()
            or self.timed_crr_mode()
            or self.timed_bulk_mode()
        )

    def benchmark_accepts_new_work(self) -> bool:
        return self.phase != BenchmarkPhase.DRAIN

    def benchmark_next_wakeup(self) -> int | None:
        if not self.timed_mode() or self.benchmark_started_at is None:
            return None
        if self.phase == BenchmarkPhase.WARMUP:
            return self.benchmark_started_at + duration_us(self.config.warmup)
        if self.phase == BenchmarkPhase.MEASURE:
            return self.measure_deadline
        if self.timed_bulk_mode():
            return self.drain_deadline
        return None

    def next_wait_wakeup(self, core_next_wakeup: int | None) -> int | None:
        benchmark = self.benchmark_next_wakeup()
        values = [value for value in (core_next_wakeup, benchmark) if value is not None]
        return min(values) if values else None

    def result_elapsed_seconds(self, now: int) -> float:
        if self.timed_mode():
            if self.phase == BenchmarkPhase.WARMUP:
                return 0.0
            measurement_now = (
                self.measure_deadline if self.phase == BenchmarkPhase.DRAIN else now
            )
            return max(measurement_now - self.measure_started_at, 0) / 1_000_000.0
        return max(now - self.run_started_at, 0) / 1_000_000.0

    def run_complete(self) -> bool:
        if self.config.mode != Mode.CRR and not self.connections:
            return False

        if self.config.mode == Mode.BULK:
            if self.timed_bulk_mode():
                return self.phase == BenchmarkPhase.DRAIN and all(
                    state.close_requested and not state.active_bulk_streams
                    for state in self.connections.values()
                )
            control_complete = all(
                state.control_complete for state in self.connections.values()
            )
            if not control_complete:
                return False
            if self.config.total_bytes is not None:
                if self.config.direction == Direction.DOWNLOAD:
                    return self.summary.bytes_received >= self.config.total_bytes
                return self.summary.bytes_sent >= self.config.total_bytes
            return True

        if self.config.mode == Mode.RR:
            if self.timed_rr_mode():
                return self.phase == BenchmarkPhase.DRAIN and all(
                    state.close_requested for state in self.connections.values()
                )
            return (
                self.config.requests is not None
                and self.summary.requests_completed >= self.config.requests
                and all(
                    state.control_complete and not state.outstanding_requests
                    for state in self.connections.values()
                )
            )

        if self.timed_crr_mode():
            return self.phase == BenchmarkPhase.DRAIN and all(
                state.close_requested for state in self.connections.values()
            )
        return (
            self.config.requests is not None
            and self.summary.requests_completed >= self.config.requests
            and not self.connections
        )

    def initial_connection_target(self) -> int:
        if self.config.mode == Mode.CRR:
            return 0
        return rr_connection_target(self.config)

    def make_client_config(self, index: int) -> coquic.quic.ClientConfig:
        sequence = index + 1
        config = coquic.quic.ClientConfig.new(
            make_connection_id(0xC1, sequence),
            make_connection_id(0x83, 0x40 + sequence),
        )
        config.core.server_name = self.config.server_name.encode()
        return config

    def make_session_start(self, request_limit: int | None = None) -> SessionStart:
        return SessionStart(
            protocol_version=PROTOCOL_VERSION,
            mode=self.config.mode,
            direction=self.config.direction,
            request_bytes=self.config.request_bytes,
            response_bytes=self.config.response_bytes,
            total_bytes=self.config.total_bytes,
            requests=request_limit if request_limit is not None else self.config.requests,
            warmup=self.config.warmup,
            duration=self.config.duration,
            streams=self.config.streams,
            connections=self.config.connections,
            requests_in_flight=self.config.requests_in_flight,
        )

    def next_stream_id(self, connection: int) -> int:
        state = self.connections.get(connection)
        if state is None:
            raise PerfError("unknown connection")
        stream_id = state.next_stream_id
        state.next_stream_id = next_client_stream_id(stream_id)
        return stream_id


def make_payload(size: int) -> bytes:
    return b"\x5a" * size


def request_limit_for_connection(config: PerfConfig, connection_index: int) -> int | None:
    if config.mode != Mode.RR or config.requests is None:
        return None
    connections = rr_connection_target(config)
    base = config.requests // connections
    remainder = config.requests % connections
    return base + (1 if connection_index < remainder else 0)


def rr_connection_target(config: PerfConfig) -> int:
    if config.mode == Mode.RR and config.requests is not None:
        return min(config.connections, config.requests)
    return config.connections


def make_connection_id(prefix: int, sequence: int) -> bytes:
    value = bytearray(8)
    value[0] = prefix
    for index in range(1, len(value)):
        shift = (len(value) - 1 - index) * 8
        value[index] = (sequence >> shift) & 0xFF
    return bytes(value)


def duration_us(seconds: float) -> int:
    return min(int(seconds * 1_000_000), (1 << 64) - 1)

use crate::config::{client_endpoint_config, Direction, Mode, PerfConfig};
use crate::io::{OwnedEffect, UdpRuntime, WaitEvent};
use crate::metrics::{
    duration_millis, finalize_summary, new_run_summary, reset_measurement, RunSummary,
    ServerCounters,
};
use crate::protocol::{
    encode_control_message, next_client_stream_id, take_control_message, ControlMessage,
    SessionComplete, SessionError, SessionStart, CONTROL_STREAM_ID, FIRST_DATA_STREAM_ID,
    PROTOCOL_VERSION,
};
use crate::{PerfError, Result};
use coquic::quic::{ClientConfig, Endpoint};
use coquic::{ConnectionHandle, Lifecycle, QueryResult, StateChange, StreamId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

const IDLE_TIMEOUT: Duration = Duration::from_millis(1000);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BenchmarkPhase {
    Warmup,
    Measure,
    Drain,
}

#[derive(Clone, Debug)]
struct OutstandingRequest {
    started_at: u64,
    counts_toward_measurement: bool,
}

#[derive(Clone, Debug)]
struct ConnectionState {
    session_ready: bool,
    control_complete: bool,
    close_requested: bool,
    control_bytes: Vec<u8>,
    outstanding_requests: HashMap<StreamId, OutstandingRequest>,
    persistent_rr_outstanding_requests: VecDeque<OutstandingRequest>,
    active_bulk_streams: HashMap<StreamId, bool>,
    next_stream_id: StreamId,
    persistent_rr_stream_id: Option<StreamId>,
    persistent_rr_fin_sent: bool,
    persistent_rr_response_pending_bytes: u64,
    request_limit: Option<usize>,
    requests_started: usize,
    server_complete_counted: bool,
}

impl ConnectionState {
    fn new(_handle: ConnectionHandle, request_limit: Option<usize>) -> Self {
        Self {
            session_ready: false,
            control_complete: false,
            close_requested: false,
            control_bytes: Vec::new(),
            outstanding_requests: HashMap::new(),
            persistent_rr_outstanding_requests: VecDeque::new(),
            active_bulk_streams: HashMap::new(),
            next_stream_id: FIRST_DATA_STREAM_ID,
            persistent_rr_stream_id: None,
            persistent_rr_fin_sent: false,
            persistent_rr_response_pending_bytes: 0,
            request_limit,
            requests_started: 0,
            server_complete_counted: false,
        }
    }
}

enum ClientCommand {
    OpenConnection,
    SendStream {
        connection: ConnectionHandle,
        stream_id: StreamId,
        bytes: Vec<u8>,
        fin: bool,
    },
    Close {
        connection: ConnectionHandle,
        reason: &'static [u8],
    },
}

enum ClientWork {
    Result(QueryResult),
    Command(ClientCommand),
}

pub async fn run_client(config: PerfConfig) -> Result<RunSummary> {
    let endpoint_config = client_endpoint_config(&config);
    let mut endpoint = Endpoint::new(&endpoint_config)?;
    let (mut io, primary_route, primary_identity) =
        UdpRuntime::client(&config.host, config.port, config.max_outbound_datagram_size).await?;
    let mut client = Client {
        config: config.clone(),
        endpoint: &mut endpoint,
        io: &mut io,
        primary_route,
        primary_identity,
        connections: HashMap::new(),
        closing_connections: HashSet::new(),
        closed_connections: HashSet::new(),
        requests_started: 0,
        crr_requests_opened: 0,
        next_connection_index: 0,
        phase: BenchmarkPhase::Warmup,
        run_started_at: 0,
        benchmark_started_at: None,
        measure_started_at: 0,
        measure_deadline: 0,
        drain_deadline: None,
        summary: new_run_summary(&config),
    };

    client.run().await
}

struct Client<'a> {
    config: PerfConfig,
    endpoint: &'a mut Endpoint,
    io: &'a mut UdpRuntime,
    primary_route: coquic::RouteHandle,
    primary_identity: Vec<u8>,
    connections: HashMap<ConnectionHandle, ConnectionState>,
    closing_connections: HashSet<ConnectionHandle>,
    closed_connections: HashSet<ConnectionHandle>,
    requests_started: usize,
    crr_requests_opened: usize,
    next_connection_index: u64,
    phase: BenchmarkPhase,
    run_started_at: u64,
    benchmark_started_at: Option<u64>,
    measure_started_at: u64,
    measure_deadline: u64,
    drain_deadline: Option<u64>,
    summary: RunSummary,
}

impl Client<'_> {
    async fn run(&mut self) -> Result<RunSummary> {
        let start = self.io.now_us();
        self.run_started_at = start;
        self.measure_started_at = start;
        self.phase = BenchmarkPhase::Warmup;
        if !self.timed_mode() {
            self.benchmark_started_at = Some(start);
        }

        for _ in 0..self.initial_connection_target() {
            if let Some(result) = self.execute_command(ClientCommand::OpenConnection, start)? {
                self.handle_result(result, start).await?;
            }
        }

        loop {
            let now = self.io.now_us();
            self.advance_benchmark_phase(now).await?;

            if self.run_complete() {
                self.io.flush_sends().await?;
                if self.timed_bulk_mode()
                    && self.config.direction == Direction::Download
                    && self.config.response_bytes > 0
                    && self.summary.bytes_received == 0
                {
                    return Err(PerfError::new("timed bulk download measured zero bytes"));
                }
                self.summary.status = "ok".to_owned();
                self.summary.elapsed_ms = duration_millis(self.result_elapsed(now));
                if self.timed_rr_mode() || self.timed_persistent_rr_mode() || self.timed_crr_mode()
                {
                    self.summary.server_counters = ServerCounters {
                        bytes_sent: self.summary.bytes_received,
                        bytes_received: self.summary.bytes_sent,
                        requests_completed: self.summary.requests_completed,
                    };
                }
                finalize_summary(&mut self.summary);
                return Ok(self.summary.clone());
            }

            self.handle_due_timer().await?;
            self.maybe_open_crr_connections(self.io.now_us()).await?;
            self.io.flush_sends().await?;

            match self
                .io
                .wait(
                    self.next_wait_wakeup(self.endpoint.next_wakeup()),
                    IDLE_TIMEOUT,
                )
                .await?
            {
                WaitEvent::Datagram(datagram) => {
                    let now = self.io.now_us();
                    self.advance_benchmark_phase(now).await?;
                    let inbound = self.io.inbound_datagram(&datagram);
                    let result = self.endpoint.receive_datagram(inbound, now)?;
                    self.handle_result(result, now).await?;
                }
                WaitEvent::Timer => {
                    let now = self.io.now_us();
                    self.advance_benchmark_phase(now).await?;
                    self.handle_due_timer().await?;
                }
                WaitEvent::Idle => {
                    return Err(PerfError::new("client timed out waiting for progress"));
                }
            }
        }
    }

    async fn handle_due_timer(&mut self) -> Result<()> {
        loop {
            let Some(wakeup) = self.endpoint.next_wakeup() else {
                return Ok(());
            };
            let now = self.io.now_us();
            if wakeup > now {
                return Ok(());
            }
            let result = self.endpoint.timer_expired(now)?;
            self.handle_result(result, now).await?;
        }
    }

    async fn handle_result(&mut self, result: QueryResult, now: u64) -> Result<()> {
        let mut pending_work = vec![ClientWork::Result(result)];
        while let Some(work) = pending_work.pop() {
            match work {
                ClientWork::Result(result) => {
                    let commands = self.collect_result_commands(result, now)?;
                    pending_work.extend(commands.into_iter().rev().map(ClientWork::Command));
                }
                ClientWork::Command(command) => {
                    if let Some(result) = self.execute_command(command, now)? {
                        pending_work.push(ClientWork::Result(result));
                    }
                }
            }
        }
        self.io.flush_sends().await?;
        Ok(())
    }

    fn collect_result_commands(
        &mut self,
        result: QueryResult,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        self.advance_benchmark_phase_sync(now);
        if let Some(error) = result.local_error()? {
            self.summary.failure_reason = Some(format!("client local error: {error:?}"));
            return Err(PerfError::new(
                self.summary.failure_reason.clone().unwrap_or_default(),
            ));
        }

        let effects = self.io.collect_result_effects(&result)?;
        drop(result);

        let mut commands = Vec::new();
        for effect in effects {
            match effect {
                OwnedEffect::ConnectionLifecycleEvent { connection, event } => match event {
                    Lifecycle::Created => {
                        let connection_index = self.connections.len();
                        let request_limit =
                            request_limit_for_connection(&self.config, connection_index);
                        self.connections
                            .entry(connection)
                            .or_insert_with(|| ConnectionState::new(connection, request_limit));
                    }
                    Lifecycle::Closed => {
                        self.closed_connections.insert(connection);
                        if self.config.mode == Mode::Crr {
                            self.connections.remove(&connection);
                        } else if let Some(state) = self.connections.get_mut(&connection) {
                            state.control_complete = true;
                        }
                    }
                    Lifecycle::Accepted | Lifecycle::Unknown(_) => {}
                },
                OwnedEffect::StateEvent { connection, change } => match change {
                    StateChange::Failed if !self.closing_connections.contains(&connection) => {
                        return Err(PerfError::new(format!(
                            "client core state failed connection={connection}"
                        )));
                    }
                    StateChange::HandshakeReady => {
                        if self.connections.contains_key(&connection) {
                            let request_limit = self
                                .connections
                                .get(&connection)
                                .and_then(|state| state.request_limit);
                            commands.push(ClientCommand::SendStream {
                                connection,
                                stream_id: CONTROL_STREAM_ID,
                                bytes: encode_control_message(&ControlMessage::SessionStart(
                                    self.make_session_start(request_limit),
                                )),
                                fin: true,
                            });
                        }
                    }
                    _ => {}
                },
                OwnedEffect::ReceiveStreamData {
                    connection,
                    stream_id,
                    bytes,
                    fin,
                } => {
                    commands
                        .extend(self.handle_stream_data(connection, stream_id, bytes, fin, now)?);
                }
                OwnedEffect::PeerResetStream { .. } | OwnedEffect::PeerStopSending { .. } => {}
            }
        }

        Ok(commands)
    }

    fn handle_stream_data(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        bytes: Vec<u8>,
        fin: bool,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        if stream_id == CONTROL_STREAM_ID {
            let (messages, incomplete_at_fin) = {
                let state = self
                    .connections
                    .get_mut(&connection)
                    .ok_or_else(|| PerfError::new("control data for unknown connection"))?;
                state.control_bytes.extend_from_slice(&bytes);
                let mut messages = Vec::new();
                while let Some(message) = take_control_message(&mut state.control_bytes) {
                    messages.push(message);
                }
                let incomplete_at_fin = fin && !state.control_bytes.is_empty();
                (messages, incomplete_at_fin)
            };

            for message in messages {
                match message {
                    ControlMessage::SessionReady(_) => {
                        if let Some(state) = self.connections.get_mut(&connection) {
                            state.session_ready = true;
                        }
                        self.maybe_start_timed_benchmark(now);
                        commands.extend(self.start_work_for_connection(connection, now)?);
                    }
                    ControlMessage::SessionError(SessionError { reason }) => {
                        if let Some(state) = self.connections.get_mut(&connection) {
                            state.control_complete = true;
                        }
                        return Err(PerfError::new(reason));
                    }
                    ControlMessage::SessionComplete(SessionComplete {
                        bytes_sent,
                        bytes_received,
                        requests_completed,
                    }) => {
                        if let Some(state) = self.connections.get_mut(&connection) {
                            if !state.server_complete_counted {
                                self.summary.server_counters.bytes_sent += bytes_sent;
                                self.summary.server_counters.bytes_received += bytes_received;
                                self.summary.server_counters.requests_completed +=
                                    requests_completed;
                                state.server_complete_counted = true;
                            }
                            if self.config.mode == Mode::Bulk {
                                self.summary.requests_completed =
                                    self.summary.server_counters.requests_completed;
                            }
                            state.control_complete = true;
                        }
                    }
                    ControlMessage::SessionStart(_) => {
                        return Err(PerfError::new("client received unexpected session_start"));
                    }
                }
            }

            if incomplete_at_fin {
                return Err(PerfError::new("incomplete control frame at FIN"));
            }
            return Ok(commands);
        }

        if self.timed_bulk_mode() {
            let counts = self
                .connections
                .get(&connection)
                .and_then(|state| state.active_bulk_streams.get(&stream_id).copied())
                .unwrap_or(false);
            let within_measurement_window =
                now >= self.measure_started_at && now < self.measure_deadline;
            if self.config.direction == Direction::Download && counts && within_measurement_window {
                self.summary.bytes_received += bytes.len() as u64;
            }
            if fin {
                if let Some(state) = self.connections.get_mut(&connection) {
                    state.active_bulk_streams.remove(&stream_id);
                }
                commands.extend(self.maybe_start_bulk_streams(connection, now)?);
                if self.phase == BenchmarkPhase::Drain
                    && self
                        .connections
                        .get(&connection)
                        .map(|state| state.active_bulk_streams.is_empty())
                        .unwrap_or(false)
                {
                    commands.extend(self.maybe_close_bulk_connection(connection)?);
                }
            }
            return Ok(commands);
        }

        if self.config.mode == Mode::PersistentRr {
            let Some(state) = self.connections.get_mut(&connection) else {
                return Ok(commands);
            };
            if state.persistent_rr_stream_id != Some(stream_id) {
                return Ok(commands);
            }
            state.persistent_rr_response_pending_bytes = state
                .persistent_rr_response_pending_bytes
                .saturating_add(bytes.len() as u64);
            let response_bytes = self.config.response_bytes as u64;
            while state.persistent_rr_response_pending_bytes >= response_bytes
                && !state.persistent_rr_outstanding_requests.is_empty()
            {
                let request = state
                    .persistent_rr_outstanding_requests
                    .pop_front()
                    .expect("checked non-empty");
                state.persistent_rr_response_pending_bytes -= response_bytes;
                if request.counts_toward_measurement {
                    self.summary.bytes_received += response_bytes;
                    self.summary.latency_samples.push(Duration::from_micros(
                        now.saturating_sub(request.started_at),
                    ));
                    self.summary.requests_completed += 1;
                }
            }
            if self.phase == BenchmarkPhase::Drain {
                if state.persistent_rr_outstanding_requests.is_empty() {
                    commands.extend(self.maybe_close_persistent_rr_connection(connection)?);
                }
                return Ok(commands);
            }
            commands.extend(self.maybe_issue_persistent_rr_requests(connection, now)?);
            return Ok(commands);
        }

        if self.config.mode == Mode::Rr || self.config.mode == Mode::Crr {
            let request = self
                .connections
                .get(&connection)
                .and_then(|state| state.outstanding_requests.get(&stream_id).cloned());
            if let Some(request) = request {
                if request.counts_toward_measurement {
                    self.summary.bytes_received += bytes.len() as u64;
                }
                if fin {
                    if request.counts_toward_measurement {
                        self.summary.latency_samples.push(Duration::from_micros(
                            now.saturating_sub(request.started_at),
                        ));
                        self.summary.requests_completed += 1;
                    }
                    if let Some(state) = self.connections.get_mut(&connection) {
                        state.outstanding_requests.remove(&stream_id);
                    }
                    if self.config.mode == Mode::Rr {
                        if self.phase == BenchmarkPhase::Drain
                            && self
                                .connections
                                .get(&connection)
                                .map(|state| state.outstanding_requests.is_empty())
                                .unwrap_or(false)
                        {
                            commands.extend(self.maybe_close_rr_connection(connection)?);
                        } else {
                            commands.extend(self.maybe_issue_rr_requests(connection, now)?);
                        }
                    } else if !self
                        .connections
                        .get(&connection)
                        .map(|state| state.close_requested)
                        .unwrap_or(true)
                    {
                        commands.extend(self.close_connection(connection, b"done")?);
                    }
                }
            }
            return Ok(commands);
        }

        self.summary.bytes_received += bytes.len() as u64;
        Ok(commands)
    }

    fn execute_command(&mut self, command: ClientCommand, now: u64) -> Result<Option<QueryResult>> {
        match command {
            ClientCommand::OpenConnection => {
                let mut config = self.make_client_config(self.next_connection_index);
                self.next_connection_index += 1;
                config.initial_route_handle = self.primary_route;
                config.address_validation_identity = self.primary_identity.clone();
                let connected = self.endpoint.connect(config, now)?;
                Ok(Some(connected.result))
            }
            ClientCommand::SendStream {
                connection,
                stream_id,
                bytes,
                fin,
            } => {
                if self.closed_connections.contains(&connection) {
                    return Ok(None);
                }
                let result = self
                    .endpoint
                    .connection(connection)
                    .stream(stream_id)
                    .send(&bytes, fin, now)?;
                Ok(Some(result))
            }
            ClientCommand::Close { connection, reason } => {
                if self.closed_connections.contains(&connection) {
                    return Ok(None);
                }
                self.closing_connections.insert(connection);
                let result = self.endpoint.connection(connection).close(0, reason, now)?;
                Ok(Some(result))
            }
        }
    }

    fn start_work_for_connection(
        &mut self,
        connection: ConnectionHandle,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        commands.extend(self.maybe_start_bulk_streams(connection, now)?);
        commands.extend(self.maybe_issue_rr_requests(connection, now)?);
        commands.extend(self.maybe_issue_persistent_rr_requests(connection, now)?);
        commands.extend(self.maybe_issue_crr_request(connection, now)?);
        Ok(commands)
    }

    fn maybe_start_bulk_streams(
        &mut self,
        connection: ConnectionHandle,
        _now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        if self.config.mode != Mode::Bulk {
            return Ok(commands);
        }
        let session_ready = self
            .connections
            .get(&connection)
            .map(|state| state.session_ready && !state.control_complete)
            .unwrap_or(false);
        if !session_ready {
            return Ok(commands);
        }

        if self.timed_bulk_mode() {
            if self.phase == BenchmarkPhase::Drain {
                return Ok(commands);
            }
            while self
                .connections
                .get(&connection)
                .map(|state| state.active_bulk_streams.len() < self.config.streams)
                .unwrap_or(false)
                && self.benchmark_accepts_new_work()
            {
                commands.extend(
                    self.open_bulk_stream(connection, self.phase == BenchmarkPhase::Measure)?,
                );
            }
            return Ok(commands);
        }

        let first_stream = self
            .connections
            .get(&connection)
            .map(|state| state.next_stream_id == FIRST_DATA_STREAM_ID)
            .unwrap_or(false);
        if !first_stream {
            return Ok(commands);
        }

        let total_bytes = self.config.total_bytes.unwrap_or(0) as u64;
        let per_stream = total_bytes / self.config.streams as u64;
        let remainder = total_bytes % self.config.streams as u64;
        for index in 0..self.config.streams {
            let stream_id = self.next_stream_id(connection)?;
            let target_bytes = per_stream + u64::from((index as u64) < remainder);
            let payload = if self.config.direction == Direction::Upload {
                self.summary.bytes_sent += target_bytes;
                make_payload(target_bytes as usize)
            } else {
                Vec::new()
            };
            commands.push(ClientCommand::SendStream {
                connection,
                stream_id,
                bytes: payload,
                fin: true,
            });
        }

        Ok(commands)
    }

    fn open_bulk_stream(
        &mut self,
        connection: ConnectionHandle,
        counts_toward_measurement: bool,
    ) -> Result<Vec<ClientCommand>> {
        let stream_id = self.next_stream_id(connection)?;
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or_else(|| PerfError::new("bulk stream for unknown connection"))?;
        state
            .active_bulk_streams
            .insert(stream_id, counts_toward_measurement);
        let payload = if self.config.direction == Direction::Upload {
            let bytes = self.config.request_bytes.max(self.config.response_bytes);
            if counts_toward_measurement {
                self.summary.bytes_sent += bytes as u64;
            }
            make_payload(bytes)
        } else {
            Vec::new()
        };
        Ok(vec![ClientCommand::SendStream {
            connection,
            stream_id,
            bytes: payload,
            fin: true,
        }])
    }

    fn maybe_issue_rr_requests(
        &mut self,
        connection: ConnectionHandle,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        if self.config.mode != Mode::Rr || !self.benchmark_accepts_new_work() {
            return Ok(commands);
        }
        let ready = self
            .connections
            .get(&connection)
            .map(|state| state.session_ready && !state.control_complete)
            .unwrap_or(false);
        if !ready {
            return Ok(commands);
        }

        while self
            .connections
            .get(&connection)
            .map(|state| state.outstanding_requests.len() < self.config.requests_in_flight)
            .unwrap_or(false)
            && self
                .config
                .requests
                .map(|requests| self.requests_started < requests)
                .unwrap_or(true)
            && self
                .connections
                .get(&connection)
                .map(|state| {
                    state
                        .request_limit
                        .map(|limit| state.requests_started < limit)
                        .unwrap_or(true)
                })
                .unwrap_or(false)
        {
            commands.extend(self.issue_request(connection, now)?);
            self.requests_started += 1;
        }

        Ok(commands)
    }

    fn maybe_issue_persistent_rr_requests(
        &mut self,
        connection: ConnectionHandle,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        if self.config.mode != Mode::PersistentRr || !self.benchmark_accepts_new_work() {
            return Ok(commands);
        }
        let ready = self
            .connections
            .get(&connection)
            .map(|state| {
                state.session_ready
                    && !state.control_complete
                    && !state.close_requested
                    && !state.persistent_rr_fin_sent
            })
            .unwrap_or(false);
        if !ready {
            return Ok(commands);
        }

        let needs_stream = self
            .connections
            .get(&connection)
            .map(|state| state.persistent_rr_stream_id.is_none())
            .unwrap_or(false);
        if needs_stream {
            let stream_id = self.next_stream_id(connection)?;
            if let Some(state) = self.connections.get_mut(&connection) {
                state.persistent_rr_stream_id = Some(stream_id);
            }
        }

        while self
            .connections
            .get(&connection)
            .map(|state| {
                state.persistent_rr_outstanding_requests.len() < self.config.requests_in_flight
            })
            .unwrap_or(false)
            && self
                .config
                .requests
                .map(|requests| self.requests_started < requests)
                .unwrap_or(true)
            && self
                .connections
                .get(&connection)
                .map(|state| {
                    state
                        .request_limit
                        .map(|limit| state.requests_started < limit)
                        .unwrap_or(true)
                })
                .unwrap_or(false)
        {
            let counts_toward_measurement =
                self.config.requests.is_some() || self.phase == BenchmarkPhase::Measure;
            let stream_id = self
                .connections
                .get(&connection)
                .and_then(|state| state.persistent_rr_stream_id)
                .ok_or_else(|| PerfError::new("persistent rr stream missing"))?;
            let state = self
                .connections
                .get_mut(&connection)
                .ok_or_else(|| PerfError::new("persistent rr request for unknown connection"))?;
            state
                .persistent_rr_outstanding_requests
                .push_back(OutstandingRequest {
                    started_at: now,
                    counts_toward_measurement,
                });
            state.requests_started += 1;
            self.requests_started += 1;
            if counts_toward_measurement {
                self.summary.bytes_sent += self.config.request_bytes as u64;
            }
            commands.push(ClientCommand::SendStream {
                connection,
                stream_id,
                bytes: make_payload(self.config.request_bytes),
                fin: false,
            });
        }

        if self.config.requests.is_some()
            && self
                .connections
                .get(&connection)
                .map(|state| {
                    state
                        .request_limit
                        .map(|limit| state.requests_started >= limit)
                        .unwrap_or(true)
                })
                .unwrap_or(false)
        {
            commands.extend(self.maybe_finish_persistent_rr_stream(connection)?);
        }

        Ok(commands)
    }

    fn maybe_issue_crr_request(
        &mut self,
        connection: ConnectionHandle,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        if self.config.mode != Mode::Crr {
            return Ok(commands);
        }
        let can_issue = self
            .connections
            .get(&connection)
            .map(|state| {
                state.session_ready
                    && !state.control_complete
                    && !state.close_requested
                    && state.outstanding_requests.is_empty()
            })
            .unwrap_or(false);
        if !can_issue {
            return Ok(commands);
        }
        if !self.benchmark_accepts_new_work() {
            commands.extend(self.maybe_close_crr_connection(connection)?);
            return Ok(commands);
        }
        commands.extend(self.issue_request(connection, now)?);
        Ok(commands)
    }

    fn issue_request(
        &mut self,
        connection: ConnectionHandle,
        now: u64,
    ) -> Result<Vec<ClientCommand>> {
        let stream_id = self.next_stream_id(connection)?;
        let counts_toward_measurement =
            self.config.requests.is_some() || self.phase == BenchmarkPhase::Measure;
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or_else(|| PerfError::new("request for unknown connection"))?;
        state.outstanding_requests.insert(
            stream_id,
            OutstandingRequest {
                started_at: now,
                counts_toward_measurement,
            },
        );
        state.requests_started += 1;
        if counts_toward_measurement {
            self.summary.bytes_sent += self.config.request_bytes as u64;
        }
        Ok(vec![ClientCommand::SendStream {
            connection,
            stream_id,
            bytes: make_payload(self.config.request_bytes),
            fin: true,
        }])
    }

    async fn maybe_open_crr_connections(&mut self, _now: u64) -> Result<()> {
        if self.config.mode != Mode::Crr || !self.benchmark_accepts_new_work() {
            return Ok(());
        }

        while self.connections.len() < self.config.connections
            && self
                .config
                .requests
                .map(|requests| self.crr_requests_opened < requests)
                .unwrap_or(true)
        {
            let now = self.io.now_us();
            self.crr_requests_opened += 1;
            if let Some(result) = self.execute_command(ClientCommand::OpenConnection, now)? {
                self.handle_result(result, now).await?;
            }
        }
        Ok(())
    }

    fn maybe_close_rr_connection(
        &mut self,
        connection: ConnectionHandle,
    ) -> Result<Vec<ClientCommand>> {
        let force_timed_drain_close = self.timed_rr_mode() && self.phase == BenchmarkPhase::Drain;
        let Some(state) = self.connections.get(&connection) else {
            return Ok(Vec::new());
        };
        if state.close_requested
            || (!force_timed_drain_close && !state.outstanding_requests.is_empty())
        {
            return Ok(Vec::new());
        }
        self.close_connection(connection, b"timed rr drain complete")
    }

    fn maybe_finish_persistent_rr_stream(
        &mut self,
        connection: ConnectionHandle,
    ) -> Result<Vec<ClientCommand>> {
        let mut commands = Vec::new();
        let Some(state) = self.connections.get_mut(&connection) else {
            return Ok(commands);
        };
        let Some(stream_id) = state.persistent_rr_stream_id else {
            if self.phase == BenchmarkPhase::Drain
                && state.persistent_rr_outstanding_requests.is_empty()
            {
                commands.extend(self.maybe_close_persistent_rr_connection(connection)?);
            }
            return Ok(commands);
        };
        if state.persistent_rr_fin_sent {
            if self.phase == BenchmarkPhase::Drain
                && state.persistent_rr_outstanding_requests.is_empty()
            {
                commands.extend(self.maybe_close_persistent_rr_connection(connection)?);
            }
            return Ok(commands);
        }

        state.persistent_rr_fin_sent = true;
        commands.push(ClientCommand::SendStream {
            connection,
            stream_id,
            bytes: Vec::new(),
            fin: true,
        });
        if self.phase == BenchmarkPhase::Drain
            && state.persistent_rr_outstanding_requests.is_empty()
        {
            commands.extend(self.maybe_close_persistent_rr_connection(connection)?);
        }
        Ok(commands)
    }

    fn maybe_close_persistent_rr_connection(
        &mut self,
        connection: ConnectionHandle,
    ) -> Result<Vec<ClientCommand>> {
        let force_timed_drain_close =
            self.timed_persistent_rr_mode() && self.phase == BenchmarkPhase::Drain;
        let Some(state) = self.connections.get(&connection) else {
            return Ok(Vec::new());
        };
        if state.close_requested
            || (!force_timed_drain_close && !state.persistent_rr_outstanding_requests.is_empty())
        {
            return Ok(Vec::new());
        }
        if !state.persistent_rr_fin_sent {
            return self.maybe_finish_persistent_rr_stream(connection);
        }
        self.close_connection(connection, b"persistent rr drain complete")
    }

    fn maybe_close_bulk_connection(
        &mut self,
        connection: ConnectionHandle,
    ) -> Result<Vec<ClientCommand>> {
        let Some(state) = self.connections.get(&connection) else {
            return Ok(Vec::new());
        };
        if state.close_requested || !state.active_bulk_streams.is_empty() {
            return Ok(Vec::new());
        }
        self.close_connection(connection, b"timed bulk drain complete")
    }

    fn maybe_close_crr_connection(
        &mut self,
        connection: ConnectionHandle,
    ) -> Result<Vec<ClientCommand>> {
        let force_timed_drain_close = self.timed_crr_mode() && self.phase == BenchmarkPhase::Drain;
        let Some(state) = self.connections.get(&connection) else {
            return Ok(Vec::new());
        };
        if state.close_requested
            || (!force_timed_drain_close && !state.outstanding_requests.is_empty())
        {
            return Ok(Vec::new());
        }
        self.close_connection(connection, b"timed crr drain complete")
    }

    fn close_connection(
        &mut self,
        connection: ConnectionHandle,
        reason: &'static [u8],
    ) -> Result<Vec<ClientCommand>> {
        if let Some(state) = self.connections.get_mut(&connection) {
            if state.close_requested {
                return Ok(Vec::new());
            }
            state.close_requested = true;
        }
        self.closing_connections.insert(connection);
        Ok(vec![ClientCommand::Close { connection, reason }])
    }

    async fn advance_benchmark_phase(&mut self, now: u64) -> Result<()> {
        self.advance_benchmark_phase_sync(now);
        if self.phase == BenchmarkPhase::Measure && now >= self.measure_deadline {
            self.enter_drain_phase(now).await?;
        }
        self.force_close_timed_bulk_drain(now).await?;
        Ok(())
    }

    fn advance_benchmark_phase_sync(&mut self, now: u64) {
        let Some(benchmark_started_at) = self.benchmark_started_at else {
            return;
        };
        if !self.timed_mode() {
            return;
        }
        if self.phase == BenchmarkPhase::Warmup
            && now.saturating_sub(benchmark_started_at) >= duration_us(self.config.warmup)
        {
            self.enter_measure_phase(now);
        }
    }

    async fn force_close_timed_bulk_drain(&mut self, now: u64) -> Result<()> {
        if !self.timed_bulk_mode() || self.phase != BenchmarkPhase::Drain {
            return Ok(());
        }
        if !self
            .drain_deadline
            .map(|deadline| now >= deadline)
            .unwrap_or(false)
        {
            return Ok(());
        }

        let handles: Vec<_> = self.connections.keys().copied().collect();
        for handle in handles {
            if let Some(state) = self.connections.get_mut(&handle) {
                state.active_bulk_streams.clear();
            }
            for command in self.maybe_close_bulk_connection(handle)? {
                if let Some(result) = self.execute_command(command, now)? {
                    self.handle_result(result, now).await?;
                }
            }
        }
        Ok(())
    }

    fn maybe_start_timed_benchmark(&mut self, now: u64) {
        if !self.timed_mode() || self.benchmark_started_at.is_some() {
            return;
        }
        self.benchmark_started_at = Some(now);
        self.run_started_at = now;
        self.measure_started_at = now;
        self.phase = BenchmarkPhase::Warmup;
        if self.config.warmup == Duration::ZERO {
            self.enter_measure_phase(now);
        }
    }

    fn enter_measure_phase(&mut self, now: u64) {
        self.phase = BenchmarkPhase::Measure;
        self.measure_started_at = now;
        self.measure_deadline = now.saturating_add(duration_us(self.config.duration));
        reset_measurement(&mut self.summary);
        for state in self.connections.values_mut() {
            for request in state.outstanding_requests.values_mut() {
                request.counts_toward_measurement = false;
            }
            for request in &mut state.persistent_rr_outstanding_requests {
                request.counts_toward_measurement = false;
            }
            for counts in state.active_bulk_streams.values_mut() {
                *counts = true;
            }
        }
    }

    async fn enter_drain_phase(&mut self, now: u64) -> Result<()> {
        if self.phase == BenchmarkPhase::Drain {
            return Ok(());
        }
        self.phase = BenchmarkPhase::Drain;
        self.summary.elapsed_ms = duration_millis(self.result_elapsed(now));
        if self.timed_bulk_mode() {
            self.drain_deadline =
                Some(now.saturating_add(duration_us(self.config.duration.min(DRAIN_TIMEOUT))));
        }

        let handles: Vec<_> = self.connections.keys().copied().collect();
        for handle in handles {
            let commands = if self.config.mode == Mode::Rr {
                self.maybe_close_rr_connection(handle)?
            } else if self.config.mode == Mode::PersistentRr {
                self.maybe_finish_persistent_rr_stream(handle)?
            } else if self.config.mode == Mode::Crr {
                self.maybe_close_crr_connection(handle)?
            } else if self.timed_bulk_mode() {
                self.maybe_close_bulk_connection(handle)?
            } else {
                Vec::new()
            };
            for command in commands {
                if let Some(result) = self.execute_command(command, now)? {
                    self.handle_result(result, now).await?;
                }
            }
        }
        Ok(())
    }

    fn timed_rr_mode(&self) -> bool {
        self.config.mode == Mode::Rr && self.config.requests.is_none()
    }

    fn timed_persistent_rr_mode(&self) -> bool {
        self.config.mode == Mode::PersistentRr && self.config.requests.is_none()
    }

    fn timed_crr_mode(&self) -> bool {
        self.config.mode == Mode::Crr && self.config.requests.is_none()
    }

    fn timed_bulk_mode(&self) -> bool {
        self.config.mode == Mode::Bulk && self.config.total_bytes.is_none()
    }

    fn timed_mode(&self) -> bool {
        self.timed_rr_mode()
            || self.timed_persistent_rr_mode()
            || self.timed_crr_mode()
            || self.timed_bulk_mode()
    }

    fn benchmark_accepts_new_work(&self) -> bool {
        self.phase != BenchmarkPhase::Drain
    }

    fn benchmark_next_wakeup(&self) -> Option<u64> {
        if !self.timed_mode() || self.benchmark_started_at.is_none() {
            return None;
        }
        match self.phase {
            BenchmarkPhase::Warmup => self
                .benchmark_started_at
                .map(|started| started.saturating_add(duration_us(self.config.warmup))),
            BenchmarkPhase::Measure => Some(self.measure_deadline),
            BenchmarkPhase::Drain => {
                if self.timed_bulk_mode() {
                    self.drain_deadline
                } else {
                    None
                }
            }
        }
    }

    fn next_wait_wakeup(&self, core_next_wakeup: Option<u64>) -> Option<u64> {
        match (core_next_wakeup, self.benchmark_next_wakeup()) {
            (Some(core), Some(benchmark)) => Some(core.min(benchmark)),
            (Some(core), None) => Some(core),
            (None, Some(benchmark)) => Some(benchmark),
            (None, None) => None,
        }
    }

    fn result_elapsed(&self, now: u64) -> Duration {
        if self.timed_mode() {
            if self.phase == BenchmarkPhase::Warmup {
                return Duration::ZERO;
            }
            let measurement_now = if self.phase == BenchmarkPhase::Drain {
                self.measure_deadline
            } else {
                now
            };
            return Duration::from_micros(measurement_now.saturating_sub(self.measure_started_at));
        }
        Duration::from_micros(now.saturating_sub(self.run_started_at))
    }

    fn run_complete(&self) -> bool {
        if self.config.mode != Mode::Crr && self.connections.is_empty() {
            return false;
        }

        match self.config.mode {
            Mode::Bulk => {
                if self.timed_bulk_mode() {
                    return self.phase == BenchmarkPhase::Drain
                        && self.connections.values().all(|state| {
                            state.close_requested && state.active_bulk_streams.is_empty()
                        });
                }
                let control_complete = self
                    .connections
                    .values()
                    .all(|state| state.control_complete);
                if !control_complete {
                    return false;
                }
                if let Some(total_bytes) = self.config.total_bytes {
                    if self.config.direction == Direction::Download {
                        return self.summary.bytes_received >= total_bytes as u64;
                    }
                    return self.summary.bytes_sent >= total_bytes as u64;
                }
                true
            }
            Mode::Rr => {
                if self.timed_rr_mode() {
                    return self.phase == BenchmarkPhase::Drain
                        && self.connections.values().all(|state| state.close_requested);
                }
                self.config
                    .requests
                    .map(|requests| self.summary.requests_completed >= requests as u64)
                    .unwrap_or(false)
                    && self.connections.values().all(|state| {
                        state.control_complete && state.outstanding_requests.is_empty()
                    })
            }
            Mode::PersistentRr => {
                if self.timed_persistent_rr_mode() {
                    return self.phase == BenchmarkPhase::Drain
                        && self.connections.values().all(|state| state.close_requested);
                }
                self.config
                    .requests
                    .map(|requests| self.summary.requests_completed >= requests as u64)
                    .unwrap_or(false)
                    && self.connections.values().all(|state| {
                        state.control_complete
                            && state.persistent_rr_outstanding_requests.is_empty()
                    })
            }
            Mode::Crr => {
                if self.timed_crr_mode() {
                    return self.phase == BenchmarkPhase::Drain
                        && self.connections.values().all(|state| state.close_requested);
                }
                self.config
                    .requests
                    .map(|requests| {
                        self.summary.requests_completed >= requests as u64
                            && self.connections.is_empty()
                    })
                    .unwrap_or(false)
            }
        }
    }

    fn initial_connection_target(&self) -> usize {
        if self.config.mode == Mode::Crr {
            0
        } else {
            rr_connection_target(&self.config)
        }
    }

    fn make_client_config(&self, index: u64) -> ClientConfig {
        let id = index + 1;
        let mut config = ClientConfig::new(
            make_connection_id(0xc1, id),
            make_connection_id(0x83, 0x40 + id),
        );
        config.core.server_name = self.config.server_name.as_bytes().to_vec();
        config
    }

    fn make_session_start(&self, request_limit: Option<usize>) -> SessionStart {
        SessionStart {
            protocol_version: PROTOCOL_VERSION,
            mode: self.config.mode,
            direction: self.config.direction,
            request_bytes: self.config.request_bytes as u64,
            response_bytes: self.config.response_bytes as u64,
            total_bytes: self.config.total_bytes.map(|value| value as u64),
            requests: request_limit
                .or(self.config.requests)
                .map(|value| value as u64),
            warmup: self.config.warmup,
            duration: self.config.duration,
            streams: self.config.streams as u64,
            connections: self.config.connections as u64,
            requests_in_flight: self.config.requests_in_flight as u64,
        }
    }

    fn next_stream_id(&mut self, connection: ConnectionHandle) -> Result<StreamId> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or_else(|| PerfError::new("unknown connection"))?;
        let stream_id = state.next_stream_id;
        state.next_stream_id = next_client_stream_id(stream_id);
        Ok(stream_id)
    }
}

fn request_limit_for_connection(config: &PerfConfig, connection_index: usize) -> Option<usize> {
    if config.mode != Mode::Rr && config.mode != Mode::PersistentRr {
        return None;
    }
    let requests = config.requests?;
    let connections = rr_connection_target(config);
    let base = requests / connections;
    let remainder = requests % connections;
    Some(base + usize::from(connection_index < remainder))
}

fn rr_connection_target(config: &PerfConfig) -> usize {
    if config.mode == Mode::Rr || config.mode == Mode::PersistentRr {
        if let Some(requests) = config.requests {
            return config.connections.min(requests);
        }
    }
    config.connections
}

fn make_payload(bytes: usize) -> Vec<u8> {
    vec![0x5a; bytes]
}

fn make_connection_id(prefix: u8, sequence: u64) -> Vec<u8> {
    let mut connection_id = vec![0u8; 8];
    connection_id[0] = prefix;
    for index in 1..connection_id.len() {
        let shift = ((connection_id.len() - 1 - index) * 8) as u32;
        connection_id[index] = ((sequence >> shift) & 0xff) as u8;
    }
    connection_id
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_match_native_shape() {
        assert_eq!(make_connection_id(0xc1, 1), vec![0xc1, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            make_connection_id(0x83, 0x41),
            vec![0x83, 0, 0, 0, 0, 0, 0, 0x41]
        );
    }

    #[test]
    fn initial_connection_target_matches_modes() {
        let mut config = PerfConfig::default();
        config.role = crate::config::Role::Client;
        config.connections = 3;
        let target = target_for_test(&config);
        assert_eq!(target, 3);

        config.mode = Mode::Crr;
        assert_eq!(target_for_test(&config), 0);

        config.mode = Mode::Rr;
        config.requests = Some(10);
        assert_eq!(target_for_test(&config), 1);
    }

    fn target_for_test(config: &PerfConfig) -> usize {
        if config.mode == Mode::Rr && config.requests.is_some() {
            1
        } else if config.mode == Mode::Crr {
            0
        } else {
            config.connections
        }
    }
}

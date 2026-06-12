use crate::config::{server_endpoint_config, Direction, Mode, PerfConfig};
use crate::io::{OwnedEffect, UdpRuntime, WaitEvent};
use crate::protocol::{
    decode_control_message, encode_control_message, ControlMessage, SessionComplete, SessionError,
    SessionReady, SessionStart, CONTROL_STREAM_ID, PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY,
};
use crate::{PerfError, Result};
use coquic::quic::Endpoint;
use coquic::{ConnectionHandle, Lifecycle, QueryResult, StreamId};
use std::collections::HashMap;
use std::time::Duration;

const IDLE_TIMEOUT: Duration = Duration::from_millis(1000);

#[derive(Debug)]
struct Session {
    control_bytes: Vec<u8>,
    start: Option<SessionStart>,
    complete_sent: bool,
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
    persistent_rr_pending_request_bytes: HashMap<StreamId, u64>,
}

impl Session {
    fn new(_connection: ConnectionHandle) -> Self {
        Self {
            control_bytes: Vec::new(),
            start: None,
            complete_sent: false,
            bytes_sent: 0,
            bytes_received: 0,
            requests_completed: 0,
            persistent_rr_pending_request_bytes: HashMap::new(),
        }
    }
}

pub async fn run_server(config: PerfConfig) -> Result<crate::metrics::RunSummary> {
    let endpoint_config = server_endpoint_config(&config)?;
    let mut endpoint = Endpoint::new(&endpoint_config)?;
    let mut io =
        UdpRuntime::server(&config.host, config.port, config.max_outbound_datagram_size).await?;
    let mut server = Server {
        endpoint: &mut endpoint,
        io: &mut io,
        sessions: HashMap::new(),
        payload_cache: HashMap::new(),
        accepted_session: false,
        completed_session_seen: false,
    };

    server.run().await?;
    Ok(crate::metrics::new_run_summary(&config))
}

struct Server<'a> {
    endpoint: &'a mut Endpoint,
    io: &'a mut UdpRuntime,
    sessions: HashMap<ConnectionHandle, Session>,
    payload_cache: HashMap<usize, Vec<u8>>,
    accepted_session: bool,
    completed_session_seen: bool,
}

enum ServerCommand {
    SendResponse {
        connection: ConnectionHandle,
        stream_id: StreamId,
        bytes: u64,
        fin: bool,
    },
    SendControl {
        connection: ConnectionHandle,
        message: ControlMessage,
    },
}

impl Server<'_> {
    async fn run(&mut self) -> Result<()> {
        loop {
            self.handle_due_timer().await?;
            if self.should_exit_on_session_complete() || self.should_exit_on_idle_empty() {
                return Ok(());
            }

            match self
                .io
                .wait(self.endpoint.next_wakeup(), IDLE_TIMEOUT)
                .await?
            {
                WaitEvent::Datagram(datagram) => {
                    let now = self.io.now_us();
                    let inbound = self.io.inbound_datagram(&datagram);
                    let result = self.endpoint.receive_datagram(inbound, now)?;
                    self.handle_result(result, now).await?;
                }
                WaitEvent::Timer => {
                    let now = self.io.now_us();
                    let result = self.endpoint.timer_expired(now)?;
                    self.handle_result(result, now).await?;
                }
                WaitEvent::Idle => {
                    self.io.flush_sends().await?;
                    if self.should_exit_on_idle_empty() || self.should_exit_on_session_complete() {
                        return Ok(());
                    }
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

    async fn handle_result(&mut self, result: QueryResult, now: coquic::TimeUs) -> Result<()> {
        let mut pending_results = vec![result];
        while let Some(result) = pending_results.pop() {
            let commands = self.collect_result_commands(result, now)?;
            for command in commands {
                pending_results.push(self.execute_command(command, now)?);
            }
        }
        self.io.flush_sends().await?;
        Ok(())
    }

    fn collect_result_commands(
        &mut self,
        result: QueryResult,
        now: coquic::TimeUs,
    ) -> Result<Vec<ServerCommand>> {
        if let Some(error) = result.local_error()? {
            return Err(PerfError::new(format!("server local error: {error:?}")));
        }

        let effects = self.io.collect_result_effects(&result)?;
        drop(result);

        let mut commands = Vec::new();
        for effect in effects {
            match effect {
                OwnedEffect::ConnectionLifecycleEvent { connection, event } => match event {
                    Lifecycle::Accepted => {
                        self.accepted_session = true;
                        self.sessions.insert(connection, Session::new(connection));
                    }
                    Lifecycle::Closed => {
                        self.sessions.remove(&connection);
                    }
                    Lifecycle::Created | Lifecycle::Unknown(_) => {}
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
                OwnedEffect::PeerResetStream { .. }
                | OwnedEffect::PeerStopSending { .. }
                | OwnedEffect::StateEvent { .. } => {}
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
        _now: coquic::TimeUs,
    ) -> Result<Vec<ServerCommand>> {
        let mut commands = Vec::new();
        if stream_id == CONTROL_STREAM_ID {
            let session = self
                .sessions
                .get_mut(&connection)
                .ok_or_else(|| PerfError::new("control stream for unknown session"))?;
            session.control_bytes.extend_from_slice(&bytes);
            if !fin {
                return Ok(commands);
            }

            let decoded = decode_control_message(&session.control_bytes);
            session.control_bytes.clear();
            let Some(ControlMessage::SessionStart(start)) = decoded else {
                commands.push(ServerCommand::SendControl {
                    connection,
                    message: ControlMessage::SessionError(SessionError {
                        reason: "expected session_start".to_owned(),
                    }),
                });
                return Ok(commands);
            };

            if let Some(reason) = validate_session_start(&start) {
                commands.push(ServerCommand::SendControl {
                    connection,
                    message: ControlMessage::SessionError(SessionError { reason }),
                });
                return Ok(commands);
            }

            let session = self
                .sessions
                .get_mut(&connection)
                .ok_or_else(|| PerfError::new("session disappeared"))?;
            session.start = Some(start);
            commands.push(ServerCommand::SendControl {
                connection,
                message: ControlMessage::SessionReady(SessionReady {
                    protocol_version: PROTOCOL_VERSION,
                }),
            });
            return Ok(commands);
        }

        let Some(start) = self
            .sessions
            .get(&connection)
            .and_then(|session| session.start.clone())
        else {
            return Ok(commands);
        };

        {
            let session = self
                .sessions
                .get_mut(&connection)
                .ok_or_else(|| PerfError::new("data stream for unknown session"))?;
            session.bytes_received += bytes.len() as u64;
            if fin && start.mode != Mode::PersistentRr {
                session.requests_completed += 1;
            }
        }

        if start.mode == Mode::PersistentRr {
            return self.handle_persistent_rr_data(connection, stream_id, bytes.len() as u64, fin);
        }

        match (start.mode, start.direction, fin) {
            (Mode::Bulk, Direction::Download, true) if start.total_bytes.is_none() => {
                commands.push(ServerCommand::SendResponse {
                    connection,
                    stream_id,
                    bytes: start.response_bytes,
                    fin: true,
                });
                if let Some(session) = self.sessions.get_mut(&connection) {
                    session.bytes_sent += start.response_bytes;
                }
            }
            (Mode::Bulk, Direction::Download, true) => {
                let stream_index = self
                    .sessions
                    .get(&connection)
                    .map(|session| session.requests_completed.saturating_sub(1))
                    .unwrap_or(0);
                let total_bytes = start.total_bytes.unwrap_or(0);
                let per_stream = total_bytes / start.streams;
                let remainder = total_bytes % start.streams;
                let target_bytes = per_stream + u64::from(stream_index < remainder);
                commands.push(ServerCommand::SendResponse {
                    connection,
                    stream_id,
                    bytes: target_bytes,
                    fin: true,
                });
                let should_complete = if let Some(session) = self.sessions.get_mut(&connection) {
                    session.bytes_sent += target_bytes;
                    session.requests_completed >= start.streams
                } else {
                    false
                };
                if should_complete {
                    if let Some(command) = self.make_complete_command(connection) {
                        commands.push(command);
                    }
                }
            }
            (Mode::Bulk, Direction::Upload, true) if start.total_bytes.is_some() => {
                let complete = self
                    .sessions
                    .get(&connection)
                    .map(|session| session.requests_completed >= start.streams)
                    .unwrap_or(false);
                if complete {
                    if let Some(command) = self.make_complete_command(connection) {
                        commands.push(command);
                    }
                }
            }
            (Mode::Rr | Mode::Crr, _, true) => {
                commands.push(ServerCommand::SendResponse {
                    connection,
                    stream_id,
                    bytes: start.response_bytes,
                    fin: true,
                });
                if let Some(session) = self.sessions.get_mut(&connection) {
                    session.bytes_sent += start.response_bytes;
                }
                let complete = start.mode == Mode::Rr
                    && start
                        .requests
                        .map(|requests| {
                            self.sessions
                                .get(&connection)
                                .map(|session| session.requests_completed >= requests)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                if complete {
                    if let Some(command) = self.make_complete_command(connection) {
                        commands.push(command);
                    }
                }
            }
            _ => {}
        }

        Ok(commands)
    }

    fn handle_persistent_rr_data(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        byte_count: u64,
        fin: bool,
    ) -> Result<Vec<ServerCommand>> {
        let mut commands = Vec::new();
        let Some(session) = self.sessions.get_mut(&connection) else {
            return Ok(commands);
        };
        let Some(start) = session.start.clone() else {
            return Ok(commands);
        };
        let request_bytes = start.request_bytes;
        let response_bytes = start.response_bytes;
        let mut send_complete = false;
        let pending_request_bytes = session
            .persistent_rr_pending_request_bytes
            .entry(stream_id)
            .or_insert(0);
        *pending_request_bytes = pending_request_bytes.saturating_add(byte_count);
        while *pending_request_bytes >= request_bytes {
            commands.push(ServerCommand::SendResponse {
                connection,
                stream_id,
                bytes: response_bytes,
                fin: false,
            });
            session.bytes_sent += response_bytes;
            session.requests_completed += 1;
            *pending_request_bytes -= request_bytes;
            if start
                .requests
                .map(|requests| session.requests_completed >= requests)
                .unwrap_or(false)
            {
                send_complete = true;
                break;
            }
        }
        if fin {
            session
                .persistent_rr_pending_request_bytes
                .remove(&stream_id);
        }
        if send_complete {
            if let Some(command) = self.make_complete_command(connection) {
                commands.push(command);
            }
        }
        Ok(commands)
    }

    fn execute_command(
        &mut self,
        command: ServerCommand,
        now: coquic::TimeUs,
    ) -> Result<QueryResult> {
        match command {
            ServerCommand::SendResponse {
                connection,
                stream_id,
                bytes,
                fin,
            } => self.send_response_body(connection, stream_id, bytes, fin, now),
            ServerCommand::SendControl {
                connection,
                message,
            } => self.send_control(connection, message, now),
        }
    }

    fn send_response_body(
        &mut self,
        connection: ConnectionHandle,
        stream_id: StreamId,
        bytes: u64,
        fin: bool,
        now: coquic::TimeUs,
    ) -> Result<QueryResult> {
        let endpoint = &self.endpoint;
        let payload_cache = &mut self.payload_cache;
        let payload = cached_payload(payload_cache, bytes as usize);
        endpoint
            .connection(connection)
            .stream(stream_id)
            .send(payload, fin, now)
            .map_err(Into::into)
    }

    fn send_control(
        &mut self,
        connection: ConnectionHandle,
        message: ControlMessage,
        now: coquic::TimeUs,
    ) -> Result<QueryResult> {
        let fin = matches!(
            message,
            ControlMessage::SessionError(_) | ControlMessage::SessionComplete(_)
        );
        let payload = encode_control_message(&message);
        self.endpoint
            .connection(connection)
            .stream(CONTROL_STREAM_ID)
            .send(&payload, fin, now)
            .map_err(Into::into)
    }

    fn make_complete_command(&mut self, connection: ConnectionHandle) -> Option<ServerCommand> {
        let Some(session) = self.sessions.get_mut(&connection) else {
            return None;
        };
        if session.complete_sent {
            return None;
        }
        session.complete_sent = true;
        self.completed_session_seen = true;
        let complete = SessionComplete {
            bytes_sent: session.bytes_sent,
            bytes_received: session.bytes_received,
            requests_completed: session.requests_completed,
        };
        Some(ServerCommand::SendControl {
            connection,
            message: ControlMessage::SessionComplete(complete),
        })
    }

    fn should_exit_on_idle_empty(&self) -> bool {
        self.accepted_session
            && self.sessions.is_empty()
            && env_flag_enabled("COQUIC_PERF_SERVER_EXIT_ON_IDLE_EMPTY")
    }

    fn should_exit_on_session_complete(&self) -> bool {
        self.accepted_session
            && self.completed_session_seen
            && env_flag_enabled("COQUIC_PERF_SERVER_EXIT_ON_SESSION_COMPLETE")
            && self.sessions.values().all(|session| session.complete_sent)
            && !self.endpoint.has_send_continuation_pending()
            && !self.endpoint.has_pending_stream_send()
    }
}

pub fn validate_session_start(start: &SessionStart) -> Option<String> {
    if start.protocol_version != PROTOCOL_VERSION
        && start.protocol_version != PROTOCOL_VERSION_LEGACY
    {
        return Some("unsupported protocol version".to_owned());
    }
    if start.streams == 0 {
        return Some("streams must be greater than zero".to_owned());
    }
    if start.connections == 0 {
        return Some("connections must be greater than zero".to_owned());
    }
    if start.requests_in_flight == 0 {
        return Some("requests_in_flight must be greater than zero".to_owned());
    }
    if start.mode == Mode::PersistentRr && (start.request_bytes == 0 || start.response_bytes == 0) {
        return Some("persistent-rr requires nonzero request and response bytes".to_owned());
    }
    None
}

fn make_payload(bytes: usize) -> Vec<u8> {
    vec![0x5a; bytes]
}

fn cached_payload(cache: &mut HashMap<usize, Vec<u8>>, bytes: usize) -> &[u8] {
    cache
        .entry(bytes)
        .or_insert_with(|| make_payload(bytes))
        .as_slice()
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_session_start_counts() {
        let mut start = SessionStart::default();
        assert_eq!(validate_session_start(&start), None);
        start.streams = 0;
        assert_eq!(
            validate_session_start(&start),
            Some("streams must be greater than zero".to_owned())
        );
    }
}
